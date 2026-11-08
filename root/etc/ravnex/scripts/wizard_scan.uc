#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Routing Wizard: provider scan (Ф2, пересмотр Ф7).
 *
 * One-shot background prober spawned by the rpcd method wizard_provider_scan.
 * For each test host it measures FOUR facts and derives a verdict:
 *
 *   1. DNS view: nslookup via the ROUTER resolver (what LAN clients get) vs a
 *      PLAIN public resolver (8.8.8.8, UDP/53 — TCP/53 is ISP-blocked). A
 *      mismatch alone is not a verdict (CDN geo-splitting is normal); only a
 *      mismatch that also breaks the real path is reported as DNS poisoning.
 *   2. DIRECT path: HTTPS through the pinned loopback inbound auto-direct-in
 *      (:5336 → direct-out), with the host pinned to the PLAIN resolver's
 *      answer (--resolve) — the same RU-facing resolution a browser would get.
 *      A plain router-originated curl is NOT a reliable direct probe: the
 *      router's own output interception reroutes blocklisted hosts through the
 *      proxy, silently faking "direct works".
 *   3. MAIN path: HTTPS through auto-proxy-in (:5337 → main-out), resolved at
 *      the tunnel end (socks5h) so local poisoning cannot break the
 *      measurement; falls back to the mixed inbound (live rules) when the
 *      pinned pair is absent.
 *   4. LIVE path (Ф7): plain router-originated HTTPS with NO pin and NO
 *      inbound — it rides the app's own output interception, so the resource
 *      is served exactly the way LAN clients are served right now: through
 *      the configured rules (proxy_ru_rule, learned lists, Zapret/ByeDPI
 *      desync on the marked flow). This answers the real question "does my
 *      configured routing deliver this resource", which the pinned probes
 *      cannot answer.
 *
 * Probe honesty rules (Ф7 пересмотр):
 *   - curl runs with -L (redirects followed) and the CURL EXIT CODE is part
 *     of the verdict: a 301/200 answer whose redirect chain (or body) was
 *     reset mid-way (rc 35/56 = TLS reset after the first response — the
 *     classic RU DPI pattern on YouTube/Discord) is NOT a success. Code
 *     alone lies; code + rc does not (youtube.com "✓ 301" was reported as
 *     "opens directly" before this fix).
 *   - body checks: RU block pages, geo-refusal phrases and per-service
 *     geo markers (Gemini serves 200 with "Something went wrong" outside
 *     supported regions) turn an HTTP success into a refusal.
 *   - transport failures classify by curl rc (tls_dpi/tcp/timeout/resolve) —
 *     the unified classification lives in diag_core.uc (Ф6.1).
 *
 * Verdicts (per host, Ф8-W2): opens_direct / works_live / needs_proxy /
 * needs_strategy / dns_poison / geo_blocked / main_path_fail /
 * config_broken / control_fail / down / partial / unknown.
 *   The verdict is about the CONFIGURED path (live probe first); the direct
 *   probe is the reference column. works_live — the LIVE configured path
 *   opens the resource (the main user-facing "it works" state); when the
 *   client knows the rule for the service it reads "works via the configured
 *   path (→ node)".
 *   geo_blocked carries geo_side: 'remote' (the service refuses the RU
 *   region — node with a supported region fixes it), 'both' (refused from
 *   both sides), 'exit' (the configured exit node's region is refused —
 *   switch the node).
 *   config_broken — both bare paths work but the LIVE configured path
 *   fails: the rule/strategy points the wrong way.
 *
 * Ф6.1 Diagnostic Core: the ROUTING verdict (above) is now SEPARATE from the
 * CAUSE verdict — every row additionally carries `cause` =
 * { type, confidence, evidence[] } with the ONE taxonomy
 * (isp_interference / origin_geo_restriction / origin_waf / origin_ip_policy /
 * dns_interference / client_filtering / remote_failure / inconclusive).
 * Differential discipline: direct TLS-reset + working proxy = confirmed ISP
 * interference (needs_strategy basis); BOTH paths failing the same way is
 * inconclusive ("cause not established") — no more needs_strategy from a
 * single tls_dpi. A bare 403/406 without markers is NOT DPI/geo proof.
 * A TLS trust probe (curl WITHOUT -k) on suspicious direct answers
 * distinguishes an injected page (bad cert = MITM) from an origin answer.
 *
 * Each probe carries a seconds float; a slow but working path (regional
 * throttling) surfaces in the UI as a "slow" hint.
 *
 * Status  → /var/run/ravnex/wizard_scan.json         {running,done,total,current,…}
 * Result  → /var/run/ravnex/wizard_scan_result.json  {ts, hosts:[…], summary}
 * Both files are written atomically (temp + mv): the RPC reads them
 * concurrently and a truncated JSON would surface as "—" in the UI
 * (automation.atomic_write constraint — same for this scanner).
 *
 * Custom hosts (optional) come from /var/run/ravnex/wizard_scan_hosts.txt
 * (one per line, written by the RPC before spawning) — never from ARGV (the
 * ARGV indexing differs between ucode builds on this platform).
 *
 * ucode constraints honored: no `typeof` in standalone ucode (type() only),
 * push(arr, x) as a function, for-in over an array yields ELEMENTS, match()
 * with regex literals only, index() for substring checks, json() parses but
 * never serializes (sprintf('%.J') writes JSON), no function hoisting (helpers
 * declared before first call), no fs.remove (system rm).
 */

'use strict';

import { access, readfile, writefile, popen } from 'fs';
import { atomic_write } from '/etc/ravnex/scripts/statestore.uc';
import { cursor } from 'uci';
/* Ф6.1 Diagnostic Core: ЕДИНАЯ классификация пути и причин — этот сканер
 * измеряет (mechanics) и передаёт факты в diag_cause(); сигнатуры-списки
 * (block/geo/WAF) импортируются, не копируются. */
import { classify_path, diag_cause, code_class, trust_kind }
	from '/etc/ravnex/scripts/diag_core.uc';

const RUN_DIR = '/var/run/ravnex';
const STATUS = RUN_DIR + '/wizard_scan.json';
const RESULT = RUN_DIR + '/wizard_scan_result.json';
const EXTRA  = RUN_DIR + '/wizard_scan_hosts.txt';

const DIRECT_PORT = 5336;   /* auto-direct-in → direct-out (pinned) */
const PROXY_PORT  = 5337;   /* auto-proxy-in  → main-out   (pinned) */
const PROBE_TMO   = 7;      /* curl --max-time seconds */
const LIVE_TMO    = 9;      /* live-path probe (router output rules) */

/* Test corpus (Ф8-W2, R4). svc feeds the recommendation text; ru_control hosts
 * must NEVER be recommended for proxying (RU services flag VPN exits, RU-protect
 * keeps them direct) — a failed control host is an internet/RU-protect anomaly.
 * New svc groups: whatsapp (WhatsApp web), anthropic (Claude web + API),
 * twitch (streaming — the HTTP probe sees the page, not the video stream).
 * 🔴 gemini.google.com УДАЛЁН из корпуса (урок 205, РЕШЕНИЕ ПОЛЬЗОВАТЕЛЯ):
 * автоматические пробы gemini кормят анти-абьюз Google (инцидент временного
 * бана ч.157); полная проверка Google AI остаётся РУЧНОЙ кнопкой на странице
 * «Правила для сервисов». */
const CORPUS = [
	{ host: 'www.youtube.com',      svc: 'youtube' },
	{ host: 'i.ytimg.com',          svc: 'youtube' },
	{ host: 'discord.com',          svc: 'discord' },
	{ host: 'gateway.discord.gg',   svc: 'discord' },
	{ host: 'web.telegram.org',     svc: 'telegram' },
	{ host: 'web.whatsapp.com',     svc: 'whatsapp' },
	{ host: 'chatgpt.com',          svc: 'openai' },
	{ host: 'api.openai.com',       svc: 'openai' },
	{ host: 'claude.ai',            svc: 'anthropic' },
	{ host: 'api.anthropic.com',    svc: 'anthropic' },
	{ host: 'x.com',                svc: 'twitter' },
	{ host: 'instagram.com',        svc: 'meta' },
	{ host: 'www.twitch.tv',        svc: 'twitch' },
	{ host: 'rutube.ru',            svc: 'ru_control' },
	{ host: 'gosuslugi.ru',         svc: 'ru_control' }
];

/* Сигнатуры-списки (block/geo/WAF) — в diag_core.uc (Ф6.1, единый источник);
 * этот сканер передаёт свои per-service маркеры в classify_path как
 * extra_markers. */

/* Per-service geo/refusal markers: services that answer 200 with an
 * application-level error page instead of a refusal code. Gemini serves
 * "Something went wrong" to unsupported regions (verified in a browser by
 * the user — a plain 200 here is NOT a success); the Generative Language
 * API answers with a location refusal in the error body. */
const SVC_REFUSAL_PATTERNS = {
	google_ai: [ 'something went wrong', 'что-то пошло не так' ],
	google_ai_api: [ 'user location is not supported', 'location is not supported' ]
};

/* Google AI needs an API-level geo probe: the gemini.google.com SPA shell
 * serves 200 everywhere, the refusal shows up only when the API answers
 * "User location is not supported for the API use" (that is exactly the
 * "something went wrong" the user sees when the model request fails). */
const GOOGLE_AI_API_PROBE = 'generativelanguage.googleapis.com/v1beta/models';

/* Exit countries the Google AI API refuses outright. The gemini web shell
 * also misbehaves from datacenter/VPN exits even when the region is fine —
 * a static 200 probe CANNOT see that; the honest full check is the
 * wizard_service_check RPC (API with a key + region), the scan only adds
 * the region guard and points the user at the full check. */
const AI_EXIT_BLOCKLIST = [ 'RU', 'BY', 'CN', 'HK', 'MO', 'IR', 'KP' ];

/* Plain public resolvers for the direct-side DNS view, in fallback order —
 * TCP/53 is ISP-blocked here but UDP works; 8.8.8.8 alone proved flaky
 * (the engine falls back the same way). */
const PLAIN_RESOLVERS = [ '8.8.8.8', '1.1.1.1', '77.88.8.8' ];

/* ── Small helpers (NO hoisting in ucode: all declared before first call) ── */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

/* Каноническая атомарная запись — State Store (statestore.uc, Ф1.7). */

function write_status(obj) {
	obj.ts = time();
	atomic_write(STATUS, sprintf('%.J', obj) + '\n');
}

/* body_sig / body_waf / code_class / rc_transport_kind — в diag_core.uc
 * (Ф6.1, единый классификатор; импортированы выше). */

/* TLS trust probe (65): curl БЕЗ -k через тот же путь — нужен только rc.
 * Проверка доверия к цепочке отличает подменённую страницу (чужой сертификат →
 * rc 60/19/51/82 = перехват TLS) от честного ответа источника (rc 0). Запускается
 * ТОЛЬКО для подозрительных прямых ответов (не на каждый хост — бюджет проб,
 * урок 197). */
function trust_probe(host, port, socks_h, pin_ip) {
	const px = `socks5${socks_h ? 'h' : ''}://127.0.0.1:${port}`;
	const pin = (!socks_h && pin_ip) ? ` --resolve ${sq(host + ':443:' + pin_ip)}` : '';
	const bf = RUN_DIR + '/wiz_probe.body';
	system(`rm -f ${sq(bf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} --connect-timeout 4 --max-time ${PROBE_TMO} -x ${px}${pin} ${sq('https://' + host)} >/dev/null 2>&1`;
	const rc = system(cmd, PROBE_TMO * 1000 + 3000);
	system(`rm -f ${sq(bf)} 2>/dev/null`);
	return rc;
}

/* Router-resolver answer (what LAN clients get): single server, no fallback —
 * the fallback chain is for the PLAIN public view. */
function resolve_router(host) {
	const fd = popen(`nslookup -type=A ${sq(host)} 127.0.0.1 2>/dev/null`);
	if (!fd) return null;
	const out = fd.read('all') || '';
	fd.close();
	for (let l in split(out, '\n')) {
		const m = match(trim(l), /^Address(\s+[0-9]+)?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(\s|$)/);
		if (m && m[2] !== '127.0.0.1')
			return m[2];
	}
	return null;
}

/* nslookup (UDP) answer extraction — busybox prints "Address: x.x.x.x" lines.
 * Falls back through PLAIN_RESOLVERS (TCP/53 is ISP-blocked here, UDP works;
 * the engine falls back the same way). */
function resolve_via(host) {
	for (let srv in PLAIN_RESOLVERS) {
		const fd = popen(`nslookup -type=A ${sq(host)} ${sq(srv)} 2>/dev/null`);
		if (!fd) continue;
		const out = fd.read('all') || '';
		fd.close();
		for (let l in split(out, '\n')) {
			const m = match(trim(l), /^Address(\s+[0-9]+)?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(\s|$)/);
			if (m && m[2] !== '127.0.0.1')
				return m[2];
		}
	}
	return null;
}

function is_ip_literal(h) {
	return !!match(h, /^\d{1,3}(\.\d{1,3}){3}$/);
}

function port_listening(port) {
	const fd = popen('netstat -tln 2>/dev/null');
	if (!fd) return false;
	let found = false;
	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		if (index(line, ':' + port + ' ') >= 0) {
			found = true;
			break;
		}
	}
	fd.close();
	return found;
}

/* Country of the LIVE exit (the same providers hp_exit_lookup uses — api.ip.sb
 * alone proved unreliable from VPN exits). ONE lookup per scan run: the exit
 * country feeds the Google AI region guard. A router-originated call rides
 * the output rules → the real configured exit. */
function live_exit_country() {
	const providers = [
		'https://api.ip.sb/geoip',
		'https://ipwho.is/',
		'http://ip-api.com/json/?fields=status,country,countryCode,as,asnum,query'
	];
	for (let p in providers) {
		const cf = RUN_DIR + '/wiz_probe.code';
		system(`rm -f ${sq(cf)} 2>/dev/null`);
		const rc = system(`curl -s --connect-timeout 4 --max-time 7 -k ${sq(providers[p])} > ${sq(cf)} 2>/dev/null`, 8000);
		if (rc !== 0) continue;
		let j = null;
		try { j = json(readfile(cf) || ''); } catch (e) { j = null; }
		if (!j || type(j) !== 'object') continue;
		const cc = lc(trim('' + (j.countryCode || j.country_code || '')));
		if (length(cc)) return cc;
	}
	return null;
}

/* curl -w code+time parser: '%{http_code} %{time_total}'. */
function parse_cwt(out) {
	const parts = split(trim(out || ''), /[[:space:]]+/);
	const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
	const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
	return { code: code, tsec: tsec };
}

/* Классификация сырого замера — classify_path() из diag_core.uc (Ф6.1):
 * единая форма пути { code, rc, tsec, ok, net, app_state, kind, geo_refused,
 * geo_via, waf, trust, slow } для ВСЕХ потребителей диагностики. */

/* One HTTPS probe through a loopback inbound. Returns the classify_path shape.
 * `socks_h` selects socks5h (resolve at the tunnel end — main path) vs plain
 * socks5 (resolve locally — direct path, pin the plain-view answer). */
function probe(host, port, socks_h, pin_ip, svc) {
	const px = `socks5${socks_h ? 'h' : ''}://127.0.0.1:${port}`;
	const pin = (!socks_h && pin_ip) ? ` --resolve ${sq(host + ':443:' + pin_ip)}` : '';
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';
	const markers = SVC_REFUSAL_PATTERNS[svc];

	const attempt = (scheme) => {
		system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
		const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
			`--connect-timeout 4 --max-time ${PROBE_TMO} -x ${px}${pin} ` +
			`${sq(scheme + '://' + host)} > ${sq(cf)} 2>/dev/null`;
		const rc = system(cmd, PROBE_TMO * 1000 + 3000);
		const cwt = parse_cwt(readfile(cf));
		const body = readfile(bf) || '';
		return { code: cwt.code, tsec: cwt.tsec, rc: rc, body: body };
	};

	/* HTTPS first; retry plain HTTP only when HTTPS produced no HTTP answer at
	 * all (HTTP-only / redirect-to-http sites). A TLS reset (rc 35) or TCP
	 * failure is already definitive — retrying there wastes seconds and can
	 * mislead (a working :80 does not mean the service works). */
	let r = attempt('https');
	if (code_class(r.code) === 'fail' && r.rc !== 35 && r.rc !== 56 && r.rc !== 7) {
		const r2 = attempt('http');
		if (code_class(r2.code) !== 'fail') {
			r = r2;
		}
	}
	return classify_path(r, !!pin, markers);
}

/* LIVE probe: plain router-originated HTTPS — rides the app's own output
 * interception (configured rules, learned lists, engine desync), DNS through
 * the router resolver. This is what a LAN client experiences right now. */
function probe_live(host, svc) {
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
		`--connect-timeout 4 --max-time ${LIVE_TMO} ${sq('https://' + host)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, LIVE_TMO * 1000 + 3000);
	const cwt = parse_cwt(readfile(cf));
	const body = readfile(bf) || '';
	return classify_path({ code: cwt.code, tsec: cwt.tsec, rc: rc, body: body },
		false, SVC_REFUSAL_PATTERNS[svc]);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

/* Refuse a second concurrent run (the RPC guards too; this is the belt).
 * Stale-guard: a scan that died mid-run must not lock the scanner forever —
 * status older than 15 minutes counts as not running. */
let prev = null;
if (access(STATUS)) {
	try { prev = json(readfile(STATUS) || ''); } catch (e) { prev = null; }
}
if (prev && prev.running && (time() - int(prev.ts) < 900)) {
	exit(0);
}

const ctx = cursor();
function uci_get(section, opt) {
	return ctx.get('ravnex', section, opt);
}
const mixed_port = '' + (uci_get('infra', 'mixed_port') || '5330');

const direct_in = port_listening(DIRECT_PORT);
const proxy_in = port_listening(PROXY_PORT);
const mixed_in = port_listening(int(mixed_port));

/* Host list: fixed corpus + optional custom hosts (one per line). */
const hosts = [];
for (let c in CORPUS)
	push(hosts, { host: c.host, svc: c.svc });
/* Ф8-F1: dpi-detect seeds (splify2-lists, updated by wizard_dpidetect.uc).
 * Domains where the provider's TSPU is confirmed cutting connections — the
 * honest "does my provider still cut this" checks. Rules: plain domains
 * only, .ru/.su/.рф NEVER (ru_tld_exclusion), no duplicates of the fixed
 * corpus or their subdomains, hard cap 12 so the scan time stays bounded. */
const DPI_FILE = '/etc/ravnex/resources/dpi_detect.txt';
const DPI_CAP = 12;
if (access(DPI_FILE)) {
	let dpi_n = 0;
	for (let l in split(readfile(DPI_FILE) || '', '\n')) {
		if (dpi_n >= DPI_CAP)
			break;
		const h = lc(trim(l));
		if (!length(h) || match(h, /^#/))
			continue;
		if (match(h, /\.(ru|su|xn--p1ai)$/) || index(h, '.рф') >= 0 || match(h, /^ru\./))
			continue;
		if (!match(h, /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$/))
			continue;
		let dup = false;
		for (let x in hosts)
			if (h === x.host ||
			    (length(h) > length(x.host) + 1 &&
			     substr(h, length(h) - length(x.host) - 1) === '.' + x.host)) {
				dup = true;
				break;
			}
		if (!dup) {
			push(hosts, { host: h, svc: 'dpi_detect' });
			dpi_n++;
		}
	}
}
if (access(EXTRA)) {
	const raw = readfile(EXTRA) || '';
	for (let l in split(raw, '\n')) {
		const h = lc(trim(l));
		if (!length(h) || match(h, /^#/))
			continue;
		let dup = false;
		for (let x in hosts)
			if (x.host === h) { dup = true; break; }
		if (!dup)
			push(hosts, { host: h, svc: 'custom' });
	}
	system('rm -f ' + sq(EXTRA));
}

const total = length(hosts);
const exit_cc = live_exit_country();
write_status({ running: true, done: 0, total: total, current: '',
	direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port });

const results = [];
let done = 0;

for (let item in hosts) {
	const host = item.host;
	const svc = item.svc;
	write_status({ running: true, done: done, total: total, current: host,
		direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port });

	const res = { host: host, svc: svc };
	const literal = is_ip_literal(host);

	/* DNS view: router resolver (LAN truth) vs plain public resolver.
	 * IP literals have no DNS view — skip both lookups. */
	if (literal) {
		res.router_ip = host;
		res.plain_ip = host;
		res.dns_differs = false;
	} else {
		res.router_ip = resolve_router(host);
		res.plain_ip = resolve_via(host);
		res.dns_differs = !!(res.router_ip && res.plain_ip && res.router_ip !== res.plain_ip);
	}

	/* DIRECT probe — pinned to the plain answer when we have one. */
	if (!direct_in) {
		res.direct = null;   /* inbound not emitted (custom mode) */
	} else if (literal) {
		res.direct = probe(host, DIRECT_PORT, false, null, svc);
	} else if (res.plain_ip) {
		res.direct = probe(host, DIRECT_PORT, false, res.plain_ip, svc);
	} else {
		/* Plain DNS silent → the browser cannot resolve either: report a
		 * DNS-side gap, not a routing verdict. */
		res.direct = { code: '000', rc: 6, tsec: null, ok: false, net: false,
			app_state: null, kind: 'resolve', geo_refused: false, geo_via: null,
			waf: null, trust: null, slow: false };
	}

	/* MAIN path probe — socks5h (resolve at the tunnel end). The pinned
	 * :5337 rides main-out; the mixed inbound rides the LIVE rules and is
	 * the honest fallback when the pinned pair is absent. */
	const main_port = proxy_in ? PROXY_PORT : int(mixed_port);
	if (proxy_in) {
		res.proxy = probe(host, main_port, true, null, svc);
	} else if (mixed_in) {
		res.proxy = probe(host, main_port, true, null, svc);
		res.proxy.via = 'mixed';
	} else {
		res.proxy = null;
	}

	/* LIVE probe — the configured path (rules + strategies), always. */
	res.live = probe_live(host, svc);

	/* Google AI API geo probe: the web shell serves 200 everywhere, so the
	 * region refusal is only visible in the API error body (through the
	 * LIVE path — the same exit the user's rules select). */
	res.api_geo = null;
	if (svc === 'google_ai') {
		res.api_geo = probe_live(GOOGLE_AI_API_PROBE, 'google_ai_api');
	}

	/* DNS-poison confirmation: router answer differs AND the router-answer
	 * path fails while the plain-answer path works. One extra unpinned direct
	 * probe, only in that rare case. */
	res.dns_poison = false;
	if (res.dns_differs && res.direct && res.direct.ok) {
		const via_router = probe(host, DIRECT_PORT, false, null, svc);   /* no pin → router DNS */
		res.dns_poison = !via_router.ok;
	}

	/* TLS trust probe (Ф6.1, урок 65): подозрительный ПРЯМОЙ ответ с HTTP-телом
	 * (заглушка/отказ/challenge) — одна доп. проба БЕЗ -k: чужой сертификат =
	 * перехват (MITM), валидный = ответ настоящего источника. Только rc.
	 * Бюджет: только строки с поднозрительным прямым ответом, не каждый хост. */
	if (res.direct && res.direct.rc === 0 && res.direct.code !== '000' &&
	    (!res.direct.ok || res.direct.waf)) {
		res.direct.trust = trust_kind(trust_probe(host, DIRECT_PORT, false,
			(!literal && res.plain_ip) ? res.plain_ip : null));
	}

	/* ── Verdict + Cause (Ф6.1 Diagnostic Core) ──
	 * Роутинг-вердикт (таксономия Ф8-W2) и причина (единая таксономия) теперь
	 * РАЗДЕЛЬНЫ и считаются ОДНИМ кодом в diag_core.uc — классификатор общий
	 * с Automation/Autopilot (Ф6.6/Ф6.7 подключат его же). Рекомендация —
	 * server-side, JS остаётся тупым. */
	const verdict = diag_cause({
		svc: svc,
		dns: { differs: res.dns_differs, poison: res.dns_poison, plain_ip: res.plain_ip },
		direct: res.direct,
		proxy: res.proxy,
		live: res.live,
		api_geo: res.api_geo,
		exit_blocked: !!(exit_cc && svc === 'google_ai' &&
			index(AI_EXIT_BLOCKLIST, uc(exit_cc)) >= 0),
		inbounds: { direct: direct_in, proxy: proxy_in, mixed: mixed_in }
	});
	res.verdict = verdict.verdict;
	res.geo_side = verdict.geo_side;
	res.recommend = verdict.recommend;
	res.cause = verdict.cause;

	push(results, res);
	done++;
	write_status({ running: true, done: done, total: total, current: '',
		direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port });
}

/* Summary counted from the results — no counter to forget. */
const SUMMARY_KEYS = {
	opens_direct: true, works_live: true, needs_proxy: true, needs_strategy: true,
	dns_poison: true, geo_blocked: true, main_path_fail: true, config_broken: true,
	control_fail: true, down: true, partial: true, unknown: true
};
const summary = { opens_direct: 0, works_live: 0, needs_proxy: 0, needs_strategy: 0,
	dns_poison: 0, geo_blocked: 0, main_path_fail: 0, config_broken: 0,
	control_fail: 0, down: 0, partial: 0, unknown: 0 };
for (let r in results)
	if (SUMMARY_KEYS[r.verdict])
		summary[r.verdict]++;

atomic_write(RESULT, sprintf('%.J', {
	ts: time(),
	direct_in: direct_in,
	proxy_in: proxy_in,
	mixed_in: mixed_in,
	mixed_port: mixed_port,
	exit: exit_cc,
	hosts: results,
	summary: summary
}) + '\n');
write_status({ running: false, done: total, total: total, current: 'done',
	direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port,
	finished: time() });
