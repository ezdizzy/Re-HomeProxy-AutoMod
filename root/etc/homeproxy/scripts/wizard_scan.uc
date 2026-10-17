#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Routing Wizard: provider scan (Ф2).
 *
 * One-shot background prober spawned by the rpcd method wizard_provider_scan.
 * For each test host it measures THREE facts and derives a verdict:
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
 *
 * Verdicts (per host): opens_direct / dns_poison / needs_proxy /
 * needs_strategy / geo_blocked / main_path_fail / control_fail / down /
 * unknown. The verdict feeds the Wizard UI recommendations; nothing here
 * writes UCI or touches routing.
 *
 * Status  → /var/run/homeproxy/wizard_scan.json         {running,done,total,current,…}
 * Result  → /var/run/homeproxy/wizard_scan_result.json  {ts, hosts:[…], summary}
 * Both files are written atomically (temp + mv): the RPC reads them
 * concurrently and a truncated JSON would surface as "—" in the UI
 * (automation.atomic_write constraint — same for this scanner).
 *
 * Custom hosts (optional) come from /var/run/homeproxy/wizard_scan_hosts.txt
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
import { cursor } from 'uci';

const RUN_DIR = '/var/run/homeproxy';
const STATUS = RUN_DIR + '/wizard_scan.json';
const RESULT = RUN_DIR + '/wizard_scan_result.json';
const EXTRA  = RUN_DIR + '/wizard_scan_hosts.txt';

const DIRECT_PORT = 5336;   /* auto-direct-in → direct-out (pinned) */
const PROXY_PORT  = 5337;   /* auto-proxy-in  → main-out   (pinned) */
const PROBE_TMO   = 7;      /* curl --max-time seconds */

/* Test corpus. svc feeds the recommendation text; ru_control hosts must NEVER
 * be recommended for proxying (RU services flag VPN exits, RU-protect keeps
 * them direct) — a failed control host is an internet/RU-protect anomaly. */
const CORPUS = [
	{ host: 'www.youtube.com',      svc: 'youtube' },
	{ host: 'i.ytimg.com',          svc: 'youtube' },
	{ host: 'discord.com',          svc: 'discord' },
	{ host: 'gateway.discord.gg',   svc: 'discord' },
	{ host: 'web.telegram.org',     svc: 'telegram' },
	{ host: 'gemini.google.com',    svc: 'google_ai' },
	{ host: 'chatgpt.com',          svc: 'openai' },
	{ host: 'api.openai.com',       svc: 'openai' },
	{ host: 'x.com',                svc: 'twitter' },
	{ host: 'instagram.com',        svc: 'meta' },
	{ host: 'rutube.ru',            svc: 'ru_control' },
	{ host: 'gosuslugi.ru',         svc: 'ru_control' }
];

/* 200/3xx page whose body matches one of these is an operator block page
 * (same list as the engine's BLOCK_SIGNATURES — keep in sync). */
const BLOCK_SIGNATURES = [
	'access denied', 'access forbidden', 'forbidden', 'доступ ограничен',
	'доступ запрещен', 'заблокир', 'заблокиров', 'blocked by', 'block page',
	'the site is blocked', 'сайт заблокирован', 'err_blocked', 'доступ к ресурсу',
	'blocked site', 'не доступен', 'resource is limited', 'request blocked'
];

/* Geo-refusal phrases (same list as the engine's GEO_REFUSAL_PATTERNS): a 200
 * that refuses the region at application level is NOT a success. */
const GEO_REFUSAL_PATTERNS = [
	"isn't currently supported in your country",
	'not supported in your country',
	'not available in your country',
	'is not supported in your country',
	'unavailable in your region',
	'not available in your region',
	'unsupported_country_region_territory',
	'страна не поддерживается',
	'не поддерживается в вашей стране',
	'недоступен в вашей стране'
];

/* Strong WAF/challenge markers (engine's WAF_SIGNATURES_STRONG): a 4xx page
 * carrying one of these means the request REACHED the real service — the path
 * is open, the client shape is the problem. Not a censorship verdict. */
const WAF_SIGNATURES_STRONG = [
	'just a moment', 'attention required', 'checking your browser',
	'cf-chl', 'challenge-platform', 'cf-mitigated', 'cf-turnstile',
	'are you a robot', 'bot protection', 'ddos protection', 'captcha'
];

/* Plain public resolvers for the direct-side DNS view, in fallback order —
 * TCP/53 is ISP-blocked here but UDP works; 8.8.8.8 alone proved flaky
 * (the engine falls back the same way). */
const PLAIN_RESOLVERS = [ '8.8.8.8', '1.1.1.1', '77.88.8.8' ];

/* ── Small helpers (NO hoisting in ucode: all declared before first call) ── */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function atomic_write(path, content) {
	const tmp = path + '.tmp';
	writefile(tmp, content);
	system(`mv -f ${sq(tmp)} ${sq(path)}`);
}

function write_status(obj) {
	obj.ts = time();
	atomic_write(STATUS, sprintf('%.J', obj) + '\n');
}

function body_sig(body) {
	if (!body || length(body) > 32768)
		return null;
	const b = lc(body);
	for (let s in BLOCK_SIGNATURES)
		if (index(b, s) >= 0) return 'sigpage';
	for (let s in GEO_REFUSAL_PATTERNS)
		if (index(b, s) >= 0) return 'geo_refused';
	return null;
}

function body_waf(body) {
	if (!body || length(body) > 32768)
		return false;
	const b = lc(body);
	for (let s in WAF_SIGNATURES_STRONG)
		if (index(b, s) >= 0) return true;
	return false;
}

/* HTTP-code class: 'ok' (2xx/3xx), 'block' (4xx/5xx), 'fail' (no response). */
function code_class(code) {
	const c = trim('' + (code || '000'));
	if (c === '' || c === '000') return 'fail';
	const n = int(c);
	if (n >= 200 && n < 400) return 'ok';
	if (n >= 400 && n <= 599) return 'block';
	return 'fail';
}

/* curl exit code → transport-level block kind. rc 35/56 = TLS handshake reset
 * right after ClientHello (classic SNI DPI); rc 7 = TCP connect refused/
 * unreachable (IP block when the IP was pinned, DNS gap otherwise); rc 28 =
 * total timeout (DPI drop or filtered route); rc 5/6 = resolution failure. */
function rc_kind(rc, had_pin) {
	if (rc === 35 || rc === 56) return 'tls_dpi';
	if (rc === 7) return had_pin ? 'tcp' : 'resolve';
	if (rc === 28) return 'timeout';
	if (rc === 5 || rc === 6) return 'resolve';
	if (rc === 0) return null;
	return 'transport';
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

/* One HTTPS probe through a loopback inbound. Returns
 * { code, rc, ok, kind, geo_refused } — kind/geo_refused explain WHY it failed.
 * `socks_h` selects socks5h (resolve at the tunnel end — main path) vs plain
 * socks5 (resolve locally — direct path, pin the plain-view answer). */
function probe(host, port, socks_h, pin_ip) {
	const px = `socks5${socks_h ? 'h' : ''}://127.0.0.1:${port}`;
	const pin = (!socks_h && pin_ip) ? ` --resolve ${sq(host + ':443:' + pin_ip)}` : '';
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';

	const attempt = (scheme) => {
		system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
		const cmd = `curl -sL --max-redirs 2 -o ${sq(bf)} -w '%{http_code}' -k ` +
			`--connect-timeout 4 --max-time ${PROBE_TMO} -x ${px}${pin} ` +
			`${sq(scheme + '://' + host)} > ${sq(cf)} 2>/dev/null`;
		const rc = system(cmd, PROBE_TMO * 1000 + 3000);
		const code = trim(readfile(cf) || '000');
		const body = readfile(bf) || '';
		return { code: code, rc: rc, body: body };
	};

	/* HTTPS first; retry plain HTTP only when HTTPS produced no HTTP answer at
	 * all (HTTP-only / redirect-to-http sites). A TLS reset (rc 35) or TCP
	 * failure is already definitive — retrying there wastes seconds and can
	 * mislead (a working :80 does not mean the service works). */
	let r = attempt('https');
	let cls = code_class(r.code);
	if (cls === 'fail' && r.rc !== 35 && r.rc !== 56 && r.rc !== 7) {
		const r2 = attempt('http');
		if (code_class(r2.code) !== 'fail') {
			r = r2;
			cls = code_class(r2.code);
		}
	}

	const kind = rc_kind(r.rc, !!pin);
	/* REACHABILITY semantics (diagnostics, not the engine's learning rules):
	 * any HTTP answer means the TCP+TLS path is OPEN — censorship shows up as
	 * no answer at all (RST/timeout) or a substituted page. Only genuine
	 * refusal codes (403/406/451) count as "not usable", and only a strong
	 * WAF page excuses them (the request reached the real service). */
	let ok = false;
	let use_kind = kind;
	if (cls === 'ok') {
		const sig = body_sig(r.body);
		if (sig === 'sigpage') {
			use_kind = 'sigpage';
		} else if (sig === 'geo_refused') {
			ok = false;
			use_kind = kind;
			return { code: r.code, rc: r.rc, ok: false, kind: use_kind, geo_refused: true };
		} else {
			ok = true;
		}
	} else if (cls === 'block') {
		if (body_waf(r.body)) {
			ok = true;
			use_kind = 'waf';
		} else if (r.code === '403' || r.code === '406' || r.code === '451') {
			ok = false;
			use_kind = 'hardcode';
		} else {
			/* 404 on a CDN root, 421 from an API, 5xx app errors — the PATH
			 * itself works; the service-level verdicts come from the
			 * service check RPC, not from this scan. */
			ok = true;
			use_kind = null;
		}
	}
	return { code: r.code, rc: r.rc, ok: ok, kind: use_kind, geo_refused: false };
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
	return ctx.get('homeproxy', section, opt);
}
const mixed_port = '' + (uci_get('infra', 'mixed_port') || '5330');

const direct_in = port_listening(DIRECT_PORT);
const proxy_in = port_listening(PROXY_PORT);
const mixed_in = port_listening(int(mixed_port));

/* Host list: fixed corpus + optional custom hosts (one per line). */
const hosts = [];
for (let c in CORPUS)
	push(hosts, { host: c.host, svc: c.svc });
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
write_status({ running: true, done: 0, total: total, current: '',
	direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port });

const results = [];
let done = 0;

for (let item in hosts) {
	const host = item.host;
	write_status({ running: true, done: done, total: total, current: host,
		direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port });

	const res = { host: host, svc: item.svc };
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
		res.direct = probe(host, DIRECT_PORT, false, null);
	} else if (res.plain_ip) {
		res.direct = probe(host, DIRECT_PORT, false, res.plain_ip);
	} else {
		/* Plain DNS silent → the browser cannot resolve either: report a
		 * DNS-side gap, not a routing verdict. */
		res.direct = { code: '000', rc: 6, ok: false, kind: 'resolve', geo_refused: false };
	}

	/* MAIN path probe — socks5h (resolve at the tunnel end). The pinned
	 * :5337 rides main-out; the mixed inbound rides the LIVE rules and is
	 * the honest fallback when the pinned pair is absent. */
	const main_port = proxy_in ? PROXY_PORT : int(mixed_port);
	if (proxy_in) {
		res.proxy = probe(host, main_port, true, null);
	} else if (mixed_in) {
		res.proxy = probe(host, main_port, true, null);
		res.proxy.via = 'mixed';
	} else {
		res.proxy = null;
	}

	/* DNS-poison confirmation: router answer differs AND the router-answer
	 * path fails while the plain-answer path works. One extra unpinned direct
	 * probe, only in that rare case. */
	res.dns_poison = false;
	if (res.dns_differs && res.direct && res.direct.ok) {
		const via_router = probe(host, DIRECT_PORT, false, null);   /* no pin → router DNS */
		res.dns_poison = !via_router.ok;
	}

	/* ── Verdict ── */
	const d_ok = !!(res.direct && res.direct.ok);
	const p_ok = !!(res.proxy && res.proxy.ok);
	const d_geo = !!(res.direct && res.direct.geo_refused);
	const p_geo = !!(res.proxy && res.proxy.geo_refused);

	if (!direct_in && !proxy_in && !mixed_in) {
		res.verdict = 'unknown';       /* nothing measured — do not invent */
	} else if (item.svc === 'ru_control') {
		res.verdict = d_ok ? 'opens_direct' : 'control_fail';
	} else if (d_ok && p_ok) {
		res.verdict = 'opens_direct';
	} else if (d_ok && !p_ok) {
		/* Direct works but the user's main path does not: dead node/misconfig. */
		res.verdict = 'main_path_fail';
	} else if (!direct_in) {
		res.verdict = 'partial';       /* only the proxy side was measurable */
	} else if (!d_ok && p_ok) {
		if (res.dns_poison || (res.direct.kind === 'resolve' && res.plain_ip))
			res.verdict = 'dns_poison';
		else
			res.verdict = 'needs_proxy';
	} else if (!d_ok && !p_ok) {
		if (d_geo && p_geo)
			res.verdict = 'geo_blocked';
		else if ((res.direct.kind === 'tls_dpi') || (res.proxy && res.proxy.kind === 'tls_dpi'))
			res.verdict = 'needs_strategy';
		else
			res.verdict = 'down';
	} else {
		res.verdict = 'unknown';
	}

	/* Recommendation for the Wizard UI (server-side so JS stays dumb). */
	switch (res.verdict) {
	case 'opens_direct': res.recommend = null; break;
	case 'dns_poison':   res.recommend = 'dns'; break;
	case 'needs_proxy':  res.recommend = 'rule'; break;
	case 'needs_strategy': res.recommend = 'strategy'; break;
	case 'geo_blocked':  res.recommend = 'node'; break;
	case 'main_path_fail': res.recommend = 'main_path'; break;
	case 'control_fail': res.recommend = 'anomaly'; break;
	default:             res.recommend = 'none'; break;
	}

	push(results, res);
	done++;
	write_status({ running: true, done: done, total: total, current: '',
		direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port });
}

/* Summary counted from the results — no counter to forget. */
const SUMMARY_KEYS = {
	opens_direct: true, needs_proxy: true, needs_strategy: true, dns_poison: true,
	geo_blocked: true, main_path_fail: true, control_fail: true, down: true,
	partial: true, unknown: true
};
const summary = { opens_direct: 0, needs_proxy: 0, needs_strategy: 0, dns_poison: 0,
	geo_blocked: 0, main_path_fail: 0, control_fail: 0, down: 0, partial: 0, unknown: 0 };
for (let r in results)
	if (SUMMARY_KEYS[r.verdict])
		summary[r.verdict]++;

atomic_write(RESULT, sprintf('%.J', {
	ts: time(),
	direct_in: direct_in,
	proxy_in: proxy_in,
	mixed_in: mixed_in,
	mixed_port: mixed_port,
	hosts: results,
	summary: summary
}) + '\n');
write_status({ running: false, done: total, total: total, current: 'done',
	direct_in: direct_in, proxy_in: proxy_in, mixed_in: mixed_in, mixed_port: mixed_port,
	finished: time() });
