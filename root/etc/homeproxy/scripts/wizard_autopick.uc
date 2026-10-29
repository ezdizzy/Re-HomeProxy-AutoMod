#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Strategy auto-pick runner (Ф8-F7, T3).
 *
 * Spawned by the wizard_auto_pick_start RPC: the RPC owns the lock and the
 * validation, this process drives the stages and rewrites the status file
 * atomically at every step (file-mode one-shot, the wizard_compose.uc
 * pattern — the lock lives in the RPC, never in the runner).
 *
 * Input:  /var/run/homeproxy/wizard_autopick_req.json
 *         { resource: "youtube"|"discord"|"telegram"|"general",
 *           mode: "quick"|"full", set_rule: true|false,
 *           strategy: "<args>" (optional — skip fuzz+pick), ts }
 * Output: /var/run/homeproxy/wizard_autopick.json
 *         { running, stage: "started"|"fuzz"|"pick"|"apply"|"verify"|"done"|"error",
 *           resource, mode, chosen: {name, args, score, avg_tls_ms, tag_ms, runners},
 *           verify: {host, code, tsec, rc, ok}, rule: {source, node}, notes, error, ts }
 *
 * Flow:
 *   1. FUZZ — reuse zapret_fuzz_result.json when fresh (< 6 h) and complete;
 *      when a fuzz is already running, WAIT for it (someone else started it —
 *      a second sweep would fight the same temp queue); otherwise start
 *      zapret_fuzz.sh <mode> 2 in the background and poll its status.
 *   2. PICK — from the fuzz ranking: strategies whose host entry for the
 *      resource tag passed the round majority AND was NOT a free pass (a
 *      baseline pass cannot credit a strategy). ч.116 ranking: the
 *      resource's OWN deep verdict (page/CDN/edge/REAL video-stream
 *      throughput, differential-only) ranks first — deep-verified above
 *      untested, deep-failed below — then the host's minimal TLS, then
 *      the global score. "general" takes the global ranking head
 *      (strategies[0]).
 *   3. RULE — when set_rule, hand the resource rule to the EXISTING
 *      wizard_preset_apply RPC through ubus (its guards — one-rule-per-source,
 *      main_is_direct, mode check — stay the single implementation). Never
 *      edit proxy_ru_rule directly here.
 *   4. APPLY — snapshot BOTH engines to /etc/homeproxy/backups/zapret_prev.json
 *      (exactly the file the Restore button reads back). ч.116: a TARGETED
 *      apply builds a SCOPED composition through the existing
 *      wizard_compose_build (the resource's own --hostlist-domains block,
 *      the other managed resources' auto-pilot winners kept, the general
 *      tail) — the old global write silently changed what served every
 *      other resource routed to Zapret; 'general' keeps the global write.
 *      When the auto-pilot daemon is enabled, the manual pick is handed
 *      over through zapret_autopilot_manual.json (the daemon adopts it as
 *      the winner on its next tick). Then zapret_cmd_opts +
 *      zapret_enabled=1 through the uci module (no shell), restart in the
 *      background.
 *   5. VERIFY — wait for the core to come back, then probe the resource
 *      through the CONFIGURED path (router-originated HTTPS, the scanner's
 *      live-probe method): HTTP code + seconds. youtube → www.youtube.com,
 *      discord → discord.com, telegram → web.telegram.org,
 *      general → gstatic generate_204. ч.116: the YouTube verify ends with
 *      the REAL video-stream throughput probe (a ranged 4 MB download of a
 *      live videoplayback URL from yt_stream_probe.uc, ≥128 KB/s = pass) —
 *      the honest «превью и видео грузятся» metric.
 *
 * Honesty rules: the strategy only serves the resource when its rule leads
 * to zapret-out — the notes always carry the actual rule state; a failed
 * live check does NOT roll back automatically (the fuzz measured the
 * strategy on the isolated queue — the server snapshot + Restore button
 * stay available; an auto-rollback would also undo the user's intent).
 *
 * ucode constraints honored (05-doc): popen from fs; sleep() in ms; push()/
 * shift() functions; for-in over arrays yields elements; match() only with
 * /regex/ literals; json() is a parser (serialize via sprintf('%.J'));
 * atomic writes (tmp + mv -f); no optional chaining.
 */

import { readfile, access, writefile, popen } from 'fs';
import { cursor } from 'uci';

const RUN_DIR = '/var/run/homeproxy';
const REQ = RUN_DIR + '/wizard_autopick_req.json';
const OUT = RUN_DIR + '/wizard_autopick.json';
const FUZZ_STATUS = RUN_DIR + '/zapret_fuzz.json';
const FUZZ_RESULT = RUN_DIR + '/zapret_fuzz_result.json';
const BAK = '/etc/homeproxy/backups/zapret_prev.json';
const NFQWS = '/opt/zapret2/nfq2/nfqws2';

const RESOURCES = {
	youtube:  { tag: 'yt', host: 'www.youtube.com',
		/* ч.109 deep verify: page (content) + thumbnail CDN + the video-stream
		 * edge — «сайт открывается» не значит «ресурс работает целиком»
		 * (карточки, превью и видео идут с разных CDN). The edge root
		 * legitimately answers 404 — ANY HTTP answer is a pass there.
		 * ч.116 adds the REAL video-stream throughput probe (a ranged 4 MB
		 * download of a live videoplayback URL, measured in bytes/second) —
		 * TSPU lets the handshake through and throttles the sustained
		 * stream, which no handshake or tiny fetch can see. */
		deep: [ 'https://www.youtube.com/', 'https://i.ytimg.com/generate_204', 'https://redirector.googlevideo.com/' ] },
	discord:  { tag: 'dc', host: 'discord.com',
		deep: [ 'https://discord.com/' ] },
	telegram: { tag: 'tg', host: 'web.telegram.org',
		deep: [ 'https://web.telegram.org/' ] },
	general:  { tag: null, host: 'www.gstatic.com/generate_204',
		deep: [ 'http://www.gstatic.com/generate_204' ] }
};
const YT_STREAM_MIN_SPEED = 131072;   /* 128 KB/s — below this «кружок»   */
const YT_STREAM_MIN_BYTES = 524288;   /* a 4 MB ranged window sanity floor */
const YT_STREAM_TTL = 1800;           /* the helper's own cache TTL        */
const FUZZ_FRESH = 6 * 3600;      /* reuse a ranking younger than 6 h       */
const FUZZ_WAIT_MAX = 2700;       /* floor for waiting a full fuzz (~45 min)*/
const FUZZ_DEAD = 900;            /* running:true with a stale ts = dead    */
const CORE_WAIT_MAX = 90;         /* cap for the service restart            */
const VERIFY_TMO = 9;             /* live-path probe --max-time             */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function wstat(o) {
	o.ts = time();
	writefile(OUT + '.tmp', sprintf("%.J\n", o));
	system(`mv -f ${sq(OUT + '.tmp')} ${sq(OUT)}`);
}

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function note(res, msg) {
	if (res.notes == null)
		res.notes = [];
	push(res.notes, msg);
}

/* The resource's OWN deep verdict (page/CDN/edge/stream, differential-only
 * — the fuzzer filters probe items identical across all deep-tested
 * strategies). null = the strategy was not deep-tested for this resource;
 * a 0..1 ratio otherwise. (The old ranking used the GLOBAL deep ratio —
 * other resources' hosts diluted the verdict of THIS resource.) */
function deep_ratio_of(s, tag) {
	if (s.deep == null || type(s.deep) !== 'object' || type(s.deep.hosts) !== 'array')
		return null;
	for (let h in s.deep.hosts)
		if (type(h) === 'object' && h.tag === tag && int(h.deep_total || 0) > 0)
			return (int(h.deep_pass || 0) * 1.0) / int(h.deep_total);
	return null;
}

/* Rule state for the source (honest reporting only — never edited here).
 * cursor.foreach is the working enumeration (cursor.get with a TYPE answers
 * null in this ucode-uci build — caught live; cursor has no length()). */
function rule_state(src) {
	const c = cursor();
	let found = null;
	c.foreach('homeproxy', 'proxy_ru_rule', (s) => {
		if (found == null && s.source === src && s.enabled === '1')
			found = { source: src, node: s.node || '' };
	});
	return (found != null) ? found : { source: src, node: null };
}

/* Router-originated HTTPS probe (the scanner's live-probe method): rides
 * the app's own output interception, so the resource is served exactly the
 * way LAN clients are served. Returns {code, tsec, rc, ok}. */
function probe_live(url, host) {
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
		`--connect-timeout 4 --max-time ${VERIFY_TMO} ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, VERIFY_TMO * 1000 + 3000);
	const parts = split(trim(readfile(cf) || ''), /[[:space:]]+/);
	const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
	const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
	const ok = (rc === 0 && int(code) >= 200 && int(code) < 400);
	return { code: code, tsec: tsec, rc: rc, ok: ok, host: host };
}

/* Rough seconds-to-finish estimate from a live fuzz status: resolve+baseline
 * (~60 s) + unmeasured strategies × rounds × ~55 s (the 70 s per-pass
 * watchdog is the worst case, typical passes are faster) + the deep battery
 * tail (~8 runs × 75 s worst case). ч.123: the pick no longer caps at a
 * fixed 45 min — a full sweep honestly takes up to a few hours, so the wait
 * extends to the sweep's own estimate while it keeps making progress. */
function fuzz_remaining_est(st) {
	if (st == null || int(st.total || 0) <= 0)
		return 0;
	const done = int(st.done || 0);
	const rem = int(st.total) - done;
	if (rem <= 0)
		return 700;   /* the deep battery tail */
	return 60 + rem * int(st.rounds || 2) * 55 + 600;
}

/* Wait until the fuzz is no longer running (status file says so); the
 * result file is written just before the status flips to false.
 * ч.123: returns a VERDICT object instead of a bare result:
 *   { fz: result }                     — the sweep finished, ranking ready;
 *   { fail: 'stale'|'empty'|'timeout', error: <honest message> }.
 * A stale running:true (the writer died) breaks out after FUZZ_DEAD instead
 * of hanging to the cap; the wait extends past the 45-min floor to the
 * sweep's own remaining estimate (a full sweep takes hours). */
function wait_fuzz(deadline) {
	let sized = false;
	while (time() < deadline) {
		const st = read_json(FUZZ_STATUS);
		if (st && st.running && (time() - int(st.ts || 0)) > FUZZ_DEAD)
			return { fail: 'stale', error: 'процесс фаззинга умер посреди прогона (нет обновлений статуса 15+ мин) — запустите его снова из Лаборатории стратегий' };
		if (st == null || !st.running) {
			const r = read_json(FUZZ_RESULT);
			if (r && r.strategies && length(r.strategies))
				return { fz: r };
			if (st == null) {
				sleep(2000);
				continue;
			}
			if (st.error != null && length('' + st.error))
				return { fail: 'empty', error: 'фаззинг завершился с ошибкой: ' + st.error };
			return { fail: 'empty', error: 'фаззинг завершился без результата (и без ошибки) — запустите его снова из Лаборатории стратегий' };
		}
		if (!sized && int(st.total || 0) > 0) {
			sized = true;
			const rem = fuzz_remaining_est(st) + 300;
			if (rem > (deadline - time()))
				deadline = time() + rem;
		}
		sleep(10000);
	}
	let prog = '';
	const stx = read_json(FUZZ_STATUS);
	if (stx && stx.current)
		prog = ' (' + stx.current + ')';
	return { fail: 'timeout',
		error: 'фаззинг всё ещё идёт' + prog + ' — подбор перестал ждать; рейтинг появится в Лаборатории стратегий, когда прогон завершится' };
}

function fuzz_fail(res, msg) {
	res.running = false;
	res.stage = 'error';
	res.error = msg || 'фаззинг не успел завершиться вовремя';
	wstat(res);
}

/* After WE spawn a fuzz, wait until the status/result is owned by the NEW
 * run (its ts is not older than our spawn moment): the old files must not
 * be mistaken for the fresh ranking (race caught live — the first
 * wait_fuzz iteration ran before the new sweep rewrote the status). */
function wait_fuzz_owner(t_start) {
	while (time() < t_start + 120) {
		const sx = read_json(FUZZ_STATUS);
		if (sx && int(sx.ts || 0) >= t_start - 2)
			return true;
		const rx = read_json(FUZZ_RESULT);
		if (rx && int(rx.ts || 0) >= t_start - 2)
			return true;
		sleep(1000);
	}
	return false;
}

function main() {
	const req = read_json(REQ);
	const meta = RESOURCES[req && req.resource];
	if (meta == null) {
		wstat({ running: false, stage: 'error', error: 'неизвестный ресурс' });
		return;
	}
	const resource = req.resource;
	const mode = (req.mode === 'full') ? 'full' : 'quick';
	const res = {
		running: true, stage: 'started', resource: resource, mode: mode,
		rule: rule_state(resource), chosen: null, verify: null, notes: []
	};
	wstat(res);

	if (!access(NFQWS)) {
		res.running = false; res.stage = 'error';
		res.error = 'zapret2 не установлен';
		wstat(res);
		return;
	}

	/* 1. FUZZ — fresh result / wait for a running sweep / start one.
	 * ч.109: when the request carries an explicit strategy (the
	 * «apply from the ranking table» flow), stages 1–2 are skipped —
	 * the table already ranked it; only rule+apply+verify run. */
	res.stage = 'fuzz';
	wstat(res);
	const fixed = (req.strategy != null && length(trim('' + req.strategy)));
	let fz = null;
	if (!fixed) {
		fz = read_json(FUZZ_RESULT);
		const st = read_json(FUZZ_STATUS);
		const fresh = (fz && fz.strategies && length(fz.strategies) &&
			(fz.ts && (time() - int(fz.ts)) < FUZZ_FRESH));
		const running = (st && st.running);
		if (running) {
			note(res, 'Прогон фаззинга уже идёт — жду его завершения…');
			wstat(res);
			const w = wait_fuzz(time() + FUZZ_WAIT_MAX);
			if (w.fz == null) {
				fuzz_fail(res, w.error);
				return;
			}
			fz = w.fz;
		} else if (!fresh) {
			note(res, 'Запускаю ' + ((mode === 'full') ? 'полный' : 'быстрый') +
				' фаззинг (прошлого рейтинга нет или он старше 6 ч)…');
			wstat(res);
			const t0 = time();
			system(`sh /etc/homeproxy/scripts/zapret_fuzz.sh ${mode} 2 >/dev/null 2>&1 &`);
			if (!wait_fuzz_owner(t0)) {
				fuzz_fail(res, 'фаззинг не стартовал вовремя — проверьте статус в Лаборатории стратегий');
				return;
			}
			const w = wait_fuzz(time() + FUZZ_WAIT_MAX);
			if (w.fz == null) {
				fuzz_fail(res, w.error);
				return;
			}
			fz = w.fz;
		} else {
			note(res, 'Использую существующий рейтинг фаззинга (моложе 6 ч).');
		}

		/* 2. PICK — resource-tag ranking (majority pass, non-free-pass host). */
		res.stage = 'pick';
		wstat(res);
		let chosen = null;
		let chosen_deep = null;
		let chosen_deep_pass = null;
		let chosen_deep_total = null;
		let chosen_stream = 0;
		let chosen_start = 0;
		const runners = [];
		if (meta.tag == null) {
			/* general: the global ranking head (score order already encodes
			 * distinguishing successes minus handshake cost). */
			for (let s in fz.strategies) {
				if (s.ok > 0) { chosen = s; break; }
			}
	} else {
		const elig = [];
		for (let s in fz.strategies) {
			let h = null;
			for (let x in s.hosts)
				if (x.tag === meta.tag) { h = x; break; }
			if (h && h.ok && h.dist) {
				const dr = deep_ratio_of(s, meta.tag);
				let dp = null, dt = null, stm = 0, stms = 0;
				if (s.deep && type(s.deep.hosts) === 'array')
					for (let dh in s.deep.hosts)
						if (type(dh) === 'object' && dh.tag === meta.tag) {
							if (int(dh.deep_total || 0) > 0) {
								dp = int(dh.deep_pass || 0);
								dt = int(dh.deep_total);
							}
							stm = int(dh.stream || 0);
							stms = int(dh.start_ms || 0);
						}
				push(elig, { s: s, ms: int(h.tls_ms) || 0, deep: dr,
					deep_pass: dp, deep_total: dt, stream: stm, start: stms });
			}
		}
		/* ч.116 ranking: a MEASURED strategy ranks first — the resource's own
		 * deep verdict or the sustained video flow speed (the TLS handshake
		 * time does not predict the throttled flow — the live ч.116
		 * comparison: Multisplit 306 KB/s vs Syndata 555 KB/s at a 3 ms
		 * handshake difference). deep-failed ranks last. When the
		 * differential deep totals zero out (every probe identical across
		 * the deep-tested strategies — the ч.110 live fact), the stream
		 * measurement still separates the tested strategies from the
		 * untested ones.
		 * ч.129: the fresh-connection START latency (the hover-preview
		 * metric, «навожу на карточку — превью не стартует») is what the
		 * user FEELS first — a >25% better START wins outright; a smaller
		 * gap is bursty TSPU noise (tie). The sustained flow decides next
		 * at a >10% gap, then the handshake. */
		const band = (e) => (((e.deep != null) && (e.deep > 0)) ||
			((e.deep == null) && (int(e.stream || 0) > 0))) ? 0
			: (((e.deep != null) && (e.deep == 0)) ? 2 : 1);
		sort(elig, (a, b) => {
			const ba = band(a), bb = band(b);
			if (ba != bb)
				return ba - bb;
			const da = (a.deep == null) ? -1 : a.deep;
			const db_ = (b.deep == null) ? -1 : b.deep;
			if (da != db_)
				return db_ - da;
			const ta = int(a.start || 0), tb = int(b.start || 0);
			if (ta > 0 && tb > 0 && ta != tb) {
				const hi = (ta > tb) ? ta : tb, lo = (ta > tb) ? tb : ta;
				if (hi - lo > int(hi / 4))
					return ta - tb;
			}
			const sa = int(a.stream || 0), sb = int(b.stream || 0);
			if (sa != sb) {
				if (sa > 0 && sb > 0) {
					const hi = (sa > sb) ? sa : sb, lo = (sa > sb) ? sb : sa;
					if (hi - lo > int(hi / 10))
						return sb - sa;
				} else if (sa > 0 || sb > 0)
					return sb - sa;
			}
			return (a.ms - b.ms) || (b.s.score - a.s.score);
		});
		if (length(elig)) {
			chosen = elig[0].s;
			chosen_deep = elig[0].deep;
			chosen_deep_pass = elig[0].deep_pass;
			chosen_deep_total = elig[0].deep_total;
			chosen_stream = elig[0].stream;
			chosen_start = elig[0].start;
			for (let i = 1; i < length(elig) && i <= 3; i++)
				push(runners, elig[i].s.name + ' (' + elig[i].ms + ' ms)');
		}
	}
		if (chosen == null) {
			res.running = false; res.stage = 'error';
			res.error = (meta.tag == null)
				? 'ни одна стратегия не прошла различающие хосты'
				: 'ни одна стратегия корпуса не прошла проверку ресурса — попробуйте полный фаззинг или генератор стратегий';
			wstat(res);
			return;
		}
		if (chosen.args && (match(chosen.args, /[`$;&|<>\n]/) || !match(chosen.args, /^--[a-z]/))) {
			res.running = false; res.stage = 'error';
			res.error = 'у стратегии-победителя неожиданный формат — по соображениям безопасности отказано';
			wstat(res);
			return;
		}
		res.chosen = {
			name: chosen.name || '', args: chosen.args || '',
			score: int(chosen.score) || 0, avg_tls_ms: int(chosen.avg_tls_ms) || 0,
			stream: int(chosen_stream || 0), start_ms: int(chosen_start || 0),
			runners: runners
		};
		/* ч.116: the resource's own deep verdict (pass/total of THIS
		 * resource's probes), not the global mix across all resources. */
		if (chosen_deep_total != null && int(chosen_deep_total) > 0)
			res.chosen.deep = { ok: int(chosen_deep_pass || 0), total: int(chosen_deep_total) };
		/* QUIC honesty (ч.123, measured): the sweep-level probe_pool
		 * -quic-check verdict says whether UDP/443 passes the provider AT
		 * ALL. A TCP-only strategy never touches the browser's QUIC
		 * attempts: an OPEN path leaves them riding raw (the browser may
		 * pick QUIC for some videos and TCP for others — the per-video
		 * variance the user reported); a CUT path makes the fallback quick,
		 * so a TCP-only strategy is fine there. */
		if (meta.tag === 'yt' && !match('' + (chosen.args || ''), /--filter-udp=443/)) {
			const qv = (fz != null && fz.quic != null) ? ('' + (fz.quic.verdict || '')) : '';
			if (qv === 'vn')
				note(res, 'QUIC (UDP 443) до YouTube у провайдера ОТКРЫТ (измерено в этом прогоне) — стратегия работает только с TCP, поэтому QUIC-попытки браузера идут без дезинка. Если часть видео грузится медленно, а часть летает, возьмите стратегию с fake QUIC (в Лаборатории они помечены QUIC).');
			else if (qv === 'silence' || qv === 'icmp')
				note(res, 'QUIC (UDP 443) до YouTube у провайдера отрезан (измерено в этом прогоне: ' + qv + ') — браузер быстро падает на TCP, поэтому TCP-стратегия обслуживает весь ресурс.');
			else
				note(res, 'Стратегия работает только с TCP (без блока QUIC/UDP) — если видео всё же тормозит при проходящих проверках, попробуйте стратегию с блоком QUIC (fake QUIC) или не отключайте UDP 443 для YouTube.');
		}
	} else {
		/* ч.109: explicit strategy from the ranking table — resolve its
		 * catalog name for the report, then apply as usual. */
		const args = trim('' + req.strategy);
		if (match(args, /[`$;&|<>\n]/) || !match(args, /^--[a-z]/)) {
			res.running = false; res.stage = 'error';
			res.error = 'у стратегии неожиданный формат — по соображениям безопасности отказано';
			wstat(res);
			return;
		}
		res.chosen = { name: '', args: args, score: 0, avg_tls_ms: 0, stream: 0, start_ms: 0, runners: [] };
		const corpus = read_json('/etc/homeproxy/zapret_candidates.json');
		if (corpus && type(corpus.candidates) == 'array') {
			for (let c in corpus.candidates)
				if (type(c) == 'object' && c.args === args) {
					res.chosen.name = '' + (c.name || '');
					break;
				}
		}
		/* ч.116: carry the ranking's measured sustained-flow speed into the
		 * manual pick (the daemon margin and the honest report use it).
		 * ч.127: the START latency (the hover-preview metric) rides along. */
		const fzr = read_json(FUZZ_RESULT);
		if (fzr != null && type(fzr.strategies) === 'array')
			for (let s in fzr.strategies)
				if (type(s) === 'object' && s.args === args &&
					type(s.deep) === 'object' && type(s.deep.hosts) === 'array')
					for (let dh in s.deep.hosts)
						if (type(dh) === 'object' && dh.tag === RESOURCES[resource].tag) {
							res.chosen.stream = int(dh.stream || 0);
							res.chosen.start_ms = int(dh.start_ms || 0);
						}
	}
	if (!fixed) {
		note(res, 'Выбрана: ' + (res.chosen.name || 'кастомные аргументы') +
			((res.chosen.avg_tls_ms > 0) ? (' · средний TLS ' + res.chosen.avg_tls_ms + ' мс') : '') +
			((res.chosen.deep && res.chosen.deep.total)
				? (' · deep ' + res.chosen.deep.ok + '/' + res.chosen.deep.total)
				: '') +
			((int(res.chosen.stream || 0) > 0)
				? (' · видео-поток ' + int(res.chosen.stream / 1024) + ' КБ/с')
				: '') +
			((int(res.chosen.start_ms || 0) > 0)
				? (' · старт ' + int(res.chosen.start_ms) + ' мс')
				: ''));
	} else {
		note(res, 'Применяю выбранную вами стратегию: ' + (res.chosen.name || 'кастомные аргументы') + '.');
	}

	/* 3. RULE — through the existing preset RPC (single guard set). */
	if (req.set_rule === true && resource !== 'general') {
		/* urltest_nodes crosses as a JSON-encoded STRING: a string typehint is
		 * the only rpcd-args policy that works on old AND strict new rpcd
		 * (GitHub issue #11 — native [] crashed registration on updated
		 * 25.12 stacks). */
		const payload = sprintf('{"source":%.J,"node":"zapret-out","urltest_nodes":"[]"}', resource);
		const fd = popen(`ubus call luci.homeproxy wizard_preset_apply ${sq(payload)} 2>/dev/null`);
		let out = '';
		if (fd) { out = trim(fd.read('all') || ''); fd.close(); }
		let pr = null;
		try { pr = json(out || ''); } catch (e) { pr = null; }
		if (pr && pr.result) {
			res.rule = { source: resource, node: 'zapret-out' };
			note(res, 'Правило установлено: ' + resource + ' → Zapret.');
		} else {
			note(res, 'Правило НЕ изменено: ' + ((pr && pr.error) || 'применение пресета не удалось') +
				' — стратегия всё равно применяется (без своего правила она может не обслуживать ресурс).');
		}
	}

	/* 4. APPLY — server snapshot first (same file Restore reads), then
	 * write through the uci module (no shell metachar risk) and restart.
	 * ч.116: a TARGETED apply (a resource was picked in the Lab / by the
	 * auto-pick) builds a SCOPED composition through the EXISTING
	 * wizard_compose_build (the per-resource --hostlist-domains block +
	 * the other managed resources' strategies kept + the general tail) —
	 * the old code wrote the strategy GLOBALLY, so «применить для
	 * YouTube» молча меняло то, чем обслуживается Discord. For 'general'
	 * the global write stays (that IS the general strategy). */
	res.stage = 'apply';
	wstat(res);
	const c = cursor();
	const snap = {
		ts: time(),
		zapret: {
			cmd_opts: '' + (c.get('homeproxy', 'config', 'zapret_cmd_opts') || ''),
			enabled: (c.get('homeproxy', 'config', 'zapret_enabled') === '1')
		},
		byedpi: {
			cmd_opts: '' + (c.get('homeproxy', 'config', 'byedpi_cmd_opts') || ''),
			enabled: (c.get('homeproxy', 'config', 'byedpi_enabled') === '1')
		}
	};
	system('mkdir -p /etc/homeproxy/backups');
	writefile(BAK + '.tmp', sprintf("%.J\n", snap));
	system(`mv -f ${sq(BAK + '.tmp')} ${sq(BAK)}`);
	let final_args = res.chosen.args;
	if (resource !== 'general') {
		const profiles = [];
		push(profiles, { engine: 'zapret', resource: resource, strategy: res.chosen.args });
		/* Other managed resources keep their own scoped strategies (the
		 * auto-pilot winners when the daemon runs); without it the general
		 * tail below would serve them with THIS strategy again. */
		const ap = read_json(RUN_DIR + '/zapret_autopilot.json');
		const others = {};
		if (ap != null && type(ap.resources) === 'object') {
			for (let rk in ['youtube', 'discord', 'telegram']) {
				if (rk === resource)
					continue;
				const rr = ap.resources[rk];
				if (type(rr) === 'object' && rr.mgmt && type(rr.winner) === 'object' &&
					rr.winner.args != null && length('' + rr.winner.args))
					others[rk] = '' + rr.winner.args;
			}
		}
		/* The general tail: the auto-pilot's general winner, else the
		 * CURRENT strategy — when the current one is a COMPOSITION (contains
		 * --new), adopt only its catch-all TAIL (the last block): a whole
		 * composition as one profile breaks the builder's per-profile cap
		 * (caught live ч.116: 'strategy longer than 2000 chars'). The
		 * composition's scoped blocks are re-emitted from the winners above. */
		let tail = '';
		if (ap != null && type(ap.resources) === 'object' &&
			type(ap.resources.general) === 'object' &&
			type(ap.resources.general.winner) === 'object' &&
			ap.resources.general.winner.args != null)
			tail = '' + ap.resources.general.winner.args;
		else
			tail = '' + (c.get('homeproxy', 'config', 'zapret_cmd_opts') || '');
		if (index(tail, '--new') >= 0) {
			const parts_ = split(tail, '--new');
			tail = trim(parts_[length(parts_) - 1] || '');
		}
		if (length(tail) > 2000) {
			note(res, 'Общий хвост отброшен (длиннее лимита профиля) — трафик вне сценарных ресурсов идёт без дезинка.');
			tail = '';
		}
		for (let rk in keys(others))
			push(profiles, { engine: 'zapret', resource: rk, strategy: others[rk] });
		if (length(tail))
			push(profiles, { engine: 'zapret', resource: 'general', strategy: tail });
		/* max 5 zapret profiles here (target + 3 resources + general tail) —
		 * under the builder's 8-profile cap by construction. */
		/* profiles cross as a JSON-encoded STRING (issue #11): %.J of the
		 * JSON text embeds it as a quoted JSON string. */
		const pj = sprintf('%.J', profiles);
		const payload = sprintf('{"profiles":%.J}', pj);
		const fd = popen(`ubus call luci.homeproxy wizard_compose_build ${sq(payload)} 2>/dev/null`);
		let cout = '';
		if (fd) { cout = trim(fd.read('all') || ''); fd.close(); }
		let pr = null;
		try { pr = json(cout || ''); } catch (e) { pr = null; }
		if (pr && pr.result && length('' + (pr.zapret || ''))) {
			final_args = '' + pr.zapret;
			for (let n in (pr.notes || []))
				note(res, 'Конструктор: ' + n);
			note(res, 'Стратегия применена как СЦЕНАРНЫЙ профиль для ' + resource +
				' (другие управляемые ресурсы сохраняют свои стратегии; общий профиль обслуживает остальное).');
		} else {
			res.running = false; res.stage = 'error';
			res.error = 'не удалось собрать сценарную композицию: ' +
				((pr && pr.error) || 'сборка композиции не удалась');
			wstat(res);
			return;
		}
	}
	c.set('homeproxy', 'config', 'zapret_cmd_opts', final_args);
	c.set('homeproxy', 'config', 'zapret_enabled', '1');
	c.commit('homeproxy');
	/* ч.116: hand the manual pick to the auto-pilot daemon — on its next
	 * tick the daemon adopts it as the resource winner (a manual choice
	 * must not be overwritten by the next re-rank before the daemon even
	 * sees it). Written only while the daemon is enabled; consumed there. */
	if (resource !== 'general' &&
		(c.get('homeproxy', 'autopilot', 'enabled') === '1')) {
		const man = { ts: time(), resources: {} };
		man.resources[resource] = { name: res.chosen.name, args: res.chosen.args,
			stream: int(res.chosen.stream || 0), start_ms: int(res.chosen.start_ms || 0) };
		const manp = RUN_DIR + '/zapret_autopilot_manual.json';
		writefile(manp + '.tmp', sprintf("%.J\n", man));
		system(`mv -f ${sq(manp + '.tmp')} ${sq(manp)}`);
	}
	/* Light apply when the zapret instance already runs: the launcher
	 * (dpi_engine.sh) re-reads UCI on the procd respawn, so the strategy
	 * swap is a kill — the core keeps running and tunneled sessions (the
	 * user report: a Minecraft session) are NOT kicked by an auto-pick.
	 * The verify stage below polls the CORE pid; with the light path the
	 * core never disappears, so `seen` fills in immediately. */
	const zq = '' + (c.get('homeproxy', 'config', 'zapret_qnum') || '200');
	const z_alive = system(`ps w | grep '[n]fqws2' | grep -q "qnum=${zq}"`) === 0;
	if (z_alive) {
		system('/etc/init.d/homeproxy engine_restart >/dev/null 2>&1 &');
		note(res, 'Стратегия применена с лёгким рестартом движка (ядро не перезапускается).');
	} else {
		system('/etc/init.d/homeproxy restart >/dev/null 2>&1 &');
		note(res, 'Стратегия применена — служба перезапускается.');
	}

	/* 5. VERIFY — wait for the core, then the configured-path probe. */
	res.stage = 'verify';
	wstat(res);
	let seen = 0;
	const t0 = time();
	if (!z_alive) {
		while ((time() - t0) < CORE_WAIT_MAX) {
			sleep(5000);
			const fd = popen('pidof hiddify-core 2>/dev/null');
			let pid = '';
			if (fd) { pid = trim(fd.read('all') || ''); fd.close(); }
			if (length(pid)) {
				seen++;
				if (seen >= 2) break;
			} else {
				seen = 0;
			}
		}
		if (seen < 2)
			note(res, 'Ядро не вернулось за 90 с — проверьте его на странице Обзора.');
		sleep(3000);
	} else {
		/* Light path: the core never went away — give the engine respawn (~1 s)
		 * and the firewall re-render a moment, then verify. */
		sleep(5000);
	}
	res.verify = (resource === 'general')
		? probe_live('http://www.gstatic.com/generate_204', 'gstatic generate_204')
		: probe_live('https://' + meta.host, meta.host);
	/* ч.109: the deep battery — a resource works when ALL its hosts answer
	 * through the configured path (YouTube: page + thumbnail CDN + video edge). */
	res.verify_multi = [];
	const urls = (meta.deep && length(meta.deep)) ? meta.deep
		: [ (resource === 'general') ? 'http://www.gstatic.com/generate_204' : ('https://' + meta.host) ];
	let deep_ok = 0;
	/* for-in over an array yields the ELEMENTS (lesson 20/31) — url IS the
	 * URL string, `urls[url]` would be undefined. */
	for (let url in urls) {
		let pr = probe_live(url, url);
		/* one retry: right after the engine respawn a probe can flake
		 * (DNS/DAD moment) — an honest verdict must not hinge on that. */
		if (!pr.ok) {
			sleep(2000);
			pr = probe_live(url, url);
		}
		/* the video-stream edge: ANY HTTP answer = the DPI let it through */
		if (index('' + url, 'redirector.googlevideo.com') >= 0)
			pr.ok = (pr.code != '000' && pr.rc == 0);
		push(res.verify_multi, pr);
		if (pr.ok) deep_ok++;
	}
	/* ч.116: the SUSTAINED-FLOW throughput probe (the LIVE path — the way
	 * LAN clients are served). A 200 on the tiny edge 404 does not exclude
	 * TSPU throttling of the flow — 24 real thumbnails over ONE keep-alive
	 * TLS flow, measured in bytes/s, do. */
	if (resource === 'youtube') {
		const ff = RUN_DIR + '/wiz_probe_flow.json';
		system(`sh /etc/homeproxy/scripts/yt_flow_probe.sh > ${sq(ff)} 2>/dev/null`, 30000);
		const fj = read_json(ff);
		system(`rm -f ${sq(ff)} 2>/dev/null`);
		if (fj != null && type(fj) === 'object' && fj.code != null) {
			const fok = (fj.ok == 1);
			push(res.verify_multi, { url: '(поток видео)', host: 'поток видео (24 миниатюры / один TLS-поток)',
				code: '' + (fj.code || '0'), tsec: (fj.secs != null) ? ('' + fj.secs) : null,
				bytes: int(fj.bytes || 0), speed: int(fj.speed || 0), ok: fok });
			if (fok) deep_ok++;
		} else {
			note(res, 'Проба sustained-потока не выполнялась (нет файла с id).');
		}
		/* the REAL video stream when the upstream hands out a URL (often
		 * bot-gated — then honestly absent). */
		let yj = read_json(RUN_DIR + '/yt_stream.json');
		if (yj == null || type(yj) !== 'object' || !yj.ok || !yj.url ||
			(time() - int(yj.ts || 0)) > YT_STREAM_TTL) {
			system(`ucode /etc/homeproxy/scripts/yt_stream_probe.uc get >/dev/null 2>&1`);
			yj = read_json(RUN_DIR + '/yt_stream.json');
		}
		if (yj != null && type(yj) === 'object' && yj.ok && yj.url &&
			index('' + yj.url, "'") < 0) {
			const sf = RUN_DIR + '/wiz_probe.stream';
			system(`rm -f ${sq(sf)} 2>/dev/null`);
			const cmd = `curl -s -r 0-4194303 -o /dev/null ` +
				`-w '%{http_code} %{time_total} %{size_download} %{speed_download}' ` +
				`--connect-timeout 4 --max-time 9 ${sq('' + yj.url)} > ${sq(sf)} 2>/dev/null`;
			const rc = system(cmd, 12000);
			const parts = split(trim(readfile(sf) || ''), /[[:space:]]+/);
			const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
			const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
			const bytes = (length(parts) > 2) ? int(parts[2]) : 0;
			const speed = (length(parts) > 3) ? int(parts[3]) : 0;
			const sok = (rc === 0 && (code === '200' || code === '206') &&
				speed >= YT_STREAM_MIN_SPEED && bytes >= YT_STREAM_MIN_BYTES);
			push(res.verify_multi, { url: '(реальный видеопоток)', host: 'реальный видеопоток (googlevideo)',
				code: code, tsec: tsec, bytes: bytes, speed: speed, ok: sok });
			if (sok) deep_ok++;
		}
	}
	res.verify.deep_ok = deep_ok;
	res.verify.deep_total = length(res.verify_multi);
	if (res.verify.ok && deep_ok == length(res.verify_multi))
		note(res, 'Живая проверка: ' + res.verify.host + ' → ' + res.verify.code +
			((res.verify.tsec != null) ? (' за ' + res.verify.tsec + ' с') : '') +
			' — отвечают все ' + length(res.verify_multi) + ' хостов ресурса' +
			((resource === 'youtube') ? ' (включая реальный видеопоток)' : '') + '.');
	else if (res.verify.ok)
		note(res, 'Живая проверка: главный хост отвечает (' + res.verify.code + '), но ' +
			(length(res.verify_multi) - deep_ok) + ' из ' + length(res.verify_multi) +
			' хостов ресурса НЕ отвечают — ресурс НЕ работает целиком (застряли медиа/CDN или видеопоток режется). Возьмите другую стратегию или полный фаззинг.');
	else
		note(res, 'Живая проверка ПРОВАЛЕНА (' + res.verify.code + ') — правило/режим может не вести ресурс через Zapret, либо стратегия не держит реальный трафик. Возврат остаётся доступен.');

	res.running = false;
	res.stage = 'done';
	wstat(res);
	system(`rm -f ${sq(REQ)}`);
}

main();
