#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex — Service Profile battery runner (Ф6.3).
 *
 * One-shot background prober spawned by the RPC wizard_service_profile_run.
 * Executes the battery of ONE service profile (or all four) over the LIVE
 * path — the same way LAN clients are served — and classifies every
 * component through the Diagnostic Core (diag_core.uc, Ф6.1):
 *
 *   http  — router-originated HTTPS (classify_path + judge_http);
 *   ws    — Discord gateway checked AS a WebSocket (Upgrade headers,
 *           101 Switching Protocols = gateway alive; audit 74);
 *   video — real googlevideo ranged download, level judged
 *           bitrate-RELATIVE (unusable→excellent, audit 79) — not the
 *           fixed 128 KiB/s bar;
 *   tcp   — Telegram MTProto DC transport (time_connect > 0 is the ONLY
 *           proof of a completed handshake: rc 28 is ambiguous);
 *   stun  — Discord Voice UDP path through a real STUN binding request
 *           when nc -u exists; honest unprobed otherwise (audit 60/91);
 *   quic_passive — passive observation of UDP/443 flows through the
 *           Discovery Engine — active HTTP/3 probes stay OFF (§2.5).
 *
 * Differential cause (Ф6.1): a component that is broken/refused gets ONE
 * direct + ONE proxy probe of the same host and diag_cause() computes the
 * unified cause {type, confidence, evidence[]} — the same taxonomy as the
 * provider scan. Budget: base battery ≤16 probes (lesson 197), the
 * differential adds ≤2 per failing component, hard cap +8.
 *
 * Status  → /var/run/homeproxy/service_profile.json         {running,done,total,current}
 * Result  → /var/run/homeproxy/service_profile_result.json  {ts, profile, components[…], summary}
 * Task    → /var/run/homeproxy/service_profile_task.txt     (one profile name, written by the RPC)
 * All writes atomic (statestore.atomic_write): a truncated JSON would
 * surface as "—" in the UI (automation.atomic_write constraint).
 *
 * ucode constraints honored: no typeof (type()), match() with /regex/
 * literals only, for-in over arrays yields ELEMENTS, push()/sort()/keys()
 * are GLOBAL functions, json() is a global builtin, sleep() in ms,
 * no function hoisting (helpers before first call), ARGV unreliable on
 * this platform (task comes from a file).
 */

'use strict';

import { access, readfile, writefile, popen } from 'fs';
import { atomic_write } from '/etc/homeproxy/scripts/statestore.uc';
import { classify_path, diag_cause, code_class } from '/etc/homeproxy/scripts/diag_core.uc';
import {
	PROFILES, PROFILE_KEYS, judge_http, judge_video, judge_ws, judge_tcp,
	judge_stun, judge_quic
} from '/etc/homeproxy/scripts/service_profiles.uc';
import { conntrack_flows, clash_conns } from '/etc/homeproxy/scripts/discovery.uc';

const RUN_DIR = '/var/run/homeproxy';
const STATUS = RUN_DIR + '/service_profile.json';
const RESULT = RUN_DIR + '/service_profile_result.json';
const TASK = RUN_DIR + '/service_profile_task.txt';

const DIRECT_PORT = 5336;   /* auto-direct-in → direct-out (pinned) */
const PROXY_PORT  = 5337;   /* auto-proxy-in  → main-out   (pinned) */
const LIVE_TMO    = 9;
const DIFF_TMO    = 8;
const DIFF_CAP    = 8;      /* hard cap of extra differential probes */

/* ── Small helpers (NO hoisting) ── */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function write_status(obj) {
	obj.ts = time();
	atomic_write(STATUS, sprintf('%.J', obj) + '\n');
}

function parse_cwt(out) {
	const parts = split(trim(out || ''), /[[:space:]]+/);
	const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
	const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
	const third = (length(parts) > 2) ? ('' + parts[2]) : null;
	return { code: code, tsec: tsec, third: third };
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

/* Plain public resolver answer (for pinning the direct-side differential
 * probe — the same discipline as the provider scanner). */
function resolve_plain(host) {
	for (let srv in [ '8.8.8.8', '1.1.1.1', '77.88.8.8' ]) {
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

/* LIVE probe: router-originated HTTPS — rides the app's own output
 * interception (configured rules, learned lists, engine desync). */
function probe_live(url) {
	const bf = RUN_DIR + '/sp_probe.body';
	const cf = RUN_DIR + '/sp_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
		`--connect-timeout 4 --max-time ${LIVE_TMO} ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, LIVE_TMO * 1000 + 3000);
	const cwt = parse_cwt(readfile(cf));
	const body = readfile(bf) || '';
	return classify_path({ code: cwt.code, tsec: cwt.tsec, rc: rc, body: body }, false, null);
}

/* Pinned-path probe for the differential (direct/proxy). */
function probe_via(url, port, socks_h, pin_host, pin_ip) {
	const px = `socks5${socks_h ? 'h' : ''}://127.0.0.1:${port}`;
	const pin = (!socks_h && pin_host && pin_ip) ?
		` --resolve ${sq(pin_host + ':443:' + pin_ip)}` : '';
	const bf = RUN_DIR + '/sp_probe.body';
	const cf = RUN_DIR + '/sp_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
		`--connect-timeout 4 --max-time ${DIFF_TMO} -x ${px}${pin} ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, DIFF_TMO * 1000 + 3000);
	const cwt = parse_cwt(readfile(cf));
	const body = readfile(bf) || '';
	return classify_path({ code: cwt.code, tsec: cwt.tsec, rc: rc, body: body }, !!pin, null);
}

/* WebSocket Upgrade probe (audit 74): the gateway is verified AS a WS —
 * a plain HTTPS GET would lie. 101 Switching Protocols proves the gateway
 * speaks WebSocket through this path. */
function probe_ws(url) {
	const cf = RUN_DIR + '/sp_probe.code';
	system(`rm -f ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -s -o /dev/null -w '%{http_code} %{time_total}' --connect-timeout 4 --max-time 6 ` +
		`-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' ` +
		`-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, 6 * 1000 + 3000);
	const cwt = parse_cwt(readfile(cf));
	/* 101 нормализуется в 200-форму с rc=0: classify_path иначе трактовал бы
	 * висящее WS-соединение (rc 28 = max-time на открытом сокете) как обрыв
	 * посреди цепочки. Сырой код сохраняется для judge_ws. */
	const is_101 = (cwt.code === '101');
	const path = classify_path({ code: is_101 ? '200' : cwt.code,
		tsec: cwt.tsec, rc: is_101 ? 0 : rc, body: is_101 ? 'websocket upgrade confirmed' : '' },
		false, null);
	return { path: path, raw_code: cwt.code };
}

/* TCP-connect probe (Telegram MTProto DC): telnet:// connects raw TCP.
 * The only proof of a completed handshake is time_connect > 0 — a connect
 * timeout AND an idle timeout both exit 28. */
function probe_tcp(host, port) {
	const cf = RUN_DIR + '/sp_probe.code';
	system(`rm -f ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -s -o /dev/null -w '%{time_connect}' --connect-timeout 3 --max-time 4 ` +
		`${sq('telnet://' + host + ':' + port)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, 4 * 1000 + 3000);
	const out = trim(readfile(cf) || '');
	let tcon = 0;
	const m = match(out, /^([0-9]*\.[0-9]+|[0-9]+)$/);
	if (m)
		tcon = m[1] + 0.0;
	return { rc: rc, tcon: tcon };
}

/* STUN binding probe through a real UDP datagram (audit 60). Busybox nc -u
 * availability is probed with a harmless datagram to the router itself; an
 * unsupported -u gives the usage text. The binding REQUEST is a fixed
 * 20-byte message (type 0x0001, zero length, magic cookie, txid). */
function probe_stun(host, port) {
	const chk = popen(`printf '' | nc -u -w 1 127.0.0.1 5330 2>&1 | head -c 200`);
	let usage = '';
	if (chk) {
		usage = lc(chk.read('all') || '');
		chk.close();
	}
	if (index(usage, 'usage') >= 0 || index(usage, 'invalid option') >= 0)
		return { probed: false, ok: false };
	const req = '\\x00\\x01\\x00\\x00\\x21\\x12\\xa4\\x42\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c';
	const fd = popen(`printf '${req}' | nc -u -w 3 ${sq(host)} ${int(port)} 2>/dev/null | wc -c`);
	if (!fd)
		return { probed: false, ok: false };
	const out = trim(fd.read('all') || '');
	fd.close();
	const bytes = int(out) || 0;
	return { probed: true, ok: (bytes > 0), bytes: bytes };
}

/* Video-stream probe: the shared yt_stream_probe helper produces a REAL
 * videoplayback URL (cached 30 min — the same cache the Strategy Lab and
 * the auto-pilot use), then a ranged download measures throughput on the
 * LIVE path. A timeout with bytes on the wire is an honest partial (the
 * throttled link still reports its speed). */
function probe_video() {
	const uf = RUN_DIR + '/sp_yt.json';
	system(`rm -f ${sq(uf)} 2>/dev/null`);
	system(`ucode /etc/homeproxy/scripts/yt_stream_probe.uc get > ${sq(uf)} 2>/dev/null`, 60000);
	let meta = null;
	try { meta = json(readfile(uf) || ''); } catch (e) { meta = null; }
	system(`rm -f ${sq(uf)} 2>/dev/null`);
	if (meta == null || type(meta) !== 'object' || !meta.ok || !length(meta.url))
		return { probed: false };
	const cf = RUN_DIR + '/sp_probe.code';
	system(`rm -f ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -s -r 0-8388607 --connect-timeout 4 --max-time 10 -o /dev/null ` +
		`-w '%{http_code} %{time_total} %{size_download}' ${sq(meta.url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, 10 * 1000 + 4000);
	const cwt = parse_cwt(readfile(cf));
	return { probed: true, code: cwt.code, rc: rc, tsec: cwt.tsec,
		size: int(cwt.third) || 0, host: meta.host };
}

/* Passive QUIC observation (Discovery Engine): UDP/443 flows whose mapped
 * hostname belongs to the service. Zero probes spent. */
function probe_quic(host_class) {
	const flows = conntrack_flows(400);
	const conns = clash_conns(3);
	const map = {};
	for (let c in conns) {
		const h = lc(trim('' + (c.host || '')));
		const dip = trim('' + (c.dip || ''));
		if (length(h) && length(dip) && h !== dip && index(h, ':') < 0)
			map[dip] = h;
	}
	let observed = 0, total_quic = 0;
	for (let f in flows) {
		if (f.proto !== 'udp' || f.dport !== 443)
			continue;
		total_quic++;
		const h = lc(map[f.dst] || '');
		if (length(host_class) && length(h) && index(h, host_class) >= 0)
			observed++;
	}
	return { observed: (observed > 0), flows: observed, total_quic: total_quic };
}

/* ── Component execution ── */

function run_component(comp, prof_key, counters) {
	const row = { id: comp.id, label: comp.label, kind: comp.kind, host: comp.host || null };

	if (comp.kind === 'http') {
		counters.probes++;
		const path = probe_live(comp.url);
		const j = judge_http(path);
		row.state = j.state;
		row.note = j.note;
		row.code = path.code;
		row.tsec = path.tsec;
		row.transport_kind = (path.kind != null) ? path.kind : null;
		row.path = path;
	} else if (comp.kind === 'ws') {
		counters.probes++;
		const w = probe_ws(comp.url);
		const j = judge_ws(w.path, w.raw_code);
		row.state = j.state;
		row.note = j.note;
		row.code = w.raw_code;
		row.tsec = w.path.tsec;
		row.path = w.path;
	} else if (comp.kind === 'video') {
		counters.probes += 1;   /* innertube-запрос (часто из кэша) */
		const v = probe_video();
		if (v.probed)
			counters.probes++;  /* + ranged-GET — только если URL получен */
		const j = judge_video(v);
		row.state = j.state;
		row.note = j.note;
		row.level = j.level || null;
		row.plays = j.plays || null;
		row.speed_bps = j.speed_bps || null;
		row.host = v.host || null;
	} else if (comp.kind === 'tcp') {
		counters.probes++;
		const r = probe_tcp(comp.host, comp.port);
		const j = judge_tcp(r);
		row.state = j.state;
		row.note = j.note;
		row.code = '000';
	} else if (comp.kind === 'stun') {
		counters.probes++;
		const r = probe_stun(comp.host, comp.port);
		const j = judge_stun(r);
		row.state = j.state;
		row.note = j.note;
		row.code = '000';
	} else if (comp.kind === 'quic_passive') {
		const host_class = (prof_key === 'youtube') ? 'googlevideo' : '';
		const r = probe_quic(host_class);
		const j = judge_quic({ observed: r.observed, note: r.flows + ' потока к хостам сервиса, всего QUIC-потоков в моменте: ' + r.total_quic });
		row.state = j.state;
		row.note = j.note;
		row.code = null;
	}
	return row;
}

/* Differential cause for a FAILED http component (broken/refused): one
 * direct + one proxy probe of the SAME url, then diag_cause (Ф6.1 taxonomy).
 * WebSocket rows are excluded — their differential would need WS headers
 * on both paths and a bare HTTPS answer there reads as a false refusal. */
function differential(row, prof_key, counters) {
	if (counters.diff >= DIFF_CAP)
		return;
	if (row.kind !== 'http')
		return;
	if (row.state !== 'broken' && row.state !== 'refused')
		return;
	if (row.path == null || !row.host || !length(row.url))
		return;
	const direct_in = port_listening(DIRECT_PORT);
	const proxy_in = port_listening(PROXY_PORT);
	if (!direct_in && !proxy_in)
		return;
	const plain_ip = (index(row.host, ':') < 0 && match(row.host, /^[a-z0-9]/)) ?
		resolve_plain(row.host) : null;
	let d = null, p = null;
	if (direct_in) {
		counters.probes++;
		counters.diff++;
		d = probe_via(row.url, DIRECT_PORT, false,
			plain_ip ? row.host : null, plain_ip);
	}
	if (proxy_in) {
		counters.probes++;
		counters.diff++;
		p = probe_via(row.url, PROXY_PORT, true, null, null);
	}
	const v = diag_cause({
		svc: prof_key,
		dns: { differs: false, poison: false, plain_ip: plain_ip },
		direct: d,
		proxy: p,
		live: row.path,
		inbounds: { direct: direct_in, proxy: proxy_in, mixed: false }
	});
	if (v.cause != null)
		row.cause = { type: v.cause.type, confidence: v.cause.confidence,
			evidence: v.cause.evidence };
	row.routing_verdict = v.verdict;
}

/* ── Main ── */

/* Guard: one battery at a time; a runner that died mid-run stops blocking
 * after 15 minutes (the RPC applies the same staleness rule). */
let prev = null;
if (access(STATUS)) {
	try { prev = json(readfile(STATUS) || ''); } catch (e) { prev = null; }
}
if (prev && prev.running && (time() - int(prev.ts) < 900)) {
	exit(0);
}

let profile = 'all';
if (access(TASK)) {
	const t = lc(trim(readfile(TASK) || ''));
	system('rm -f ' + sq(TASK));
	let ok = false;
	for (let k in PROFILE_KEYS)
		if (k === t) { ok = true; break; }
	if (ok)
		profile = t;
}

const prof_names = [];
if (profile === 'all') {
	for (let k in [ 'youtube', 'discord', 'telegram', 'games' ])
		push(prof_names, k);
} else {
	push(prof_names, profile);
}

const rows = [];
const counters = { probes: 0, diff: 0 };
let done = 0;
let total = 0;
for (let pk in prof_names) {
	const prof = PROFILES[pk];
	if (prof == null)
		continue;
	total += length(prof.components);
}
write_status({ running: true, done: 0, total: total, current: '', profile: profile });

for (let pk in prof_names) {
	const prof = PROFILES[pk];
	if (prof == null)
		continue;
	const first_state = {};
	/* Первый проход: все компоненты, кроме repeat-строк стабильности. */
	for (let comp in prof.components) {
		if (comp.kind === 'repeat')
			continue;
		write_status({ running: true, done: done, total: total, current: comp.id, profile: profile });
		const row = run_component(comp, pk, counters);
		row.url = comp.url || null;
		row.profile = pk;
		first_state[comp.id] = row.state;
		if (row.path != null)
			differential(row, pk, counters);
		delete row.path;   /* внутренняя форма classify_path — не для JSON-результата */
		push(rows, row);
		done++;
		write_status({ running: true, done: done, total: total, current: '', profile: profile });
	}
	/* Стабильность (аудит 60): повтор ключевого компонента, честный вердикт
	 * флапания; при неработающем первом ответе стабильность НЕ оценивается
	 * (не приравнивается к пройдено — аудит 91). */
	for (let comp in prof.components) {
		if (comp.kind !== 'repeat')
			continue;
		let tcomp = null;
		for (let c in prof.components)
			if (c.id === comp.target)
				tcomp = c;
		const first = first_state[comp.target];
		if (tcomp == null || first == null) {
			push(rows, { id: comp.id, label: comp.label, kind: 'repeat', profile: pk,
				state: 'unprobed', note: 'целевой компонент не найден в профиле' });
			done++;
			continue;
		}
		if (first !== 'working') {
			push(rows, { id: comp.id, label: comp.label, kind: 'repeat', profile: pk,
				state: 'unprobed',
				note: 'стабильность не оценивается — компонент «' + comp.target + '» не working (' + first + ')' });
			done++;
			write_status({ running: true, done: done, total: total, current: '', profile: profile });
			continue;
		}
		write_status({ running: true, done: done, total: total, current: comp.id, profile: profile });
		counters.probes++;
		let second_ok = false;
		if (tcomp.kind === 'ws') {
			second_ok = (probe_ws(tcomp.url).raw_code === '101');
		} else if (tcomp.kind === 'http') {
			second_ok = !!probe_live(tcomp.url).ok;
		}
		push(rows, { id: comp.id, label: comp.label, kind: 'repeat', profile: pk,
			state: second_ok ? 'working' : 'degraded',
			note: second_ok ? 'стабильно: компонент подтвердился дважды (2/2)' :
				'флапает: первый ответ рабочий, повторный — нет (1/2)' });
		done++;
		write_status({ running: true, done: done, total: total, current: '', profile: profile });
	}
}

/* Summary from the rows — no counter to forget. */
const summary = { working: 0, degraded: 0, refused: 0, broken: 0, unprobed: 0, unusable: 0 };
for (let r in rows)
	if (summary[r.state] != null)
		summary[r.state]++;

atomic_write(RESULT, sprintf('%.J', {
	ts: time(),
	profile: profile,
	probes_used: counters.probes,
	diff_used: counters.diff,
	components: rows,
	summary: summary
}) + '\n');
write_status({ running: false, done: total, total: total, current: 'done',
	profile: profile, finished: time() });
