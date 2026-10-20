/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — Overview metrics sampler (Ф4, ч.76).
 *
 * WHY: the "Overview" (Главная) tab charts need a HISTORY of system and
 * engine metrics. The core's Clash API keeps only connection totals, CPU is
 * a /proc read that must be DELTA-ed over time, and temperature comes from
 * the thermal zones. A tiny always-on procd instance collects a ring buffer
 * (≤120 points) into /var/run/homeproxy/overview_metrics.json; the UI polls
 * the overview_metrics RPC every 4 s and renders inline SVG on the client
 * (no external resources — D5 hard condition).
 *
 * WHAT (each sample, ~5 s apart):
 *   cpu     % busy since the PREVIOUS sample (delta of /proc/stat "cpu" row;
 *           null on the first sample — no delta yet)
 *   ram     % used (100 × (MemTotal − MemAvailable) / MemTotal)
 *   temp    °C (first thermal zone, when present; null otherwise)
 *   conns   active connections (Clash API /connections; null when core down)
 *   vpn_b / dir_b / byp_b   per-exit traffic SPEED, bytes/s since the
 *           previous sample (Clash API /connections per-connection deltas,
 *           aggregated by the chain of outbounds: vpn = main-out/node leaf,
 *           dir = direct-out, byp = zapret + byedpi + tg-ws bridges;
 *           null when the core is down or on the baseline sample)
 *   delay   active node last TLS delay, ms (Clash API /proxies, leaf history;
 *           null when core down / direct main / no fresh history)
 *   learned records in the automation learned lists (domains + raw IPs,
 *           recounted only when either file changes size/mtime)
 *   totals  CUMULATIVE per-exit VOLUME (bytes) carried in the output doc
 *           (vpn/node/direct/zapret/byedpi/tgws/block/other + since).
 *           Only LAN-client connections count — the router's own 127.0.0.1
 *           probes (scanner, diagnostics, bridges) are excluded. The
 *           counters are restored from the output file at startup, so they
 *           survive a service restart; a REBOOT clears /var/run (tmpfs) and
 *           honestly resets them.
 * Points missing a source carry null — the UI breaks the line there.
 *
 * Live-verified on this build (05-doc, ч.76): ucode standalone HAS the
 * shift()/slice() builtins; fs.stat keys have NO st_ prefix (mtime/size);
 * procfs is readable via readfile(); match() only with /regex/ literals.
 *
 * ucode constraints honored (05-doc): sleep() takes MILLISECONDS, push()/
 * shift() are FUNCTIONS (no array methods), for-in over arrays yields
 * elements, json() is a PARSER only (serialize via sprintf('%.J')), all
 * helpers declared ABOVE the loop (no hoisting), no optional chaining
 * (conservative standalone style), atomic writes (tmp + mv -f). */

'use strict';

/* ⚠ popen comes from the fs module (NOT a global) in standalone ucode —
 * the same trap that silently killed the urltest watchdog at its first
 * fetch (ч.59). */
import { access, readfile, writefile, stat, popen } from 'fs';

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

const RUN_DIR = '/var/run/homeproxy';
const OUT = RUN_DIR + '/overview_metrics.json';
const API = 'http://127.0.0.1:9090';
const RES = '/etc/homeproxy/resources';
const SAMPLE_INTERVAL = 5;    /* s between samples; UI polls ≤5 s (D5)      */
const MAX_POINTS = 120;       /* ring size: 120 × 5 s ≈ 10 min of history   */
const TEMP_SANITY = 150000;   /* thermal value sanity cap (m°C)             */

let prev_cpu = null;          /* previous /proc/stat totals (CPU delta)     */
let prev_idle = null;
let points = [];
let learn_sig = '';
let learned = 0;
let last_probe = 0;           /* rate-limited active-node delay probe       */
const PROBE_EVERY = 60;       /* s between API delay probes (1 req/min)     */
const PROBE_URL = 'http://www.gstatic.com/generate_204';

/* Per-exit traffic (Ф8-F7 T2). totals = cumulative bytes per bucket;
 * prev_conn = last cumulative upload/download per connection id (the delta
 * source). null prev_conn → the next sample is a BASELINE (long-lived
 * connections must not dump their whole history into a fresh counter). */
let totals = { vpn: 0, node: 0, direct: 0, zapret: 0, byedpi: 0, tgws: 0, block: 0, other: 0 };
let totals_since = time();
let prev_conn = null;

function read_all(path) {
	if (!access(path))
		return null;
	let raw = null;
	try { raw = readfile(path); } catch (e) { return null; }
	return (raw != null && length(raw)) ? raw : null;
}

/* Busy % between the last two "cpu" rows: 100 × (Δtotal − Δidle) / Δtotal.
 * idle = idle + iowait (standard formula). Integer math only — ucode `/`
 * truncates. */
function sample_cpu() {
	const raw = read_all('/proc/stat');
	if (raw == null)
		return null;
	const nl = index(raw, '\n');
	const line = (nl >= 0) ? substr(raw, 0, nl) : raw;
	const m = match(line, /^cpu +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+)/);
	if (!m)
		return null;
	const idle_all = int(m[4]) + int(m[5]);
	const total = int(m[1]) + int(m[2]) + int(m[3]) + int(m[4]) + int(m[5]);
	let cpu = null;
	if (prev_cpu != null) {
		const dt = total - prev_cpu;
		const di = idle_all - prev_idle;
		if (dt > 0)
			cpu = (di < 0 || di == 0) ? 100 : int(((dt - di) * 100) / dt);
	}
	prev_cpu = total;
	prev_idle = idle_all;
	return cpu;
}

/* /proc/meminfo labels appear once — match without anchors (POSIX ERE). */
function sample_ram() {
	const raw = read_all('/proc/meminfo');
	if (raw == null)
		return null;
	const mt = match(raw, /MemTotal: +([0-9]+) kB/);
	const ma = match(raw, /MemAvailable: +([0-9]+) kB/);
	if (!mt || !ma)
		return null;
	const total = int(mt[1]);
	if (total <= 0)
		return null;
	return int(((total - int(ma[1])) * 100) / total);
}

/* First thermal zone (m°C → °C, truncated). Absent hardware → null. */
function sample_temp() {
	const raw = read_all('/sys/class/thermal/thermal_zone0/temp');
	if (raw == null)
		return null;
	const v = int(trim(raw));
	if (v <= 0 || v > TEMP_SANITY)
		return null;
	return int(v / 1000);
}

/* One-shot Clash API GET; parsed JSON or null (core down / bad JSON). */
function clash_get(path) {
	const fd = popen('wget -qO- --timeout=3 ' + API + path + ' 2>/dev/null');
	if (!fd)
		return null;
	const raw = trim(fd.read('all'));
	fd.close();
	if (!length(raw))
		return null;
	let data = null;
	try { data = json(raw); } catch (e) { return null; }
	return data;
}

/* ── Per-exit traffic aggregation (Ф8-F7 T2) ─────────────────────────────
 * The Clash API /connections reply carries ACTIVE connections with their
 * CUMULATIVE upload/download. Deltas between samples give the per-exit
 * speed; the deltas also accumulate into the totals. Exit = the connection
 * chain ([leaf, …, root]): tg-ws bridge beats the groups (a per-source
 * urltest group can carry both tgws-out and main-out — what "now" points
 * at decides), then main-out, then the engines, then direct/block; a bare
 * cfg-*-out leaf is a specific node (custom routing / node rules). */
function classify_chains(chains) {
	if (chains == null || type(chains) !== 'array')
		return 'other';
	const has = (t) => (index(chains, t) >= 0);
	if (has('tgws-out')) return 'tgws';
	if (has('main-out')) return 'vpn';
	if (has('zapret-out')) return 'zapret';
	if (has('byedpi-out')) return 'byedpi';
	if (has('direct-out')) return 'direct';
	if (has('block-out')) return 'block';
	const leaf = '' + chains[0];
	if (match(leaf, /^cfg-.+-out$/))
		return 'node';
	return 'other';
}

/* One /connections sample → per-exit rate deltas {vpn, dir, byp} in bytes
 * (per SAMPLE_INTERVAL), or null when the core is down (totals untouched;
 * prev_conn reset so the next sample re-baselines). Router-originated
 * probes (sourceIP 127.0.0.1) never count — only LAN-client traffic. */
function sample_traffic(list) {
	if (list == null || type(list) !== 'array') {
		prev_conn = null;
		return null;
	}
	const cur = {};
	const d = { vpn: 0, dir: 0, byp: 0 };
	for (let c in list) {
		if (type(c) !== 'object' || !c.id)
			continue;
		const md = c.metadata;
		if (md && md.sourceIP === '127.0.0.1')
			continue;
		const u = int(c.upload) || 0;
		const dn = int(c.download) || 0;
		cur[c.id] = { u: u, d: dn };
		if (prev_conn == null)
			continue;   /* baseline sample: counters start from here */
		const p = prev_conn[c.id];
		if (p == null)
			continue;   /* first sight of a NEW connection: it started
			           * within this interval with ≈zero counters —
			           * its deltas count from the next sample on */
		const du = (u >= p.u) ? (u - p.u) : u;
		const dd = (dn >= p.d) ? (dn - p.d) : dn;
		if (!du && !dd)
			continue;
		const b = classify_chains(c.chains);
		totals[b] = int(totals[b] || 0) + du + dd;
		if (b === 'vpn' || b === 'node') d.vpn += du + dd;
		else if (b === 'direct') d.dir += du + dd;
		else if (b === 'zapret' || b === 'byedpi' || b === 'tgws') d.byp += du + dd;
	}
	prev_conn = cur;
	return d;
}

/* Self-probe of the active leaf: the core refreshes a node's delay history
 * only when a URLTest group probes it — a plain Selector leaf (the common
 * "specific node" main) can sit with an EMPTY history forever, so the
 * delay chart would stay null. Fire the same API delay test init.d runs
 * at cold start (gstatic generate_204, 5 s timeout), rate-limited to one
 * request per minute. The probe also refreshes the core's own history,
 * keeping clash_active_node and this ring consistent. */
function probe_leaf(tag) {
	if ((time() - last_probe) < PROBE_EVERY)
		return null;
	last_probe = time();
	const fd = popen('wget -qO- --timeout=6 ' +
		shellquote(API + '/proxies/' + tag + '/delay?timeout=5000&url=' + PROBE_URL) +
		' 2>/dev/null');
	if (!fd)
		return null;
	const raw = trim(fd.read('all'));
	fd.close();
	const m = match(raw, /"delay": *([0-9]+)/);
	const d = (m != null) ? int(m[1]) : 0;
	return (d > 0 && d < 65535) ? d : null;
}

/* Active node delay: start at main-out (the selector this app always uses
 * for the main node — sing-box's Clash API has NO GLOBAL group, the /proxies/
 * GLOBAL fetch answers EMPTY, so a GLOBAL-led descent would return null on
 * every sample) and follow the group chain → leaf (≤4 hops, the same descent
 * as the rpcd clash_leaf_tag helper), then read the leaf's LAST history
 * entry. direct-out/block-out mains have no TLS delay — null. */
function sample_delay() {
	const data = clash_get('/proxies');
	if (data == null || type(data) !== 'object')
		return null;
	const proxies = data.proxies;
	if (proxies == null || type(proxies) !== 'object')
		return null;
	let tag = null;
	const mo = proxies['main-out'];
	const g = proxies['GLOBAL'];
	if (mo && mo.now)
		tag = mo.now;
	else if (g && g.now)
		tag = g.now;
	if (tag == null || tag === 'direct-out' || tag === 'block-out')
		return null;
	for (let i = 0; i < 4; i++) {
		const p = proxies[tag];
		if (!p)
			return null;
		if (p.type !== 'URLTest' && p.type !== 'Selector' && p.type !== 'Fallback')
			break;
		if (!p.now)
			break;
		tag = p.now;
	}
	const p = proxies[tag];
	if (!p)
		return null;
	const h = p.history;
	if (h == null || type(h) !== 'array' || !length(h))
		return probe_leaf(tag);
	const d = int(h[length(h) - 1].delay) || 0;
	return (d > 0 && d < 65535) ? d : probe_leaf(tag);
}

function count_lines(path) {
	const raw = read_all(path);
	if (raw == null)
		return 0;
	let n = 0;
	for (let l in split(raw, '\n')) {
		if (length(trim(l)))
			n++;
	}
	return n;
}

/* Learned records (domains + raw IPs), recounted only when either file
 * changed (size/mtime signature — fs.stat keys have NO st_ prefix, ч.75). */
function sample_learned() {
	const files = [ RES + '/auto_proxy_list.txt', RES + '/auto_proxy_ip.txt' ];
	let sig = '';
	for (let p in files) {
		let st = null;
		try { st = stat(p); } catch (e) { st = null; }
		sig += (st != null) ? (st.mtime + ':' + st.size) : 'x';
		sig += ';';
	}
	if (sig === learn_sig)
		return learned;
	learn_sig = sig;
	learned = 0;
	for (let p in files)
		learned += count_lines(p);
	return learned;
}

function atomic_write(path, content) {
	const tmp = path + '.tmp';
	writefile(tmp, content);
	system('mv -f ' + shellquote(tmp) + ' ' + shellquote(path));
}

/* Restore the carried per-exit totals from the output file left by the
 * previous metrics run (same tmpfs file): the counters then survive a
 * service restart. A reboot wipes /var/run — the counters honestly reset. */
function restore_totals() {
	const raw = read_all(OUT);
	if (raw == null)
		return;
	let doc = null;
	try { doc = json(raw); } catch (e) { return; }
	if (doc == null || type(doc.totals) !== 'object')
		return;
	for (let k in totals) {
		if (type(doc.totals[k]) === 'number' && doc.totals[k] >= 0)
			totals[k] = int(doc.totals[k]);
	}
	if (type(doc.totals.since) === 'number' && doc.totals.since > 0)
		totals_since = int(doc.totals.since);
}

function flush() {
	const tdoc = { since: totals_since };
	for (let k in totals)
		tdoc[k] = totals[k];
	const doc = {
		interval: SAMPLE_INTERVAL,
		max_points: MAX_POINTS,
		updated: time(),
		points: points,
		totals: tdoc
	};
	try {
		atomic_write(OUT, sprintf('%.J', doc) + '\n');
	} catch (e) { /* a failed write retries on the next sample; never die */ }
}

system('mkdir -p ' + shellquote(RUN_DIR) + ' 2>/dev/null; true');
restore_totals();

/* Main loop. Sleep FIRST so every emitted point sits on the interval grid;
 * the very first point has no CPU delta yet (null) by design. */
while (true) {
	sleep(SAMPLE_INTERVAL * 1000);

	const t = time();
	let pt = null;
	try {
		/* One /connections fetch feeds BOTH the connection count and the
		 * per-exit traffic deltas (the aggregate is the same reply). */
		const cj = clash_get('/connections');
		let conns_n = null;
		let rates = null;
		if (cj != null && type(cj) === 'object') {
			const list = cj.connections;
			conns_n = (list != null && type(list) === 'array') ? length(list) : 0;
			rates = sample_traffic(list);
		} else {
			prev_conn = null;
		}
		pt = {
			t: t,
			cpu: sample_cpu(),
			ram: sample_ram(),
			temp: sample_temp(),
			conns: conns_n,
			vpn_b: (rates != null) ? int(rates.vpn / SAMPLE_INTERVAL) : null,
			dir_b: (rates != null) ? int(rates.dir / SAMPLE_INTERVAL) : null,
			byp_b: (rates != null) ? int(rates.byp / SAMPLE_INTERVAL) : null,
			delay: sample_delay(),
			learned: sample_learned()
		};
	} catch (e) {
		pt = null;
	}
	if (pt != null) {
		try {
			push(points, pt);
			while (length(points) > MAX_POINTS)
				shift(points);
			flush();
		} catch (e) { /* never die */ }
	}
}
