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
 *   delay   active node last TLS delay, ms (Clash API /proxies, leaf history;
 *           null when core down / direct main / no fresh history)
 *   learned records in the automation learned lists (domains + raw IPs,
 *           recounted only when either file changes size/mtime)
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

function sample_conns() {
	const data = clash_get('/connections');
	if (data == null || type(data) !== 'object')
		return null;
	const list = data.connections;
	/* No-connection cores marshal a nil slice as JSON null — the core is
	 * UP here (we parsed its reply), so null means zero connections. */
	return (list != null && type(list) === 'array') ? length(list) : 0;
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

function flush() {
	const doc = {
		interval: SAMPLE_INTERVAL,
		max_points: MAX_POINTS,
		updated: time(),
		points: points
	};
	try {
		atomic_write(OUT, sprintf('%.J', doc) + '\n');
	} catch (e) { /* a failed write retries on the next sample; never die */ }
}

system('mkdir -p ' + shellquote(RUN_DIR) + ' 2>/dev/null; true');

/* Main loop. Sleep FIRST so every emitted point sits on the interval grid;
 * the very first point has no CPU delta yet (null) by design. */
while (true) {
	sleep(SAMPLE_INTERVAL * 1000);

	const t = time();
	let pt = null;
	try {
		pt = {
			t: t,
			cpu: sample_cpu(),
			ram: sample_ram(),
			temp: sample_temp(),
			conns: sample_conns(),
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
