/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Process Manager (Ф1.4, ч.150).
 *
 * WHY: every kill path used to be "pidof NAME && kill $(pidof NAME)" or a
 * ps|grep pipeline. That kills FOREIGN daemons with the same name (audit 11:
 * kill_our_mosdns() killed ANY mosdns), kills the wrong process after PID
 * reuse (audit 34: a dnsmasq pidfile pid could be a NEW process), matches
 * shells/interpreters (audit 36: ps|grep killed rc.common), and pidof does
 * not even match ucode script daemons (lesson 23). The Process Manager gives
 * every managed process an IDENTITY — (pid, starttime-ticks, exe/script) —
 * and every stop goes through an identity-verified kill. Never kill by name.
 *
 * IDENTITY: /proc/<pid>/stat field 22 (starttime, ticks since boot) + the
 * pid. A reused PID carries a DIFFERENT starttime, so a stale entry is
 * honestly "not alive". boot epoch comes from /proc/stat btime; the identity
 * is void after a reboot (registry boot-check + tmpfs wipe).
 *
 * MATCHING (find_daemons): /proc enumeration via readfile only — NO ps, NO
 * pidof, NO pgrep, NO forks in the scan loop:
 *   spec.exe    — exact binary path (contains '/') or exact basename
 *                 (readlink(/proc/pid/exe), ' (deleted)' suffix stripped)
 *   spec.script — exact script file under /etc/homeproxy/scripts/ matched
 *                 as a whole cmdline element (argv), never a substring —
 *                 the only reliable identity for ucode daemons
 *   spec.arg    — a cmdline ELEMENT equal to the value (string) or to ANY
 *                 listed value (array) — pins "our" instance by its config
 *                 path/flag (audit 11: mosdns -c OUR.yaml; audit 34: dnsmasq
 *                 -C OUR.conf), never a substring match
 *
 * REGISTRY (/var/run/homeproxy/daemons.json): daemons.json is the shared
 * base (plan Ф1.4). Owners (multidns, automation, control_apply, …) register
 * identity right after a successful spawn; the CLI `scan` merges scanned
 * identities for everything else. Entry:
 *   { name, kind, pid, start, started, exe, script, arg, hb, note }
 * reg_gc() drops entries whose identity is dead (or whose boot differs).
 *
 * UNIFIED ATOMIC STATE WRITES (audit 10): wstat()/wjson() = temp + rename;
 * new code writes state files through them instead of a bare writefile().
 *
 * KILL POLICY: kill_entry() verifies the identity BEFORE the signal and on
 * every poll (PID reuse during the wait window cannot redirect the KILL):
 * TERM → wait (default 3 s) → KILL → wait → honest boolean. Guards: never
 * pid < 2, never self, never a name-based sweep. Do NOT point kill_entry at
 * a procd-managed instance: a stray SIGTERM burns the procd respawn budget
 * (lesson 135) — procd instances are stopped through init.d only.
 *
 * CLI: this file is a MODULE ONLY (exports cannot run as a script — ucode
 * compiles imports in module mode, direct execution rejects `export`). The
 * command-line face lives in pmgr_cli.uc (thin script wrapper):
 *   ucode pmgr_cli.uc scan | status | gc | selftest
 *   ucode pmgr_cli.uc mosdns_stop | dnsf_stop [dir]
 *   ucode pmgr_cli.uc kill_if <exe|script:NAME.uc> [arg]
 *   ucode pmgr_cli.uc find <exe[,exe2…]|script:NAME.uc> [arg…]   (exit code)
 *   ucode pmgr_cli.uc kill_args <exe|script:NAME.uc> [arg…]      (arg_all kill)
 *
 * ucode constraints honored (lessons 2/20/26/93/103/126/166): module export
 * functions end with `};`; helpers declared ABOVE callers (no hoisting);
 * match() only with /regex/ literals; rindex()/index() verified on the
 * router; NUL = sprintf('%c', 0) and split-on-NUL of /proc/<pid>/cmdline
 * verified live (microtest ч.150); sleep() is MILLISECONDS; atomic rename();
 * for-in over an array yields ELEMENTS; for-in over an object yields KEYS.
 */

'use strict';

import { access, readfile, readlink, writefile, rename, stat, unlink, mkdir, popen } from 'fs';

export const RUN_DIR = '/var/run/homeproxy';
export const REG_PATH = RUN_DIR + '/daemons.json';
export const SCRIPTS_DIR = '/etc/homeproxy/scripts';

/* CLK_TCK on this build is 100 — microtest ч.150: btime + start/100 == time(). */
const HZ = 100;
const NUL = sprintf('%c', 0);

/* ── procfs primitives (all null-safe: a process may vanish mid-read) ───── */

function self_pid() {
	const raw = readfile('/proc/self/stat');
	if (raw == null)
		return 0;
	const m = match(raw, /^([0-9]+) \(/);
	return m ? int(m[1]) : 0;
};

/* Own pid/start — the identity a script daemon registers itself with
 * (reg_self) before the main loop starts heartbeating (Ф1.4b). */
export function own_pid() {
	return self_pid();
};

export function boot_epoch() {
	const raw = readfile('/proc/stat');
	if (raw == null)
		return 0;
	const m = match(raw, /btime +([0-9]+)/);
	return m ? int(m[1]) : 0;
};

/* /proc/<pid>/stat: comm may contain spaces and ')' — split after the LAST
 * ')'. Post-tail fields (0-based): state=0, ppid=1, …, starttime=19
 * (overall field 22). Returns null when the process is gone. */
function stat_fields(pid) {
	const raw = readfile('/proc/' + pid + '/stat');
	if (raw == null)
		return null;
	const i = rindex(raw, ')');
	if (i < 0)
		return null;
	const f = split(substr(raw, i + 2), ' ');
	if (length(f) < 20)
		return null;
	return { state: f[0], ppid: f[1], start: int(f[19]) };
};

/* Identity info of one process, or null. cmdline elements split on NUL
 * (verified live: readfile keeps NUL bytes, split works). */
export function proc_info(pid) {
	const sf = stat_fields(pid);
	if (sf == null)
		return null;
	const exe_raw = access('/proc/' + pid + '/exe') ? readlink('/proc/' + pid + '/exe') : null;
	const craw = readfile('/proc/' + pid + '/cmdline');
	const cmd = [];
	if (craw != null)
		for (let e in split(craw, NUL))
			if (length(e))
				push(cmd, e);
	let uid = null;
	const st = readfile('/proc/' + pid + '/status');
	if (st != null) {
		const um = match(st, /Uid:\s+([0-9]+)/);
		if (um)
			uid = int(um[1]);
	}
	return {
		pid: int(pid),
		state: sf.state,
		ppid: int(sf.ppid),
		start: sf.start,
		started: boot_epoch() + int(sf.start / HZ),
		exe: (exe_raw != null) ? replace('' + exe_raw, ' (deleted)', '') : null,
		cmdline: cmd,
		uid: uid
	};
};

export function proc_start(pid) {
	const sf = stat_fields(pid);
	return (sf != null) ? sf.start : null;
};

function basename_of(p) {
	const i = rindex('' + p, '/');
	return (i >= 0) ? substr('' + p, i + 1) : ('' + p);
};

/* spec.exe match: full path when the spec contains '/', else basename. */
function exe_matches(exe, want) {
	if (exe == null || !length('' + exe))
		return false;
	if (index('' + want, '/') >= 0)
		return ('' + exe) === ('' + want);
	return basename_of(exe) === ('' + want);
};

/* spec.script match: a WHOLE cmdline element equals
 * /etc/homeproxy/scripts/<script> — never a substring (audit 36). */
function script_matches(cmd, script) {
	const want = SCRIPTS_DIR + '/' + script;
	for (let e in cmd)
		if (e === want)
			return true;
	return false;
};

/* spec.arg match: some cmdline element EQUALS the value (or any listed). */
function arg_matches(cmd, arg) {
	const vals = (type(arg) === 'array') ? arg : [ arg ];
	for (let v in vals)
		for (let e in cmd)
			if (e === ('' + v))
				return true;
	return false;
};

export function entry_alive(e) {
	if (e == null || type(e) !== 'object')
		return false;
	const pid = int(e.pid);
	if (pid < 2)
		return false;
	const sf = stat_fields(pid);
	if (sf == null || int(sf.start) !== int(e.start))
		return false;
	/* A ZOMBIE is dead: /proc still exists (reaping pending, init/procd
	 * gets to it within moments), but the process can never run again —
	 * reporting it alive would make kill_entry() wait out its whole
	 * timeout and report "failed" for a corpse. */
	if (sf.state === 'Z')
		return false;
	if (e.exe != null && length('' + e.exe)) {
		const ex = access('/proc/' + pid + '/exe') ? readlink('/proc/' + pid + '/exe') : null;
		if (ex == null || !exe_matches(replace('' + ex, ' (deleted)', ''), '' + e.exe))
			return false;
	}
	return true;
};

/* One full /proc snapshot: { "<pid>": proc_info }. NO ps, NO pidof, NO pgrep
 * — readfile-only enumeration (lesson 23: busybox pidof cannot even see
 * ucode script daemons). */
function proc_table() {
	const out = {};
	const fd = popen('ls -1 /proc 2>/dev/null');
	if (!fd)
		return out;
	const listing = fd.read('all') || '';
	fd.close();
	for (let line in split(listing, '\n')) {
		const p = trim(line);
		if (!match(p, /^[0-9]+$/))
			continue;
		const info = proc_info(int(p));
		if (info != null)
			out['' + info.pid] = info;
	}
	return out;
};

/* Find processes by identity spec. spec = { exe } and/or { script } and/or
 * { arg } / { arg_all } / { neg }. At least one of exe/script is REQUIRED
 * (never a bare arg — an arg alone could match an unrelated binary carrying
 * the same path).
 *   spec.arg     — SOME cmdline element equals the value / any listed value
 *                  (pins "our" instance by one config path or flag)
 *   spec.arg_all — EVERY listed value must appear as a whole cmdline element
 *                  (a conjunction: e.g. the rc.common shell running OUR init
 *                  script = ['/etc/rc.common', '/etc/init.d/homeproxy'])
 *   spec.neg     — NO listed value may appear as a cmdline element (excludes
 *                  the `--check` probe runs of the very same binary) */
export function find_daemons(spec) {
	const out = [];
	if (spec == null || type(spec) !== 'object')
		return out;
	const want_exe = (spec.exe != null && length('' + spec.exe)) ? '' + spec.exe : null;
	const want_script = (spec.script != null && length('' + spec.script)) ? '' + spec.script : null;
	if (want_exe == null && want_script == null)
		return out;
	const all_args = (type(spec.arg_all) === 'array') ? spec.arg_all : null;
	const neg_args = (type(spec.neg) === 'array') ? spec.neg : null;
	const tbl = proc_table();
	for (let k in tbl) {
		const info = tbl[k];
		let hit = false;
		if (want_exe != null && exe_matches(info.exe, want_exe))
			hit = true;
		if (!hit && want_script != null && script_matches(info.cmdline, want_script))
			hit = true;
		if (!hit)
			continue;
		if (spec.arg != null && !arg_matches(info.cmdline, spec.arg))
			continue;
		if (all_args != null) {
			for (let a in all_args) {
				if (!arg_matches(info.cmdline, a)) {
					hit = false;
					break;
				}
			}
			if (!hit)
				continue;
		}
		if (neg_args != null) {
			for (let n in neg_args) {
				if (arg_matches(info.cmdline, n)) {
					hit = false;
					break;
				}
			}
			if (!hit)
				continue;
		}
		push(out, {
			pid: info.pid,
			start: info.start,
			started: info.started,
			exe: info.exe,
			uid: info.uid,
			state: info.state
		});
	}
	return out;
};

/* ── identity-verified kill ─────────────────────────────────────────────── */

/* Identity-verified kill. TERM → wait_ms (default 3000) → KILL → 2 s, or
 * with force_kill=true straight KILL (the mosdns restart path needs the
 * IMMEDIATE socket release the old SIGKILL gave: a graceful TERM keeps the
 * listeners bound for seconds and the next start hits "Address in use").
 * The identity is re-checked on EVERY poll: a PID reused mid-wait is a
 * different process and the signal is withheld. Returns true when "our"
 * process is gone. */
export function kill_entry(e, wait_ms, force_kill) {
	if (e == null || type(e) !== 'object')
		return false;
	const pid = int(e.pid);
	if (pid < 2 || pid === self_pid())
		return false;
	if (!entry_alive(e))
		return true;   /* already gone / PID reused — nothing of ours to kill */
	const wait = (wait_ms == null || int(wait_ms) <= 0) ? 3000 : int(wait_ms);
	if (force_kill) {
		system('kill -9 ' + pid + ' 2>/dev/null');
	} else {
		system('kill -TERM ' + pid + ' 2>/dev/null');
		let steps = int(wait / 100);
		for (let i = 0; i < steps; i++) {
			if (!entry_alive(e))
				return true;
			sleep(100);
		}
		if (!entry_alive(e))
			return true;
		system('kill -9 ' + pid + ' 2>/dev/null');
	}
	for (let i = 0; i < 20; i++) {
		if (!entry_alive(e))
			return true;
		sleep(100);
	}
	return !entry_alive(e);
};

/* find + kill each match. Returns { killed: [pid…], failed: [pid…] }. */
export function kill_matched(spec, wait_ms, force_kill) {
	const res = { killed: [], failed: [] };
	const found = find_daemons(spec);
	for (let e in found) {
		if (kill_entry(e, wait_ms, force_kill))
			push(res.killed, e.pid);
		else
			push(res.failed, e.pid);
	}
	return res;
};

/* ── process-tree reaper (Ф1.4b) ────────────────────────────────────────── */

/* Snapshot the whole descendant subtree of a live process (the root included,
 * breadth-first: root, children, grandchildren…). Every node carries its own
 * (pid, start, exe) identity — kill_tree() re-verifies each at signal time,
 * so a PID reused between the snapshot and the kill never receives anything.
 * Depth is capped at 20 as a paranoia guard against procfs oddities. */
export function proc_descendants(pid) {
	const root = proc_info(pid);
	if (root == null)
		return [];
	const out = [ { pid: root.pid, start: root.start, exe: root.exe } ];
	const seen = {};
	seen['' + root.pid] = true;
	let frontier = [ root.pid ];
	const tbl = proc_table();   /* ONE snapshot; kill_entry re-verifies each node */
	for (let depth = 0; depth < 20 && length(frontier); depth++) {
		const next = [];
		for (let p in frontier) {
			/* for-in over an OBJECT yields KEYS — k is the "<pid>" string key
			 * of the snapshot (arrays yield ELEMENTS). */
			for (let k in tbl) {
				const q = tbl[k];
				if (q == null || seen['' + q.pid] || int(q.ppid) !== int(p))
					continue;
				seen['' + q.pid] = true;
				push(out, { pid: q.pid, start: q.start, exe: q.exe });
				push(next, q.pid);
			}
		}
		frontier = next;
	}
	return out;
};

/* Identity-verified subtree kill: find the spec's roots, snapshot each
 * root's descendants BEFORE any signal, then kill DEEPEST-FIRST (a parent
 * must not outlive its children and spawn replacements). Every signal goes
 * through kill_entry — the (pid, start) identity is re-checked on every
 * poll, a reused PID is skipped. Returns { killed: [pid…], failed: [pid…] }. */
export function kill_tree(spec, wait_ms, force_kill) {
	const res = { killed: [], failed: [] };
	const roots = find_daemons(spec);
	for (let r in roots) {
		const snap = proc_descendants(r.pid);
		for (let i = length(snap) - 1; i >= 0; i--) {
			const e = snap[i];
			if (kill_entry({ pid: e.pid, start: e.start, exe: e.exe }, wait_ms, force_kill))
				push(res.killed, e.pid);
			else
				push(res.failed, e.pid);
		}
	}
	return res;
};

/* ── unified atomic state writes (audit 10) ─────────────────────────────── */

function mkdir_p(p) {
	let cur = '';
	for (let part in split(p, '/')) {
		if (!length(part))
			continue;
		cur += '/' + part;
		if (!access(cur)) {
			try { mkdir(cur); } catch (e) { /* exists race */ }
		}
	}
};

function uniq_tail() {
	const c = clock();
	return int((c[1] / 1000) % 1000000);
};

export function wstat(path, content) {
	const tmp = path + '.tmp.' + uniq_tail();
	writefile(tmp, content);
	rename(tmp, path);
};

export function wjson(path, obj) {
	wstat(path, sprintf('%.J', obj) + '\n');
};

export function rjson(path) {
	if (!access(path))
		return null;
	let raw = null;
	try { raw = readfile(path); } catch (e) { raw = null; }
	if (raw == null || !length(trim(raw)))
		return null;
	try { return json(raw); } catch (e) { return null; }
};

/* ── registry (daemons.json) ────────────────────────────────────────────── */

function empty_doc() {
	return { schema: 1, boot: boot_epoch(), updated: time(), daemons: {} };
};

export function reg_load() {
	const raw = rjson(REG_PATH);
	if (raw == null || type(raw) !== 'object' || type(raw.daemons) !== 'object')
		return empty_doc();
	if (int(raw.boot) !== boot_epoch())
		return empty_doc();   /* reboot voids every pid identity */
	return raw;
};

export function reg_save(doc) {
	doc.schema = 1;
	doc.boot = boot_epoch();
	doc.updated = time();
	mkdir_p(RUN_DIR);
	wjson(REG_PATH, doc);
};

/* Register (or refresh) one managed instance. info = { kind, pid, start,
 * started?, exe?, script?, arg?, hb?, note? }. start is REQUIRED — callers
 * take it from proc_info()/find_daemons(), never guess. */
export function reg_set(name, info) {
	name = '' + name;
	if (!length(name) || info == null || type(info) !== 'object')
		return false;
	const start = int(info.start);
	if (!(start > 0) || !(int(info.pid) > 1))
		return false;
	const doc = reg_load();
	doc.daemons[name] = {
		name: name,
		kind: (info.kind != null) ? ('' + info.kind) : 'daemon',
		pid: int(info.pid),
		start: start,
		started: (int(info.started) > 0) ? int(info.started) : (boot_epoch() + int(start / HZ)),
		exe: (info.exe != null) ? ('' + info.exe) : null,
		script: (info.script != null) ? ('' + info.script) : null,
		arg: (info.arg != null) ? ('' + info.arg) : null,
		hb: (int(info.hb) > 0) ? int(info.hb) : time(),
		note: (info.note != null) ? ('' + info.note) : null
	};
	reg_save(doc);
	return true;
};

export function reg_get(name) {
	const doc = reg_load();
	return (type(doc.daemons['' + name]) === 'object') ? doc.daemons['' + name] : null;
};

export function reg_del(name) {
	const doc = reg_load();
	if (doc.daemons['' + name] == null)
		return false;
	delete doc.daemons['' + name];
	reg_save(doc);
	return true;
};

/* Heartbeat touch — only refreshes an EXISTING entry, never resurrects one. */
export function reg_hb(name) {
	const doc = reg_load();
	const e = doc.daemons['' + name];
	if (e == null)
		return false;
	e.hb = time();
	reg_save(doc);
	return true;
};

/* Drop entries whose identity is dead (dead pid, reused pid, stale boot). */
export function reg_gc() {
	const doc = reg_load();
	let dropped = 0;
	for (let name in doc.daemons) {
		if (!entry_alive(doc.daemons[name])) {
			delete doc.daemons[name];
			dropped++;
		}
	}
	if (dropped)
		reg_save(doc);
	return dropped;
};

/* Registry liveness by name (entry_alive on the stored identity). */
export function reg_alive(name) {
	return entry_alive(reg_get(name));
};

/* Self-registration of a script daemon (Ф1.4b): the identity is the CALLER's
 * own (pid, starttime) — call once at daemon startup, then reg_hb(name) once
 * per main-loop cycle. Returns true when the entry exists. */
export function reg_self(name, script, kind, note) {
	const pid = self_pid();
	const st = proc_start(pid);
	if (!(pid > 1) || st == null || !(int(st) > 0))
		return false;
	return reg_set(name, {
		pid: pid,
		start: st,
		script: (script != null) ? ('' + script) : null,
		kind: (kind != null) ? ('' + kind) : 'script',
		note: (note != null) ? ('' + note) : 'owner'
	});
};

/* Build a registry-ready info from a live scan result / proc_info. */
export function reg_info_from(found, extra) {
	const info = {
		pid: int(found.pid),
		start: int(found.start),
		started: int(found.started) || (boot_epoch() + int(found.start / HZ)),
		exe: (found.exe != null) ? ('' + found.exe) : null
	};
	if (extra != null && type(extra) === 'object')
		for (let k in extra)
			info[k] = extra[k];
	return info;
};

/* ── high-level owned operations (CLI runners + daemons call these) ─────── */

export function basename(p) {
	return basename_of(p);
};

/* Ownership-grade mosdns stop (audit 11): registry identity + the instance
 * whose -c argument is OUR config (or candidate). A FOREIGN mosdns is left
 * alone. Replaces "pidof mosdns && kill $(pidof mosdns)". */
export function mosdns_stop() {
	const CONF = RUN_DIR + '/multidns/mosdns.yaml';
	/* Candidate keeps the .yaml extension (mosdns parses by extension, ч.150). */
	const CAND = RUN_DIR + '/multidns/mosdns.candidate.yaml';
	const spec = { exe: '/usr/bin/mosdns', arg: [ CONF, CAND ] };
	const res = kill_matched(spec, 5000);
	/* Registry identity as the belt-and-suspenders path (the process may have
	 * been started with an older conf path). */
	const e = reg_get('mosdns');
	if (e != null && entry_alive(e)) {
		if (kill_entry(e, 5000))
			push(res.killed, e.pid);
		else
			push(res.failed, e.pid);
	}
	reg_del('mosdns');
	/* Wait for the sockets to actually release (issue #8): the next start
	 * rebinds immediately; 10 × 1 s is only the pathological ceiling. */
	for (let i = 0; i < 10; i++) {
		if (!length(find_daemons(spec)))
			break;
		sleep(1000);
	}
	const pidf = RUN_DIR + '/multidns/mosdns.pid';
	system('rm -f ' + pidf + ' 2>/dev/null');
	res.ok = !length(res.failed);
	return res;
};

/* Parental-control DNS filter instances (audit 34): stop every dnsmasq with
 * an identity file under dir (default /var/run/homeproxy/dnsf) — identity
 * verified; a legacy text pidfile is killed only when /proc still shows a
 * dnsmasq started from OUR -C conf. */
export function dnsf_stop(dir) {
	dir = (dir != null && length('' + dir)) ? '' + dir : (RUN_DIR + '/dnsf');
	const res = { ok: true, killed: [], failed: [], skipped: 0, dir: dir };
	const fd = popen('ls -1 ' + dir + ' 2>/dev/null');
	const listing = fd ? (fd.read('all') || '') : '';
	if (fd)
		fd.close();
	for (let line in split(listing, '\n')) {
		const f = trim(line);
		if (!length(f))
			continue;
		if (substr(f, length(f) - 9) === '.pid.json') {
			const e = rjson(dir + '/' + f);
			if (e != null && type(e) === 'object' && int(e.pid) > 1) {
				const target = { pid: int(e.pid), start: int(e.start), exe: 'dnsmasq' };
				if (kill_entry(target, 3000))
					push(res.killed, e.pid);
				else
					push(res.failed, e.pid);
			} else
				res.skipped++;
			continue;
		}
		if (substr(f, length(f) - 4) === '.pid') {
			const raw = trim(readfile(dir + '/' + f) || '');
			const pid = int(raw) || 0;
			if (pid < 2) {
				res.skipped++;
				continue;
			}
			const info = proc_info(pid);
			const conf = dir + '/' + substr(f, 0, length(f) - 4) + '.conf';
			if (info != null && info.exe != null && basename_of(info.exe) === 'dnsmasq' &&
			    index(info.cmdline, conf) >= 0) {
				if (kill_entry({ pid: pid, start: info.start }, 3000))
					push(res.killed, pid);
				else
					push(res.failed, pid);
			} else
				res.skipped++;   /* stale/reused pid — NOT ours, never touched */
		}
	}
	res.ok = !length(res.failed);
	return res;
};

/* Sanctioned kill-by-match for shell callers: `kill_if <exe|script:NAME> [arg]`.
 * The ONLY by-anything matching this project allows — exact exe/script plus
 * an optional exact cmdline element, never a substring sweep (audit 36). */
export function kill_if(what, arg) {
	const spec = {};
	if (what == null || !length('' + what))
		return { ok: false, error: 'usage: kill_if <exe|script:NAME.uc> [arg]' };
	if (substr('' + what, 0, 7) === 'script:')
		spec.script = substr('' + what, 7);
	else
		spec.exe = '' + what;
	if (arg != null && length('' + arg))
		spec.arg = '' + arg;
	const res = kill_matched(spec, 3000);
	res.ok = !length(res.failed);
	res.spec = spec;
	return res;
};

/* Registry refresh: drop dead identities, merge identities of the known
 * daemon set scanned from /proc. */
export function scan_registry() {
	const doc = reg_load();
	for (let name in doc.daemons)
		if (!entry_alive(doc.daemons[name]))
			delete doc.daemons[name];
	const known = [
		{ name: 'core', kind: 'core', spec: { exe: 'hiddify-core' } },
		{ name: 'core', kind: 'core', spec: { exe: 'sing-box' } },
		{ name: 'core', kind: 'core', spec: { exe: 'sing-box-core' } },
		{ name: 'mosdns', kind: 'dns', spec: { exe: '/usr/bin/mosdns' } },
		{ name: 'nfqws2', kind: 'dpi', spec: { exe: 'nfqws2' } },
		{ name: 'ciadpi', kind: 'dpi', spec: { exe: 'ciadpi' } },
		{ name: 'tgws_go', kind: 'tgws', spec: { exe: 'tg-ws-proxy-go' } },
		{ name: 'tgws_rs', kind: 'tgws', spec: { exe: 'tg-ws-proxy-rs' } },
		{ name: 'sni_sniffer', kind: 'automation', spec: { exe: 'sni_sniffer' } },
		{ name: 'probe_pool', kind: 'automation', spec: { exe: 'probe_pool' } },
		{ name: 'automation', kind: 'script', spec: { script: 'automation.uc' } },
		{ name: 'telegram_bot', kind: 'script', spec: { script: 'telegram.uc' } },
		{ name: 'control', kind: 'script', spec: { script: 'control_engine.uc' } },
		{ name: 'multidns', kind: 'script', spec: { script: 'multidns.uc' } },
		{ name: 'urltest_watchdog', kind: 'script', spec: { script: 'urltest_watchdog.uc' } },
		{ name: 'zapret_autopilot', kind: 'script', spec: { script: 'zapret_autopilot.uc' } },
		{ name: 'hotswap', kind: 'script', spec: { script: 'hotswap.uc' } },
		{ name: 'metrics', kind: 'script', spec: { script: 'metrics.uc' } }
	];
	for (let item in known) {
		/* for-in over an array yields ELEMENTS (lesson 20) — item IS the
		 * known-daemon record, never an index. */
		const found = find_daemons(item.spec);
		if (!length(found))
			continue;
		/* Multiple instances (test engines, several bridges): the registry
		 * keeps the FIRST, the rest go into extra_pids for observation. */
		const info = reg_info_from(found[0], { kind: item.kind });
		const prev = doc.daemons[item.name];
		if (prev != null && entry_alive(prev)) {
			/* Owner-registered entry (reg_self / a spawn that registered its
			 * child): refresh the identity facts ONLY — the owner keeps
			 * script/kind/note and its own heartbeat cadence. Same-name
			 * multi-spec records (core: hiddify / sing-box / sing-box-core)
			 * must not be re-pointed by ANOTHER spec's stray match. */
			const same_bin = (prev.exe == null) || (info.exe == null) ||
				(basename_of(prev.exe) === basename_of(info.exe));
			if (same_bin || int(prev.pid) === int(info.pid)) {
				prev.pid = info.pid;
				prev.start = info.start;
				prev.started = info.started;
				if (info.exe != null && !length('' + (prev.exe || '')))
					prev.exe = info.exe;
			}
		} else {
			doc.daemons[item.name] = {
				name: item.name, kind: info.kind, pid: info.pid, start: info.start,
				started: info.started, exe: info.exe,
				script: (item.spec.script != null) ? item.spec.script : null,
				arg: null, hb: time(), note: 'scanned'
			};
		}
		if (length(found) > 1) {
			const extras = [];
			for (let i = 1; i < length(found); i++)
				push(extras, found[i].pid);
			doc.daemons[item.name].extra_pids = extras;
		} else if (doc.daemons[item.name].extra_pids != null)
			delete doc.daemons[item.name].extra_pids;
	}
	reg_save(doc);
	return doc;
};

export function registry_status() {
	const doc = reg_load();
	const out = { boot: doc.boot, updated: doc.updated, daemons: {} };
	for (let name in doc.daemons) {
		const e = doc.daemons[name];
		e.alive = entry_alive(e);
		out.daemons[name] = e;
	}
	return out;
};

/* Mandatory selftest (KB rules): every primitive, honestly. The CLI runner
 * turns .ok into the exit code. */
export function selftest() {
	const checks = [];
	const check = function(name, ok, detail) {
		push(checks, { check: name, ok: ok, detail: detail || null });
		return ok;
	};
	const me = proc_info(self_pid());
	check('proc_info_self', me != null && int(me.pid) > 1 && length(me.cmdline) > 0,
		(me != null) ? sprintf('%d args', length(me.cmdline)) : 'null');
	check('boot_epoch', boot_epoch() > 0, sprintf('%d', boot_epoch()));
	const st = (me != null) ? proc_start(me.pid) : null;
	check('proc_start', st != null && int(st) > 0, sprintf('%d', int(st) || 0));
	check('entry_alive_self', entry_alive({ pid: me.pid, start: me.start, exe: 'ucode' }), null);
	check('entry_alive_reject_reuse', entry_alive({ pid: me.pid, start: int(me.start) + 99999 }) === false, null);
	const found = find_daemons({ script: 'pmgr_cli.uc' });
	let saw_self = false;
	for (let e in found)
		if (int(e.pid) === int(me.pid))
			saw_self = true;
	check('find_daemons_script', saw_self, sprintf('%d hits', length(found)));
	const found2 = find_daemons({ exe: '/usr/bin/ucode', arg: '/etc/homeproxy/scripts/pmgr_cli.uc' });
	saw_self = false;
	for (let e in found2)
		if (int(e.pid) === int(me.pid))
			saw_self = true;
	check('find_daemons_exe_arg', saw_self, sprintf('%d hits', length(found2)));
	const p1 = proc_info(1);
	check('proc_info_pid1', p1 != null && int(p1.pid) === 1, (p1 != null && p1.exe != null) ? p1.exe : 'null');
	/* registry roundtrip (real registry, unique test name, cleaned up) */
	const rname = 'selftest-' + uniq_tail();
	const fake = { pid: 39999, start: 1, kind: 'test', exe: '/nonexistent', hb: time() };
	check('reg_set', reg_set(rname, fake) === true, null);
	const back = reg_get(rname);
	check('reg_get_roundtrip', back != null && int(back.pid) === 39999 && int(back.start) === 1, null);
	check('reg_alive_dead', reg_alive(rname) === false, null);
	check('reg_del', reg_del(rname) === true && reg_get(rname) == null, null);
	/* identity kill of a spawned child */
	system('sleep 8 & echo $! > /tmp/pmgr_st_child.pid');
	const cpid = int(trim(readfile('/tmp/pmgr_st_child.pid')) || 0);
	const cs = (cpid > 1) ? proc_start(cpid) : null;
	const killed = (cs != null) && kill_entry({ pid: cpid, start: cs }, 2000);
	check('kill_entry_child', killed === true, sprintf('pid %d', cpid));
	system('rm -f /tmp/pmgr_st_child.pid');
	/* Ф1.4b: arg_all / neg matching + the subtree reaper. A `sh -c` chain
	 * with TWO commands (a single command would be exec-optimized away and
	 * lose the shell parent) — the sh is matched by exe+arg_all, its `sleep`
	 * child is reachable ONLY through the tree walk. */
	system('sh -c "sleep 30; sleep 30" & echo $! > /tmp/pmgr_st_tree.pid');
	const tpid = int(trim(readfile('/tmp/pmgr_st_tree.pid')) || 0);
	const tinfo = (tpid > 1) ? proc_info(tpid) : null;
	const targs = (tinfo != null && length(tinfo.cmdline) > 2) ? tinfo.cmdline[2] : null;
	check('find_arg_all', (tinfo != null && targs != null &&
		length(find_daemons({ exe: tinfo.exe, arg_all: [ '-c', targs ] })) > 0),
		(tinfo != null) ? sprintf('pid %d exe %s', tpid, tinfo.exe) : 'spawn failed');
	check('find_neg_excludes', (targs != null &&
		length(find_daemons({ exe: (tinfo != null) ? tinfo.exe : '/bin/sh',
			arg_all: [ '-c', targs ], neg: [ '-c' ] })) === 0), null);
	const tr = (targs != null)
		? kill_tree({ exe: tinfo.exe, arg_all: [ '-c', targs ] }, 2000)
		: { killed: [] };
	/* Zombie window: a killed child may keep its /proc entry until the
	 * parent reaps it — entry_alive() already treats state Z as dead. */
	check('kill_tree', (targs != null && length(tr.killed) >= 2 &&
		!entry_alive({ pid: tpid, start: tinfo.start, exe: tinfo.exe })),
		sprintf('killed %d', length(tr.killed)));
	system('rm -f /tmp/pmgr_st_tree.pid');
	let all_ok = true;
	for (let c in checks)
		if (!c.ok)
			all_ok = false;
	return { ok: all_ok, checks: checks };
};
