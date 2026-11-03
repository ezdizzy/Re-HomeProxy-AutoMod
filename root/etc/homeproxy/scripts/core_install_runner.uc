#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * core_install_runner.uc — BACKGROUND core install driver (issue: a core
 * install used to run SYNCHRONOUSLY under the UI request: download_pkg
 * (up to 300 s for a ~46-95 MB package) + install_pkg (up to 300 s) froze
 * the tab for minutes and made the whole app look dead; a page reload in
 * the middle lost all progress and invited double installs).
 *
 * Spawned detached by rpcd (core_install_start). Drives the FULL flow —
 * prepare → download → install → kmods — reusing core_mgmt.uc actions
 * verbatim (one ucode invocation per stage), and reports every stage into
 * /var/run/homeproxy/core_install.json for core_install_status polling.
 * The status file survives page reloads, so the UI resumes watching an
 * already-running install. A mkdir lock prevents concurrent installs; a
 * stale lock (runner killed mid-way) self-heals after 40 minutes.
 *
 * Ф1.4b (audit 36): every stage process carries a recorded IDENTITY — the
 * stage spawns detached with its pid written to a pidfile, (pid, starttime,
 * exe) is snapshotted into core_install_stage.json, and the whole install
 * runs as an opman operation (kind core_install) in the journal. The old
 * `ps w | grep -E … | xargs kill -9` reaper matched SUBSTRINGS and killed
 * rc.common shells it did not own; the reaper now walks the stage's
 * descendant tree (pmgr kill_tree, identity re-verified per signal) and
 * only sweeps an rc.common running OUR init script inside the stage's time
 * window.
 *
 * Lesson 167 honored: the 2-arg system(cmd, timeout) is instant-kill on
 * this build — the stage runs in a DETACHED chain (rc collected into a
 * rcfile, pid into a pidfile) and the runner polls the rcfile with a
 * deadline instead of ever passing a timeout to system().
 */

'use strict';

import { access, readfile, writefile, rename, mkdir, rmdir, stat, unlink, popen } from 'fs';
import { begin as op_begin, heartbeat as op_heartbeat, stage as op_stage, finish as op_finish } from '/etc/homeproxy/scripts/opman.uc';
import { kill_tree as pm_kill_tree, kill_entry as pm_kill_entry, find_daemons as pm_find, proc_info as pm_proc_info } from '/etc/homeproxy/scripts/pmgr.uc';

const CORE_MGMT = '/usr/share/homeproxy/scripts/core_mgmt.uc';
const RUN_FILE = '/var/run/homeproxy/core_install.json';
const LOCK_DIR = '/var/run/homeproxy/core_install.lock';
const STAGE_FILE = '/var/run/homeproxy/core_install_stage.json';
const STALE_SEC = 2400;

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

/* Atomic write (temp + mv): a UI poller must never read a truncated file. */
function wstatus(o) {
	mkdir('/var/run/homeproxy');
	const tmp = RUN_FILE + '.tmp';
	writefile(tmp, sprintf('%.J', o) + '\n');
	rename(tmp, RUN_FILE);
}

/* Stage identity file — the (pid, start, exe) anchor every kill goes by. */
function wstage(o) {
	mkdir('/var/run/homeproxy');
	const tmp = STAGE_FILE + '.tmp';
	writefile(tmp, sprintf('%.J', o) + '\n');
	rename(tmp, STAGE_FILE);
}

/* Identity-only reaper (audit 36):
 *   1. kill_tree from the stage root (ucode CORE_MGMT <action>) — covers the
 *      whole in-tree chain: wget/apk/tar, the lite installer sh, the service
 *      restarts it spawned. Every signal re-verifies (pid, start).
 *   2. Escapees by exact identity: a busybox rc.common running OUR init
 *      script — killed only when its start time falls INSIDE the stage
 *      window (a concurrent user restart predating the stage is untouched).
 *   3. Catch-up rounds for late spawns (same identity rules). */
function reap_stage(action, stage_started) {
	const spec = { exe: '/usr/bin/ucode', arg_all: [ CORE_MGMT, action ] };
	const rc_spec = { exe: '/bin/busybox', arg_all: [ '/etc/rc.common', '/etc/init.d/homeproxy' ] };
	for (let round = 0; round < 3; round++) {
		pm_kill_tree(spec, 3000);
		const found = pm_find(rc_spec);
		for (let e in found) {
			if (int(e.started) >= int(stage_started) - 5)
				pm_kill_entry({ pid: e.pid, start: e.start, exe: e.exe }, 3000);
		}
		if (!length(pm_find(spec)) && !length(pm_find(rc_spec)))
			break;
		sleep(1000);
	}
}

/* Run one core_mgmt.uc action as a DETACHED chain with a hard deadline.
 * Returns the stage's JSON result, or { error } after reaping by identity. */
function run_action(action, args, timeout_ms, op_id) {
	const outfile = '/tmp/hp_ci_stage.json';
	const rcfile = '/tmp/hp_ci_stage.rc';
	const pidfile = '/tmp/hp_ci_stage.pid';
	system(`rm -f ${shellquote(outfile)} ${shellquote(rcfile)} ${shellquote(pidfile)} 2>/dev/null; true`);
	let full = `ucode ${shellquote(CORE_MGMT)} ${action}`;
	for (let a in (args || []))
		full += ' ' + shellquote(a);
	/* 1000>&-: never inherit a procd_lock fd from the spawning chain */
	full += ` >${shellquote(outfile)} 2>/dev/null 1000>&-`;
	/* 900 s: the lite installer downloads its own ~46 MB tarball INSIDE the
	 * install stage (a slow uplink needs minutes), then swaps, restarts the
	 * service and runs its health-check. 420 s killed a healthy run on a
	 * throttled link (2026-10-24) — give it headroom; the stage-level caps
	 * inside core_mgmt (300 s wget) still bound each individual fetch.
	 * download_pkg: core_mgmt's gh_fetch runs TWO wget attempts (GitHub 300 s
	 * + mirror fallback 300 s) — a 420 s runner cap killed the mirror attempt
	 * mid-flight on a slow link and left a partial tmp file (audit 2026-10-25);
	 * 650 s covers the full budget. */
	const caps = { download_pkg: 650000, install_pkg: 900000 };
	const cap = caps[action] || timeout_ms || 420000;
	/* Detached chain: the stage runs in background inside the subshell, $!
	 * (the ucode pid) lands in the pidfile as its identity anchor, wait
	 * collects the rc into the rcfile. system() returns immediately. */
	system('( ' + full + ' & echo $! > ' + shellquote(pidfile) +
		'; wait $!; echo $? > ' + shellquote(rcfile) + ' ) </dev/null &');
	const stage_started = time();
	let spid = 0;
	for (let i = 0; i < 30 && !spid; i++) {
		if (access(pidfile))
			spid = int(trim(readfile(pidfile) || '') || 0);
		if (!spid)
			sleep(100);
	}
	const sinfo = (spid > 1) ? pm_proc_info(spid) : null;
	wstage({
		stage: action, op_id: op_id || null, started: stage_started,
		pid: sinfo ? sinfo.pid : spid, start: sinfo ? sinfo.start : 0,
		exe: sinfo ? sinfo.exe : null
	});
	const deadline = time() + int(cap / 1000) + 5;
	while (true) {
		if (access(rcfile))
			break;
		if (time() >= deadline) {
			reap_stage(action, stage_started);
			return { error: `stage ${action} failed or timed out (deadline ${int(cap / 1000)}s) — orphans reaped by identity` };
		}
		if (op_id) {
			try { op_heartbeat(op_id); } catch (e) { /* journal hiccup — the poll continues */ }
		}
		sleep(500);
	}
	const rc = int(trim(readfile(rcfile) || '') || 0);
	const raw = trim(readfile(outfile) || '');
	let out;
	try { out = json(raw); } catch (e) { out = null; }
	return (out && type(out) == 'object') ? out : { error: `no valid JSON from: ${action} (rc=${rc})` };
}

/* Post-failure recovery: if the binary on disk IS a valid lite build, the
 * swap already happened (only the installer's health-check/rollback died) —
 * start the service and report success with an honest note (same contract
 * as core_mgmt install_pkg's own recovery). */
function lite_recovery_note() {
	const fd = popen('/usr/bin/sing-box version 2>/dev/null');
	const vout = fd ? fd.read('all') : '';
	if (fd) fd.close();
	const lite_now = !!match(vout, /-extended-/) &&
		!match(vout, /with_gvisor/) && !match(vout, /with_tailscale/);
	if (!lite_now)
		return null;
	system('/etc/init.d/homeproxy start >/dev/null 2>&1');
	return 'installed; the installer was killed after the binary swap (health-check hang) — the service was restarted';
}

function main() {
	/* ARGV[0] = the first script argument (ucode convention, same as
	 * core_mgmt.uc's `const action = ARGV[0]`). */
	const core = ARGV[0];
	const variant = ARGV[1] || '';

	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		wstatus({ running: false, ok: false, error: 'illegal core', finished: time() });
		return;
	}

	/* One install at a time. mkdir() is atomic; a stale lock (the runner was
	 * killed mid-install) self-heals after STALE_SEC. */
	if (!mkdir(LOCK_DIR)) {
		const st = stat(LOCK_DIR);
		if (st && (time() - st.mtime) > STALE_SEC) {
			rmdir(LOCK_DIR);
			if (!mkdir(LOCK_DIR)) {
				wstatus({ running: false, ok: false, error: 'another install is already running', finished: time() });
				return;
			}
		} else {
			wstatus({ running: false, ok: false, error: 'another install is already running', finished: time() });
			return;
		}
	}

	/* The journal operation (Ф1.4b): the install becomes visible in
	 * app_op_list with a live heartbeat; a runner death self-heals via the
	 * 120 s lease. A busy journal never blocks the install — the mkdir lock
	 * above is the real serializer, the op is the record. */
	const opr = op_begin('core_install', 'install ' + core + (length(variant) ? ' ' + variant : ''),
		'core_install_runner', 'background core install');
	const op_id = (opr && opr.ok) ? opr.op.op_id : null;

	try { unlink(STAGE_FILE); } catch (e) { /* first run */ }

	const started = time();
	wstatus({ running: true, core: core, variant: variant, stage: 'prepare', started: started, ts: time(), op_id: op_id });
	if (op_id) {
		try { op_stage(op_id, 'prepare'); } catch (e) { /* journal hiccup */ }
	}

	const prep = run_action('prepare_install', [core, variant], null, op_id);
	if (prep.error || prep.result === false) {
		wstatus({ running: false, ok: false, core: core, stage: 'prepare', error: prep.error || 'prepare failed', started: started, finished: time(), op_id: op_id });
		if (op_id) {
			try { op_finish(op_id, false, false, 'prepare: ' + (prep.error || 'prepare failed')); } catch (e) { /* journal hiccup */ }
		}
		try { unlink(STAGE_FILE); } catch (e) { /* already gone */ }
		rmdir(LOCK_DIR);
		return;
	}

	const dl_url = prep.dl_url || prep.installer_url;
	if (!dl_url || !prep.tmp_path) {
		wstatus({ running: false, ok: false, core: core, stage: 'prepare', error: 'prepare returned no download URL', started: started, finished: time(), op_id: op_id });
		if (op_id) {
			try { op_finish(op_id, false, false, 'prepare returned no download URL'); } catch (e) { /* journal hiccup */ }
		}
		try { unlink(STAGE_FILE); } catch (e) { /* already gone */ }
		rmdir(LOCK_DIR);
		return;
	}

	wstatus({ running: true, core: core, variant: variant, stage: 'download', note: prep.note || '', started: started, ts: time(), op_id: op_id });
	if (op_id) {
		try { op_stage(op_id, 'download'); } catch (e) { /* journal hiccup */ }
	}
	const dl = run_action('download_pkg', [core, dl_url, prep.tmp_path], null, op_id);
	if (!dl.result) {
		wstatus({ running: false, ok: false, core: core, stage: 'download', error: dl.error || 'download failed', started: started, finished: time(), op_id: op_id });
		if (op_id) {
			try { op_finish(op_id, false, false, 'download: ' + (dl.error || 'download failed')); } catch (e) { /* journal hiccup */ }
		}
		try { unlink(STAGE_FILE); } catch (e) { /* already gone */ }
		rmdir(LOCK_DIR);
		return;
	}

	wstatus({ running: true, core: core, variant: variant, stage: 'install', note: prep.note || '', started: started, ts: time(), op_id: op_id });
	if (op_id) {
		try { op_stage(op_id, 'install'); } catch (e) { /* journal hiccup */ }
	}
	const inst = run_action('install_pkg', [core, prep.tmp_path, prep.pkg_manager], null, op_id);
	if (!inst.result) {
		/* Recovery: the binary swap may have happened before the installer
		 * died (health-check hang) — detect a valid lite/extended build on
		 * disk and still finish the job. */
		const note = (core === 'singbox-lite') ? lite_recovery_note() : null;
		if (note) {
			wstatus({ running: true, core: core, variant: variant, stage: 'kmods', started: started, ts: time(), op_id: op_id });
			if (op_id) {
				try { op_stage(op_id, 'kmods'); } catch (e) { /* journal hiccup */ }
			}
			const kr = run_action('install_kmods', [prep.pkg_manager], null, op_id);
			wstatus({
				running: false, ok: true, core: core, stage: 'done',
				started: started, finished: time(), note: note, op_id: op_id,
				warning: (kr && kr.result === true) ? null : 'kmod install failed',
				kmods_ok: (kr && kr.result === true) ? true : false
			});
			if (op_id) {
				try { op_finish(op_id, true, false, note); } catch (e) { /* journal hiccup */ }
			}
			try { unlink(STAGE_FILE); } catch (e) { /* already gone */ }
			rmdir(LOCK_DIR);
			return;
		}
		wstatus({ running: false, ok: false, core: core, stage: 'install', error: inst.error || 'installation failed', started: started, finished: time(), op_id: op_id });
		if (op_id) {
			try { op_finish(op_id, false, false, 'install: ' + (inst.error || 'installation failed')); } catch (e) { /* journal hiccup */ }
		}
		try { unlink(STAGE_FILE); } catch (e) { /* already gone */ }
		rmdir(LOCK_DIR);
		return;
	}

	wstatus({ running: true, core: core, variant: variant, stage: 'kmods', started: started, ts: time(), op_id: op_id });
	if (op_id) {
		try { op_stage(op_id, 'kmods'); } catch (e) { /* journal hiccup */ }
	}
	const kmods = run_action('install_kmods', [prep.pkg_manager], null, op_id);
	/* kmod failure is not fatal: usually already present from a previous core */

	const detail = join('; ', filter([inst.note || null, inst.warning || null], (x) => (x != null)));
	wstatus({
		running: false,
		ok: true,
		core: core,
		stage: 'done',
		started: started,
		finished: time(),
		note: inst.note || null,
		warning: inst.warning || null,
		kmods_ok: (kmods && kmods.result === true) ? true : false,
		op_id: op_id
	});
	if (op_id) {
		try { op_finish(op_id, true, false, detail); } catch (e) { /* journal hiccup */ }
	}
	try { unlink(STAGE_FILE); } catch (e) { /* already gone */ }
	rmdir(LOCK_DIR);
}

main();
