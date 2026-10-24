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
 */

'use strict';

import { access, readfile, writefile, rename, mkdir, rmdir, stat, unlink, popen } from 'fs';

const CORE_MGMT = '/usr/share/homeproxy/scripts/core_mgmt.uc';
const RUN_FILE = '/var/run/homeproxy/core_install.json';
const LOCK_DIR = '/var/run/homeproxy/core_install.lock';
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

/* Run one core_mgmt.uc action with a HARD timeout. system(cmd, timeout)
 * kills the direct child on expiry; the kill sweep below reaps ucode
 * stragglers the shell left behind (busybox has no timeout(1) and a hung
 * installer must never wedge the runner — lesson of the 2026-10-24 live
 * wedge: an installer's health-check blocked on the init flock forever). */
function run_action(action, args, timeout_ms) {
	const outfile = '/tmp/hp_ci_stage.json';
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
	const rc = system(full, caps[action] || timeout_ms || 420000);
	if (rc != 0) {
		/* system() kills only the DIRECT child — the installer (a grandchild)
		 * survives as an orphan and keeps spawning service starts (live
		 * 2026-10-24: an orphaned lite installer re-ran start/rollback loops
		 * for minutes). Reap the whole chain, a few rounds to catch spawns. */
		for (let round = 0; round < 3; round++) {
			system("ps w | grep -E 'sing-box-extended-lite-installer|rc.common /etc/init.d/homeproxy|core_mgmt.uc (prepare_install|download_pkg|install_pkg|install_kmods)' | grep -v grep | awk '{print $1}' | xargs -r kill -9 2>/dev/null");
			system('sleep 1');
		}
		return { error: `stage ${action} failed or timed out (rc=${rc})` };
	}
	const raw = trim(readfile(outfile) || '');
	let out;
	try { out = json(raw); } catch (e) { out = null; }
	return (out && type(out) == 'object') ? out : { error: `no valid JSON from: ${action}` };
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

	const started = time();
	wstatus({ running: true, core: core, variant: variant, stage: 'prepare', started: started, ts: time() });

	const prep = run_action('prepare_install', [core, variant]);
	if (prep.error || prep.result === false) {
		wstatus({ running: false, ok: false, core: core, stage: 'prepare', error: prep.error || 'prepare failed', started: started, finished: time() });
		rmdir(LOCK_DIR);
		return;
	}

	const dl_url = prep.dl_url || prep.installer_url;
	if (!dl_url || !prep.tmp_path) {
		wstatus({ running: false, ok: false, core: core, stage: 'prepare', error: 'prepare returned no download URL', started: started, finished: time() });
		rmdir(LOCK_DIR);
		return;
	}

	wstatus({ running: true, core: core, variant: variant, stage: 'download', note: prep.note || '', started: started, ts: time() });
	const dl = run_action('download_pkg', [core, dl_url, prep.tmp_path]);
	if (!dl.result) {
		wstatus({ running: false, ok: false, core: core, stage: 'download', error: dl.error || 'download failed', started: started, finished: time() });
		rmdir(LOCK_DIR);
		return;
	}

	wstatus({ running: true, core: core, variant: variant, stage: 'install', note: prep.note || '', started: started, ts: time() });
	const inst = run_action('install_pkg', [core, prep.tmp_path, prep.pkg_manager]);
	if (!inst.result) {
		/* Recovery: the binary swap may have happened before the installer
		 * died (health-check hang) — detect a valid lite/extended build on
		 * disk and still finish the job. */
		const note = (core === 'singbox-lite') ? lite_recovery_note() : null;
		if (note) {
			wstatus({ running: true, core: core, variant: variant, stage: 'kmods', started: started, ts: time() });
			const kr = run_action('install_kmods', [prep.pkg_manager]);
			wstatus({
				running: false, ok: true, core: core, stage: 'done',
				started: started, finished: time(), note: note,
				warning: (kr && kr.result === true) ? null : 'kmod install failed',
				kmods_ok: (kr && kr.result === true) ? true : false
			});
			rmdir(LOCK_DIR);
			return;
		}
		wstatus({ running: false, ok: false, core: core, stage: 'install', error: inst.error || 'installation failed', started: started, finished: time() });
		rmdir(LOCK_DIR);
		return;
	}

	wstatus({ running: true, core: core, variant: variant, stage: 'kmods', started: started, ts: time() });
	const kmods = run_action('install_kmods', [prep.pkg_manager]);
	/* kmod failure is not fatal: usually already present from a previous core */

	wstatus({
		running: false,
		ok: true,
		core: core,
		stage: 'done',
		started: started,
		finished: time(),
		note: inst.note || null,
		warning: inst.warning || null,
		kmods_ok: (kmods && kmods.result === true) ? true : false
	});
	rmdir(LOCK_DIR);
}

main();
