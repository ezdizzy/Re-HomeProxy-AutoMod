#!/usr/bin/ucode
/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy — Sentinel CLI runner + daemon (Ф2.2, ч.165).
 *
 * Thin SCRIPT wrapper over the sentinel.uc module (урок 178: a ucode module
 * with `export` cannot be executed directly). Commands (ARGV[0]):
 *   run        — resident daemon loop (procd instance "sentinel"): light pass
 *                (health freshness + configs, NO forks) every 30 s, full pass
 *                (service list / ops journal / registry) every 10th light tick
 *                (~5 min); repairs through the opman door, events to the bus;
 *   once       — one full compute_and_store + JSON summary (deploy/acceptance);
 *   status     — print the stored sentinel document as-is;
 *   selftest   — module selftest (pure logic, fake inputs) → exit code.
 *
 * Independence (A.1): the sentinel does NOT import health.uc — a broken health
 * deploy cannot take the guard down with the guarded. Its own liveness witness
 * is the ts of the document it writes every pass (RPC sentinel_status checks
 * it). All findings/events go to the Event Bus with src='sentinel'; every
 * repair emits an event; the loop-guard stops runaway auto-repairs.
 *
 * Adaptive load: light = readfile-only; full = ≤3 forks (service list, ls ops,
 * registry readfile) + blocking only during an actual repair. Full passes are
 * SKIPPED while MemAvailable < 48 MB (OOM edge, lesson 197) — light stays.
 *
 * ucode constraints honored: no hoisting (helpers above callers, lesson 126),
 * non-fatal wrapper while(true){try{main()}catch{log}} (lesson 126), fs only
 * after import, sleep() = MILLISECONDS, for-in arrays = elements, no 2-arg
 * system() (lesson 167).
 */

'use strict';

import { access, readfile, open, stat } from 'fs';
import { reg_self, reg_hb } from '/etc/homeproxy/scripts/pmgr.uc';
import {
	compute_and_store, selftest, SENTINEL_PATH,
	MEM_SKIP_KB, BOOT_GRACE_SEC, parse_meminfo_kb
} from '/etc/homeproxy/scripts/sentinel.uc';
import { read_state as ss_read_state } from '/etc/homeproxy/scripts/statestore.uc';

const RUN_DIR = '/var/run/homeproxy';
const LOG_FILE = RUN_DIR + '/sentinel.log';
const MAX_LOG_BYTES = 51200;

/* ── logging (best-effort, bounded — same pattern as health_cli.uc) ─────── */

function log(msg) {
	const line = '[' + sprintf('%d', time()) + '] [SENTINEL] ' + msg + '\n';
	try {
		if (access(LOG_FILE)) {
			let sz = 0;
			try { sz = stat(LOG_FILE).size || 0; } catch (e) { sz = 0; }
			if (sz > MAX_LOG_BYTES) {
				const tmp = LOG_FILE + '.tmp';
				system('tail -n 500 ' + LOG_FILE + ' > ' + tmp + ' 2>/dev/null; mv -f ' + tmp + ' ' + LOG_FILE);
			}
		}
		const fd = open(LOG_FILE, 'a');
		if (fd != null) {
			fd.write(line);
			fd.close();
		}
	} catch (e) { /* logging must never kill the daemon */ }
};

/* ── daemon loop ────────────────────────────────────────────────────────── */

const LIGHT_MS = 30000;    /* light pass every 30 s (no forks)          */
const FAST_MS = 15000;     /* incident: every 15 s                      */
const FULL_DIV_SLOW = 10;  /* full every 10th light tick (~5 мин)       */
const FULL_DIV_FAST = 2;   /* incident: full every 2nd tick (~30 с)     */
const DWELL_SEC = 300;     /* fast mode lingers 5 min after last non-ok */

function mem_available_kb() {
	return parse_meminfo_kb(readfile('/proc/meminfo'));
};

/* Own pid for the document (reg_self stores OUR (pid, start) already). */
function reg_self_pid() {
	const raw = readfile('/proc/self/stat');
	if (raw == null)
		return null;
	const m = match(raw, /^([0-9]+) \(/);
	return (m != null) ? int(m[1]) : null;
};

function run_daemon() {
	const started = time();
	reg_self('sentinel', 'sentinel_cli.uc', 'sentinel', 'Ф2.2 Sentinel (сторож здоровья)');
	log('sentinel started (pid ' + sprintf('%d', reg_self_pid()) + ')');
	let tick = 0;
	let full_countdown = 0;
	let fast_until = 0;
	while (true) {
		try {
			const fast = (time() < fast_until);
			/* First tick always full (baseline + expectations). */
			let full = (tick === 0) || (full_countdown <= 0);
			if (full && tick > 0 && mem_available_kb() < MEM_SKIP_KB) {
				full = false;
				log('full pass skipped: MemAvailable < 48 MB (OOM edge, lesson 197)');
				full_countdown = 1;
			}
			if (full)
				full_countdown = (fast ? FULL_DIV_FAST : FULL_DIV_SLOW);
			const r = compute_and_store({
				full: full,
				grace_until: started + BOOT_GRACE_SEC,
				daemon_pid: reg_self_pid()
			});
			full_countdown--;
			if (r.baseline)
				log('baseline written (no previous doc this boot): overall=' + r.data.overall);
			else if (length(r.events))
				log('events: ' + sprintf('%J', r.events));
			if (length(r.repairs))
				log('repairs: ' + sprintf('%J', r.repairs));
			if (r.data.overall !== 'ok')
				fast_until = time() + DWELL_SEC;
			reg_hb('sentinel');
			tick++;
		} catch (e) {
			log('tick failed (non-fatal): ' + e);
		}
		const fast_now = (time() < fast_until);
		sleep(fast_now ? FAST_MS : LIGHT_MS);
	}
};

/* ── dispatch ───────────────────────────────────────────────────────────── */

const cmd = ARGV[0] || '';
let rc = 0;

if (cmd === 'run') {
	run_daemon();
} else if (cmd === 'once') {
	const r = compute_and_store({ full: true, grace_until: 0, daemon_pid: reg_self_pid() });
	printf('%.J\n', { overall: r.data.overall, baseline: r.baseline,
		events: r.events, repairs: r.repairs, findings: r.data.findings,
		health_age: r.data.health_age, instances: r.data.instances });
} else if (cmd === 'status') {
	const rd = ss_read_state(SENTINEL_PATH);
	if (rd == null || rd.data == null) {
		printf('%.J\n', { ok: false, error: 'no sentinel document (daemon never ran)' });
		rc = 1;
	} else {
		printf('%.J\n', { ok: true, meta: rd.meta, sentinel: rd.data });
	}
} else if (cmd === 'selftest') {
	const r = selftest();
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else {
	printf('%.J\n', { ok: false, error: 'usage: sentinel_cli.uc run|once|status|selftest' });
	rc = 1;
}

exit(rc);
