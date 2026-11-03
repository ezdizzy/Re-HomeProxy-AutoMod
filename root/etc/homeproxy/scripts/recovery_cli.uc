#!/usr/bin/ucode
/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy — Recovery Manager CLI runner + daemon (Ф2.3, ч.166).
 *
 * Thin SCRIPT wrapper over the recovery.uc module (урок 178: a ucode module
 * with `export` cannot be executed directly). Commands (ARGV[0]):
 *   run        — resident daemon loop (procd instance "recovery"): one tick
 *                every 15 s — collects findings from the SENTINEL and HEALTH
 *                documents (no imports of those modules — documents only),
 *                settles recovery campaigns, executes at most ONE action per
 *                tick through the opman door (kind 'repair'), honors the
 *                manual-freeze and apply gates, emits every decision to the
 *                Event Bus (src='recovery');
 *   once       — one full compute_and_recover + JSON summary (deploy/acceptance);
 *   status     — print the stored recovery document as-is;
 *   selftest   — module selftest (pure logic, fake inputs) → exit code.
 *
 * Independence (same principle as the Sentinel, Ф2.2): recovery.uc imports
 * ONLY leaf modules (statestore/opman/eventbus/pmgr) — a broken health or
 * sentinel deploy cannot take the coordinator down with the guarded. While
 * the coordinator is ALIVE the Sentinel stops executing repairs itself and
 * only detects (its findings are picked up here); a dead coordinator is
 * repaired by procd (respawn) and, in the worst case, the Sentinel falls
 * back to one-shot repairs.
 *
 * Load profile: a light tick is 3-4 readfile's; the ops journal (one fork)
 * is read only when there is something to execute or once per ~minute
 * (apply discovery). Executions are synchronous and may hold a tick up to
 * SVC_START_TIMEOUT (150 s) — same pattern as the Sentinel repairs.
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
	compute_and_recover, selftest, RECOVERY_PATH
} from '/etc/homeproxy/scripts/recovery.uc';
import { read_state as ss_read_state } from '/etc/homeproxy/scripts/statestore.uc';

const RUN_DIR = '/var/run/homeproxy';
const LOG_FILE = RUN_DIR + '/recovery.log';
const MAX_LOG_BYTES = 51200;

/* ── logging (best-effort, bounded — same pattern as sentinel_cli.uc) ───── */

function log(msg) {
	const line = '[' + sprintf('%d', time()) + '] [RECOVERY] ' + msg + '\n';
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

const TICK_MS = 15000;

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
	reg_self('recovery', 'recovery_cli.uc', 'recovery', 'Ф2.3 Recovery Manager (координатор восстановления)');
	log('recovery started (pid ' + sprintf('%d', reg_self_pid()) + ')');
	let tick = 0;
	while (true) {
		try {
			const r = compute_and_recover({
				daemon_pid: reg_self_pid(),
				tick: tick,
				started: started
			});
			if (r.baseline)
				log('baseline written (no previous doc this boot): overall=' + r.data.overall);
			else if (length(r.events))
				log('events: ' + sprintf('%J', r.events));
			if (r.executed != null)
				log('executed: ' + sprintf('%J', r.executed));
			reg_hb('recovery');
			tick++;
		} catch (e) {
			log('tick failed (non-fatal): ' + e);
		}
		sleep(TICK_MS);
	}
};

/* ── dispatch ───────────────────────────────────────────────────────────── */

const cmd = ARGV[0] || '';
let rc = 0;

if (cmd === 'run') {
	run_daemon();
} else if (cmd === 'once') {
	const r = compute_and_recover({ daemon_pid: reg_self_pid(), tick: 1 });
	printf('%.J\n', { overall: r.data.overall, baseline: r.baseline,
		events: r.events, executed: r.executed, keys: r.data.keys,
		blocked: r.data.blocked, manual_queue: r.data.manual_queue,
		history: r.data.history });
} else if (cmd === 'status') {
	const rd = ss_read_state(RECOVERY_PATH);
	if (rd == null || rd.data == null) {
		printf('%.J\n', { ok: false, error: 'no recovery document (daemon never ran)' });
		rc = 1;
	} else {
		printf('%.J\n', { ok: true, meta: rd.meta, recovery: rd.data });
	}
} else if (cmd === 'selftest') {
	const r = selftest();
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else {
	printf('%.J\n', { ok: false, error: 'usage: recovery_cli.uc run|once|status|selftest' });
	rc = 1;
}

exit(rc);
