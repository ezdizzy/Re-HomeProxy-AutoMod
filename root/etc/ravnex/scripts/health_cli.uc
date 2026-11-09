#!/usr/bin/ucode
/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy — Health Monitor CLI runner + daemon (Ф2.1, ч.164).
 *
 * Thin SCRIPT wrapper over the health.uc module (урок 178: a ucode module
 * with `export` cannot be executed directly). Commands (ARGV[0]):
 *   run        — resident daemon loop (procd instance "health"): adaptive
 *                light/deep passes, status doc written EVERY tick (its ts is
 *                the monitor's own liveness witness for the RPC), status
 *                changes emitted to the Event Bus (src='health');
 *   once       — one deep compute_and_store + JSON summary (deploy/acceptance);
 *   status     — print the stored health document as-is;
 *   selftest   — module selftest (pure logic, fake inputs) → exit code.
 *
 * Adaptive load (risk map Ф2, OOM edge Ф10, lesson 197): light pass = NO
 * forks (readfile-only: pmgr registry, tun_state.json, sni_state.json,
 * /proc/meminfo) every 20 s; deep pass = ≤6 forks (service list, /proc scan,
 * Clash API, netstat, nft, op journal) every ~2 min. Any non-ok entry → fast
 * mode (5 s / every 2nd tick) for 120 s after the last non-ok tick. Deep pass
 * is SKIPPED while MemAvailable is below the RAM-derived deep edge (pmgr
 * mem_thresholds_kb; 48 MB on a 1 GB board — light stays — detection never
 * dies, only the expensive refinements wait).
 *
 * Ф10.1 resource profile: the all-ok light cadence scales by the profile
 * factor (Lite ×3, Balanced ×2, Performance ×1 — re-read every tick, live);
 * the incident fast mode and the deep dividers stay UNscaled.
 *
 * Status changes ride the Event Bus with src='health' (Ф2.1 contract: future
 * Recovery Manager repairs Ф2.3 write there too). Baseline (no previous doc —
 * reboot wiped tmpfs) is silent; a daemon restart continues diffing against
 * the stored doc, so a crash-loop cannot spam events.
 *
 * ucode constraints honored: no hoisting (helpers above callers, lesson 126),
 * non-fatal wrapper while(true){try{main()}catch{log}} (lesson 126), fs only
 * after import, sleep() = MILLISECONDS, for-in arrays = elements, no 2-arg
 * system() (lesson 167).
 */

'use strict';

import { access, readfile, open, stat } from 'fs';
import { reg_self, reg_hb, res_profile,
	mem_total_kb as pm_mem_total_kb, mem_thresholds_kb as pm_mem_thresholds_kb } from '/etc/ravnex/scripts/pmgr.uc';
import {
	compute_and_store, snapshot, selftest, HEALTH_PATH,
	MEM_DEEP_SKIP_KB, parse_meminfo_kb
} from '/etc/ravnex/scripts/health.uc';
import { read_state as ss_read_state } from '/etc/ravnex/scripts/statestore.uc';

const RUN_DIR = '/var/run/ravnex';
const LOG_FILE = RUN_DIR + '/health.log';
const MAX_LOG_BYTES = 51200;

/* ── logging (best-effort, bounded — same pattern as automation.uc) ─────── */

function log(msg) {
	const line = '[' + sprintf('%d', time()) + '] [HEALTH] ' + msg + '\n';
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

const LIGHT_SLOW_MS = 20000;   /* all-ok: light every 20 s            */
const LIGHT_FAST_MS = 5000;    /* incident: light every 5 s           */
const DEEP_DIV_SLOW = 6;       /* deep every 6th light tick (~2 мин)  */
const DEEP_DIV_FAST = 2;       /* deep every 2nd tick (~10 с)         */
const DWELL_SEC = 120;         /* fast mode lingers 120 s after ok    */

function mem_available_kb() {
	return parse_meminfo_kb(readfile('/proc/meminfo'));
};

/* Own pid for the document (reg_self stores OUR (pid, start) already — this
 * just re-derives the number honestly). Declared ABOVE run_daemon — no
 * hoisting in ucode (lesson 126). */
function reg_self_pid() {
	const raw = readfile('/proc/self/stat');
	if (raw == null)
		return null;
	const m = match(raw, /^([0-9]+) \(/);
	return (m != null) ? int(m[1]) : null;
};

function run_daemon() {
	reg_self('health', 'health_cli.uc', 'health', 'Ф2.1 Health Monitor');
	log('health monitor started (pid ' + sprintf('%d', reg_self_pid()) + ')');
	let tick = 0;
	let deep_countdown = 0;
	let fast_until = 0;
	let svc_map = null;
	/* Ф10.1: profile-scaled light cadence — re-read every tick (readfile +
	 * uci, cheap); the reactive passes (LIGHT_FAST_MS, deep dividers) are
	 * NEVER scaled (D34h: optimize, not disable). */
	let light_slow_ms = LIGHT_SLOW_MS;
	while (true) {
		try {
			const rp = res_profile();
			const want_ms = LIGHT_SLOW_MS * (int(rp.factor) || 1);
			if (want_ms !== light_slow_ms) {
				log('resource profile ' + (rp.profile || '?') + ' (factor ' +
					sprintf('%d', rp.factor) + '): light pass every ' +
					sprintf('%d', want_ms / 1000) + ' s');
				light_slow_ms = want_ms;
			}
			const now = time();
			const fast = (now < fast_until);
			/* Deep cadence: first tick always deep (fills svc_map + carries);
			 * afterwards strictly by the divider, unless memory is short.
			 * ч.264: deep-skip от RAM (pmgr.mem_thresholds_kb; фолбэк —
			 * абсолютный MEM_DEEP_SKIP_KB, /proc-дыра не даёт ложного скипа). */
			let deep = (tick === 0) || (deep_countdown <= 0);
			const mem_tot = pm_mem_total_kb();
			const deep_skip_kb = (mem_tot > 0) ? int(pm_mem_thresholds_kb(mem_tot).deep) : MEM_DEEP_SKIP_KB;
			if (deep && tick > 0 && mem_available_kb() < deep_skip_kb) {
				deep = false;
				log('deep pass skipped: MemAvailable < ' + sprintf('%d', int(deep_skip_kb / 1024)) +
					' MB (OOM edge, lesson 197; RAM-derived)');
				deep_countdown = 1;   /* retry on the next tick */
			}
			if (deep)
				deep_countdown = (fast ? DEEP_DIV_FAST : DEEP_DIV_SLOW);
			const r = compute_and_store({
				deep: deep,
				svc_map: svc_map,
				daemon_pid: reg_self_pid()
			});
			svc_map = (r.data.instances != null) ? r.data.instances : svc_map;
			deep_countdown--;
			if (r.baseline)
				log('baseline written (no previous doc this boot): overall=' + r.data.overall);
			else if (length(r.events))
				log('status changes: ' + sprintf('%J', r.events));
			if (r.data.overall !== 'ok')
				fast_until = time() + DWELL_SEC;
			reg_hb('health');
			tick++;
		} catch (e) {
			log('tick failed (non-fatal): ' + e);
		}
		const fast_now = (time() < fast_until);
		sleep(fast_now ? LIGHT_FAST_MS : light_slow_ms);
	}
};

/* ── dispatch ───────────────────────────────────────────────────────────── */

const cmd = ARGV[0] || '';
let rc = 0;

if (cmd === 'run') {
	run_daemon();
} else if (cmd === 'once') {
	const r = compute_and_store({ deep: true, svc_map: null, daemon_pid: reg_self_pid() });
	printf('%.J\n', { overall: r.data.overall, baseline: r.baseline,
		events: r.events, entries: r.data.entries });
} else if (cmd === 'snapshot') {
	printf('%.J\n', snapshot({ deep: true, svc_map: null }));
} else if (cmd === 'status') {
	const rd = ss_read_state(HEALTH_PATH);
	if (rd == null || rd.data == null) {
		printf('%.J\n', { ok: false, error: 'no health document (daemon never ran)' });
		rc = 1;
	} else {
		printf('%.J\n', { ok: true, meta: rd.meta, health: rd.data });
	}
} else if (cmd === 'selftest') {
	const r = selftest();
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else {
	printf('%.J\n', { ok: false, error: 'usage: health_cli.uc run|once|snapshot|status|selftest' });
	rc = 1;
}

exit(rc);
