#!/usr/bin/ucode
/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy daemons — Process Manager CLI runner (Ф1.4, ч.150).
 *
 * Thin SCRIPT wrapper over the pmgr.uc module: a ucode module with `export`
 * cannot be executed directly ("Exports may only appear at top level of a
 * module"), so shell callers (init.d, acceptance) run THIS file and it calls
 * the module in-process. Command set + exit codes:
 *   scan | status | gc | selftest | mosdns_stop | dnsf_stop [dir]
 *   kill_if <exe|script:NAME.uc> [arg]
 *   find <exe[,exe2…]|script:NAME.uc> [arg…]   → exit 0 when a match exists
 *   kill_args <exe|script:NAME.uc> [arg…]      → identity kill, arg_all pins
 * Exit 0 = ok, 1 = any failed kill / bad usage / failed selftest.
 */

'use strict';

import * as pm from '/etc/ravnex/scripts/pmgr.uc';

/* `find`/`kill_args` target: ARGV token → { exe: [list] } | { script } and
 * the remaining tokens as the arg_all conjunction (each must appear as a
 * whole cmdline element — never a substring, lesson 36). */
function parse_target(argv) {
	const spec = { args: [] };
	if (argv == null || !length(argv) || !length('' + argv[0]))
		return null;
	const head = '' + argv[0];
	if (substr(head, 0, 7) === 'script:') {
		spec.script = substr(head, 7);
	} else {
		spec.exes = split(head, ',');
		for (let e in spec.exes)
			if (!length('' + e))
				return null;
	}
	for (let i = 1; i < length(argv); i++)
		push(spec.args, '' + argv[i]);
	return spec;
};

const cmd = ARGV[0] || '';
let rc = 0;

/* ч.229 FIX (prod-killer): the old call sites passed parse_target([ ARGV[1] ])
 * — ONLY the exe — so the pinning tokens ("--qnum=210" …) were silently
 * dropped, spec.arg_all stayed EMPTY, and find/kill_args matched EVERY
 * nfqws2 process. Proven live: every zapret_test.sh cleanup TERMed the PROD
 * engine (qnum 200) alongside the test engine — the whole "nfqws2 crash
 * loop" saga (procd 17 crashes, recovery svc_start x10 on 2026-11-07) was
 * our own cleanup, and the identity checks passed whenever ANY nfqws2 was
 * alive. Tokens are now forwarded verbatim: ARGV[1] = target head,
 * ARGV[2..] = the arg_all conjunction. */
const argv_target = [];
for (let i = 1; i < length(ARGV); i++)
	push(argv_target, ARGV[i]);

if (cmd === 'scan') {
	printf('%.J\n', pm.scan_registry());
} else if (cmd === 'status') {
	printf('%.J\n', pm.registry_status());
} else if (cmd === 'gc') {
	printf('%.J\n', { ok: true, dropped: pm.reg_gc() });
} else if (cmd === 'kill_if') {
	const r = pm.kill_if(ARGV[1], ARGV[2]);
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else if (cmd === 'find') {
	const t = parse_target(argv_target);
	let n = 0;
	if (t == null || (!t.exes && !t.script)) {
		printf('%.J\n', { ok: false, error: 'usage: find <exe[,exe2…]|script:NAME.uc> [arg…]' });
		rc = 1;
	} else {
		for (let e in (t.exes || [ null ])) {
			/* for-in yields ELEMENTS; `null` exe keeps the script-only probe. */
			const spec = (e != null) ? { exe: '' + e } : { script: t.script };
			if (length(t.args))
				spec.arg_all = t.args;
			n += length(pm.find_daemons(spec));
		}
		printf('%.J\n', { ok: true, found: n });
		rc = (n > 0) ? 0 : 1;
	}
} else if (cmd === 'kill_args') {
	const t = parse_target(argv_target);
	if (t == null || (!t.exes && !t.script)) {
		printf('%.J\n', { ok: false, error: 'usage: kill_args <exe|script:NAME.uc> [arg…]' });
		rc = 1;
	} else {
		const res = { killed: [], failed: [] };
		for (let e in (t.exes || [ null ])) {
			const spec = (e != null) ? { exe: '' + e } : { script: t.script };
			if (length(t.args))
				spec.arg_all = t.args;
			const r = pm.kill_matched(spec, 2000);
			for (let p in r.killed)
				push(res.killed, p);
			for (let p in r.failed)
				push(res.failed, p);
		}
		res.ok = !length(res.failed);
		res.killed_n = length(res.killed);
		printf('%.J\n', res);
		/* exit codes: 0 = ok AND something killed, 2 = ok but nothing
		 * matched (callers tell "killed" apart from "was already gone"),
		 * 1 = a kill failed. */
		rc = res.ok ? (res.killed_n > 0 ? 0 : 2) : 1;
	}
} else if (cmd === 'mosdns_stop') {
	const r = pm.mosdns_stop();
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else if (cmd === 'dnsf_stop') {
	const r = pm.dnsf_stop(ARGV[1]);
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else if (cmd === 'selftest') {
	const r = pm.selftest();
	printf('%.J\n', r);
	rc = r.ok ? 0 : 1;
} else {
	printf('%.J\n', { ok: false, error: 'unknown command: ' + cmd,
		usage: 'scan|status|gc|selftest|mosdns_stop|dnsf_stop|kill_if|find|kill_args' });
	rc = 1;
}

exit(rc);
