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
 * Exit 0 = ok, 1 = any failed kill / bad usage / failed selftest.
 */

'use strict';

import * as pm from '/etc/homeproxy/scripts/pmgr.uc';

const cmd = ARGV[0] || '';
let rc = 0;

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
		usage: 'scan|status|gc|selftest|mosdns_stop|dnsf_stop|kill_if' });
	rc = 1;
}

exit(rc);
