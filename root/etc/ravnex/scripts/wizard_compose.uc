#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Composition Builder v2 test runner (Ф8-F4).
 *
 * Spawned by the wizard_compose_run RPC: the RPC owns the lock, the profile
 * validation and the BUILD (hp_compose_build); this process only RUNS the
 * isolated tests and rewrites the status file at every stage.
 *
 * Input:  /var/run/ravnex/wizard_compose_req.json
 *         { zapret: "nfqws2 args", byedpi: "ciadpi args", notes: [...], ts }
 * Output: /var/run/ravnex/wizard_compose_result.json
 *         { running, stage: "started"|"zapret"|"byedpi"|"done"|"error",
 *           zapret: { args, test }, byedpi: { args, test }, notes, error, ts }
 *
 * The nfqws2 part runs through zapret_test.sh (temp NFQUEUE 209, self-
 * tearing firewall surgery, 35 s watchdog). The ciadpi part is tested by
 * the EXISTING byedpi_strategy_test RPC through one ubus call — a single
 * implementation of the OUTPUT-redirect flush/probe/restore dance.
 *
 * Lesson 83: a local forwarder needs its egress excluded BEFORE prod — the
 * runner spawns no forwarder itself; the ciadpi tester flushes the OUTPUT
 * redirect while probing and rebuilds it (with the skgid guard) after.
 */

import { readfile, access, writefile, popen } from 'fs';
import { acquire as resmgr_acquire, release as resmgr_release } from '/etc/ravnex/scripts/test_resmgr.uc';

const RUN_DIR = '/var/run/ravnex';
const REQ = RUN_DIR + '/wizard_compose_req.json';
const OUT = RUN_DIR + '/wizard_compose_result.json';
const TEST_OUT = RUN_DIR + '/wizard_compose_test.json';

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function wstat(o) {
	o.ts = time();
	writefile(OUT + '.tmp', sprintf("%.J\n", o));
	system(`mv -f ${sq(OUT + '.tmp')} ${sq(OUT)}`);
}

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function main() {
	const req = read_json(REQ);
	if (req == null ||
	    (type(req.zapret) !== 'string' && type(req.byedpi) !== 'string')) {
		wstat({ running: false, stage: 'error', error: 'no composition request' });
		return;
	}
	const zapret = '' + (req.zapret || '');
	const byedpi = '' + (req.byedpi || '');
	const res = {
		running: true, stage: 'started',
		zapret: { args: zapret },
		byedpi: { args: byedpi },
		notes: (type(req.notes) === 'array') ? req.notes : []
	};

	if (length(zapret)) {
		res.stage = 'zapret';
		wstat(res);
		/* Ф6.4 Test Resource Manager (audit 80): the test owns a pool queue —
		 * never the shared 209 the fuzzer may be using right now. */
		const qa = resmgr_acquire('compose');
		if (qa == null || qa.ok !== true) {
			res.zapret.test = { ok: 0, total: 0, error: 'нет свободной тестовой очереди (209–212) — другая задача лаборатории ещё работает' };
		} else {
			/* zapret_test.sh prints one JSON line into TEST_OUT and self-tears
			 * down (35 s watchdog); the 60 s system() timeout is the outer cap. */
			system(sprintf('TEST_QNUM=%d sh /etc/ravnex/scripts/zapret_test.sh %s > %s 2>/dev/null',
				int(qa.qnum), sq(zapret), sq(TEST_OUT)), 60000);
			res.zapret.test = read_json(TEST_OUT);
			system(`rm -f ${sq(TEST_OUT)}`);
			resmgr_release(qa.qnum, 'compose');
		}
	}

	if (length(byedpi)) {
		res.stage = 'byedpi';
		wstat(res);
		/* One ubus call into the existing tester; -t 45 caps the wait. */
		const payload = sprintf('{"cmd_opts":%.J}', byedpi);
		const fd = popen(`ubus -t 45 call luci.ravnex byedpi_strategy_test ${sq(payload)} 2>/dev/null`);
		let out = '';
		if (fd) { out = trim(fd.read('all') || ''); fd.close(); }
		try { res.byedpi.test = json(out || ''); } catch (e) { res.byedpi.test = null; }
	}

	res.running = false;
	res.stage = 'done';
	wstat(res);
	system(`rm -f ${sq(REQ)}`);
}

main();
