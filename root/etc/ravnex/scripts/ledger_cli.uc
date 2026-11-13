#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Persister Ledger selftest (s205). Авторитетный гейт модуля:
// `ucode /etc/ravnex/scripts/ledger_cli.uc selftest` → rc=0, ok:true.
// Полный путь импорта (урок 403); sandbox-каталог в /tmp (живой леджер
// на боксе не трогается — паттерн s196/POOL_FILE).

'use strict';

import { access, readfile, writefile, unlink, mkdir, open } from 'fs';
import {
	set_dir, LEDGER_VERSION, append_events, read_events, read_snapshot,
	write_snapshot, clear_journal, reset_files, journal_bytes, replay_plan
} from '/etc/ravnex/scripts/ledger.uc';

const SB = '/tmp/ledger_selftest';
let failures = 0;

function check(name, cond) {
	if (cond) {
		printf('ok   %s\n', name);
	} else {
		printf('FAIL %s\n', name);
		failures++;
	}
}

function rmrf(path) {
	try { unlink(path); } catch (e) { /* нет — норма */ }
}

function fresh() {
	reset_files();
	rmrf(SB + '/journal.1.jsonl');
	rmrf(SB + '/journal.jsonl');
	rmrf(SB + '/snapshot.json');
}

/* ── 0. sandbox ── */
set_dir(SB);
try { mkdir(SB); } catch (e) { /* уже есть */ }

/* ── 1. холодный старт: пусто везде ── */
fresh();
check('cold: snapshot null', read_snapshot() == null);
check('cold: events empty', length(read_events()) == 0);
check('cold: journal_bytes 0', journal_bytes() == 0);

/* ── 2. append + roundtrip ── */
const evs1 = [
	{ seq: 1, ts: 100, op: 'L', h: 'rutracker.org', d: { ip: 0 } },
	{ seq: 2, ts: 101, op: 'Q1', h: 'rutracker.org', d: {} },
	{ seq: 3, ts: 102, op: 'FA', h: 'cdn.example.net', d: { a: 'rutracker.org', k: 'domain', t: 90, ls: 100 } }
];
check('append: batch ok', append_events(evs1) === true);
const rt = read_events();
check('roundtrip: count', length(rt) == 3);
check('roundtrip: op/h/d', length(rt) && rt[0].op == 'L' && rt[0].h == 'rutracker.org' &&
	int(rt[0].d.ip) == 0 && rt[2].op == 'FA' && rt[2].d.a == 'rutracker.org' && int(rt[2].d.t) == 90);

/* ── 3. снапшот: roundtrip и валидация ── */
const snapdata = {
	state: { 'rutracker.org': { status: 'blocked', block_kind: 'tls_dpi', added: 5, last_probe: 9 } },
	maps: { poi: { 'poisoned.example': 777 }, blk: {} },
	fam_ledger: { 'cdn.example.net': { t_last: 100, clients: { '192.168.1.5': 95 } } },
	yt: { 'aj5goc-5x': { first_ts: 1, last_ts: 2, hits: 7 } }
};
write_snapshot(snapdata, 3);
const rs = read_snapshot();
check('snapshot: read ok', rs != null && int(rs.seq) == 3);
check('snapshot: state equal', rs != null && sprintf('%J', rs.data.state) == sprintf('%J', snapdata.state));
check('snapshot: maps equal', rs != null && int(rs.data.maps.poi['poisoned.example']) == 777);
check('snapshot: fam_ledger equal', rs != null && int(rs.data.fam_ledger['cdn.example.net'].clients['192.168.1.5']) == 95);
check('snapshot: yt equal', rs != null && int(rs.data.yt['aj5goc-5x'].hits) == 7);

/* версия схемы: чужой ledger_version = состояния нет */
const wrong = sprintf('%.J\n', { schema_version: 1, config_revision: 1, ts: time(),
	data: { ledger_version: 99, seq: 5, state: {}, maps: {}, fam_ledger: {}, yt: {} } });
writefile(SB + '/snapshot.json', wrong);
check('snapshot: wrong version -> null', read_snapshot() == null);

/* протухший снапшот (max_age=-1) = null */
write_snapshot(snapdata, 3);
check('snapshot: stale -> null', read_snapshot(-1) == null);
check('snapshot: fresh again', read_snapshot() != null);

/* ── 4. битая строка (рваный хвост) — толерантность ── */
clear_journal();
append_events([{ seq: 1, ts: 1, op: 'L', h: 'a.example', d: {} }]);
const fd = open(SB + '/journal.jsonl', 'a');
fd.write('{"seq":2,"ts":2,"op":"L","h":"torn.exa');
fd.close();
const rt2 = read_events();
check('torn: only whole lines', length(rt2) == 1 && rt2[0].h == 'a.example');

/* ── 5. replay_plan: правила реплея ── */
fresh();
const plan_evs = [
	{ seq: 1, ts: 1, op: 'L', h: 'h1', d: {} },
	{ seq: 2, ts: 2, op: 'P1', h: 'h2', d: { t: 5 } },
	/* дыра: seq 3 потерялся */
	{ seq: 4, ts: 4, op: 'U', h: 'h1', d: {} }
];
const rp0 = replay_plan(plan_evs, 0);
check('replay: applies prefix', length(rp0.to_apply) == 2 && int(rp0.base) == 2 && int(rp0.torn) == 4);
const rp1 = replay_plan(plan_evs, 2);
check('replay: base skips', length(rp1.to_apply) == 0 && int(rp1.base) == 2 && int(rp1.torn) == 4);
const rp2 = replay_plan(plan_evs, 4);
check('replay: everything consumed', length(rp2.to_apply) == 0 && int(rp2.base) == 4 && int(rp2.torn) == 0);

/* ── 6. ротация журнала по размеру (128 КБ; проверка на входе в append) ── */
fresh();
let big = [];
for (let i = 1; i <= 2000; i++)
	push(big, { seq: i, ts: i, op: 'L', h: 'host-' + i + '.example.tld', d: { ip: 0 } });
check('rotate: append 2000 ok', append_events(big) === true);
/* порог проверяется ПЕРЕД дописью пачки → ротация случится на следующем
 * append (одиночный батч может переложить порог — компакция догонит). */
check('rotate: next append triggers', append_events([{ seq: 2001, ts: 2001, op: 'L', h: 'host-2001.example.tld', d: { ip: 0 } }]) === true);
check('rotate: prev exists', access(SB + '/journal.1.jsonl'));
check('rotate: size capped', journal_bytes() < 2 * 131072 + 4096);
const rt3 = read_events();
check('rotate: all generations read', length(rt3) == 2001 && int(rt3[0].seq) == 1 && int(rt3[2000].seq) == 2001);

/* ── 7. clear/reset ── */
reset_files();
check('reset: snapshot gone', !access(SB + '/snapshot.json'));
check('reset: journal gone', !access(SB + '/journal.jsonl'));
check('reset: events empty', length(read_events()) == 0);

/* ── 8. пустые/мусорные входы не роняют ── */
check('empty: append [] ok', append_events([]) === true);
check('empty: replay null-safe', replay_plan(null, 0).base == 0);
check('empty: snapshot null-safe', read_snapshot() == null);

printf('\n');
if (failures > 0) {
	printf('ok:false, failed:%d\n', failures);
	exit(1);
}
printf('ok:true, ledger selftest passed (version %d)\n', LEDGER_VERSION);
