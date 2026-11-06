// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — detached-исполнитель операций применения (Ф1.1; аудит 1.6/1.7/48).
// Usage: ucode apply_runner.uc <op_id> <action>
//   actions: restart | reload | engine_restart | fw_refresh
//
// Лок уже удержан opman.begin() (rpcd создал операцию и заспавнил руннер).
// Руннер ведёт стадии Applying→Verifying→Completed/Failed (аудит 48),
// обновляет lease между стадиями и в поллингах верификации (держатель
// detached — PID недостижим, lease живёт на heartbeat), и помечает verified
// ТОЛЬКО по живой проверке фактического состояния:
//   restart/reload  → procd-инстанс 'hiddify-c' = running; если служба
//                     выключена в конфиге — verified с честной заметкой;
//   engine_restart  → включённые движки (nfqws2/ciadpi) живы по identity
//                     (pmgr find_daemons; у Zapret пинуется живая очередь).
//
// Конфиг ЯДРА генерирует сам init.d-старт (строка ~317) — руннер НЕ вызывает
// generate_client и НЕ бампает ревизию до применения (исключена петля
// «generate → bump → stale → restart»).
//
// Уроки: 106 (вся логика в main(); top-level — только объявления),
// 2/93/126 (хелперы ВЫШЕ вызывающих), 112 (system(cmd, timeout) убивает
// только прямого ребёнка), 166 (в модуле функция кончается `};`; `ucode -c`
// модуль с export не проверяет), 🔴 167 (НА ЭТОЙ СБОРКЕ второй аргумент
// system() — МИЛЛИсекунды и ребёнок убивается мгновенно: system("/bin/sleep 2",
// 90) возвращает -9 сразу — двухаргументный system() НЕ ИСПОЛЬЗОВАТЬ; таймаут
// делаем фоновым действием + rc-файл + опрос с heartbeat),
// 100/111/113 (никаких fd-локов procd — сериализация в opman), 168/169
// (rmdir непустого каталога не работает; беззвучная смерть раннера = op
// навсегда running — main() в try/catch с честным finish), 2/93/126
// (fs-функции — только после import: access/readfile!), 
// join(sep, arr), push(arr, x), `in` по массиву = индексы.

'use strict';

import { get_op, stage, heartbeat, finish } from '/etc/homeproxy/scripts/opman.uc';
import { find_daemons as pm_find } from '/etc/homeproxy/scripts/pmgr.uc';
import { access, readfile, popen } from 'fs';
import { cursor } from 'uci';

const ACTIONS = { restart: 90, reload: 90, engine_restart: 60, fw_refresh: 30 };   /* action → system() timeout, s */
const VERIFY_SEC = { restart: 25, reload: 25, engine_restart: 20, fw_refresh: 15 };

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) {
		out = fd.read('all') || '';
		fd.close();
	}
	return out;
}

function uci_flag1(key, def) {
	try {
		const c = cursor();
		return ('' + (c.get('homeproxy', 'config', key) || def)) === '1';
	} catch (e) {
		return ('' + def) === '1';
	}
}

function uci_str(key, def) {
	try {
		const c = cursor();
		return trim('' + (c.get('homeproxy', 'config', key) || def));
	} catch (e) {
		return '' + def;
	}
}

function svc_instances() {
	let svc = null;
	try { svc = json(capture('ubus call service list 2>/dev/null')); } catch (e) { svc = null; }
	if (svc && type(svc) === 'object' && svc.homeproxy &&
	    type(svc.homeproxy.instances) === 'object')
		return svc.homeproxy.instances;
	return {};
}

function verify_core(op_id) {
	const deadline = time() + VERIFY_SEC.restart;
	while (true) {
		const inst = svc_instances()['hiddify-c'];
		if (inst && inst.running === true)
			return { ok: true, note: 'hiddify-c running' };
		if (time() >= deadline)
			break;
		heartbeat(op_id);
		sleep(2000);
	}
	if (!uci_flag1('enabled', '0'))
		return { ok: true, note: 'service disabled in config — nothing to run (verified)' };
	const inst = svc_instances()['hiddify-c'];
	if (inst && inst.running === true)
		return { ok: true, note: 'hiddify-c running' };
	return {
		ok: false,
		note: inst ? 'hiddify-c exists but not running' : 'hiddify-c instance absent while enabled'
	};
}

/* Ф9.14: firewall-only apply — the interception chains must be PRESENT in
 * the live ruleset after the fw4 reload (same check the start_service
 * self-heal pass 2 uses). The fresh render is the whole apply: init.d
 * fw_refresh returns rc=1 on a render failure, and the runner mirrors it. */
function verify_nft(op_id) {
	const deadline = time() + VERIFY_SEC.fw_refresh;
	while (true) {
		const t = capture('nft list table inet fw4 2>/dev/null');
		if (index(t, 'homeproxy_') !== -1)
			return { ok: true, note: 'homeproxy nft chains present' };
		if (time() >= deadline)
			break;
		heartbeat(op_id);
		sleep(2000);
	}
	return { ok: false, note: 'homeproxy nft chains missing after fw_refresh' };
}

function verify_engines(op_id) {
	const z_on = uci_flag1('zapret_enabled', '0');
	const b_on = uci_flag1('byedpi_enabled', '0');
	if (!z_on && !b_on)
		return { ok: true, note: 'no DPI engines enabled (verified)' };
	/* Ф1.4b: pm-liveness — exact (exe, arg) identity instead of a ps|grep
	 * substring. The Zapret probe pins the LIVE queue number, so the
	 * tester's temp instance (qnum 209) can never read as the running
	 * production engine. */
	const zq = uci_str('zapret_qnum', '200');
	const deadline = time() + VERIFY_SEC.engine_restart;
	while (true) {
		const z_ok = !z_on || length(pm_find({ exe: 'nfqws2', arg_all: [ '--qnum=' + zq ] })) > 0;
		const b_ok = !b_on || length(pm_find({ exe: 'ciadpi' })) > 0;
		if (z_ok && b_ok) {
			const names = [];
			if (z_on) push(names, 'nfqws2');
			if (b_on) push(names, 'ciadpi');
			return { ok: true, note: join(' + ', names) + ' running' };
		}
		if (time() >= deadline)
			break;
		heartbeat(op_id);
		sleep(2000);
	}
	return { ok: false, note: 'engine process missing after restart' };
}

function run_initd(op_id, action) {
	/* Урок 167: system(cmd, timeout) на этой сборке убивает ребёнка
	 * МГНОВЕННО (второй аргумент — мс) — рестарт не успевает начаться.
	 * Поэтому действие идёт фоном, код возврата — в rc-файл, руннер опрашивает
	 * его с heartbeat; дедлайн — честный failed (действие продолжает идти
	 * фоном, успех не декларируется). */
	const rcfile = '/tmp/hp_apply_' + op_id + '.rc';
	system(`( /etc/init.d/homeproxy ${action} >/dev/null 2>&1; echo $? > ${rcfile} ) &`);
	const deadline = time() + (ACTIONS[action] || 90);
	while (true) {
		if (access(rcfile)) {
			const rc = trim(readfile(rcfile) || '');
			system(`rm -f ${rcfile}`);
			return rc;
		}
		if (time() >= deadline) {
			system(`rm -f ${rcfile}`);
			finish(op_id, false, false,
				'init.d action did not report within ' + (ACTIONS[action] || 90) + 's (it keeps running detached — check the service state)');
			exit(1);
		}
		heartbeat(op_id);
		sleep(1000);
	}
};

function main() {
	const op_id = '' + (ARGV[0] || '');
	const action = '' + (ARGV[1] || '');
	const op = get_op(op_id);
	if (!op || op.action !== action ||
	    (action !== 'restart' && action !== 'reload' && action !== 'engine_restart' &&
	     action !== 'fw_refresh'))
		exit(1);   /* нет записи операции — протоколировать некуда */

	/* 🔴 Урок 169: stderr руннера уходит в /dev/null (spawn из rpcd) — ЛЮБОЕ
	 * падение беззвучно оставляет op=running и лок до истечения lease.
	 * Раннер обязан закрыть операцию ЧЕСТНО даже при собственном сбое. */
	try {
		stage(op_id, 'applying');
		heartbeat(op_id);

		const rc = run_initd(op_id, action);
		/* Код rc.common ненадёжен как признак успеха (procd асинхронен) —
		 * решает верификация; rc попадает в detail при не-нуле. */

		stage(op_id, 'verifying');
		let v;
		if (action === 'engine_restart')
			v = verify_engines(op_id);
		else if (action === 'fw_refresh')
			v = verify_nft(op_id);
		else
			v = verify_core(op_id);
		/* fw_refresh: rc=1 (render failure) — честный failed даже при
		 * живых цепях (они остались старыми). */
		if (action === 'fw_refresh' && length(rc) && rc != '0')
			v = { ok: false, note: join('; ', [ 'init.d rc=' + rc, v.note ]) };

		const parts = [];
		if (length(rc) && rc != '0')
			push(parts, 'init.d rc=' + rc);
		if (length(v.note))
			push(parts, v.note);
		finish(op_id, v.ok, v.ok, join('; ', parts));
	} catch (e) {
		finish(op_id, false, false, 'runner crashed: ' + e);
		exit(1);
	}
}

main();
