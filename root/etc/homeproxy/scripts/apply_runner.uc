// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — detached-исполнитель операций применения (Ф1.1; аудит 1.6/1.7/48).
// Usage: ucode apply_runner.uc <op_id> <action>
//   actions: restart | reload | engine_restart | fw_refresh | app_update
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

const ACTIONS = { restart: 90, reload: 90, engine_restart: 60, fw_refresh: 30, app_update: 900 };   /* action → system() timeout, s */
const VERIFY_SEC = { restart: 25, reload: 25, engine_restart: 20, fw_refresh: 15, app_update: 60 };


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

/* 🔴 СЕАНС 158/Б1-класс: хелперы ВЫШЕ вызывающих (shellq — выше run_app_update). */
function shellq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

/* Сеанс 158/Б6: фоновое действие с rc-файлом (урок 167: 2-arg system() на этой
 * сборке убивает ребёнка мгновенно). Возвращает rc-строку или '' при таймауте. */
function run_bg_rc(op_id, tag, cmd, cap_s) {
	const rcfile = '/tmp/hp_apply_' + op_id + '_' + tag + '.rc';
	system(`( ${cmd} >/dev/null 2>&1; echo $? > ${rcfile} ) &`);
	const deadline = time() + cap_s;
	while (true) {
		if (access(rcfile)) {
			const rc = trim(readfile(rcfile) || '');
			system(`rm -f ${rcfile}`);
			return rc;
		}
		if (time() >= deadline) {
			system(`rm -f ${rcfile}`);
			return '';
		}
		heartbeat(op_id);
		sleep(1000);
	}
}

/* Сеанс 158/Б6: одна фаза самообновления. Ревизии/загрузки идут через
 * core_mgmt.uc (проверенная лестница download_pkg, тот же путь, что у UI),
 * установка — apk/opkg c --allow-untrusted/--force-reinstall (тот же контракт,
 * что у app_install_pkg). Каждая фаза — фоновый cmd + rc-файл + опрос. */
function run_app_update(op_id, spec) {
	const pm = ('' + (spec.pkg_manager || 'apk'));
	const parts = [];
	let ok = true;

	/* 1. Загрузка пакетов. */
	stage(op_id, 'downloading');
	heartbeat(op_id);
	const dls = [ { url: spec.app.dl_url, tmp: spec.app.tmp_path, tag: 'dlapp' } ];
	if (spec.i18n != null && length('' + (spec.i18n.dl_url || '')))
		push(dls, { url: spec.i18n.dl_url, tmp: spec.i18n.tmp_path, tag: 'dli18n' });
	for (let d in dls) {
		/* Сеанс 160: core_mgmt.uc живёт в /usr/share/homeproxy/scripts (переезд
		 * ч.237) — /etc-путь не существует, ucode даёт "Failed to open" = rc=1
		 * мгновенно (Б6: download failed rc=1 5/5 при рабочих CLI-тестах). */
		const CM = '/usr/share/homeproxy/scripts/core_mgmt.uc';
		const rc = run_bg_rc(op_id, d.tag,
			'/usr/bin/ucode ' + CM + ' download_pkg ' + shellq(d.url) + ' ' + shellq(d.tmp), 300);
		if (!access(d.tmp)) {
			finish(op_id, false, false, 'download failed: ' + d.tmp +
				((length(rc)) ? ' (rc=' + rc + ')' : ' (timeout)'));
			return false;
		}
	}

	/* 2. Установка (app, затем i18n). */
	stage(op_id, 'installing');
	heartbeat(op_id);
	for (let d in dls) {
		const cmd = (pm === 'apk')
			? `apk add --allow-untrusted ${shellq(d.tmp)}; RC=$?; rm -f ${shellq(d.tmp)}; exit $RC`
			: `opkg install --force-reinstall ${shellq(d.tmp)}; RC=$?; rm -f ${shellq(d.tmp)}; exit $RC`;
		const rc = run_bg_rc(op_id, 'inst_' + d.tag, cmd, 300);
		if (length(rc) && rc != '0')
			push(parts, 'install rc=' + rc + ' (' + d.tmp + ')');
	}

	/* 3. Пост-чек версии (apk-запись честнее rc — урок ч.223). */
	const vout = (pm === 'apk')
		? capture('apk info luci-app-re-homeproxy 2>/dev/null | head -1')
		: capture('opkg status luci-app-re-homeproxy 2>/dev/null');
	const vm = match(vout, /luci-app-re-homeproxy-([0-9][0-9.]*)/) ||
		match(vout, /Version: ([0-9][0-9.]*)/);
	const inst_v = (vm != null) ? vm[1] : '';
	if (inst_v != ('' + spec.version)) {
		finish(op_id, false, false, 'version check failed: installed ' +
			(inst_v == '' ? '?' : inst_v) + ' != expected ' + spec.version +
			((length(parts)) ? '; ' + join('; ', parts) : ''));
		return false;
	}

	/* 4. Сервис-рестарт (пакет сервис не стартует — как и в прежнем пути) +
	 * верификация ядра (та же verify_core, что у restart). */
	stage(op_id, 'restarting');
	heartbeat(op_id);
	run_bg_rc(op_id, 'svc', '/etc/init.d/homeproxy restart', ACTIONS.app_update);
	const vc = verify_core(op_id);
	if (!vc.ok) {
		finish(op_id, false, false, 'service verify failed after update: ' + vc.note);
		return false;
	}
	push(parts, vc.note);

	/* 5. ФИНАЛЬНАЯ СТАДИЯ — rpcd restart (сеанс 158/Б7: UI-путь больше не
	 * зависит от postinst; rpcd перечитает новые методы). Раннер detached и
	 * переживает смерть rpcd; журнал опов — на диске. */
	stage(op_id, 'rpcd');
	heartbeat(op_id);
	run_bg_rc(op_id, 'rpcd', '/etc/init.d/rpcd restart', 90);
	/* Живая проверка: rpcd снова отвечает (дешёвый метод, без GitHub). */
	const vdeadline = time() + VERIFY_SEC.app_update;
	let rpcd_ok = false;
	while (time() < vdeadline) {
		const out = capture('ubus call luci.homeproxy res_profile 2>/dev/null');
		if (length(trim(out))) { rpcd_ok = true; break; }
		heartbeat(op_id);
		sleep(2000);
	}
	if (!rpcd_ok) {
		finish(op_id, false, false, 'rpcd did not answer after restart (res_profile)');
		return false;
	}
	push(parts, 'rpcd restarted and serving');
	finish(op_id, true, true, join('; ', parts));
	return true;
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
	/* 🔴 Сеанс 159/Б6 живой тест: RPC спавнит руннер с kind ('app_update'),
	 * а op.action = человекочитаемое действие ('app self-update') — сверка
	 * только с op.action давала молчаливый exit(1) (урок 169: stderr в
	 * /dev/null) и оставляла op=queued без руннера. Совпадение с op.action
	 * ИЛИ op.kind. */
	if (!op ||
	    (op.action !== action && ('' + (op.kind || '')) !== action) ||
	    (action !== 'restart' && action !== 'reload' && action !== 'engine_restart' &&
	     action !== 'fw_refresh' && action !== 'app_update'))
		exit(1);   /* нет записи операции — протоколировать некуда */

	/* 🔴 Урок 169: stderr руннера уходит в /dev/null (spawn из rpcd) — ЛЮБОЕ
	 * падение беззвучно оставляет op=running и лок до истечения lease.
	 * Раннер обязан закрыть операцию ЧЕСТНО даже при собственном сбое. */
	try {
		stage(op_id, 'applying');
		heartbeat(op_id);

		if (action === 'app_update') {
			/* Сеанс 158/Б6: самообновление целиком в op-машине (спека от RPC). */
			const specf = '/tmp/hp_app_update_' + op_id + '.json';
			if (!access(specf)) {
				finish(op_id, false, false, 'app_update spec missing: ' + specf);
				exit(1);
			}
			let spec = null;
			try { spec = json(readfile(specf) || ''); } catch (e) { spec = null; }
			if (spec == null || type(spec) !== 'object' || spec.app == null) {
				finish(op_id, false, false, 'app_update spec unreadable');
				exit(1);
			}
			stage(op_id, 'downloading');
			heartbeat(op_id);
			run_app_update(op_id, spec);
			system(`rm -f ${shellq(specf)} 2>/dev/null`);
			exit(0);
		}

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
