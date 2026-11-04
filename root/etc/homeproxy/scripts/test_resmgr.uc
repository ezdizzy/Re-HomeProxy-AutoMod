// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Test Resource Manager (Ф6.4, план 20 §Ф6; аудит 80/81).
//
// ОДИН владелец на каждую изолированную тестовую задачу (аудит 80): очередь
// NFQUEUE/temp-qnum и nfqws2-инстанс задачи принадлежат задаче, а не «всем» —
// до сих пор импорт стратегий и фаззинг делили жёсткий qnum 209, и smoke-тест
// импорта убивал nfqws2 идущего фаззинга (kill_temp_nfqws без владения).
//
// Пул qnum: 209–212 (продакшн-очередь NEVER в пуле — исключается по UCI
// zapret_qnum). Реестр владения: /var/run/homeproxy/test_resmgr.json
// (атомарная запись tmp+mv), запись {task, ts}; протухшая запись (старше
// RES_TTL) перехватывается — упавший воркер не блокирует лабораторию навсегда.
//
// Лабораторный лок (аудит 81 — гонка wizard_strategy_update/wizard_fuzz_generate):
// атомарный mkdir /var/run/homeproxy/lab_lock (busybox mkdir атомарен, rc!=0 =
// занято) + owner-файл внутри {task, ts}. Берётся RPC ДО записи mode-файла,
// снимает сам воркер в конце; протухший лок (старше LOCK_TTL) ломается
// следующей попыткой. flock/busybox -w недоступны (уроки 100/111).
//
// Уроки учтены: 245 (export через `};`), 246 (нет undefined — type()),
// 20/31 (for-in по массиву = элементы), 2/93 (хелперы выше использующих),
// 253 (falsy-ноль), 255 (наличие инструмента проверять, не предполагать),
// atomic_write (temp + mv -f).

'use strict';

import { access, readfile, writefile, popen } from 'fs';
import { kill_matched as pm_kill_matched } from '/etc/homeproxy/scripts/pmgr.uc';

const RUN_DIR = '/var/run/homeproxy';
const REG = RUN_DIR + '/test_resmgr.json';
const LOCK_DIR = RUN_DIR + '/lab_lock';
const LOCK_OWNER = LOCK_DIR + '/owner';

/* Протухание записей: смок-тесты/проход фаззинга живут минуты; упавший
 * воркер (без release) не должен держать очередь вечно. 35 мин > худшего
 * прохода фаззинга одной стратегии (watchdog 100 с × раунды), но << ночного
 * простоя. Лок — отдельный TTL (импорт с валидацией ≤ ~15 мин по гварду RPC). */
const RES_TTL = 35 * 60;
const LOCK_TTL = 18 * 60;
const POOL_LO = 209;
const POOL_HI = 212;

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function write_json(path, obj) {
	writefile(path + '.tmp', sprintf("%.J\n", obj));
	system(`mv -f '${path}.tmp' '${path}' 2>/dev/null`);
}

/* Продакшн-очередь Zapret (UCI zapret_qnum) НИКОГДА не выдаётся тесту — даже
 * если пользователь сменил 200 на нестандарт. popen читается здесь: resmgr
 * вызывается ИЗ rpcd-воркера и one-shot воркеров (не из длинного демона);
 * пустота = дефолт 200 (урок 209: семантика отсутствия — одна на всех
 * читателях, генератор пишет значение явно). */
function production_qnum() {
	const fd = popen("uci -q get homeproxy.config.zapret_qnum 2>/dev/null");
	let v = '';
	if (fd) { v = trim(fd.read('all') || ''); fd.close(); }
	return (length(v) && match('' + v, /^[0-9]+$/)) ? int(v) : 200;
}

/* acquire(task) → {ok:true, qnum} | {ok:false, error}. Первый свободный qnum
 * пула (не протухшая запись — перехватывается). Взаимное исключение
 * импорт/фаззинг обеспечивает lab_lock + симметричные гварды RPC; здесь —
 * только честное владение очередью. */
export function acquire(task) {
	const prod = production_qnum();
	const reg = read_json(REG) || {};
	const now = time();
	if (type(reg.queues) !== 'object')
		reg.queues = {};
	for (let q = POOL_LO; q <= POOL_HI; q++) {
		if (q === prod)
			continue;
		const key = '' + q;
		const rec = reg.queues[key];
		if (rec != null && type(rec) === 'object' &&
			(now - int(rec.ts || 0)) < RES_TTL)
			continue;
		reg.queues[key] = { task: '' + task, ts: now };
		write_json(REG, reg);
		return { ok: true, qnum: q };
	}
	return { ok: false, error: 'нет свободной тестовой очереди (209–212) — другая задача лаборатории ещё работает' };
};

/* release(qnum, task) — снимает запись ТОЛЬКО владельца (запрет чужих
 * release — зеркальный к «запрету чужих kill»). */
export function release(qnum, task) {
	const reg = read_json(REG);
	if (reg == null || type(reg.queues) !== 'object')
		return { ok: false, error: 'нет реестра очередей' };
	const key = '' + int(qnum);
	const rec = reg.queues[key];
	if (rec == null || type(rec) !== 'object')
		return { ok: true };   /* уже пусто — не ошибка */
	if (rec.task !== ('' + task))
		return { ok: false, error: 'очередь принадлежит другой задаче (' + rec.task + ')' };
	delete reg.queues[key];
	write_json(REG, reg);
	return { ok: true };
};

/* kill_own(qnum, task) — сигнализировать nfqws2 на СВОЕЙ очереди: владение
 * проверяется ДО pm_kill_matched (точный элемент --qnum=N — продакшн-очередь
 * с другим элементом не совпадёт никогда, Ф1.4b). */
export function kill_own(qnum, task) {
	const reg = read_json(REG);
	const key = '' + int(qnum);
	const rec = (reg != null && type(reg.queues) === 'object') ? reg.queues[key] : null;
	if (rec == null || rec.task !== ('' + task))
		return { ok: false, error: 'kill отклонён: очередь ' + key + ' не принадлежит задаче ' + task };
	pm_kill_matched({ exe: 'nfqws2', arg_all: [ '--qnum=' + key ] }, 2000);
	return { ok: true };
};

/* lab_lock(task) → {ok} | {ok:false, error} — атомарный mkdir-лок
 * (busybox flock не умеет -w, уроки 100/111; mkdir атомарен). Протухший лок
 * (owner.ts старше LOCK_TTL) ломается и берётся заново (одна ретра-попытка). */
export function lab_lock(task) {
	const rc = system(`mkdir '${LOCK_DIR}' 2>/dev/null`);
	if (rc === 0) {
		write_json(LOCK_OWNER, { task: '' + task, ts: time() });
		return { ok: true };
	}
	/* Занято: честно смотрим, чей и протух ли. */
	const own = read_json(LOCK_OWNER);
	const now = time();
	if (own == null || type(own) !== 'object' ||
		(now - int(own.ts || 0)) >= LOCK_TTL) {
		system(`rm -rf '${LOCK_DIR}' 2>/dev/null`);
		const rc2 = system(`mkdir '${LOCK_DIR}' 2>/dev/null`);
		if (rc2 === 0) {
			write_json(LOCK_OWNER, { task: '' + task, ts: time() });
			return { ok: true, stolen_stale: true };
		}
		return { ok: false, error: 'лабораторный лок занят (перехват протухшего не удался)' };
	}
	return { ok: false, error: 'лаборатория занята: идёт ' + ('' + (own.task || '?')) +
		' (' + int((now - int(own.ts || 0)) / 60) + ' мин)' };
};

/* lab_unlock(task) — снимает лок ТОЛЬКО владелец. */
export function lab_unlock(task) {
	const own = read_json(LOCK_OWNER);
	if (own == null || type(own) !== 'object')
		return { ok: true };
	if (own.task !== ('' + task))
		return { ok: false, error: 'лок принадлежит ' + ('' + (own.task || '?')) };
	system(`rm -rf '${LOCK_DIR}' 2>/dev/null`);
	return { ok: true };
};

/* Снимок для диагностики/support_bundle: кто держит очереди и лок. */
export function status() {
	const reg = read_json(REG) || {};
	const own = read_json(LOCK_OWNER);
	return { queues: (type(reg.queues) === 'object') ? reg.queues : {},
		lock: (type(own) === 'object') ? own : null,
		pool: [ POOL_LO, POOL_HI ], ts: time() };
};

export function selftest() {
	const pass = [], fail = [];
	const t = (name, cond) => (cond) ? push(pass, name) : push(fail, name);

	/* Продакшн-очередь не в пуле — инвариант доверия между задачами. */
	const prod = production_qnum();
	t('production qnum outside pool', prod < POOL_LO || prod > POOL_HI);

	/* acquire → чужой release/kill отклонён → владелец снимает. */
	const a1 = acquire('selftest');
	t('acquire ok', a1.ok === true && int(a1.qnum) >= POOL_LO && int(a1.qnum) <= POOL_HI);
	const r1 = release(a1.qnum, 'чужой');
	t('foreign release refused', r1.ok === false);
	const r2 = release(a1.qnum, 'selftest');
	t('owner release ok', r2.ok === true);
	const r3 = release(a1.qnum, 'selftest');
	t('double release is a no-op ok', r3.ok === true);
	const k1 = kill_own(a1.qnum, 'selftest');
	t('kill without ownership refused', k1.ok === false);

	/* лок: взять → второй берущий отказан с именем владельца → чужой unlock
	 * отклонён → владелец снимает → снова берётся. */
	const l1 = lab_lock('selftest');
	t('lab_lock acquired', l1.ok === true);
	const l2 = lab_lock('selftest2');
	t('second locker refused with owner name', l2.ok === false && index('' + l2.error, 'selftest') >= 0);
	const u1 = lab_unlock('selftest2');
	t('foreign unlock refused', u1.ok === false);
	const u2 = lab_unlock('selftest');
	t('owner unlock ok', u2.ok === true);
	const l3 = lab_lock('selftest');
	t('lock re-acquirable after unlock', l3.ok === true);
	lab_unlock('selftest');

	/* status() честно отражает, что ЗАДАЧА selftest нигде не осталась
	 * (чужие задачи, если идут живьём, не трогаются). */
	const st = status();
	let self_left = false;
	for (let q in keys(st.queues))
		if (st.queues[q] != null && st.queues[q].task === 'selftest')
			self_left = true;
	t('selftest released everywhere', !self_left && (st.lock == null || st.lock.task !== 'selftest'));

	return { pass: length(pass), fail: length(fail), details: fail };
};
