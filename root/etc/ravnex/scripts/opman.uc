// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Operation/Apply Manager (plan 20 §3 Ф1.1; audit 1.6/1.7/18/39–44/48–50).
// Единая точка сериализации операций применения конфигурации и честного
// протоколирования результата: успех операции = ТОЛЬКО после живой верификации
// (аудит 1.7 «не сообщать успех до verified»); параллельное применение
// невозможно (аудит 1.6 — никаких «applying anyway»); застрявший лок
// самолечится lease-таймером (аудит 50 — SIGKILL держателя не блокирует
// применения навсегда).
//
// Механика:
//   - Операция — JSON-файл /var/run/ravnex/ops/op-<id>.json:
//       { op_id, kind, action, note, owner,
//         status: queued|running|verifying|completed|failed,
//         stage, verified, detail, started, heartbeat, finished,
//         config_revision, applied_revision, ts }
//   - Сериализация — lease-lock: каталог /var/run/ravnex/ops/.lock-<kind>/
//     с owner.json { op_id, owner, started, heartbeat }. Лок «протухает», если
//     heartbeat старше LEASE_SEC — следующий примен снимает его и начинает
//     свой. PID-проверка держателя здесь недостижима честно: держатель —
//     detached-раннер, чей PID из ucode не получить (lessons 100/111/113 —
//     fd/flock-локи procd не используются вовсе); lease живёт на heartbeat,
//     который руннер обновляет между ВСЕМИ стадиями и в поллингах верификации.
//   - config_revision — монотонный счётчик VERIFIED применений
//     (/var/run/ravnex/state/config_revision, tmpfs: после ребута = 1 —
//     консистентно с журналом операций, который живёт там же).
//
// Уроки: 106 (исполняемая логика — только в функциях), 2/93/126 (хелперы
// ВЫШЕ вызывающих), 166 (в МОДУЛЕ функция обязана кончаться `};` — без `;`
// парсер модуля даёт «Expecting ';'» на закрывающей скобке; `ucode -c` модуль
// с export проверить не может вообще), атомарные записи temp+rename,
// join(sep, arr), push(arr, x), for-in по массиву = элементы.

'use strict';

import { access, readfile, stat, mkdir, rmdir, unlink, popen } from 'fs';
import { REV_PATH, read_revision, atomic_write } from '/etc/ravnex/scripts/statestore.uc';

const OPS_DIR = '/var/run/ravnex/ops';
const STATE_DIR = '/var/run/ravnex/state';
const LEASE_SEC = 120;
const KEEP_OPS = 50;

/* ── низкоуровневые хелперы (выше всех вызывающих — no hoisting) ── */

function mkdir_p(p) {
	let cur = '';
	for (let part in split(p, '/')) {
		if (!length(part))
			continue;
		cur += '/' + part;
		if (!access(cur))
			mkdir(cur);
	}
};

function uniq_tail() {
	/* clock() = [секунды, наносекунды] на этой сборке (automation.uc). */
	const c = clock();
	return int((c[1] / 1000) % 1000000);
};

function json_safe(s) {
	if (s == null)
		return null;
	try {
		const d = json(s);
		return d;
	} catch (e) {
		return null;
	}
};

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) {
		out = fd.read('all') || '';
		fd.close();
	}
	return out;
};

function valid_id(s) {
	return length('' + s) <= 64 && match('' + s, /^[A-Za-z0-9_-]+$/) != null;
};

function valid_kind(s) {
	return length('' + s) <= 32 && match('' + s, /^[a-z0-9_-]+$/) != null;
};

/* ── ревизии (счётчик VERIFIED применений) ── */

export function get_revision() {
	return read_revision();
};

export function bump_revision() {
	mkdir_p(STATE_DIR);
	const n = get_revision() + 1;
	atomic_write(REV_PATH, n + '\n');
	return n;
};

/* ── журнал операций ── */

export function get_op(op_id) {
	if (!valid_id(op_id))
		return null;
	return json_safe(readfile(OPS_DIR + '/op-' + op_id + '.json'));
};

export function save_op(op) {
	mkdir_p(OPS_DIR);
	atomic_write(OPS_DIR + '/op-' + op.op_id + '.json', sprintf('%.J', op) + '\n');
};

export function list_ops() {
	const out = [];
	const raw = capture('ls -1 ' + OPS_DIR + '/ 2>/dev/null');
	for (let line in split(raw, '\n')) {
		const f = trim(line);
		if (!match(f, /^op-[A-Za-z0-9_-]+\.json$/))
			continue;
		const op = json_safe(readfile(OPS_DIR + '/' + f));
		if (op && type(op) === 'object' && valid_id('' + op.op_id))
			push(out, op);
	}
	sort(out, (a, b) => (int(a.started) < int(b.started)) ? 1 : -1);
	return out;
};

function gc_ops() {
	const ops = list_ops();
	if (length(ops) <= KEEP_OPS)
		return;
	for (let i = KEEP_OPS; i < length(ops); i++)
		unlink(OPS_DIR + '/op-' + ops[i].op_id + '.json');
};

/* ── lease-lock ── */

function lock_dir(kind) {
	if (!valid_kind(kind))
		return null;
	return OPS_DIR + '/.lock-' + kind;
};

function lock_owner(ld) {
	return json_safe(readfile(ld + '/owner.json'));
};

/* 🔴 Урок 168: rmdir НЕ удаляет непустой каталог — лок с owner.json внутри
 * не освободится «простым rmdir» (первый живой прогон заклинил rpcd в
 * бесконечном steal-цикле). Порядок всегда: unlink owner.json → rmdir.
 * Steal-путь ограничен счётчиком — никаких безграничных retry-циклов
 * вокруг падающего примитива. */
function release_lock(ld, op_id) {
	const ownerj = lock_owner(ld);
	if (ld && access(ld) && (!ownerj || !op_id || ownerj.op_id === op_id)) {
		unlink(ld + '/owner.json');
		rmdir(ld);
		return true;
	}
	return false;
};

/* Протух ли lease: heartbeat старше LEASE_SEC (держатель убит или завис —
 * живой держатель обновляет heartbeat минимум раз в несколько секунд). */
function lease_expired(owner, mtime) {
	const now = time();
	const hb = (owner && int(owner.heartbeat)) || 0;
	if (hb > 0)
		return (now - hb) > LEASE_SEC;
	if (mtime > 0)
		return (now - mtime) > LEASE_SEC;
	return false;
};

function touch_lease(op, now) {
	const ld = lock_dir(op.kind);
	if (!ld || !access(ld))
		return;
	const ownerj = lock_owner(ld);
	if (ownerj && ownerj.op_id === op.op_id) {
		ownerj.heartbeat = now;
		atomic_write(ld + '/owner.json', sprintf('%.J', ownerj) + '\n');
	}
};

/* ── публичный протокол ── */

/* begin(): взять лок (wait_ms=0 → мгновенный честный busy — путь RPC;
 * detached-исполнители могут передать бюджет ожидания) и создать операцию.
 * Возвращает { ok, op } | { busy, holder } | { error }. */
export function begin(kind, action, owner, note, wait_ms) {
	const ld = lock_dir(kind);
	if (!ld)
		return { error: 'bad kind' };
	mkdir_p(OPS_DIR);
	const wait_s = (int(wait_ms) > 0) ? int(wait_ms / 1000) : 0;
	const deadline = time() + wait_s;
	let steals = 0;
	while (true) {
		if (mkdir(ld)) {
			const now = time();
			const op = {
				op_id: sprintf('%d-%06d', now, uniq_tail()),
				kind: kind,
				action: '' + (action || ''),
				note: '' + (note || ''),
				owner: '' + (owner || 'unknown'),
				status: 'queued',
				stage: 'queued',
				verified: false,
				detail: '',
				started: now,
				heartbeat: now,
				finished: 0,
				config_revision: get_revision(),
				applied_revision: 0,
				ts: now
			};
			/* Lease записать ДО журнала: crash между ними = лок с lease,
			 * который самолечится, а не лок-призрак без heartbeat. */
			atomic_write(ld + '/owner.json', sprintf('%.J',
				{ op_id: op.op_id, owner: op.owner, started: now, heartbeat: now }) + '\n');
			save_op(op);
			gc_ops();
			return { ok: true, op: op };
		}
		const st = stat(ld);
		const ownerj = lock_owner(ld);
		if (lease_expired(ownerj, st ? st.mtime : 0)) {
			/* Протухший lease: снимаем (файл → каталог, ограниченно). */
			if (steals >= 3)
				return { busy: true, holder: ownerj || null, error: 'steal loop' };
			steals++;
			unlink(ld + '/owner.json');
			rmdir(ld);
			continue;
		}
		if (time() >= deadline)
			return { busy: true, holder: ownerj || null };
		sleep(500);
	}
};

export function heartbeat(op_id) {
	const op = get_op(op_id);
	if (!op)
		return false;
	const now = time();
	op.heartbeat = now;
	op.ts = now;
	save_op(op);
	touch_lease(op, now);
	return true;
};

export function stage(op_id, st) {
	const op = get_op(op_id);
	if (!op)
		return false;
	const now = time();
	op.stage = '' + st;
	op.status = (st === 'verifying') ? 'verifying' : 'running';
	op.heartbeat = now;
	op.ts = now;
	save_op(op);
	touch_lease(op, now);
	return true;
};

/* finish(): зафиксировать честный результат и отпустить лок. applied_revision
 * бампается ТОЛЬКО при verified-успехе — это счётчик живых применений. */
export function finish(op_id, ok, verified, detail) {
	const op = get_op(op_id);
	if (!op)
		return false;
	const now = time();
	op.status = ok ? 'completed' : 'failed';
	op.stage = ok ? 'completed' : 'failed';
	op.verified = (ok && verified) ? true : false;
	op.detail = '' + (detail || '');
	op.finished = now;
	op.ts = now;
	if (op.verified)
		op.applied_revision = bump_revision();
	save_op(op);
	release_lock(lock_dir(op.kind), op_id);
	return true;
};
