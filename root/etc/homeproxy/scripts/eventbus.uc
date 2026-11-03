// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Event Bus-основа (plan 20 §3 Ф1.7; audit 21).
// Единый append-only журнал событий для LuCI, Telegram-информатора и
// автоматизации (задел Ф2.4 — подписчики с durable-курсорами подключаются там).
//
// Формат: JSONL — одна запись = одна строка, ОДИН write() при открытии в
// режиме 'a' (O_APPEND: ядро атомарно ставит offset — параллельные писатели
// не рвут строки друг друга; read-modify-write из audit 21 устранён):
//   { "id": <монотонный int>, "ts": <unix>, "src": "<подсистема>",
//     "type": "<тип>", "who": "<кто/что>", "detail": "<детали>" }
//
// Монотонный event_id: счётчик-файл инкрементируется ПОД mkdir-локом
// (mkdir атомарен — тот же примитив, что lease-лок opman; критическая секция
// ~1-2 мс, поэтому даже бurst в сотни параллельных писателей укладывается в
// бюджет ожидания). Залипший лок (держатель умер между mkdir и rmdir) снимается
// по возрасту mtime > STALE_SEC (rmdir пустого каталога — урок 168). Если лок
// не взят и за весь бюджет ожидания — emit честно возвращает null (событие
// best-effort: это возможно только при сломанной fs, где упало бы и само
// добавление). Fallback-id вне лока НЕ существует намеренно: любой «обход»
// лока гонится со счётчиком и ломает монотонность (доказано при ревью Ф1.7).
//
// Ротация: journal.jsonl > MAX_BYTES → mv в journal.1.jsonl (atomically
// заменяет прошлую генерацию; читатели читают ОБЕ — событие, застрявшее в
// ротируемом файле, не теряется). Журнал живёт в tmpfs: после ребута и журнал,
// и счётчик обнуляются вместе — id монотонны в пределах одной загрузки;
// подписчики держат курсор в памяти или хранят его вместе с boot_epoch (Ф2.4).
//
// Уроки: 166 (`};`, проверка модуля только импортирующим чекером), 2/93/126
// (импорты до использования, хелперы выше), 167/112 (без shell и system()),
// 168 (rmdir только пустого каталога), 21 (timestamp-секунды неуникальны —
// id, а не ts, есть курсор подписчика), best-effort контракт: emit() никогда
// не бросает исключений и не роняет вызывающего.

'use strict';

import { access, readfile, open, unlink, rename, mkdir, rmdir, stat } from 'fs';
import { atomic_write, mkdir_p } from '/etc/homeproxy/scripts/statestore.uc';

const EV_DIR = '/var/run/homeproxy/events';
const JOURNAL = EV_DIR + '/journal.jsonl';
const JOURNAL_PREV = EV_DIR + '/journal.1.jsonl';
const COUNTER = EV_DIR + '/.next_id';
const LOCK = EV_DIR + '/.idlock';

const MAX_BYTES = 262144;   /* ротация текущего журнала (плюс прошлый — ≤ 512 КБ tmpfs) */
const STALE_SEC = 5;        /* залп-лок старше этого = держатель мёртв */
const LOCK_TRIES = 40;
const LOCK_RETRY_MS = 50;   /* бюджет ожидания лока ≈ 2 с */

/* ── хелперы (выше вызывающих — no hoisting) ── */

function take_lock() {
	mkdir_p(EV_DIR);
	for (let i = 0; i < LOCK_TRIES; i++) {
		if (mkdir(LOCK))
			return true;
		const st = stat(LOCK);
		if (st && (time() - st.mtime) > STALE_SEC) {
			/* Каталог лока ПУСТ (mkdir-лок без файлов) — rmdir легален (урок 168). */
			try { rmdir(LOCK); } catch (e) { /* кто-то уже снял */ }
		}
		sleep(LOCK_RETRY_MS);
	}
	return false;
};

function release_lock() {
	try { rmdir(LOCK); } catch (e) { /* не наш/уже снят */ }
};

function unlink_quiet(path) {
	try { unlink(path); } catch (e) { /* нет файла — норма */ }
};

function read_counter() {
	const n = int(trim(readfile(COUNTER) ?? ''));
	return (n > 0) ? n : 1;
};

function append_line(path, line) {
	const fd = open(path, 'a');
	if (fd == null)
		return false;
	try {
		fd.write(line);
		fd.close();
		return true;
	} catch (e) {
		try { fd.close(); } catch (e2) { /* уже закрыт */ }
		return false;
	}
};

function rotate_if_needed() {
	let sz = 0;
	try { const st = stat(JOURNAL); if (st) sz = st.size; } catch (e) { sz = 0; }
	if (sz >= MAX_BYTES) {
		try { rename(JOURNAL, JOURNAL_PREV); } catch (e) { /* prev занят? событий не теряем: текущий останется */ }
	}
};

/* ── публичный протокол ── */

/* Записать событие. Возвращает присвоенный id или null (best-effort).
 * src = 'control' | 'homeproxy' | ... ; type/who/detail — свободные строки. */
export function emit(src, type, who, detail) {
	mkdir_p(EV_DIR);
	if (!take_lock())
		return null;   /* fs сломан — append упал бы так же; честный drop */
	let id = null;
	try {
		id = read_counter();
		atomic_write(COUNTER, (id + 1) + '\n');
	} catch (e) {
		id = null;
	}
	release_lock();
	if (id == null)
		return null;
	const rec = {
		id: id,
		ts: time(),
		src: '' + (src || ''),
		type: '' + (type || ''),
		who: '' + (who || ''),
		detail: '' + (detail || '')
	};
	try { rotate_if_needed(); } catch (e) { /* ротация — не критична */ }
	/* 🔴 Компактный %J, НЕ %.J (доказано микротестом Ф1.7): %.J на этой сборке
	 * = pretty-print с переводами строк — многострочные записи рвут JSONL. */
	if (!append_line(JOURNAL, sprintf('%J', rec) + '\n'))
		return null;
	return id;
};

/* Текущая голова id (счётчик) — для базлайна подписчика при старте. */
export function last_id() {
	try { return read_counter(); } catch (e) { return 0; }
};

/* Хвост журнала: события с id > since_id (0 = все), последние limit, по
 * возрастанию id. Читает прошлую и текущую генерации; битые/надорванные
 * строки молча пропускаются. */
export function tail(limit, since_id) {
	const lim = (int(limit) > 0) ? int(limit) : 100;
	const since = (int(since_id) > 0) ? int(since_id) : 0;
	const out = [];
	for (let path in [JOURNAL_PREV, JOURNAL]) {
		if (!access(path))
			continue;
		let raw = null;
		try { raw = readfile(path); } catch (e) { raw = null; }
		if (raw == null)
			continue;
		for (let line in split(raw, '\n')) {
			const s = trim(line);
			if (!length(s))
				continue;
			let rec = null;
			try { rec = json(s); } catch (e) { rec = null; }
			if (rec == null || type(rec) !== 'object' || rec.id == null)
				continue;
			if (int(rec.id) <= since)
				continue;
			rec.id = int(rec.id);
			rec.ts = int(rec.ts);
			push(out, rec);
		}
	}
	sort(out, (a, b) => (a.id > b.id) ? 1 : (a.id < b.id) ? -1 : 0);
	const start = max(0, length(out) - lim);
	const res = [];
	for (let i = start; i < length(out); i++)
		push(res, out[i]);
	return res;
};

/* Очистить журнал (UI «очистить»): обе генерации + счётчик. Под локом,
 * чтобы параллельный emit не оказался «между» удалениями. */
export function clear() {
	try {
		mkdir_p(EV_DIR);
		if (take_lock()) {
			unlink_quiet(JOURNAL);
			unlink_quiet(JOURNAL_PREV);
			unlink_quiet(COUNTER);
			release_lock();
		}
	} catch (e) { /* best-effort */ }
};
