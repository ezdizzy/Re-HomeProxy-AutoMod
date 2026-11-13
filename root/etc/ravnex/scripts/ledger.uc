// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Persister Ledger (s205, REPORT_s205_persister_ledger_design.md).
//
// Низкочастотный флеш-слой для learned-состояния движка. Два носителя в
// /etc/ravnex/ledger/: СНАПШОТ (полная копия состояния, атомарная запись,
// редкая компакция) + append-only JSONL-журнал СЕМАНТИЧЕСКИХ переходов
// (learn/unlearn/quic/poison/fam/yt). Restore = снапшот + реплей хвоста
// журнала по монотонности seq (дыра/рваный хвост/битый файл = честная
// остановка и холодный старт, НИКОГДА не краш — контракт eventbus/statestore).
//
// Модуль листовой (импортирует только fs + statestore) — циклов в DAG нет.
// Высокочастотные данные (state-файл tmpfs, счётчики) остаются в tmpfs —
// s188-трейд не нарушается; леджер добавляет только низкочастотный слой.
//
// Износ флеша: журнал ~50–200 событий/день × ~150 Б; компакция только
// когда грязно и ≤1 раз за интервал; на eMMC (MT6000, f2fs) — десятилетия,
// бюджетный профиль для NOR-устройств см. дизайн §3.3 п.5.
//
// Уроки учтены: 166 (export-функции закрываются `};`), 2/93/126 (fs после
// import; хелперы ВЫШЕ вызывающих), 167/112 (никаких shell/system),
// eventbus-паттерн append (open 'a' + один write + close), `%J` для JSONL
// (НЕ `%.J` — pretty-print рвёт строки).

'use strict';

import { access, readfile, open, unlink, rename, stat } from 'fs';
import { write_state, read_state, mkdir_p } from '/etc/ravnex/scripts/statestore.uc';

/* ── каталог (переопределяемый селфтестом) ── */

let LG_DIR = '/etc/ravnex/ledger';
let LG_JOURNAL = LG_DIR + '/journal.jsonl';
let LG_JOURNAL_PREV = LG_DIR + '/journal.1.jsonl';
let LG_SNAPSHOT = LG_DIR + '/snapshot.json';

/* Селфтест-харнесс перенаправляет весь каталог (живые файлы не трогаются —
 * паттерн sandbox-пути s196/POOL_FILE). */
export function set_dir(dir) {
	LG_DIR = '' + dir;
	LG_JOURNAL = LG_DIR + '/journal.jsonl';
	LG_JOURNAL_PREV = LG_DIR + '/journal.1.jsonl';
	LG_SNAPSHOT = LG_DIR + '/snapshot.json';
};

export const LEDGER_VERSION = 1;
const JOURNAL_MAX_BYTES = 131072;   /* ротация текущего журнала (×2 файла ≤ 256 КБ) */

/* ── хелперы (выше вызывающих — no hoisting) ── */

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

function unlink_quiet(path) {
	try { unlink(path); } catch (e) { /* нет файла — норма */ }
};

function file_size(path) {
	try {
		const st = stat(path);
		return (st && st.size) ? st.size : 0;
	} catch (e) {
		return 0;
	}
};

function rotate_if_needed() {
	if (file_size(LG_JOURNAL) >= JOURNAL_MAX_BYTES) {
		try { rename(LG_JOURNAL, LG_JOURNAL_PREV); } catch (e) { /* prev занят — не критично */ }
	}
};

/* ── журнал ── */

/* Дописать пачку событий ОДНИМ open/write/close (батч цикла). Каждое событие:
 * { seq, ts, op, h, d } — seq присваивает вызывающий (монотонно). */
export function append_events(events) {
	if (events == null || type(events) !== 'array' || !length(events))
		return true;
	mkdir_p(LG_DIR);
	rotate_if_needed();
	let buf = '';
	for (let ev in events) {
		if (ev == null || type(ev) !== 'object')
			continue;
		buf += sprintf('%J', { seq: int(ev.seq || 0), ts: int(ev.ts || 0),
			op: '' + (ev.op || ''), h: '' + (ev.h || ''), d: (ev.d == null) ? {} : ev.d }) + '\n';
	}
	if (!length(buf))
		return true;
	return append_line(LG_JOURNAL, buf);
};

/* Прочитать обе генерации журнала по порядку (prev → current); битые/
 * надорванные строки молча пропускаются (тот же толеранс, что eventbus). */
export function read_events() {
	const out = [];
	for (let path in [LG_JOURNAL_PREV, LG_JOURNAL]) {
		if (!access(path))
			continue;
		let raw = null;
		try { raw = readfile(path); } catch (e) { raw = null; }
		if (raw == null || !length(raw))
			continue;
		for (let line in split(raw, '\n')) {
			line = trim(line);
			if (!length(line))
				continue;
			let ev = null;
			try { ev = json(line); } catch (e) { ev = null; }
			if (ev != null && type(ev) === 'object' && length('' + (ev.op || '')))
				push(out, ev);
		}
	}
	return out;
};

export function journal_bytes() {
	return file_size(LG_JOURNAL) + file_size(LG_JOURNAL_PREV);
};

/* План реплея: события с seq > base ПО ПОРЯДКУ, стоп ПЕРЕД дырой монотонности
 * (sq > base+1 → хвост не рискуем). Возвращает { base, torn, to_apply }:
 * base — последний применённый seq, torn — seq дыры (0 = цело), to_apply —
 * список событий для применения (САМО применение — у вызывающего, состояние
 * у него). Чистая функция — селфтест-гейт правил реплея. */
export function replay_plan(evs, base) {
	let cur = int(base || 0);
	let torn = 0;
	const to_apply = [];
	for (let ev in (evs || [])) {
		const sq = int(ev && ev.seq || 0);
		if (sq <= cur)
			continue;
		if (sq > cur + 1) {
			torn = sq;
			break;
		}
		push(to_apply, ev);
		cur = sq;
	}
	return { base: cur, torn: torn, to_apply: to_apply };
};

/* Убрать журналы (после компакции в снапшот). */
export function clear_journal() {
	unlink_quiet(LG_JOURNAL);
	unlink_quiet(LG_JOURNAL_PREV);
};

/* ── снапшот (statestore-конверт + ledger_version/seq внутри data) ── */

/* Возвращает { data, ts, seq } или null (нет/бит/чужая версия/старше 30 дней). */
export function read_snapshot(max_age_sec) {
	const r = read_state(LG_SNAPSHOT);
	if (r == null || r.data == null || type(r.data) !== 'object')
		return null;
	const d = r.data;
	if (int(d.ledger_version || 0) !== LEDGER_VERSION)
		return null;
	if (d.state == null || type(d.state) !== 'object')
		return null;
	/* Протухший снапшот = мусор лучше честного переобучения (дизайн §5).
	 * max_age_sec: не передан → дефолт 30 дней; передан (в т.ч. -1) → как есть. */
	const ts = int(r.meta && r.meta.ts || 0);
	const max_age = (max_age_sec == null || max_age_sec == '') ? 2592000 : int(max_age_sec);
	if (ts > 0 && (time() - ts) > max_age)
		return null;
	return { data: d, ts: ts, seq: int(d.seq || 0) };
};

/* Атомарно записать снапшот. data = { state, maps, fam_ledger, yt }. */
export function write_snapshot(data, seq) {
	mkdir_p(LG_DIR);
	write_state(LG_SNAPSHOT, {
		ledger_version: LEDGER_VERSION,
		seq: int(seq || 0),
		state: (data && data.state != null) ? data.state : {},
		maps: (data && data.maps != null) ? data.maps : {},
		fam_ledger: (data && data.fam_ledger != null) ? data.fam_ledger : {},
		yt: (data && data.yt != null) ? data.yt : {}
	});
};

/* Полный сброс (кнопка «Забыть выученное»): журналы + снапшот. */
export function reset_files() {
	unlink_quiet(LG_JOURNAL);
	unlink_quiet(LG_JOURNAL_PREV);
	unlink_quiet(LG_SNAPSHOT);
};
