// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — State Store (plan 20 §3 Ф1.7; audit 10).
// Единый механизм состояния рантайма: КАНОНИЧЕСКАЯ атомарная запись
// (temp с уникальным суффиксом + rename — без shell, без 2-arg system()),
// безопасное чтение JSON и ВЕРСИОНИРОВАННЫЙ конверт state-документов
// (schema_version + config_revision + ts), по которому Ф2 (Sentinel/Health)
// отличает свежее состояние от протухшего и переживает смену формата.
//
// Конверт (write_state):
//   { "schema_version": 1, "config_revision": <VERIFIED-ревизия opman>,
//     "ts": <unix>, "data": { ...сам документ... } }
// read_state() толерантен к легаси: документ без schema_version — это «старый
// формат целиком» (data = весь документ, meta = null), поэтому писатели и
// читатели мигрируют пофайлово без сломанного окна между деплоями.
//
// config_revision: монотонный счётчик VERIFIED применений — ЕДИНЫЙ источник
// значения это файл opman'а; здесь только ЧТЕНИЕ (путь экспортируется, opman
// импортирует его отсюда — дублирования константы нет; запись счётчика —
// исключительное право opman.bump_revision).
//
// DAG импортов: statestore — листовой модуль (импортирует только fs), его
// импортируют opman/pmgr/eventbus/все демоны — циклов нет.
//
// Уроки учтены: 166 (декларации функций модуля через `};`; `ucode -c` модуль
// с export не проверяет — только исполнение импортирующего чекера), 2/93/126
// (fs-функции после import; хелперы ВЫШЕ вызывающих), 167 (никаких shell-вызовов
// на горячем пути — rename() из fs), 112 (нет system() — нечего свипать),
// 110/100 (никаких flock/fd-локов), атомарность = temp+rename в том же каталоге.

'use strict';

import { access, readfile, writefile, rename, mkdir } from 'fs';

/* ── константы ── */

export const SCHEMA_VERSION = 1;

/* Единый с opman счётчик VERIFIED применений (opman пишет, здесь читаем). */
export const REV_PATH = '/var/run/homeproxy/state/config_revision';

/* ── низкоуровневые хелперы (выше всех вызывающих — no hoisting) ── */

/* 🔴 Доказано живьём (микротест Ф1.7): dirname на этой сборке НЕ глобальный
 * билтин — контрольная функция control.uc была собственной. Держим здесь. */
export function dirname(p) {
	const m = match('' + p, /^(.*)\/[^\/]+$/);
	return m ? m[1] : '.';
};

export function mkdir_p(p) {
	let cur = '';
	for (let part in split(p, '/')) {
		if (!length(part))
			continue;
		cur += '/' + part;
		if (!access(cur)) {
			try { mkdir(cur); } catch (e) { /* гонка exists — не фатал */ }
		}
	}
};

/* Уникальный суффикс temp-файла: параллельные писатели одного пути не
 * затирают temp друг друга (фиксированный '.tmp' из старых копий — гонка).
 * clock() на этой сборке = [секунды, наносекунды] (доказано opman/pmgr). */
function uniq_tail() {
	const c = clock();
	return int((c[1] / 1000) % 1000000);
};

/* ── каноническая атомарная запись (аудит 10: единый механизм) ── */

export function atomic_write(path, content) {
	mkdir_p(dirname(path));
	const tmp = path + '.tmp.' + uniq_tail();
	writefile(tmp, content);
	rename(tmp, path);
};

export function wjson(path, obj) {
	atomic_write(path, sprintf('%.J', obj) + '\n');
};

/* Safe JSON read: null для отсутствующего/битого/пустого файла. */
export function rjson(path) {
	if (!access(path))
		return null;
	let raw = null;
	try { raw = readfile(path); } catch (e) { raw = null; }
	if (raw == null || !length(trim(raw)))
		return null;
	try { return json(raw); } catch (e) { return null; }
};

/* ── ревизия применений (ЧТЕНИЕ; bump — только opman) ── */

export function read_revision() {
	const n = int(trim(readfile(REV_PATH) ?? ''));
	return (n > 0) ? n : 1;
};

/* ── версионированный конверт state-документов ── */

/* Атомарно записать state-документ в конверте
 * { schema_version, config_revision, ts, data }. */
export function write_state(path, data) {
	wjson(path, {
		schema_version: SCHEMA_VERSION,
		config_revision: read_revision(),
		ts: time(),
		data: data
	});
};

/* Прочитать state-документ с толерантностью к легаси.
 * Возвращает { meta, data }:
 *   конверт        → meta = { schema_version, config_revision, ts }, data = .data
 *   легаси (без schema_version) → meta = null, data = весь документ
 *   отсутствует/бит → meta = null, data = null
 * Читатель обязан рассматривать data == null как «состояния нет». */
export function read_state(path) {
	const doc = rjson(path);
	if (doc == null || type(doc) !== 'object')
		return { meta: null, data: null };
	if (doc.schema_version == null)
		return { meta: null, data: doc };
	return {
		meta: {
			schema_version: doc.schema_version,
			config_revision: doc.config_revision,
			ts: doc.ts
		},
		data: (type(doc.data) === 'object' || type(doc.data) === 'array') ? doc.data : null
	};
};
