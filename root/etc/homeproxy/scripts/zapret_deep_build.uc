#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex — Strategy Lab v3: deep-probe classifier + result builder for
 * zapret_test.sh --deep (Ф6.4; аудит 82 — ЕДИНЫЙ формат проб и ЕДИНА
 * классификация). zapret_test.sh собирает сырые файлы и скормляет этому
 * билдеру манифест через stdin; вся классификация — diag_core.classify_path
 * (Ф6.1), здесь только сборка и пороги скоростей (79/116 — битрейт-гейты
 * ytv/yts остаются честными скоростными, классификация контента к ним не
 * применима: ytv/yts не сохраняют тело).
 *
 * Вход (stdin, одна JSON-строка):
 *   { tmp:   "/tmp/zapret_test.NNN",
 *     hosts: [ ["tag","label","host"], … ],
 *     owners:{ yt:["ytp","ytpf","yti","ytr","ytv","yts"], tg:[…], … } }
 *
 * Читает (в каталоге tmp):
 *   r_<tag>  — "http_code time_appconnect redirect_url curl_exit" (3 или 4
 *              токена: redirect пуст → 3 токена, «-» подставляется);
 *   d_<id>   — сырая строка пробы: generic "code secs bytes speed rc",
 *              ytv "code secs bytes speed fetched start";
 *   b_<id>   — сохранённое тело пробы (для классификации контента).
 *
 * Выход (stdout, одна JSON-строка — прежняя форма + расширения):
 *   {"ok":N,"total":M,"deep_ok":K,"deep_total":T,
 *    "results":[{"tag","label","host","ip","code","tls","redirect","rc",
 *                "ok","reason","deep_ok","deep_total","deep":[item,…]}]}
 *   item = {"id","code","sec","bytes","speed","rc","ok","app_state","kind",
 *           "geo_refused","waf"[,"ttfb"]}
 *
 * Уроки учтены: 8 (ARGV ненадёжен — манифест через stdin), 245/252 (программа
 * — ucode -c, без export), 20/31 (for-in по массиву = элементы), 246 (нет
 * undefined — type()/null), 26/27 (match только /литералы/), 253 (falsy-ноль
 * в порогах — явные сравнения), 129 (обрезанная строка = честные нули).
 */

'use strict';

import { access, readfile } from 'fs';
import { classify_path } from '/etc/homeproxy/scripts/diag_core.uc';

const YTV_MIN_SPEED = 131072;   /* ≥128 КБ/с на держ-алайв-потоке (ч.116) */
const YTV_MIN_BYTES = 409600;   /* ≥0.4 МБ суммарно */
const YTS_MIN_SPEED = 131072;
const YTS_MIN_BYTES = 524288;   /* ≥0.5 МБ реального потока */

const man = json(readfile('/dev/stdin') || '');
const TMP = '' + (man != null ? man.tmp : '');
const hosts = (man != null && type(man.hosts) === 'array') ? man.hosts : [];
const owners = (man != null && type(man.owners) === 'object') ? man.owners : {};

const num = (v) => {
	const n = ('' + (v == null ? '' : v)) * 1.0;
	return (n != n) ? 0.0 : n;   /* NaN-проверка без isNaN (его может не быть) */
};

/* Один пункт deep-батареи → унифицированная запись (или null — пробы не
 * было: честное отсутствие, не «провал», урок 91). */
function deep_item(id) {
	const rp = TMP + '/d_' + id;
	if (!access(rp)) return null;
	const raw = trim(readfile(rp) || '');
	if (!length(raw)) return null;
	const parts = split(raw, /[[:space:]]+/);
	if (!length(parts)) return null;
	const code = ('' + parts[0]);
	const item = { id: id, code: (length(code) === 3) ? code : '000',
		sec: 0.0, bytes: 0, speed: 0, rc: 0, ok: 0,
		app_state: null, kind: null, geo_refused: 0, waf: null };
	if (id === 'ytv') {
		/* code tt ss spd oo st — синтетический вердикт окна (медиана), rc нет */
		item.sec = num(parts[1]);
		item.bytes = int(num(parts[2]));
		item.speed = int(num(parts[3]));
		item.rc = 0;
		item.ttfb = int(num(parts[5]) * 1000.0);
		item.ok = (item.code === '200' && item.speed >= YTV_MIN_SPEED &&
			item.bytes >= YTV_MIN_BYTES) ? 1 : 0;
		return item;
	}
	item.sec = num(parts[1]);
	item.bytes = int(num(parts[2]));
	item.speed = int(num(parts[3]));
	/* Ф6.4: content probes carry ttfb (time_starttransfer, сек → мс) —
	 * старт ОТВЕТА края; yts/yts2 несут его для видео-края (замер пользователя
	 * 2026-11-04: старт ВИДЕО не равен старту миниатюр). rc — последний токен. */
	item.ttfb = (length(parts) > 4) ? int(num(parts[4]) * 1000.0) : 0;
	item.rc = (length(parts) > 5) ? int(num(parts[5])) : ((length(parts) > 4) ? int(num(parts[4])) : 1);
	if (id === 'yts' || id === 'yts2') {
		item.ok = ((item.code === '200' || item.code === '206') &&
			item.speed >= YTS_MIN_SPEED && item.bytes >= YTS_MIN_BYTES) ? 1 : 0;
		return item;
	}
	/* Классификация контента — ТОЛЬКО diag_core (Ф6.1): одна реализация для
	 * всего проекта (аудит 72/82). Тело может отсутствовать (204/обрыв до
	 * тела) — classify_path честно отработает пустоту. */
	let body = '';
	const bp = TMP + '/b_' + id;
	if (access(bp))
		body = readfile(bp) || '';
	const c = classify_path({ code: item.code, rc: item.rc, tsec: null, body: body }, false, null);
	item.ok = (c.ok === true) ? 1 : 0;
	item.app_state = c.app_state;
	item.kind = c.kind;
	item.geo_refused = (c.geo_refused === true) ? 1 : 0;
	item.waf = c.waf;
	return item;
}

/* Ручная (handshake) проба тега → {code, tls, redirect, rc, ok, reason}. */
function hand_item(tag) {
	const rp = TMP + '/r_' + tag;
	if (!access(rp)) return null;
	const raw = trim(readfile(rp) || '');
	const parts = split(raw, /[[:space:]]+/);
	if (!length(parts)) return null;
	const code = (length(parts) > 0) ? ('' + parts[0]) : '000';
	const tls = num(parts[1]);
	let redirect = '-';
	let rc = 1;
	if (length(parts) >= 4) { redirect = '' + parts[2]; rc = int(num(parts[3])); }
	else if (length(parts) === 3) { rc = int(num(parts[2])); }
	if (redirect == null || !length(redirect) || !match(redirect, /^http/))
		redirect = '-';
	const ok = (tls > 0.0 && rc === 0) ? 1 : 0;
	let reason = '';
	if (tls > 0.0 && rc !== 0)
		reason = 'flow_reset';   /* handshake прошёл, поток порван — НЕ успех (82) */
	else if (!ok) {
		const rcmap = { '6': 'dns', '7': 'refused', '28': 'timeout',
			'35': 'tls', '51': 'tls', '53': 'tls', '56': 'tls',
			'58': 'tls', '59': 'tls', '60': 'tls' };
		reason = (rcmap['' + rc] != null) ? rcmap['' + rc] : 'fail';
	}
	return { code: code, tls: tls, redirect: redirect, rc: rc, ok: ok, reason: reason };
}

let deep_all = 0, deep_total_all = 0;
const results = [];
for (let h in hosts) {
	const tag = '' + h[0], label = '' + h[1], host = '' + h[2];
	const r = hand_item(tag);
	const hres = (r != null) ? r : { code: '000', tls: 0.0, redirect: '-', rc: 1, ok: false, reason: 'fail' };
	const ipf = TMP + '/ip_' + tag;
	const ip = access(ipf) ? trim(readfile(ipf) || '') : '';
	const out = { tag: tag, label: label, host: host, ip: ip,
		code: hres.code, tls: sprintf('%.6f', hres.tls),
		redirect: hres.redirect, rc: hres.rc, ok: hres.ok, reason: hres.reason };
	if (man.deep === true) {
		const ids = owners[tag];
		const items = [];
		if (type(ids) === 'array')
			for (let id in ids) {
				const it = deep_item('' + id);
				if (it != null)
					push(items, it);
			}
		let dok = 0;
		for (let it in items)
			if (it.ok == 1) dok++;
		out.deep_ok = dok;
		out.deep_total = length(items);
		out.deep = items;
		deep_all += dok;
		deep_total_all += length(items);
	}
	push(results, out);
}

let okc = 0;
for (let r in results)
	if (r.ok == 1) okc++;

const top = { ok: okc, total: length(results) };
if (man.deep === true) {
	top.deep_ok = deep_all;
	top.deep_total = deep_total_all;
}
/* Честный режим проб (skuid|fallback) — фаззер поднимает его в UI. */
if (man.probe != null)
	top.probe = '' + man.probe;
top.results = results;
print(sprintf("%.J\n", top));
