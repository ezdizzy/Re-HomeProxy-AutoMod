// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Health Monitor (plan 20 §3 Ф2.1; A.1 аудита, находки 3/4/37/46/49/88).
//
// Единый реестр наблюдаемых подсистем: ядро, движки (zapret/byedpi), MultiDNS +
// mosdns, автоматизация (+ probe_pool/sni_sniffer), telegram-бот,
// выход-движок (hotswap)/автопилот/контроль/метрики, TUN/route (tun_state.json),
// fw4-перехват, генераторы (opman-журнал применений) и память роутера.
// (ч.200, D34b: tg-ws мост удалён из продукта — запись реестра убрана.)
//
// Статусы (честные, раздельные — A.1 «отказ VPN ≠ отказ WAN ≠ отказ DNS»):
//   ok       — работает, свидетельство свежее;
//   degraded — работает, но с проблемой (слушателей нет, API молчит, память на
//              грани, применение не верифицировано) — ОТЛИЧИМ от падения;
//   down     — не работает, хотя должен;
//   off      — выключен настройками (инстанса нет в procd) — НОРМА, не аларм
//              (урок 126: несмертельные демоны; выход-движок штатно не
//              запущен при Hot Swap и т.п.).
// Уверенность: certain — прямая проверка сейчас (identity /proc, слушатель,
// ответ API, procd-вердикт); indirect — вывод (окно респавна, несвежее
// свидетельство, перенос с прошлой глубокой проверки).
//
// Источник ожиданий: НАБОР procd-инстансов службы homeproxy (`ubus call
// service list`, урок 171 — service get сломан) ЕСТЬ истина «что должно
// работать»: init.d сам гейтит инстансы по UCI. Идентичность процессов —
// Process Manager (pmgr): реестр daemons.json (владельцы регистрируются сами
// и пингуют heartbeat) + скан /proc для не-владельческих (ядро, движки,
// tun-route) ОДНИМ проходом. mosdns проверяется по СЛУШАТЕЛЯМ, не по pid
// (урок 215). SNI-сниффер — runtime-state (находка 88). TUN — tun_state.json
// (Ф1.3). fw4 — наличие цепей homeproxy в таблице inet fw4 (рантайм-правда).
// Генераторы — вердикт последней операции opman (Ф1.1), статус ≠ блокировка
// (находка 49).
//
// Адаптивная нагрузка (риск-карта Ф2, ОOM-грань Ф10, урок 197): лёгкий проход
// БЕЗ fork'ов (readfile-реестр + файлы состояния) по умолчанию каждые 20 с;
// глубокий (до 6 fork'ов: service list, скан /proc, Clash API, netstat, nft,
// журнал опов) раз в ~2 мин. Любая проблема → быстрый режим (5 с / ~10 с) с
// откатом через 120 с стабильного ok. MemAvailable < 48 МБ — глубокие проверки
// пропускаются (лёгкие остаются). Документ пишется КАЖДЫЙ тик (ts = живое
// свидетельство работы самого монитора — RPC проверяет свежесть по нему).
//
// События: изменение статуса (без off-переходов и базлайна) → шина
// eventbus.emit(src='health'); читатели — единая лента LuCI-журнала и будущие
// подписчики (ремонты Recovery Manager'а Ф2.3 обязаны писать в ту же шину).
// Базлайн — при отсутствии предыдущего документа (ребут: tmpfs пуст) — молча,
// без событий (урок 220: базлайн ОДИН раз; рестарт демона базлайнит только
// если файла нет — иначе честная дифф-разница продолжается).
//
// DAG импортов: health → pmgr/opman/eventbus/statestore (листовые) — циклов нет.
// Модуль ТОЛЬКО вычисляет/хранит; демон-цикл живёт в health_cli.uc (урок 178:
// модуль+CLI раздельно — export нельзя исполнять как скрипт).
//
// Уроки учтены: 166 (`};` у функций модуля; проверка модуля только импортирующим
// чекером), 216 (top-level const НАВЕРХУ файла), 2/93/126 (fs после import,
// хелперы выше вызывающих, несмертельная обёртка в CLI), 20/180 (for-in по
// массиву = элементы), 26 (match только с /литералом/ — проверки портов через
// index()), 211 (%J компактный JSON), 212 (dirname не билтин), 209 (дефолты
// портов едины с multidns.uc: 5453/5454), 171 (service list), 215 (слушатели
// ≠ pid), 179 (identity (pid,start), zombie = мёртв), 167 (никаких 2-arg
// system()), 130 (не-ASCII в исходнике допустимо — строки бэкенда русские).

'use strict';

import { readfile, popen, stat, access } from 'fs';
import { cursor } from 'uci';
import {
	read_state as ss_read_state, write_state as ss_write_state, rjson as ss_rjson,
	atomic_write as ss_atomic_write
} from '/etc/ravnex/scripts/statestore.uc';
import {
	REG_PATH as PM_REG_PATH, entry_alive as pm_entry_alive,
	reg_get as pm_reg_get, reg_set as pm_reg_set
} from '/etc/ravnex/scripts/pmgr.uc';
import { list_ops as op_list } from '/etc/ravnex/scripts/opman.uc';
import { emit as ev_emit } from '/etc/ravnex/scripts/eventbus.uc';

/* ── константы (урок 216: всё наверху, выше первой функции) ─────────────── */

export const HEALTH_PATH = '/var/run/ravnex/health.json';
export const SRC = 'health';

const RUN_DIR = '/var/run/ravnex';
const SCRIPTS_DIR = '/etc/ravnex/scripts';
const NUL = sprintf('%c', 0);

const TUN_STATE_PATH = RUN_DIR + '/tun_state.json';
const SNI_STATE_PATH = RUN_DIR + '/sni_state.json';
/* Heartbeat-файл резидентного probe_pool (пишет сам Go-демон; семантика
 * живости — mtime < 30 с, ровно как automation.pp_daemon_alive). */
const PP_HB_PATH = RUN_DIR + '/pp.daemon.json';

/* Память роутера (урок 197: Keenetic живёт на грани — OOM-киллер убивал ядро
 * при 727 МБ RSS). Пороги в КБ MemAvailable. */
export const MEM_WARN_KB = 65536;      /* < 64 МБ — degraded */
export const MEM_CRIT_KB = 32768;      /* < 32 МБ — down */
export const MEM_DEEP_SKIP_KB = 49152; /* < 48 МБ — глубокие проверки пропустить */

/* tun_state.json пишется ТОЛЬКО по изменению (Ф1.3) — старый ts при ok-статусе
 * легален; «несвежесть» снижает уверенность, но не создаёт аларм. */
export const TUN_STALE_SEC = 300;

/* Оп применения старше этого — «завис» (lease opman = 120 с; урок 216-хвост:
 * застрявший queued чистится ручным прогоном руннера). */
export const OP_STALE_SEC = 900;
/* Генераторы смотрят только свежие операции (за сутки). */
export const OP_WINDOW_SEC = 86400;

/* Окно доверия переносам глубокой проверки в лёгкий проход. */
export const CARRY_SEC = 600;

/* Clash API — тот же источник, что у всех helpers RPC (127.0.0.1:9090). */
export const API_URL = 'http://127.0.0.1:9090';

/* Порты mosdns по умолчанию — РОВНО как в multidns.uc (урок 209: дефолт
 * отсутствующей опции един во всех читателях). */
export const MDNS_PLAIN_DEFAULT = 5453;
export const MDNS_SECURE_DEFAULT = 5454;

const RANK = { ok: 0, off: 0, degraded: 1, down: 2 };

/* ── мелкие хелперы (выше вызывающих — no hoisting) ─────────────────────── */

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) {
		out = fd.read('all') || '';
		fd.close();
	}
	return out;
};

function parse_json(s) {
	if (s == null || !length('' + s))
		return null;
	try { return json(s); } catch (e) { return null; }
};

function basename_of(p) {
	const i = rindex('' + p, '/');
	return (i >= 0) ? substr('' + p, i + 1) : ('' + p);
};

export function status_rank(st) {
	const r = RANK['' + st];
	return (r != null) ? r : 0;
};

/* Общий вердикт = худший статус среди НАБЛЮДАЕМЫХ записей (off не считается).
 * Все off → 'off' (сервис выключен настройками — норма). */
export function overall_of(entries) {
	let worst = 'off';
	for (let k in entries) {
		const st = '' + (entries[k].status || 'off');
		if (st === 'off')
			continue;
		if (worst === 'off' || status_rank(st) > status_rank(worst))
			worst = st;
	}
	return worst;
};

function mk_entry(name, label, group, status, confidence, reason, detail) {
	return {
		name: '' + name,
		label: '' + label,
		group: '' + group,
		status: '' + status,
		confidence: '' + confidence,
		reason: '' + (reason || ''),
		expected: (status !== 'off'),
		checked: time(),
		detail: (detail != null && type(detail) === 'object') ? detail : {}
	};
};

/* ── parse-хелперы (чистые — покрываются selftest) ──────────────────────── */

export function parse_meminfo_kb(raw) {
	const m = match('' + (raw || ''), /MemAvailable:\s+([0-9]+)/);
	return (m != null) ? int(m[1]) : -1;
};

export function parse_load1(raw) {
	const m = match('' + (raw || ''), /^([0-9]+\.[0-9]+)/);
	return (m != null) ? m[1] : null;
};

/* Число цепей homeproxy в таблице fw4 (рантайм-правда nftables, не файлы). */
export function parse_nft_count(raw) {
	const n = int(trim('' + (raw || '')));
	return (n > 0) ? n : 0;
};

/* Слушатель mosdns в выводе netstat: локальный адрес 127.0.0.1:<порт>.
 * index() вместо match() со строкой (урок 26); ':5453' не матчит ':15453'
 * (после ':' в ':15453' идёт '1'). */
export function listener_count(netstat_out, plain, secure) {
	let n = 0;
	const p1 = '127.0.0.1:' + int(plain);
	const p2 = '127.0.0.1:' + int(secure);
	for (let line in split('' + (netstat_out || ''), '\n')) {
		if (index(line, p1) >= 0 || index(line, p2) >= 0)
			n++;
	}
	return n;
};

/* ── procd-инстансы (ожидания; урок 171: service list, не service get) ──── */

export function service_instances() {
	const doc = parse_json(capture('ubus call service list 2>/dev/null'));
	const inst = (doc != null &&
		((doc.ravnex && type(doc.ravnex.instances) === 'object') ||
		 (doc.homeproxy && type(doc.homeproxy.instances) === 'object'))) ? (doc.ravnex || doc.homeproxy).instances : {};
	const out = {};
	for (let k in inst)
		out['' + k] = (inst[k] != null && inst[k].running === true) ? true : false;
	return out;
};

	/* ── скан процессов ОДНИМ проходом (не-владельческие: ядро, движки,
 * tun-route; реестр pmgr гарантирует их только после scan_registry, который
 * в рантайме никто не зовёт) ──────────────────────────────────────────────
 * want = { '<имя записи>': { exe: 'hiddify-core' } | { script: 'tun_route_watch.sh' } }
 * → { '<имя записи>': { pid, start, exe } } — первая находка на имя.
 * readfile на cmdline каждого pid — дёшево (память); fork ОДИН (ls /proc). */
export function scan_procs(want) {
	const out = {};
	if (want == null || type(want) !== 'object')
		return out;
	const listing = capture('ls -1 /proc 2>/dev/null');
	for (let line in split(listing, '\n')) {
		const p = trim(line);
		if (!match(p, /^[0-9]+$/))
			continue;
		const craw = readfile('/proc/' + p + '/cmdline');
		if (craw == null || !length(craw))
			continue;
		const parts = split(craw, NUL);
		for (let name in want) {
			if (out[name] != null)
				continue;
			const spec = want[name];
			let hit = null;
			if (spec.exe != null) {
				/* exe is a bare name OR an array of names (multi-core: the
				 * active engine may be hiddify-core or a sing-box family
				 * binary; lesson 233 still applies — basenames only). */
				const exes = (type(spec.exe) === 'array') ? spec.exe : [ '' + spec.exe ];
				for (let e in parts) {
					if (!length(e))
						continue;
					const bn = basename_of(e);
					for (let x in exes) {
						if (bn === '' + x) {
							hit = { pid: int(p), exe: '' + e };
							break;
						}
					}
					if (hit != null)
						break;
				}
			} else if (spec.script != null) {
				const full = SCRIPTS_DIR + '/' + spec.script;
				for (let e in parts) {
					if (e === full) {
						hit = { pid: int(p), exe: full };
						break;
					}
				}
			}
			if (hit == null)
				continue;
			/* starttime из /proc/<pid>/stat — после последней ')', поле 22. */
			const raw = readfile('/proc/' + p + '/stat');
			let start = 0;
			if (raw != null) {
				const i = rindex(raw, ')');
				if (i >= 0) {
					const f = split(substr(raw, i + 2), ' ');
					if (length(f) >= 20)
						start = int(f[19]);
				}
			}
			hit.start = start;
			out[name] = hit;
		}
	}
	return out;
};

/* Живая запись реестра pmgr (смерть/переиспользование pid/zombie — урок 179). */
function live_reg(name) {
	const e = pm_reg_get('' + name);
	return (e != null && pm_entry_alive(e)) ? e : null;
};

/* Впитать свежую identity из скана в реестр (ТОЛЬКО когда запись отсутствует
 * или мертва — живые владельческие записи не трогаем). Само-лечение гонки
 * потерь обновлений при старте службы (найдено Ф2.1 ч.164).
 * 🔴 Урок 225 (ч.165, живой лов — флап degraded↔recovered каждые 5 с):
 * для SCRIPT-попаданий в exe пишется null: /proc/<pid>/exe у ucode-демона —
 * путь ИНТЕРПРЕТАТОРА (/usr/bin/ucode), а не скрипта; exe=путь-скрипта делал
 * entry_alive вечным false (light-проход — все мёртвые, deep — живые по
 * скану → флаб в fast-режиме, шторм событий в ленте). Для бинарных движков
 * exe=hит-путь легален (basename/полный путь матчатся). */
function heal_reg(name, hit, kind, script_name) {
	if (hit == null)
		return;
	const prev = pm_reg_get('' + name);
	if (prev != null && pm_entry_alive(prev))
		return;
	pm_reg_set('' + name, {
		pid: hit.pid, start: hit.start,
		exe: (script_name != null) ? null : hit.exe,
		script: (script_name != null) ? ('' + script_name) : null,
		kind: kind || 'scanned', note: 'health-scan'
	});
};

/* ── ucode-читатели (урок 208: без shell, курсором) ─────────────────────── */

function uci_str(conf, sect, opt) {
	try {
		const c = cursor();
		const v = c.get(conf, sect, opt);
		return (v != null) ? '' + v : '';
	} catch (e) {
		return '';
	}
};

function mdns_ports() {
	const p = uci_str('ravnex', 'multidns', 'plain_port');
	const s = uci_str('ravnex', 'multidns', 'secure_port');
	return {
		plain: (length(p) && int(p) > 0) ? int(p) : MDNS_PLAIN_DEFAULT,
		secure: (length(s) && int(s) > 0) ? int(s) : MDNS_SECURE_DEFAULT
	};
};

/* Карта живости реестра pmgr одним чтением (+ entry_alive на каждую запись —
 * readfile-дёшево). */
function registry_status_map() {
	const raw = ss_rjson(PM_REG_PATH);
	const out = {};
	if (raw == null || type(raw.daemons) !== 'object')
		return out;
	for (let name in raw.daemons) {
		const e = raw.daemons[name];
		e.alive = pm_entry_alive(e);
		out[name] = e;
	}
	return out;
};

/* ── конструкторы записей ───────────────────────────────────────────────── */

/* Типовой procd-демон со скриптовой идентичностью. Живость = СКАН (глубокий)
 * ИЛИ живая identity реестра (лёгкий); скан сильнее — реестр может нести
 * запись с мёртвым identity при живом hb (гонка потерь обновлений при старте
 * службы, найдено Ф2.1 ч.164; pmgr.reg_hb теперь переприсваивает identity,
 * а глубокий проход дополнительно само-лечит запись). */
function daemon_entry(name, label, group, inst_name, reg_name, script_name, svc, regst, scan) {
	if (svc['' + inst_name] == null)
		return mk_entry(name, label, group, 'off', 'certain',
			'выключен настройками — инстанс «' + inst_name + '» не запущен', {});
	if (svc['' + inst_name] === false)
		return mk_entry(name, label, group, 'down', 'certain',
			'procd: инстанс «' + inst_name + '» не работает (respawn-окно или бюджет исчерпан)', {});
	const e = (regst != null && regst['' + reg_name] != null) ? regst['' + reg_name] : null;
	const reg_alive = (e != null && e.alive === true);
	const hit = (scan != null && scan['' + name] != null) ? scan['' + name] : null;
	if (hit != null) {
		/* Само-лечение реестра: запись отсутствует или мертва — впишем
		 * свежую identity из скана (владельческие hb не трогаем). */
		heal_reg(reg_name, hit, 'script', script_name);
		const hb_age = (e != null && e.hb > 0) ? (time() - int(e.hb)) : null;
		return mk_entry(name, label, group, 'ok', 'certain',
			'инстанс и идентичность подтверждены', {
				pid: hit.pid, hb_age: hb_age
			});
	}
	if (reg_alive) {
		const hb_age = (e.hb > 0) ? (time() - int(e.hb)) : -1;
		return mk_entry(name, label, group, 'ok', 'certain',
			'инстанс и идентичность подтверждены', {
				pid: e.pid, hb_age: (hb_age >= 0) ? hb_age : null
			});
	}
	return mk_entry(name, label, group, 'degraded', 'indirect',
		'инстанс жив, идентичность «' + reg_name + '» не подтверждена (окно респавна или старт)',
		{ respawn_window: true });
};

/* «Напрямую» (Ф3.1) — единственный режим, где отсутствие инстанса ядра
 * легитимно (ядро по настройкам не запускается). Легаси custom/custom_json
 * читаются как рабочий режим (та же нормализация, что в init.d). */
function core_mode_direct() {
	const m = uci_str('ravnex', 'config', 'routing_mode');
	return (m === 'direct');
};

const CORE_LABEL = 'Ядро (hiddify-core/sing-box)';

/* Ф3.2 (T2b, живой лов 2026-11-04): в рабочем режиме отсутствие инстанса
 * ядра — это СМЕРТЬ (убит/удалён извне/procd сдался), а не «выключено
 * настройками»: перехват ещё активен, LAN без интернета. Ложный off глушил
 * и событие (off-переходы не алармятся), и ремонт (Recovery off не читает) —
 * пользователь оставался без интернета, пока сам не нажал «Перезапуск
 * службы». Чистая функция — самопроверяемая (mode_direct параметром). */
export function core_missing_verdict(mode_direct) {
	if (mode_direct === true)
		return mk_entry('core', CORE_LABEL, 'core', 'off', 'certain',
			'режим «Напрямую» — ядро по настройкам не запускается', {});
	return mk_entry('core', CORE_LABEL, 'core', 'down', 'certain',
		'инстанс «hiddify-c» исчез из service list в рабочем режиме — ' +
		'внешнее вмешательство или сбой procd (перехват висит без слушателей)', {});
};

/* Честный вердикт ядра в ЛЁГКОМ проходе (чистая функция — самопроверяемая):
 * svc-факт из кэша глубокого прохода, живость identity реестра СВЕЖАЯ
 * (registry_status_map пересчитал alive форклесс), API-факт — переносом.
 * Мёртвая identity ядра = down, а не «окно респавна»: degraded никем не
 * ремонтируется (Recovery читает только down) — T2b простоял 2 мин. */
/* 🔴 СЕАНС 158/Б1-класс: хелперы Б2/Б4 (mosdns_broken_read/entry,
 * core_stale_compare/feed_note, core_stale_reason) объявлены ЗДЕСЬ — ВЫШЕ
 * всех вызывающих (mosdns_entry/light_entries/core_entry): на этой сборке
 * ucode вызов top-level имени, объявленного НИЖЕ вызывающей функции, крашится
 * в момент исполнения (урок 294 в полной форме, доказано t1–t7 + живой репро). */
/* Сеанс 158/Б2: mosdns — НЕ apk-пакет, а бинарник из фида/install.sh. Отсутствие
 * бинарника или незапускаемость — НЕ «down» (авто-рестарт не поможет), а честное
 * деградировавшее состояние с путём установки. multidns.uc после 3 неудачных
 * стартов подряд пишет флаг и приостанавливает шторм рестартов (10 мин). */
const MOSDNS_BIN = '/usr/bin/mosdns';
const MOSDNS_BROKEN_FILE = '/var/run/ravnex/multidns/mosdns.broken';
const MOSDNS_BROKEN_TTL = 1800;
/* Сеанс 158/Б4: кэш манифеста фида (пишет RPC feed_status; здесь ТОЛЬКО чтение,
 * сеть не трогается) — источник подсказки «в фиде доступно ядро X». */
const FEED_MANIFEST_CACHE = '/var/run/ravnex/feed_manifest.json';

/* Чтение свежего флага «mosdns не запускается» (сеанс 158/Б2). null = флага
 * нет/протух. */
export function mosdns_broken_read(now) {
	try {
		if (!access(MOSDNS_BROKEN_FILE))
			return null;
		const j = parse_json(readfile(MOSDNS_BROKEN_FILE) || '');
		if (j != null && type(j) === 'object' && int(j.ts || 0) > 0 &&
		    (now - int(j.ts)) <= MOSDNS_BROKEN_TTL)
			return j;
	} catch (e) { /* нет/битый файл — норма */ }
	return null;
};

/* Чистая часть вердикта «не запускается» (selftest). */
export function mosdns_broken_entry(flag, now) {
	if (flag == null || type(flag) !== 'object')
		return null;
	const n = int(flag.attempts || 0);
	return {
		name: 'mosdns', label: 'mosdns (пулы MultiDNS)', group: 'dns',
		status: 'degraded', confidence: 'certain',
		reason: 'mosdns не запускается (' + n + ' неудачных стартов подряд, автоподъём приостановлен) — переустановите: Обслуживание → Управление ядром, карточка mosdns (установка из фида)',
		expected: true,
		checked: now,
		detail: { attempts: n, broken_ts: int(flag.ts || 0), broken: true }
	};
};

/* Чистое сравнение версий ядра с кандидатом фида (сеанс 158/Б4): версия пакета
 * фида несёт суффикс -rN (5.5.5-r1), бинарник отвечает upstream-версией (5.5.5) —
 * сравниваем базу. null = совпадает/несравнимо (подсказки нет). */
export function core_stale_compare(installed_v, candidate_v) {
	const iv = trim('' + (installed_v || ''));
	const cv = trim('' + (candidate_v || ''));
	if (!length(iv) || !length(cv))
		return null;
	const cm = match(cv, /^([0-9]+(\.[0-9]+)*)/);
	const base = (cm != null) ? cm[1] : cv;
	if (iv === base)
		return null;
	return { installed: iv, candidate: cv };
};

/* Установленная версия ядра против кэша манифеста фида. fork (bin version) —
 * только в deep-проходе; без кэша/версии — null (подсказки нет). */
export function core_stale_feed_note() {
	let cand = null;
	try {
		const cache = parse_json(readfile(FEED_MANIFEST_CACHE) || '');
		if (cache != null && type(cache) === 'object' && cache.manifest != null &&
		    type(cache.manifest.pkgs) === 'object' &&
		    cache.manifest.pkgs['hiddify-core'] != null)
			cand = '' + (cache.manifest.pkgs['hiddify-core'].version || '');
	} catch (e) { /* нет кэша — подсказки нет */ }
	if (cand == null || !length(cand))
		return null;
	const out = trim(capture('/usr/bin/hiddify-core version 2>/dev/null'));
	const vm = match(out, /version v?([0-9][0-9a-zA-Z._-]*)/);
	if (vm == null)
		return null;
	return core_stale_compare(vm[1], cand);
};
function core_stale_reason(base_reason) {
	try {
		const stale = core_stale_feed_note();
		if (stale != null)
			return base_reason + '; в фиде доступно ядро ' + stale.candidate +
				' (установлено ' + stale.installed + ') — обновите: Обслуживание → Управление ядром';
	} catch (e) { /* подсказка — best-effort */ }
	return base_reason;
}

export function light_core_entry(svc_core, core_reg_all, prev_core, mode_direct, now) {
	if (svc_core == null)
		return core_missing_verdict(mode_direct);
	if (svc_core === false)
		return mk_entry('core', CORE_LABEL, 'core', 'down', 'certain',
			'procd: инстанс ядра не работает (respawn-окно или бюджет исчерпан)', {});
	const core_reg = (core_reg_all != null && core_reg_all.alive === true) ? core_reg_all : null;
	if (core_reg != null) {
		const d = { pid: core_reg.pid };
		let api_degraded = false;
		if (prev_core != null && prev_core.detail != null &&
		    prev_core.detail.api_checked != null &&
		    (now - int(prev_core.detail.api_checked)) < CARRY_SEC &&
		    prev_core.detail.api_ok === false) {
			d.api_ok = false;
			d.api_checked = prev_core.detail.api_checked;
			api_degraded = true;
		}
		return (api_degraded)
			? mk_entry('core', CORE_LABEL, 'core', 'degraded', 'indirect',
				'Clash API не отвечал при последней глубокой проверке (' +
				int((now - int(prev_core.detail.api_checked)) / 60) + ' мин назад)', d)
			: mk_entry('core', CORE_LABEL, 'core', 'ok', 'certain',
				'ядро живо (идентичность подтверждена; API — с последней глубокой проверки)', d);
	}
	if (core_reg_all != null)
		return mk_entry('core', CORE_LABEL, 'core', 'down', 'certain',
			'процесс ядра мёртв (identity реестра не отвечает) — ' +
			'перехват висит без слушателей', { dead_identity: true });
	return mk_entry('core', CORE_LABEL, 'core', 'degraded', 'indirect',
		'инстанс жив, процесс ядра не подтверждён (окно респавна или старт)',
		{ respawn_window: true });
};

function core_entry(core_hit, svc, now) {
	const label = CORE_LABEL;
	if (svc['hiddify-c'] == null)
		return core_missing_verdict(core_mode_direct());
	if (svc['hiddify-c'] === false)
		return mk_entry('core', label, 'core', 'down', 'certain',
			'procd: инстанс ядра не работает (respawn-окно или бюджет исчерпан)', {});
	if (core_hit == null)
		return mk_entry('core', label, 'core', 'degraded', 'indirect',
			'инстанс жив, процесс ядра не подтверждён (окно респавна или старт)',
			{ respawn_window: true });
	/* Глубокое уточнение: живой ответ Clash API (процесс может быть жив и
	 * подвешен — API молчит; класс «перезапуск с проверкой слушателя»). */
	const api_out = trim(capture('wget -qO- --timeout=3 ' + API_URL + '/version 2>/dev/null'));
	const api_ok = length(api_out) > 0;
	if (!api_ok)
		return mk_entry('core', label, 'core', 'degraded', 'certain',
			'процесс ядра жив, Clash API (9090) не отвечает', {
				pid: core_hit.pid, api_ok: false, api_checked: now
			});
	return mk_entry('core', label, 'core', 'ok', 'certain',
		core_stale_reason('ядро живо, Clash API отвечает'), {
			pid: core_hit.pid, api_ok: true, api_checked: now
		});
};

/* Сеанс 158/Б4: в ok-записи ядра — честная подсказка «в фиде доступно X»,
 * когда установленная версия отличается от кандидата фида (кэш манифеста,
 * только чтение). fork (bin version) — deep-проход и так делает форки. */

function engine_entry(name, label, inst_name, hit, svc) {
	if (svc['' + inst_name] == null)
		return mk_entry(name, label, 'dpi', 'off', 'certain',
			'выключен настройками — инстанс «' + inst_name + '» не запущен', {});
	if (svc['' + inst_name] === false)
		return mk_entry(name, label, 'dpi', 'down', 'certain',
			'procd: инстанс «' + inst_name + '» не работает (respawn-окно или бюджет исчерпан)', {});
	if (hit == null)
		return mk_entry(name, label, 'dpi', 'degraded', 'indirect',
			'инстанс жив, процесс движка не подтверждён (окно респавна или старт)',
			{ respawn_window: true });
	return mk_entry(name, label, 'dpi', 'ok', 'certain',
		'движок жив (идентичность подтверждена)', { pid: hit.pid });
};

/* Плановое окно рестарта mosdns (Ф9.15а, ч.200): пересборка конфигурации
 * (learned-списки/quarantine/UCI) рестартит mosdns на секунды — это НЕ
 * инцидент. multidns.uc пишет RESTART_MARK перед рестартом (ts внутри)
 * и снимает после подъёма слушателей; протухшая копия само-истекает
 * (60 с, семантика multidns_status «restarting»). Пока маркер свеж —
 * запись остаётся 'ok' с честной пометкой; аларма только если mosdns
 * не вернётся за окно маркера. Рестарты прорежены дебаунсом в multidns.uc. */
const MOSDNS_RESTART_MARK = '/var/run/ravnex/multidns/mosdns.restarting';
const MOSDNS_RESTART_FRESH = 60;

function mosdns_restarting(now) {
	let ts = -1;
	try {
		const txt = trim(readfile(MOSDNS_RESTART_MARK) || '');
		if (match(txt, /^[0-9]+$/))
			ts = int(txt);
	} catch (e) {}
	if (ts < 0) {
		try {
			const st = stat(MOSDNS_RESTART_MARK);
			if (st != null && st.mtime > 0)
				ts = int(st.mtime);
		} catch (e) {}
	}
	return (ts > 0 && (now - ts) < MOSDNS_RESTART_FRESH);
};

function mosdns_entry(svc, regst, now) {
	const label = 'mosdns (пулы MultiDNS)';
	if (svc['multidns'] == null)
		return mk_entry('mosdns', label, 'dns', 'off', 'certain',
			'MultiDNS выключен — mosdns не ожидается', {});
	/* Сеанс 158/Б2: бинарника нет — честное «не установлен» с путём установки
	 * (авто-рестарт бессмыслен; down-цикл и неверный совет «Перезапуск службы»
	 * сняты). Слушатели у работающего mosdns проверяются ниже. */
	if (!access(MOSDNS_BIN))
		return mk_entry('mosdns', label, 'dns', 'degraded', 'certain',
			'mosdns не установлен (MultiDNS включён) — установите: Обслуживание → Управление ядром, карточка mosdns (установка из фида)', {
				listeners: 0, listeners_checked: now, not_installed: true
			});
	/* Сеанс 158/Б2: multidns приостановил автоподъём после неудачных стартов —
	 * честное «не запускается» вместо цикла down↔«плановый рестарт». */
	const brk = mosdns_broken_entry(mosdns_broken_read(now), now);
	if (brk != null)
		return mk_entry(brk.name, brk.label, brk.group, brk.status, brk.confidence,
			brk.reason, brk.detail);
	/* Живая проверка: слушатели 5453/5454 (урок 215 — не pid). */
	const ports = mdns_ports();
	const listeners = listener_count(capture('netstat -lun 2>/dev/null'), ports.plain, ports.secure);
	const e = (regst != null && regst['mosdns'] != null) ? regst['mosdns'] : null;
	const alive = (e != null && e.alive === true);
	if (listeners > 0)
		return mk_entry('mosdns', label, 'dns', 'ok', 'certain',
			'слушатели ' + ports.plain + '/' + ports.secure + ' привязаны', {
				listeners: listeners, listeners_checked: now,
				pid: (e != null) ? e.pid : null
			});
	/* Плановое окно рестарта — не инцидент (см. комментарий над mosdns_restarting). */
	if (mosdns_restarting(now))
		return mk_entry('mosdns', label, 'dns', 'ok', 'indirect',
			'короткое окно планового рестарта (пересборка конфигурации MultiDNS) — ' +
			'аларма только если mosdns не вернётся за ' + MOSDNS_RESTART_FRESH + ' с', {
				listeners: 0, listeners_checked: now, restarting: true
			});
	if (alive)
		return mk_entry('mosdns', label, 'dns', 'degraded', 'certain',
			'процесс жив, слушатели ' + ports.plain + '/' + ports.secure + ' не поднялись ' +
			'(старт асинхронный — урок 215; пулы могут быть пусты)', {
				listeners: 0, listeners_checked: now, pid: e.pid
			});
	return mk_entry('mosdns', label, 'dns', 'down', 'certain',
		'процесс mosdns отсутствует, слушателей нет', {
			listeners: 0, listeners_checked: now
		});
};

/* probe_pool — ЛЕНИВЫЙ резидент (живой факт ч.164): automation.uc поднимает
 * его при первой волне классификации (spawn-окно до 5 мин), между волнами
 * процесса может легитимно не быть. Отсутствие процесса = НЕ деградация.
 * Деградация — когда heartbeat-файл свежий (<30 с, семантика
 * automation.pp_daemon_alive), а процесса нет: «умер между heartbeat'ами». */
export function probe_pool_entry_from(hit, hb_age, auto_uptime) {
	const label = 'probe_pool (резидентный prober)';
	if (hit != null)
		return mk_entry('probe_pool', label, 'automation', 'ok', 'certain',
			'prober жив (идентичность подтверждена)', { pid: hit.pid });
	if (hb_age >= 0 && hb_age < 30)
		return mk_entry('probe_pool', label, 'automation', 'degraded', 'certain',
			'prober умер между heartbeat\'ами (hb ' + int(hb_age) + ' с)', { hb_age: hb_age });
	const note = (auto_uptime != null && auto_uptime >= 0 && auto_uptime < 180)
		? 'демон автоматизации стартует — prober поднимется лениво при первой волне'
		: 'ленивый резидент: процессы нет между волнами (поднимется при первой волне, spawn-окно до 5 мин)';
	return mk_entry('probe_pool', label, 'automation', 'ok', 'indirect', note, {
		lazy_idle: true
	});
};

function probe_pool_entry(svc, regst, scan, now) {
	if (svc['automation'] == null)
		return mk_entry('probe_pool', 'probe_pool (резидентный prober)', 'automation',
			'off', 'certain', 'автоматизация выключена — prober не ожидается', {});
	/* Сеанс 158/Б3: бинарника нет — ленивый spawn его никогда не поднимет;
	 * честная деградация с путём установки вместо обещания «поднимется». */
	if (!access('/usr/bin/probe_pool'))
		return mk_entry('probe_pool', 'probe_pool (резидентный prober)', 'automation',
			'degraded', 'certain',
			'probe_pool не установлен — установите: Автообход → «Установить хелперы» (фид/релиз)', {
				not_installed: true
			});
	const hit = (scan != null && scan['probe_pool'] != null) ? scan['probe_pool'] : null;
	let hb_age = -1;
	const st = stat(PP_HB_PATH);
	if (st != null && st.mtime > 0)
		hb_age = now - int(st.mtime);
	const auto = (regst != null && regst['automation'] != null) ? regst['automation'] : null;
	const auto_uptime = (auto != null && auto.alive === true && int(auto.started) > 0)
		? (now - int(auto.started)) : -1;
	return probe_pool_entry_from(hit, hb_age, auto_uptime);
};

function sni_entry(svc, regst, scan) {
	const label = 'sni_sniffer (ClientHello-сниффер)';
	const auto_on = (svc['automation'] === true);
	const hit = (scan != null && scan['sni_sniffer'] != null) ? scan['sni_sniffer'] : null;
	const e = (regst != null && regst['sni_sniffer'] != null) ? regst['sni_sniffer'] : null;
	const alive = (hit != null) || (e != null && e.alive === true);
	if (!alive && !auto_on)
		return mk_entry('sni_sniffer', label, 'automation', 'off', 'certain',
			'не запущен (автоматизация выключена)', {});
	if (alive) {
		const st = ss_rjson(SNI_STATE_PATH);
		const iface = (st != null && type(st) === 'object' && length('' + (st.iface || '')))
			? '' + st.iface : null;
		const note = auto_on ? 'сниффер жив (идентичность подтверждена)'
			: 'работает после отключения автоматизации (урок 88 — снимется при ребуте)';
		return mk_entry('sni_sniffer', label, 'automation', 'ok', 'certain', note, {
			pid: (hit != null) ? hit.pid : e.pid, iface: iface, legacy: !auto_on
		});
	}
	/* Автоматизация включена, сниффера нет: DISCOVERY-источник деградирует
	 * (внутри приложения честный tcpdump-фолбэк), но автоматизация жива —
	 * это degraded, не down. Сеанс 158/Б3: если бинарника НЕТ — путь
	 * установки из фида в совете (spawn его не поднимет никогда). */
	const sni_missing = !access('/usr/bin/sni_sniffer');
	return mk_entry('sni_sniffer', label, 'automation', 'degraded', 'certain',
		(sni_missing
			? 'sni_sniffer не установлен — установите: Автообход → «Установить хелперы» (фид/релиз); '
			: '') +
		'сниффер не запущен — автоматизация уйдёт в tcpdump-фолбэк ' +
		'(spawn-окно/cooldown респавна до 10 мин)', {});
};

function inst_only_entry(name, label, group, inst_name, svc) {
	if (svc['' + inst_name] == null)
		return mk_entry(name, label, group, 'off', 'certain',
			'выключен настройками — инстанс «' + inst_name + '» не запущен', {});
	if (svc['' + inst_name] === false)
		return mk_entry(name, label, group, 'down', 'certain',
			'procd: инстанс «' + inst_name + '» не работает', {});
	return mk_entry(name, label, group, 'ok', 'indirect',
		'инстанс procd жив (идентичность не сверяется)', {});
};

function tun_route_entry(svc, scan, regst) {
	const label = 'TUN-watcher (policy route)';
	if (svc['tun-route'] == null)
		return mk_entry('tun_route', label, 'net', 'off', 'certain',
			'не запущен (TUN-режим не активен)', {});
	if (svc['tun-route'] === false)
		return mk_entry('tun_route', label, 'net', 'down', 'certain',
			'procd: инстанс «tun-route» не работает', {});
	const hit = (scan != null && scan['tun_route'] != null) ? scan['tun_route'] : null;
	if (hit != null) {
		heal_reg('tun_route', hit, 'infra', 'tun_route_watch.sh');
		return mk_entry('tun_route', label, 'net', 'ok', 'certain',
			'watcher жив (идентичность подтверждена)', { pid: hit.pid });
	}
	const e = (regst != null && regst['tun_route'] != null) ? regst['tun_route'] : null;
	if (e != null && e.alive === true)
		return mk_entry('tun_route', label, 'net', 'ok', 'certain',
			'watcher жив (реестр процессов)', { pid: e.pid });
	return mk_entry('tun_route', label, 'net', 'degraded', 'indirect',
		'инстанс жив, процесс watcher\'а не подтверждён (окно респавна)', {});
};

/* ── чистые конструкторы (файлы/выводы — параметрами; честный selftest) ─── */

export function tun_entry_from(doc, now) {
	const label = 'TUN/route (fail-closed полка)';
	const st = (doc != null && type(doc) === 'object') ? '' + (doc.status || '') : '';
	if (!length(st))
		return mk_entry('tun', label, 'net', 'degraded', 'indirect',
			'статус TUN не пишется watcher\'ом (файла нет или бит)', {});
	const ts = int((doc != null && doc.ts) || 0);
	const age = (ts > 0) ? (now - ts) : -1;
	const fresh = (age >= 0 && age < TUN_STALE_SEC);
	const conf = fresh ? 'certain' : 'indirect';
	const detail = { device: (doc != null) ? doc.device : null, state_ts: ts, stale: !fresh };
	if (st === 'ok')
		return mk_entry('tun', label, 'net', 'ok', conf,
			fresh ? ('policy route на месте (' + ('' + ((doc != null) ? doc.detail : '')) + ')')
				: ('данные не обновлялись ' + int(age) + ' с'), detail);
	if (st === 'degraded')
		return mk_entry('tun', label, 'net', 'degraded', conf,
			'TUN деградировал: ' + ('' + ((doc != null) ? doc.detail : '')), detail);
	return mk_entry('tun', label, 'net', 'down', conf,
		'TUN вниз: ' + ('' + ((doc != null) ? doc.detail : '')), detail);
};

function tun_entry(svc, now) {
	/* TUN-перехват ожидается ТОЛЬКО когда инстанс tun-route вообще есть
	 * (init.d гейтит его по режиму): нет инстанса = режим без TUN = off. */
	if (svc['tun-route'] == null)
		return mk_entry('tun', 'TUN/route (fail-closed полка)', 'net', 'off', 'certain',
			'TUN-перехват не активен (режим без TUN)', {});
	return tun_entry_from(ss_rjson(TUN_STATE_PATH), now);
};

export function fw4_entry_from(chains, core_expected, now) {
	const label = 'fw4-перехват (цепи homeproxy)';
	if (!core_expected)
		return mk_entry('fw4', label, 'net', 'off', 'certain',
			'ядро не ожидается — перехват не проверяется', {});
	if (chains > 0)
		return mk_entry('fw4', label, 'net', 'ok', 'certain',
			'цепи homeproxy присутствуют в fw4 (' + chains + ')', { chains: chains, checked: now });
	/* Ф3.2 (T5, живой прогон): полный роспуск цепей при живом ядре — это down,
	 * а не degraded: degraded Recovery не читает, и «пропал перехват» уходил бы
	 * без proposal (фикстура Ф2.3 ждала down — урок 229-класс, код расходился
	 * с замыслом). Ожидаемый перехват исчез = авария координатора. */
	return mk_entry('fw4', label, 'net', 'down', 'certain',
		'цепи homeproxy в fw4 не найдены — перехват не активен', { chains: 0, checked: now });
};

function fw4_entry(svc, now) {
	const chains = parse_nft_count(
		capture('nft list table inet fw4 2>/dev/null | grep -c "chain homeproxy"'));
	return fw4_entry_from(chains, svc['hiddify-c'] != null, now);
};

export function generators_entry_from(ops, now) {
	const label = 'Генераторы конфигурации';
	/* Ремонты Sentinel'а (kind='repair', Ф2.2) — не применения генераторов:
	 * вердикт считается по последней НЕ-ремонтной операции. */
	const list = [];
	if (ops != null)
		for (let op in ops)
			if ('' + (op.kind || '') !== 'repair')
				push(list, op);
	ops = list;
	if (ops == null || !length(ops))
		return mk_entry('generators', label, 'config', 'ok', 'indirect',
			'применений ещё не было', {});
	const last = ops[0];
	const age = now - int((last != null && last.started) || 0);
	if (age > OP_WINDOW_SEC)
		return mk_entry('generators', label, 'config', 'ok', 'indirect',
			'применений за сутки не было (последнее — ' + int(age / 3600) + ' ч назад)', {
				last_op: last.op_id
			});
	const st = '' + ((last != null && last.status) || '');
	const detail = { last_op: last.op_id, last_action: last.action, last_status: st };
	if (st === 'completed')
		return mk_entry('generators', label, 'config',
			(last.verified === true) ? 'ok' : 'degraded', 'certain',
			(last.verified === true)
				? ('применение «' + last.action + '» верифицировано')
				: ('применение «' + last.action + '» завершено БЕЗ верификации'),
			detail);
	if (st === 'failed')
		return mk_entry('generators', label, 'config', 'degraded', 'certain',
			'применение «' + last.action + '» не удалось — работает прежний конфиг (LKG)', detail);
	/* queued / running / verifying. */
	if (age > OP_STALE_SEC)
		return mk_entry('generators', label, 'config', 'degraded', 'certain',
			'операция «' + last.action + '» зависла (' + int(age) + ' с, статус ' + st + ')', detail);
	return mk_entry('generators', label, 'config', 'ok', 'indirect',
		'выполняется применение «' + last.action + '» (стадия ' + ('' + ((last != null && last.stage) || st)) + ')',
		detail);
};

function generators_entry(now) {
	return generators_entry_from(op_list(), now);
};

export function system_entry_from(mem_kb, load1) {
	const label = 'Память/нагрузка роутера';
	const detail = { mem_available_kb: mem_kb, load1: load1 };
	if (mem_kb < 0)
		return mk_entry('system', label, 'system', 'degraded', 'indirect',
			'MemAvailable недоступен (/proc/meminfo не прочитан)', detail);
	const mb = int(mem_kb / 1024);
	detail.mem_mb = mb;
	if (mem_kb < MEM_CRIT_KB)
		return mk_entry('system', label, 'system', 'down', 'certain',
			'критически мало памяти (' + mb + ' МБ) — OOM-киллер убивает процессы', detail);
	if (mem_kb < MEM_WARN_KB)
		return mk_entry('system', label, 'system', 'degraded', 'certain',
			'мало памяти (' + mb + ' МБ) — риск OOM (урок 197: массовые пробы)', detail);
	return mk_entry('system', label, 'system', 'ok', 'certain',
		'память в норме (' + mb + ' МБ доступно)', detail);
};

function system_entry() {
	return system_entry_from(
		parse_meminfo_kb(readfile('/proc/meminfo')),
		parse_load1(readfile('/proc/loadavg')));
};

/* ── глубокий проход (fork'и: service list + скан + wget + netstat + nft) ──
 * ВСЕ идентичности — ОДНИМ сканом /proc (fork один; ~200 readfile cmdline —
 * дёшево). Сканируются и не-владельческие (ядро/движки), и скриптовые
 * демоны: реестр может нести мёртвую identity при живом hb (гонка старта,
 * ч.164) — скан сильнее и само-лечит реестр через heal_reg(). */

const DEEP_SCAN_SPECS = {
	/* Multi-core: the scan must find the ACTIVE engine — hiddify-core OR a
	 * sing-box-family binary (sing-box / sing-box-core lite wrapper). The
	 * old hiddify-only spec left sing-box boxes with scan.core=null on every
	 * deep pass → 'процесс ядра не подтверждён' flapping against the ok
	 * light pass (registry was fine; only the deep /proc identity was blind). */
	core: { exe: [ 'hiddify-core', 'sing-box', 'sing-box-core' ] },
	/* 🔴 Урок 233 (ч.167, живой лов — шторм down/ok каждые 5 с): scan_procs
	 * сравнивает basename_of(cmdline-элемента) со spec.exe — ПОЛНЫЙ ПУТЬ
	 * ('/usr/bin/mosdns') никогда не матчился (basename 'mosdns' ≠ путь),
	 * scan.mosdns всегда null → heal_reg не лечил реестр → light-проход
	 * читал пустой реестр и писал «процесс mosdns отсутствует» на каждом
	 * лёгком тике, а глубокий (по слушателям) — ok. Флап каждые 5 с в
	 * fast-режиме + шторм событий. Спеки — ТОЛЬКО голые имена бинарников. */
	mosdns: { exe: 'mosdns' },
	ciadpi: { exe: 'ciadpi' },
	nfqws2: { exe: 'nfqws2' },
	sni_sniffer: { exe: 'sni_sniffer' },
	probe_pool: { exe: 'probe_pool' },
	tun_route: { script: 'tun_route_watch.sh' },
	automation: { script: 'automation.uc' },
	telegram: { script: 'telegram.uc' },
	autopilot: { script: 'zapret_autopilot.uc' },
	control: { script: 'control_engine.uc' },
	multidns: { script: 'multidns.uc' },
	hotswap: { script: 'hotswap.uc' },
	metrics: { script: 'metrics.uc' },
	sentinel: { script: 'sentinel_cli.uc' },
	recovery: { script: 'recovery_cli.uc' }
};

function deep_entries(svc, regst, now) {
	const entries = {};
	const scan = scan_procs(DEEP_SCAN_SPECS);
	heal_reg('core', scan.core, 'core', null);
	heal_reg('mosdns', scan.mosdns, 'dns', null);
	heal_reg('ciadpi', scan.ciadpi, 'dpi', null);
	heal_reg('nfqws2', scan.nfqws2, 'dpi', null);
	heal_reg('probe_pool', scan.probe_pool, 'automation', null);
	heal_reg('sni_sniffer', scan.sni_sniffer, 'automation', null);

	entries.core = core_entry(scan.core, svc, now);
	entries.byedpi = engine_entry('byedpi', 'ByeDPI (ciadpi)', 'byedpi', scan.ciadpi, svc);
	entries.zapret = engine_entry('zapret', 'Zapret (nfqws2)', 'zapret', scan.nfqws2, svc);

	entries.multidns = daemon_entry('multidns', 'MultiDNS (демон)', 'dns',
		'multidns', 'multidns', 'multidns.uc', svc, regst, scan);
	entries.mosdns = mosdns_entry(svc, regst, now);

	entries.automation = daemon_entry('automation', 'Автообход блокировок (демон)',
		'automation', 'automation', 'automation', 'automation.uc', svc, regst, scan);
	entries.probe_pool = probe_pool_entry(svc, regst, scan, now);
	entries.sni_sniffer = sni_entry(svc, regst, scan);

	entries.telegram = daemon_entry('telegram', 'Telegram-бот', 'telegram',
		'telegram', 'telegram_bot', 'telegram.uc', svc, regst, scan);

	entries.hotswap = daemon_entry('hotswap', 'Выход (движок)', 'failover',
		'hotswap', 'hotswap', 'hotswap.uc', svc, regst, scan);
	entries.autopilot = daemon_entry('autopilot', 'Автопилот Zapret', 'dpi',
		'autopilot', 'zapret_autopilot', 'zapret_autopilot.uc', svc, regst, scan);
	entries.control = daemon_entry('control', 'Контроль доступа (демон)', 'access',
		'control', 'control', 'control_engine.uc', svc, regst, scan);
	entries.sentinel = daemon_entry('sentinel', 'Sentinel (сторож здоровья)', 'system',
		'sentinel', 'sentinel', 'sentinel_cli.uc', svc, regst, scan);
	entries.recovery = daemon_entry('recovery', 'Recovery (координатор восстановления)', 'system',
		'recovery', 'recovery', 'recovery_cli.uc', svc, regst, scan);
	entries.metrics = daemon_entry('metrics', 'Сборщик метрик', 'system',
		'metrics', 'metrics', 'metrics.uc', svc, regst, scan);
	entries.log_cleaner = inst_only_entry('log_cleaner', 'Чистка логов', 'system',
		'log-cleaner', svc);

	entries.tun_route = tun_route_entry(svc, scan, regst);
	entries.tun = tun_entry(svc, now);
	entries.fw4 = fw4_entry(svc, now);

	entries.generators = generators_entry(now);
	entries.system = system_entry();

	return entries;
};

/* ── лёгкий проход: база без fork'ов + переносы глубокой проверки ─────────
 * svc_map — кэш service list с последнего глубокого прохода (передаёт CLI);
 * prev_data — предыдущий документ (перенос deep-only записей и уточнений).
 * Возвращает null, когда лёгкий невозможен (нет кэша — нужен глубокий). */
export function light_entries(svc, regst, prev, now) {
	if (svc == null || prev == null || prev.entries == null)
		return null;
	const entries = {};

	/* Ядро: вердикт в light_core_entry (Ф3.2 — мёртвая identity = down,
	 * отсутствие инстанса в рабочем режиме = down, не «off настройками»). */
	entries.core = light_core_entry(svc['hiddify-c'], regst['core'],
		(prev.entries.core != null) ? prev.entries.core : null,
		core_mode_direct(), now);

	/* Движки: identity из реестра (прошлый скан). 🔴 Ключ реестра — pmgr-имя
	 * ('ciadpi'/'nfqws2'), ключ записи — 'byedpi'/'zapret' (не совпадают!). */
	for (let pair in [ ['byedpi', 'ciadpi', 'ByeDPI (ciadpi)'], ['zapret', 'nfqws2', 'Zapret (nfqws2)'] ]) {
		const nm = pair[0];
		const rn = pair[1];
		const e = (regst[rn] != null && regst[rn].alive === true) ? regst[rn] : null;
		entries[nm] = engine_entry(nm, pair[2], nm,
			(e != null) ? { pid: e.pid, start: e.start } : null, svc);
	}

	/* MultiDNS демон; mosdns — identity + перенос слушателей. */
	entries.multidns = daemon_entry('multidns', 'MultiDNS (демон)', 'dns',
		'multidns', 'multidns', 'multidns.uc', svc, regst, null);
	const md_e = (regst['mosdns'] != null && regst['mosdns'].alive === true) ? regst['mosdns'] : null;
	const prev_md = (prev.entries.mosdns != null) ? prev.entries.mosdns : null;
	if (svc['multidns'] == null) {
		entries.mosdns = mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'off', 'certain',
			'MultiDNS выключен — mosdns не ожидается', {});
	} else if (!access(MOSDNS_BIN)) {
		/* Сеанс 158/Б2: бинарника нет — честное «не установлен» (см. mosdns_entry). */
		entries.mosdns = mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'degraded', 'certain',
			'mosdns не установлен (MultiDNS включён) — установите: Обслуживание → Управление ядром, карточка mosdns (установка из фида)', {
				not_installed: true
			});
	} else {
		const brk = mosdns_broken_entry(mosdns_broken_read(now), now);
		if (brk != null) {
			/* Сеанс 158/Б2: автоподъём приостановлен — «не запускается». */
			entries.mosdns = mk_entry(brk.name, brk.label, brk.group, brk.status, brk.confidence,
				brk.reason, brk.detail);
		} else if (md_e != null) {
		const d = { pid: md_e.pid };
		let carried_ok = true;
		if (prev_md != null && prev_md.detail != null &&
		    prev_md.detail.listeners_checked != null &&
		    (now - int(prev_md.detail.listeners_checked)) < CARRY_SEC) {
			d.listeners = prev_md.detail.listeners;
			d.listeners_checked = prev_md.detail.listeners_checked;
			carried_ok = (int(prev_md.detail.listeners) > 0);
		}
		entries.mosdns = (carried_ok)
			? mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'ok', 'certain',
				'процесс жив (слушатели — с последней глубокой проверки)', d)
			: (mosdns_restarting(now))
				? mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'ok', 'indirect',
					'короткое окно планового рестарта (пересборка конфигурации MultiDNS)', d)
				: mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'degraded', 'indirect',
					'процесс жив, слушатели не подтверждались последней глубокой проверкой', d);
	} else if (mosdns_restarting(now)) {
		entries.mosdns = mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'ok', 'indirect',
			'короткое окно планового рестарта (пересборка конфигурации MultiDNS)', {});
	} else {
		entries.mosdns = mk_entry('mosdns', 'mosdns (пулы MultiDNS)', 'dns', 'down', 'certain',
			'процесс mosdns отсутствует', {});
	}
	}

	/* Автоматизация и дети. */
	entries.automation = daemon_entry('automation', 'Автообход блокировок (демон)',
		'automation', 'automation', 'automation', 'automation.uc', svc, regst, null);
	const pp_e = (regst['probe_pool'] != null && regst['probe_pool'].alive === true)
		? regst['probe_pool'] : null;
	if (svc['automation'] == null) {
		entries.probe_pool = mk_entry('probe_pool', 'probe_pool (резидентный prober)',
			'automation', 'off', 'certain', 'автоматизация выключена — prober не ожидается', {});
	} else if (pp_e != null) {
		entries.probe_pool = mk_entry('probe_pool', 'probe_pool (резидентный prober)',
			'automation', 'ok', 'certain', 'prober жив (идентичность подтверждена)',
			{ pid: pp_e.pid });
	} else {
		let hb_age = -1;
		const st = stat(PP_HB_PATH);
		if (st != null && st.mtime > 0)
			hb_age = now - int(st.mtime);
		const auto = (regst['automation'] != null) ? regst['automation'] : null;
		const auto_up = (auto != null && auto.alive === true && int(auto.started) > 0)
			? (now - int(auto.started)) : -1;
		entries.probe_pool = probe_pool_entry_from(null, hb_age, auto_up);
	}
	entries.sni_sniffer = sni_entry(svc, regst, null);

	/* Telegram. */
	entries.telegram = daemon_entry('telegram', 'Telegram-бот', 'telegram',
		'telegram', 'telegram_bot', 'telegram.uc', svc, regst, null);

	/* Сторожа/служебные. */
	entries.hotswap = daemon_entry('hotswap', 'Выход (движок)', 'failover',
		'hotswap', 'hotswap', 'hotswap.uc', svc, regst, null);
	entries.autopilot = daemon_entry('autopilot', 'Автопилот Zapret', 'dpi',
		'autopilot', 'zapret_autopilot', 'zapret_autopilot.uc', svc, regst, null);
	entries.control = daemon_entry('control', 'Контроль доступа (демон)', 'access',
		'control', 'control', 'control_engine.uc', svc, regst, null);
	entries.sentinel = daemon_entry('sentinel', 'Sentinel (сторож здоровья)', 'system',
		'sentinel', 'sentinel', 'sentinel_cli.uc', svc, regst, null);
	entries.recovery = daemon_entry('recovery', 'Recovery (координатор восстановления)', 'system',
		'recovery', 'recovery', 'recovery_cli.uc', svc, regst, null);
	entries.metrics = daemon_entry('metrics', 'Сборщик метрик', 'system',
		'metrics', 'metrics', 'metrics.uc', svc, regst, null);
	entries.log_cleaner = inst_only_entry('log_cleaner', 'Чистка логов', 'system',
		'log-cleaner', svc);
	entries.tun_route = tun_route_entry(svc, null, regst);
	entries.tun = tun_entry(svc, now);

	/* Deep-only записи — перенос целиком. */
	for (let dn in [ 'fw4', 'generators' ]) {
		entries[dn] = (prev.entries[dn] != null) ? prev.entries[dn] : null;
		if (entries[dn] == null)
			entries[dn] = mk_entry(dn, (dn === 'fw4') ? 'fw4-перехват (цепи homeproxy)'
				: 'Генераторы конфигурации', (dn === 'fw4') ? 'net' : 'config', 'ok',
				'indirect', 'ещё не проверялось (ожидается глубокий проход)', {});
	}

	entries.system = system_entry();
	return entries;
};

/* ── события (чистая функция — покрывается selftest) ──────────────────────
 * Переходы статусов → события шины. off-переходы (вкл/выкл настройки) и
 * появление новых записей НЕ алармят. */
export function diff_events(prev_entries, new_entries) {
	const out = [];
	if (prev_entries == null || new_entries == null || type(prev_entries) !== 'object')
		return out;
	for (let name in new_entries) {
		const nv = new_entries[name];
		const ov = prev_entries[name];
		if (ov == null || type(ov) !== 'object')
			continue;   /* новая запись — часть базлайна/расширения реестра */
		const os = '' + (ov.status || 'off');
		const ns = '' + (nv.status || 'off');
		if (os === ns)
			continue;
		if (os === 'off' || ns === 'off')
			continue;   /* настройка включена/выключена — не инцидент */
		let ev_type = null;
		if (ns === 'down')
			ev_type = 'down';
		else if (ns === 'degraded')
			ev_type = 'degraded';
		else if (ns === 'ok')
			ev_type = 'recovered';
		if (ev_type == null)
			continue;
		push(out, {
			type: ev_type,
			who: ('' + (nv.label || name)),
			detail: ('' + (nv.reason || ''))
		});
	}
	return out;
};

/* ── снимок ───────────────────────────────────────────────────────────────
 * opts = { deep: bool, svc_map: obj|null, prev_data: obj|null }.
 * Возвращает data-документ (без конверта statestore). deep=true → полная
 * проверка (fork'и); deep=false → лёгкий (нужны svc_map и prev_data; при их
 * отсутствии честно уходит в глубокий). */
export function snapshot(opts) {
	let deep = (opts != null && opts.deep === true);
	let svc = (opts != null && opts.svc_map != null) ? opts.svc_map : null;
	const prev = (opts != null && opts.prev_data != null) ? opts.prev_data : null;
	const now = time();
	let entries = null;
	if (!deep) {
		entries = light_entries(svc, registry_status_map(), prev, now);
		if (entries != null && svc == null && prev != null && prev.instances != null)
			svc = prev.instances;
	}
	if (entries == null) {
		deep = true;
		svc = service_instances();
		entries = deep_entries(svc, registry_status_map(), now);
	}
	return {
		overall: overall_of(entries),
		ts: time(),
		deep: deep,
		instances: svc,
		entries: entries
	};
};

/* Вычислить + записать + разница-события в шину. Возвращает { data, events,
 * baseline }. Пишет КАЖДЫЙ вызов: ts документа = живое свидетельство работы
 * монитора (RPC проверяет свежесть по нему). opts.daemon_pid — pid CLI-демона
 * для документа. */
export function compute_and_store(opts) {
	const prev_rd = ss_read_state(HEALTH_PATH);
	const prev_data = (prev_rd != null && prev_rd.data != null) ? prev_rd.data : null;
	const o = (opts != null) ? opts : {};
	o.prev_data = prev_data;
	const data = snapshot(o);
	data.daemon = {
		pid: (o.daemon_pid != null) ? int(o.daemon_pid) : null,
		note: 'health monitor'
	};
	let events = [];
	const baseline = (prev_data == null);
	if (!baseline) {
		events = diff_events(prev_data.entries, data.entries);
		for (let ev in events) {
			try { ev_emit(SRC, ev.type, ev.who, ev.detail); } catch (e) { /* best-effort */ }
		}
	}
	ss_write_state(HEALTH_PATH, data);
	return { data: data, events: events, baseline: baseline };
};

/* ── selftest (чистая логика на подставных входах; KB: обязательные
 * микротесты) — CLI: ucode health_cli.uc selftest ───────────────────────── */
export function selftest() {
	const checks = [];
	const check = function(name, ok, detail) {
		push(checks, { check: name, ok: ok, detail: detail || null });
		return ok;
	};
	const now = time();
	const fe = (n, s) => ({ name: n, status: s, label: n, reason: '' });

	/* ranks + overall. */
	check('rank_order', status_rank('ok') === 0 && status_rank('off') === 0 &&
		status_rank('degraded') === 1 && status_rank('down') === 2 &&
		status_rank('nonsense') === 0, null);
	check('overall_mixed', overall_of({ a: fe('a', 'ok'), b: fe('b', 'down'), c: fe('c', 'off') }) === 'down', null);
	check('overall_degraded', overall_of({ a: fe('a', 'ok'), b: fe('b', 'degraded') }) === 'degraded', null);
	check('overall_all_off', overall_of({ a: fe('a', 'off'), b: fe('b', 'off') }) === 'off', null);
	check('overall_empty', overall_of({}) === 'off', null);

	/* diff_events. */
	const prev = { a: fe('a', 'ok'), b: fe('b', 'ok'), c: fe('c', 'off'), d: fe('d', 'degraded'), f: fe('f', 'off') };
	const nxt = { a: fe('a', 'down'), b: fe('b', 'ok'), c: fe('c', 'ok'), d: fe('d', 'degraded'), f: fe('f', 'ok'), g: fe('g', 'down') };
	const ev = diff_events(prev, nxt);
	check('diff_only_down', length(ev) === 1 && ev[0].type === 'down' && ev[0].who === 'a',
		'events=' + sprintf('%J', ev));
	const ev2 = diff_events({ a: fe('a', 'down') }, { a: fe('a', 'ok') });
	check('diff_recovered', length(ev2) === 1 && ev2[0].type === 'recovered', null);
	check('diff_baseline_null', length(diff_events(null, nxt)) === 0, null);
	check('diff_off_silent', length(diff_events({ a: fe('a', 'off') }, { a: fe('a', 'down') })) === 0, null);
	check('diff_to_off_silent', length(diff_events({ a: fe('a', 'down') }, { a: fe('a', 'off') })) === 0, null);

	/* parse-хелперы. */
	check('meminfo_parse', parse_meminfo_kb('MemTotal:  100 kB\nMemAvailable:  713000 kB\n') === 713000, null);
	check('meminfo_missing', parse_meminfo_kb('MemTotal: 1 kB') === -1, null);
	check('load_parse', parse_load1('0.42 0.30 0.25 1/100 1234') === '0.42', null);
	check('nft_count', parse_nft_count('12\n') === 12 && parse_nft_count('0\n') === 0 &&
		parse_nft_count('') === 0, null);
	check('listener_count', listener_count(
		'udp 0 0 127.0.0.1:5453 0.0.0.0:*\nudp 0 0 127.0.0.1:5454 0.0.0.0:*\nudp 0 0 0.0.0.0:53 0.0.0.0:*\n',
		5453, 5454) === 2, null);
	check('listener_count_partial', listener_count('udp 0 0 127.0.0.1:5453 0.0.0.0:*\n', 5453, 5454) === 1, null);
	check('listener_count_none', listener_count('udp 0 0 0.0.0.0:53 0.0.0.0:*\n', 5453, 5454) === 0, null);
	check('listener_no_prefix_false', listener_count('udp 0 0 127.0.0.1:15453 0.0.0.0:*\n', 5453, 5454) === 0, null);

	/* Сеанс 158/Б2: честный вердикт «mosdns не запускается» (флаг multidns).
	 * Чистая функция не судит свежесть — протухание снимает mosdns_broken_read. */
	const mb_fresh = mosdns_broken_entry({ ts: now - 60, attempts: 4 }, now);
	check('mosdns_broken_entry_degraded', mb_fresh != null && mb_fresh.status === 'degraded' &&
		mb_fresh.detail.attempts === 4 && mb_fresh.detail.broken === true, null);
	check('mosdns_broken_entry_none', mosdns_broken_entry(null, now) == null, null);

	/* Сеанс 158/Б4: сравнение версий ядра с кандидатом фида (база без -rN). */
	check('core_stale_differs', core_stale_compare('4.1.0', '5.5.5-r1') != null &&
		core_stale_compare('4.1.0', '5.5.5-r1').candidate === '5.5.5-r1', null);
	check('core_stale_same_base', core_stale_compare('5.5.5', '5.5.5-r1') == null, null);
	check('core_stale_empty', core_stale_compare('', '5.5.5-r1') == null &&
		core_stale_compare('4.1.0', '') == null, null);

	/* tun_entry_from: fresh ok / stale ok / degraded / missing / down. */
	const tun_fresh = tun_entry_from({ status: 'ok', device: 'tunhp', detail: 'policy route present', ts: now - 10 }, now);
	check('tun_fresh_ok', tun_fresh.status === 'ok' && tun_fresh.confidence === 'certain', null);
	const tun_stale = tun_entry_from({ status: 'ok', device: 'tunhp', detail: 'policy route present', ts: now - 400 }, now);
	check('tun_stale_indirect', tun_stale.status === 'ok' && tun_stale.confidence === 'indirect' &&
		tun_stale.detail.stale === true, null);
	const tun_deg = tun_entry_from({ status: 'degraded', device: 'tunhp', detail: 'route install failed', ts: now - 5 }, now);
	check('tun_degraded', tun_deg.status === 'degraded' && tun_deg.confidence === 'certain', null);
	const tun_miss = tun_entry_from(null, now);
	check('tun_missing', tun_miss.status === 'degraded' && tun_miss.confidence === 'indirect', null);
	const tun_down = tun_entry_from({ status: 'down', device: 'tunhp', detail: 'device absent', ts: now - 5 }, now);
	check('tun_down', tun_down.status === 'down', null);

	/* fw4_entry_from. */
	const fw_ok = fw4_entry_from(5, true, now);
	check('fw4_ok', fw_ok.status === 'ok' && fw_ok.detail.chains === 5, null);
	const fw_bad = fw4_entry_from(0, true, now);
	check('fw4_missing_chains_down', fw_bad.status === 'down', null);
	const fw_off = fw4_entry_from(0, false, now);
	check('fw4_off_when_no_core', fw_off.status === 'off', null);

	/* generators_entry_from: матрица статусов опа. */
	check('gen_none', generators_entry_from([], now).status === 'ok', null);
	const op_ok = { op_id: 'x1', action: 'restart', status: 'completed', verified: true, started: now - 60 };
	check('gen_verified_ok', generators_entry_from([op_ok], now).status === 'ok', null);
	const op_nover = { op_id: 'x2', action: 'reload', status: 'completed', verified: false, started: now - 60 };
	const gen_nover = generators_entry_from([op_nover], now);
	check('gen_unverified_degraded', gen_nover.status === 'degraded' && gen_nover.confidence === 'certain', null);
	const op_fail = { op_id: 'x3', action: 'restart', status: 'failed', verified: false, started: now - 60 };
	check('gen_failed_degraded', generators_entry_from([op_fail], now).status === 'degraded', null);
	/* Ремонты Sentinel'а (kind='repair') не считаются применением генератора. */
	const op_rep = { op_id: 'x7', kind: 'repair', action: 'svc_start', status: 'completed', verified: true, started: now - 10 };
	const op_fail2 = { op_id: 'x8', kind: 'restart', action: 'restart', status: 'failed', verified: false, started: now - 3600 };
	const gen_rep = generators_entry_from([op_rep, op_fail2], now);
	check('gen_repair_skipped', gen_rep.status === 'degraded' &&
		gen_rep.detail.last_op === 'x8', 'verdict=' + sprintf('%J', gen_rep));
	const op_run = { op_id: 'x4', action: 'restart', status: 'running', stage: 'Verifying', started: now - 30 };
	check('gen_running_ok', generators_entry_from([op_run], now).status === 'ok', null);
	const op_stuck = { op_id: 'x5', action: 'restart', status: 'running', stage: 'Applying', started: now - (OP_STALE_SEC + 60) };
	const gen_stuck = generators_entry_from([op_stuck], now);
	check('gen_stuck_degraded', gen_stuck.status === 'degraded' && gen_stuck.confidence === 'certain', null);
	const op_old = { op_id: 'x6', action: 'restart', status: 'failed', verified: false, started: now - (OP_WINDOW_SEC + 3600) };
	check('gen_old_ok', generators_entry_from([op_old], now).status === 'ok', null);

	/* system_entry_from: пороги. */
	check('sys_ok', system_entry_from(700 * 1024, '0.4').status === 'ok', null);
	check('sys_warn', system_entry_from(MEM_WARN_KB - 1024, '0.4').status === 'degraded', null);
	check('sys_crit', system_entry_from(MEM_CRIT_KB - 1024, '3.1').status === 'down', null);
	check('sys_unreadable', system_entry_from(-1, null).status === 'degraded', null);

	/* probe_pool_entry_from: ленивая резидентная семантика (ч.164). */
	check('pp_alive', probe_pool_entry_from({ pid: 5 }, -1, 600).status === 'ok', null);
	check('pp_lazy_idle', (() => {
		const e = probe_pool_entry_from(null, -1, 600);
		return e.status === 'ok' && e.confidence === 'indirect' && e.detail.lazy_idle === true;
	})(), null);
	check('pp_starting', probe_pool_entry_from(null, -1, 60).status === 'ok', null);
	check('pp_died_between_hb', probe_pool_entry_from(null, 10, 600).status === 'degraded', null);

	/* scan-хелпер: basename. */
	check('basename', basename_of('/usr/bin/hiddify-core') === 'hiddify-core' &&
		basename_of('nfqws2') === 'nfqws2', null);

	/* Ф3.2 (T2b, живой лов 2026-11-04): честные вердикты ядра. */
	const cv_missing = core_missing_verdict(false);
	check('core_missing_working_down', cv_missing.status === 'down' && cv_missing.expected === true,
		sprintf('%J', cv_missing));
	const cv_off = core_missing_verdict(true);
	check('core_missing_direct_off', cv_off.status === 'off' && cv_off.expected === false, null);
	check('light_core_dead_identity_down',
		light_core_entry(true, { pid: 1, alive: false }, null, false, now).status === 'down', null);
	check('light_core_missing_working_down',
		light_core_entry(null, { pid: 1, alive: true }, null, false, now).status === 'down', null);
	check('light_core_alive_ok',
		light_core_entry(true, { pid: 2, alive: true }, null, false, now).status === 'ok', null);
	check('light_core_api_carry_degraded',
		light_core_entry(true, { pid: 2, alive: true },
			{ detail: { api_ok: false, api_checked: now - 60 } }, false, now).status === 'degraded', null);
	check('light_core_respawn_window_degraded',
		light_core_entry(true, null, null, false, now).status === 'degraded', null);

	let all_ok = true;
	for (let c in checks)
		if (!c.ok)
			all_ok = false;
	return { ok: all_ok, checks: checks };
};
