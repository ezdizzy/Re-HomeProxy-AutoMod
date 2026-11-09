// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Sentinel (plan 20 §3 Ф2.2; A.1 аудита «RAVNEX Sentinel» = идея №1 B0).
//
// Сторож здоровья САМОГО Ravnex. Не зависит от контролируемых им механизмов:
// собственный procd-инстанс (init.d), собственный цикл, чтение только листовых
// модулей (statestore/pmgr/opman/eventbus) — 🔴 БЕЗ импорта health.uc: битый
// деплой health-кода не должен ронять сторожа вместе с охраняемым.
//
// Обязанности (A.1; B0):
//   1. «Сам монитор молчит» — живость Health Monitor = свежесть ts документа
//      health.json (демон пишет КАЖДЫЙ тик; протух >120 с = мёртв/завис).
//   2. «Какие демоны ДОЛЖНЫ работать» — собственная сверка ожиданий: `ubus
//      call service list` (procd = единственный источник ожиданий, урок 223);
//      running:false = должен, но не работает.
//   3. «Какие конфиги обязаны существовать» — рабочий конфиг ядра (+LKG),
//      конфиг mosdns при включённом MultiDNS, UCI-конфиг приложения.
//   4. «Устаревшие стейты» — зависшие операции opman (heartbeat руннера
//      протух > 300 с при lease 120 с = руннер умер без честного финиша,
//      урок 169-класс) и зависшие циклы демонов (identity жива, heartbeat
//      не обновляется > 15 мин).
//   5. «Бесконечные циклы восстановления» — свой loop-guard: ≤ 3 починок
//      одного ключа за 30 мин; дальше авто-ремонт ключа приостанавливается
//      до исчезновения проблемы (или TTL 2 ч) и честно рапортует событием.
//
// Ф10.3 (ресурсные бюджеты): по живым pid реестра daemons.json собирается
//   fork-free снапшот ресурсов (VmRSS + счёт fd), вердикты — против щедрых
//   бюджетов; перерасход = находка res:<имя> (всегда degraded — «процесс
//   мёртв» резервируется down) + снапшот-документ resources.json для RPC/UI.
//   ИСКЛЮЧЕНИЕ Б5 (сеанс 161): res:core RSS-крит → core_restart по identity
//   (procd respawn ДО OOM-грани; коллатеральные жертвы oom-killer, hostapd
//   и др., недопустимы) — прочие res:* по-прежнему без авто-ремонта.
//
// Политика алармов (без дублирования шума): когда health-документ СВЕЖИЙ,
// Sentinel молчит о классах svc:*/op:* — Health Monitor сам поднимет тревогу
// переходом статуса (его зона); Sentinel в это время выполняет РЕМОНТЫ и
// пишет события repair. Когда health протух — Sentinel берёт тревогу на себя
// (down/degraded своими событиями). Классы config/hung/loop/health_monitor —
// уникальная зона Sentinel'а, алармятся всегда. Базлайн (нет документа после
// ребута) молчит (урок 220).
//
// Ремонты — разовые, через opman-дверь (kind 'repair', НЕ параллельно с
// apply: пока жив op классов restart/reload/engine_restart со свежим
// heartbeat, сервисные ремонты откладываются на следующий проход):
//   svc_start  — /etc/init.d/ravnex start (идемпотентный: поднимает ТОЛЬКО
//                мёртвые инстансы, живые не трогает — урок 135); rc-файл +
//                опрос с heartbeat (урок 167 — никаких 2-arg system()).
//   op_finish  — честное закрытие зависшего опа (opman.finish, лок
//                освобождается; действие НЕ повторяется — Sentinel не может
//                знать, началось ли оно).
// Каждая починка → событие шины (src='sentinel'). Конфиг-проблемы и зависшие
// демоны — события БЕЗ авто-ремонта (регенерация/LKG и киллы — зоны apply и
// Ф2.3 Recovery).
//
// Статус-документ /var/run/ravnex/sentinel.json (конверт statestore)
// пишется КАЖДЫЙ проход — ts = живое свидетельство самого сторожа (RPC
// sentinel_status проверяет свежесть по нему; пересчёта в rpcd нет и не
// должно быть: документ и ЕСТЬ вердикт сторожа).
//
// Уроки учтены: 166 (`};` у функций модуля; проверка модуля импортирующим
// чекером), 216 (top-level const НАВЕРХУ), 221 (НЕТ try/finally), 2/93/126
// (fs после import; хелперы выше вызывающих), 20/180 (for-in по массиву =
// элементы), 26 (index() вместо match()-строки), 211 (%J компактный),
// 167 (никаких 2-arg system(); rc-файл + опрос), 168 (rmdir — не наш путь,
// локи opman), 171 (service list), 223 (procd-инстансы = источник ожиданий),
// 135 (init.d start идемпотентен), 197 (MemAvailable-грань — глубокие
// проходы пропускаются), 209-класс (дефолты едины).

'use strict';

import { access, readfile, popen, unlink, lsdir, readlink } from 'fs';
import {
	read_state as ss_read_state, write_state as ss_write_state, rjson as ss_rjson,
	read_revision as ss_read_revision
} from '/etc/ravnex/scripts/statestore.uc';
import {
	REG_PATH as PM_REG_PATH, entry_alive as pm_entry_alive,
	kill_entry as pm_kill_entry, res_profile as pm_res_profile
} from '/etc/ravnex/scripts/pmgr.uc';
import {
	list_ops as op_list, begin as op_begin, heartbeat as op_heartbeat,
	finish as op_finish, get_op as op_get
} from '/etc/ravnex/scripts/opman.uc';
import { emit as ev_emit } from '/etc/ravnex/scripts/eventbus.uc';

/* ── константы (урок 216: всё наверху, выше первой функции) ─────────────── */

export const SENTINEL_PATH = '/var/run/ravnex/sentinel.json';
export const HEALTH_PATH = '/var/run/ravnex/health.json';
export const SRC = 'sentinel';

/* Живость Health Monitor: он пишет документ каждый тик (5–20 с); протухший
 * >120 с = демон мёртв или завис. ≤90 с = «свежий» (порог RPC health_status). */
export const HEALTH_STALE_SEC = 120;

/* Зависшая операция opman: lease = 120 с, руннер обновляет heartbeat каждые
 * ≤2 с в поллингах; без heartbeat >300 с руннер точно мёртв (урок 169). */
export const OP_HB_STALE_SEC = 300;

/* Зависший цикл демона: identity жива, но heartbeat не обновляется. Демоны
 * пингуют каждые 15–30 с; 900 с = 30+ пропущенных пингов. */
export const HB_STALE_SEC = 900;

/* Анти-флап ленты (ч.230): повторный degraded/recovered-аларм ТОГО ЖЕ ключа
 * не чаще раза в 6 ч. Находка остаётся в документе/UI честно (свежие цифры),
 * молчит только ЛЕНТА событий — живой случай: core fd гулял вокруг линии
 * 2048 (2054↔2047) и multidns-бенч давал пары degraded/recovered каждый
 * бенч-цикл. Класс 'down' (мёртвый инстанс) — ВСЕГДА звонит. */
export const ALARM_REPEAT_SEC = 21600;

/* Loop-guard: максимум починок одного ключа за окно; блокировка ключа живёт
 * до исчезновения проблемы либо до TTL (одна попытка каждые 2 часа). */
export const REPAIR_WINDOW_SEC = 1800;
export const REPAIR_MAX = 3;
export const BLOCKED_TTL_SEC = 7200;

/* Бут-грейс: procd раскачивает инстансы не мгновенно (урок 223: 11 демонов
 * в одну секунду старта службы) — svc/health-проверки начинаются после. */
export const BOOT_GRACE_SEC = 180;

/* Таймаут идемпотентного start (он же регенерирует конфиг через LKG — до
 * минут на слабом железе; apply_runner даёт restart 90 с). */
export const SVC_START_TIMEOUT = 150;

/* OOM-грань (урок 197 — единый порог с Health Monitor). */
export const MEM_SKIP_KB = 49152;

/* ── ч.263: динамические бюджеты ядра от железа (пакет A аудита) ───────────
 * fd-бюджет: от nf_conntrack_max (OpenWrt сам масштабирует его от RAM:
 * buckets = RAM/2048/8). warn = clamp(C/8, 2048, 16384), crit = 2×warn.
 * Доли от RLIMIT_nofile неприменимы (лимит 1e6 завышен в сотни раз);
 * единственный честный якорь = потребление. На 1 ГБ это 8192/16384 —
 * боевой шторм ч.230 (2054↔2047) и инцидент ч.263 (2166) теперь молчат
 * ЧЕСТНО (это нагрузка, не утечка), на lite 128-256 МБ — 2048.
 * RSS: warn = min(384 MiB, 40% RAM); crit = max(min(512 MiB, 55% RAM),
 * 135% GOMEMLIMIT_eff). Инварианты: crit строго выше худшего устойчивого
 * RSS при мягком GOMEMLIMIT (GC-гвард ещё справляется) и достижимо ниже
 * OOM-грани на слабом железе (на lite сегодня защиты нет вовсе). */
export const RES_FD_WARN_MIN = 2048;
export const RES_FD_WARN_MAX = 16384;
export const RES_CORE_GML_REQ_MIB = 384;
export const RES_RSS_WARN_MT_PCT = 40;
export const RES_RSS_CRIT_MT_PCT = 55;
export const RES_CRIT_GML_PCT = 135;
export const RES_CRIT_FAST_PCT = 150;

/* Подтверждённость рестарта ядра (armed, ч.263 — инцидент «двух kill'ов»):
 * rss-crit должен продержаться RES_CRIT_CONFIRM_PASSES полных прохода
 * ПОДРЯД, либо одномоментно ≥ RES_CRIT_FAST_PCT% от crit (явное бегство).
 * До подтверждения находка честно crit (сигнал есть), но рестарта НЕТ —
 * мгновенный пик памяти больше не убивает живое ядро. */
export const RES_CRIT_CONFIRM_PASSES = 2;

/* Живость health-документа: базовая грань 120 с, но НЕ меньше трёх тиков
 * самого монитора (light 20 с × профильный фактор: lite 3 → 180 с —
 * ровно 2 тика на lite клали запас на грань ложного «монитор молчит»). */
export const HEALTH_LIGHT_SEC = 20;
export const HEALTH_STALE_TICKS = 3;

/* ── Ф10.3: ресурсные бюджеты демонов ─────────────────────────────────────
 * База — реестр daemons.json (имена+pid живых демонов); замер fork-free
 * (readfile /proc/<pid>/status + lsdir /proc/<pid>/fd — readdir на этой
 * сборке ucode нет, lsdir возвращает массив имён-строк). Бюджеты ЩЕДРЫЕ
 * относительно базы ч.218 (core ~132 МБ/fd 482, automation ~40 МБ, mosdns
 * ~26 МБ, probe_pool ~13 МБ, прочие ≤2 МБ) — находка означает рост тренда,
 * а не «сейчас упадёт». Крит-порог RSS ядра — зона перед OOM-гранью WR3000H
 * (727 МБ, ч.218). Имена ключей = имена реестра (core/ciadpi/nfqws2/...).
 * 🔴 ч.263: бюджет ЯДРА — динамический (res_budget_core от RAM/
 * nf_conntrack_max/GOMEMLIMIT, пакет A аудита), здесь больше нет. */
export const RES_PATH = '/var/run/ravnex/resources.json';

const RES_BUDGETS = {
	automation:  { rss_warn_kb:  98304, rss_crit_kb: 163840, fd_warn:  512, fd_crit: 1024 },
	mosdns:      { rss_warn_kb:  98304, rss_crit_kb: 163840, fd_warn:  512, fd_crit: 1024 },
	probe_pool:  { rss_warn_kb:  49152, rss_crit_kb:  98304, fd_warn:  512, fd_crit: 1024 },
	sni_sniffer: { rss_warn_kb:  49152, rss_crit_kb:  98304, fd_warn:  512, fd_crit: 1024 }
};

/* Демоны без персонального бюджета (скрипты-демоны, движки) — общий. */
export const RES_BUDGET_GENERIC = { rss_warn_kb: 65536, rss_crit_kb: 131072, fd_warn: 512, fd_crit: 1024 };

/* Kinds apply-опов, при живых которых сервисные ремонты откладываются.
 * 🔴 Урок 229 (ч.166): РЕАЛЬНЫЕ kind'ы — 'service' (RPC op_spawn делает
 * op_begin('service', action, …)) и 'core_install'; прежний список сравнивал
 * kind с ИМЕНАМИ action'ов ('restart'/'reload'/'engine_restart') и в
 * рантайме не матчил ни один живой apply (selftest ч.165 был на синтетике
 * kind='restart' — урок «selftest чист, рантайм отравлен»). */
const APPLY_KINDS = [ 'service', 'core_install' ];

const CORE_CFG = '/var/run/ravnex/hiddify-c.json';
const CORE_LKG = '/var/run/ravnex/hiddify-c.json.lastgood';
const MDNS_CONF = '/var/run/ravnex/multidns/mosdns.yaml';
const SYS_CONF = '/etc/config/ravnex';
const SVC_EPOCH_PATH = '/var/run/ravnex/.service_epoch';

/* Человекочитаемые имена инстансов (сообщения — именами, не сырыми id —
 * память hotswap.messages_node_names_not_cfg_ids). */
const INST_LABELS = {
	'hiddify-c': 'Ядро',
	'byedpi': 'ByeDPI (ciadpi)',
	'zapret': 'Zapret (nfqws2)',
	'multidns': 'MultiDNS (демон)',
	'automation': 'Автообход блокировок',
	'telegram': 'Telegram-бот',
	'autopilot': 'Автопилот Zapret',
	'control': 'Контроль доступа',
	'health': 'Health Monitor',
	'sentinel': 'Sentinel',
	'recovery': 'Recovery (координатор)',
	'hotswap': 'Выход (движок)',
	'metrics': 'Сборщик метрик',
	'log-cleaner': 'Чистка логов',
	'tun-route': 'TUN-watcher'
};

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

export function inst_label(name) {
	const l = INST_LABELS['' + name];
	return (l != null) ? l : ('' + name);
};

/* Человекочитаемые имена демонов РЕЕСТРА (имена реестра ≠ имена procd-инстансов:
 * core ≠ hiddify-c, telegram_bot ≠ telegram, zapret_autopilot ≠ autopilot).
 * Сообщения — именами, не сырыми id (память hotswap.messages_node_names_not_cfg_ids). */
const RES_LABELS = {
	core: 'Ядро (hiddify-core)', mosdns: 'DNS-движок mosdns',
	ciadpi: 'ByeDPI (ciadpi)', nfqws2: 'Zapret (nfqws2)',
	probe_pool: 'Пул проб', sni_sniffer: 'SNI-сниффер',
	telegram_bot: 'Telegram-бот', zapret_autopilot: 'Автопилот Zapret',
	clean_log: 'Чистка логов'
};

export function res_label(name) {
	const l = RES_LABELS['' + name];
	return (l != null) ? l : inst_label(name);
};

/* Общий вердикт = худший статус находок. */
export function overall_of(findings) {
	let worst = 'ok';
	for (let k in findings) {
		const st = '' + ((findings[k] != null) ? findings[k].status : '');
		if (st === 'down')
			return 'down';
		if (st === 'degraded')
			worst = 'degraded';
	}
	return worst;
};

/* ── чистые проверки (покрываются selftest) ─────────────────────────────── */

export function parse_meminfo_kb(raw) {
	const m = match('' + (raw || ''), /MemAvailable:\s+([0-9]+)/);
	return (m != null) ? int(m[1]) : -1;
};

/* Возраст документа здоровья: -1 = документа нет/бит (монитор не писал). */
export function health_age(envelope, now) {
	const ts = (envelope != null && envelope.meta != null && envelope.meta.ts != null)
		? int(envelope.meta.ts) : 0;
	return (ts > 0) ? (now - ts) : -1;
};

/* Мёртвые procd-инстансы (ожидания = сам service list, урок 223). */
export function dead_instances(svc) {
	const out = [];
	if (svc == null || type(svc) !== 'object')
		return out;
	for (let k in svc)
		if (svc[k] === false)
			push(out, '' + k);
	return out;
};

/* Дрейф набора инстансов: был в прошлом проходе — исчез сейчас — БЕЗ bump'а
 * config_revision (т.е. без применения). Класс отказа урок 219: `ubus call
 * service delete` убирает инстанс ИЗ service list вовсе (выглядит как «off»,
 * ни один читатель service list его не видит), а возврат — только
 * init.d start/reload. Смена набора ЛЕГАТИМНА только при применении
 * (opman ревизия растёт на verified) — иначе это аномалия. */
export function drifted_instances(prev_inst, svc) {
	const out = [];
	if (prev_inst == null || type(prev_inst) !== 'object' ||
		svc == null || type(svc) !== 'object')
		return out;
	for (let k in prev_inst)
		if (svc['' + k] == null)
			push(out, '' + k);
	return out;
};

/* Легитимность смены набора (Ф3.1): применился op (ревизия выросла), живой
 * apply, ИЛИ служба рестартовала (счётчик стартов .service_epoch вырос —
 * init.d заново оценил все гейты по UCI). Только «всё без изменений» = аномалия. */
export function instance_change_legit(prev_rev, prev_epoch, rev, epoch, apply_running) {
	return int(prev_rev) !== int(rev) || int(prev_epoch) !== int(epoch) ||
		apply_running === true;
};

/* Зависшие операции: queued/running/verifying с протухшим heartbeat. */
export function stale_ops(ops, now) {
	const out = [];
	if (ops == null || type(ops) !== 'array')
		return out;
	for (let op in ops) {
		const st = '' + (op.status || '');
		if (st !== 'queued' && st !== 'running' && st !== 'verifying')
			continue;
		const hb = int(op.heartbeat || 0);
		const age = (hb > 0) ? (now - hb) : (now - int(op.started || 0));
		if (age > OP_HB_STALE_SEC)
			push(out, {
				op_id: '' + op.op_id, action: '' + (op.action || ''),
				kind: '' + (op.kind || ''), status: st, stale_sec: age
			});
	}
	return out;
};

/* Жив ли apply (сервисные ремонты откладываются — «не параллельно с apply»). */
export function apply_in_progress(ops, now) {
	const stale = stale_ops(ops, now);   // мёртвые руннеры apply не считаются
	for (let op in (ops || [])) {
		const st = '' + (op.status || '');
		if (st !== 'queued' && st !== 'running' && st !== 'verifying')
			continue;
		let is_apply = false;
		for (let k in APPLY_KINDS)
			if (('' + (op.kind || '')) === k)
				is_apply = true;
		if (!is_apply)
			continue;
		let stuck = false;
		for (let s in stale)
			if (s.op_id === ('' + op.op_id))
				stuck = true;
		if (!stuck)
			return true;
	}
	return false;
};

/* Зависшие демоны: identity жива, heartbeat протух (зависший цикл).
 * 🔴 Урок 226 (ч.165, живой лов — ложный шторм): только ХОЗЯЕВСКИЕ записи
 * имеют hb-цикл; скан/heal-записи (note 'health-scan'/'scanned' — их пишут
 * heal_reg/сканы) НЕ пингуют по дизайну, их замороженный hb = момент записи,
 * а не зависание. Чёрный список нотаций, остальное — hb-владельцы. */
const HUNG_SKIP_NOTES = [ 'health-scan', 'scanned' ];

export function hung_daemons(regst, now) {
	const out = [];
	if (regst == null || type(regst) !== 'object')
		return out;
	for (let name in regst) {
		const e = regst[name];
		if (e == null || type(e) !== 'object' || e.alive !== true)
			continue;
		const note = '' + (e.note || '');
		let skipped = false;
		for (let n in HUNG_SKIP_NOTES)
			if (note === n)
				skipped = true;
		if (skipped)
			continue;
		const hb = int(e.hb || 0);
		if (hb <= 0)
			continue;   /* никогда не пинговал — не «завис» */
		const age = now - hb;
		if (age > HB_STALE_SEC)
			push(out, {
				name: '' + name, hb_age: age,
				pid: (e.pid != null) ? int(e.pid) : null
			});
	}
	return out;
};

/* Карта живости реестра pmgr одним чтением (урок 179: zombie = мёртв). */
export function registry_map(raw_doc) {
	const raw = (raw_doc != null) ? raw_doc : ss_rjson(PM_REG_PATH);
	const out = {};
	if (raw == null || type(raw.daemons) !== 'object')
		return out;
	for (let name in raw.daemons) {
		const e = raw.daemons[name];
		e.alive = pm_entry_alive(e);
		out['' + name] = e;
	}
	return out;
};

/* ── конфиг-проверки ─────────────────────────────────────────────────────── */

/* Чистая часть: из списка проверок {key,label,severity,ok,reason} → находки. */
export function config_findings(checks) {
	const out = {};
	if (checks == null || type(checks) !== 'array')
		return out;
	for (let c in checks) {
		if (c == null || c.ok === true)
			continue;
		out['' + c.key] = {
			status: '' + (c.severity || 'degraded'),
			label: '' + (c.label || c.key),
			reason: '' + (c.reason || 'отсутствует или нечитаем'),
			confidence: 'certain'
		};
	}
	return out;
};

function build_config_checks(core_expected, mdns_expected) {
	const checks = [];
	push(checks, {
		key: 'uci', label: 'UCI-конфиг ravnex', severity: 'down',
		ok: access(SYS_CONF),
		reason: '/etc/config/ravnex не читается — настройкам приложения не к чему применяться'
	});
	if (core_expected) {
		const raw = readfile(CORE_CFG);
		let ok = false;
		let reason = 'рабочий конфиг ядра отсутствует — следующий старт восстановит его (генератор/LKG)';
		if (raw != null) {
			if (parse_json(raw) != null)
				ok = true;
			else
				reason = 'рабочий конфиг ядра не парсится как JSON (порчен?) — LKG восстановит на следующем старте';
		}
		push(checks, {
			key: 'core_cfg', label: 'Конфиг ядра (hiddify-c.json)', severity: 'degraded',
			ok: ok, reason: reason
		});
		push(checks, {
			key: 'core_lkg', label: 'LKG-копия конфига ядра (.lastgood)', severity: 'degraded',
			ok: access(CORE_LKG),
			reason: '.lastgood отсутствует — страховка Ф1.2 ещё не создана (её напишет первый верифицированный старт)'
		});
	}
	if (mdns_expected) {
		push(checks, {
			key: 'mdns_conf', label: 'Конфиг mosdns', severity: 'degraded',
			ok: access(MDNS_CONF),
			reason: 'mosdns.yaml отсутствует — демон MultiDNS пересоберёт его в ближайшем цикле'
		});
	}
	return checks;
};

/* ── loop-guard (чистая математика) ─────────────────────────────────────── */

export function prune_repairs(repairs, now) {
	const out = {};
	if (repairs == null || type(repairs) !== 'object')
		return out;
	for (let k in repairs) {
		const times = (repairs[k] != null && type(repairs[k].times) === 'array')
			? repairs[k].times : [];
		const fresh = [];
		for (let t in times) {
			const ts = int(t);
			if (ts > 0 && (now - ts) <= REPAIR_WINDOW_SEC)
				push(fresh, ts);
		}
		if (length(fresh))
			out['' + k] = { times: fresh };
	}
	return out;
};

export function repair_allowed(repairs, key, now) {
	const r = (repairs != null && repairs['' + key] != null) ? repairs['' + key] : null;
	const count = (r != null && r.times != null) ? length(r.times) : 0;
	return { allowed: (count < REPAIR_MAX), count: count };
};

export function record_repair(repairs, key, now) {
	const r = prune_repairs(repairs, now);
	const times = (r['' + key] != null && r['' + key].times != null)
		? r['' + key].times : [];
	push(times, now);
	r['' + key] = { times: times };
	return r;
};
/* ── diff находок → события (политика алармов) ────────────────────────────
 * svc:/op: классы молчат при свежем health (его зона), но ПЕРЕХВАТЫВАЮТ
 * тревогу, как только health протух. Остальные классы алармятся всегда. */

/* Гвард анти-флапа (ч.230): ключ алармил в окно ALARM_REPEAT_SEC.
 * alarm_ts — карта ключ → ts ПОСЛЕДНЕГО отправленного события, живёт в
 * статус-документе между проходами. */
function alarm_cooled(ats, key, now) {
	if (ats == null || type(ats) !== 'object')
		return false;
	const last = int(ats['' + key] || 0);
	return (last > 0 && (now - last) < ALARM_REPEAT_SEC);
};

export function alarm_policy(key, health_fresh) {

	if ((index('' + key, 'svc:') === 0 || index('' + key, 'op:') === 0) && health_fresh)
		return false;

	return true;
};

export function diff_finding_events(prev_f, findings, health_fresh, now, alarm_ts) {
	const ts_now = (now != null) ? int(now) : time();
	const ats = (alarm_ts != null && type(alarm_ts) === 'object') ? alarm_ts : {};
	const out = [];
	if (findings == null)
		return out;
	if (prev_f == null) {
		for (let k in findings)
			findings[k].alarmed = false;   /* базлайн молчит (урок 220) */
		return out;
	}
	for (let k in findings) {
		const f = findings[k];
		const want = alarm_policy(k, health_fresh);
		const is_down = (f.status === 'down');
		if (prev_f[k] == null) {
			f.alarmed = want;
			if (want && (is_down || !alarm_cooled(ats, k, ts_now))) {
				ats[k] = ts_now;
				push(out, { type: (f.status === 'down') ? 'down' : 'degraded',
					who: f.label, detail: f.reason });
			}
		} else if (want && prev_f[k].alarmed !== true) {
			f.alarmed = true;
			if (is_down || !alarm_cooled(ats, k, ts_now)) {
				ats[k] = ts_now;
				push(out, { type: (f.status === 'down') ? 'down' : 'degraded',
					who: f.label, detail: f.reason });
			}
		} else {
			f.alarmed = (prev_f[k].alarmed === true);
		}
	}
	for (let k in prev_f) {
		if (findings[k] != null)
			continue;
		if (prev_f[k].alarmed === true) {
			if (alarm_cooled(ats, k, ts_now))
				continue;   /* ч.230: флип ключа в окне — лента молчит, документ честен */
			ats[k] = ts_now;
			push(out, { type: 'recovered', who: prev_f[k].label,
				detail: 'больше не наблюдается' });
		}
	}
	return out;
};
/* ── procd-инстансы (собственная сверка; урок 171: service list) ────────── */

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

/* Счётчик стартов службы (Ф3.1): init.d bump'ит его на КАЖДОМ start_service.
 * Легитимность смены набора инстансов: рестарт службы = init.d заново оценил
 * все гейты по UCI — набор обязан измениться; исчезновение инстанса БЕЗ
 * рестарта (ubus service delete, урок 219) счётчик не трогает = аномалия.
 * Дискриминатор строже bump'а config_revision: он покрывает и смены набора
 * через обычные LuCI-формы (Save&Apply → procd reload-триггер → stop+start,
 * мимо opman). Файл в tmpfs: ребут обнуляет вместе с документом сторожа. */
export function service_epoch() {
	const raw = readfile(SVC_EPOCH_PATH);
	if (raw == null)
		return 0;
	const m = match(trim('' + raw), /^([0-9]+)$/);
	return (m != null) ? int(m[1]) : 0;
};


/* ── ремонты ─────────────────────────────────────────────────────────────── */

/* Идемпотентный start службы: rc-файл + опрос с heartbeat ора (урок 167:
 * никаких 2-arg system(); detached-подшелл независим от Sentinel'а). */
function run_svc_start(op_id) {
	const rcfile = '/tmp/hp_sentinel_' + op_id + '.rc';
	system('( /etc/init.d/ravnex start >/dev/null 2>&1; echo $? > ' + rcfile + ' ) &');
	const deadline = time() + SVC_START_TIMEOUT;
	while (true) {
		if (access(rcfile)) {
			const rc = trim(readfile(rcfile) || '');
			try { unlink(rcfile); } catch (e) { /* уже нет */ }
			return { ok: true, detail: 'start отчитался (rc=' + (length(rc) ? rc : '?') + ')' };
		}
		if (time() >= deadline) {
			try { unlink(rcfile); } catch (e) { /* уже нет */ }
			return { ok: false, detail: 'start не отчитался за ' + SVC_START_TIMEOUT +
				' с (продолжается фоном — верифицируется service list)' };
		}
		try { op_heartbeat(op_id); } catch (e) { /* lease продержится сам */ }
		sleep(2000);
	}
};

/* Ф10.2: ремонт rpcd через гвард init.d — rpcd_heal восстанавливает
 * /etc/init.d/rpcd (класс whiteout, урок 130) и поднимает ТОЛЬКО мёртвый
 * rpcd, живой не трогается. Тот же rc-файл + опрос, что и run_svc_start
 * (урок 167); rpcd под procd — respawn продолжается сам. */
function run_rpcd_heal(op_id) {
	const rcfile = '/tmp/hp_sentinel_' + op_id + '.rc';
	system('( /etc/init.d/ravnex rpcd_heal >/dev/null 2>&1; echo $? > ' + rcfile + ' ) &');
	const deadline = time() + SVC_START_TIMEOUT;
	while (true) {
		if (access(rcfile)) {
			const rc = trim(readfile(rcfile) || '');
			try { unlink(rcfile); } catch (e) { /* уже нет */ }
			return { ok: true, detail: 'rpcd_heal отчитался (rc=' + (length(rc) ? rc : '?') + ')' };
		}
		if (time() >= deadline) {
			try { unlink(rcfile); } catch (e) { /* уже нет */ }
			return { ok: false, detail: 'rpcd_heal не отчитался за ' + SVC_START_TIMEOUT +
				' с (продолжается фоном — верифицируется следующим проходом)' };
		}
		try { op_heartbeat(op_id); } catch (e) { /* lease продержится сам */ }
		sleep(2000);
	}
};

/* Честное закрытие зависшего опа: лок освобождается, действие НЕ повторяется
 * (Sentinel не может знать, началось ли оно — но журнал честен). */
function do_op_finish(stuck_op_id) {
	const op = op_get('' + stuck_op_id);
	if (op == null)
		return { ok: false, detail: 'операция исчезла из журнала' };
	const st = '' + (op.status || '');
	if (st !== 'queued' && st !== 'running' && st !== 'verifying')
		return { ok: false, detail: 'операция уже закрыта (' + st + ')' };
	op_finish('' + stuck_op_id, false, false,
		'sentinel: руннер умер без честного финиша (heartbeat протух ' +
		'>' + OP_HB_STALE_SEC + ' с) — операция закрыта сторожем, лок освобождён');
	return { ok: true, detail: 'операция «' + (op.action || stuck_op_id) + '» честно закрыта (лок освобождён)' };
};

/* Б5 (сеанс 161): рестарт ядра по identity при RSS-крите — FALLBACK-путь,
 * живёт ТОЛЬКО когда Recovery-координатор мёртв (живой координатор исполняет
 * core_restart сам — classify_key res:core; Sentinel остаётся детектором).
 * Семантика «сброс утечки ДО OOM-грани»: завершение по identity, procd
 * respawn вернёт процесс с чистой памятью. */
function do_core_restart() {
	const e = registry_map()['core'];
	if (e == null || type(e) !== 'object' || pm_entry_alive(e) !== true)
		return { ok: false, detail: 'ядро не работает — за живость отвечает svc_start (следующий проход)' };
	const pid = int(e.pid);
	const k1 = pm_kill_entry(e, 5000, false);
	return (k1)
		? { ok: true, detail: 'ядро перезапущено по identity (pid ' + pid +
			') — RSS-крит сброшен, procd вернёт процесс с чистой памятью' }
		: { ok: false, detail: 'не удалось завершить ядро по identity (pid ' + pid + ')' };
};

/* ── Ф10.3: ресурсы демонов (снапшот + бюджеты) ──────────────────────────── */

/* Бюджет ЯДРА от железа (чистая функция — selftest; пакет A аудита ч.263).
 * gml_eff = min(запрошенный GOMEMLIMIT, пол-ОЗУ в MiB) — зеркало CAP
 * oom_adj.sh (MT/2048 kB → MiB). ct_max = nf_conntrack_max. Неизвестные
 * входы (mem ≤ 0, ct ≤ 0) дают статические фолбэки — safe при /proc-дырах. */
export function res_budget_core(mem_kb, ct_max, gml_req_mib) {
	let gml = (gml_req_mib != null && int(gml_req_mib) > 0) ? int(gml_req_mib) : 0;
	if (int(mem_kb) > 0) {
		const cap = int(mem_kb / 2048);
		if (cap > 0 && (gml <= 0 || gml > cap))
			gml = cap;
	}
	let fdw;
	if (int(ct_max) > 0)
		fdw = int(ct_max / 8);
	else
		fdw = RES_FD_WARN_MIN;
	if (fdw < RES_FD_WARN_MIN)
		fdw = RES_FD_WARN_MIN;
	if (fdw > RES_FD_WARN_MAX)
		fdw = RES_FD_WARN_MAX;
	/* rss warn: min(384 MiB, RES_RSS_WARN_MT_PCT% RAM). */
	let rw = 393216;
	if (int(mem_kb) > 0) {
		const w = int(mem_kb * RES_RSS_WARN_MT_PCT / 100);
		if (w > 0 && w < rw)
			rw = w;
	}
	/* rss crit: max(min(512 MiB, 55% RAM), 135% GML_eff). */
	let rc = 524288;
	if (int(mem_kb) > 0) {
		const c = int(mem_kb * RES_RSS_CRIT_MT_PCT / 100);
		if (c > 0 && c < rc)
			rc = c;
	}
	if (gml > 0) {
		const g = int(gml * 1024 * RES_CRIT_GML_PCT / 100);
		if (g > rc)
			rc = g;
	}
	return { rss_warn_kb: rw, rss_crit_kb: rc, fd_warn: fdw, fd_crit: fdw * 2, gml_eff_mib: gml };
};

/* Вердикт одного демона против бюджета (чистая функция — selftest).
 * level 'ok'/'warn'/'crit', what 'rss'/'fd'/''; crit сильнее warn; rss-крит
 * сильнее fd-warn. rss_kb ≤ 0 = замер не удался — не вердикт. b — явный
 * бюджет (для ядра — динамический из res_budget_core); без него — таблица
 * по имени или общий. */
export function res_verdict(name, rss_kb, fds, b) {
	const nb = (b != null) ? b
		: ((RES_BUDGETS['' + name] != null) ? RES_BUDGETS['' + name] : RES_BUDGET_GENERIC);
	let level = 'ok', what = '';
	if (rss_kb != null && int(rss_kb) > 0) {
		if (int(nb.rss_crit_kb) > 0 && int(rss_kb) >= int(nb.rss_crit_kb)) {
			level = 'crit'; what = 'rss';
		} else if (int(rss_kb) >= int(nb.rss_warn_kb)) {
			level = 'warn'; what = 'rss';
		}
	}
	if (fds != null && int(fds) >= 0) {
		if (int(nb.fd_crit) > 0 && int(fds) >= int(nb.fd_crit)) {
			level = 'crit'; what = 'fd';
		} else if (level === 'ok' && int(fds) >= int(nb.fd_warn)) {
			level = 'warn'; what = 'fd';
		}
	}
	return { budget: nb, level: level, what: what };
};

/* Состав fd ядра при перерасходе (ч.263, пакет A): выборка до 512
 * дескрипторов по типам (readlink — fork-free): «утечка pipe-пар splice»
 * видна в находке сразу, без strace/форков. */
function res_fd_mix(fdpath, d) {
	let socket = 0, pipe = 0, other = 0;
	const cap = (length(d) > 512) ? 512 : length(d);
	for (let i = 0; i < cap; i++) {
		const t = readlink(fdpath + '/' + d[i]);
		if (t == null) {
			other = other + 1;
			continue;
		}
		const s = '' + t;
		if (index(s, 'socket:') === 0)
			socket = socket + 1;
		else if (index(s, 'pipe:') === 0)
			pipe = pipe + 1;
		else
			other = other + 1;
	}
	return 'socket ' + socket + ', pipe ' + pipe + ', прочее ' + other +
		' (выборка ' + cap + ' из ' + length(d) + ')';
};

/* Снапшот ресурсов живых демонов реестра (fork-free: readfile + lsdir).
 * Мёртвые pid пропускаются — их живость зона svc-проверок. Строка:
 * { name, label, pid, rss_kb, fds, level, what, rss_warn_kb, rss_crit_kb,
 *   fd_warn, fd_crit [, fd_mix] } — бюджеты едут в строке, чтобы RPC/UI не
 * знали таблицу. ctx = { mem_kb, ct_max, gml_mib } — железо для
 * динамического бюджета ЯДРА (res_budget_core); null/неполный ctx = стат.
 * фолбэки (crit = 1.35×GOMELIMIT от запрошенного, warn 384). fd_mix
 * считается ТОЛЬКО для ядра в зоне fd-перерасхода. */
export function res_snapshot(regst, ctx) {
	const out = [];
	if (regst == null || type(regst) !== 'object')
		return out;
	const cx = (ctx != null && type(ctx) === 'object') ? ctx : {};
	for (let name in regst) {
		const e = regst[name];
		if (e == null || type(e) !== 'object' || e.pid == null)
			continue;
		const pid = int(e.pid);
		if (pid <= 0 || !access('/proc/' + pid + '/stat'))
			continue;
		const st = readfile('/proc/' + pid + '/status') || '';
		const m = match(st, /VmRSS:[ \t]+([0-9]+)/);
		const fdpath = '/proc/' + pid + '/fd';
		let fds = -1;
		let flist = null;
		if (access(fdpath)) {
			flist = lsdir(fdpath);
			fds = (flist != null) ? length(flist) : -1;
		}
		const rss = (m != null) ? int(m[1]) : 0;
		if (rss <= 0 && fds < 0)
			continue;   /* /proc недоступен — нет замера, нет строки */
		const iscore = ('' + name) === 'core';
		const v = (iscore)
			? res_verdict(name, rss, fds,
				res_budget_core(int(cx.mem_kb || 0), int(cx.ct_max || 0), int(cx.gml_mib || RES_CORE_GML_REQ_MIB)))
			: res_verdict(name, rss, fds);
		const row = {
			name: '' + name, label: res_label(name), pid: pid,
			rss_kb: rss, fds: fds, level: v.level, what: v.what,
			rss_warn_kb: int(v.budget.rss_warn_kb), rss_crit_kb: int(v.budget.rss_crit_kb),
			fd_warn: int(v.budget.fd_warn), fd_crit: int(v.budget.fd_crit)
		};
		if (iscore && v.level !== 'ok' && v.what === 'fd' && flist != null)
			row.fd_mix = res_fd_mix(fdpath, flist);
		push(out, row);
	}
	return out;
};

/* Причина находки перерасхода (вынесено ч.230 — один текст для свежего
 * вердикта и для гистерезис-удержания). level едет В находке (ч.263):
 * Recovery гейтит рестарт ядра на what==='rss' && level==='crit' &&
 * armed===true. extra = { crit_run, armed } для ядра (armed-гвард). */
function res_finding(r, level, what, extra) {
	let reason;
	if (what === 'fd')
		reason = 'открытых fd: ' + sprintf('%d', int(r.fds)) +
			((level === 'crit')
				? ' при бюджете ' + sprintf('%d', int(r.fd_crit)) + ' — критическая зона, вероятна утечка дескрипторов'
				: ' при бюджете ' + sprintf('%d', int(r.fd_warn)) + ' — возможна утечка дескрипторов, наблюдение участится');
	else
		reason = 'RSS ' + sprintf('%.1f', int(r.rss_kb) / 1024) + ' МБ' +
			((level === 'crit')
				? ' при бюджете ' + sprintf('%.0f', int(r.rss_crit_kb) / 1024) + ' МБ — зона OOM-грани (кейс WR3000H: ядро убивалось при ~727 МБ)'
				: ' при бюджете ' + sprintf('%.0f', int(r.rss_warn_kb) / 1024) + ' МБ — потребление выше штатного, наблюдение участится');
	const out = {
		status: 'degraded', label: res_label(r.name), reason: reason,
		confidence: 'certain', what: what, level: level
	};
	if (extra != null && type(extra) === 'object') {
		if (extra.crit_run != null)
			out.crit_run = int(extra.crit_run);
		if (extra.armed != null)
			out.armed = (extra.armed === true);
		if (out.what === 'rss' && out.level === 'crit')
			out.reason += (out.armed === true)
				? ' — рестарт ядра вооружён'
				: ' — подтверждение рестарта ' + int(extra.crit_run || 0) + '/' +
					sprintf('%d', RES_CRIT_CONFIRM_PASSES);
	}
	if (what === 'fd' && r.fd_mix != null)
		out.reason += ' (состав: ' + ('' + r.fd_mix) + ')';
	return out;
};

/* Б5 (сеанс 161): рестарт ядра по RSS-криту wanted? Чистая функция.
 * ТОЛЬКО core + rss-крит: fd-крит ядра лечится падением соединений сам,
 * прочие демоны в своих бюджетах. До сеанса 161 действовало решение ч.218
 * «OOM = само-лечение»: dmesg этого класса боксов показал цену — жертвой
 * oom-killer становится не только ядро (hostapd-коллатерали), а restart по
 * identity (procd respawn) сбрасывает утечку ДО OOM-грани. */
export function res_core_restart_wanted(snap) {
	if (snap == null || type(snap) !== 'array')
		return null;
	for (let r in snap) {
		if (r == null || type(r) !== 'object')
			continue;
		if (('' + r.name) === 'core' && r.level === 'crit' && r.what === 'rss')
			return r;
	}
	return null;
};

/* Находки перерасхода из снапшота. status ВСЕГДА 'degraded': перерасход не
 * означает «процесс мёртв» (down резервируется смертям), авто-ремонта нет.
 * prev_f (ч.230) — находки прошлого прохода: активная находка того же класса
 * (what) держится, пока метрика не уйдёт ниже 90% warn-линии (гистерезис),
 * иначе значения, гуляющие вокруг линии бюджета, дают пары
 * degraded/recovered каждые полпрохода (живой случай: core fd 2054↔2047).
 * Вердикт снапшота (resources.json / карточка UI) остаётся честным live. */
export function res_findings(snap, prev_f) {
	const out = {};
	if (snap == null || type(snap) !== 'array')
		return out;
	for (let r in snap) {
		if (r == null || r.level == null)
			continue;
		if (r.level === 'ok') {
			if (prev_f != null && type(prev_f) === 'object') {
				const pf = prev_f['res:' + r.name];
				if (pf != null && type(pf) === 'object') {
					/* Класс удержания — из прошлой находки (у ok-строки снапшота
					 * what пуст); hold = метрика того же класса в полосе ≥90% warn. */
					const pw = '' + pf.what;
					const warn_fd = int(r.fd_warn);
					const warn_rss = int(r.rss_warn_kb);
					if (pw === 'fd' && warn_fd > 0 &&
					    int(r.fds) >= warn_fd - int(warn_fd / 10))
						out['res:' + r.name] = res_finding(r, 'warn', 'fd');
					else if (pw === 'rss' && warn_rss > 0 &&
					    int(r.rss_kb) >= warn_rss - int(warn_rss / 10))
						out['res:' + r.name] = res_finding(r, 'warn', 'rss');
				}
			}
			continue;
		}
		if (('' + r.name) === 'core' && r.level === 'crit' && r.what === 'rss') {
			/* ч.263: крит-находка ядра по RSS несёт armed — подтверждённость
			 * рестарта. crit_run = число ПОДРЯД проходов с rss ≥ crit (едет в
			 * находке через prev_f); armed = хватает подтверждений ИЛИ
			 * одномоментно ≥ RES_CRIT_FAST_PCT% crit (явное бегство памяти).
			 * Быстрые проходы тоже считают — свежий замер есть свежий замер;
			 * любой не-crit вердикт ядра сбрасывает серию (streak не пишется). */
			let run = 0;
			if (prev_f != null && type(prev_f) === 'object') {
				const pf = prev_f['res:core'];
				if (pf != null && type(pf) === 'object' && pf.crit_run != null)
					run = int(pf.crit_run);
			}
			run = run + 1;
			const fast = int(r.rss_kb) * 100 >= int(r.rss_crit_kb) * RES_CRIT_FAST_PCT;
			out['res:core'] = res_finding(r, r.level, r.what,
				{ crit_run: run, armed: (run >= RES_CRIT_CONFIRM_PASSES) || fast });
			continue;
		}
		out['res:' + r.name] = res_finding(r, r.level, r.what);
	}
	return out;
};

/* ── ч.264: тренд-наблюдение 2-го уровня (копилка аудита ч.263, B) ─────────
 * Мягкое наблюдение ДО warn-линии: строгие подъёмы fd/RSS на серии из
 * TREND_RUN_TICKS проходов при значении ≥ TREND_FLOOR_PCT% warn-бюджета
 * помечают строку снапшота row.trend — карточка «Ресурсы демонов» показывает
 * честную стрелку роста. Находок/алармов нет, overall не меняется: это
 * НЕ деградация, а раннее наблюдение (restoring-class тайпчеки не задеты).
 * Гвард с seed (урок 399): первый проход только засеивает базлайн, серия
 * обязана накопиться. Состояние in-process: рестарт Sentinel'а = тихий
 * пересев (пара проходов слепоты — приемлемо, ложных тревог не даёт). */
const TREND_RUN_TICKS = 3;
const TREND_FLOOR_PCT = 60;
const _res_trend = {};

export function res_trend_reset() {
	const names = [];
	for (let k in _res_trend)
		push(names, k);
	for (let k in names)
		delete _res_trend[names[k]];
};

export function res_trend_apply(rows) {
	if (rows == null || type(rows) !== 'array')
		return;
	for (let r in rows) {
		if (r == null || type(r) !== 'object' || r.level !== 'ok')
			continue;
		const nm = '' + r.name;
		const st = _res_trend[nm] || {};
		const parts = [];
		/* Строгое «больше прошлого замера» И ≥ floor% warn — иначе серия
		 * обнуляется (гвард монотонности с seed: первый проход только
		 * засеивает, trend невозможен до накопления серии). */
		const fds = int(r.fds);
		if (fds > 0 && int(r.fd_warn) > 0) {
			const prev = int(st.fd_prev || 0);
			if (prev > 0 && fds > prev &&
			    fds * 100 >= int(r.fd_warn) * TREND_FLOOR_PCT)
				st.fd_run = int(st.fd_run || 0) + 1;
			else
				st.fd_run = 0;
			st.fd_prev = fds;
			if (st.fd_run >= TREND_RUN_TICKS) {
				const w = int(r.fd_warn);
				push(parts, 'fd растёт ' + TREND_RUN_TICKS + '+ проходов (' +
					int(fds * 100 / w) + '% бюджета)');
			}
		}
		const kb = int(r.rss_kb);
		if (kb > 0 && int(r.rss_warn_kb) > 0) {
			const prev = int(st.rss_prev || 0);
			if (prev > 0 && kb > prev &&
			    kb * 100 >= int(r.rss_warn_kb) * TREND_FLOOR_PCT)
				st.rss_run = int(st.rss_run || 0) + 1;
			else
				st.rss_run = 0;
			st.rss_prev = kb;
			if (st.rss_run >= TREND_RUN_TICKS) {
				const w = int(r.rss_warn_kb);
				push(parts, 'RSS растёт ' + TREND_RUN_TICKS + '+ проходов (' +
					int(kb * 100 / w) + '% бюджета)');
			}
		}
		_res_trend[nm] = st;
		if (length(parts))
			r.trend = join('; ', parts);
	}
};

/* ── главный проход ────────────────────────────────────────────────────────
 * opts = { full: bool, grace_until: int, daemon_pid: int|null }.
 * Возвращает { data, events, baseline, repairs }. */
export function compute_and_store(opts) {
	const o = (opts != null) ? opts : {};
	const full = (o.full === true);
	const grace_until = int(o.grace_until || 0);
	const now = time();
	const prev_rd = ss_read_state(SENTINEL_PATH);
	const prev = (prev_rd != null && prev_rd.data != null && type(prev_rd.data) === 'object')
		? prev_rd.data : null;
	const baseline = (prev == null);
	const prev_f = (prev != null && prev.findings != null && type(prev.findings) === 'object')
		? prev.findings : {};
	const findings = {};
	const actions = [];
	const svc_want = [];

	/* 1. Живость самого Health Monitor. */
	const hrd = ss_read_state(HEALTH_PATH);
	const hage = health_age(hrd, now);
	/* ч.263 (пакет A): грань живости — не меньше трёх тиков самого монитора:
	 * lite (фактор 3) тикает light каждые 60 с; базовые 120 с = ровно 2 тика —
	 * один пропуск уже ложил запас на грань ложного «монитор молчит». */
	const rp_prof = pm_res_profile();
	const prof_factor = (rp_prof != null && rp_prof.factor != null && int(rp_prof.factor) > 0)
		? int(rp_prof.factor) : 1;
	let stale_eff = HEALTH_LIGHT_SEC * HEALTH_STALE_TICKS * prof_factor;
	if (stale_eff < HEALTH_STALE_SEC)
		stale_eff = HEALTH_STALE_SEC;
	const health_fresh = (hage >= 0 && hage <= stale_eff);
	if (!health_fresh && now >= grace_until) {
		findings.health_monitor = {
			status: 'down', label: 'Health Monitor',
			reason: (hage < 0)
				? 'документ здоровья отсутствует — монитор не писал с ребута'
				: 'монитор молчит ' + int(hage) + ' с (health.json не обновляется)',
			confidence: 'certain'
		};
		push(svc_want, 'Health Monitor');
	}

	/* 2. Полный проход: procd-ожидания + зависшие опы + зависшие демоны. */
	let svc = (prev != null && prev.instances != null) ? prev.instances : null;
	let apply_running = false;
	let ops_now = null;
	let epoch = 0;
	const rev = ss_read_revision();
	if (full) {
		svc = service_instances();
		ops_now = op_list();
		apply_running = apply_in_progress(ops_now, now);
		epoch = service_epoch();
		if (now >= grace_until) {
			/* Дрейф набора (урок 219): только при НЕизменившейся ревизии,
			 * НЕизменившемся счётчике стартов службы и вне окна apply —
			 * иначе смена набора легитимна. 🔴 Ф3.1: рестарт службы —
			 * ЕДИНСТВЕННЫЙ легитимный способ смены набора (init.d заново
			 * оценивает все гейты по UCI — смена режима маршрутизации,
			 * движков, автоматизации), и он bump'ит .service_epoch. Смена
			 * набора при НЕизменившемся счётчике = внешний вмешатель­ство
			 * (ubus delete) — именно оно и есть аномалия. */
			const prev_inst = (prev != null && prev.instances != null) ? prev.instances : null;
			const prev_rev = (prev != null) ? int(prev.config_revision || 0) : -1;
			const prev_epoch = (prev != null) ? int(prev.service_epoch || 0) : -1;
			if (prev_inst != null && !instance_change_legit(prev_rev, prev_epoch, rev, epoch, apply_running)) {
				for (let name in drifted_instances(prev_inst, svc)) {
					findings['svc_drift:' + name] = {
						status: 'down', label: inst_label(name),
						reason: 'инстанс исчез из service list без рестарта службы (ревизия ' +
							rev + ' и счётчик стартов ' + epoch + ' не менялись) — внешний вмешательство (ubus delete?)',
						confidence: 'certain'
					};
					push(svc_want, inst_label(name));
				}
			}
			const dead = dead_instances(svc);
			if (length(dead)) {
				for (let name in dead) {
					findings['svc:' + name] = {
						status: 'down', label: inst_label(name),
						reason: 'procd: инстанс «' + name + '» не работает (respawn-окно или бюджет исчерпан)',
						confidence: 'certain'
					};
					push(svc_want, inst_label(name));
				}
			}
			/* Ф10.2: rpcd НЕ homeproxy-инстанс — его смерть = класс «LuCI
			 * заблокирована» (уроки 130: whiteout init-скрипта, 132: crash-loop
			 * регистрации — LuCI/RPC мёртвы целиком). Бинарный pidof надёжен
			 * (rpcd = /sbin/rpcd; урок 320 о ucode-CLI сюда не относится).
			 * Ремонт — rpcd_heal (тот же гвард, что на каждом старте службы). */
			if (now >= grace_until && !length(trim(capture('pidof rpcd 2>/dev/null') || ''))) {
				findings['svc:rpcd'] = {
					status: 'down', label: 'rpcd (LuCI/RPC-плоскость)',
					reason: 'rpcd не работает — LuCI/RPC недоступны для новых сессий; авто-ремонт rpcd_heal',
					confidence: 'certain'
				};
				push(svc_want, 'rpcd');
				push(actions, {
					key: 'rpcd_heal', action: 'rpcd_heal', who: 'rpcd',
					detail: 'гвард rpcd_heal: восстановление init-скрипта + идемпотентный старт rpcd (живой не трогается)'
				});
			}
			for (let so in stale_ops(ops_now, now)) {
				findings['op:' + so.op_id] = {
					status: 'degraded', label: 'Операция ' + so.op_id,
					reason: '«' + so.action + '» (' + so.status + ') без heartbeat ' +
						int(so.stale_sec) + ' с — руннер умер без честного финиша',
					confidence: 'certain'
				};
				push(actions, {
					key: 'op_finish', action: 'op_finish', op_id: so.op_id,
					who: 'Операция ' + so.op_id,
					detail: 'честное закрытие зависшей операции «' + so.action + '» (действие не повторяется)'
				});
			}
			for (let h in hung_daemons(registry_map(), now)) {
				findings['hung:' + h.name] = {
					status: 'degraded', label: 'Демон «' + inst_label(h.name) + '»',
					reason: 'процесс жив (identity подтверждена), heartbeat не обновляется ' +
						int(h.hb_age) + ' с — возможно, завис цикл демона',
					confidence: 'certain'
				};
			}
		}
	}

	/* 3. Конфиги обязаны существовать (без fork'ов; ожидания — инстансы). */
	const core_expected = (svc != null && svc['hiddify-c'] != null);
	const mdns_expected = (svc != null && svc['multidns'] != null);
	const cfgf = config_findings(build_config_checks(core_expected, mdns_expected));
	for (let k in cfgf)
		findings[k] = cfgf[k];

	/* 3a. Ф10.3: ресурсы демонов — снапшот + бюджеты. ПОЛНЫЙ проход всегда;
	 * light — ТОЛЬКО когда перерасход уже активен в прошлом документе
	 * (адаптивный интервал: деградация проверяется каждым проходом ~30 с,
	 * спокойный фон — раз в ~5 мин). Fork-free (readfile + lsdir) — light
	 * остаётся без fork'ов. Снапшот-документ — отдельный файл (statestore,
	 * атомарно); его читает RPC resource_status / карточка «Ресурсы демонов».
	 * Находки res:* ремонтов НЕ порождают, КРОМЕ Б5 (сеанс 161): RSS-крит
	 * ядра → core_restart по identity (procd respawn) — рестарт ДО OOM-грани
	 * дешевле oom-kill'а с коллатеральными жертвами (решение пользователя
	 * поверх ч.218; гварды: full-проход, нет живого apply, loop-guard). */
	const prev_res_active = (function() {
		for (let k in prev_f)
			if (index('' + k, 'res:') === 0)
				return true;
		return false;
	})();
	if (full || prev_res_active) {
		/* ч.263: железо для динамического бюджета ядра — снять ДО снапшота. */
		const memraw = readfile('/proc/meminfo') || '';
		const mtot = match(memraw, /MemTotal:\s+([0-9]+)/);
		const mem_total_kb = (mtot != null) ? int(mtot[1]) : -1;
		const ctraw = readfile('/proc/sys/net/netfilter/nf_conntrack_max');
		const ct_max = (ctraw != null) ? int(trim('' + ctraw)) : 0;
		const ctx = { mem_kb: mem_total_kb, ct_max: ct_max, gml_mib: RES_CORE_GML_REQ_MIB };
		const snap = res_snapshot(registry_map(), ctx);
		/* ч.264: тренд-наблюдение — маркер в строках снапшота (без находок). */
		res_trend_apply(snap);
		const rf = res_findings(snap, prev_f);
		/* Б5: RSS-крит ядра → действие core_restart (ключ res:core —
		 * loop-guard и координатор работают по нему как по обычному поводу).
		 * 🔴 ч.263: только ARMED-находка (2 прохода подряд или ≥1.5×crit —
		 * гвард подтверждённости в res_findings); инстант-пик не рестартует. */
		if (full && !apply_running) {
			const rcr = res_core_restart_wanted(snap);
			const fcore = (rcr != null) ? rf['res:core'] : null;
			if (rcr != null && fcore != null && fcore.armed === true)
				push(actions, {
					key: 'res:core', action: 'core_restart',
					who: res_label('core'),
					detail: 'авто-рестарт ядра по identity (RSS ' + sprintf('%.1f', int(rcr.rss_kb) / 1024) +
						' МБ ≥ крит-бюджета ' + sprintf('%.0f', int(rcr.rss_crit_kb) / 1024) +
						' МБ) — procd вернёт процесс с чистой памятью, OOM-килл не случится'
				});
		}
		for (let k in rf) {
			/* Сеанс 158/Б4: на роутерах с малым ОЗУ перерасход ядра — прямая
			 * дорога к OOM-киллу (кейс WR3000H: 2×OOM на 4.1.0 при 757 МБ) —
			 * к находке добавляется честный путь: профиль «Лёгкий». */
			if (k === 'res:core' && mem_total_kb > 0 && mem_total_kb <= 1048576) {
				const f = rf[k];
				f.reason += ' — для этого роутера включите профиль «Лёгкий» (Обслуживание → профиль ресурсов) и обновите ядро из фида';
			}
			findings[k] = rf[k];
		}
		let res_overall = 'ok';
		for (let r in snap)
			if (r.level !== 'ok')
				res_overall = 'degraded';
		ss_write_state(RES_PATH, {
			ts: time(), deep: full, overall_res: res_overall,
			mem_available_kb: parse_meminfo_kb(memraw),
			mem_total_kb: mem_total_kb,
			res: snap
		});
	}

	/* 3b. Light-проход ПЕРЕНОСИТ full-проходные находки op:/hung:/svc:/
	 * svc_drift:/res: (Recovery читает поводы из этого документа между полными
	 * проходами — без переноса зависший оп/демон и убранный ubus-delete'ом
	 * инстанс «моргали» бы пустотой каждые 30–150 с, а health видит
	 * ubus-delete как 'off', не down). 🔴 Перенос помечается carried=true:
	 * координатор держит по нему alive, но ПОВТОРНЫХ попыток не делает —
	 * вердикт после попытки подтверждает только следующий ПОЛНЫЙ проход
	 * (иначе свет-переносы порождали бы лишние start'ы после успешного
	 * ремонта). Перенос честен: stale_sec/hb_age только растут. */
	if (!full && prev_f != null) {
		for (let k in prev_f) {
			if ((index('' + k, 'op:') === 0 || index('' + k, 'hung:') === 0 ||
			     index('' + k, 'svc:') === 0 || index('' + k, 'svc_drift:') === 0 ||
			     index('' + k, 'res:') === 0) &&
			    findings['' + k] == null) {
				const cf = prev_f[k];
				if (cf != null && type(cf) === 'object') {
					cf.carried = true;
					findings['' + k] = cf;
				}
			}
		}
	}

	/* 4. Сервисный ремонт — один батч на все svc-поводы. ТОЛЬКО в full-проходе:
	 * light не читает журнал опов и не знает об идущем apply — сервисный старт
	 * параллельно с apply недопустим (урок 113-класс). Light оставляет находку
	 * (детект честный), ремонт откладывается до ближайшего full (fast-mode:
	 * ≤30 с после детекта). */
	if (full && length(svc_want) && !apply_running)
		push(actions, {
			key: 'svc_start', action: 'svc_start',
			who: join(', ', svc_want),
			detail: 'идемпотентный старт службы (поднимает только мёртвые инстансы, живые не трогаются)'
		});

	/* 5. Loop-guard: ключ под блокировкой → находка цикла; новый перебор →
	 * блокировка + находка. Блокировка живёт до исчезновения проблемы
	 * (или TTL — одна попытка раз в 2 часа). Дедуп: svc_start один батч,
	 * op_finish — по одному на каждый зависший оп. */
	let reps = prune_repairs((prev != null) ? prev.repairs : null, now);
	let blocked = (prev != null && prev.blocked != null && type(prev.blocked) === 'object')
		? prev.blocked : {};
	const wants = {};
	for (let a in actions)
		wants['' + a.key] = true;
	for (let k in blocked) {
		if (!wants['' + k] || (now - int(blocked[k] || 0)) > BLOCKED_TTL_SEC)
			delete blocked[k];
	}
	const acts = [];
	const seen = {};
	for (let a in actions) {
		if (seen['' + a.key] != null && a.key !== 'op_finish')
			continue;
		seen['' + a.key] = true;
		push(acts, a);
	}
	const acts_run = [];
	for (let a in acts) {
		const k = '' + a.key;
		if (blocked[k] != null) {
			findings['loop:' + k] = {
				status: 'degraded', label: 'Цикл восстановления: ' + k,
				reason: 'авто-ремонт «' + k + '» приостановлен (перебор) — проблемы остаются, нужен взгляд пользователя',
				confidence: 'certain'
			};
			continue;
		}
		const guard = repair_allowed(reps, k, now);
		if (!guard.allowed) {
			blocked[k] = now;
			findings['loop:' + k] = {
				status: 'degraded', label: 'Цикл восстановления: ' + k,
				reason: 'починок «' + k + '» — ' + guard.count + ' за последние ' +
					int(REPAIR_WINDOW_SEC / 60) + ' мин без результата; авто-ремонт остановлен',
				confidence: 'certain'
			};
			continue;
		}
		push(acts_run, a);
	}

	/* 6. Diff находок → события (до исполнения ремонтов — ремонтные события
	 * добавляются следом, порядок в ленте честный). Ч.230: карта alarm_ts
	 * (ключ → ts последнего отправленного события) живёт в документе между
	 * проходами — гвард ALARM_REPEAT_SEC глушит флип ключа взад-вперёд
	 * (degraded/recovered спам); находки в документе честны и без ленты. */
	const prev_ats = (prev != null && prev.alarm_ts != null && type(prev.alarm_ts) === 'object')
		? prev.alarm_ts : {};
	const events = diff_finding_events(baseline ? null : prev_f, findings, health_fresh, now, prev_ats);

	/* 7. Исполнение ремонтов через opman-дверь.
	 * Ф2.3: пока Recovery-координатор ЖИВ, Sentinel — только детектор: поводы
	 * и так пишутся в этот документ, координатор их подбирает и исполняет с
	 * полной политикой (гистерезис/backoff/лимиты/ручной приоритет). Мёртвый
	 * Recovery (нет инстанса в service list) — Sentinel возвращается к
	 * разовому исполнению (fallback Ф2.2: контракт opman-двери/событий не
	 * менялся). Урок 219: отсутствие инстанса в service list = мёртв. */
	const recovery_live = (svc != null && svc['recovery'] === true);
	const repairs_done = [];
	let last_repair = (prev != null) ? prev.last_repair : null;
	for (let a in acts_run) {
		if (recovery_live)
			break;   /* поводы остаются в findings — их подберёт координатор */
		const b = op_begin('repair', a.action, 'sentinel', 'sentinel auto-repair', 0);
		if (b == null || b.ok !== true)
			continue;   /* apply/предыдущий ремонт держит ресурс — повторим позже */
		const op = b.op;
		let res = { ok: false, detail: 'неизвестное действие' };
		if (a.action === 'svc_start')
			res = run_svc_start(op.op_id);
		else if (a.action === 'op_finish')
			res = do_op_finish(a.op_id);
		else if (a.action === 'rpcd_heal')
			res = run_rpcd_heal(op.op_id);
		else if (a.action === 'core_restart')
			res = do_core_restart();
		/* 🔴 verified=false ВСЕГДА: ремонт не есть применение конфигурации —
		 * verified=true бампнул бы config_revision (опман) и подавил бы
		 * следующий drift-детект (поймано приёмкой ч.165). Честность
		 * ремонта верифицируется следующим проходом по service list. */
		op_finish(op.op_id, res.ok, false, '' + (res.detail || ''));
		reps = record_repair(reps, a.key, now);
		push(repairs_done, { key: a.key, op_id: op.op_id, ok: res.ok, ts: time() });
		push(events, {
			type: 'repair', who: a.who,
			detail: (res.ok ? '' : 'НЕ УДАЛОСЬ: ') + a.detail +
				(length('' + (res.detail || '')) ? (' — ' + res.detail) : '')
		});
		last_repair = { key: a.key, who: a.who, ok: res.ok, op_id: op.op_id, ts: time() };
	}

	/* 8. События — В ШИНУ (каждая починка → событие, Ф2.2 контракт). Эмиссия
	 * живёт ЗДЕСЬ, не в CLI: compute_and_store — единственная точка, где
	 * собран полный набор событий прохода (поймано приёмкой ч.165: модуль
	 * вычислял события и возвращал их, но ev_emit никогда не звался —
	 * журнал и TG молчали при живых ремонтах). */
	for (let ev in events) {
		try {
			ev_emit(SRC, '' + ev.type, '' + (ev.who || ''), '' + (ev.detail || ''));
		} catch (e) { /* шина — best-effort */ }
	}

	/* 9. Статус-документ (ts = живое свидетельство сторожа). */
	const data = {
		overall: overall_of(findings),
		ts: time(),
		deep: full,
		health_age: hage,
		config_revision: int(rev),
		service_epoch: epoch,
		instances: svc,
		coordinator: (recovery_live) ? 'live' : 'self',
		findings: findings,
		repairs: reps,
		blocked: blocked,
		alarm_ts: prev_ats,
		last_repair: last_repair,
		daemon: { pid: (o.daemon_pid != null) ? int(o.daemon_pid) : null, note: 'sentinel' }
	};
	ss_write_state(SENTINEL_PATH, data);
	return { data: data, events: events, baseline: baseline, repairs: repairs_done };
};

/* ── selftest (чистая логика на подставных входах) ──────────────────────── */
export function selftest() {
	const checks = [];
	const check = function(name, ok, detail) {
		push(checks, { check: name, ok: ok, detail: detail || null });
		return ok;
	};
	const now = time();

	/* meminfo. */
	check('meminfo', parse_meminfo_kb('MemTotal: 1 kB\nMemAvailable:  700000 kB\n') === 700000, null);
	check('meminfo_missing', parse_meminfo_kb('MemTotal: 1 kB') === -1, null);

	/* health_age. */
	check('hage_fresh', health_age({ meta: { ts: now - 10 } }, now) === 10, null);
	check('hage_stale', health_age({ meta: { ts: now - 200 } }, now) === 200, null);
	check('hage_missing', health_age(null, now) === -1 &&
		health_age({ meta: {} }, now) === -1, null);

	/* dead_instances. */
	check('dead_mixed', (function() {
		const d = dead_instances({ a: true, b: false, c: false, d: true });
		return length(d) === 2 && d[0] === 'b' && d[1] === 'c';
	})(), null);
	check('dead_empty', length(dead_instances({ a: true })) === 0 &&
		length(dead_instances(null)) === 0, null);

	/* drifted_instances (урок 219). */
	check('drift_one', (function() {
		const d = drifted_instances({ a: true, b: false, c: true }, { a: true, b: false });
		return length(d) === 1 && d[0] === 'c';
	})(), null);
	check('drift_none', length(drifted_instances(null, { a: true })) === 0 &&
		length(drifted_instances({ a: true }, { a: true, b: false })) === 0 &&
		length(drifted_instances({ a: null }, { a: false })) === 0, null);

	/* instance_change_legit (Ф3.1): рестарт службы (эпоха выросла), применение
	 * (ревизия выросла) и живой apply легитимизируют смену набора; только
	 * «всё без изменений» — аномалия. */
	check('chg_legit_epoch', instance_change_legit(5, 3, 5, 4, false) === true &&
		instance_change_legit(5, 3, 6, 3, false) === true &&
		instance_change_legit(5, 3, 5, 3, true) === true, null);
	check('chg_anomaly', instance_change_legit(5, 3, 5, 3, false) === false, null);

	/* stale_ops. */
	const ops = [
		{ op_id: 'x1', action: 'restart', kind: 'restart', status: 'running', heartbeat: now - 400 },
		{ op_id: 'x2', action: 'reload', kind: 'reload', status: 'running', heartbeat: now - 10 },
		{ op_id: 'x3', action: 'restart', kind: 'restart', status: 'completed', heartbeat: now - 9999 },
		{ op_id: 'x4', action: 'reload', kind: 'reload', status: 'queued', started: now - 500, heartbeat: 0 }
	];
	const so = stale_ops(ops, now);
	check('stale_ops', length(so) === 2 && so[0].op_id === 'x1' && so[1].op_id === 'x4' &&
		so[0].stale_sec === 400, null);
	check('stale_ops_empty', length(stale_ops(null, now)) === 0, null);

	/* apply_in_progress — урок 229: РЕАЛЬНЫЕ kind'ы ('service' — так создаёт
	 * op_spawn RPC; 'core_install'); action-имена kind'ами НЕ являются. */
	check('apply_busy', apply_in_progress([
		{ op_id: 'r1', kind: 'service', action: 'restart', status: 'running', heartbeat: now - 5 }
	], now) === true, null);
	check('apply_core_install', apply_in_progress([
		{ op_id: 'r1', kind: 'core_install', status: 'verifying', heartbeat: now - 5 }
	], now) === true, null);
	check('apply_busy_stuck_not_blocking', apply_in_progress([
		{ op_id: 'r1', kind: 'service', status: 'running', heartbeat: now - 400 }
	], now) === false, null);
	check('apply_free', apply_in_progress([
		{ op_id: 'r1', kind: 'service', status: 'completed' }
	], now) === false, null);
	check('apply_free_other_kind', apply_in_progress([
		{ op_id: 'r1', kind: 'repair', status: 'running', heartbeat: now - 5 }
	], now) === false, null);

	/* hung_daemons. */
	const reg = {
		automation: { pid: 1, hb: now - 1000, alive: true, note: 'owner' },
		metrics: { pid: 2, hb: now - 5, alive: true, note: 'owner' },
		core: { pid: 3, hb: now - 5000, alive: true, note: 'health-scan' },  /* скан-запись: hb заморожен — НЕ «завис» (урок 226) */
		tg: { pid: 4, hb: now - 10, alive: false, note: 'owner' }            /* мёртв — не «завис» */
	};
	const hd = hung_daemons(reg, now);
	check('hung_one', length(hd) === 1 && hd[0].name === 'automation' && hd[0].hb_age === 1000, null);
	check('hung_skip_scan', length(hd) === 1, 'scanned entry with stale hb must be skipped');
	check('hung_empty', length(hung_daemons(null, now)) === 0, null);

	/* registry_map (на подставном документе). */
	const rm = registry_map({ daemons: { a: { pid: 1, start: 5, exe: 'x' } } });
	check('reg_map_alive', rm.a.alive === false, null);   /* фиктивный pid — честно мёртв */

	/* config_findings. */
	const cf = config_findings([
		{ key: 'a', label: 'A', severity: 'down', ok: false, reason: 'r1' },
		{ key: 'b', label: 'B', severity: 'degraded', ok: true, reason: 'x' },
		{ key: 'c', label: 'C', severity: 'degraded', ok: false, reason: 'r2' }
	]);
	check('cfg_findings', length(cf) === 2 && cf.a.status === 'down' &&
		cf.c.status === 'degraded' && cf.a.reason === 'r1', null);
	check('cfg_findings_empty', length(config_findings(null)) === 0, null);

	/* loop-guard математика. */
	let reps = prune_repairs(null, now);
	check('prune_empty', length(reps) === 0, null);
	reps = prune_repairs({ k: { times: [ now - 100, now - 2000 ] } }, now);
	check('prune_window', length(reps.k.times) === 1, null);
	check('allowed', repair_allowed(reps, 'k', now).allowed === true &&
		repair_allowed(reps, 'other', now).count === 0, null);
	reps = record_repair(reps, 'k', now);
	reps = record_repair(reps, 'k', now);
	check('cap', repair_allowed(reps, 'k', now).allowed === false &&
		repair_allowed(reps, 'k', now).count === REPAIR_MAX, null);
	reps = prune_repairs(reps, now + REPAIR_WINDOW_SEC + 1);
	check('window_clears', repair_allowed(reps, 'k', now + REPAIR_WINDOW_SEC + 1).allowed === true, null);

	/* alarm_policy + diff. */
	check('policy_svc_fresh_silent', alarm_policy('svc:core', true) === false, null);
	check('policy_svc_stale_alarm', alarm_policy('svc:core', false) === true, null);
	check('policy_cfg_always', alarm_policy('core_cfg', true) === true &&
		alarm_policy('health_monitor', true) === true, null);
	const f_now = { 'svc:core': { status: 'down', label: 'Ядро', reason: 'r' } };
	const ev1 = diff_finding_events(null, f_now, false);
	check('diff_baseline_silent', length(ev1) === 0 && f_now['svc:core'].alarmed === false, null);
	const ev2 = diff_finding_events({}, { 'svc:core': { status: 'down', label: 'Ядро', reason: 'r' } }, false);
	check('diff_new_alarmed', length(ev2) === 1 && ev2[0].type === 'down', null);
	const f_prev2 = { 'svc:core': { status: 'down', label: 'Ядро', reason: 'r', alarmed: true } };
	const ev3 = diff_finding_events(f_prev2, {}, true);
	check('diff_recovered', length(ev3) === 1 && ev3[0].type === 'recovered', null);
	/* перехват тревоги: находка была тихой при свежем health → health протух → аларм. */
	const f_quiet = { 'svc:core': { status: 'down', label: 'Ядро', reason: 'r', alarmed: false } };
	const f_same = { 'svc:core': { status: 'down', label: 'Ядро', reason: 'r' } };
	const ev4 = diff_finding_events(f_quiet, f_same, false);
	check('diff_takeover', length(ev4) === 1 && ev4[0].type === 'down' && f_same['svc:core'].alarmed === true, null);
	const ev5 = diff_finding_events(f_quiet, f_same, true);
	check('diff_stay_quiet', length(ev5) === 0 && f_same['svc:core'].alarmed === false, null);

	/* ч.230: анти-флап — повторный аларм ключа глушится в окне ALARM_REPEAT_SEC,
	 * recovered в том же окне молчит, 'down' звонит всегда. */
	const ats_t = {};
	const fdeg = { 'hung:mdns': { status: 'degraded', label: 'D', reason: 'r' } };
	const ec1 = diff_finding_events({}, fdeg, true, 1000, ats_t);
	check('cool_first_rings', length(ec1) === 1 && int(ats_t['hung:mdns']) === 1000, null);
	const fdeg2 = { 'hung:mdns': { status: 'degraded', label: 'D', reason: 'r' } };
	const ec2 = diff_finding_events({}, fdeg2, true, 1000 + 60, ats_t);
	check('cool_reflip_silent', length(ec2) === 0 && fdeg2['hung:mdns'].alarmed === true, null);
	const ec3 = diff_finding_events({ 'hung:mdns': { status: 'degraded', label: 'D', reason: 'r', alarmed: true } },
		{}, true, 1000 + 120, ats_t);
	check('cool_recovered_silent', length(ec3) === 0, null);
	const fdeg3 = { 'hung:mdns': { status: 'degraded', label: 'D', reason: 'r' } };
	const ec4 = diff_finding_events({}, fdeg3, true, 1000 + ALARM_REPEAT_SEC + 1, ats_t);
	check('cool_expired_rings', length(ec4) === 1, null);
	const fdown = { 'hung:x': { status: 'down', label: 'X', reason: 'r' } };
	const ec5 = diff_finding_events({}, fdown, true, 2000, ats_t);
	check('cool_down_always', length(ec5) === 1 && ec5[0].type === 'down', null);

	/* overall. */
	check('overall_ok', overall_of({}) === 'ok', null);
	check('overall_degraded', overall_of({ a: { status: 'degraded' } }) === 'degraded', null);
	check('overall_down', overall_of({ a: { status: 'degraded' }, b: { status: 'down' } }) === 'down', null);

	/* Ф10.3: ресурсные вердикты (базы ч.218: core ~132 МБ/fd 482,
	 * automation ~40 МБ, mosdns ~26 МБ — все в бюджете). */
	/* ч.263: динамический бюджет ядра от железа (пакет A) + armed-гвард. */
	const cb1g = res_budget_core(1048576, 65536, 384);
	check('rbc_1gb', cb1g.fd_warn === 8192 && cb1g.fd_crit === 16384 &&
		cb1g.rss_warn_kb === 393216 && cb1g.rss_crit_kb === 530841 &&
		cb1g.gml_eff_mib === 384, '1 GB: fd from conntrack, crit = 1.35x GML');
	const cb_lite = res_budget_core(262144, 16384, 384);
	check('rbc_lite256', cb_lite.fd_warn === 2048 && cb_lite.fd_crit === 4096 &&
		cb_lite.rss_warn_kb === 104857 && cb_lite.rss_crit_kb === 176947 &&
		cb_lite.gml_eff_mib === 128, 'lite 256 MB: GML eff 128, crit 172.8 MB');
	check('rbc_unknown_fb', res_budget_core(0, 0, 0).fd_warn === 2048 &&
		res_budget_core(0, 0, 0).fd_crit === 4096, 'no /proc data = static fallback');
	check('res_ok_core', res_verdict('core', 135160, 482, cb1g).level === 'ok', null);
	check('res_ok_generic', res_verdict('multidns', 2008, 12).level === 'ok' &&
		res_verdict('multidns', 2008, 12).budget.rss_warn_kb === 65536, null);
	check('res_warn_rss_edge', res_verdict('automation', 98304, 13).level === 'warn' &&
		res_verdict('automation', 98304, 13).what === 'rss', null);
	check('res_crit_rss_core', res_verdict('core', 600000, 5, cb1g).level === 'crit' &&
		res_verdict('core', 600000, 5, cb1g).what === 'rss', null);
	check('res_warn_fd', res_verdict('multidns', 2008, 512).level === 'warn' &&
		res_verdict('multidns', 2008, 512).what === 'fd', null);
	check('res_crit_fd', res_verdict('multidns', 2008, 1024).level === 'crit' &&
		res_verdict('multidns', 2008, 1024).what === 'fd', null);
	check('res_fd_crit_wins', res_verdict('automation', 98304, 1024).level === 'crit' &&
		res_verdict('automation', 98304, 1024).what === 'fd', null);
	check('res_rss_crit_beats_fd_warn', res_verdict('core', 600000, 9000, cb1g).level === 'crit' &&
		res_verdict('core', 600000, 9000, cb1g).what === 'rss', null);
	check('res_nodata', res_verdict('core', 0, -1, cb1g).level === 'ok', null);
	const rf1 = res_findings([
		{ name: 'core', label: res_label('core'), pid: 1, rss_kb: 98304, fds: 5,
			level: 'warn', what: 'rss', rss_warn_kb: 393216, rss_crit_kb: 524288, fd_warn: 2048, fd_crit: 4096 },
		{ name: 'mosdns', label: res_label('mosdns'), pid: 2, rss_kb: 26492, fds: 26,
			level: 'ok', what: '' }
	]);
	check('res_findings_one', length(rf1) === 1 && rf1['res:core'] != null &&
		rf1['res:core'].status === 'degraded' && rf1['res:mosdns'] == null, null);
	check('res_findings_label', length(rf1) === 1 && rf1['res:core'].label === 'Ядро (hiddify-core)', null);
	check('res_findings_level', length(rf1) === 1 && rf1['res:core'].level === 'warn' &&
		rf1['res:core'].what === 'rss',
		'level rides the finding — Recovery gate (ч.263) needs it');
	check('res_findings_empty', length(res_findings(null)) === 0 && length(res_findings([])) === 0, null);

	/* ч.263: armed-гвард рестарта ядра (2 прохода подряд или ≥1.5×crit). */
	const afrow = { name: 'core', label: res_label('core'), pid: 1, rss_kb: 560000, fds: 5,
		level: 'crit', what: 'rss', rss_warn_kb: 393216, rss_crit_kb: 530841, fd_warn: 8192, fd_crit: 16384 };
	const arm1 = res_findings([ afrow ], {});
	check('armed_first_pass', arm1['res:core'] != null && arm1['res:core'].armed === false &&
		arm1['res:core'].crit_run === 1, 'instant peak below 1.5x is NOT armed');
	const arm2 = res_findings([ afrow ], arm1);
	check('armed_second_pass', arm2['res:core'] != null && arm2['res:core'].armed === true &&
		arm2['res:core'].crit_run === 2, 'two consecutive passes arm the restart');
	const ffrow = { name: 'core', label: res_label('core'), pid: 1, rss_kb: 800000, fds: 5,
		level: 'crit', what: 'rss', rss_warn_kb: 393216, rss_crit_kb: 530841, fd_warn: 8192, fd_crit: 16384 };
	const armf = res_findings([ ffrow ], {});
	check('armed_fast', armf['res:core'] != null && armf['res:core'].armed === true &&
		armf['res:core'].crit_run === 1, '1.5x crit arms instantly (runaway memory)');
	const arm_reset = res_findings([ afrow ], { 'res:core': { status: 'degraded', label: 'x', reason: 'x', what: 'fd', level: 'warn' } });
	check('armed_streak_reset', arm_reset['res:core'].crit_run === 1 && arm_reset['res:core'].armed === false,
		'non-crit previous finding resets the streak');
	const mixrow = { name: 'core', label: res_label('core'), pid: 1, rss_kb: 100000, fds: 9000,
		level: 'warn', what: 'fd', rss_warn_kb: 393216, rss_crit_kb: 530841, fd_warn: 8192, fd_crit: 16384,
		fd_mix: 'socket 400, pipe 480, прочее 20 (выборка 512 из 9000)' };
	const mixf = res_findings([ mixrow ], {});
	check('fd_mix_reason', mixf['res:core'] != null && index('' + mixf['res:core'].reason, 'состав:') > 0,
		'fd breakdown rides the warn finding (package A diagnostics)');

	/* ч.230: гистерезис res-находок — активная fd-находка держится в полосе
	 * до 90% warn (1900 ≥ 1844), чистится ниже (1800 < 1844); без prev — нет. */
	const mkrow = function(fds) {
		return { name: 'core', label: res_label('core'), pid: 1, rss_kb: 98304, fds: fds,
			level: 'ok', what: '', rss_warn_kb: 393216, rss_crit_kb: 524288,
			fd_warn: 2048, fd_crit: 4096 };
	};
	const prev_fd = { 'res:core': { status: 'degraded', label: 'Ядро (hiddify-core)', reason: 'x', what: 'fd' } };
	check('res_hyst_no_prev', length(res_findings([ mkrow(1900) ], null)) === 0, null);
	const row_in = res_findings([ mkrow(1900) ], prev_fd);
	check('res_hyst_hold', row_in['res:core'] != null && row_in['res:core'].what === 'fd' &&
		row_in['res:core'].status === 'degraded', null);
	const row_out = res_findings([ mkrow(1800) ], prev_fd);
	check('res_hyst_clear', row_out['res:core'] == null, null);
	check('res_hyst_class_match', length(res_findings([ mkrow(1900) ],
		{ 'res:core': { status: 'degraded', label: 'x', reason: 'x', what: 'rss' } })) === 0, null);

	check('res_snapshot_dead_pid', length(res_snapshot({ core: { pid: 999999, start: 1 } })) === 0, null);
	check('res_snapshot_empty', length(res_snapshot(null)) === 0, null);

	/* ч.264: тренд-наблюдение — seed + серия из 3 подъёмов ≥60% warn +
	 * удержание при дальнейшем росте + сброс при спаде + скип не-ok строк. */
	res_trend_reset();
	const trrow = function(fds, kb) {
		return { name: 't', label: 't', pid: 1, rss_kb: kb, fds: fds,
			level: 'ok', what: '', rss_warn_kb: 10000, rss_crit_kb: 20000,
			fd_warn: 100, fd_crit: 200 };
	};
	res_trend_apply([ trrow(61, 1000) ]);   /* seed — серии нет */
	const tr2 = trrow(65, 1000);
	res_trend_apply([ tr2 ]);
	const tr3 = trrow(70, 1000);
	res_trend_apply([ tr3 ]);
	check('trend_no_premature', tr3.trend == null, '' + tr3.trend);
	const tr4 = trrow(76, 1000);
	res_trend_apply([ tr4 ]);
	check('trend_marks_series', tr4.trend != null && index('' + tr4.trend, 'fd растёт') === 0,
		'' + tr4.trend);
	const tr5 = trrow(80, 1000);
	res_trend_apply([ tr5 ]);
	check('trend_still_marked', tr5.trend != null, null);
	const tr6 = trrow(50, 1000);
	res_trend_apply([ tr6 ]);
	check('trend_resets_on_dip', tr6.trend == null, '' + tr6.trend);
	res_trend_reset();
	const trw = trrow(80, 1000);
	trw.level = 'warn';
	res_trend_apply([ trw ]);
	const trn = trrow(85, 1000);
	res_trend_apply([ trn ]);
	check('trend_skips_non_ok', trn.trend == null, '' + trn.trend);

	/* Б5 (сеанс 161): рестарт ядра wanted ТОЛЬКО при core/rss-крите. */
	check('rcr_crit', res_core_restart_wanted([
		{ name: 'core', label: 'x', pid: 1, rss_kb: 600000, fds: 10,
			level: 'crit', what: 'rss', rss_warn_kb: 393216, rss_crit_kb: 530841, fd_warn: 8192, fd_crit: 16384 }
	]) != null, null);
	check('rcr_warn_no', res_core_restart_wanted([
		{ name: 'core', label: 'x', pid: 1, rss_kb: 400000, fds: 10,
			level: 'warn', what: 'rss', rss_warn_kb: 393216, rss_crit_kb: 530841, fd_warn: 8192, fd_crit: 16384 }
	]) == null, null);
	check('rcr_fd_no', res_core_restart_wanted([
		{ name: 'core', label: 'x', pid: 1, rss_kb: 100, fds: 17000,
			level: 'crit', what: 'fd', rss_warn_kb: 393216, rss_crit_kb: 530841, fd_warn: 8192, fd_crit: 16384 }
	]) == null, null);
	check('rcr_other_no', res_core_restart_wanted([
		{ name: 'automation', label: 'x', pid: 1, rss_kb: 170000, fds: 10,
			level: 'crit', what: 'rss', rss_warn_kb: 98304, rss_crit_kb: 163840, fd_warn: 512, fd_crit: 1024 }
	]) == null, null);
	check('rcr_empty', res_core_restart_wanted(null) == null, null);

	/* label. */
	check('label_known', inst_label('hiddify-c') === 'Ядро', null);
	check('label_fallback', inst_label('unknown-inst') === 'unknown-inst', null);

	let all_ok = true;
	for (let c in checks)
		if (!c.ok)
			all_ok = false;
	return { ok: all_ok, checks: checks };
};
