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
//   РЕСУРСНАЯ находка БЕЗ авто-ремонта: рестарт ядра по высокому RSS
//   недопустим, OOM-убийство = само-лечение утечки (решение ч.218).
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
//   svc_start  — /etc/init.d/homeproxy start (идемпотентный: поднимает ТОЛЬКО
//                мёртвые инстансы, живые не трогает — урок 135); rc-файл +
//                опрос с heartbeat (урок 167 — никаких 2-arg system()).
//   op_finish  — честное закрытие зависшего опа (opman.finish, лок
//                освобождается; действие НЕ повторяется — Sentinel не может
//                знать, началось ли оно).
// Каждая починка → событие шины (src='sentinel'). Конфиг-проблемы и зависшие
// демоны — события БЕЗ авто-ремонта (регенерация/LKG и киллы — зоны apply и
// Ф2.3 Recovery).
//
// Статус-документ /var/run/homeproxy/sentinel.json (конверт statestore)
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

import { access, readfile, popen, unlink, lsdir } from 'fs';
import {
	read_state as ss_read_state, write_state as ss_write_state, rjson as ss_rjson,
	read_revision as ss_read_revision
} from '/etc/homeproxy/scripts/statestore.uc';
import {
	REG_PATH as PM_REG_PATH, entry_alive as pm_entry_alive
} from '/etc/homeproxy/scripts/pmgr.uc';
import {
	list_ops as op_list, begin as op_begin, heartbeat as op_heartbeat,
	finish as op_finish, get_op as op_get
} from '/etc/homeproxy/scripts/opman.uc';
import { emit as ev_emit } from '/etc/homeproxy/scripts/eventbus.uc';

/* ── константы (урок 216: всё наверху, выше первой функции) ─────────────── */

export const SENTINEL_PATH = '/var/run/homeproxy/sentinel.json';
export const HEALTH_PATH = '/var/run/homeproxy/health.json';
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

/* ── Ф10.3: ресурсные бюджеты демонов ─────────────────────────────────────
 * База — реестр daemons.json (имена+pid живых демонов); замер fork-free
 * (readfile /proc/<pid>/status + lsdir /proc/<pid>/fd — readdir на этой
 * сборке ucode нет, lsdir возвращает массив имён-строк). Бюджеты ЩЕДРЫЕ
 * относительно базы ч.218 (core ~132 МБ/fd 482, automation ~40 МБ, mosdns
 * ~26 МБ, probe_pool ~13 МБ, прочие ≤2 МБ) — находка означает рост тренда,
 * а не «сейчас упадёт». Крит-порог RSS ядра — зона перед OOM-гранью WR3000H
 * (727 МБ, ч.218). Имена ключей = имена реестра (core/ciadpi/nfqws2/...). */
export const RES_PATH = '/var/run/homeproxy/resources.json';

const RES_BUDGETS = {
	core:        { rss_warn_kb: 393216, rss_crit_kb: 524288, fd_warn: 2048, fd_crit: 4096 },
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

const CORE_CFG = '/var/run/homeproxy/hiddify-c.json';
const CORE_LKG = '/var/run/homeproxy/hiddify-c.json.lastgood';
const MDNS_CONF = '/var/run/homeproxy/multidns/mosdns.yaml';
const SYS_CONF = '/etc/config/homeproxy';
const SVC_EPOCH_PATH = '/var/run/homeproxy/.service_epoch';

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
		key: 'uci', label: 'UCI-конфиг homeproxy', severity: 'down',
		ok: access(SYS_CONF),
		reason: '/etc/config/homeproxy не читается — настройкам приложения не к чему применяться'
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
export function alarm_policy(key, health_fresh) {
	if ((index('' + key, 'svc:') === 0 || index('' + key, 'op:') === 0) && health_fresh)
		return false;
	return true;
};

export function diff_finding_events(prev_f, findings, health_fresh) {
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
		if (prev_f[k] == null) {
			f.alarmed = want;
			if (want)
				push(out, { type: (f.status === 'down') ? 'down' : 'degraded',
					who: f.label, detail: f.reason });
		} else if (want && prev_f[k].alarmed !== true) {
			f.alarmed = true;
			push(out, { type: (f.status === 'down') ? 'down' : 'degraded',
				who: f.label, detail: f.reason });
		} else {
			f.alarmed = (prev_f[k].alarmed === true);
		}
	}
	for (let k in prev_f) {
		if (findings[k] != null)
			continue;
		if (prev_f[k].alarmed === true)
			push(out, { type: 'recovered', who: prev_f[k].label,
				detail: 'больше не наблюдается' });
	}
	return out;
};

/* ── procd-инстансы (собственная сверка; урок 171: service list) ────────── */

export function service_instances() {
	const doc = parse_json(capture('ubus call service list 2>/dev/null'));
	const inst = (doc != null && type(doc.homeproxy) === 'object' &&
		type(doc.homeproxy.instances) === 'object') ? doc.homeproxy.instances : {};
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
	system('( /etc/init.d/homeproxy start >/dev/null 2>&1; echo $? > ' + rcfile + ' ) &');
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
	system('( /etc/init.d/homeproxy rpcd_heal >/dev/null 2>&1; echo $? > ' + rcfile + ' ) &');
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

/* ── Ф10.3: ресурсы демонов (снапшот + бюджеты) ──────────────────────────── */

/* Вердикт одного демона против бюджета (чистая функция — selftest).
 * level 'ok'/'warn'/'crit', what 'rss'/'fd'/''; crit сильнее warn; rss-крит
 * сильнее fd-warn. rss_kb ≤ 0 = замер не удался — не вердикт. */
export function res_verdict(name, rss_kb, fds) {
	const b = (RES_BUDGETS['' + name] != null) ? RES_BUDGETS['' + name] : RES_BUDGET_GENERIC;
	let level = 'ok', what = '';
	if (rss_kb != null && int(rss_kb) > 0) {
		if (int(b.rss_crit_kb) > 0 && int(rss_kb) >= int(b.rss_crit_kb)) {
			level = 'crit'; what = 'rss';
		} else if (int(rss_kb) >= int(b.rss_warn_kb)) {
			level = 'warn'; what = 'rss';
		}
	}
	if (fds != null && int(fds) >= 0) {
		if (int(b.fd_crit) > 0 && int(fds) >= int(b.fd_crit)) {
			level = 'crit'; what = 'fd';
		} else if (level === 'ok' && int(fds) >= int(b.fd_warn)) {
			level = 'warn'; what = 'fd';
		}
	}
	return { budget: b, level: level, what: what };
};

/* Снапшот ресурсов живых демонов реестра (fork-free: readfile + lsdir).
 * Мёртвые pid пропускаются — их живость зона svc-проверок. Строка:
 * { name, label, pid, rss_kb, fds, level, what, rss_warn_kb, rss_crit_kb,
 *   fd_warn, fd_crit } — бюджеты едут в строке, чтобы RPC/UI не знали таблицу. */
export function res_snapshot(regst) {
	const out = [];
	if (regst == null || type(regst) !== 'object')
		return out;
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
		if (access(fdpath)) {
			const d = lsdir(fdpath);
			fds = (d != null) ? length(d) : -1;
		}
		const rss = (m != null) ? int(m[1]) : 0;
		if (rss <= 0 && fds < 0)
			continue;   /* /proc недоступен — нет замера, нет строки */
		const v = res_verdict(name, rss, fds);
		push(out, {
			name: '' + name, label: res_label(name), pid: pid,
			rss_kb: rss, fds: fds, level: v.level, what: v.what,
			rss_warn_kb: int(v.budget.rss_warn_kb), rss_crit_kb: int(v.budget.rss_crit_kb),
			fd_warn: int(v.budget.fd_warn), fd_crit: int(v.budget.fd_crit)
		});
	}
	return out;
};

/* Находки перерасхода из снапшота. status ВСЕГДА 'degraded': перерасход не
 * означает «процесс мёртв» (down резервируется смертям), авто-ремонта нет. */
export function res_findings(snap) {
	const out = {};
	if (snap == null || type(snap) !== 'array')
		return out;
	for (let r in snap) {
		if (r == null || r.level == null || r.level === 'ok')
			continue;
		let reason;
		if (r.what === 'fd')
			reason = 'открытых fd: ' + sprintf('%d', int(r.fds)) +
				((r.level === 'crit')
					? ' при бюджете ' + sprintf('%d', int(r.fd_crit)) + ' — критическая зона, вероятна утечка дескрипторов'
					: ' при бюджете ' + sprintf('%d', int(r.fd_warn)) + ' — возможна утечка дескрипторов, наблюдение участится');
		else
			reason = 'RSS ' + sprintf('%.1f', int(r.rss_kb) / 1024) + ' МБ' +
				((r.level === 'crit')
					? ' при бюджете ' + sprintf('%.0f', int(r.rss_crit_kb) / 1024) + ' МБ — зона OOM-грани (кейс WR3000H: ядро убивалось при ~727 МБ)'
					: ' при бюджете ' + sprintf('%.0f', int(r.rss_warn_kb) / 1024) + ' МБ — потребление выше штатного, наблюдение участится');
		out['res:' + r.name] = {
			status: 'degraded', label: res_label(r.name), reason: reason,
			confidence: 'certain'
		};
	}
	return out;
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
	const health_fresh = (hage >= 0 && hage <= HEALTH_STALE_SEC);
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
	 * Находка res:* НЕ порождает ремонтов (OOM = само-лечение, ч.218). */
	const prev_res_active = (function() {
		for (let k in prev_f)
			if (index('' + k, 'res:') === 0)
				return true;
		return false;
	})();
	if (full || prev_res_active) {
		const snap = res_snapshot(registry_map());
		const rf = res_findings(snap);
		for (let k in rf)
			findings[k] = rf[k];
		const memraw = readfile('/proc/meminfo') || '';
		const mtot = match(memraw, /MemTotal:\s+([0-9]+)/);
		let res_overall = 'ok';
		for (let r in snap)
			if (r.level !== 'ok')
				res_overall = 'degraded';
		ss_write_state(RES_PATH, {
			ts: time(), deep: full, overall_res: res_overall,
			mem_available_kb: parse_meminfo_kb(memraw),
			mem_total_kb: (mtot != null) ? int(mtot[1]) : -1,
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
	 * добавляются следом, порядок в ленте честный). */
	const events = diff_finding_events(baseline ? null : prev_f, findings, health_fresh);

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

	/* overall. */
	check('overall_ok', overall_of({}) === 'ok', null);
	check('overall_degraded', overall_of({ a: { status: 'degraded' } }) === 'degraded', null);
	check('overall_down', overall_of({ a: { status: 'degraded' }, b: { status: 'down' } }) === 'down', null);

	/* Ф10.3: ресурсные вердикты (базы ч.218: core ~132 МБ/fd 482,
	 * automation ~40 МБ, mosdns ~26 МБ — все в бюджете). */
	check('res_ok_core', res_verdict('core', 135160, 482).level === 'ok', null);
	check('res_ok_generic', res_verdict('multidns', 2008, 12).level === 'ok' &&
		res_verdict('multidns', 2008, 12).budget.rss_warn_kb === 65536, null);
	check('res_warn_rss_edge', res_verdict('automation', 98304, 13).level === 'warn' &&
		res_verdict('automation', 98304, 13).what === 'rss', null);
	check('res_crit_rss_core', res_verdict('core', 524288, 5).level === 'crit' &&
		res_verdict('core', 524288, 5).what === 'rss', null);
	check('res_warn_fd', res_verdict('multidns', 2008, 512).level === 'warn' &&
		res_verdict('multidns', 2008, 512).what === 'fd', null);
	check('res_crit_fd', res_verdict('multidns', 2008, 1024).level === 'crit' &&
		res_verdict('multidns', 2008, 1024).what === 'fd', null);
	check('res_fd_crit_wins', res_verdict('automation', 98304, 1024).level === 'crit' &&
		res_verdict('automation', 98304, 1024).what === 'fd', null);
	check('res_rss_crit_beats_fd_warn', res_verdict('core', 600000, 600).level === 'crit' &&
		res_verdict('core', 600000, 600).what === 'rss', null);
	check('res_nodata', res_verdict('core', 0, -1).level === 'ok', null);
	const rf1 = res_findings([
		{ name: 'core', label: res_label('core'), pid: 1, rss_kb: 98304, fds: 5,
			level: 'warn', what: 'rss', rss_warn_kb: 393216, rss_crit_kb: 524288, fd_warn: 2048, fd_crit: 4096 },
		{ name: 'mosdns', label: res_label('mosdns'), pid: 2, rss_kb: 26492, fds: 26,
			level: 'ok', what: '' }
	]);
	check('res_findings_one', length(rf1) === 1 && rf1['res:core'] != null &&
		rf1['res:core'].status === 'degraded' && rf1['res:mosdns'] == null, null);
	check('res_findings_label', length(rf1) === 1 && rf1['res:core'].label === 'Ядро (hiddify-core)', null);
	check('res_findings_empty', length(res_findings(null)) === 0 && length(res_findings([])) === 0, null);
	check('res_snapshot_dead_pid', length(res_snapshot({ core: { pid: 999999, start: 1 } })) === 0, null);
	check('res_snapshot_empty', length(res_snapshot(null)) === 0, null);

	/* label. */
	check('label_known', inst_label('hiddify-c') === 'Ядро', null);
	check('label_fallback', inst_label('unknown-inst') === 'unknown-inst', null);

	let all_ok = true;
	for (let c in checks)
		if (!c.ok)
			all_ok = false;
	return { ok: all_ok, checks: checks };
};
