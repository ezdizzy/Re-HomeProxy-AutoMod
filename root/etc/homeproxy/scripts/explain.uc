// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Explainable (plan 20 §3 Ф2.5; A.4 аудита «каждое решение объяснимо»).
//
// Композитор ЧЕСТНЫХ объяснений из документов подсистем Ф2: health.json
// (статус/уверенность/причина), sentinel.json (findings с причинами),
// recovery.json (кампании: попытки/backoff/блокировки/история ремонтов).
// Модуль ЧИСТЫЙ: документы ВХОДЯТ параметрами, ничего не читает и не пишет,
// fork'ов нет — вызывается RPC-методом health_explain (rpcd) на каждый тик
// страницы «Центр здоровья» (Ф2.6).
//
// Что объясняет каждая запись (вопросы пользователя — план Ф2.5):
//   почему статус такой          → reason из Health (+ находка Sentinel'а);
//   что система уже сделала      → история ремонтов кампании (Recovery);
//   что будет дальше             → следующая проверка монитора ИЛИ следующая
//                                  попытка координатора (backoff/стабилизация/
//                                  блокировка/очередь ручных заявок);
//   что можно сделать руками     → кнопка «Ремонт» (repairable-классы) /
//                                  «Разблокировать» (blocked) / «Перезапуск
//                                  службы» (apply-дверь) / U4-предложение
//                                  (proposal-классы, тексты PROPOSAL_HINTS).
//
// Честность: объяснение НИКОГДА не придумывает фактов. Нет кампании — нет
// строки «система сделала»; нет повода — нет строки «что дальше кроме
// мониторинга»; proposal-классы честно говорят «авто-ремонта нет».
//
// Маппинг Health-запись → ключ Recovery: procd-службы → 'svc:<инстанс>'
// (+ 'svc_drift:'), proposal-классы → голое имя (core/mosdns/tgws/tun/fw4/
// generators/system). Ключи реестра pmgr ≠ имена записей Health — этот
// маппинг ДРУГОЙ (здесь имена записей Health, у Recovery — procd-инстансы;
// урок 223 не переносится сюда напрямую, но маппинги сверены с
// HEALTH_SVC_NAMES в recovery.uc).
//
// Находки Sentinel'а, не ложащиеся на запись Health (op:/hung:/loop:/
// config:/health_monitor) и находки при ок-статусе записи, — уходят в
// extra-список «Внимание системы» страницы. Запись с находкой при ок —
// помечается alert (кэш лёгкого прохода vs свежий full-проход сторожа).
//
// Уроки учтены: 166 (`};` у функций модуля; проверка импортирующим чекером),
// 216 (top-level const НАВЕРХУ), 2/93/126 (хелперы выше вызывающих),
// 20/180 (for-in по массиву = элементы), 26 (index() вместо match()-строки),
// 130/стайл (строки бэкенда — русские в исходнике, не через _()).

'use strict';

import {
	classify_key as rc_classify_key, PROPOSAL_HINTS as RC_PROPOSAL_HINTS
} from '/etc/homeproxy/scripts/recovery.uc';

/* ── константы (урок 216: всё наверху, выше первой функции) ─────────────── */

/* Порядок групп на странице (значение group в записях Health). */
export const GROUP_ORDER = [
	'core', 'dpi', 'dns', 'automation', 'telegram', 'failover', 'access',
	'net', 'config', 'system'
];

/* Health-запись → procd-инстанс (зеркало HEALTH_SVC_NAMES recovery.uc —
 * источник тот же класс ключей 'svc:'); сверено с recovery.uc ч.166. */
const SVC_INST = {
	automation: 'automation', multidns: 'multidns', telegram: 'telegram',
	urltest: 'urltest', hotswap: 'hotswap', autopilot: 'autopilot',
	control: 'control', sentinel: 'sentinel', health: 'health',
	recovery: 'recovery', metrics: 'metrics', log_cleaner: 'log-cleaner',
	byedpi: 'byedpi', zapret: 'zapret', tun_route: 'tun-route'
};

/* Health-запись → proposal-ключ Recovery (голое имя записи). */
const PLAIN_KEYS = {
	core: 'core', mosdns: 'mosdns', tgws: 'tgws', tun: 'tun', fw4: 'fw4',
	generators: 'generators', system: 'system'
};

/* Метки действий в истории ремонтов (человекочитаемые, бэкенд-русские). */
const ACT_LABELS = {
	svc_start: 'старт службы', op_finish: 'закрытие зависшей операции',
	hung_kill: 'перезапуск зависшего демона', apply_ok: 'применение конфигурации',
	request: 'ручная заявка', unblock: 'разблокировка'
};

/* ── мелкие хелперы (выше вызывающих — no hoisting) ─────────────────────── */

/* Возможные ключи Recovery для записи Health (порядок приоритета). */
function campaign_keys(name) {
	const keys = [];
	const inst = SVC_INST['' + name];
	if (inst != null) {
		push(keys, 'svc:' + inst);
		push(keys, 'svc_drift:' + inst);
	}
	if (PLAIN_KEYS['' + name] != null)
		push(keys, '' + name);
	return keys;
};

/* Ключ Recovery → имя записи Health (для находок Sentinel'а). null = ключ
 * не ложится ни на одну запись (op:/loop:/config:/health_monitor). */
function entry_of_key(key) {
	const k = '' + (key || '');
	if (index(k, 'svc:') === 0 || index(k, 'svc_drift:') === 0) {
		const inst = substr(k, index(k, ':') + 1);
		for (let nm in SVC_INST)
			if (SVC_INST[nm] === inst)
				return nm;
		return null;
	}
	if (index(k, 'hung:') === 0) {
		const nm = substr(k, index(k, ':') + 1);
		for (let e in SVC_INST)
			if (e === nm)
				return nm;
		return null;
	}
	if (PLAIN_KEYS[k] != null)
		return k;
	return null;
};

function fmt_dur(sec) {
	const n = int(sec);
	if (n >= 3600)
		return int(n / 3600) + ' ч';
	if (n >= 60)
		return int(n / 60) + ' мин';
	return n + ' с';
};

/* Свежие попытки кампании за окно (те же 30 мин, что у координатора). */
function fresh_attempts(times, now) {
	let n = 0;
	if (times != null && type(times) === 'array')
		for (let t in times)
			if (int(t) > 0 && (now - int(t)) <= 1800)
				n++;
	return n;
};

/* Строки «что дальше» по кампании/статусу (чистая функция). */
export function next_lines(entry, camp, manual_here, now) {
	const out = [];
	const st = '' + ((entry != null) ? entry.status : 'off');
	if (manual_here != null)
		push(out, 'ручная заявка в очереди — координатор исполнит её в ближайшем тике (до ~15 с)');
	if (camp != null && camp.action == null) {
		push(out, 'авто-ремонта для этого класса нет — следуйте предложению системы ниже');
	} else if (camp != null) {
		if (camp.blocked_ts > 0)
			push(out, 'авто-ремонт приостановлен (перебор) — координатор пробует раз в 2 ч, либо сбросьте блокировку вручную');
		else if (camp.attempts > 0)
			push(out, 'повторная авто-попытка не раньше, чем через ' +
				fmt_dur(camp.next_in) + ' (экспоненциальная пауза, потолок 30 мин)');
		else
			push(out, 'первая авто-попытка координатора — после окна стабилизации ~45 с (если проблема не уйдёт сама)');
	} else if (st === 'ok' || st === 'off') {
		push(out, 'монитор продолжит проверки: лёгкий проход каждые ~20 с, глубокий раз в ~2 мин');
	} else {
		push(out, 'монитор проверяет в быстром режиме (каждые 5–10 с); координатор ремонт не назначает — класс самовосстанавливающийся или требует ручного вмешательства');
	}
	return out;
};

/* ── объяснение одной записи Health ─────────────────────────────────────── */

export function entry_explain(name, entry, recovery_data, findings, now) {
	const e = (entry != null && type(entry) === 'object') ? entry : {};
	const st = '' + (e.status || 'off');
	const conf = '' + (e.confidence || 'indirect');

	/* Кампании: все возможные ключи записи; live-кампания — та, что жива
	 * (last_seen в окне флап-памяти). */
	let camp = null;
	let camp_key = null;
	const keys = campaign_keys(name);
	const rkeys = (recovery_data != null && recovery_data.keys != null &&
		type(recovery_data.keys) === 'object') ? recovery_data.keys : {};
	for (let k in keys) {
		/* 🔴 k здесь — ЭЛЕМЕНТ массива (урок 20/180), не индекс. */
		const ke = rkeys['' + k];
		if (ke == null || type(ke) !== 'object')
			continue;
		if ((now - int(ke.last_seen || 0)) > 1800)
			continue;   /* флап-память протухла — кампании фактически нет */
		if (camp == null) {
			camp = ke;
			camp_key = '' + k;
		}
	}
	const blocked_map = (recovery_data != null && recovery_data.blocked != null &&
		type(recovery_data.blocked) === 'object') ? recovery_data.blocked : {};
	const blocked_ts = (camp_key != null && blocked_map[camp_key] != null)
		? int(blocked_map[camp_key]) : 0;

	/* Ручная заявка в очереди на эту запись. */
	let manual_here = null;
	const mq = (recovery_data != null && recovery_data.manual_queue != null &&
		type(recovery_data.manual_queue) === 'array') ? recovery_data.manual_queue : [];
	for (let q in mq) {
		if (q == null)
			continue;
		for (let k in keys)
			if ('' + q.key === '' + k)
				manual_here = q;
	}

	/* Находка Sentinel'а для этой записи (сторож может знать раньше/точнее). */
	let finding = null;
	let finding_key = null;
	if (findings != null && type(findings) === 'object') {
		for (let k in findings) {
			if (index('' + k, 'loop:') === 0)
				continue;   /* цикл — отдельная находка, не повод записи */
			if (entry_of_key('' + k) === ('' + name)) {
				finding = findings[k];
				finding_key = '' + k;
			}
		}
	}

	/* Что система уже сделала: история ремонтов по ключам записи. */
	const done = [];
	const hist = (recovery_data != null && recovery_data.history != null &&
		type(recovery_data.history) === 'array') ? recovery_data.history : [];
	for (let h in hist) {
		if (h == null)
			continue;
		for (let k in keys)
			if ('' + h.key === '' + k)
				push(done, { ts: int(h.ts || 0), text:
					((h.manual === true) ? 'ручное действие' : 'авто-действие') + ' «' +
					(ACT_LABELS['' + (h.action || '')] || ('' + (h.action || ''))) + '» — ' +
					((h.ok === true) ? 'удалось' : 'не удалось') });
	}
	/* Свежей истории нет, но кампания жива — честная строка о попытках. */
	if (length(done) === 0 && camp != null && camp.action != null) {
		const att = fresh_attempts(camp.times, now);
		if (att > 0)
			push(done, { ts: int(camp.last_seen || 0),
				text: 'координатор уже пытался автоматически (' + att + ' попытки за 30 мин) — результат не устоялся' });
	}

	/* Заморозка авто-ремонтов после ручного действия/применения. */
	const freeze_until = (recovery_data != null) ? int(recovery_data.manual_freeze_until || 0) : 0;
	if (freeze_until > now) {
		push(done, { ts: freeze_until,
			text: 'авто-ремонты заморожены после ручного действия (ещё ' + fmt_dur(freeze_until - now) + ')' });
	}

	/* Идущее применение конфигурации — координатор ждёт вердикт. */
	const watch = (recovery_data != null) ? recovery_data.watch_op : null;

	/* Что можно сделать руками. */
	const manual = [];
	let repairable = false;
	let unblockable = (blocked_ts > 0);
	const ck = (camp_key != null) ? rc_classify_key(camp_key) : null;
	const can_repair = (camp_key != null && ck != null && ck.action != null);
	if (can_repair) {
		repairable = true;
		push(manual, 'кнопка «Ремонт» — ручная заявка координатору (исполнится немедленно, вне лимитов и стабилизации)');
	}
	if (unblockable)
		push(manual, 'кнопка «Разблокировать» сбросит кампанию и блокировку авто-ремонта');
	const hint = RC_PROPOSAL_HINTS[(ck != null) ? ck.class : ''] || null;
	if (hint != null)
		push(manual, 'предложение системы: ' + hint);
	push(manual, '«Перезапуск службы» внизу страницы — полная пересборка через применяющую дверь (верифицированный apply сбрасывает все авто-кампании)');

	return {
		name: '' + name,
		label: '' + (e.label || name),
		group: '' + (e.group || 'system'),
		status: st,
		confidence: conf,
		confidence_note: (conf === 'certain')
			? 'подтверждено прямой проверкой сейчас'
			: 'по выводу (окно респавна, несвежее свидетельство или перенос с последней глубокой проверки)',
		reason: '' + (e.reason || ''),
		alert: (finding != null && st === 'ok')
			? ('сторож видит проблему, монитор пока нет: ' + ('' + (finding.reason || '')))
			: null,
		done: done,
		next: next_lines(e, (camp != null) ? {
			action: camp.action, class: camp.class,
			attempts: fresh_attempts(camp.times, now),
			next_in: max(0, int(camp.next_ok || 0) - now),
			blocked_ts: blocked_ts
		} : null, manual_here, now),
		manual: manual,
		hint: hint,
		campaign: (camp != null) ? {
			key: camp_key,
			label: '' + (camp.label || camp_key),
			action: camp.action, class: camp.class,
			alive: (camp.alive === true), carried: (camp.carried === true),
			attempts: fresh_attempts(camp.times, now),
			next_ok: int(camp.next_ok || 0),
			blocked_ts: blocked_ts
		} : null,
		repairable: repairable,
		unblockable: unblockable,
		checked: int(e.checked || 0)
	};
};

/* ── объяснение внеленточной находки Sentinel'а («Внимание системы») ────── */

export function extra_explain(key, finding, recovery_data, now) {
	const f = (finding != null && type(finding) === 'object') ? finding : {};
	const k = '' + key;
	const c = rc_classify_key(k);
	/* Кампании для ключей, ложащихся на записи, здесь НЕ дублируются —
	 * extra только для ключей без записи Health. */
	const blocked_map = (recovery_data != null && recovery_data.blocked != null &&
		type(recovery_data.blocked) === 'object') ? recovery_data.blocked : {};
	const blocked_ts = (blocked_map[k] != null) ? int(blocked_map[k]) : 0;
	let camp = null;
	const rkeys = (recovery_data != null && recovery_data.keys != null &&
		type(recovery_data.keys) === 'object') ? recovery_data.keys : {};
	if (rkeys[k] != null && type(rkeys[k]) === 'object' &&
	    (now - int(rkeys[k].last_seen || 0)) <= 1800)
		camp = rkeys[k];

	const manual = [];
	let repairable = false;
	const can_repair = (c != null && c.action != null);
	if (can_repair) {
		repairable = true;
		push(manual, 'кнопка «Ремонт» — ручная заявка координатору (немедленно, вне лимитов)');
	}
	if (blocked_ts > 0)
		push(manual, 'кнопка «Разблокировать» сбросит блокировку авто-ремонта');
	const hint = RC_PROPOSAL_HINTS[(c != null) ? c.class : ''] || null;
	if (hint != null)
		push(manual, 'предложение системы: ' + hint);

	return {
		key: k,
		label: '' + (f.label || k),
		status: '' + (f.status || 'degraded'),
		reason: '' + (f.reason || ''),
		carried: (f.carried === true),
		done: [],
		next: next_lines({ status: '' + (f.status || 'degraded') },
			(camp != null) ? {
				action: camp.action, class: camp.class,
				attempts: fresh_attempts(camp.times, now),
				next_in: max(0, int(camp.next_ok || 0) - now),
				blocked_ts: blocked_ts
			} : null, null, now),
		manual: manual,
		hint: hint,
		repairable: repairable,
		unblockable: (blocked_ts > 0),
		found_ts: int(f.found_ts || 0)
	};
};

/* ── история ремонтов в человекочитаемом виде ───────────────────────────── */

export function history_view(recovery_data, health_data) {
	const hist = (recovery_data != null && recovery_data.history != null &&
		type(recovery_data.history) === 'array') ? recovery_data.history : [];
	const labels = {};
	if (health_data != null && health_data.entries != null)
		for (let nm in health_data.entries)
			labels['' + nm] = '' + ((health_data.entries[nm] != null)
				? health_data.entries[nm].label : nm);
	/* svc-ключи → лейбл записи. */
	const key_label = (key) => {
		const nm = entry_of_key(key);
		return (nm != null && labels[nm] != null) ? labels[nm] : ('' + key);
	};
	const out = [];
	for (let h in hist) {
		if (h == null)
			continue;
		const act = '' + (h.action || '');
		let who;
		if (act === 'apply_ok')
			who = 'применение конфигурации';
		else
			who = key_label(h.key);
		push(out, {
			ts: int(h.ts || 0),
			text: ((h.manual === true) ? 'вручную' : 'авто') + ' — ' +
				(ACT_LABELS[act] || act) +
				((act === 'apply_ok') ? '' : (' · ' + who)) +
				' — ' + ((h.ok === true) ? 'удалось' : 'не удалось')
		});
	}
	return out;
};

/* ── композит: три документа → объяснения ─────────────────────────────────
 * Возвращает { entries, extra, history, summary }. */
export function compose(health_data, sentinel_data, recovery_data, now) {
	const entries = {};
	const extra = [];
	const counts = { ok: 0, degraded: 0, down: 0, off: 0 };
	const he = (health_data != null && health_data.entries != null &&
		type(health_data.entries) === 'object') ? health_data.entries : {};

	for (let nm in he) {
		const ex = entry_explain(nm, he[nm], recovery_data, sentinel_data != null ? sentinel_data.findings : null, now);
		entries['' + nm] = ex;
		const st = ex.status;
		if (counts[st] != null)
			counts[st]++;
	}

	/* Находки Sentinel'а: ложащиеся на НЕ-ок записи уже учтены кампаниями;
	 * остальное — в extra (op:/hung:/loop:/config:/health_monitor и находки
	 * при ок-статусе записи — последних там не должно быть: extra берёт
	 * только ключи БЕЗ записи Health, находка при ок идёт полем alert). */
	const findings = (sentinel_data != null && sentinel_data.findings != null &&
		type(sentinel_data.findings) === 'object') ? sentinel_data.findings : {};
	for (let k in findings) {
		if (index('' + k, 'loop:') === 0) {
			push(extra, extra_explain(k, findings[k], recovery_data, now));
			continue;
		}
		const nm = entry_of_key('' + k);
		if (nm != null && he[nm] != null && type(he[nm]) === 'object')
			continue;   /* лег на запись Health — объяснение уже внутри неё */
		push(extra, extra_explain(k, findings[k], recovery_data, now));
	}

	const active_keys = (recovery_data != null) ? int(recovery_data.active_keys || 0) : 0;
	const blocked_keys = (recovery_data != null) ? int(recovery_data.blocked_keys || 0) : 0;
	const manual_queue = (recovery_data != null && recovery_data.manual_queue != null)
		? recovery_data.manual_queue : [];
	const watch = (recovery_data != null) ? recovery_data.watch_op : null;
	const freeze_until = (recovery_data != null) ? int(recovery_data.manual_freeze_until || 0) : 0;

	const summary = {
		counts: counts,
		overall: '' + ((health_data != null) ? health_data.overall : 'off'),
		health_ts: (health_data != null) ? int(health_data.ts || 0) : 0,
		sentinel: {
			overall: '' + ((sentinel_data != null) ? sentinel_data.overall : 'ok'),
			coordinator: '' + ((sentinel_data != null) ? (sentinel_data.coordinator || 'self') : 'unknown'),
			findings: length(extra)
		},
		recovery: {
			overall: '' + ((recovery_data != null) ? recovery_data.overall : 'ok'),
			active_keys: active_keys,
			blocked_keys: blocked_keys,
			manual_queue: length(manual_queue),
			watch_op: (watch != null) ? { op_id: '' + (watch.op_id || ''),
				action: '' + (watch.action || '') } : null,
			freeze_left: (freeze_until > now) ? (freeze_until - now) : 0
		}
	};

	return {
		entries: entries,
		extra: extra,
		history: history_view(recovery_data, health_data),
		summary: summary
	};
};

/* ── selftest (чистая логика на подставных документах) ──────────────────── */
export function selftest() {
	const checks = [];
	const check = function(name, ok, detail) {
		push(checks, { check: name, ok: ok, detail: detail || null });
		return ok;
	};
	const now = time();
	const fe = (name, label, group, status, conf, reason) => ({
		name: name, label: label, group: group, status: status,
		confidence: conf, reason: reason, expected: (status !== 'off'),
		checked: now, detail: {}
	});
	const camp = function(key, opts) {
		const base = {
			first_seen: now - 200, last_seen: now, times: [], next_ok: 0,
			proposed: false, alive: true, carried: false,
			label: key, reason: 'r', action: 'svc_start',
			target: substr(key, 4), class: 'svc'
		};
		if (opts != null)
			for (let k in opts)
				base[k] = opts[k];
		return base;
	};

	/* 1. ok-запись без кампании: строка мониторинга, без «сделал». */
	const health = { overall: 'ok', ts: now, entries: {
		metrics: fe('metrics', 'Сборщик метрик', 'system', 'ok', 'certain', 'всё хорошо')
	} };
	let c = compose(health, { overall: 'ok', coordinator: 'live', findings: {} },
		{ overall: 'ok', active_keys: 0, blocked_keys: 0, manual_queue: [],
		  keys: {}, blocked: {}, history: [], manual_freeze_until: 0, watch_op: null }, now);
	let ex = c.entries.metrics;
	check('ok_next_monitoring', length(ex.next) === 1 &&
		index(ex.next[0], 'монитор продолжит') >= 0, sprintf('%J', ex.next));
	check('ok_done_empty', length(ex.done) === 0, null);
	check('ok_not_repairable', ex.repairable === false, null);
	check('counts_ok', c.summary.counts.ok === 1 && c.summary.counts.down === 0, null);

	/* 2. down-запись с кампанией: стабилизация/повтор/блокировка. */
	health.entries.metrics = fe('metrics', 'Сборщик метрик', 'system', 'down', 'certain', 'procd: не работает');
	const rd = { overall: 'active', active_keys: 1, blocked_keys: 0,
		manual_queue: [], manual_freeze_until: 0, watch_op: null,
		keys: { 'svc:metrics': camp('svc:metrics', {}) }, blocked: {},
		history: [] };
	c = compose(health, { overall: 'down', coordinator: 'live', findings: {
		'svc:metrics': { status: 'down', label: 'Сборщик метрик', reason: 'procd: не работает' } } }, rd, now);
	ex = c.entries.metrics;
	check('down_first_attempt_line', length(ex.next) === 1 &&
		index(ex.next[0], 'окна стабилизации') >= 0, sprintf('%J', ex.next));
	check('down_repairable', ex.repairable === true, null);
	check('down_finding_not_extra', length(c.extra) === 0, 'svc:metrics merged into the entry');
	check('down_alert_none', ex.alert == null, 'alert only when entry status is ok');

	/* 3. Повторная попытка: backoff-строка. */
	rd.keys['svc:metrics'].times = [ now - 400 ];
	rd.keys['svc:metrics'].next_ok = now + 900;
	c = compose(health, { overall: 'down', coordinator: 'live', findings: {} }, rd, now);
	ex = c.entries.metrics;
	check('down_backoff_line', index(ex.next[0], 'повторная авто-попытка') >= 0 &&
		index(ex.next[0], '15 мин') >= 0, sprintf('%J', ex.next));
	check('down_attempts_1', ex.campaign.attempts === 1, null);

	/* 4. Блокировка: unblock-кнопка + строка приостановки. */
	rd.blocked = { 'svc:metrics': now - 100 };
	c = compose(health, { overall: 'down', coordinator: 'live', findings: {} }, rd, now);
	ex = c.entries.metrics;
	check('blocked_line', index(ex.next[0], 'приостановлен') >= 0, null);
	check('blocked_unblockable', ex.unblockable === true &&
		index(ex.manual[1], 'Разблокировать') >= 0, sprintf('%J', ex.manual));
	check('blocked_btn_hint', index(ex.manual[0], 'Ремонт') >= 0, 'repair button stays for svc class');
	delete rd.blocked['svc:metrics'];

	/* 5. История ремонтов → строки «что уже сделано». */
	rd.history = [ { ts: now - 60, key: 'svc:metrics', action: 'svc_start', ok: true, manual: false } ];
	c = compose(health, { overall: 'down', coordinator: 'live', findings: {} }, rd, now);
	ex = c.entries.metrics;
	check('done_history_line', length(ex.done) === 1 &&
		index(ex.done[0].text, 'старт службы') >= 0 && index(ex.done[0].text, 'удалось') >= 0,
		sprintf('%J', ex.done));
	check('history_view_ok', length(c.history) === 1 &&
		index(c.history[0].text, 'Сборщик метрик') >= 0 &&
		index(c.history[0].text, 'авто') === 0, sprintf('%J', c.history));

	/* 6. Ручная заявка в очереди → строка очереди; заморозка. */
	rd.manual_queue = [ { seq: '1', key: 'svc:metrics', target: 'metrics', action: 'svc_start' } ];
	rd.manual_freeze_until = now + 120;
	c = compose(health, { overall: 'down', coordinator: 'live', findings: {} }, rd, now);
	ex = c.entries.metrics;
	check('manual_queue_line', index(ex.next[0], 'ручная заявка в очереди') >= 0, sprintf('%J', ex.next));
	check('freeze_line', length(ex.done) === 2 &&
		index(ex.done[1].text, 'заморожены') >= 0, sprintf('%J', ex.done));
	rd.manual_queue = [];
	rd.manual_freeze_until = 0;
	rd.history = [];

	/* 7. Proposal-класс (core): подсказка в manual, честное «авто-ремонта нет». */
	health.entries.core = fe('core', 'Ядро', 'core', 'down', 'certain', 'API не отвечает');
	c = compose(health, { overall: 'down', coordinator: 'live', findings: {
		core: { status: 'down', label: 'Ядро', reason: 'API не отвечает' } } },
		{ overall: 'active', active_keys: 1, blocked_keys: 0, manual_queue: [],
		  keys: { core: camp('core', { action: null, target: 'core', class: 'core' }) },
		  blocked: {}, history: [], manual_freeze_until: 0, watch_op: null }, now);
	ex = c.entries.core;
	check('proposal_no_auto', index(ex.next[0], 'авто-ремонта для этого класса нет') >= 0, sprintf('%J', ex.next));
	check('proposal_hint', ex.hint != null && length(ex.hint) > 0, null);
	check('proposal_not_repairable', ex.repairable === false, null);
	check('proposal_manual_hint', index(ex.manual[0], 'предложение системы') >= 0, sprintf('%J', ex.manual));

	/* 8. Находка при ок-записи → alert на записи (Sentinel заметил раньше). */
	health.entries.core = fe('core', 'Ядро', 'core', 'ok', 'certain', 'ядро живо');
	health.entries.metrics = fe('metrics', 'Сборщик метрик', 'system', 'ok', 'certain', 'всё хорошо');
	c = compose(health, { overall: 'degraded', coordinator: 'live', findings: {
		'core': { status: 'degraded', label: 'Ядро', reason: 'сторож: API отвечает медленно' } } },
		{ overall: 'ok', active_keys: 0, blocked_keys: 0, manual_queue: [],
		  keys: {}, blocked: {}, history: [], manual_freeze_until: 0, watch_op: null }, now);
	check('ok_alert', c.entries.core.alert != null &&
		index(c.entries.core.alert, 'сторож видит проблему') >= 0, null);
	check('ok_finding_not_extra', length(c.extra) === 0, 'finding merged into the ok entry');

	/* 9. Внеленточные находки → extra. */
	c = compose(health, { overall: 'degraded', coordinator: 'live', findings: {
		'op:1-2': { status: 'degraded', label: 'Операция 1-2', reason: 'руннер умер' },
		'health_monitor': { status: 'down', label: 'Health Monitor', reason: 'молчит' },
		'loop:svc_start': { status: 'degraded', label: 'Цикл', reason: 'перебор' },
		'config:core_cfg': { status: 'down', label: 'Конфиг', reason: 'не парсится' }
	} }, { overall: 'ok', active_keys: 0, blocked_keys: 0, manual_queue: [],
		keys: {}, blocked: {}, history: [], manual_freeze_until: 0, watch_op: null }, now);
	check('extra_count', length(c.extra) === 4, 'loop + op + monitor + config');
	let has_loop = false;
	for (let x in c.extra)   /* x — ЭЛЕМЕНТ массива (урок 20/180) */
		if (index(x.key, 'loop:') === 0)
			has_loop = true;
	check('extra_loop_present', has_loop, null);
	check('svc_drift_maps_to_entry', entry_of_key('svc_drift:health') === 'health' &&
		entry_of_key('svc:telegram') === 'telegram' &&
		entry_of_key('hung:automation') === 'automation', null);
	check('entry_of_key_none', entry_of_key('op:1-2') == null && entry_of_key('config:x') == null, null);

	/* 10. watch_op + freeze в summary. */
	c = compose(health, { overall: 'ok', findings: {} }, {
		overall: 'active', active_keys: 0, blocked_keys: 0, manual_queue: [],
		keys: {}, blocked: {}, history: [], manual_freeze_until: now + 60,
		watch_op: { op_id: 'op1', action: 'restart', kind: 'service' } }, now);
	check('summary_watch', c.summary.recovery.watch_op != null &&
		c.summary.recovery.watch_op.action === 'restart', null);
	check('summary_freeze', c.summary.recovery.freeze_left > 0, null);

	/* 11. Пустые документы — не падает, честная пустота. */
	c = compose(null, null, null, now);
	check('null_docs', length(c.extra) === 0 && c.summary.overall === 'off' &&
		c.summary.sentinel.coordinator === 'unknown', null);

	let all_ok = true;
	for (let x in checks)
		if (!x.ok)
			all_ok = false;
	return { ok: all_ok, checks: checks };
};
