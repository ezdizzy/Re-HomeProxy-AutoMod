// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Recovery Manager (plan 20 §3 Ф2.3; A.1 аудита «Recovery Manager»).
//
// ЕДИНЫЙ координатор восстановления: очередь поводов (findings Sentinel'а +
// down-вердикты Health Monitor'а + ручные заявки RPC), гистерезис (окно
// стабилизации нового повода), экспоненциальные повторы (backoff 30 с → 30 мин),
// лимит авто-рестартов (≤3 за 30 мин на ключ, дальше блокировка до исчезновения
// проблемы или TTL 2 ч — procd retry-бюджет не выжигается, уроки 23/198),
// приоритет РУЧНЫХ действий (заявка исполняется немедленно, авто-ремонты
// замораживаются на 10 мин), запрет параллельных восстановлений (строго ОДНО
// действие за раз — opman-дверь kind 'repair' сериализует и с fallback'ом
// Sentinel'а). Каждая починка/решение → Event Bus (src='recovery').
//
// Разделение ролей (Ф2): Health — источник вердиктов, Sentinel — независимый
// сторож-детектор (и аварийный исполнитель, пока Recovery мёртв), Recovery —
// исполнитель ПОЛИТИКИ восстановления. Sentinel при живом Recovery не
// исполняет ремонты сам (gate по service list) — поводы он и так честно пишет
// в свой документ, координатор их подбирает. Мёртвый Recovery = Sentinel
// возвращается к разовому исполнению (fallback, контракт Ф2.2 не менялся).
//
// Источники поводов — ТОЛЬКО ДОКУМЕНТЫ (health.json/sentinel.json в конверте
// statestore): recovery.uc НЕ импортирует health.uc/sentinel.uc — битый деплой
// охраняемых не роняет координатора (тот же принцип, что у Sentinel'а, урок
// Ф2.2). Импорты — листовые (statestore/opman/eventbus/pmgr).
//
// Действия: svc_start (идемпотентный init.d start, урок 135), op_finish
// (честное закрытие зависшего опа), hung_kill (identity-kill зависшего
// владельческого демона — procd respawn вернёт). Классы без авто-ремонта
// (конфиги при живом ядре, TUN/fw4, ядро-API, память) → событие proposal
// (U4: оповещение С ПРЕДЛОЖЕНИЕМ исправления). Ручные ПЕРЕЗАПУСКИ службы
// остаются на существующей apply-двери (Ф1.1): Recovery видит их в журнале
// опов, трактует как ручные действия — freeze авто-ремонтов на время и 10 мин
// после, а верифицированное применение СБРАСЫВАЕТ все авто-кампании.
//
// Статус-документ /var/run/homeproxy/recovery.json (конверт statestore)
// пишется каждый тик — ts = живость координатора (RPC recovery_status).
// Ручные заявки — /var/run/homeproxy/recovery_request.json (атомарно, под
// mkdir-локом; демоном считывается и стирается).
//
// Уроки учтены: 166 (`};` у функций модуля; проверка импортирующим чекером),
// 216 (top-level const НАВЕРХУ), 221 (НЕТ try/finally), 2/93/126 (fs после
// import; хелперы выше вызывающих), 20/180 (for-in по массиву = элементы),
// 26 (index() вместо match()-строки), 211 (%J компактный), 167 (никаких
// 2-arg system(); rc-файл + опрос), 168 (rmdir непустого — unlink → rmdir),
// 171/223 (service list; procd-инстансы = источник ожиданий), 135 (start
// идемпотентен), 197 (MemAvailable-грань), 226 (hung — только владельческие),
// 229 (🔴 реальные kind'ы apply = 'service'/'core_install' — selftest ч.165
// был на синтетике kind='restart' и в рантайм-гейт не попадал),
// 228 (эмиссия ВНУТРИ compute — модуль сам доставляет события в шину).

'use strict';

import { access, readfile, popen, unlink, mkdir, rmdir, stat } from 'fs';
import {
	read_state as ss_read_state, write_state as ss_write_state,
	rjson as ss_rjson, wjson as ss_wjson
} from '/etc/homeproxy/scripts/statestore.uc';
import {
	list_ops as op_list, begin as op_begin, heartbeat as op_heartbeat,
	finish as op_finish, get_op as op_get
} from '/etc/homeproxy/scripts/opman.uc';
import {
	REG_PATH as PM_REG_PATH, entry_alive as pm_entry_alive,
	reg_get as pm_reg_get, kill_entry as pm_kill_entry
} from '/etc/homeproxy/scripts/pmgr.uc';
import { emit as ev_emit } from '/etc/homeproxy/scripts/eventbus.uc';

/* ── константы (урок 216: всё наверху, выше первой функции) ─────────────── */

export const RECOVERY_PATH = '/var/run/homeproxy/recovery.json';
/* Пути чужих документов — ЛОКАЛЬНЫЕ константы (не импорт модулей-писателей:
 * битый деплой health/sentinel не роняет координатора). */
export const SENTINEL_PATH = '/var/run/homeproxy/sentinel.json';
export const HEALTH_PATH = '/var/run/homeproxy/health.json';
export const REQUEST_PATH = '/var/run/homeproxy/recovery_request.json';
export const SRC = 'recovery';

/* Гистерезис: новый повод не чинится мгновенно — окно стабилизации (проблема
 * может уйти сама: procd-респавн, цикл демона-хозяина). */
export const STABILIZE_SEC = 45;

/* Экспоненциальные повторы: после неудачи следующая попытка через
 * base * 2^(n-1), cap 30 мин. Успех/верифицированный apply сбрасывают серию. */
export const RETRY_BASE_SEC = 30;
export const RETRY_CAP_SEC = 1800;

/* Лимит авто-рестартов (уроки 23/198: procd retry-бюджет выжигается серией):
 * ≤3 авто-исполнений ключа за 30 мин; исчерпан — блокировка до исчезновения
 * проблемы либо TTL 2 ч (одна попытка раз в 2 часа). */
export const AUTO_WINDOW_SEC = 1800;
export const AUTO_MAX = 3;
export const BLOCKED_TTL_SEC = 7200;

/* Флап-память: повод исчез — ключ держится 30 мин (кампания не дребезжит);
 * дольше — ключ удалён (событие recovered), возврат = новый цикл. */
export const FLAP_FORGET_SEC = 1800;

/* Приоритет ручного: ручное действие (заявка или верифицированный apply)
 * замораживает авто-ремонты на 10 мин. */
export const MANUAL_FREEZE_SEC = 600;

/* Зависшая операция (руннер мёртв) — порог как у Sentinel'а (урок 169). */
export const OP_HB_STALE_SEC = 300;

/* 🔴 Урок 229: РЕАЛЬНЫЕ kind'ы применений — 'service' (RPC op_spawn:
 * op_begin('service', action, …)) и 'core_install'. Ф2.2-гейт сравнивал kind
 * с action-именами ('restart'/'reload') и в рантайме не срабатывал вовсе. */
export const APPLY_KINDS = [ 'service', 'core_install' ];

/* Таймаут идемпотентного start (тот же, что у Sentinel'а). */
export const SVC_START_TIMEOUT = 150;

/* Лента истории ремонтов в документе. */
export const HISTORY_MAX = 20;

/* Действия координатора. */
export const ACT_SVC_START = 'svc_start';
export const ACT_OP_FINISH = 'op_finish';
export const ACT_HUNG_KILL = 'hung_kill';

/* Health-записи, маппящиеся на procd-инстанс (лечение svc_start / hung_kill —
 * respawn гарантирован procd'ом). Остальные имена — proposal-классы или
 * пропуск (ленивые/самовосстанавливающиеся — урок 223).
 * 🔴 Ф3.2 (T2b, живой лов 2026-11-04): запись 'core' → procd-инстанс
 * «hiddify-c». Раньше down ядра уходил в proposal-класс — координатор только
 * «предлагал», а не ремонтировал, и убитое/удалённое ядро оставало LAN без
 * интернета до ручного «Перезапуск службы». Идемпотентный start безопасен:
 * битый конфиг откатывает LKG-конвейер (Ф1.2) с маркером против шторма. */
const HEALTH_SVC_NAMES = {
	core: 'hiddify-c',
	automation: 'automation', multidns: 'multidns', telegram: 'telegram',
	hotswap: 'hotswap', autopilot: 'autopilot',
	control: 'control', sentinel: 'sentinel', health: 'health',
	recovery: 'recovery', metrics: 'metrics', log_cleaner: 'log-cleaner',
	byedpi: 'byedpi', zapret: 'zapret', tun_route: 'tun-route'
};

/* hung_kill допускается ТОЛЬКО для procd-демонов (respawn вернёт процесс).
 * probe_pool/sni_sniffer — ленивые/хозяйские (automation поднимет сам). */
const HUNG_KILLABLE = [ 'automation', 'multidns', 'telegram',
	'hotswap', 'autopilot', 'control', 'metrics', 'health', 'sentinel',
	'recovery' ];

/* Человекочитаемые метки классов proposal-поводов (U4-тексты).
 * Export для Ф2.5 Explainable (explain.uc — композитор объяснений). */
export const PROPOSAL_HINTS = {
	core: 'проверьте узлы/подписку; «Перезапуск службы» пересоберёт конфиг (Контроль → Обход блокировок)',
	mosdns: 'MultiDNS-демон пересобирает mosdns сам; если не восстановился — «Перезапуск службы»',
	tun: 'проверьте режим перехвата; «Перезапуск службы» пересоздаст TUN',
	fw4: '«Перезапуск службы» перестроит правила перехвата',
	generators: 'посмотрите журнал операций (Центр здоровья → Журнал операций): последнее применение не верифицировано',
	system: 'память на грани OOM — отключите тяжёлые функции (массовые пробы, большие батчи)',
	config: 'проверьте настройки раздела; «Перезапуск службы» пересоберёт конфигурацию',
	monitor: 'Health Monitor не отвечает — координатор поднимет службу; если повторяется — перезагрузите роутер'
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

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
};

/* ── классификация ключей-поводов ───────────────────────────────────────── */

/* Ключ → действие. null action = proposal-класс (только U4-предложение),
 * miss = класс неизвестен (не координаторская зона — молча игнорируется). */
export function classify_key(key) {
	const k = '' + (key || '');
	if (index(k, 'svc:') === 0 || index(k, 'svc_drift:') === 0)
		return { action: ACT_SVC_START, target: substr(k, index(k, ':') + 1), class: 'svc' };
	if (index(k, 'op:') === 0)
		return { action: ACT_OP_FINISH, target: substr(k, index(k, ':') + 1), class: 'op' };
	if (index(k, 'hung:') === 0) {
		const nm = substr(k, index(k, ':') + 1);
		let killable = false;
		for (let n in HUNG_KILLABLE)
			if (n === nm)
				killable = true;
		return (killable)
			? { action: ACT_HUNG_KILL, target: nm, class: 'hung' }
			: { action: null, target: nm, class: 'hung_other' };
	}
	if (k === 'health_monitor')
		return { action: null, target: k, class: 'monitor' };
	if (k === 'uci' || index(k, 'config:') === 0)
		return { action: null, target: k, class: 'config' };
	/* Health-записи без procd-инстанса: mosdns/tun/tun_route/fw4/
	 * generators/system — proposal по имени записи. 'core' остаётся proposal
	 * ТОЛЬКО для босого ключа (легаси/ручная заявка): реальный down ядра
	 * collect_findings маппит в 'svc:hiddify-c' (Ф3.2 — авто-ремонт). */
	if (k === 'core' || k === 'mosdns' || k === 'tun' ||
	    k === 'tun_route' || k === 'fw4' || k === 'generators' || k === 'system')
		return { action: null, target: k, class: k };
	return null;
};

/* Валидация ручной заявки (RPC и демоном): формат + известный класс. */
export function validate_manual(action, target) {
	const a = '' + (action || '');
	const t = '' + (target || '');
	if (a !== 'repair' && a !== 'unblock')
		return { ok: false, error: 'действие должно быть repair или unblock' };
	if (!length(t) || length(t) > 64 || match(t, /^[A-Za-z0-9_:.-]+$/) == null)
		return { ok: false, error: 'недопустимый формат ключа' };
	if (a === 'unblock')
		return { ok: true, key: t, action: a, target: t };
	const c = classify_key(t);
	if (c == null)
		return { ok: false, error: 'ключ не относится к зоне координатора' };
	if (c.action == null)
		return { ok: false, error: 'этот класс без авто-ремонта — используйте «Перезапуск службы» (Контроль → Обход блокировок) или восстановите конфигурацию' };
	return { ok: true, key: t, action: a, target: c.target, exec: c.action };
};

/* ── сбор поводов из документов (чистая функция) ──────────────────────────
 * sentinel.json findings — полные ключи Sentinel'а; health.json entries —
 * down-вердикты, маппятся ограниченно (procd-демоны → svc_start, прочие —
 * proposal). Первый источник побеждает (дедуп по ключу). */

export function collect_findings(sent_data, health_data) {
	const out = {};
	const add = function(key, label, reason, action, target, cls) {
		if (out['' + key] != null)
			return;
		out['' + key] = {
			label: '' + label, reason: '' + reason,
			action: (action != null) ? '' + action : null,
			target: (target != null) ? '' + target : null,
			class: '' + cls
		};
	};
	/* 1. Sentinel (детектор — его находки приоритетны: свежие и точные). */
	const sf = (sent_data != null && sent_data.findings != null &&
		type(sent_data.findings) === 'object') ? sent_data.findings : {};
	for (let k in sf) {
		const f = sf[k];
		const c = classify_key('' + k);
		if (c == null)
			continue;   /* loop: и hung_other — не координаторская зона */
		if (c.action != null)
			add(k, f.label || k, f.reason || '', c.action, c.target, c.class);
		else if (c.class === 'monitor' || c.class === 'config')
			add(k, f.label || k, f.reason || '', null, k, c.class);
		/* hung_other (ленивые дети automation) пропускается: сами восстанавливаются. */
	}
	/* 2. Health down-вердикты (быстрый источник: fast-тик 5 с при аварии). */
	const he = (health_data != null && health_data.entries != null &&
		type(health_data.entries) === 'object') ? health_data.entries : {};
	for (let nm in he) {
		const e = he[nm];
		if (e == null || type(e) !== 'object' || '' + (e.status || '') !== 'down')
			continue;
		if (e.expected === false)
			continue;   /* off-класс не алармится Health'ом и не чинится */
		const inst = HEALTH_SVC_NAMES['' + nm];
		if (inst != null) {
			add('svc:' + inst, e.label || nm,
				e.reason || 'Health: подсистема не работает',
				ACT_SVC_START, inst, 'svc');
		} else if (nm === 'probe_pool' || nm === 'sni_sniffer') {
			continue;   /* ленивые/самовосстанавливающиеся (урок 223) */
		} else {
			const cls = (nm === 'mosdns') ? 'mosdns'
				: (nm === 'core') ? 'core'
				: (nm === 'tun') ? 'tun'
				: (nm === 'fw4') ? 'fw4'
				: (nm === 'generators') ? 'generators'
				: (nm === 'system') ? 'system' : null;
			if (cls != null)
				add('' + nm, e.label || nm,
					e.reason || 'Health: подсистема в состоянии down',
					null, nm, cls);
		}
	}
	return out;
};

/* ── политики кампаний (чистые, selftest) ───────────────────────────────── */

export function backoff_sec(attempts) {
	const n = (int(attempts) > 0) ? int(attempts) : 1;
	const d = RETRY_BASE_SEC;
	let v = d;
	for (let i = 1; i < n; i++) {
		v = v * 2;
		if (v >= RETRY_CAP_SEC)
			return RETRY_CAP_SEC;
	}
	return v;
};

export function fresh_times(times, now) {
	const out = [];
	if (times != null && type(times) === 'array')
		for (let t in times) {
			const ts = int(t);
			if (ts > 0 && (now - ts) <= AUTO_WINDOW_SEC)
				push(out, ts);
		}
	return out;
};

/* settle: живые поводы обновляют last_seen + ставят alive; переносимые
 * (carried=true — light-проход Sentinel'а между полными) дают alive, но при
 * УЖЕ сделанной попытке (times непуст) сбрасывают её — повторная попытка
 * требует неперенесённого подтверждения следующего ПОЛНОГО прохода (иначе
 * свет-переносы порождали бы лишние start'ы после успешного ремонта);
 * исчезнувшие держатся FLAP_FORGET (флап-память, alive=false) — попытки по
 * не-живому ключу не делаются; протухшие удаляются. Возвращает { keys,
 * dropped }. */
export function settle_keys(prev_keys, findings, now) {
	const keys = {};
	const dropped = [];
	if (prev_keys != null && type(prev_keys) === 'object')
		for (let k in prev_keys) {
			const p = prev_keys[k];
			if (p == null || type(p) !== 'object')
				continue;
			const f = findings['' + k];
			if (f != null) {
				p.first_seen = int(p.first_seen) || now;
				p.last_seen = now;
				p.alive = (f.carried !== true || length(fresh_times(p.times, now)) === 0);
				keys['' + k] = p;
			} else if ((now - int(p.last_seen || 0)) <= FLAP_FORGET_SEC) {
				p.first_seen = int(p.first_seen) || now;
				p.alive = false;
				keys['' + k] = p;
			} else {
				push(dropped, { key: '' + k, entry: p });
			}
		}
	for (let k in findings) {
		if (keys['' + k] != null)
			continue;
		const f = findings[k];
		keys['' + k] = {
			first_seen: now, last_seen: now, times: [], next_ok: 0,
			proposed: false, alive: true, carried: (f.carried === true),
			label: f.label, reason: f.reason,
			action: f.action, target: f.target, class: f.class
		};
	}
	return { keys: keys, dropped: dropped };
};

/* Повод считается исчезнувшим (кампания закрыта) после FLAP_FORGET. */
function findings_gone(e, now) {
	return (now - int(e.last_seen || 0)) > FLAP_FORGET_SEC;
};

/* Кандидат к авто-исполнению: ЖИВОЙ повод (alive), действие, окно стабилизации
 * (новый) / next_ok (повторный), не blocked (или TTL-проба), в пределах
 * лимита. Возвращает { key, entry } | null. */
export function pick_auto(keys, blocked, now) {
	let best = null;
	for (let k in keys) {
		const e = keys[k];
		if (e == null || e.action == null)
			continue;
		if (e.alive !== true)
			continue;   /* повод исчез — попытка по не-живому ключу лишняя */
		const bl = (blocked != null && blocked['' + k] != null)
			? int(blocked['' + k]) : 0;
		const ft = fresh_times(e.times, now);
		if (bl > 0) {
			if ((now - bl) <= BLOCKED_TTL_SEC)
				continue;   /* блокировка жива — только TTL-проба ниже */
			/* TTL-истёк: одна проба поверх лимита — берём такой ключ. */
		} else if (length(ft) >= AUTO_MAX) {
			continue;   /* лимит — блокировка ставится исполнителем */
		}
		if (length(ft) === 0 && (now - int(e.first_seen || 0)) < STABILIZE_SEC)
			continue;   /* гистерезис: новый повод ждёт окно стабилизации */
		if (length(ft) > 0 && now < int(e.next_ok || 0))
			continue;   /* backoff ещё не вышел */
		if (best == null || int(e.first_seen) < int(best.entry.first_seen))
			best = { key: '' + k, entry: e };
	}
	return best;
};

/* Применение результата попытки. Возвращает события-добавки (blocked). */
export function apply_result(keys, blocked, key, ok, now) {
	const e = keys['' + key];
	const evs = [];
	if (e == null)
		return evs;
	if (ok && e.manual === true) {
		e.times = [];
		e.next_ok = 0;
		if (blocked != null && blocked['' + key] != null) {
			delete blocked['' + key];
			push(evs, { type: 'unblocked', who: e.label, key: '' + key,
				detail: 'ручной ремонт удался — авто-кампания сброшена' });
		}
	} else if (ok) {
		e.next_ok = now + backoff_sec(length(fresh_times(e.times, now)) + 1);
	} else {
		e.next_ok = now + backoff_sec(length(fresh_times(e.times, now)) + 1);
		const ft = fresh_times(e.times, now);
		if (length(ft) >= AUTO_MAX && (blocked == null || blocked['' + key] == null)) {
			blocked['' + key] = now;
			const c = classify_key('' + key);
			const hint = PROPOSAL_HINTS[(c != null) ? c.class : ''] ||
				PROPOSAL_HINTS.config;
			push(evs, {
				type: 'blocked', who: e.label, key: '' + key,
				detail: 'авто-ремонт «' + key + '» приостановлен (' + AUTO_MAX +
					' попытки за ' + int(AUTO_WINDOW_SEC / 60) + ' мин без результата). ' +
					'Предложение: ' + hint
			});
		}
	}
	return evs;
};

/* Живое применение (apply) в журнале: kind из APPLY_KINDS, статус живой,
 * heartbeat не протух (урок 229: kind='service'/'core_install'). */
export function apply_in_progress(ops, now) {
	if (ops == null || type(ops) !== 'array')
		return null;
	for (let op in ops) {
		const st = '' + (op.status || '');
		if (st !== 'queued' && st !== 'running' && st !== 'verifying')
			continue;
		let is_apply = false;
		for (let k in APPLY_KINDS)
			if (('' + (op.kind || '')) === k)
				is_apply = true;
		if (!is_apply)
			continue;
		const hb = int(op.heartbeat || 0);
		const age = (hb > 0) ? (now - hb) : (now - int(op.started || 0));
		if (age <= OP_HB_STALE_SEC)
			return { op_id: '' + op.op_id, action: '' + (op.action || ''),
				kind: '' + (op.kind || '') };
	}
	return null;
};

/* ── исполнение действий (синхронно, с heartbeat — урок 167) ────────────── */

function run_svc_start(op_id) {
	const rcfile = '/tmp/hp_recovery_' + op_id + '.rc';
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

function do_op_finish(stuck_op_id) {
	const op = op_get('' + stuck_op_id);
	if (op == null)
		return { ok: true, stale: true, detail: 'операция исчезла из журнала — повод устарел' };
	const st = '' + (op.status || '');
	if (st !== 'queued' && st !== 'running' && st !== 'verifying')
		return { ok: true, stale: true, detail: 'операция уже закрыта (' + st + ') — повод устарел' };
	op_finish('' + stuck_op_id, false, false,
		'recovery: руннер умер без честного финиша (heartbeat протух) — операция закрыта координатором, лок освобождён');
	return { ok: true, detail: 'операция «' + (op.action || stuck_op_id) + '» честно закрыта (лок освобождён)' };
};

/* Зависший владелец-демон: identity-kill, procd respawn вернёт процесс. */
function do_hung_kill(name) {
	const e = pm_reg_get('' + name);
	if (e == null || type(e) !== 'object' || pm_entry_alive(e) !== true)
		return { ok: true, stale: true, detail: 'идентичность «' + name + '» уже мертва — повод устарел' };
	const k1 = pm_kill_entry(e, 3000, false);
	if (!k1)
		return { ok: false, detail: 'не удалось завершить зависший процесс «' + name +
			'» (pid ' + int(e.pid) + ') — попытка останется в кампании' };
	return { ok: true, detail: 'зависший демон «' + name + '» завершён по identity (pid ' +
		int(e.pid) + ') — procd вернёт его автоматически' };
};

export function execute_action(action, target, op_id) {
	if (action === ACT_SVC_START)
		return run_svc_start(op_id);
	if (action === ACT_OP_FINISH)
		return do_op_finish(target);
	if (action === ACT_HUNG_KILL)
		return do_hung_kill(target);
	return { ok: false, detail: 'неизвестное действие «' + action + '»' };
};

/* ── ручная заявка (RPC-путь: лок + атомарная запись; демоном стирается) ── */

export function request_manual(action, target, note) {
	const v = validate_manual(action, target);
	if (v.ok !== true)
		return v;
	const ld = '/var/run/homeproxy/.recreq';
	if (!access('/var/run/homeproxy'))
		mkdir('/var/run/homeproxy');
	let held = false;
	for (let i = 0; i < 20; i++) {
		if (mkdir(ld)) {
			held = true;
			break;
		}
		/* Чужой лок протух (>5 с — RPC-воркеры быстрые) снимаем честно
		 * (урок 168: unlink файла → rmdir; steal ограничен). */
		const st = stat(ld);
		if (st != null && (time() - int(st.mtime)) > 5) {
			unlink(ld + '/owner.json');
			rmdir(ld);
			continue;
		}
		sleep(100);
	}
	if (!held)
		return { ok: false, error: 'очередь заявок занята — повторите' };
	const c = clock();
	const req = {
		seq: sprintf('%d-%06d', time(), int((c[1] / 1000) % 1000000)),
		action: '' + action, key: v.key, target: v.target,
		note: '' + (note || ''), ts: time()
	};
	/* 🔴 Заявка — сырой JSON (ss_wjson), НЕ statestore-конверт: демоном она
	 * читается ss_rjson и структуру конверта не распаковывает. */
	ss_wjson(REQUEST_PATH, req);
	unlink(ld + '/owner.json');
	rmdir(ld);
	return { ok: true, seq: req.seq };
};

/* ── главный проход (эмиссия ВНУТРИ — урок 228) ───────────────────────────
 * opts = { daemon_pid }. Возвращает { data, events, executed }. */
export function compute_and_recover(opts) {
	const o = (opts != null) ? opts : {};
	const now = time();
	const prev_rd = ss_read_state(RECOVERY_PATH);
	const prev = (prev_rd != null && prev_rd.data != null &&
		type(prev_rd.data) === 'object') ? prev_rd.data : null;
	const baseline = (prev == null);
	const events = [];
	let executed = null;

	let keys = (prev != null && prev.keys != null && type(prev.keys) === 'object')
		? prev.keys : {};
	let blocked = (prev != null && prev.blocked != null && type(prev.blocked) === 'object')
		? prev.blocked : {};
	let manual_until = (prev != null) ? int(prev.manual_freeze_until || 0) : 0;
	let watch = (prev != null && prev.watch_op != null) ? prev.watch_op : null;
	let manual_queue = (prev != null && prev.manual_queue != null &&
		type(prev.manual_queue) === 'array') ? prev.manual_queue : [];
	let history = (prev != null && prev.history != null && type(prev.history) === 'array')
		? prev.history : [];

	/* 1. Ручная заявка (сырой JSON-файл: RPC пишет, координатор стирает). */
	const req = ss_rjson(REQUEST_PATH);
	if (req != null && type(req) === 'object' && req.seq != null) {
		try { unlink(REQUEST_PATH); } catch (e) { /* уже нет */ }
		const v = validate_manual(req.action, req.key);
		if (v.ok === true) {
			const entry = {
				seq: '' + req.seq, key: '' + req.key, label: '' + req.key,
				action: '' + v.exec, target: '' + v.target,
				note: '' + (req.note || ''), ts: now
			};
			/* unblock — мгновенное административное действие без исполнения. */
			if (('' + req.action) === 'unblock') {
				delete blocked[entry.key];
				if (keys[entry.key] != null) {
					keys[entry.key].times = [];
					keys[entry.key].next_ok = 0;
					keys[entry.key].proposed = false;
				}
				push(events, { type: 'unblocked', who: entry.key,
					detail: 'кампания сброшена вручную' + (length(entry.note) ? (' — ' + entry.note) : '') });
				push(history, { ts: now, key: entry.key, action: 'unblock', ok: true, manual: true });
			} else {
				push(manual_queue, entry);
				push(events, { type: 'manual', who: entry.key,
					detail: 'принята ручная заявка на ремонт' + (length(entry.note) ? (' — ' + entry.note) : '') });
				push(history, { ts: now, key: entry.key, action: 'request', ok: true, manual: true });
			}
		}
	}

	/* 2. Поводы из документов. */
	const sent_rd = ss_read_state(SENTINEL_PATH);
	const health_rd = ss_read_state(HEALTH_PATH);
	const findings = collect_findings(
		(sent_rd != null && sent_rd.data != null) ? sent_rd.data : null,
		(health_rd != null && health_rd.data != null) ? health_rd.data : null);

	/* 3. settle кампаний (last_seen/удаление флап-протухших).
	 * 🔴 Латентный баг ч.166 (вскрыт живьём ч.167: первый тик, когда кампания
	 * прожила FLAP_FORGET — приёмка T1–T5 кампании 30+ мин не ждала):
	 * for-in по массиву даёт ЭЛЕМЕНТ (урок 20/180) — stl.dropped[d] был
	 * undefined и тик умирал «left-hand side expression is null» КАЖДЫЙ раз,
	 * когда хоть один повод доживал до флап-протухания. */
	const stl = settle_keys(keys, findings, now);
	keys = stl.keys;
	for (let de in stl.dropped) {
		if (de.entry.proposed === true || length(fresh_times(de.entry.times, now)) > 0)
			push(events, { type: 'recovered', who: de.entry.label || de.key,
				detail: 'повод исчез — кампания закрыта' });
		if (blocked['' + de.key] != null) {
			delete blocked['' + de.key];
			push(events, { type: 'unblocked', who: de.entry.label || de.key,
				detail: 'проблема исчезла — авто-ремонт возобновлён' });
		}
	}

	/* 4. Поллинг наблюдаемого apply (без fork: get_op = readfile). */
	if (watch != null) {
		const op = op_get('' + watch.op_id);
		if (op == null) {
			watch = null;   /* журнал вычищен — ничего сбрасывать по честности нельзя */
		} else {
			const st = '' + (op.status || '');
			if (st === 'completed' || st === 'failed') {
				if (op.verified === true) {
					for (let k in keys) {
						keys[k].times = [];
						keys[k].next_ok = 0;
						keys[k].proposed = false;
					}
					blocked = {};
					manual_until = now + MANUAL_FREEZE_SEC;
					push(events, { type: 'manual',
						who: 'Применение конфигурации',
						detail: 'применение «' + (op.action || '') + '» верифицировано — авто-кампании сброшены, автоматика выжидает ' +
							int(MANUAL_FREEZE_SEC / 60) + ' мин' });
					push(history, { ts: now, key: 'apply:' + (op.action || ''), action: 'apply_ok', ok: true, manual: true });
				}
				watch = null;
			}
		}
	}

	/* 5. Кандидаты; опман опрашивается: КАЖДЫЙ тик при живых кампаниях
	 * с действием (сброс по верифицированному apply — ради них) и каждый
	 * второй тик иначе (фон).
	 * 🔴 Ч.167 (живой лов): периодика раз в ~60 с пропускала КОРОТКИЕ
	 * применения — верифицированный restart 52 с проскочил между опросами,
	 * кампании НЕ сброшены и freeze не выставлен (обещание «verified apply
	 * сбрасывает все кампании» нарушалось в окне пробела). list_ops = один
	 * ls-fork + readfile'ы — по карману. Честная граница: применение КОРОЧЕ
	 * тика (15 с) всё ещё может проскочить между опросами (класс урока 181
	 * «рестарт мимо») — применять-стадии в дверях длиннее. */
	let has_camps = false;
	for (let k in keys) {
		const e = keys[k];
		if (e != null && e.action != null && findings_gone(e, now) !== true)
			has_camps = true;
	}
	const periodic = has_camps || ((int(o.tick || 0) % 2) === 0);
	let apply_now = null;
	const any_manual = length(manual_queue) > 0;
	const auto_cand = pick_auto(keys, blocked, now);
	/* 🔴 op_finish НЕ гейтится ручным freeze: закрытие зависшего опа —
	 * гигиена лока/журнала, а не вмешательство в работающую систему
	 * (зависший op держит lease и сам блокирует будущие применения). */
	const auto_allowed = (auto_cand != null) &&
		((manual_until <= now) || (auto_cand.entry.action === ACT_OP_FINISH));
	if (any_manual || auto_cand != null || (periodic && watch == null)) {
		const ops = op_list();
		apply_now = apply_in_progress(ops, now);
		if (apply_now != null && watch == null)
			watch = apply_now;
	}

	/* 4b. Стартовый догон (ч.167, живой лов): ПОЛНЫЙ рестарт службы
	 * пересоздаёт САМ координатор — демон, который смотрел apply, умирает
	 * вместе с рестартом, а новый поднимается уже ПОСЛЕ завершения опа
	 * (тёплый restart ~12 с < респавн+первый тик). На первом тике запуска
	 * демона смотрим ПОСЛЕДНИЙ оп журнала: completed+verified в окне 10 мин
	 * → тот же сброс (кампании очищены + freeze + событие manual). Повтор
	 * идемпотентен; догон только когда watch не подхвачен (иначе сброс уже
	 * сделала ветка поллинга watch). Ребут безопасен: журнал в tmpfs пуст. */
	if (int(o.tick || 0) === 0 && watch == null) {
		const ops0 = op_list();
		const last0 = (ops0 != null && length(ops0) > 0) ? ops0[0] : null;
		if (last0 != null && ('' + (last0.status || '')) === 'completed' &&
		    last0.verified === true &&
		    (now - int(last0.started || 0)) <= 600) {
			for (let k in keys) {
				keys[k].times = [];
				keys[k].next_ok = 0;
				keys[k].proposed = false;
			}
			blocked = {};
			manual_until = now + MANUAL_FREEZE_SEC;
			push(events, { type: 'manual',
				who: 'Применение конфигурации',
				detail: 'применение «' + (last0.action || '') + '» верифицировано (координатор перезапустился вместе со службой) — авто-кампании сброшены, автоматика выжидает ' +
					int(MANUAL_FREEZE_SEC / 60) + ' мин' });
			push(history, { ts: now, key: 'apply:' + (last0.action || ''),
				action: 'apply_ok', ok: true, manual: true });
		}
	}

	/* 6. Исполнение СТРОГО ОДНОГО действия (запрет параллельных). */
	const busy = (apply_now != null) || (manual_until > now && !any_manual);
	if (!busy && (any_manual || auto_allowed)) {
		let cand = null;
		let is_manual = false;
		if (any_manual) {
			const q = manual_queue[0];
			cand = { key: q.key, entry: {
				label: q.label, action: q.action, target: q.target, manual: true } };
			is_manual = true;
		} else if (auto_allowed) {
			cand = auto_cand;
		}
		if (cand != null && cand.entry.action != null) {
			const b = op_begin('repair', cand.entry.action, 'recovery',
				'recovery: ' + cand.key, 0);
			if (b != null && b.ok === true) {
				const res = execute_action(cand.entry.action, cand.entry.target, b.op.op_id);
				op_finish(b.op.op_id, res.ok === true, false, '' + (res.detail || ''));
				if (res.stale === true) {
					/* Повод устарел (цель уже закрыта/мертва) — кампания
					 * закрывается БЕЗ учёта попытки и без шума. */
					const old = keys[cand.key];
					if (old != null)
						delete keys[cand.key];
					push(events, { type: 'recovered',
						who: cand.entry.label || cand.key,
						detail: res.detail || 'повод устарел — кампания закрыта' });
					push(history, { ts: now, key: cand.key,
						action: cand.entry.action, ok: true, manual: is_manual });
					executed = { key: cand.key, action: cand.entry.action,
						ok: true, stale: true, manual: is_manual, op_id: b.op.op_id };
				} else {
					const e = (keys[cand.key] != null) ? keys[cand.key] : {
						first_seen: now, last_seen: now, times: [], next_ok: 0,
						proposed: false, alive: true, label: cand.entry.label,
						reason: '', action: cand.entry.action,
						target: cand.entry.target, class: 'manual' };
					if (keys[cand.key] == null)
						keys[cand.key] = e;
					if (is_manual) {
						e.manual = true;
						shift(manual_queue);
						manual_until = now + MANUAL_FREEZE_SEC;
					} else {
						e.manual = false;
						push(e.times, now);
					}
					const bevs = apply_result(keys, blocked, cand.key, res.ok === true, now);
					for (let ev in bevs)
						push(events, ev);
					push(events, {
						type: 'repair', who: cand.entry.label || cand.key,
						detail: (res.ok ? '' : 'НЕ УДАЛОСЬ: ') +
							(is_manual ? 'ручной ремонт' : 'авто-ремонт') + ': ' +
							(res.detail || cand.entry.action)
					});
					push(history, { ts: now, key: cand.key, action: cand.entry.action,
						ok: (res.ok === true), manual: is_manual });
					executed = { key: cand.key, action: cand.entry.action,
						ok: (res.ok === true), manual: is_manual, op_id: b.op.op_id };
				}
			}
			/* busy у opman (чужой repair в полёте) — отложим на следующий тик. */
		}
	}

	/* 7. U4-предложения для классов без авто-ремонта (разово на кампанию).
	 * 🔴 Ч.167: (а) сброс кампаний оживлял proposal для проблем из флап-
	 * памяти; (б) честное правило — предложение ТОЛЬКО о ЖИВОМ поводе
	 * (alive=true = находка видна прямо сейчас; флап-память держит кампанию
	 * для ремонтов, но не для оповещений о problem, которой уже нет). */
	for (let k in keys) {
		const e = keys[k];
		if (e == null || e.action != null || e.proposed === true)
			continue;
		if (findings_gone(e, now) || e.alive !== true)
			continue;
		const c = classify_key('' + k);
		if (c != null && c.action != null)
			continue;
		e.proposed = true;
		const hint = PROPOSAL_HINTS[(c != null) ? c.class : ''] ||
			PROPOSAL_HINTS.config;
		push(events, { type: 'proposal', who: e.label || k,
			detail: (e.reason || 'подсистема в состоянии down') + '. Предложение: ' + hint });
	}

	/* 8. Активные количества для статуса. */
	let active = 0;
	let blocked_n = 0;
	for (let k in keys) {
		const e = keys[k];
		if (findings_gone(e, now))
			continue;
		active++;
		if (blocked['' + k] != null)
			blocked_n++;
	}

	/* 9. События — В ШИНУ (урок 228: эмиссия в compute, CLI — цикл/лог). */
	for (let ev in events) {
		try {
			ev_emit(SRC, '' + ev.type, '' + (ev.who || ''), '' + (ev.detail || ''));
		} catch (e) { /* шина — best-effort */ }
	}

	/* 10. История (cap) и статус-документ. */
	while (length(history) > HISTORY_MAX)
		shift(history);
	const data = {
		overall: (active > 0 || length(manual_queue) > 0) ? 'active' : 'ok',
		ts: time(),
		active_keys: active,
		blocked_keys: blocked_n,
		manual_freeze_until: manual_until,
		manual_queue: manual_queue,
		watch_op: watch,
		keys: keys,
		blocked: blocked,
		history: history,
		last_repair: executed,
		daemon: { pid: (o.daemon_pid != null) ? int(o.daemon_pid) : null, note: 'recovery' }
	};
	ss_write_state(RECOVERY_PATH, data);
	return { data: data, events: events, baseline: baseline, executed: executed };
};

/* ── selftest (чистая логика на подставных входах) ──────────────────────── */
export function selftest() {
	const checks = [];
	const check = function(name, ok, detail) {
		push(checks, { check: name, ok: ok, detail: detail || null });
		return ok;
	};
	const now = time();

	/* classify_key. */
	check('cls_svc', classify_key('svc:metrics').action === ACT_SVC_START &&
		classify_key('svc:metrics').target === 'metrics', null);
	check('cls_drift', classify_key('svc_drift:health').action === ACT_SVC_START &&
		classify_key('svc_drift:health').target === 'health', null);
	check('cls_op', classify_key('op:123-000001').action === ACT_OP_FINISH &&
		classify_key('op:123-000001').target === '123-000001', null);
	check('cls_hung', classify_key('hung:automation').action === ACT_HUNG_KILL &&
		classify_key('hung:automation').target === 'automation', null);
	check('cls_hung_lazy', classify_key('hung:probe_pool') != null &&
		classify_key('hung:probe_pool').action == null, 'lazy prober is not killable');
	check('cls_monitor', classify_key('health_monitor').action == null &&
		classify_key('health_monitor').class === 'monitor', null);
	check('cls_config', classify_key('config:core_cfg').action == null &&
		classify_key('uci').class === 'config', null);
	check('cls_health_names', classify_key('core').class === 'core' &&
		classify_key('mosdns').class === 'mosdns' &&
		classify_key('fw4').class === 'fw4', null);
	check('cls_unknown', classify_key('loop:svc_start') == null &&
		classify_key('что-то иное') == null, null);

	/* validate_manual. */
	check('vm_repair_ok', validate_manual('repair', 'svc:metrics').ok === true, null);
	check('vm_bad_action', validate_manual('restart', 'svc:metrics').ok === false, null);
	check('vm_bad_key', validate_manual('repair', 'тест; rm -rf').ok === false, null);
	check('vm_unknown_class', validate_manual('repair', 'loop:svc_start').ok === false, null);
	check('vm_repair_proposal', validate_manual('repair', 'config:core_cfg').ok === false,
		'proposal classes are repaired by the apply door, not the coordinator');
	check('vm_unblock_any', validate_manual('unblock', 'svc:metrics').ok === true, null);

	/* collect_findings: Sentinel приоритетен; health down → svc-ключ; ленивые
	 * пропускаются; proposal-классы проходят. */
	const sf = {
		'svc:metrics': { label: 'Сборщик метрик', reason: 'procd: не работает' },
		'config:core_cfg': { label: 'Конфиг ядра', reason: 'не парсится' },
		'loop:svc_start': { label: 'Цикл', reason: 'r' }
	};
	const he = {
		metrics: { name: 'metrics', label: 'Сборщик метрик', status: 'down', reason: 'r2', expected: true },
		probe_pool: { name: 'probe_pool', label: 'pp', status: 'down', reason: 'r3', expected: true },
		core: { name: 'core', label: 'Ядро', status: 'down', reason: 'инстанс исчез из service list', expected: true },
		system: { name: 'system', label: 'Память', status: 'down', reason: 'мало', expected: true },
		tun: { name: 'tun', label: 'TUN', status: 'down', reason: 'tun down', expected: true },
		fw4: { name: 'fw4', label: 'fw4-перехват', status: 'down', reason: 'цепей нет', expected: true },
		tun_route: { name: 'tun_route', label: 'TUN-watcher', status: 'down', reason: 'procd', expected: true }
	};
	const f = collect_findings({ findings: sf }, { entries: he });
	check('cf_sent_priority', f['svc:metrics'] != null && f['svc:metrics'].reason === 'procd: не работает' &&
		f['svc:metrics'].action === ACT_SVC_START, null);
	check('cf_config_proposal', f['config:core_cfg'] != null &&
		f['config:core_cfg'].action == null, null);
	check('cf_loop_ignored', f['loop:svc_start'] == null, null);
	/* 🔴 Ф3.2 (T2b): down ядра — это svc:hiddify-c (авто-ремонт), не proposal. */
	check('cf_core_svc', f['svc:hiddify-c'] != null &&
		f['svc:hiddify-c'].action === ACT_SVC_START &&
		f['svc:hiddify-c'].target === 'hiddify-c' &&
		f['svc:hiddify-c'].class === 'svc', null);
	check('cf_core_not_proposal', f['core'] == null,
		'the bare core proposal key is no longer produced from a down verdict');
	check('cf_fw4_proposal', f['fw4'] != null && f['fw4'].action == null &&
		f['fw4'].class === 'fw4', 'fw4 down verdict is a proposal, not silence');
	check('cf_system_proposal', f['system'] != null, null);
	check('cf_tun_proposal', f['tun'] != null, null);
	check('cf_tun_route_svc', f['svc:tun-route'] != null &&
		f['svc:tun-route'].target === 'tun-route', 'TUN-watcher is a procd instance');
	check('cf_lazy_skipped', f['probe_pool'] == null, 'lazy prober never a recovery key');

	/* backoff. */
	check('backoff_1', backoff_sec(1) === 30, null);
	check('backoff_2', backoff_sec(2) === 60, null);
	check('backoff_3', backoff_sec(3) === 120, null);
	check('backoff_cap', backoff_sec(20) === RETRY_CAP_SEC, null);

	/* fresh_times. */
	check('fresh_prune', length(fresh_times([ now - 10, now - 2000 ], now)) === 1, null);
	check('fresh_empty', length(fresh_times(null, now)) === 0, null);

	/* settle_keys: живой повод обновляет, исчезнувший держится FLAP_FORGET,
	 * протухший удаляется. */
	const fk = { 'svc:metrics': { label: 'M', reason: 'r', action: ACT_SVC_START,
		target: 'metrics', class: 'svc' } };
	const s1 = settle_keys({}, fk, now);
	check('settle_new', s1.keys['svc:metrics'] != null &&
		s1.keys['svc:metrics'].first_seen === now &&
		s1.keys['svc:metrics'].alive === true, null);
	const s2 = settle_keys(s1.keys, {}, now);
	check('settle_kept', s2.keys['svc:metrics'] != null &&
		s2.keys['svc:metrics'].alive === false && length(s2.dropped) === 0,
		'flap memory keeps the campaign, not alive');
	const s3 = settle_keys(s2.keys, {}, now + FLAP_FORGET_SEC + 1);
	check('settle_dropped', length(s3.dropped) === 1 && s3.dropped[0].key === 'svc:metrics', null);

	/* carried-семантика: переносимая находка (light-проход Sentinel'а) даёт
	 * alive первой попытке, но после сделанной — сбрасывает до следующего
	 * полного подтверждения. */
	const fc = { 'svc:metrics': { label: 'M', reason: 'r', action: ACT_SVC_START,
		target: 'metrics', class: 'svc', carried: true } };
	const c1 = settle_keys({}, fc, now).keys;
	check('carried_first_ok', c1['svc:metrics'].alive === true &&
		c1['svc:metrics'].carried === true, null);
	c1['svc:metrics'].times = [ now - 5 ];
	const c2 = settle_keys(c1, fc, now).keys;
	check('carried_after_attempt', c2['svc:metrics'].alive === false,
		'carried findings do not license a retry before the next full pass');
	const c3 = settle_keys(c2, fk, now).keys;
	check('carried_full_confirm', c3['svc:metrics'].alive === true,
		'a non-carried (full-pass) finding re-licenses retries');

	/* pick_auto: стабилизация нового; next_ok повторного; blocked пропуска;
	 * TTL-проба; не-живой повод не выбирается. */
	const k1 = settle_keys({}, { 'svc:metrics': fk['svc:metrics'] }, now).keys;
	check('pick_stabilize', pick_auto(k1, {}, now) == null &&
		pick_auto(k1, {}, now + STABILIZE_SEC) != null, null);
	k1['svc:metrics'].alive = false;
	check('pick_gone', pick_auto(k1, {}, now + STABILIZE_SEC) == null,
		'no attempts against a vanished finding');
	k1['svc:metrics'].alive = true;
	k1['svc:metrics'].times = [ now - 10 ];
	k1['svc:metrics'].next_ok = now + 500;
	check('pick_backoff', pick_auto(k1, {}, now + STABILIZE_SEC) == null &&
		pick_auto(k1, {}, now + 501) != null, null);
	k1['svc:metrics'].times = [ now - 10, now - 20, now - 30 ];
	check('pick_limit_skip', pick_auto(k1, {}, now + 501) == null, 'limit reached');
	check('pick_ttl_probe', pick_auto(k1, { 'svc:metrics': now - BLOCKED_TTL_SEC - 1 }, now + 501) != null, null);
	check('pick_blocked_alive', pick_auto(k1, { 'svc:metrics': now - 100 }, now + 501) == null, null);

	/* apply_result: неудача двигает next_ok; исчерпание → blocked + proposal;
	 * ручной успех сбрасывает серию и разблокирует. 🔴 Тест симулирует
	 * ПОСЛЕДОВАТЕЛЬНОСТЬ рантайма (урок 213): compute пушит попытку в times
	 * ДО apply_result — здесь третья попытка добавлена руками. */
	const kk = settle_keys({}, { 'svc:metrics': fk['svc:metrics'] }, now).keys;
	kk['svc:metrics'].times = [ now - 1000, now - 500 ];
	push(kk['svc:metrics'].times, now);   /* attempt #3 just executed */
	const bl = {};
	let evs = apply_result(kk, bl, 'svc:metrics', false, now);
	check('res_fail_backoff', kk['svc:metrics'].next_ok > now, null);
	check('res_blocked', length(evs) === 1 && evs[0].type === 'blocked' &&
		bl['svc:metrics'] != null && index(evs[0].detail, 'Предложение') >= 0, null);
	kk['svc:metrics'].manual = true;
	evs = apply_result(kk, bl, 'svc:metrics', true, now);
	check('res_manual_ok_resets', length(kk['svc:metrics'].times) === 0 &&
		length(evs) === 1 && evs[0].type === 'unblocked' && bl['svc:metrics'] == null, null);

	/* apply_in_progress — урок 229 (kind='service', не action-имена). */
	check('apply_service_kind', apply_in_progress([
		{ op_id: 'a', kind: 'service', action: 'restart', status: 'running', heartbeat: now - 5 }
	], now) != null, null);
	check('apply_core_install', apply_in_progress([
		{ op_id: 'a', kind: 'core_install', status: 'verifying', heartbeat: now - 5 }
	], now) != null, null);
	check('apply_stale_not_blocking', apply_in_progress([
		{ op_id: 'a', kind: 'service', status: 'running', heartbeat: now - 400 }
	], now) == null, null);
	check('apply_repair_kind_free', apply_in_progress([
		{ op_id: 'a', kind: 'repair', status: 'running', heartbeat: now - 5 }
	], now) == null, null);
	check('apply_empty', apply_in_progress(null, now) == null, null);

	/* backoff сброс верифицированным apply — семантика в compute (интеграционно);
	 * здесь — единица backoff уже покрыта. */

	let all_ok = true;
	for (let c in checks)
		if (!c.ok)
			all_ok = false;
	return { ok: all_ok, checks: checks };
};
