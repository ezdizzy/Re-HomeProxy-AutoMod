// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Service Path Optimizer (Ф6.5, план 20 §Ф6; аудит 70/78/92/93).
//
// Выбор цепочки Service → Route → Engine → Strategy → Transport → Exit для
// КАЖДОГО сервиса НЕЗАВИСИМО (аудит 70: автопилот управляет только Zapret,
// не выбирает между механизмами). Модуль ЧИСТЫЙ — только вычисления плана
// из уже измеренных фактов: вердикты Strategy Lab (Ф6.4, strategy_lab.uc),
// состояния профилей сервисов (Ф6.3, service_profiles.uc), состояние правил
// маршрутизации, матрица возможностей движков (93). Пробы ЗДЕСЬ НЕТ — их
// делают раннеры (wizard_autopick.uc / service_profile_run.uc), как в
// strategy_lab.uc.
//
// АУДИТ 93 (матрица движков ДО подбора): ByeDPI не умеет UDP/QUIC/STUN —
// сервис с UDP-компонентами (Discord Voice, звонки TG/WA) движком byedpi по
// звонкам не обслуживается. Это honest-замечание о совместимости, а не
// «провал» компонента (то же правило, что в strategy_lab.resource_verdict).
//
// АУДИТ 78 (авто-rollback обязателен): автоподбор обязан откатить
// применение, если живая проверка ПОСЛЕ apply провалилась; ручное
// применение («применить из таблицы ранжирования») — результат + решение
// пользователя, без автоматического отката.
//
// АУДИТ 92 (гейт автоподбора): автоприменяется ТОЛЬКО best_verified;
// best_available — ТОЛЬКО вручную с предупреждением; no_candidate — честный
// отказ со списком, ЧТО не работает.
//
// §2.4: простой автоподбор популярных сервисов «понятный любому» —
// план-сервисы это YouTube/Discord/Telegram (есть фаззинг-корпус лаборатории)
// + WhatsApp (корпуса НЕТ — честный no_lab, диагностика = батарея профиля и
// сканер провайдера; стратегий для него лаборатория не измеряла).
//
// 🔴 Ограничение проекта (решение пользователя, routing.direct_main_node_rules):
// когда Main node = Напрямую (Direct), заблокированные ресурсы НЕ должны
// уходить напрямую — правило сервиса обязано указывать на Zapret/ByeDPI
// (zapret-out/byedpi-out), а не на main-out.
//
// Уроки учтены: 245 (export через `};`), 246 (нет undefined — type()),
// 20/31 (for-in по массиву = элементы), 249 (push/sort/keys — глобальные),
// 2/93 (хелперы выше), 251 (классические индексные циклы), 253 (falsy-ноль),
// 197 (модуль без активных проб — только вычисления).

'use strict';

import { ENGINE_MATRIX } from '/etc/homeproxy/scripts/strategy_lab.uc';

/* ── Потребности популярных сервисов (§2.4) ──
 * fuzz     — есть ли фаззинг-корпус лаборатории для сервиса (иначе честный
 *            no_lab: стратегий не измерялось, «не проверено» ≠ «нет»);
 * udp_calls — есть ли у сервиса UDP-компоненты (звонки/Voice) — для
 *            честной заметки матрицы движков (93);
 * quic     — заметен ли QUIC-трафик сервиса (YouTube) — тоже для 93. */
export const SERVICE_NEEDS = {
	youtube:  { label: 'YouTube',  udp_calls: 0, quic: 1, fuzz: true,
		host: 'www.youtube.com' },
	discord:  { label: 'Discord',  udp_calls: 1, quic: 0, fuzz: true,
		host: 'discord.com' },
	telegram: { label: 'Telegram', udp_calls: 1, quic: 0, fuzz: true,
		host: 'web.telegram.org' },
	whatsapp: { label: 'WhatsApp', udp_calls: 1, quic: 0, fuzz: false,
		host: 'web.whatsapp.com' }
};

export const SERVICE_KEYS = [ 'youtube', 'discord', 'telegram', 'whatsapp' ];

/* Пригодность движка для сервиса (аудит 93) — ДО подбора.
 * Возвращает { fits, missing[], note } или null при неизвестном входе.
 * fits=false не запрещает обслуживание ВЕБА — оно честно называет, ЧТО
 * движок этим сервисом не покроет (звонки/QUIC). */
export function engine_suitability(service, engine) {
	const needs = SERVICE_NEEDS['' + service];
	const m = ENGINE_MATRIX['' + engine];
	if (needs == null || m == null || type(m) !== 'object')
		return null;
	const res = { fits: true, missing: [], note: '' };
	if (needs.udp_calls === 1 && m.udp !== 1) {
		res.fits = false;
		push(res.missing, 'udp');
	}
	if (needs.quic === 1 && m.quic !== 1) {
		res.fits = false;
		push(res.missing, 'quic');
	}
	if (length(res.missing))
		res.note = m.note;
	return res;
};

/* Честная заметка о движке для ЛОГИЧЕСКОГО выбора (93). zapret обслуживает
 * и TCP, и UDP-профили — но КОНКРЕТНАЯ стратегия может не иметь UDP-блока
 * (--filter-udp=443): это проверяется в раннере по args, здесь — уровень
 * движка. byedpi: только TCP/TLS. */
export function engine_note(service, engine) {
	const s = engine_suitability(service, engine);
	if (s == null)
		return null;
	if (s.fits)
		return null;
	if (index(join(',', s.missing), 'udp') >= 0)
		return 'движок ' + engine + ' не обслуживает UDP: звонки/Voice этого сервиса пойдут без дезинка (напрямую или через основной путь) — это ограничение движка, не отказ сервиса (аудит 93)';
	return 'движок ' + engine + ' не покрывает: ' + join(', ', s.missing);
};

/* ── Решение об откате (аудит 78) ──
 * before_ok/after_ok — ресурс ПОЛНОСТЬЮ обслуживался до/после (замер той же
 * батареи, урок 64: одинаковая матрица). auto=true только для АВТОПОДБОРА;
 * ручное применение — результат + решение пользователя (без отката).
 * verify_failed при !before_ok: применённая стратегия не помогла — откат
 * ОБЯЗАТЕЛЕН по аудиту 78 (возврат к прежнему состоянию без двойного
 * состояния «сломано новым»); note объясняет, что регрессии не было. */
export function rollback_decision(before_ok, after_ok, auto) {
	if (auto !== true)
		return { rollback: false, reason: 'manual', note: 'ручное применение — результат и решение за пользователем (Restore доступен)' };
	if (after_ok === true)
		return { rollback: false, reason: 'verify_ok', note: '' };
	if (before_ok === true)
		return { rollback: true, reason: 'regression',
			note: 'регрессия: ресурс работал до применения и не работает после — авто-откат обязателен (аудит 78)' };
	return { rollback: true, reason: 'verify_failed',
		note: 'проверка после применения не прошла (до применения ресурс тоже не работал полностью) — откат по протоколу автоподбора (аудит 78), Restore доступен' };
};

/* ── ПЛАН цепочки для ОДНОГО сервиса (аудит 70) ──
 * Вход (только ИЗМЕРЕННЫЕ факты, без проб):
 *   service      — ключ SERVICE_NEEDS;
 *   lab_verdict  — вердикт Strategy Lab: best_verified|best_available|
 *                  no_candidate|null (лаборатория не ранжировала);
 *   lab_chosen   — { name, args } выбранной лабораторией стратегии|null;
 *   profile      — сводка батареи Ф6.3 {working,degraded,refused,broken,
 *                  unprobed}|null (батарея не гонялась);
 *   rule         — {source,node,enabled}|null (текущее правило сервиса);
 *   main_node    — UCI homeproxy.config.main_node (строка);
 *   routing_mode — UCI routing_mode;
 *   zapret_enabled — boolean (движок включён).
 * Выход: { service, verdict, chain|null, actions[], reasons[], notes[] }
 *   verdict: 'ok' | 'apply' | 'manual_only' | 'no_candidate' | 'no_lab'
 *            | 'unknown'
 *   'ok'           — ресурс уже обслуживается (батарея подтверждает):
 *                    НИЧЕГО не трогаем (не ломать ручные пики/композиции);
 *   'apply'        — автоприменение best_verified разрешено (92), откат
 *                    обязателен (78);
 *   'manual_only'  — best_available: только вручную с предупреждением;
 *   'no_candidate' — подтверждённых стратегий нет; notes = ЧТО не работает;
 *   'no_lab'       — для сервиса нет фаззинг-корпуса (whatsapp) — честное
 *                    «не измерялось», направление: батарея профиля + сканер. */
export function chain_plan(input) {
	const inp = (type(input) === 'object') ? input : {};
	const service = '' + (inp.service || '');
	const needs = SERVICE_NEEDS[service];
	if (needs == null)
		return { service: service, verdict: 'unknown', chain: null,
			actions: [], reasons: [ 'неизвестный сервис' ], notes: [] };

	const out = { service: service, verdict: 'unknown', chain: null,
		actions: [], reasons: [], notes: [] };
	const lab_v = '' + (inp.lab_verdict || '');
	const lab_chosen = (type(inp.lab_chosen) === 'object' &&
		type(inp.lab_chosen.args) === 'string' && length(inp.lab_chosen.args)) ?
		{ name: '' + (inp.lab_chosen.name || ''), args: '' + inp.lab_chosen.args } : null;
	const prof = (type(inp.profile) === 'object') ? inp.profile : null;
	const rule = (type(inp.rule) === 'object') ? inp.rule : null;
	const main_node = '' + (inp.main_node || '');
	const rmode = '' + (inp.routing_mode || 'proxy_banned_ru');
	const main_is_direct = (main_node === 'direct-out' || main_node === 'nil' ||
		rmode === 'direct' || rmode === 'custom' || rmode === 'custom_json');

	/* Заметки матрицы движков (93) — всегда, до любых решений. */
	const sz = engine_suitability(service, 'zapret');
	const sb = engine_suitability(service, 'byedpi');
	if (sb != null && !sb.fits)
		push(out.notes, 'ByeDPI не подходит для ' + needs.label + ': ' + sb.note +
			' — если сервису нужен только TCP/веб, ByeDPI возможен, но измеренных стратегий для него в лаборатории нет (корпус — Zapret)');

	/* 1. Батарея профиля подтверждает работу → ничего не трогаем. */
	if (prof != null && type(prof) === 'object') {
		const bad = int(prof.broken || 0) + int(prof.refused || 0);
		const good = int(prof.working || 0);
		if (good > 0 && bad === 0) {
			out.verdict = 'ok';
			push(out.reasons, 'батарея профиля: работают все измеренные компоненты (' +
				good + ' working, ' + int(prof.unprobed || 0) + ' не проверено) — изменений не требуется');
			/* Даже при 'ok' честно назвать UDP-границу движка (93). */
			const zn = engine_note(service, 'zapret');
			if (zn != null)
				push(out.notes, zn);
			return out;
		}
	}

	/* 2. Нет фаззинг-корпуса → честное no_lab (91: не измерялось ≠ нет). */
	if (needs.fuzz !== true) {
		out.verdict = 'no_lab';
		push(out.reasons, 'лаборатория стратегий не измеряет ' + needs.label +
			' (нет фаззинг-корпуса) — «не измерялось» НЕ значит «не обходится»');
		push(out.actions, 'диагностика: батарея профиля сервиса + сканер провайдера (причина: провайдер или удалённая сторона)');
		if (rule != null && rule.enabled === '1' && rule.node === 'main-out' && main_is_direct)
			push(out.notes, '🔴 Main node = Direct: правило ' + service + ' указывает на main-out (напрямую) — заблокированные ресурсы не должны уходить напрямую, поставьте узел Zapret/ByeDPI или прокси');
		return out;
	}

	/* 3. Гейт лаборатории (92). */
	if (lab_v === 'best_verified' && lab_chosen != null) {
		out.verdict = 'apply';
		const route_node = 'zapret-out';
		out.chain = {
			service: service,
			route: 'правило ' + service + ' → ' + route_node +
				((rule != null && rule.enabled === '1' && rule.node === route_node) ?
					' (уже установлено)' : ' (будет создано/обновлено)'),
			engine: 'zapret',
			strategy: lab_chosen.name || 'кастомные аргументы',
			transport: 'TCP+UDP-профили стратегии nfqws2 (дезинк на выходе)',
			exit: 'напрямую через дезинк (DPI-обход предпочтительнее VPN — §2.4)'
		};
		push(out.reasons, 'вердикт Strategy Lab: best_verified — все обязательные компоненты ресурса прошли deep-батарею на изолированной очереди');
		push(out.actions, 'автоприменение разрешено (аудит 92) с ОБЯЗАТЕЛЬНЫМ авто-rollback при провале живой проверки (аудит 78)');
		const zn = engine_note(service, 'zapret');
		if (zn != null)
			push(out.notes, zn);
		if (rule != null && rule.enabled === '1' && rule.node === 'main-out' && main_is_direct)
			push(out.notes, '🔴 Main node = Direct: правило сервиса сейчас на main-out — заблокированные ресурсы не должны уходить напрямую (ограничение проекта)');
		return out;
	}
	if (lab_v === 'best_available') {
		out.verdict = 'manual_only';
		push(out.reasons, 'вердикт Strategy Lab: best_available — рукопожатие проходит, но обязательные компоненты не подтверждены');
		push(out.actions, 'применение ТОЛЬКО вручную из Лаборатории стратегий с предупреждением (аудит 92: автоприменение запрещено)');
		if (lab_chosen != null)
			push(out.notes, 'кандидат: ' + (lab_chosen.name || 'кастомные аргументы'));
		return out;
	}
	/* no_candidate или лаборатория не ранжировала. */
	out.verdict = 'no_candidate';
	if (lab_v !== 'no_candidate')
		push(out.reasons, 'лаборатория ещё не ранжировала ресурс (нет свежего вердикта) — запустите автоподбор или фаззинг');
	else
		push(out.reasons, 'вердикт Strategy Lab: no_candidate — ни одна стратегия корпуса не прошла обязательные проверки ресурса');
	if (needs.udp_calls === 1) {
		push(out.notes, 'звонки/Voice (UDP) без подтверждённой стратегии идут без дезинка; реальный UDP-путь на этом роутере инструментами не измеряется (nc -u нет) — это честное «не проверено», не «работает» (аудит 60/91)');
		if (!main_is_direct)
			push(out.notes, 'звонки может обслуживать основной прокси-узел (полный тракт) — правило сервиса на основной узел легально, пока стратегия не подтверждена');
		else
			push(out.notes, '🔴 Main node = Direct: звонки уйдут напрямую — при блокировке провайдером это отказ; путь — узел Zapret/прокси (ограничение проекта)');
	}
	return out;
};

export function selftest() {
	const pass = [], fail = [];
	const t = (name, cond) => (cond) ? push(pass, name) : push(fail, name);

	/* SERVICE_NEEDS структурно целы */
	t('4 popular services', length(keys(SERVICE_NEEDS)) === 4);
	t('whatsapp no fuzz corpus', SERVICE_NEEDS.whatsapp.fuzz !== true);
	t('discord has udp calls', SERVICE_NEEDS.discord.udp_calls === 1);

	/* engine_suitability (93) */
	let s = engine_suitability('discord', 'byedpi');
	t('byedpi misses discord udp', s != null && s.fits === false &&
		s.missing[0] === 'udp');
	s = engine_suitability('youtube', 'zapret');
	t('zapret fits youtube', s != null && s.fits === true && length(s.missing) === 0);
	s = engine_suitability('youtube', 'byedpi');
	t('byedpi misses youtube quic', s != null && s.fits === false &&
		s.missing[0] === 'quic');
	t('unknown service null', engine_suitability('x', 'zapret') == null);

	/* rollback_decision (78) */
	let rd = rollback_decision(true, false, true);
	t('regression → rollback', rd.rollback === true && rd.reason === 'regression');
	rd = rollback_decision(false, false, true);
	t('verify failed → rollback (78)', rd.rollback === true && rd.reason === 'verify_failed');
	rd = rollback_decision(false, true, true);
	t('ok → no rollback', rd.rollback === false && rd.reason === 'verify_ok');
	rd = rollback_decision(true, false, false);
	t('manual → no rollback', rd.rollback === false && rd.reason === 'manual');

	/* chain_plan (70/92) */
	let p = chain_plan({ service: 'youtube', lab_verdict: 'best_verified',
		lab_chosen: { name: 'Fake+multisplit', args: '--lua-desync=fake' },
		profile: null, rule: { source: 'youtube', node: 'main-out', enabled: '1' },
		main_node: 'urltest', routing_mode: 'proxy_banned_ru', zapret_enabled: true });
	t('best_verified → apply', p.verdict === 'apply' && p.chain != null &&
		p.chain.engine === 'zapret' && index(p.chain.route, 'zapret-out') >= 0);
	t('strategy named in chain', index(p.chain.strategy, 'Fake+multisplit') >= 0);

	p = chain_plan({ service: 'discord', lab_verdict: 'best_available',
		lab_chosen: { name: 'X', args: '--a' }, profile: null, rule: null,
		main_node: 'urltest', routing_mode: 'proxy_banned_ru' });
	t('best_available → manual_only', p.verdict === 'manual_only');

	p = chain_plan({ service: 'telegram', lab_verdict: 'no_candidate',
		lab_chosen: null, profile: null, rule: null,
		main_node: 'urltest', routing_mode: 'proxy_banned_ru' });
	t('no_candidate honest', p.verdict === 'no_candidate' && p.chain == null);
	t('udp calls honesty note (60/91)', index(join(';', p.notes), 'не проверено') >= 0);
	t('proxy-node fallback note', index(join(';', p.notes), 'основной прокси-узел') >= 0);

	/* батарея подтверждает работу → 'ok', ничего не трогаем */
	p = chain_plan({ service: 'youtube', lab_verdict: 'best_verified',
		lab_chosen: { name: 'X', args: '--a' },
		profile: { working: 4, degraded: 0, refused: 0, broken: 0, unprobed: 1 },
		rule: { source: 'youtube', node: 'zapret-out', enabled: '1' },
		main_node: 'urltest', routing_mode: 'proxy_banned_ru' });
	t('working profile → ok (не ломать пики)', p.verdict === 'ok' && p.chain == null);

	/* whatsapp → no_lab (честное «не измерялось») */
	p = chain_plan({ service: 'whatsapp', lab_verdict: null, lab_chosen: null,
		profile: null, rule: null, main_node: 'urltest', routing_mode: 'proxy_banned_ru' });
	t('whatsapp no_lab', p.verdict === 'no_lab');

	/* Main = Direct: заблокированные не уходят напрямую (ограничение проекта) */
	p = chain_plan({ service: 'telegram', lab_verdict: 'no_candidate',
		lab_chosen: null, profile: null, rule: { source: 'telegram', node: 'main-out', enabled: '1' },
		main_node: 'direct-out', routing_mode: 'proxy_banned_ru' });
	t('direct main warns on calls', index(join(';', p.notes), 'Direct') >= 0);

	/* unknown service */
	p = chain_plan({ service: 'nope' });
	t('unknown → unknown', p.verdict === 'unknown');

	return { pass: length(pass), fail: length(fail), details: fail };
};
