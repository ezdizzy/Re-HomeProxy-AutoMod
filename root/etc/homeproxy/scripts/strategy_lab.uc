// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Strategy Lab v3 (Ф6.4, план 20 §Ф6; аудит 66/67/71/92/93).
//
// ЧЕТЫРЕ НЕЗАВИСИМЫХ ИЗМЕРЕНИЯ стратегии (аудит 66/71: один рейтинг за всё —
// ложь; измерения раздельные, вердикт собирается из них ЯВНО):
//   reachability  — работает ли путь вообще (строгое рукопожатие + живой
//                   поток: TLS-рукопожатие И curl exit 0 — audit 82);
//   performance   — median TLS / старт соединения (TTFB) / скорость потока;
//   stability     — success rate по раундам + jitter (P90−P10);
//   compatibility — какие КОМПОНЕНТЫ сервиса реально обслужены (deep-батарея
//                   через diag_core) + матрица возможностей движка (93).
//
// ABSOLUTE SERVICE GATE (аудит 67/92): обязательные проверки ресурса должны
// проходить, иначе вердикт NO_CANDIDATE с честным списком ЧТО не работает —
// «победила лучшая» без решения проблемы запрещён. Вердикты стратегии:
//   best_verified  — deep-батареи ресурса ВСЕ прошли (+ рукопожатие);
//   best_available — рукопожатие прошло, но обязательные тесты не
//                    подтверждены (не deep-тестировалась/частичный провал) —
//                    ТОЛЬКО вручную, с предупреждением (аудит 92);
//   no_candidate   — не кандидат.
//
// МАТРИЦА ВОЗМОЖНОСТЕЙ ДВИЖКОВ (аудит 93) учитывается ДО подбора: ByeDPI не
// умеет UDP/QUIC/STUN — компонент вне возможностей движка не «провал» и не
// «успех», он honest "не применимо" (не подмешивается в измерения).
//
// Уроки учтены: 245 (export через `};`), 246 (нет undefined — type()),
// 20/31 (for-in по массиву = элементы; push()/sort()/keys() — ГЛОБАЛЬНЫЕ
// функции, урок 249), 2/93 (хелперы выше), 251 (классич. индексные циклы),
// 253 (falsy-ноль), 91 (не проверено ≠ провалено), 197 (модуль без активных
// проб — только вычисления).

'use strict';

/* ── Матрица возможностей движков (аудит 93) ──
 * tcp/tls — рукопожатия и потоки TCP; udp — произвольный UDP;
 * quic — UDP/443 (HTTP/3); stun — UDP-голос (STUN). */
export const ENGINE_MATRIX = {
	zapret: { tcp: 1, tls: 1, udp: 1, quic: 1, stun: 1,
		note: 'nfqws2: TCP+UDP, QUIC/STUN — по UDP-профилям стратегии' },
	byedpi: { tcp: 1, tls: 1, udp: 0, quic: 0, stun: 0,
		note: 'ByeDPI (ciadpi): только TCP/TLS — UDP/QUIC/STUN вне возможностей движка' },
	proxy:  { tcp: 1, tls: 1, udp: 1, quic: 1, stun: 1,
		note: 'Proxy/VPN-узел: полный тракт, не зависит от DPI-движка' }
};

export function engine_can(engine, component) {
	const m = ENGINE_MATRIX['' + engine];
	if (m == null || type(m) !== 'object')
		return false;
	return m['' + component] === 1;
};

/* ── Статистика серии замеров (аудит 66: median/P90/success rate/jitter
 * вместо «лучшего одиночного замера») ──
 * times — замеры в мс (провал = 0), oks — 1/0 по каждому раунду.
 * median/p10/p90 считаются по УСПЕШНЫМ замерам; jitter = P90−P10;
 * ok_rate = успехи/попытки (0 при отсутствии попыток). */
export function samples_stats(times, oks) {
	const vals = [], oks_ = [];
	for (let i = 0; i < length(times); i++) {
		const t = (type(times[i]) === 'number') ? times[i] : ((('' + times[i]) * 1.0) || 0.0);
		const o = (oks != null && int(oks[i]) == 1) ? 1 : 0;
		push(vals, t);
		push(oks_, o);
	}
	const n = length(vals);
	const res = { n: n, ok_n: 0, ok_rate: 0.0, median: 0.0, p10: 0.0, p90: 0.0,
		min: 0.0, max: 0.0, jitter: 0.0 };
	if (n === 0)
		return res;
	let oksum = 0;
	for (let o in oks_)
		oksum += o;
	res.ok_n = oksum;
	res.ok_rate = (oksum * 1.0) / n;
	const succ = [];
	for (let i = 0; i < n; i++)
		if (oks_[i] === 1 && vals[i] > 0.0)
			push(succ, vals[i]);
	if (length(succ) === 0)
		return res;
	sort(succ, (a, b) => a - b);
	/* percentile — nearest-rank; медиана — lower-median (та же конвенция,
	 * что у ytv/START-медиан zapret_test.sh: чётная серия берёт НИЖНИЙ). */
	const pick = (q) => {
		const idx = int(q * length(succ) + 0.999);
		return succ[(idx < 1) ? 0 : ((idx > length(succ)) ? length(succ) - 1 : idx - 1)];
	};
	const med_idx = int((length(succ) + 1) / 2) - 1;
	res.min = succ[0];
	res.max = succ[length(succ) - 1];
	res.median = succ[(med_idx < 0) ? 0 : med_idx];
	res.p10 = pick(0.1);
	res.p90 = pick(0.9);
	res.jitter = res.p90 - res.p10;
	return res;
};

/* ── Обязательные компоненты ресурса (absolute gate, аудит 67) ──
 * id — id deep-проб zapret_test.sh; видео-компонент YouTube = РЕАЛЬНЫЙ
 * поток (yts) ИЛИ sustained-батч (ytv) — замеряется то, что доступно;
 * отсутствие замера = «не подтверждено» (91), НЕ провал. */
export const GATE_MANDATORY = {
	youtube:  { ids: ['ytp', 'yti'], video: true, label: 'YouTube' },
	discord:  { ids: ['dcp'], video: false, label: 'Discord' },
	telegram: { ids: ['tgp'], video: false, label: 'Telegram' },
	general:  { ids: [], video: false, label: 'Общий профиль' }
};

/* Вердикт ОДНОЙ стратегии по ресурсу. Вход:
 *   reach_ok   — рукопожатие ресурса прошло большинством раундов И не было
 *                бесплатным (не baseline-хост);
 *   deep_items — массив deep-пунктов ЭТОЙ стратегии по ресурсу (может быть
 *   null — стратегия не deep-тестировалась: потолок best_available).
 * Выход: 'best_verified' | 'best_available' | 'no_candidate'. */
export function strategy_verdict(reach_ok, deep_items) {
	if (reach_ok !== true)
		return 'no_candidate';
	if (deep_items == null || type(deep_items) !== 'array' || length(deep_items) === 0)
		return (reach_ok === true) ? 'best_available' : 'no_candidate';
	for (let it in deep_items)
		if (type(it) === 'object' && it.ok != 1)
			return 'best_available';
	return 'best_verified';
};

/* Компонентный вердикт ресурса по ВСЕМУ списку стратегий (аудит 67/92).
 * Вход:
 *   entries   — массив {name, args, reach_ok, deep_items|null} по каждой
 *               стратегии РЕСУРСА;
 *   quic_vn   — вердикт sweep-уровня QUIC: 'vn'|'icmp'|'silence'|null;
 *   udp_any   — есть ли в корпусе стратегии с UDP-профилем (--filter-udp=443).
 * Выход: { verdict, chosen, what_failed[], notes[] } — verdict ресурса:
 *   'best_verified' (есть подтверждённый — автоподбор МОЖЕТ применить),
 *   'best_available' (только доступные — ТОЛЬКО вручную с предупреждением),
 *   'no_candidate' (никто; what_failed называет, ЧТО не работает). */
export function resource_verdict(entries, quic_vn, udp_any) {
	const out = { verdict: 'no_candidate', chosen: null,
		what_failed: [], notes: [] };
	let verified = null, available = null;
	for (let e in entries) {
		if (type(e) !== 'object')
			continue;
		const v = strategy_verdict(e.reach_ok === true, e.deep_items);
		if (v === 'best_verified' && verified == null)
			verified = e;
		if (v === 'best_available' && available == null)
			available = e;
	}
	if (verified != null) {
		out.verdict = 'best_verified';
		out.chosen = { name: verified.name, args: verified.args };
	} else if (available != null) {
		out.verdict = 'best_available';
		out.chosen = { name: available.name, args: available.args };
		push(out.notes, 'подтверждённого победителя нет: доступна только стратегия с пройденным рукопожатием без полного подтверждения компонентов — автоприменение ЗАПРЕЩЕНО (аудит 92), решение вручную');
	}

	/* ЧТО не работает (аудит 67): равномерные отказы обязательных
	 * компонентов — у ВСЕХ deep-тестированных стратегий одинаково. */
	const mand = {
		ytp: 'страница YouTube', yti: 'CDN миниатюр YouTube',
		yts: 'реальный видеопоток YouTube', ytv: 'поток миниатюр (sustained)',
		dcp: 'страница Discord', tgp: 'страница Telegram'
	};
	const mand_ids = keys(mand);
	for (let mi = 0; mi < length(mand_ids); mi++) {
		const id = mand_ids[mi];
		let have = 0, failed = 0;
		const states = {};
		for (let e in entries) {
			if (type(e) !== 'object' || e.deep_items == null || type(e.deep_items) !== 'array')
				continue;
			for (let it in e.deep_items) {
				if (type(it) !== 'object' || it.id !== id)
					continue;
				have++;
				if (it.ok != 1) {
					failed++;
					const st = (it.app_state != null) ? ('' + it.app_state) : (('' + (it.kind || 'fail')));
					states[st] = 1;
				}
			}
		}
		if (have > 0 && failed === have) {
			const stl = [];
			const stkeys = keys(states);
			for (let si = 0; si < length(stkeys); si++)
				push(stl, stkeys[si]);
			push(out.what_failed, mand[id] + ' — не работает ни у одной стратегии (' + join(', ', stl) + ')');
		}
	}
	/* QUIC-честность (61/§2.5): вердикт контура + покрытие UDP-профилями —
	 * это ЗАМЕТКА о совместимости, а не отказ сервиса (TCP остаётся). */
	if (quic_vn === 'silence' || quic_vn === 'icmp') {
		push(out.notes, 'QUIC (UDP/443) отрезан у провайдера (' + quic_vn + ') — TCP-стратегии от этого не страдают, браузер падает на TCP');
	} else if (quic_vn === 'vn' && udp_any !== true) {
		push(out.notes, 'QUIC (UDP/443) у провайдера ОТКРЫТ, но ни одна стратегия корпуса не несёт UDP-профиля — QUIC-попытки браузера идут без дезинка');
	}
	return out;
};

/* ── Четыре измерения одной стратегии по ОДНОМУ ресурсу ──
 * rounds    — массив {ok, tls_ms} по раундам (строгое рукопожатие);
 * deep_h    — deep-запись ресурса этой стратегии {deep_ok, deep_total,
 *             stream, start_ms} | null;
 * engine    — движок стратегии (матрица 93; по умолчанию 'zapret').
 * Возвращает { reachability, performance, stability, compatibility }. */
export function dims_of(rounds, deep_h, engine) {
	const times = [], oks = [];
	for (let r in rounds) {
		if (type(r) !== 'object') continue;
		push(times, (r.tls_ms != null) ? r.tls_ms : 0);
		/* JSON-данные приходят и булевыми, и 1/0 — принимаем оба честно */
		push(oks, (r.ok === true || r.ok == 1) ? 1 : 0);
	}
	const st = samples_stats(times, oks);
	let reach_ok_n = 0;
	for (let o in oks)
		reach_ok_n += o;
	const has_deep = (deep_h != null && type(deep_h) === 'object');
	const dims = {
		reachability: { attempts: st.n, ok: reach_ok_n, rate: st.ok_rate },
		performance: { median_ms: st.median, p90_ms: st.p90,
			start_ms: has_deep ? int(deep_h.start_ms || 0) : 0,
			stream_bps: has_deep ? int(deep_h.stream || 0) : 0 },
		stability: { ok_rate: st.ok_rate, jitter_ms: st.jitter },
		compatibility: { engine: '' + (engine || 'zapret'),
			engine_can_udp: engine_can(engine || 'zapret', 'udp'),
			deep_ok: has_deep ? int(deep_h.deep_ok || 0) : null,
			deep_total: has_deep ? int(deep_h.deep_total || 0) : null }
	};
	return dims;
};

export function selftest() {
	const pass = [], fail = [];
	const t = (name, cond) => (cond) ? push(pass, name) : push(fail, name);

	/* samples_stats: медиана/P90/jitter/rate на известной серии */
	const st = samples_stats([100, 200, 300, 400, 500], [1, 1, 1, 1, 1]);
	t('stats median', st.median === 300.0);
	t('stats p10', st.p10 === 100.0);
	t('stats p90', st.p90 === 500.0);
	t('stats jitter = p90-p10', st.jitter === 400.0);
	t('stats ok_rate 1.0', st.ok_rate === 1.0);
	const st2 = samples_stats([100, 0, 300], [1, 0, 1]);
	t('stats ok_rate 2/3', st2.ok_rate > 0.66 && st2.ok_rate < 0.67);
	t('stats median over successes only (lower-median)', st2.median === 100.0);
	const st3 = samples_stats([0, 0], [0, 0]);
	t('stats all-fail honest zeros', st3.ok_rate === 0.0 && st3.median === 0.0 && st3.jitter === 0.0);
	const st4 = samples_stats([], []);
	t('stats empty series', st4.n === 0 && st4.ok_rate === 0.0);

	/* матрица движков (93) */
	t('byedpi no udp', engine_can('byedpi', 'udp') === false);
	t('byedpi tcp yes', engine_can('byedpi', 'tcp') === true);
	t('zapret quic yes', engine_can('zapret', 'quic') === true);
	t('unknown engine false', engine_can('x', 'tcp') === false);

	/* verdicts (92): reach-only = best_available; full deep = best_verified */
	t('no reach -> no_candidate', strategy_verdict(false, null) === 'no_candidate');
	t('reach only -> best_available', strategy_verdict(true, null) === 'best_available');
	t('deep partial -> best_available',
		strategy_verdict(true, [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 0 } ]) === 'best_available');
	t('deep full -> best_verified',
		strategy_verdict(true, [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 1 } ]) === 'best_verified');
	t('deep zero-length -> best_available', strategy_verdict(true, []) === 'best_available');

	/* resource verdict (67): verified -> verified; only available ->
	 * best_available с предупреждением; пусто -> no_candidate + what_failed */
	const ok_deep = [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 1 }, { id: 'yts', ok: 1 } ];
	const rv1 = resource_verdict([
		{ name: 'A', args: '--a', reach_ok: true, deep_items: ok_deep },
		{ name: 'B', args: '--b', reach_ok: true, deep_items: null }
	], 'vn', true);
	t('resource best_verified', rv1.verdict === 'best_verified' && rv1.chosen.name === 'A');
	const rv2 = resource_verdict([
		{ name: 'B', args: '--b', reach_ok: true, deep_items: null }
	], 'vn', false);
	t('resource best_available (manual only)', rv2.verdict === 'best_available' &&
		length(rv2.notes) === 2);   /* предупреждение + QUIC-заметка */
	const rv3 = resource_verdict([
		{ name: 'C', args: '--c', reach_ok: false, deep_items: [ { id: 'ytp', ok: 0 }, { id: 'yti', ok: 0 } ] },
		{ name: 'D', args: '--d', reach_ok: false, deep_items: [ { id: 'ytp', ok: 0 }, { id: 'yti', ok: 0 } ] }
	], 'silence', false);
	t('resource no_candidate', rv3.verdict === 'no_candidate' && rv3.chosen == null);
	const wf3 = join(';', rv3.what_failed);
	t('uniform page failure reported', index(wf3, 'страница YouTube') >= 0);
	t('uniform cdn failure reported', index(wf3, 'CDN миниатюр') >= 0);
	t('video NOT reported (unmeasured != failed, 91)', index(wf3, 'видеопоток') < 0);
	t('quic cut noted', index(join(';', rv3.notes), 'QUIC') >= 0);
	const rv4 = resource_verdict([
		{ name: 'E', args: '--e', reach_ok: true, deep_items: [ { id: 'dcp', ok: 1 } ] }
	], 'vn', false);
	t('discord verified via dcp', rv4.verdict === 'best_verified');

	/* dims_of: независимость измерений (66/71) */
	const d1 = dims_of([ { ok: true, tls_ms: 100 }, { ok: true, tls_ms: 300 } ],
		{ deep_ok: 2, deep_total: 3, stream: 500000, start_ms: 250 }, 'zapret');
	t('dims reachability', d1.reachability.ok === 2 && d1.reachability.attempts === 2);
	t('dims performance median (lower-median of 2)', d1.performance.median_ms === 100.0);
	t('dims performance stream', d1.performance.stream_bps === 500000);
	t('dims stability jitter', d1.stability.jitter_ms === 200.0);
	t('dims compatibility engine', d1.compatibility.engine === 'zapret' && d1.compatibility.deep_total === 3);
	const d2 = dims_of([ { ok: false, tls_ms: 0 } ], null, 'byedpi');
	t('dims byedpi udp=false', d2.compatibility.engine_can_udp === false);
	t('dims untested deep null', d2.compatibility.deep_total == null);

	return { pass: length(pass), fail: length(fail), details: fail };
};
