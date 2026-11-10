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
// ч.232 DEVICE-МЕТКИ (инвариант «лабораторный победитель обязан
// подтверждаться устройством»): проба-модель (curl, пиновые IP, temp-очередь)
// не видит ClientHello браузера/телефона, QUIC-фоллбек и паттерн соединений —
// живой факт 2026-11-07 (Default best_verified опровергнут телефоном).
// Метка с устройства ('works'/'broken') — НАИВЫСШИЙ вес в resource_verdict:
// works выбирается первым, broken не выбирается при наличии альтернатив.
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
export function strategy_verdict(reach_ok, deep_items, ignore_ids) {
	if (reach_ok !== true)
		return 'no_candidate';
	if (deep_items == null || type(deep_items) !== 'array' || length(deep_items) === 0)
		return (reach_ok === true) ? 'best_available' : 'no_candidate';
	for (let it in deep_items) {
		if (type(it) !== 'object')
			continue;
		/* ч.270: dedg* (dead-edge revive) НЕ участвует в обязательном гейте —
		 * оживление это БОНУС-измерение: стратегия, не оживившая край, не
		 * провалила ресурс (край может ожить под другой стратегией — именно
		 * это и есть дифференцирующий признак сеанса 182). */
		if (index('' + it.id, 'dedg') === 0)
			continue;
		if (ignore_ids != null && type(ignore_ids) === 'array') {
			/* ч.269: компонент, чей провал ПРОВАЙДЕРСКИЙ (baseline тоже
			 * молчит), не демотит стратегию — но и не считается подтверждением */
			let skip = false;
			for (let x in ignore_ids)
				if ('' + x === '' + it.id) { skip = true; break; }
			if (skip)
				continue;
		}
		if (it.ok != 1)
			return 'best_available';
	}
	return 'best_verified';
};

/* Компонентный вердикт ресурса по ВСЕМУ списку стратегий (аудит 67/92).
 * Вход:
 *   entries   — массив {name, args, reach_ok, deep_items|null} по каждой
 *               стратегии РЕСУРСА;
 *   quic_vn   — вердикт sweep-уровня QUIC: 'vn'|'icmp'|'silence'|null;
 *   udp_any   — есть ли в корпусе стратегии с UDP-профилем (--filter-udp=443).
 *   device    — ч.232: метки С УСТРОЙСТВА { '<args>': 'works'|'broken' }|null.
 *               Проба-модель лаборатории (curl, пиновые IP, тестовая очередь)
 *               НЕ видит решающих факторов TSPU: ClientHello браузера/телефона
 *               (curl-овый TLS-fingerprint ≠ браузерный; utls на mipsle
 *               недоступен), QUIC-фоллбек клиента, паттерн соединений —
 *               живой факт 2026-11-07: лабораторный best_verified Default
 *               опровергнут телефоном, реально работающая стратегия в лидеры
 *               не попадала. Инвариант: лабораторный победитель обязан
 *               подтверждаться устройством → device-метка — НАИВЫСШИЙ вес
 *               выбора, 'broken' не выбирается, пока есть альтернатива.
 *               ч.234: реальный формат device_verdicts.json —
 *               { '<args>': { verdict: 'works'|'broken' } } (ОБЪЕКТ);
 *               принимается и строковое значение для совместимости.
 *   dead      — ч.234: тег ресурса МЁРТВ для измерения (ни одна стратегия
 *               не прошла хост И оба контрольных baseline-прохода провалены
 *               — окно дрейфа сети/TSPU). Это отказ ИЗМЕРЕНИЯ, а не вердикт
 *               стратегий: красный «ни одна стратегия не прошла» здесь ложь
 *               (живой факт ч.233: YouTube жил в браузере, свип писал
 *               no_candidate). Метка с устройства сильнее — works всё ещё
 *               выбирается.
 * Выход: { verdict, chosen, what_failed[], notes[], device_confirmed } —
 *   verdict ресурса:
 *   'best_verified' (есть подтверждённый — автоподбор МОЖЕТ применить),
 *   'best_available' (только доступные — ТОЛЬКО вручную с предупреждением),
 *   'no_candidate' (никто; what_failed называет, ЧТО не работает).
 *   device_confirmed — выбор сделан по метке с устройства (true|false). */
export function resource_verdict(entries, quic_vn, udp_any, device, dead, extra) {
	const out = { verdict: 'no_candidate', chosen: null,
		what_failed: [], notes: [], device_confirmed: false };
	/* ч.269 (сеанс 181): extra — контекст уровня СВИПА, влияющий на честность
	 * вердикта, но НЕ на лабораторные факты:
	 *   dns           — {verdict, note} DNS-наборов тега ресурса
	 *                   (device_fail капает best_verified → best_available —
	 *                   измерение шло по резервному пути; divergence = note);
	 *   dead_edges    — [{host,ip}] инфраструктурно мёртвые края пула (край
	 *                   не ответил НИ У ОДНОЙ стратегии в двух проходах) —
	 *                   свойство ПУТИ (провайдера), видео с такого края не
	 *                   открываются независимо от стратегии;
	 *   stun_baseline — false ⇒ STUN молчит и без стратегии (baseline):
	 *                   провал dcv = состояние провайдера, НЕ вина стратегии
	 *                   (сегодня dcv молчаливо демотил discord до
	 *                   best_available, живых pass dcv не было — «первое
	 *                   измерение silence» ч.237); true ⇒ dcv-провал реален;
	 *   scan_note     — примечание из провайдер-скана (если есть). */
	const ex = (extra != null && type(extra) === 'object') ? extra : null;
	const ex_dns = (ex != null && type(ex.dns) === 'object') ? ex.dns : null;
	const ex_dead = (ex != null && type(ex.dead_edges) === 'array') ? ex.dead_edges : null;
	const ex_stun = (ex != null) ? ex.stun_baseline : null;
	const ex_rev = (ex != null && type(ex.revived) === 'array') ? ex.revived : null;
	const ex_scan = (ex != null && ex.scan_note != null) ? ('' + ex.scan_note) : null;
const ex_pools = (ex != null && type(ex.pools) === 'array') ? ex.pools : null;
	/* ч.234: метка в device_verdicts.json — ОБЪЕКТ { verdict: 'works'|… };
	 * прежний dv делал '' + объект (≠ 'works') — метка была МЕРТВА в
	 * лабораторном вердикте с момента появления (ч.232): свип ч.233 писал
	 * no_candidate при живой works-метке на составной (ключ 1862 симв.
	 * байт-в-байт совпадал — доказано сверкой коробки). Разворачиваем. */
	const dv = (device != null && type(device) === 'object')
		? ((a) => {
			const mv = device['' + a];
			if (mv == null)
				return '';
			if (type(mv) === 'object')
				return '' + (mv.verdict || '');
			return '' + mv;
		}) : (() => '');
	const ignore_ids = (ex_stun === false) ? ['dcv'] : null;
	let verified = null, available = null, dev_confirmed = null;
	let refuted_verified = null, any_refuted = false;
	for (let e in entries) {
		if (type(e) !== 'object')
			continue;
		const v = strategy_verdict(e.reach_ok === true, e.deep_items, ignore_ids);
		const d = dv(e.args);
		if (d === 'works') {
			/* устройство сказало «работает» — сильнее любой лаборатории,
			 * включая стратегии без полного лабораторного подтверждения */
			if (dev_confirmed == null)
				dev_confirmed = e;
			continue;
		}
		if (d === 'broken')
			any_refuted = true;
		if (v === 'best_verified') {
			if (d === 'broken') {
				if (refuted_verified == null)
					refuted_verified = e;
			} else if (verified == null)
				verified = e;
		}
		if (v === 'best_available' && d !== 'broken' && available == null)
			available = e;
	}
	/* ч.234: измерение НЕВОЗМОЖНО (аудит 91 — не проверено ≠ провалено).
	 * Тег мёртв: ни одна стратегия не прошла хост И оба контрольных
	 * прохода провалены — сломалось ИЗМЕРЕНИЕ, а не все стратегии сразу.
	 * Серый вердикт вместо красного no_candidate; what_failed и QUIC-
	 * заметки опускаются — они дали бы ложь в мёртвом окне. Метка с
	 * устройства сильнее: works выше этого отказа (dev_confirmed). */
	if (dev_confirmed == null && dead === true) {
		out.verdict = 'unmeasured';
		push(out.notes, 'измерение ресурса НЕВОЗМОЖНО: тестовый хост не ответил ни у одной стратегии и в обоих контрольных проходах — отказ измерения (дрейф сети/TSPU), не вердикт стратегий; повторите свип позже');
		return out;
	}
	if (dev_confirmed != null) {
		out.verdict = 'best_verified';
		out.chosen = { name: dev_confirmed.name, args: dev_confirmed.args };
		out.device_confirmed = true;
		push(out.notes, 'выбор подтверждён на УСТРОЙСТВЕ (' +
			((dev_confirmed.name != null && length('' + dev_confirmed.name))
				? dev_confirmed.name : 'кастомные аргументы') +
			') — сигнал с реального устройства сильнее лабораторной пробы: curl не воспроизводит ClientHello браузера/телефона и QUIC-фоллбек');
	} else if (verified != null) {
		out.verdict = 'best_verified';
		out.chosen = { name: verified.name, args: verified.args };
		if (any_refuted)
			push(out.notes, 'лабораторный победитель выбран с учётом меток с устройства: опровергнутые на устройстве стратегии пропущены');
	} else if (available != null) {
		out.verdict = 'best_available';
		out.chosen = { name: available.name, args: available.args };
		push(out.notes, 'подтверждённого победителя нет: доступна только стратегия с пройденным рукопожатием без полного подтверждения компонентов — автоприменение ЗАПРЕЩЕНО (аудит 92), решение вручную');
	} else if (refuted_verified != null) {
		/* все лабораторно подтверждённые опровергнуты устройством —
		 * автоприменение отменяется, решение вручную (метка сильнее лаборатории) */
		out.verdict = 'best_available';
		out.chosen = { name: refuted_verified.name, args: refuted_verified.args };
		push(out.notes, 'единственная лабораторно подтверждённая стратегия ОПРОВЕРГНУТА на устройстве — автоприменение отменено (аудит 92 + метка с устройства), решение вручную');
	} else if (any_refuted) {
		push(out.notes, 'лабораторные кандидаты этого ресурса опровергнуты на устройстве — честный отказ до подтверждения альтернативы');
	}

	/* ЧТО не работает (аудит 67): равномерные отказы обязательных
	 * компонентов — у ВСЕХ deep-тестированных стратегий одинаково. */
	const mand = {
		ytp: 'страница YouTube', yti: 'CDN миниатюр YouTube',
		yts: 'реальный видеопоток YouTube', ytv: 'поток миниатюр (sustained)',
		dcp: 'страница Discord', tgp: 'страница Telegram',
		dcv: 'голос Discord (STUN, UDP/3478)'
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
	 * это ЗАМЕТКА о совместимости, а не отказ сервиса (TCP остаётся).
	 * ч.234: формулировка явно называет это СОСТОЯНИЕМ ПРОВАЙДЕРА в момент
	 * свипа — пользователь читал «QUIC отрезан» как «в v3 сломалось»
	 * (вопрос 2026-11-07: до v3 QUIC не измерялся вовсе, «работал всегда»
	 * — наблюдение из браузера, где резаный QUIC невидим: TCP-фоллбек). */
	if (quic_vn === 'silence' || quic_vn === 'icmp') {
		push(out.notes, 'QUIC (UDP/443) отрезан у провайдера (' + quic_vn + ') — состояние провайдера в момент свипа, НЕ вердикт стратегий: TCP-стратегии от этого не страдают, браузер падает на TCP');
	} else if (quic_vn === 'vn' && udp_any !== true) {
		push(out.notes, 'QUIC (UDP/443) у провайдера ОТКРЫТ (состояние провайдера, не вердикт стратегий), но ни одна стратегия корпуса не несёт UDP-профиля — QUIC-попытки браузера идут без дезинка, браузер добивает их TCP-фоллбеком');
	}

	/* ч.269: честный контекст уровня пути/провайдера — notes рядом с
	 * вердиктом (рендер уже печатает notes в карточке ресурса). */
	if (out.chosen != null) {
		for (let e2 in entries)
			if (type(e2) === 'object' && ('' + e2.args) === ('' + out.chosen.args)) {
				out.chosen.unstable_edges = int(e2.unstable_edges || 0);
				break;
			}
		/* ч.272/185 dedgu: the browser sign — did the CHOSEN strategy carry a
		 * chrome ClientHello through the same dead edges its curl revived?
		 * ок ≠ браузер ок (ч.271 live fact; сеанс 185 matrix: on a revivable
		 * pool five formator classes lift uok=1, a hard pool lifts none).
		 * Signed beside the verdict, never into it: dead-edge revive is a
		 * bonus measurement (ч.270), the browser twin inherits that role. */
		for (let e3 in entries) {
			if (type(e3) !== 'object' || ('' + e3.args) !== ('' + out.chosen.args))
				continue;
			let dbok = 0, dbtot = 0, unmeasured = false;
			if (e3.deep_items != null && type(e3.deep_items) === 'array')
				/* урок 417: ucode for..in по массиву даёт ЭЛЕМЕНТЫ — индексация
				 * по значению внутри такого цикла = null (поймано селфтестом) */
				for (let di in e3.deep_items) {
					if (type(di) !== 'object' || index('' + di.id, 'dedg') !== 0)
						continue;
					if (di.uok == null) {
						unmeasured = true;
						continue;
					}
					dbtot++;
					if (di.uok == 1)
						dbok++;
				}
			if (dbtot > 0) {
				out.chosen.dead_browser_ok = dbok;
				out.chosen.dead_browser_total = dbtot;
				push(out.notes, 'браузерная проба мёртвых краёв (chrome-ClientHello): ' +
					dbok + '/' + dbtot + ' ожили под выбранной стратегией' +
					((dbok == dbtot) ? ' — стратегия браузер-совместима на мягком классе пулов' :
						((dbok == 0) ? ' — браузерный Hello под ней на оживлённых curl краях НЕ выживает' : '')));
			} else if (unmeasured) {
				push(out.notes, 'браузерная проба мёртвых краёв не проводилась (utls_probe не установлен) — «браузер-совместимость» не измерена');
			}
			break;
		}
	}
	if (ex_stun === false) {
		push(out.notes, 'STUN (голос Discord, UDP/3478) молчит и БЕЗ стратегии (baseline тоже) — провайдерский уровень UDP, а не вина стратегий: провал dcv больше не демотит вердикт (решение пользователя «baseline + provider-note», сеанс 181)');
	} else if (ex_stun === true) {
		push(out.notes, 'STUN (голос Discord) на baseline ОТВЕЧАЕТ — провал dcv у стратегии означает реальный провал её UDP-профиля на голосовом контуре');
	}
	if (ex_dead != null && length(ex_dead) > 0) {
		let shown = 0;
		for (let de in ex_dead) {
			if (type(de) !== 'object' || de.ip == null || shown >= 3)
				continue;
			push(out.notes, 'крае CDN ' + ('' + (de.host || '?')) + ' (' + de.ip + ') отрезан ПО ПУТИ: не ответил ни у одной стратегии в обоих проходах — инфраструктура, не стратегия; видео с этого края не открываются независимо от выбора (феномен «одна выдача — разные видео»)');
			shown++;
		}
	}
	/* ч.270: revive-заметка — мёртвость края СТРАТЕГИЯ-зависима (сеанс 182:
	 * .48 оживает под Hostfakesplit, мёртв под fakedsplit catch-all; после
	 * ревизии такие края больше НЕ входят в infra_dead). */
	if (ex_rev != null && length(ex_rev) > 0) {
		const rips = [];
		for (let re2 in ex_rev)
			if (type(re2) === 'object' && re2.ip != null)
				push(rips, '' + re2.ip);
		if (length(rips) > 0)
			push(out.notes, 'край(-я) пула ' + join(', ', rips) + ' ОЖИВАЮТ не всеми стратегиями (1 MB проба под каждой): мёртвость края зависит от формы потока стратегии, а не от инфраструктуры — revive считается первосортным признаком выбора');
	}
	/* ч.183: МУЛЬТИПУЛОВАЯ правда — «пул мёртв целиком» не спрашивает
	 * стратегии: выдача из такого пула не играет ни при какой. Честный
	 * вердикт юзеру = перегенерировать страницу (новая выдача обычно из
	 * другого пула), а не крутить список стратегий. */
	if (ex_pools != null) {
		let pw = 0, partial = [];
		for (let pl in ex_pools) {
			if (type(pl) !== 'object' || pl.suffix == null) continue;
			const ps = '' + pl.suffix;
			const pd = int(pl.dead || 0), pa = int(pl.alive || 0);
			if (int(pl.dead_whole) == 1 && pd > 0 && pw < 3) {
				push(out.notes, 'пул ' + ps + ' мёртв ЦЕЛИКОМ (' + pd + ' краёв не отвечают): выдача из него не играет НИ ПРИ КАКОЙ стратегии — обновите страницу/откройте другое видео (новая выдача обычно из другого пула), винить стратегию бессмысленно');
				pw++;
			} else if (pd > 0 && pa > 0 && length(partial) < 4)
				push(partial, ps + ' (' + pa + '/' + (pa + pd) + ' краёв живы)');
		}
		if (length(partial) > 0)
			push(out.notes, 'пулы с частичной чернотой: ' + join(', ', partial) + ' — видео из чёрных краёв может не открываться, это свойство пула, не стратегии');
	}
	if (ex_dns != null) {
		const dvv = '' + (ex_dns.verdict || '');
		const dnn = '' + (ex_dns.note || '');
		if (dvv === 'device_fail') {
			if (out.verdict === 'best_verified') {
				out.verdict = 'best_available';
				push(out.notes, 'вердикт СНИЖЕН до «только вручную»: DNS пути устройства не ответил (' + (length(dnn) ? dnn : 'наборы DNS не сравнимы') + ') — измерение шло по резервному пути');
			} else {
				push(out.notes, 'DNS пути устройства не ответил — ' + (length(dnn) ? dnn : 'измерение DNS неполно'));
			}
		} else if (dvv === 'divergence') {
			push(out.notes, 'DNS-наборы расходятся (гео/anycast/CDN-политика, НЕ доказательство подмены)' + (length(dnn) ? (': ' + dnn) : ''));
		} else if (dvv === 'device_only') {
			push(out.notes, 'внешние резолверы не ответили (UDP-фильтрация у провайдера) — сравнение DNS-наборов невозможно, набор устройства взят как есть');
		}
	}
	if (ex_scan != null && length(ex_scan))
		push(out.notes, ex_scan);
	/* ч.269: нестабильность краёв выбранной стратегии (entropy) — честная
	 * оговорка рядом с вердиктом (метрики шумнее, когда края флипуют). */
	if (out.chosen != null && out.chosen.unstable_edges != null &&
		int(out.chosen.unstable_edges) > 0)
		push(out.notes, 'края видеопотока выбранной стратегии ФЛИПУЮТ между проходами (нестабильность пути) — её метрики шумнее соседних');
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

	/* ч.232: device-метки — наивысший вес выбора. ч.234: РЕАЛЬНЫЙ формат
	 * device_verdicts.json — ОБЪЕКТ {verdict:'works'} (прежний тест
	 * прогонял строковые значения и пропустил мёртвый dv: свип ч.233
	 * писал no_candidate при живой метке — урок «микротест реплеит
	 * реальный формат данных, а не удобный»). */
	const dev = { '--default': { verdict: 'broken' }, '--composite': { verdict: 'works' } };
	/* device-confirmed бьёт лабораторного verified (Default опровергнут) */
	const rv5 = resource_verdict([
		{ name: 'Default', args: '--default', reach_ok: true, deep_items: ok_deep },
		{ name: 'Composite', args: '--composite', reach_ok: true, deep_items: null }
	], 'vn', true, dev);
	t('device works beats lab verified', rv5.verdict === 'best_verified' &&
		rv5.chosen.args === '--composite' && rv5.device_confirmed === true);
	t('device note present', index(join(';', rv5.notes), 'УСТРОЙСТВЕ') >= 0);
	/* опровергнутый verified пропускается, выбирается следующий */
	const rv6 = resource_verdict([
		{ name: 'Default', args: '--default', reach_ok: true, deep_items: ok_deep },
		{ name: 'Other', args: '--other', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, dev);
	t('refuted verified skipped', rv6.chosen.args === '--other' &&
		rv6.device_confirmed === false);
	/* все verified опровергнуты → manual-only с честной заметкой */
	const rv7 = resource_verdict([
		{ name: 'Default', args: '--default', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, dev);
	t('all verified refuted → manual only', rv7.verdict === 'best_available' &&
		rv7.chosen.args === '--default' &&
		index(join(';', rv7.notes), 'ОПРОВЕРГНУТА') >= 0);
	/* без меток — прежнее поведение */
	const rv8 = resource_verdict([
		{ name: 'Default', args: '--default', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, null);
	t('no device map → lab order', rv8.verdict === 'best_verified' &&
		rv8.chosen.args === '--default' && rv8.device_confirmed === false);
	/* ч.270: dedg (dead-edge revive) НЕ демотит вердикт — бонус-измерение */
	t('dedg fail does not demote',
		strategy_verdict(true, [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 1 }, { id: 'dedg1', ok: 0 } ]) === 'best_verified');
	t('dedg pass still passes',
		strategy_verdict(true, [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 1 }, { id: 'dedg2', ok: 1 } ]) === 'best_verified');
	/* ч.272/185: dedgu — браузерный знак у выбранной стратегии (рядом,
	 * не в вердикт): uok=1 считается, отсутствие uok = честное «не измерено» */
	const db_deep = [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 1 },
		{ id: 'dedg1', ok: 1, uok: 1, utls_ms: 42 }, { id: 'dedg2', ok: 0, uok: 0, u_err: 'timeout' } ];
	const rv21 = resource_verdict([
		{ name: 'A', args: '--a', reach_ok: true, deep_items: db_deep }
	], 'vn', true, null);
	t('dedgu browser sign attached',
		rv21.verdict === 'best_verified' &&
		rv21.chosen.dead_browser_ok === 1 && rv21.chosen.dead_browser_total === 2 &&
		index(join(';', rv21.notes), 'chrome-ClientHello') >= 0);
	const rv22 = resource_verdict([
		{ name: 'B', args: '--b', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, null);
	/* без dedg-пунктов (мёртвых краёв не было) — чистое отсутствие:
	 * ни полей, ни заметки (заявлять нечего) */
	t('dedgu absent = clean absence',
		rv22.verdict === 'best_verified' &&
		rv22.chosen.dead_browser_ok == null &&
		rv22.chosen.dead_browser_total == null &&
		index(join(';', rv22.notes), 'chrome-ClientHello') < 0);
	/* dedg-пункты есть, uok нет (utls-бинарник отсутствовал) — честное
	 * «не измерено», а не ноль из нуля */
	const rv23 = resource_verdict([
		{ name: 'C', args: '--c', reach_ok: true,
			deep_items: [ { id: 'ytp', ok: 1 }, { id: 'yti', ok: 1 },
				{ id: 'dedg1', ok: 1 } ] }
	], 'vn', true, null);
	t('dedgu unmeasured (no uok) = honest note',
		rv23.verdict === 'best_verified' &&
		rv23.chosen.dead_browser_ok == null &&
		index(join(';', rv23.notes), 'не проводилась') >= 0);
	/* ч.270: revive-заметка рядом с вердиктом youtube */
	const rv20 = resource_verdict([
		{ name: 'A', args: '--a', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, null, false,
		{ revived: [ { ip: '185.221.46.48', host: 'rr5---sn-nx5pm-3ggl.googlevideo.com' } ] });
	t('revived note present', rv20.verdict === 'best_verified' &&
		index(join(';', rv20.notes), 'ОЖИВАЮТ не всеми стратегиями') >= 0);
	/* ч.234: строковое значение метки — обратная совместимость */
	const rv9 = resource_verdict([
		{ name: 'Composite', args: '--composite', reach_ok: false, deep_items: null }
	], 'silence', true, { '--composite': 'works' });
	t('string verdict value still works', rv9.verdict === 'best_verified' &&
		rv9.device_confirmed === true);
	/* ч.234: dead-тег — серый unmeasured вместо красного no_candidate */
	const rv10 = resource_verdict([
		{ name: 'C', args: '--c', reach_ok: false, deep_items: null },
		{ name: 'D', args: '--d', reach_ok: false, deep_items: null }
	], 'silence', true, null, true);
	t('dead tag → unmeasured (not red)', rv10.verdict === 'unmeasured' &&
		rv10.chosen == null && length(rv10.what_failed) === 0 &&
		index(join(';', rv10.notes), 'НЕВОЗМОЖНО') >= 0);
	/* метка с устройства сильнее даже мёртвого измерения */
	const rv11 = resource_verdict([
		{ name: 'Composite', args: '--composite', reach_ok: false, deep_items: null }
	], 'silence', true, dev, true);
	t('device works beats dead measurement', rv11.verdict === 'best_verified' &&
		rv11.device_confirmed === true && rv11.chosen.args === '--composite');
	/* dead без дрейфа (по умолчанию) — прежнее поведение */
	const rv12 = resource_verdict([
		{ name: 'C', args: '--c', reach_ok: false, deep_items: null }
	], 'silence', true, null, false);
	t('no dead flag → no_candidate', rv12.verdict === 'no_candidate');

	/* ч.269 (сеанс 181): контекст свипа — STUN-baseline, инфраструктурно
	 * мёртвые края, DNS-кап, entropy-оговорка. */
	const rv13 = resource_verdict([
		{ name: 'G', args: '--g', reach_ok: true,
			deep_items: [ { id: 'dcp', ok: 1 }, { id: 'dcv', ok: 0 } ] }
	], 'vn', false, null, false,
		{ stun_baseline: false });
	t('provider-cut dcv does not demote', rv13.verdict === 'best_verified' &&
		index(join(';', rv13.notes), 'провайдерский уровень') >= 0);
	const rv14 = resource_verdict([
		{ name: 'G', args: '--g', reach_ok: true,
			deep_items: [ { id: 'dcp', ok: 1 }, { id: 'dcv', ok: 0 } ] }
	], 'vn', false, null, false,
		{ stun_baseline: true });
	t('live dcv failure still demotes', rv14.verdict === 'best_available');
	const rv15 = resource_verdict([
		{ name: 'H', args: '--h', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, null, false,
		{ dns: { verdict: 'device_fail', note: 'нет ответа' } });
	t('dns device_fail caps verified', rv15.verdict === 'best_available' &&
		index(join(';', rv15.notes), 'СНИЖЕН') >= 0);
	const rv16 = resource_verdict([
		{ name: 'I', args: '--i', reach_ok: true, deep_items: ok_deep }
	], 'vn', true, null, false,
		{ dns: { verdict: 'divergence', note: '' },
			dead_edges: [ { host: 'rr5---sn-x', ip: '185.221.46.48' } ] });
	t('divergence note only + dead edge note', rv16.verdict === 'best_verified' &&
		index(join(';', rv16.notes), '185.221.46.48') >= 0 &&
		index(join(';', rv16.notes), 'расходятся') >= 0);
	const rv17 = resource_verdict([
		{ name: 'J', args: '--j', reach_ok: true, deep_items: ok_deep, unstable_edges: 2 }
	], 'vn', true, null, false, null);
	t('unstable chosen flagged', rv17.verdict === 'best_verified' &&
		index(join(';', rv17.notes), 'ФЛИПУЮТ') >= 0);

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
