// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Diagnostic Core (Ф6.1, план 20 §Ф6; аудит B4 54/55/72/73/75/87, B5.7/B5.8, 65).
//
// ЕДИНАЯ модель результата диагностики и ЕДИНЫЙ классификатор причин.
// До Ф6.1 у Wizard Scan / Automation / Autopilot были свои трактовки одних и тех же
// фактов (403, 503, TLS reset, геоотказ) — «одна из главных архитектурных находок»
// аудита (B4.72). Этот модуль — единственный источник:
//
//   1. Классификация ОДНОГО пути (direct/proxy/live) — classify_path():
//      слои dns/tcp/tls/http в форме { code, rc, tsec, ok, net, app_state, kind,
//      geo_refused, geo_via, waf, trust, slow }.
//      net — network_reachable (полный чистый HTTP-ответ, 73);
//      app_state — состояние ПРИЛОЖЕНИЯ независимо от кода (B5.8/87):
//        ok | geo_refused | blockpage | waf_challenge | waf_rate_limit |
//        waf_origin_denied | server_error.
//   2. Разделение routing_verdict (какой путь лучше) и cause_verdict (почему
//      недоступен) — diag_cause() (54, B5.7). Типы причин:
//        isp_interference / origin_geo_restriction / origin_waf / origin_ip_policy /
//        dns_interference / client_filtering / remote_failure / inconclusive.
//   3. TLS-MITM отличим от транспорта (65): проводник доверия (curl БЕЗ -k) даёт
//      evidence trust = ok|bad_cert — подменённая страница/чужой сертификат = перехват,
//      а не честный ответ источника. Классифицируется trust_kind().
//   4. Дифференциальные правила (55/75/76): прямой TLS-сброс + рабочий прокси =
//      подтверждённый ISP; оба пути упали одинаково = inconclusive (локальный DPI
//      или сбой удалённой стороны — различить нельзя, честно так и говорим);
//      403/406 без маркеров — НЕ доказательство DPI/гео (origin может отдать 403 легально).
//
// Механика проб (curl/nslookup/порты) ЗДЕСЬ НЕТ — потребители (wizard_scan.uc и
// далее Ф6.x) измеряют сами и отдают факты в diag_cause(). Сигнатуры-списки —
// единый источник: потребители импортируют, а не копируют.
//
// Уроки учтены: 245 (export-функции через `};`, модуль проверять IMPORT'ом),
// 246 (глобального undefined НЕТ — type()/null), 20/31 (for-in по массиву = элементы),
// 26/27 (match() только с regex-литералами), 2/93 (хелперы ВЫШЕ вызывающих),
// 253 (falsy-ноль в диапазонах), 197 (модуль без проб/задержек — только классификация).

'use strict';

/* ── Сигнатуры (единый источник; ранее копировались в wizard_scan.uc) ── */

/* 200/3xx-страница-заглушка оператора (стиль блокировочных страниц ТСПУ/провайдера). */
export const BLOCK_SIGNATURES = [
	'access denied', 'access forbidden', 'forbidden', 'доступ ограничен',
	'доступ запрещен', 'заблокир', 'заблокиров', 'blocked by', 'block page',
	'the site is blocked', 'сайт заблокирован', 'err_blocked', 'доступ к ресурсу',
	'blocked site', 'не доступен', 'resource is limited', 'request blocked'
];

/* Гео-отказ источника: 200/4xx с этим текстом — НЕ успех (регион отказан). */
export const GEO_REFUSAL_PATTERNS = [
	"isn't currently supported in your country",
	'not supported in your country',
	'not available in your country',
	'is not supported in your country',
	'unavailable in your region',
	'not available in your region',
	'unsupported_country_region_territory',
	'страна не поддерживается',
	'не поддерживается в вашей стране',
	'недоступен в вашей стране'
];

/* Сильные маркеры WAF/challenge: запрос ДОШЁЛ до реального сервиса — путь открыт,
 * клиентская форма запроса не проходит. НЕ цензурный вердикт. */
export const WAF_SIGNATURES = [
	'just a moment', 'attention required', 'checking your browser',
	'cf-chl', 'challenge-platform', 'cf-mitigated', 'cf-turnstile',
	'are you a robot', 'bot protection', 'ddos protection', 'captcha'
];

/* Порог «медленного, но рабочего» пути (подсказка о троттлинге) — классификация
 * пути здесь, UI-подсказка у потребителя. */
export const SLOW_SEC = 2.0;

/* ── Хелперы (выше вызывающих — no hoisting) ── */

const _body_lc = (body) => {
	if (!body || length(body) > 32768)
		return null;
	return lc(body);
};

const _find_marker = (body, list) => {
	const b = _body_lc(body);
	if (b == null)
		return null;
	for (let s in list)
		if (index(b, s) >= 0)
			return s;
	return null;
};

/* HTTP-класс кода: 'ok' (2xx/3xx), 'block' (4xx/5xx), 'fail' (нет ответа). */
export function code_class(code) {
	const c = trim('' + (code || '000'));
	if (c === '' || c === '000')
		return 'fail';
	const n = int(c);
	if (n >= 200 && n < 400)
		return 'ok';
	if (n >= 400 && n <= 599)
		return 'block';
	return 'fail';
};

/* curl exit code → транспортная причина сбоя. rc 35/56 = TLS-сброс после
 * ClientHello (классический SNI-DPI) или сброс посреди redirect-цепочки;
 * rc 7 = TCP connect (блок IP при пине, иначе DNS-дыра); rc 28 = полный
 * таймаут (DPI-дроп или фильтрованный маршрут); rc 5/6 = резолв. */
export function rc_transport_kind(rc, had_pin) {
	if (rc === 35 || rc === 56)
		return 'tls_dpi';
	if (rc === 7)
		return had_pin ? 'tcp' : 'resolve';
	if (rc === 28)
		return 'timeout';
	if (rc === 5 || rc === 6)
		return 'resolve';
	if (rc === 0)
		return null;
	return 'transport';
};

/* Сигнатура тела: 'sigpage' (заглушка оператора) / 'geo_refused' (гео-отказ
 * маркерами) / null. Возвращает найденный маркер для evidence. */
export function body_sig(body, extra_markers) {
	const m1 = _find_marker(body, BLOCK_SIGNATURES);
	if (m1 != null)
		return { state: 'sigpage', marker: m1 };
	const m2 = _find_marker(body, GEO_REFUSAL_PATTERNS);
	if (m2 != null)
		return { state: 'geo_refused', marker: m2 };
	if (type(extra_markers) === 'array') {
		const m3 = _find_marker(body, extra_markers);
		if (m3 != null)
			return { state: 'geo_refused', marker: m3 };
	}
	return { state: null, marker: null };
};

/* WAF-состояние НЕЗАВИСИМО от кода (B5.8/87): challenge-маркеры в теле на любом
 * коде = waf_challenge; 429 = waf_rate_limit. */
export function waf_state(code, body) {
	if (_find_marker(body, WAF_SIGNATURES) != null)
		return 'waf_challenge';
	if (trim('' + (code || '')) === '429')
		return 'waf_rate_limit';
	return null;
};

/* Проводник доверия (65): классификация rc у probe БЕЗ -k. rc 0 = цепочка
 * валидна (ответ от настоящего источника); rc 60/19/51/82 = сертификат не
 * проходит проверку (подменён/неизвестен) — перехват TLS; rc 35/56 = сброс
 * (транспорт, не MITM). */
export function trust_kind(rc) {
	if (rc === 0)
		return 'ok';
	if (rc === 60 || rc === 19 || rc === 51 || rc === 82)
		return 'bad_cert';
	if (rc === 35 || rc === 56)
		return 'reset';
	return 'other';
};

/* ── Классификация ОДНОГО пути ──
 * r = { code, rc, tsec, body } — сырой замер (probe механика потребителя).
 * had_pin — путь шёл с пином (--resolve; rc 7 тогда = блок IP, не DNS).
 * extra_markers — per-service гео-маркеры (адаптеры сервисов — Ф6.3; сейчас
 * передаёт wizard_scan из SVC_REFUSAL_PATTERNS).
 *
 * ok — «путь доставляет ресурс или доказанно открыт» (WAF-состояния ok=true:
 * путь открыт, клиентская форма не проходит); НЕ путать с app_state='ok'.
 * net — network_reachable (73): полный чистый HTTP-ответ (rc 0, код не 000).
 * Сброс посреди цепочки (rc!=0 при полученных заголовках) — НЕ net: путь не
 * доставил ресурс целиком, но свидетельство HTTP-ответа остаётся в evidence. */
export function classify_path(r, had_pin, extra_markers) {
	const cls = code_class(r.code);
	let ok = false;
	let net = false;
	let app_state = null;
	let kind = rc_transport_kind(r.rc, had_pin);
	let geo_refused = false;
	let geo_via = null;
	let waf = null;

	if (r.rc !== 0 && cls === 'ok') {
		/* Заголовки пришли, потом цепочка/тело умерли — DPI-сброс между хопами.
		 * Однозначный провал пути с транспортной причиной. */
		return { code: r.code, rc: r.rc, tsec: r.tsec, ok: false, net: false,
			app_state: null, kind: kind || 'transport', geo_refused: false,
			geo_via: null, waf: null, trust: null, slow: false };
	}
	if (cls === 'ok' && r.rc === 0) {
		net = true;
		const sig = body_sig(r.body, extra_markers);
		waf = waf_state(r.code, r.body);
		if (sig.state === 'sigpage') {
			app_state = 'blockpage';
			kind = 'sigpage';
		} else if (sig.state === 'geo_refused') {
			app_state = 'geo_refused';
			kind = 'geo';
			geo_refused = true;
			geo_via = 'marker';
		} else if (waf === 'waf_challenge') {
			/* 200 с challenge-страницей — путь ОТКРЫТ (настоящий браузер
			 * проходит challenge), приложение не отдало контент. Не успех,
			 * не цензура (B5.8/87). */
			app_state = 'waf_challenge';
			kind = 'waf';
			ok = true;
		} else {
			app_state = 'ok';
			ok = true;
		}
	} else if (cls === 'block' && r.rc === 0) {
		net = true;
		waf = waf_state(r.code, r.body);
		if (waf === 'waf_challenge') {
			/* 4xx с challenge-маркерами: запрос ДОШЁЛ до реального сервиса —
			 * путь открыт, клиентская форма — проблема (не цензура). */
			app_state = 'waf_challenge';
			kind = 'waf';
			ok = true;
		} else if (waf === 'waf_rate_limit') {
			app_state = 'waf_rate_limit';
			kind = 'waf_rl';
			ok = true;
		} else {
			const sig = body_sig(r.body, extra_markers);
			if (sig.state === 'sigpage') {
				app_state = 'blockpage';
				kind = 'sigpage';
			} else if (sig.state === 'geo_refused') {
				app_state = 'geo_refused';
				kind = 'geo';
				geo_refused = true;
				geo_via = 'marker';
			} else if (r.code === '451') {
				/* 451 Unavailable For Legal Reasons — юридический гео-отказ
				 * источника (в RU-контексте), но маркеров нет — уверенность
				 * средняя (451 бывает и DMCA-блоком). */
				app_state = 'geo_refused';
				kind = 'geo';
				geo_refused = true;
				geo_via = '451';
			} else if (r.code === '403' || r.code === '406') {
				/* 403/406 БЕЗ маркеров — НЕ доказательство DPI/гео (55):
				 * origin может отказать легально. Отдельное состояние. */
				app_state = 'waf_origin_denied';
				kind = 'hardcode';
			} else if (int(r.code) >= 500) {
				/* 5xx: путь доказанно открыт, ОТКАЗЫВАЕТ ИСТОЧНИК (73). */
				app_state = 'server_error';
				kind = 'server';
				ok = true;
			} else {
				/* 404 на корне CDN, 421 у API — путь сам по себе работает (73). */
				app_state = 'ok';
				ok = true;
			}
		}
	}
	/* cls === 'fail': ответа нет — kind уже несёт транспортную причину. */

	const tsec = (r.tsec != null) ? ('' + r.tsec) : null;
	const slow = !!(ok && tsec != null && (tsec + 0.0) > SLOW_SEC);
	return { code: r.code, rc: r.rc, tsec: tsec, ok: ok, net: net,
		app_state: app_state, kind: kind, geo_refused: geo_refused,
		geo_via: geo_via, waf: waf, trust: r.trust || null, slow: slow };
};

/* ── ЕДИНЫЙ классификатор причин (routing_verdict ≠ cause_verdict) ──
 *
 * ВХОД facts:
 *   svc          — 'youtube'|'discord'|...|'ru_control'|'custom' (семантика контролей)
 *   dns          — { differs, poison, plain_ip } (poison = ПОДТВЕРЖДЁН дифференциальной пробой)
 *   direct/proxy/live/api_geo — формы classify_path() или null (не измерялось)
 *   exit_blocked — регион выхода настроенного пути в списке отказа сервиса (google_ai)
 *   inbounds     — { direct, proxy, mixed } — какие входы существуют (полнота картины)
 *
 * ВЫХОД: { verdict, geo_side, recommend, cause }
 *   verdict/geo_side/recommend — routing-слой (таксономия Ф8-W2, ключи прежние —
 *   UI-совместимость); cause — { type, confidence, evidence[] } | null.
 *
 * Дифференциальная дисциплина (55/75/76): причина «провайдер» доказывается
 * ТОЛЬКО разницей путей (direct сломан + proxy жив). Одинаковый провал обоих
 * путей = inconclusive — честное «причина не установлена». */
export function diag_cause(facts) {
	const svc = '' + (facts.svc || '');
	const d = facts.direct || null;
	const p = facts.proxy || null;
	const l = facts.live || null;
	const ag = facts.api_geo || null;
	const dns = facts.dns || {};
	const inb = facts.inbounds || {};
	const exit_blocked = !!facts.exit_blocked;

	const d_ok = !!(d && d.ok);
	const p_ok = !!(p && p.ok);
	const l_ok = !!(l && l.ok);
	const d_geo = !!(d && d.geo_refused);
	const p_geo = !!(p && p.geo_refused);
	/* «ответил» = came headers вообще (даже если потом сброс посреди цепочки) */
	const d_ans = !!(d && d.code !== '000');
	const l_ans = !!(l && l.code !== '000');

	const ev = [];
	const add_ev = (s) => { push(ev, s); };

	/* ── routing-лестница (таксономия Ф8-W2 + фиксы 73/75) ── */
	let verdict = 'unknown';
	let geo_side = null;

	if (svc === 'ru_control') {
		verdict = (d_ans && l_ans) ? 'opens_direct' : 'control_fail';
	} else if (exit_blocked) {
		verdict = 'geo_blocked';
		geo_side = 'exit';
	} else if (ag && ag.geo_refused) {
		verdict = 'geo_blocked';
		geo_side = 'exit';
	} else if (l_ok) {
		verdict = d_ok ? 'opens_direct' : 'works_live';
	} else if (!inb.direct && !inb.proxy && !inb.mixed) {
		verdict = 'down';
	} else if (d_geo && p_geo) {
		verdict = 'geo_blocked';
		geo_side = 'both';
	} else if (p_geo) {
		verdict = 'geo_blocked';
		geo_side = 'exit';
	} else if (d_geo) {
		verdict = 'geo_blocked';
		geo_side = 'remote';
	} else if (d_ok && p_ok) {
		verdict = 'config_broken';
	} else if (d_ok && p != null && !p_ok) {
		verdict = 'main_path_fail';
	} else if (p == null && !inb.proxy && !inb.mixed) {
		/* основной путь в принципе не измеряем — частичная картина, не «узел сломан» */
		verdict = 'partial';
	} else if (!inb.direct) {
		verdict = 'partial';
	} else if (!d_ok && p_ok) {
		if (dns.poison || (d.kind === 'resolve' && dns.plain_ip))
			verdict = 'dns_poison';
		else if (d.kind === 'tls_dpi')
			/* дифференциальное ОСНОВАНИЕ (75/76): прямой сброс + живой прокси */
			verdict = 'needs_strategy';
		else
			verdict = 'needs_proxy';
	} else if (!d_ok && !p_ok) {
		/* оба упали — дифференциала нет (75/76): «needs_strategy по tls_dpi на
		 * любом пути» был ложью; честно — недоступен, причина не установлена */
		verdict = 'down';
	} else {
		verdict = 'unknown';
	}

	/* ── cause-лестница (единая таксономия причин) ── */
	let ctype = null;
	let cconf = null;

	const _tls_evidence = (path, label) => {
		add_ev(label + ': TLS-сброс после ClientHello (SNI-DPI), код ' + (path.code || '000'));
	};

	if (verdict === 'geo_blocked') {
		ctype = 'origin_geo_restriction';
		if (geo_side === 'both') {
			cconf = 'high';
			add_ev('источник отказывает и с прямого выхода (RU), и с текущего прокси-выхода');
		} else if (geo_side === 'exit') {
			cconf = 'high';
			if (exit_blocked)
				add_ev('регион выхода настроенного пути в списке отказа сервиса');
			else if (ag && ag.geo_refused)
				add_ev('API источника отвечает отказом региона (' + (ag.code || '?') + ')');
			else
				add_ev('прямой путь открывает, а текущий прокси-выход источник отказывает');
		} else {
			/* remote */
			if (d && d.geo_via === 'marker') {
				cconf = 'high';
				add_ev('гео-отказ маркерами в теле с прямого пути, прокси-выход источник принимает');
			} else {
				cconf = 'medium';
				add_ev('451 (Unavailable For Legal Reasons) с прямого пути — юридический гео-отказ, маркеров нет');
			}
		}
	} else if (verdict === 'dns_poison') {
		ctype = 'dns_interference';
		cconf = dns.poison ? 'high' : 'medium';
		if (dns.poison)
			add_ev('роутер-резолвер даёт другой адрес: с ним прямой путь ломается, plain-адрес работает');
		else
			add_ev('прямой путь не резолвит, plain-резолвер отвечает — разрыв DNS-видов');
	} else if (verdict === 'needs_strategy') {
		ctype = 'isp_interference';
		cconf = 'high';
		_tls_evidence(d, 'прямой путь');
		add_ev('через прокси ресурс открывается — дифференциальное подтверждение провайдер-блокировки');
	} else if (verdict === 'needs_proxy') {
		/* прямой путь сломан, прокси жив — разбираем ЧТО именно сломано */
		if (d && d.rc !== 0 && d.kind === 'tls_dpi') {
			ctype = 'isp_interference';
			cconf = 'high';
			_tls_evidence(d, 'прямой путь');
			add_ev('через прокси ресурс открывается — дифференциальное подтверждение');
		} else if (d && d.rc !== 0 && d.kind === 'timeout') {
			ctype = 'isp_interference';
			cconf = 'medium';
			add_ev('прямой путь молчит (дроп пакетов), прокси открывает — дроп может быть и транзитным');
		} else if (d && d.app_state === 'blockpage') {
			if (d.trust === 'bad_cert') {
				ctype = 'isp_interference';
				cconf = 'high';
				add_ev('страница-заглушка с сертификатом, не проходящим проверку — перехват TLS');
			} else {
				ctype = 'isp_interference';
				cconf = 'medium';
				add_ev('страница-заглушка (стиль блокировки) вместо ресурса');
			}
		} else if (d && d.app_state === 'waf_origin_denied') {
			if (d.trust === 'bad_cert') {
				ctype = 'isp_interference';
				cconf = 'high';
				add_ev('ответ ' + (d.code || '?') + ' с чужим сертификатом — подмена, не источник');
			} else {
				ctype = 'origin_ip_policy';
				cconf = 'low';
				add_ev('отказ ' + (d.code || '?') + ' только с прямого пути без маркеров гео/WAF — геоограничение или политика источника к IP/ASN, различить нельзя');
			}
		} else if (d && d.app_state === 'geo_refused') {
			/* сюда не попадаем (гео перехватывается раньше в routing), страховка */
			ctype = 'origin_geo_restriction';
			cconf = 'medium';
		} else if (d && d.app_state === 'server_error') {
			ctype = 'inconclusive';
			cconf = 'low';
			add_ev('источник отвечает ' + (d.code || '?') + ' только с прямого пути');
		} else if (d && d.kind === 'resolve') {
			ctype = 'dns_interference';
			cconf = 'medium';
			add_ev('прямой путь не резолвит, прокси-путь (резолв на туннельном конце) работает');
		} else {
			ctype = 'inconclusive';
			cconf = 'low';
			add_ev('прямой путь не открывает, прокси открывает — транспортная причина: ' + ((d && d.kind) || 'неизвестно'));
		}
	} else if (verdict === 'main_path_fail') {
		if (p && p.app_state === 'server_error') {
			ctype = 'inconclusive';
			cconf = 'low';
			add_ev('основной путь получает ' + (p.code || '?') + ' от источника, прямой путь работает');
		} else {
			ctype = 'client_filtering';
			cconf = 'high';
			add_ev('прямой путь работает, основной путь (узел) не открывает ресурс — узел/конфигурация');
		}
	} else if (verdict === 'config_broken') {
		ctype = 'client_filtering';
		cconf = 'high';
		add_ev('оба bare-пути открывают ресурс, настроенный путь не доставляет — правило/стратегия/выученный список/движок');
	} else if (verdict === 'down') {
		/* оба пути упали — дифференциала нет (75/76) */
		const both_server = !!(d && p && d.app_state === 'server_error' && p.app_state === 'server_error');
		const both_resolve = !!(d && p && d.kind === 'resolve' && p.kind === 'resolve');
		const both_cut = !!(d && p && (d.kind === 'tls_dpi' || d.kind === 'timeout') &&
			(p.kind === 'tls_dpi' || p.kind === 'timeout'));
		if (both_server) {
			ctype = 'remote_failure';
			cconf = 'high';
			add_ev('источник отвечает ' + (d.code || '?') + ' на обоих путях — сервис недоступен на удалённой стороне');
		} else if (both_cut) {
			ctype = 'inconclusive';
			cconf = 'medium';
			add_ev('оба пути режутся одинаково (' + (d.kind || '?') + ') — локальный DPI или сбой/защита удалённой стороны, различить нельзя');
		} else if (both_resolve) {
			ctype = 'inconclusive';
			cconf = 'medium';
			add_ev('DNS не отвечает ни с одного резолвера — домен мёртв или DNS недоступен');
		} else {
			ctype = 'inconclusive';
			cconf = 'low';
			add_ev('оба пути не открывают (прямой: ' + ((d && d.kind) || '—') + ', прокси: ' + ((p && p.kind) || '—') + ')');
		}
	} else if (verdict === 'partial') {
		/* измерен только один путь — причина по нему, уверенность ограничена */
		const only = d || p || l;
		if (only && only.kind === 'tls_dpi') {
			ctype = 'isp_interference';
			cconf = 'low';
			_tls_evidence(only, 'измеренный путь');
			add_ev('другие пути не измерялись — дифференциального подтверждения нет');
		} else if (only && only.app_state === 'server_error') {
			ctype = 'remote_failure';
			cconf = 'medium';
			add_ev('источник отвечает ' + (only.code || '?') + ' (измерен один путь)');
		} else if (only && only.geo_refused) {
			ctype = 'origin_geo_restriction';
			cconf = 'medium';
			add_ev('гео-отказ на измеренном пути');
		} else if (only && only.waf) {
			ctype = 'origin_waf';
			cconf = 'medium';
			add_ev('challenge-страница от источника');
		} else {
			ctype = 'inconclusive';
			cconf = 'low';
			add_ev('измерены не все пути — картина неполная');
		}
	} else if (verdict === 'control_fail') {
		ctype = 'inconclusive';
		cconf = 'medium';
		add_ev('RU-контроль не открылся напрямую — проверять интернет/RU-protect, не маршрутизацию');
	} else if (verdict === 'opens_direct' || verdict === 'works_live') {
		/* путь доставляет — причины НЕТ, но фиксируем честные состояния (73/87) */
		if (l && l.waf === 'waf_challenge') {
			ctype = 'origin_waf';
			cconf = 'high';
			add_ev('challenge-страница от источника (код ' + (l.code || '?') + ') — путь открыт, клиентская форма запроса не проходит');
		} else if (l && l.waf === 'waf_rate_limit') {
			ctype = 'origin_waf';
			cconf = 'high';
			add_ev('источник ограничивает частоту (429) на настроенном пути');
		} else if (l && l.app_state === 'server_error') {
			if (d_ok && p_ok && d && d.app_state === 'ok' && p && p.app_state === 'ok') {
				/* bare-пути отдали контент, 5xx только на настроенном пути —
				 * источник не «лежит», он отказывает ИМЕННО этому выходу */
				ctype = 'inconclusive';
				cconf = 'low';
				add_ev('источник отвечает ' + (l.code || '?') + ' только на настроенном пути (bare-пути отвечают) — политика источника к IP выхода или приложение');
			} else {
				ctype = 'remote_failure';
				cconf = 'high';
				add_ev('источник отвечает ' + (l.code || '?') + ' на настроенном пути — путь открыт, сервис недоступен');
			}
		} else if (d && d.app_state === 'server_error' && p && p.app_state === 'server_error') {
			ctype = 'remote_failure';
			cconf = 'high';
			add_ev('источник отвечает ' + (d.code || '?') + ' на обоих bare-путях');
		} else if (d && d.waf === 'waf_challenge') {
			ctype = 'origin_waf';
			cconf = 'medium';
			add_ev('challenge-страница от источника на прямом пути (прокси-путь проходит)');
		} else {
			ctype = null;
		}
	} else {
		ctype = 'inconclusive';
		cconf = 'low';
		add_ev('данных недостаточно для причины');
	}

	/* ── рекомендация (routing-слой; коды прежние — UI-совместимость) ── */
	let recommend = 'none';
	switch (verdict) {
	case 'opens_direct':
	case 'works_live':
		recommend = (svc === 'google_ai') ? 'ai_full' : 'none';
		break;
	case 'dns_poison': recommend = 'dns'; break;
	case 'needs_proxy': recommend = 'rule'; break;
	case 'needs_strategy': recommend = 'strategy'; break;
	case 'geo_blocked':
		recommend = (geo_side === 'exit') ? 'node_exit'
			: (geo_side === 'both') ? 'node_both' : 'node';
		break;
	case 'main_path_fail': recommend = 'main_path'; break;
	case 'config_broken': recommend = 'config_broken'; break;
	case 'control_fail': recommend = 'anomaly'; break;
	default: recommend = 'none'; break;
	}

	return {
		verdict: verdict,
		geo_side: geo_side,
		recommend: recommend,
		cause: ctype ? { type: ctype, confidence: cconf, evidence: ev } : null
	};
};

/* ── Selftest (таблица кейсов; без fs/shell — чистая классификация) ── */

const _path = (over) => {
	const base = { code: '000', rc: 0, tsec: null, ok: false, net: false,
		app_state: null, kind: null, geo_refused: false, geo_via: null,
		waf: null, trust: null, slow: false };
	for (let k in over)
		base[k] = over[k];
	return base;
};

const _ok200 = () => _path({ code: '200', rc: 0, ok: true, net: true, app_state: 'ok' });

/* null-безопасный доступ к cause в ожиданиях: регрессия даёт FAIL, а не крэш */
const _C = (rr) => rr.cause || { type: null, confidence: null };

export function selftest() {
	const pass = [];
	const fail = [];
	const t = (name, cond) => {
		if (cond)
			push(pass, name);
		else
			push(fail, name);
	};

	/* classify_path: единицы */
	let cp = classify_path({ code: '200', rc: 0, tsec: '0.3', body: 'hello world' }, false, null);
	t('cp 200 clean ok', cp.ok === true && cp.net === true && cp.app_state === 'ok' && cp.kind == null);
	cp = classify_path({ code: '301', rc: 35, tsec: '1.1', body: '' }, false, null);
	t('cp mid-chain reset not net', cp.ok === false && cp.net === false && cp.kind === 'tls_dpi');
	cp = classify_path({ code: '200', rc: 0, tsec: '0.2', body: 'Just a moment...' }, false, null);
	t('cp 200 waf challenge', cp.waf === 'waf_challenge' && cp.ok === true && cp.net === true && cp.kind === 'waf');
	cp = classify_path({ code: '403', rc: 0, tsec: '0.2', body: 'Just a moment...' }, false, null);
	t('cp 403 waf markers path open', cp.ok === true && cp.app_state === 'waf_challenge');
	cp = classify_path({ code: '429', rc: 0, tsec: '0.2', body: '' }, false, null);
	t('cp 429 rate limit', cp.waf === 'waf_rate_limit' && cp.kind === 'waf_rl' && cp.ok === true);
	cp = classify_path({ code: '503', rc: 0, tsec: '0.4', body: 'oops' }, false, null);
	t('cp 503 server_error path ok', cp.ok === true && cp.net === true && cp.app_state === 'server_error' && cp.kind === 'server');
	cp = classify_path({ code: '404', rc: 0, tsec: '0.2', body: 'nope' }, false, null);
	t('cp 404 path ok (73)', cp.ok === true && cp.app_state === 'ok');
	cp = classify_path({ code: '403', rc: 0, tsec: '0.2', body: 'nope' }, false, null);
	t('cp 403 bare no markers', cp.ok === false && cp.app_state === 'waf_origin_denied' && cp.kind === 'hardcode');
	cp = classify_path({ code: '451', rc: 0, tsec: '0.2', body: '' }, false, null);
	t('cp 451 geo via 451', cp.geo_refused === true && cp.geo_via === '451');
	cp = classify_path({ code: '200', rc: 0, tsec: '0.2', body: 'доступ ограничен' }, false, null);
	t('cp 200 blockpage ru', cp.app_state === 'blockpage' && cp.kind === 'sigpage');
	cp = classify_path({ code: '200', rc: 0, tsec: '0.2', body: 'not available in your region' }, false, null);
	t('cp 200 geo marker', cp.geo_refused === true && cp.geo_via === 'marker');
	cp = classify_path({ code: '000', rc: 28, tsec: null, body: '' }, true, null);
	t('cp timeout kind', cp.kind === 'timeout' && cp.ok === false);
	cp = classify_path({ code: '000', rc: 7, tsec: null, body: '' }, false, null);
	t('cp rc7 no pin = resolve', cp.kind === 'resolve');
	cp = classify_path({ code: '000', rc: 7, tsec: null, body: '' }, true, null);
	t('cp rc7 pinned = tcp', cp.kind === 'tcp');
	t('trust kind bad_cert', trust_kind(60) === 'bad_cert' && trust_kind(19) === 'bad_cert');
	t('trust kind ok/reset', trust_kind(0) === 'ok' && trust_kind(35) === 'reset');

	/* diag_cause: таблица дифференциальных кейсов */
	const F = (over) => {
		const base = {
			svc: 'youtube',
			dns: { differs: false, poison: false, plain_ip: '1.2.3.4' },
			direct: null, proxy: null, live: null, api_geo: null,
			exit_blocked: false,
			inbounds: { direct: true, proxy: true, mixed: true }
		};
		for (let k in over)
			base[k] = over[k];
		return base;
	};

	let r = diag_cause(F({ direct: _ok200(), proxy: _ok200(), live: _ok200() }));
	t('all ok → opens_direct, no cause', r.verdict === 'opens_direct' && r.cause == null);

	r = diag_cause(F({
		direct: _path({ code: '000', rc: 35, kind: 'tls_dpi' }),
		proxy: _ok200(),
		live: _path({ code: '000', rc: 35, kind: 'tls_dpi' })
	}));
	t('direct reset + proxy ok → needs_strategy/isp high', r.verdict === 'needs_strategy' &&
		_C(r).type === 'isp_interference' && _C(r).confidence === 'high' && r.recommend === 'strategy');

	r = diag_cause(F({
		direct: _ok200(),
		proxy: _path({ code: '000', rc: 28, kind: 'timeout' }),
		live: _path({ code: '000', rc: 28, kind: 'timeout' })
	}));
	t('direct ok + main fail → main_path_fail/client_filtering', r.verdict === 'main_path_fail' &&
		_C(r).type === 'client_filtering' && r.recommend === 'main_path');

	r = diag_cause(F({ direct: _ok200(), proxy: _ok200(), live: _path({ code: '000', rc: 35, kind: 'tls_dpi' }) }));
	t('bare ok + live fail → config_broken/client_filtering', r.verdict === 'config_broken' &&
		_C(r).type === 'client_filtering' && _C(r).confidence === 'high');

	r = diag_cause(F({
		dns: { differs: true, poison: true, plain_ip: '1.2.3.4' },
		direct: _path({ code: '000', rc: 6, kind: 'resolve' }),
		proxy: _ok200(),
		live: _path({ code: '000', rc: 7, kind: 'tcp' })
	}));
	t('confirmed poison → dns_poison/dns_interference high', r.verdict === 'dns_poison' &&
		_C(r).type === 'dns_interference' && _C(r).confidence === 'high' && r.recommend === 'dns');

	r = diag_cause(F({
		direct: _path({ code: '200', rc: 0, ok: true, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: 'marker' }),
		proxy: _ok200(),
		live: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: 'marker' })
	}));
	t('direct geo marker + proxy ok → geo_blocked/remote geo high', r.verdict === 'geo_blocked' &&
		r.geo_side === 'remote' && _C(r).type === 'origin_geo_restriction' && _C(r).confidence === 'high' && r.recommend === 'node');

	r = diag_cause(F({
		direct: _ok200(),
		proxy: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: 'marker' }),
		live: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: 'marker' })
	}));
	t('proxy geo → geo_blocked/exit', r.verdict === 'geo_blocked' && r.geo_side === 'exit' &&
		_C(r).type === 'origin_geo_restriction' && r.recommend === 'node_exit');

	r = diag_cause(F({
		direct: _path({ code: '451', rc: 0, ok: false, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: '451' }),
		proxy: _ok200(),
		live: _path({ code: '451', rc: 0, ok: false, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: '451' })
	}));
	t('451 → geo medium confidence', r.verdict === 'geo_blocked' && r.geo_side === 'remote' &&
		_C(r).confidence === 'medium');

	r = diag_cause(F({
		direct: _path({ code: '403', rc: 0, ok: false, net: true, app_state: 'waf_origin_denied', kind: 'hardcode' }),
		proxy: _ok200(),
		live: _path({ code: '403', rc: 0, ok: false, net: true, app_state: 'waf_origin_denied', kind: 'hardcode' })
	}));
	t('403 bare + proxy ok → needs_proxy/origin_ip_policy low', r.verdict === 'needs_proxy' &&
		_C(r).type === 'origin_ip_policy' && _C(r).confidence === 'low');

	r = diag_cause(F({
		direct: _path({ code: '403', rc: 0, ok: false, net: true, app_state: 'waf_origin_denied', kind: 'hardcode', trust: 'bad_cert' }),
		proxy: _ok200(),
		live: _path({ code: '403', rc: 0, ok: false, net: true, app_state: 'waf_origin_denied', kind: 'hardcode' })
	}));
	t('403 + bad cert → isp_interference high (MITM)', r.verdict === 'needs_proxy' &&
		_C(r).type === 'isp_interference' && _C(r).confidence === 'high');

	r = diag_cause(F({
		direct: _path({ code: '000', rc: 35, kind: 'tls_dpi' }),
		proxy: _path({ code: '000', rc: 35, kind: 'tls_dpi' }),
		live: _path({ code: '000', rc: 35, kind: 'tls_dpi' })
	}));
	t('both reset → down/inconclusive (75 fix)', r.verdict === 'down' &&
		_C(r).type === 'inconclusive' && _C(r).confidence === 'medium');

	r = diag_cause(F({
		direct: _path({ code: '503', rc: 0, ok: true, net: true, app_state: 'server_error', kind: 'server' }),
		proxy: _path({ code: '503', rc: 0, ok: true, net: true, app_state: 'server_error', kind: 'server' }),
		live: _path({ code: '503', rc: 0, ok: true, net: true, app_state: 'server_error', kind: 'server' })
	}));
	t('all 5xx → opens_direct/remote_failure high (73)', r.verdict === 'opens_direct' &&
		_C(r).type === 'remote_failure' && _C(r).confidence === 'high');

	r = diag_cause(F({
		direct: _ok200(), proxy: _ok200(),
		live: _path({ code: '200', rc: 0, ok: true, net: true, app_state: 'waf_challenge', kind: 'waf', waf: 'waf_challenge' })
	}));
	t('200 challenge live → opens_direct/origin_waf high (87)', r.verdict === 'opens_direct' &&
		_C(r).type === 'origin_waf' && _C(r).confidence === 'high');

	r = diag_cause(F({
		svc: 'ru_control',
		direct: _ok200(), proxy: _ok200(), live: _ok200()
	}));
	t('ru_control answered → opens_direct/no cause', r.verdict === 'opens_direct' && r.cause == null);

	r = diag_cause(F({
		svc: 'ru_control',
		direct: _path({ code: '000', rc: 28, kind: 'timeout' }),
		proxy: _ok200(), live: _path({ code: '000', rc: 28, kind: 'timeout' })
	}));
	t('ru_control fail → control_fail/inconclusive', r.verdict === 'control_fail' &&
		_C(r).type === 'inconclusive' && r.recommend === 'anomaly');

	r = diag_cause(F({
		svc: 'google_ai', exit_blocked: true,
		direct: _ok200(), proxy: _ok200(), live: _ok200()
	}));
	t('exit blocked → geo_blocked/exit geo high', r.verdict === 'geo_blocked' && r.geo_side === 'exit' &&
		_C(r).type === 'origin_geo_restriction' && _C(r).confidence === 'high' && r.recommend === 'node_exit');

	r = diag_cause(F({
		svc: 'google_ai',
		direct: _ok200(), proxy: _ok200(),
		live: _ok200(),
		api_geo: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'geo_refused', kind: 'geo', geo_refused: true, geo_via: 'marker' })
	}));
	t('api geo refused → geo_blocked/exit', r.verdict === 'geo_blocked' && r.geo_side === 'exit' &&
		_C(r).type === 'origin_geo_restriction');

	r = diag_cause(F({
		inbounds: { direct: false, proxy: true, mixed: true },
		direct: null, proxy: _ok200(),
		live: _path({ code: '000', rc: 28, kind: 'timeout' })
	}));
	t('no direct inbound → partial/inconclusive low', r.verdict === 'partial' &&
		_C(r).type === 'inconclusive' && _C(r).confidence === 'low');

	r = diag_cause(F({
		inbounds: { direct: true, proxy: false, mixed: false },
		direct: _ok200(), proxy: null, live: _path({ code: '000', rc: 28, kind: 'timeout' })
	}));
	t('no proxy inbound + direct ok → partial (не main_path_fail)', r.verdict === 'partial');

	r = diag_cause(F({
		dns: { differs: false, poison: false, plain_ip: '1.2.3.4' },
		direct: _path({ code: '000', rc: 6, kind: 'resolve' }),
		proxy: _ok200(),
		live: _path({ code: '000', rc: 6, kind: 'resolve' })
	}));
	t('resolve fail + plain ip → dns_poison/dns medium', r.verdict === 'dns_poison' &&
		_C(r).type === 'dns_interference' && _C(r).confidence === 'medium');

	r = diag_cause(F({
		inbounds: { direct: true, proxy: true, mixed: true },
		direct: _ok200(), proxy: _ok200(),
		live: _path({ code: '503', rc: 0, ok: true, net: true, app_state: 'server_error', kind: 'server' })
	}));
	t('live 5xx only → opens_direct/inconclusive low', r.verdict === 'opens_direct' &&
		_C(r).type === 'inconclusive' && _C(r).confidence === 'low');

	r = diag_cause(F({
		direct: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'blockpage', kind: 'sigpage' }),
		proxy: _ok200(),
		live: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'blockpage', kind: 'sigpage' })
	}));
	t('blockpage 200 direct + proxy ok → isp medium', r.verdict === 'needs_proxy' &&
		_C(r).type === 'isp_interference' && _C(r).confidence === 'medium');

	r = diag_cause(F({
		direct: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'blockpage', kind: 'sigpage', trust: 'bad_cert' }),
		proxy: _ok200(),
		live: _path({ code: '200', rc: 0, ok: false, net: true, app_state: 'blockpage', kind: 'sigpage' })
	}));
	t('blockpage + bad cert → isp high', _C(r).type === 'isp_interference' && _C(r).confidence === 'high');

	r = diag_cause(F({ direct: null, proxy: null, live: null, inbounds: { direct: false, proxy: false, mixed: false } }));
	t('nothing measured → down/inconclusive', r.verdict === 'down' && _C(r).type === 'inconclusive');

	return { pass: length(pass), fail: length(fail), details: fail };
};
