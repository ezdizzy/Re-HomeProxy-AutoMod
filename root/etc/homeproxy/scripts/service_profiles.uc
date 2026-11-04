// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Service Profiles (Ф6.3, план 20 §Ф6; аудит A.2, 60–62, 74, 79, 63/86, 64).
//
// Проверяется СЕРВИС, а не главная страница (аудит 62/74): профиль сервиса —
// это батарея компонентов (web/API/CDN/видео-поток/QUIC/gateway WS/Voice
// UDP-STUN), каждый компонент — честная проба через путь, которым сервис
// реально получают клиенты (LIVE-путь роутера).
//
// Профили — АДАПТЕРЫ над ядром диагностики (diag_core.uc, Ф6.1): классификация
// пути живёт там; здесь только определение батарей и ПРИСПОСОБЛЕНИЕ формы
// classify_path к компонентным вердиктам. Механики проб ЗДЕСЬ НЕТ — их делает
// раннер service_profile_run.uc (как wizard_scan.uc для сканера).
//
// Компонентные состояния (словарь UI):
//   working  — компонент доставляется;
//   degraded — путь ОТКРЫТ, приложение не обслуживает (WAF-challenge/429/5xx,
//              видео ниже порога играбельности) — НЕ отказ и НЕ смерть;
//   refused  — источник отказывает (гео-отказ/блок-страница/голый 403/406);
//   broken   — путь не доставляет (транспорт: TLS-DPI/таймаут/DNS/TCP);
//   unprobed — НЕ ПРОВЕРЕНО (нет инструмента/нет потока для пассивного
//              наблюдения) — не приравнивается к «пройдено» (аудит 91).
//
// Видео по битрейту-ОТНОСИТЕЛЬНО (79): YT_STREAM_MIN_SPEED = 128 КиБ/с не
// гарантирует воспроизведение — уровень считается от требуемого битрейта
// разрешений (360p ≈ 1 Мбит/с … 4K ≈ 20 Мбит/с) с запасом 25% на вариативность:
//   unusable < 1.25 Мбит/с · poor ≥ 1.25 · acceptable ≥ 3 · good ≥ 6 ·
//   excellent ≥ 12.
//
// Стабильность (60): повторная проба ключевого компонента (gateway WS) —
// два одинаковых успеха = стабильно, разброс = флапает, оба провала = сломан.
//
// Бюджеты (урок 197: пакеты проб ≤16 на Keenetic за проход движка; ручной
// прогон батарее может выходить за бюджет движка, но остаётся ограниченным):
// youtube 5 · discord ≤7 · telegram 3 · games 2; «все» = 16 базовых проб,
// дифференциал причины — ≤2 доп. пробы на ОТКАЗАВШИЙ компонент, потолок +8.
//
// QUIC-компонент YouTube — ПАССИВНОЕ наблюдение (Discovery Engine): активные
// HTTP/3-пробы НЕ возвращаются без новых данных (§2.5 плана) — отсутствие
// наблюдаемого QUIC-трафика это НЕ отказ, и снимок говорит об этом честно.
//
// Уроки учтены: 245 (export через `};`), 246 (нет undefined), 20/31
// (for-in = элементы), 26/27 (match только /регулярки/), 2/93 (хелперы выше),
// 251 (индексные циклы классические), 253 (falsy-ноль в диапазонах),
// 197 (модуль без активных проб/задержек — только определения и классификация).

'use strict';

/* ── Уровни видео по битрейту-относительно (аудит 79) ──
 * required_mbps — битрейт разрешения; headroom 1.25. */
export const VIDEO_TIERS = [
	{ level: 'excellent', min_mbps: 10,  plays: '1440p+/4K (частично)' },
	{ level: 'good',      min_mbps: 5,   plays: '1080p' },
	{ level: 'acceptable', min_mbps: 2.5, plays: '720p' },
	{ level: 'poor',      min_mbps: 1,   plays: '360p' }
];
const VIDEO_MIN_BYTES = 262144;   /* 256 КБ — иначе «передача не состоялась» */
const VIDEO_HEADROOM = 1.25;

/* Уровень по измеренной скорости (байт/с) → { level, plays }.
 * Ниже poor → unusable («ниже 360p — не играбельно»).
 * for-in по массиву даёт ЭЛЕМЕНТЫ (урок 20/31) — tier уже объект. */
export function video_level(speed_bps) {
	const mbps = (speed_bps + 0.0) * 8 / 1000000;
	for (let tier in VIDEO_TIERS)
		if (mbps >= (tier.min_mbps + 0.0) * VIDEO_HEADROOM)
			return { level: tier.level, plays: tier.plays, mbps: mbps };
	return { level: 'unusable', plays: 'ниже 360p — не играбельно', mbps: mbps };
};

/* ── Приспособление формы classify_path к компонентному вердикту ── */
export function judge_http(path) {
	if (path == null || type(path) !== 'object')
		return { state: 'unprobed', note: 'компонент не измерялся' };
	if (path.ok && path.app_state === 'ok')
		/* Медленно, но работает — деградация (путь открыт, отклик плохой). */
		return (path.slow != null && path.slow)
			? { state: 'degraded', note: 'медленно, но работает (возможно троттлинг)' }
			: { state: 'working', note: '' };
	if (path.waf === 'waf_challenge')
		return { state: 'degraded', note: 'challenge-страница WAF — путь открыт, клиентская форма не проходит' };
	if (path.waf === 'waf_rate_limit')
		return { state: 'degraded', note: 'источник ограничивает частоту (429) — путь открыт' };
	if (path.app_state === 'server_error')
		return { state: 'degraded', note: 'источник отвечает ' + (path.code || '?') + ' — путь открыт, сервис не обслуживает' };
	if (path.app_state === 'geo_refused')
		return { state: 'refused', note: 'гео-отказ источника' };
	if (path.app_state === 'blockpage')
		return { state: 'refused', note: 'страница-заглушка (стиль блокировки) вместо ресурса' };
	if (path.app_state === 'waf_origin_denied')
		return { state: 'refused', note: 'отказ ' + (path.code || '?') + ' без маркеров гео/WAF — политика источника к выходу' };
	/* !ok: транспортная причина в kind */
	return { state: 'broken', note: 'путь не доставляет: ' + (path.kind || 'неизвестно') };
};

/* Видео-компонент: r = { probed (есть ли URL), code, rc, size, tsec }.
 * rc 0/28 с частичной передачей — ЧЕСТНОЕ измерение (таймаут на медленном
 * канале не «смерть», если байты шли). */
export function judge_video(r) {
	if (r == null || type(r) !== 'object')
		return { state: 'unprobed', note: 'компонент не измерялся' };
	if (!r.probed)
		return { state: 'unprobed', note: 'нет видео-URL (innertube не отдал поток — проба пропущена честно)' };
	const code = trim('' + (r.code || '000'));
	const size = int(r.size) || 0;
	const tsec = (r.tsec != null) ? (r.tsec + 0.0) : 0;
	if (code === '000' || code === '0')
		return { state: 'broken', note: 'видео-хост не отвечает (транспорт)' };
	if (size < VIDEO_MIN_BYTES || tsec <= 0.2)
		return { state: 'unusable', note: 'передача не состоялась (' + int(size / 1024) + ' КБ) — поток не играбелен' };
	const speed = size / tsec;
	const lvl = video_level(speed);
	const state = (lvl.level === 'good' || lvl.level === 'excellent') ? 'working' : 'degraded';
	return { state: state, level: lvl.level, plays: lvl.plays,
		speed_bps: int(speed), note: 'уровень ' + lvl.level + ' (' + lvl.plays + ')' };
};

/* Gateway WebSocket (аудит 74): проверяется ИМЕННО WS Upgrade — HTTPS-GET
 * врёт. path — форма classify_path от сырого замера, raw_code — настоящий
 * код (101 в code_class не входит и нормализуется здесь). */
export function judge_ws(path, raw_code) {
	const rc = trim('' + (raw_code || ''));
	if (rc === '101')
		return { state: 'working', note: 'WS Upgrade 101 подтверждён — gateway жив' };
	const j = judge_http(path);
	if (j.state === 'working')
		return { state: 'degraded', note: 'HTTPS отвечает, но WS Upgrade не подтверждён (101 не получен)' };
	return j;
};

/* TCP-транспорт (Telegram MTProto, аудио-класс целей): по time_connect —
 * rc 28 двусмысленен (и connect-таймаут, и idle-таймаут), соединение
 * доказывает ТОЛЬКО time_connect > 0. */
export function judge_tcp(r) {
	if (r == null || type(r) !== 'object')
		return { state: 'unprobed', note: 'компонент не измерялся' };
	const tcon = (r.tcon != null) ? (r.tcon + 0.0) : 0;
	if (tcon > 0.000001)
		return { state: 'working', note: 'TCP-подключение установлено (транспорт; прикладной MTProto не проверялся)' };
	if ((int(r.rc) || 0) === 7)
		return { state: 'broken', note: 'TCP-подключение отклонено (RST/недоступно)' };
	return { state: 'broken', note: 'TCP не установлено (дроп пакетов или таймаут)' };
};

/* Voice UDP-STUN (аудит 60): активный STUN binding, если в системе есть
 * UDP-инструмент; иначе честное unprobed. */
export function judge_stun(r) {
	if (r == null || type(r) !== 'object')
		return { state: 'unprobed', note: 'компонент не измерялся' };
	if (!r.probed)
		return { state: 'unprobed', note: 'UDP-инструмент (nc -u) недоступен — компонент не проверен, это НЕ отказ' };
	if (r.ok)
		return { state: 'working', note: 'STUN binding получен — UDP-путь работает (Voice-релеи Discord требуют клиентский токен и отдельно не проверяются)' };
	return { state: 'broken', note: 'STUN не ответил — UDP-путь не работает' };
};

/* Пассивное QUIC-наблюдение (YouTube): r = { observed, flows, note } —
 * факт «видны ли UDP/443-потоки к хостам сервиса в моменте». */
export function judge_quic(r) {
	if (r == null || type(r) !== 'object')
		return { state: 'unprobed', note: 'наблюдение не выполнялось' };
	if (r.observed)
		return { state: 'working', note: 'наблюдаются QUIC-потоки (UDP/443) к хостам сервиса — ' + (r.note || '') };
	return { state: 'unprobed', note: 'QUIC-трафик к сервису в моменте не наблюдался — это НЕ отказ (клиент может не использовать QUIC); активные HTTP/3-пробы отключены (§2.5)' };
};

/* ── Определения профилей ──
 * kind: http | ws | video | tcp | stun | quic_passive | repeat.
 * Бюджет проб — метаданные для раннера. */
export const PROFILES = {
	youtube: {
		label: 'YouTube',
		note: 'веб/API/CDN/видео-поток/QUIC — проверяется сервис, а не главная страница',
		probes: 5,
		components: [
			{ id: 'web',   label: 'Веб (www.youtube.com)',      kind: 'http', url: 'https://www.youtube.com/', host: 'www.youtube.com' },
			{ id: 'api',   label: 'API (youtubei)',             kind: 'http', url: 'https://youtubei.googleapis.com/', host: 'youtubei.googleapis.com' },
			{ id: 'cdn',   label: 'CDN (i.ytimg.com)',          kind: 'http', url: 'https://i.ytimg.com/generate_204', host: 'i.ytimg.com' },
			{ id: 'video', label: 'Видео-поток (googlevideo)',  kind: 'video' },
			{ id: 'quic',  label: 'QUIC (HTTP/3)',              kind: 'quic_passive' }
		]
	},
	discord: {
		label: 'Discord',
		note: 'веб/API/gateway WebSocket/CDN/Voice UDP-STUN/стабильность',
		probes: 6,
		components: [
			{ id: 'web',     label: 'Веб (discord.com)',        kind: 'http', url: 'https://discord.com/', host: 'discord.com' },
			{ id: 'api',     label: 'API (v10/gateway)',        kind: 'http', url: 'https://discord.com/api/v10/gateway', host: 'discord.com' },
			{ id: 'gateway', label: 'Gateway WebSocket',        kind: 'ws',   url: 'https://gateway.discord.gg/?v=10&encoding=json', host: 'gateway.discord.gg' },
			{ id: 'cdn',     label: 'CDN (cdn.discordapp.com)', kind: 'http', url: 'https://cdn.discordapp.com/', host: 'cdn.discordapp.com' },
			{ id: 'voice',   label: 'Voice UDP-STUN',           kind: 'stun', host: 'stun.l.google.com', port: 19302 },
			{ id: 'stability', label: 'Стабильность gateway',   kind: 'repeat', target: 'gateway' }
		]
	},
	telegram: {
		label: 'Telegram',
		note: 'веб + MTProto-датацентры (TCP-транспорт к известным адресам DC)',
		probes: 3,
		components: [
			{ id: 'web', label: 'Веб (web.telegram.org)', kind: 'http', url: 'https://web.telegram.org/', host: 'web.telegram.org' },
			{ id: 'dc1', label: 'DC2 (149.154.167.51)',   kind: 'tcp', host: '149.154.167.51', port: 443 },
			{ id: 'dc2', label: 'DC4 (149.154.175.53)',   kind: 'tcp', host: '149.154.175.53', port: 443 }
		]
	},
	games: {
		label: 'Игры и лаунчеры',
		note: 'магазины/API лаунчеров (TCP/443); игровой UDP видит Discovery (пассивно) — Steam/Epic-клиенты используют свои UDP-порты динамически',
		probes: 2,
		components: [
			{ id: 'steam_api',   label: 'Steam API',   kind: 'http', url: 'https://api.steampowered.com/', host: 'api.steampowered.com' },
			{ id: 'steam_store', label: 'Steam Store', kind: 'http', url: 'https://store.steampowered.com/', host: 'store.steampowered.com' }
		]
	}
};

export const PROFILE_KEYS = [ 'youtube', 'discord', 'telegram', 'games', 'all' ];

/* Базовый бюджет проб профиля (видео = 2 запроса: innertube + ranged-GET;
 * QUIC-наблюдение пассивное — проб не тратит). */
export function profile_probe_budget(name) {
	if (name === 'all') {
		let n = 0;
		for (let k in [ 'youtube', 'discord', 'telegram', 'games' ])
			n += (PROFILES[k] != null) ? PROFILES[k].probes : 0;
		return n;
	}
	return (PROFILES[name] != null) ? PROFILES[name].probes : 0;
};

/* ── Selftest (чистые judges + уровни видео) ── */
export function selftest() {
	const pass = [];
	const fail = [];
	const t = (name, cond) => {
		if (cond)
			push(pass, name);
		else
			push(fail, name);
	};

	/* video_level (79) */
	let vl = video_level(0.5 * 1000000 / 8);
	t('video unusable below 360p', vl.level === 'unusable');
	vl = video_level(1.3 * 1000000 / 8);
	t('video poor at 1.3 Mbps', vl.level === 'poor' && vl.plays === '360p');
	vl = video_level(3.2 * 1000000 / 8);
	t('video acceptable at 3.2 Mbps', vl.level === 'acceptable' && vl.plays === '720p');
	vl = video_level(7.0 * 1000000 / 8);
	t('video good at 7 Mbps', vl.level === 'good' && vl.plays === '1080p');
	vl = video_level(15.0 * 1000000 / 8);
	t('video excellent at 15 Mbps', vl.level === 'excellent');
	vl = video_level(2.9 * 1000000 / 8);
	t('video poor just under acceptable', vl.level === 'poor');

	/* judge_http — формы classify_path */
	const P = (over) => {
		const base = { code: '000', rc: 0, tsec: null, ok: false, net: false,
			app_state: null, kind: null, geo_refused: false, geo_via: null,
			waf: null, trust: null, slow: false };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let j = judge_http(P({ code: '200', rc: 0, ok: true, net: true, app_state: 'ok' }));
	t('http ok → working', j.state === 'working');
	j = judge_http(P({ code: '200', rc: 0, ok: true, net: true, app_state: 'ok', slow: true }));
	t('http slow → degraded', j.state === 'degraded');
	j = judge_http(P({ code: '200', rc: 0, ok: true, net: true, app_state: 'waf_challenge', waf: 'waf_challenge' }));
	t('http waf challenge → degraded', j.state === 'degraded');
	j = judge_http(P({ code: '503', rc: 0, ok: true, net: true, app_state: 'server_error', kind: 'server' }));
	t('http 5xx → degraded', j.state === 'degraded');
	j = judge_http(P({ code: '200', rc: 0, ok: false, net: true, app_state: 'geo_refused', geo_refused: true, kind: 'geo' }));
	t('http geo → refused', j.state === 'refused');
	j = judge_http(P({ code: '200', rc: 0, ok: false, net: true, app_state: 'blockpage', kind: 'sigpage' }));
	t('http blockpage → refused', j.state === 'refused');
	j = judge_http(P({ code: '403', rc: 0, ok: false, net: true, app_state: 'waf_origin_denied', kind: 'hardcode' }));
	t('http 403 bare → refused', j.state === 'refused');
	j = judge_http(P({ code: '000', rc: 35, kind: 'tls_dpi' }));
	t('http tls reset → broken', j.state === 'broken' && index(j.note, 'tls_dpi') >= 0);
	j = judge_http(null);
	t('http null → unprobed', j.state === 'unprobed');

	/* judge_ws (74) */
	j = judge_ws(null, '101');
	t('ws 101 → working', j.state === 'working');
	j = judge_ws(P({ code: '400', rc: 0, ok: true, net: true, app_state: 'ok' }), '200');
	t('ws https ok but no 101 → degraded', j.state === 'degraded');
	j = judge_ws(P({ code: '000', rc: 35, kind: 'tls_dpi' }), '000');
	t('ws transport fail → broken', j.state === 'broken');

	/* judge_video */
	j = judge_video({ probed: false });
	t('video unprobed honest', j.state === 'unprobed');
	j = judge_video({ probed: true, code: '000', rc: 7, size: 0, tsec: 1 });
	t('video dead transport → broken', j.state === 'broken');
	j = judge_video({ probed: true, code: '206', rc: 28, size: 200000, tsec: 2.0 });
	t('video tiny transfer unusable', j.state === 'unusable');
	j = judge_video({ probed: true, code: '206', rc: 0, size: 4000000, tsec: 2.0 });
	/* 4 MB / 2 s = 2 MB/s = 16 Мбит/с → excellent */
	t('video fast excellent', j.state === 'working' && j.level === 'excellent');
	j = judge_video({ probed: true, code: '206', rc: 28, size: 600000, tsec: 4.0 });
	/* 600 КБ / 4 с = 1.2 Мбит/с → unusable/граница poor */
	t('video slow honest from partial', j.state === 'unusable' || j.state === 'degraded');

	/* judge_tcp / judge_stun / judge_quic */
	j = judge_tcp({ rc: 28, tcon: 0.03 });
	t('tcp connected → working', j.state === 'working');
	j = judge_tcp({ rc: 28, tcon: 0 });
	t('tcp rc28 without connect → broken', j.state === 'broken');
	j = judge_tcp({ rc: 7, tcon: 0 });
	t('tcp refused → broken', j.state === 'broken');
	j = judge_stun({ probed: false });
	t('stun unprobed honest (91)', j.state === 'unprobed');
	j = judge_stun({ probed: true, ok: true });
	t('stun ok → working', j.state === 'working');
	j = judge_stun({ probed: true, ok: false });
	t('stun fail → broken', j.state === 'broken');
	j = judge_quic({ observed: true, note: '3 потока' });
	t('quic observed → working', j.state === 'working');
	j = judge_quic({ observed: false });
	t('quic not observed → unprobed, не отказ', j.state === 'unprobed');

	/* Профили структурно целы и в бюджете урока 197 для «all». */
	t('profiles defined', length(keys(PROFILES)) === 4);
	for (let pk in [ 'youtube', 'discord', 'telegram', 'games' ])
		t('profile ' + pk + ' has components', PROFILES[pk] != null && length(PROFILES[pk].components) > 0);
	t('all budget ≤ 16 (урок 197)', profile_probe_budget('all') <= 16);

	return { pass: length(pass), fail: length(fail), details: fail };
};
