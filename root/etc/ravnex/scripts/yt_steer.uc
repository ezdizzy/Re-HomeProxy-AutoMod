//
// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — YouTube negative-steering derivation (session 187, отчёт
// REPORT_s187_yt_ab_design.md §2). Pure derivation logic, no I/O here:
//
//   steer_pools(pools, now, current_suffix)
//     pools = the `pools` object of /var/run/ravnex/zapret_pools.json
//             (keys "sn-xxxx.googlevideo.com", rows {last_ts, alive, dead,
//             dead_whole}; dead_whole === 1 = the pool never delivered under
//             ANY measured strategy).
//     current_suffix = the sn-suffix of the stream the yt_stream cache
//             currently holds (never refused — it is what the player uses
//             right now).
//   → sorted array of KEYWORDS to refuse: "sn-<pool>." — substring form
//     (session 188): the matcher of the core AND mosdns file domain_sets is
//     label-boundary for plain suffixes, so "sn-xxxx.googlevideo.com" NEVER
//     matches the real host "rrN---sn-xxxx" (the cluster lives in ONE label).
//     The bare "sn-<pool>." keyword is a true substring and covers BOTH host
//     families (…sn-<pool>.googlevideo.com AND …sn-<pool>.c.youtube.com).
//
// Guards (must survive here, the feeder only reads):
//   - fresh only: now - last_ts <= 48 h (the catalog itself prunes at 30 d,
//     but a stale dead_whole must not steer);
//   - dead_whole strictly === 1 (alive/-dead of -1 = "touched, unmeasured"
//     and never steers; single dead edges (dead_whole 0) never steer);
//   - alive > 0 never steers (defense in depth against a stale verdict);
//   - the current-stream suffix never steers;
//   - if nothing qualifies → EMPTY list (the caller writes an empty file =
//     steering silently inactive; "the sole live pool" cannot be the only
//     survivor here because a live pool never carries dead_whole === 1).
//
// Authoritative gate: selftest() via the full path import (lesson 403).
'use strict';

const YT_FRESH_SEC = 172800;

/* ── сеанс 188 (решение юзера): автообучение мёртвых пулов из живых зомби ──
 * Google ротирует идентификаторы пулов CDN: новые кластеры (напр. aj5goc-5x,
 * aj5go5-5i) не попадают в свип-каталог и накапливают ЗОМБИ-соединения —
 * коннект к краю принят, но отдачи нет (0 B download), браузер держит их и
 * плодит. Зомби-скан чистой логикой: conns = массив connections clash-api.
 *   Зомби = живое (не closed) соединение к кластеру youtube
 *   (googlevideo./c.youtube.), обслуженное НЕ direct-out (RU-direct = норма),
 *   download < 2048 (рукопожатие без отдачи), возраст >= ZOMBIE_MIN_AGE с.
 *   Пул выучивается при >= ZOMBIE_MIN_HITS зомби-коннектах.
 *   current_suffix = суффикс живого стрима (никогда не учим — им играют сейчас).
 * → { learned: <обновлённый объект>, new_pools: [..] } — new_pools = пулы,
 *   только что перешагнувшие порог (сигнал «каталог изменился» для caller'а). */
const ZOMBIE_MIN_AGE = 60;
const ZOMBIE_MIN_HITS = 3;

/* ── сеанс 189: гвард ложного выучивания ЖИВОГО пула ──────────────────────
 * Сценарий (пойман живьём на трафике юзера 189): видео на живом пуле
 * стартует/буферизуется/столлится — конн открыт, download < 8192, возраст
 * уже > 60 с (столл юзера: 1383 Б за 2 мин). Детектор видит «зомби» и
 * копит хиты; три таких столла = пул «выучен» = DNS-отказ ЕДИНСТВЕННОМУ
 * живому пулу = полное падение видео. Лечится пул-уровневым свидетельством
 * контента: ЛЮБОЙ конн (даже direct-out, даже закрытый-в-этом-скане) с
 * download >= 8192 в любом скане = пул жив. Пока свидетельство свежее
 * (CONTENT_GUARD_SEC), выучивание заблокировано, а накопленные зомби-хиты
 * невыученного пула сбрасываются (столл — не мёртвость). Выученные пулы
 * гвард не трогает (авто-unlearn = отдельная ревизия, копилка). */
const CONTENT_DL = 8192;
const CONTENT_GUARD_SEC = 21600;

/* ── сеанс 189: RFC3339 → epoch ───────────────────────────────────────────
 * 🔴 КЛАСС БАГА (пойман живьём): clash-api несёт start как RFC3339-строку
 * ("2026-11-10T20:01:03.274594401Z") — int() парсит только ведущие "2026"
 * (ГОД), поэтому возраст-гейт ZOMBIE_MIN_AGE был всегда истинен и хиты
 * копились с первой секунды жизни конна. Селфтесты 188 это пропускали:
 * их conn() строил числовой start. Чистая арифметика days-from-civil
 * (Hinnant); ucode '/' дробный — все деления через int(); regex ERE
 * без (?:) и \d. Формат Go RFC3339Nano: дата T время [.дробь] (Z|±HH:MM). */
function rfc3339_to_epoch(s) {
	const str = '' + (s || '');
	const m = match(str, /^([0-9]+)-([0-9]+)-([0-9]+)[Tt ]([0-9]+):([0-9]+):([0-9]+)/);
	if (m == null || length(m) < 7)
		return 0;
	const y = int(m[1]), mo = int(m[2]), d = int(m[3]);
	const hh = int(m[4]), mm = int(m[5]), ss = int(m[6]);
	if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mm > 59 || ss > 60)
		return 0;
	let yy = y;
	if (mo <= 2) yy -= 1;
	const era = int((yy >= 0 ? yy : yy - 399) / 400);
	const yoe = yy - era * 400;
	const doy = int((153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5) + d - 1;
	const doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy;
	let ep = (era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss;
	const mz = match(str, /([+-])([0-9][0-9]):([0-9][0-9])$/);
	if (mz != null && length(mz) > 3) {
		const off = int(mz[2]) * 3600 + int(mz[3]) * 60;
		ep += (mz[1] === '+') ? -off : off;
	}
	return ep;
}

function conn_start_epoch(e) {
	const st = (e != null) ? e.start : null;
	if (st == null)
		return 0;
	/* ucode type() для целых = 'integer', для дробных = 'double' — строковый
	 * путь только для строк (RFC3339), всё остальное = числовой epoch. */
	if (type(st) !== 'string')
		return int(st);
	return rfc3339_to_epoch(st);
}

export function zombie_pools(conns, now, learned, current_suffix) {
	/* 🔴 клон входа (сеанс 188, пойман своим же селфтестом): мутация passed-in
	 * объекта алиасит state caller'а — rb-скан изменял ra.learned задним
	 * числом. Контракт: r.learned = НОВЫЙ объект, вход не трогается. */
	const src = (learned != null && type(learned) === 'object') ? learned : {};
	const out = { pools: {} };
	for (let pool in keys(src.pools || {})) {
		const pr = src.pools[pool];
		out.pools[pool] = (pr != null && type(pr) === 'object')
			? { first_ts: int(pr.first_ts || 0), last_ts: int(pr.last_ts || 0), hits: int(pr.hits || 0) }
			: { first_ts: 0, last_ts: 0, hits: 0 };
	}
	const cur = lc(trim('' + (current_suffix || '')));
	const touched = {};
	const content = {};
	for (let e in (conns || [])) {
		if (e == null || type(e) !== 'object')
			continue;
		if (e.closed)
			continue;
		const md = e.metadata || {};
		const host = lc(trim('' + (md.host || '')));
		if (!length(host))
			continue;
		if (!((index(host, 'googlevideo.') >= 0) || (index(host, '.c.youtube.') >= 0)))
			continue;
		/* the pool token follows '---' in rr-hosts (rr4---sn-aj5goc-5x...) or a
		 * dot in bare ones (sn-aj5goc-5x.c.youtube.com) */
		const m = match(host, /(^|---|\.)(sn-[^.]+)\./);
		if (m == null || length(m) < 3)
			continue;
		const pool = m[2];
		/* сеанс 189: свидетельство контента — считается ДО всех зомби-фильтров
		 * (в т.ч. direct-out: пул, качающий по direct, жив как пул). */
		if (int(e.download || 0) >= CONTENT_DL)
			content[pool] = true;
		if (length(cur) && index(cur, pool + '.') === 0)
			continue;
		const ch = e.chains || [];
		let direct = false;
		for (let c in ch)
			if (c === 'direct-out')
				direct = true;
		if (direct)
			continue;
		/* «нет КОНТЕНТА»: TLS-полёт (сертификат 3–5 КБ) и 404-тело — не контент;
		 * реальный видеопоток за 60 с = сотни КБ. Порог 8 КБ (живой калибровкой
		 * holders 188: TLS-ok-зомби несли ~4 КБ и должны учиться). */
		if (int(e.download || 0) >= CONTENT_DL)
			continue;
		if ((now - conn_start_epoch(e)) < ZOMBIE_MIN_AGE)
			continue;
		touched[pool] = int(touched[pool] || 0) + 1;
	}
	const new_pools = [];
	/* сеанс 189: контент-свидетельство пулов ВНЕ зомби-скана (в т.ч. текущий
	 * стрим, исключённый из зомби per-конном) — персистится в state, чтобы
	 * гвард контента жил и после того, как стрим ушёл с пула. Такие пулы
	 * попадают в state с hits=0 — merge каталога их не стирит (гейт hits>=3). */
	const cks = keys(content);
	sort(cks, (a, b) => (a < b ? -1 : (a > b ? 1 : 0)));
	for (let pool in cks) {
		if (touched[pool] != null)
			continue;
		const prev = out.pools[pool];
		const row = (prev != null && type(prev) === 'object') ? prev : { first_ts: now };
		row.last_ts = int(row.last_ts || 0) || now;
		row.last_content_ts = now;
		out.pools[pool] = row;
	}
	const ks = keys(touched);
	sort(ks, (a, b) => (a < b ? -1 : (a > b ? 1 : 0)));
	for (let pool in ks) {
		const prev = out.pools[pool];
		const was = (prev != null && type(prev) === 'object' && int(prev.hits || 0) >= ZOMBIE_MIN_HITS);
		const row = (prev != null && type(prev) === 'object') ? prev : { first_ts: now };
		row.last_ts = now;
		row.hits = int(row.hits || 0) + int(touched[pool]);
		if (content[pool])
			row.last_content_ts = now;
		/* сеанс 189: гвард контента — ДО перехода порога. Невыученный пул со
		 * свежим контентом не учится, его зомби-хиты обнуляются (столл живого
		 * пула — не мёртвость). Уже выученный (was) — не трогается. */
		const cg = int(row.last_content_ts || 0);
		if (!was && cg > 0 && (now - cg) < CONTENT_GUARD_SEC) {
			row.hits = 0;
			out.pools[pool] = row;
			continue;
		}
		out.pools[pool] = row;
		if (!was && int(row.hits) >= ZOMBIE_MIN_HITS)
			push(new_pools, pool);
	}
	return { learned: out, new_pools: new_pools };
};

export function current_suffix_from_host(host) {
	const h = lc(trim('' + (host || '')));
	if (!length(h))
		return '';
	const m = match(h, /^rr[0-9]+---(.+)$/);
	const base = (m != null && length(m) > 1) ? m[1] : h;
	return trim(base);
};

/* сеанс 188: pool core → substring keyword. "sn-aj5go5-53.googlevideo.com"
 * → "sn-aj5go5-53." (label-boundary trailing dot keeps the match tight:
 * "rr9---sn-aj5go5-53..." contains it; a longer pool sharing the prefix,
 * e.g. "sn-aj5go5-5x", does NOT contain "sn-aj5go5-53."). */
export function pool_keyword_from_suffix(suffix) {
	const s = trim('' + (suffix || ''));
	if (!length(s))
		return '';
	const m = match(s, /^([^.]+)\./);
	const core = (m != null && length(m) > 1) ? m[1] : s;
	return trim(core) + '.';
};

export function steer_pools(pools, now, current_suffix) {
	const out = [];
	if (pools == null || type(pools) !== 'object')
		return out;
	const cur = '' + (current_suffix || '');
	const ks = keys(pools);
	sort(ks, (a, b) => (a < b ? -1 : (a > b ? 1 : 0)));
	for (let k in ks) {
		const row = pools[k];
		if (row == null || type(row) !== 'object')
			continue;
		if (int(row.dead_whole || 0) !== 1)
			continue;
		if (int(row.alive || 0) > 0)
			continue;
		const ts = int(row.last_ts || 0);
		if (ts <= 0 || (now - ts) > YT_FRESH_SEC)
			continue;
		const suffix = current_suffix_from_host(k);
		if (!length(suffix))
			continue;
		const kw = pool_keyword_from_suffix(suffix);
		if (!length(kw))
			continue;
		/* the current-stream pool never steers: the keyword must be a PREFIX
		 * of the live stream suffix ("sn-x." starts "sn-x.googlevideo.com"
		 * and "sn-x.c.youtube.com" alike). */
		if (length(cur) && index(cur, kw) === 0)
			continue;
		push(out, kw);
	}
	return out;
};

export function selftest() {
	const pass = [], fail = [];
	const t = (name, cond) => (cond) ? push(pass, name) : push(fail, name);
	const NOW = 1000000;

	t('null pools -> empty', length(steer_pools(null, NOW, '')) === 0);
	t('garbage pools -> empty', length(steer_pools('x', NOW, '')) === 0);

	const good = { last_ts: NOW - 100, alive: 0, dead: 4, dead_whole: 1 };
	const fresh_dead = { last_ts: NOW - 100, alive: 0, dead: 4, dead_whole: 1 };
	const pools = {
		'sn-aaaa11.googlevideo.com': good,
		'sn-bbbb22.googlevideo.com': fresh_dead,
		'sn-cccc33.googlevideo.com': { last_ts: NOW - 200000, alive: 0, dead: 4, dead_whole: 1 },
		'sn-dddd44.googlevideo.com': { last_ts: NOW - 100, alive: 2, dead: 1, dead_whole: 0 },
		'sn-eeee55.googlevideo.com': { last_ts: NOW - 100, alive: -1, dead: -1, dead_whole: -1 },
		'sn-ffff66.googlevideo.com': { last_ts: NOW - 100, alive: 0, dead: 4, dead_whole: 1 }
	};
	const res = steer_pools(pools, NOW, '');
	t('fresh dead_whole selected', length(res) === 3);
	t('stale pool skipped', index(res, 'sn-cccc33.') < 0);
	t('alive pool skipped', index(res, 'sn-dddd44.') < 0);
	t('touched-only pool skipped', index(res, 'sn-eeee55.') < 0);
	t('keywords sorted', res[0] === 'sn-aaaa11.' && res[1] === 'sn-bbbb22.' && res[2] === 'sn-ffff66.');

	const res2 = steer_pools(pools, NOW, 'sn-bbbb22.googlevideo.com');
	t('current pool excluded (prefix match)', index(res2, 'sn-bbbb22.') < 0 && length(res2) === 2);

	t('keyword from suffix', pool_keyword_from_suffix('sn-aj5go5-53.googlevideo.com') === 'sn-aj5go5-53.');
	t('keyword covers youtube family', index('rr4---sn-aj5go5-53.c.youtube.com', 'sn-aj5go5-53.') >= 0);
	t('keyword prefix-tight', index('rr9---sn-aj5go5-5x.googlevideo.com', 'sn-aj5go5-53.') < 0);
	t('keyword bare core', pool_keyword_from_suffix('sn-nx5pm-3ggl') === 'sn-nx5pm-3ggl.');
	t('keyword empty', pool_keyword_from_suffix('') === '');
	t('suffix from rr host', current_suffix_from_host('rr5---sn-ajaig5-5h.googlevideo.com') === 'sn-ajaig5-5h.googlevideo.com');
	t('suffix passthrough', current_suffix_from_host('sn-nx5pm-3ggl.googlevideo.com') === 'sn-nx5pm-3ggl.googlevideo.com');
	t('suffix empty host', current_suffix_from_host('') === '');
	t('suffix casefold', current_suffix_from_host('RR1---sn-nx5pm-3ggl.googlevideo.COM') === 'sn-nx5pm-3ggl.googlevideo.com');

	/* ── zombie scan (session 188) ── */
	const conn = (host, dl, age, chains, closed) => ({
		metadata: { host },
		download: dl,
		start: NOW - age,
		chains: chains || ['zapret-out'],
		closed: !!closed
	});
	const r0 = zombie_pools(null, NOW, null, '');
	t('zombie: null conns -> empty', length(r0.new_pools) === 0 && length(keys(r0.learned.pools)) === 0);
	const conns1 = [
		conn('rr4---sn-aj5goc-5x.googlevideo.com', 0, 120),
		conn('rr4---sn-aj5goc-5x.googlevideo.com', 100, 90),
		conn('rr2---sn-aj5go5-5i.googlevideo.com', 0, 120),
		conn('rr1---sn-aj5go5-5i.googlevideo.com', 0, 120),
		conn('rr1---sn-aj5go5-5i.googlevideo.com', 0, 120),
		conn('rr4---sn-aj5goc-5x.c.youtube.com', 0, 150)
	];
	const r1 = zombie_pools(conns1, NOW, null, '');
	t('zombie: two pools crossed', length(r1.new_pools) === 2);
	t('zombie: keyword form keys', r1.learned.pools['sn-aj5goc-5x'] != null && r1.learned.pools['sn-aj5go5-5i'] != null);
	t('zombie: c.youtube folded into same pool', int(r1.learned.pools['sn-aj5goc-5x'].hits) === 3);
	t('zombie: no direct-out zombies', (function () {
		const d = [conn('rr9---sn-dddd99.googlevideo.com', 0, 300, ['direct-out'])];
		const rd = zombie_pools(d, NOW, r1.learned, '');
		return rd.learned.pools['sn-dddd99'] == null;
	})());
	t('zombie: real download excluded (content evidence instead)', (function () {
		const d = [conn('rr9---sn-aaaa77.googlevideo.com', 16384, 300)];
		const rd = zombie_pools(d, NOW, r1.learned, '');
		return rd.learned.pools['sn-aaaa77'] != null &&
			int(rd.learned.pools['sn-aaaa77'].hits) === 0 &&
			int(rd.learned.pools['sn-aaaa77'].last_content_ts) === NOW &&
			length(rd.new_pools) === 0;
	})());
	t('zombie: too young excluded', (function () {
		const d = [conn('rr9---sn-bbbb88.googlevideo.com', 0, 30)];
		const rd = zombie_pools(d, NOW, r1.learned, '');
		return rd.learned.pools['sn-bbbb88'] == null;
	})());
	t('zombie: current stream pool excluded', (function () {
		const d = [
			conn('rr1---sn-nx5pm-3ggl.googlevideo.com', 0, 300),
			conn('rr2---sn-nx5pm-3ggl.googlevideo.com', 0, 300),
			conn('rr3---sn-nx5pm-3ggl.googlevideo.com', 0, 300)
		];
		const rd = zombie_pools(d, NOW, r1.learned, 'sn-nx5pm-3ggl.googlevideo.com');
		return rd.learned.pools['sn-nx5pm-3ggl'] == null;
	})());
	t('zombie: hits accumulate across scans', (function () {
		const d = [
			conn('rr9---sn-cccc66.googlevideo.com', 0, 120),
			conn('rr9---sn-cccc66.googlevideo.com', 0, 120)
		];
		const ra = zombie_pools(d, NOW, null, '');
		const rb = zombie_pools(d, NOW, ra.learned, '');
		return int(rb.learned.pools['sn-cccc66'].hits) === 4 && length(rb.new_pools) === 1 && int(ra.learned.pools['sn-cccc66'].hits) === 2;
	})());
	t('zombie: closed conns skipped', (function () {
		const d = [conn('rr9---sn-dddd55.googlevideo.com', 0, 120, null, true)];
		const rd = zombie_pools(d, NOW, null, '');
		return rd.learned.pools['sn-dddd55'] == null;
	})());
	t('zombie: unrelated host skipped', (function () {
		const d = [conn('example.com', 0, 300)];
		const rd = zombie_pools(d, NOW, null, '');
		return length(keys(rd.learned.pools)) === 0;
	})());

	/* ── сеанс 189: RFC3339 age gate (живой баг-класс int('2026-…')=2026) ── */
	t('epoch: live sample 188/189', rfc3339_to_epoch('2026-11-10T20:01:03.274594401Z') === 1794340863);
	t('epoch: unix zero', rfc3339_to_epoch('1970-01-01T00:00:00Z') === 0);
	t('epoch: offset +03:00 folds to UTC', rfc3339_to_epoch('2026-11-10T23:01:03+03:00') === 1794340863);
	t('epoch: offset -05:00 folds to UTC', rfc3339_to_epoch('2026-11-10T15:01:03-05:00') === 1794340863);
	t('epoch: garbage -> 0', rfc3339_to_epoch('not-a-date') === 0 && rfc3339_to_epoch('') === 0);
	t('zombie: young RFC3339 conn NOT counted (int-trap regression)', (function () {
		const d = [{
			metadata: { host: 'rr9---sn-eeee77.googlevideo.com' },
			download: 0,
			start: '2026-11-10T20:01:03.274594401Z', /* 1794340863 */
			chains: ['zapret-out'],
			closed: false
		}];
		const rd = zombie_pools(d, 1794340863 + 30, null, ''); /* 30 с жизни */
		return rd.learned.pools['sn-eeee77'] == null;
	})());
	t('zombie: old RFC3339 conn counted', (function () {
		const d = [
			{ metadata: { host: 'rr9---sn-ffff88.googlevideo.com' }, download: 0,
			  start: '2026-11-10T20:01:03.274594401Z', chains: ['zapret-out'], closed: false },
			{ metadata: { host: 'rr8---sn-ffff88.googlevideo.com' }, download: 100,
			  start: '2026-11-10T20:01:03.274594401Z', chains: ['zapret-out'], closed: false },
			{ metadata: { host: 'rr7---sn-ffff88.googlevideo.com' }, download: 0,
			  start: '2026-11-10T20:01:03.274594401Z', chains: ['zapret-out'], closed: false }
		];
		const rd = zombie_pools(d, 1794340863 + 120, null, '');
		return length(rd.new_pools) === 1 && int(rd.learned.pools['sn-ffff88'].hits) === 3;
	})());
	t('zombie: numeric start still works (188 compat)', (function () {
		const d = [conn('rr9---sn-gggg99.googlevideo.com', 0, 120)];
		const rd = zombie_pools(d, NOW, null, '');
		return int(rd.learned.pools['sn-gggg99'].hits) === 1;
	})());

	/* ── сеанс 189: гвард контента (ложное выучивание живого пула) ── */
	t('guard: stalled conns + real content -> NOT learned, hits reset', (function () {
		const d = [
			/* 3 столла (класс юзера 189: старт видео на живом пуле) */
			conn('rr1---sn-aaaa11.googlevideo.com', 1383, 130),
			conn('rr2---sn-aaaa11.googlevideo.com', 6286, 200),
			conn('rr3---sn-aaaa11.googlevideo.com', 2376, 170),
			/* + реальный контент на другом крае того же пула */
			conn('rr4---sn-aaaa11.googlevideo.com', 2781377, 300)
		];
		const rd = zombie_pools(d, NOW, null, '');
		return rd.learned.pools['sn-aaaa11'] != null &&
			int(rd.learned.pools['sn-aaaa11'].hits) === 0 &&
			length(rd.new_pools) === 0 &&
			int(rd.learned.pools['sn-aaaa11'].last_content_ts) === NOW;
	})());
	t('guard: content evidence expires -> pool learnable again', (function () {
		const state = { pools: { 'sn-bbbb22': { first_ts: NOW - 40000, last_ts: NOW - 30000, hits: 0, last_content_ts: NOW - 30000 - CONTENT_GUARD_SEC } } };
		const d = [
			conn('rr1---sn-bbbb22.googlevideo.com', 0, 130),
			conn('rr2---sn-bbbb22.googlevideo.com', 0, 130),
			conn('rr3---sn-bbbb22.googlevideo.com', 0, 130)
		];
		const rd = zombie_pools(d, NOW, state, '');
		return length(rd.new_pools) === 1 && int(rd.learned.pools['sn-bbbb22'].hits) === 3;
	})());
	t('guard: content on ANY chain (direct too) protects the pool', (function () {
		const d = [
			conn('rr1---sn-cccc33.googlevideo.com', 0, 130),
			conn('rr2---sn-cccc33.googlevideo.com', 0, 130),
			conn('rr9---sn-cccc33.googlevideo.com', 16384, 300, ['direct-out'])
		];
		const rd = zombie_pools(d, NOW, null, '');
		return length(rd.new_pools) === 0 && int(rd.learned.pools['sn-cccc33'].hits) === 0;
	})());
	t('guard: ALREADY learned pool untouched by content guard', (function () {
		const state = { pools: { 'sn-dddd44': { first_ts: NOW - 400, last_ts: NOW - 300, hits: 6 } } };
		const d = [
			conn('rr1---sn-dddd44.googlevideo.com', 0, 130),
			conn('rr2---sn-dddd44.googlevideo.com', 2781377, 300)
		];
		const rd = zombie_pools(d, NOW, state, '');
		return int(rd.learned.pools['sn-dddd44'].hits) === 7 && length(rd.new_pools) === 0;
	})());
	t('guard: input state not mutated (clone contract 188)', (function () {
		const state = { pools: { 'sn-eeee55': { first_ts: 1, last_ts: 2, hits: 2 } } };
		const d = [conn('rr1---sn-eeee55.googlevideo.com', 0, 130)];
		zombie_pools(d, NOW, state, '');
		return int(state.pools['sn-eeee55'].hits) === 2;
	})());

	return { pass: length(pass), fail: length(fail), details: fail };
};
