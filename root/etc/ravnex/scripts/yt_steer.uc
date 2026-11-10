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
		if (int(e.download || 0) >= 8192)
			continue;
		if ((now - int(e.start || 0)) < ZOMBIE_MIN_AGE)
			continue;
		touched[pool] = int(touched[pool] || 0) + 1;
	}
	const new_pools = [];
	const ks = keys(touched);
	sort(ks, (a, b) => (a < b ? -1 : (a > b ? 1 : 0)));
	for (let pool in ks) {
		const prev = out.pools[pool];
		const was = (prev != null && type(prev) === 'object' && int(prev.hits || 0) >= ZOMBIE_MIN_HITS);
		const row = (prev != null && type(prev) === 'object') ? prev : { first_ts: now };
		row.last_ts = now;
		row.hits = int(row.hits || 0) + int(touched[pool]);
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
	t('zombie: real download excluded', (function () {
		const d = [conn('rr9---sn-aaaa77.googlevideo.com', 16384, 300)];
		const rd = zombie_pools(d, NOW, r1.learned, '');
		return rd.learned.pools['sn-aaaa77'] == null;
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

	return { pass: length(pass), fail: length(fail), details: fail };
};
