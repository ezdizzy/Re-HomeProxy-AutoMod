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
//   → sorted array of suffixes to DNS-refuse (black-hole).
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

export function current_suffix_from_host(host) {
	const h = lc(trim('' + (host || '')));
	if (!length(h))
		return '';
	const m = match(h, /^rr[0-9]+---(.+)$/);
	const base = (m != null && length(m) > 1) ? m[1] : h;
	return trim(base);
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
		if (length(cur) && suffix === cur)
			continue;
		push(out, suffix);
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
	t('stale pool skipped', index(res, 'sn-cccc33.googlevideo.com') < 0);
	t('alive pool skipped', index(res, 'sn-dddd44.googlevideo.com') < 0);
	t('touched-only pool skipped', index(res, 'sn-eeee55.googlevideo.com') < 0);
	t('suffixes sorted', res[0] === 'sn-aaaa11.googlevideo.com' && res[1] === 'sn-bbbb22.googlevideo.com' && res[2] === 'sn-ffff66.googlevideo.com');

	const res2 = steer_pools(pools, NOW, 'sn-bbbb22.googlevideo.com');
	t('current suffix excluded', index(res2, 'sn-bbbb22.googlevideo.com') < 0 && length(res2) === 2);

	t('suffix from rr host', current_suffix_from_host('rr5---sn-ajaig5-5h.googlevideo.com') === 'sn-ajaig5-5h.googlevideo.com');
	t('suffix passthrough', current_suffix_from_host('sn-nx5pm-3ggl.googlevideo.com') === 'sn-nx5pm-3ggl.googlevideo.com');
	t('suffix empty host', current_suffix_from_host('') === '');
	t('suffix casefold', current_suffix_from_host('RR1---sn-nx5pm-3ggl.googlevideo.COM') === 'sn-nx5pm-3ggl.googlevideo.com');

	return { pass: length(pass), fail: length(fail), details: fail };
};
