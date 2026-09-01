#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — RU-geo database downloader/builder.
 *
 * Downloads plain-text RU network + domain databases and installs them as
 * /etc/homeproxy/resources/ru_geoip.txt + ru_geosite.txt (+ ru_geo.meta), then
 * regenerates the watched sing-box rule-set JSON files (ru_geoip.json /
 * ru_geosite.json via sync_ru_geo_rulesets) and drops the daemon reload marker.
 *
 * Sources (fallback order per resource):
 *   networks  GrimbirdUsers/ru-routing-dat data-geoip/ru.txt (v4+v6, ~25k CIDR)
 *             → jsDelivr CDN mirrors → ipdeny.com ru.zone (v4-only last resort)
 *   domains   GrimbirdUsers data-geosite/category-ru-whitelist, with `include:`
 *             recursion resolved against the same repo (v2ray geosite source
 *             format: domain:/full:/keyword: lines are kept verbatim; regexp
 *             lines and @attributes are dropped).
 *
 * NOTE: this ucode build has NO `throw` support and NO function hoisting —
 * errors are returned, includes are resolved with an explicit queue loop,
 * and helpers are declared above their callers.
 *
 * Called by the RPC automation_geo_update, by the daemon's hourly auto-update
 * check (geo_auto_update) and manually from a shell. Lock-guarded; safe to run
 * concurrently with the daemon (it only reads the final files).
 */

'use strict';

import { access, readfile, writefile, open, stat } from 'fs';
import { sync_ru_geo_rulesets } from 'homeproxy';

const RES = '/etc/homeproxy/resources';
const TMP = '/tmp/ru_geo';
const LOCK_DIR = '/tmp/ru_geo_lock';
const UPDATING = TMP + '/updating';
const RELOAD_MARKER = '/var/run/homeproxy/automation.reload_geo';
const LOG_FILE = '/var/run/homeproxy/automation.log';

const GEOIP_URLS = [
	'https://raw.githubusercontent.com/GrimbirdUsers/ru-routing-dat/main/data-geoip/ru.txt',
	'https://fastly.jsdelivr.net/gh/GrimbirdUsers/ru-routing-dat@main/data-geoip/ru.txt',
	'https://cdn.jsdelivr.net/gh/GrimbirdUsers/ru-routing-dat@main/data-geoip/ru.txt',
	'https://www.ipdeny.com/ipblocks/data/countries/ru.zone'
];
const GEOSITE_BASES = [
	'https://raw.githubusercontent.com/GrimbirdUsers/ru-routing-dat/main/data-geosite/',
	'https://fastly.jsdelivr.net/gh/GrimbirdUsers/ru-routing-dat@main/data-geosite/',
	'https://cdn.jsdelivr.net/gh/GrimbirdUsers/ru-routing-dat@main/data-geosite/'
];
const TOP_CAT = 'category-ru-whitelist';

function shellq(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function log(msg) {
	const line = `[${sprintf('%d', time())}] [GEO] ${msg}\n`;
	try {
		const fd = open(LOG_FILE, 'a');
		if (fd) { fd.write(line); fd.close(); }
	} catch (e) { /* best effort */ }
	print(line);
}

function fetch(url, dest) {
	system(`curl -sL --connect-timeout 10 --max-time 180 -o ${shellq(dest)} ${shellq(url)} 2>/dev/null`);
	return !!(access(dest) && stat(dest) && stat(dest).size > 0);
}

function read_lines(path) {
	if (!access(path))
		return [];
	let c = readfile(path);
	if (!c) return [];
	c = trim(c);
	if (!length(c)) return [];
	return filter(split(c, /[\r\n]/), (x) => length(trim(x)) && !match(trim(x), /^\s*#/));
}

/* Fetch the first URL that yields a non-empty body. Returns true/false. */
function fetch_any(dest, urls) {
	for (let u in urls) {
		system(`rm -f ${shellq(dest)}`);
		if (fetch(u, dest))
			return true;
	}
	return false;
}

function atomic_txt(path, content) {
	let tmp = path + '.tmp';
	writefile(tmp, content);
	system('mv -f ' + shellq(tmp) + ' ' + shellq(path));
}

/* Download one geosite category, strip regexp/@attribute lines, return its body
 * lines (no include resolution here — the queue loop in do_update does that). */
function fetch_cat_lines(cat) {
	let tmp = TMP + '/cat_' + cat;
	for (let b in GEOSITE_BASES) {
		if (fetch(b + cat, tmp)) {
			let lines = read_lines(tmp);
			let out = [];
			for (let i, l in lines) {
				l = trim(l);
				if (match(l, /^regexp:/))
					continue;
				/* strip v2ray @attribute suffixes: "domain:x @cn" -> "domain:x" */
				l = trim(replace(l, /@.*$/, ''));
				if (length(l))
					push(out, l);
			}
			system(`rm -f ${shellq(tmp)}`);
			return out;
		}
	}
	log(`warn: category '${cat}' could not be downloaded — skipped`);
	return null;
}

/* ── Main pipeline. Returns { err: null|string, geoip, geosite, categories } ── */
function do_update() {
	/* Networks */
	if (!fetch_any(TMP + '/geoip.txt', GEOIP_URLS))
		return { err: 'all RU-geoip sources are unreachable' };
	let v4 = 0, v6 = 0;
	let nets = [];
	for (let l in read_lines(TMP + '/geoip.txt')) {
		l = trim(l);
		if (!length(l) || match(l, /^\s*#/)) continue;
		if (match(l, /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)) {
			push(nets, l);
			v4++;
		} else if (match(l, /^[0-9a-fA-F:]+\/\d{1,3}$/)) {
			push(nets, lc(l));
			v6++;
		}
	}
	/* Sanity gate: a truncated/garbage download must never replace a good
	 * database (RU has >10k v4 prefixes even on the small lists). */
	if (v4 < 1000)
		return { err: sprintf('RU-geoip download failed validation (%d v4 networks)', v4) };

	/* Domains: resolve include: with an explicit QUEUE (no recursion — this
	 * ucode build's function declaration order/limits make recursion risky). */
	let geo_lines = [];
	let dom_seen = {};
	let cat_count = 0, cat_failed = 0;
	let queue = [ TOP_CAT ];
	let visited = {};
	let qi = 0;
	while (qi < length(queue) && qi < 64) {
		let cat = queue[qi];
		qi++;
		if (visited[cat]) continue;
		visited[cat] = true;
		let lines = fetch_cat_lines(cat);
		if (lines === null) { cat_failed++; continue; }
		cat_count++;
		for (let i, l in lines) {
			let m = match(l, /^include:(.+)$/);
			if (m) {
				let inc = trim(m[1]);
				if (!visited[inc] && length(inc) && qi < 64)
					push(queue, inc);
				continue;
			}
			if (dom_seen[l]) continue;
			dom_seen[l] = true;
			push(geo_lines, l);
		}
	}
	if (length(geo_lines) < 200)
		return { err: sprintf('RU-geosite download failed validation (%d domain entries)', length(geo_lines)) };

	/* Deduplicate + persist. */
	let doms = sort(keys(dom_seen));
	atomic_txt(RES + '/ru_geoip.txt', join('\n', nets) + '\n');
	atomic_txt(RES + '/ru_geosite.txt', join('\n', doms) + '\n');

	/* Meta (hand-built JSON: %.J printf is unsupported on this build). */
	atomic_txt(RES + '/ru_geo.meta', sprintf(
		'{"updated": %d, "geoip": %d, "geoip_v4": %d, "geoip_v6": %d, "geosite": %d, "categories": %d, "categories_failed": %d}\n',
		time(), v4 + v6, v4, v6, length(doms), cat_count, cat_failed));

	/* Regenerate the watched rule-set JSONs (stale-source check inside) and
	 * ping the daemon so it re-reads the databases. */
	sync_ru_geo_rulesets();
	try { writefile(RELOAD_MARKER, 'geo\n'); } catch (e) { /* tmpfs always writable */ }

	log(`RU-geo database updated: ${v4} v4 + ${v6} v6 networks, ${length(doms)} domain entries from ${cat_count} categories.`);
	return { err: null, geoip: v4 + v6, geosite: length(doms), categories: cat_count };
}

/* ── Main ────────────────────────────────────────────────────────────────── */
function main() {
	/* Lock: another update already running (RPC + daemon auto-update can race). */
	if (system(`mkdir ${shellq(LOCK_DIR)} 2>/dev/null`) !== 0) {
		log('another RU-geo update is already running — skipped.');
		return;
	}

	system(`mkdir -p ${shellq(TMP)} ${shellq(RES)}`);
	try { writefile(UPDATING, sprintf('%d\n', time())); } catch (e) {}

	let r = { err: 'internal error' };
	try {
		r = do_update();
	} catch (e) {
		r = { err: sprintf('%s', e) };
	}

	if (r.err) {
		log('RU-geo update FAILED: ' + r.err);
		print('RESULT {"result": false, "error": "' + replace(r.err, /"/g, '') + '"}\n');
	} else {
		print('RESULT {"result": true, "geoip": ' + sprintf('%d', r.geoip) + ', "geosite": ' + sprintf('%d', r.geosite) + ', "categories": ' + sprintf('%d', r.categories) + '}\n');
	}

	try { system(`rm -f ${shellq(UPDATING)}`); } catch (e) {}
	system(`rm -rf ${shellq(TMP)} ${shellq(LOCK_DIR)} 2>/dev/null; true`);
}

try {
	main();
} catch (e) {
	log('fatal: ' + sprintf('%s', e));
	try { system(`rm -rf ${shellq(TMP)} ${shellq(LOCK_DIR)} 2>/dev/null; rm -f ${shellq(UPDATING)}`); } catch (x) {}
}
