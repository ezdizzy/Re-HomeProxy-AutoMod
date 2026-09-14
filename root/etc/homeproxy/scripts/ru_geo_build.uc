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
/* CDN/cloud IP→ASN ranges (free IPtoASN TSV; best-effort — the engine works
 * without this file, it only makes IP-learning more conservative). */
const CDN_TSV_URLS = [
	'https://iptoasn.com/data/ip2asn-v4.tsv.gz'
];
/* Shared-fate CDN/cloud ASNs — their addresses serve blocked and unblocked
 * services alike, so a learned IP there reroutes unrelated traffic. */
const KNOWN_CDN_ASNS = {
	'13335': 1,   // Cloudflare
	'15169': 1,   // Google
	'16509': 1,   // Amazon AWS
	'14618': 1,   // Amazon CloudFront
	'54113': 1,   // Fastly
	'20940': 1,   // Akamai
	'24940': 1,   // Hetzner
	'16276': 1,   // OVH
	'14061': 1,   // DigitalOcean
	'63949': 1,   // Linode
	'20473': 1,   // Vultr/Choopa
	'36352': 1,   // Leaseweb
	'60068': 1,   // CDN77
	'19551': 1,   // Incapsula/Imperva
	'395747': 1,  // BunnyCDN
	'200325': 1,  // BunnyCDN (alt)
	'394406': 1,  // Azion
	'395962': 1,  // G-Core Labs
	'202425': 1,  // CacheFly
	'197847': 1,  // KeyCDN
};
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

/* ── CDN ranges (cdn_ip4.txt) ──────────────────────────────────────────────
 * 32-bit math in doubles (exact below 2^53); bitwise operators are avoided
 * on purpose — they coerce through int32 and trap on the sign bit. */
const CDN_POW2 = [
	1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
	65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608,
	16777216, 33554432, 67108864, 134217728, 268435456, 536870912,
	1073741824, 2147483648, 4294967296
];

function int_to_ip(n) {
	return sprintf('%d.%d.%d.%d', int(n / 16777216) % 256, int(n / 65536) % 256, int(n / 256) % 256, n % 256);
}

/* Dotted-quad -> 32-bit integer (doubles; exact below 2^53). Returns NaN on
 * anything that is not exactly four octets. */
function ip_to_int(ip) {
	let o = split(ip, '.');
	if (length(o) != 4)
		return NaN;
	let n = 0;
	for (let i, x in o) {
		x = int(trim(x));
		if (x != x || x < 0 || x > 255)
			return NaN;
		n = n * 256 + x;
	}
	return n;
}

/* Expand an inclusive integer range into the minimal sorted CIDR list.
 * For each step pick the LARGEST power-of-two block that is aligned with s
 * and fits inside [s, e] — starting the probe at size=1 (p=32) would match
 * trivially and degenerate every range into /32s (verified live). */
function range_to_cidrs(s, e, out) {
	while (s <= e) {
		let size = 2147483648;
		let p = 1;
		while (p < 32 && (s % size != 0 || s + size - 1 > e)) {
			size = int(size / 2);
			p++;
		}
		push(out, int_to_ip(s) + '/' + p);
		s += size;
	}
}

/* Download the IPtoASN v4 TSV and build resources/cdn_ip4.txt (CIDR ranges of
 * KNOWN_CDN_ASNS). Streaming line reader — the full table is ~350k rows and
 * must not be slurped into one array on a 128 MB router. Returns the range
 * count or -1 on failure (the previous file stays in place). */
function build_cdn_ranges() {
	if (!fetch_any(TMP + '/cdn_tsv.gz', CDN_TSV_URLS))
		return -1;
	/* A dead source can still yield an HTTP error page (non-gzip), which
	 * passes the size>0 check — verify the payload decompresses (verified
	 * live: iptoasn 404 page was silently accepted before this check). */
	if (system(`gunzip -t ${shellq(TMP + '/cdn_tsv.gz')} 2>/dev/null`) != 0) {
		log('warn: CDN source returned a non-gzip payload');
		return -1;
	}
	system(`gunzip -f -c ${shellq(TMP + '/cdn_tsv.gz')} > ${shellq(TMP + '/cdn_tsv.tsv')} 2>/dev/null`);
	let fd = open(TMP + '/cdn_tsv.tsv', 'r');
	if (!fd) return -1;
	let ranges = [];
	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		line = trim(line);
		if (!length(line)) continue;
		let parts = split(line, '\t');
		if (length(parts) < 3) continue;
		let asn = trim(parts[2]);
		if (!KNOWN_CDN_ASNS[asn]) continue;
		/* IPtoASN v4 TSV carries DOTTED-QUAD range bounds
		 * ("1.0.0.0\t1.0.0.255\t13335\t...") — verified live; parsing them
		 * with int() yielded garbage /32s like 0.0.0.1. */
		let rs = ip_to_int(trim(parts[0])), re = ip_to_int(trim(parts[1]));
		if (rs != rs || re != re || rs > re || rs < 0 || re > 4294967295) continue;
		range_to_cidrs(rs, re, ranges);
		if (length(ranges) > 40000) { log('warn: CDN ranges exceeded 40k entries - truncated'); break; }
	}
	fd.close();
	return length(ranges) ? ranges : -1;
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
	log(`warn: category '${cat}' could not be downloaded - skipped`);
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

	/* CDN/cloud ranges for IP-learning exclusions (Phase 4). Strictly
	 * optional: a failed download keeps the previous cdn_ip4.txt and never
	 * fails the RU-geo update itself. */
	let cdn_ranges = build_cdn_ranges();
	let cdn_note = 'cdn ranges unavailable';
	if (type(cdn_ranges) === 'array') {
		cdn_ranges = sort(cdn_ranges);
		/* One range can be covered by several known ASNs — keep a single
		 * copy so the engine's bucket table stays compact. */
		let uniq = [];
		for (let i, r in cdn_ranges) {
			if (!i || cdn_ranges[i - 1] != r)
				push(uniq, r);
		}
		cdn_ranges = uniq;
		atomic_txt(RES + '/cdn_ip4.txt', join('\n', cdn_ranges) + '\n');
		cdn_note = sprintf('%d cdn ranges', length(cdn_ranges));
	} else {
		if (access(RES + '/cdn_ip4.txt'))
			cdn_note = 'cdn ranges kept from the previous update';
		log('warn: CDN range source unreachable - IP-learning exclusions stay as-is');
	}

	atomic_txt(RES + '/ru_geoip.txt', join('\n', nets) + '\n');
	atomic_txt(RES + '/ru_geosite.txt', join('\n', doms) + '\n');

	/* Meta (hand-built JSON: %.J printf is unsupported on this build). */
	atomic_txt(RES + '/ru_geo.meta', sprintf(
		'{"updated": %d, "geoip": %d, "geoip_v4": %d, "geoip_v6": %d, "geosite": %d, "categories": %d, "categories_failed": %d, "cdn_ranges": "%s"}\n',
		time(), v4 + v6, v4, v6, length(doms), cat_count, cat_failed, cdn_note));

	/* Regenerate the watched rule-set JSONs (stale-source check inside) and
	 * ping the daemon so it re-reads the databases. */
	sync_ru_geo_rulesets();
	try { writefile(RELOAD_MARKER, 'geo\n'); } catch (e) { /* tmpfs always writable */ }

	log(`RU-geo database updated: ${v4} v4 + ${v6} v6 networks, ${length(doms)} domain entries from ${cat_count} categories (${cdn_note}).`);
	return { err: null, geoip: v4 + v6, geosite: length(doms), categories: cat_count };
}

/* ── Main ────────────────────────────────────────────────────────────────── */
function main() {
	/* Lock: another update already running (RPC + daemon auto-update can race). */
	if (system(`mkdir ${shellq(LOCK_DIR)} 2>/dev/null`) !== 0) {
		log('another RU-geo update is already running - skipped.');
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
