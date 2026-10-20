#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Routing Wizard: dpi-detect corpus updater (Ф8-F1).
 *
 * One-shot background runner (the ru_geo_build.uc / wizard_tgwsp.uc pattern):
 * downloads the splify2-lists dpi-detect.lst catalog entry — domains where the
 * provider's TSPU is CONFIRMED cutting connections (>24 h: TLS teardown or the
 * ~16 KB traffic freeze; upstream rechecks every 6 h and drops healed entries
 * by itself) — filters it into a scanner seed file:
 *
 *   - plain domains only (the validation regex mirrors wizard_provider_scan);
 *   - .ru/.su/.рф/.xn--p1ai NEVER pass (ru_tld_exclusion standing rule);
 *   - dedup, hard cap 200 lines (the file must stay tiny);
 *   - atomic write (temp + mv — automation.atomic_write constraint).
 *
 * Output:
 *   /etc/homeproxy/resources/dpi_detect.txt   (scanner seeds; wizard_scan.uc
 *          merges up to 12 of them into the diagnostic corpus, svc dpi_detect)
 *   /var/run/homeproxy/dpi_detect.json        (status: {stage,count,…,ts})
 *
 * ucode constraints honored: no strftime (epoch timestamps), push() as a
 * function, match() with regex literals only, json() parses but never
 * serializes (sprintf('%.J') writes JSON), no function hoisting.
 */

'use strict';

import { access, lstat, readfile, writefile, popen } from 'fs';

const RUN_DIR = '/var/run/homeproxy';
const HP_DIR = '/etc/homeproxy';
const LIST_URL = 'https://raw.githubusercontent.com/splify2/splify2-lists/main/lists/dpi-detect.lst';
const DST = HP_DIR + '/resources/dpi_detect.txt';
const STATUS = RUN_DIR + '/dpi_detect.json';
const TMP_DL = RUN_DIR + '/dpi_detect.dl';

const CAP = 200;

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function wstat(o) {
	o.ts = time();
	writefile(STATUS + '.tmp', sprintf('%.J\n', o));
	system(`mv -f ${sq(STATUS + '.tmp')} ${sq(STATUS)}`);
}

/* NOTE: no self-lock here — the spawning RPC (wizard_dpidetect_update)
 * enforces the single-run guard against the status file. A lock inside the
 * runner would deadlock recovery after a crashed run (its stale stage=run
 * blocks any retry for the whole window). */

wstat({ stage: 'run', count: 0, skipped_ru: 0, skipped_bad: 0 });

/* Watchdog: a hung download must not leave stage=run forever (the RPC refuses
 * a new start while stage=run looks fresh). curl has -m, so this is belt;
 * still, wrap the whole thing in a bounded pipeline. */
const dl = popen(`curl -fsSL -m 25 -o ${sq(TMP_DL)} ${sq(LIST_URL)} 2>/dev/null`);
if (dl) {
	dl.read('all');
	dl.close();
}

if (!access(TMP_DL) || (lstat(TMP_DL) || {}).size === 0) {
	wstat({ stage: 'error', error: 'download failed', count: 0 });
	system(`rm -f ${sq(TMP_DL)}`);
	exit(0);
}

const raw = readfile(TMP_DL) || '';
system(`rm -f ${sq(TMP_DL)}`);

const seen = {};
const out = [];
let skipped_ru = 0;
let skipped_bad = 0;
for (let l in split(raw, '\n')) {
	const h = lc(trim(l));
	if (!length(h) || match(h, /^#/))
		continue;
	/* ru_tld_exclusion (standing rule): .ru/.su/.рф/.xn--p1ai never probed;
	 * plus RU-segment mirrors (ru.<anything>, R4: ru.spankbang.com) — they
	 * are RU services, not DPI-bypass candidates. */
	if (match(h, /\.(ru|su|xn--p1ai)$/) || index(h, '.рф') >= 0 || match(h, /^ru\./)) {
		skipped_ru++;
		continue;
	}
	if (!match(h, /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$/)) {
		skipped_bad++;
		continue;
	}
	if (seen[h])
		continue;
	seen[h] = true;
	if (length(out) < CAP)
		push(out, h);
}

if (!length(out)) {
	wstat({ stage: 'error', error: 'empty list after filter', skipped_ru: skipped_ru, skipped_bad: skipped_bad });
	exit(0);
}

/* Atomic list write (temp + mv): the scanner may read it concurrently. */
const body = '# dpi-detect.lst (splify2-lists) — TSPU-cut domains, RU-filtered (ru_tld_exclusion)\n' +
	'# auto-refresh: wizard_dpidetect_update; consumed by wizard_scan.uc (cap 12)\n' +
	join('\n', out) + '\n';
writefile(DST + '.tmp', body);
system(`mv -f ${sq(DST + '.tmp')} ${sq(DST)}`);

wstat({ stage: 'done', count: length(out), skipped_ru: skipped_ru, skipped_bad: skipped_bad });
