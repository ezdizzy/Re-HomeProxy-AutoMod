#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * rulesets_seed.uc — local rule-set seeder (issue #12). The core initializes
 * remote rule-sets SYNCHRONOUSLY at start; on a cold boot (fresh flash or a
 * wiped /var/run — empty cache.db) the first failing download is FATAL and
 * the proxy never comes up. This runner pre-downloads every remote .srs of
 * the LIVE generated config into the local fallback dir as <tag>.srs, which
 * the generator wires into the config via initial_path (the core loads the
 * file for the first start and refreshes from the network afterwards).
 *
 * Spawned detached by rpcd (app_rulesets_local_seed). Downloads each URL
 * DIRECT first (the same URLs the core uses — github releases / raw mirrors);
 * on failure the fetch is retried through the wizard's forced-main socks
 * inbound (127.0.0.1:5337), which rides the main exit — a host blocked by
 * DPI in the direct view still downloads while the proxy is up. Files land
 * atomically (tmp + mv) and pass a binary sanity check (a .srs starts with
 * a small version byte; an HTML/JSON error page is refused — a poisoned
 * local copy would be worse than no copy at all).
 *
 * Progress: /var/run/homeproxy/rulesets_seed.json (atomic tmp+mv per file),
 * polled by app_rulesets_local_status. A running entry younger than 15 min
 * blocks a second spawn; a stale one is taken over by this new run.
 */

'use strict';

import { access, readfile, writefile, rename, mkdir, stat, popen } from 'fs';
import { cursor } from 'uci';

const RUN_DIR = '/var/run/homeproxy';
const ST_FILE = RUN_DIR + '/rulesets_seed.json';
const DEFAULT_DIR = '/etc/homeproxy/rulesets';
/* Wizard diagnostic inbound that forces the main exit (always-on with a
 * configured main node; generate_client.uc emits it). */
const MAIN_SOCKS = '127.0.0.1:5337';
/* curl budgets: GitHub needs a few seconds per .srs; 12 files/hit is the
 * realistic cap (sources with an enabled proxy_ru_rule). */
const DL_TIMEOUT = 90;

const uci = cursor();
uci.load('homeproxy');

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function wstatus(o) {
	mkdir(RUN_DIR);
	const tmp = ST_FILE + '.tmp';
	writefile(tmp, sprintf('%.J', o) + '\n');
	rename(tmp, ST_FILE);
}

/* Absolute path only, no traversal — it ends up in shell commands.
 * Same rule as the rpcd helper of the same name. */
function local_dir() {
	const d = trim('' + (uci.get('homeproxy', 'config', 'ruleset_local_path') || ''));
	if (!length(d) || substr(d, 0, 1) !== '/' || index(d, '..') >= 0)
		return DEFAULT_DIR;
	return d;
}

/* Remote rule-sets of the live config — the exact set the core would fetch. */
function remote_list() {
	let data = null;
	try { data = json(readfile(RUN_DIR + '/hiddify-c.json') || ''); } catch (e) { data = null; }
	const out = [];
	const rs = (data && data.route && type(data.route.rule_set) === 'array') ? data.route.rule_set : [];
	for (let r in rs) {
		if (r.type !== 'remote' || !length('' + (r.tag || '')) || !length('' + (r.url || '')))
			continue;
		push(out, { tag: '' + r.tag, url: '' + r.url });
	}
	return out;
}

/* The sing-box binary rule-set starts with the ASCII magic "SRS" followed by
 * a version byte (verified live: head -c 32 | hexdump). Anything else (an
 * HTML/JSON error page, a truncated body) is refused — a poisoned local copy
 * would be worse than no copy at all (the core side still self-heals: a bad
 * initial_path file only warns and falls back to the normal fetch). */
function srs_sane(path) {
	const st = stat(path);
	if (!st || st.size < 64)
		return false;
	const fd = popen(`head -c 3 ${shellquote(path)} 2>/dev/null`);
	if (!fd)
		return false;
	const magic = fd.read('all');
	fd.close();
	return substr(magic, 0, 3) === 'SRS';
}

function fetch(url, dest, via_proxy) {
	const tmp = dest + '.tmp';
	system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
	const proxy = via_proxy ? ` --proxy socks5h://${MAIN_SOCKS}` : '';
	const rc = system(
		`curl -sSL --connect-timeout 8 -m ${DL_TIMEOUT}${proxy} -o ${shellquote(tmp)} ${shellquote(url)} 2>/dev/null`,
		(DL_TIMEOUT + 15) * 1000
	);
	if (rc === 0 && srs_sane(tmp)) {
		rename(tmp, dest);
		return true;
	}
	system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
	return false;
}

/* ── main ────────────────────────────────────────────────────────────────── */

const force = (ARGV[0] === 'force');
const dir = local_dir();

/* Take over a stale run: the spawn guard lives in the RPC (15 min), here we
 * just record the fresh state. */
const list = remote_list();
wstatus({ running: true, ts: time(), dir: dir, done: 0, total: length(list), results: [] });

if (!length(list)) {
	wstatus({ running: false, ts: time(), ok: false, error: 'no remote rule-sets in the active config' });
	exit(0);
}

if (!access(dir))
	mkdir(dir);
if (!access(dir)) {
	wstatus({ running: false, ts: time(), ok: false, error: 'cannot create ' + dir });
	exit(0);
}

let done = 0;
let results = [];
for (let r in list) {
	const dest = dir + '/' + r.tag + '.srs';
	let status = 'kept';
	if (force || !access(dest)) {
		if (fetch(r.url, dest, false))
			status = 'direct';
		else if (fetch(r.url, dest, true))
			status = 'proxy';
		else
			status = 'failed';
	}
	push(results, { tag: r.tag, status: status });
	done++;
	wstatus({ running: true, ts: time(), dir: dir, done: done, total: length(list), results: results });
}

let failed = 0;
for (let x in results)
	if (x.status === 'failed') failed++;

wstatus({
	running: false, ts: time(), dir: dir,
	ok: (failed === 0), failed: failed,
	done: done, total: length(list), results: results
});
