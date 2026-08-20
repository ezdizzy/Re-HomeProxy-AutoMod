#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy — Automatic blocked-site detection daemon.
 *
 * How it works (transparent, compatible with ByeDPI & Zapret):
 *   1. Discover candidate destinations the user actually reaches (via the core's Clash
 *      API /connections, or conntrack as a fallback).
 *   2. For each unknown candidate, probe it BOTH direct (forced through `auto-direct-in`
 *      -> direct-out) and through the configured main path (forced through `auto-proxy-in`
 *      -> main-out). The test inbounds are created by generate_client.uc only while
 *      automation is enabled, and bound to 127.0.0.1.
 *   3. If direct fails but the proxy path succeeds, the site is classified "blocked" and
 *      its domain is appended to resources/auto_proxy_list.txt. generate_client.uc merges
 *      that file into the proxy-domain ruleset, so the site is routed via the user's main
 *      outbound (main-out, which already IS byedpi-out / zapret-out when those are the
 *      configured main node). Nothing about ByeDPI/Zapret rule wiring changes.
 *   4. On change, regenerate + reload the core (throttled) so the learned rule applies.
 *
 * The daemon is intentionally conservative: it only ADDS sites it has proven unreachable
 * directly yet reachable via the proxy. Direct-only sites are left alone.
 */

'use strict';

import { access, readfile, writefile, remove } from 'fs';
import { cursor } from 'uci';

const HP_DIR = '/etc/homeproxy';
const RUN_DIR = '/var/run/homeproxy';
const RES = HP_DIR + '/resources';

const AUTO_DIRECT_PORT = 5336;
const AUTO_PROXY_PORT = 5337;

const STATE_FILE = RUN_DIR + '/automation_state.json';
const AUTO_LIST = RES + '/auto_proxy_list.txt';
const TRIGGER_FILE = RUN_DIR + '/automation.trigger';
const LOG_FILE = RUN_DIR + '/automation.log';

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function log(msg) {
	const line = `$(date "+%Y-%m-%d %H:%M:%S") [AUTO] ${msg}\n`;
	try {
		const fd = open(LOG_FILE, 'a');
		if (fd) { fd.write(line); fd.close(); }
	} catch (e) { /* best effort */ }
}

function read_lines(path) {
	if (!access(path))
		return [];
	let c = readfile(path);
	if (!c) return [];
	c = trim(c);
	if (!length(c)) return [];
	let arr = split(c, /[\r\n]/);
	return filter(arr, (x) => length(trim(x)) && !match(trim(x), /^\s*#/));
}

function load_state() {
	if (!access(STATE_FILE))
		return {};
	let c = readfile(STATE_FILE);
	if (!c) return {};
	try { return json(c) || {}; } catch (e) { return {}; }
}

function save_state(state) {
	try { writefile(STATE_FILE, sprintf('%.J\n', state)); } catch (e) { /* ignore */ }
}

function write_auto_list(set) {
	let arr = sort(keys(set));
	let content = join('\n', arr) + (length(arr) ? '\n' : '');
	system(`mkdir -p ${RES}`);
	writefile(AUTO_LIST, content);
}

/* Probe a single host (domain or IP) through a forced outbound. Returns 'ok' on a
 * successful TLS handshake, 'fail' otherwise. Uses curl when present (SOCKS5 aware);
 * falls back to wget through the mixed inbounds' HTTP proxy mode. */
function have_curl() {
	return !!access('/usr/bin/curl');
}

function probe(host, via_proxy, timeout) {
	const url = `https://${host}`;
	if (have_curl()) {
		let proxy_arg = via_proxy ? ` -x socks5h://127.0.0.1:${AUTO_PROXY_PORT}` : '';
		let fd = popen(`curl -s -o /dev/null -w '%{http_code}' -k --connect-timeout ${timeout} --max-time ${timeout} ${proxy_arg} ${shellquote(url)} 2>/dev/null`);
		let code = '';
		if (fd) { code = trim(fd.read('all')); fd.close(); }
		return (code != '000' && code != '' && code != null) ? 'ok' : 'fail';
	}
	/* wget fallback: HTTP CONNECT proxy (mixed inbound is http-proxy capable). */
	let proxy_env = via_proxy
		? `http_proxy=http://127.0.0.1:${AUTO_PROXY_PORT} https_proxy=http://127.0.0.1:${AUTO_PROXY_PORT}`
		: `http_proxy= https_proxy=`;
	let rc = system(`${proxy_env} /usr/bin/wget -q -T ${timeout} -t 1 --no-check-certificate -O /dev/null ${shellquote(url)} 2>/dev/null`, timeout * 1000 + 2000);
	return (rc === 0) ? 'ok' : 'fail';
}

/* Candidate discovery ------------------------------------------------------- */

function discover_clash(timeout) {
	let fd = popen(`curl -s --max-time 3 http://127.0.0.1:9090/connections 2>/dev/null`);
	let raw = '';
	if (fd) { raw = fd.read('all'); fd.close(); }
	if (!raw) return [];
	let data;
	try { data = json(raw); } catch (e) { return []; }
	let hosts = [];
	for (let i, c in (data.connections || [])) {
		let m = c.metadata || {};
		let host = m.host;
		if (!host || match(host, /^[0-9.]+$/) || match(host, /^[0-9a-fA-F:]+$/))
			host = m.destinationIP;
		if (!host) continue;
		/* Only re-classify traffic that currently goes DIRECT (the default in
		 * selective/global modes). Anything already proxied is not a candidate. */
		if (m.outbound && m.outbound !== 'direct-out' && m.outbound !== 'auto-direct-in')
			continue;
		push(hosts, host);
	}
	return hosts;
}

function discover_conntrack() {
	let fd = popen(`conntrack -L 2>/dev/null | awk '/ESTABLISHED/ { for (i=1;i<=NF;i++) if ($i ~ /^dst=/) { sub("dst=", "", $i); print $i } }' | head -200`);
	let raw = '';
	if (fd) { raw = fd.read('all'); fd.close(); }
	if (!raw) return [];
	return split(trim(raw), /\n/);
}

/* Main loop ---------------------------------------------------------------- */

function main() {
	const uci = cursor();
	uci.load('homeproxy');

	let enabled = uci.get('homeproxy', 'automation', 'enabled');
	if (enabled !== '1') {
		log('automation disabled, exiting.');
		return;
	}

	let timeout = int(uci.get('homeproxy', 'automation', 'timeout') || '6') || 6;
	let max_entries = int(uci.get('homeproxy', 'automation', 'max_entries') || '2000') || 2000;
	let min_confirm = int(uci.get('homeproxy', 'automation', 'min_confirm') || '1') || 1;
	let mode = uci.get('homeproxy', 'automation', 'mode') || 'balanced';
	let discover = uci.get('homeproxy', 'automation', 'discover') || 'clash';
	let reeval_interval = int(uci.get('homeproxy', 'automation', 'reeval_interval') || '3600') || 3600;
	let reload_interval = int(uci.get('homeproxy', 'automation', 'reload_interval') || '300') || 300;
	let excludes = split(trim(uci.get('homeproxy', 'automation', 'exclude') || 'localhost,local,lan,in-addr.arpa,ip6.arpa'), ',');
	excludes = filter(excludes, (x) => length(trim(x)));

	/* Static lists we must never touch / never re-probe as "unknown". */
	let direct_set = {};
	for (let d in read_lines(RES + '/direct_list.txt')) direct_set[trim(d)] = true;
	let proxy_set = {};
	for (let d in read_lines(RES + '/proxy_list.txt')) proxy_set[trim(d)] = true;
	let auto_set = {};
	for (let d in read_lines(AUTO_LIST)) auto_set[trim(d)] = true;
	let state = load_state();

	let last_reload = 0;
	let pending_reload = false;

	function is_excluded(host) {
		host = trim(host);
		if (!length(host)) return true;
		for (let e in excludes) {
			e = trim(e);
			if (!length(e)) continue;
			if (host === e) return true;
			/* domain-suffix match: "local" matches "foo.local" but not "localfoo" */
			if (length(host) > length(e) && substr(host, length(host) - length(e) - 1) === '.' + e)
				return true;
		}
		if (direct_set[host] || proxy_set[host] || auto_set[host]) return true;
		return false;
	}

	function do_reload() {
		log('regenerating core config and reloading service...');
		system(`ucode ${HP_DIR}/scripts/generate_client.uc >/dev/null 2>&1`);
		system('/etc/init.d/homeproxy reload >/dev/null 2>&1');
		last_reload = time();
		pending_reload = false;
	}

	function classify_and_store(host, direct_res, proxy_res) {
		host = trim(host);
		if (!state[host]) state[host] = {};
		let st = state[host];
		st.last_probe = time();
		st.direct = direct_res;
		st.proxy = proxy_res;

		let blocked = (direct_res === 'fail' && proxy_res === 'ok');

		if (blocked) {
			st.status = 'blocked';
			st.confirms = (st.confirms || 0) + 1;
			/* Require min_confirm independent confirmations before committing, so a
			 * transient blip doesn't permanently route a site through the proxy. */
			if (st.confirms >= min_confirm && !auto_set[host]) {
				auto_set[host] = true;
				write_auto_list(auto_set);
				log(`learned BLOCKED: ${host}`);
				pending_reload = true;
			}
		} else if (direct_res === 'ok') {
			st.status = 'direct';
			st.confirms = 0;
		} else {
			st.status = 'unknown';
		}
	}

	/* One discovery + probe pass. */
	function pass(run_now) {
		/* Refresh config in case the user toggled something. */
		enabled = uci.get('homeproxy', 'automation', 'enabled');
		if (enabled !== '1') return;

		let candidates = {};
		if (discover === 'clash' || discover === 'both') {
			for (let i, h in discover_clash(timeout)) candidates[h] = true;
		}
		if ((discover === 'conntrack' || discover === 'both') && !length(keys(candidates))) {
			for (let i, h in discover_conntrack()) candidates[h] = true;
		}
		/* In aggressive mode, also re-evaluate already-learned entries so they stay correct. */
		if (mode === 'aggressive') {
			for (let h in auto_set) {
				let st = state[h];
				if (!st || !st.last_probe || (time() - st.last_probe) > reeval_interval)
					candidates[h] = true;
			}
		}

		let now = time();
		let probed = 0;
		const cap = 24;
		for (let host in candidates) {
			if (probed >= cap) break;
			if (is_excluded(host)) continue;
			if (length(keys(auto_set)) >= max_entries && !auto_set[host]) continue;

			let st = state[host];
			if (st && st.last_probe && (now - st.last_probe) < (mode === 'aggressive' ? reeval_interval : 86400))
				continue;

			probed++;
			let direct_res = probe(host, false, timeout);
			let proxy_res = probe(host, true, timeout);
			classify_and_store(host, direct_res, proxy_res);
			save_state(state);
			sleep(150);
		}

		if (pending_reload && (now - last_reload) > reload_interval)
			do_reload();
		else if (pending_reload && run_now)
			do_reload();
	}

	log('automation daemon started (mode=' + mode + ', discover=' + discover + ').');

	let cycle = 0;
	while (true) {
		enabled = uci.get('homeproxy', 'automation', 'enabled');
		if (enabled !== '1') {
			log('automation disabled, exiting.');
			return;
		}

		let run_now = false;
		if (access(TRIGGER_FILE)) {
			remove(TRIGGER_FILE);
			run_now = true;
		}

		pass(run_now);

		/* Idle between passive-discovery cycles; trigger file forces an immediate pass. */
		for (let i = 0; i < 30; i++) {
			sleep(1);
			if (access(TRIGGER_FILE)) { remove(TRIGGER_FILE); break; }
			if (uci.get('homeproxy', 'automation', 'enabled') !== '1') return;
		}
		cycle++;
	}
}

try {
	main();
} catch (e) {
	log('fatal: ' + tostring(e));
}
