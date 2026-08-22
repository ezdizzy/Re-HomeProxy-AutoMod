#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Automatic blocked-site / destination detection daemon.
 *
 * Discovery sources (UCI automation.discover, comma-separated):
 *   clash     — Clash API /connections (domain names of live traffic)
 *   dns       — dnsmasq query log (captures the domain at DNS time, BEFORE the
 *               connection — makes learning transparent: the site is usually fixed
 *               before the user navigates/retries)  [A]
 *   conntrack — destination IPs of established flows (for IP-only apps/games)  [B]
 *
 * Classification (for every candidate): probe it BOTH direct (auto-direct-in →
 * direct-out) and through the configured main path (auto-proxy-in → main-out, which
 * already IS byedpi-out / zapret-out). A destination is learned as "blocked" only when
 * direct FAILS but the proxy WORKS — so a merely-down site (both fail) or a site that
 * works direct is never rerouted. Learned domains go to resources/auto_proxy_list.txt
 * (→ proxy-domain ruleset); learned IPs go to resources/auto_proxy_ip.txt (→ auto-ip
 *   ip_cidr ruleset). Both route via the user's main path → ByeDPI/Zapret compatible.
 *
 * C — DNS failover: if enabled, monitor the primary DNS (config.dns_server) and the
 *   alt_dns_servers list; if the primary becomes unreachable, rewrite dns_server to a
 *   healthy alternate and regenerate.  [C]
 */

'use strict';

import { access, readfile, writefile, open, stat } from 'fs';
import { cursor } from 'uci';
import { sync_learned_rulesets, isEmpty } from 'homeproxy';

const HP_DIR = '/etc/homeproxy';
const RUN_DIR = '/var/run/homeproxy';
const RES = HP_DIR + '/resources';

const AUTO_DIRECT_PORT = 5336;
const AUTO_PROXY_PORT = 5337;

const STATE_FILE = RUN_DIR + '/automation_state.json';
const AUTO_LIST = RES + '/auto_proxy_list.txt';
const AUTO_IP_LIST = RES + '/auto_proxy_ip.txt';
const TRIGGER_FILE = RUN_DIR + '/automation.trigger';
const LOG_FILE = RUN_DIR + '/automation.log';
const DNS_LOG = '/var/log/dnsmasq-q.log';

/* Module-level state shared with the top-level helper function dns_failover_check().
 * Some ucode builds do not support closures over main()'s locals, so these helpers
 * must read module-scoped variables. */
let uci = null;
let dns_failover = '0';
let dns_failover_plain = '0';
let dns_failover_secure = '0';
let alt_dns = [];
let auto_set = {};
let pending_reload = false;
let pending_new = 0;
let excludes = [];
let direct_set = {};
let proxy_set = {};
let auto_ip_set = {};

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function first_of(v) {
	return (type(v) === 'array') ? (length(v) ? v[0] : '') : v;
}

function capture(cmd) {
	const tmp = RUN_DIR + '/capture.tmp';
	system(cmd + ' > ' + shellquote(tmp) + ' 2>/dev/null');
	if (!access(tmp)) return '';
	let c = readfile(tmp);
	return c ? c : '';
}

function log(msg) {
	const line = `[${sprintf('%d', time())}] [AUTO] ${msg}\n`;
	try {
		/* Bound the log so it can never grow without limit. When it passes the
		 * soft cap, keep only the most recent MAX_LOG_LINES by truncating in place
		 * (best effort — a failed rotation must never break logging). */
		if (access(LOG_FILE)) {
			const MAX_LOG_BYTES = 51200;
			let sz = 0;
			try { sz = stat(LOG_FILE).size || 0; } catch (e) { sz = 0; }
			if (sz > MAX_LOG_BYTES) {
				const tmp = LOG_FILE + '.tmp';
				system('tail -n 500 ' + shellquote(LOG_FILE) + ' > ' + shellquote(tmp) + ' 2>/dev/null; mv -f ' + shellquote(tmp) + ' ' + shellquote(LOG_FILE));
			}
		}
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
	return filter(split(c, /[\r\n]/), (x) => length(trim(x)) && !match(trim(x), /^\s*#/));
}

function load_state() {
	if (!access(STATE_FILE))
		return {};
	let c = readfile(STATE_FILE);
	if (!c) return {};
	try { return json(c) || {}; } catch (e) { return {}; }
}

function atomic_write(path, content) {
	let tmp = path + '.tmp';
	writefile(tmp, content);
	system('mv -f ' + tmp + ' ' + path);
}

function save_state(state) {
	atomic_write(STATE_FILE, sprintf('%.J\n', state));
}

function write_auto_list(set) {
	let arr = sort(keys(set));
	atomic_write(AUTO_LIST, join('\n', arr) + (length(arr) ? '\n' : ''));
}

function write_auto_ip_list(set) {
	let arr = sort(keys(set));
	atomic_write(AUTO_IP_LIST, join('\n', arr) + (length(arr) ? '\n' : ''));
}

function have_curl() {
	return !!access('/usr/bin/curl');
}

/* Probe a host BOTH direct and via the configured main path. Returns an object
 * { code, ok, block } instead of a bare 'ok'/'fail' so classification can tell
 * apart "unreachable" (000/timeout), "blocked" (4xx/5xx or a 200 block-page),
 * and "reachable" (2xx/3xx with a real page). This is what lets us learn the
 * 403-via-direct / works-via-proxy case that the old code missed. */
function probe(host, via_proxy, timeout) {
	const url = `https://${host}`;
	if (have_curl()) {
		let proxy_arg = via_proxy ? ` -x socks5h://127.0.0.1:${AUTO_PROXY_PORT}` : '';
		let bodyf = RUN_DIR + '/pb.tmp';
		let codef = RUN_DIR + '/pc.tmp';
		/* Follow redirects (-L) so we judge the FINAL page the browser would see;
		 * capture the code AND the body (to detect 200 block-pages). */
		system(`curl -sL --max-redirs 3 -o ${shellquote(bodyf)} -w '%{http_code}' -k --connect-timeout ${timeout} --max-time ${timeout} ${proxy_arg} ${shellquote(url)} > ${shellquote(codef)} 2>/dev/null`);
		let code = trim(readfile(codef) || '000');
		let c = classify_code(code);
		let block = (c === 'block');
		if (c === 'ok') {
			let body = readfile(bodyf) || '';
			if (body_blocked(body)) block = true;
		}
		let ok = (c === 'ok') && !block;
		return { code: code, ok: ok, block: block };
	}
	let proxy_env = via_proxy
		? `http_proxy=http://127.0.0.1:${AUTO_PROXY_PORT} https_proxy=http://127.0.0.1:${AUTO_PROXY_PORT}`
		: `http_proxy= https_proxy=`;
	let rc = system(`${proxy_env} /usr/bin/wget -q -T ${timeout} -t 1 --no-check-certificate -O /dev/null ${shellquote(url)} 2>/dev/null`, timeout * 1000 + 2000);
	let ok = (rc === 0);
	return { code: ok ? '200' : '000', ok: ok, block: false };
}

function base_domain(host) {
	host = trim(host);
	if (!length(host)) return host;
	if (substr(host, -1) === '.') host = substr(host, 0, length(host) - 1);
	let parts = split(host, '.');
	if (length(parts) <= 2) return host;
	const multi = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'co.jp', 'com.br', 'co.za'];
	for (let m in multi)
		if (length(host) > length(m) + 1 && substr(host, length(host) - length(m) - 1) === '.' + m)
			return parts[length(parts)-3] + '.' + parts[length(parts)-2] + '.' + parts[length(parts)-1];
	return parts[length(parts)-2] + '.' + parts[length(parts)-1];
}

function is_private_ip(ip) {
	return match(ip, /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) || match(ip, /^fc00:|^fe80:/) || ip === '0.0.0.0';
}

function is_excluded(host) {
	host = trim(host);
	if (!length(host)) return true;
	for (let e in excludes) {
		e = trim(e);
		if (!length(e)) continue;
		if (host === e) return true;
		if (length(host) > length(e) && substr(host, length(host) - length(e) - 1) === '.' + e)
			return true;
	}
	if (direct_set[host] || proxy_set[host] || auto_set[host] || auto_ip_set[host]) return true;
	return false;
}

	function looks_like_host(h) {
		if (match(h, /^(https?|tls|quic):\/\//)) return false;
		if (match(h, /^[0-9a-fA-F:]+$/)) return false;             /* bare IPv6 fragment */
		if (match(h, /^\d{1,3}(\.\d{1,3}){3}$/)) return true;      /* IPv4 */
		if (match(h, /^[a-zA-Z0-9._-]+$/)) {
			let parts = split(h, '.');
			let last = parts[length(parts) - 1];
			if (match(last, /^[0-9]+$/)) return false;             /* final label all digits → junk (e.g. "192.100", "0.1") */
			return true;
		}
		return false;
	}

/* Blocking-pattern signatures: a 200/3xx page whose body matches one of these is
 * treated as a DPI/operator block page (the request "succeeded" but the content is
 * a refusal). Catches the case where direct returns a 200 block-page while the
 * proxy returns the real page. Matched case-insensitively. */
const BLOCK_SIGNATURES = [
	'access denied', 'access forbidden', 'forbidden', 'доступ ограничен',
	'доступ запрещен', 'заблокир', 'заблокиров', 'blocked by', 'block page',
	'the site is blocked', 'сайт заблокирован', 'err_blocked', 'доступ к ресурсу',
	'blocked site', 'не доступен', 'resource is limited', 'request blocked'
];
function body_blocked(body) {
	if (!body) return false;
	body = lower(body);
	for (let s in BLOCK_SIGNATURES) if (index(body, s) >= 0) return true;
	return false;
}
/* Classify a raw HTTP code string: 'ok' (2xx/3xx), 'block' (4xx/5xx), 'fail' (no response). */
function classify_code(code) {
	let c = trim(code || '000');
	if (c === '' || c === '000') return 'fail';
	let n = int(c);
	if (n >= 200 && n < 400) return 'ok';
	if (n >= 400 && n <= 599) return 'block';
	return 'fail';
}

/* ── Discovery ──────────────────────────────────────────────────────────── */

function discover_clash(timeout) {
	let raw = capture(`curl -s --max-time 3 http://127.0.0.1:9090/connections 2>/dev/null`);
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
		if (m.outbound && m.outbound !== 'direct-out' && m.outbound !== 'auto-direct-in')
			continue;
		push(hosts, host);
	}
	return hosts;
}

function discover_conntrack() {
	let raw = capture(`conntrack -L 2>/dev/null | awk '/ESTABLISHED/ { for (i=1;i<=NF;i++) if ($i ~ /^dst=/) { sub("dst=", "", $i); print $i } }' | head -300`);
	if (!raw) return [];
	return split(trim(raw), /\n/);
}

let dns_log_offset = 0;
function discover_dns() {
	if (!access(DNS_LOG)) return [];
	let size = stat(DNS_LOG).size;
	if (dns_log_offset > size) dns_log_offset = 0; /* log rotated */
	let fd = open(DNS_LOG, 'r');
	if (!fd) return [];
	fd.seek(dns_log_offset);
	let hosts = [];
	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		let m = match(trim(line), /query\[[Aq]+\]\s+([^ ]+)\s+from/);
		if (m) push(hosts, m[1]);
	}
	/* ucode file objects have no tell(); we read to EOF so the new offset is the file size. */
	dns_log_offset = size;
	fd.close();
	return hosts;
}

function enable_dns_log() {
	system('uci -q set dhcp.@dnsmasq[0].logqueries=1');
	system('uci -q set dhcp.@dnsmasq[0].logfacility=' + shellquote(DNS_LOG));
	system('uci commit dhcp');
	system('/etc/init.d/dnsmasq restart >/dev/null 2>&1');
}

function disable_dns_log() {
	system('uci -q del dhcp.@dnsmasq[0].logqueries');
	system('uci -q del dhcp.@dnsmasq[0].logfacility');
	system('uci commit dhcp');
	system('/etc/init.d/dnsmasq restart >/dev/null 2>&1');
}

/* ── DNS failover (C) ───────────────────────────────────────────────────── */

function dns_reachable(server) {
	/* Only plain UDP/Do53 servers are health-checked; DoH/DoT are treated as always up. */
	if (match(server, /^(https?|tls|quic):\/\//)) return true;
	if (have_curl())
		return system(`curl -s --max-time 3 --connect-timeout 3 ${shellquote('https://' + server + '/dns-query')} -o /dev/null 2>/dev/null`, 4000) === 0
		    || system(`dig +short +time=2 +tries=1 +timeout=2 @${shellquote(server)} example.com >/dev/null 2>&1`, 6000) === 0;
	return system(`nc -u -z -w 2 ${shellquote(server)} 53 >/dev/null 2>&1`, 4000) === 0;
}

	function dns_failover_check() {
		/* MultiDNS already races EVERY server in each pool and returns the fastest
		 * live answer, so the legacy single-primary failover is redundant (and would
		 * fight MultiDNS's own pool management). Skip it whenever MultiDNS is enabled. */
		if ((uci.get('homeproxy', 'multidns', 'enabled') || '0') === '1') return;
		/* Legacy Reserve/backup DNS failover. Covers BOTH plain and encrypted pools, each
	 * with its own on/off switch. Plain-pool primary = russia_dns_server (or region/dns
	 * server in other modes); secure-pool primary = secure_dns_server. The first healthy
	 * server from the *matching* pool's list becomes the new primary. DoH/DoT servers are
	 * now health-checked for real (see dns_reachable). */
	if (dns_failover !== '1') return;
	let mode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
	let plain_key = (mode === 'proxy_banned_ru') ? 'russia_dns_server'
		: (mode === 'bypass_cn') ? 'china_dns_server'
		: (mode === 'bypass_ir') ? 'iran_dns_server' : 'dns_server';
	let plain_primary = first_of(uci.get('homeproxy', 'config', plain_key));
	let secure_primary = first_of(uci.get('homeproxy', 'config', 'secure_dns_server'));
	let plain_list = (type(uci.get('homeproxy', 'config', plain_key)) === 'array') ? uci.get('homeproxy', 'config', plain_key) : [ plain_primary ];
	let secure_list = (type(uci.get('homeproxy', 'config', 'secure_dns_server')) === 'array') ? uci.get('homeproxy', 'config', 'secure_dns_server') : [ secure_primary ];

	if (dns_failover_plain === '1' && !isEmpty(plain_primary) && plain_primary !== 'wan') {
		if (!dns_reachable(plain_primary)) {
			log('DNS failover (plain): primary ' + plain_primary + ' unreachable, looking for a healthy alternate');
			for (let s in plain_list) {
				if (s === plain_primary) continue;
				if (dns_reachable(s)) {
					uci.set('homeproxy', 'config', plain_key, s);
					uci.commit('homeproxy');
					log('DNS failover (plain): switched ' + plain_key + ' to ' + s);
					return do_failover_reload();
				}
			}
			log('DNS failover (plain): no healthy alternate available');
		}
	}
	if (dns_failover_secure === '1' && !isEmpty(secure_primary) && secure_primary !== 'wan') {
		if (!dns_reachable(secure_primary)) {
			log('DNS failover (secure): primary ' + secure_primary + ' unreachable, looking for a healthy alternate');
			for (let s in secure_list) {
				if (s === secure_primary) continue;
				if (dns_reachable(s)) {
					uci.set('homeproxy', 'config', 'secure_dns_server', s);
					uci.commit('homeproxy');
					log('DNS failover (secure): switched secure_dns_server to ' + s);
					return do_failover_reload();
				}
			}
			log('DNS failover (secure): no healthy alternate available');
		}
	}
}

function do_failover_reload() {
	system('ucode ' + HP_DIR + '/scripts/generate_client.uc >' + RUN_DIR + '/generate_client.log 2>&1');
	if (!access(RUN_DIR + '/hiddify-c.json')) {
		log('DNS failover: regenerate FAILED — see ' + RUN_DIR + '/generate_client.log');
		return;
	}
	log('DNS failover: restarting service to load new config.');
	system('/etc/init.d/homeproxy reload >/dev/null 2>&1');
}

/* ── Main ───────────────────────────────────────────────────────────────── */

function main() {
	uci = cursor();
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
	let reload_interval = int(uci.get('homeproxy', 'automation', 'reload_interval') || '10') || 10;
	let flush_min_entries = int(uci.get('homeproxy', 'automation', 'flush_min_entries') || '1') || 1;
	let ip_learn = uci.get('homeproxy', 'automation', 'ip_learn') || '0';
	excludes = split(trim(uci.get('homeproxy', 'automation', 'exclude') || 'localhost,local,lan,in-addr.arpa,ip6.arpa'), ',');
	excludes = filter(excludes, (x) => length(trim(x)));

	/* DNS failover (C) reads the DNS section, not the automation section. */
	dns_failover = uci.get('homeproxy', 'config', 'dns_failover') || '0';
	dns_failover_plain = uci.get('homeproxy', 'config', 'dns_failover_plain') || '0';
	dns_failover_secure = uci.get('homeproxy', 'config', 'dns_failover_secure') || '0';
	alt_dns = uci.get('homeproxy', 'config', 'alt_dns_servers') || [];
	if (type(alt_dns) !== 'array') alt_dns = [ alt_dns ];

	direct_set = {}; proxy_set = {}; auto_ip_set = {}; auto_set = {};
	for (let d in read_lines(RES + '/direct_list.txt')) direct_set[trim(d)] = true;
	for (let d in read_lines(RES + '/proxy_list.txt')) proxy_set[trim(d)] = true;
	for (let d in read_lines(AUTO_LIST)) auto_set[trim(d)] = true;
	for (let d in read_lines(AUTO_IP_LIST)) auto_ip_set[trim(d)] = true;
	let state = load_state();
	if (state.__dns_offset) dns_log_offset = int(state.__dns_offset) || 0;

	let last_reload = 0;
	pending_reload = false;
	const has = (s) => (discover === 'all') || index(split(discover, ','), s) >= 0;

	function do_reload() {
		let marker = RUN_DIR + '/.learned_hotreload';
		if (access(marker)) {
			/* Hot path: rewrite the watched local rule-set files (proxy_domain.json /
			 * auto_ip.json). Both cores auto-reload a `type: local` rule-set on file
			 * change, so learned sites apply to NEW connections immediately — no service
			 * restart, no dropped connections. In-flight flows keep their route. */
			let r = sync_learned_rulesets();
			log('applied learned list (hot reload, no restart): ' + ((r && r.domains) || 0) + ' domains, ' + ((r && r.ips) || 0) + ' ips.');
			last_reload = time();
			pending_reload = false;
			pending_new = 0;
			return;
		}
		/* First run / migration: the running config does not yet reference the learned
		 * local rule-sets, so one full restart is required to inject them (generate_client
		 * writes the marker above, enabling the hot path afterwards). */
		log('learned rule-sets not in running config — doing full service reload to inject them.');
		system('ucode ' + HP_DIR + '/scripts/generate_client.uc >' + RUN_DIR + '/generate_client.log 2>&1');
		if (!access(RUN_DIR + '/hiddify-c.json')) {
			log('regenerate FAILED — see ' + RUN_DIR + '/generate_client.log');
			return; /* do NOT reload onto a broken/absent config */
		}
		sync_learned_rulesets();
		log('applying learned list — restarting service to load new config.');
		system('/etc/init.d/homeproxy reload >/dev/null 2>&1');
		last_reload = time();
		pending_reload = false;
		pending_new = 0;
	}

	function classify(dom, d, p, is_ip) {
		if (!state[dom]) state[dom] = {};
		let st = state[dom];
		st.last_probe = time();
		st.direct = d.code;
		st.proxy = p ? p.code : 'n/a';
		st.type = is_ip ? 'ip' : 'domain';

		/* A host is learned as BLOCKED only when direct is NOT ok (fails, times out,
		 * gets a 4xx/5xx, or a 200 block-page) AND the proxy reaches a real page.
		 * - direct ok                       -> not blocked, leave as-is
		 * - direct not ok + proxy ok        -> blocked, learn it
		 * - direct not ok + proxy blocked   -> proxy can't help (blocked_no_proxy)
		 * - direct not ok + proxy fail      -> both unreachable / transient (unknown)
		 * This covers: timeout/reset, poisoning (NXDOMAIN/bogus IP), DPI 403/451/5xx,
		 * MITM block-pages served with 200, and the 403-direct / 200-proxy case. */
		if (d.ok) {
			st.status = 'direct';
			st.confirms = 0;
			return;
		}
		let p_ok = p && p.ok;
		if (p_ok) {
			st.status = 'blocked';
			st.confirms = (st.confirms || 0) + 1;
			if (st.confirms >= min_confirm) {
				if (is_ip) {
					if (!auto_ip_set[dom]) { auto_ip_set[dom] = true; st.added = time(); write_auto_ip_list(auto_ip_set); log(`learned BLOCKED ip: ${dom} (direct ${d.code} / proxy ${p.code})`); pending_reload = true; pending_new++; }
				} else if (!auto_set[dom]) {
					auto_set[dom] = true; st.added = time(); write_auto_list(auto_set); log(`learned BLOCKED: ${dom} (direct ${d.code} / proxy ${p.code})`); pending_reload = true; pending_new++;
				}
			}
		} else if (p && p.block) {
			st.status = 'blocked_no_proxy';
			st.confirms = 0;
		} else {
			st.status = 'unknown';
			st.confirms = 0;
		}
	}

	function pass(run_now) {
		enabled = uci.get('homeproxy', 'automation', 'enabled');
		if (enabled !== '1') return;

		let domain_candidates = {}, ip_candidates = {};
		if (has('clash'))     for (let i, h in discover_clash(timeout)) domain_candidates[h] = true;
		if (has('dns'))       for (let i, h in discover_dns())          domain_candidates[h] = true;
		if (has('conntrack') && !length(keys(domain_candidates)))
			for (let i, ip in discover_conntrack()) ip_candidates[ip] = true;

		if (mode === 'aggressive') {
			for (let h in auto_set)     { let st = state[h]; if (!st || !st.last_probe || (time() - st.last_probe) > reeval_interval) domain_candidates[h] = true; }
			for (let h in auto_ip_set)  { let st = state[h]; if (!st || !st.last_probe || (time() - st.last_probe) > reeval_interval) ip_candidates[h] = true; }
		}

		let now = time();
		let probed = 0;
		const cap = 24;
		for (let host in domain_candidates) {
			if (probed >= cap) break;
			let dom = base_domain(host);
			if (!looks_like_host(dom)) continue;
			if (is_excluded(dom)) continue;
			if (length(keys(auto_set)) >= max_entries && !auto_set[dom]) continue;
			let st = state[dom];
			if (st && st.last_probe && (now - st.last_probe) < (mode === 'aggressive' ? reeval_interval : 86400)) continue;
			probed++;
			let d_res = probe(dom, false, timeout);
			let p_res = null;
			if (!d_res.ok) { p_res = probe(dom, true, timeout); sleep(150); }
			classify(dom, d_res, p_res, false);
			save_state(state);
		}

		/* IP learning (B): only when enabled and for non-private destinations. */
		if (ip_learn === '1') {
			for (let ip in ip_candidates) {
				if (probed >= cap) break;
				if (is_private_ip(ip) || is_excluded(ip)) continue;
				if (length(keys(auto_ip_set)) >= max_entries && !auto_ip_set[ip]) continue;
				let st = state[ip];
				if (st && st.last_probe && (now - st.last_probe) < (mode === 'aggressive' ? reeval_interval : 86400)) continue;
				probed++;
				let d_res = probe(ip, false, timeout);
				let p_res = null;
				if (!d_res.ok) { p_res = probe(ip, true, timeout); sleep(150); }
				classify(ip, d_res, p_res, true);
				save_state(state);
			}
		}

		/* Batch-flush window: apply when the time throttle elapsed OR enough new entries
		 * accumulated (so a burst of learns triggers a single core restart, not many). */
		if (pending_reload && ((now - last_reload) > reload_interval || (flush_min_entries > 0 && pending_new >= flush_min_entries)))
			do_reload();
		else if (pending_reload && run_now)
			do_reload();
	}

	/* Enable DNS query logging if we discover via dns. */
	if (has('dns')) enable_dns_log();

	if (state.__dns_offset) dns_log_offset = int(state.__dns_offset) || 0;

	log('automation daemon started (mode=' + mode + ', discover=' + discover + ', failover=' + dns_failover + ').');

		let last_failover = 0;
		while (true) {
			enabled = uci.get('homeproxy', 'automation', 'enabled');
			if (enabled !== '1') {
				log('automation disabled, exiting.');
				if (has('dns')) disable_dns_log();
				return;
			}

			let run_now = false;
			if (access(TRIGGER_FILE)) { 		system('rm -f ' + shellquote(TRIGGER_FILE)); run_now = true; }

			pass(run_now);

			/* DNS failover (C) at most once per minute. */
			let now = time();
			if (dns_failover === '1' && (now - last_failover) > 60) { last_failover = now; dns_failover_check(); }

		/* Persist dns log offset so we don't re-scan from the start after a restart. */
		state.__dns_offset = dns_log_offset;
		save_state(state);

		for (let i = 0; i < 10; i++) {
			sleep(1);
			if (access(TRIGGER_FILE)) { 		system('rm -f ' + shellquote(TRIGGER_FILE)); break; }
			if (uci.get('homeproxy', 'automation', 'enabled') !== '1') { if (has('dns')) disable_dns_log(); return; }
		}
	}
}

try {
	main();
} catch (e) {
		log('fatal: ' + sprintf('%s', e));
	if (access(DNS_LOG)) disable_dns_log();
}
