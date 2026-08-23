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
 *   sni       — TLS ClientHello SNI capture on the LAN (catches DoH clients,
 *               apps with hardcoded IPs and games that never hit the DNS log)
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
	body = lc(body);
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
/* Normalized body fingerprint (length + head/tail, lowercased) — enough to tell
 * "the same block page" from "a different real page". */
function fingerprint(b) {
	if (!b) return '';
	b = lc(b);
	let head = substr(b, 0, 64);
	let tail = (length(b) > 64) ? substr(b, length(b) - 64, 64) : '';
	return sprintf('%d:%s:%s', length(b), head, tail);
}

/* Probe a host BOTH direct and via the configured main path. Returns an object
 * { code, ok, block, fp } instead of a bare 'ok'/'fail' so classification can tell
 * apart "unreachable" (000/timeout), "blocked" (4xx/5xx or a 200 block-page),
 * and "reachable" (2xx/3xx with a real page). This is what lets us learn the
 * 403-via-direct / works-via-proxy case that the old code missed. `fp` is a
 * normalized body fingerprint used to detect "proxy returns the same block page"
 * (a block page the signature list missed). HTTPS is tried first; on failure a
 * plain HTTP retry covers HTTP-only / redirect-to-http sites.
 *
 * BOTH probes go through the dedicated automation test inbounds (generate_client
 * emits them with hard route rules): direct = auto-direct-in (:5336) → direct-out,
 * proxy = auto-proxy-in (:5337) → main-out. A plain router-originated curl is NOT
 * a reliable "direct" probe — the router's own output interception can reroute it
 * through the proxy (e.g. when the host matches the blocklist), which silently
 * fakes "direct works". The pinned inbounds make the two paths explicit.
 *
 * DNS-view matters a lot: the direct probe must measure the path the user's
 * browser actually gets. The router's DNS (mosdns racing) can intermittently
 * fall back to the SECURE pool (DoH through the proxy) and return non-RU-edge
 * answers (observed with Vercel: browser got arn1 403, probe got iad1 200 —
 * the probe resolved through the proxy's DNS view and "direct" looked fine).
 * So the direct probe resolves the host against a PLAIN public resolver as seen
 * from Russia and pins the connection to that answer with --resolve — the same
 * RU-facing resolution a browser would use. The proxy probe keeps `socks5h`
 * (resolve at the tunnel end) so locally poisoned answers can't break the
 * proxy-side measurement. */
function resolve_plain_view(host) {
	let out = capture(`nslookup -type=A ${shellquote(host)} 8.8.8.8 2>/dev/null`);
	if (!match(out, /Address/)) {
		out = capture(`nslookup -type=A ${shellquote(host)} 1.1.1.1 2>/dev/null`);
		if (!match(out, /Address/))
			out = capture(`nslookup -type=A ${shellquote(host)} 77.88.8.8 2>/dev/null`);
	}
	for (let l in split(out, '\n')) {
		let m = match(trim(l), /^Address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/);
		if (m && m[1] !== '127.0.0.1')
			return m[1];
	}
	return null;
}

function probe(host, via_proxy, timeout) {
	let pin = '';
	if (!via_proxy) {
		/* Plain-view resolution is mandatory for the direct probe: if the plain
		 * public DNS can't answer (RKN blocks it intermittently), the user's
		 * browser can't reach the site directly either — report unreachable
		 * (000) instead of falling back to a possibly proxy-side DNS answer. */
		let ip = null;
		for (let t = 0; t < 3 && !ip; t = t + 1) {
			ip = resolve_plain_view(host);
			if (!ip) sleep(150);
		}
		if (!ip)
			return { code: '000', ok: false, block: false, fp: '' };
		pin = ` --resolve ${shellquote(host + ':443:' + ip)}`;
	}
	let proxy_arg = via_proxy
		? ` -x socks5h://127.0.0.1:${AUTO_PROXY_PORT}`
		: ` -x socks5://127.0.0.1:${AUTO_DIRECT_PORT}`;
	if (have_curl()) {
		let bodyf = RUN_DIR + '/pb.tmp';
		let codef = RUN_DIR + '/pc.tmp';
		let code = '000', c = 'fail';
		/* 1) HTTPS. Always clear the temp files first: a failed/timed-out curl
		 * leaves STALE content behind, and reading it back silently reports the
		 * previous probe's code — a nasty source of false "200 direct" results. */
		system(`rm -f ${shellquote(bodyf)} ${shellquote(codef)}`);
		system(`curl -sL --max-redirs 3 -o ${shellquote(bodyf)} -w '%{http_code}' -k --connect-timeout ${timeout} --max-time ${timeout} ${proxy_arg}${pin} ${shellquote('https://' + host)} > ${shellquote(codef)} 2>/dev/null`);
		code = trim(readfile(codef) || '000');
		c = classify_code(code);
		if (c === 'fail') {
			/* 2) HTTPS failed — retry plain HTTP (HTTP-only / redirect-to-http sites). */
			system(`rm -f ${shellquote(bodyf)} ${shellquote(codef)}`);
			system(`curl -sL --max-redirs 3 -o ${shellquote(bodyf)} -w '%{http_code}' -k --connect-timeout ${timeout} --max-time ${timeout} ${proxy_arg}${pin} ${shellquote('http://' + host)} > ${shellquote(codef)} 2>/dev/null`);
			code = trim(readfile(codef) || '000');
			c = classify_code(code);
		}
		let body = readfile(bodyf) || '';
		let fp = fingerprint(body);
		let block = (c === 'block');
		if (c === 'ok') {
			/* A 2xx/3xx response is a real page UNLESS the body is small AND
			 * carries a block-page signature (MITM block pages served with 200).
			 * Large pages are never block pages — this kills false positives on
			 * big portals/news sites that merely contain a signature word
			 * somewhere in their markup. */
			if (length(body) < 32768 && body_blocked(body))
				block = true;
		}
		let ok = (c === 'ok') && !block;
		return { code: code, ok: ok, block: block, fp: fp };
	}
	let wget_port = via_proxy ? AUTO_PROXY_PORT : AUTO_DIRECT_PORT;
	let proxy_env = `http_proxy=http://127.0.0.1:${wget_port} https_proxy=http://127.0.0.1:${wget_port}`;
	let rc = system(`${proxy_env} /usr/bin/wget -q -T ${timeout} -t 1 --no-check-certificate -O /dev/null ${shellquote('https://' + host)} 2>/dev/null`, timeout * 1000 + 2000);
	let ok = (rc === 0);
	return { code: ok ? '200' : '000', ok: ok, block: false, fp: '' };
}

function is_private_ip(ip) {
	return match(ip, /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) || match(ip, /^fc00:|^fe80:/) || ip === '0.0.0.0';
}

function is_excluded(host) {
	host = trim(host);
	if (!length(host)) return true;
	/* Russian TLDs are NEVER learned — in Russia they must always go direct.
	 * Hard-coded (not just the default exclude list) so no config change can
	 * accidentally start probing .ru/.рф/.su sites. */
	if (substr(host, -3) === '.ru' || substr(host, -3) === '.su' || substr(host, -3) === '.рф')
		return true;
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

/* SNI discovery (source `sni`): capture TLS ClientHello packets on the LAN bridge
 * and extract the server_name (SNI) hostnames. This catches DoH clients, apps with
 * hardcoded IPs and games that never hit the dnsmasq log. Best-effort — requires
 * tcpdump and returns nothing ([]) when it is absent. The normal probe/classify
 * step still filters junk, so false candidates are never learned. */
function discover_sni() {
	if (!access('/usr/sbin/tcpdump') && !access('/usr/bin/tcpdump')) return [];
	let tmp = RUN_DIR + '/sni.tmp';
	/* PSH set (tcp[13]&8 != 0) + dst port 443 → ClientHello/first data. ASCII dump
	 * (-A) reveals the plaintext SNI. Bounded to ~20 packets and ~5s. */
	system(`tcpdump -i br-lan -s 160 -A -c 20 'tcp port 443 and (tcp[13] & 8 != 0)' > ` + shellquote(tmp) + ` 2>/dev/null & TDPID=$!; sleep 5; kill $TDPID 2>/dev/null`);
	let out = readfile(tmp) || '';
	if (!length(out)) return [];
	let hosts = [];
	let lines = split(out, '\n');
	for (let i = 0; i < length(lines); i = i + 1) {
		/* No {1,} quantifier — this ucode's regex engine rejects open-ended
		 * intervals ("Repetition not preceded by valid expression"); use +. */
		let m = match(lines[i], /([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+)/);
		if (m && looks_like_host(m[1])) push(hosts, m[1]);
	}
	return hosts;
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
	/* Newest first: the domains queried most recently are the most likely to be
	 * the user's current pain — the per-cycle probe cap should spend on them,
	 * not on the oldest traffic in the log. */
	let rev = [];
	for (let i = length(hosts) - 1; i >= 0; i = i - 1)
		push(rev, hosts[i]);
	return rev;
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

function do_failover_reload() {
	system('ucode ' + HP_DIR + '/scripts/generate_client.uc >' + RUN_DIR + '/generate_client.log 2>&1');
	if (!access(RUN_DIR + '/hiddify-c.json')) {
		log('DNS failover: regenerate FAILED — see ' + RUN_DIR + '/generate_client.log');
		return;
	}
	log('DNS failover: restarting service to load new config.');
	system('/etc/init.d/homeproxy reload >/dev/null 2>&1');
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
	/* Load the learned list but drop entries that are now excluded (.ru/.рф/.su
	 * or user excludes) — self-heals lists learned by older versions. If anything
	 * was dropped, persist the cleaned list right away. */
	let dropped = 0;
	for (let d in read_lines(AUTO_LIST)) {
		d = trim(d);
		if (!length(d)) continue;
		if (substr(d, -3) === '.ru' || substr(d, -3) === '.su' || substr(d, -3) === '.рф') {
			log('dropping learned entry (RU TLD always goes direct): ' + d);
			dropped++;
			continue;
		}
		auto_set[d] = true;
	}
	for (let d in read_lines(AUTO_IP_LIST)) auto_ip_set[trim(d)] = true;
	if (dropped > 0)
		write_auto_list(auto_set);
	let state = load_state();
	if (state.__dns_offset) dns_log_offset = int(state.__dns_offset) || 0;

	let last_reload = 0;
	pending_reload = false;
	const has = (s) => (discover === 'all') || index(split(discover, ','), s) >= 0 || (discover === 'both' && s in ['clash', 'dns']);

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
			/* Proxy returns a real page, but if its body matches the direct body
			 * (a block page the signature list missed), the proxy doesn't actually
			 * help → treat as blocked_no_proxy, not a learnable block. */
			if (d.fp && p.fp && d.fp === p.fp) {
				st.status = 'blocked_no_proxy';
				st.confirms = 0;
				return;
			}
			/* Unreachable direct (000/timeout/RST) can be a transient blip — require
			 * ONE extra confirmation before learning. A hard refusal (4xx/5xx) is a
			 * strong block signal and learns at the normal min_confirm. */
			const need = (d.code === '000') ? min_confirm + 1 : min_confirm;
			st.status = 'blocked';
			st.confirms = (st.confirms || 0) + 1;
			if (st.confirms >= need) {
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
		/* DNS first: it captures the domain at query time, newest-first, so the
		 * probe cap always spends on the user's most recent activity — the most
		 * transparent and reliable source. Clash/SNI/conntrack fill in the gaps. */
		if (has('dns'))       for (let i, h in discover_dns())          domain_candidates[h] = true;
		if (has('clash'))     for (let i, h in discover_clash(timeout)) domain_candidates[h] = true;
		if (has('sni'))       for (let i, h in discover_sni())          domain_candidates[h] = true;
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
			/* Probe the ACTUAL candidate host (the exact domain the user queried /
			 * the SNI their client sent) — NOT the collapsed base domain. Many
			 * blocks are subdomain-scoped (e.g. app.kilo.ai is blocked while
			 * kilo.ai works), and probing only the base domain hides them. */
			let dom = trim(host);
			if (substr(dom, -1) === '.') dom = substr(dom, 0, length(dom) - 1);
			if (substr(dom, 0, 4) === 'www.') dom = substr(dom, 4);
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
