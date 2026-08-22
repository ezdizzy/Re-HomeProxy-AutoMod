#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — MultiDNS analyzer daemon.
 *
 * Complements (does NOT replace) the per-query racing done by the dedicated
 * smartdns instance. smartdns answers every client query by racing ALL servers
 * in a pool concurrently and returning the fastest LIVE IP (speed-check-mode
 * ping,tcp:443 + response-mode fastest-ip). This daemon is the OUT-OF-BAND
 * quality layer that:
 *   1. builds the smartdns config from the same UCI DNS lists (plain "Russia"
 *      pool + encrypted "secure" pool) — two separate groups / listeners;
 *   2. periodically probes every server of both pools IN PARALLEL, measuring
 *      reachability, answer latency and whether the returned IP is actually
 *      LIVE (TCP connect) — fast-but-dead (polluted / block-page) answers are
 *      detected and penalised (poisoning heuristic);
 *   3. keeps per-server trend stats (EWMA latency / success / live-IP ratio)
 *      and a composite quality SCORE, so the UI can show WHY a server is or
 *      isn't preferred;
 *   4. prunes redundant/ill servers from the live smartdns pool and reloads it,
 *      while always re-checking (trend-aware, never drops a server that was
 *      merely momentarily slow) — the fastest/reliable stay prioritised.
 *
 * The two pools mirror the app's split routing: the plain pool resolves
 * unblocked (domestic) sites; the secure pool resolves blocked / proxied
 * domains. Each runs on its own loopback listener the main config points at.
 *
 * NOTE: this ucode build has NO floating point and NO clamp()/float(), so all
 * ratios are kept as 0..100 scaled integers and all math is integer.
 */

'use strict';

import { access, readfile, writefile, open, stat } from 'fs';
import { cursor } from 'uci';
import { isEmpty } from 'homeproxy';

const HP_DIR = '/etc/homeproxy';
const RUN_DIR = '/var/run/homeproxy';
const MD_DIR = RUN_DIR + '/multidns';
const CONF = MD_DIR + '/smartdns.conf';
const PID = MD_DIR + '/smartdns.pid';
const STATE_FILE = MD_DIR + '/multidns_state.json';
const LOG_FILE = MD_DIR + '/multidns.log';
const SMARTDNS = '/usr/sbin/smartdns';
let PROXY = '127.0.0.1:5338';   /* dedicated socks5 inbound (secure pool tunnel); port from UCI multidns.proxy_port */

let uci = null;
let enabled = '0', use_plain = '1', use_secure = '1', secure_via_proxy = '1',
    bench_interval = 300, alpha = 40, min_live_ratio = 50, min_score = 20,
    plain_port = 5453, secure_port = 5454;

function log(msg) {
	const line = `[${sprintf('%d', time())}] [MDNS] ${msg}\n`;
	try {
		const fd = open(LOG_FILE, 'a');
		if (fd) { fd.write(line); fd.close(); }
	} catch (e) { /* best effort */ }
}

function dbg(m) {
	try { const fd = open('/tmp/mdbg.txt', 'a'); if (fd) { fd.write(m + '\n'); fd.close(); } } catch (e) {}
}

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function capture(cmd) {
	const tmp = MD_DIR + '/cap.tmp';
	system(cmd + ' > ' + shellquote(tmp) + ' 2>/dev/null');
	if (!access(tmp)) return '';
	let c = readfile(tmp);
	return c ? c : '';
}

function have_nc() { return !!access('/usr/bin/nc'); }

/* Atomically replace a file (temp + mv) so readers never see a truncated file. */
function atomic_write(path, content) {
	let tmp = path + '.tmp';
	writefile(tmp, content);
	system('mv -f ' + tmp + ' ' + path);
}

/* Parse a decimal-string option as a 0..100 scaled integer ("0.4" -> 40). */
function ratio100(s, def) {
	let t = trim(s || '');
	if (!length(t)) return def;
	let m = match(t, /^(\d+)(\.(\d+))?$/);
	if (!m) return def;
	let whole = int(m[1]);
	let frac = m[3] ? substr(m[3], 0, 2) : '0';
	while (length(frac) < 2) frac = frac + '0';
	let v = whole * 100 + int(frac);
	return (v > 100) ? 100 : v;
}

/* Split a configured DNS entry ("https://host/path", "tls://host", "1.2.3.4") into
 * transport + host + port + path so we can emit the right smartdns server line. */
function parse_entry(e) {
	let scheme = '', rest = e, host = e, port = '', path = '';
	let m = match(e, /^(https?|tls|quic):\/\/(.+)$/);
	if (m) { scheme = m[1]; rest = m[2]; }
	if (scheme === 'https')
		port = '443', path = '/dns-query';
	else if (scheme === 'tls' || scheme === 'quic')
		port = '853';
	let hp = match(rest, /^([^/:]+)(:(\d+))?(\/\S*)?$/);
	if (hp) { host = hp[1]; if (hp[3]) port = hp[3]; if (hp[4]) path = hp[4]; }
	return { scheme: scheme, host: host, port: port, path: path };
}

function to_list(v) {
	if (isEmpty(v)) return [];
	let a = (type(v) === 'array') ? v : [ v ];
	return filter(a, (x) => length(trim(x)) && x !== 'wan');
}

/* Parse a curl `%{time_total}` value ("0.123456") into integer milliseconds
 * (ucode has no floats, so keep it as a 0..N scaled int). Returns null if NaN. */
function ms_of(s) {
	let m = match(s, /^(\d+)(\.(\d+))?$/);
	if (!m) return null;
	let sec = int(m[1]);
	/* group 2 is ".\d+"; the bare digits we want are in the inner group 3. */
	let frac = m[3] ? substr(m[3], 0, 3) : '0';
	while (length(frac) < 3) frac = frac + '0';
	return sec * 1000 + int(frac);
}

/* Probe each server DIRECTLY (not via the racing listener) so every server gets
 * its own quality sample. The router's UDP/53 hijack (tproxy+nat) loops a direct
 * UDP query back into the resolver, so plain servers are probed over TCP (a raw
 * DNS query sent via nc) and secure servers over DoH (curl). No second smartdns
 * instance is started — smartdns is a singleton and refuses to run twice — and
 * no dig/drill/openssl are available. Returns { ok, ip, live, lat }. */
function have_ping() { return !!access('/bin/ping'); }
function have_curl() { return !!access('/usr/bin/curl'); }
function bchr(n) { return sprintf('%c', n); }

/* Build a minimal DNS A-query wire message (12-byte header + question) for name. */
function build_query(name) {
	let q = bchr(0x12) + bchr(0x12) + bchr(0x01) + bchr(0x00) + bchr(0x00) + bchr(0x01)
	      + bchr(0x00) + bchr(0x00) + bchr(0x00) + bchr(0x00) + bchr(0x00) + bchr(0x00);
	let labels = split(name, '.');
	for (let i = 0; i < length(labels); i = i + 1) {
		let l = labels[i];
		q = q + bchr(length(l)) + l;
	}
	q = q + bchr(0x00) + bchr(0x00) + bchr(0x01) + bchr(0x00) + bchr(0x01);
	return q;
}

/* Resolve `canary` against a plain DNS server over TCP/53 and return the A-record
 * IP, or null. TCP bypasses the UDP/53 hijack that loops UDP back into the resolver. */
function tcp_dns_query(server, canary) {
	let qf = MD_DIR + '/dq.bin';
	let af = MD_DIR + '/da.bin';
	let q = build_query(canary);
	let qlen = length(q);
	/* DNS-over-TCP prefixes the message with its 2-byte big-endian length. */
	let msg = bchr(int(qlen / 256)) + bchr(qlen % 256) + q;
	writefile(qf, msg);
	/* busybox nc is minimal (no -w/-z flags), so background it and cap the probe
	 * at ~3s so an unresponsive server can't hang the analyze loop. */
 	system('nc ' + shellquote(server) + ' 53 < ' + shellquote(qf) + ' > ' + shellquote(af) + ' 2>/dev/null & NCPID=$!; sleep 6; kill $NCPID 2>/dev/null');
	let a = readfile(af);
	if (!a || length(a) < 14) return null;
	/* 2-byte length prefix, then the 12-byte header; ANCOUNT is at header
	 * offset 6-7 => absolute offset 8-9. */
	let an = ord(substr(a, 8, 1)) * 256 + ord(substr(a, 9, 1));
	if (an < 1) return null;
	if (length(a) < 4) return null;
	let b1 = ord(substr(a, length(a) - 4, 1));
	let b2 = ord(substr(a, length(a) - 3, 1));
	let b3 = ord(substr(a, length(a) - 2, 1));
	let b4 = ord(substr(a, length(a) - 1, 1));
	if (b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) return null;
	return sprintf('%d.%d.%d.%d', b1, b2, b3, b4);
}

/* Resolve `canary` against a DoH server and return { ip, lat }. Tries both the
 * RFC8484 JSON endpoint (/dns-query?name=…, used by Cloudflare) and Google's
 * /resolve?name=… (Google rejects ?name= on /dns-query), and both the proxied
 * and direct paths so the monitor reflects reachability whether or not the
 * tunnel is up. */
function doh_query(host, path, canary, via_proxy) {
	if (!have_curl()) return { ip: null, lat: null };
	let hdr = "-H 'accept: application/dns-json' ";
	let url1 = 'https://' + host + (path || '/dns-query') + '?name=' + canary + '&type=A';
	let url2 = 'https://' + host + '/resolve?name=' + canary + '&type=A';
	let attempts = [];
	if (via_proxy) push(attempts, '-x socks5h://' + PROXY + ' ');
	push(attempts, '');
	for (let ai = 0; ai < length(attempts); ai = ai + 1) {
		let proxy = attempts[ai];
		for (let u = 0; u < 2; u = u + 1) {
			let url = (u === 0) ? url1 : url2;
			let out = MD_DIR + '/cap.tmp';
			system(`curl -s --max-time 4 ${proxy}${hdr}-w '\\n%{time_total}' ${shellquote(url)} > ${shellquote(out)} 2>/dev/null`);
			let raw = readfile(out) || '';
			let parts = split(raw, '\n');
			if (!length(parts)) continue;
			let body = join('\n', slice(parts, 0, length(parts) - 1));
			if (body) {
				try {
					let j = json(body);
					let ans = j.Answer || [];
					for (let k = 0; k < length(ans); k = k + 1) {
						let x = ans[k];
						if (x.type === 1 && match(x.data, /^[0-9.]+$/)) {
							let lat = ms_of(trim(parts[length(parts) - 1]));
							return { ip: x.data, lat: lat };
						}
					}
				} catch (e) {}
			}
		}
	}
	return { ip: null, lat: null };
}

function probe_server(server, group, via_proxy, canary) {
	let ip = null, lat = null;
	if (group === 'secure') {
		let p = parse_entry(server);
		let r = doh_query(p.host, p.path, canary, via_proxy);
		ip = r.ip; lat = r.lat;
	} else {
		ip = tcp_dns_query(server, canary);
		if (have_ping()) {
			let out = MD_DIR + '/cap.tmp';
			system(`ping -c1 -w2 ${shellquote(server)} > ${shellquote(out)} 2>/dev/null`);
			let raw = readfile(out) || '';
			let m = match(raw, /time[= ]+([0-9]+)(\.[0-9]+)?\s*ms/);
			if (m) lat = int(m[1]);
		}
	}
	let live = !!ip;
	return { ok: !!ip, ip: ip, live: live, lat: lat };
}

/* If a server's canary answer disagrees with the clear majority it is very
 * likely poisoned (ISP block-page / bogus answer). Only flag when a consensus
 * of >=2 servers exists. Returns a map server->true (poisoned). */
function score_consensus(canary_ips) {
	let counts = {};
	for (let s, ip in canary_ips) if (ip) counts[ip] = (counts[ip] || 0) + 1;
	let best = null, bestn = 0;
	for (let ip, n in counts) if (n > bestn) { bestn = n; best = ip; }
	if (bestn < 2) return {};
	let poisoned = {};
	for (let s, ip in canary_ips) if (ip && ip !== best) poisoned[s] = true;
	return poisoned;
}

function load_state() {
	if (!access(STATE_FILE)) return { servers: {} };
	let c = readfile(STATE_FILE);
	if (!c) return { servers: {} };
	try { let j = json(c); return j && j.servers ? j : { servers: {} }; } catch (e) { return { servers: {} }; }
}

function save_state(state) {
	atomic_write(STATE_FILE, sprintf('%.J\n', state));
}

/* Composite quality score 0..100 (all integer math). Faster latency and higher
 * live/success ratios win; a poisoned answer is crushed. */
function compute_score(s) {
  /* NaN guard: ucode has no isFinite(); NaN is the only value that differs
   * from itself, so `x == x` is false exactly for NaN. */
  let lat = (s.lat != null && s.lat == s.lat) ? s.lat : null;
  let speed = (lat != null) ? (100 - ((lat * 100) / 500)) : 100;
  if (speed < 0) speed = 0; if (speed > 100) speed = 100;
  if (speed != speed) speed = 100;
  let succ = (s.succ != null && s.succ == s.succ) ? s.succ : 50;   /* 0..100 */
  let live = (s.live != null && s.live == s.live) ? s.live : 50;   /* 0..100 */
  let sc = (45 * speed + 30 * succ + 25 * live) / 100;
  if (sc != sc) sc = 0;
  if (s.poisoned) sc = (sc * 20) / 100;
  return sc;
}

/* Build the smartdns config text. Pruned servers (in state) are omitted so they
 * are dropped from the live racing pool. */
function build_smartdns_conf() {
	let lines = [];
	push(lines, 'server-name hp-multidns');
	push(lines, 'log-level warn');
	push(lines, 'log-file ' + LOG_FILE + '.sd');
	push(lines, 'log-size 256K');
	push(lines, 'log-num 1');
	push(lines, 'cache-size 4096');
	push(lines, 'prefetch-domain no');
	push(lines, 'serve-expired yes');
	push(lines, 'dualstack-ip-selection no');
	push(lines, 'force-AAAA-SOA yes');

	let main_node = uci.get('homeproxy', 'config', 'main_node') || 'nil';
	let proxy_real = !(main_node in ['byedpi-out', 'zapret-out']);
	if (secure_via_proxy !== '0' && proxy_real)
		push(lines, `proxy-server socks5://${PROXY} -name hpproxy`);
	let proxy_line = (secure_via_proxy !== '0' && proxy_real) ? ' -proxy hpproxy' : '';

	push(lines, 'response-mode fastest-ip');
	push(lines, 'speed-check-mode ping,tcp:443');
	if (use_plain !== '0') {
		push(lines, `bind 127.0.0.1:${plain_port} -group ru -no-rule-addr`);
	}
	if (use_secure !== '0') {
		push(lines, `bind 127.0.0.1:${secure_port} -group secure -no-rule-addr`);
	}

	let mode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
	let plain = [];
	if (mode === 'proxy_banned_ru')
		plain = to_list(uci.get('homeproxy', 'config', 'russia_dns_server'));
	else if (mode === 'bypass_cn')
		plain = to_list(uci.get('homeproxy', 'config', 'china_dns_server'));
	else if (mode === 'bypass_ir')
		plain = to_list(uci.get('homeproxy', 'config', 'iran_dns_server'));
	else if (mode === 'global')
		plain = to_list(uci.get('homeproxy', 'config', 'dns_server'));

	let secure = to_list(uci.get('homeproxy', 'config', 'secure_dns_server'));

	let st = load_state();
	for (let e in plain) {
		if (st.servers[e] && st.servers[e].pruned) continue;
		/* Use TCP upstreams for the plain pool: the router's DNS interception
		 * (nftables tproxy + nat hijack) only catches UDP/53, so a plain UDP
		 * query from smartdns would be looped back into the resolver (which,
		 * with MultiDNS on, points at smartdns) and never reach the server.
		 * TCP/53 is exempt from that interception and reaches the server directly. */
		push(lines, `server-tcp ${e} -group ru`);
	}
	for (let e in secure) {
		if (st.servers[e] && st.servers[e].pruned) continue;
		let p = parse_entry(e);
		if (p.scheme === 'https')
			push(lines, `server-https https://${p.host}${p.path || '/dns-query'} -group secure${proxy_line}`);
		else if (p.scheme === 'tls')
			push(lines, `server-tls tls://${p.host}${p.port ? ':' + p.port : ''} -group secure${proxy_line}`);
		else if (p.scheme === 'quic')
			push(lines, `server-quic quic://${p.host}${p.port ? ':' + p.port : ''} -group secure${proxy_line}`);
		else
			push(lines, `server-tcp ${e} -group secure`);
	}
	return join('\n', lines) + '\n';
}

/* Kill every smartdns instance started from OUR config (smartdns is a
 * singleton and refuses to start while a stale pid/lock points at a dead
 * process, which left the daemon in a "not running — restarting" loop). */
function kill_our_smartdns() {
	let out = trim(capture('pidof smartdns 2>/dev/null'));
	if (!length(out)) return;
	let pids = split(out, ' ');
	for (let i = 0; i < length(pids); i = i + 1)
		system('kill ' + trim(pids[i]) + ' 2>/dev/null');
	sleep(1);
}

function smartdns_running() {
	/* busybox `ps` truncates the cmdline, so a `ps | grep` on our config
	 * matches nothing. Detect by process name instead (only our instance
	 * runs — the system smartdns service is disabled). */
	let out = trim(capture('pidof smartdns 2>/dev/null'));
	return length(out) > 0;
}

function start_smartdns() {
	/* Guard: if smartdns is already running with the exact same config, leave it
	 * alone. This prevents a restart spiral (kill+restart every tick) if the
	 * periodic config-diff check ever fires spuriously, and avoids the TCP port
	 * getting stuck in TIME_WAIT on a needless restart. */
	let conf = build_smartdns_conf();
	if (smartdns_running() && access(CONF) && trim(readfile(CONF)) === trim(conf)) {
		/* Already running with the same config: don't delete our pid file
		 * (the monitor reads it) — just (re)record the live pid. */
		let out = trim(capture('pidof smartdns 2>/dev/null'));
		if (length(out)) atomic_write(PID, out);
		return;
	}
	system('mkdir -p ' + MD_DIR);
	atomic_write(CONF, conf);
	if (!access(SMARTDNS)) { log('smartdns not installed — MultiDNS disabled.'); return; }
	/* Always (re)start cleanly: kill any instance of our config and clear the
	 * singleton locks smartdns consults, then launch directly. start-stop-daemon
	 * fought the smartdns singleton and left it dead in a restart loop. */
	kill_our_smartdns();
	system('rm -f /var/run/smartdns.pid /tmp/run/smartdns.pid /var/run/homeproxy/multidns/smartdns.pid /tmp/run/homeproxy/multidns/smartdns.pid');
	let err = MD_DIR + '/smartdns.start.err';
	system(`${SMARTDNS} -f -c ${shellquote(CONF)} >${shellquote(err)} 2>&1 &`);
	sleep(2);
	if (smartdns_running()) {
		/* Record the live pid (echo $! across system() is unreliable here). */
		let out = trim(capture('pidof smartdns 2>/dev/null'));
		if (length(out)) atomic_write(PID, out);
		system('rm -f ' + shellquote(err));
	} else {
		log('smartdns failed to start — last error: ' + trim(readfile(err) || '(none)'));
	}
}

function stop_smartdns() {
	if (access(PID)) {
		let c = trim(readfile(PID));
		if (c) system(`kill ${shellquote(c)} 2>/dev/null`);
		system('rm -f ' + shellquote(PID));
	}
	kill_our_smartdns();
}

function analyze() {
	dbg('a:enter');
	let st = load_state();
	dbg('a:loaded');
	if (!st.servers) st.servers = {};
	let mode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
	dbg('a:mode=' + mode);
	let canary_plain = 'example.com';
	let canary_secure = 'cloudflare.com';
	let main_node = uci.get('homeproxy', 'config', 'main_node') || 'nil';
	dbg('a:main=' + main_node);
	let via_proxy = (secure_via_proxy !== '0') && !(main_node in ['byedpi-out', 'zapret-out']);
	dbg('a:via=' + via_proxy);

	let pools = [];
	if (use_plain) {
		let pl = (mode === 'proxy_banned_ru') ? to_list(uci.get('homeproxy', 'config', 'russia_dns_server'))
			: (mode === 'bypass_cn') ? to_list(uci.get('homeproxy', 'config', 'china_dns_server'))
			: (mode === 'bypass_ir') ? to_list(uci.get('homeproxy', 'config', 'iran_dns_server'))
			: (mode === 'global') ? to_list(uci.get('homeproxy', 'config', 'dns_server')) : [];
		push(pools, { group: 'ru', servers: pl, canary: canary_plain, via: false });
	}
	if (use_secure)
		push(pools, { group: 'secure', servers: to_list(uci.get('homeproxy', 'config', 'secure_dns_server')), canary: canary_secure, via: via_proxy });

	/* EWMA smoothing factors as scaled ints. */
	let a_ok = alpha;            /* weight of new sample (0..100) */
	let a_old = 100 - alpha;     /* weight of history */

	let canary_ips_ru = {};
	let canary_ips_secure = {};
	dbg('analyze enter pools=' + length(pools));
	for (let pi = 0; pi < length(pools); pi = pi + 1) {
		let p = pools[pi];
		for (let si = 0; si < length(p.servers); si = si + 1) {
			let s = p.servers[si];
			try {
			let r = probe_server(s, p.group, p.via, p.canary);
			if (r.lat != null && r.lat != r.lat) r.lat = null;  /* NaN guard */
			if (p.group === 'ru') canary_ips_ru[s] = r.ok ? r.ip : null;
				else canary_ips_secure[s] = r.ok ? r.ip : null;
				let cur = st.servers[s] || { lat: null, succ: null, live: null, samples: 0, pruned: false };
				let okf = r.ok ? 100 : 0;
				let livef = (r.ok && r.live) ? 100 : 0;
				cur.succ = (cur.succ == null) ? okf : ((a_ok * okf + a_old * cur.succ) / 100);
				cur.live = (cur.live == null) ? livef : ((a_ok * livef + a_old * cur.live) / 100);
				cur.samples = (cur.samples || 0) + 1;
				cur.last_ip = r.ip;
				cur.last_ok = r.ok;
				cur.last_live = r.live;
				cur.lat = r.lat;
				st.servers[s] = cur;
			} catch (e) { dbg('probe error [' + s + ']: ' + sprintf('%s', e)); }
		}
	}
	dbg('analyze probed');
	/* Poisoning is per-pool: a server whose canary answer disagrees with its pool's
	 * majority is very likely returning a polluted/block-page IP. */
	dbg('analyze consensus');
	let poisoned_ru = score_consensus(canary_ips_ru);
	let poisoned_sec = score_consensus(canary_ips_secure);
	let all_poisoned = {};
	for (let s in poisoned_ru) all_poisoned[s] = true;
	for (let s in poisoned_sec) all_poisoned[s] = true;
	for (let s in all_poisoned) if (st.servers[s]) st.servers[s].poisoned = true;

	dbg('analyze scoring');
	let changed = false;
	for (let s in st.servers) {
		let sc = compute_score(st.servers[s]);
		st.servers[s].score = sc;
		let samples = st.servers[s].samples || 0;
		let bad = (sc < int(min_score)) && (samples >= 3)
			&& (st.servers[s].live != null && st.servers[s].live < int(min_live_ratio))
			&& (st.servers[s].succ != null && st.servers[s].succ < 50);
		if (bad && !st.servers[s].pruned) { st.servers[s].pruned = true; changed = true; log('pruned bad server ' + s + ' (score ' + sc + ')'); }
		else if (!bad && st.servers[s].pruned) { st.servers[s].pruned = false; changed = true; log('restored server ' + s + ' (score ' + sc + ')'); }
	}
	dbg('analyze save');
	save_state(st);
	if (changed) { log('pool changed — reloading smartdns'); start_smartdns(); 	}
}

function main() {
	dbg('main:start');
	uci = cursor();
	system('mkdir -p ' + MD_DIR);

	/* Outer loop: stay resident. If MultiDNS is disabled we idle (stop smartdns
	 * and sleep) instead of exiting — procd respawns an exiting instance, which
	 * would create a crash-loop on every disable toggle. procd SIGTERM on service
	 * stop still kills us cleanly. */
	while (true) {
		uci.load('homeproxy');
		enabled = uci.get('homeproxy', 'multidns', 'enabled') || '0';
		if (enabled !== '1') {
			stop_smartdns();
			dbg('main: disabled, waiting');
			sleep(10);
			continue;
		}
		use_plain = (uci.get('homeproxy', 'multidns', 'use_plain') || '1') !== '0';
		use_secure = (uci.get('homeproxy', 'multidns', 'use_secure') || '1') !== '0';
		secure_via_proxy = (uci.get('homeproxy', 'multidns', 'secure_via_proxy') || '1') !== '0';
		bench_interval = int(uci.get('homeproxy', 'multidns', 'bench_interval') || '300') || 300;
		alpha = ratio100(uci.get('homeproxy', 'multidns', 'alpha') || '0.4', 40);
		min_live_ratio = ratio100(uci.get('homeproxy', 'multidns', 'min_live_ratio') || '0.5', 50);
		min_score = int(uci.get('homeproxy', 'multidns', 'min_score') || '20') || 20;
		plain_port = uci.get('homeproxy', 'multidns', 'plain_port') || '5453';
		secure_port = uci.get('homeproxy', 'multidns', 'secure_port') || '5454';
		PROXY = '127.0.0.1:' + (uci.get('homeproxy', 'multidns', 'proxy_port') || '5338');

		if (!access(SMARTDNS)) { log('smartdns binary missing — install smartdns to use MultiDNS.'); sleep(30); continue; }

		log('MultiDNS analyzer started (plain=' + use_plain + ', secure=' + use_secure + ', via_proxy=' + secure_via_proxy + ').');
		start_smartdns();
		/* Run an initial analysis at startup so the monitor shows real pool data
		 * immediately instead of waiting a full bench_interval. */
		dbg('analyze call (initial)');
		analyze();
		dbg('analyze done (initial)');

		let last = time(), last_cfg = 0;
		while (true) {
			sleep(5);
			let now = time();
			uci.load('homeproxy');
			let en2 = uci.get('homeproxy', 'multidns', 'enabled') || '0';
			if (en2 !== '1') { log('MultiDNS disabled, stopping smartdns.'); stop_smartdns(); break; }
			use_plain = (uci.get('homeproxy', 'multidns', 'use_plain') || '1') !== '0';
			use_secure = (uci.get('homeproxy', 'multidns', 'use_secure') || '1') !== '0';
			secure_via_proxy = (uci.get('homeproxy', 'multidns', 'secure_via_proxy') || '1') !== '0';
			bench_interval = int(uci.get('homeproxy', 'multidns', 'bench_interval') || '300') || 300;
			plain_port = uci.get('homeproxy', 'multidns', 'plain_port') || '5453';
			secure_port = uci.get('homeproxy', 'multidns', 'secure_port') || '5454';
			PROXY = '127.0.0.1:' + (uci.get('homeproxy', 'multidns', 'proxy_port') || '5338');

			/* Fast self-heal: if smartdns died for any reason, bring it back up
			 * within one loop tick (~5s) so DNS never stays down. */
			if (!smartdns_running()) { log('smartdns not running — restarting.'); start_smartdns(); }

			if ((now - last_cfg) > 30) {
				dbg('loop cfg-check');
				last_cfg = now;
				let fresh = build_smartdns_conf();
				if (!access(CONF) || trim(readfile(CONF)) !== fresh) {
					atomic_write(CONF, fresh);
					start_smartdns();
				}
			}
			if ((now - last) > bench_interval) {
				last = now;
				dbg('analyze call');
				analyze();
				dbg('analyze done');
			}
		}
		/* inner loop exited because MultiDNS was disabled; outer loop sleeps and
		 * waits for it to be re-enabled. */
	}
}

try {
	main();
} catch (e) {
	dbg('CATCH: ' + sprintf('%s', e));
	log('fatal: ' + sprintf('%s', e));
}