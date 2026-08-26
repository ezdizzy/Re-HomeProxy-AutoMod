#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — MultiDNS analyzer daemon (mosdns engine).
 *
 * Complements the per-query racing done by a dedicated mosdns instance. mosdns
 * answers every client query by racing several servers of a pool concurrently and
 * returning the fastest valid answer, with anti-poisoning (plain → secure fallback)
 * and dead-IP filtering (an out-of-band HTTP verifier blacklists IPs that do not
 * actually serve the site). This daemon is the OUT-OF-BAND quality layer that:
 *   1. builds the mosdns v5 YAML config from the same UCI DNS lists (plain "Russia"
 *      pool + encrypted "secure" pool) — two separate groups / listeners;
 *   2. periodically probes every server of both pools IN PARALLEL, measuring
 *      reachability, answer latency and whether the returned IP actually OPENS the
 *      site over HTTPS (a real HTTP request, not a ping) — fast-but-dead (polluted /
 *      block-page) answers are detected and their IPs blacklisted;
 *   3. keeps per-server trend stats (EWMA latency / success / open-ratio) and a
 *      composite quality SCORE, so the UI can show WHY a server is or isn't preferred;
 *   4. prunes servers that are consistently bad (success or open-ratio below threshold
 *      for several consecutive cycles) from the live mosdns pool and reloads it, while
 *      always re-checking so a transiently-slow server recovers — the fastest/reliable
 *      stay prioritised.
 *
 * The two pools mirror the app's split routing: the plain pool resolves unblocked
 * (domestic) sites; the secure pool resolves blocked / proxied domains. Each runs on
 * its own loopback listener the main config points at (127.0.0.1:5453 / :5454).
 * When secure_via_proxy is set, the secure pool's DoH/DoT rides the dedicated
 * loopback inbound mdns-proxy-in (127.0.0.1:5338 → main-out) so the ISP cannot even
 * see the encrypted query.
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
const RES = HP_DIR + '/resources';
const CONF = MD_DIR + '/mosdns.yaml';
const PID = MD_DIR + '/mosdns.pid';
const STATE_FILE = MD_DIR + '/multidns_state.json';
const LOG_FILE = MD_DIR + '/multidns.log';
const MOSDNS = '/usr/bin/mosdns';
const DEAD_IPS_FILE = MD_DIR + '/dead_ips.txt';
const PROXY_DOMAINS_FILE = MD_DIR + '/proxy_domains.txt';
const PROXY_IPS_FILE = MD_DIR + '/proxy_ips.txt';
const QUARANTINE_FILE = MD_DIR + '/quarantine_domains.txt';
const DNS_LOG = '/var/log/dnsmasq-q.log';   /* dnsmasq query log (enabled by the automation daemon) */
let PROXY = '127.0.0.1:5338';   /* dedicated mdns-proxy-in (mixed) pinned to main-out */

/* Direct (unproxied) DoH upstreams spliced into the plain group when EVERY
 * plaintext entry of the pool is measured dead or poisoned — the wholesale
 * port-53 interception case (UDP swallowed, TCP answered with fakes, DoT
 * blocked) where plaintext DNS cannot ever work. By-IP endpoints: no hostname,
 * so no DNS bootstrap is needed to reach them. */
const AUTO_DOH = [ 'https://1.1.1.1/dns-query', 'https://8.8.8.8/resolve' ];

/* Canary set for the plain pool's poisoning verification (multi-canary): a mix
 * of stable international and domestic names, rotated per cycle. An answer IP
 * counts as "open" if it opens at least one canary — a poisoned answer opens
 * none. */
const CANARIES_PLAIN = [ 'example.com', 'cloudflare.com', 'ya.ru' ];
const CANARIES_SECURE = [ 'cloudflare.com', 'example.com' ];

let uci = null;
let enabled = '0', use_plain = '1', use_secure = '1', secure_via_proxy = '1',
    bench_interval = 120, alpha = 40, min_live_ratio = 50, min_score = 20,
    plain_port = 5453, secure_port = 5454;
let autodoh_active = null;   /* tri-state: unset/true/false — for one-shot logging */
let user_dns_offset = 0;     /* incremental read position in the dnsmasq query log */
let self_mark = 100;         /* core's fwmark; hoisted for the probe table too */
let http_budget_total = 24;  /* total HTTP-verify checks per cycle, split across pools */
let autodoh_injected = false;/* last assemble_plain_pool() actually injected AUTO_DOH */

function log(msg) {
	const line = `[${sprintf('%d', time())}] [MDNS] ${msg}\n`;
	try {
		const fd = open(LOG_FILE, 'a');
		if (fd) { fd.write(line); fd.close(); }
	} catch (e) { /* best effort */ }
}

function dbg(m) {
	/* Debug trace is opt-in: touch /tmp/mdbg.enable to enable. The old unconditional
	 * version appended to /tmp/mdbg.txt forever (tmpfs growth for zero value). */
	if (!access('/tmp/mdbg.enable')) return;
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

/* Atomically replace a file (temp + mv) so readers never see a truncated file. */
function atomic_write(path, content) {
	let tmp = path + '.tmp';
	writefile(tmp, content);
	system('mv -f ' + tmp + ' ' + path);
}

function read_lines(path) {
	if (!access(path)) return [];
	let c = readfile(path);
	if (!c) return [];
	c = trim(c);
	if (!length(c)) return [];
	return filter(split(c, /[\r\n]/), (x) => length(trim(x)) && !match(trim(x), /^\s*#/));
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

/* Per-pool state key. The SAME server entry may belong to both pools and is
 * probed on DIFFERENT paths (plain = direct, secure = via the tunnel), so its
 * samples must never overwrite each other: secure entries are stored under a
 * "sec:" prefix, plain entries keep the bare name (backwards compatible). */
function skey(group, s) {
	return (group === 'secure') ? ('sec:' + s) : s;
}

/* True when host looks like a literal IPv4/IPv6 address (no DNS bootstrap needed). */
function is_ip(host) {
	return !!match(host, /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/) || !!match(host, /^[0-9a-fA-F:]+$/);
}

/* Split a configured DNS entry ("https://host/path", "tls://host", "1.2.3.4") into
 * transport + host + port + path so we can emit the right mosdns upstream line. */
function parse_entry(e) {
	let scheme = '', rest = e, host = e, port = '', path = '';
	let m = match(e, /^(https?|tls|quic|tcp):\/\/(.+)$/);
	if (m) { scheme = m[1]; rest = m[2]; }
	if (scheme === 'https')
		port = '443', path = '/dns-query';
	else if (scheme === 'tls' || scheme === 'quic')
		path = '';   /* mosdns defaults DoT/DoQ to 853 anyway; keep empty so the
		              * emitted addr matches the state key exactly */
	let hp = match(rest, /^([^/:]+)(:(\d+))?(\/\S*)?$/);
	if (hp) { host = hp[1]; if (hp[3]) port = hp[3]; if (hp[4]) path = hp[4]; }
	return { scheme: scheme, host: host, port: port, path: path };
}

function to_list(v) {
	if (isEmpty(v)) return [];
	let a = (type(v) === 'array') ? v : [ v ];
	return filter(a, (x) => length(trim(x)) && x !== 'wan');
}

/* Auto-detect the provider's DNS servers. Sources in priority order:
 *  1) ubus network.interface.* status → "dns-server": authoritative runtime
 *     state for EVERY WAN type — static (manual DNS list), DHCP and PPPoE
 *     (usepeerdns) alike. The old file-only reader silently missed static-WAN
 *     routers whose netifd layout differs.
 *  2) netifd resolver files: /tmp/resolv.conf.d/resolv.conf.auto (modern) and
 *     /tmp/resolv.conf.auto (legacy 21.02/older vendor trees).
 * Loopback, unspecified, ULA and link-local entries are filtered; capped at 4.
 * Best effort: an unreachable source simply yields no extra servers. */
function wan_dns_servers() {
	let out = [];
	const add_ip = (ip) => {
		if (!length(ip)) return;
		ip = trim(ip);
		if (!match(ip, /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) && !match(ip, /^[0-9A-Fa-f:.]+:[0-9A-Fa-f:.]*$/)) return;
		if (match(ip, /^127\./)) return;
		if (match(ip, /^[0.]+$/)) return;
		if (ip === '::1' || match(ip, /^fe80:/i)) return;
		if (match(ip, /^f[cd]/i)) return;          /* ULA / fc00::/7 */
		if (index(out, ip) < 0 && length(out) < 4) push(out, ip);
	};
	let line;
	/* 1) ubus dump for every published interface (one shell pass). */
	const tmpf = '/var/run/homeproxy/multidns/wan_dns.tmp';
	system(`( ubus list 'network.interface.*' 2>/dev/null | while read _if; do ubus call "$_if" status 2>/dev/null | jsonfilter -e '@["dns-server"][*]' 2>/dev/null; done ) > ${shellquote(tmpf)} 2>/dev/null`);
	line = readfile(tmpf);
	system(`rm -f ${shellquote(tmpf)} 2>/dev/null`);
	if (line)
		for (let l in split(line, /\n/))
			add_ip(trim(l));
	/* 2) netifd resolver files (both layouts), nameserver lines only. */
	for (let p in ['/tmp/resolv.conf.d/resolv.conf.auto', '/tmp/resolv.conf.auto']) {
		let c = readfile(p);
		if (!c) continue;
		for (let l in split(c, '\n')) {
			let m = match(l, /^\s*nameserver\s+([0-9A-Fa-f:.]+)\s*$/);
			if (m) add_ip(m[1]);
		}
	}
	return out;
}

/* True when EVERY configured plaintext (scheme-less) plain-pool entry has been
 * measured dead or poisoned for at least 2 samples. Entries without enough
 * data yet count as undecided → false, so a fresh start never triggers the
 * direct-DoH fallback before real evidence exists. */
function plaintext_pool_dead(st, plain) {
	let any_plain = false;
	for (let e in plain) {
		let p = parse_entry(e);
		if (p.scheme) continue;
		any_plain = true;
		let s = st.servers ? st.servers[e] : null;
		if (!s || s.samples == null || s.samples < 2) return false;   /* undecided */
		if (!s.pruned && !(s.bad_streak >= 2) && s.last_ok !== false)
			return false;                                             /* alive */
	}
	return any_plain;
}

/* Plain pool + auto-detected provider (WAN) DNS when the user enables the
 * "russia_dns_use_wan" switch in the UI. Duplicates against the configured
 * list are skipped so the monitor never shows the same server twice. */
function plain_pool_with_wan(list) {
	if ((uci.get('homeproxy', 'config', 'russia_dns_use_wan') || '0') !== '1') return list;
	let add = [];
	for (let ip in wan_dns_servers())
		if (index(list, ip) < 0) push(add, ip);
	/* NOTE: no concat() in this ucode build — append manually. */
	for (let i = 0; i < length(add); i = i + 1)
		push(list, add[i]);
	return list;
}

/* IPv4 hosts of a pool entry list (for the nft probe set). */
function v4_hosts(list) {
	let out = [];
	for (let i = 0; i < length(list); i = i + 1) {
		let h = parse_entry(list[i]).host;
		if (match(h, /^(\d{1,3}\.){3}\d{1,3}$/) && index(out, h) < 0) push(out, h);
	}
	return out;
}

/* Incrementally consume the dnsmasq query log into st.user_recent (domain →
 * last-seen ts). Same source the automation daemon uses; the log only exists
 * when automation's 'dns' discovery source is enabled — otherwise the
 * real-user-domain verification silently stays inactive.
 * NOTE: defined BEFORE analyze() — this ucode build does NOT hoist function
 * declarations, a forward reference dies with "undeclared variable". */
function read_user_domains(st) {
	if (!st.user_recent) st.user_recent = {};
	if (!access(DNS_LOG)) return;
	let sz = stat(DNS_LOG);
	if (!sz) return;
	let size = sz.size;
	if (user_dns_offset > size) user_dns_offset = 0;   /* log rotated */
	/* Self-rotation (same policy as the automation daemon): truncate in place
	 * past 4 MB — dnsmasq holds the fd with O_APPEND, writes continue safely. */
	if (size > 4194304) {
		let w = open(DNS_LOG, 'w');
		if (w) { w.close(); user_dns_offset = 0; size = 0; }
	}
	let fd = open(DNS_LOG, 'r');
	if (!fd) return;
	try { fd.seek(user_dns_offset); } catch (e) { fd.close(); return; }
	let now = time();
	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		let m = match(trim(line), /query\[[Aq]+\]\s+([^ ]+)\s+from/);
		if (m) st.user_recent[m[1]] = now;
	}
	user_dns_offset = size;
	fd.close();
	/* Cap the ring: drop week-old entries, then the single oldest until <= 420. */
	let ks = keys(st.user_recent);
	for (let i = length(ks) - 1; i >= 0; i--)
		if ((now - (st.user_recent[ks[i]] || 0)) > 604800) delete st.user_recent[ks[i]];
	ks = keys(st.user_recent);
	while (length(ks) > 420) {
		let oldest = ks[0];
		for (let i = 1; i < length(ks); i++)
			if (st.user_recent[ks[i]] < st.user_recent[oldest]) oldest = ks[i];
		delete st.user_recent[oldest];
		ks = keys(st.user_recent);
	}
}

/* ── Direct-path probing ──────────────────────────────────────────────────
 * The router's own mangle_output tproxies locally-generated UDP:53 into the
 * core, so shell probes (nslookup) read silent even for perfectly healthy
 * upstreams. Setting SO_MARK needs tools busybox lacks, but we can hand the
 * mark EARLIER than fw4: our own route-hook output chain at priority -151
 * stamps self_mark on packets to the current probe targets, and fw4's first
 * rule ("meta mark <self_mark> return") then lets them through untouched —
 * exactly the path mosdns's so_mark'd racing traffic takes.
 *
 * Scope safety: the chain hooks OUTPUT only (router-local packets); LAN
 * forwarding is untouched. Stale set elements after a disable merely let the
 * router query those specific servers directly — normal DNS behavior anyway.
 */
function ensure_probe_table(self_mark) {
	const TBL = 'hp_mdns_probe';
	system('nft list table inet ' + TBL + ' >/dev/null 2>&1 || nft add table inet ' + TBL);
	/* NOTE: the { } payloads are shell-quoted (double quotes) — an unquoted
	 * semicolon would terminate the sh -c command. */
	system('nft list set inet ' + TBL + ' probe_v4 >/dev/null 2>&1 || nft add set inet ' + TBL + ' probe_v4 "{ type ipv4_addr; }"');
	system('nft list chain inet ' + TBL + ' pre >/dev/null 2>&1 || nft add chain inet ' + TBL
		+ ' pre "{ type route hook output priority -151; policy accept; }"');
	/* Re-stamp the rule on every start so a self_mark change is picked up. */
	system('nft flush chain inet ' + TBL + ' pre');
	system('nft add rule inet ' + TBL + ' pre ip daddr @probe_v4 udp dport 53 meta mark set '
		+ int(self_mark));
}

/* Replace the probe-target set with the current plaintext pool hosts. */
function update_probe_set(ips) {
	let parts = [];
	for (let i = 0; i < length(ips); i = i + 1)
		if (match(ips[i], /^(\d{1,3}\.){3}\d{1,3}$/))
			push(parts, ips[i]);
	dbg('probe_set update: ' + length(parts) + ' v4 hosts');
	system('nft flush set inet hp_mdns_probe probe_v4');
	if (!length(parts)) return;
	/* shell-quoted payload — an unquoted brace group breaks under ash */
	system('nft add element inet hp_mdns_probe probe_v4 "{ ' + join(', ', parts) + ' }"');
}

/* Collect the current assembled plain-pool list for a routing mode. Shared by
 * build_mosdns_conf / analyze / update_probe_set so all three always agree. */
function assemble_plain_pool(st) {
	let mode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
	let pl = [];
	if (mode === 'proxy_banned_ru')
		pl = to_list(uci.get('homeproxy', 'config', 'russia_dns_server'));
	else if (mode === 'bypass_cn')
		pl = to_list(uci.get('homeproxy', 'config', 'china_dns_server'));
	else if (mode === 'bypass_ir')
		pl = to_list(uci.get('homeproxy', 'config', 'iran_dns_server'));
	else if (mode === 'global')
		pl = to_list(uci.get('homeproxy', 'config', 'dns_server'));
	pl = plain_pool_with_wan(pl);
	let inj = false;
	if ((uci.get('homeproxy', 'config', 'russia_dns_auto_doh') || '1') === '1'
	    && (st.plain_doh_latch === '1' || (st.plain_bad_streak || 0) >= 2
	        || plaintext_pool_dead(st, pl))) {
		for (let i = 0; i < length(AUTO_DOH); i++)
			if (index(pl, AUTO_DOH[i]) < 0) push(pl, AUTO_DOH[i]);
		inj = true;
	}
	autodoh_injected = inj;
	return pl;
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
 * UDP query back into the resolver, so plain servers are probed over a
 * locally-originated UDP query (nslookup) which bypasses the hijack; secure
 * servers are probed over DoH (curl). Returns { ok, ip, ips, live, lat }. */
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

/* Walk a DNS wire message (RFC1035) and return every A-record IPv4 address it
 * contains. Handles name-compression pointers so it works for both the TCP
 * response (with its 2-byte length prefix stripped) and RFC8484 DoH bodies. */
function parse_a(buf) {
	let out = [];
	if (!buf || length(buf) < 12) return out;
	let qd = ord(substr(buf, 4, 1)) * 256 + ord(substr(buf, 5, 1));
	let an = ord(substr(buf, 6, 1)) * 256 + ord(substr(buf, 7, 1));
	let off = 12;
	for (let i = 0; i < qd; i = i + 1) {
		while (off < length(buf)) {
			let b = ord(substr(buf, off, 1));
			if (b === 0) { off = off + 1; break; }
			if ((b & 0xC0) === 0xC0) { off = off + 2; break; }
			off = off + 1 + b;
		}
		off = off + 4;  /* QTYPE(2) + QCLASS(2) */
	}
	for (let i = 0; i < an; i = i + 1) {
		while (off < length(buf)) {
			let b = ord(substr(buf, off, 1));
			if (b === 0) { off = off + 1; break; }
			if ((b & 0xC0) === 0xC0) { off = off + 2; break; }
			off = off + 1 + b;
		}
		if (off + 10 > length(buf)) break;
		let type = ord(substr(buf, off, 1)) * 256 + ord(substr(buf, off + 1, 1));
		let rdlen = ord(substr(buf, off + 8, 1)) * 256 + ord(substr(buf, off + 9, 1));
		let o = off + 10;  /* TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) → start of RDATA */
		if (type === 1 && o + 4 <= length(buf)) {
			push(out, sprintf('%d.%d.%d.%d',
				ord(substr(buf, o, 1)), ord(substr(buf, o + 1, 1)),
				ord(substr(buf, o + 2, 1)), ord(substr(buf, o + 3, 1))));
		}
		off = o + rdlen;
	}
	return out;
}

/* Resolve `canary` against a plain DNS server over TCP/53 and return the list of
 * A-record IPv4 addresses (may be empty). TCP bypasses the UDP/53 hijack that
 * loops UDP back into the resolver. NOTE: busybox nc closes the connection as
 * soon as its stdin hits EOF, so a bare `nc < file` sends the question and tears
 * the socket down before the server can answer — stdin must be held open for a
 * moment after writing the query. */
function tcp_dns_query(server, port, canary) {
	let qf = MD_DIR + '/dq.bin';
	let af = MD_DIR + '/da.bin';
	let pf = MD_DIR + '/dq.pid';
	let q = build_query(canary);
	let qlen = length(q);
	/* DNS-over-TCP prefixes the message with its 2-byte big-endian length. */
	let msg = bchr(int(qlen / 256)) + bchr(qlen % 256) + q;
	writefile(qf, msg);
	/* Hold stdin open (sleep keeps the pipe alive) and poll the answer file so a
	 * fast reply costs ~1s instead of the old unconditional 6s block. */
	system('( cat ' + shellquote(qf) + '; sleep 4 ) | nc ' + shellquote(server)
		+ ' ' + port + ' > ' + shellquote(af) + ' 2>/dev/null & echo $! > ' + shellquote(pf));
	for (let i = 0; i < 8; i = i + 1) {
		sleep(1);
		let early = readfile(af);
		if (early && length(early) >= 3) break;
	}
	let pidfile = readfile(pf);
	if (pidfile) system('kill ' + shellquote(trim(pidfile)) + ' 2>/dev/null');
	let a = readfile(af) || '';
	if (!a || length(a) < 14) return [];
	/* Strip the 2-byte TCP length prefix, then parse the answer section. */
	return parse_a(substr(a, 2));
}

/* Resolve `canary` against a plain (IP/53) DNS server using the REAL query
 * path: a locally-originated UDP/53 query (busybox `nslookup`). This is the
 * same path mosdns's plain pool uses (direct-out, bypassing the router's DNS
 * hijack because locally-generated packets hit OUTPUT, not PREROUTING tproxy).
 * TCP/53 to some providers (e.g. 8.8.8.8/8.8.4.4) is BLOCKED by the ISP, so a
 * TCP probe marks working servers dead — UDP works. Returns an array of answer
 * IPs (IPv4 or IPv6); empty means no answer. */
function udp_dns_query(server, canary) {
  let out = MD_DIR + '/ns.out';
  /* UDP DNS can drop a packet occasionally; retry a few times so a single
   * lost query doesn't read as "server dead". Cap each try at ~3s. */
  for (let attempt = 0; attempt < 3; attempt = attempt + 1) {
    system('nslookup -type=A ' + shellquote(canary) + ' ' + shellquote(server)
           + ' > ' + shellquote(out) + ' 2>/dev/null & NSPID=$!; sleep 3; kill $NSPID 2>/dev/null');
    let r = readfile(out) || '';
    let ips = [];
    let lines = split(r, '\n');
    for (let i = 0; i < length(lines); i = i + 1) {
      /* Answer lines across busybox variants: "Address: <ip>" and the indexed
       * "Address 1: <ip> name" form. The server self-line carries a :port suffix
       * ("Address: 77.88.8.8:53") and is skipped by the port check below. */
      let m = match(trim(lines[i]), /^Address(\s+[0-9]+)?:\s*(\S+)/);
      if (m && !match(m[2], /:[0-9]+$/)) push(ips, m[2]);
    }
    if (length(ips) > 0) return ips;
  }
  return [];
}

/* Resolve `canary` against a DoH server and return { ips, lat }. Tries the
 * Google-style JSON API (/dns-query?name= or /resolve?name=) first, then falls
 * back to RFC8484 wire format (POST of the raw DNS query) — Quad9 only speaks
 * the latter. Both the proxied and direct paths are tried so the monitor
 * reflects reachability whether or not the tunnel is up. */
function doh_query(host, path, canary, via_proxy) {
	let attempts = [];
	if (via_proxy) push(attempts, '-x socks5h://' + PROXY + ' ');
	push(attempts, '');
	for (let ai = 0; ai < length(attempts); ai = ai + 1) {
		let proxy = attempts[ai];
		/* 1) Google-style JSON API (Cloudflare / Google). */
		let hdr = "-H 'accept: application/dns-json' ";
		let urls = [
			'https://' + host + (path || '/dns-query') + '?name=' + canary + '&type=A',
			'https://' + host + '/resolve?name=' + canary + '&type=A'
		];
		for (let u = 0; u < length(urls); u = u + 1) {
			let out = MD_DIR + '/cap.tmp';
			system(`curl -s --max-time 4 ${proxy}${hdr}-w '\\n%{time_total}' ${shellquote(urls[u])} > ${shellquote(out)} 2>/dev/null`);
			let raw = readfile(out) || '';
			let parts = split(raw, '\n');
			if (!length(parts)) continue;
			let body = join('\n', slice(parts, 0, length(parts) - 1));
			if (body) {
				try {
					let j = json(body);
					let ans = j.Answer || [];
					let ips = [];
					for (let k = 0; k < length(ans); k = k + 1) {
						let x = ans[k];
						if (x.type === 1 && match(x.data, /^[0-9.]+$/)) push(ips, x.data);
					}
					if (length(ips)) return { ips: ips, lat: ms_of(trim(parts[length(parts) - 1])) };
				} catch (e) {}
			}
		}
		/* 2) RFC8484 wire format (Quad9 etc.). POST the raw DNS query; no base64
		 * needed — curl sends the binary body. Latency goes to a separate file. */
		let qf = MD_DIR + '/dq.bin';
		writefile(qf, build_query(canary));
		let bfile = MD_DIR + '/doh.body';
		let tfile = MD_DIR + '/doh.time';
		system(`curl -s --max-time 4 -X POST --data-binary @${shellquote(qf)} `
			+ `-H 'Content-Type: application/dns-message' -H 'Accept: application/dns-message' `
			+ `${proxy}-o ${shellquote(bfile)} -w '%{time_total}' ${shellquote('https://' + host + (path || '/dns-query'))} `
			+ `> ${shellquote(tfile)} 2>/dev/null`);
		let wire = readfile(bfile) || '';
		let ips = parse_a(wire);
		if (length(ips)) return { ips: ips, lat: ms_of(trim(readfile(tfile) || '')) };
	}
	return { ips: [], lat: null };
}

function probe_server(server, group, via_proxy, canary) {
	let ips = [], lat = null;
	if (group === 'secure') {
		let p = parse_entry(server);
		let r = doh_query(p.host, p.path, canary, via_proxy);
		ips = r.ips; lat = r.lat;
	} else {
		/* Plain pool entries may carry an explicit transport scheme:
		 *   bare IP / no scheme → UDP/53 first, TCP/53 fallback;
		 *   tcp://host          → TCP/53 only;
		 *   https://host/path   → DoH DIRECT (no proxy — plain pool stays direct);
		 *   tls:// quic://      → no local TLS client to probe for real, assume up. */
		let p = parse_entry(server);
		let host = p.host;
		if (p.scheme === 'https') {
			let r = doh_query(host, p.path || '/dns-query', canary, false);
			ips = r.ips; lat = r.lat;
		} else if (p.scheme === 'tcp') {
			ips = tcp_dns_query(host, 53, canary);
		} else if (p.scheme === 'tls' || p.scheme === 'quic') {
			if (have_ping()) {
				let out = MD_DIR + '/cap.tmp';
				system(`ping -c1 -w2 ${shellquote(host)} > ${shellquote(out)} 2>/dev/null`);
				let raw = readfile(out) || '';
				let m = match(raw, /time[= ]+([0-9]+)(\.[0-9]+)?\s*ms/);
				if (m) lat = int(m[1]);
			}
			return { ok: true, ip: null, ips: [], live: true, lat: lat };
		} else {
			/* TCP FIRST: the local UDP probe (busybox nslookup) rides the
			 * router's own tproxy/mangle loop and reads near-dead even when
			 * the upstream is perfectly healthy, while a direct DNS-over-TCP
			 * query answered cleanly everywhere we tested (byte-level dump,
			 * 2026-08-24). Fall back to UDP for ISPs that block TCP:53. */
			ips = tcp_dns_query(host, 53, canary);
			if (length(ips) == 0)
				ips = udp_dns_query(host, canary);
		}
		if (!lat && have_ping()) {
			let out = MD_DIR + '/cap.tmp';
			system(`ping -c1 -w2 ${shellquote(host)} > ${shellquote(out)} 2>/dev/null`);
			let raw = readfile(out) || '';
			let m = match(raw, /time[= ]+([0-9]+)(\.[0-9]+)?\s*ms/);
			if (m) lat = int(m[1]);
		}
	}
	let ip = (length(ips) > 0) ? ips[0] : null;
	let live = length(ips) > 0;
	return { ok: live, ip: ip, ips: ips, live: live, lat: lat };
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

/* Blocking-pattern signatures (mirrors automation.uc): a 200/3xx page whose body
 * matches one of these is a DPI/operator block page, not the real site. */
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
function classify_code(code) {
	let c = trim(code || '000');
	if (c === '' || c === '000') return 'fail';
	let n = int(c);
	if (n >= 200 && n < 400) return 'ok';
	if (n >= 400 && n <= 599) return 'block';
	return 'fail';
}

/* HTTP-verify one resolved IP: does it actually OPEN the site over HTTPS?
 * This is the quality signal smartdns could never provide. via_proxy rides the
 * dedicated mdns-proxy-in (127.0.0.1:5338 → main-out) so the secure pool's
 * check exercises the REAL proxied path. NOTE: use `socks5://` (not socks5h)
 * so curl keeps the --resolve mapping (local DNS) and only the TCP flows through
 * the tunnel. */
function verify_ip(ip, domain, via_proxy) {
	if (!have_curl()) return { code: '000', opens: false };
	let proxy = via_proxy ? ' -x socks5://' + PROXY : '';
	let bodyf = MD_DIR + '/http.body';
	let codef = MD_DIR + '/http.code';
	system('curl -sL -k --max-time 8 --connect-timeout 5 --resolve ' + shellquote(domain + ':443:' + ip)
		+ ' -o ' + shellquote(bodyf) + ' -w "%{http_code}"' + proxy
		+ ' ' + shellquote('https://' + domain) + ' > ' + shellquote(codef) + ' 2>/dev/null');
	let code = trim(readfile(codef) || '000');
	let c = classify_code(code);
	let opens = (c === 'ok');
	if (opens) {
		let body = readfile(bodyf) || '';
		/* Size guard (mirrors automation.uc): a large page is never a block page —
		 * without this, a big portal whose markup merely contains a signature word
		 * would mark the server's IP as dead. */
		if (length(body) < 32768 && body_blocked(body)) opens = false;
	}
	return { code: code, opens: opens };
}

/* Composite quality score 0..100 (all integer math). HTTP "site opens" is the
 * dominant weight; latency and success support it. */
function compute_score(s) {
  /* NaN guard: ucode has no isFinite(); NaN is the only value that differs
   * from itself, so `x == x` is false exactly for NaN. */
  let lat = (s.lat != null && s.lat == s.lat) ? s.lat : null;
  let speed = (lat != null) ? (100 - ((lat * 100) / 500)) : 100;
  if (speed < 0) speed = 0; if (speed > 100) speed = 100;
  if (speed != speed) speed = 100;
  let succ = (s.succ != null && s.succ == s.succ) ? s.succ : 50;   /* 0..100 */
  let open = (s.open != null && s.open == s.open) ? s.open : 50;   /* 0..100 */
  let sc = (20 * speed + 30 * succ + 50 * open) / 100;
  if (sc != sc) sc = 0;
  if (s.poisoned) sc = (sc * 20) / 100;
  /* A server that is not actually answering (low success) cannot be "fast":
   * ping latency alone must not produce a misleading mid score. Gate the whole
   * score by the success ratio so a dead / fast-but-dead server scores ~0
   * (and is then pruned) instead of looking healthy. */
  if (s.succ != null && s.succ == s.succ)
    sc = (sc * s.succ) / 100;
  if (sc != sc) sc = 0;
  return sc;
}

/* Double-quote a YAML scalar value. */
function yaml_q(s) {
	return '"' + replace(replace(s, '\\', '\\\\'), '"', '\\"') + '"';
}

/* Ensure the mosdns data-provider files exist (mosdns fails to start if a
 * referenced file is missing) and mirror the learned proxy lists. Returns true
 * if any file changed. */
function ensure_data_files() {
	let changed = false;
	if (!access(DEAD_IPS_FILE)) { writefile(DEAD_IPS_FILE, ''); changed = true; }
	let dl = access(RES + '/auto_proxy_list.txt') ? (readfile(RES + '/auto_proxy_list.txt') || '') : '';
	let il = access(RES + '/auto_proxy_ip.txt') ? (readfile(RES + '/auto_proxy_ip.txt') || '') : '';
	let cur_dl = access(PROXY_DOMAINS_FILE) ? (readfile(PROXY_DOMAINS_FILE) || '') : null;
	let cur_il = access(PROXY_IPS_FILE) ? (readfile(PROXY_IPS_FILE) || '') : null;
	if (cur_dl == null || cur_dl !== dl) { atomic_write(PROXY_DOMAINS_FILE, dl); changed = true; }
	if (cur_il == null || cur_il !== il) { atomic_write(PROXY_IPS_FILE, il); changed = true; }
	/* Quarantine mirror: state (st.quarantine, updated by analyze) → domain_set
	 * file. A content change flips `changed` so the caller restarts mosdns and
	 * the new set takes effect. */
	let qcontent = '';
	try {
		let qs = load_state();
		let qk = keys(qs.quarantine || {});
		if (length(qk)) qcontent = join('\n', qk) + '\n';
	} catch (e) { /* best effort */ }
	let cur_q = access(QUARANTINE_FILE) ? (readfile(QUARANTINE_FILE) || '') : null;
	if (cur_q == null || cur_q !== qcontent) { atomic_write(QUARANTINE_FILE, qcontent); changed = true; }
	return changed;
}

/* Build the mosdns v5 YAML config. Pruned servers (in state) are omitted so they
 * are dropped from the live racing pool. */
function build_mosdns_conf() {
	let lines = [];
	push(lines, 'log:');
	push(lines, '  level: warn');
	push(lines, '');
	push(lines, 'plugins:');

	let mode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
	let main_node = uci.get('homeproxy', 'config', 'main_node') || 'nil';
	let proxy_real = !(main_node in ['byedpi-out', 'zapret-out']);
	let use_proxy = (secure_via_proxy !== '0') && proxy_real;

	/* self_mark: stamp mosdns's OWN outbound DNS traffic with the core's self_mark
	 * so the router's mangle_output chain (redirect_tproxy) returns it instead of
	 * tproxy-marking it. Without this, mosdns's plain-pool UDP queries are tproxied
	 * into sing-box, which resolves them back through mosdns → an infinite DNS loop
	 * ("context deadline exceeded"). Same exclusion sing-box uses for its own egress. */

	let secure = to_list(uci.get('homeproxy', 'config', 'secure_dns_server'));

	let st = load_state();
	let plain = assemble_plain_pool(st);

	/* One-shot logging of the direct-DoH fallback state. Tracks the INJECTION
	 * flag (not string matching): the user may have manually added entries equal
	 * to AUTO_DOH to their pool. */
	if (autodoh_injected && autodoh_active !== true) {
		log('direct DoH fallback engaged (' + join(' ', AUTO_DOH) + ')');
		autodoh_active = true;
	} else if (!autodoh_injected && autodoh_active === true) {
		log('a plaintext plain-pool server recovered — direct DoH fallback removed');
		autodoh_active = false;
	}

	let plain_up = [], secure_up = [];
	for (let e in plain) if (!(st.servers[e] && st.servers[e].pruned)) push(plain_up, e);
	for (let e in secure) if (!(st.servers[skey('secure', e)] && st.servers[skey('secure', e)].pruned)) push(secure_up, e);

	/* First plain IP doubles as the bootstrap resolver for domain-based secure
	 * upstreams so mosdns never has to consult the (loop-risky) system resolver. */
	let bootstrap_ip = '8.8.8.8';
	for (let e in plain) {
		let p = parse_entry(e);
		if (!p.scheme && is_ip(p.host)) { bootstrap_ip = p.host; break; }
	}

	let have_plain = length(plain_up) > 0;
	let have_secure = length(secure_up) > 0;

	/* --- forward plugins --- */
	if (have_plain) {
		push(lines, '  - tag: fwd_plain');
		push(lines, '    type: forward');
		push(lines, '    args:');
		push(lines, '      concurrent: 3');
		push(lines, '      so_mark: ' + self_mark);
		push(lines, '      upstreams:');
		for (let e in plain_up) {
			let p = parse_entry(e);
			/* plain pool: bare IP → default udp:// (direct, no proxy) */
			let addr = p.scheme ? (p.scheme + '://' + p.host + (p.port ? ':' + p.port : '') + (p.path || '')) : (p.host + (p.port ? ':' + p.port : ''));
			push(lines, '        - addr: ' + yaml_q(addr));
		}
	}
	if (have_secure) {
		push(lines, '  - tag: fwd_secure');
		push(lines, '    type: forward');
		push(lines, '    args:');
		push(lines, '      concurrent: 3');
		push(lines, '      so_mark: ' + self_mark);
		push(lines, '      upstreams:');
		for (let e in secure_up) {
			let p = parse_entry(e);
			let addr;
			if (p.scheme === 'https')
				addr = 'https://' + p.host + (p.port ? ':' + p.port : '') + (p.path || '/dns-query');
			else if (p.scheme === 'tls' || p.scheme === 'quic')
				addr = p.scheme + '://' + p.host + (p.port ? ':' + p.port : '');
			else
				addr = 'tcp://' + p.host + (p.port ? ':' + p.port : '');
			push(lines, '        - addr: ' + yaml_q(addr));
			if (!is_ip(p.host)) {
				/* domain host → resolve it via the plain bootstrap (no loop) */
				push(lines, '          bootstrap: ' + yaml_q(bootstrap_ip));
				push(lines, '          bootstrap_version: 4');
			}
			/* socks5 only for TCP-based protocols (DoH/DoT); DoQ/DoH3 stay direct
			 * (encrypted) because mosdns socks5 does not support UDP transports. */
			if (use_proxy && (p.scheme === 'https' || p.scheme === 'tls'))
				push(lines, '          socks5: ' + yaml_q(PROXY));
		}
	}

	/* --- cache plugins --- */
	/* size: LRU entries; lazy_cache_ttl: serve an expired entry instantly (one query
	 * cycle of staleness at most — the fresh answer is fetched in the background
	 * right after); dump_file/interval: survive mosdns restarts without a cold cache. */
	if (have_plain) {
		push(lines, '  - tag: cache_plain');
		push(lines, '    type: cache');
		push(lines, '    args:');
		push(lines, '      size: 4096');
		push(lines, '      lazy_cache_ttl: 86400');
		push(lines, '      dump_file: ' + yaml_q(MD_DIR + '/plain_cache.dump'));
		push(lines, '      dump_interval: 60');
	}
	if (have_secure) {
		push(lines, '  - tag: cache_secure');
		push(lines, '    type: cache');
		push(lines, '    args:');
		push(lines, '      size: 4096');
		push(lines, '      lazy_cache_ttl: 86400');
		push(lines, '      dump_file: ' + yaml_q(MD_DIR + '/secure_cache.dump'));
		push(lines, '      dump_interval: 60');
	}

	/* --- data sets: dead-IP blacklist + learned proxy domains/IPs --- */
	push(lines, '  - tag: dead_ips');
	push(lines, '    type: ip_set');
	push(lines, '    args:');
	push(lines, '      files:');
	push(lines, '        - ' + yaml_q(DEAD_IPS_FILE));
	push(lines, '  - tag: proxy_domains');
	push(lines, '    type: domain_set');
	push(lines, '    args:');
	push(lines, '      files:');
	push(lines, '        - ' + yaml_q(PROXY_DOMAINS_FILE));
	push(lines, '  - tag: proxy_ips');
	push(lines, '    type: ip_set');
	push(lines, '    args:');
	push(lines, '      files:');
	push(lines, '        - ' + yaml_q(PROXY_IPS_FILE));
	push(lines, '  - tag: quarantine_domains');
	push(lines, '    type: domain_set');
	push(lines, '    args:');
	push(lines, '      files:');
	push(lines, '        - ' + yaml_q(QUARANTINE_FILE));

	/* --- plain sequence --- */
	push(lines, '  - tag: seq_plain');
	push(lines, '    type: sequence');
	push(lines, '    args:');
	if (have_secure) {
		/* learned blocked domains → secure pool (defense in depth; sing-box already
		 * routes proxy-domain → secure-dns, this catches any query reaching plain) */
		push(lines, '      - matches:');
		push(lines, '          - ' + yaml_q('qname $proxy_domains'));
		push(lines, '        exec: $fwd_secure');
		/* quarantined user domains (persistently forged answers) → secure pool.
		 * Placed BEFORE cache_plain so a quarantined domain never consults (or
		 * populates) the plain cache. */
		push(lines, '      - matches:');
		push(lines, '          - ' + yaml_q('qname $quarantine_domains'));
		push(lines, '        exec: $fwd_secure');
	}
	if (have_plain) {
		push(lines, '      - exec: $cache_plain');
		push(lines, '      - matches:');
		push(lines, '          - ' + yaml_q('!has_resp'));
		push(lines, '        exec: $fwd_plain');
		if (have_secure) {
			/* drop answers carrying a known-dead IP → fall through to secure */
			push(lines, '      - matches:');
			push(lines, '          - has_resp');
			push(lines, '          - ' + yaml_q('resp_ip $dead_ips'));
			push(lines, '        exec: drop_resp');
			/* empty / dropped answer → encrypted fallback (anti-poisoning) */
			push(lines, '      - matches:');
			push(lines, '          - ' + yaml_q('!has_resp'));
			push(lines, '        exec: $fwd_secure');
		}
	} else if (have_secure) {
		/* plain pool empty (all dead/poisoned) → resolve the plain bind via the
		 * encrypted pool (the same safety net the smartdns version had). */
		push(lines, '      - exec: $cache_secure');
		push(lines, '      - matches:');
		push(lines, '          - ' + yaml_q('!has_resp'));
		push(lines, '        exec: $fwd_secure');
	}

	/* --- secure sequence --- */
	if (have_secure) {
		push(lines, '  - tag: seq_secure');
		push(lines, '    type: sequence');
		push(lines, '    args:');
		push(lines, '      - exec: $cache_secure');
		push(lines, '      - matches:');
		push(lines, '          - ' + yaml_q('!has_resp'));
		push(lines, '        exec: $fwd_secure');
	}

	/* --- servers (listeners) --- */
	/* Plain listener only when seq_plain actually exists (either pool non-empty):
	 * with both pools empty the reference to $seq_plain made mosdns fail to start,
	 * and generate_client would repoint russia-dns at a dead 5453. */
	if (use_plain !== '0' && (have_plain || have_secure)) {
		push(lines, '  - type: udp_server');
		push(lines, '    args:');
		push(lines, '      entry: seq_plain');
		push(lines, '      listen: ' + yaml_q('127.0.0.1:' + plain_port));
		push(lines, '  - type: tcp_server');
		push(lines, '    args:');
		push(lines, '      entry: seq_plain');
		push(lines, '      listen: ' + yaml_q('127.0.0.1:' + plain_port));
	}
	if (use_secure !== '0' && have_secure) {
		push(lines, '  - type: udp_server');
		push(lines, '    args:');
		push(lines, '      entry: seq_secure');
		push(lines, '      listen: ' + yaml_q('127.0.0.1:' + secure_port));
		push(lines, '  - type: tcp_server');
		push(lines, '    args:');
		push(lines, '      entry: seq_secure');
		push(lines, '      listen: ' + yaml_q('127.0.0.1:' + secure_port));
	}

	return join('\n', lines) + '\n';
}

/* Kill every mosdns instance started from OUR config (SIGKILL so the OS releases
 * the listening sockets immediately, avoiding "Address in use" on the next start). */
function kill_our_mosdns() {
	let out = trim(capture('pidof mosdns 2>/dev/null'));
	if (!length(out)) return;
	let pids = split(out, ' ');
	for (let i = 0; i < length(pids); i = i + 1)
		system('kill -9 ' + trim(pids[i]) + ' 2>/dev/null');
	/* Wait for the process(es) to actually disappear before we rebind. */
	for (let i = 0; i < 10; i = i + 1) {
		if (!length(trim(capture('pidof mosdns 2>/dev/null')))) break;
		sleep(1);
	}
}

function mosdns_running() {
	let out = trim(capture('pidof mosdns 2>/dev/null'));
	return length(out) > 0;
}

function start_mosdns() {
	/* MultiDNS accelerates DNS: start the dedicated mosdns instance that races
	 * several servers of each pool (plain "Russia" + encrypted "secure") and returns
	 * the fastest valid answer, dropping poisoned/dead-IP answers. Kill any stale
	 * instance bound to our config/ports first, then launch a fresh one. The main
	 * app's russia-dns / secure-dns resolvers are pointed at these listeners
	 * (127.0.0.1:5453 / :5454) by generate_client.uc when MultiDNS is enabled. */
	let conf = build_mosdns_conf();
	atomic_write(CONF, conf);
	kill_our_mosdns();
	sleep(1);
	system('setsid ' + MOSDNS + ' start -c ' + shellquote(CONF) + ' -d ' + shellquote(MD_DIR)
		+ ' </dev/null >>' + shellquote(LOG_FILE + '.md') + ' 2>&1 &');
	let alive = false;
	for (let i = 0; i < 10; i = i + 1) {
		sleep(1);
		if (mosdns_running()) { alive = true; break; }
	}
	if (alive) {
		let pids = split(trim(capture('pidof mosdns 2>/dev/null')), ' ');
		if (length(pids)) atomic_write(PID, pids[0]);
	} else {
		/* One retry: the previous instance's socket may still be held by the OS
		 * for a moment after kill. Force-clear and try again. */
		kill_our_mosdns();
		sleep(2);
		system('setsid ' + MOSDNS + ' start -c ' + shellquote(CONF) + ' -d ' + shellquote(MD_DIR)
			+ ' </dev/null >>' + shellquote(LOG_FILE + '.md') + ' 2>&1 &');
		for (let i = 0; i < 10; i = i + 1) {
			sleep(1);
			if (mosdns_running()) { alive = true; break; }
		}
		if (alive) {
			let pids = split(trim(capture('pidof mosdns 2>/dev/null')), ' ');
			if (length(pids)) atomic_write(PID, pids[0]);
		}
	}
	if (!alive) {
		let err = access(LOG_FILE + '.md') ? trim(readfile(LOG_FILE + '.md')) : '';
		log('mosdns failed to start — resolution will not be accelerated.'
			+ (err ? ' err: ' + err : ''));
	}
	return alive;
}

function stop_mosdns() {
	if (access(PID)) {
		let c = trim(readfile(PID));
		if (c) system(`kill ${shellquote(c)} 2>/dev/null`);
		system('rm -f ' + shellquote(PID));
	}
	kill_our_mosdns();
}

function analyze() {
	dbg('a:enter');
	let st = load_state();
	if (!st.servers) st.servers = {};
	let mode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
	let main_node = uci.get('homeproxy', 'config', 'main_node') || 'nil';
	let via_proxy = (secure_via_proxy !== '0') && !(main_node in ['byedpi-out', 'zapret-out']);

	/* Canary sets: fixed, stable domains, rotated per cycle (multi-canary). The
	 * secure pool verifies anti-poisoning with cloudflare.com (a stable domain
	 * whose IPs always serve the site), NOT a learned blocked domain — learned
	 * domains resolve to unstable round-robin IPs and would produce false
	 * "open=0" readings (verified on the live router). The plain set mixes an
	 * international name with a domestic one so selective poisoning patterns
	 * are caught across cycles. */
	let cyc = st.cycle || 0;

	let pools = [];
	if (use_plain) {
		/* Mirror the auto-DoH fallback so the monitor shows exactly what mosdns races. */
		let pl = assemble_plain_pool(st);
		push(pools, { group: 'ru', servers: pl, canaries: CANARIES_PLAIN, via: false,
			/* The plain pool EXISTS to resolve domestic names — judge its servers by
			 * a domestic anchor. Some resolvers (e.g. Yandex TCP) answer domestic
			 * queries genuinely but refuse international ones; probing those with
			 * rotating international canaries reads false-dead. */
			anchor: (mode === 'proxy_banned_ru') ? 'ya.ru' : null });
	}
	if (use_secure)
		push(pools, { group: 'secure', servers: to_list(uci.get('homeproxy', 'config', 'secure_dns_server')), canaries: CANARIES_SECURE, via: via_proxy });

	/* EWMA smoothing factors as scaled ints. */
	let a_ok = alpha;            /* weight of new sample (0..100) */
	let a_old = 100 - alpha;     /* weight of history */

	let dead_this = {};          /* ip → failed this cycle */
	let good_this = {};          /* ip → opened this cycle */

	/* --- group-level ground truth FIRST: what would a CLIENT actually receive?
	 * Per-server probes below measure each upstream, but their local nslookup
	 * path (tproxied into the core) differs from mosdns's real racing path
	 * (direct, self-marked) where in-path injection fakes answers.
	 *
	 * Detection is DNS-level CROSS-VALIDATION: fetch reference answers for the
	 * canary via DIRECT DoH (TLS:443 — verified untouchable where port 53 is
	 * intercepted) and compare them with what OUR plain listener returns. An
	 * answer whose IPs never appear in the reference set is forged.
	 *
	 * NOTE: HTTP-verification is deliberately NOT used here — router-local :443
	 * is tproxied into the core, which routes by SNI through the tunnel, so ANY
	 * IP "opens" a proxied domain regardless of its validity. */
	if (use_plain) {
		let gbad = 0, gtotal = 0;
		for (let ci = 0; ci < length(CANARIES_PLAIN); ci = ci + 1) {
			let dom = CANARIES_PLAIN[ci];
			let ref = {};
			let r1 = doh_query('1.1.1.1', '/dns-query', dom, false);
			for (let i = 0; i < length(r1.ips); i = i + 1) ref[r1.ips[i]] = true;
			let r2 = doh_query('8.8.8.8', '/resolve', dom, false);
			for (let i = 0; i < length(r2.ips); i = i + 1) ref[r2.ips[i]] = true;
			if (!length(keys(ref))) continue;   /* references unreachable — cannot judge */
			/* A config-rebuild restart may briefly bounce the listener; retry
			 * once so a restart window isn't mistaken for a healthy answer. */
			let ips = tcp_dns_query('127.0.0.1', '' + plain_port, dom);
			if (!length(ips)) {
				sleep(2);
				ips = tcp_dns_query('127.0.0.1', '' + plain_port, dom);
			}
			if (!length(ips)) continue;         /* listener silent — not evidence of poison */
			gtotal = gtotal + 1;
			let clean = false;
			for (let i = 0; i < length(ips); i = i + 1) {
				if (ref[ips[i]]) { clean = true; break; }
				/* Confirmed forged vs a fresh reference set — feed the blacklist
				 * so the live pool drops such answers immediately (2-cycle rule). */
				dead_this[ips[i]] = (dead_this[ips[i]] || 0) + 1;
			}
			if (!clean) gbad = gbad + 1;
			dbg('gcheck: ' + dom + ' refs=' + length(keys(ref)) + ' got=[' + join(' ', ips) + '] -> ' + (clean ? 'clean' : 'FORGED'));
		}
		dbg('gcheck total=' + gtotal + ' bad=' + gbad);
		let poisoned = (gtotal > 0 && (gbad * 2) >= gtotal);
		st.plain_poisoned = poisoned ? '1' : '0';
		if (poisoned) {
			st.plain_bad_streak = (st.plain_bad_streak || 0) + 1;
			let autodoh = (uci.get('homeproxy', 'config', 'russia_dns_auto_doh') || '1') === '1';
			if (st.plain_doh_latch !== '1') {
				log('plain listener serves forged answers (' + gbad + '/' + gtotal + ' bad), streak=' + st.plain_bad_streak);
				if (autodoh && st.plain_bad_streak >= 2) {
					st.plain_doh_latch = '1';
					log('port-53 interception confirmed — direct DoH fallback latched ON');
				}
			}
		} else {
			st.plain_bad_streak = 0;
		}
	}

	/* --- real-user-domain verification: sample recently-queried names from the
	 * dnsmasq log and cross-validate the plain listener against direct-DoH
	 * references. A domain that persistently (>=3 samples) returns answers
	 * disjoint from every reference is QUARANTINED into a mosdns domain_set
	 * routed straight to the secure pool — the client stops receiving forged
	 * answers for it. Everything stays on-router. Rotation-tolerant by design:
	 * CDN answers legitimately differ between resolvers, so a single mismatch is
	 * never enough and any matching sample clears the streak. --- */
	if (use_plain && (uci.get('homeproxy', 'multidns', 'verify_user_domains') || '1') === '1'
	    && access(DNS_LOG)) {
		read_user_domains(st);
		if (!st.uv_fail) st.uv_fail = {};
		if (!st.uv_last) st.uv_last = {};
		let excl = {};
		for (let l in read_lines(PROXY_DOMAINS_FILE)) excl[trim(l)] = true;
		excl['ya.ru'] = true; excl['example.com'] = true; excl['cloudflare.com'] = true;
		excl['google.com'] = true; excl['www.google.com'] = true;
		/* NOTE: quarantined domains are NOT excluded - they must keep being
		 * sampled (at the usual cadence) or a lifted verdict could never happen. */
		let cands = [];
		for (let k in keys(st.user_recent)) {
			if (excl[k]) continue;
			if (!match(k, /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/)) continue;
			if ((cyc - (st.uv_last[k] || -100)) < 3) continue;   /* verified recently */
			push(cands, { d: k, t: st.user_recent[k] });
		}
		let verified = 0;
		while (verified < 4 && length(cands)) {
			let mi = 0;   /* freshest query first — the user's current pain */
			for (let i = 1; i < length(cands); i++)
				if (cands[i].t > cands[mi].t) mi = i;
			let dom = cands[mi].d;
			let rest = [];
			for (let i = 0; i < length(cands); i++) if (i !== mi) push(rest, cands[i]);
			cands = rest;
			st.uv_last[dom] = cyc;
			let r1 = doh_query('1.1.1.1', '/dns-query', dom, false);
			let r2 = doh_query('8.8.8.8', '/resolve', dom, false);
			/* Self-consistency gate: if the two references disagree with each
			 * other, the name rotates by design (pool.ntp.org, geo CDN) and can
			 * not be judged at all - cross-validation would flag EVERY answer. */
			let consistent = false;
			for (let i = 0; i < length(r1.ips) && !consistent; i = i + 1)
				if (index(r2.ips, r1.ips[i]) >= 0) consistent = true;
			if (!consistent) continue;
			let ref = {};
			for (let i = 0; i < length(r1.ips); i = i + 1) ref[r1.ips[i]] = true;
			for (let i = 0; i < length(r2.ips); i = i + 1) ref[r2.ips[i]] = true;
			let got = tcp_dns_query('127.0.0.1', '' + plain_port, dom);
			if (!length(got)) continue;                     /* listener silent — no verdict */
			let clean = false;
			for (let i = 0; i < length(got); i = i + 1)
				if (ref[got[i]]) { clean = true; break; }
			if (clean) {
				delete st.uv_fail[dom];
				if (st.quarantine && st.quarantine[dom]) {
					delete st.quarantine[dom];
					log('user domain ' + dom + ' verified clean — quarantine lifted');
				}
			} else {
				st.uv_fail[dom] = (st.uv_fail[dom] || 0) + 1;
				if (!st.quarantine) st.quarantine = {};
				if (st.uv_fail[dom] >= 3 && !st.quarantine[dom]) {
					st.quarantine[dom] = time();
					for (let i = 0; i < length(got); i = i + 1)
						dead_this[got[i]] = (dead_this[got[i]] || 0) + 1;
					log('user domain ' + dom + ' forged across ' + st.uv_fail[dom]
						+ ' samples — QUARANTINED to secure pool');
				}
			}
			verified = verified + 1;
		}
	}

	for (let pi = 0; pi < length(pools); pi = pi + 1) {
		let p = pools[pi];
		/* Fair share: each pool gets an equal slice of the HTTP budget so a long
		 * plain list can't starve secure-pool verification (AdGuard showed
		 * open=— purely from budget exhaustion). Budget is UCI-tunable
		 * (multidns.http_budget, default 24). */
		let pool_budget = int(http_budget_total / length(pools));
		let cs = p.canaries;
		let c1 = cs[cyc % length(cs)];
		let c2 = cs[(cyc + 1) % length(cs)];
		for (let si = 0; si < length(p.servers); si = si + 1) {
			let s = p.servers[si];
			try {
				let pd = cs[cyc % length(cs)];
				let r = probe_server(s, p.group, p.via, pd);
				/* Domestic-anchor retry: when the rotated canary yields nothing and
				 * the pool has an anchor domain (ru → ya.ru), give the server a
				 * second chance on the query type it actually exists to serve. */
				if (!r.ok && p.anchor && pd !== p.anchor) {
					let r2 = probe_server(s, p.group, p.via, p.anchor);
					if (r2.ok || length(r2.ips)) r = r2;
				}
				if (r.lat != null && r.lat != r.lat) r.lat = null;  /* NaN guard */
				let sk = skey(p.group, s);
				let cur = st.servers[sk] || { lat: null, succ: null, live: null, open: null, samples: 0, pruned: false, bad_streak: 0 };
				let okf = r.ok ? 100 : 0;
				let livef = (r.ok && r.live) ? 100 : 0;
				cur.succ = (cur.succ == null) ? okf : ((a_ok * okf + a_old * cur.succ) / 100);
				cur.live = (cur.live == null) ? livef : ((a_ok * livef + a_old * cur.live) / 100);
				cur.samples = (cur.samples || 0) + 1;
				cur.last_ip = r.ip;
				cur.last_ok = r.ok;
				cur.last_live = r.live;
				cur.lat = r.lat;

				/* HTTP verification: does the IP this server returned actually open
				 * the site? Multi-canary verdict: an IP is "open" if it opens the
				 * primary canary, or — when the primary fails — the secondary one.
				 * A poisoned/block-page answer opens neither. This avoids false
				 * dead-verdicts when a single canary site is temporarily down. */
				let opens = 0, checked = 0;
				if (r.ok && length(r.ips) && pool_budget > 0) {
					let n = (length(r.ips) > 3) ? 3 : length(r.ips);
					for (let vi = 0; vi < n && pool_budget > 0; vi = vi + 1) {
						pool_budget = pool_budget - 1;
						checked = checked + 1;
						let h = verify_ip(r.ips[vi], c1, p.via);
						let ok_open = h.opens;
						if (!ok_open && pool_budget > 0) {
							pool_budget = pool_budget - 1;
							let h2 = verify_ip(r.ips[vi], c2, p.via);
							ok_open = h2.opens;
						}
						if (ok_open) { opens = opens + 1; good_this[r.ips[vi]] = true; }
						else dead_this[r.ips[vi]] = (dead_this[r.ips[vi]] || 0) + 1;
					}
				}
				if (checked > 0) {
					let openf = int((opens * 100) / checked);
					cur.open = (cur.open == null) ? openf : ((a_ok * openf + a_old * cur.open) / 100);
				}
				st.servers[sk] = cur;
			} catch (e) { dbg('probe error [' + s + ']: ' + sprintf('%s', e)); }
		}
	}

	/* Dead-IP blacklist streaks: an IP must fail to open the site in >=2
	 * consecutive cycles before it is blacklisted, so a transient failure never
	 * poisons the live pool. Entries carry a last-seen timestamp and expire after
	 * 7 days without a failure observation — otherwise stale entries accumulated
	 * over the daemon's lifetime would blacklist IPs that work fine again. */
	let now_ts = time();
	if (!st.dead_ips) st.dead_ips = {};
	if (!st.dead_ips_t) st.dead_ips_t = {};
	for (let ip in good_this) { delete st.dead_ips[ip]; delete st.dead_ips_t[ip]; }
	for (let ip in dead_this) {
		st.dead_ips[ip] = (st.dead_ips[ip] || 0) + 1;
		st.dead_ips_t[ip] = now_ts;
	}
	for (let ip in keys(st.dead_ips))
		if ((now_ts - (st.dead_ips_t[ip] || 0)) > 604800) {
			delete st.dead_ips[ip];
			delete st.dead_ips_t[ip];
		}
	let blacklist = [];
	for (let ip in st.dead_ips) if ((st.dead_ips[ip] || 0) >= 2) push(blacklist, ip);
	atomic_write(DEAD_IPS_FILE, join('\n', blacklist) + (length(blacklist) ? '\n' : ''));

	/* Record the authoritative current pool membership in the state so the
	 * RPC/UI can label pools and counts straight from config. */
	st.pools = { ru: [], secure: [] };
	for (let pi = 0; pi < length(pools); pi = pi + 1) {
		let key = (pools[pi].group === 'ru') ? 'ru' : 'secure';
		for (let si = 0; si < length(pools[pi].servers); si = si + 1) {
			let s = pools[pi].servers[si];
			if (index(st.pools[key], s) < 0) push(st.pools[key], s);
		}
	}
	/* Drop any server no longer present in a configured pool so the monitor
	 * reflects EXACTLY the servers the user selected. */
	let keep = {};
	for (let k in st.pools)
		for (let i = 0; i < length(st.pools[k]); i = i + 1) {
			keep[st.pools[k][i]] = true;
			if (k === 'secure') keep[skey('secure', st.pools[k][i])] = true;
		}
	for (let s in st.servers)
		if (!keep[s]) delete st.servers[s];

	/* Scoring + real pruning. A server that stays bad (low success OR low open
	 * ratio OR low score) for several consecutive cycles is excluded from the
	 * live mosdns pool (not from UCI); it is re-checked every cycle and returns
	 * as soon as it recovers. */
	for (let s in st.servers) {
		if (!st.servers[s]) continue;
		let stt = st.servers[s];
		let sc = compute_score(stt);
		stt.score = sc;
		stt.poisoned = false;
		let bad = (stt.succ != null && stt.succ == stt.succ && stt.succ < min_live_ratio)
			|| (stt.open != null && stt.open == stt.open && stt.open < min_live_ratio)
			|| sc < min_score;
		if (bad) stt.bad_streak = (stt.bad_streak || 0) + 1;
		else stt.bad_streak = 0;
		stt.pruned = (stt.bad_streak >= 3);
	}
	dbg('analyze save');
	st.cycle = cyc + 1;
	save_state(st);
}

/* Synchronous one-shot used by init.d BEFORE generate_client.uc runs: build the
 * mosdns config from the current UCI and start the racing instance so the
 * generated client config can repoint its resolvers at the live listener. Exits
 * after starting (does not enter the analysis loop). The full analyzer daemon
 * (started by procd afterwards) takes over and keeps mosdns maintained. */
function bootstrap() {
	dbg('bootstrap:start');
	uci = cursor();
	uci.load('homeproxy');
	system('mkdir -p ' + MD_DIR);
	use_plain = (uci.get('homeproxy', 'multidns', 'use_plain') || '1') !== '0';
	use_secure = (uci.get('homeproxy', 'multidns', 'use_secure') || '1') !== '0';
	secure_via_proxy = (uci.get('homeproxy', 'multidns', 'secure_via_proxy') || '1') !== '0';
	plain_port = uci.get('homeproxy', 'multidns', 'plain_port') || '5453';
	secure_port = uci.get('homeproxy', 'multidns', 'secure_port') || '5454';
	http_budget_total = int(uci.get('homeproxy', 'multidns', 'http_budget') || '24') || 24;
	PROXY = '127.0.0.1:5338';  /* dedicated mdns-proxy-in → main-out */
	self_mark = int(uci.get('homeproxy', 'infra', 'self_mark') || '100') || 100;
	ensure_probe_table(self_mark);
	if (!access(MOSDNS)) { log('mosdns binary missing — install mosdns to use MultiDNS.'); return; }
	ensure_data_files();
	start_mosdns();
	dbg('bootstrap:done alive=' + mosdns_running());
}

function main() {
	dbg('main:start');
	uci = cursor();
	system('mkdir -p ' + MD_DIR);
	/* Start each daemon process with a clean quality state. The EWMA lives
	 * inside a single run (it is rebuilt continuously); persisting it across
	 * restarts only carries over stale/garbage samples from a previous probe
	 * method and poisons the score for a long time. A fresh process re-baselines
	 * immediately from the current, reliable UDP/53 probe. */
	system('rm -f ' + STATE_FILE);
	/* Outer loop: stay resident. If MultiDNS is disabled we idle (stop mosdns
	 * and sleep) instead of exiting — procd respawns an exiting instance, which
	 * would create a crash-loop on every disable toggle. procd SIGTERM on service
	 * stop still kills us cleanly. */
	while (true) {
		uci.load('homeproxy');
		enabled = uci.get('homeproxy', 'multidns', 'enabled') || '0';
		if (enabled !== '1') {
			stop_mosdns();
			dbg('main: disabled, waiting');
			sleep(10);
			continue;
		}
		use_plain = (uci.get('homeproxy', 'multidns', 'use_plain') || '1') !== '0';
		use_secure = (uci.get('homeproxy', 'multidns', 'use_secure') || '1') !== '0';
		secure_via_proxy = (uci.get('homeproxy', 'multidns', 'secure_via_proxy') || '1') !== '0';
			bench_interval = int(uci.get('homeproxy', 'multidns', 'bench_interval') || '120') || 120;
		alpha = ratio100(uci.get('homeproxy', 'multidns', 'alpha') || '0.4', 40);
		min_live_ratio = ratio100(uci.get('homeproxy', 'multidns', 'min_live_ratio') || '0.5', 50);
		min_score = int(uci.get('homeproxy', 'multidns', 'min_score') || '20') || 20;
		plain_port = uci.get('homeproxy', 'multidns', 'plain_port') || '5453';
		secure_port = uci.get('homeproxy', 'multidns', 'secure_port') || '5454';
		http_budget_total = int(uci.get('homeproxy', 'multidns', 'http_budget') || '24') || 24;
		PROXY = '127.0.0.1:5338';  /* dedicated mdns-proxy-in → main-out */
		self_mark = int(uci.get('homeproxy', 'infra', 'self_mark') || '100') || 100;
		ensure_probe_table(self_mark);

		if (!access(MOSDNS)) { log('mosdns binary missing — install mosdns to use MultiDNS.'); sleep(30); continue; }

	log('MultiDNS analyzer started (plain=' + use_plain + ', secure=' + use_secure + ', via_proxy=' + secure_via_proxy + ').');
	ensure_data_files();
	/* Adopt a healthy instance left by the synchronous init.d bootstrap instead of
	 * restarting it: a restart kills the racing listeners AFTER generate_client.uc
	 * has already pointed russia-dns/secure-dns at 127.0.0.1:5453/5454, producing
	 * seconds of SERVFAIL on every service start. Restart only when the running
	 * instance's config differs from what we would build now (or it is dead). */
	let conf_fresh = build_mosdns_conf();
	if (!(mosdns_running() && access(CONF) && trim(readfile(CONF)) === conf_fresh))
		start_mosdns();
		/* Run an initial analysis at startup so the monitor shows real pool data
		 * immediately instead of waiting a full bench_interval. */
		dbg('analyze call (initial)');
		analyze();
		dbg('analyze done (initial)');

		let last = time(), last_cfg = 0, last_pools_sig = '';
		while (true) {
			sleep(5);
			let now = time();
			uci.load('homeproxy');
			let en2 = uci.get('homeproxy', 'multidns', 'enabled') || '0';
			if (en2 !== '1') { log('MultiDNS disabled, stopping mosdns.'); stop_mosdns(); break; }
			use_plain = (uci.get('homeproxy', 'multidns', 'use_plain') || '1') !== '0';
			use_secure = (uci.get('homeproxy', 'multidns', 'use_secure') || '1') !== '0';
			secure_via_proxy = (uci.get('homeproxy', 'multidns', 'secure_via_proxy') || '1') !== '0';
		bench_interval = int(uci.get('homeproxy', 'multidns', 'bench_interval') || '120') || 120;
			plain_port = uci.get('homeproxy', 'multidns', 'plain_port') || '5453';
			secure_port = uci.get('homeproxy', 'multidns', 'secure_port') || '5454';
			PROXY = '127.0.0.1:5338';  /* dedicated mdns-proxy-in → main-out */

			/* Fast self-heal: if mosdns died for any reason, bring it back up
			 * within one loop tick (~5s) so DNS never stays down. */
			if (!mosdns_running()) { log('mosdns not running — restarting.'); start_mosdns(); }

			if ((now - last_cfg) > 30) {
				dbg('loop cfg-check');
				last_cfg = now;
				/* mirror learned lists + ensure data files; restart if any changed */
				let data_changed = ensure_data_files();
				let fresh = build_mosdns_conf();
				if (data_changed || !access(CONF) || trim(readfile(CONF)) !== fresh) {
					atomic_write(CONF, fresh);
					start_mosdns();
				}
				/* Keep the direct-path probe set in sync with the current pool. */
				update_probe_set(v4_hosts(assemble_plain_pool(load_state())));
				/* If the configured server list changed, re-probe now instead
				 * of waiting up to a full bench_interval for the monitor to
				 * reflect the new pool. */
				let sig = join(',', to_list(uci.get('homeproxy', 'config', 'russia_dns_server')))
				        + '|' + join(',', to_list(uci.get('homeproxy', 'config', 'china_dns_server')))
				        + '|' + join(',', to_list(uci.get('homeproxy', 'config', 'iran_dns_server')))
				        + '|' + join(',', to_list(uci.get('homeproxy', 'config', 'dns_server')))
				        + '|' + join(',', to_list(uci.get('homeproxy', 'config', 'secure_dns_server')))
			        + '|' + ((uci.get('homeproxy', 'config', 'russia_dns_use_wan') || '0') === '1'
					? join(',', wan_dns_servers()) : '');
				if (sig !== last_pools_sig) {
					last_pools_sig = sig;
					dbg('pools changed -> analyze');
					analyze();
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

if (ARGV[0] === 'bootstrap') {
	try {
		bootstrap();
	} catch (e) {
		log('bootstrap fatal: ' + sprintf('%s', e));
	}
} else {
	try {
		main();
	} catch (e) {
		dbg('CATCH: ' + sprintf('%s', e));
		log('fatal: ' + sprintf('%s', e));
	}
}
