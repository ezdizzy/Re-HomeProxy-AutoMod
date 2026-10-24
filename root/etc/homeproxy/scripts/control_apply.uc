// SPDX-License-Identifier: GPL-2.0-only
//
// Re:HomeProxy AutoMod — «Контроль» enforcement (plan 14; adapted from
// luci-app-homecontrol apply.uc with hardening for the re-homeproxy
// interception, see LOCAL_DOCS/14-PLAN_CONTROL_INTEGRATION.md §0).
//
// Enforcement model:
//   - blocked clients -> table inet homecontrol:
//       hc_pre_drop (hook prerouting, priority -155 — BEFORE the fw4 tproxy
//       mangle chain (-150) and the fw4 dstnat REDIRECT chain (-100)): drops
//       ALL intercepted traffic of blocked clients too. MAC-based drops also
//       cover IPv6. DoT/DoQ (853) drops for DNS-filtered clients live here
//       (prerouting cannot `reject`, and the forward chain never sees
//       intercepted packets).
//       dns_redirect (nat prerouting, priority -105 — before the fw4 dstnat
//       DNS hijack at -100): per-client DNS redirect to a dedicated dnsmasq
//       filter instance (NXDOMAIN for its domains, forwards the rest to the
//       main dnsmasq — the re-homeproxy DNS pipeline stays intact).
//       block_forward (hook forward, priority -100): backstop for traffic
//       that is not intercepted (ICMP, non-intercepted modes).
//       block_output_reject (hook output): the ROUTER refuses blocked
//       destinations — a proxied client's connection dialed by the core
//       dies here for GLOBAL IP rules.
//   - GLOBAL rules (no client list): domains -> main dnsmasq server=/d/
//     (NXDOMAIN), IPs -> nft set blocked_rule_v4 (prerouting + forward +
//     output reject).
//   - PER-CLIENT rules (rule lists clients): IPs -> nft set pc_<id>_v4;
//     domains -> dedicated dnsmasq filter instance on port 5353+n.
//   - Wi-Fi -> wireless.<iface>.disabled + marker files (auto restore).
//   - Expired temporary blocks are logged as events and removed from
//     temps.json (feeds the Telegram pushes).
//
// Usage: ucode -L /etc/homeproxy/scripts /etc/homeproxy/scripts/control_apply.uc

'use strict';

import { access, readfile, writefile, popen, readlink } from 'fs';
import {
	RUN_DIR, atomic_write, mkdir_p, get_sections, main_opt,
	client_states, active_rules, client_rule_targets, wifi_off_map,
	read_temps_raw, read_temps, write_temps, list_wifi_ifaces, log, add_event
} from 'control';

const DNSF_DIR = RUN_DIR + '/dnsf';
const DNSF_PORT_BASE = 5353;
const DNSF_MAX = 16; /* safety cap: max parallel filter instances */

/* Make a uci section id safe for nft set names / file names. */
function safe_id(id) {
	return replace(id, /[^A-Za-z0-9_-]/g, '_');
}

/* Strict validators for everything rendered into nft/dnsmasq syntax: a
 * garbage UCI value (hand edit, restore, bug) must never break `nft -f`
 * (all-or-nothing: the whole enforcement would silently disappear) or
 * inject into a dnsmasq conf. Invalid entries are SKIPPED, not fatal. */
function valid_ip4(v) {
	return type(v) === 'string' &&
		!!match(trim(v), /^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}(\/(3[0-2]|[12]?[0-9]))?$/);
}
function valid_mac(v) {
	return type(v) === 'string' && !!match(trim(v), /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/);
}
function valid_ifname(v) {
	return type(v) === 'string' && !!match(trim(v), /^[A-Za-z0-9._-]{1,15}$/);
}
function valid_domain(v) {
	v = trim('' + (v || ''));
	return length(v) > 2 && length(v) <= 253 &&
		!!match(v, /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/) &&
		index(v, '.') > 0 && !match(v, /\.\./);
}

/* Resolve the active dnsmasq conf-dir at runtime (/var is a symlink to
 * /tmp on OpenWrt, so this finds /tmp/dnsmasq.cfg01411c.d). */
function dnsmasq_conf_dir() {
	const fd = popen(
		`grep -m1 -h "^conf-dir=" /var/etc/dnsmasq.conf.* 2>/dev/null | sed -n "s/^conf-dir=//p" | head -n1`);
	if (!fd)
		return '/tmp/dnsmasq.d/homecontrol.d';
	let dir = trim((fd.read('all') || ''));
	fd.close();
	while (length(dir) && substr(dir, length(dir) - 1) === '/')
		dir = substr(dir, 0, length(dir) - 1);
	return length(dir) ? dir : '/tmp/dnsmasq.d/homecontrol.d';
}

const CONF_DIR = dnsmasq_conf_dir();

/* ── nftables render ─────────────────────────────────────────────── */

/* pc:   [ { id, ip, mac, ips: [targets] } ]  — per-client IP rules
 * dnsf: [ { id, ip, mac, port } ]            — active DNS filter clients
 * wblk: [ macs ]                             — Wi-Fi-blocked client MACs
 * wifaces: [ names ]                         — live Wi-Fi iface names (iw dev) */
function render_nft(ips, macs, rule_ips, pc, dnsf, wblk, wifaces) {
	const lines = [];
	/* Choke-point validation: only well-formed values reach the nft render. */
	const ipL = length(ips) ? uniq(filter(ips, valid_ip4)) : [];
	const macL = length(macs) ? uniq(filter(macs, valid_mac)) : [];
	const ripL = length(rule_ips) ? uniq(filter(rule_ips, valid_ip4)) : [];
	const wblkL = length(wblk) ? uniq(filter(wblk, valid_mac)) : [];
	const wfL = length(wifaces) ? uniq(filter(wifaces, valid_ifname)) : [];

	const dnsf_ips = [];
	for (let i = 0; i < length(dnsf); i++)
		if (dnsf[i].ip)
			push(dnsf_ips, dnsf[i].ip);

	push(lines, `table inet homecontrol`);
	push(lines, `delete table inet homecontrol`);
	push(lines, `table inet homecontrol {`);

	/* blocked clients (v4) */
	push(lines, `	set blocked_v4 {`);
	push(lines, `		type ipv4_addr`);
	push(lines, `		flags interval`);
	if (length(ipL))
		push(lines, `		elements = { ${join(', ', ipL)} }`);
	push(lines, `	}`);
	/* blocked clients (L2 — covers IPv6 and every protocol) */
	push(lines, `	set blocked_macs {`);
	push(lines, `		type ether_addr`);
	if (length(macL))
		push(lines, `		elements = { ${join(', ', macL)} }`);
	push(lines, `	}`);
	/* GLOBAL IP rule targets (destination drop for the whole network) */
	push(lines, `	set blocked_rule_v4 {`);
	push(lines, `		type ipv4_addr`);
	push(lines, `		flags interval`);
	if (length(ripL))
		push(lines, `		elements = { ${join(', ', ripL)} }`);
	push(lines, `	}`);

	/* per-client IP rule sets */
	for (let i = 0; i < length(pc); i++) {
		const p = pc[i];
		const pips = (p && length(p.ips)) ? uniq(filter(p.ips, valid_ip4)) : [];
		if (!length(pips))
			continue;
		push(lines, `	set pc_${safe_id(p.id)}_v4 {`);
		push(lines, `		type ipv4_addr`);
		push(lines, `		flags interval`);
		push(lines, `		elements = { ${join(', ', pips)} }`);
		push(lines, `	}`);
	}
	/* DNS-filtered clients (for the DoT/DoQ bypass protection) */
	push(lines, `	set dnsf_v4 {`);
	push(lines, `		type ipv4_addr`);
	push(lines, `		flags interval`);
	if (length(dnsf_ips))
		push(lines, `		elements = { ${join(', ', uniq(dnsf_ips))} }`);
	push(lines, `	}`);

	/* Per-client Wi-Fi block (plan 15): drop by MAC only when the packet
	 * ENTERS through a Wi-Fi interface — wired stays untouched. */
	push(lines, `	set wifi_ifaces {`);
	push(lines, `		type ifname`);
	if (length(wfL))
		push(lines, `		elements = { ${join(', ', wfL)} }`);
	push(lines, `	}`);
	push(lines, `	set wifi_blocked_macs {`);
	push(lines, `		type ether_addr`);
	if (length(wblkL))
		push(lines, `		elements = { ${join(', ', wblkL)} }`);
	push(lines, `	}`);

	/* ── EARLY prerouting drop: runs BEFORE the fw4 tproxy mangle chain
	 * (-150) and the fw4 dstnat REDIRECT/DNS-hijack chain (-100), so a
	 * blocked client (or a blocked destination) is dead even when its
	 * traffic would be intercepted by re-homeproxy. Loopback is exempt. */
	push(lines, `	chain hc_pre_drop {`);
	push(lines, `		type filter hook prerouting priority -155; policy accept;`);
	push(lines, `		iifname "lo" counter accept`);
	push(lines, `		ether saddr @blocked_macs counter drop`);
	push(lines, `		ip saddr @blocked_v4 counter drop`);
	push(lines, `		ip daddr @blocked_rule_v4 counter drop`);
	if (length(wblkL) && length(wfL))
		push(lines, `		iifname @wifi_ifaces ether saddr @wifi_blocked_macs counter drop`);
	for (let i = 0; i < length(pc); i++) {
		const p = pc[i];
		if (!(p && length(p.ips)) || !length(uniq(filter(p.ips, valid_ip4))))
			continue;
		const sname = `pc_${safe_id(p.id)}_v4`;
		if (p.ip && valid_ip4(p.ip))
			push(lines, `		ip saddr ${p.ip} ip daddr @${sname} counter drop`);
		if (p.mac && valid_mac(p.mac))
			push(lines, `		ether saddr ${p.mac} ip daddr @${sname} counter drop`);
	}
	if (length(dnsf_ips)) {
		/* DoT/DoQ bypass protection (reject is invalid in prerouting — drop) */
		push(lines, `		ip saddr @dnsf_v4 tcp dport 853 counter drop`);
		push(lines, `		ip saddr @dnsf_v4 udp dport 853 counter drop`);
	}
	push(lines, `	}`);

	/* Per-client DNS redirect: nat prerouting at -105 wins the NAT decision
	 * BEFORE the fw4 dstnat chain (-100, homeproxy DNS hijack) for filtered
	 * clients; everyone else falls through to the standard hijack. */
	push(lines, `	chain dns_redirect {`);
	push(lines, `		type nat hook prerouting priority -105; policy accept;`);
	for (let i = 0; i < length(dnsf); i++) {
		const d = dnsf[i];
		if (d.ip && valid_ip4(d.ip)) {
			push(lines, `		ip saddr ${d.ip} udp dport 53 redirect to :${d.port}`);
			push(lines, `		ip saddr ${d.ip} tcp dport 53 redirect to :${d.port}`);
		}
		if (d.mac && valid_mac(d.mac)) {
			push(lines, `		ether saddr ${d.mac} udp dport 53 redirect to :${d.port}`);
			push(lines, `		ether saddr ${d.mac} tcp dport 53 redirect to :${d.port}`);
		}
	}
	push(lines, `	}`);

	/* Backstop for traffic that never reached the early chain (ICMP,
	 * non-intercepted modes). */
	push(lines, `	chain block_forward {`);
	push(lines, `		type filter hook forward priority -100; policy accept;`);
	push(lines, `		ip saddr @blocked_v4 counter drop`);
	push(lines, `		ether saddr @blocked_macs counter drop`);
	push(lines, `		ip daddr @blocked_rule_v4 counter drop`);
	if (length(wblkL) && length(wfL))
		push(lines, `		iifname @wifi_ifaces ether saddr @wifi_blocked_macs counter drop`);
	for (let i = 0; i < length(pc); i++) {
		const p = pc[i];
		if (!(p && length(p.ips)) || !length(uniq(filter(p.ips, valid_ip4))))
			continue;
		const sname = `pc_${safe_id(p.id)}_v4`;
		if (p.ip && valid_ip4(p.ip))
			push(lines, `		ip saddr ${p.ip} ip daddr @${sname} counter drop`);
		if (p.mac && valid_mac(p.mac))
			push(lines, `		ether saddr ${p.mac} ip daddr @${sname} counter drop`);
	}
	if (length(dnsf_ips)) {
		push(lines, `		ip saddr @dnsf_v4 tcp dport 853 counter reject`);
		push(lines, `		ip saddr @dnsf_v4 udp dport 853 counter reject`);
	}
	push(lines, `	}`);

	/* Router-side: globally-blocked destinations are refused for proxied
	 * clients too (the core dials them from the router — this output hook
	 * kills the egress leg). */
	push(lines, `	chain block_output_reject {`);
	push(lines, `		type filter hook output priority -100; policy accept;`);
	push(lines, `		oifname != "lo" ip daddr @blocked_v4 counter reject`);
	push(lines, `		oifname != "lo" ip daddr @blocked_rule_v4 counter reject`);
	push(lines, `	}`);
	push(lines, `}`);

	return join('\n', lines) + '\n';
}

/* ── dnsmasq render (GLOBAL domain rules) ────────────────────────── */

function render_dnsmasq(rules) {
	mkdir_p(CONF_DIR);
	const out = [];
	for (let i = 0; i < length(rules); i++) {
		const r = rules[i];
		if ((r.type || 'domain') !== 'domain')
			continue;
		const targets = r.target || [];
		for (let k = 0; k < length(targets); k++)
			if (valid_domain(targets[k]))
				push(out, `server=/${trim(targets[k])}/`);
	}
	const content = length(out) ? (join('\n', out) + '\n') : '';

	/* Skip restart when content did not change (avoids DNS blips). */
	const path = CONF_DIR + '/hc-blocked.conf';
	const old = access(path) ? readfile(path) : '';
	if (old === content)
		return false;
	atomic_write(path, content);
	return true;
}

/* ── per-client dnsmasq filter instances ─────────────────────────── */

function dnsf_conf_content(safe, port) {
	const lines = [
		'# generated by homeproxy control apply — do not edit',
		`port=${port}`,
		'no-resolv',
		'server=127.0.0.1#53',
		'no-hosts',
		'cache-size=300',
		'local-ttl=1',
		`pid-file=${DNSF_DIR}/${safe}.pid`,
		`conf-file=${DNSF_DIR}/domains.${safe}.conf`,
		`log-facility=${DNSF_DIR}/${safe}.log`
	];
	return join('\n', lines) + '\n';
}

function dnsf_domains_content(domains) {
	const lines = [];
	for (let i = 0; i < length(domains); i++)
		if (valid_domain(domains[i]))
			push(lines, `server=/${trim(domains[i])}/`);
	return length(lines) ? (join('\n', lines) + '\n') : '';
}

/* Is the filter instance for `safe` actually alive (pidfile + /proc exe)?
 * /proc/<pid>/cmdline contains NUL bytes and ucode regex matching truncates
 * at the first NUL — use /proc/<pid>/exe instead. */
function dnsf_running(safe) {
	const pidp = `${DNSF_DIR}/${safe}.pid`;
	if (!access(pidp))
		return false;
	const pid = int(trim(readfile(pidp) || '')) || 0;
	if (pid < 2)
		return false;
	const exe = access(`/proc/${pid}/exe`) ? (readlink(`/proc/${pid}/exe`) || '') : '';
	return match(exe || '', /dnsmasq/) ? true : false;
}

function stop_dnsf(safe) {
	const pidp = `${DNSF_DIR}/${safe}.pid`;
	if (access(pidp)) {
		const pid = int(trim(readfile(pidp) || '')) || 0;
		if (pid >= 2 && system(`kill -0 ${pid} 2>/dev/null`) === 0)
			system(`kill ${pid} 2>/dev/null`);
	}
	system(`rm -f '${DNSF_DIR}/${safe}.pid'`);
}

/* Make sure a filter instance is running with this exact config.
 * Returns true when the instance is alive afterwards. */
function ensure_dnsf(safe, port, domains, label) {
	mkdir_p(DNSF_DIR);
	const confp = `${DNSF_DIR}/${safe}.conf`;
	const domp = `${DNSF_DIR}/domains.${safe}.conf`;

	const ccontent = dnsf_conf_content(safe, port);
	const dcontent = dnsf_domains_content(domains);
	const oldc = access(confp) ? readfile(confp) : '';
	const oldd = access(domp) ? readfile(domp) : '';

	if (oldc === ccontent && oldd === dcontent && dnsf_running(safe))
		return true;

	atomic_write(confp, ccontent);
	atomic_write(domp, dcontent);
	stop_dnsf(safe);
	system(`dnsmasq -C '${confp}' >/dev/null 2>&1`);
	sleep(300);   /* sleep() is MILLISECONDS on this build — let it daemonize */
	if (dnsf_running(safe)) {
		log(`dnsf ${label}: filter instance on port ${port} (${length(domains)} domains)`);
		return true;
	}
	log(`dnsf ${label}: FAILED to start on port ${port}`);
	return false;
}

/* Kill filter instances that are no longer needed. */
function cleanup_dnsf(wanted) {
	mkdir_p(DNSF_DIR);
	const fd = popen(`ls ${DNSF_DIR}/*.conf 2>/dev/null`);
	if (!fd)
		return;
	const raw = fd.read('all') || '';
	fd.close();
	const files = split(trim(raw), /\n/);
	for (let i = 0; i < length(files); i++) {
		const f = trim(files[i]);
		const m = match(f, /\/([^\/]+)\.conf$/);
		if (!m)
			continue;
		const safe = m[1];
		if (substr(safe, 0, 8) === 'domains.')
			continue;
		if (safe in wanted)
			continue;
		stop_dnsf(safe);
		system(`rm -f '${DNSF_DIR}/${safe}.conf' '${DNSF_DIR}/domains.${safe}.conf' '${DNSF_DIR}/${safe}.log'`);
		log(`dnsf ${safe}: filter removed (no active per-client rules)`);
	}
}

/* ── wireless management ─────────────────────────────────────────── */

/* Only touch ifaces we manage: those in the off map, the registry, or
 * ifaces we disabled before (markers) — the last group must be enumerated
 * so we can restore them after a window closes / temp marker expires. */
function apply_wifi(off_map, now) {
	const wifis = get_sections('wifi');
	const managed = {};
	for (let k in off_map)
		managed[k] = true;
	for (let i = 0; i < length(wifis); i++)
		if (wifis[i].network)
			managed[wifis[i].network] = true;

	/* ifaces with our markers (off/on/temp) are ours to restore/clean */
	const fd0 = popen(`ls ${RUN_DIR}/wifi.off.* ${RUN_DIR}/wifi.temp.* 2>/dev/null`);
	if (fd0) {
		const raw0 = fd0.read('all') || '';
		fd0.close();
		const files0 = split(trim(raw0), /\n/);
		for (let i = 0; i < length(files0); i++) {
			const m = match(trim(files0[i]), /wifi\.(off|temp)\.(.+)$/);
			if (m && length(m[2]))
				managed[m[2]] = true;
		}
	}

	let changed = false;
	for (let iface in managed) {
		if (!iface)
			continue;
		const want_off = (off_map[iface] === true);
		const offMarker = `${RUN_DIR}/wifi.off.${iface}`;

		const fd = popen(`uci -q get wireless.${iface}.disabled 2>/dev/null`);
		const cur = fd ? trim((fd.read('all') || '')) : '';
		if (fd)
			fd.close();

		if (want_off) {
			if (cur !== '1') {
				system(`uci -q set wireless.${iface}.disabled='1'`);
				system(`touch '${offMarker}'`);
				add_event('wifi', iface, 'turned off (schedule/timer)');
				changed = true;
			}
		} else {
			/* Window closed: re-enable only what WE disabled. */
			if (access(offMarker)) {
				system(`rm -f '${offMarker}'`);
				if (cur === '1') {
					system(`uci -q delete wireless.${iface}.disabled`);
					add_event('wifi', iface, 'turned on (window ended)');
					changed = true;
				}
			}
		}

		/* drop expired temp markers */
		const tempMarker = `${RUN_DIR}/wifi.temp.${iface}`;
		if (access(tempMarker)) {
			const tu = int(trim(readfile(tempMarker) || '')) || 0;
			if (tu <= now) {
				system(`rm -f '${tempMarker}'`);
				add_event('wifi', iface, 'temporary off expired');
			}
		}
	}

	if (changed)
		system(`wifi reload 2>/dev/null`);
	return changed;
}

/* Deauth Wi-Fi-blocked clients from every Wi-Fi interface (best effort):
 * the nft drop kills their traffic already — this makes the disconnection
 * visible on the device at once instead of a silent "no internet". */
function kick_wifi(macs, wifaces) {
	for (let i = 0; i < length(macs); i++)
		for (let k = 0; k < length(wifaces); k++)
			system(`ubus call hostapd.${wifaces[k]}.del_client '{"addr":"${macs[i]}","reason":5,"deauth":true,"ban_time":60000}' >/dev/null 2>&1`);
}

/* ── main ──────────────────────────────────────────────────────────
 * The WHOLE flow runs inside a function: ucode's script-top-level
 * scoping of let/const/IIFE is fragile (live: loop variables resolved
 * to unrelated globals, "left-hand side expression is null") — every
 * long daemon in this app (telegram/automation/hotswap) executes from
 * main() for the same reason. */

function main() {
	/* Serialize applies: the RPC layer (apply_async) and the engine tick can
	 * both run this at the same time — overlapping dnsmasq restarts raced
	 * each other into a dead resolver (live-verified). mkdir is atomic; a
	 * crashed apply leaves a stale lock, so the wait is bounded. */
	let locked = false;
	for (let i = 0; i < 20; i++) {
		if (system('mkdir /tmp/hc_apply.lock 2>/dev/null') === 0) {
			locked = true;
			break;
		}
		sleep(500);
	}
	if (!locked)
		log('apply: lock busy >10s — applying anyway');

	mkdir_p(RUN_DIR);
	mkdir_p(CONF_DIR);
	mkdir_p(DNSF_DIR);

	const now = time();
	const enabled = main_opt('enabled', '0') === '1';

	/* Expired temporary blocks: log + prune from temps.json (the engine
	 * sees the temps change in its signature and re-applies after). */
	const raw_temps = read_temps_raw();
	const live_temps = read_temps();
	let expired_temps = 0;
	for (let k in raw_temps) {
		if (k in live_temps)
			continue;
		const v = raw_temps[k];
		const is_allow = (type(v) === 'object' && v.mode === 'allow');
		add_event('temp', k, is_allow ? 'temporary allow expired' : 'temporary block expired');
		delete raw_temps[k];
		expired_temps++;
	}
	if (expired_temps > 0)
		write_temps(raw_temps);

	let ips = [], macs = [], rule_ips = [];
	let global_rules = [];   /* global domain rules -> main dnsmasq */
	let pc = [];             /* per-client IP rules for nft */
	let dnsf_want = [];      /* per-client domain rules -> filter instances */
	let dnsf = [];           /* ACTIVE filter clients (for nft redirect) */
	let wblk = [];           /* Wi-Fi-blocked client MACs (plan 15) */
	let wifaces = [];        /* live Wi-Fi iface names for the wifi sets */
	let woff = {};

if (enabled) {
	const paused_now = main_opt('paused', '0') === '1';
	const states = client_states(now);
	for (let i = 0; i < length(states); i++) {
		if (!states[i].blocked)
			continue;
		if (states[i].ip)
			push(ips, states[i].ip);
		if (states[i].mac)
			push(macs, states[i].mac);
	}
	if (!paused_now) {
		for (let i = 0; i < length(states); i++)
			if (states[i].wifi_blocked && states[i].mac)
				push(wblk, states[i].mac);
		if (length(wblk))
			wifaces = list_wifi_ifaces();
	}

	const all_rules = active_rules(now);
	for (let i = 0; i < length(all_rules); i++) {
		const r = all_rules[i];
		/* rules that list clients are per-client, handled below */
		const cids = r.client_ids || [];
		if (length(cids))
			continue;
		if ((r.type || 'domain') === 'ip') {
			const targets = r.target || [];
			for (let k = 0; k < length(targets); k++)
				push(rule_ips, targets[k]);
		} else {
			push(global_rules, r);
		}
	}

	/* per-client rule targets, resolved to the client's CURRENT ip/mac
	 * (client_states resolves the DHCP address by MAC — a renewed lease
	 * moves the rules automatically). */
	const crt = client_rule_targets(now);
	const resolved = {};
	for (let i = 0; i < length(states); i++)
		resolved[states[i].id] = states[i];

	const cids_sorted = [];
	for (let cid in crt)
		push(cids_sorted, cid);
	sort(cids_sorted);

	for (let i = 0; i < length(cids_sorted); i++) {
		const cid = cids_sorted[i];
		const c = resolved[cid] || {};
		if (!c.ip && !c.mac) {
			log(`dnsf ${cid}: skipped, client has no resolvable ip/mac`);
			continue;
		}
		if (length(crt[cid].ips))
			push(pc, { id: cid, ip: c.ip || '', mac: c.mac || '', ips: crt[cid].ips });
		if (length(crt[cid].domains) && length(dnsf_want) < DNSF_MAX)
			push(dnsf_want, { id: cid, ip: c.ip || '', mac: c.mac || '', domains: crt[cid].domains });
	}

	woff = wifi_off_map(now);
}

/* start/restart filter instances (even when disabled -> none wanted) */
for (let i = 0; i < length(dnsf_want); i++) {
	const d = dnsf_want[i];
	const safe = safe_id(d.id);
	const port = DNSF_PORT_BASE + i;
	if (ensure_dnsf(safe, port, d.domains, d.id)) {
		push(dnsf, { id: d.id, safe: safe, port: port, ip: d.ip, mac: d.mac, n: length(d.domains) });
	} else {
		add_event('system', d.id, 'per-client DNS filter failed to start — client falls back to global DNS');
	}
}

/* remove stale filter instances */
const wanted = {};
for (let i = 0; i < length(dnsf); i++)
	wanted[dnsf[i].safe] = true;
cleanup_dnsf(wanted);

/* persist the active instance map for the UI */
const insts = [];
for (let i = 0; i < length(dnsf); i++)
	push(insts, { id: dnsf[i].id, port: dnsf[i].port, domains: dnsf[i].n });
atomic_write(DNSF_DIR + '/instances.json', sprintf('%J', insts) + '\n');

const nft_file = RUN_DIR + '/hc.nft';
if (enabled) {
	writefile(nft_file, render_nft(ips, macs, rule_ips, pc, dnsf, wblk, wifaces));
	system(`nft -f '${nft_file}' 2>/dev/null`);
	if (length(wblk))
		kick_wifi(wblk, length(wifaces) ? wifaces : list_wifi_ifaces());
} else {
	/* disabled: remove the table entirely (an empty table would be a
	 * no-op, but its absence is the honest "control is off" state) */
	system(`nft delete table inet homecontrol 2>/dev/null`);
}

const dns_changed = render_dnsmasq(global_rules);
if (dns_changed)
	system(`/etc/init.d/dnsmasq restart >/dev/null 2>&1`);

apply_wifi(woff, now);

log(`applied: enabled=${enabled} clients=${length(ips)}/${length(macs)} rule_ips=${length(rule_ips)} pc_rules=${length(pc)} dns_filters=${length(dnsf)} dns_domains_applied=${length(global_rules) ? 'y' : 'n'} dns_restart=${dns_changed ? 'y' : 'n'} wifi_off=${length(keys(woff))} wifi_block=${length(wblk)}`);
print(`control applied: ${length(ips)} ip, ${length(macs)} mac, ${length(rule_ips)} rule-ip, ${length(pc)} pc-rules, ${length(dnsf)} dns-filters, ${length(wblk)} wifi-block\n`);
	system('rmdir /tmp/hc_apply.lock 2>/dev/null');
}

main();
