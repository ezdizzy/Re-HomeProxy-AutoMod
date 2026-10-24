// SPDX-License-Identifier: GPL-2.0-only
//
// Re:HomeProxy AutoMod — «Контроль» (HomeControl integration, plan 14).
// Shared library: config access, lease/ARP device tracking, effective state
// computation, schedule logic, events journal. Used by control_apply.uc
// (enforcer), control_engine.uc (watcher), the rpcd backend (control_* RPCs)
// and the Telegram control module.
//
// ucode notes (see LOCAL_DOCS/05-KNOWN_ISSUES_AND_LESSONS.md):
//  - `export function f() {...}` REQUIRES the trailing `;`;
//  - json() only PARSES — stringify with sprintf('%J');
//  - no Array.prototype methods — global push()/join(sep, arr)/sort()/keys();
//  - `for (let k in obj)` only (no const, no for..of);
//  - NO hoisting in modules — helpers are declared before their callers;
//  - match() with a string PATTERN is broken — regex literals only;
//  - localtime() returns a FULL year and a 1-based .mon;
//  - no `typeof` in standalone ucode — use the type() builtin;
//  - no `?.` here: this module runs in rpcd AND in standalone daemons.

'use strict';

import { access, readfile, writefile, open, popen } from 'fs';
import { cursor } from 'uci';

export const CONF = 'homecontrol';
export const RUN_DIR = '/var/run/homecontrol';
export const STATE_DIR = '/etc/homecontrol';
export const LOG_PATH = RUN_DIR + '/control.log';
export const EVENTS_PATH = RUN_DIR + '/events.json';

let _cursor = null;
let _cursor_ts = 0;

/* ucode cursors snapshot the config at creation — TTL cache so long-lived
 * processes (rpcd, engine) see fresh UCI after `uci commit`. */
export function get_cursor() {
	const now = time();
	if (!_cursor || (now - _cursor_ts) > 2) {
		_cursor = cursor();
		_cursor_ts = now;
	}
	return _cursor;
};

/* Invalidate the cursor cache: a MUTATION (shell `uci commit`) must be
 * visible to the NEXT read even in the same process — without this a
 * rapid delete→re-add sequence read a stale snapshot and failed with
 * "already exists"/"unknown client id" (live-caught, ч.108). Callers that
 * commit via the shell tool must call this right after the commit. */
export function bump_cursor() {
	_cursor = null;
	_cursor_ts = 0;
};

export function systime_stamp() {
	const d = localtime(time());
	return sprintf('%04d-%02d-%02d %02d:%02d:%02d',
		d.year, d.mon, d.mday, d.hour, d.min, d.sec);
};

export function log(msg) {
	const f = open(LOG_PATH, 'a');
	if (!f)
		return;
	f.write(sprintf('%s %s\n', systime_stamp(), msg));
	f.close();
};

export function dirname(p) {
	const m = match(p, /^(.*)\/[^\/]+$/);
	return m ? m[1] : '.';
};

export function mkdir_p(p) {
	system(`mkdir -p '${p}'`);
};

/* Atomic write: temp + mv, so the UI/TG readers never see a truncated file. */
export function atomic_write(path, content) {
	mkdir_p(dirname(path));
	const tmp = path + '.tmp';
	writefile(tmp, content);
	system(`mv -f '${tmp}' '${path}'`);
};

export function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
};

/* Read all sections of a given UCI type as objects with .id. */
export function get_sections(ctype) {
	const uc = get_cursor();
	const res = [];
	const all = uc.get_all(CONF);
	if (!all)
		return res;
	for (let sid in all) {
		const sec = uc.get_all(CONF, sid);
		if (!sec || sec['.type'] !== ctype)
			continue;
		const obj = { id: sid };
		for (let k in sec) {
			if (k === '.type' || k === '.name' || k === '.anonymous')
				continue;
			obj[k] = sec[k];
		}
		push(res, obj);
	}
	return res;
};

export function get_section(sid) {
	const uc = get_cursor();
	return uc.get_all(CONF, sid);
};

export function sec_opt(sid, opt, def) {
	const uc = get_cursor();
	const v = uc.get(CONF, sid, opt);
	if (v == null || v === '')
		return def;
	return v;
};

export function main_opt(opt, def) {
	const uc = get_cursor();
	const v = uc.get(CONF, 'main', opt);
	if (v == null || v === '')
		return def;
	return v;
};

/* Append an event to the events journal (capped, atomic). */
export function add_event(type, who, detail) {
	if (main_opt('log_enabled', '1') !== '1')
		return;
	let events = [];
	const raw = access(EVENTS_PATH) ? readfile(EVENTS_PATH) : null;
	if (raw) {
		try { events = json(raw); } catch (e) { events = []; }
	}
	const maxn = int(main_opt('log_max', '500')) || 500;
	push(events, {
		ts: time(),
		type: type,        /* block, allow, wifi, schedule, temp, system */
		who: who || '',
		detail: detail || ''
	});
	while (length(events) > maxn)
		shift(events);
	atomic_write(EVENTS_PATH, sprintf('%J', events) + '\n');
};

/* Parse "HH:MM" to minutes-since-midnight, or null. */
export function parse_hhmm(v) {
	const m = match(v || '', /^(\d{1,2}):(\d{2})$/);
	if (!m)
		return null;
	const h = int(m[1]), mi = int(m[2]);
	if (h > 24 || mi > 59)
		return null;
	return h * 60 + mi;
};

/* Weekday name to index (Mon=0..Sun=6). */
const WD = { Mon: 0, Tue: 1, Wed: 2, Thu: 3, Fri: 4, Sat: 5, Sun: 6 };

export function wd_index(name) {
	return (name in WD) ? WD[name] : -1;
};

function any_day(days, wday) {
	for (let i = 0; i < length(days); i++)
		if (wd_index(days[i]) === wday)
			return true;
	return false;
};

function date_to_ts(ymd, hhmm) {
	const m = match(ymd || '', /^(\d{4})-(\d{2})-(\d{2})$/);
	if (!m)
		return null;
	const t = parse_hhmm(hhmm);
	if (t == null)
		return null;
	return time(sprintf('%04d-%02d-%02d %02d:%02d:00',
		int(m[1]), int(m[2]), int(m[3]), int(t / 60), t % 60));
};

/* Is the schedule section s active right now?
 *  daily  - time window each day (may cross midnight, 21:00→07:00)
 *  weekly - time window on selected weekdays
 *  range  - whole-day window between two dates
 *  timer  - one-shot absolute window (date_start+time_start .. date_stop+time_stop)
 */
export function schedule_active(s, now) {
	const d = localtime(now);
	const wday = (d.wday + 6) % 7; /* localtime: Sun=0 -> Mon=0 index */
	const now_min = d.hour * 60 + d.min;
	const ymd = sprintf('%04d-%02d-%02d', d.year, d.mon, d.mday);

	const stype = s.type || 'daily';

	if (stype === 'range') {
		const d1 = s.date_start, d2 = s.date_stop;
		if (!d1 && !d2)
			return true;
		if (d1 && ymd < d1)
			return false;
		if (d2 && ymd > d2)
			return false;
		return true;
	}

	if (stype === 'timer') {
		const t1 = date_to_ts(s.date_start, s.time_start || '00:00');
		const t2 = date_to_ts(s.date_stop, s.time_stop || '23:59');
		if (t1 == null || t2 == null)
			return false;
		return now >= t1 && now <= t2;
	}

	/* daily / weekly */
	const days = s.days || [];
	if (length(days) && !any_day(days, wday))
		return false;

	const t1 = parse_hhmm(s.time_start);
	const t2 = parse_hhmm(s.time_stop);
	if (t1 == null || t2 == null)
		return true; /* no time window => whole day */

	if (t1 <= t2)
		return now_min >= t1 && now_min < t2;
	/* window crosses midnight */
	return now_min >= t1 || now_min < t2;
};

/* Enabled schedules only. */
export function get_schedules() {
	const res = [];
	const all = get_sections('schedule');
	for (let i = 0; i < length(all); i++) {
		const s = all[i];
		if (s.enabled !== '1')
			continue;
		push(res, s);
	}
	return res;
};

/* Temporary blocks AND temporary allows (plan 15):
 * { key: until_epoch }                      — legacy (block);
 * { key: { until, mode: 'block'|'allow' } } — current format.
 * Keys are MAC (primary) and IP. Normalized output: expired entries are
 * pruned, every entry is { until, mode }. */
export function read_temps() {
	const p = RUN_DIR + '/temps.json';
	if (!access(p))
		return {};
	const raw = readfile(p);
	let t = null;
	try {
		t = json(raw);
	} catch (e) {
		return {};
	}
	const now = time();
	const out = {};
	for (let k in t) {
		const v = t[k];
		let until = 0, mode = 'block';
		if (type(v) === 'object') {
			until = int(v.until) || 0;
			if (v.mode === 'allow')
				mode = 'allow';
		} else {
			until = int(v) || 0;
		}
		if (until > now)
			out[k] = { until: until, mode: mode };
	}
	return out;
};

/* Look up the temp entries of a client (by MAC and IP).
 * Returns { block: until|0, allow: until|0 } — maxima across both keys.
 * A temporary ALLOW beats a temporary BLOCK (an explicit parental
 * permission wins over an earlier temp block set by mistake). */
export function temps_for(temps, mac, ip) {
	let block = 0, allow = 0;
	const keys = [];
	if (mac) push(keys, mac);
	if (ip) push(keys, ip);
	for (let i = 0; i < length(keys); i++) {
		const e = temps[keys[i]];
		if (!e)
			continue;
		if (e.mode === 'allow') {
			if (e.until > allow)
				allow = e.until;
		} else {
			if (e.until > block)
				block = e.until;
		}
	}
	if (allow > 0)
		block = 0;   /* allow wins */
	return { block: block, allow: allow };
};

/* Raw temps INCLUDING expired entries (apply logs the expiries). */
export function read_temps_raw() {
	const p = RUN_DIR + '/temps.json';
	if (!access(p))
		return {};
	let t = {};
	try { t = json(readfile(p)); } catch (e) { t = {}; }
	return t;
};

export function write_temps(t) {
	mkdir_p(RUN_DIR);
	atomic_write(RUN_DIR + '/temps.json', sprintf('%J', t));
};

/* Temporary Wi-Fi off markers: { iface: until_epoch }. */
export function read_wifi_temps() {
	mkdir_p(RUN_DIR);
	const out = {};
	const fd = popen(`ls ${RUN_DIR}/wifi.temp.* 2>/dev/null`);
	if (!fd)
		return out;
	const raw = fd.read('all') || '';
	fd.close();
	const files = split(trim(raw), /\n/);
	const now = time();
	for (let i = 0; i < length(files); i++) {
		const f = trim(files[i]);
		const m = match(f, /wifi\.temp\.(.+)$/);
		if (!m)
			continue;
		const until = int(trim(readfile(f) || '')) || 0;
		if (until > now)
			out[m[1]] = until;
	}
	return out;
};

export function wifi_temp_set(iface, until) {
	mkdir_p(RUN_DIR);
	writefile(`${RUN_DIR}/wifi.temp.${iface}`, '' + until + '\n');
};

export function wifi_temp_clear(iface) {
	system(`rm -f '${RUN_DIR}/wifi.temp.${iface}'`);
};

/* Live Wi-Fi interface names (phyX-apY style) from `iw dev` — used by the
 * enforcer for the per-client Wi-Fi block (plan 15) and by nothing else. */
export function list_wifi_ifaces() {
	const out = [];
	const fd = popen(`iw dev 2>/dev/null | sed -n 's/[[:space:]]*Interface //p'`);
	if (!fd)
		return out;
	const raw = trim(fd.read('all') || '');
	fd.close();
	const lines = split(raw, /\n/);
	for (let i = 0; i < length(lines); i++) {
		const v = trim(lines[i]);
		if (length(v))
			push(out, v);
	}
	return out;
};

/* ── Live device tracking (DHCP leases + ARP) ──────────────────────────
 * The client's identity is its MAC (stable across DHCP address changes);
 * the CURRENT IP is resolved from the lease file / ARP cache at every
 * apply, so a renewed DHCP address moves the block automatically.
 * /tmp/dhcp.leases line: "<expires> <mac> <ip> <hostname> <cid>"          */

export function read_leases() {
	const out = {};
	const raw = readfile('/tmp/dhcp.leases') || '';
	const lines = split(trim(raw), '\n');
	for (let i = 0; i < length(lines); i++) {
		const f = split(trim(lines[i]), ' ');
		if (length(f) < 4)
			continue;
		const mac = lc(f[1]), ip = f[2], host = (length(f[3]) && f[3] !== '*') ? f[3] : '';
		if (!match(mac, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/))
			continue;
		out[mac] = { ip: ip, hostname: host, lease: int(f[0]) || 0 };
	}
	return out;
};

/* ARP cache: { ip: mac, mac: ip } — catches devices without an active
 * lease (static addressing) and marks "online" reliably. */
export function read_arp() {
	const out = { byip: {}, bymac: {} };
	const raw = readfile('/proc/net/arp') || '';
	const lines = split(trim(raw), '\n');
	for (let i = 1; i < length(lines); i++) {
		const f = split(trim(lines[i]), /\s+/);
		if (length(f) < 6)
			continue;
		const ip = f[0], mac = lc(f[3]);
		if (mac === '00:00:00:00:00:00' || !match(mac, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/))
			continue;
		out.byip[ip] = mac;
		if (!(mac in out.bymac))   /* first (freshest) entry wins */
			out.bymac[mac] = ip;
	}
	return out;
};

export function normalize_mac(mac) {
	let m = lc(trim('' + (mac || '')));
	return (match(m, /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/) != null) ? m : '';
};

export function valid_ip4(ip) {
	if (match(ip || '', /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) == null)
		return false;
	const f = split(ip, '.');
	for (let i = 0; i < 4; i++)
		if (int(f[i]) > 255)
			return false;
	return true;
};

/* Live device list (for the UI picker and the Telegram /devices): every
 * device seen in leases/ARP, annotated with its configured client. */
export function list_devices() {
	const leases = read_leases();
	const arp = read_arp();
	const clients = get_sections('client');
	const out = [];
	const seen = {};

	for (let i = 0; i < length(clients); i++) {
		const c = clients[i];
		const mac = normalize_mac(c.mac);
		const l = mac ? leases[mac] : null;
		const aip = mac ? arp.bymac[mac] : '';
		const ip = c.ip || (l ? l.ip : '') || aip || '';
		const online = (ip && (ip in arp.byip)) ? true : false;
		seen[mac] = true;
		push(out, {
			mac: mac, ip: ip,
			hostname: l ? l.hostname : '',
			online: online,
			client_id: c.id,
			alias: c.name || '',
			configured: true,
			blocked: c.blocked === '1',
			wifi_blocked: c.wifi_blocked === '1'
		});
	}

	/* devices seen on the network but not configured yet */
	const macs = [];
	for (let mac in leases) push(macs, mac);
	for (let mac in arp.bymac) if (!(mac in leases)) push(macs, mac);
	for (let i = 0; i < length(macs); i++) {
		const mac = macs[i];
		if (mac in seen) continue;
		seen[mac] = true;
		const l = leases[mac];
		const ip = (l && l.ip) || arp.bymac[mac] || '';
		push(out, {
			mac: mac, ip: ip,
			hostname: (l && l.hostname) || '',
			online: (ip && (ip in arp.byip)) ? true : false,
			client_id: '', alias: '', configured: false, blocked: false
		});
	}

	sort(out, (a, b) => {
		const an = a.alias || a.hostname || a.ip || a.mac;
		const bn = b.alias || b.hostname || b.ip || b.mac;
		return an > bn ? 1 : (an < bn ? -1 : 0);
	});
	return out;
};

/* ── Effective state computation (shared by apply/engine/rpcd) ──────── */

/* Per-client effective state:
 * { id, name, ip, mac, hostname, blocked, reason: manual|temp|schedule,
 *   until, allow_until, wifi_blocked } */
export function client_states(now) {
	const temps = read_temps();
	const paused = main_opt('paused', '0') === '1';
	const clients = get_sections('client');
	const leases = read_leases();
	const arp = read_arp();
	const schs = get_schedules();
	const out = [];

	for (let i = 0; i < length(clients); i++) {
		const c = clients[i];
		const mac = normalize_mac(c.mac);
		const l = mac ? leases[mac] : null;
		const ip = c.ip || (l ? l.ip : '') || (mac ? arp.bymac[mac] : '') || '';
		const hostname = (l && l.hostname) || '';
		const wifi_blocked = (c.wifi_blocked === '1');

		let blocked = false, reason = '', until = 0, allow_until = 0;

		if (!paused) {
			if (c.blocked === '1') {
				blocked = true;
				reason = 'manual';
			} else {
				const t = temps_for(temps, mac, ip);
				if (t.allow > 0) {
					/* explicit temporary permission: beats temp block AND schedule */
					allow_until = t.allow;
				} else if (t.block > 0) {
					blocked = true;
					reason = 'temp';
					until = t.block;
				} else {
					let allow_bound = false, allow_active = false;
					for (let j = 0; j < length(schs); j++) {
						const s = schs[j];
						const cids = s.client_ids || [];
						if (!length(cids))
							continue;
						let mine = false;
						for (let k = 0; k < length(cids); k++)
							if (cids[k] === c.id || (c.name && cids[k] === c.name))
								mine = true;
						if (!mine)
							continue;
						const act = schedule_active(s, now);
						const deny = (s.action || 'deny') === 'deny';
						if (deny) {
							if (act) {
								blocked = true;
								reason = 'schedule';
								break;
							}
						} else {
							allow_bound = true;
							if (act)
								allow_active = true;
						}
					}
					if (!blocked && allow_bound && !allow_active) {
						blocked = true;
						reason = 'schedule';
					}
				}
			}
		}

		push(out, {
			id: c.id,
			name: c.name || hostname || ip || mac || '?',
			ip: ip,
			mac: mac,
			hostname: hostname,
			blocked: blocked,
			reason: reason,
			until: until,
			allow_until: allow_until,
			wifi_blocked: wifi_blocked
		});
	}
	return out;
};

/* Rules to enforce right now (enabled, not paused-for, inside time window).
 * Empty when the global pause ("allow everything") is on. */
export function active_rules(now) {
	const out = [];
	if (main_opt('paused', '0') === '1')
		return out;
	const rules = get_sections('rule');
	for (let i = 0; i < length(rules); i++) {
		const r = rules[i];
		if (r.enabled !== '1')
			continue;
		/* temporary pause (e.g. "allow for 1h") */
		const du = int(r.disabled_until) || 0;
		if (du > now)
			continue;
		/* embedded daily/weekly window */
		if (r.time_start || r.time_stop || (r.days && length(r.days))) {
			const probe = { type: 'daily', time_start: r.time_start, time_stop: r.time_stop, days: r.days };
			if (!schedule_active(probe, now))
				continue;
		}
		/* embedded date range */
		if (r.date_start || r.date_stop) {
			const probe = { type: 'range', date_start: r.date_start, date_stop: r.date_stop };
			if (!schedule_active(probe, now))
				continue;
		}
		push(out, r);
	}
	return out;
};

function in_list(arr, v) {
	for (let i = 0; i < length(arr); i++)
		if (arr[i] === v)
			return true;
	return false;
};

/* Per-client rule targets active right now — only rules that list clients
 * (client_ids). Rules with an EMPTY client_ids list are GLOBAL and handled
 * separately (main dnsmasq blocked.conf / blocked_rule_v4 set).
 * Returns { client_section_id: { domains: [...], ips: [...] } } */
export function client_rule_targets(now) {
	const out = {};
	const rules = active_rules(now);
	const clients = get_sections('client');

	for (let i = 0; i < length(rules); i++) {
		const r = rules[i];
		const cids = r.client_ids || [];
		if (!length(cids))
			continue;
		const rtype = r.type || 'domain';
		const targets = r.target || [];
		for (let k = 0; k < length(cids); k++) {
			/* resolve the rule's client ref (section id or name) to a real client */
			let cid = '';
			for (let c = 0; c < length(clients); c++)
				if (clients[c].id === cids[k] || (clients[c].name && clients[c].name === cids[k]))
					cid = clients[c].id;
			if (!cid)
				continue;
			if (!out[cid])
				out[cid] = { domains: [], ips: [] };
			for (let t = 0; t < length(targets); t++) {
				const v = targets[t];
				if (!length(v))
					continue;
				if (rtype === 'ip') {
					if (!in_list(out[cid].ips, v))
						push(out[cid].ips, v);
				} else if (length(v) > 2) {
					if (!in_list(out[cid].domains, v))
						push(out[cid].domains, v);
				}
			}
		}
	}
	return out;
};

/* Wi-Fi ifaces that must be OFF right now:
 *  - deny-schedule active, OR allow-schedule outside its window;
 *  - temp off markers (auto-expiring). */
export function wifi_off_map(now) {
	const off = {};
	const schs = get_schedules();
	const wifis = get_sections('wifi');

	function resolve(wid) {
		for (let n = 0; n < length(wifis); n++)
			if (wifis[n].id === wid || wifis[n].name === wid)
				return wifis[n].network || wid;
		return wid;
	}

	for (let j = 0; j < length(schs); j++) {
		const s = schs[j];
		const wids = s.wifi_ids || [];
		if (!length(wids))
			continue;
		const act = schedule_active(s, now);
		const deny = (s.action || 'deny') === 'deny';
		/* deny+active => off; allow+outside-window => off ("Wi-Fi only during...") */
		if (act === deny) {
			for (let k = 0; k < length(wids); k++) {
				const iface = resolve(wids[k]);
				if (iface)
					off[iface] = true;
			}
		}
	}

	const wtemps = read_wifi_temps();
	for (let k in wtemps)
		off[k] = true;

	return off;
};
