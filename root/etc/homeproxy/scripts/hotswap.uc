/* Hot Swap daemon — Re:HomeProxy AutoMod (ч.59)
 *
 * WHY: a FIXED main node has no failover at all — when the server dies, sing-box
 * keeps dialing the dead node and every proxied connection is gone until it
 * recovers. URLTest pools have kernel failover, but the Clash API can pin
 * SELECTOR groups only ("Must be a Selector" on PUT /proxies for URLTest), so
 * the watchdog cannot rescue a URLTest group without a full service restart
 * (which tears down DIRECT traffic too). Hot Swap solves both:
 *
 *   generate_client.uc emits `main-out` as a SELECTOR
 *   [primary, backup…(count-1), …cold spares] and writes $RUN_DIR/hotswap.json;
 *   THIS daemon actively probes the active node and the backups through the
 *   core's Clash API delay endpoint (each probe is a real dial through that
 *   node's tunnel — TLS/NAT state stays warm), and re-pins the selector with
 *   PUT /proxies/main-out when the active node dies.
 *
 *   The switch is a pure API operation: the core process never restarts, so
 *   direct traffic, LAN DNS and unrelated connections are untouched. Existing
 *   connections riding the dead node are torn down by its own tunnel error and
 *   clients reconnect instantly onto the new pick (the selector is emitted with
 *   interrupt_exist_connections: false so failback/rotation never kills the
 *   sessions that still work).
 *
 * Contract ($RUN_DIR/hotswap.json, written by generate_client.uc):
 *   { enabled: true, mode: "node"|"urltest", group: "main-out",
 *     primary: "cfg-<sid>-out"|"main-out-auto", hot: [tag…], count: N,
 *     interval: seconds, failback: bool }
 * The daemon is mode-agnostic: with mode "urltest" the primary IS the kernel
 * URLTest group (main-out-auto) — probing it tests the group's current pick,
 * and a selector switch to a direct node bypasses a group stuck on a dead
 * member until the group answers again (failback returns to the group).
 * Missing file / group with <2 members → idle loop (no respawn storm); the
 * contract is re-read every tick, so a regeneration is picked up live.
 *
 * Failback (UCI hotswap_failback, default on): when the primary passes 3
 * consecutive probes across >= 30 s, traffic returns to it. Manual dashboard
 * picks are treated the same way — disable failback for full manual control.
 *
 * ucode constraints honored: sleep() is MILLISECONDS, no Array.includes(),
 * no optional chaining in this daemon, POSIX-ERE regex, atomic file writes
 * (tmp + mv -f), function definitions ordered before first use. */

'use strict';

import { access, readfile, writefile, open, stat, popen } from 'fs';

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

const RUN_DIR = '/var/run/homeproxy';
const HS_FILE = RUN_DIR + '/hotswap.json';
const STATE_FILE = RUN_DIR + '/hotswap_state.json';
const LOG_FILE = RUN_DIR + '/hotswap.log';
const API = 'http://127.0.0.1:9090';
const HAVE_CURL = access('/usr/bin/curl');

const IDLE_INTERVAL = 30;        /* s between contract re-checks when off */
const DEAD_AFTER = 2;            /* failed probes to call the active dead  */
const RECHECK_MS = 2000;         /* fast double-check after first failure   */
const PROBE_TIMEOUT = 4000;      /* ms cap of the core-side delay test      */
const SWITCH_COOLDOWN = 15;      /* s between selector switches             */
const FAILBACK_OKS = 3;          /* consecutive primary successes           */
const FAILBACK_WINDOW = 30;      /* s over which they must be collected     */
const STATE_HEARTBEAT = 60;      /* s between unchanged state refreshes     */
const MAX_LOG_BYTES = 65536;

/* Runtime state (module level — shared across the loop, survives iterations). */
let hs = null;                   /* active contract                          */
let hs_sig = '';                 /* contract signature (change resets health)*/
let health = {};                 /* tag → {fails, oks, first_ok, last_delay} */
let switches = 0;
let last_switch_ts = 0;
let last_reason = '';
let last_state_write = 0;

function log(msg) {
	try {
		let sz = 0;
		try { sz = stat(LOG_FILE).size || 0; } catch (e) { sz = 0; }
		if (sz > MAX_LOG_BYTES)
			system('tail -n 100 ' + shellquote(LOG_FILE) + ' > ' + shellquote(LOG_FILE + '.tmp') + ' 2>/dev/null; mv -f ' + shellquote(LOG_FILE + '.tmp') + ' ' + shellquote(LOG_FILE));
		const fd = open(LOG_FILE, 'a');
		if (!fd) return;
		fd.write(sprintf('[%d] %s\n', time(), msg));
		fd.close();
	} catch (e) { /* logging must never kill the daemon */ }
}

function atomic_write(path, content) {
	const tmp = path + '.tmp';
	writefile(tmp, content);
	system('mv -f ' + shellquote(tmp) + ' ' + shellquote(path));
}

/* GET /proxies → the proxies map, null on any failure (core down etc.). */
function fetch_proxies() {
	let fd = popen('wget -qO- --timeout=8 ' + API + '/proxies 2>/dev/null');
	if (!fd)
		return null;
	const body = fd.read('all');
	fd.close();
	if (!length(body))
		return null;
	let data = null;
	try { data = json(body); } catch (e) { return null; }
	if (type(data) !== 'object' || type(data.proxies) !== 'object')
		return null;
	return data.proxies;
}

/* Active delay test through a node: GET /proxies/<tag>/delay. A 200 with a
 * positive delay = the node dialed the test URL through its tunnel RIGHT NOW.
 * This is also what keeps the standby tunnels warm (real handshake + NAT). */
function probe_node(tag) {
	if (!tag || type(tag) !== 'string')
		return null;
	const url = API + '/proxies/' + tag + '/delay?timeout=' + PROBE_TIMEOUT;
	let body = '';
	if (HAVE_CURL) {
		let fd = popen('curl -s --max-time ' + (int(PROBE_TIMEOUT / 1000) + 4) + ' ' + shellquote(url) + ' 2>/dev/null');
		if (!fd)
			return null;
		body = fd.read('all');
		fd.close();
	} else {
		let fd = popen('wget -qO- --timeout=' + (int(PROBE_TIMEOUT / 1000) + 4) + ' ' + shellquote(url) + ' 2>/dev/null');
		if (!fd)
			return null;
		body = fd.read('all');
		fd.close();
	}
	if (!length(body))
		return null;
	try {
		const r = json(body);
		const d = int(r.delay) || 0;
		return (d > 0) ? d : null;
	} catch (e) {
		return null;
	}
}

function health_of(tag) {
	if (type(health[tag]) !== 'object')
		health[tag] = { fails: 0, oks: 0, first_ok: 0, last_delay: 0 };
	return health[tag];
}

function mark_probe(tag, delay) {
	const h = health_of(tag);
	if (delay) {
		h.fails = 0;
		h.oks = h.oks + 1;
		if (!h.first_ok)
			h.first_ok = time();
		h.last_delay = delay;
	} else {
		h.fails = h.fails + 1;
		h.oks = 0;
		h.first_ok = 0;
		h.last_delay = 0;
	}
	return h;
}

/* PUT /proxies/<group> — Selector-only (sing-box rejects URLTest with 400;
 * Hot Swap's main-out IS a selector by construction). busybox/uclient wget has
 * no PUT, so switching requires curl (present on every install that ships the
 * diagnostics tab; without it the daemon stays probe-only and says so). Returns
 * true when the group actually reports the new pick afterwards. */
function switch_to(group, tag) {
	if (!HAVE_CURL)
		return false;
	const body = '{"name":"' + tag + '"}';
	system('curl -s -o /dev/null -X PUT -d ' + shellquote(body) + ' ' + shellquote(API + '/proxies/' + group) + ' 2>/dev/null');
	const proxies = fetch_proxies();
	return !!(proxies && type(proxies[group]) === 'object' && proxies[group].now === tag);
}

function write_state(active, primary) {
	const now = time();
	let members = {};
	for (let k, v in health)
		members[k] = { state: (v.fails ? 'down' : (v.oks ? 'alive' : 'unknown')), fails: v.fails, oks: v.oks, last_delay: v.last_delay };
	atomic_write(STATE_FILE, sprintf('%.J\n', {
		enabled: (hs != null),
		mode: hs ? (hs.mode || 'node') : null,
		group: hs ? hs.group : 'main-out',
		active: active,
		primary: primary,
		hot: hs ? hs.hot : [],
		count: hs ? hs.count : 0,
		interval: hs ? hs.interval : 0,
		failback: hs ? hs.failback : false,
		switches: switches,
		last_switch: last_switch_ts,
		last_reason: last_reason,
		members: members,
		updated: now
	}));
	last_state_write = now;
}

/* Read + validate the contract; reset health when it changed. */
function read_contract() {
	if (!access(HS_FILE))
		return null;
	let c = null;
	try {
		c = json(readfile(HS_FILE) || '');
	} catch (e) {
		return null;
	}
	if (type(c) !== 'object' || c.enabled !== true || type(c.group) !== 'string' ||
	    type(c.primary) !== 'string')
		return null;
	if (type(c.hot) !== 'array' || length(c.hot) < 2)
		return null;
	if (c.mode !== 'urltest' && c.mode !== 'node')
		c.mode = 'node';
	const sig = sprintf('%s|%s|%s|%s|%d|%d', c.mode, c.group, c.primary, join(',', c.hot), c.count || 0, c.failback ? 1 : 0);
	if (sig !== hs_sig) {
		hs_sig = sig;
		health = {};
		log('contract adopted: mode=' + c.mode + ' group=' + c.group + ' primary=' + c.primary + ' hot=' + length(c.hot) + ' failback=' + (c.failback ? 'on' : 'off'));
	}
	return c;
}

system('mkdir -p ' + RUN_DIR + ' 2>/dev/null; true');

log('hotswap daemon started (probe timeout ' + PROBE_TIMEOUT + 'ms, dead after ' + DEAD_AFTER + ', cooldown ' + SWITCH_COOLDOWN + 's)');

/* The main loop intentionally never exits: procd respawns would burn the
 * respawn budget, and a temporarily missing contract (config regenerating)
 * must simply be picked up on a later tick. */
while (true) {
	hs = read_contract();

	if (hs == null) {
		/* Feature off or between generations: keep the state file honest. */
		if (access(STATE_FILE) && (time() - last_state_write) > STATE_HEARTBEAT) {
			const proxies = fetch_proxies();
			const active = (proxies && type(proxies['main-out']) === 'object') ? proxies['main-out'].now : null;
			write_state(active, null);
		}
		sleep(IDLE_INTERVAL * 1000);
		continue;
	}

	const interval = (hs.interval >= 5) ? hs.interval : 5;
	const proxies = fetch_proxies();
	if (proxies == null) {
		/* Core down/restarting: never counts as a node failure. */
		sleep(interval * 1000);
		continue;
	}
	const grp = proxies[hs.group];
	if (type(grp) !== 'object' || type(grp.all) !== 'array') {
		sleep(interval * 1000);
		continue;
	}
	const members = grp.all;
	const active = grp.now;
	if (length(members) < 2 || !active || type(active) !== 'string') {
		sleep(interval * 1000);
		continue;
	}

	/* ── 1. Probe the ACTIVE node (fresh data, not the core's own history) ── */
	let active_alive = null;
	if (index(members, active) >= 0) {
		active_alive = mark_probe(active, probe_node(active));
		if (active_alive.fails === 1) {
			/* Fast path: one miss might be a hiccup — double-check within
			 * seconds instead of waiting a full interval. This is what keeps
			 * the outage window at ~5 s, not interval+timeout. */
			sleep(RECHECK_MS);
			active_alive = mark_probe(active, probe_node(active));
		}
	}

	/* ── 2. Probe backups until (count-1) proven-alive ones are known ────────
	 * Primary is scanned first (failback freshness); dead candidates cost one
	 * probe each, the scan stops at the alive quota.
	 * ⚠ ucode `for-in` over an ARRAY yields the ELEMENTS (verified live, ч.59):
	 * iterate tags directly, never `members[mi]`. */
	const quota = (hs.count >= 1) ? hs.count - 1 : 1;
	let alive_others = [];
	for (let tag in members) {
		if (tag === active || type(tag) !== 'string')
			continue;
		const need_more = (length(alive_others) < quota);
		const want_primary = (hs.failback && tag === hs.primary);
		if (!need_more && !want_primary)
			continue;
		const h = mark_probe(tag, probe_node(tag));
		if (h.fails === 0)
			push(alive_others, tag);
	}

	/* ── 3. Switch decision ────────────────────────────────────────────────── */
	const now_ts = time();
	if (active_alive != null && active_alive.fails >= DEAD_AFTER && length(alive_others) &&
	    index(members, active) >= 0) {
		/* Active node is dead and a live alternative exists. */
		if ((now_ts - last_switch_ts) < SWITCH_COOLDOWN) {
			log('active ' + active + ' down, switch suppressed (cooldown)');
		} else {
			let target = null;
			/* Prefer a non-primary backup; fall back to the primary itself
			 * when it is the only alive member. */
			for (let t in alive_others)
				if (t !== hs.primary) { target = t; break; }
			if (target == null)
				target = alive_others[0];
			if (target && target !== active) {
				if (switch_to(hs.group, target)) {
					switches = switches + 1;
					last_switch_ts = now_ts;
					last_reason = 'primary down: ' + active + ' -> ' + target;
					log('HOT SWAP: ' + last_reason + ' (switch #' + switches + ')');
					health_of(target).fails = 0;
				} else {
					log('switch to ' + target + ' FAILED (core refused) - will retry');
				}
			}
		}
	} else if (hs.failback && active !== hs.primary && index(members, hs.primary) >= 0) {
		const ph = health_of(hs.primary);
		if (ph.oks >= FAILBACK_OKS && ph.first_ok && (now_ts - ph.first_ok) >= FAILBACK_WINDOW) {
			if ((now_ts - last_switch_ts) < SWITCH_COOLDOWN) {
				log('primary recovered, failback suppressed (cooldown)');
			} else if (switch_to(hs.group, hs.primary)) {
				switches = switches + 1;
				last_switch_ts = now_ts;
				last_reason = 'primary recovered: ' + hs.primary;
				log('HOT SWAP: ' + last_reason + ' (switch #' + switches + ')');
				health_of(hs.primary).oks = 0;
				health_of(hs.primary).first_ok = 0;
			} else {
				log('failback to ' + hs.primary + ' FAILED (core refused) - will retry');
			}
		}
	}

	/* ── 4. State file for RPC/UI (on change + heartbeat) ──────────────────── */
	if ((time() - last_state_write) >= STATE_HEARTBEAT || last_switch_ts === now_ts)
		write_state(active, hs.primary);

	sleep(interval * 1000);
}
