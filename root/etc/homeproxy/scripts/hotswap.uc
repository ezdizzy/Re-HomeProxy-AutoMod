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
 *     interval: seconds, failback: bool, antiflap: bool, pool_mode: "auto"|
 *     "prefer"|"manual", tolerance: ms, labels: {tag: human name} }
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
 * ANTI-FLAP (ч.67, UCI hotswap_antiflap, default ON, URLTest mode only):
 * WHY — the kernel's URLTest re-picks on a SINGLE bad probe: any one timed-out
 * probe of the current pick deletes its delay history and the group moves
 * instantly (tolerance is never consulted on that path), and one spiky probe
 * round (pick worse than another member by > tolerance) moves it too. The
 * daemon's own group probes multiply the sampling rate, so with close-latency
 * nodes the visible pick flaps although pings are stable. HOW — the daemon
 * OWNS the selection through the selector it already controls: on the first
 * tick it pins the group's current pick (or the selector's existing node)
 * with PUT /proxies/main-out, so kernel re-ranks stop moving the exit. The
 * pin moves only on real evidence, never on one probe:
 *   - the pinned node fails DEAD_AFTER consecutive probes (real death — the
 *     proven-alive reserve with the lowest fresh delay wins);
 *   - OR another pool member stays faster by MORE than the URLTest tolerance
 *     for ANTIFLAP_ROUNDS consecutive daemon rounds AND passes a direct probe
 *     (sustained superiority, "auto/manual" pools only — "prefer" holds its
 *     preferred node exactly as the kernel would);
 *   - failback returns to the previous pinned node after it recovers
 *     (FAILBACK_OKS / FAILBACK_WINDOW), mirroring the node-mode behavior.
 * External selector moves are adopted (user agency), a move back to the group
 * is re-pinned. Absorbed kernel re-ranks are counted in the state file
 * (`suppressed`) for the UI. With antiflap off the daemon keeps the exact
 * ч.60 behavior (probe the group, rescue on death, failback to the group).
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
/* 6000 ms (ч.67, was 4000): the probe IS a real dial through the tunnel and a
 * false timeout here is expensive — besides counting toward DEAD_AFTER it
 * (while unpinned) deletes the node's history in the kernel and triggers an
 * instant URLTest re-pick. 6 s still keeps the outage window at ~15 s. */
const PROBE_TIMEOUT = 6000;      /* ms cap of the core-side delay test      */
const SWITCH_COOLDOWN = 15;      /* s between selector switches             */
const FAILBACK_OKS = 3;          /* consecutive primary successes           */
const FAILBACK_WINDOW = 30;      /* s over which they must be collected     */
const STATE_HEARTBEAT = 60;      /* s between unchanged state refreshes     */
const ANTIFLAP_ROUNDS = 3;       /* consecutive rounds a challenger must win */
const HIST_FRESH = 120;          /* s: max age of a history entry used here  */
const MAX_LOG_BYTES = 65536;

/* Runtime state (module level — shared across the loop, survives iterations). */
let hs = null;                   /* active contract                          */
let hs_sig = '';                 /* contract signature (change resets health)*/
let health = {};                 /* tag → {fails, oks, first_ok, last_delay} */
let switches = 0;
let last_switch_ts = 0;
let last_reason = '';
let last_state_write = 0;
/* ч.67 anti-flap state (meaningful only while hs.antiflap is on). */
let pinned = null;               /* node the selector is pinned to           */
let last_pinned = null;          /* previous pin — the failback target       */
let last_group_pick = null;      /* previous kernel group pick (absorb count)*/
let suppressed = 0;              /* kernel re-ranks absorbed by the pin      */
let chase = {};                  /* tag → consecutive faster-than-pin rounds */

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

/* Parse a Go/Clash timestamp ("2026-09-14T09:00:00.123+03:00") into a Unix
 * epoch (UTC-based, numeric offset applied). Times without an offset are taken
 * as UTC. Returns null when unparsable. Days-from-civil (Howard Hinnant).
 * Same routine the urltest watchdog carries (daemons stay self-contained). */
function iso_epoch(s) {
	if (type(s) !== 'string')
		return null;
	const m = match(s, /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})/);
	if (!m)
		return null;
	let y = int(m[1]);
	const mo = int(m[2]),
	      d = int(m[3]),
	      H = int(m[4]),
	      Mi = int(m[5]),
	      S = int(m[6]);
	let off = 0;
	const om = match(s, /([+-])(\d{2}):(\d{2})$/);
	if (om)
		off = (om[1] === '-') ? -(int(om[2]) * 3600 + int(om[3]) * 60)
		                      : (int(om[2]) * 3600 + int(om[3]) * 60);
	if (mo <= 2)
		y = y - 1;
	const era = int((y >= 0 ? y : y - 399) / 400);
	const yoe = y - era * 400;
	const mp = (mo + ((mo > 2) ? -3 : 9));
	const doy = int((153 * mp + 2) / 5) + d - 1;
	const doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy;
	const days = era * 146097 + doe - 719468;
	return days * 86400 + H * 3600 + Mi * 60 + S - off;
}

/* Fresh positive delay of `tag` from the core's history (the /proxies dump).
 * This is the SAME source the kernel's URLTest picks from, so chase/absorb
 * decisions see what the kernel sees; stale (older than HIST_FRESH) or failed
 * entries read as null. */
function hist_delay(proxies, tag) {
	const p = proxies[tag];
	if (type(p) !== 'object')
		return null;
	const h = p.history;
	if (type(h) !== 'array' || !length(h))
		return null;
	const last = h[length(h) - 1];
	const dly = int(last.delay) || 0;
	if (dly <= 0 || dly >= 65535)
		return null;
	const ts = iso_epoch(last.time);
	if (ts == null)
		return null;
	return ((time() - ts) <= HIST_FRESH) ? dly : null;
}

/* A concrete node tag that may hold the pin: never our own groups, the
 * selector itself or the built-in service outbounds. */
function pinnable(tag) {
	if (!tag || type(tag) !== 'string' || !length(tag))
		return false;
	if (tag === 'main-out' || tag === 'main-out-auto' || tag === 'main-out-auto-alt')
		return false;
	return (index([ 'direct-out', 'block-out' ], tag) < 0);
}

/* Human-readable name for the UI-facing last_reason (ч.67): the generator
 * ships a tag→label map in the contract (the daemon stays UCI-blind by
 * design); unknown tags fall back to their raw form. */
function tag_label(tag) {
	if (hs && type(hs.labels) === 'object' && type(hs.labels[tag]) === 'string' && length(hs.labels[tag]))
		return hs.labels[tag];
	return tag;
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
	const af = (hs != null && hs.antiflap === true);
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
		/* ч.67 anti-flap: regime flag + the node the exit is pinned to + how
		 * many kernel re-ranks the pin absorbed (UI: «анти-флап» line). */
		antiflap: af,
		pinned: (af && pinned != null) ? pinned : null,
		suppressed: suppressed,
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
	/* ч.67: anti-flap is a URLTest-mode regime. The field is absent in
	 * contracts written by older generators — default ON there, so every
	 * URLTest+Hot Swap install gets the fix without waiting for a regen. */
	c.antiflap = (c.mode === 'urltest') ? (c.antiflap !== false) : false;
	c.tolerance = int(c.tolerance) || 150;
	if (c.pool_mode !== 'auto' && c.pool_mode !== 'prefer' && c.pool_mode !== 'manual')
		c.pool_mode = 'manual';
	/* Tag→label map for human-facing reasons (ч.67); NOT part of the sig —
	 * renaming a node must not reset the pin. */
	c.labels = (type(c.labels) === 'object') ? c.labels : {};
	const sig = sprintf('%s|%s|%s|%s|%d|%d|%d|%s|%d', c.mode, c.group, c.primary, join(',', c.hot), c.count || 0, c.failback ? 1 : 0, c.antiflap ? 1 : 0, c.pool_mode, c.tolerance);
	if (sig !== hs_sig) {
		hs_sig = sig;
		health = {};
		pinned = null;
		last_pinned = null;
		chase = {};
		log('contract adopted: mode=' + c.mode + ' group=' + c.group + ' primary=' + c.primary + ' hot=' + length(c.hot) + ' failback=' + (c.failback ? 'on' : 'off') + ' antiflap=' + (c.antiflap ? 'on' : 'off') + ' pool=' + c.pool_mode + ' tolerance=' + c.tolerance);
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

	/* ── 0. ANTI-FLAP (ч.67, URLTest mode): own the selection ────────────────
	 * The kernel re-picks on a SINGLE bad probe of its pick (history deleted,
	 * tolerance never consulted) — the visible active node flaps although the
	 * pings are stable. While antiflap is on, the selector is pinned to one
	 * node and kernel re-ranks stop moving the exit; the pin itself moves
	 * only on sustained evidence (steps 3b/3c below). */
	if (hs.antiflap) {
		if (pinned == null) {
			/* Seed: respect a concrete selector pick (sticky default from the
			 * generator or a manual pick); otherwise pin the group's current
			 * pick so the exit stops following the kernel's noisy re-ranks. */
			let seed = pinnable(active) ? active : null;
			if (seed == null && hs.mode === 'urltest') {
				const gsel = proxies[hs.primary];
				const gpick = (gsel && type(gsel) === 'object') ? gsel.now : null;
				if (pinnable(gpick))
					seed = gpick;
			}
			if (seed != null) {
				if (active === seed) {
					/* Adopted an external/sticky pick: the group's own pick is
					 * unknown right now — let the next tick record it before
					 * counting any absorbs. */
					pinned = seed;
					last_group_pick = null;
					log('ANTIFLAP: pinned ' + seed + ' (adopted selector pick; kernel re-ranks no longer move the exit)');
				} else if (switch_to(hs.group, seed)) {
					pinned = seed;
					last_group_pick = seed;
					log('ANTIFLAP: pinned ' + seed + ' (seed = current group pick; kernel re-ranks no longer move the exit)');
				} else {
					log('ANTIFLAP: seed pin to ' + seed + ' failed (curl missing / core refused) - will retry');
				}
			}
		} else if (active === hs.primary) {
			/* The selector was moved back to the group (external API call):
			 * restore the pin — that is the whole point of the regime. */
			if (switch_to(hs.group, pinned))
				log('ANTIFLAP: selector was moved back to the group - re-pinned ' + pinned);
		} else if (active !== pinned && pinnable(active)) {
			/* External move to another concrete node: adopt it as the new pin
			 * instead of fighting the user. */
			pinned = active;
			chase = {};
			last_group_pick = null;
			log('ANTIFLAP: selector moved externally to ' + active + ' - adopted as pinned');
		}
		/* Count absorbed kernel re-ranks for the UI (probe-only observation:
		 * while pinned, a group re-rank no longer moves the exit). */
		if (pinned != null && hs.mode === 'urltest') {
			const gsel = proxies[hs.primary];
			const gpick = (gsel && type(gsel) === 'object') ? gsel.now : null;
			if (type(gpick) === 'string' && length(gpick)) {
				if (last_group_pick != null && gpick !== last_group_pick && gpick !== pinned) {
					suppressed = suppressed + 1;
					log('ANTIFLAP: kernel re-ranked ' + last_group_pick + ' -> ' + gpick + ' (absorbed #' + suppressed + ', exit stays on ' + pinned + ')');
				}
				last_group_pick = gpick;
			}
		}
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
	 * Failback target is scanned first (freshness); dead candidates cost one
	 * probe each, the scan stops at the alive quota.
	 * ⚠ ucode `for-in` over an ARRAY yields the ELEMENTS (verified live, ч.59):
	 * iterate tags directly, never `members[mi]`. */
	const quota = (hs.count >= 1) ? hs.count - 1 : 1;
	/* Failback target: the previous pinned node under antiflap, otherwise the
	 * contract primary (specific node / URLTest group) — ч.59/ч.60 behavior. */
	let fb_target = null;
	if (hs.failback) {
		if (hs.antiflap) {
			if (pinned == null)
				fb_target = hs.primary;
			else if (last_pinned != null && last_pinned !== pinned)
				fb_target = last_pinned;
		} else
			fb_target = hs.primary;
	}
	let alive_others = [];
	for (let tag in members) {
		if (tag === active || type(tag) !== 'string')
			continue;
		const need_more = (length(alive_others) < quota);
		const want_primary = (fb_target != null && tag === fb_target);
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
			if (hs.antiflap) {
				/* The fastest PROVEN-alive reserve wins (URLTest spirit); the
				 * scan order is only a tie-breaker. */
				let best_d = -1;
				for (let t in alive_others) {
					const d = health_of(t).last_delay || 0;
					if (target == null || (d > 0 && (best_d <= 0 || d < best_d))) {
						target = t;
						best_d = d;
					}
				}
			} else {
				/* Prefer a non-primary backup; fall back to the primary itself
				 * when it is the only alive member. */
				for (let t in alive_others)
					if (t !== hs.primary) { target = t; break; }
			}
			if (target == null)
				target = alive_others[0];
			if (target && target !== active) {
				if (switch_to(hs.group, target)) {
					switches = switches + 1;
					last_switch_ts = now_ts;
					last_reason = 'primary down: ' + tag_label(active) + ' -> ' + tag_label(target);
					log('HOT SWAP: ' + last_reason + ' (switch #' + switches + ')');
					health_of(target).fails = 0;
					if (hs.antiflap) {
						last_pinned = pinned;
						pinned = target;
						chase = {};
					}
				} else {
					log('switch to ' + target + ' FAILED (core refused) - will retry');
				}
			}
		}
	} else {
		/* ── 3b. Sustained-better migration (antiflap, auto/manual pools) ────
		 * A challenger must read faster than the pinned node by MORE than the
		 * URLTest tolerance for ANTIFLAP_ROUNDS consecutive daemon rounds AND
		 * pass a direct probe — a single lucky probe never moves the exit.
		 * "prefer" is exempt: its top group holds the preferred node by
		 * design (PREFER_HOLD_TOLERANCE in the generator). Independent of the
		 * failback step below: SWITCH_COOLDOWN arbitrates if both fire. */
		if (hs.antiflap && pinned != null && pinned === active &&
		    hs.pool_mode !== 'prefer' && active_alive != null && active_alive.fails === 0) {
			const tol = hs.tolerance || 150;
			const pd = hist_delay(proxies, pinned);
			if (pd != null) {
				let best = null, best_d = 0;
				for (let tag in members) {
					if (!pinnable(tag) || tag === pinned)
						continue;
					const d = hist_delay(proxies, tag);
					if (d == null || !(d + tol < pd)) {
						delete chase[tag];
						continue;
					}
					chase[tag] = (chase[tag] || 0) + 1;
					if (chase[tag] >= ANTIFLAP_ROUNDS && (best == null || d < best_d)) {
						best = tag;
						best_d = d;
					}
				}
				if (best != null && (now_ts - last_switch_ts) >= SWITCH_COOLDOWN && probe_node(best)) {
					if (switch_to(hs.group, best)) {
						last_pinned = pinned;
						pinned = best;
						chase = {};
						switches = switches + 1;
						last_switch_ts = now_ts;
						last_reason = 'antiflap: sustained better node: ' + tag_label(last_pinned) + ' -> ' + tag_label(best);
						log('ANTIFLAP: ' + last_reason + ' (switch #' + switches + ')');
					}
				}
			}
		}
		/* ── 3c. Failback: return to the previous pinned node (antiflap) or to
		 * the contract primary (ч.59/ч.60) once it is stable again. */
		if (fb_target != null && active !== fb_target && index(members, fb_target) >= 0) {
			const ph = health_of(fb_target);
			if (ph.oks >= FAILBACK_OKS && ph.first_ok && (now_ts - ph.first_ok) >= FAILBACK_WINDOW) {
				if ((now_ts - last_switch_ts) < SWITCH_COOLDOWN) {
					log('failback target recovered, failback suppressed (cooldown)');
				} else if (switch_to(hs.group, fb_target)) {
					switches = switches + 1;
					last_switch_ts = now_ts;
					last_reason = (fb_target === hs.primary) ? ('primary recovered: ' + tag_label(fb_target))
					                                          : ('failback to the previous node: ' + tag_label(fb_target));
					log('HOT SWAP: ' + last_reason + ' (switch #' + switches + ')');
					health_of(fb_target).oks = 0;
					health_of(fb_target).first_ok = 0;
					if (hs.antiflap) {
						pinned = fb_target;
						last_pinned = null;
						chase = {};
					}
				} else {
					log('failback to ' + fb_target + ' FAILED (core refused) - will retry');
				}
			}
		}
	}

	/* ── 4. State file for RPC/UI (on change + heartbeat) ──────────────────── */
	if ((time() - last_state_write) >= STATE_HEARTBEAT || last_switch_ts === now_ts)
		write_state(active, hs.primary);

	sleep(interval * 1000);
}
