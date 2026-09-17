/* URLTest failover watchdog — Re:HomeProxy AutoMod
 *
 * WHY: in every URLTest pool mode (auto / prefer / manual) the group can end up
 * pinned to a node whose probes TIMEOUT. New sing-box cores delete a member's
 * delay history when its probe fails and then re-pick, but older/other builds
 * keep the STALE history entry, and the tolerance math never replaces a member
 * that still "has" a delay — so the group rides a dead node for hours while a
 * perfectly working node sits in the same pool ("no switching, internet gone").
 *
 * WHAT: every CHECK_INTERVAL seconds read the Clash API /proxies dump once and,
 * for each URLTest group, check the SELECTED member ("now"):
 *   - alive  = its last history entry has delay > 0 AND is fresh (<= HISTORY_TTL
 *     seconds). Freshness matters: stale-history cores stop refreshing the time
 *     of dead nodes, so an old timestamp means the node is not really answering.
 *   - dead   = no history, delay 0, or a stale timestamp.
 * A dead selection is only acted on when ANOTHER pool member is verifiably
 * alive (if nothing is alive the problem is upstream/WAN, not the group).
 * After DEAD_AFTER consecutive dead sightings:
 *   1. the dead node's outbound tag is written to $RUN_DIR/urltest_dead
 *      (atomic) — generate_client.uc then refuses to FRONT it via the sticky
 *      snapshot and sinks it to the END of every pool;
 *   2. the service is restarted (rate-limited by RESTART_COOLDOWN). A fresh
 *      core starts with empty history, so its first probe round selects a
 *      living node instead of the dead one.
 * Recovery: if a dead-marked node later measures alive again, its mark is
 * dropped, so it may be fronted/selected as usual.
 *
 * The watchdog only starts when config.main_node = urltest (init.d gate) and
 * exits silently when the core's Clash API is not reachable (core respawn etc.)
 * — it never counts those as failures.
 *
 * ucode constraints honored: sleep() takes MILLISECONDS, no Array.includes(),
 * no optional chaining, atomic file writes (tmp + mv -f). */

'use strict';

import { access, readfile, writefile, open, stat } from 'fs';

/* Local shell quote. This build of ucode has NO shellquote builtin and this
 * file imports nothing that provides one — the original release called the
 * bare identifier, which fatals at runtime ("access to undeclared variable")
 * on the FIRST flush_dead()/restart (exactly when the watchdog tries to act
 * on a dead node). Same one-liner the other daemons carry. */
function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

const RUN_DIR = '/var/run/homeproxy';
const DEAD_FILE = RUN_DIR + '/urltest_dead';
const LOG_FILE = RUN_DIR + '/urltest_watchdog.log';
const API = 'http://127.0.0.1:9090';

/* Groups we babysit (present = monitored; absent = skipped). */
const GROUPS = ['main-out', 'main-udp-out', 'main-out-alt', 'main-udp-out-alt'];

const CHECK_INTERVAL = 30;      /* s between Clash API polls            */
const BOOT_GRACE = 90;          /* s before the first check             */
const DEAD_AFTER = 3;           /* consecutive dead sightings to act    */
const HISTORY_TTL = 120;        /* s: older history = stale = dead      */
const RESTART_COOLDOWN = 600;   /* s between auto-restarts              */
const MAX_LOG_BYTES = 65536;

let fail = {};
let deadset = {};
let last_restart = 0;

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

function flush_dead() {
	let lines = [];
	for (let k, v in deadset)
		push(lines, k);
	atomic_write(DEAD_FILE, (length(lines) ? join(lines, '\n') + '\n' : ''));
}

/* Parse a Go/Clash timestamp ("2026-09-14T09:00:00.123+03:00") into a Unix
 * epoch (UTC-based, numeric offset applied). Times without an offset are taken
 * as UTC. Returns null when unparsable. Days-from-civil (Howard Hinnant). */
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

/* Fetch the full /proxies map, null on any failure (core down / not sing-box). */
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

/* A member is "alive" only with a REAL delay on a FRESH history entry:
 * - hiddify/sing-box cores store delay 0 ("unmeasured") and 65535 (uint16 max =
 *   "timeout", observed live in the /proxies dump) for failing members;
 * - cores that keep stale history stop refreshing the timestamp of dead nodes,
 *   so an old timestamp also means the node is not really answering. */
function member_alive(proxies, tag) {
	const p = proxies[tag];
	if (type(p) !== 'object')
		return false;
	const h = p.history;
	if (type(h) !== 'array' || !length(h))
		return false;
	const last = h[length(h) - 1];
	const dly = int(last.delay) || 0;
	if (dly <= 0 || dly >= 65535)
		return false;
	const ts = iso_epoch(last.time);
	if (ts == null)
		return false; /* unparsable time: treat as stale */
	return (time() - ts) <= HISTORY_TTL;
}

/* True when tag is one of our own group tags (a nested-group pick — switching
 * already happened at the parent level; nothing to judge here). */
function is_group_tag(tag) {
	return (index(GROUPS, tag) >= 0);
}

system('mkdir -p ' + RUN_DIR + ' 2>/dev/null; true');

/* Re-adopt an existing dead mark file (service restart keeps marks — they only
 * fade when the node measures alive again). */
if (access(DEAD_FILE)) {
	const c = trim(readfile(DEAD_FILE) || '');
	if (length(c))
		for (let l in split(c, /\n/)) {
			const t = trim(l);
			if (length(t))
				deadset[t] = true;
		}
}

log('urltest watchdog started (interval ' + CHECK_INTERVAL + 's, grace ' + BOOT_GRACE + 's, marks ' + length(keys(deadset)) + ')');

sleep(BOOT_GRACE * 1000);

while (true) {
	sleep(CHECK_INTERVAL * 1000);

	const proxies = fetch_proxies();
	if (proxies == null)
		continue; /* core down or API absent — never counts as a failure */

	/* Fade dead marks for nodes that measure alive again. */
	let dead_changed = false;
	for (let k, v in deadset) {
		if (member_alive(proxies, k)) {
			delete deadset[k];
			dead_changed = true;
			log('node recovered, mark removed: ' + k);
		}
	}
	if (dead_changed)
		flush_dead();

	for (let gname in GROUPS) {
		const grp = proxies[gname];
		if (type(grp) !== 'object')
			continue;
		const now = grp.now;
		const members = grp.all;
		if (type(now) !== 'string' || !length(now) || type(members) !== 'array' || !length(members))
			continue;
		/* 'direct-out'/'block-out' or a nested-group pick: nothing to judge. */
		if (!is_group_tag(now) && index(members, now) < 0)
			continue;
		if (is_group_tag(now))
			continue;

		if (member_alive(proxies, now)) {
			fail[gname] = 0;
			continue;
		}

		/* Selected node is dead/unmeasured. Only act when a WORKING alternative
		 * exists — otherwise the outage is upstream (WAN/exit provider) and a
		 * restart would change nothing. */
		let alt = null;
		for (let m in members) {
			const tag = members[m];
			if (tag === now || is_group_tag(tag))
				continue;
			if (member_alive(proxies, tag)) {
				alt = tag;
				break;
			}
		}
		if (alt == null) {
			fail[gname] = 0;
			continue;
		}

		fail[gname] = (fail[gname] || 0) + 1;
		log('group ' + gname + ' stuck on dead node ' + now + ' (sighting ' + fail[gname] + '/' + DEAD_AFTER + ', alive alternative: ' + alt + ')');
		if (fail[gname] < DEAD_AFTER)
			continue;

		/* 1) Dead-mark the node so generate_client.uc sinks it to the pool end
		 *    and never fronts it via the sticky snapshot. */
		if (deadset[now] == null) {
			deadset[now] = true;
			flush_dead();
		}

		/* 2) Rate-limited restart: a fresh core starts with empty history, its
		 *    first probe round selects a living member. */
		const now_ts = time();
		if ((now_ts - last_restart) < RESTART_COOLDOWN) {
			log('restart suppressed (cooldown)');
			fail[gname] = 0;
			continue;
		}
		last_restart = now_ts;
		fail[gname] = 0;
		log('RESTART to escape dead URLTest pick ' + now + ' (group ' + gname + ')');

		/* setsid: survive the procd kill of our own instance long enough to
		 * trigger the restart; detached so system() returns immediately. */
		if (system('command -v setsid >/dev/null 2>&1') === 0)
			system('setsid sh -c ' + shellquote('/etc/init.d/homeproxy restart >/dev/null 2>&1') + ' &');
		else
			system('/etc/init.d/homeproxy restart >/dev/null 2>&1 &');
	}
}
