/* Exit Engine (Ф9.16, D35a) — единый выход-движок Re:HomeProxy — эволюция Hot Swap
 * (ч.59/ч.60/ч.67). ОДИН демон владеет решением «через какой узел выходит трафик».
 *
 * WHY: раньше выходом управляли ТРИ механизма с разными интервалами (kernel URLTest
 * пере-ранжировал по одной пробе, hotswap.uc пиннил селектор, urltest_watchdog.uc поллил
 * /proxies и рестартил службу) — уликовое поле размазывалось, состояние жило в 4 местах,
 * main-UDP не имел анти-флап-покрытия, а смерть hotswap-демона возвращала kernel-флап.
 * Теперь ОДИН цикл проб, ОДНА машина состояний, ОДИН контракт.
 *
 * РЕЖИМЫ (config.exit_mode, поверх main_node — D35a):
 *   auto   — Полный автомат: движок держит лучший живой узел; уход на другого только по
 *            устойчивому превосходству (> tolerance, HYST_ROUNDS раундов подряд + прямой dial).
 *   prefer — Удержание предпочтительного: preferred держится, пока отвечает; уход ТОЛЬКО при
 *            реальной смерти (dead_after подряд мёртвых проб при живом резерве); возврат при
 *            восстановлении (recovery_oks за recovery_window). exit_upgrade=1 разрешает уход
 *            на устойчиво лучшего.
 *   manual — Ручной: держится конкретный узел (выбор пользователя); смерть → резервы;
 *            восстановление → возврат (если failback≠0).
 * Резервный список (contract reserves) — сквозной: приоритет горячих проб и порядок
 * фейловера во всех режимах; в auto замена = живой с наименьшей задержкой, в prefer —
 * preferred если жив, иначе первый живой по списку.
 *
 * КОНТУРЫ: main-out и (при выделенном UDP-выходе) main-udp-out — одна машина состояний на
 * контур, общий тик и бюджет проб. UDP-контур спит, когда его нет в контракте.
 *
 * ВЛАДЕНИЕ СЕЛЕКТОРОМ: движок пиннит селектор PUT /proxies/<selector> и всегда
 * принимает внешние перемещения как выбор пользователя (пин двигается за пользователем;
 * НИКАКОГО авто-возврата на preferred при живом принятом пике). Движение селектора назад
 * на группу восстанавливает пин. Смерть/respawn движка: старт с adopt текущего пика —
 * kernel не «отбирает» выход.
 *
 * DEAD-МАРКИ: движок ведёт $RUN_DIR/urltest_dead (сам пишет/снимает по СВОИМ пробам —
 * dead_after подряд мёртвых); генератор тонет помеченных в конец пулов и не фронтирует их
 * sticky-снапшотом. Рестарт службы из движка НЕ выполняется: движок владеет селектором,
 * kernel-залипание группы перестало быть аварийным.
 *
 * КОНТРАКТ (generate_client.uc → $RUN_DIR/exit_engine.json, envelope statestore):
 *   { enabled, mode:'auto'|'prefer'|'manual', failback, upgrade,
 *     probe:{interval,timeout}, thresholds:{dead_after,recovery_oks,recovery_window,
 *     hysteresis_rounds,tolerance}, labels:{tag:имя},
 *     contours:{ 'main-out':     { selector, group, preferred, manual_pick, reserves:[…] },
 *                'main-udp-out': { … } } }
 * Контракт перечитывается каждый тик (регенерация подхватывается живьём); пул берётся из
 * ЖИВОГО /proxies (селектор-члены), резервы фильтруются по нему. Старый hotswap.json
 * читается как фолбэк (переход до первой регенерации).
 *
 * ucode constraints honored: sleep() is MILLISECONDS, no Array.includes(), no optional
 * chaining, POSIX-ERE regex, atomic file writes (statestore), helpers above callers,
 * for-in over array yields elements. */

'use strict';

import { access, open, stat, popen, readfile } from 'fs';
import { write_state as ss_write_state, read_state as ss_read_state, atomic_write } from '/etc/homeproxy/scripts/statestore.uc';
import { reg_self as pm_reg_self, reg_hb as pm_reg_hb } from '/etc/homeproxy/scripts/pmgr.uc';
import { emit as ev_emit } from '/etc/homeproxy/scripts/eventbus.uc';

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

const RUN_DIR = '/var/run/homeproxy';
const CONTRACT_FILE = RUN_DIR + '/exit_engine.json';
const CONTRACT_LEGACY = RUN_DIR + '/hotswap.json';
const STATE_FILE = RUN_DIR + '/hotswap_state.json';
const DEAD_FILE = RUN_DIR + '/urltest_dead';
const LOG_FILE = RUN_DIR + '/hotswap.log';
const API = 'http://127.0.0.1:9090';
const HAVE_CURL = access('/usr/bin/curl');

const IDLE_INTERVAL = 30;        /* s between contract re-checks when off        */
const RECHECK_MS = 2000;         /* fast double-check after first failure         */
const PROBE_TIMEOUT = 6000;      /* ms cap of the core-side delay test (default)  */
/* 6000 ms: the probe IS a real dial through the tunnel; a false timeout deletes
 * the node's kernel history and (unpinned) triggers an instant URLTest re-pick. */
const SWITCH_COOLDOWN = 15;      /* s between selector switches (per contour)     */
const STATE_HEARTBEAT = 60;      /* s between unchanged state refreshes           */
const HIST_FRESH = 120;          /* s: max age of a history entry used here       */
const MAX_LOG_BYTES = 65536;
const RESERVE_QUOTA = 3;         /* max proven-alive alternates probed per tick   */

/* Defaults for thresholds absent in the contract (also the legacy-compat values). */
const DEF_DEAD_AFTER = 2;
const DEF_RECOVERY_OKS = 3;
const DEF_RECOVERY_WINDOW = 30;
const DEF_HYST_ROUNDS = 3;
const DEF_TOLERANCE = 150;
const DEF_INTERVAL = 10;

/* Runtime state (module level — shared across the loop). */
let contract = null;             /* normalized contract (v2)                      */
let contract_sig = '';           /* change resets per-contour state               */
let contours = {};               /* selector → contour runtime state              */
let deadset = {};                /* tag → true (urltest_dead, shared by generator)*/
let health = {};                 /* tag → {fails, oks, first_ok, last_delay, ts}  */
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

/* ── Clash API helpers ─────────────────────────────────────────────────────── */

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

/* Active delay test through a node: GET /proxies/<tag>/delay — a real dial that
 * also keeps standby tunnels warm (TLS/NAT). Returns positive delay or null. */
function probe_node(tag, timeout_ms) {
	if (!tag || type(tag) !== 'string')
		return null;
	const to = (timeout_ms > 0) ? timeout_ms : PROBE_TIMEOUT;
	const url = API + '/proxies/' + tag + '/delay?timeout=' + to;
	let body = '';
	if (HAVE_CURL) {
		let fd = popen('curl -s --max-time ' + (int(to / 1000) + 4) + ' ' + shellquote(url) + ' 2>/dev/null');
		if (!fd) return null;
		body = fd.read('all');
		fd.close();
	} else {
		let fd = popen('wget -qO- --timeout=' + (int(to / 1000) + 4) + ' ' + shellquote(url) + ' 2>/dev/null');
		if (!fd) return null;
		body = fd.read('all');
		fd.close();
	}
	if (!length(body))
		return null;
	try {
		const r = json(body);
		const d = int(r.delay) || 0;
		return (d > 0 && d < 65535) ? d : null;
	} catch (e) {
		return null;
	}
}

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

/* Fresh positive delay of `tag` from the core's history — the SAME source the
 * kernel re-ranks from; stale (older than HIST_FRESH) reads as null. */
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

/* A concrete node tag that may hold the pin: never our own groups/selector or
 * the built-in service outbounds. */
function pinnable(tag) {
	if (!tag || type(tag) !== 'string' || !length(tag))
		return false;
	if (tag === 'main-out' || tag === 'main-out-auto' || tag === 'main-out-alt' ||
	    tag === 'main-udp-out' || tag === 'main-udp-auto' || tag === 'main-udp-out-alt')
		return false;
	return (index([ 'direct-out', 'block-out' ], tag) < 0);
}

function tag_label(tag) {
	if (contract && type(contract.labels) === 'object' && type(contract.labels[tag]) === 'string' && length(contract.labels[tag]))
		return contract.labels[tag];
	return tag;
}

/* Ф2.4: publish to the shared Event Bus. Switches ride src 'hotswap' (bot
 * push_hotswap), dead-mark events ride src 'urltest' (bot push_watchdog) —
 * historical src names are preserved for the merged toggles (D35a). */
function ev_switch(who) {
	try { ev_emit('hotswap', 'switch', who, last_reason + ' (#' + switches + ')'); } catch (e) { /* best-effort */ }
}

function ev_dead(kind, who, detail) {
	try { ev_emit('urltest', kind, who, detail); } catch (e) { /* best-effort */ }
}

/* ── Dead marks (urltest_dead) — engine-owned now ──────────────────────────── */

function dead_load() {
	try {
		const c = trim(readfile(DEAD_FILE) || '');
		if (length(c))
			for (let l in split(c, /\n/)) {
				const t = trim(l);
				if (length(t))
					deadset[t] = true;
			}
	} catch (e) { /* no file yet */ }
}

function dead_flush() {
	let lines = [];
	for (let k, v in deadset)
		push(lines, k);
	/* ucode builtin form: join(sep, arr) (lesson 103). */
	atomic_write(DEAD_FILE, (length(lines) ? join('\n', lines) + '\n' : ''));
}

function dead_mark(tag, why) {
	if (deadset[tag] != null)
		return;
	deadset[tag] = true;
	dead_flush();
	log('DEAD-MARK: ' + tag_label(tag) + ' (' + why + ')');
	ev_dead('dead', tag_label(tag), why);
}

function dead_clear(tag) {
	if (deadset[tag] == null)
		return;
	delete deadset[tag];
	dead_flush();
	log('dead-mark removed: ' + tag_label(tag));
	ev_dead('recovered', tag_label(tag), 'узел снова отвечает — метка мёртвого снята');
}

/* ── Probe health bookkeeping (shared across contours — same node, same probe) */

function health_of(tag) {
	if (type(health[tag]) !== 'object')
		health[tag] = { fails: 0, oks: 0, first_ok: 0, last_delay: 0, ts: 0 };
	return health[tag];
}

function cur_dead_after() {
	return (contract && int(contract.dead_after) >= 1) ? int(contract.dead_after) : DEF_DEAD_AFTER;
}

function mark_probe(tag, delay) {
	const h = health_of(tag);
	h.ts = time();
	if (delay) {
		if (h.fails > 0 && deadset[tag] != null)
			dead_clear(tag);
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
		if (h.fails >= cur_dead_after())
			dead_mark(tag, 'проб не отвечало подряд: ' + h.fails);
	}
	return h;
}

/* ── Contours ──────────────────────────────────────────────────────────────── */
/* A contour = one selector the engine owns. Runtime state per contour:
 *   held           — node the selector is pinned to (null = not seeded yet)
 *   fb_target      — node to return to after a failover (null = none)
 *   chase          — tag → consecutive faster-than-held rounds (BETTER)
 *   last_group_pick / suppressed — kernel re-ranks absorbed by the pin
 *   last_switch_ts — cooldown anchor
 *   last_reason    — human-readable reason of the last contour switch           */

function contour_of(tag) {
	if (type(contours[tag]) !== 'object')
		contours[tag] = { held: null, fb_target: null, chase: {}, last_group_pick: null,
		                  suppressed: 0, last_switch_ts: 0, last_reason: '' };
	return contours[tag];
}

function reset_contours() {
	contours = {};
}

/* Selector switch: PUT /proxies/<group>. curl required (busybox wget has no PUT).
 * Returns true when the group reports the new pick afterwards. */
function switch_to(group, tag) {
	if (!HAVE_CURL)
		return false;
	const body = '{"name":"' + tag + '"}';
	system('curl -s -o /dev/null -X PUT -d ' + shellquote(body) + ' ' + shellquote(API + '/proxies/' + group) + ' 2>/dev/null');
	const proxies = fetch_proxies();
	return !!(proxies && type(proxies[group]) === 'object' && proxies[group].now === tag);
}

/* ── Contract reading + normalization (+ legacy hotswap.json compat) ──────── */

function norm_contour_spec(tag, spec) {
	if (type(spec) !== 'object')
		return null;
	const sel = (type(spec.selector) === 'string' && length(spec.selector)) ? spec.selector : tag;
	const r = { selector: sel, group: null, preferred: null, manual_pick: null, reserves: [] };
	if (type(spec.group) === 'string' && length(spec.group))
		r.group = spec.group;
	if (type(spec.preferred) === 'string' && length(spec.preferred))
		r.preferred = spec.preferred;
	if (type(spec.manual_pick) === 'string' && length(spec.manual_pick))
		r.manual_pick = spec.manual_pick;
	if (type(spec.reserves) === 'array')
		for (let t in spec.reserves)
			if (type(t) === 'string' && length(t) && pinnable(t) && index(r.reserves, t) < 0)
				push(r.reserves, t);
	return r;
}

/* Normalize a raw contract envelope (v2) or map the legacy hotswap contract. */
function normalize_contract(raw) {
	if (type(raw) !== 'object' || raw.enabled !== true)
		return null;
	let c = { mode: 'manual', failback: true, upgrade: false,
	          interval: DEF_INTERVAL, probe_timeout: PROBE_TIMEOUT,
	          dead_after: DEF_DEAD_AFTER, recovery_oks: DEF_RECOVERY_OKS,
	          recovery_window: DEF_RECOVERY_WINDOW, hysteresis_rounds: DEF_HYST_ROUNDS,
	          tolerance: DEF_TOLERANCE, labels: {}, contours: {}, legacy: false };

	const m = raw.mode;
	if (type(raw.labels) === 'object')
		c.labels = raw.labels;

	if (m === 'auto' || m === 'prefer' || m === 'manual') {
		c.mode = m;
		c.failback = (raw.failback !== false);
		c.upgrade = (raw.upgrade === true);
		if (type(raw.probe) === 'object') {
			if (int(raw.probe.interval) >= 5)
				c.interval = (int(raw.probe.interval) > 120) ? 120 : int(raw.probe.interval);
			if (int(raw.probe.timeout) >= 2000)
				c.probe_timeout = int(raw.probe.timeout);
		}
		if (type(raw.thresholds) === 'object') {
			const t = raw.thresholds;
			if (int(t.dead_after) >= 1) c.dead_after = (int(t.dead_after) > 10) ? 10 : int(t.dead_after);
			if (int(t.recovery_oks) >= 1) c.recovery_oks = int(t.recovery_oks);
			if (int(t.recovery_window) >= 10) c.recovery_window = int(t.recovery_window);
			if (int(t.hysteresis_rounds) >= 1) c.hysteresis_rounds = int(t.hysteresis_rounds);
			if (int(t.tolerance) > 0) c.tolerance = int(t.tolerance);
		}
		if (type(raw.contours) === 'object')
			for (let tag, spec in raw.contours) {
				const mc = norm_contour_spec(tag, spec);
				if (mc != null)
					c.contours[tag] = mc;
			}
	} else if (m === 'urltest' || m === 'node') {
		/* Legacy contract: map pool_mode → engine mode, hot list → reserves. */
		c.legacy = true;
		c.mode = (raw.pool_mode === 'auto' || raw.pool_mode === 'prefer') ? raw.pool_mode : 'manual';
		c.failback = (raw.failback !== false);
		if (int(raw.tolerance) > 0)
			c.tolerance = int(raw.tolerance);
		if (int(raw.interval) >= 5)
			c.interval = (int(raw.interval) > 120) ? 120 : int(raw.interval);
		const hot = (type(raw.hot) === 'array') ? raw.hot : [];
		const spec = { selector: (type(raw.group) === 'string' && length(raw.group)) ? raw.group : 'main-out',
		               group: (m === 'urltest') ? raw.primary : null,
		               preferred: null,
		               manual_pick: (m === 'node') ? raw.primary : null,
		               reserves: hot };
		const mc = norm_contour_spec('main-out', spec);
		if (mc != null)
			c.contours['main-out'] = mc;
	} else {
		return null;
	}
	return (length(keys(c.contours))) ? c : null;
}

function read_contract() {
	const rs = ss_read_state(CONTRACT_FILE);
	let raw = (rs != null && rs.data != null) ? rs.data : null;
	if (raw == null) {
		/* Legacy fallback: old generator's contract (transition before regen). */
		const rs2 = ss_read_state(CONTRACT_LEGACY);
		raw = (rs2 != null && rs2.data != null) ? rs2.data : null;
	}
	const c = normalize_contract(raw);
	if (c == null)
		return null;
	/* Signature: mode/flags/thresholds/reserves change resets per-contour state
	 * (labels excluded — renaming a node must not reset the pin). */
	let sig_parts = [ c.mode, c.failback ? '1' : '0', c.upgrade ? '1' : '0',
	                  '' + c.interval, '' + c.probe_timeout, '' + c.dead_after,
	                  '' + c.recovery_oks, '' + c.recovery_window,
	                  '' + c.hysteresis_rounds, '' + c.tolerance ];
	for (let tag, spec in c.contours)
		push(sig_parts, tag + '=' + (spec.group || '-') + '|' + (spec.preferred || '-') + '|' + (spec.manual_pick || '-') + '|' + join(',', spec.reserves));
	const sig = join(';', sig_parts);
	if (sig !== contract_sig) {
		contract_sig = sig;
		health = {};
		reset_contours();
		log('contract adopted: mode=' + c.mode + ' failback=' + (c.failback ? 'on' : 'off') +
		    ' upgrade=' + (c.upgrade ? 'on' : 'off') + ' interval=' + c.interval +
		    ' dead_after=' + c.dead_after + ' recovery=' + c.recovery_oks + '/' + c.recovery_window +
		    ' hysteresis=' + c.hysteresis_rounds + ' tolerance=' + c.tolerance +
		    ' contours=' + length(keys(c.contours)) + (c.legacy ? ' (legacy)' : ''));
	}
	return c;
}

/* ── Per-tick contour machine ──────────────────────────────────────────────── */

/* Ordered candidate scan: reserves (contract order) first, then the rest of the
 * live selector membership — reserve priority drives both hot probing and the
 * failover order. */
function scan_order(spec, members) {
	let ordered = [];
	for (let t in spec.reserves)
		if (pinnable(t) && index(members, t) >= 0 && index(ordered, t) < 0)
			push(ordered, t);
	for (let t in members)
		if (pinnable(t) && index(ordered, t) < 0)
			push(ordered, t);
	return ordered;
}

/* Prefer-mode seed arming: the preferred node is the documented hold target
 * ("returns to it once it recovers") — a restart or any settings save must not
 * sever that promise just because the engine was in a failover at the time.
 * (Declared ABOVE seed_contour — ucode has no hoisting, lesson 294.) */
function seed_prefer_fb(c, spec, ct, seed) {
	if (c != null && c.mode === 'prefer' &&
	    type(spec.preferred) === 'string' && length(spec.preferred) &&
	    spec.preferred !== seed)
		ct.fb_target = spec.preferred;
}

/* Seed the pin at first tick / after a contract change: respect a concrete
 * external/sticky pick; otherwise take the nested group's pick (prefer: that IS
 * the preferred node via sticky; auto: kernel's best); otherwise first member.
 * Prefer-mode: an adopted pick that differs from the preferred is NOT user
 * agency — it is leftover kernel/selector state after a restart or a contract
 * reset (any settings save changes the signature and wipes fb_target with it).
 * Arm the preferred as the failback target here so the recovery gate (3c)
 * returns to it once it is stable; while the preferred is dead the gate never
 * passes and the adopted pick keeps serving — no dead-node window at seed.
 * A mid-run external move (user agency) rides the adoption path in the tick,
 * not the seed, so it is never undone by this. */
function seed_contour(c, spec, proxies, active) {
	const ct = contour_of(spec.selector);
	let seed = null;
	if (pinnable(active)) {
		seed = active;
	} else if (spec.group != null) {
		const gsel = proxies[spec.group];
		const gpick = (gsel && type(gsel) === 'object') ? gsel.now : null;
		if (pinnable(gpick))
			seed = gpick;
	}
	if (seed == null) {
		/* No group pick either: first pinnable member of the selector. */
		const sel = proxies[spec.selector];
		const all = (sel && type(sel) === 'object' && type(sel.all) === 'array') ? sel.all : [];
		for (let t in all)
			if (pinnable(t)) { seed = t; break; }
	}
	if (seed == null)
		return false;
	if (active === seed) {
		ct.held = seed;
		ct.last_group_pick = null;
		seed_prefer_fb(c, spec, ct, seed);
		log('[' + spec.selector + '] pinned ' + tag_label(seed) + ' (adopted selector pick)');
		return true;
	}
	if (switch_to(spec.selector, seed)) {
		ct.held = seed;
		ct.last_group_pick = seed;
		seed_prefer_fb(c, spec, ct, seed);
		log('[' + spec.selector + '] pinned ' + tag_label(seed) + ' (seed)');
		return true;
	}
	log('[' + spec.selector + '] seed pin to ' + tag_label(seed) + ' failed (curl missing / core refused) — will retry');
	return false;
}

/* One engine tick for ONE contour. proxies = fresh /proxies map. */
function tick_contour(c, spec, proxies, now_ts) {
	const ct = contour_of(spec.selector);
	const sel = proxies[spec.selector];
	if (type(sel) !== 'object' || type(sel.all) !== 'array')
		return;
	const members = sel.all;
	const active = sel.now;
	if (length(members) < 2 || !active || type(active) !== 'string')
		return; /* nothing to switch between (single-node selector / plain shape) */

	const dead_after = c.dead_after;
	const tol = c.tolerance;

	/* ── 0. OWN the selection (adopt external moves, restore the pin) ─────── */
	if (ct.held == null) {
		if (!seed_contour(c, spec, proxies, active))
			return;
	} else if (active === spec.group) {
		/* Selector moved back to the nested group by an external API call:
		 * restore the pin — that is the whole point of ownership. */
		if (switch_to(spec.selector, ct.held))
			log('[' + spec.selector + '] selector moved back to the group — re-pinned ' + tag_label(ct.held));
	} else if (active !== ct.held && pinnable(active)) {
		/* External move to another concrete node: adopt it as the new held pick
		 * (user agency) — NO automatic return while the adopted pick is alive. */
		ct.held = active;
		ct.chase = {};
		ct.last_group_pick = null;
		log('[' + spec.selector + '] selector moved externally to ' + tag_label(active) + ' — adopted as held');
	}

	/* Count absorbed kernel re-ranks for the UI (probe-only observation). */
	if (ct.held != null && spec.group != null) {
		const gsel = proxies[spec.group];
		const gpick = (gsel && type(gsel) === 'object') ? gsel.now : null;
		if (type(gpick) === 'string' && length(gpick)) {
			if (ct.last_group_pick != null && gpick !== ct.last_group_pick && gpick !== ct.held) {
				ct.suppressed = ct.suppressed + 1;
				log('[' + spec.selector + '] kernel re-ranked ' + tag_label(ct.last_group_pick) + ' → ' + tag_label(gpick) + ' (absorbed #' + ct.suppressed + ', exit stays on ' + tag_label(ct.held) + ')');
			}
			ct.last_group_pick = gpick;
		}
	}

	/* ── 1. Probe the HELD node (fresh data, not the core's own history) ──── */
	let held_alive = null;
	if (index(members, ct.held) >= 0) {
		held_alive = mark_probe(ct.held, probe_node(ct.held, c.probe_timeout));
		if (held_alive.fails === 1) {
			/* Fast path: one miss might be a hiccup — double-check within seconds. */
			sleep(RECHECK_MS);
			held_alive = mark_probe(ct.held, probe_node(ct.held, c.probe_timeout));
		}
	} else {
		/* Held node vanished from the selector (regen shrank the pool): unpin. */
		ct.held = null;
		ct.fb_target = null;
		ct.chase = {};
		return;
	}

	/* ── 2. Probe candidates until the alive quota is known ─────────────────
	 * Reserve order first (hot dials); the failback target is always probed;
	 * dead-marked candidates cost one probe each (and fade their mark). */
	const order = scan_order(spec, members);
	let fb_probe = null;
	if (c.mode === 'prefer' && type(spec.preferred) === 'string' && spec.preferred !== ct.held)
		fb_probe = spec.preferred;
	else if (c.mode === 'manual' && ct.fb_target != null && ct.fb_target !== ct.held)
		fb_probe = ct.fb_target;
	let alive_others = [];
	for (let tag in order) {
		if (tag === ct.held)
			continue;
		const need_more = (length(alive_others) < RESERVE_QUOTA);
		const want_fb = (fb_probe != null && tag === fb_probe);
		if (!need_more && !want_fb)
			continue;
		const h = mark_probe(tag, probe_node(tag, c.probe_timeout));
		if (h.fails === 0)
			push(alive_others, tag);
	}

	/* ── 3. Decisions ─────────────────────────────────────────────────────── */
	if (held_alive != null && held_alive.fails >= dead_after && length(alive_others)) {
		/* ── 3a. DEATH: the held node is dead, a live alternative exists ───── */
		if ((now_ts - ct.last_switch_ts) < SWITCH_COOLDOWN) {
			log('[' + spec.selector + '] held ' + tag_label(ct.held) + ' down, switch suppressed (cooldown)');
		} else {
			let target = null;
			if (c.mode === 'auto') {
				/* The fastest PROVEN-alive candidate wins (URLTest spirit). */
				let best_d = -1;
				for (let t in alive_others) {
					const d = health_of(t).last_delay || 0;
					if (target == null || (d > 0 && (best_d <= 0 || d < best_d))) {
						target = t;
						best_d = d;
					}
				}
			} else {
				/* prefer: preferred first (if alive); manual: first alive in
				 * reserve order (alive_others preserves scan_order). */
				for (let t in alive_others) {
					if (c.mode === 'prefer' && t === spec.preferred) { target = t; break; }
					if (target == null)
						target = t;
				}
				if (target == null)
					target = alive_others[0];
			}
			if (target && target !== ct.held) {
				if (switch_to(spec.selector, target)) {
					const prev = ct.held;
					switches = switches + 1;
					ct.last_switch_ts = now_ts;
					last_switch_ts = now_ts;
					last_reason = 'основной узел недоступен: ' + tag_label(prev) + ' → ' + tag_label(target);
					ct.last_reason = last_reason;
					log('[' + spec.selector + '] SWITCH: ' + last_reason + ' (switch #' + switches + ')');
					ev_switch(tag_label(target));
					health_of(target).fails = 0;
					/* Failback target: prefer returns to preferred — or, when no
					 * valid preferred is configured (dangling/empty), to the pick
					 * it was holding (manual semantics); manual returns to the
					 * pick it was holding; auto has none (BETTER decides). */
					ct.fb_target = (c.mode === 'prefer') ? (spec.preferred || prev) : prev;
					ct.held = target;
					ct.chase = {};
				} else {
					log('[' + spec.selector + '] switch to ' + tag_label(target) + ' FAILED (core refused) — will retry');
				}
			}
		}
	} else if (held_alive != null && held_alive.fails === 0) {
		/* ── 3b. BETTER (auto, or prefer with upgrade opt-in) ───────────────── */
		if ((c.mode === 'auto' || (c.mode === 'prefer' && c.upgrade)) &&
		    ct.held === active) {
			const pd = hist_delay(proxies, ct.held);
			if (pd != null) {
				let best = null, best_d = 0;
				for (let tag in members) {
					if (!pinnable(tag) || tag === ct.held)
						continue;
					const d = hist_delay(proxies, tag);
					if (d == null || !(d + tol < pd)) {
						delete ct.chase[tag];
						continue;
					}
					ct.chase[tag] = (ct.chase[tag] || 0) + 1;
					if (ct.chase[tag] >= c.hysteresis_rounds && (best == null || d < best_d)) {
						best = tag;
						best_d = d;
					}
				}
				if (best != null && (now_ts - ct.last_switch_ts) >= SWITCH_COOLDOWN && probe_node(best, c.probe_timeout)) {
					if (switch_to(spec.selector, best)) {
						switches = switches + 1;
						ct.last_switch_ts = now_ts;
						last_switch_ts = now_ts;
						last_reason = (c.mode === 'auto')
							? ('автомат: найден стабильно лучший узел: ' + tag_label(ct.held) + ' → ' + tag_label(best))
							: ('upgrade: устойчиво лучший узел: ' + tag_label(ct.held) + ' → ' + tag_label(best));
						ct.last_reason = last_reason;
						log('[' + spec.selector + '] ' + last_reason + ' (switch #' + switches + ')');
						ev_switch(tag_label(best));
						ct.held = best;
						ct.fb_target = null;
						ct.chase = {};
					}
				}
			}
		}
		/* ── 3c. RECOVERED: return to the failback target once it is stable ── */
		if (ct.fb_target != null && ct.fb_target !== ct.held && index(members, ct.fb_target) >= 0) {
			const ph = health_of(ct.fb_target);
			if (ph.oks >= c.recovery_oks && ph.first_ok && (now_ts - ph.first_ok) >= c.recovery_window) {
				if ((now_ts - ct.last_switch_ts) < SWITCH_COOLDOWN) {
					log('[' + spec.selector + '] failback target recovered, switch suppressed (cooldown)');
				} else if (switch_to(spec.selector, ct.fb_target)) {
					switches = switches + 1;
					ct.last_switch_ts = now_ts;
					last_switch_ts = now_ts;
					last_reason = (c.mode === 'prefer' && spec.preferred != null && ct.fb_target === spec.preferred)
						? ('предпочтительный узел восстановился: ' + tag_label(ct.fb_target))
						: ('возврат на прежний узел: ' + tag_label(ct.fb_target));
					ct.last_reason = last_reason;
					log('[' + spec.selector + '] RECOVER: ' + last_reason + ' (switch #' + switches + ')');
					ev_switch(tag_label(ct.fb_target));
					health_of(ct.fb_target).oks = 0;
					health_of(ct.fb_target).first_ok = 0;
					ct.held = ct.fb_target;
					ct.fb_target = null;
					ct.chase = {};
				} else {
					log('[' + spec.selector + '] failback to ' + tag_label(ct.fb_target) + ' FAILED (core refused) — will retry');
				}
			}
		}
	}
}

/* ── State file for RPC/UI (legacy top-level fields mirror the main contour) ─ */

function write_state(enabled, main_now) {
	const now = time();
	/* Drop health bookkeeping for members untouched for 48 h. */
	for (let hk in keys(health))
		if (!(health[hk].ts > 0) || (now - health[hk].ts) > 172800)
			delete health[hk];
	let members = {};
	for (let k, v in health)
		members[k] = { state: (v.fails ? 'down' : (v.oks ? 'alive' : 'unknown')), fails: v.fails, oks: v.oks, last_delay: v.last_delay };

	const mspec = (contract && type(contract.contours['main-out']) === 'object') ? contract.contours['main-out'] : null;
	const mc = contours['main-out'] || null;
	let contour_out = {};
	for (let tag, ct in contours)
		contour_out[tag] = { held: ct.held, fb_target: ct.fb_target, suppressed: ct.suppressed, last_reason: ct.last_reason };

	ss_write_state(STATE_FILE, {
		engine_version: 2,
		enabled: enabled,
		mode: contract ? contract.mode : null,
		group: 'main-out',
		/* legacy mirror (main contour) */
		active: mc ? mc.held : main_now,
		primary: mspec ? (mspec.group || mspec.manual_pick) : null,
		hot: mspec ? mspec.reserves : [],
		count: mspec ? (length(mspec.reserves) + 1) : 0,
		interval: contract ? contract.interval : 0,
		failback: contract ? contract.failback : false,
		antiflap: enabled,
		pinned: (mc && mc.held != null) ? mc.held : null,
		suppressed: mc ? mc.suppressed : 0,
		switches: switches,
		last_switch: last_switch_ts,
		last_reason: last_reason,
		members: members,
		contours: contour_out,
		updated: now
	});
	last_state_write = now;
}

/* ── Main loop (never exits: procd respawns would burn the budget) ─────────── */

system('mkdir -p ' + RUN_DIR + ' 2>/dev/null; true');
dead_load();
log('exit engine started (probe timeout ' + PROBE_TIMEOUT + 'ms, switch cooldown ' + SWITCH_COOLDOWN + 's, dead marks ' + length(keys(deadset)) + ')');
pm_reg_self('hotswap', 'hotswap.uc');

while (true) {
	pm_reg_hb('hotswap');
	contract = read_contract();

	if (contract == null) {
		/* Feature off or between generations: keep the state file honest. */
		if (access(STATE_FILE) && (time() - last_state_write) > STATE_HEARTBEAT) {
			const proxies = fetch_proxies();
			const active = (proxies && type(proxies['main-out']) === 'object') ? proxies['main-out'].now : null;
			write_state(false, active);
		}
		sleep(IDLE_INTERVAL * 1000);
		continue;
	}

	const proxies = fetch_proxies();
	if (proxies == null) {
		/* Core down/restarting: never counts as a node failure. */
		sleep(contract.interval * 1000);
		continue;
	}
	const now_ts = time();

	for (let tag, spec in contract.contours) {
		const sel = proxies[spec.selector];
		if (type(sel) !== 'object')
			continue; /* contour's selector not in this core build */
		tick_contour(contract, spec, proxies, now_ts);
	}

	if ((time() - last_state_write) >= STATE_HEARTBEAT || last_switch_ts === now_ts) {
		const active = (type(proxies['main-out']) === 'object') ? proxies['main-out'].now : null;
		write_state(true, active);
	}

	sleep(contract.interval * 1000);
}
