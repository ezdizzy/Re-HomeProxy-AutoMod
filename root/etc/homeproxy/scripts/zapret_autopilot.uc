#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Zapret strategy auto-pilot daemon (ч.97).
 *
 * ALWAYS-ON procd instance (the telegram.uc pattern): the daemon gates
 * itself on the UCI section `homeproxy.autopilot` EVERY tick, so toggles
 * from the Wizard page apply without a service restart.
 *
 * UCI (created by init.d / install.sh / wizard_autopilot_set):
 *   enabled '0'|'1'
 *   resources 'youtube discord telegram general'   (subset, space-separated)
 *   set_rules '0'|'1'   — managed resources get their (first) rule repointed
 *                         to zapret-out: a strategy serves a resource ONLY
 *                         through its rule. Telegram is skipped while the
 *                         tg-ws bridge owns that rule.
 *   interval_h 1..24    — scheduled re-rank interval (default 6)
 *   check_min 5..180    — health probe interval (default 15)
 *   window ''|'HH:MM-HH:MM' — scheduled re-ranks only inside the window
 *                         (the "night pick" idea). HEALTH re-picks happen
 *                         immediately — a broken resource cannot wait.
 *   fuzz_mode 'quick'|'full'
 *   fail_strikes 1..5   — failed probes in a row before a re-pick (default 2)
 *
 * State: /var/run/homeproxy/zapret_autopilot.json — written ATOMICALLY on
 * every change; it is both the UI status and the RESUME journal. Any action
 * that restarts the service (rule ensure via wizard_preset_apply, strategy
 * apply via wizard_compose_apply) is preceded by a `pending` record — the
 * respawned daemon resumes (verify → rollback-on-regression) from it, so a
 * half-done apply can never be lost (reload = full stop/start of ALL
 * procd instances, including this daemon).
 *
 * Policy:
 *   - scheduled re-rank: fresh fuzz ranking (reuse < 6 h / wait a running
 *     sweep / spawn one, setsid-detached) → best strategy PER RESOURCE
 *     (majority pass, distinguishing host, minimal TLS = fastest) → rebuild
 *     the composition (scoped blocks + general tail) through the EXISTING
 *     wizard_compose_build/compose_apply RPCs (server snapshot, the Restore
 *     button keeps working) → post-verify. A resource that was OK before
 *     and fails after the apply → automatic rollback and the winner goes
 *     into the tried-failed list (24 h TTL).
 *   - health re-pick: fail_strikes failed probes in a row → the next
 *     alternative (excluding tried-failed and the current one) applies NOW.
 *   - anti-flap: a scheduled switch needs a >10% TLS win (or a failing
 *     current); an equal winner never triggers an apply. While enabled the
 *     auto-pilot OWNS the Zapret strategy — manual changes are overwritten
 *     on the next cycle (the Restore snapshot always reverts), and the
 *     user's single-block strategy is adopted as the general tail on the
 *     first apply.
 *   - ByeDPI is NOT managed (honest note); the nfqws2 corpus only.
 *
 * ucode constraints honored (05-doc): no function hoisting (main() last);
 * push()/shift()/sort()/index() builtin forms; for-in over an ARRAY yields
 * ELEMENTS (lesson 20/31 — never arr[i] under for-in); match() only with
 * /regex/ literals (lesson 26); json() is a parser only (serialize via
 * sprintf('%.J'), lesson 32); sleep() in ms; atomic writes (tmp + mv -f);
 * no typeof/strftime/optional chaining in standalone ucode (type() works);
 * cursor.get with a TYPE answers null — enumerate through cursor.foreach.
 */

import { readfile, writefile, access, popen } from 'fs';
import { cursor } from 'uci';

const RUN_DIR = '/var/run/homeproxy';
const STATE = RUN_DIR + '/zapret_autopilot.json';
const FUZZ_STATUS = RUN_DIR + '/zapret_fuzz.json';
const FUZZ_RESULT = RUN_DIR + '/zapret_fuzz_result.json';
const ONESHOT = RUN_DIR + '/wizard_autopick.json';
const COMP_STATUS = RUN_DIR + '/wizard_compose_result.json';
const RELOAD_MARK = RUN_DIR + '/.reload_running';
const NFQWS = '/opt/zapret2/nfq2/nfqws2';

const RESOURCES = {
	youtube:  { tag: 'yt', url: 'https://www.youtube.com', host: 'www.youtube.com' },
	discord:  { tag: 'dc', url: 'https://discord.com', host: 'discord.com' },
	telegram: { tag: 'tg', url: 'https://web.telegram.org', host: 'web.telegram.org' },
	general:  { tag: null, url: 'http://www.gstatic.com/generate_204', host: 'gstatic generate_204' }
};
const RES_KEYS = ['youtube', 'discord', 'telegram', 'general'];

const TICK = 60;                /* main loop step, s                     */
const FUZZ_FRESH = 6 * 3600;    /* reuse a ranking younger than 6 h      */
const FUZZ_WAIT_MAX = 2700;     /* cap for a full fuzz (~45 min)         */
const FUZZ_DEAD = 900;          /* running:true with a stale ts = dead   */
const CORE_WAIT_MAX = 90;       /* cap for the service restart           */
const VERIFY_TMO = 9;           /* live-path probe --max-time            */
const PENDING_TTL = 600;        /* an unclaimed pending older than this is
                                 * orphaned (the restart must be over)   */
const TRIED_TTL = 24 * 3600;    /* tried-and-failed memory               */
const MARGIN_PCT = 10;          /* anti-flap: a switch needs a >10% win  */
const GENERAL_SCORE_STEP = 100; /* general: +1 distinguishing host       */

/* ── module state (persisted through wstat) ─────────────────────────── */
let S = {
	alive: true, ts: 0,
	enabled: false,
	stage: 'idle', stage_note: '', stage_ts: 0,
	error: '',
	pending: null,
	config: {},
	mode: '', zapret_enabled: false, tgws: false,
	resources: {},
	general: { winner: null, probe: null, strikes: 0, note: '' },
	last_apply: null,
	tried: {},
	next_check_ts: 0, next_cycle_ts: 0,
	log: []
};

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function wstat() {
	S.ts = time();
	writefile(STATE + '.tmp', sprintf("%.J\n", S));
	system(`mv -f ${sq(STATE + '.tmp')} ${sq(STATE)}`);
}

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function log(msg) {
	push(S.log, { ts: time(), m: '' + msg });
	while (length(S.log) > 24)
		shift(S.log);
	wstat();
}

/* Log only when a keyed note CHANGES (health ticks would otherwise spam). */
function log_once(key, msg) {
	const k = 'n_' + key;
	if (S[k] == msg)
		return;
	S[k] = '' + msg;
	log(msg);
}

function once_clear(key) {
	S['n_' + key] = null;
}

function stage(st, note) {
	S.stage = st;
	S.stage_note = (note != null) ? '' + note : '';
	S.stage_ts = time();
	wstat();
}

/* Make a loaded (possibly older-shape) state object complete. */
function state_ensure() {
	if (type(S.log) !== 'array') S.log = [];
	if (type(S.tried) !== 'object' || S.tried == null) S.tried = {};
	if (type(S.resources) !== 'object' || S.resources == null) S.resources = {};
	for (let r in RES_KEYS) {
		if (S.resources[r] == null)
			S.resources[r] = { mgmt: false, rule_node: null, winner: null, probe: null, strikes: 0, note: '' };
	}
	if (S.general == null)
		S.general = { winner: null, probe: null, strikes: 0, note: '' };
	if (type(S.config) !== 'object' || S.config == null) S.config = {};
	if (S.pending != null && type(S.pending) !== 'object')
		S.pending = null;
}

/* ── shell/proc helpers ─────────────────────────────────────────────── */

function popen_read(cmd) {
	const fd = popen(cmd + ' 2>/dev/null');
	let out = '';
	if (fd) { out = trim(fd.read('all') || ''); fd.close(); }
	return out;
}

function core_up() {
	return (length(popen_read('pidof hiddify-core')) > 0 ||
	        length(popen_read('pidof sing-box')) > 0);
}

/* Local wall-clock minutes since midnight — busybox `date` is TZ-aware and
 * free of the missing-strftime/os.date uncertainty in standalone ucode. */
function now_hm() {
	const out = popen_read('date +%H:%M');
	const m = match(out, /^([0-9]{1,2}):([0-9]{2})$/);
	if (m == null)
		return -1;
	return int(m[1]) * 60 + int(m[2]);
}

function window_active(cfg) {
	if (!cfg.window.on)
		return true;
	const cur = now_hm();
	if (cur < 0) {
		log_once('windate', 'the local time is unreadable — the window is treated as inactive');
		return true;
	}
	const a = cfg.window.from, b = cfg.window.to;
	if (a <= b)
		return (cur >= a && cur < b);
	return (cur >= a || cur < b);   /* wrap past midnight */
}

function has_res(list, what) {
	for (let x in list)
		if (x === what)
			return true;
	return false;
}

/* ── config ─────────────────────────────────────────────────────────── */

function cfg_read() {
	const c = cursor();
	const get = (o, d) => {
		const v = c.get('homeproxy', 'autopilot', o);
		return (v == null) ? d : '' + v;
	};
	const raw = split(get('resources', 'youtube discord telegram'), /[[:space:],]+/);
	const resources = [];
	const seen = {};
	for (let x in raw) {
		x = trim(x);
		if (length(x) && RESOURCES[x] != null && !seen[x]) {
			seen[x] = true;
			push(resources, x);
		}
	}
	const wm = match(get('window', ''), /^([0-9]{1,2}):([0-9]{2})-([0-9]{1,2}):([0-9]{2})$/);
	const window = (wm && int(wm[1]) < 24 && int(wm[3]) < 24 && int(wm[2]) < 60 && int(wm[4]) < 60 &&
		(int(wm[1]) * 60 + int(wm[2])) != (int(wm[3]) * 60 + int(wm[4])))
		? { on: true, from: int(wm[1]) * 60 + int(wm[2]), to: int(wm[3]) * 60 + int(wm[4]) }
		: { on: false };
	const ih = int(get('interval_h', '6'));
	const cm = int(get('check_min', '15'));
	const fs_ = int(get('fail_strikes', '2'));
	return {
		enabled: (get('enabled', '0') === '1'),
		resources: resources,
		set_rules: (get('set_rules', '1') === '1'),
		interval_h: (ih >= 1 && ih <= 24) ? ih : 6,
		check_min: (cm >= 5 && cm <= 180) ? cm : 15,
		fail_strikes: (fs_ >= 1 && fs_ <= 5) ? fs_ : 2,
		fuzz_mode: (get('fuzz_mode', 'quick') === 'full') ? 'full' : 'quick',
		window: window
	};
}

/* ── environment ────────────────────────────────────────────────────── */

function shape_ok(args) {
	return (length(args) && match(args, /^--[a-z]/) && !match(args, /[`$;&|<>\n]/));
}

function others_busy() {
	const o = read_json(ONESHOT);
	if (o && o.running && (time() - int(o.ts || 0) < 3600))
		return true;
	const cp = read_json(COMP_STATUS);
	if (cp && cp.running && (time() - int(cp.ts || 0) < 300))
		return true;
	return false;
}

function fuzz_running() {
	const st = read_json(FUZZ_STATUS);
	return !!(st && st.running && (time() - int(st.ts || 0)) < FUZZ_DEAD);
}

function routing_mode() {
	return '' + (cursor().get('homeproxy', 'config', 'routing_mode') || '');
}

function tgws_enabled() {
	return (cursor().get('homeproxy', 'config', 'tgws_enabled') === '1');
}

/* Rule state for a source: the FIRST enabled rule. */
function rule_node_of(src) {
	const c = cursor();
	let node = null;
	c.foreach('homeproxy', 'proxy_ru_rule', (s) => {
		if (node == null && ('' + (s.source || '')) === src && s.enabled === '1')
			node = '' + (s.node || '');
	});
	return node;
}

/* ── probe (the runner's live-probe method: router-originated HTTPS over
 * the app's own output interception = exactly how LAN clients are served) */

function probe_live(url) {
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
		`--connect-timeout 4 --max-time ${VERIFY_TMO} ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, VERIFY_TMO * 1000 + 3000);
	const parts = split(trim(readfile(cf) || ''), /[[:space:]]+/);
	const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
	const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
	return { code: code, tsec: tsec, ok: (rc === 0 && int(code) >= 200 && int(code) < 400), ts: time() };
}

/* ── fuzz ───────────────────────────────────────────────────────────── */

function wait_fuzz_owner(t0) {
	while (time() < t0 + 120) {
		const sx = read_json(FUZZ_STATUS);
		if (sx && int(sx.ts || 0) >= t0 - 2)
			return true;
		const rx = read_json(FUZZ_RESULT);
		if (rx && int(rx.ts || 0) >= t0 - 2)
			return true;
		wstat();   /* heartbeat while waiting */
		sleep(1000);
	}
	return false;
}

/* Wait for the sweep to finish; a stale running:true (the writer died)
 * breaks out after FUZZ_DEAD instead of hanging to the cap. */
function wait_fuzz(deadline) {
	while (time() < deadline) {
		const st = read_json(FUZZ_STATUS);
		if (st && st.running && (time() - int(st.ts || 0)) > FUZZ_DEAD)
			return null;
		if (st == null || !st.running) {
			const r = read_json(FUZZ_RESULT);
			if (r && r.strategies && length(r.strategies))
				return r;
			if (st == null) {
				wstat();
				sleep(2000);
				continue;
			}
			return null;
		}
		wstat();   /* heartbeat while waiting */
		sleep(10000);
	}
	return null;
}

/* Reuse a fresh ranking / wait for a running sweep / spawn one (setsid
 * when available, so a daemon respawn cannot take the sweep down). */
function ensure_ranking(cfg) {
	let fz = read_json(FUZZ_RESULT);
	const fresh = (fz && fz.strategies && length(fz.strategies) &&
		(fz.ts && (time() - int(fz.ts)) < FUZZ_FRESH));
	if (fresh) {
		log_once('fuzzreuse', 'reusing the existing fuzz ranking (younger than 6 h)');
		return fz;
	}
	if (fuzz_running()) {
		log_once('fuzzwait', 'a fuzz run is in progress — waiting for the fresh ranking…');
		return wait_fuzz(time() + FUZZ_WAIT_MAX);
	}
	const setsid = (access('/usr/bin/setsid') || access('/bin/setsid')) ? 'setsid ' : '';
	stage('fuzz', 'starting a ' + cfg.fuzz_mode + ' fuzz…');
	log('the ranking is missing or older than 6 h — starting a ' + cfg.fuzz_mode + ' fuzz');
	const t0 = time();
	system(`${setsid}sh /etc/homeproxy/scripts/zapret_fuzz.sh ${cfg.fuzz_mode} 2 >/dev/null 2>&1 &`);
	if (!wait_fuzz_owner(t0))
		return null;
	return wait_fuzz(time() + FUZZ_WAIT_MAX);
}

/* ── pick ───────────────────────────────────────────────────────────── */

function tried_prune() {
	const cut = time() - TRIED_TTL;
	for (let r in S.tried) {
		const keep = {};
		for (let a in S.tried[r])
			if (int(S.tried[r][a]) >= cut)
				keep[a] = S.tried[r][a];
		if (length(keys(keep)))
			S.tried[r] = keep;
		else
			delete S.tried[r];
	}
}

function tried_has(res, args) {
	return !!(S.tried[res] && S.tried[res][args] != null);
}

function tried_add(res, args) {
	if (!length(args))
		return;
	if (!S.tried[res])
		S.tried[res] = {};
	S.tried[res][args] = time();
	tried_prune();
}

/* Best eligible strategy for a resource tag: majority pass AND a
 * distinguishing host (a baseline pass cannot credit a strategy), ranked
 * by that host's minimal TLS (fastest = best), tie-break global score.
 * ч.109: a deep-verified strategy (page/CDN/media fetches passed) beats an
 * equal-TLS one — the resource must work AS A WHOLE, not just open. */
function pick_resource(fz, res, exclude_args) {
	const tag = RESOURCES[res].tag;
	const elig = [];
	for (let s in fz.strategies) {
		if (!shape_ok('' + (s.args || '')) || s.args == exclude_args || tried_has(res, s.args))
			continue;
		let h = null;
		for (let x in s.hosts)
			if (x.tag === tag) { h = x; break; }
		if (h && h.ok && h.dist)
			push(elig, { s: s, ms: int(h.tls_ms) || 0 });
	}
	sort(elig, (a, b) => {
		const da = (a.s.deep) ? (a.s.deep.total ? a.s.deep.ok * 1.0 / a.s.deep.total : 0) : -1;
		const db = (b.s.deep) ? (b.s.deep.total ? b.s.deep.ok * 1.0 / b.s.deep.total : 0) : -1;
		return (db - da) || (a.ms - b.ms) || (b.s.score - a.s.score);
	});
	if (!length(elig))
		return null;
	const runners = [];
	for (let i = 1; i < length(elig) && i <= 3; i++)
		push(runners, { name: elig[i].s.name, ms: elig[i].ms });
	return { name: '' + (elig[0].s.name || 'custom args'), args: '' + elig[0].s.args,
		tls_ms: elig[0].ms, score: int(elig[0].s.score) || 0, runners: runners };
}

/* General: the global ranking head (score order already encodes
 * distinguishing successes minus handshake cost). */
function pick_general(fz, exclude_args) {
	for (let s in fz.strategies) {
		if (s.ok <= 0)
			continue;
		const args = '' + (s.args || '');
		if (!shape_ok(args) || args == exclude_args || tried_has('general', args))
			continue;
		return { name: '' + (s.name || 'custom args'), args: args,
			tls_ms: int(s.avg_tls_ms) || 0, score: int(s.score) || 0, runners: [] };
	}
	return null;
}

/* The general tail when 'general' is NOT managed: adopt the user's manual
 * single-block strategy, else the global ranking best. */
function tail_for(cfg, fz) {
	if (has_res(cfg.resources, 'general'))
		return null;
	const cur = '' + (cursor().get('homeproxy', 'config', 'zapret_cmd_opts') || '');
	if (length(cur) && shape_ok(cur) && index(cur, '--new') < 0)
		return { name: 'current (adopted)', args: cur, tls_ms: 0, score: 0, runners: [] };
	return fz ? pick_general(fz, null) : null;
}

/* ── rules (through the EXISTING preset RPC — single guard set) ─────── */

function wait_core(cap) {
	const t0 = time();
	let seen = 0;
	while ((time() - t0) < (cap || CORE_WAIT_MAX)) {
		wstat();   /* heartbeat while waiting */
		sleep(5000);
		if (core_up()) {
			seen++;
			if (seen >= 2)
				return true;
		} else {
			seen = 0;
		}
	}
	return false;
}

function preset_apply(src, node) {
	const payload = sprintf('{"source":%.J,"node":%.J,"urltest_nodes":[]}', src, node);
	const out = popen_read(`ubus call luci.homeproxy wizard_preset_apply ${sq(payload)}`);
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	return !!(pr && pr.result);
}

/* Ensure the managed resources' rules lead to Zapret. The RPC regenerates
 * the config and RELOADS the service (a full stop/start that kills this
 * daemon) — the pending journal makes the respawn resume cleanly. */
function ensure_rules(cfg) {
	const rm = routing_mode();
	if (rm !== 'proxy_banned_ru') {
		log_once('rulesmode', 'routing rules apply only in the "Bypass blocking" mode — set_rules is paused (' + rm + ')');
		return;
	}
	once_clear('rulesmode');
	for (let res in cfg.resources) {
		if (res === 'general')
			continue;
		if (res === 'telegram' && S.tgws) {
			log_once('tgrule', 'telegram is served by the tg-ws bridge — its rule is not touched');
			continue;
		}
		const node = rule_node_of(res);
		S.resources[res].rule_node = node;
		if (node === 'zapret-out')
			continue;
		S.pending = { kind: 'rule', ts: time(), src: res };
		stage('rule', 'setting the ' + res + ' rule → Zapret (the service reloads)…');
		log('the ' + res + ' rule does not lead to Zapret (' + (node || 'no rule') + ') — setting it → Zapret');
		const ok = preset_apply(res, 'zapret-out');
		if (ok) {
			wait_core(45);
			S.resources[res].rule_node = 'zapret-out';
			S.resources[res].note = '';
			log('the ' + res + ' rule now leads to Zapret');
		} else {
			S.resources[res].note = 'the rule was NOT changed (preset apply failed)';
			log('the ' + res + ' rule was NOT changed (preset apply failed)');
		}
		S.pending = null;
		wstat();
	}
}

/* ── apply (through the EXISTING compose RPCs — snapshot/Restore intact) */

function compose_build(profiles) {
	const payload = sprintf('{"profiles":%.J}', profiles);
	const out = popen_read(`ubus call luci.homeproxy wizard_compose_build ${sq(payload)}`);
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	if (!(pr && pr.result))
		return { error: (pr && pr.error) || 'compose build failed' };
	return { zapret: '' + (pr.zapret || ''), byedpi: '' + (pr.byedpi || ''), notes: pr.notes || [] };
}

function compose_apply(zapret) {
	const payload = sprintf('{"zapret":%.J,"byedpi":""}', zapret);
	const out = popen_read(`ubus call luci.homeproxy wizard_compose_apply ${sq(payload)}`);
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	return !!(pr && pr.result);
}

function compose_rollback() {
	const out = popen_read('ubus call luci.homeproxy wizard_compose_rollback');
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	return !!(pr && pr.result);
}

/* Probes BEFORE an apply — the honest was_ok baseline for the regression
 * check (a resource that already fails cannot "regress"). Only MANAGED
 * resources are probed: the others are served by their own paths (e.g.
 * tg-ws), the auto-pilot does not touch them. */
function preapply_probe(cfg) {
	const was = {};
	for (let res in cfg.resources) {
		if (res !== 'general' && !S.resources[res].mgmt)
			continue;
		was[res] = probe_live(RESOURCES[res].url).ok;
	}
	return was;
}

/* Post-apply verification: a resource that was OK and now fails is a
 * regression → server rollback + the winner into tried-failed. */
function resume() {
	const p = S.pending;
	if (!p)
		return;
	if ((time() - int(p.ts || 0)) > PENDING_TTL) {
		S.pending = null;
		log('an orphaned pending record was dropped');
		wstat();
		return;
	}
	if (p.kind === 'rule') {
		wait_core(60);
		if (p.src && rule_node_of(p.src) === 'zapret-out')
			S.resources[p.src].rule_node = 'zapret-out';
		S.pending = null;
		stage('watch', '');
		log('resumed after the rule change');
		wstat();
		return;
	}
	/* kind === 'compose' */
	stage('verify', 'waiting for the core, then the post-apply check…');
	if (!wait_core(CORE_WAIT_MAX)) {
		/* Keep the pending — the verify continues on the next tick. */
		wstat();
		return;
	}
	sleep(8000);
	const cur = '' + (cursor().get('homeproxy', 'config', 'zapret_cmd_opts') || '');
	if (cur != p.zapret) {
		/* The apply never landed — nothing to verify; the next cycle decides. */
		S.pending = null;
		stage('watch', '');
		log('the apply did not land — the next cycle decides again');
		S.next_cycle_ts = time() + 120;
		wstat();
		return;
	}
	const winners = p.winners || {};
	const regressed = [];
	for (let res in (p.was_ok || {})) {
		const pr = probe_live(RESOURCES[res].url);
		if (res === 'general')
			S.general.probe = pr;
		else
			S.resources[res].probe = pr;
		if ((p.was_ok[res] === true) && !pr.ok)
			push(regressed, res);
	}
	if (length(regressed)) {
		log('post-apply check FAILED for: ' + join(', ', regressed) + ' — rolling back (the Restore snapshot)');
		compose_rollback();
		wait_core(CORE_WAIT_MAX);
		for (let res in regressed) {
			if (res === 'general') {
				tried_add('general', p.general_winner ? p.general_winner.args : '');
				S.general.winner = (p.prev_general) ? p.prev_general : null;
				S.general.strikes = 0;
			} else {
				tried_add(res, winners[res] ? winners[res].args : '');
				S.resources[res].winner = (p.prev_winners && p.prev_winners[res]) ? p.prev_winners[res] : null;
				S.resources[res].strikes = 0;
			}
		}
		S.last_apply = (p.prev_apply) ? p.prev_apply : null;
	} else {
		for (let res in winners) {
			S.resources[res].winner = winners[res];
			S.resources[res].strikes = 0;
		}
		if (p.general_winner) {
			S.general.winner = p.general_winner;
			S.general.strikes = 0;
		}
		S.last_apply = { ts: time(), zapret: p.zapret, winners: winners,
			general: (p.general_winner) ? p.general_winner.name : null };
		const names = [];
		for (let res in winners)
			push(names, res + ' → ' + (winners[res] ? winners[res].name : '?'));
		if (p.general_winner)
			push(names, 'general → ' + p.general_winner.name);
		log('applied: ' + join(' · ', names));
	}
	S.pending = null;
	S.next_cycle_ts = time() + ((S.config && S.config.interval_h) ? S.config.interval_h : 6) * 3600;
	S.next_check_ts = time() + 180;
	S.error = '';
	stage('watch', '');
	wstat();
}

/* Build the target profiles and apply. The service restart kills this
 * daemon right after the apply — the respawn resumes the verification
 * from the pending journal written BEFORE the apply. */
function apply_target(cfg, target) {
	const was_ok = preapply_probe(cfg);
	const profiles = [];
	for (let res in RES_KEYS) {
		if (!has_res(cfg.resources, res) || res === 'general')
			continue;
		const w = target.resources[res];
		if (w && w.args)
			push(profiles, { engine: 'zapret', resource: res, strategy: w.args });
	}
	if (target.general && target.general.args)
		push(profiles, { engine: 'zapret', resource: 'general', strategy: target.general.args });
	if (!length(profiles)) {
		log('the target composition is empty — nothing to apply');
		return false;
	}
	const built = compose_build(profiles);
	if (built.error) {
		log('compose build failed: ' + built.error);
		return false;
	}
	const cur = '' + (cursor().get('homeproxy', 'config', 'zapret_cmd_opts') || '');
	if (built.zapret == cur) {
		log_once('uptodate', 'the composition is already up to date');
		S.next_cycle_ts = time() + cfg.interval_h * 3600;
		return false;
	}
	const target_names = [];
	for (let res in RES_KEYS) {
		const w = target.resources[res];
		if (w && has_res(cfg.resources, res) && res !== 'general')
			push(target_names, res + ' → ' + w.name);
	}
	if (target.general)
		push(target_names, 'general → ' + target.general.name);
	S.pending = {
		kind: 'compose', ts: time(), zapret: built.zapret,
		winners: (function() {
			const m = {};
			for (let res in RES_KEYS) {
				const w = target.resources[res];
				if (w && has_res(cfg.resources, res) && res !== 'general')
					m[res] = w;
			}
			return m;
		})(),
		prev_winners: (function() {
			const m = {};
			for (let res in RES_KEYS)
				m[res] = S.resources[res].winner;
			return m;
		})(),
		prev_general: S.general.winner,
		prev_apply: S.last_apply,
		general_winner: target.general,
		was_ok: was_ok,
		notes: built.notes
	};
	stage('apply', 'applying the composition — the service restarts…');
	log('applying: ' + join(' · ', target_names));
	if (length(built.notes))
		log('builder notes: ' + join(' | ', built.notes));
	compose_apply(built.zapret);
	/* If the restart kill is slow, finish the verify inline; otherwise the
	 * respawned daemon resumes from the pending journal. */
	resume();
	return true;
}

/* Rebuild the winners for the CURRENT ranking and apply when changed. */
function cycle(cfg) {
	const fz = ensure_ranking(cfg);
	if (fz == null) {
		stage('error', 'the fuzz did not finish in time');
		log('the fuzz did not finish — retrying in 30 min');
		S.next_cycle_ts = time() + 1800;
		wstat();
		return;
	}
	const target = { resources: {}, general: null };
	for (let res in cfg.resources) {
		if (res === 'general') {
			const cur = S.general.winner;
			const cand = pick_general(fz, null);
			let use = cand;
			if (cur && cand && cand.args == cur.args)
				use = null;
			else if (cur && cand && (S.general.strikes == 0) &&
				(cand.score < cur.score + GENERAL_SCORE_STEP)) {
				log_once('genhold', 'general: the current strategy stays the best within the score margin');
				use = null;
			}
			if (use)
				target.general = use;
			continue;
		}
		/* A resource whose rule does not lead to Zapret is never served by
		 * the engine — a scoped block for it would be dead weight. */
		if (!S.resources[res].mgmt) {
			log_once('nomgmt_' + res, res + ': the rule does not lead to Zapret — skipped in the composition (repoint the rule or enable "Keep the rules")');
			continue;
		}
		const cur = S.resources[res].winner;
		const cand = pick_resource(fz, res, null);
		let use = cand;
		if (cur && cand && cand.args == cur.args)
			use = null;
		else if (cur && cand && (S.resources[res].strikes == 0) &&
			cand.tls_ms > 0 && cur.tls_ms > 0 &&
			cand.tls_ms >= int(cur.tls_ms * (100 - MARGIN_PCT) / 100)) {
			log_once('hold_' + res, res + ': the current strategy stays best within the ' + MARGIN_PCT + '% margin');
			use = null;
		}
		if (use)
			target.resources[res] = use;
		else if (cur)
			target.resources[res] = cur;   /* re-emit the unchanged winner */
		else
			log_once('nopick_' + res, res + ': nothing passed the ranking — it rides the general tail');
	}
	/* Unchanged general winner re-emit + the tail when not managed. */
	if (target.general == null && has_res(cfg.resources, 'general') && S.general.winner)
		target.general = S.general.winner;
	if (target.general == null)
		target.general = tail_for(cfg, fz);
	apply_target(cfg, target);
	S.error = '';
	S.next_cycle_ts = time() + cfg.interval_h * 3600;
	wstat();
}

/* Health repair: the resource failed fail_strikes probes in a row — pick
 * the next alternative NOW (the window does not gate a broken resource). */
function repair(cfg, res) {
	const cur = (res === 'general') ? S.general.winner : S.resources[res].winner;
	stage('fuzz', 'repairing ' + res + '…');
	const fz = ensure_ranking(cfg);
	if (fz == null) {
		stage('error', 'the fuzz did not finish in time (repair)');
		S.next_check_ts = time() + 600;
		wstat();
		return;
	}
	const alt = (res === 'general') ? pick_general(fz, cur ? cur.args : null)
		: pick_resource(fz, res, cur ? cur.args : null);
	if (!alt) {
		log_once('repair_' + res, res + ': no alternative in the ranking — keeping the current strategy');
		S.next_check_ts = time() + cfg.check_min * 60;
		stage('watch', '');
		wstat();
		return;
	}
	if (cur)
		tried_add(res, cur.args);
	log(res + ': the strategy stopped working (' + ((res === 'general') ? S.general.strikes : S.resources[res].strikes) +
		' failed checks in a row) — switching to ' + alt.name);
	const target = { resources: {}, general: null };
	for (let rr in cfg.resources) {
		if (rr === 'general') {
			target.general = (rr === res) ? alt : S.general.winner;
			continue;
		}
		target.resources[rr] = (rr === res) ? alt : S.resources[rr].winner;
	}
	if (target.general == null)
		target.general = tail_for(cfg, fz);
	if (res === 'general')
		S.general.strikes = 0;
	else
		S.resources[res].strikes = 0;
	apply_target(cfg, target);
}

/* ── per-tick probe + repair gate ───────────────────────────────────── */

function health(cfg) {
	if (access(RELOAD_MARK))
		return;
	if (!core_up()) {
		log_once('core', 'the core is down — probes are paused');
		return;
	}
	once_clear('core');
	if (fuzz_running()) {
		log_once('probehold', 'probes are paused while the fuzz occupies the CPU (false failures avoided)');
		return;
	}
	once_clear('probehold');
	for (let res in cfg.resources) {
		if (res !== 'general' && !S.resources[res].mgmt) {
			/* Not managed — its own path serves it (e.g. tg-ws); no red
			 * noise from paths the auto-pilot does not own. */
			if (S.resources[res].probe != null || S.resources[res].strikes)
				S.resources[res].probe = null;
			S.resources[res].strikes = 0;
			continue;
		}
		const meta = RESOURCES[res];
		const pr = probe_live(meta.url);
		const st = (res === 'general') ? S.general : S.resources[res];
		st.probe = pr;
		if (pr.ok) {
			if (int(st.strikes || 0) > 0)
				log(res + ': back to normal (' + pr.code + ')');
			st.strikes = 0;
			st.note = '';
		} else {
			/* Cap at the strike threshold: the repair keeps retriggering on
			 * >= while the resource stays broken, the counter must not run
			 * away (an unmanaged resource never repairs at all). */
			st.strikes = (int(st.strikes || 0) < cfg.fail_strikes)
				? int(st.strikes || 0) + 1 : cfg.fail_strikes;
			st.note = 'failed ' + st.strikes + ' check(s) in a row (' + pr.code + ')';
			log_once('fail_' + res, res + ': the live check failed (' + pr.code + ') — ' + st.strikes + '/' + cfg.fail_strikes);
		}
	}
	S.next_check_ts = time() + cfg.check_min * 60;
	wstat();
	for (let res in cfg.resources) {
		const st = (res === 'general') ? S.general : S.resources[res];
		const managed = (res === 'general')
			? (S.general.winner != null)
			: (S.resources[res].mgmt && S.resources[res].winner != null);
		if (managed && int(st.strikes) >= cfg.fail_strikes) {
			repair(cfg, res);
			return;   /* one repair per tick */
		}
	}
}

/* ── main loop ──────────────────────────────────────────────────────── */

function tick() {
	const cfg = cfg_read();
	S.config = cfg;
	S.enabled = cfg.enabled;
	S.mode = routing_mode();
	S.zapret_enabled = (cursor().get('homeproxy', 'config', 'zapret_enabled') === '1');
	S.tgws = tgws_enabled();
	tried_prune();

	if (!cfg.enabled) {
		S.pending = null;
		if (S.stage != 'idle') {
			stage('idle', 'disabled');
			log('the auto-pilot is disabled');
		} else {
			wstat();
		}
		return;
	}
	if (S.next_check_ts == 0)
		S.next_check_ts = time() + 60;
	if (S.next_cycle_ts == 0)
		S.next_cycle_ts = time() + 90;

	if (!access(NFQWS) || !S.zapret_enabled) {
		stage('idle', 'Zapret is not installed or is disabled in Node Settings');
		wstat();
		return;
	}

	if (S.pending) {
		resume();
		wstat();
		return;
	}
	if (others_busy()) {
		log_once('busy', 'a one-click auto-pick or a composition test is running — postponed');
		wstat();
		return;
	}
	once_clear('busy');

	if (cfg.set_rules) {
		ensure_rules(cfg);
		/* The ensure may have reloaded the service (and killed us — the
		 * respawn resumes from the pending journal); when we survived,
		 * the rules are aligned and the watch stage is back on. */
		if (!S.pending)
			stage('watch', '');
	}
	for (let res in cfg.resources) {
		if (res === 'general') {
			S.general.note = '';
			continue;
		}
		const node = rule_node_of(res);
		S.resources[res].rule_node = node;
		S.resources[res].mgmt = (node === 'zapret-out');
		if (node !== 'zapret-out' && !cfg.set_rules)
			log_once('mgmt_' + res, res + ': the rule does not lead to Zapret — strategy management is off for it (enable "set rules")');
		if (res === 'telegram' && S.tgws)
			log_once('tgrule', 'telegram is served by the tg-ws bridge — its rule is not touched');
	}

	health(cfg);

	if (time() >= S.next_cycle_ts) {
		if (window_active(cfg)) {
			stage('watch', '');
			cycle(cfg);   /* arms next_cycle itself (apply may kill us) */
			return;
		}
		log_once('window', 'outside the maintenance window — the scheduled re-rank waits');
	}
	wstat();
}

function main() {
	const prev = read_json(STATE);
	if (prev && type(prev) === 'object' && prev.alive)
		S = prev;
	state_ensure();
	S.alive = true;
	S.error = '';
	wstat();
	log('the auto-pilot daemon started');
	if (S.pending) {
		stage('resume', 'resuming the interrupted action…');
		resume();
	}
	while (true) {
		try {
			tick();
		} catch (e) {
			S.error = '' + e;
			stage('error', 'internal error: ' + S.error);
			log('internal error: ' + S.error);
		}
		sleep(TICK * 1000);
	}
}

main();
