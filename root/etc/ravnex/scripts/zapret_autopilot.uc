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
 *                         through its rule. (ч.200, D34b: прежняя оговорка
 *                         «Telegram пропускается, пока правилом владеет мост
 *                         tg-ws» удалена вместе с мостом.)
 *   interval_h 1..168   — scheduled re-rank interval (default 6)
 *   check_min 5..180    — health probe interval (default 15)
 *   window ''|'HH:MM-HH:MM' — scheduled re-ranks only inside the window
 *                         (the "night pick" idea). HEALTH re-picks happen
 *                         immediately — a broken resource cannot wait.
 *   fuzz_mode 'quick'|'full'
 *   fail_strikes 1..5   — failed probes in a row before a re-pick (default 2)
 *
 * State: /var/run/ravnex/zapret_autopilot.json — written ATOMICALLY on
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
 *     (majority pass, distinguishing host; ч.116: the resource's OWN deep
 *     verdict — incl. the REAL video-stream throughput — ranks first, a
 *     merely-faster handshake on an equal deep verdict does not switch)
 *     → rebuild the composition (scoped blocks + general tail) through the
 *     EXISTING wizard_compose_build/compose_apply RPCs (server snapshot,
 *     the Restore button keeps working) → post-verify. A resource that was
 *     OK before and fails after the apply → automatic rollback and the
 *     winner goes into the tried-failed list (24 h TTL).
 *   - health re-pick: fail_strikes DEAD probes in a row → the next
 *     alternative (excluding tried-failed and the current one) applies NOW.
 *     ч.116: a probe covers the WHOLE resource — for YouTube that includes
 *     the media hosts and the REAL video-stream throughput (a page probe
 *     alone passes while TSPU throttles the video, the user's complaint).
 *     ч.127: the probe verdict is THREE-STATE — dead (no HTTP / operator
 *     stub / block page / a fully dead flow) strikes; degraded-but-alive
 *     (HTTP answers, the flow transfers under the bar) NEVER strikes and
 *     NEVER swaps the strategy the user can see working — it logs an honest
 *     note and pulls the scheduled re-rank closer (min 30 min), where the
 *     anti-flap margins decide. The fresh-connection START latency
 *     (time-to-first-byte of each flow window — the hover-preview
 *     experience) ranks strategies and enters the switch margins at 25%.
 *   - manual picks: the Strategy Lab's scoped apply hands the chosen
 *     strategy over through zapret_autopilot_manual.json; the daemon
 *     adopts it as the winner on its next tick (the user's explicit
 *     choice must not be overwritten by the next re-rank before it
 *     mattered).
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
import {
	reg_self as pm_reg_self, reg_hb as pm_reg_hb,
	find_daemons as pm_find, entry_alive as pm_entry_alive, reg_get as pm_reg_get
} from '/etc/ravnex/scripts/pmgr.uc';
/* Ф6.1 Diagnostic Core: классификация пути живёт в ЕДИНОМ классификаторе —
 * probe_live ниже приспосабливает форму classify_path к трёхсостоянию
 * автопилота; сигнатуры блок-страниц больше НЕ копируются сюда (аудит 72:
 * один классификатор вместо нескольких несовместимых). */
import { classify_path } from '/etc/ravnex/scripts/diag_core.uc';
/* Ф7.3: решения автопилота — события в общей шине (центр событий LuCI и
 * лента «Журналы» на странице автоматизации). Best-effort: сломанная шина
 * никогда не роняет демона (тот же контракт, что у log()). */
import { emit as ev_emit } from '/etc/ravnex/scripts/eventbus.uc';

const RUN_DIR = '/var/run/ravnex';
const STATE = RUN_DIR + '/zapret_autopilot.json';
const FUZZ_STATUS = RUN_DIR + '/zapret_fuzz.json';
const FUZZ_RESULT = RUN_DIR + '/zapret_fuzz_result.json';
const ONESHOT = RUN_DIR + '/wizard_autopick.json';
const COMP_STATUS = RUN_DIR + '/wizard_compose_result.json';
const RELOAD_MARK = RUN_DIR + '/.reload_running';
const NFQWS = '/opt/zapret2/nfq2/nfqws2';

const RESOURCES = {
	youtube:  { tag: 'yt', url: 'https://www.youtube.com', host: 'www.youtube.com',
		/* ч.116: the health check covers the WHOLE resource — the page alone
		 * passes while TSPU throttles the video stream (the user's exact
		 * complaint: «страница открывается, а видео грузится вечность»).
		 * ч.236: the redirector root edge-probe is REMOVED — edge-dominated
		 * (a swallowed edge failed the matrix and churned repairs while
		 * devices worked, the ч.235 class); the stream is measured by
		 * probe_flow() — the REAL sustained stream. */
		deep: [ 'https://i.ytimg.com/generate_204' ] },
	discord:  { tag: 'dc', url: 'https://discord.com', host: 'discord.com' },
	telegram: { tag: 'tg', url: 'https://web.telegram.org', host: 'web.telegram.org' },
	general:  { tag: null, url: 'http://www.gstatic.com/generate_204', host: 'gstatic generate_204' }
};
const RES_KEYS = ['youtube', 'discord', 'telegram', 'general'];
const MANUAL_FILE = RUN_DIR + '/zapret_autopilot_manual.json';

const TICK = 60;                /* main loop step, s                     */
const FUZZ_FRESH = 6 * 3600;    /* reuse a ranking younger than 6 h      */
const FUZZ_WAIT_MAX = 2700;     /* floor for a full fuzz wait (~45 min)  */
const FUZZ_DEAD = 900;          /* running:true with a stale ts = dead   */
const CORE_WAIT_MAX = 90;       /* cap for the service restart           */
const VERIFY_TMO = 15;          /* live-path probe --max-time (was 9: a
                                 * slow provider path answered — the old
                                 * cap graded «slow but working» as down) */
const SLOW_T = 6;               /* s: an HTTP-ok probe slower than this is
                                 * degraded (no strike), not dead         */
const PENDING_TTL = 600;        /* an unclaimed pending older than this is
                                 * orphaned (the restart must be over)   */
const TRIED_TTL = 24 * 3600;    /* tried-and-failed memory               */
const MARGIN_PCT = 10;          /* anti-flap: a switch needs a >10% win  */
const START_MARGIN_PCT = 25;    /* anti-flap: START-latency switch needs a
                                 * bigger win (fresh-connection TTFB is
                                 * bursty; a persistent slow start is what
                                 * the user feels, a single burst is not) */
const GENERAL_SCORE_STEP = 100; /* general: +1 distinguishing host       */

/* Ф6.7 (автопилот v4): Hot Swap 9 — ручные пики и ручные композиции
 * сохраняются. Внешняя/ручная смена zapret_cmd_opts (пользователь из UI или
 * применение из Лаборатории) ставит manual_hold: ПЛАНОВАЯ переразметка
 * удержана, живые проверки и ремонт умершего ресурса работают как раньше. */
const MANUAL_HOLD_TTL = 7 * 24 * 3600;  /* удержа недели — дальше честный лог   */
const NIGHT_FROM = 60;          /* ночной автоподбор: 01:00 (мин)          */
const NIGHT_TO = 360;           /* …06:00 (мин)                            */

/* ч.127 honesty: TSPU/operator verdicts the old probe missed. A cross-host
 * redirect to a known stub host or a SMALL 200 body carrying a refusal
 * signature is a blocked resource (strike-worthy); the strongest hosts of
 * automation.uc's STUB_REDIRECT_HOSTS and BLOCK_SIGNATURES lists. The size
 * gate (a real YouTube page is huge, a stub is tiny) keeps the signature
 * scan from ever inventing a false failure on a real page. */
const STUB_HOSTS = [
	'warning.rt.ru', 'blocked.mts.ru', 'blocked.beeline.ru', 'stop.deti.mail.ru',
	'warningrt.ru', 'rkn.gov.ru', 'blocklist.rkn.gov.ru', 'eais.rkn.gov.ru',
	'blocked.tele2.ru', 'blocked.megafon.ru', 'block.domru.ru', 'warning.ttk.ru'
];
/* Подписи блок-страниц больше НЕ копируются сюда: единый источник —
 * BLOCK_SIGNATURES в diag_core.uc (Ф6.1), probe_live классифицирует через
 * classify_path (аудит 72). */

/* ── module state (persisted through wstat) ─────────────────────────── */
let S = {
	alive: true, ts: 0,
	enabled: false,
	stage: 'idle', stage_note: '', stage_ts: 0,
	error: '',
	pending: null,
	config: {},
	mode: '', zapret_enabled: false,
	resources: {},
	general: { winner: null, probe: null, strikes: 0, note: '' },
	last_apply: null,
	tried: {},
	/* s179 (user decision «вердикт + 2 прогона»): per-resource two-run lab
	 * agreement + the ts of the fuzz result last seen by tick(). */
	lab_agree: {},
	last_fuzz_ts: 0,
	next_check_ts: 0, next_cycle_ts: 0,
	log: [],
	manual_hold: null            /* Ф6.7: { ts, src } — Hot Swap 9 */
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

/* ── ч.232: метки С УСТРОЙСТВА — наивысший вес переразметки ─────────────
 * Проба-модель лаборатории не видит ClientHello браузера/телефона, QUIC-
 * фоллбек и паттерн соединений — живой факт 2026-11-07: лабораторный
 * best_verified Default опровергнут телефоном, реально работающая стратегия
 * в лидеры не попадала. Метки хранит /etc/ravnex/device_verdicts.json:
 * 'broken' исключает кандидата из подбора; 'works' поднимает кандидата над
 * лабораторным порядком и удерживает текущего победителя от плановой замены
 * лабораторным лидером без подтверждения устройством. Кэш перечитывается на
 * каждой плановой переразметке (метка пользователя вступает в силу сразу).
 * Объявлено НИЖЕ read_json: ucode не имеет hoisting (урок 2/93/126/ч.231). */
const DEV_FILE = '/etc/ravnex/device_verdicts.json';
let DEV_CACHE = {};
function dev_reload() {
	DEV_CACHE = {};
	const dj = read_json(DEV_FILE);
	if (dj != null && type(dj.resources) === 'object')
		DEV_CACHE = dj.resources;
}
function dv_of(res, args) {
	const dm = DEV_CACHE['' + res];
	if (type(dm) !== 'object')
		return '';
	const mv = dm['' + (args || '')];
	return (mv != null && type(mv) === 'object') ? ('' + (mv.verdict || '')) : '';
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

/* Ф7.3: событие шины по КРАЮ решения (не по тику). who/detail — русские
 * строки в исходнике (правило бэкенд-строк). Вызывается ПОСЛЕ wstat-точек
 * принятия решения — detail объясняет, что произошло и что с этим делать. */
function ap_emit(type, who, detail) {
	try { ev_emit('autopilot', type, who || '', detail || ''); } catch (e) { /* best-effort */ }
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
	/* Ф1.4b: identity liveness — the registry entry first, then the exact
	 * /proc scan. The lite build runs as sing-box-core (the bare pidof of
	 * the old code missed it entirely). */
	const cre = pm_reg_get('core');
	if (cre != null && pm_entry_alive(cre))
		return true;
	return length(pm_find({ exe: 'hiddify-core' })) > 0 ||
	       length(pm_find({ exe: 'sing-box' })) > 0 ||
	       length(pm_find({ exe: 'sing-box-core' })) > 0;
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
		log_once('windate', 'локальное время нечитаемо — окно считается неактивным');
		return true;
	}
	const a = cfg.window.from, b = cfg.window.to;
	if (a <= b)
		return (cur >= a && cur < b);
	return (cur >= a || cur < b);   /* wrap past midnight */
}

/* Ф6.7: ночной автоподбор (01:00–06:00) — опция; плановая переразметка
 * разрешена ночью даже вне окна обслуживания, применяет только «лучше»
 * (антифлап-марджины в cycle() остаются фильтром). */
function night_active(cfg) {
	if (!cfg.night_pick)
		return false;
	const cur = now_hm();
	if (cur < 0)
		return false;
	return (cur >= NIGHT_FROM && cur < NIGHT_TO);
}

/* Ф6.7: объяснимый вердикт решения — живёт в состоянии ресурса, UI
 * показывает его строкой под winner'ом (не чёрный ящик, аудит A.2). */
function explain(res, text) {
	const st = (res === 'general') ? S.general : S.resources[res];
	if (st == null)
		return;
	st.explain = { ts: time(), text: '' + text };
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
		const v = c.get('ravnex', 'autopilot', o);
		return (v == null) ? d : '' + v;
	};
	/* ч.233: telegram УБРАН из автопилота (решение пользователя: без VPN/
	 * туннеля Telegram в РФ не поднимается — автоперебор стратегий лишь тратит
	 * время; владение стратегией у пользователя). Фильтр ниже гарантирует, что
	 * даже УСТАРЕВШИЙ UCI-список с telegram не вернёт tg в управление. */
	const raw = split(get('resources', 'youtube discord general'), /[[:space:],]+/);
	const resources = [];
	const seen = {};
	for (let x in raw) {
		x = trim(x);
		if (x === 'telegram') {
			log_once('tg_removed', 'telegram: автоподбор отключён (решение пользователя) — из ресурсов автопилота исключён, стратегию для Telegram подбирают вручную');
			continue;
		}
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
		interval_h: (ih >= 1 && ih <= 168) ? ih : 6,
		check_min: (cm >= 5 && cm <= 180) ? cm : 15,
		fail_strikes: (fs_ >= 1 && fs_ <= 5) ? fs_ : 2,
		fuzz_mode: (get('fuzz_mode', 'quick') === 'full') ? 'full' : 'quick',
		window: window,
		night_pick: (get('night_pick', '0') === '1')
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
	/* Ф3.1: legacy custom/custom_json read as the working mode (D23); a
	 * missing/empty value is the working mode too (lesson 209 — one default
	 * in every reader). */
	const rm = '' + (cursor().get('ravnex', 'config', 'routing_mode') || 'proxy_banned_ru');
	return (rm === 'custom' || rm === 'custom_json') ? 'proxy_banned_ru' : rm;
}

/* Rule state for a source: the FIRST enabled rule. */
function rule_node_of(src) {
	const c = cursor();
	let node = null;
	c.foreach('ravnex', 'proxy_ru_rule', (s) => {
		if (node == null && ('' + (s.source || '')) === src && s.enabled === '1')
			node = '' + (s.node || '');
	});
	return node;
}

/* ── probe (the runner's live-probe method: router-originated HTTPS over
 * the app's own output interception = exactly how LAN clients are served)
 *
 * ч.127: the verdict is THREE-STATE. A resource that answers HTTP (2xx/3xx)
 * is ALIVE even when the router-side curl hit the transfer cap mid-body —
 * the browser user sees the same slow-but-working page; grading that as
 * «unavailable» switched away strategies the user could see working.
 *   dead = no HTTP answer (000), an operator stub redirect, or a small
 *          block-page body (strike-worthy — the resource is really gone);
 *   slow = alive but degraded (tsec ≥ SLOW_T or the transfer did not
 *          finish — honest note, NO strike, an earlier re-rank instead);
 *   ok   = everything else. */
function url_host(u) {
	const m = match('' + u, /^[a-zA-Z]+:\/\/([^\/]+)/);
	return (m && m[1]) ? m[1] : '';
}

function is_stub_host(h) {
	h = lc(trim('' + h));
	if (!length(h))
		return false;
	for (let s in STUB_HOSTS) {
		if (h === s)
			return true;
		const n = length(h) - length(s) - 1;
		if (n > 0 && substr(h, n) === '.' + s)
			return true;
	}
	return false;
}

function probe_live(url) {
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total} %{url_effective}' -k ` +
		`--connect-timeout 6 --max-time ${VERIFY_TMO} ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, VERIFY_TMO * 1000 + 3000);
	const parts = split(trim(readfile(cf) || ''), /[[:space:]]+/);
	const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
	const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
	const eff = (length(parts) > 2) ? ('' + parts[2]) : '';
	/* Ф6.3 (63/86): классификация — через ЕДИНЫЙ Diagnostic Core. Гео-отказ
	 * в HTTP 200 (маркеры в теле) и 451 теперь СТАВЯТ dead — раньше такой
	 * ответ читался успехом и автопилот бесконечно держал стратегию, которая
	 * ресурс не доставляет. Голый 403/406 БЕЗ маркеров — НЕ dead (55: origin
	 * может отказать легально; доказательства DPI/гео нет) — честная
	 * деградация с пояснением, не «неудачная проверка». WAF-challenge/429/5xx
	 * — путь открыт, приложение не обслуживает (деградация). */
	const cp = classify_path({ code: code, tsec: tsec, rc: rc, body: readfile(bf) || '' },
		false, null);
	let dead = false;
	let refused = false;
	let note = '';
	if (cp.app_state === 'blockpage') {
		dead = true;
		note = 'страница-заглушка (стиль блокировки)';
	} else if (cp.app_state === 'geo_refused') {
		dead = true;
		refused = true;
		note = (cp.geo_via === '451')
			? 'юридический гео-отказ источника (451) — регион выхода не обслуживается'
			: 'гео-отказ источника (регион выхода не обслуживается)';
	} else if (cp.app_state === 'waf_challenge') {
		note = 'challenge-страница WAF — путь открыт, клиентская форма запроса не проходит';
	} else if (cp.app_state === 'waf_rate_limit') {
		note = 'источник ограничивает частоту (429) — путь открыт';
	} else if (cp.app_state === 'waf_origin_denied') {
		note = 'отказ ' + (code || '?') + ' без маркеров гео/WAF — политика источника к выходу, не доказательство блокировки';
	} else if (cp.app_state === 'server_error') {
		note = 'источник отвечает ' + (code || '?') + ' — путь открыт, сервис не обслуживает';
	} else if (cp.app_state === 'ok') {
		const n = int(code) || 0;
		if (n >= 400) {
			/* 404/421: путь открыт, но ресурс не отдаёт контент — для
			 * автопилота это деградация, не успех. */
			note = 'путь открыт, ресурс отвечает ' + code + ' без контента';
		}
	} else {
		/* cls fail: ответа нет — транспортная причина в kind. */
		dead = true;
		note = 'нет HTTP-ответа (' + (cp.kind || 'транспорт') + ')';
	}
	if (!dead && length(eff)) {
		const oh = url_host(url), eh = url_host(eff);
		if (length(oh) && length(eh) && oh !== eh && is_stub_host(eh)) {
			dead = true;
			note = 'редирект на заглушку оператора (' + eh + ')';
		}
	}
	/* ok = ресурс ДОСТАВЛЕН (2xx/3xx без маркеров отказа) — не «путь открыт». */
	const ok = (!dead && cp.app_state === 'ok' && (int(code) || 0) >= 200 && (int(code) || 0) < 400);
	const slow = (ok && (((tsec != null) && (tsec + 0) >= SLOW_T) || rc != 0));
	return { code: code, tsec: tsec, ok: ok, dead: dead, refused: refused,
		waf: cp.waf, slow: slow, note: note, ts: time() };
}

/* ч.116: the SUSTAINED-FLOW throughput probe (the LIVE path, the shared
 * yt_flow_probe.sh — 24 real thumbnails over ONE keep-alive TLS flow to
 * i.ytimg.com, Σbytes/Σtime). TSPU lets the handshake through and throttles
 * the flow — a page probe cannot see it, this can. null = the probe did not
 * run (no ids file); ok:false = throttled (honest). ч.127: the answer also
 * carries start_ms — the time-to-first-byte of each window's FIRST transfer
 * (a fresh connection: TCP+TLS+request+first byte) — the hover-preview
 * latency the user pointed at. */
function probe_flow() {
	const of = RUN_DIR + '/autopilot_flow.json';
	system(`sh /etc/ravnex/scripts/yt_flow_probe.sh > ${sq(of)} 2>/dev/null`, 30000);
	const j = read_json(of);
	system(`rm -f ${sq(of)} 2>/dev/null`);
	if (j == null || type(j) !== 'object')
		return null;
	return { ok: (j.ok == 1), code: '' + (j.code || '0'), speed: int(j.speed || 0),
		bytes: int(j.bytes || 0), secs: j.secs, fetched: int(j.fetched || 0),
		start_ms: int(j.start_ms || 0) };
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

/* Rough seconds-to-finish estimate from a live fuzz status (the same
 * formula the one-shot auto-pick uses): resolve+baseline + unmeasured
 * strategies × rounds × ~55 s + the deep-battery tail. ч.123: a full sweep
 * honestly takes up to a few hours — the daemon POSTPONES its cycle instead
 * of blocking the health checks for that long. */
function fuzz_remaining_est(st) {
	if (st == null || int(st.total || 0) <= 0)
		return 0;
	const done = int(st.done || 0);
	const rem = int(st.total) - done;
	if (rem <= 0)
		return 700;   /* the deep battery tail */
	return 60 + rem * int(st.rounds || 2) * 55 + 600;
}

/* Reuse a fresh ranking / wait for a running sweep / spawn one (setsid
 * when available, so a daemon respawn cannot take the sweep down).
 * ч.123: when the running sweep needs more than the wait floor, the cycle
 * is POSTPONED (ENSURE_POSTPONED) instead of blocking — the sweep keeps
 * running and a later tick re-evaluates; health probes stay on schedule. */
let ENSURE_POSTPONED = false;
function ensure_ranking(cfg) {
	ENSURE_POSTPONED = false;
	let fz = read_json(FUZZ_RESULT);
	const fresh = (fz && fz.strategies && length(fz.strategies) &&
		(fz.ts && (time() - int(fz.ts)) < FUZZ_FRESH));
	if (fresh) {
		log_once('fuzzreuse', 'использую существующий рейтинг фаззинга (моложе 6 ч)');
		return fz;
	}
	if (fuzz_running()) {
		const rem = fuzz_remaining_est(read_json(FUZZ_STATUS));
		if (rem > FUZZ_WAIT_MAX) {
			ENSURE_POSTPONED = true;
			log_once('fuzzskip', 'идёт долгий прогон (~' + int(rem / 60) +
				' мин до конца) — переразметка продолжится после него; проверки здоровья идут');
			return null;
		}
		log_once('fuzzwait', 'идёт прогон фаззинга — жду свежий рейтинг (~' +
			int(rem / 60) + ' мин до конца)…');
		return wait_fuzz(time() + rem + 300);
	}
	const setsid = (access('/usr/bin/setsid') || access('/bin/setsid')) ? 'setsid ' : '';
	stage('fuzz', 'запускаю ' + ((cfg.fuzz_mode === 'full') ? 'полный' : 'быстрый') + ' фаззинг…');
	log('рейтинга нет или он старше 6 ч — запускаю ' +
		((cfg.fuzz_mode === 'full') ? 'полный' : 'быстрый') + ' фаззинг');
	const t0 = time();
	system(`${setsid}sh /etc/ravnex/scripts/zapret_fuzz.sh ${cfg.fuzz_mode} 2 >/dev/null 2>&1 &`);
	if (!wait_fuzz_owner(t0))
		return null;
	const rem = fuzz_remaining_est(read_json(FUZZ_STATUS));
	if (rem > FUZZ_WAIT_MAX) {
		ENSURE_POSTPONED = true;
		log('прогону нужно ~' + int(rem / 60) + ' мин — демон продолжит цикл после него (прогон не прерывается)');
		return null;
	}
	return wait_fuzz(time() + rem + 300);
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

/* s179 (user decision «вердикт + 2 прогона»): the lab VERDICT outranks the
 * raw rating head for a resource. The rating favors the incumbent on
 * noise-level differential probes ("probes identical do not rank") and the
 * anti-flap margins then lock the incumbent forever (live 2026-11-09:
 * Default kept while the verdict proved fakedsplit). Here the
 * best_verified winner of the Strategy Lab IS the candidate — but a swap
 * needs TWO consecutive fresh runs agreeing (n>=2, counted per result ts:
 * a reused file never double-counts). Device/tried guards apply at the
 * call site. Returns a winner-shaped cand with verdict_pick=true, or null
 * (no verdict / not yet agreed / incumbent already the winner). */
function verdict_pick(res, labv, cur, fts) {
	if (type(S.lab_agree) !== 'object')
		S.lab_agree = {};
	const lv = (labv != null && type(labv[res]) === 'object') ? labv[res] : null;
	if (lv == null || lv.verdict !== 'best_verified' || lv.chosen == null)
		return null;
	const args = '' + (lv.chosen.args || '');
	if (!length(args) || !match(args, /^--[a-z]/))
		return null;
	if (cur && ('' + cur.args) === args) {
		S.lab_agree[res] = null;
		return null;
	}
	let ag = S.lab_agree[res];
	if (ag == null || type(ag) !== 'object' || ag.args !== args)
		ag = { args: args, name: '' + (lv.chosen.name || ''), n: 0, ts: fts };
	if (ag.ts != fts) {
		ag.n++;
		ag.ts = fts;
	}
	S.lab_agree[res] = ag;
	if (ag.n < 2)
		return null;
	return {
		name: (ag.name || 'lab verdict winner'),
		args: args,
		tls_ms: int(lv.chosen.tls_ms || 0),
		score: int(lv.chosen.score || 0),
		verdict_pick: true
	};
}

/* The resource's OWN deep verdict (differential-only items — the fuzzer
 * filters probe items identical across all deep-tested strategies).
 * null = not deep-tested for this resource; a 0..1 ratio otherwise. */
function deep_ratio_of(s, tag) {
	if (s.deep == null || type(s.deep) !== 'object' || type(s.deep.hosts) !== 'array')
		return null;
	for (let h in s.deep.hosts)
		if (type(h) === 'object' && h.tag === tag && int(h.deep_total || 0) > 0)
			return (int(h.deep_pass || 0) * 1.0) / int(h.deep_total);
	return null;
}

/* Best eligible strategy for a resource tag: majority pass AND a
 * distinguishing host (a baseline pass cannot credit a strategy).
 * ч.116 ranking: the resource's OWN deep verdict ranks FIRST (deep-verified
 * passes above untested, deep-failed below untested), then that host's
 * minimal TLS, then the global score. The old TLS-first order promoted
 * handshake-fast strategies that throttle the actual video stream (the
 * user report: Multisplit beat Hostfakesplit on the handshake while the
 * video crawled). */
function pick_resource(fz, res, exclude_args) {
	const tag = RESOURCES[res].tag;
	const elig = [];
	for (let s in fz.strategies) {
		if (!shape_ok('' + (s.args || '')) || s.args == exclude_args || tried_has(res, s.args))
			continue;
		/* ч.232: кандидат, опровергнутый на устройстве, подбором не берётся
		 * (метка сильнее лаборатории). */
		if (dv_of(res, '' + (s.args || '')) === 'broken')
			continue;
		let h = null;
		for (let x in s.hosts)
			if (x.tag === tag) { h = x; break; }
		if (h && h.ok && h.dist) {
			const dr = deep_ratio_of(s, tag);
			let dp = null, dt = null, stm = 0, stms = 0;
			if (s.deep && type(s.deep.hosts) === 'array')
				for (let dh in s.deep.hosts)
					if (type(dh) === 'object' && dh.tag === tag) {
						if (int(dh.deep_total || 0) > 0) {
							dp = int(dh.deep_pass || 0);
							dt = int(dh.deep_total);
						}
						stm = int(dh.stream || 0);
						stms = int(dh.start_ms || 0);
					}
			push(elig, { s: s, ms: int(h.tls_ms) || 0, deep: dr,
				deep_pass: dp, deep_total: dt, stream: stm, start: stms,
				revive: int(s.dead_edge_revive || 0) });
		}
	}
	/* ч.116 ranking: a MEASURED strategy ranks first — the resource's own
	 * deep verdict or the sustained video flow speed (the TLS handshake
	 * time does not predict the throttled flow — the live ч.116 comparison:
	 * Multisplit 306 KB/s vs Syndata 555 KB/s at a 3 ms handshake
	 * difference). deep-failed ranks last. When the differential deep
	 * totals zero out (every probe identical across the deep-tested
	 * strategies), the stream measurement still separates the tested
	 * strategies from the untested ones.
	 * ч.129: the fresh-connection START latency (the hover-preview metric,
	 * «навожу на карточку — превью не стартует») is what the user FEELS
	 * first — a >25% better START wins outright; a smaller gap is bursty
	 * TSPU noise (tie). The sustained flow decides next at a >10% gap,
	 * then the handshake. The old order (flow first, START only inside a
	 * 10% flow tie) kept a fast-bulk/slow-start strategy on top — exactly
	 * the user's complaint; a measured stream still beats an untested one.
	 * ч.232: device-confirmed ('works') outranks the whole lab order —
	 * the only evidence class that sees what the phone sees. */
	const dband = (e) => (dv_of(res, e.s.args) === 'works') ? 0 : 1;
	const band = (e) => (((e.deep != null) && (e.deep > 0)) ||
		((e.deep == null) && (int(e.stream || 0) > 0))) ? 0
		: (((e.deep != null) && (e.deep == 0)) ? 2 : 1);
	sort(elig, (a, b) => {
		const da = dband(a), dbb = dband(b);
		if (da != dbb)
			return da - dbb;
		/* ч.270: оживление мёртвого края — первосортный дифференцирующий
		 * признак, вес ВЫШЕ band: стратегия, оживившая ≥1 «мёртвый» край
		 * матрицы под собой, выигрывает ничью band'ов сразу (живое
		 * доказательство сеанса 182: .48 оживает под Hostfakesplit, мёртв
		 * под fakedsplit catch-all — смерть края shaped-зависима). */
		const ra = int(a.revive || 0), rb = int(b.revive || 0);
		if (ra != rb)
			return rb - ra;
		const ba = band(a), bb = band(b);
		if (ba != bb)
			return ba - bb;
		const da = (a.deep == null) ? -1 : a.deep;
		const db_ = (b.deep == null) ? -1 : b.deep;
		if (da != db_)
			return db_ - da;
		const ta = int(a.start || 0), tb = int(b.start || 0);
		if (ta > 0 && tb > 0 && ta != tb) {
			const hi = (ta > tb) ? ta : tb, lo = (ta > tb) ? tb : ta;
			if (hi - lo > int(hi / 4))
				return ta - tb;
		}
		const sa = int(a.stream || 0), sb = int(b.stream || 0);
		if (sa != sb) {
			if (sa > 0 && sb > 0) {
				const hi = (sa > sb) ? sa : sb, lo = (sa > sb) ? sb : sa;
				if (hi - lo > int(hi / 10))
					return sb - sa;
			} else if (sa > 0 || sb > 0)
				return sb - sa;
		}
		/* ч.269 (сеанс 181): tie-break по НАДЁЖНОСТИ при полной ничьей —
		 * выше ok_rate, затем ниже джиттер рукопожатий ресурсного тега.
		 * Спред/флап края = нестабильность пути: флапающая стратегия не
		 * выигрывает пустую ничью. */
		const rt = (RESOURCES[res] != null) ? RESOURCES[res].tag : null;
		const hstat = (e2) => {
			let orate = null, jit = null;
			if (rt != null && e2.s != null && type(e2.s.hosts) === 'array')
				for (let hh in e2.s.hosts) {
					if (type(hh) !== 'object' || hh.tag !== rt) continue;
					orate = (hh.ok_rate != null) ? (1.0 * hh.ok_rate) : null;
					jit = (hh.jitter_ms != null) ? int(hh.jitter_ms) : null;
					break;
				}
			return { o: orate, j: jit };
		};
		const hs_a = hstat(a), hs_b = hstat(b);
		if (hs_a.o != null && hs_b.o != null && hs_a.o != hs_b.o)
			return (hs_a.o > hs_b.o) ? -1 : 1;
		if (hs_a.j != null && hs_b.j != null && hs_a.j != hs_b.j)
			return hs_a.j - hs_b.j;
		return (a.ms - b.ms) || (b.s.score - a.s.score);
	});
	if (!length(elig))
		return null;
	const runners = [];
	for (let i = 1; i < length(elig) && i <= 3; i++)
		push(runners, { name: elig[i].s.name, ms: elig[i].ms });
	return { name: '' + (elig[0].s.name || 'кастомные аргументы'), args: '' + elig[0].s.args,
		tls_ms: elig[0].ms, deep: elig[0].deep,
		deep_pass: elig[0].deep_pass, deep_total: elig[0].deep_total,
		stream: int(elig[0].stream || 0), start_ms: int(elig[0].start || 0),
		score: int(elig[0].s.score) || 0, runners: runners };
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
		/* ч.232: опровергнутая на устройстве стратегия подбором не берётся. */
		if (dv_of('general', args) === 'broken')
			continue;
		return { name: '' + (s.name || 'кастомные аргументы'), args: args,
			tls_ms: int(s.avg_tls_ms) || 0, score: int(s.score) || 0, runners: [] };
	}
	return null;
}

/* The general tail when 'general' is NOT managed: adopt the user's manual
 * single-block strategy, else the global ranking best. */
function tail_for(cfg, fz) {
	if (has_res(cfg.resources, 'general'))
		return null;
	const cur = '' + (cursor().get('ravnex', 'config', 'zapret_cmd_opts') || '');
	if (length(cur) && shape_ok(cur) && index(cur, '--new') < 0)
		return { name: 'текущая (принята)', args: cur, tls_ms: 0, score: 0, runners: [] };
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
	/* urltest_nodes crosses as a JSON-encoded STRING (issue #11 — a string
	 * typehint is the only rpcd args policy that works on old AND strict new
	 * rpcd stacks). */
	const payload = sprintf('{"source":%.J,"node":%.J,"urltest_nodes":"[]"}', src, node);
	const out = popen_read(`ubus call luci.ravnex wizard_preset_apply ${sq(payload)}`);
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
		log_once('rulesmode', 'правила маршрутизации работают только в режиме «Обход блокировок» — держать правила приостановлено (' + rm + ')');
		return;
	}
	once_clear('rulesmode');
	for (let res in cfg.resources) {
		if (res === 'general')
			continue;
		const node = rule_node_of(res);
		S.resources[res].rule_node = node;
		if (node === 'zapret-out')
			continue;
		S.pending = { kind: 'rule', ts: time(), src: res };
		stage('rule', 'ставлю правило ' + res + ' → Zapret (служба перезагружается)…');
		log('правило ' + res + ' не ведёт на Zapret (' + (node || 'правила нет') + ') — ставлю → Zapret');
		const ok = preset_apply(res, 'zapret-out');
		if (ok) {
			wait_core(45);
			S.resources[res].rule_node = 'zapret-out';
			S.resources[res].note = '';
			log('правило ' + res + ' теперь ведёт на Zapret');
		} else {
			S.resources[res].note = 'правило НЕ изменено (применение пресета не удалось)';
			log('правило ' + res + ' НЕ изменено (применение пресета не удалось)');
		}
		S.pending = null;
		wstat();
	}
}

/* ── apply (through the EXISTING compose RPCs — snapshot/Restore intact) */

function compose_build(profiles) {
	/* profiles cross as a JSON-encoded STRING (issue #11): %.J of the JSON
	 * text embeds it as a quoted JSON string. */
	const pj = sprintf('%.J', profiles);
	const payload = sprintf('{"profiles":%.J}', pj);
	const out = popen_read(`ubus call luci.ravnex wizard_compose_build ${sq(payload)}`);
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	if (!(pr && pr.result))
		return { error: (pr && pr.error) || 'compose build failed' };
	return { zapret: '' + (pr.zapret || ''), byedpi: '' + (pr.byedpi || ''), notes: pr.notes || [] };
}

function compose_apply(zapret) {
	const payload = sprintf('{"zapret":%.J,"byedpi":""}', zapret);
	const out = popen_read(`ubus call luci.ravnex wizard_compose_apply ${sq(payload)}`);
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	return !!(pr && pr.result);
}

function compose_rollback() {
	const out = popen_read('ubus call luci.ravnex wizard_compose_rollback');
	let pr = null;
	try { pr = json(out || ''); } catch (e) { pr = null; }
	return !!(pr && pr.result);
}

/* Ресурсная матрица (аудит 64): страница + deep-хосты (+ видео-поток для
 * youtube) — ОДНА И ТА ЖЕ матрица используется health(), preapply_probe()
 * (до применения) и resume() (после): откат срабатывает при потере ЛЮБОГО
 * критичного компонента (видео/медиа-хосты), а не только главной страницы,
 * и «regression» сравнивает равные величины.
 * 🔴 СЕАНС 158/Б1: объявлена ВЫШЕ preapply_probe/resume — на этой сборке
 * ucode вызов top-level имени, объявленного НИЖЕ вызывающей функции, крашится
 * «left-hand side is not a function» в момент исполнения вызова (урок 294 в
 * полной форме, доказано t1–t7 + живой репро на UCI/стейте чужого роутера:
 * cycle() → hold_active() ниже на ~500 строк = краш каждого цикла). */
function resource_matrix(res, meta) {
	const pr = probe_live(meta.url);
	let ok_all = pr.ok;
	let dead_hit = pr.dead;
	let slow_hit = pr.slow;
	let fail_note = pr.note || '';
	if (meta.deep != null && length(meta.deep)) {
		for (let du in meta.deep) {
			const dpr = probe_live(du);
			/* ч.236: the redirector 404-tolerance special case is gone with
			 * the edge-probe itself — every deep probe is judged by dpr.ok;
			 * a dead edge can no longer fail the matrix while devices work. */
			if (ok_all && !dpr.ok) {
				ok_all = false;
				if (dpr.dead)
					dead_hit = true;
				else
					slow_hit = true;
				fail_note = 'медиа-хост не отвечает (' + dpr.code +
					(dpr.note ? (' — ' + dpr.note) : '') + '): ' + du;
			}
		}
	}
	if (res === 'youtube') {
		const fp = probe_flow();
		if (fp == null)
			log_once('ytflow', 'проба sustained-потока не выполнялась (нет файла с id)');
		else {
			once_clear('ytflow');
			pr.speed = fp.speed;
			pr.start_ms = fp.start_ms;
			const fdead = (int(fp.code || 0) === 0 || int(fp.bytes || 0) === 0 ||
				int(fp.fetched || 0) === 0);
			if (ok_all && fdead) {
				ok_all = false;
				dead_hit = true;
				fail_note = 'видео-поток мёртв (код ' + (fp.code || '0') + ', ' +
					int((fp.bytes || 0) / 1024) + ' КБ за ' + ((fp.secs != null) ? fp.secs : '?') + ' с)';
			} else if (ok_all && !fp.ok) {
				ok_all = false;
				slow_hit = true;
				fail_note = 'видео-поток медленный (' + int((fp.speed || 0) / 1024) + ' КБ/с, ' +
					int((fp.bytes || 0) / 1024) + ' КБ за ' + ((fp.secs != null) ? fp.secs : '?') +
					' с) — деградация, не смерть';
			}
		}
	}
	pr.ok = ok_all;
	pr.dead = dead_hit;
	pr.slow = (!dead_hit && slow_hit);
	if (length(fail_note))
		pr.note = fail_note;
	return pr;
}

/* Ф6.7: активна ли удержа плановой переразметки (Hot Swap 9). Без TTL —
 * снятие только явное: ремонт умершего ресурса, успешный автоподбор или
 * кнопка «Снять удержание» в автопилот-вью (сеанс 158/Б8).
 * 🔴 СЕАНС 158/Б1: объявлена ВЫШЕ cycle()/repair() (см. комментарий над
 * resource_matrix — порядок деклараций строгий, краш при вызове имени,
 * объявленного ниже вызывающей функции). */
function hold_active() {
	return !!(S.manual_hold && type(S.manual_hold) === 'object');
}

/* Probes BEFORE an apply — the honest was_ok baseline for the regression
 * check (a resource that already fails cannot "regress"). Only MANAGED
 * resources are probed: the others are served by their own paths, the
 * auto-pilot does not touch them.
 * Ф6.3 (аудит 64): baseline — ПОЛНАЯ ресурсная матрица (та же, что в
 * resume() после применения): потеря видео/медиа-компонента теперь тоже
 * регрессия, и откат сравнивает равные величины. */
function preapply_probe(cfg) {
	const was = {};
	for (let res in cfg.resources) {
		if (res !== 'general' && !S.resources[res].mgmt)
			continue;
		was[res] = resource_matrix(res, RESOURCES[res]).ok;
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
		log('осиротевшая pending-запись отброшена');
		wstat();
		return;
	}
	if (p.kind === 'rule') {
		wait_core(60);
		if (p.src && rule_node_of(p.src) === 'zapret-out')
			S.resources[p.src].rule_node = 'zapret-out';
		S.pending = null;
		stage('watch', '');
		log('продолжено после смены правила');
		wstat();
		return;
	}
	/* kind === 'compose' */
	stage('verify', 'жду ядро, затем проверка после применения…');
	if (!wait_core(CORE_WAIT_MAX)) {
		/* Keep the pending — the verify continues on the next tick. */
		wstat();
		return;
	}
	sleep(8000);
	const cur = '' + (cursor().get('ravnex', 'config', 'zapret_cmd_opts') || '');
	if (cur != p.zapret) {
		/* The apply never landed — nothing to verify; the next cycle decides. */
		S.pending = null;
		stage('watch', '');
		log('применение не доехало — следующий цикл решит заново');
		S.next_cycle_ts = time() + 120;
		wstat();
		return;
	}
	const winners = p.winners || {};
	const regressed = [];
	for (let res in (p.was_ok || {})) {
		/* Ф6.3 (аудит 64): та же матрица, что в baseline — видео/медиа
		 * входят в regression-проверку. */
		const pr = resource_matrix(res, RESOURCES[res]);
		if (res === 'general')
			S.general.probe = pr;
		else
			S.resources[res].probe = pr;
		if ((p.was_ok[res] === true) && !pr.ok)
			push(regressed, res);
	}
	if (length(regressed)) {
		log('проверка после применения ПРОВАЛЕНА для: ' + join(', ', regressed) + ' — откатываю (снапшот Restore)');
		ap_emit('rollback', 'проверка после применения провалена: ' + join(', ', regressed),
			'автопилот откатил композицию по снапшоту Restore — стратегии вернулись к прежним, живые проверки продолжаются');
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
		/* Ф6.7: применение автопилота вернуло владение композицией — удержа
		 * снята (внешние изменения после этого снова детектируются). */
		S.manual_hold = null;
		const names = [];
		for (let res in winners)
			push(names, res + ' → ' + (winners[res] ? winners[res].name : '?'));
		if (p.general_winner)
			push(names, 'general → ' + p.general_winner.name);
		log('применено: ' + join(' · ', names));
		ap_emit('applied', 'автопилот применил стратегии',
			join(' · ', names) + '; снимок Restore доступен, следующая переразметка по расписанию');
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
		log('целевая композиция пуста — применять нечего');
		return false;
	}
	const built = compose_build(profiles);
	if (built.error) {
		log('сборка композиции не удалась: ' + built.error);
		return false;
	}
	const cur = '' + (cursor().get('ravnex', 'config', 'zapret_cmd_opts') || '');
	if (built.zapret == cur) {
		log_once('uptodate', 'композиция уже актуальна');
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
	stage('apply', 'применяю композицию — служба перезапускается…');
	log('применяю: ' + join(' · ', target_names));
	if (length(built.notes))
		log('заметки конструктора: ' + join(' | ', built.notes));
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
		if (ENSURE_POSTPONED) {
			/* ч.123: a long sweep is running — re-evaluate on the next tick
			 * instead of blocking (and instead of a false "error" stage). */
			stage('watch', 'жду идущий фаззинг (~' +
				int(fuzz_remaining_est(read_json(FUZZ_STATUS)) / 60) + ' мин до конца)');
			S.next_cycle_ts = time() + 900;
			wstat();
			return;
		}
		stage('error', 'фаззинг не успел завершиться вовремя');
		log('фаззинг не завершился — повтор через 30 мин');
		S.next_cycle_ts = time() + 1800;
		wstat();
		return;
	}
	const target = { resources: {}, general: null };
	const hold = hold_active();
	if (hold) {
		log_once('hold_active', 'действует удержа плановой переразметки (Hot Swap 9, источник: ' +
			((S.manual_hold.src === 'lab') ? 'ручной пик' : 'внешняя/ручная композиция') +
			') — живые проверки и ремонт умершего ресурса продолжаются');
	}
	/* Ф6.7: вердикты Strategy Lab — ЕДИНСТВЕННЫЙ источник истины с
	 * карточкой «Оптимизатор маршрутов» (service_optimizer_plan читает те же
	 * вердикты). best_available = manual_only: автоприменение запрещено (92). */
	const labv = (fz != null && type(fz.verdicts) === 'object') ? fz.verdicts : null;
	/* ч.234: счётчик ресурсов с отказом лаборатории — для досрочного свипа. */
	let labnone_n = 0;
	/* ч.232: свежие метки с устройства — на каждую переразметку. */
	dev_reload();
	for (let res in cfg.resources) {
		if (res === 'general') {
			const cur = S.general.winner;
			const cand = pick_general(fz, null);
			let use = cand;
			/* ч.232: device-метки для general — те же правила, что у ресурсов. */
			const gd_cur = (cur != null) ? dv_of('general', cur.args) : '';
			const gd_cand = (cand != null) ? dv_of('general', cand.args) : '';
			if (hold) {
				if (cur)
					target.general = cur;
				use = null;
			}
			else if (cur && cand && cand.args == cur.args)
				use = null;
			else if (cur && cand && (S.general.strikes == 0) &&
				gd_cur === 'works' && gd_cand !== 'works') {
				log_once('devhold_general', 'general: текущая стратегия подтверждена на УСТРОЙСТВЕ — плановая замена не выполняется (метка сильнее лаборатории)');
				explain('general', 'держу текущую: подтверждена устройством');
				use = null;
			}
			else if (cur && cand && (S.general.strikes == 0) &&
				gd_cand === 'works' && gd_cur !== 'works') {
				log_once('devpick_general', 'general: кандидат подтверждён на УСТРОЙСТВЕ — смена без запаса по score (метка сильнее лаборатории)');
				explain('general', 'смена: кандидат подтверждён устройством, текущий — нет');
			}
			else if (cur && cand && (S.general.strikes == 0) &&
				(cand.score < cur.score + GENERAL_SCORE_STEP)) {
				log_once('genhold', 'general: текущая стратегия остаётся лучшей в пределах запаса по score');
				explain('general', 'держу текущую: кандидат хуже в пределах запаса по score (' + cand.score + ' против ' + cur.score + ')');
				use = null;
			}
			if (use) {
				target.general = use;
				explain('general', 'смена: кандидат ' + use.name + ' лучше по score (' + use.score + ' против ' + (cur ? cur.score : '—') + ')');
			}
			continue;
		}
		/* A resource whose rule does not lead to Zapret is never served by
		 * the engine — a scoped block for it would be dead weight. */
		if (!S.resources[res].mgmt) {
			log_once('nomgmt_' + res, res + ': правило не ведёт на Zapret — в композицию не входит (перенаправьте правило или включите «Держать правила на Zapret»)');
			continue;
		}
		const cur = S.resources[res].winner;
		/* Hot Swap 9: удержа — ресурс остаётся на текущей стратегии. */
		if (hold || (cur && cur.manual === true)) {
			if (cur)
				target.resources[res] = cur;
			if (!hold)
				log_once('manualhold_' + res, res + ': ручной пик сохранён (Hot Swap 9) — плановая переразметка его не заменяет');
			continue;
		}
		/* Ф6.7: честные вердикты лаборатории ДО выбора кандидата. */
		const lv = (labv != null && type(labv[res]) === 'object') ? labv[res] : null;
		if (lv != null && lv.verdict === 'best_available') {
			log_once('labavail_' + res, res + ': вердикт лаборатории best_available — автоприменение запрещено (аудит 92), примените вручную из Лаборатории');
			explain(res, 'best_available: обязательные компоненты не подтверждены deep-пробами — только ручное применение (92)');
			if (cur)
				target.resources[res] = cur;
			continue;
		}
		if (lv != null && (lv.verdict === 'no_candidate' || lv.verdict === 'unmeasured')) {
			log_once('labnone_' + res, res + ': вердикт лаборатории ' + lv.verdict +
				((lv.verdict === 'unmeasured')
					? ' — измерение ресурса в этом прогоне не состоялось (дрейф сети/TSPU)'
					: ' — ни одна стратегия корпуса не прошла обязательные проверки'));
			explain(res, (lv.verdict === 'unmeasured')
				? 'измерение не состоялось: держу текущую, лаборатория в этом окне бессильна'
				: 'no_candidate: корпус не дал подтверждённой стратегии; подробности — в вердиктах лаборатории');
			if (cur)
				target.resources[res] = cur;
			labnone_n++;
			continue;
		}
		/* s179: the lab verdict drives the candidate — pick_resource stays
		 * as the fallback when the verdict has nothing agreed yet. */
		const verdict_cand = verdict_pick(res, labv, cur, int(fz.ts));
		const verdict_driven = (verdict_cand != null);
		let cand = verdict_cand;
		if (verdict_cand != null && tried_has(res, verdict_cand.args)) {
			log_once('triedskip_' + res, res + ': победитель вердикта уже откатывался автопилотом (24 ч) — остаётся текущая');
			cand = pick_resource(fz, res, null);
		}
		if (cand == null)
			cand = pick_resource(fz, res, null);
		let use = cand;
		/* ч.232: device-правила переразметки. Подтверждённая на устройстве
		 * ТЕКУЩАЯ не заменяется лабораторным лидером без его же подтверждения;
		 * подтверждённый КАНДИДАТ сменяет неподтверждённого текущего даже в
		 * пределах антифлап-запаса (метка сильнее лаборатории). При strikes>0
		 * ремонт работает как раньше — живые провалы сильнее любых меток. */
		const cur_dv = (cur != null) ? dv_of(res, cur.args) : '';
		const cand_dv = (cand != null) ? dv_of(res, cand.args) : '';
		if (cur && cand && cand.args == cur.args)
			use = null;
		else if (cur && cand && (S.resources[res].strikes == 0) &&
			cur_dv === 'works' && cand_dv !== 'works') {
			log_once('devhold_' + res, res + ': текущая стратегия подтверждена на УСТРОЙСТВЕ — плановая замена не выполняется (метка сильнее лаборатории)');
			explain(res, 'держу текущую: подтверждена устройством; лабораторный кандидат подтверждения устройства не имеет');
			use = null;
		}
		else if (verdict_driven) {
			/* s179: the two-run lab agreement IS the margin — no stream/start
			 * flap arithmetic on top of a proven verdict; the device verdict
			 * 'broken' on the lab winner still refuses the swap. */
			if (cand_dv === 'broken') {
				log_once('devbrok_' + res, res + ': победитель вердикта помечен «не работает на устройстве» — остаётся текущая');
				explain(res, 'держу текущую: лабораторный победитель отвергнут меткой устройства');
				use = null;
			} else
				explain(res, 'смена на «' + cand.name + '»: вердикт лаборатории best_verified подтверждён двумя прогонами подряд');
		}
		else if (cur && cand && (S.resources[res].strikes == 0)) {
			/* ч.116 anti-flap: a switch needs a clear win on the resource's
			 * MEASURED verdicts — a tested candidate replaces an untested
			 * one, the deep ratio (≥ +0.25 = one probe), or the sustained
			 * video flow (>25% faster), or (both untested) a >10% TLS win.
			 * The old TLS-only margin is exactly how handshake-fast
			 * video-throttlers got promoted. A candidate with a WORSE band
			 * never replaces the current one. */
			const band = (e) => (((e.deep != null) && (e.deep > 0)) ||
				((e.deep == null) && (int(e.stream || 0) > 0))) ? 0
				: (((e.deep != null) && (e.deep == 0)) ? 2 : 1);
			const cd = (cand.deep == null) ? -1 : cand.deep;
			const cud = (cur.deep == null) ? -1 : cur.deep;
			const cspd = int(cand.stream || 0), uspd = int(cur.stream || 0);
			const cst = int(cand.start_ms || 0), ust = int(cur.start_ms || 0);
			const cb = band(cand), ub = band(cur);
			const tls_better = cand.tls_ms > 0 && cur.tls_ms > 0 &&
				cand.tls_ms < int(cur.tls_ms * (100 - MARGIN_PCT) / 100);
			const stream_better = (uspd > 0) &&
				(cspd > int(uspd * (100 + MARGIN_PCT) / 100));
			/* ч.127: the START latency (fresh-connection TTFB — the hover-
			 * preview experience) replaces the current one only at a clear
			 * 25% win: single bursts are normal TSPU behaviour, a persistent
			 * slow start is what the user actually feels. */
			const start_better = (ust > 0) && (cst > 0) &&
				(cst < int(ust * (100 - START_MARGIN_PCT) / 100));
			let switch_ok = false;
			/* ч.232: кандидат подтверждён устройством, текущий — нет →
			 * смена без запасов (метка сильнее лабораторных замеров). */
			if (cand_dv === 'works' && cur_dv !== 'works')
				switch_ok = true;
			else if (cb > ub)
				switch_ok = false;
			else if (cb < ub)
				switch_ok = true;
			else if (cd >= cud + 0.25)
				switch_ok = true;
			else if (cb == 0)
				switch_ok = stream_better || start_better || (tls_better && cspd >= uspd);
			else if (cb == 1)
				switch_ok = tls_better;
			if (!switch_ok) {
				log_once('hold_' + res, res + ': текущая стратегия остаётся лучшей в пределах запаса (deep ' +
					((cud >= 0) ? '' + cud : 'n/a') + ' против ' + ((cd >= 0) ? '' + cd : 'n/a') +
					', старт ' + ust + ' против ' + cst + ' мс, поток ' + uspd + ' против ' + cspd +
					' Б/с, TLS ' + cand.tls_ms + ' против ' + cur.tls_ms + ' мс)');
				explain(res, 'держу текущую: кандидат хуже в пределах антифлап-запаса (deep ' +
					((cud >= 0) ? '' + cud : 'n/a') + ' против ' + ((cd >= 0) ? '' + cd : 'n/a') +
					', старт ' + ust + '/' + cst + ' мс, поток ' + uspd + '/' + cspd + ' Б/с)');
				use = null;
			} else {
				explain(res, 'смена на «' + cand.name + '»: замер лучше (deep ' +
					((cd >= 0) ? '' + cd : 'n/a') + ', старт ' + cst + ' мс, поток ' + cspd + ' Б/с, TLS ' + cand.tls_ms + ' мс)');
			}
		}
		if (use) {
			target.resources[res] = use;
		}
		else if (cur) {
			target.resources[res] = cur;   /* re-emit the unchanged winner */
			explain(res, 'оставил текущую стратегию: подтверждённых улучшений нет');
		}
		else
			log_once('nopick_' + res, res + ': в рейтинге ничего не прошло — обслуживает общий хвост');
	}
	/* Unchanged general winner re-emit + the tail when not managed. */
	if (target.general == null && has_res(cfg.resources, 'general') && S.general.winner)
		target.general = S.general.winner;
	if (target.general == null)
		target.general = tail_for(cfg, fz);
	apply_target(cfg, target);
	S.error = '';
	S.next_cycle_ts = time() + cfg.interval_h * 3600;
	/* ч.234: отказ лаборатории — дрейф-окно, явление часа. Вердикт без
	 * повторного прогона не обновится никогда, а плановый интервал может
	 * быть много длиннее. Досрочный повторный свип через ~75 мин
	 * (окно 60–90 мин — решение пользователя ч.234), только если
	 * плановый цикл позже; holds/ремонты не затрагиваются. */
	if (labnone_n > 0) {
		const early = time() + 75 * 60;
		if (S.next_cycle_ts > early) {
			S.next_cycle_ts = early;
			log('лаборатория дала no_candidate/unmeasured по ' + labnone_n +
				' ресурсу(ам) — досрочный повторный свип через ~75 мин (дрейф-окно); текущие стратегии не тронуты');
		}
	}
	wstat();
}

/* Health repair: the resource failed fail_strikes probes in a row — pick
 * the next alternative NOW (the window does not gate a broken resource). */
function repair(cfg, res) {
	const cur = (res === 'general') ? S.general.winner : S.resources[res].winner;
	stage('fuzz', 'ремонт ' + res + '…');
	const fz = ensure_ranking(cfg);
	if (fz == null) {
		if (ENSURE_POSTPONED) {
			/* ч.123: a long sweep is running — the repair retries after it
			 * (probes stay honest: the fuzz holds the CPU either way). */
			stage('watch', 'жду идущий фаззинг перед ремонтом');
			S.next_check_ts = time() + 600;
			wstat();
			return;
		}
		stage('error', 'фаззинг не успел завершиться вовремя (ремонт)');
		S.next_check_ts = time() + 600;
		wstat();
		return;
	}
	const alt = (res === 'general') ? pick_general(fz, cur ? cur.args : null)
		: pick_resource(fz, res, cur ? cur.args : null);
	if (!alt) {
		log_once('repair_' + res, res + ': в рейтинге нет альтернативы — держу текущую стратегию');
		S.next_check_ts = time() + cfg.check_min * 60;
		stage('watch', '');
		wstat();
		return;
	}
	if (cur)
		tried_add(res, cur.args);
	/* ч.234: честное предупреждение — кандидат берётся по критерию
	 * majority+dist из рейтинга, собранного в ТО ЖЕ время, что и провал
	 * живой проверки. Если лаборатория в этом прогоне дала no_candidate/
	 * unmeasured по ресурсу или контрольные проходы тега разошлись —
	 * кандидат «слепой» (один счастливый раунд возможен). Поведение
	 * ремонта НЕ меняем (живой провал сильнее), только предупреждаем. */
	const lvw = (fz != null && type(fz.verdicts) === 'object' &&
		type(fz.verdicts[res]) === 'object') ? fz.verdicts[res] : null;
	const lvw_bad = (lvw != null &&
		(lvw.verdict === 'no_candidate' || lvw.verdict === 'unmeasured'));
	const rtag = (RESOURCES[res] != null) ? RESOURCES[res].tag : null;
	let drift_hit = false;
	if (rtag != null && fz != null && type(fz.baseline_series) === 'object' &&
		type(fz.baseline_series.drift) === 'array')
		for (let d in fz.baseline_series.drift)
			if (type(d) === 'object' && d.tag === rtag)
				drift_hit = true;
	const driftwarn = lvw_bad || drift_hit;
	if (driftwarn)
		log_once('rep_driftwarn_' + res, res + ': ⚠ КАНДИДАТ ИЗ РЕЙТИНГА, СОБРАННОГО В ДРЕЙФ-ОКНО (вердикт лаборатории: ' +
			((lvw != null) ? ('' + lvw.verdict) : 'нет') +
			(drift_hit ? '; контрольные проходы ресурса разошлись' : '') +
			') — после переключения проверьте ресурс на устройстве');
	log(res + ': стратегия перестала работать (' + ((res === 'general') ? S.general.strikes : S.resources[res].strikes) +
		' неудачных проверок подряд) — переключаюсь на ' + alt.name +
		(hold_active() ? ' — удержа (Hot Swap 9) снята: ресурс МЁРТВ, ремонт важнее удержи' : ''));
	ap_emit('repair', res + ': стратегия перестала работать (' +
		((res === 'general') ? S.general.strikes : S.resources[res].strikes) + ' неудачных проверок подряд)',
		'переключаюсь на «' + alt.name + '»' + (hold_active() ? '; удержа снята — ремонт важнее удержи' : '') +
		(driftwarn ? '; ⚠ рейтинг собран в дрейф-окно — проверьте на устройстве' : '') +
		'; снимок Restore доступен');
	/* Ф6.7: ремонт снимает удержу — мёртвый ресурс ремонтируется даже при
	 * ручном пике (иначе пользователь остаётся на сломанной стратегии). */
	S.manual_hold = null;
	explain(res, 'ремонт: ' + ((res === 'general') ? S.general.strikes : S.resources[res].strikes) +
		' неудачных проверок подряд — смена на «' + alt.name + '»');
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

/* Ресурсная матрица объявлена ВЫШЕ (preapply_probe/resume/health — callers);
 * комментарий-история: аудит 64 — одна и та же матрица до/после применения. */

/* Ф6.7: свежая батарея профилей (Ф6.3) как ДОПОЛНИТЕЛЬНОЕ измерение health —
 * ноль новых проб: результат уже измерен батареей (пользователем или RPC).
 * Свежесть 30 мин; сводка по сервисам, которые ведёт автопилот. */
function profile_battery() {
	const p = read_json(RUN_DIR + '/service_profile_result.json');
	if (p == null || type(p.components) !== 'array')
		return null;
	if ((time() - int(p.ts || 0)) > 1800)
		return null;                     /* старше 30 мин — не свежая */
	const sums = {};
	for (let k in ['youtube', 'discord', 'telegram'])
		sums[k] = { working: 0, degraded: 0, bad: 0, unprobed: 0 };
	/* for-in over an array yields the ELEMENTS (lesson 20/31). */
	for (let r in p.components) {
		if (type(r) !== 'object') continue;
		const k = '' + (r.profile || '');
		if (sums[k] == null) continue;
		const s = '' + (r.state || '');
		if (s === 'working') sums[k].working++;
		else if (s === 'degraded') sums[k].degraded++;
		else if (s === 'broken' || s === 'refused') sums[k].bad++;
		else if (s === 'unprobed') sums[k].unprobed++;
	}
	return sums;
}

function health(cfg) {
	if (access(RELOAD_MARK))
		return;
	if (!core_up()) {
		log_once('core', 'ядро лежит — пробы приостановлены');
		return;
	}
	once_clear('core');
	if (fuzz_running()) {
		log_once('probehold', 'пробы приостановлены, пока фаззинг занимает CPU (чтобы не было ложных отказов)');
		return;
	}
	once_clear('probehold');
	/* Ф6.7: свежая батарея профилей (Ф6.3) — дополнительное измерение без проб. */
	const battery = profile_battery();
	for (let res in cfg.resources) {
		if (res !== 'general' && !S.resources[res].mgmt) {
			/* Not managed — its own path serves it; no red
			 * noise from paths the auto-pilot does not own. */
			if (S.resources[res].probe != null || S.resources[res].strikes)
				S.resources[res].probe = null;
			S.resources[res].strikes = 0;
			continue;
		}
		const meta = RESOURCES[res];
		/* Ф6.3 (аудит 64): та же ресурсная матрица, что до/после применения. */
		const pr = resource_matrix(res, meta);
		/* ч.116: the whole-resource check. For YouTube the page alone
		 * passes while the media hosts fail or the video stream is
		 * throttled — the honest «ресурс работает» verdict needs them all;
		 * otherwise the auto-pilot never re-picks a throttling strategy
		 * (the user's exact complaint).
		 * ч.127: the verdicts stay THREE-STATE to the very end — only a
		 * DEAD resource (no HTTP / stub / block page / a fully dead flow)
		 * earns a strike; a slow-but-alive one (page slow, flow under the
		 * bar but transferring) is DEGRADED: it works, the user can see
		 * it — the old code counted it as unavailable and switched away
		 * strategies that were visibly working. A degraded resource pulls
		 * the scheduled re-rank closer instead (the anti-flap margins
		 * still keep the switch honest). */
		let ok_all = pr.ok;
		let dead_hit = pr.dead;
		let slow_hit = pr.slow;
		let fail_note = pr.note || '';
		const st = (res === 'general') ? S.general : S.resources[res];
		st.probe = pr;
		if (pr.ok) {
			if (int(st.strikes || 0) > 0) {
				log(res + ': снова в норме (' + pr.code + ')');
				ap_emit('recovered', res + ': снова в норме',
					'живая проверка прошла (' + pr.code + ') — стратегия продолжает работать');
			}
			st.strikes = 0;
			st.slow = false;
			st.note = '';
		} else if (dead_hit) {
			/* Cap at the strike threshold: the repair keeps retriggering on
			 * >= while the resource stays broken, the counter must not run
			 * away (an unmanaged resource never repairs at all). */
			st.strikes = (int(st.strikes || 0) < cfg.fail_strikes)
				? int(st.strikes || 0) + 1 : cfg.fail_strikes;
			st.slow = false;
			st.note = 'неудачных проверок подряд: ' + st.strikes + ' (' + pr.code + ')';
			log_once('fail_' + res, res + ': живая проверка ПРОВАЛЕНА (' + pr.code +
				((pr.note) ? (' — ' + pr.note) : '') + ') — ' + st.strikes + '/' + cfg.fail_strikes);
		} else {
			/* degraded: alive but slow — never a strike, never a repair-swap
			 * (the user watches the resource work). The scheduled re-rank
			 * comes closer (min 30 min) and re-decides through the normal
			 * anti-flap margins. */
			st.slow = true;
			st.note = 'деградация: ' + fail_note;
			log_once('degraded_' + res, res + ': деградация, но ЖИВОЙ — ' + fail_note +
				' (без смены: стратегия работает, переразметка придёт раньше)');
			if (S.next_cycle_ts == 0 || S.next_cycle_ts > time() + 1800)
				S.next_cycle_ts = time() + 1800;
		}
		/* Ф6.7: кросс-проверка с батареей профилей (Ф6.3). Батарея — ДРУГОЕ
		 * измерение (компоненты, которых страница/deep-матрица не видит:
		 * MTProto DC, gateway WS). broken/refused при нашем ok → честная
		 * деградация и подтягивание переразметки, БЕЗ страйка (не наш замер;
		 * двойное наказание одним фактом запрещено). */
		const batt = (battery != null && res !== 'general') ? battery[res] : null;
		if (batt != null && int(batt.bad || 0) > 0) {
			st.note = 'батарея профиля: ' + int(batt.bad) + ' сломано' +
				((length(st.note || '')) ? ' · ' + st.note : '');
			if (pr.ok) {
				st.slow = true;
				if (S.next_cycle_ts == 0 || S.next_cycle_ts > time() + 1800)
					S.next_cycle_ts = time() + 1800;
			}
			log_once('batt_' + res, res + ': батарея профиля сообщает о ' + int(batt.bad) +
				' сломанных компонентах — деградация, без страйка (не наш замер)');
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

/* ч.116: manual picks from the Strategy Lab (the scoped apply of the
 * auto-pick runner) are handed over through zapret_autopilot_manual.json;
 * the daemon adopts them as the resource winners on its next tick —
 * otherwise the next re-rank could overwrite the user's explicit choice
 * before it ever mattered. The file is consumed (deleted) after adoption. */
/* Сеанс 158/Б8: явное снятие удержания (Hot Swap 9) — команда-файл от RPC
 * wizard_autopilot_hold_release (атомарная запись, стирание здесь). Тот же
 * контракт, что у MANUAL_FILE. Снятие честное: плановая переразметка снова
 * работает, живые проверки не прерывались. */
function adopt_hold_release() {
	const f = RUN_DIR + '/zapret_autopilot_holdclear.json';
	const c = read_json(f);
	if (c == null || type(c) !== 'object')
		return;
	system(`rm -f ${sq(f)} 2>/dev/null`);
	if (!hold_active())
		return;
	S.manual_hold = null;
	S.n_hold_active = null;   /* log_once-ключ цикла — после снятия не нужен */
	/* Внешний детект (tick) снова поставил бы удержу на ТОЙ ЖЕ композиции
	 * (curz != last_apply.zapret) — пользователь сказал «снять», значит
	 * текущая композиция принимается как осознанный выбор: выравниваем
	 * маркер «не перевзводить по той же смене». */
	{
		const cz = '' + (cursor().get('ravnex', 'config', 'zapret_cmd_opts') || '');
		if (S.last_apply && type(S.last_apply) === 'object' && length(cz))
			S.last_apply.zapret = cz;
	}
	log('удержание ручной композиции (Hot Swap 9) снято вручную из интерфейса — плановая переразметка снова работает');
	ap_emit('hold_released', 'удержание Hot Swap снято вручную',
		'плановая переразметка возобновится по расписанию; живые проверки и ремонт продолжались и продолжаются');
	wstat();
}

function adopt_manual() {
	const m = read_json(MANUAL_FILE);
	if (m == null || type(m) !== 'object' || type(m.resources) !== 'object')
		return;
	let any = false;
	let adopted = [];
	for (let res in keys(m.resources)) {
		const w = m.resources[res];
		if (RESOURCES[res] == null || type(w) !== 'object' || !length('' + (w.args || '')))
			continue;
		S.resources[res].winner = { name: '' + (w.name || 'ручной выбор'),
			args: '' + w.args, tls_ms: 0, deep: null,
			stream: int(w.stream || 0), start_ms: int(w.start_ms || 0), score: 0,
			manual: true, runners: [] };
		S.resources[res].strikes = 0;
		explain(res, 'ручной выбор принят (Hot Swap 9): плановая переразметка не заменит его; живые проверки продолжаются');
		log('ручной выбор из Лаборатории стратегий принят для ' + res + ': ' + (w.name || 'кастомные аргументы'));
		push(adopted, res);
		any = true;
	}
	if (any) {
		/* Ф6.7: ручной пик ставит удержу плановой переразметки. */
		S.manual_hold = { ts: time(), src: 'lab' };
		wstat();
		ap_emit('manual_pick', 'принят ручной выбор из Лаборатории: ' + join(', ', adopted),
			'плановая переразметка удержана (Hot Swap 9) — ваш выбор старше измерения; живые проверки и ремонт продолжаются');
	}
	system(`rm -f ${sq(MANUAL_FILE)} 2>/dev/null`);
}

/* Ф6.7: hold_active() объявлена ВЫШЕ (cycle/repair — callers; сеанс 158/Б1). */

/* ── main loop ──────────────────────────────────────────────────────── */

function tick() {
	const cfg = cfg_read();
	S.config = cfg;
	S.enabled = cfg.enabled;
	S.mode = routing_mode();
	S.zapret_enabled = (cursor().get('ravnex', 'config', 'zapret_enabled') === '1');
	tried_prune();

	if (!cfg.enabled) {
		S.pending = null;
		if (S.stage != 'idle') {
			stage('idle', 'выключен');
			log('автопилот выключен');
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
		stage('idle', 'Zapret не установлен или выключен в настройках узлов');
		wstat();
		return;
	}

	if (S.pending) {
		resume();
		wstat();
		return;
	}
	if (others_busy()) {
		log_once('busy', 'идёт автоподбор в один клик или тест композиции — отложено');
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
			log_once('mgmt_' + res, res + ': правило не ведёт на Zapret — управление стратегией для него выключено (включите «Держать правила на Zapret»)');
	}

	adopt_manual();
	adopt_hold_release();

	/* Ф6.7 (Hot Swap 9): детект ВНЕШНЕЙ смены композиции — пользователь
	 * применил стратегию/композицию из UI (или руками). Плановая переразметка
	 * удержана, живые проверки продолжаются. Снимается ремонтом умершего
	 * ресурса или успешным применением автопилота. */
	{
		const curz = '' + (cursor().get('ravnex', 'config', 'zapret_cmd_opts') || '');
		if (!S.pending && S.last_apply && type(S.last_apply) === 'object' &&
		    length('' + (S.last_apply.zapret || '')) && curz != S.last_apply.zapret &&
		    length(curz)) {
			S.last_apply.zapret = curz;   /* not re-armed by the same change */
			S.manual_hold = { ts: time(), src: 'external' };
			log('обнаружена внешняя/ручная композиция — плановая переразметка удержана (Hot Swap 9); живые проверки и ремонт продолжаются');
			ap_emit('manual_hold', 'обнаружена внешняя/ручная смена композиции',
				'плановая переразметка удержана (Hot Swap 9) — ваш выбор старше измерения; живые проверки и ремонт продолжаются');
			wstat();
		}
	}

	/* ч.127 ROOT FIX: health() was called on EVERY tick (60 s) — the
	 * check_min interval (the UI's honest «next check: HH:MM») was written
	 * but never used as a gate. The result: 5 probes a minute against the
	 * strategy, fail_strikes=2 = a service-reloading strategy swap within
	 * ~2 minutes of ONE transient failure episode (the user's report:
	 * «переключения происходят очень часто, не может стратегия перестать
	 * работать в течение часа»). The gate restores the promised cadence. */
	if (time() >= S.next_check_ts)
		health(cfg);

	/* s179 (user decision «вердикт + 2 прогона»): a fresh lab result —
	 * scheduled sweep OR the user pressing the Lab button — pulls the
	 * planned review closer (~15 min) instead of waiting the whole
	 * interval_h. Holds/pending/busy states keep their priority. */
	{
		const fr = read_json(FUZZ_RESULT);
		const fts = (fr != null && fr.ts != null) ? int(fr.ts) : 0;
		if (fts > 0 && S.last_fuzz_ts > 0 && fts > S.last_fuzz_ts &&
		    S.next_cycle_ts > 0) {
			const early = time() + 15 * 60;
			if (S.next_cycle_ts > early) {
				S.next_cycle_ts = early;
				log('свежий замер лаборатории — пересмотр победителей через ~15 мин (вердикт + 2 прогона)');
			}
		}
		if (fts > 0 && fts != S.last_fuzz_ts) {
			S.last_fuzz_ts = fts;
			wstat();
		}
	}

	if (time() >= S.next_cycle_ts) {
		if (hold_active()) {
			/* Удержа: переразметка не нужна — не тратим ни слот, ни фаззинг. */
			S.next_cycle_ts = time() + cfg.interval_h * 3600;
			log_once('holdskip', 'плановая переразметка удержана (Hot Swap 9) — слот отложен');
			wstat();
		} else if (window_active(cfg) || night_active(cfg)) {
			stage('watch', '');
			cycle(cfg);   /* arms next_cycle itself (apply may kill us) */
			return;
		}
		else
			log_once('window', 'вне окна обслуживания — плановая переразметка ждёт');
	}
	wstat();
}

function main() {
	const prev = read_json(STATE);
	if (prev && type(prev) === 'object' && prev.alive)
		S = prev;
	/* Ф9.8: в state-файле остался ключ-призрак 'tgws' (мост удалён ч.200/D34b):
	 * main() возобновляет S = prev ЦЕЛИКОМ, и неизвестный схеме ключ кочует
	 * через каждый respawn. ucode не имеет delete — выкидываем его копированием
	 * (for-in по объекту = ключи, урок 20). Один раз — дальше схема чиста. */
	if ('tgws' in S) {
		const clean = {};
		for (let k in S)
			if (k !== 'tgws')
				clean[k] = S[k];
		S = clean;
	}
	state_ensure();
	S.alive = true;
	S.error = '';
	wstat();
	log('демон автопилота запущен');
	/* Ф1.4b: own identity in the daemon registry + a heartbeat every cycle —
	 * the Sentinel (Ф2), support bundle and status RPCs read liveness here. */
	pm_reg_self('zapret_autopilot', 'zapret_autopilot.uc');
	if (S.pending) {
		stage('resume', 'продолжаю прерванное действие…');
		resume();
	}
	while (true) {
		pm_reg_hb('zapret_autopilot');
		try {
			tick();
		} catch (e) {
			S.error = '' + e;
			stage('error', 'внутренняя ошибка: ' + S.error);
			log('внутренняя ошибка: ' + S.error);
			ap_emit('error', 'внутренняя ошибка автопилота',
				S.error + '; демон продолжит работу со следующего тика — при повторе смотрите журнал на странице автоматизации');
		}
		sleep(TICK * 1000);
	}
}

main();
