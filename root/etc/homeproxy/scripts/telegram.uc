#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Telegram control bot v2 (Ф6, ч.78; v1 — ч.69).
 *
 * Always-on procd instance (init.d spawns it unconditionally, like metrics):
 * the daemon gates itself on UCI every loop — enabled=0 or a bad token means
 * an idle 15 s loop, so EVERY setting (token, chat, mute, pushes, intervals)
 * is hot-reloadable without touching the service. The core/engines/hotswap
 * are never touched: the bot is an observer + actor over the existing RPC
 * surface (ubus calls) and the Clash API.
 *
 * Long-polls the Bot API (getUpdates, UCI-configurable timeout) in HTML
 * parse_mode with inline keyboards, answers commands from the bound chat
 * only (homeproxy.telegram.chat_id; empty = the first chat wins — pinned on
 * the first message, as in v1), and pushes notifications. Ф2.4: the informer
 * is a SUBSCRIBER of the shared Event Bus (eventbus.uc, journal.jsonl) —
 * one durable cursor ('telegram-bus') covers Hot Swap switches, URLTest
 * watchdog dead/recovered/reload and automation learn/heal/outage records;
 * the «Контроль» module subscribes to its own src=control stream with the
 * same mechanism ('telegram-ctrl'). Remaining file probes:
 *   automation_stats.json (learned counters for /status),
 *   Clash /version        — core down / recovered.
 *
 * Commands (v1 kept, RU texts — the bot audience is the router owner):
 *   /status /ping /connections /close /restart /help /start
 *   /nodes        nodes + delays (sorted by label, stable numbering)
 *   /switch <n|prefix>   PUT /proxies/main-out — switch WITHOUT a restart
 *                 (hotswap antiflap adopts an external move as its pin);
 *                 refused in custom routing (no main-out) — гейт ч.74
 *   /service start|stop|restart
 *   /snapshot     app_snapshot_create (same RPC the UI uses)
 *   /status_engine  zapret/byedpi strategy + NFQUEUE (wizard_dpi_status data)
 *   /mute | /unmute   silence push notifications (commands keep working)
 *
 * Rate limiting / dedup: pushes are spaced >= UCI push_interval seconds,
 * identical push text per kind within 300 s is dropped. 429 honors
 * retry_after with backoff+jitter and at most ONE automatic retry per
 * send call; the polling side never inline-retries (audit 1.4/TG-05).
 * ALL dynamic text goes through esc_html (<>&) — lesson ч.69 fix. edited
 * updates are ignored (the offset still advances); channel_post is served
 * like a normal message only for the exact bound chat — other groups/
 * channels are denied by default (Ф8.1).
 *
 * Ф8.1 Security core (ч.184):
 *   - RBAC Owner/Admin/Operator/Viewer by Telegram user_id (UCI lists
 *     homeproxy.telegram.{owner,admin,operator,viewer}_user); checks run
 *     on commands AND callbacks (audit 1.1/TG-01/02). user_id is compared
 *     AS A STRING (the ids are ints in JSON, strings in UCI).
 *   - Pairing: a 6-digit one-time code valid 60 s is generated in LuCI
 *     (telegram_pair_generate); the first /start <code> (or bare code)
 *     from an unknown user in a PRIVATE chat binds them under the chosen
 *     role and burns the code. Bootstrap: with NO users at all and a bound
 *     PRIVATE chat, the chat owner is seeded as Owner once (live compat).
 *   - Durable Update Queue (audit 1.2/B0.2/TG-03): every polled update is
 *     written to /var/run/homeproxy/tg_queue/<id>.json BEFORE handling;
 *     the offset file advances only AFTER the update is processed; a
 *     done-journal (1 h ring) makes re-delivery idempotent.
 *   - The token never appears on a command line (audit 44): every Bot API
 *     call carries the URL in a curl config file (0600, removed at once),
 *     POST bodies travel via --data-binary @file.
 *   - A token change applies at once: api_base is rebuilt and getMe
 *     resolves the bot id; the offset file is per bot (audit 1.3/TG-04).
 *   - /nodes is paginated (8 per page, stable global numbering for
 *     /switch N — audit 42); /users lists the RBAC state (Admin+).
 *
 * Ф8.2 Subsystem split (ч.185):
 *   - ALL mutations from the chat ride the Control API (luci.homeproxy RPC,
 *     audit 1.5/TG-06) — mute/pin/pairing/service via ubus, «Контроль»
 *     device/rule/wifi/pause actions via the control_* RPC door; the Clash
 *     API PUT/DELETE (switch, /close) stays the core's own control plane
 *     (the same door hotswap uses).
 *   - Danger-level confirmations (D25): heavy actions (service stop/restart,
 *     persistent device block/allow, Wi-Fi off, rules add/del, mode change,
 *     updates, repairs) ask for a SECOND TAP — a pending map with a 5 min
 *     TTL, the role is re-checked at the tap itself.
 *   - D25 full control: /mode (routing mode), /safe (Safe Mode — direct
 *     egress with DNS/firewall kept, unlike the «Direct» mode), /doctor
 *     (Recovery/Sentinel status), /repair (manual repair requests),
 *     /update (app self-update + core install + engine packages).
 */

'use strict';

import { access, popen, readfile, open, stat, writefile, mkdir, chmod, rename } from 'fs';
/* «Контроль» module (plan 14): the control feature rides the same bot —
 * the module receives the bot primitives (api object) and never touches
 * the daemon internals itself. */
import * as ctrl from '/etc/homeproxy/scripts/telegram_control.uc';
/* Control state summary for /status (plan 15): the same library the
 * rpcd backend and the enforcer use. */
import { client_states, main_opt } from '/etc/homeproxy/scripts/control.uc';
/* Process Manager (Ф1.4b): registry self-registration + heartbeats, and
 * identity-grade liveness for the /status engine lines (a bare pidof
 * accepted a foreign mosdns and cannot see ucode scripts at all). */
import {
	reg_self as pm_reg_self, reg_hb as pm_reg_hb,
	reg_get as pm_reg_get, entry_alive as pm_entry_alive, find_daemons as pm_find
} from '/etc/homeproxy/scripts/pmgr.uc';
/* Event Bus (Ф2.4): the informer subscribes to the shared journal with a
 * durable cursor (survives daemon restarts within one boot; a reboot wipes
 * the journal and the cursor together). */
import {
	tail as bus_tail, last_id as bus_head,
	cursor_get as bus_cursor_get, cursor_set as bus_cursor_set
} from '/etc/homeproxy/scripts/eventbus.uc';

const RUN_DIR = '/var/run/homeproxy';
const LOG_FILE = RUN_DIR + '/telegram.log';
const OFF_FILE = RUN_DIR + '/telegram_offset';
const STATS_FILE = RUN_DIR + '/automation_stats.json';
const API = 'http://127.0.0.1:9090';
const PROBE_URL = 'http://www.gstatic.com/generate_204';
const MAXMSG = 3800;      /* Telegram hard limit is 4096 — keep a margin */
const DEDUP_SEC = 300;
/* Ф8.1 security core */
const QUEUE_DIR = RUN_DIR + '/tg_queue';   /* durable update queue (audit 1.2) */
const DONE_FILE = RUN_DIR + '/tg_done.json';
const CURL_F = RUN_DIR + '/.tg.curl';     /* the ONLY place the token may appear (0600) */
const BODY_F = RUN_DIR + '/.tg.body';
const ROLES = [ 'owner', 'admin', 'operator', 'viewer' ];
const ROLE_RANK = { owner: 4, admin: 3, operator: 2, viewer: 1 };
const NODES_PAGE = 8;
/* RU-имена режимов маршрутизации (D25 /mode; значения — из client.js). */
const MODE_RU = {
	proxy_banned_ru: 'Обход блокировок',
	global: 'Всё через узел',
	direct: 'Напрямую (всё выключено)'
};

/* Module-level state (module scope is safe for closures; ucode lesson 44/45
 * only bites function-locals declared AFTER the closure). */
let boot_ts = time();
let api_base = '';
let allowed_chat = 0;
let last_update_id = 0;
let last_send_ts = 0;
let token_used = '';    /* token the api_base was built for (audit 1.3) */
let bot_id = 0;         /* resolved via getMe — the offset file is per bot */
let rate_until = 0;     /* honest 429 status: skip polling until this time */
let seeded_owner = false;
let done = {};          /* idempotency journal: update_id -> ts (1 h ring) */
let cfg = {
	enabled: '0', token: '', chat_id: '', mute: '0',
	poll: '25', push_interval: '2',
	push_hotswap: '1', push_watchdog: '1', push_learn: '1', push_service: '1',
	push_control: '1',
	users: { owner: [], admin: [], operator: [], viewer: [] }
};
let seen = {
	core_ok: null
};
let last_push = {};   /* kind -> { text, ts } dedup */
let bus_id = 0;       /* Ф2.4: Event Bus cursor (last consumed event_id) */
let bus_saved = 0;    /* id already persisted to the durable cursor */
let bus_ready = false;/* baseline done (never re-baseline mid-boot) */

/* ── basics ───────────────────────────────────────────────────────────── */

/* ч.118: shellquote MUST stay ABOVE log() — in this ucode dialect a
 * top-level function declared LATER is INVISIBLE at call time to a
 * function declared earlier (router-proven A–F matrix: plain script,
 * 'use strict', module import, template and concat call forms all fail
 * with "access to undeclared variable / not a function" the moment the
 * caller runs). The log-rotation branch below used to carry the ONLY
 * shellquote reference of log() while shellquote sat BELOW log(): the
 * daemon worked for weeks until the log crossed the 64 KB cap, then every
 * log() call killed the process (respawn spam, retries exhausted, bot
 * dead until a manual intervention — the live ч.118 incident). */
function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function log(msg) {
	/* Standalone ucode has NO strftime (v1 carried this bug since ч.69 —
	 * its log() crashed the daemon at the very first call). Epoch-only,
	 * same as automation.uc/metrics.uc. ч.118: the WHOLE body is
	 * best-effort try/catch — the logger must never throw (a throwing
	 * logger turned the ч.113 log-cap into a death spiral: the rotation
	 * branch itself was the crash, so every write killed the daemon). */
	try {
		const line = sprintf('[%d] [TG] %s\n', time(), msg);
		let f = open(LOG_FILE, 'a');
		if (f) { f.write(line); f.close(); }
		if (!access(LOG_FILE)) return;
		const st = stat(LOG_FILE);
		if (st && st.size > 65536) {
			const old = popen(`tail -n 100 ${shellquote(LOG_FILE)}`);
			const tail = old ? old.read('all') : '';
			if (old) old.close();
			let w = open(LOG_FILE, 'w');
			if (w) { w.write(tail); w.close(); }
		}
	} catch (e) { /* best effort — logging must never kill the daemon */ }
}

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

function uci_get(opt, def) {
	const fd = popen(`uci -q get homeproxy.telegram.${opt} 2>/dev/null`);
	let v = null;
	if (fd) { v = trim(fd.read('all') || ''); fd.close(); }
	return (v != null && length(v)) ? v : def;
}

/* UCI LIST read: busybox `uci get` returns NOTHING for list options
 * (proven live ч.184) — parse `uci -q show` instead (one line per element,
 * form: homeproxy.telegram.opt='value'; user ids are digits — safe). */
function uci_list(opt) {
	const out = capture(`uci -q show homeproxy.telegram.${opt} 2>/dev/null`);
	const vals = [];
	const lines = split(trim(out || ''), '\n');
	for (let i = 0; i < length(lines); i++) {
		const m = match(trim(lines[i]), /='([0-9-]+)'$/);
		if (m && length(m[1]))
			push(vals, m[1]);
	}
	return vals;
}

/* Control API bridge (Ф8.2, аудит 1.5/TG-06): ВСЕ мутации из чата идут
 * через ту же RPC-дверь luci.homeproxy, что и UI. Возвращает разбор ответа
 * или null (честный отказ — вызывающий сообщает об ошибке). Аргументы —
 * только строки (rpcd string-policy, урок 132). */
function ubus_call(method, args, timeout_s) {
	const t = (timeout_s != null && timeout_s > 0 && timeout_s <= 60) ? int(timeout_s) : 10;
	const cmd = `ubus -t ${t} call luci.homeproxy ${method} ${shellquote(sprintf('%J', args))}`;
	const raw = capture(cmd);
	let j = null;
	try { j = json(raw || ''); } catch (e) { j = null; }
	if (j == null)
		log('ubus ' + method + ': no/invalid reply (rpcd недоступен?)');
	return j;
}

/* One telegram.* UCI value read (safe state etc. — read-only probes). */
function uci_tg_snap(key) {
	const fd = popen(`uci -q get homeproxy.telegram.${key} 2>/dev/null`);
	let v = null;
	if (fd) {
		v = trim(fd.read('all') || '');
		fd.close();
	}
	return (length(v || '')) ? v : null;
}

/* Hot-reload the whole config from UCI (called every loop iteration — the
 * daemon never needs a service restart after settings changes). */
function read_cfg() {
	cfg.enabled  = uci_get('enabled', '0');
	cfg.token    = uci_get('token', '');
	cfg.chat_id  = uci_get('chat_id', '');
	cfg.mute     = uci_get('mute', '0');
	cfg.poll     = uci_get('poll_timeout', '25');
	cfg.push_interval = uci_get('push_interval', '2');
	cfg.push_hotswap  = uci_get('push_hotswap', '1');
	cfg.push_watchdog = uci_get('push_watchdog', '1');
	cfg.push_learn    = uci_get('push_learn', '1');
	cfg.push_service  = uci_get('push_service', '1');
	cfg.push_control  = uci_get('push_control', '1');
	cfg.users = {
		owner:    uci_list('owner_user'),
		admin:    uci_list('admin_user'),
		operator: uci_list('operator_user'),
		viewer:   uci_list('viewer_user')
	};
}

function token_ok(t) {
	return length(t) && match(t, /^[0-9]+:[A-Za-z0-9_-]+$/) != null;
}

/* ── RBAC (Ф8.1): role resolution by user_id — STRING comparison (the ids
 * are ints in Telegram JSON, strings in UCI lists). ───────────────────── */

function users_count() {
	let n = 0;
	for (let r in cfg.users)
		n += length(cfg.users[r]);
	return n;
}

function role_for(uid) {
	if (uid == null)
		return null;
	const s = '' + uid;
	for (let i = 0; i < length(ROLES); i++) {
		const r = ROLES[i];
		for (let k = 0; k < length(cfg.users[r]); k++)
			if (cfg.users[r][k] === s)
				return r;
	}
	return null;
}

function role_ok(role, need) {
	return (ROLE_RANK[role] || 0) >= (ROLE_RANK[need] || 99);
}

/* Bootstrap (live compat): with NO users at all and a bound PRIVATE chat,
 * the chat owner becomes Owner exactly once — RBAC is strict from the
 * first pairing on. A bound GROUP chat cannot be seeded (its id is not a
 * user id) — the daemon keeps legacy access there and logs a warning. */
function ensure_owner_seed() {
	if (seeded_owner)
		return;
	seeded_owner = true;
	const cid = trim('' + (cfg.chat_id || ''));
	if (users_count() > 0 || !length(cid) ||
	    match(cid, /^-?[0-9]+$/) == null || int(cid) < 0) {
		if (users_count() === 0 && length(cid) && int(cid) < 0)
			log('RBAC: bound chat is a group — owner cannot be seeded, legacy access applies there');
		return;
	}
	/* Ф8.2: the seed (chat_id + owner_user) rides the Control API; the RPC
	 * guards itself (seeds ONLY when no users exist). On failure the legacy
	 * in-chat access keeps the bot usable (users_count() is still 0). */
	const r = ubus_call('telegram_bind_set', { chat_id: cid, owner_uid: cid }, 10);
	if (r && r.result === true && r.owner_seeded === true) {
		push(cfg.users.owner, cid);
		log('RBAC: owner seeded from the bound private chat (' + cid + ')');
	} else
		log('RBAC: owner seed via Control API did not apply (' +
			((r && r.error) ? r.error : 'rpcd недоступен') + ') — legacy access stays');
}

/* Entities are split so no tooling decodes them back (lesson 51 family). */
const AMP_E = '&' + 'amp;';
const LT_E = '&' + 'lt;';
const GT_E = '&' + 'gt;';

function esc_html(s) {
	s = replace('' + s, '&', AMP_E);
	s = replace(s, '<', LT_E);
	s = replace(s, '>', GT_E);
	return s;
}

/* JSON-string escape (no regex classes — ucode lesson 4 family). */
function jesc(s) {
	let esc = '';
	s = '' + s;
	for (let i = 0; i < length(s); i++) {
		const ch = substr(s, i, 1);
		if (ch === '"') esc += '\\"';
		else if (ch === '\n') esc += '\\n';
		else if (ch === '\r') esc += '\\r';
		else if (ch === '\\') esc += '\\\\';
		else if (ch === '\t') esc += '\\t';
		else esc += ch;
	}
	return esc;
}

/* ── Bot API ──────────────────────────────────────────────────────────── */

/* One POST/GET call. Returns parsed JSON or null.
 * Audit 44 (Ф8.1): the bot token (inside the URL) NEVER appears on a
 * command line — it lives in a curl config file (0600, removed right
 * after); POST bodies travel via --data-binary @file (chat text, also
 * 0600 while it exists).
 * Audit 1.4/TG-05: a 429 honors retry_after with backoff+jitter and at
 * most ONE automatic retry per send call; the polling side (params ==
 * null) never inline-retries — the main loop backs off and skips polling
 * while rate_until has not passed. rand() is ABSENT on this ucode build
 * (proven live) — the jitter derives from the wall clock instead. */
function tg_call(method, params, retried) {
	const url = `${api_base}/${method}`;
	let out = '';
	let cleaned = false;
	try {
		let c = 'url = "' + jesc(url) + '"\n';
		if (params == null) {
			const poll = (match(cfg.poll, /^[0-9]+$/) != null) ? int(cfg.poll) : 25;
			c += `max-time = ${poll + 5}\n`;
			writefile(CURL_F, c);
			chmod(CURL_F, 384);
			cleaned = true;
			out = capture(`curl -s -K ${shellquote(CURL_F)} 2>/dev/null`);
		} else {
			c += 'max-time = 15\n';
			writefile(BODY_F, params);
			chmod(BODY_F, 384);
			writefile(CURL_F, c);
			chmod(CURL_F, 384);
			cleaned = true;
			out = capture(`curl -s -K ${shellquote(CURL_F)} --data-binary @${shellquote(BODY_F)} 2>/dev/null`);
		}
	} catch (e) { log('tg_call io: ' + e); }
	if (cleaned)
		system(`rm -f ${shellquote(CURL_F)} ${shellquote(BODY_F)}`);
	if (!length(trim(out)))
		return null;
	let j = null;
	try { j = json(out); } catch (e) { j = null; }
	if (j && j.ok === false && j.error_code === 429 && j.parameters &&
	    j.parameters.retry_after != null) {
		const raw = '' + j.parameters.retry_after;
		const ra = (match(raw, /^[0-9]+$/) != null) ? int(raw) : 1;
		const wait = (ra > 0 && ra < 120) ? ra : 1;
		rate_until = time() + wait;
		log('rate limited (429), retry_after=' + wait + ' s, auto-retry: ' +
			((params != null && !retried) ? 'once' : 'none'));
		if (params != null && !retried) {
			sleep((wait + (int(time()) % 3)) * 1000);   /* backoff + jitter */
			return tg_call(method, params, 1);          /* MAX ONE auto-retry */
		}
	}
	return j;
}

function send_gap() {
	let gap = (match(cfg.push_interval, /^[0-9]+$/) != null) ? int(cfg.push_interval) : 2;
	if (gap < 1) gap = 1;
	const now = time();
	const wait = gap - (now - last_send_ts);
	if (wait > 0 && wait <= gap)
		sleep(wait * 1000);
	last_send_ts = time();
}

/* HTML message with an optional inline keyboard (already-built JSON). */
function tg_send_html(chat_id, text, kb) {
	let t = '' + text;
	if (length(t) > MAXMSG)
		t = substr(t, 0, MAXMSG) + '…';
	send_gap();
	const body = sprintf('{"chat_id":%d,"text":"%s","parse_mode":"HTML","disable_web_page_preview":true%s}',
		chat_id, jesc(t), kb ? ',"reply_markup":' + kb : '');
	return tg_call('sendMessage', body);
}

/* Document upload (Р4 /logs): multipart/form-data через curl -F.
 * Возвращает true при ok:true в ответе Bot API. */
function tg_send_document(chat_id, path, caption) {
	send_gap();
	const url = `${api_base}/sendDocument`;
	const cap = length('' + (caption || '')) ? ` -F "caption=${jesc('' + caption)}"` : '';
	/* Audit 44: the token stays in the curl config file, not in argv. */
	try {
		writefile(CURL_F, 'url = "' + jesc(url) + '"\nmax-time = 120\n');
		chmod(CURL_F, 384);
	} catch (e) { log('doc io: ' + e); }
	const out = capture(`curl -s -K ${shellquote(CURL_F)} -F "chat_id=${chat_id}"${cap} -F "document=@${path}" 2>/dev/null`);
	system(`rm -f ${shellquote(CURL_F)}`);
	let j = null;
	try { j = json(out); } catch (e) { j = null; }
	if (!j || j.ok !== true)
		log('sendDocument failed: ' + substr(out || '', 0, 120));
	return !!(j && j.ok === true);
}

function kb_rows(rows) {
	/* rows: array of rows; each row is EITHER
	 *   - [text, callback_data]          — a single button, OR
	 *   - [[text, callback_data], ...]   — a row of buttons.
	 * Both forms are accepted (issue #7): every caller except main_menu_kb()
	 * passed the flat form, and indexing a *string* with [0] throws
	 * "left-hand side expression is not an array or object" — /status and
	 * /status_engine died on it (the exception was caught in main(), so the
	 * chat just got no reply). */
	let parts = [];
	for (let r = 0; r < length(rows); r++) {
		const row = rows[r];
		let cells = [];
		if (length(row) > 0 && type(row[0]) === 'array') {
			for (let c = 0; c < length(row); c++) {
				const b = row[c];
				push(cells, sprintf('{"text":"%s","callback_data":"%s"}', jesc(b[0]), jesc(b[1])));
			}
		} else if (length(row) >= 2) {
			push(cells, sprintf('{"text":"%s","callback_data":"%s"}', jesc(row[0]), jesc(row[1])));
		}
		if (length(cells))
			push(parts, '[' + join(',', cells) + ']');
	}
	return '{"inline_keyboard":[' + join(',', parts) + ']}';
}

function tg_answer_cb(cb_id, text) {
	if (!length(cb_id)) return;
	tg_call('answerCallbackQuery', sprintf('{"callback_query_id":"%s","text":"%s"}',
		jesc(cb_id), jesc(text || '')));
}

/* ── pairing + RBAC denials (Ф8.1) — need the tg primitives above ─────── */

/* One-time 60 s pairing code (generated in LuCI): /start <code> or a bare
 * code message from an unknown user in a PRIVATE chat binds them under the
 * chosen role and burns the code. Ф8.2: the whole transaction (validate,
 * add the user, burn the code — one atomic commit) runs in the Control API
 * (telegram_pair_consume); the daemon only reports the outcome. Returns
 * true when the message was consumed as a pairing attempt. */
function pair_try(chat_id, uid, text) {
	const m = match(text, /^\/start\s+([0-9]{4,8})$/) || match(text, /^([0-9]{4,8})$/);
	if (!m)
		return false;
	const r = ubus_call('telegram_pair_consume', { code: trim(m[1]), uid: '' + uid }, 10);
	if (r == null) {
		tg_send_html(chat_id, '⚠ Проверить код не удалось (Control API недоступен). Попробуйте ещё раз.', null);
		return true;
	}
	if (r.result !== true) {
		log('pairing: wrong/expired code from user ' + uid + ' (' + ((r && r.error) || '?') + ')');
		tg_send_html(chat_id, '⛔ Код не принят (неверный или истёкший). Сгенерируйте новый на странице «Telegram-бот» в LuCI.', null);
		return true;
	}
	const role = (ROLE_RANK[r.role] != null) ? r.role : 'viewer';
	read_cfg();   /* fresh RBAC mirror (the daemon re-reads UCI each loop anyway) */
	log('pairing: user ' + uid + ' paired as ' + role);
	tg_send_html(chat_id, `✅ Пользователь привязан (роль: <b>${role}</b>). /help — список команд.`, null);
	return true;
}

/* Unknown user: a polite refusal in private chats (a foreign chat cannot
 * receive our message anyway — Telegram returns «chat not found», which is
 * harmless and logged); in the bound group chat — silent (no spam). */
function deny_unknown(chat_id, uid, ctype) {
	log('RBAC: unknown user ' + uid + ' in chat ' + chat_id + ' (' + ctype + ') — denied');
	if (ctype === 'private')
		tg_send_html(chat_id, '⛔ Нет доступа. Попросите владельца сгенерировать код привязки на странице «Telegram-бот» в LuCI и отправьте его мне.', null);
}

function deny_role(chat_id, role, need) {
	log('RBAC: action denied for role ' + role + ' (needs ' + need + ')');
	tg_send_html(chat_id, '⛔ Недостаточно прав: ваша роль «' + role + '», действие требует «' + need + '».', null);
}

/* ── data sources (the same ones the LuCI pages use) ──────────────────── */

function clash_get(path) {
	const raw = capture(`wget -qO- --timeout=3 ${API}${path} 2>/dev/null`);
	if (!length(trim(raw || ''))) return null;
	let j = null;
	try { j = json(raw); } catch (e) { j = null; }
	return j;
}

function node_label(tag) {
	/* Mirrors the rpcd node_label(): strip the cfg- prefix / -out suffix and
	 * read the human UCI label (hotswap.messages_node_names_not_cfg_ids). */
	let sid = replace('' + tag, /^cfg-/, '');
	sid = replace(sid, /-out$/, '');
	const fd = popen(`uci -q get homeproxy.${sid}.label 2>/dev/null`);
	let v = null;
	if (fd) { v = trim(fd.read('all') || ''); fd.close(); }
	return (v != null && length(v)) ? v : sid;
}

const SKIP_TAG = /^(direct-out|block-out|main-out|main-out-auto|zapret-out|byedpi-out|dns-out)$/;
const GROUP_TYPE = { Selector: true, URLTest: true, Fallback: true, Direct: true, Block: true, Reject: true, Compatible: true, Pass: true };

/* Real leaf nodes with delays, sorted by label — stable numbering for
 * /switch <n>. Delays come from the core history (empty for leaves outside
 * URLTest pools — shown as «—», lesson 56; /switch probes live instead). */
function list_nodes() {
	const j = clash_get('/proxies');
	if (!j || type(j.proxies) !== 'object')
		return null;
	let out = [];
	for (let tag in j.proxies) {
		if (match(tag, /-out$/) == null) continue;
		if (match(tag, /-shadowtls-out$/) != null) continue;
		if (match(tag, SKIP_TAG) != null) continue;
		const p = j.proxies[tag];
		if (type(p) !== 'object') continue;
		if (GROUP_TYPE[p.type]) continue;
		let delay = null;
		const h = p.history;
		if (type(h) === 'array' && length(h)) {
			const last = h[length(h) - 1];
			if (last && last.delay > 0) delay = int(last.delay);
		}
		push(out, { tag: tag, label: node_label(tag), delay: delay });
	}
	sort(out, (a, b) => (a.label + a.tag) > (b.label + b.tag) ? 1 : -1);
	return out;
}

/* ── commands (RU texts) ──────────────────────────────────────────────── */

function fmt_dur(s) {
	const d = int(s / 86400);
	const h = int((s % 86400) / 3600);
	const m = int((s % 3600) / 60);
	if (d > 0) return sprintf('%d д %d ч', d, h);
	if (h > 0) return sprintf('%d ч %d мин', h, m);
	return sprintf('%d мин', m);
}

function proc_up(name) {
	/* Ф1.4b: identity-grade liveness. mosdns — registry identity first, then
	 * the instance whose -c argument is OUR config (a foreign mosdns is not
	 * "ours"); nfqws2 — the live production queue pinned by its --qnum
	 * element (the tester's temp queue never counts); ciadpi — our loopback
	 * listen port element. */
	if (name === 'mosdns') {
		const e = pm_reg_get('mosdns');
		if (e != null && pm_entry_alive(e))
			return true;
		return length(pm_find({ exe: '/usr/bin/mosdns', arg: [
			'/var/run/homeproxy/multidns/mosdns.yaml',
			'/var/run/homeproxy/multidns/mosdns.candidate.yaml'
		] })) > 0;
	}
	if (name === 'nfqws2') {
		let qnum = '200';
		try {
			const c = uci_cfg_snap('zapret_qnum');
			if (c != null && length('' + c)) qnum = '' + c;
		} catch (e) {}
		return length(pm_find({ exe: 'nfqws2', arg_all: [ '--qnum=' + qnum ] })) > 0;
	}
	if (name === 'ciadpi')
		return length(pm_find({ exe: 'ciadpi', arg_all: [ '-p', '5335' ] })) > 0;
	return length(pm_find({ exe: name })) > 0;
}

/* One UCI value read (the bot reads config through `uci -q get` — the same
 * pattern as uci_get above; a fresh popen per call keeps hot-reload honest). */
function uci_cfg_snap(key) {
	const fd = popen(`uci -q get homeproxy.config.${key} 2>/dev/null`);
	let v = null;
	if (fd) {
		v = trim(fd.read('all') || '');
		fd.close();
	}
	return (length(v || '')) ? v : null;
}

function cmd_status() {
	const core_info = trim(readfile(RUN_DIR + '/core.info') || '');
	let core = 'неизвестно';
	try { const j = json(core_info || ''); if (j) core = esc_html((j.core_type || '?') + ' ' + (j.version || '')); } catch (e) {}
	let main_line = 'main-out: ?';
	const main = clash_get('/proxies/main-out');
	if (main && main.now) {
		let label = node_label(main.now);
		let dl = '';
		const h = clash_get(`/proxies/${main.now}/history`);
		const hist = (h && h.history && length(h.history)) ? h.history[length(h.history) - 1] : null;
		if (hist && hist.delay > 0) dl = ` (${hist.delay} ms)`;
		main_line = `Выход: <b>${esc_html(label)}</b>${dl}`;
	} else if (main == null || !main.now) {
		/* 404 body ({"message":...}) counts as absent too — custom mode. */
		main_line = 'Выход: main-out недоступен (custom-режим или ядро лежит)';
	}
	const zapret = proc_up('nfqws2') ? 'вкл' : 'выкл';
	const byedpi = proc_up('ciadpi') ? 'вкл' : 'выкл';
	const mosdns = proc_up('mosdns') ? 'вкл' : 'выкл';
	let learned = 0;
	const sf = readfile(STATS_FILE || '');
	if (sf) {
		try { const j = json(sf); if (j && j.learned) learned = (j.learned.domains || 0) + (j.learned.ips || 0); } catch (e) {}
	}
	/* Control line (plan 15): one glanceable summary of parental control. */
	let ctl_line = 'Контроль: выкл';
	try {
		if (main_opt('enabled', '0') === '1') {
			let blocked = 0;
			const states = client_states(time());
			for (let i = 0; i < length(states); i++)
				if (states[i].blocked)
					blocked++;
			ctl_line = (main_opt('paused', '0') === '1')
				? 'Контроль: пауза (всё разрешено)'
				: `Контроль: вкл · заблокировано: ${blocked}`;
		}
	} catch (e) { ctl_line = 'Контроль: ?'; }
	/* Ф8.2: режим маршрутизации + Safe Mode в статусе. */
	const rmode = uci_cfg_snap('routing_mode') || 'proxy_banned_ru';
	let mode_line = 'Режим: ' + esc_html(MODE_RU[rmode] || rmode);
	const safe_st = uci_tg_snap('safe');
	if (safe_st === '1') {
		const sprev = uci_tg_snap('safe_prev');
		mode_line += '\n🛡 <b>SAFE MODE</b>: выход = direct' +
			(length('' + (sprev || '')) ? ' (возврат узла ' + esc_html(sprev) + ': /safeoff)' : ' (возврат: /safeoff)');
	}
	return `<b>Re:HomeProxy</b>
Ядро: ${core}
${main_line}
Zapret: ${zapret} · ByeDPI: ${byedpi} · MultiDNS: ${mosdns}
Автоматизация: ${learned} записей
${esc_html(ctl_line)}
${mode_line}`;
}

function cmd_ping() {
	const up = time() - boot_ts;
	const load = trim(split(readfile('/proc/loadavg') || '', ' ')[0] || '?');
	const memf = readfile('/proc/meminfo') || '';
	const mm = match(memf, /MemAvailable:[[:space:]]+([0-9]+)/);
	const mem_mb = mm ? int(mm[1]) / 1024 : 0;
	return `pong
аптайм службы: ${fmt_dur(up)}
load(1m): ${esc_html(load)}
доступно RAM: ${sprintf('%.0f', mem_mb)} MB`;
}

function cmd_connections() {
	const j = clash_get('/connections');
	if (!j || type(j.connections) !== 'array' || !length(j.connections))
		return 'активных соединений нет';
	const conns = j.connections;
	sort(conns, (a, b) => (b.start || '') > (a.start || '') ? 1 : -1);
	let out = sprintf('активных: %d\n', length(conns));
	const n = (length(conns) > 10) ? 10 : length(conns);
	for (let i = 0; i < n; i++) {
		const c = conns[i];
		const meta = (c.metadata && c.metadata.host) ? c.metadata.host
			: ((c.metadata && c.metadata.destinationIP) ? c.metadata.destinationIP : '?');
		const chain = (c.chains && length(c.chains)) ? c.chains[0] : '?';
		out += `• ${esc_html(meta)} → ${esc_html(chain)}\n`;
	}
	if (length(conns) > n)
		out += `… и ещё ${length(conns) - n}`;
	return out;
}

function cmd_close() {
	const rc = system(`curl -s -m 5 -X DELETE ${API}/connections >/dev/null 2>&1`);
	return (rc === 0) ? 'все соединения закрыты' : 'Clash API отказал (ядро лежит?)';
}

/* Reply FIRST, then act: stop/restart kills this very daemon, so the
 * confirmation must be out before the command runs. Ф8.2: the action
 * itself rides the Control API (control_service_set — allowlist start/
 * stop/restart), not a bare shell from the bot. */
function do_service(action, chat_id) {
	let txt = '';
	if (action === 'stop') txt = '🛑 Останавливаю службу — это последнее сообщение до запуска. Запустить обратно: /service start';
	else if (action === 'restart') txt = '🔄 Перезапускаю службу (~10 с; /status подтвердит).';
	else if (action === 'start') txt = '▶️ Запускаю службу…';
	else return 'использование: /service start|stop|restart';
	log('service ' + action + ' via Telegram (Control API)');
	tg_send_html(chat_id, txt, null);
	const r = ubus_call('control_service_set', { action: action }, 15);
	if (r == null || r.result !== true)
		tg_send_html(chat_id, '⚠ Команда ушла, но Control API не подтвердил (' +
			esc_html('' + ((r && r.error) || 'rpcd недоступен')) + ').', null);
	return null;   /* already answered */
}

function cmd_snapshot() {
	const raw = capture(`ubus -t 30 call luci.homeproxy app_snapshot_create 2>/dev/null`);
	let j = null;
	try { j = json(raw || ''); } catch (e) { j = null; }
	if (j && j.result === true && j.snapshot)
		return `📸 Снапшот создан: <code>${esc_html(j.snapshot)}</code>`;
	return 'снапшот не удался' + ((j && j.error) ? (': ' + esc_html('' + j.error)) : '');
}

function cmd_status_engine() {
	const raw = capture(`ubus -t 8 call luci.homeproxy wizard_dpi_status 2>/dev/null`);
	let j = null;
	try { j = json(raw || ''); } catch (e) { j = null; }
	if (!j || !j.zapret)
		return 'статус движков недоступен (RPC не ответил)';
	const z = j.zapret || {};
	const b = j.byedpi || {};
	const nfq = z.nfqueue || {};
	let strat = trim('' + (z.strategy || ''));
	if (length(strat) > 200) strat = substr(strat, 0, 200) + '…';
	let bopts = trim('' + (b.opts || ''));
	if (length(bopts) > 200) bopts = substr(bopts, 0, 200) + '…';
	const corpus = j.corpus || {};
	return `<b>Обход DPI</b>
Zapret: ${z.enabled === true ? 'вкл' : 'выкл'} · ${z.running === true ? 'запущен' : 'остановлен'}${length(strat) ? ' · стратегия: <code>' + esc_html(strat) + '</code>' : ''}${(nfq.packets != null) ? sprintf('\nNFQUEUE: %d pkts / %d KB', int(nfq.packets), int((nfq.bytes || 0) / 1024)) : ''}
ByeDPI: ${b.enabled === true ? 'вкл' : 'выкл'} · ${b.running === true ? 'запущен' : 'остановлен'}${length(bopts) ? ' · <code>' + esc_html(bopts) + '</code>' : ''}${corpus.count ? sprintf('\nКорпус стратегий: %d', int(corpus.count)) : ''}`;
}

/* ── /logs (Р4): отчёт для поддержки. Собираем sanitized-бандл
 * (support_bundle.uc build, 10–30 с) и шлём файлом (<45 МБ); если сбор
 * не удался или архив велик — sanitized текст-отчёт кусками. ───────── */
function cmd_logs(chat_id) {
	tg_send_html(chat_id, 'Собираю отчёт для поддержки… (10–30 секунд, секреты вычищаются автоматически)', null);
	const rc = system('ucode /etc/homeproxy/scripts/support_bundle.uc build >/dev/null 2>&1', 120000);
	let meta = null;
	if (access('/tmp/ravnex_bundle_meta.json')) {
		try { meta = json(readfile('/tmp/ravnex_bundle_meta.json') || ''); } catch (e) { meta = null; }
	}
	if (rc === 0 && meta && meta.ok && meta.path && access(meta.path)) {
		const st = stat(meta.path);
		const size = st ? st.size : 0;
		if (size > 0 && size < 45 * 1024 * 1024) {
			const ok = tg_send_document(chat_id, meta.path,
				'Отчёт для поддержки Ravnex · ' + int(size / 1024) + ' КБ · секреты вычищены, самопроверка пройдена');
			if (ok)
				return;
		}
	}
	/* Фолбэк: быстрый текст-отчёт (уже sanitized самой утилитой). */
	const out = capture('ucode /etc/homeproxy/scripts/support_bundle.uc text 2>/dev/null');
	if (!length(trim(out))) {
		tg_send_html(chat_id, 'не удалось собрать отчёт — попробуйте ещё раз позже', null);
		return;
	}
	tg_send_html(chat_id, 'Архив недоступен — отправляю текст-отчёт кусками:', null);
	let rest = out;
	while (length(rest) > 0) {
		tg_send_html(chat_id, substr(rest, 0, MAXMSG), null);
		rest = substr(rest, MAXMSG);
	}
}

/* /nodes pagination (audit 42): NODES_PAGE nodes per page, the numbering
 * stays GLOBAL across pages so /switch N keeps its meaning; the page rides
 * in the callback data (stable — audit 20), never in an index of a live
 * list. */
function nodes_text(nodes, page) {
	const total = length(nodes);
	const pages = (total > 0) ? int((total + NODES_PAGE - 1) / NODES_PAGE) : 1;
	if (page == null || page < 0 || page >= pages)
		page = 0;
	const p0 = page * NODES_PAGE;
	const n = (p0 + NODES_PAGE < total) ? (p0 + NODES_PAGE) : total;
	let out = sprintf('<b>Узлы</b> (стр. %d/%d, номер = /switch N):\n', page + 1, pages);
	for (let i = p0; i < n; i++) {
		const nd = nodes[i];
		out += sprintf('%d. %s%s\n', i + 1, esc_html(nd.label),
			nd.delay ? ` — ${nd.delay} ms` : ' — —');
	}
	if (n === p0)
		out += '(узлов нет)';
	return out;
}

function nodes_kb(nodes, page) {
	const total = length(nodes);
	const pages = (total > 0) ? int((total + NODES_PAGE - 1) / NODES_PAGE) : 1;
	if (page == null || page < 0 || page >= pages)
		page = 0;
	const p0 = page * NODES_PAGE;
	const rows = [];
	for (let i = p0; i < (p0 + NODES_PAGE) && i < total; i += 2) {
		const row = [];
		for (let j = i; j < i + 2 && j < total; j++) {
			let lbl = nodes[j].label;
			if (length(lbl) > 22) lbl = substr(lbl, 0, 21) + '…';
			/* Telegram callback_data is capped at 64 bytes — skip overlong tags. */
			if (length('sw:' + nodes[j].tag) > 60)
				continue;
			push(row, [ lbl, 'sw:' + nodes[j].tag ]);
		}
		if (length(row))
			push(rows, row);
	}
	const nav = [];
	if (page > 0)
		push(nav, [ '⬅', 'act:nodes:' + (page - 1) ]);
	push(nav, [ sprintf('%d/%d', page + 1, pages), 'act:nodes:' + page ]);
	if (page + 1 < pages)
		push(nav, [ '➡', 'act:nodes:' + (page + 1) ]);
	push(rows, nav);
	push(rows, [ '🔄 Обновить', 'act:nodes:' + page ]);
	return kb_rows(rows);
}

/* Switch main-out WITHOUT a restart (the same PUT hotswap's switch_to uses);
 * refused when main-out does not exist (custom routing — гейт ч.74). The
 * hotswap antiflap adopts an external move as its pin, so this is safe. */
/* The actual switch: PUT /proxies/main-out (the same call hotswap's
 * switch_to uses), verified against the API, plus a live delay probe. */
function do_switch_tag(tag, label) {
	const body = sprintf('{"name":"%s"}', jesc(tag));
	const rc = system(`curl -s -o /dev/null -m 5 -X PUT -d ${shellquote(body)} ${shellquote(API + '/proxies/main-out')} 2>/dev/null`);
	const after = clash_get('/proxies/main-out');
	if (rc !== 0 || !after || after.now !== tag)
		return `переключение на ${esc_html(label)} не подтвердилось ядром`;
	/* Live confirmation probe (same probe init.d/metrics use). */
	const raw = capture(`curl -s -m 8 ${shellquote(API + '/proxies/' + tag + '/delay?timeout=5000&url=' + PROBE_URL)} 2>/dev/null`);
	const m = match(raw || '', /"delay": *([0-9]+)/);
	let probe = '';
	if (m) probe = sprintf('\nПроба: %d ms — узел жив.', int(m[1]));
	else probe = '\n⚠ Проба не прошла — узел может быть недоступен.';
	log('switched main-out to ' + tag + ' via Telegram');
	return `✅ Выход переключён: <b>${esc_html(label)}</b>${probe}
(без рестарта; Hot Swap примет смену как свой пин)`;
}

function cmd_switch(arg, chat_id) {
	const main = clash_get('/proxies/main-out');
	/* 404 body ({"message":...}) counts as absent — custom-mode gate (ч.74). */
	if (main == null || !main.now)
		return 'main-out не существует (режим Custom / ядро лежит) — переключение невозможно.';
	if (!length(trim(arg)))
		return 'использование: /switch <номер из /nodes> или <начало имени>';
	const nodes = list_nodes();
	if (!nodes || !length(nodes))
		return 'узлы не найдены (ядро лежит?)';
	let target = null;
	if (match(trim(arg), /^[0-9]+$/) != null) {
		const idx = int(trim(arg));
		if (idx < 1 || idx > length(nodes))
			return sprintf('нет узла №%d (всего %d — см. /nodes)', idx, length(nodes));
		target = nodes[idx - 1];
	} else {
		for (let i = 0; i < length(nodes); i++)
			if (nodes[i].label == arg) { target = nodes[i]; break; }
		if (!target)
			for (let i = 0; i < length(nodes); i++)
				if (substr(nodes[i].label, 0, length(trim(arg))) == trim(arg)) { target = nodes[i]; break; }
		if (!target)
			return 'узел не найден — точный или начальный фрагмент имени из /nodes';
	}
	return do_switch_tag(target.tag, target.label);
}

const HELP = '<b>Команды</b>\n' +
	'/menu — инлайн-меню (всё в кнопках)\n' +
	'/status — ядро, выход, движки, контроль\n' +
	'/nodes — узлы и задержки\n' +
	'/switch N — переключить выход (без рестарта)\n' +
	'/control — контроль (родительский): панель\n' +
	'/devices — устройства сети (блок / ⏱ временный / ✅ разрешить / 📶 Wi-Fi-блок)\n' +
	'/blocksite домен [№] — блок сайта (/unblocksite)\n' +
	'/pause · /resume — пауза контроля\n' +
	'/wifi — Wi-Fi сети вкл/выкл\n' +
	'/doctor — здоровье, сторож, recovery (🩺)\n' +
	'/repair — ручные ремонты по находкам (админ+)\n' +
	'/safe — Safe Mode: выход напрямую, DNS/firewall живы\n' +
	'/safeoff — вернуть прежний узел\n' +
	'/mode — режим маршрутизации (владелец)\n' +
	'/update — обновления: приложение, ядро, пакеты (владелец)\n' +
	'/cmd [-t сек] команда — произвольная команда роутеру (владелец)\n' +
	'/ping — аптайм, load, память\n' +
	'/connections — активные соединения\n' +
	'/close — закрыть все соединения\n' +
	'/service start|stop|restart — служба\n' +
	'/snapshot — снапшот конфигурации\n' +
	'/status_engine — Zapret/ByeDPI статус\n' +
	'/logs — отчёт для поддержки (архив файлом, секреты вычищены)\n' +
	'/mute · /unmute — пуш-уведомления вкл/выкл\n' +
	'/users — пользователи и роли (админ+)\n' +
	'/restart — перезапуск службы\n' +
	'/help — этот список\n\n' +
	'⚠ Опасные действия исполняются после второй кнопки «Подтвердить».';

/* RBAC state (Ф8.1): who is allowed and with which role (Admin+ view). */
function cmd_users() {
	let out = '<b>Пользователи RBAC</b>\n';
	for (let i = 0; i < length(ROLES); i++) {
		const r = ROLES[i];
		const us = cfg.users[r];
		out += '• <b>' + r + '</b> (' + length(us) + '): ' +
			(length(us) ? esc_html(join(', ', us)) : '—') + '\n';
	}
	if (users_count() === 0)
		out += '\nПользователей нет — выдайте доступ кодом привязки из LuCI.';
	return out;
}

/* Main inline menu (plan 15): every feature one tap away — no need to
 * remember command names. */
function main_menu_text() {
	return '<b>Re:HomeProxy — меню</b>\nЯдро, узлы, контроль, доктор и Safe Mode — в кнопках ниже.';
}

function main_menu_kb() {
	return kb_rows([
		[ [ '📊 Статус', 'act:refresh' ], [ '📡 Узлы', 'act:nodes' ] ],
		[ [ '🛡 Контроль', 'ctl:menu' ], [ '📶 Wi-Fi', 'ctl:wifi' ] ],
		[ [ '🩺 Доктор', 'act:doctor' ], [ '🛠 Ремонт', 'act:repair' ] ],
		[ [ '🆘 Safe Mode', 'act:safe' ], [ '🎚 Режим', 'act:mode' ] ],
		[ [ '⚙️ Движки', 'act:engine' ], [ '⬆ Обновления', 'act:update' ] ],
		[ [ '❓ Помощь', 'act:help' ] ]
	]);
}

/* ── push notifications (observer over run-state files) ───────────────── */

function push_enabled(kind) {
	if (cfg.mute === '1') return false;
	if (kind === 'hotswap') return cfg.push_hotswap === '1';
	if (kind === 'watchdog') return cfg.push_watchdog === '1';
	if (kind === 'learn') return cfg.push_learn === '1';
	if (kind === 'service') return cfg.push_service === '1';
	if (kind === 'control') return cfg.push_control === '1';
	return false;
}

function send_push(kind, text) {
	/* Dedup: identical text per kind within DEDUP_SEC is dropped. */
	const now = time();
	const prev = last_push[kind];
	if (prev && prev.text === text && (now - prev.ts) < DEDUP_SEC) {
		last_push[kind] = { text: text, ts: now };
		return;
	}
	last_push[kind] = { text: text, ts: now };
	if (!push_enabled(kind))
		return;   /* baselines already advanced — unmute will not replay */
	tg_send_html(allowed_chat, text, null);
}

/* ── Ф2.4: Event Bus subscription (one cursor, hotswap/urltest/automation) ──
 * The «Контроль» src=control stream is consumed by telegram_control.push_scan
 * with its own cursor. Here: the remaining sources. Toggles map like before —
 * push_hotswap guards src=hotswap, push_watchdog guards src=urltest,
 * push_learn guards src=automation — so user settings keep their meaning.
 * Durable cursor: daemon restart continues from the last consumed id (events
 * written during downtime are pushed, nothing replays); reboot wipes the
 * journal + cursor together → baseline at the head. */

/* Ф3.4: src=init (события старта службы — миграция routing_mode) идёт в
 * service-класс (toggle push_service), как сторожевые источники. Ф5.1/Ф5.2:
 * обновления подписок (src=subscribe) и rule-set'ов (src=rulesets) — тоже
 * service-класс. */
const BUS_SRC_KIND = { hotswap: 'hotswap', urltest: 'watchdog', automation: 'learn', sentinel: 'service', recovery: 'service', init: 'service', subscribe: 'service', rulesets: 'service' };

function bus_text(ev) {
	const who = trim('' + (ev.who || ''));
	const detail = trim('' + (ev.detail || ''));
	if (ev.src === 'init') {
		/* Ф3.4: старта службы — честные события конфигурации (миграция
		 * routing_mode со снимком; откат — вручную из снимка). */
		return '⚙️ <b>Служба</b>' + (length(who) ? ': <b>' + esc_html(who) + '</b>' : '') +
			(length(detail) ? '\n' + esc_html(detail) : '');
	}
	if (ev.src === 'sentinel') {
		if (ev.type === 'repair')
			return '🛠 <b>Сторож</b>: ' + esc_html(who || 'ремонт') +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'recovered')
			return '✅ <b>Сторож</b>: ' + esc_html(who || '') + ' — больше не наблюдается';
		if (ev.type === 'loop')
			return '🔁 <b>Сторож</b>: цикл восстановления' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		return '🛡 <b>Сторож</b>' + (length(who) ? ': <b>' + esc_html(who) + '</b>' : '') +
			(length(detail) ? '\n' + esc_html(detail) : '');
	}
	if (ev.src === 'recovery') {
		/* Ф2.3: координатор восстановления — ремонты, блокировки, ручные
		 * заявки и предложения (U4: оповещение С ПРЕДЛОЖЕНИЕМ исправления). */
		if (ev.type === 'repair')
			return '🛠 <b>Recovery</b>: ' + esc_html(who || 'ремонт') +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'blocked')
			return '🔁 <b>Recovery</b>: авто-ремонт приостановлен' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'unblocked')
			return '✅ <b>Recovery</b>: ' + esc_html(who || '') + ' — кампания возобновлена' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'manual')
			return '🖐 <b>Recovery</b>: ' + esc_html(who || 'ручное действие') +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'proposal')
			return '💡 <b>Recovery</b>: предложение' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'recovered')
			return '✅ <b>Recovery</b>: ' + esc_html(who || '') + ' — проблема ушла';
		return '🩺 <b>Recovery</b>' + (length(who) ? ': <b>' + esc_html(who) + '</b>' : '') +
			(length(detail) ? '\n' + esc_html(detail) : '');
	}
	if (ev.src === 'hotswap')
		return '🔄 <b>Hot Swap</b>' +
			(length(who) ? ': <b>' + esc_html(who) + '</b>' : '') +
			(length(detail) ? '\n' + esc_html(detail) : '');
	/* Ф5.1/Ф5.2: подписки и rule-set'ы (service-класс). */
	if (ev.src === 'subscribe') {
		if (ev.type === 'done')
			return '✅ <b>Подписки обновлены</b>' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'aborted')
			return '⚠️ <b>Подписки: обновление отклонено</b> — узлы не тронуты' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		if (ev.type === 'rolled_back')
			return '↩️ <b>Подписки: откат</b> — узлы восстановлены из бекапа' +
				(length(detail) ? '\n' + esc_html(detail) : '');
		return '❗ <b>Подписки</b>' + (length(detail) ? ': ' + esc_html(detail) : '');
	}
	if (ev.src === 'rulesets') {
		if (ev.type === 'seed_done')
			return '✅ <b>Rule-sets</b>: ' + esc_html(detail || 'локальные копии обновлены');
		if (ev.type === 'seed_failed')
			return '⚠️ <b>Rule-sets</b>: ' + esc_html(detail || 'загрузка копий с ошибками');
		if (ev.type === 'geo_done')
			return '✅ <b>База RU-geo обновлена</b>: ' + esc_html(detail || '');
		if (ev.type === 'geo_failed')
			return '⚠️ <b>База RU-geo</b>: ' + esc_html(detail || 'обновление не применено');
		return '📦 <b>Rule-sets</b>' + (length(detail) ? ': ' + esc_html(detail) : '');
	}
	if (ev.src === 'urltest') {
		if (ev.type === 'recovered')
			return '✅ <b>URLTest</b>: узел восстановился' +
				(length(who) ? ': ' + esc_html(who) : '');
		if (ev.type === 'reload')
			return '♻️ <b>URLTest</b>' + (length(detail) ? ': ' + esc_html(detail) : '');
		return '⛔ <b>URLTest</b>: узел помечен мёртвым' +
			(length(who) ? ': ' + esc_html(who) : '') +
			(length(detail) ? '\n' + esc_html(detail) : '');
	}
	/* automation */
	if (ev.type === 'outage')
		return '⚠️ <b>Автоматизация</b>: ' + esc_html(detail || 'авария: обучение приостановлено');
	if (ev.type === 'outage_end')
		return '✅ <b>Автоматизация</b>: ' + esc_html(detail || 'авария завершена');
	if (ev.type === 'heal')
		return '✅ <b>Автоматизация</b>: самолечение' +
			(length(detail) ? ':\n' + esc_html(detail) : '');
	return '🧠 <b>Автоматизация</b>' + (length(who) ? ': ' + esc_html(who) : '') +
		(length(detail) ? '\n' + esc_html(detail) : '');
}

function push_bus() {
	/* Baseline ONCE per daemon run: durable cursor (same boot) or the journal
	 * head. A zero head is a LEGITIMATE baseline (empty journal after boot) —
	 * re-baselining on every scan would silently skip the first events. */
	if (!bus_ready) {
		bus_ready = true;
		const cur = bus_cursor_get('telegram-bus');
		bus_id = (cur != null) ? int(cur) : bus_head();
		bus_saved = bus_id;
	}
	const evs = bus_tail(200, bus_id);
	let sent = 0;
	for (let i = 0; i < length(evs); i++) {
		const ev = evs[i];
		if (ev.id <= bus_id)
			continue;
		/* Cap BEFORE consuming: events past the cap stay unconsumed (cursor
		 * keeps their id) — the next scan resumes, nothing is lost. */
		if (sent >= 10) {
			log('bus: 10 pushes sent this scan, tail deferred');
			break;
		}
		bus_id = ev.id;
		const kind = BUS_SRC_KIND[ev.src];
		if (kind == null || !push_enabled(kind))
			continue;   /* baseline advances regardless of toggles — unmute never replays */
		sent++;
		send_push(kind, bus_text(ev));
	}
	if (bus_id !== bus_saved) {
		bus_cursor_set('telegram-bus', bus_id);
		bus_saved = bus_id;
	}
}

function push_service() {
	const j = clash_get('/version');
	const ok = (j != null);
	if (seen.core_ok === null) { seen.core_ok = ok; return; }
	if (ok === seen.core_ok) return;
	seen.core_ok = ok;
	if (!ok)
		send_push('service', '⛔ <b>Ядро не отвечает</b> (Clash API недоступен).');
	else
		send_push('service', '✅ <b>Ядро снова отвечает</b>.');
}

/* ── подтверждения второй кнопкой (Ф8.2/D25) ────────────────────────────
 * Опасные действия исполняются ТОЛЬКО после явного тапа «Подтвердить».
 * Pending живёт в памяти с TTL 5 минут и не переживает рестарт демона
 * (честно: «срок подтверждения истёк»); роль перепроверяется в момент
 * тапа — кнопку нельзя перепродать другому пользователю. ──────────────── */
/* App self-update: prepare → download → install (the SAME chain the UI
 * runs; the package scripts restart rpcd, the apply door restarts the
 * service — the bot warns FIRST and may die mid-chain, by design). */
function upd_app_chain(chat_id) {
	const prep = ubus_call('app_prepare_install', {}, 30);
	if (prep == null || prep.error != null) {
		tg_send_html(chat_id, '⚠ Приложение: подготовка не удалась (' +
			esc_html('' + ((prep && prep.error) || 'rpcd недоступен')) + ').', null);
		return;
	}
	tg_send_html(chat_id, '⬇ Обновляю приложение до ' + esc_html('' + (prep.version || '?')) +
		'… LuCI и бот перезапустятся; /status после перезапуска покажет версию.', null);
	capture(`ucode /usr/share/homeproxy/scripts/core_mgmt.uc download_pkg ${shellquote('' + prep.app.dl_url)} ${shellquote('' + prep.app.tmp_path)} 2>&1`);
	if (!access('' + prep.app.tmp_path)) {
		tg_send_html(chat_id, '⚠ Приложение: скачивание не удалось — обновление НЕ выполнено.', null);
		return;
	}
	let i18n = '';
	if (prep.i18n) {
		capture(`ucode /usr/share/homeproxy/scripts/core_mgmt.uc download_pkg ${shellquote('' + prep.i18n.dl_url)} ${shellquote('' + prep.i18n.tmp_path)} 2>&1`);
		if (access('' + prep.i18n.tmp_path))
			i18n = '' + prep.i18n.tmp_path;
	}
	const inst = ubus_call('app_install_pkg', {
		app_path: '' + prep.app.tmp_path, i18n_path: i18n, pkg_manager: '' + (prep.pkg_manager || 'apk')
	}, 150);
	if (inst && inst.result === true)
		tg_send_html(chat_id, '✅ Пакет установлен — служба перезапускается через apply-дверь. Бот вернётся сам.', null);
	else
		tg_send_html(chat_id, '⚠ Установка не удалась: ' +
			esc_html('' + ((inst && inst.error) || 'rpcd недоступен')), null);
}

/* Core install: detached runner + progress in core_install_status (the bot
 * does NOT wait minutes — /update shows the live stage on the next call). */
function upd_core_start(chat_id, core) {
	const r = ubus_call('core_install_start', { core: core, variant: '' }, 15);
	if (r && r.result === true)
		tg_send_html(chat_id, '⬇ Установка ядра ' + esc_html(core) + ' запущена в фоне (скачивание ~46–95 МБ). Стадия: /update.', null);
	else
		tg_send_html(chat_id, '⚠ Установка ядра не запущена: ' +
			esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
}

/* Engine package (byedpi/zapret/mosdns): prepare → download → install. */
function upd_pkg_chain(chat_id, name) {
	const prep = ubus_call(name + '_prepare_install', {}, 30);
	if (prep == null || prep.error != null) {
		tg_send_html(chat_id, '⚠ ' + esc_html(name) + ': подготовка не удалась (' +
			esc_html('' + ((prep && prep.error) || 'rpcd недоступен')) + ').', null);
		return;
	}
	tg_send_html(chat_id, '⬇ Скачиваю ' + esc_html(name) + '… (бот занят ~1–2 мин, отчёт следующим сообщением)', null);
	capture(`ucode /usr/share/homeproxy/scripts/core_mgmt.uc download_pkg ${shellquote('' + prep.dl_url)} ${shellquote('' + prep.tmp_path)} 2>&1`);
	if (!access('' + prep.tmp_path)) {
		tg_send_html(chat_id, '⚠ ' + esc_html(name) + ': скачивание не удалось — обновление НЕ выполнено.', null);
		return;
	}
	const iargs = { tmp_path: '' + prep.tmp_path };
	if (name !== 'mosdns')
		iargs.pkg_manager = '' + (prep.pkg_manager || 'apk');
	const inst = ubus_call(name + '_install_pkg', iargs, 150);
	if (inst && inst.result === true)
		tg_send_html(chat_id, '✅ ' + esc_html(name) + ': установлен.', null);
	else
		tg_send_html(chat_id, '⚠ ' + esc_html(name) + ': установка не удалась: ' +
			esc_html('' + ((inst && inst.error) || 'rpcd недоступен')), null);
}

const CONFIRM_TTL = 300;
const CONFIRM_MAX = 8;
let confirms = {};      /* key -> { chat, role, kind, payload, ts } */
let confirm_seq = 0;

function confirm_gc() {
	const now = time();
	for (let k in confirms) {
		const c = confirms[k];
		if (c == null || c.ts + CONFIRM_TTL < now)
			delete confirms[k];
	}
	let n = 0;
	for (let k in confirms)
		n++;
	while (n >= CONFIRM_MAX) {
		let oldest = null, oldest_k = '';
		for (let k in confirms)
			if (confirms[k] && (oldest == null || confirms[k].ts < oldest)) {
				oldest = confirms[k].ts;
				oldest_k = k;
			}
		if (!length(oldest_k))
			break;
		delete confirms[oldest_k];
		n--;
	}
}

/* Shows the confirmation card; role = the role the ASKER must keep at the
 * tap time (the payload carries everything the executor needs). */
function confirm_ask(chat_id, role, kind, payload, title, warn_text) {
	confirm_gc();
	confirm_seq = (confirm_seq + 1) % 1000000;
	const key = '' + confirm_seq;
	confirms[key] = { chat: chat_id, role: role, kind: kind, payload: payload, ts: time() };
	tg_send_html(chat_id,
		'⚠ <b>' + esc_html(title) + '</b>\n' + esc_html(warn_text) +
		'\nПодтвердите действие второй кнопкой — она живёт 5 минут.',
		kb_rows([ [ [ '✅ Подтвердить', 'cfm:' + key ], [ '✖ Отмена', 'cfx:' + key ] ] ]));
}

function confirm_drop(key, chat_id, cbid) {
	const c = confirms[key];
	delete confirms[key];
	if (c) {
		tg_answer_cb(cbid, 'Отменено');
		if (c.chat === chat_id)
			tg_send_html(chat_id, '✖ Отменено — ничего не изменено.', null);
	} else
		tg_answer_cb(cbid, 'Срок подтверждения истёк');
}

/* Title line for the rep:/unb: confirmation cards. */
function rep_unb_title(prefix, key) {
	return (prefix === 'rep:')
		? ('Выполнить ремонт «' + key + '»?')
		: ('Разблокировать кампанию «' + key + '»?');
}

function confirm_resolve(key, chat_id, role, cbid) {
	const c = confirms[key];
	if (c == null) {
		tg_answer_cb(cbid, 'Срок подтверждения истёк');
		return;
	}
	delete confirms[key];
	if (c.chat !== chat_id) {
		tg_answer_cb(cbid, 'Чужое подтверждение');
		return;
	}
	if (!role_ok(role, c.role)) {
		log('RBAC: confirm denied for role ' + role + ' (needs ' + c.role + ')');
		tg_answer_cb(cbid, 'Недостаточно прав');
		tg_send_html(chat_id, '⛔ Подтверждение отклонено: ваша роль «' + role + '», действие требует «' + c.role + '».', null);
		return;
	}
	confirm_exec(c, chat_id, cbid);
}

/* Executes a confirmed action — each kind has exactly ONE place where the
 * mutation happens. */
function confirm_exec(c, chat_id, cbid) {
	const kind = c.kind;
	if (kind === 'service') {
		tg_answer_cb(cbid, 'Выполняю');
		do_service(c.payload, chat_id);
		return;
	}
	if (kind === 'mode') {
		tg_answer_cb(cbid, 'Меняю режим');
		tg_send_html(chat_id, '🎚 Меняю режим на <b>' + esc_html(MODE_RU[c.payload] || c.payload) +
			'</b> — служба перезапустится (~30 с), затем /status подтвердит.', null);
		const r = ubus_call('control_mode_set', { mode: c.payload }, 15);
		if (r == null || r.result !== true)
			tg_send_html(chat_id, '⚠ Смена режима не подтверждена: ' +
				esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
		else if (r.unchanged === true)
			tg_send_html(chat_id, 'Режим уже «' + esc_html(MODE_RU[c.payload] || c.payload) + '» — ничего не изменено.', null);
		return;
	}
	if (kind === 'wifi') {
		const parts = split('' + c.payload, '|');
		const iface = (length(parts) > 0) ? parts[0] : '';
		const off = (length(parts) > 1 && parts[1] === '1');
		tg_answer_cb(cbid, off ? 'Выключаю Wi-Fi' : 'Включаю Wi-Fi');
		try { ctrl.wifi_toggle(ctrl_api, chat_id, iface, off, cbid); }
		catch (e) { log('wifi exec: ' + e); }
		return;
	}
	if (kind === 'dev') {
		const parts = split('' + c.payload, '|');
		const act = (length(parts) > 0) ? parts[0] : '';
		const ref = (length(parts) > 1) ? parts[1] : '';
		tg_answer_cb(cbid, 'Выполняю');
		try { ctrl.dev_action(ctrl_api, ref, act, cbid, chat_id); }
		catch (e) { log('dev exec: ' + e); }
		return;
	}
	if (kind === 'rule_add') {
		const parts = split('' + c.payload, '|');
		const doms = (length(parts) > 0) ? parts[0] : '';
		const cids = (length(parts) > 1) ? parts[1] : '';
		tg_answer_cb(cbid, 'Добавляю');
		try { ctrl.blocksite_exec(ctrl_api, chat_id, doms, cids, cbid); }
		catch (e) { log('rule_add exec: ' + e); }
		return;
	}
	if (kind === 'rule_del') {
		tg_answer_cb(cbid, 'Удаляю');
		try { ctrl.rule_delete_exec(ctrl_api, chat_id, '' + c.payload, cbid); }
		catch (e) { log('rule_del exec: ' + e); }
		return;
	}
	if (kind === 'rule_del_domain') {
		tg_answer_cb(cbid, 'Удаляю');
		try { ctrl.unblocksite_exec(ctrl_api, chat_id, '' + c.payload, cbid); }
		catch (e) { log('rule_del_domain exec: ' + e); }
		return;
	}
	if (kind === 'repair' || kind === 'unblock') {
		tg_answer_cb(cbid, 'Заявка…');
		const r = ubus_call('recovery_action', {
			action: (kind === 'repair') ? 'repair' : 'unblock',
			target: '' + c.payload, note: 'manual request via Telegram'
		}, 15);
		if (r && r.result === true)
			tg_send_html(chat_id, '🛠 Заявка принята координатором (seq ' + esc_html('' + (r.seq || '')) +
				') — исполнение в ближайшем тике. /doctor покажет результат.', null);
		else
			tg_send_html(chat_id, '⚠ Заявка не принята: ' +
				esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
		return;
	}
	if (kind === 'upd') {
		tg_answer_cb(cbid, 'Запускаю');
		const p = '' + c.payload;
		if (p === 'app')
			upd_app_chain(chat_id);
		else if (substr(p, 0, 5) === 'core:')
			upd_core_start(chat_id, substr(p, 5));
		else if (substr(p, 0, 4) === 'pkg:')
			upd_pkg_chain(chat_id, substr(p, 4));
		else
			tg_send_html(chat_id, 'неизвестная цель обновления', null);
		return;
	}
	if (kind === 'exec') {
		/* Ф8.3/D15: the whole exec flow lives in the «Контроль» module (an
		 * import is visible everywhere — a locally declared function would
		 * NOT be visible from here: no hoisting in this ucode dialect). */
		try { ctrl.exec_run(ctrl_api, c.chat, c.payload, cbid); }
		catch (e) { log('exec run: ' + e); }
		return;
	}
	tg_answer_cb(cbid, '');
}

/* ── Ф8.2/D25: режимы, Safe Mode, доктор, ремонт, обновления ──────────── */

/* Primitives handed to the «Контроль» module. ч.118: moved ABOVE push_scan —
 * in this ucode dialect a name declared LATER is invisible to a function
 * defined earlier (no hoisting at all; lesson 126), so push_scan's
 * ctrl.push_scan(ctrl_api) compiled as an unresolved lookup and EVERY
 * control push died with "access to undeclared variable ctrl_api" — the
 * feature never fired once since plan 14 (each failure was caught and
 * logged, the bot itself kept working). All referenced primitives are
 * declared above this block; push_scan follows it. */
const ctrl_api = {
	send_html: tg_send_html,
	kb_rows: kb_rows,
	answer_cb: tg_answer_cb,
	esc_html: esc_html,
	jesc: jesc,
	log: log,
	uci_get: uci_get,
	push: send_push,
	/* Ф8.2: the «Контроль» module asks its own second-button confirmations
	 * for the HEAVY actions and quiets the matching event pushes (the bot's
	 * own actions must not echo back into the same chat). */
	confirm_ask: confirm_ask,
	role: 'viewer',
	quiet: { until: 0 },
	maxmsg: MAXMSG
};

function push_scan() {
	try { push_bus(); } catch (e) { log('push bus: ' + e); }
	try { push_service(); } catch (e) { log('push service: ' + e); }
	try { ctrl.push_scan(ctrl_api); } catch (e) { log('push control: ' + e); }
}

const ST_RU = { ok: '✅ норма', degraded: '⚠️ деградация', down: '⛔ недоступен', off: '⚪ выключен' };

function cmd_mode_text() {
	const cur = uci_cfg_snap('routing_mode') || 'proxy_banned_ru';
	return '<b>Режим маршрутизации</b>\nТекущий: <b>' + esc_html(MODE_RU[cur] || cur) + '</b>' +
		'\nСмена режима перезапускает службу (~30 с).';
}

function mode_kb() {
	const cur = uci_cfg_snap('routing_mode') || 'proxy_banned_ru';
	const mk = (v) => [ (cur === v ? '• ' : '') + (MODE_RU[v] || v), 'mdo:' + v ];
	return kb_rows([
		[ mk('proxy_banned_ru'), mk('global') ],
		[ mk('direct') ],
		[ '⬅ Меню', 'act:menu' ]
	]);
}

function cmd_mode_ask(chat_id, role, mode) {
	confirm_ask(chat_id, role, 'mode', mode,
		'Сменить режим на «' + (MODE_RU[mode] || mode) + '»?',
		'Служба перезапустится (~30 с), активные соединения оборвутся. Прежний режим: ' +
		esc_html(MODE_RU[uci_cfg_snap('routing_mode') || 'proxy_banned_ru'] || '?') + '.');
}

/* Safe Mode (A.3): instant escape hatch — NO confirmation (the whole point
 * is one tap to safety); DNS/firewall/engines stay up by construction. */
function cmd_safe(chat_id) {
	tg_send_html(chat_id, '🛡 Включаю Safe Mode: выход пойдёт напрямую, а MultiDNS/zapret/firewall остаются включёнными. Служба перезапустится (~30 с); /status подтвердит.', null);
	const r = ubus_call('control_safe_set', { enable: '1' }, 15);
	if (r == null || r.result !== true)
		tg_send_html(chat_id, '⚠ Safe Mode не включён: ' +
			esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
	else if (r.unchanged === true)
		tg_send_html(chat_id, 'Выход уже прямой — Safe Mode не требуется.', null);
}

function cmd_safeoff(chat_id) {
	tg_send_html(chat_id, '↩ Выхожу из Safe Mode: возвращаю прежний главный узел. Служба перезапустится (~30 с).', null);
	const r = ubus_call('control_safe_set', { enable: '0' }, 15);
	if (r == null || r.result !== true)
		tg_send_html(chat_id, '⚠ Не выполнено: ' +
			esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
	else
		tg_send_html(chat_id, '✅ Главный узел возвращён (' + esc_html('' + (r.restored || '?')) + '); /status покажет живой выход.', null);
}

/* ДОКТОР (Ф8.2): статусы/ремонт/лечение как интерфейс к Recovery/Sentinel —
 * один вызов health_explain отдаёт health+sentinel+recovery и честные
 * объяснения. Читают все роли; ремонты — отдельная команда (admin). */
function doctor_text() {
	const j = ubus_call('health_explain', {}, 30);
	if (j == null || j.result !== true)
		return 'статус здоровья недоступен (RPC не ответил — rpcd или демоны?)';
	const h = (j.health && j.health.data) ? j.health.data : null;
	const entries = (h && h.entries) ? h.entries : {};
	const overall = (h && h.overall != null) ? '' + h.overall : '?';
	let out = '<b>🩺 Доктор</b>\nОбщее состояние: <b>' + (ST_RU[overall] || esc_html(overall)) + '</b>';
	const bad = [];
	for (let k in entries) {
		const e = entries[k];
		const st = '' + (e.status || 'off');
		if (st === 'ok' || st === 'off')
			continue;
		push(bad, e);
	}
	if (length(bad)) {
		out += '\n\n<b>Проблемы:</b>';
		for (let i = 0; i < length(bad) && i < 10; i++)
			out += '\n• ' + esc_html(bad[i].label || bad[i].name) + ': ' +
				(ST_RU['' + bad[i].status] || esc_html('' + bad[i].status)) +
				(length('' + (bad[i].reason || '')) ? ' — ' + esc_html('' + bad[i].reason) : '');
	} else
		out += '\nВсе компоненты в норме.';
	const rc = (j.recovery && j.recovery.data) ? j.recovery.data : null;
	if (rc) {
		let rline = '\n\nRecovery: ' + ((rc.overall === 'active') ? 'кампания активна' : 'ок');
		if (int(rc.active_keys || 0) > 0)
			rline += ' · активных ключей: ' + int(rc.active_keys);
		if (int(rc.blocked_keys || 0) > 0)
			rline += ' · заблокировано кампаний: ' + int(rc.blocked_keys);
		const until = int(rc.manual_freeze_until || 0);
		if (until > time())
			rline += ' · авто-ремонты заморожены ещё ' + fmt_dur(until - time());
		out += rline;
	}
	const fresh = (j.health && j.health.fresh === true);
	const age = (j.health && j.health.age != null) ? int(j.health.age) : null;
	out += '\n<i>данные: ' + (fresh ? ('свежие (' + age + ' с)') : 'пересчитаны сейчас') + '</i>';
	return out;
}

function repair_view() {
	const j = ubus_call('health_explain', {}, 30);
	if (j == null || j.result !== true)
		return { text: 'список ремонтов недоступен (RPC не ответил)', kb: null };
	const exs = (type(j.explains) === 'array') ? j.explains : [];
	const rep = [], unb = [];
	for (let i = 0; i < length(exs); i++) {
		const ex = exs[i];
		if (ex.status === 'ok' || !ex.campaign || !length('' + ex.campaign.key))
			continue;
		if (ex.repairable === true)
			push(rep, ex);
		else if (ex.unblockable === true)
			push(unb, ex);
	}
	if (!length(rep) && !length(unb))
		return { text: '🛠 Ремонты не требуются — координатор не видит проблем с ручным ремонтом. /doctor — общий статус.', kb: null };
	let out = '<b>🛠 Ремонт</b>\n';
	const rows = [];
	for (let i = 0; i < length(rep) && i < 8; i++) {
		const ex = rep[i];
		out += '• ' + esc_html(ex.label || ex.name) + ': ' + (ST_RU['' + ex.status] || esc_html('' + ex.status)) +
			(length('' + (ex.reason || '')) ? ' — ' + esc_html('' + ex.reason) : '') + '\n';
		push(rows, [ '🛠 ' + substr('' + (ex.label || ex.name), 0, 18), 'rep:' + ex.campaign.key ]);
	}
	for (let i = 0; i < length(unb) && i < 4; i++) {
		const ex = unb[i];
		out += '⛔ ' + esc_html(ex.label || ex.name) + ' — кампания заблокирована\n';
		push(rows, [ '🔓 Разблокировать', 'unb:' + ex.campaign.key ]);
	}
	push(rows, [ '⬅ Меню', 'act:menu' ]);
	return { text: out, kb: kb_rows(rows) };
}

/* Обновления (Ф8.2/D25): версии и доступные обновления; кнопки — только
 * для того, что умеет сама (ядро — core_install_start; приложение и пакеты
 * движков — prepare → download → install, та же цепочка, что в UI). */
function update_text() {
	let out = '<b>Обновления</b>\n';
	const ap = ubus_call('app_check_update', {}, 25);
	if (ap && ap.latest_version != null)
		out += 'Приложение: ' + esc_html('' + (ap.installed_version || '—')) + ' → ' +
			esc_html('' + ap.latest_version) + (ap.update_available ? ' — <b>есть обновление</b>' : '') + '\n';
	else
		out += 'Приложение: проверка не удалась (GitHub?)\n';
	const ci = trim(readfile(RUN_DIR + '/core.info') || '');
	try {
		const cj = json(ci || '');
		if (cj)
			out += 'Ядро: ' + esc_html((cj.core_type || '?') + ' ' + (cj.version || '')) + '\n';
	} catch (e) {}
	const cis = ubus_call('core_install_status', {}, 10);
	if (cis && cis.running === true)
		out += '⚠ Установка ядра уже идёт' + (cis.stage ? ' (' + esc_html('' + cis.stage) + ')' : '') + '\n';
	const rows = [];
	if (ap && ap.update_available === true)
		push(rows, [ '⬆ Приложение', 'upd:app' ]);
	const engs = [ 'byedpi', 'zapret', 'mosdns' ];
	for (let i = 0; i < length(engs); i++) {
		const name = engs[i];
		const r = ubus_call(name + '_check_update', {}, 25);
		if (r && r.latest_version != null) {
			out += esc_html(name) + ': ' + esc_html('' + (r.installed_version || '—')) + ' → ' +
				esc_html('' + r.latest_version) + (r.update_available ? ' — <b>есть обновление</b>' : '') + '\n';
			if (r.update_available === true)
				push(rows, [ '⬆ ' + name, 'upd:pkg:' + name ]);
		} else
			out += esc_html(name) + ': проверка не удалась (GitHub?)\n';
	}
	push(rows, [ '⬆ Ядро (hiddify-core)', 'upd:core:hiddify' ]);
	push(rows, [ '⬅ Меню', 'act:menu' ]);
	return { text: out, kb: kb_rows(rows) };
}

/* ── dispatch ─────────────────────────────────────────────────────────── */

/* Minimum role per command (Ф8.1, audit 1.1): the gate runs BEFORE any
 * dispatch — including the «Контроль» module commands. */
const CMD_MIN = {
	status: 'viewer', ping: 'viewer', connections: 'viewer', menu: 'viewer',
	start: 'viewer', help: 'viewer', nodes: 'viewer', status_engine: 'viewer',
	doctor: 'viewer',
	control: 'viewer', devices: 'viewer', sites: 'viewer', wifi: 'viewer',
	safe: 'operator', safeoff: 'operator',
	switch: 'operator', close: 'operator', mute: 'operator', unmute: 'operator',
	pause: 'operator', resume: 'operator',
	service: 'admin', restart: 'admin', snapshot: 'admin', logs: 'admin',
	blocksite: 'admin', unblocksite: 'admin', users: 'admin', repair: 'admin',
	mode: 'owner', update: 'owner', cmd: 'owner'
};

function cmd_need(cmd) {
	return CMD_MIN[cmd] || 'viewer';
}

function handle_command(chat_id, text, role) {
	const m = match(text, /^\/([a-z_]+)(@[A-Za-z0-9_]*)?(.*)$/);
	if (!m) return;
	const cmd = m[1];
	const rest = trim(m[3] || '');
	const need = cmd_need(cmd);
	if (!role_ok(role, need)) {
		deny_role(chat_id, role, need);
		return;
	}
	/* «Контроль» commands (/control /devices /sites /blocksite /unblocksite
	 * /pause /resume /wifi) — the module answers them itself (already gated
	 * by the CMD_MIN check above). Ф8.2: the module sees the ASKER's role
	 * (api.role) for its own second-button confirmations. */
	try {
		ctrl_api.role = role;
		if (ctrl.handle_command(ctrl_api, chat_id, cmd, rest))
			return;
	} catch (e) {
		log('control cmd: ' + e);
	}
	if (cmd === 'status') {
		tg_send_html(chat_id, cmd_status(), kb_rows([ [ 'Узлы', 'act:nodes' ], [ 'Снапшот', 'act:snapshot' ], [ 'Перезапуск', 'act:restart' ] ]));
	} else if (cmd === 'ping') {
		tg_send_html(chat_id, cmd_ping(), null);
	} else if (cmd === 'connections') {
		tg_send_html(chat_id, cmd_connections(), null);
	} else if (cmd === 'close') {
		tg_send_html(chat_id, cmd_close(), null);
	} else if (cmd === 'restart') {
		confirm_ask(chat_id, role, 'service', 'restart',
			'Перезапустить службу?',
			'Активные соединения оборвутся (~10 с). Это последний шанс отменить.');
	} else if (cmd === 'service') {
		if (rest === 'stop' || rest === 'restart')
			confirm_ask(chat_id, role, 'service', rest,
				(rest === 'stop') ? 'Остановить службу?' : 'Перезапустить службу?',
				(rest === 'stop')
					? 'Прокси, DNS-перехват и этот бот остановятся. Запуск обратно: /service start.'
					: 'Активные соединения оборвутся (~10 с).');
		else {
			const r = do_service(rest, chat_id);
			if (r != null) tg_send_html(chat_id, esc_html(r), null);
		}
	} else if (cmd === 'nodes') {
		const nodes = list_nodes();
		if (!nodes || !length(nodes))
			tg_send_html(chat_id, 'узлы не найдены (ядро лежит?)', null);
		else
			tg_send_html(chat_id, nodes_text(nodes, 0), nodes_kb(nodes, 0));
	} else if (cmd === 'users') {
		tg_send_html(chat_id, cmd_users(), null);
	} else if (cmd === 'switch') {
		tg_send_html(chat_id, cmd_switch(rest, chat_id), null);
	} else if (cmd === 'snapshot') {
		tg_send_html(chat_id, cmd_snapshot(), null);
	} else if (cmd === 'logs') {
		cmd_logs(chat_id);
	} else if (cmd === 'status_engine') {
		tg_send_html(chat_id, cmd_status_engine(), kb_rows([ [ '🔄 Обновить', 'act:engine' ] ]));
	} else if (cmd === 'mute') {
		const r = ubus_call('telegram_flag_set', { key: 'mute', value: '1' }, 10);
		if (r && r.result === true) {
			cfg.mute = '1';
			tg_send_html(chat_id, '🔇 Пуш-уведомления выключены (команды работают). /unmute — обратно.', null);
		} else
			tg_send_html(chat_id, '⚠ Не удалось: ' + esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
	} else if (cmd === 'unmute') {
		const r = ubus_call('telegram_flag_set', { key: 'mute', value: '0' }, 10);
		if (r && r.result === true) {
			cfg.mute = '0';
			tg_send_html(chat_id, '🔔 Пуш-уведомления включены.', null);
		} else
			tg_send_html(chat_id, '⚠ Не удалось: ' + esc_html('' + ((r && r.error) || 'rpcd недоступен')), null);
	} else if (cmd === 'mode') {
		tg_send_html(chat_id, cmd_mode_text(), mode_kb());
	} else if (cmd === 'safe') {
		cmd_safe(chat_id);
	} else if (cmd === 'safeoff') {
		cmd_safeoff(chat_id);
	} else if (cmd === 'doctor') {
		tg_send_html(chat_id, doctor_text(), kb_rows([ [ '🛠 Ремонт', 'act:repair' ], [ '🔄 Обновить', 'act:doctor' ] ]));
	} else if (cmd === 'repair') {
		const rv = repair_view();
		tg_send_html(chat_id, rv.text, rv.kb);
	} else if (cmd === 'update') {
		const uv = update_text();
		tg_send_html(chat_id, uv.text, uv.kb);
	} else if (cmd === 'menu' || cmd === 'start') {
		tg_send_html(chat_id, main_menu_text(), main_menu_kb());
	} else if (cmd === 'help') {
		tg_send_html(chat_id, HELP, main_menu_kb());
	} else {
		tg_send_html(chat_id, 'неизвестная команда — /help', null);
	}
}

/* Minimum role per callback prefix (Ф8.1): the same gate commands have,
 * applied to inline buttons (audit 1.1 — checks on callbacks too). Matched
 * top-down; the plain 'act:' catch-all stays last. Ф8.2: cfm:/cfx: stay
 * viewer here — the pending confirmation re-checks the REQUIRED role at
 * the tap itself (confirm_resolve). */
const CB_MIN_PREFIX = [
	[ 'cfm:', 'viewer' ], [ 'cfx:', 'viewer' ],
	[ 'mdo:', 'owner' ], [ 'upd:', 'owner' ],
	[ 'rep:', 'admin' ], [ 'unb:', 'admin' ],
	[ 'saf:', 'operator' ],
	[ 'ctl:blk:', 'admin' ], [ 'ctl:alw:', 'admin' ],
	[ 'ctl:wblk:', 'admin' ], [ 'ctl:walm:', 'admin' ], [ 'sdel:', 'admin' ],
	[ 'woff:', 'admin' ],
	[ 'act:snapshot', 'admin' ], [ 'act:restart', 'admin' ],
	[ 'act:repair', 'admin' ], [ 'act:mode', 'owner' ], [ 'act:update', 'owner' ],
	[ 'act:safe', 'operator' ],
	[ 'sw:', 'operator' ],
	[ 'wton:', 'operator' ],
	[ 'ctl:pause', 'operator' ], [ 'ctl:resume', 'operator' ],
	[ 'ctl:t30:', 'operator' ], [ 'ctl:t60:', 'operator' ],
	[ 'ctl:t120:', 'operator' ], [ 'ctl:t1440:', 'operator' ],
	[ 'ctl:tunb:', 'operator' ], [ 'ctl:tal60:', 'operator' ], [ 'ctl:tal1440:', 'operator' ],
	[ 'act:doctor', 'viewer' ],
	[ 'ctl:devi:', 'viewer' ], [ 'ctl:dev:', 'viewer' ],
	[ 'ctl:sites', 'viewer' ], [ 'ctl:wifi', 'viewer' ],
	[ 'ctl:refresh', 'viewer' ], [ 'ctl:menu', 'viewer' ],
	[ 'act:', 'viewer' ]
];

function cb_need(data) {
	for (let i = 0; i < length(CB_MIN_PREFIX); i++)
		if (substr(data, 0, length(CB_MIN_PREFIX[i][0])) === CB_MIN_PREFIX[i][0])
			return CB_MIN_PREFIX[i][1];
	return 'viewer';
}

function handle_update(u) {
	const msg = u.message || u.channel_post;
	if (msg && type(msg.chat) === 'object') {
		const chat_id = msg.chat.id;
		const ctype = '' + (msg.chat.type || '');
		const uid = (msg.from && msg.from.id != null) ? msg.from.id : null;
		const is_private = (ctype === 'private');
		/* Groups/channels are denied by default (audit A.3) — EXCEPT the
		 * exact bound chat (live compat for an already-bound group).
		 * PRIVATE chats from anyone pass through to the RBAC layer: the
		 * one-time pairing code arrives exactly from a NOT-yet-paired
		 * user's own private chat — rejecting foreign chats here would
		 * make pairing impossible (caught live, ч.184). */
		if (chat_id !== allowed_chat && !is_private) {
			log('ignored ' + (length(ctype) ? ctype : 'unknown-type') + ' chat ' + chat_id + ' (groups denied by default)');
			return;
		}
		if (allowed_chat === 0) {
			/* Pin the first PRIVATE chat that ever talks to us; a group or
			 * channel cannot pin itself (a bound group keeps working only
			 * when it was already bound). Ф8.2: the pin (+ owner seed) rides
			 * the Control API (telegram_bind_set) — no bare UCI writes. */
			if (!is_private) {
				log('ignored ' + ctype + ' chat ' + chat_id + ' pin attempt');
				return;
			}
			const br = ubus_call('telegram_bind_set', {
				chat_id: '' + chat_id,
				owner_uid: (uid != null) ? '' + uid : ''
			}, 10);
			if (br == null || br.result !== true) {
				log('bind via Control API failed: ' + ((br && br.error) || 'rpcd недоступен'));
				tg_send_html(chat_id, '⚠ Не удалось привязать чат (Control API недоступен). Попробуйте ещё раз.', null);
				return;   /* honest rollback — the pin did not happen */
			}
			allowed_chat = chat_id;
			cfg.chat_id = '' + chat_id;
			log('pinned allowed chat: ' + chat_id + (br.owner_seeded === true ? ' (owner seeded)' : ''));
			if (uid != null) {
				cfg.users.owner = [ '' + uid ];
				log('RBAC: owner paired at pin (' + uid + ')');
			}
			tg_send_html(chat_id, 'Бот привязан к этому чату (Re:HomeProxy). /help — список команд.', null);
			return;
		}
		const text = (type(msg.text) === 'string') ? msg.text : '';
		/* RBAC by from.id (commands AND callbacks — audit 1.1). With no
		 * users at all the BOUND chat keeps legacy access until the first
		 * pairing happens; a foreign private chat goes to pairing. */
		let role = (uid != null) ? role_for(uid) : null;
		if (role == null && users_count() === 0 && chat_id === allowed_chat)
			role = 'owner';
		if (role == null) {
			if (is_private && length(text) && pair_try(chat_id, uid, text))
				return;
			deny_unknown(chat_id, uid, ctype);
			return;
		}
		if (length(text))
			handle_command(chat_id, text, role);
		return;
	}
	const cb = u.callback_query;
	if (cb && cb.message && cb.message.chat) {
		const chat_id = cb.message.chat.id;
		const data = '' + (cb.data || '');
		const cbid = '' + (cb.id || '');
		if (chat_id !== allowed_chat) {
			log('ignored callback from foreign chat ' + chat_id);
			return;
		}
		const uid = (cb.from && cb.from.id != null) ? cb.from.id : null;
		let role = (uid != null) ? role_for(uid) : null;
		if (role == null && users_count() === 0)
			role = 'owner';
		const need = cb_need(data);
		if (role == null || !role_ok(role, need)) {
			log('RBAC: callback denied for user ' + uid + ' (need ' + need + ')');
			tg_answer_cb(cbid, 'Недостаточно прав');
			return;
		}
		if (match(data, /^sw:/) != null) {
			const tag = substr(data, 3);
			let lbl = tag;
			const main0 = clash_get('/proxies/main-out');
			if (main0 == null || !main0.now) {
				tg_answer_cb(cbid, 'main-out недоступен');
				tg_send_html(chat_id, 'main-out не существует (режим Custom / ядро лежит) — переключение невозможно.', null);
				return;
			}
			const nodes = list_nodes();
			for (let i = 0; nodes && i < length(nodes); i++)
				if (nodes[i].tag === tag) { lbl = nodes[i].label; break; }
			tg_answer_cb(cbid, 'Переключаю: ' + lbl);
			tg_send_html(chat_id, do_switch_tag(tag, lbl), null);
		} else if (match(data, /^act:nodes(:[0-9]+)?$/) != null) {
			const pm = match(data, /^act:nodes:([0-9]+)$/);
			const page = pm ? int(pm[1]) : 0;
			const nodes = list_nodes();
			tg_answer_cb(cbid, 'Узлы');
			if (!nodes || !length(nodes))
				tg_send_html(chat_id, 'узлы не найдены (ядро лежит?)', null);
			else
				tg_send_html(chat_id, nodes_text(nodes, page), nodes_kb(nodes, page));
		} else if (data === 'act:engine') {
			tg_answer_cb(cbid, 'Статус движков');
			tg_send_html(chat_id, cmd_status_engine(), kb_rows([ [ '🔄 Обновить', 'act:engine' ] ]));
		} else if (data === 'act:snapshot') {
			tg_answer_cb(cbid, 'Снапшот');
			tg_send_html(chat_id, cmd_snapshot(), null);
		} else if (data === 'act:restart') {
			tg_answer_cb(cbid, 'Перезапуск службы');
			confirm_ask(chat_id, role, 'service', 'restart',
				'Перезапустить службу?',
				'Активные соединения оборвутся (~10 с). Это последний шанс отменить.');
		} else if (data === 'act:doctor') {
			tg_answer_cb(cbid, 'Доктор');
			tg_send_html(chat_id, doctor_text(), kb_rows([ [ '🛠 Ремонт', 'act:repair' ], [ '🔄 Обновить', 'act:doctor' ] ]));
		} else if (data === 'act:repair') {
			tg_answer_cb(cbid, 'Ремонт');
			const rv = repair_view();
			tg_send_html(chat_id, rv.text, rv.kb);
		} else if (data === 'act:mode') {
			tg_answer_cb(cbid, 'Режим');
			tg_send_html(chat_id, cmd_mode_text(), mode_kb());
		} else if (data === 'act:safe') {
			tg_answer_cb(cbid, 'Safe Mode');
			cmd_safe(chat_id);
		} else if (data === 'act:update') {
			tg_answer_cb(cbid, 'Обновления');
			const uv = update_text();
			tg_send_html(chat_id, uv.text, uv.kb);
		} else if (substr(data, 0, 4) === 'cfm:' || substr(data, 0, 4) === 'cfx:') {
			const key = substr(data, 4);
			if (substr(data, 0, 4) === 'cfx:')
				confirm_drop(key, chat_id, cbid);
			else
				confirm_resolve(key, chat_id, role, cbid);
		} else if (substr(data, 0, 4) === 'saf:') {
			tg_answer_cb(cbid, 'Возврат узла');
			cmd_safeoff(chat_id);
		} else if (substr(data, 0, 4) === 'mdo:') {
			cmd_mode_ask(chat_id, role, substr(data, 4));
		} else if (substr(data, 0, 4) === 'rep:' || substr(data, 0, 4) === 'unb:') {
			const key = substr(data, 4);
			confirm_ask(chat_id, role, (substr(data, 0, 4) === 'rep:') ? 'repair' : 'unblock', key,
				(rep_unb_title(substr(data, 0, 4), key)),
				'Заявка уйдёт координатору восстановления и исполнится в ближайшем тике.');
		} else if (substr(data, 0, 4) === 'upd:') {
			const target = substr(data, 4);
			let title = 'Запустить обновление?', warn = 'Опасность зависит от цели; установка может занять несколько минут.';
			if (target === 'app') {
				title = 'Обновить приложение (сам-обновление)?';
				warn = 'LuCI и бот перезапустятся; на время установки бот будет недоступен.';
			} else if (substr(target, 0, 5) === 'core:')
				title = 'Установить ядро ' + substr(target, 5) + '?';
			else if (substr(target, 0, 4) === 'pkg:')
				title = 'Обновить пакет ' + substr(target, 4) + '?';
			confirm_ask(chat_id, role, 'upd', target, title, warn);
		} else if (data === 'act:help') {
			tg_answer_cb(cbid, 'Помощь');
			tg_send_html(chat_id, HELP, main_menu_kb());
		} else if (data === 'act:menu') {
			tg_answer_cb(cbid, 'Меню');
			tg_send_html(chat_id, main_menu_text(), main_menu_kb());
		} else if (data === 'act:refresh') {
			tg_answer_cb(cbid, 'Обновляю');
			tg_send_html(chat_id, cmd_status(), kb_rows([ [ 'Узлы', 'act:nodes' ], [ 'Снапшот', 'act:snapshot' ], [ 'Перезапуск', 'act:restart' ] ]));
		} else {
			/* «Контроль» callbacks — device actions first, then the panel
			 * views; an unconsumed callback is acknowledged silently.
			 * Ф8.2: the module sees the TAPPER's role (api.role). */
			let consumed = false;
			try {
				ctrl_api.role = role;
				consumed = ctrl.handle_dev_action(ctrl_api, chat_id, data, cbid);
				if (!consumed)
					consumed = ctrl.handle_cb(ctrl_api, chat_id, data, cbid);
			} catch (e) {
				log('control cb: ' + e);
			}
			if (!consumed)
				tg_answer_cb(cbid, '');
		}
	}
}

/* ── durable update queue (Ф8.1, audit 1.2/B0.2/TG-03) ──────────────────
 * Every polled update is written to disk BEFORE handling; the offset file
 * advances only AFTER the update is processed (a crash can never lose a
 * command — Telegram re-delivers what was not confirmed); the done journal
 * (1 h ring, atomic write) makes re-delivery idempotent. */

function off_file() {
	return (bot_id > 0) ? (RUN_DIR + '/telegram_offset.' + bot_id) : OFF_FILE;
}

function done_load() {
	try {
		const j = json(readfile(DONE_FILE) || '');
		if (type(j) === 'object')
			return j;
	} catch (e) {}
	return {};
}

/* Atomic write (temp + rename) — a torn journal would disable idempotency.
 * NOTE: json() on this build PARSES only (an object argument = «does not
 * implement read()») — serialization is sprintf('%J', …) (lesson 256). */
function done_save() {
	try {
		const now = time();
		for (let k in done)
			if (done[k] + 3600 < now)
				delete done[k];
		const tmp = DONE_FILE + '.tmp';
		writefile(tmp, sprintf('%J', done));
		rename(tmp, DONE_FILE);
	} catch (e) { log('done save: ' + e); }
}

function queue_put(u) {
	try {
		mkdir(QUEUE_DIR);
		writefile(QUEUE_DIR + '/' + u.update_id + '.json', sprintf('%J', { bot: bot_id, u: u }));
	} catch (e) { log('queue put: ' + e); }
}

function queue_files() {
	const out = [];
	const ls = capture(`ls -1 ${QUEUE_DIR} 2>/dev/null`);
	const lines = split(trim(ls || ''), '\n');
	for (let i = 0; i < length(lines); i++) {
		const f = trim(lines[i]);
		if (length(f) && match(f, /^[0-9]+\.json$/) != null)
			push(out, f);
	}
	sort(out, (a, b) => (int(a) > int(b)) ? 1 : -1);
	return out;
}

function queue_drain() {
	const files = queue_files();
	for (let i = 0; i < length(files); i++) {
		const qid = int(files[i]);
		const qpath = QUEUE_DIR + '/' + files[i];
		let rec = null;
		try { rec = json(readfile(qpath) || ''); } catch (e) { rec = null; }
		if (rec == null || type(rec.u) !== 'object' || rec.bot !== bot_id) {
			system(`rm -f ${shellquote(qpath)}`);   /* corrupt or foreign-bot leftover */
			continue;
		}
		if (qid <= last_update_id || done['' + qid] != null) {
			system(`rm -f ${shellquote(qpath)}`);   /* already confirmed / handled */
			continue;
		}
		try { handle_update(rec.u); } catch (e) { log('update: ' + e); }
		done['' + qid] = time();
		done_save();
		system(`rm -f ${shellquote(qpath)}`);
		/* The offset advances CONTIGUOUSLY (bounded): a corrupt/stale queue
		 * file must never catapult the confirmed offset past real updates
		 * (a jumped offset = commands unfetchable forever). Real Telegram
		 * batches are contiguous; anything beyond the bound is processed
		 * and done-marked, but the offset stays (caught live, ч.184 — the
		 * queue-hardening probe itself jumped the offset to a synthetic
		 * id). */
		if (qid > last_update_id && qid <= last_update_id + 1000) {
			last_update_id = qid;
			writefile(off_file(), sprintf('%d', last_update_id));
		} else if (qid > last_update_id) {
			log('queue: update ' + qid + ' is too far ahead of the confirmed offset (' + last_update_id + ') — processed, offset NOT advanced');
		}
	}
}

/* ── token application (Ф8.1, audit 1.3/TG-04) ────────────────────────── */

/* A token change must apply AT ONCE: api_base is rebuilt and getMe resolves
 * the bot identity; the offset file is PER BOT (a second bot starts from
 * its own offset, the legacy file migrates once). */
function apply_token() {
	if (cfg.token === token_used && length(api_base))
		return;
	token_used = cfg.token;
	api_base = `https://api.telegram.org/bot${cfg.token}`;
	bot_id = 0;
	const me = tg_call('getMe', null);
	if (me && me.ok === true && me.result && me.result.id != null) {
		const bid = int(me.result.id);
		if (bid > 0) {
			bot_id = bid;
			const f = off_file();
			if (!access(f) && access(OFF_FILE)) {
				try { writefile(f, trim(readfile(OFF_FILE) || '0') || '0'); } catch (e) {}
			}
		}
	}
	log('token applied (bot_id=' + bot_id + ')');
}

/* ── main loop ────────────────────────────────────────────────────────── */

function main() {
	done = done_load();
	let off_loaded_for = -1;   /* bot id the offset was last loaded for */
	log('telegram bot v2 started (always-on instance; idle until enabled)');
	/* Ф1.4b: own identity in the daemon registry + a heartbeat every cycle —
	 * the Sentinel (Ф2), support bundle and status RPCs read liveness here
	 * (busybox pidof cannot see ucode scripts at all, lesson 23). */
	pm_reg_self('telegram_bot', 'telegram.uc');
	while (true) {
		pm_reg_hb('telegram_bot');
		try {
			read_cfg();
			if (cfg.enabled !== '1' || !token_ok(cfg.token)) {
				/* Idle: the instance stays alive so settings changes never
				 * need a service restart (procd keeps it, respawn is quiet). */
				api_base = '';
				token_used = '';
				bot_id = 0;
				sleep(15000);
				continue;
			}
			ensure_owner_seed();
			apply_token();
			allowed_chat = int(cfg.chat_id || '0') || 0;
			if (off_loaded_for !== bot_id) {
				off_loaded_for = bot_id;
				try { last_update_id = int(trim(readfile(off_file()) || '0') || '0') || 0; }
				catch (e) { last_update_id = 0; }
			}
			/* Honest rate-limit state (audit 1.4): while a fresh 429 window
			 * is running, skip polling entirely (the send side handles its
			 * own single retry; pushes wait with the loop). */
			if (time() < rate_until) {
				sleep(10000);
				continue;
			}
			const poll = (match(cfg.poll, /^[0-9]+$/) != null) ? int(cfg.poll) : 25;
			if (poll < 5) cfg.poll = '5';
			const j = tg_call(`getUpdates?timeout=${poll}&offset=${last_update_id + 1}`, null);
			if (j && type(j.result) === 'array') {
				for (let i = 0; i < length(j.result); i++) {
					const u = j.result[i];
					if (type(u) !== 'object' || !u.update_id) continue;
					queue_put(u);   /* durable BEFORE handling (audit 1.2) */
				}
			}
			queue_drain();
			/* Back off on network failure AND on API errors (401 bad token,
			 * 409 getUpdates conflict, 429 without an inline retry) — without
			 * this a rejected long-poll becomes a busy loop hammering the
			 * Bot API. */
			if (!j || j.ok === false)
				sleep(10000);
			push_scan();
		} catch (e) {
			log('loop: ' + e);
			sleep(10000);
		}
	}
}

/* ч.118: IMMORTAL wrapper. The instance runs with procd respawn_retry 0 by
 * design (a self-exiting daemon must not respawn-spam), so ANY escaped
 * fatal ended the process with exit code 0 — procd marks the instance
 * "done" and never starts it again, and telegram_set() deliberately never
 * touches the service (hot reload), i.e. the bot stayed dead until a full
 * service restart no matter how often settings were saved (the live ч.118
 * incident). main()'s own while(true) never returns; if anything ever
 * escapes it, log, pause and re-enter — the update offset survives via
 * OFF_FILE. */
while (true) {
	try {
		main();
		log('main returned?! (immortal loop re-entering)');
	} catch (e) {
		log('fatal: ' + sprintf('%s', e) + ((type(e) === 'object' && e.stackline) ? ' @line ' + e.stackline : ''));
	}
	sleep(15000);
}
