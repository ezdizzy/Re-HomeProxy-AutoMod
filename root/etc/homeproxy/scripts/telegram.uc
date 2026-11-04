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
 * identical push text per kind within 300 s is dropped, 429 retry_after is
 * honored once. ALL dynamic text goes through esc_html (<>&) — lesson ч.69
 * fix. edited and business updates are ignored (the offset still advances);
 * channel_post is served like a normal message.
 */

'use strict';

import { access, popen, readfile, open, stat, writefile } from 'fs';
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

/* Module-level state (module scope is safe for closures; ucode lesson 44/45
 * only bites function-locals declared AFTER the closure). */
let boot_ts = time();
let api_base = '';
let allowed_chat = 0;
let last_update_id = 0;
let last_send_ts = 0;
let cfg = {
	enabled: '0', token: '', chat_id: '', mute: '0',
	poll: '25', push_interval: '2',
	push_hotswap: '1', push_watchdog: '1', push_learn: '1', push_service: '1',
	push_control: '1'
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
}

function token_ok(t) {
	return length(t) && match(t, /^[0-9]+:[A-Za-z0-9_-]+$/) != null;
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

/* One POST/GET call. Returns parsed JSON or null. Honors 429 retry_after
 * once (rate limit — the plan §2.5 quality fix). */
function tg_call(method, params) {
	const url = `${api_base}/${method}`;
	let out = '';
	if (params == null) {
		const poll = (match(cfg.poll, /^[0-9]+$/) != null) ? int(cfg.poll) : 25;
		out = capture(`curl -s --max-time ${poll + 5} ${shellquote(url)} 2>/dev/null`);
	} else {
		const f = RUN_DIR + '/tg_send.json';
		system(`rm -f ${shellquote(f)}`);
		system(`curl -s --max-time 15 -o ${shellquote(f)} -X POST -H 'Content-Type: application/json' -d ${shellquote(params)} ${shellquote(url)} 2>/dev/null`);
		if (access(f)) { out = readfile(f) || ''; system('rm -f ' + shellquote(f)); }
	}
	if (!length(trim(out)))
		return null;
	let j = null;
	try { j = json(out); } catch (e) { j = null; }
	if (j && j.ok === false && j.error_code === 429 && j.parameters &&
	    j.parameters.retry_after != null) {
		const wait = int(j.parameters.retry_after) + 1;
		if (wait > 0 && wait < 120) {
			log('rate limited, sleeping ' + wait + ' s');
			sleep(wait * 1000);
			if (params == null)
				return tg_call(method, null);
			return tg_call(method, params);
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
	const out = capture(`curl -s --max-time 120 -F "chat_id=${chat_id}"${cap} -F "document=@${path}" ${shellquote(url)} 2>/dev/null`);
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
	return `<b>Re:HomeProxy</b>
Ядро: ${core}
${main_line}
Zapret: ${zapret} · ByeDPI: ${byedpi} · MultiDNS: ${mosdns}
Автоматизация: ${learned} записей
${esc_html(ctl_line)}`;
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
 * confirmation must be out before the command runs. */
function do_service(action, chat_id) {
	let txt = '';
	if (action === 'stop') txt = '🛑 Останавливаю службу — это последнее сообщение до запуска. Запустить обратно: /service start';
	else if (action === 'restart') txt = '🔄 Перезапускаю службу (~10 с; /status подтвердит).';
	else if (action === 'start') txt = '▶️ Запускаю службу…';
	else return 'использование: /service start|stop|restart';
	log('service ' + action + ' via Telegram');
	tg_send_html(chat_id, txt, null);
	system(`/etc/init.d/homeproxy ${action} >/dev/null 2>&1 &`);
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

function nodes_text(nodes) {
	let out = '<b>Узлы</b> (номер = /switch N):\n';
	const cap = 12;
	const n = (length(nodes) > cap) ? cap : length(nodes);
	for (let i = 0; i < n; i++) {
		const nd = nodes[i];
		out += sprintf('%d. %s%s\n', i + 1, esc_html(nd.label),
			nd.delay ? ` — ${nd.delay} ms` : ' — —');
	}
	if (length(nodes) > n)
		out += `… и ещё ${length(nodes) - n} (номера продолжаются)`;
	return out;
}

function nodes_kb(nodes) {
	const rows = [];
	const cap = 8;
	const n = (length(nodes) > cap) ? cap : length(nodes);
	for (let i = 0; i < n; i += 2) {
		const row = [];
		for (let j = i; j < i + 2 && j < n; j++) {
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
	push(rows, [ '🔄 Обновить', 'act:nodes' ]);
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
	'/ping — аптайм, load, память\n' +
	'/connections — активные соединения\n' +
	'/close — закрыть все соединения\n' +
	'/service start|stop|restart — служба\n' +
	'/snapshot — снапшот конфигурации\n' +
	'/status_engine — Zapret/ByeDPI статус\n' +
	'/logs — отчёт для поддержки (архив файлом, секреты вычищены)\n' +
	'/mute · /unmute — пуш-уведомления вкл/выкл\n' +
	'/restart — перезапуск службы\n' +
	'/help — этот список';

/* Main inline menu (plan 15): every feature one tap away — no need to
 * remember command names. */
function main_menu_text() {
	return '<b>Re:HomeProxy — меню</b>\nЯдро, узлы, родительский контроль и Wi-Fi — в кнопках ниже.';
}

function main_menu_kb() {
	return kb_rows([
		[ [ '📊 Статус', 'act:refresh' ], [ '📡 Узлы', 'act:nodes' ] ],
		[ [ '🛡 Контроль', 'ctl:menu' ], [ '📶 Wi-Fi', 'ctl:wifi' ] ],
		[ [ '⚙️ Движки', 'act:engine' ], [ '📸 Снапшот', 'act:snapshot' ] ],
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
	push: send_push
};

function push_scan() {
	try { push_bus(); } catch (e) { log('push bus: ' + e); }
	try { push_service(); } catch (e) { log('push service: ' + e); }
	try { ctrl.push_scan(ctrl_api); } catch (e) { log('push control: ' + e); }
}

/* ── dispatch ─────────────────────────────────────────────────────────── */

function handle_command(chat_id, text) {
	const m = match(text, /^\/([a-z_]+)(@[A-Za-z0-9_]*)?(.*)$/);
	if (!m) return;
	const cmd = m[1];
	const rest = trim(m[3] || '');
	/* «Контроль» commands (/control /devices /sites /blocksite /unblocksite
	 * /pause /resume /wifi) — the module answers them itself. */
	try {
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
		do_service('restart', chat_id);
	} else if (cmd === 'service') {
		const r = do_service(rest, chat_id);
		if (r != null) tg_send_html(chat_id, esc_html(r), null);
	} else if (cmd === 'nodes') {
		const nodes = list_nodes();
		if (!nodes || !length(nodes))
			tg_send_html(chat_id, 'узлы не найдены (ядро лежит?)', null);
		else
			tg_send_html(chat_id, nodes_text(nodes), nodes_kb(nodes));
	} else if (cmd === 'switch') {
		tg_send_html(chat_id, cmd_switch(rest, chat_id), null);
	} else if (cmd === 'snapshot') {
		tg_send_html(chat_id, cmd_snapshot(), null);
	} else if (cmd === 'logs') {
		cmd_logs(chat_id);
	} else if (cmd === 'status_engine') {
		tg_send_html(chat_id, cmd_status_engine(), kb_rows([ [ '🔄 Обновить', 'act:engine' ] ]));
	} else if (cmd === 'mute') {
		system('uci -q set homeproxy.telegram.mute=1; uci commit homeproxy');
		cfg.mute = '1';
		tg_send_html(chat_id, '🔇 Пуш-уведомления выключены (команды работают). /unmute — обратно.', null);
	} else if (cmd === 'unmute') {
		system('uci -q set homeproxy.telegram.mute=0; uci commit homeproxy');
		cfg.mute = '0';
		tg_send_html(chat_id, '🔔 Пуш-уведомления включены.', null);
	} else if (cmd === 'menu' || cmd === 'start') {
		tg_send_html(chat_id, main_menu_text(), main_menu_kb());
	} else if (cmd === 'help') {
		tg_send_html(chat_id, HELP, main_menu_kb());
	} else {
		tg_send_html(chat_id, 'неизвестная команда — /help', null);
	}
}

function handle_update(u) {
	const msg = u.message || u.channel_post;
	if (msg && type(msg.chat) === 'object') {
		const chat_id = msg.chat.id;
		if (allowed_chat === 0) {
			/* Pin the first chat that ever talks to us (safe: foreign chats
			 * are ignored; the plan keeps this v1 behavior). */
			allowed_chat = chat_id;
			system(`uci set homeproxy.telegram.chat_id=${chat_id}; uci commit homeproxy`);
			cfg.chat_id = '' + chat_id;
			log('pinned allowed chat: ' + chat_id);
			tg_send_html(chat_id, 'Бот привязан к этому чату (Re:HomeProxy). /help — список команд.', null);
			return;
		}
		if (chat_id !== allowed_chat) {
			log('ignored message from foreign chat ' + chat_id);
			return;
		}
		const text = (type(msg.text) === 'string') ? msg.text : '';
		if (length(text))
			handle_command(chat_id, text);
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
		} else if (data === 'act:nodes') {
			const nodes = list_nodes();
			tg_answer_cb(cbid, 'Узлы');
			if (!nodes || !length(nodes))
				tg_send_html(chat_id, 'узлы не найдены (ядро лежит?)', null);
			else
				tg_send_html(chat_id, nodes_text(nodes), nodes_kb(nodes));
		} else if (data === 'act:engine') {
			tg_answer_cb(cbid, 'Статус движков');
			tg_send_html(chat_id, cmd_status_engine(), kb_rows([ [ '🔄 Обновить', 'act:engine' ] ]));
		} else if (data === 'act:snapshot') {
			tg_answer_cb(cbid, 'Снапшот');
			tg_send_html(chat_id, cmd_snapshot(), null);
		} else if (data === 'act:restart') {
			tg_answer_cb(cbid, 'Перезапуск службы');
			do_service('restart', chat_id);
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
			 * views; an unconsumed callback is acknowledged silently. */
			let consumed = false;
			try {
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

/* ── main loop ────────────────────────────────────────────────────────── */

function main() {
	if (access(OFF_FILE)) {
		try { last_update_id = int(readfile(OFF_FILE) || '0') || 0; } catch (e) { last_update_id = 0; }
	}
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
				sleep(15000);
				continue;
			}
			if (!length(api_base)) {
				api_base = `https://api.telegram.org/bot${cfg.token}`;
				allowed_chat = int(cfg.chat_id || '0') || 0;
				log('telegram polling started (allowed_chat=' + allowed_chat + ')');
			}
			allowed_chat = int(cfg.chat_id || '0') || 0;
			const poll = (match(cfg.poll, /^[0-9]+$/) != null) ? int(cfg.poll) : 25;
			if (poll < 5) cfg.poll = '5';
			const j = tg_call(`getUpdates?timeout=${poll}&offset=${last_update_id + 1}`, null);
			if (j && type(j.result) === 'array') {
				for (let i = 0; i < length(j.result); i++) {
					const u = j.result[i];
					if (type(u) !== 'object' || !u.update_id) continue;
					if (u.update_id > last_update_id) {
						last_update_id = u.update_id;
						writefile(OFF_FILE, sprintf('%d', last_update_id));
					}
					try { handle_update(u); } catch (e) { log('update: ' + e); }
				}
			}
			/* Back off on network failure AND on API errors (401 bad token,
			 * 409 getUpdates conflict, 429 after the single retry) — without
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
