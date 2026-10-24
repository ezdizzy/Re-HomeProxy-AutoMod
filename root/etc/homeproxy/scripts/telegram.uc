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
 * the first message, as in v1), and pushes notifications by watching the
 * run-state files (NOT the engine internals):
 *   hotswap_state.json   — Hot Swap node changes / failback
 *   urltest_dead         — watchdog dead-node marks (added / recovered)
 *   automation_stats.json events ring — learned blocks, self-heals
 *   Clash /version       — core down / recovered
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

const RUN_DIR = '/var/run/homeproxy';
const LOG_FILE = RUN_DIR + '/telegram.log';
const OFF_FILE = RUN_DIR + '/telegram_offset';
const HS_FILE = RUN_DIR + '/hotswap_state.json';
const DEAD_FILE = RUN_DIR + '/urltest_dead';
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
	hs_switches: -1, hs_active: '', dead_str: null,
	learn_t: 0, core_ok: null
};
let last_push = {};   /* kind -> { text, ts } dedup */

/* ── basics ───────────────────────────────────────────────────────────── */

function log(msg) {
	/* Standalone ucode has NO strftime (v1 carried this bug since ч.69 —
	 * its log() crashed the daemon at the very first call). Epoch-only,
	 * same as automation.uc/metrics.uc. */
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
}

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
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
	return (system(`pidof ${name} >/dev/null 2>&1`) === 0);
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
${esc_html(main_line)}
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

function push_hotswap() {
	if (!access(HS_FILE)) return;
	let st = null;
	try { st = json(readfile(HS_FILE) || ''); } catch (e) { st = null; }
	if (!st || type(st) !== 'object') return;
	const sw = int(st.switches || 0);
	const active = '' + (st.active || '');
	if (seen.hs_switches === -1) { seen.hs_switches = sw; seen.hs_active = active; return; }
	if (sw === seen.hs_switches && active === seen.hs_active)
		return;
	const old = seen.hs_active;
	seen.hs_switches = sw;
	seen.hs_active = active;
	let arrow = '';
	if (length(old) && old !== active)
		arrow = `${esc_html(node_label(old))} → `;
	send_push('hotswap',
		`🔄 <b>Hot Swap</b>: ${arrow}<b>${esc_html(node_label(active))}</b>` +
		((st.last_reason && length('' + st.last_reason)) ? `\nПричина: ${esc_html('' + st.last_reason)}` : '') +
		sprintf('\n(переключение #%d)', sw));
}

/* Membership check without dynamic regex: exact line compare on split lists. */
function in_list(list, item) {
	for (let i = 0; i < length(list); i++)
		if (trim(list[i]) === item) return true;
	return false;
}

function push_watchdog() {
	const cur = access(DEAD_FILE) ? trim(readfile(DEAD_FILE) || '') : '';
	if (seen.dead_str == null) { seen.dead_str = cur; return; }
	if (cur === seen.dead_str) return;
	const oldl = split(seen.dead_str, '\n');
	const newl = split(cur, '\n');
	seen.dead_str = cur;
	let added = [];
	for (let i = 0; i < length(newl); i++) {
		const t = trim(newl[i]);
		if (length(t) && !in_list(oldl, t))
			push(added, t);
	}
	let gone = [];
	for (let i = 0; i < length(oldl); i++) {
		const t = trim(oldl[i]);
		if (length(t) && !in_list(newl, t))
			push(gone, t);
	}
	if (length(added)) {
		let lines = [];
		for (let i = 0; i < length(added) && i < 6; i++)
			push(lines, '• ' + esc_html(node_label(added[i])));
		send_push('watchdog', '⛔ <b>URLTest</b>: узел помечен мёртвым:\n' + join('\n', lines));
	}
	if (length(gone)) {
		let lines = [];
		for (let i = 0; i < length(gone) && i < 6; i++)
			push(lines, '• ' + esc_html(node_label(gone[i])));
		send_push('watchdog', '✅ <b>URLTest</b>: узел восстановился:\n' + join('\n', lines));
	}
}

function push_learn() {
	if (!access(STATS_FILE)) return;
	let st = null;
	try { st = json(readfile(STATS_FILE) || ''); } catch (e) { st = null; }
	if (!st || type(st.events) !== 'array') return;
	const evs = st.events;
	let maxt = seen.learn_t;
	for (let i = 0; i < length(evs); i++)
		if (evs[i].t > maxt) maxt = evs[i].t;
	if (seen.learn_t === 0) { seen.learn_t = maxt; return; }
	if (maxt <= seen.learn_t) return;
	let learned = [], healed = [];
	for (let i = 0; i < length(evs); i++) {
		const ev = evs[i];
		if (ev.t <= seen.learn_t) continue;
		if (ev.k === 'learn' && cfg.push_learn === '1') push(learned, '' + (ev.m || ''));
		else if (ev.k === 'heal' && cfg.push_learn === '1') push(healed, '' + (ev.m || ''));
	}
	seen.learn_t = maxt;
	if (length(learned)) {
		const cap = 8;
		let lines = [];
		for (let i = 0; i < length(learned) && i < cap; i++)
			push(lines, '• ' + esc_html(learned[i]));
		let tail = (length(learned) > cap) ? `\n… и ещё ${length(learned) - cap}` : '';
		send_push('learn', '🧠 <b>Автоматизация</b> выучила:\n' + join('\n', lines) + tail);
	}
	if (length(healed)) {
		const cap = 6;
		let lines = [];
		for (let i = 0; i < length(healed) && i < cap; i++)
			push(lines, '• ' + esc_html(healed[i]));
		send_push('learn', '✅ <b>Автоматизация</b>: самолечение:\n' + join('\n', lines));
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

function push_scan() {
	try { push_hotswap(); } catch (e) { log('push hotswap: ' + e); }
	try { push_watchdog(); } catch (e) { log('push watchdog: ' + e); }
	try { push_learn(); } catch (e) { log('push learn: ' + e); }
	try { push_service(); } catch (e) { log('push service: ' + e); }
	try { ctrl.push_scan(ctrl_api); } catch (e) { log('push control: ' + e); }
}

/* Primitives handed to the «Контроль» module (declared after the functions
 * it references — module scope, evaluated at load time). */
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
	while (true) {
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

try {
	main();
} catch (e) {
	log('fatal: ' + sprintf('%s', e) + ((type(e) === 'object' && e.stackline) ? ' @line ' + e.stackline : ''));
}
