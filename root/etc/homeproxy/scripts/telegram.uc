#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Telegram control bot (ч.69).
 *
 * Long-polls the Telegram Bot API (getUpdates, 25 s) and answers commands
 * from the ALLOWED chat only (homeproxy.telegram.chat_id; empty = first
 * chat wins — it pins itself on the first message it sees). Commands:
 *   /status       core, main exit node + delay, ByeDPI/Zapret, automation verdicts
 *   /ping         uptime, load, free RAM
 *   /connections  top active connections (Clash API)
 *   /close        close all active connections
 *   /restart      restart the proxy service
 *   /help         this list
 *
 * procd instance: homeproxy.telegram (started from init.d when enabled + token).
 * The bot NEVER learns anything beyond what LuCI already shows — no secrets are
 * sent; the token lives in UCI and is never echoed back.
 */

'use strict';

import { access, popen, readfile, open, stat } from 'fs';

const RUN_DIR = '/var/run/homeproxy';
const LOG_FILE = RUN_DIR + '/telegram.log';

/* Module-level state (ucode closure constraints: declare before use). */
let api_base = '';
let allowed_chat = 0;
let last_update_id = 0;
let boot_ts = time();

function log(msg) {
	const line = sprintf('%s %s\n', strftime('%Y-%m-%d %H:%M:%S', time()), msg);
	let f = open(LOG_FILE, 'a');
	if (f) { f.write(line); f.close(); }
	/* keep the log bounded */
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

function uci_get(section, opt, def) {
	const fd = popen(`uci -q get homeproxy.${section}.${opt} 2>/dev/null`);
	let v = null;
	if (fd) { v = trim(fd.read('all') || ''); fd.close(); }
	return length(v) ? v : def;
}

function capture(cmd, timeout_ms) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

function tg_call(method, params) {
	/* params: JSON string or null. GET for getUpdates, POST otherwise. */
	const url = `${api_base}/${method}`;
	let out = '';
	if (params == null) {
		out = capture(`curl -s --max-time 30 ${shellquote(url)} 2>/dev/null`, 32000);
	} else {
		const f = RUN_DIR + '/tg_send.json';
		system(`rm -f ${shellquote(f)}`);
		system(`curl -s --max-time 15 -o ${shellquote(f)} -X POST -H 'Content-Type: application/json' -d ${shellquote(params)} ${shellquote(url)} 2>/dev/null`, 17000);
		if (access(f)) { out = readfile(f) || ''; system('rm -f ' + shellquote(f)); }
	}
	if (!length(trim(out))) return null;
	let j = null;
	try { j = json(out); } catch (e) { j = null; }
	return j;
}

function tg_send(chat_id, text) {
	/* JSON-escape quotes/newlines/backslashes without regex classes. */
	let esc = '';
	for (let i = 0; i < length(text); i++) {
		const ch = substr(text, i, 1);
		if (ch === '"') esc += '\\"';
		else if (ch === '\n') esc += '\\n';
		else if (ch === '\\') esc += '\\\\';
		else esc += ch;
	}
	const body = sprintf('{"chat_id":%d,"text":"%s"}', chat_id, esc);
	tg_call('sendMessage', body);
}

/* ── Command implementations (mirror the LuCI data sources) ───────────── */

function clash_get(path) {
	const raw = capture(`wget -qO- --timeout=3 http://127.0.0.1:9090${path} 2>/dev/null`);
	if (!length(trim(raw || ''))) return null;
	let j = null;
	try { j = json(raw); } catch (e) { j = null; }
	return j;
}

function cmd_status() {
	const core_info = trim(readfile(RUN_DIR + '/core.info') || '');
	let core = 'unknown';
	try { const j = json(core_info || ''); if (j) core = (j.core_type || '?') + ' ' + (j.version || ''); } catch (e) {}
	const main = clash_get('/proxies/main-out');
	let main_line = 'main-out: ?';
	if (main && main.now) {
		main_line = 'main-out: ' + main.now;
		const h = clash_get(`/proxies/${main.now}/history`);
		const hist = (h && h.history && length(h.history)) ? h.history[length(h.history) - 1] : null;
		if (hist && hist.delay > 0)
			main_line += ` (${hist.delay} ms)`;
	}
	const byedpi = (system('pidof ciadpi >/dev/null 2>&1') === 0) ? 'on' : 'off';
	const zapret = (system('pidof nfqws2 >/dev/null 2>&1') === 0) ? 'on' : 'off';
	const mosdns = (system('pidof mosdns >/dev/null 2>&1') === 0) ? 'on' : 'off';
	/* automation counters */
	let learned = '—';
	const af = RUN_DIR + '/automation_state.json';
	if (access(af)) {
		try {
			const st = json(readfile(af) || '');
			let n = 0;
			for (let k in keys(st || {}))
				if (substr(k, 0, 2) !== '__' && type(st[k]) === 'object') n++;
			learned = sprintf('%d', n);
		} catch (e) {}
	}
	return `[Re:HomeProxy]
core: ${core}
${main_line}
ByeDPI: ${byedpi} · Zapret: ${zapret} · mosdns: ${mosdns}
automation entries: ${learned}`;
}

function cmd_ping() {
	const up = time() - boot_ts;
	const load = trim(split(readfile('/proc/loadavg') || '', ' ')[0] || '?');
	const memf = readfile('/proc/meminfo') || '';
	const mm = match(memf, /MemAvailable:\s+([0-9]+)/);
	const mem_mb = mm ? int(mm[1]) / 1024 : 0;
	return `pong
uptime: ${sprintf('%dd %dh', up / 86400, (up % 86400) / 3600)}
load(1m): ${load}
mem available: ${sprintf('%.0f', mem_mb)} MB`;
}

function cmd_connections() {
	const j = clash_get('/connections');
	if (!j || type(j.connections) !== 'array' || !length(j.connections))
		return 'no active connections';
	const conns = j.connections;
	/* newest first by start time */
	sort(conns, (a, b) => (b.start || '') > (a.start || '') ? 1 : -1);
	let out = sprintf('active: %d\n', length(conns));
	const n = (length(conns) > 10) ? 10 : length(conns);
	for (let i = 0; i < n; i++) {
		const c = conns[i];
		const meta = (c.metadata && c.metadata.host) ? c.metadata.host
			: ((c.metadata && c.metadata.destinationIP) ? c.metadata.destinationIP : '?');
		const chain = (c.chains && length(c.chains)) ? c.chains[0] : '?';
		out += `· ${meta} → ${chain}\n`;
	}
	if (length(conns) > n)
		out += `… and ${length(conns) - n} more`;
	return out;
}

function cmd_close() {
	const rc = system(`curl -s -m 5 -X DELETE http://127.0.0.1:9090/connections >/dev/null 2>&1`);
	return (rc === 0) ? 'all connections closed' : 'Clash API refused (core down?)';
}

function cmd_restart() {
	log('restart requested via Telegram');
	system('/etc/init.d/homeproxy restart >/dev/null 2>&1 &');
	return 'service restart started (takes ~10 s; /status will confirm)';
}

const HELP = 'commands:
/status — core, exit node, engines, automation
/ping — uptime, load, memory
/connections — top active connections
/close — close all connections
/restart — restart the proxy service
/help — this list';

function handle_command(chat_id, text) {
	const cmd = trim(text);
	if (cmd === '/status' || cmd === '/status@' + '')
		tg_send(chat_id, cmd_status());
	else if (cmd === '/ping')
		tg_send(chat_id, cmd_ping());
	else if (cmd === '/connections')
		tg_send(chat_id, cmd_connections());
	else if (cmd === '/close')
		tg_send(chat_id, cmd_close());
	else if (cmd === '/restart')
		tg_send(chat_id, cmd_restart());
	else if (cmd === '/help' || cmd === '/start')
		tg_send(chat_id, HELP);
	else if (length(cmd) && substr(cmd, 0, 1) === '/')
		tg_send(chat_id, 'unknown command — /help');
}

/* ── Main loop ────────────────────────────────────────────────────────── */

function main() {
	const enabled = uci_get('telegram', 'enabled', '0');
	const token = uci_get('telegram', 'token', '');
	allowed_chat = int(uci_get('telegram', 'chat_id', '0') || '0');
	if (enabled !== '1') {
		log('telegram disabled, exiting.');
		return;
	}
	if (!length(token) || !match(token, /^[0-9]+:[A-Za-z0-9_-]+$/)) {
		log('invalid or missing bot token, exiting.');
		return;
	}
	api_base = `https://api.telegram.org/bot${token}`;

	/* Restore the update offset so a restart does not replay old commands. */
	const off_file = RUN_DIR + '/telegram_offset';
	if (access(off_file)) {
		try { last_update_id = int(readfile(off_file) || '0') || 0; } catch (e) { last_update_id = 0; }
	}

	log('telegram bot started (allowed_chat=' + allowed_chat + ')');

	while (true) {
		const j = tg_call('getUpdates?timeout=25&offset=' + (last_update_id + 1), null);
		if (j && type(j.result) === 'array') {
			for (let u in j.result) {
				if (type(u) !== 'object' || !u.update_id) continue;
				if (u.update_id > last_update_id) {
					last_update_id = u.update_id;
					const f = open(off_file, 'w');
					if (f) { f.write(sprintf('%d', last_update_id)); f.close(); }
				}
				const msg = u.message;
				if (!msg || type(msg.chat) !== 'object') continue;
				const chat_id = msg.chat.id;
				if (allowed_chat === 0) {
					/* Pin the first chat that ever talks to us. */
					allowed_chat = chat_id;
					system(`uci set homeproxy.telegram.chat_id=${chat_id}`);
					system('uci commit homeproxy');
					log('pinned allowed chat: ' + chat_id);
					tg_send(chat_id, 'Bot bound to this chat (Re:HomeProxy). /help for commands.');
					continue;
				}
				if (chat_id !== allowed_chat) {
					log('ignored message from foreign chat ' + chat_id);
					continue;
				}
				const text = (type(msg.text) === 'string') ? msg.text : '';
				if (length(text))
					handle_command(chat_id, text);
			}
		}
		/* Poll errors (network down / API throttling): back off a bit. */
		if (!j)
			sleep(10);
	}
}

try {
	main();
} catch (e) {
	log('fatal: ' + sprintf('%s', e) + ((type(e) === 'object' && e.stackline) ? ' @line ' + e.stackline : ''));
}
