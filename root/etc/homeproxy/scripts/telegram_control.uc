// SPDX-License-Identifier: GPL-2.0-only
//
// Re:HomeProxy AutoMod — Telegram-модуль «Контроль» (plan 14).
//
// Imported by the always-on telegram.uc daemon (telegram bot v2) as a whole
// module (import * as ctrl from ...). No circular import: the daemon passes
// its primitives in an api object — send_html / kb_rows / answer_cb /
// esc_html / jesc / log / uci_get / push (dedup + rate limit of the bot).
// Conservative ucode style for the standalone daemon: no `?.`, no typeof
// (use type()), sleep() is MILLISECONDS, join() always with a separator,
// functions declared before their callers (no hoisting in ucode modules).
//
// Commands (handled before the bot's "unknown command" reply):
//   /control            панель контроля + меню
//   /devices            устройства сети: состояние, блок, временный блок
//   /sites              правила сайтов (+удаление)
//   /blocksite <домен[,домен]> [№ устройства] — блок домена (всей сети или
//                       выбранному устройству; устройство добавится само)
//   /unblocksite <домен>                — удалить правила с этим доменом
//   /pause | /resume    глобальная пауза контроля
//   /wifi               Wi-Fi сети: вкл/выкл
// Pushes (kind "control", telegram.push_control): блок/разрешение/расписания/
// Wi-Fi/системные события из events.json + новые устройства в сети.
//
// Ф8.2 (ч.185, аудит 1.5/TG-06): ВСЕ мутации ходят через Control API —
// RPC-методы luci.homeproxy (control_client_*, control_rule_*,
// control_set_paused, control_wifi_set) вызываются по ubus; модуль больше
// НЕ пишет UCI и не дёргает shell для действий. Тяжёлые действия (постоянный
// блок/Wi-Fi-блок устройства, удаление/добавление правил, выключение Wi-Fi)
// получают подтверждение второй кнопкой через api.confirm_ask (роль — в
// api.role); лёгкие временные действия идут сразу. События пишут RPC'и —
// модуль только гасит эхо-пуш этих же событий (api.quiet.until), чтобы
// результат действия не приходил в тот же чат дважды.

'use strict';

import { readfile, popen } from 'fs';
/* ч.118: ceil was used by the device-list pagination without an import —
 * every /devices page beyond the first threw "access to undeclared variable
 * ceil" and the callback died. NOTE: this ucode build's 'math' module does
 * NOT export ceil (importing it breaks the whole module load — proven
 * live), so the ceiling is done with integer arithmetic instead. */
import {
	client_states, get_sections, get_section,
	main_opt, list_devices, bump_cursor,
	read_arp
} from '/etc/homeproxy/scripts/control.uc';
import { tail as ev_tail, last_id as ev_head, cursor_get as ev_cursor_get, cursor_set as ev_cursor_set } from '/etc/homeproxy/scripts/eventbus.uc';

/* Module state (module scope is closure-safe; declared before use). */
let API = null;
let ev_last_id = 0;    /* Event Bus cursor (Ф1.7/Ф2.4): монотонный id, не ts.
                        * Ф2.4: курсор durably в tmpfs ('telegram-ctrl') —
                        * рестарт демона продолжает с последнего обработанного
                        * события (простой не теряет события, реплея нет);
                        * ребут роняет курсор вместе с журналом → базлайн. */
let ev_saved_id = 0;   /* id already persisted to the durable cursor */
let ev_ready = false;  /* baseline done (never re-baseline mid-boot) */
let arp_seen = null;   /* MACs seen on the network (new-device pushes) */
let dev_last_err = null;   /* last honest Control API error (for the reply) */

const DEV_PAGE = 6;    /* devices per page in the inline keyboard */

/* ── small helpers ────────────────────────────────────────────────────── */

function esc(s) {
	return API.esc_html('' + (s || ''));
}

function fmt_clock(ts) {
	const d = localtime(ts || 0);
	return sprintf('%02d:%02d', d.hour, d.min);
}

function fmt_minutes(mins) {
	if (mins >= 1440 && (mins % 1440) === 0)
		return sprintf('%d д', mins / 1440);
	if (mins >= 60 && (mins % 60) === 0)
		return sprintf('%d ч', mins / 60);
	return sprintf('%d мин', mins);
}

function clean_text(s) {
	return trim(replace('' + (s || ''), /['"`\\\n\r]/g, ''));
}

/* Ф1.5 (аудит 31): callback-data и id-строки никогда не попадают в shell
 * без проверки формата uci-имени ([A-Za-z0-9_]+) и существования секции
 * нужного типа — подделанный коллбек обязан быть честной ошибкой. */
function sid_ok(sid, stype) {
	if (type(sid) !== 'string' || length(sid) > 64 ||
	    match(sid, /^[A-Za-z0-9_]+$/) == null)
		return false;
	const s = get_section(sid);
	return !!(s && s['.type'] === stype);
};

function kb(rows) {
	return API.kb_rows(rows);
}

function reason_text(reason, until, allow_until) {
	if (allow_until && allow_until > 0)
		return '✅ разрешён временно до ' + fmt_clock(allow_until);
	if (reason === 'temp')
		return '⏱ временно до ' + fmt_clock(until);
	if (reason === 'schedule')
		return '📅 по расписанию';
	if (reason === 'manual')
		return '🔒 вручную';
	return '🟢 разрешён';
}

/* Current effective states keyed by client id (devices map by client_id). */
function states_map() {
	const states = client_states(time());
	const out = {};
	for (let i = 0; i < length(states); i++)
		out[states[i].id] = states[i];
	return out;
}

function dev_display(d, st) {
	let s = d.alias || d.hostname || d.ip || d.mac;
	if (d.ip)
		s += ' (' + d.ip + ')';
	if (st && st.blocked)
		s += ' — 🔒 ' + reason_text(st.reason, st.until, st.allow_until);
	else {
		if (st && st.allow_until)
			s += ' — ✅ ' + reason_text('', 0, st.allow_until);
		else
			s += d.online ? ' — 🟢' : ' — ⚪ офлайн';
	}
	if (st && st.wifi_blocked)
		s += ' · 📶🚫';
	return s;
}

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

/* Minimal JSON writer for the ubus args (strings only; no json() — lesson
 * 266: json() PARSES only). Escape \ " and control chars. */
function jstr(s) {
	let esc = '';
	s = '' + s;
	for (let i = 0; i < length(s); i++) {
		const ch = substr(s, i, 1);
		if (ch === '"') esc += '\\"';
		else if (ch === '\\') esc += '\\\\';
		else if (ch === '\n') esc += '\\n';
		else if (ch === '\r') esc += '\\r';
		else if (ch === '\t') esc += '\\t';
		else esc += ch;
	}
	return esc;
}

function api_json(o) {
	let out = '{';
	let first = true;
	for (let k in o) {
		if (!first)
			out += ',';
		first = false;
		out += '"' + jstr(k) + '":"' + jstr('' + o[k]) + '"';
	}
	return out + '}';
}

/* Ф8.2 Control API bridge: mutations ride the SAME luci.homeproxy RPC door
 * the UI uses (audit 1.5/TG-06) — no bare UCI writes, no shell actions from
 * the chat path. The commit happens in rpcd; the module only invalidates
 * its cached uci cursor and quiets the echo push (api.quiet.until). */
function ubus_call(method, args, timeout_s) {
	const t = (timeout_s != null && timeout_s > 0 && timeout_s <= 60) ? int(timeout_s) : 10;
	const cmd = `ubus -t ${t} call luci.homeproxy ${method} '${api_json(args)}'`;
	const raw = capture(cmd);
	let j = null;
	try { j = json(raw || ''); } catch (e) { j = null; }
	if (j == null)
		API.log('ubus ' + method + ': no/invalid reply (rpcd недоступен?)');
	return j;
}

/* Suppress the next control pushes for a short window: the action the bot
 * JUST performed must not echo back into the same chat as a second message
 * (the direct reply is the single result place). */
function quiet_touch(api) {
	try {
		if (api.quiet)
			api.quiet.until = time() + 25;
	} catch (e) {}
}

/* ── configured-client management (Ф8.2: via Control API) ─────────────── */

function cfg_id_for_dev(d, create) {
	/* configured device -> its section id; unconfigured -> create one */
	if (d.client_id)
		return d.client_id;
	if (!create)
		return null;
	if (!d.mac && !d.ip)
		return null;
	/* Ф1.5: the device fields come from live ARP/DHCP state — only strict
	 * charset-safe forms may reach the RPC (belt-and-braces). */
	const mac_ok = length(d.mac) && match(d.mac, /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/) != null;
	const ip_ok = length(d.ip) && match(d.ip, /^(\d{1,3}\.){3}\d{1,3}$/) != null;
	if (!mac_ok && !ip_ok)
		return null;
	const r = ubus_call('control_client_add', {
		name: clean_text(d.alias || d.hostname),
		mac: mac_ok ? d.mac : '',
		ip: ip_ok ? d.ip : ''
	}, 10);
	if (r && r.result === true && length('' + (r.id || ''))) {
		bump_cursor();   /* the commit happened in rpcd — invalidate our cache */
		return '' + r.id;
	}
	return null;
}

/* ── panel ────────────────────────────────────────────────────────────── */

function panel_text() {
	const enabled = main_opt('enabled', '0') === '1';
	const paused = main_opt('paused', '0') === '1';
	const states = client_states(time());
	let blocked = 0, temp = 0;
	for (let i = 0; i < length(states); i++) {
		if (states[i].blocked) {
			blocked++;
			if (states[i].reason === 'temp')
				temp++;
		}
	}
	const rules = get_sections('rule');
	const scheds = get_sections('schedule');
	const devs = list_devices();
	let unseen = 0;
	for (let i = 0; i < length(devs); i++)
		if (!devs[i].configured)
			unseen++;
	let head = (enabled)
		? (paused ? '🛡 <b>Контроль</b>: вкл · ⏸ ПАУЗА (всё разрешено)'
			: '🛡 <b>Контроль</b>: вкл')
		: '🛡 <b>Контроль</b>: выключен';
	return head + '\n' +
		'Устройств: ' + length(states) + ' · заблокировано: ' + blocked +
		' (временно: ' + temp + ')\n' +
		'Правил сайтов: ' + length(rules) + ' · расписаний: ' + length(scheds) + '\n' +
		'Новых устройств в сети: ' + unseen;
}

function panel_kb() {
	const paused = main_opt('paused', '0') === '1';
	return kb([
		[ 'Устройства', 'ctl:dev:0' ], [ 'Правила', 'ctl:sites' ],
		[ 'Wi-Fi', 'ctl:wifi' ],
		[ paused ? '▶ Продолжить' : '⏸ Пауза', paused ? 'ctl:resume' : 'ctl:pause' ],
		[ '🔄 Обновить', 'ctl:refresh' ]
	]);
}

/* ── devices view / actions ───────────────────────────────────────────── */

function devices_text(page) {
	const devs = list_devices();
	const stmap = states_map();
	const total = length(devs);
	if (!total)
		return 'устройства не найдены (нет DHCP-аренд и ARP-записей)';
	if (page * DEV_PAGE >= total)
		page = 0;
	const p0 = page * DEV_PAGE;
	let out = '🛡 <b>Устройства</b> (' + (p0 + 1) + '–' +
		((p0 + DEV_PAGE) < total ? (p0 + DEV_PAGE) : total) + ' из ' + total + '):\n';
	for (let i = p0; i < (p0 + DEV_PAGE) && i < total; i++) {
		const d = devs[i];
		const st = (d.client_id && (d.client_id in stmap)) ? stmap[d.client_id] : null;
		out += (i - p0 + 1) + '. ' + esc(dev_display(d, st)) + '\n';
	}
	if (total > DEV_PAGE)
		out += '\nстраница ' + (page + 1) + ' из ' + (int((total + DEV_PAGE - 1) / DEV_PAGE));
	return out;
}

function devices_kb(page) {
	const devs = list_devices();
	const total = length(devs);
	if (page * DEV_PAGE >= total)
		page = 0;
	const rows = [];
	const p0 = page * DEV_PAGE;
	for (let i = p0; i < (p0 + DEV_PAGE) && i < total; i += 2) {
		const row = [];
		for (let j = i; j < (i + 2) && j < total; j++) {
			const d = devs[j];
			let lbl = d.alias || d.hostname || d.ip || d.mac;
			if (length(lbl) > 18)
				lbl = substr(lbl, 0, 17) + '…';
			/* Ф8.1 (audit 20): the button carries the STABLE device ref,
			 * not an index into a live ARP/DHCP-ordered list. */
			const ref = 'ctl:devi:' + dev_ref(d);
			if (length(ref) > 60)
				continue;
			push(row, [ lbl, ref ]);
		}
		push(rows, row);
	}
	const nav = [];
	if (page > 0)
		push(nav, [ '⬅', 'ctl:dev:' + (page - 1) ]);
	if ((p0 + DEV_PAGE) < total)
		push(nav, [ '➡', 'ctl:dev:' + (page + 1) ]);
	if (length(nav))
		push(rows, nav);
	push(rows, [ '🔄 Обновить', 'ctl:dev:' + page ]);
	return kb(rows);
}

function dev_by_idx(idx) {
	const devs = list_devices();
	if (idx < 0 || idx >= length(devs))
		return null;
	return devs[idx];
}

/* Ф8.1 (audit 20): buttons carry a STABLE device reference, not an index
 * into a live list — ARP/DHCP churn reorders list_devices(), so an index
 * callback could act on the WRONG device. Reference forms (the stable
 * identity available for that device):
 *   c:<client section id>   configured device
 *   m:<lowercase MAC>       unconfigured but seen on the wire
 *   i:<ip>                  no MAC (rare, e.g. some VPN clients)
 *   x:<label>               unacteable placeholder (no MAC/IP) */
function dev_ref(d) {
	if (d.client_id)
		return 'c:' + d.client_id;
	if (d.mac)
		return 'm:' + lc(d.mac);
	if (d.ip)
		return 'i:' + d.ip;
	return 'x:' + (d.alias || d.hostname || '?');
}

function dev_by_ref(ref) {
	const m = match('' + ref, /^([cmi]):(.+)$/);
	if (!m)
		return null;
	const devs = list_devices();
	for (let i = 0; i < length(devs); i++) {
		const d = devs[i];
		if (m[1] === 'c' && d.client_id === m[2])
			return d;
		if (m[1] === 'm' && d.mac && lc(d.mac) === m[2])
			return d;
		if (m[1] === 'i' && d.ip === m[2])
			return d;
	}
	return null;
}

function device_menu_text(ref) {
	const d = dev_by_ref(ref);
	if (!d)
		return 'устройство не найдено — /devices обновит список';
	const stmap = states_map();
	const st = (d.client_id && (d.client_id in stmap)) ? stmap[d.client_id] : null;
	let body = '<b>' + esc(d.alias || d.hostname || d.ip || d.mac) + '</b>\n';
	body += 'MAC: <code>' + esc(d.mac || '—') + '</code> · IP: <code>' + esc(d.ip || '—') + '</code>\n';
	body += 'Состояние: ' + (st ? reason_text(st.reason, st.until, st.allow_until)
		: (d.blocked ? '🔒 вручную' : (d.online ? '🟢 в сети' : '⚪ офлайн'))) + '\n';
	if (d.wifi_blocked)
		body += '📶 Wi-Fi заблокирован (кабель работает)\n';
	else if (d.configured)
		body += '📶 Wi-Fi разрешён\n';
	if (!d.configured)
		body += '(не добавлен в контроль — действие добавит его автоматически)\n';
	if (!d.mac && !d.ip)
		body += '\n⚠ Нет MAC/IP — блокировка невозможна.';
	return body;
}

function device_menu_kb(ref) {
	const d = dev_by_ref(ref);
	if (!d)
		return kb([ [ '⬅ Устройства', 'ctl:dev:0' ] ]);
	const rows = [
		[ '🔒 Блок', 'ctl:blk:' + ref ], [ '🔓 Разрешить', 'ctl:alw:' + ref ],
		[ '✅ На 1 ч', 'ctl:tal60:' + ref ], [ '✅ На сутки', 'ctl:tal1440:' + ref ],
		[ '⏱ 30 мин', 'ctl:t30:' + ref ], [ '⏱ 1 ч', 'ctl:t60:' + ref ],
		[ '⏱ 2 ч', 'ctl:t120:' + ref ], [ '⏱ Сутки', 'ctl:t1440:' + ref ]
	];
	if (d.configured && d.mac)
		push(rows, [ d.wifi_blocked ? '📶 Разрешить Wi-Fi' : '📶 Запретить Wi-Fi',
			(d.wifi_blocked ? 'walm:' : 'wblk:') + ref ]);
	if (d.configured)
		push(rows, [ '↩ Снять временный', 'ctl:tunb:' + ref ]);
	push(rows, [ '⬅ Устройства', 'ctl:dev:0' ]);
	return kb(rows);
}

/* Block/unblock/temp for a device (auto-adds unconfigured ones).
 * Ф8.2: EVERY mutation rides the control_* RPC door (commit + apply + the
 * event happen in rpcd); the module reports the honest outcome and quiets
 * the echo push. EXPORTED: the bot's confirm flow calls it directly. */
export function dev_action(api, ref, action, cbid, chat_id) {
	const d = dev_by_ref(ref);
	if (!d) {
		api.answer_cb(cbid, 'Список изменился');
		api.send_html(chat_id, 'устройство не найдено — обновляю', devices_kb(0));
		return;
	}
	if (!d.mac && !d.ip) {
		api.answer_cb(cbid, 'Нет MAC/IP');
		api.send_html(chat_id, 'у устройства нет MAC/IP — блокировка невозможна', null);
		return;
	}
	const cid = cfg_id_for_dev(d, true);
	if (!cid) {
		api.answer_cb(cbid, 'Ошибка');
		api.send_html(chat_id, 'не удалось добавить устройство в контроль' +
			' (Control API: ' + ((dev_last_err != null) ? dev_last_err : 'rpcd недоступен') + ')', null);
		return;
	}
	if ((action === 'wblk' || action === 'walm') && !length(d.mac)) {
		api.answer_cb(cbid, 'Нет MAC');
		api.send_html(chat_id, 'Wi-Fi-блок работает по MAC — у устройства нет MAC-адреса', null);
		return;
	}
	const label = d.alias || d.hostname || d.ip || d.mac;
	let ok = false, note = '', err = null;
	let method = null, args = null;
	if (action === 'blk' || action === 'alw') {
		method = 'control_client_block';
		args = { id: cid, blocked: (action === 'blk') ? '1' : '0' };
		note = (action === 'blk') ? 'заблокирован' : 'разрешён';
	} else if (action === 'wblk' || action === 'walm') {
		method = 'control_client_wifi_block';
		args = { id: cid, blocked: (action === 'wblk') ? '1' : '0' };
		note = (action === 'wblk') ? 'Wi-Fi заблокирован (кабель работает)' : 'Wi-Fi разблокирован';
	} else if (action === 'tal60' || action === 'tal1440') {
		method = 'control_client_temp_allow';
		args = { id: cid, minutes: (action === 'tal60') ? '60' : '1440' };
		note = 'временно разрешён на ' + ((action === 'tal60') ? '1 ч' : 'сутки');
	} else if (action === 't30' || action === 't60' || action === 't120' || action === 't1440') {
		const TEMP_MIN = { t30: '30', t60: '60', t120: '120', t1440: '1440' };
		method = 'control_client_temp_block';
		args = { id: cid, minutes: TEMP_MIN[action] };
		note = 'временный блок на ' + fmt_minutes(int(TEMP_MIN[action]));
	} else if (action === 'tunb') {
		method = 'control_client_temp_unblock';
		args = { id: cid };
		note = 'временный блок снят';
	} else {
		api.answer_cb(cbid, 'Неизвестное действие');
		return;
	}
	dev_last_err = null;
	const r = ubus_call(method, args, 15);
	if (r && r.result === true) {
		ok = true;
		bump_cursor();
		quiet_touch(api);
	} else {
		err = (r && r.error) ? '' + r.error : 'rpcd недоступен';
		dev_last_err = err;
	}
	if (ok) {
		api.answer_cb(cbid, note);
		api.send_html(chat_id, '✅ ' + esc(label) + ': ' + esc(note), device_menu_kb(ref));
	} else {
		api.answer_cb(cbid, 'Ошибка');
		api.send_html(chat_id, '⚠ ' + esc(label) + ': действие не выполнено — ' + esc(err), device_menu_kb(ref));
	}
};

/* ── sites view / actions ─────────────────────────────────────────────── */

function sites_text() {
	const rules = get_sections('rule');
	if (!length(rules))
		return 'правил сайтов нет — /blocksite &lt;домен&gt; добавит блок';
	let out = '🛡 <b>Правила сайтов</b>:\n';
	for (let i = 0; i < length(rules); i++) {
		const r = rules[i];
		const cids = r.client_ids || [];
		let scope = 'вся сеть';
		if (length(cids)) {
			const names = [];
			for (let k = 0; k < length(cids) && k < 3; k++) {
				const c = get_section(cids[k]);
				push(names, c ? (c.name || c.ip || cids[k]) : cids[k]);
			}
			scope = join(', ', names) + ((length(cids) > 3) ? '…' : '');
		}
		const tg = (r.target && length(r.target)) ? r.target[0] : '?';
		const more = (length(r.target) > 1) ? ' +' + (length(r.target) - 1) : '';
		out += (i + 1) + '. ' + (r.enabled === '1' ? '🟢' : '⚪') + ' <b>' +
			esc(tg) + '</b>' + esc(more) + ' → ' + esc(scope) + '\n';
	}
	return out;
}

function sites_kb() {
	const rules = get_sections('rule');
	const rows = [];
	for (let i = 0; i < length(rules) && i < 12; i++) {
		const r = rules[i];
		const tg = (r.target && length(r.target)) ? r.target[0] : '?';
		if (length('sdel:' + r.id) > 60)
			continue;
		push(rows, [ '✖ ' + tg, 'sdel:' + r.id ]);
	}
	push(rows, [ '🔄 Обновить', 'ctl:sites' ]);
	return kb(rows);
}

/* Validation only — the mutation waits for the second button. */
function blocksite_check(rest) {
	const parts = split(trim(rest || ''), /\s+/);
	if (!length(parts) || !length(trim(parts[0])))
		return { error: 'использование: /blocksite <домен[,домен]> [№ устройства из /devices]' };
	const doms = [];
	const raw = split(parts[0], ',');
	for (let i = 0; i < length(raw); i++) {
		const d = lc(clean_text(raw[i]));
		if (length(d))
			push(doms, d);
	}
	if (!length(doms))
		return { error: 'укажите хотя бы один домен' };
	for (let i = 0; i < length(doms); i++)
		if (match(doms[i], /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z-]{2,}$/) == null)
			return { error: 'не похоже на домен: ' + doms[i] };
	const cids = [];
	if (length(parts) > 1 && (match(trim(parts[1]), /^[0-9]+$/) != null)) {
		const d = dev_by_idx(int(trim(parts[1])) - 1);
		if (!d)
			return { error: 'нет устройства с таким номером — /devices' };
		const cid = cfg_id_for_dev(d, true);
		if (!cid)
			return { error: 'у устройства нет MAC/IP — правило для него невозможно' };
		if (!sid_ok(cid, 'client'))
			return { error: 'идентификатор устройства неверен — попробуйте ещё раз' };
		push(cids, cid);
	}
	return { doms: doms, cids: cids };
}

/* The confirmed mutation: one control_rule_add RPC (commit + apply + event
 * happen in rpcd). */
export function blocksite_exec(api, chat_id, doms_csv, cids_csv, cbid) {
	const doms = [];
	const dra = split('' + (doms_csv || ''), ',');
	for (let i = 0; i < length(dra); i++)
		if (length(trim(dra[i])))
			push(doms, trim(dra[i]));
	const cids = [];
	const cra = split('' + (cids_csv || ''), ',');
	for (let i = 0; i < length(cra); i++)
		if (length(trim(cra[i])))
			push(cids, trim(cra[i]));
	if (!length(doms)) {
		api.answer_cb(cbid, 'Пусто');
		return;
	}
	const r = ubus_call('control_rule_add', {
		name: doms[0], type: 'domain',
		targets: join(',', doms), client_ids: join(',', cids)
	}, 15);
	if (r && r.result === true) {
		bump_cursor();
		quiet_touch(api);
		api.answer_cb(cbid, 'Добавлено');
		api.send_html(chat_id, '✅ блок добавлен: ' + esc(join(', ', doms)) +
			(length(cids) ? ' (для выбранного устройства)' : ' (вся сеть)') + '\nсписок: /sites', sites_kb());
	} else {
		api.answer_cb(cbid, 'Ошибка');
		api.send_html(chat_id, '⚠ Правило не добавлено: ' +
			esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), null);
	}
};

/* Validation + count for the confirm card. */
function unblocksite_check(rest) {
	const dom = lc(clean_text(split(trim(rest || ''), ' ')[0] || ''));
	if (!length(dom))
		return { error: 'использование: /unblocksite <домен>' };
	const rules = get_sections('rule');
	let n = 0;
	for (let i = 0; i < length(rules); i++) {
		const tg = rules[i].target || [];
		for (let k = 0; k < length(tg); k++)
			if (lc(tg[k]) === dom)
				n++;
	}
	return { dom: dom, count: n };
}

/* The confirmed mutation: delete EVERY rule still matching the domain
 * (the live list is re-resolved at confirm time — honest). */
export function unblocksite_exec(api, chat_id, dom, cbid) {
	const rules = get_sections('rule');
	let n = 0, fail = null;
	for (let i = 0; i < length(rules); i++) {
		const r0 = rules[i];
		const tg = r0.target || [];
		let hit = false;
		for (let k = 0; k < length(tg); k++)
			if (lc(tg[k]) === lc('' + dom))
				hit = true;
		if (!hit)
			continue;
		const r = ubus_call('control_rule_delete', { id: r0.id }, 15);
		if (r && r.result === true)
			n++;
		else if (fail == null)
			fail = (r && r.error) ? '' + r.error : 'rpcd недоступен';
	}
	bump_cursor();
	if (n > 0) {
		quiet_touch(api);
		api.answer_cb(cbid, 'Удалено');
		api.send_html(chat_id, '✅ удалено правил: ' + n + ' (' + esc('' + dom) + ')' +
			(fail ? '\n⚠ часть не удалась: ' + esc(fail) : ''), sites_kb());
	} else {
		api.answer_cb(cbid, fail ? 'Ошибка' : 'Не найдено');
		api.send_html(chat_id, (fail ? '⚠ удаление не выполнено: ' + esc(fail)
			: 'правил с ' + esc('' + dom) + ' не найдено — /sites'), null);
	}
};

/* The confirmed mutation for a SINGLE rule id (sdel:). */
export function rule_delete_exec(api, chat_id, rid, cbid) {
	if (!sid_ok(rid, 'rule')) {
		api.answer_cb(cbid, 'Правило уже удалено');
		api.send_html(chat_id, sites_text(), sites_kb());
		return;
	}
	const r = ubus_call('control_rule_delete', { id: rid }, 15);
	if (r && r.result === true) {
		bump_cursor();
		quiet_touch(api);
		api.answer_cb(cbid, 'Удалено');
		api.send_html(chat_id, '✅ правило удалено.', sites_kb());
	} else {
		api.answer_cb(cbid, 'Ошибка');
		api.send_html(chat_id, '⚠ Правило не удалено: ' +
			esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), sites_kb());
	}
};

/* ── wifi view ────────────────────────────────────────────────────────── */

function wifi_ifaces() {
	const st_raw = capture(`ubus call network.wireless status 2>/dev/null`);
	let st = null;
	try { st = json(st_raw); } catch (e) { st = null; }
	const ifaces = [];
	if (st) {
		for (let radio in st) {
			const confs = st[radio].interfaces || [];
			for (let i = 0; i < length(confs); i++) {
				const cfg = confs[i].config || {};
				push(ifaces, {
					id: confs[i].section || '',
					ssid: cfg.ssid || confs[i].section || radio,
					dis: cfg.disabled === true
				});
			}
		}
	}
	return ifaces;
}

function wifi_temps_now() {
	const out = {};
	const files = split(trim(capture(`ls /var/run/homecontrol/wifi.temp.* 2>/dev/null`)), /\n/);
	for (let i = 0; i < length(files); i++) {
		const m = match(trim(files[i]), /wifi\.temp\.(.+)$/);
		if (!m)
			continue;
		out[m[1]] = int(trim(readfile(trim(files[i])) || '')) || 0;
	}
	return out;
}

function wifi_text() {
	const ifaces = wifi_ifaces();
	if (!length(ifaces))
		return 'статус Wi-Fi недоступен';
	const temps = wifi_temps_now();
	let out = '📶 <b>Wi-Fi</b>:\n';
	for (let i = 0; i < length(ifaces); i++) {
		const w = ifaces[i];
		let line = '• ' + (w.ssid || w.id) + ' — ' + (w.dis ? '🔴 выкл' : '🟢 вкл');
		if (length(w.id) && (w.id in temps))
			line += ' (временно, вкл. в ' + fmt_clock(temps[w.id]) + ')';
		out += line + '\n';
	}
	return out;
}

function wifi_kb() {
	const ifaces = wifi_ifaces();
	const rows = [];
	for (let i = 0; i < length(ifaces); i++) {
		const w = ifaces[i];
		if (!length(w.id) || length('wtf:' + w.id) > 60)
			continue;
		let lbl = w.ssid || w.id;
		if (length(lbl) > 18)
			lbl = substr(lbl, 0, 17) + '…';
		push(rows, [ (w.dis ? '🟢 Вкл: ' : '🔴 Выкл: ') + lbl,
			(w.dis ? 'wton:' : 'woff:') + w.id ]);
	}
	push(rows, [ '🔄 Обновить', 'ctl:wifi' ]);
	return kb(rows);
}

/* Ф8.2: the toggle rides control_wifi_set (commit + wifi reload + event in
 * rpcd). Wi-Fi OFF carries its own second-button confirmation (telegram.uc
 * asks it — this function IS the confirmed executor). EXPORTED. */
export function wifi_toggle(api, chat_id, iface, disable, cbid) {
	/* Ф1.5: the iface id travels through callback data — allow-list it
	 * against the live Wi-Fi view (never raw shell text). */
	const ifaces = wifi_ifaces();
	let known = false;
	for (let i = 0; i < length(ifaces); i++)
		if (ifaces[i].id === iface)
			known = true;
	if (!known || match(iface, /^[A-Za-z0-9_]+$/) == null) {
		api.answer_cb(cbid, 'Ошибка');
		return;
	}
	const r = ubus_call('control_wifi_set', { iface: iface, disabled: disable ? '1' : '0' }, 20);
	if (r && r.result === true) {
		bump_cursor();
		quiet_touch(api);
		api.answer_cb(cbid, disable ? 'Выключено' : 'Включено');
		api.send_html(chat_id, wifi_text(), wifi_kb());
	} else {
		api.answer_cb(cbid, 'Ошибка');
		api.send_html(chat_id, '⚠ Wi-Fi не переключён: ' +
			esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), null);
	}
};

/* ── command / callback entry points (called by telegram.uc) ─────────── */

/* Handle a /command. Returns true when consumed. */
export function handle_command(api, chat_id, cmd, rest) {
	API = api;
	if (cmd === 'control') {
		api.send_html(chat_id, panel_text(), panel_kb());
		return true;
	}
	if (cmd === 'devices' || cmd === 'dev') {
		api.send_html(chat_id, devices_text(0), devices_kb(0));
		return true;
	}
	if (cmd === 'sites') {
		api.send_html(chat_id, sites_text(), sites_kb());
		return true;
	}
	if (cmd === 'blocksite') {
		const c = blocksite_check(rest);
		if (c.error != null) {
			api.send_html(chat_id, esc(c.error), null);
			return true;
		}
		/* Ф8.2: adding a rule is a HEAVY action — the second button. The
		 * optional device number may already have added the client section
		 * (an auxiliary mutation, disclosed here honestly). */
		api.confirm_ask(chat_id, (api.role != null) ? api.role : 'admin', 'rule_add',
			join(',', c.doms) + '|' + join(',', c.cids),
			'Заблокировать ' + join(', ', c.doms) + '?',
			(length(c.cids) ? 'Правило для выбранного устройства (устройство добавлено в контроль).'
				: 'Правило на ВСЮ сеть — все устройства теряют доступ к домену.'));
		return true;
	}
	if (cmd === 'unblocksite') {
		const c = unblocksite_check(rest);
		if (c.error != null) {
			api.send_html(chat_id, esc(c.error), null);
			return true;
		}
		if (c.count === 0) {
			api.send_html(chat_id, 'правил с ' + esc(c.dom) + ' не найдено — /sites', null);
			return true;
		}
		api.confirm_ask(chat_id, (api.role != null) ? api.role : 'admin', 'rule_del_domain',
			c.dom, 'Удалить правила с ' + c.dom + '?',
			'Будет удалено правил: ' + c.count + '. Список пересматривается в момент подтверждения.');
		return true;
	}
	if (cmd === 'pause') {
		const r = ubus_call('control_set_paused', { paused: '1' }, 15);
		if (r && r.result === true) {
			bump_cursor();
			quiet_touch(api);
			api.send_html(chat_id, '⏸ Контроль на паузе — всё разрешено. /resume — обратно.', panel_kb());
		} else
			api.send_html(chat_id, '⚠ Пауза не применена: ' +
				esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), null);
		return true;
	}
	if (cmd === 'resume') {
		const r = ubus_call('control_set_paused', { paused: '0' }, 15);
		if (r && r.result === true) {
			bump_cursor();
			quiet_touch(api);
			api.send_html(chat_id, '▶ Контроль возобновлён.', panel_kb());
		} else
			api.send_html(chat_id, '⚠ Возобновление не применено: ' +
				esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), null);
		return true;
	}
	if (cmd === 'wifi') {
		api.send_html(chat_id, wifi_text(), wifi_kb());
		return true;
	}
	return false;
};

/* Handle a device action callback. Returns true when consumed.
 * Ф8.2: PERSISTENT actions (block / allow / Wi-Fi-block / Wi-Fi-unblock)
 * ask for the second button here; TEMP actions stay one-tap (operator). */
export function handle_dev_action(api, chat_id, data, cbid) {
	API = api;
	const ask = { 'ctl:blk:': 'blk', 'ctl:alw:': 'alw',
		'ctl:wblk:': 'wblk', 'ctl:walm:': 'walm' };
	for (let p in ask) {
		if (substr(data, 0, length(p)) === p) {
			/* Ф8.1 (audit 20): the remainder is the STABLE device reference
			 * (c:<sid> / m:<mac> / i:<ip>) — resolved against the live list
			 * at EXEC time; stale/foreign refs are an honest «not found». */
			const ref = substr(data, length(p));
			const d = dev_by_ref(ref);
			let lbl = ref;
			if (d)
				lbl = d.alias || d.hostname || d.ip || d.mac;
			api.confirm_ask(chat_id, (api.role != null) ? api.role : 'admin',
				'dev', ask[p] + '|' + ref,
				(p === 'ctl:blk:') ? ('Заблокировать «' + lbl + '»?')
					: (p === 'ctl:alw:') ? ('Разрешить «' + lbl + '»?')
					: (p === 'ctl:wblk:') ? ('Запретить Wi-Fi «' + lbl + '»?')
					: ('Разрешить Wi-Fi «' + lbl + '»?'),
				'Постоянное действие (переживает перезапуски). Временные варианты — в меню устройства.');
			return true;
		}
	}
	const temps = { 'ctl:t30:': 't30', 'ctl:t60:': 't60', 'ctl:t120:': 't120',
		'ctl:t1440:': 't1440', 'ctl:tunb:': 'tunb',
		'ctl:tal60:': 'tal60', 'ctl:tal1440:': 'tal1440' };
	for (let p in temps) {
		if (substr(data, 0, length(p)) === p) {
			dev_action(api, substr(data, length(p)), temps[p], cbid, chat_id);
			return true;
		}
	}
	return false;
};

/* Handle generic control callbacks. Returns true when consumed. */
export function handle_cb(api, chat_id, data, cbid) {
	API = api;
	if (data === 'ctl:refresh') {
		api.answer_cb(cbid, 'Обновляю');
		api.send_html(chat_id, panel_text(), panel_kb());
		return true;
	}
	if (data === 'ctl:menu') {
		api.answer_cb(cbid, 'Контроль');
		api.send_html(chat_id, panel_text(), panel_kb());
		return true;
	}
	if (substr(data, 0, 8) === 'ctl:dev:') {
		const page = int(substr(data, 8)) || 0;
		api.answer_cb(cbid, 'Устройства');
		api.send_html(chat_id, devices_text(page), devices_kb(page));
		return true;
	}
	if (substr(data, 0, 9) === 'ctl:devi:') {
		const ref = substr(data, 9);
		api.answer_cb(cbid, 'Устройство');
		api.send_html(chat_id, device_menu_text(ref), device_menu_kb(ref));
		return true;
	}
	if (data === 'ctl:sites') {
		api.answer_cb(cbid, 'Правила');
		api.send_html(chat_id, sites_text(), sites_kb());
		return true;
	}
	if (substr(data, 0, 5) === 'sdel:') {
		const rid = substr(data, 5);
		/* Ф1.5 (аудит 31): a forged callback must not become anything —
		 * format + existence + exact type BEFORE the confirmation. */
		if (!sid_ok(rid, 'rule')) {
			api.answer_cb(cbid, 'Правило уже удалено');
			api.send_html(chat_id, sites_text(), sites_kb());
			return true;
		}
		const rules = get_sections('rule');
		let lbl = rid;
		for (let i = 0; i < length(rules); i++)
			if (rules[i].id === rid) {
				lbl = (rules[i].target && length(rules[i].target)) ? rules[i].target[0] : rid;
				break;
			}
		api.confirm_ask(chat_id, (api.role != null) ? api.role : 'admin', 'rule_del', rid,
			'Удалить правило «' + lbl + '»?',
			'Правило перестанет действовать после apply (~60 с или сразу).');
		return true;
	}
	if (data === 'ctl:pause') {
		api.answer_cb(cbid, 'Пауза');
		const r = ubus_call('control_set_paused', { paused: '1' }, 15);
		if (r && r.result === true) {
			bump_cursor();
			quiet_touch(api);
			api.send_html(chat_id, '⏸ Контроль на паузе — всё разрешено.', panel_kb());
		} else
			api.send_html(chat_id, '⚠ Пауза не применена: ' +
				esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), null);
		return true;
	}
	if (data === 'ctl:resume') {
		api.answer_cb(cbid, 'Продолжаю');
		const r = ubus_call('control_set_paused', { paused: '0' }, 15);
		if (r && r.result === true) {
			bump_cursor();
			quiet_touch(api);
			api.send_html(chat_id, '▶ Контроль возобновлён.', panel_kb());
		} else
			api.send_html(chat_id, '⚠ Возобновление не применено: ' +
				esc((r && r.error) ? '' + r.error : 'rpcd недоступен'), null);
		return true;
	}
	if (data === 'ctl:wifi') {
		api.answer_cb(cbid, 'Wi-Fi');
		api.send_html(chat_id, wifi_text(), wifi_kb());
		return true;
	}
	if (substr(data, 0, 5) === 'woff:' || substr(data, 0, 5) === 'wton:') {
		const iface = substr(data, 5);
		if (substr(data, 0, 5) === 'woff:') {
			/* Ф8.2: Wi-Fi OFF is a HEAVY persistent action — second button. */
			const ifaces = wifi_ifaces();
			let ssid = iface;
			for (let i = 0; i < length(ifaces); i++)
				if (ifaces[i].id === iface)
					ssid = ifaces[i].ssid || iface;
			api.confirm_ask(chat_id, (api.role != null) ? api.role : 'admin', 'wifi',
				iface + '|1', 'Выключить Wi-Fi «' + ssid + '»?',
				'Беспроводные устройства потеряют сеть (кабель работает). Включить обратно: одна кнопка.');
		} else
			wifi_toggle(api, chat_id, iface, false, cbid);
		return true;
	}
	return false;
};

/* ── pushes: events tail + new devices ───────────────────────────────── */

const EV_ICON = {
	block: '🔒', allow: '🔓', temp: '⏱', wifi: '📶', system: '⚙️', schedule: '📅'
};

function leases_map() {
	const out = {};
	const raw = readfile('/tmp/dhcp.leases') || '';
	const lines = split(trim(raw), '\n');
	for (let i = 0; i < length(lines); i++) {
		const f = split(trim(lines[i]), ' ');
		if (length(f) < 4)
			continue;
		out[lc(f[1])] = { ip: f[2], hostname: (length(f[3]) && f[3] !== '*') ? f[3] : '' };
	}
	return out;
}

/* Periodic scan (called from the bot's push_scan). */
export function push_scan(api) {
	API = api;

	/* 1) events journal tail — Event Bus (Ф1.7/Ф2.4, аудит 21): курсор =
	 * монотонный event_id (ts-секунды неуникальны, конкурентные записи
	 * старого read-modify-write затирали события). Базлайн при старте =
	 * durable-курсор этой же загрузки либо голова шины: после рестарта
	 * демона события простоя НЕ теряются и НЕ переигрываются; после ребута
	 * журнал и курсор обнуляются вместе. */
	{
		if (!ev_ready) {
			ev_ready = true;
			const cur = ev_cursor_get('telegram-ctrl');
			ev_last_id = (cur != null) ? int(cur) : ev_head();
			ev_saved_id = ev_last_id;
		}
		const evs = ev_tail(200, ev_last_id);
		/* Ф8.2: events the bot ITSELF just caused (via RPC) are suppressed
		 * for a short window — the direct reply is the single result place.
		 * The cursor advances regardless (a suppressed event never replays). */
		const quiet_now = (api.quiet && int(api.quiet.until || 0) > time());
		for (let i = 0; i < length(evs); i++) {
			const ev = evs[i];
			if (ev.id <= ev_last_id || ev.src !== 'control')
				continue;
			ev_last_id = ev.id;
			if (quiet_now)
				continue;
			const icon = (ev.type in EV_ICON) ? EV_ICON[ev.type] : '•';
			const who = trim('' + (ev.who || ''));
			const detail = trim('' + (ev.detail || ''));
			api.push('control',
				icon + ' <b>Контроль</b>' + (length(who) ? ': ' + esc(who) : '') +
				(length(detail) ? '\n' + esc(detail) : ''));
		}
		if (ev_last_id !== ev_saved_id) {
			ev_cursor_set('telegram-ctrl', ev_last_id);
			ev_saved_id = ev_last_id;
		}
	}

	/* 2) new devices on the network (ARP-based; leases add names) */
	const arp = read_arp();
	const seen_now = {};
	for (let ip in arp.byip)
		seen_now[arp.byip[ip]] = true;
	if (arp_seen == null) {
		arp_seen = seen_now;   /* baseline */
	} else {
		const fresh = [];
		for (let mac in seen_now)
			if (!(mac in arp_seen))
				push(fresh, mac);
		for (let i = 0; i < length(fresh); i++)
			arp_seen[fresh[i]] = true;
		if (length(fresh)) {
			const leases = leases_map();
			const lines = [];
			for (let i = 0; i < length(fresh) && i < 6; i++) {
				const mac = fresh[i];
				const l = leases[mac];
				const ip = (l && l.ip) || arp.bymac[mac] || '';
				const host = (l && l.hostname) || '';
				push(lines, '• ' + esc(host || ip || mac) +
					(length(ip) ? ' (' + ip + ')' : '') + ' — <code>' + mac + '</code>');
			}
			api.push('control',
				'🔌 <b>Новое устройство в сети</b>:\n' + join('\n', lines) +
				'\n/devices — управление.');
		}
	}
};
