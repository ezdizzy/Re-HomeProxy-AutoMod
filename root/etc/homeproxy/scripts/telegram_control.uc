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

'use strict';

import { access, readfile, popen } from 'fs';
/* ч.118: ceil was used by the device-list pagination without an import —
 * every /devices page beyond the first threw "access to undeclared variable
 * ceil" and the callback died. NOTE: this ucode build's 'math' module does
 * NOT export ceil (importing it breaks the whole module load — proven
 * live), so the ceiling is done with integer arithmetic instead. */
import {
	EVENTS_PATH,
	client_states, get_sections, get_section,
	add_event, main_opt, list_devices, bump_cursor,
	read_temps, write_temps, read_arp
} from '/etc/homeproxy/scripts/control.uc';

/* Module state (module scope is closure-safe; declared before use). */
let API = null;
let ev_last_ts = 0;
let arp_seen = null;   /* MACs seen on the network (new-device pushes) */

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

function apply_async(api) {
	/* Re-apply immediately; the 60 s engine would do it anyway — feedback
	 * to a Telegram tap must be fast. */
	system(`( /usr/bin/ucode -L /etc/homeproxy/scripts /etc/homeproxy/scripts/control_apply.uc >/dev/null 2>&1 ) &`);
	api.log('control: apply scheduled');
}

function shell_uci(cmd) {
	return system(cmd + ' >/dev/null 2>&1');
}

/* commit + cursor invalidation: without it the module's cached ucode uci
 * cursor serves a stale snapshot to the NEXT view built right after an
 * action (live-caught, ч.108 — same bug as the rpcd backend). */
function commit_hc() {
	shell_uci(`uci -q commit homecontrol`);
	bump_cursor();
}

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

/* ── configured-client management ─────────────────────────────────────── */

function cfg_id_for_dev(d, create) {
	/* configured device -> its section id; unconfigured -> create one */
	if (d.client_id)
		return d.client_id;
	if (!create)
		return null;
	if (!d.mac && !d.ip)
		return null;
	const fd = popen(`uci -q add homecontrol client`);
	const newid = fd ? trim((fd.read('line') || '')) : '';
	if (fd)
		fd.close();
	if (!length(newid))
		return null;
	if (length(d.mac))
		shell_uci(`uci -q set homecontrol.${newid}.mac='${d.mac}'`);
	if (length(d.ip))
		shell_uci(`uci -q set homecontrol.${newid}.ip='${d.ip}'`);
	const nm = clean_text(d.alias || d.hostname);
	if (length(nm))
		shell_uci(`uci -q set homecontrol.${newid}.name='${nm}'`);
	shell_uci(`uci -q set homecontrol.${newid}.blocked='0'`);
	commit_hc();
	return newid;
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
			push(row, [ lbl, 'ctl:devi:' + j ]);
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

function device_menu_text(idx) {
	const d = dev_by_idx(idx);
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

function device_menu_kb(idx) {
	const d = dev_by_idx(idx);
	if (!d)
		return kb([ [ '⬅ Устройства', 'ctl:dev:0' ] ]);
	const rows = [
		[ '🔒 Блок', 'ctl:blk:' + idx ], [ '🔓 Разрешить', 'ctl:alw:' + idx ],
		[ '✅ На 1 ч', 'ctl:tal60:' + idx ], [ '✅ На сутки', 'ctl:tal1440:' + idx ],
		[ '⏱ 30 мин', 'ctl:t30:' + idx ], [ '⏱ 1 ч', 'ctl:t60:' + idx ],
		[ '⏱ 2 ч', 'ctl:t120:' + idx ], [ '⏱ Сутки', 'ctl:t1440:' + idx ]
	];
	if (d.configured && d.mac)
		push(rows, [ d.wifi_blocked ? '📶 Разрешить Wi-Fi' : '📶 Запретить Wi-Fi',
			(d.wifi_blocked ? 'walm:' : 'wblk:') + idx ]);
	if (d.configured)
		push(rows, [ '↩ Снять временный', 'ctl:tunb:' + idx ]);
	push(rows, [ '⬅ Устройства', 'ctl:dev:0' ]);
	return kb(rows);
}

/* Block/unblock/temp for a device (auto-adds unconfigured ones). */
function dev_action(api, idx, action, cbid, chat_id) {
	const d = dev_by_idx(idx);
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
		api.send_html(chat_id, 'не удалось добавить устройство в контроль', null);
		return;
	}
	if ((action === 'wblk' || action === 'walm') && !length(d.mac)) {
		api.answer_cb(cbid, 'Нет MAC');
		api.send_html(chat_id, 'Wi-Fi-блок работает по MAC — у устройства нет MAC-адреса', null);
		return;
	}
	const label = d.alias || d.hostname || d.ip || d.mac;
	let ok = false, note = '';
	if (action === 'blk' || action === 'alw') {
		const b = (action === 'blk') ? '1' : '0';
		shell_uci(`uci -q set homecontrol.${cid}.blocked='${b}'`);
		commit_hc();
		add_event((action === 'blk') ? 'block' : 'allow', label,
			(action === 'blk') ? 'blocked manually (Telegram)' : 'unblocked (Telegram)');
		ok = true;
		note = (action === 'blk') ? 'заблокирован' : 'разрешён';
	} else if (action === 'wblk' || action === 'walm') {
		const b = (action === 'wblk') ? '1' : '0';
		shell_uci(`uci -q set homecontrol.${cid}.wifi_blocked='${b}'`);
		commit_hc();
		add_event((b === '1') ? 'block' : 'allow', label,
			(b === '1') ? 'Wi-Fi blocked (Telegram)' : 'Wi-Fi block removed (Telegram)');
		ok = true;
		note = (b === '1') ? 'Wi-Fi заблокирован (кабель работает)' : 'Wi-Fi разблокирован';
	} else if (action === 'tal60' || action === 'tal1440') {
		const mins = (action === 'tal60') ? 60 : 1440;
		const temps = read_temps();
		const until = time() + mins * 60;
		if (length(d.mac))
			temps[d.mac] = { until: until, mode: 'allow' };
		if (length(d.ip))
			temps[d.ip] = { until: until, mode: 'allow' };
		write_temps(temps);
		add_event('temp', label, `temporary ALLOW for ${mins} min (Telegram)`);
		ok = true;
		note = 'временно разрешён на ' + fmt_minutes(mins) + ' (до ' + fmt_clock(until) + ')';
	} else if (action === 't30' || action === 't60' || action === 't120' || action === 't1440') {
		const TEMP_MIN = { t30: 30, t60: 60, t120: 120, t1440: 1440 };
		const mins = TEMP_MIN[action];
		const temps = read_temps();
		const until = time() + mins * 60;
		if (length(d.mac))
			temps[d.mac] = { until: until, mode: 'block' };
		if (length(d.ip))
			temps[d.ip] = { until: until, mode: 'block' };
		write_temps(temps);
		add_event('temp', label, `temporary block for ${mins} min (Telegram)`);
		ok = true;
		note = 'временный блок на ' + fmt_minutes(mins) + ' (до ' + fmt_clock(until) + ')';
	} else if (action === 'tunb') {
		const temps = read_temps();
		if (length(d.mac))
			delete temps[d.mac];
		if (length(d.ip))
			delete temps[d.ip];
		write_temps(temps);
		add_event('temp', label, 'temporary block removed (Telegram)');
		ok = true;
		note = 'временный блок снят';
	}
	if (ok) {
		apply_async(api);
		api.answer_cb(cbid, note);
		api.send_html(chat_id, '✅ ' + esc(label) + ': ' + note, device_menu_kb(idx));
	}
}

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

function blocksite(api, chat_id, rest) {
	const parts = split(trim(rest || ''), /\s+/);
	if (!length(parts) || !length(trim(parts[0])))
		return 'использование: /blocksite <домен[,домен]> [№ устройства из /devices]';
	const doms = [];
	const raw = split(parts[0], ',');
	for (let i = 0; i < length(raw); i++) {
		const d = lc(clean_text(raw[i]));
		if (length(d))
			push(doms, d);
	}
	if (!length(doms))
		return 'укажите хотя бы один домен';
	for (let i = 0; i < length(doms); i++)
		if (match(doms[i], /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z-]{2,}$/) == null)
			return 'не похоже на домен: ' + doms[i];

	/* optional scope: device number from /devices */
	const cids = [];
	if (length(parts) > 1 && (match(trim(parts[1]), /^[0-9]+$/) != null)) {
		const d = dev_by_idx(int(trim(parts[1])) - 1);
		if (!d)
			return 'нет устройства с таким номером — /devices';
		const cid = cfg_id_for_dev(d, true);
		if (!cid)
			return 'у устройства нет MAC/IP — правило для него невозможно';
		push(cids, cid);
	}

	const fd = popen(`uci -q add homecontrol rule`);
	const newid = fd ? trim((fd.read('line') || '')) : '';
	if (fd)
		fd.close();
	if (!length(newid))
		return 'uci add failed';
	shell_uci(`uci -q set homecontrol.${newid}.type='domain'`);
	const nm = clean_text(doms[0]);
	if (length(nm))
		shell_uci(`uci -q set homecontrol.${newid}.name='${nm}'`);
	for (let i = 0; i < length(doms); i++)
		shell_uci(`uci -q add_list homecontrol.${newid}.target='${doms[i]}'`);
	for (let i = 0; i < length(cids); i++)
		shell_uci(`uci -q add_list homecontrol.${newid}.client_ids='${cids[i]}'`);
	shell_uci(`uci -q set homecontrol.${newid}.enabled='1'`);
	commit_hc();
	add_event('system', doms[0], 'site rule added via Telegram' +
		(length(cids) ? ' (per-client)' : ' (whole network)'));
	apply_async(api);
	return '✅ блок добавлен: ' + join(', ', doms) +
		(length(cids) ? ' (для выбранного устройства)' : ' (вся сеть)') +
		'\nсписок: /sites';
}

function unblocksite(api, chat_id, rest) {
	const dom = lc(clean_text(split(trim(rest || ''), ' ')[0] || ''));
	if (!length(dom))
		return 'использование: /unblocksite <домен>';
	const rules = get_sections('rule');
	let n = 0;
	for (let i = 0; i < length(rules); i++) {
		const r = rules[i];
		const tg = r.target || [];
		let hit = false;
		for (let k = 0; k < length(tg); k++)
			if (lc(tg[k]) === dom)
				hit = true;
		if (hit) {
			shell_uci(`uci -q delete homecontrol.${r.id}`);
			n++;
		}
	}
	if (n > 0) {
		commit_hc();
		add_event('system', dom, `site rule(s) removed via Telegram (${n})`);
		apply_async(api);
		return '✅ удалено правил: ' + n + ' (' + dom + ')';
	}
	return 'правил с ' + dom + ' не найдено — /sites';
}

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

function wifi_toggle(api, chat_id, iface, disable, cbid) {
	if (!length(iface)) {
		api.answer_cb(cbid, 'Ошибка');
		return;
	}
	if (disable) {
		shell_uci(`uci -q set wireless.${iface}.disabled='1'`);
		add_event('wifi', iface, 'turned off (Telegram)');
	} else {
		shell_uci(`uci -q delete wireless.${iface}.disabled`);
		shell_uci(`rm -f '/var/run/homecontrol/wifi.off.${iface}'`);
		add_event('wifi', iface, 'turned on (Telegram)');
	}
	shell_uci(`uci -q commit wireless`);
	system(`wifi reload 2>/dev/null`);
	api.answer_cb(cbid, disable ? 'Выключаю' : 'Включаю');
	api.send_html(chat_id, wifi_text(), wifi_kb());
}

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
		api.send_html(chat_id, esc(blocksite(api, chat_id, rest)), null);
		return true;
	}
	if (cmd === 'unblocksite') {
		api.send_html(chat_id, esc(unblocksite(api, chat_id, rest)), null);
		return true;
	}
	if (cmd === 'pause') {
		shell_uci(`uci -q set homecontrol.main.paused='1'`);
		commit_hc();
		add_event('system', '', 'enforcement paused (Telegram)');
		apply_async(api);
		api.send_html(chat_id, '⏸ Контроль на паузе — всё разрешено. /resume — обратно.', panel_kb());
		return true;
	}
	if (cmd === 'resume') {
		shell_uci(`uci -q set homecontrol.main.paused='0'`);
		commit_hc();
		add_event('system', '', 'enforcement resumed (Telegram)');
		apply_async(api);
		api.send_html(chat_id, '▶ Контроль возобновлён.', panel_kb());
		return true;
	}
	if (cmd === 'wifi') {
		api.send_html(chat_id, wifi_text(), wifi_kb());
		return true;
	}
	return false;
};

/* Handle a device action callback. Returns true when consumed. */
export function handle_dev_action(api, chat_id, data, cbid) {
	API = api;
	const prefixes = { 'ctl:blk:': 'blk', 'ctl:alw:': 'alw', 'ctl:t30:': 't30',
		'ctl:t60:': 't60', 'ctl:t120:': 't120', 'ctl:t1440:': 't1440',
		'ctl:tunb:': 'tunb', 'ctl:tal60:': 'tal60', 'ctl:tal1440:': 'tal1440',
		'ctl:wblk:': 'wblk', 'ctl:walm:': 'walm' };
	for (let p in prefixes) {
		if (substr(data, 0, length(p)) === p) {
			dev_action(api, int(substr(data, length(p))), prefixes[p], cbid, chat_id);
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
		const idx = int(substr(data, 9));
		api.answer_cb(cbid, 'Устройство');
		api.send_html(chat_id, device_menu_text(idx), device_menu_kb(idx));
		return true;
	}
	if (data === 'ctl:sites') {
		api.answer_cb(cbid, 'Правила');
		api.send_html(chat_id, sites_text(), sites_kb());
		return true;
	}
	if (substr(data, 0, 5) === 'sdel:') {
		const rid = substr(data, 5);
		shell_uci(`uci -q delete homecontrol.${rid}`);
		commit_hc();
		add_event('system', rid, 'site rule removed (Telegram)');
		apply_async(api);
		api.answer_cb(cbid, 'Удалено');
		api.send_html(chat_id, sites_text(), sites_kb());
		return true;
	}
	if (data === 'ctl:pause') {
		api.answer_cb(cbid, 'Пауза');
		shell_uci(`uci -q set homecontrol.main.paused='1'`);
		commit_hc();
		add_event('system', '', 'enforcement paused (Telegram)');
		apply_async(api);
		api.send_html(chat_id, '⏸ Контроль на паузе — всё разрешено.', panel_kb());
		return true;
	}
	if (data === 'ctl:resume') {
		api.answer_cb(cbid, 'Продолжаю');
		shell_uci(`uci -q set homecontrol.main.paused='0'`);
		commit_hc();
		add_event('system', '', 'enforcement resumed (Telegram)');
		apply_async(api);
		api.send_html(chat_id, '▶ Контроль возобновлён.', panel_kb());
		return true;
	}
	if (data === 'ctl:wifi') {
		api.answer_cb(cbid, 'Wi-Fi');
		api.send_html(chat_id, wifi_text(), wifi_kb());
		return true;
	}
	if (substr(data, 0, 5) === 'woff:' || substr(data, 0, 5) === 'wton:') {
		const iface = substr(data, 5);
		wifi_toggle(api, chat_id, iface, (substr(data, 0, 5) === 'woff:'), cbid);
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

	/* 1) events journal tail */
	if (access(EVENTS_PATH)) {
		let events = [];
		try { events = json(readfile(EVENTS_PATH) || '[]'); } catch (e) { events = []; }
		let maxt = ev_last_ts;
		for (let i = 0; i < length(events); i++)
			if (events[i].ts > maxt)
				maxt = events[i].ts;
		if (ev_last_ts === 0) {
			ev_last_ts = maxt;   /* baseline: no flood after daemon restart */
		} else if (maxt > ev_last_ts) {
			for (let i = 0; i < length(events); i++) {
				const ev = events[i];
				if (ev.ts <= ev_last_ts)
					continue;
				const icon = (ev.type in EV_ICON) ? EV_ICON[ev.type] : '•';
				const who = trim('' + (ev.who || ''));
				const detail = trim('' + (ev.detail || ''));
				api.push('control',
					icon + ' <b>Контроль</b>' + (length(who) ? ': ' + esc(who) : '') +
					(length(detail) ? '\n' + esc(detail) : ''));
			}
			ev_last_ts = maxt;
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
