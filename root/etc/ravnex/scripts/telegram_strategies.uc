/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex — «⚡ Стратегии» для Telegram-бота (план 24 / сеанс 181, дизайн ч.268).
 *
 * Метки пользователя поверх стратегий: пара «ресурс × стратегия»
 * (device_verdicts.json, формат ч.234). Метка — вес СЛЕДУЮЩИХ решений:
 *   works  — подтверждение с устройства (наивысший вес выбора,
 *            автопилот отказывается менять works-победителя);
 *   broken — опровержение (автопилот refuse broken, автоподбор
 *            device_refused, оптимизатор manual_only);
 *   clear  — снять метку.
 * Метка НЕ переключает стратегию мгновенно — это честно сообщается в боте.
 *
 * Конвенции модуля (как telegram_control.uc): примитивы демона приходят в
 * api-объекте (send_html/kb_rows/answer_cb/esc_html/log/role/maxmsg), никаких
 * `?.` и typeof (type()), sleep() в мс, join() с разделителем, функции
 * объявлены РАНЬШЕ вызывающих (hoisting'а нет), экспорты закрываются `};`.
 * Русские строки хардкодятся в исходнике (правило бэкенд-строк).
 *
 * Безопасность:
 *   - CB-префикс 'zt:' — RBAC operator (демон гейтит CB_MIN_PREFIX, модуль
 *     перепроверяет по рангу — защита в глубину);
 *   - strategy-аргумент НЕ передаётся в callback_data (лимит 64 байта):
 *     токен = FNV-1a 32-bit 8-hex над args (клон hp_sub_strhash rpcd,
 *     держать в синхронизации); на ИСПОЛНЕНИИ множество пересобирается из
 *     ЖИВЫХ источников {текущий zapret_cmd_opts} ∪ {ключи device_verdicts}
 *     ∪ {стратегии последнего свипа} ∪ {корпус} — тап по устаревшему токену
 *     = честное «стратегия изменилась — открой карточку заново»;
 *   - мутация ТОЛЬКО через RPC-дверь zapret_device_verdict_set (та же дверь,
 *     что у UI: shape-гвард, атомарная запись tmp+mv); ACL не нужен — бот
 *     ходит ubus от root;
 *   - audit() тапа делает сам демон (все cb ≤ 64 симв.); модуль логирует
 *     результат через api.log;
 *   - стратегии длиннее 2000 символов честно БЕЗ кнопок (RPC-гвард длины):
 *     «метка недоступна».
 */

import { access, popen, readfile } from 'fs';

const DEV_FILE = '/etc/ravnex/device_verdicts.json';
const CAND_FILE = '/etc/ravnex/zapret_candidates.json';
const FUZZ_FILE = '/var/run/ravnex/zapret_fuzz_result.json';
const OPTS_MAX = 2000;
const CARD_PAGE = 8;

const RESOURCES = [
	{ key: 'yt', name: 'YouTube', res: 'youtube', icon: '🎥' },
	{ key: 'dc', name: 'Discord', res: 'discord', icon: '💬' },
	{ key: 'tg', name: 'Telegram', res: 'telegram', icon: '✈️',
		note: 'лаборатория не измеряет Telegram — у этого ресурса только твои device-метки' },
	{ key: 'gen', name: 'Общие узлы', res: 'general', icon: '🌐' }
];

let API = null;

/* ── primitives (clone of telegram_control.uc patterns) ──────────────── */

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

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

function ubus_call(method, args, timeout_s) {
	const t = (timeout_s != null && timeout_s > 0 && timeout_s <= 60) ? int(timeout_s) : 12;
	const cmd = `ubus -t ${t} call luci.ravnex ${method} '${api_json(args)}'`;
	const raw = capture(cmd);
	let j = null;
	try { j = json(raw || ''); } catch (e) { j = null; }
	if (j == null)
		API.log('strategies ubus ' + method + ': no/invalid reply (rpcd недоступен?)');
	return j;
}

/* FNV-1a 32-bit — twin of rpcd hp_sub_strhash (KEEP IN SYNC): same ucode
 * arithmetic, so tokens computed here match the ecosystem exactly. */
function strhash(s) {
	let h = 2166136261;
	const n = length(s);
	for (let i = 0; i < n; i++) {
		h = (h ^ ord(s, i)) & 0xFFFFFFFF;
		h = (h * 16777619) & 0xFFFFFFFF;
	}
	return sprintf('%08x', h);
}

function strip_shell_quotes(s) {
	let out = '';
	s = '' + s;
	for (let i = 0; i < length(s); i++) {
		const ch = substr(s, i, 1);
		if (ch !== "'")
			out += ch;
	}
	return out;
}

function parse_json_file(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function role_rank(role) {
	const r = '' + role;
	if (r === 'owner') return 4;
	if (r === 'admin') return 3;
	if (r === 'operator') return 2;
	return 1;
}

function fmt_stamp(ts) {
	let t = null;
	try { t = localtime(int(ts)); } catch (e) { t = null; }
	if (t == null || type(t) !== 'array' || length(t) < 5)
		return '';
	return sprintf('%02d.%02d.%04d %02d:%02d', t[3], int(t[4]) + 1,
		1900 + int(t[5]), t[2], t[1]);
}

/* ── strategy sources ─────────────────────────────────────────────────── */

/* The strategy universe of a resource: the CURRENT applied composite first,
 * then the last sweep's ranked order (the ranking the user saw in LuCI),
 * then corpus entries, then everything already marked. Dedup by args,
 * stable order. Each entry: { args, name, src }. */
function collect_strategies(res) {
	const out = [];
	const seen = {};
	const add = (args, name, src) => {
		args = '' + args;
		if (!length(args) || seen[args]) return;
		seen[args] = true;
		push(out, { args: args, name: (name != null && length('' + name)) ? ('' + name) : null,
			src: '' + src });
	};
	/* current applied (shell-quoted UCI value → strip the quotes) */
	const cur = strip_shell_quotes(trim(capture('uci -q get ravnex.config.zapret_cmd_opts') || ''));
	if (length(cur))
		add(cur, null, 'текущая');
	/* last sweep result — ranked order */
	const fz = parse_json_file(FUZZ_FILE);
	if (fz != null && type(fz.strategies) === 'array')
		for (let s in fz.strategies) {
			if (type(s) !== 'object' || s.args == null) continue;
			add(s.args, s.name, 'свип');
		}
	/* corpus */
	const cj = parse_json_file(CAND_FILE);
	if (cj != null && type(cj.candidates) === 'array')
		for (let c in cj.candidates) {
			if (type(c) !== 'object' || c.args == null) continue;
			add(c.args, c.name, 'корпус');
		}
	/* already-marked strategies of THIS resource (they must stay tappable
	 * even when absent from the corpus/sweep — clearing a stale mark is a
	 * legitimate operation) */
	const dev = parse_json_file(DEV_FILE);
	if (dev != null && type(dev.resources) === 'object' &&
		type(dev.resources[res]) === 'object')
		for (let a in keys(dev.resources[res]))
			add(a, null, 'метка');
	return out;
}

/* device marks of one resource: args → {verdict, ts} */
function device_map(res) {
	const dev = parse_json_file(DEV_FILE);
	if (dev == null || type(dev.resources) !== 'object' ||
		type(dev.resources[res]) !== 'object')
		return {};
	const m = {};
	for (let a in keys(dev.resources[res])) {
		const mv = dev.resources[res][a];
		if (mv == null) continue;
		const v = (type(mv) === 'object') ? ('' + (mv.verdict || '')) : ('' + mv);
		const ts = (type(mv) === 'object' && mv.ts != null) ? int(mv.ts) : 0;
		m[a] = { verdict: v, ts: ts };
	}
	return m;
}

/* token → args, resolved against the LIVE strategy set (staleness honest) */
function args_by_token(res, tok) {
	const list = collect_strategies(res);
	for (let e in list) {
		if (strhash(e.args) === ('' + tok))
			return e.args;
	}
	return null;
}

/* ── cards ────────────────────────────────────────────────────────────── */

function kb(rows) {
	return API.kb_rows(rows);
}

function esc(s) {
	return API.esc_html('' + s);
}

function head_of(args, n) {
	args = '' + args;
	return (length(args) > n) ? (substr(args, 0, n) + '…') : args;
}

function strategies_menu() {
	let text = '<b>⚡ Стратегии</b>\n';
	text += 'Метка = пара «ресурс × стратегия».\n';
	text += '✅ Работает — подтверждение с устройства (сильнее лаборатории, автопилот не сменит такого победителя).\n';
	text += '❌ Не работает — вес ПРОТИВ автоприменения (автопилот/автоподбор/оптимизатор это учитывают).\n';
	text += '↩ Снять — убрать метку.\n';
	text += 'Метка не переключает стратегию мгновенно — она влияет на следующие решения.';
	const rows = [
		[ [ '🎥 YouTube', 'zt:r:yt' ], [ '💬 Discord', 'zt:r:dc' ] ],
		[ [ '✈️ Telegram', 'zt:r:tg' ], [ '🌐 Общие узлы', 'zt:r:gen' ] ],
		[ [ '🏠 В меню', 'act:menu' ] ]
	];
	API.send_html(API.chat_id, text, kb(rows));
}

function strategies_card(key, page) {
	let rd = null;
	for (let r in RESOURCES)
		if (r.key === key) { rd = r; break; }
	if (rd == null) {
		strategies_menu();
		return;
	}
	page = (page != null && page > 0) ? int(page) : 0;
	const dev = device_map(rd.res);
	const list = collect_strategies(rd.res);
	const total = length(list);
	const pages = (total > CARD_PAGE) ? (int((total + CARD_PAGE - 1) / CARD_PAGE)) : 1;
	if (page >= pages)
		page = pages - 1;
	const from = page * CARD_PAGE;
	const to = from + CARD_PAGE;

	let text = '<b>⚡ ' + rd.icon + ' ' + esc(rd.name) + '</b> — метки стратегий\n';
	if (rd.note != null)
		text += 'ℹ ' + esc(rd.note) + '\n';
	let marks_n = 0;
	for (let a in keys(dev)) {
		const v = dev[a].verdict;
		if (v === 'works' || v === 'broken')
			marks_n++;
	}
	text += 'Меток в файле: ' + marks_n + ' · стратегий в наборе: ' + total + '\n';
	text += '<i>Номер в списке = строка кнопок под списком.</i>\n';

	const rows = [];
	const numpad = (i) => '' + (i + 1);
	for (let i = from; i < to && i < total; i++) {
		const e = list[i];
		const mv = dev[e.args];
		let badge = '· нет метки';
		if (mv != null && mv.verdict === 'works')
			badge = '✅ работает' + ((mv.ts > 0) ? (' (' + fmt_stamp(mv.ts) + ')') : '');
		else if (mv != null && mv.verdict === 'broken')
			badge = '❌ не работает' + ((mv.ts > 0) ? (' (' + fmt_stamp(mv.ts) + ')') : '');
		text += '\n<b>' + numpad(i - from) + '.</b> ' +
			esc((e.name != null) ? e.name : head_of(e.args, 42)) +
			' <i>(' + esc(e.src) + ')</i>\n  ' + badge;
		if (length(e.args) > OPTS_MAX) {
			text += '\n  <i>стратегия длиннее ' + OPTS_MAX + ' симв. — метка недоступна (лимит RPC)</i>';
			continue;
		}
		const tok = strhash(e.args);
		push(rows, [
			[ numpad(i - from) + ' ✅', 'zt:m:' + key + ':works:' + tok ],
			[ numpad(i - from) + ' ❌', 'zt:m:' + key + ':broken:' + tok ],
			[ numpad(i - from) + ' ↩', 'zt:m:' + key + ':clear:' + tok ]
		]);
	}

	const nav = [];
	if (pages > 1) {
		if (page > 0)
			push(nav, [ '◀', 'zt:r:' + key + ':' + (page - 1) ]);
		push(nav, [ (page + 1) + '/' + pages, 'zt:r:' + key + ':' + page ]);
		if (page < pages - 1)
			push(nav, [ '▶', 'zt:r:' + key + ':' + (page + 1) ]);
	}
	if (length(nav))
		push(rows, nav);
	push(rows, [ [ '⚡ К ресурсам', 'zt:menu' ], [ '🏠 В меню', 'act:menu' ] ]);
	API.send_html(API.chat_id, text, kb(rows));
}

/* set/clear a mark through the SAME RPC door the LuCI buttons use */
function mark_act(key, verdict, tok) {
	let rd = null;
	for (let r in RESOURCES)
		if (r.key === key) { rd = r; break; }
	if (rd == null) {
		API.answer_cb(API.cbid, 'Неизвестный ресурс');
		return;
	}
	const args = args_by_token(rd.res, tok);
	if (args == null) {
		API.answer_cb(API.cbid, 'Стратегия изменилась');
		API.send_html(API.chat_id,
			'⚠ Стратегия изменилась с момента карточки (токен не найден в живом наборе). Открой карточку заново.',
			kb([ [ [ '⚡ К ресурсам', 'zt:menu' ] ] ]));
		return;
	}
	const j = ubus_call('zapret_device_verdict_set',
		{ resource: rd.res, strategy: args, verdict: verdict });
	const head = (length(args) > 60) ? (substr(args, 0, 60) + '…') : args;
	if (j == null || j.result !== true) {
		const err = (j != null && j.error != null) ? ('' + j.error) : 'rpcd недоступен';
		API.log('strategies set failed: ' + err);
		API.answer_cb(API.cbid, 'Ошибка');
		API.send_html(API.chat_id,
			'⚠ Метка не записана: ' + esc(err) + '\nСтратегия: <code>' + esc(head) + '</code>',
			kb([ [ [ '↩ Назад к карточке', 'zt:r:' + key ] ] ]));
		return;
	}
	const verb = (verdict === 'works') ? '✅ «Работает» выставлена'
		: (verdict === 'broken') ? '❌ «Не работает» выставлена'
		: '↩ Метка снята';
	API.log('strategies mark: ' + rd.res + ' ' + verdict + ' (' + length(args) + ' chars)');
	API.answer_cb(API.cbid, verb);
	API.send_html(API.chat_id,
		verb + '\nСтратегия: <code>' + esc(head) + '</code>\n' +
		'Метка применится к СЛЕДУЮЩИМ решениям (автопилот/автоподбор/оптимизатор) — текущая применённая стратегия не меняется мгновенно.',
		kb([ [ [ '↩ Назад к карточке', 'zt:r:' + key ] ] ]));
}

/* ── entry points ─────────────────────────────────────────────────────── */

export function handle_cb(api, chat_id, data, cbid) {
	API = api;
	API.chat_id = chat_id;
	API.cbid = cbid;
	if (substr(data, 0, 3) !== 'zt:')
		return false;
	/* defense in depth: CB_MIN_PREFIX gates operator; re-check here */
	if (role_rank(API.role) < 2) {
		API.answer_cb(cbid, 'Нужна роль operator');
		API.log('strategies deny: role ' + API.role);
		return true;
	}
	if (data === 'zt:menu') {
		API.answer_cb(cbid, 'Стратегии');
		strategies_menu();
		return true;
	}
	if (substr(data, 0, 5) === 'zt:r:') {
		const rest = substr(data, 5);
		const parts = split(rest, ':');
		const key = (length(parts) > 0) ? ('' + parts[0]) : '';
		const page = (length(parts) > 1) ? int(parts[1]) : 0;
		API.answer_cb(cbid, 'Стратегии');
		strategies_card(key, page);
		return true;
	}
	if (substr(data, 0, 5) === 'zt:m:') {
		const parts = split(substr(data, 5), ':');
		if (length(parts) < 3) {
			API.answer_cb(cbid, 'Повреждённый токен');
			return true;
		}
		mark_act('' + parts[0], '' + parts[1], '' + parts[2]);
		return true;
	}
	API.answer_cb(cbid, '');
	return true;
};

export function handle_command(api, chat_id, cmd, rest) {
	API = api;
	API.chat_id = chat_id;
	if (cmd !== '/strategies' && cmd !== '!strategies')
		return false;
	if (role_rank(API.role) < 2) {
		API.send_html(chat_id, '⛔ Команда доступна с роли operator.');
		return true;
	}
	strategies_menu();
	return true;
};
