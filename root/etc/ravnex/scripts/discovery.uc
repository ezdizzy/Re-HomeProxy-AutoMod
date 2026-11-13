// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Discovery Engine (Ф6.2, план 20 §Ф6; аудит A.2/68, B5.1–B5.3).
//
// ЕДИНЫЙ источник обнаружения трафика для всей системы. До Ф6.2 движок
// автоматизации собирал кандидатов разрозненными функциями: conntrack видел
// ТОЛЬКО TCP/80+443 и брал dst= из ОБОИХ направлений строки (B5.1 — клиентские
// адреса съедали лимит), QUIC/STUN/игровой UDP были слепой зоной (68), IPv6
// выпадал молча (57/B5.2), а проверка «приватный ли адрес» покрывала часть
// реестра IANA (B5.3).
//
// Источники (все пассивные — НИ ОДНОЙ активной пробы, бюджеты урока 197):
//   conntrack  — TCP+UDP+прочее, ТОЛЬКО оригинальный tuple (B5.1), IPv4+IPv6
//                с явной пометкой (57/B5.2); UDP-классификация quic/stun;
//   clash-conn — Clash API /connections: host/destinationIP/сеть/outbound —
//                единственный источник пары IP↔hostname в реальном времени;
//   sni        — хвост событий sni_sniffer (TLS ClientHello, TCP/443);
//   state      — выученные записи автоматизации (host↔plain_ip) как
//                дополнительный словарь IP↔DNS.
//
// Бюджеты (68, B5.1–3): одна команда conntrack с жёстким лимитом строк,
// один curl к Clash API с таймаутом 3 с, хвост SNI-лога, итоговый снимок
// ограничен по размеру (top-N). CPU: < ~2 с; RAM: ограниченные списки;
// пробы: 0.
//
// Слепые зоны (честно, а не молча): QUIC Initial SNI не расшифровывается
// без внешнего парсера — QUIC-потоки классифицируются по UDP/443;
// ECH шифрует SNI и от TCP-хендшейков; Discord Voice/игровые релеи видны
// как «неопознанный UDP» (порты динамические); IPv6 в IP-learning
// исключён (B5.2) до поддержки — в снимке он показывается явно.
//
// Уроки учтены: 245 (export-функции через `};`), 246 (нет undefined —
// type()/null), 20/31 (for-in по массиву = элементы), 26/27 (match() только
// с /регулярками/), 2/93 (хелперы ВЫШЕ), 251 (индексные циклы — классические),
// 249 (push/sort/keys — глобальные), 254 (json() — глобальный билтин),
// 112 (system() с таймаутами), 197 (модуль НЕ делает активных проб).

'use strict';

import { access, readfile, stat, open, popen } from 'fs';
import { atomic_write, rjson } from '/etc/ravnex/scripts/statestore.uc';

/* ── Константы/бюджеты ── */

const RUN_DIR = '/var/run/ravnex';
export const DISCOVERY_SNAPSHOT = RUN_DIR + '/discovery.json';
const SNI_EVENTS = RUN_DIR + '/sni_events.jsonl';
const STATE_FILE = RUN_DIR + '/automation_state.json';

export const CT_MAX_LINES = 400;   /* строк conntrack за один сбор          */
export const CT_TOP_N = 24;        /* записей в таблице «топ направлений»   */
export const SNI_TAIL = 200;       /* хвост SNI-лога                        */
export const CLASH_TMO = 3;        /* таймаут Clash API, с                  */
export const MAP_MAX = 512;        /* предельный словарь IP↔DNS             */

/* STUN-порты (RFC 5389/8489 + публичные стуны): классификация UDP-потоков. */
export const STUN_PORTS = [ 3478, 3479, 5349, 19302, 19303 ];

/* ── Реестр IANA Special-Purpose (B5.3) — префиксный уровень точности ──
 * Столько, сколько даёт строковое сравнение префиксов: /8 и «первые октеты».
 * Покрывает: this-network, private, CGNAT (100.64/10!), loopback, link-local,
 * TEST-NET-1/2/3, benchmarking (198.18/15!), 6to4 relay, reserved/multicast. */
export const SPECIAL_V4 = [
	'0.', '10.', '100.64.', '100.65.', '100.66.', '100.67.', '100.68.',
	'100.69.', '100.70.', '100.71.', '100.72.', '100.73.', '100.74.',
	'100.75.', '100.76.', '100.77.', '100.78.', '100.79.', '100.80.',
	'100.81.', '100.82.', '100.83.', '100.84.', '100.85.', '100.86.',
	'100.87.', '100.88.', '100.89.', '100.90.', '100.91.', '100.92.',
	'100.93.', '100.94.', '100.95.', '100.96.', '100.97.', '100.98.',
	'100.99.', '100.100.', '100.101.', '100.102.', '100.103.',
	'100.104.', '100.105.', '100.106.', '100.107.', '100.108.',
	'100.109.', '100.110.', '100.111.', '100.112.', '100.113.',
	'100.114.', '100.115.', '100.116.', '100.117.', '100.118.',
	'100.119.', '100.120.', '100.121.', '100.122.', '100.123.',
	'100.124.', '100.125.', '100.126.', '100.127.',
	'127.', '169.254.', '172.16.', '172.17.', '172.18.', '172.19.',
	'172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
	'172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
	'192.0.0.', '192.0.2.', '192.88.99.', '192.168.',
	'198.18.', '198.19.', '198.51.100.', '203.0.113.',
	'224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.',
	'232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.',
	'240.', '241.', '242.', '243.', '244.', '245.', '246.', '247.',
	'248.', '249.', '250.', '251.', '252.', '253.', '254.', '255.'
];

export const SPECIAL_V6 = [
	'::', '2001:db8:', 'fc00:', 'fc01:', 'fc02:', 'fc03:', 'fc04:', 'fc05:',
	'fc06:', 'fc07:', 'fc08:', 'fc09:', 'fc0a:', 'fc0b:', 'fc0c:', 'fc0d:',
	'fc0e:', 'fc0f:', 'fd', 'fe80:', 'fe81:', 'fe82:', 'fe83:', 'fe84:',
	'fe85:', 'fe86:', 'fe87:', 'fe88:', 'fe89:', 'fe8a:', 'fe8b:', 'fe8c:',
	'fe8d:', 'fe8e:', 'fe8f:', 'fe9', 'fea', 'feb', 'ff0', 'ff1', 'ff2',
	'ff3', 'ff4', 'ff5', 'ff6', 'ff7', 'ff8', 'ff9', 'ffa', 'ffb', 'ffc',
	'ffd', 'ffe', 'fff'
];

/* ── Хелперы (выше вызывающих — no hoisting) ── */

export function ip_version(ip) {
	const s = trim('' + (ip || ''));
	if (!length(s))
		return null;
	if (match(s, /^\d{1,3}(\.\d{1,3}){3}$/))
		return 'v4';
	if (index(s, ':') >= 0)
		return 'v6';
	return null;
};

/* Специальный (не публично-маршрутизируемый) адрес по реестру IANA.
 * Надмножество прежней is_private_ip: добавлены CGNAT 100.64/10,
 * benchmarking 198.18/15, TEST-NET, 6to4 relay, зарезервированные. */
export function is_special_ip(ip) {
	const s = trim('' + (ip || ''));
	if (!length(s))
		return true;   /* пустое/непонятное — не кандидат */
	const v = ip_version(s);
	if (v === 'v4') {
		for (let p in SPECIAL_V4)
			if (substr(s, 0, length(p)) === p)
				return true;
		return false;
	}
	if (v === 'v6') {
		const l = lc(s);
		if (l === '::' || l === '::1')
			return true;
		for (let p in SPECIAL_V6)
			if (substr(l, 0, length(p)) === p)
				return true;
		return false;
	}
	return true;
};

/* UDP-классификация потока: 'quic' (UDP/443 — QUIC/HTTP3), 'stun'
 * (известные STUN-порты), 'other' (игры/Voice-релеи/прочее). */
export function udp_kind(dport) {
	const p = int(dport) || 0;
	if (p === 443)
		return 'quic';
	for (let s in STUN_PORTS)
		if (s === p)
			return 'stun';
	return 'other';
};

/* ── Парсер строки conntrack: ТОЛЬКО оригинальный tuple (B5.1) ──
 * ДВА формата (единый парсер):
 *   conntrack -L:  `tcp 6 431999 ESTABLISHED src=.. dst=.. sport=.. dport=..
 *                   [UNREPLIED] src=.. dst=.. sport=.. dport=..`
 *   /proc/net/nf_conntrack: `ipv4 2 udp 17 42 src=.. dst=.. sport=.. dport=..
 *                   packets=.. bytes=.. src=.. dst=.. sport=.. dport=..`
 * Первый src=/dst=/sport=/dport= — оригинальное направление (клиент→цель);
 * вторая пара — REPLY (цель→клиент). Старый awk брал ВСЕ dst= — в список
 * попадали адреса самих клиентов. Здесь берём только первые вхождения,
 * отсчитывая от ПЕРВОГО src= (proc-формат не имеет постоянного префикса). */
export function parse_conntrack_line(line) {
	const l = trim('' + (line || ''));
	if (!length(l))
		return null;
	const parts = split(l, /[[:space:]]+/);
	if (length(parts) < 4)
		return null;
	let proto = null;
	for (let i = 0; i < length(parts) && i < 6; i++) {
		const p = lc(parts[i]);
		if (p === 'tcp' || p === 'udp' || p === 'sctp' || p === 'dccp') {
			proto = p;
			break;
		}
	}
	if (proto == null)
		return null;
	let start = -1;
	for (let i = 0; i < length(parts); i++)
		if (substr(parts[i], 0, 4) === 'src=') {
			start = i;
			break;
		}
	if (start < 0)
		return null;
	let src = null, dst = null, sport = null, dport = null;
	for (let i = start; i < length(parts); i++) {
		const f = parts[i];
		if (src == null && substr(f, 0, 4) === 'src=')
			src = substr(f, 4);
		else if (dst == null && substr(f, 0, 4) === 'dst=')
			dst = substr(f, 4);
		else if (sport == null && substr(f, 0, 6) === 'sport=')
			sport = substr(f, 6);
		else if (dport == null && substr(f, 0, 6) === 'dport=')
			dport = substr(f, 6);
	}
	if (dst == null || dport == null)
		return null;
	const v = ip_version(dst);
	if (v == null)
		return null;
	return { proto: proto, src: src, dst: dst, sport: (sport != null) ? int(sport) : 0,
		dport: int(dport), v6: (v === 'v6'), udp_kind: (proto === 'udp') ? udp_kind(dport) : null };
};

/* ── Сбор: conntrack ──
 * 🔴 НАЙДЕНО ЖИВЬЁМ (приёмка Ф6.2): на этом роутере НЕТ бинаря conntrack —
 * старый `conntrack -L` автоматизации молча возвращал пустоту, и источник
 * IP-обучения фактически не работал. Основной источник — /proc/net/nf_conntrack
 * (тот же формат, читается построчно); бинарь — только фолбэк. Лимит строк —
 * бюджет CPU. */
export function conntrack_flows(max_lines) {
	const cap = (int(max_lines) > 0) ? int(max_lines) : CT_MAX_LINES;
	const flows = [];
	if (access('/proc/net/nf_conntrack')) {
		const fd = open('/proc/net/nf_conntrack', 'r');
		if (fd) {
			for (let line = fd.read('line'); length(line); line = fd.read('line')) {
				if (length(flows) >= cap)
					break;
				const f = parse_conntrack_line(line);
				if (f != null)
					push(flows, f);
			}
			fd.close();
			if (length(flows) > 0)
				return flows;
		}
	}
	const fd2 = popen(`conntrack -L 2>/dev/null | head -n ${cap}`);
	if (!fd2)
		return [];
	for (let line = fd2.read('line'); length(line); line = fd2.read('line')) {
		if (length(flows) >= cap)
			break;
		const f = parse_conntrack_line(line);
		if (f != null)
			push(flows, f);
	}
	fd2.close();
	return flows;
};

/* ── Сбор: Clash API /connections (метаданные живых соединений) ──
 * БЕЗ фильтра по outbound — Discovery показывает ВСЁ (фильтрация — дело
 * потребителя); метаданные дают пару host↔destinationIP и тип сети. */
export function clash_conns(timeout_s) {
	const tmo = (int(timeout_s) > 0) ? int(timeout_s) : CLASH_TMO;
	const fd = popen(`curl -s --max-time ${tmo} http://127.0.0.1:9090/connections 2>/dev/null`);
	let raw = '';
	if (fd) {
		raw = fd.read('all') || '';
		fd.close();
	}
	if (!length(raw))
		return [];
	let data = null;
	try { data = json(raw); } catch (e) { data = null; }
	if (data == null || type(data.connections) !== 'array')
		return [];
	const out = [];
	for (let c in data.connections) {
		const m = c.metadata;
		if (type(m) !== 'object')
			continue;
		let host = trim('' + (m.host || ''));
		if (!length(host) || match(host, /^[0-9.]+$/) || index(host, ':') >= 0)
			host = trim('' + (m.destinationIP || ''));
		push(out, {
			host: host,
			dip: trim('' + (m.destinationIP || '')),
			network: trim('' + (m.network || 'tcp')),
			outbound: trim('' + (m.outbound || '')),
			dst_port: int(m.destinationPort) || 0
		});
	}
	return out;
};

/* ── Сбор: хвост SNI-лога (только чтение; состояние офсета живёт у
 * automation.uc — здесь независимый читатель хвоста, append-only файл) ── */
export function sni_hosts_tail(n) {
	const cap = (int(n) > 0) ? int(n) : SNI_TAIL;
	if (!access(SNI_EVENTS))
		return [];
	let sz = 0;
	try { sz = stat(SNI_EVENTS).size || 0; } catch (e) { return []; }
	if (!sz)
		return [];
	const from = (sz > 65536) ? (sz - 65536) : 0;
	const fd = open(SNI_EVENTS, 'r');
	if (!fd)
		return [];
	if (from > 0)
		fd.seek(from);
	const hosts = [];
	let skip_first = (from > 0);   /* обрезанная середина строки */
	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		if (skip_first) { skip_first = false; continue; }
		line = trim(line);
		if (!length(line))
			continue;
		let evt = null;
		try { evt = json(line); } catch (e) { continue; }
		if (type(evt) !== 'object' || !evt.host)
			continue;
		const h = lc(trim('' + evt.host));
		if (length(h) && index(h, '.') > 0)
			push(hosts, h);
	}
	fd.close();
	/* последние cap записей */
	const out = [];
	const start = (length(hosts) > cap) ? (length(hosts) - cap) : 0;
	for (let i = start; i < length(hosts); i++)
		push(out, hosts[i]);
	return out;
};

/* ── Словари IP↔DNS ──
 * 1) пары из Clash-соединений (host ≠ dip, host не IP-литерал);
 * 2) выученные записи автоматизации (host ↔ plain_ip). */
export function dns_pair_map(conns, max_pairs) {
	const cap = (int(max_pairs) > 0) ? int(max_pairs) : MAP_MAX;
	const map = {};
	let n = 0;
	for (let c in (conns || [])) {
		if (n >= cap)
			break;
		const host = lc(trim('' + (c.host || '')));
		const dip = trim('' + (c.dip || ''));
		if (!length(host) || !length(dip) || host === dip)
			continue;
		if (ip_version(host) != null)
			continue;   /* host сам IP-литерал — пары нет */
		if (map[dip] == null) {
			map[dip] = host;
			n++;
		}
	}
	return map;
};

export function state_ip_map(max_entries) {
	const cap = (int(max_entries) > 0) ? int(max_entries) : MAP_MAX;
	const st = rjson(STATE_FILE);
	const map = {};
	let n = 0;
	if (st != null && type(st) === 'object') {
		for (let host in st) {
			if (n >= cap)
				break;
			const e = st[host];
			if (type(e) !== 'object')
				continue;
			const pip = trim('' + (e.plain_ip || ''));
			const h = lc(trim(host));
			if (!length(pip) || !length(h) || ip_version(h) != null)
				continue;
			if (map[pip] == null) {
				map[pip] = h;
				n++;
			}
		}
	}
	return map;
};

/* s200: полное состояние движка (кэш на процесс) — QUIC-факты для
 * диагностических evidence (diag_core facts.d.quic). Мягкий отказ:
 * файла нет / битый JSON = {} (честное «не измерено», никогда не крэш). */
let _eng_state_cache = null;
export function engine_state() {
	if (_eng_state_cache != null)
		return _eng_state_cache;
	_eng_state_cache = {};
	const st = rjson(STATE_FILE);
	if (st != null && type(st) === 'object')
		_eng_state_cache = st;
	return _eng_state_cache;
};

/* ── Снимок (сборка; запись файла — у вызывающего через write_snapshot) ── */
export function snapshot() {
	const flows = conntrack_flows(CT_MAX_LINES);
	const conns = clash_conns(CLASH_TMO);
	const sni = sni_hosts_tail(SNI_TAIL);

	/* Словарь IP↔DNS: пары из Clash + выученные записи (без перезаписи). */
	const map = {};
	let n_clash_pairs = 0;
	for (let c in conns) {
		const host = lc(trim('' + (c.host || '')));
		const dip = trim('' + (c.dip || ''));
		if (!length(host) || !length(dip) || host === dip || ip_version(host) != null)
			continue;
		if (map[dip] == null) {
			map[dip] = host;
			n_clash_pairs++;
			if (n_clash_pairs >= MAP_MAX)
				break;
		}
	}
	let n_state_pairs = 0;
	const smap = state_ip_map(MAP_MAX);
	for (let ip in smap) {
		if (map[ip] == null) {
			map[ip] = smap[ip];
			n_state_pairs++;
		}
	}

	/* Агрегация направлений: публичные адреса назначения, локальные
	 * (специальные по IANA) считаются отдельно и в таблицу не идут. */
	const counts = { flows: length(flows), v4: 0, v6: 0, tcp: 0, udp: 0,
		udp_quic: 0, udp_stun: 0, udp_other: 0, local: 0 };
	const agg = {};
	for (let f in flows) {
		if (f.v6)
			counts.v6++;
		else
			counts.v4++;
		if (f.proto === 'udp') {
			counts.udp++;
			if (f.udp_kind === 'quic') counts.udp_quic++;
			else if (f.udp_kind === 'stun') counts.udp_stun++;
			else counts.udp_other++;
		} else if (f.proto === 'tcp') {
			counts.tcp++;
		}
		if (is_special_ip(f.dst)) {
			counts.local++;
			continue;
		}
		const k = f.dst + '|' + f.proto;
		if (agg[k] == null)
			agg[k] = { ip: f.dst, proto: f.proto, hits: 0, dport: f.dport, udp_kind: f.udp_kind };
		agg[k].hits++;
	}

	/* Топ направлений по числу потоков (сортировка копии массива). */
	const list = [];
	for (let k in agg)
		push(list, agg[k]);
	sort(list, (a, b) => (b.hits - a.hits));
	const top = [];
	for (let i = 0; i < length(list) && i < CT_TOP_N; i++) {
		const e = list[i];
		push(top, {
			ip: e.ip, proto: e.proto, hits: e.hits, dport: e.dport,
			v6: (ip_version(e.ip) === 'v6'),
			udp_kind: e.udp_kind,
			host: (map[e.ip] != null) ? map[e.ip] : null
		});
	}

	/* Уникальные SNI-хосты (хвост уже ограничен). */
	const sni_u = {};
	for (let h in sni)
		sni_u[h] = true;
	const sni_top = [];
	for (let h in keys(sni_u)) {
		push(sni_top, h);
		if (length(sni_top) >= 16)
			break;
	}

	/* Clash: сколько соединений/UDP, какие outbound'ы задействованы. */
	const ob = {};
	let c_udp = 0;
	for (let c in conns) {
		if (c.network === 'udp')
			c_udp++;
		if (length(c.outbound))
			ob[c.outbound] = (int(ob[c.outbound]) || 0) + 1;
	}

	return {
		ts: time(),
		counts: counts,
		top: top,
		sni: sni_top,
		clash: { conns: length(conns), udp: c_udp, outbounds: ob },
		maps: { clash_pairs: n_clash_pairs, state_pairs: n_state_pairs },
		budgets: { conntrack_lines: CT_MAX_LINES, clash_timeout_s: CLASH_TMO,
			sni_tail: SNI_TAIL, probes_used: 0 },
		blind_zones: [
			'QUIC Initial SNI не расшифровывается без внешнего парсера — QUIC-потоки классифицированы по UDP/443',
			'ECH (Encrypted ClientHello) скрывает SNI и от TCP-хендшейков',
			'Discord Voice и игровые релеи видны как неопознанный UDP (порты динамические)',
			'IPv6-потоки показаны, но в IP-learning исключены (B5.2) до явной поддержки'
		]
	};
};

/* Атомарная запись снимка (RPC и демоны зовут это). */
export function write_snapshot() {
	const snap = snapshot();
	atomic_write(DISCOVERY_SNAPSHOT, sprintf('%.J', snap) + '\n');
	return snap;
};

/* ── Selftest (чистые классификаторы — парсер, UDP-классы, реестр IANA) ── */
export function selftest() {
	const pass = [];
	const fail = [];
	const t = (name, cond) => {
		if (cond)
			push(pass, name);
		else
			push(fail, name);
	};

	/* ip_version */
	t('ipv4 detect', ip_version('1.2.3.4') === 'v4');
	t('ipv6 detect', ip_version('2001:db8::1') === 'v6');
	t('junk null', ip_version('nonsense') == null && ip_version('') == null);

	/* is_special_ip (B5.3): IANA-реестр */
	t('rfc1918 private', is_special_ip('192.168.1.50') === true);
	t('cgnat private (B5.3)', is_special_ip('100.100.5.5') === true);
	t('benchmarking private (B5.3)', is_special_ip('198.18.0.7') === true);
	t('testnet private', is_special_ip('192.0.2.9') === true);
	t('multicast private', is_special_ip('224.0.0.251') === true);
	t('public not special', is_special_ip('142.250.74.14') === false);
	t('public cdn not special', is_special_ip('104.16.1.1') === false);
	t('v6 fc private', is_special_ip('fd12:3456::1') === true);
	t('v6 link local', is_special_ip('fe80::1') === true);
	t('v6 public not special', is_special_ip('2606:4700::6810:1') === false);
	t('empty special', is_special_ip('') === true);

	/* udp_kind */
	t('quic 443', udp_kind(443) === 'quic');
	t('stun 19302', udp_kind(19302) === 'stun');
	t('stun 3478', udp_kind('3478') === 'stun');
	t('udp other', udp_kind(51820) === 'other');

	/* parse_conntrack_line: оригинальный tuple (B5.1) — формат conntrack -L */
	let f = parse_conntrack_line('tcp 6 431999 ESTABLISHED src=192.168.1.50 dst=142.250.1.14 sport=51734 dport=443 [UNREPLIED] src=142.250.1.14 dst=192.168.1.50 sport=443 dport=51734 mark=0 use=1');
	t('ct original dst (B5.1)', f != null && f.dst === '142.250.1.14' && f.src === '192.168.1.50' && f.dport === 443 && f.proto === 'tcp' && f.v6 === false);
	/* формат /proc/net/nf_conntrack (без бинаря conntrack — найдено живьём) */
	f = parse_conntrack_line('ipv4 2 udp 17 42 src=185.199.9.108 dst=212.118.52.103 sport=60126 dport=56835 packets=23 bytes=10903 src=212.118.52.103 dst=185.199.9.108 sport=56835 dport=60126 packets=15 bytes=15967 mark=0 zone=0 use=2');
	t('ct proc format udp', f != null && f.proto === 'udp' && f.dst === '212.118.52.103' && f.dport === 56835 && f.src === '185.199.9.108');
	f = parse_conntrack_line('ipv4 2 tcp 6 7295 ESTABLISHED src=192.168.1.150 dst=91.105.192.100 sport=51998 dport=443 packets=73 bytes=6303 src=192.168.1.1 dst=192.168.1.150 sport=5331 dport=51998 packets=56 bytes=359270 [ASSURED] mark=0 zone=0 use=2');
	t('ct proc format tcp 443', f != null && f.proto === 'tcp' && f.dport === 443 && f.dst === '91.105.192.100' && is_special_ip(f.src) === true);
	f = parse_conntrack_line('ipv6 10 udp 17 29 src=fd00::5 dst=2606:4700::6810:1 sport=40000 dport=443 src=2606:4700::6810:1 dst=fd00::5 sport=443 dport=40000');
	t('ct proc ipv6 quic (57)', f != null && f.v6 === true && f.udp_kind === 'quic');
	f = parse_conntrack_line('udp 17 29 src=192.168.1.50 dst=8.8.8.8 sport=53121 dport=443 [UNREPLIED] src=8.8.8.8 dst=192.168.1.50 sport=443 dport=53121');
	t('ct udp quic kind', f != null && f.proto === 'udp' && f.udp_kind === 'quic' && f.dst === '8.8.8.8');
	f = parse_conntrack_line('udp 17 120 src=192.168.1.50 dst=74.125.250.129 sport=50000 dport=19302 [UNREPLIED] src=74.125.250.129 dst=192.168.1.50 sport=19302 dport=50000');
	t('ct udp stun kind', f != null && f.udp_kind === 'stun');
	f = parse_conntrack_line('tcp 6 119 ESTABLISHED src=fd00::5 dst=2606:4700::6810:1 sport=40000 dport=443 [ASSURED] src=2606:4700::6810:1 dst=fd00::5 sport=443 dport=40000');
	t('ct ipv6 explicit (57)', f != null && f.v6 === true && f.dst === '2606:4700::6810:1');
	f = parse_conntrack_line('tcp 6 TIME_WAIT src=10.0.0.2 dst=10.0.0.1 sport=1234 dport=53');
	t('ct local counted not parsed as public', f != null && is_special_ip(f.dst) === true);
	t('ct junk null', parse_conntrack_line('garbage line here') == null && parse_conntrack_line('') == null);
	f = parse_conntrack_line('tcp 6 99 SYN_SENT src=192.168.1.7 dst=1.1.1.1 sport=999 dport=853');
	t('ct dport 853 tcp other', f != null && f.dport === 853 && f.udp_kind == null);

	/* Агрегация/маппинг: чистые функции выше — здесь словарная логика. */
	const pairs = dns_pair_map([
		{ host: 'www.youtube.com', dip: '142.250.1.14', network: 'tcp', outbound: 'direct-out' },
		{ host: '142.250.1.14', dip: '142.250.1.14', network: 'tcp', outbound: 'x' },
		{ host: '', dip: '1.2.3.4', network: 'udp', outbound: 'x' }
	], 512);
	t('pair map skips literal host', pairs['142.250.1.14'] === 'www.youtube.com' && pairs['1.2.3.4'] == null);

	return { pass: length(pass), fail: length(fail), details: fail };
};
