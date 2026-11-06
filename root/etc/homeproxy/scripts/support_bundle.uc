#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * support_bundle.uc — сборщик приватно-безопасного отчёта для поддержки (Р4).
 *
 * Один источник диагностики для UI («Проверка и ремонт» → «Отчёт для поддержки»),
 * Telegram (/logs) и issue на GitHub. По модели support_bundle.uc tachyon
 * (16-RESEARCH_TACHYON §3), адаптировано под наши демоны/стейты/секреты.
 *
 * Артефакт (всё с редакцией секретов, плоский стейдж → tar.gz в /tmp):
 *   metadata.json             — время, версии (приложение/ядро), OpenWrt, arch,
 *                               uptime, mem, df, load
 *   service_status.json       — инстансы procd (running/pid/respawn), sanitized
 *                               секция config (main_node, режим, стратегии, флаги)
 *   config_<name>.txt         — UCI (homeproxy/homecontrol/network/firewall/
 *                               dhcp/wireless) с отредактированными секретами
 *   config_hiddify_c.json     — сгенерированный конфиг ядра через redact_object
 *   state_*.json / .txt       — multidns_state, automation_state/stats,
 *                               zapret_autopilot, hotswap_state, urltest_dead,
 *                               core_skipped — только sanitized-версии
 *   net_*.txt                 — ip addr/route/rule, nft fw4, conntrack summary
 *   log_*.txt + logs_sizes.json + daemons.json — logread tail 500 (redact),
 *                               хвосты собственных журналов + размеры,
 *                               RSS/fd демонов (ключевое для «зависаний»)
 *   checksums.sha256
 *
 * Редакция секретов: UCI-опции по имени (password/uuid/private_key/psk/token/
 * url/chat_id/...), JSON-ключи рекурсивно (redact_object), строковые регэкспы
 * (TG-токен, Bearer, user:pass@, share-ссылки vless/trojan/hysteria2/ss/...,
 * секреты в query). ОБЯЗАТЕЛЬНЫЙ selftest: реальные секреты из UCI собираются
 * ДО сборки и после сборки каждый стейдж-файл проверяется на их ОТСУТСТВИЕ —
 * утечка помечает бандл битым (ok:false, архив не создаётся).
 *
 * CLI:
 *   ucode support_bundle.uc build      — полный бандл (tar.gz) + selftest
 *   ucode support_bundle.uc selftest   — сборка стейджа без tar + печать проверок
 *   ucode support_bundle.uc text       — быстрый текст-отчёт в stdout
 *
 * Статус: /tmp/ravnex_bundle_meta.json (атомарно, tmp+rename), polled RPC.
 * Уроки: ucode БЕЗ hoisting (ч.118) — функции строго сверху вниз;
 * fs.stat без st_-префикса (ч.75); for-in по массиву = элементы (урок 20);
 * POSIX ERE без \b и без (?:) — только базовый синтаксис; атомарная запись
 * стейтов (tmp+rename).
 */

'use strict';

import { access, popen, readfile, writefile, stat, rename, mkdir } from 'fs';
import { cursor } from 'uci';
import {
	scan_registry as pm_scan, entry_alive as pm_entry_alive,
	reg_get as pm_reg_get, find_daemons as pm_find
} from '/etc/homeproxy/scripts/pmgr.uc';

const RUN_DIR = '/var/run/homeproxy';
const STAGE_BASE = '/tmp/ravnex_bundle';
const META_FILE = '/tmp/ravnex_bundle_meta.json';
const TEXT_LOG_TAIL = 500;      /* logread tail in the bundle */
const APP_TAIL = 200;           /* own app logs tail in the bundle */

/* Имена UCI-опций/JSON-ключей, значение которых секрет (ЕДИНЫЙ список для
 * редакции И для сбора проверок selftest — редакция обязана быть надмножеством
 * сборки, иначе selftest бессмыслен). URL — только как отдельное слово
 * ('subscription_url', JSON-ключ 'url'), НЕ 'urltest_*' (main_urltest_mode =
 * 'prefer' — не секрет, выучено selftest'ом ч.142). */
const SECRET_KEY_RE = /(^|_)url($|_)|pass|psk|secret|uuid|private|token|key|auth|link|chat_id|user|login|obfs|short_id/i;

/* Реальные значения секретов из UCI (заполняет collect_secret_values ПЕРЕД
 * сборкой): value-based редакция — вторая линия поверх редакции по имени,
 * убивает эхо в журналах (subscription URL в сервисном логе, chat_id в логе
 * бота), где по имени секрета опции уже не видно. Значение НЕ заносится в
 * артефакт нигде — только в память процесса. */
let SECRETS = [];

/* ── примитивы (строго ДО первых вызовов — ucode без hoisting) ─────────── */

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

function now_str() {
	/* Standalone ucode не экспортирует strftime — дата через date(1). */
	return trim(capture('date "+%Y-%m-%d %H:%M:%S %Z" 2>/dev/null'));
}

function ts14() {
	/* Формат 20260101-123456 — как снапшоты приложения. */
	return trim(capture('date +%Y%m%d-%H%M%S 2>/dev/null'));
}

function fsize(path) {
	const st = stat(path);
	return st ? st.size : 0;
}

function watomic(path, content) {
	const tmp = path + '.tmp';
	writefile(tmp, content);
	rename(tmp, path);
}

function first_line(s) {
	const l = split('' + s, '\n');
	return (length(l) && length(trim(l[0]))) ? trim(l[0]) : null;
}

function read_json_safe(path) {
	if (!access(path)) return null;
	let doc = null;
	try { doc = json(readfile(path) || ''); } catch (e) { doc = null; }
	return doc;
}

function app_version() {
	let av = null;
	if (access('/usr/bin/apk') || access('/sbin/apk') || access('/usr/sbin/apk')) {
		const m = match(trim(capture('apk info luci-app-re-homeproxy 2>/dev/null | head -1')),
			/luci-app-re-homeproxy-([0-9][0-9.]*)/);
		if (m) av = m[1];
	}
	return av;
}

/* ── редакция секретов ─────────────────────────────────────────────────── */

/* Строковые регэкспы поверх ЛЮБОГО текста (логи/стейты/конфиги).
 * POSIX ERE: без \b, без lazy, классы [[:space:]]; replace с регэкспом меняет
 * ВСЕ вхождения. Порядок важен: share-ссылки — первыми (внутри них и
 * user:pass@, и токены). */
function redact_line(s) {
	s = '' + s;
	/* share-ссылки целиком (uuid/ключи внутри ссылки) */
	s = replace(s, /(vless|trojan|hysteria2?|tuic|vmess|ssr?|socks5?):\/\/[^[:space:]"'<>]+/, '[REDACTED-LINK]');
	/* user:pass@ в любых URL (класс без @ — жадность не переползёт через @) */
	s = replace(s, /\/\/[^@[:space:]"'<>]{4,}@/, '//[REDACTED]@');
	/* Bearer-токены */
	s = replace(s, /([Bb]earer)[ \t]+[A-Za-z0-9._~+\/=-]{10,}/, 'Bearer [REDACTED]');
	/* Telegram bot token: <цифры>:<хэш 30+> */
	s = replace(s, /[0-9]{5,12}:[A-Za-z0-9_-]{30,}/, '[REDACTED-TOKEN]');
	/* секреты в query (?token=... / &key=... / ?auth=...) */
	s = replace(s, /[?&](token|key|secret|auth|password|apikey|api_key|access_token|sign)=[^&[:space:]"'<>]+/, '?[REDACTED]');
	/* пароли/токены в логах вида password=... / password: ... / token=... */
	s = replace(s, /([Pp]ass(word)?|[Pp]sk|[Tt]oken|[Ss]ecret|[Aa]uth)[=:][ \t]*[^[:space:]"'<>]{4,}/, '[REDACTED]');
	/* value-based: реальные секреты UCI в любом вместилище (join/split —
	 * replace-по-строке в ucode меняет только ПЕРВОЕ вхождение). */
	for (let sec in SECRETS) {
		if (length(sec) < 6)
			continue;
		if (index(s, sec) >= 0)
			s = join('[REDACTED]', split(s, sec));
	}
	return s;
}

/* UCI-конфиг текстом: значение опции с секретным именем → '[REDACTED]'.
 * Формат: option name 'value' | list name 'value' | option name value.
 * Пустые значения не трогаем (утечки нет). Группы match(): [0]=всё, [1..] —
 * группы; в ucode match возвращает полный матч в [0]. */
function redact_uci_text(text) {
	let out = [];
	for (let line in split('' + text, /[\r\n]/)) {
		let m = match(line, /^([[:space:]]*(option|list)[[:space:]]+)([A-Za-z0-9_]+)([[:space:]]+)(.+)$/);
		if (m) {
			if (match(m[3], SECRET_KEY_RE) && length(trim(m[5])))
				push(out, m[1] + m[3] + ' [REDACTED]');
			else
				push(out, redact_line(line));
			continue;
		}
		m = match(line, /^([[:space:]]*(option|list)[[:space:]]+)([A-Za-z0-9_]+)$/);
		if (m) {
			/* опция без значения — секрета нет */
			push(out, line);
			continue;
		}
		push(out, redact_line(line));
	}
	return join('\n', out) + '\n';
}

/* Рекурсивная редакция разобранного JSON: секретный ключ → '[REDACTED]',
 * вложенные структуры — обход, строки — redact_line. */
function redact_object(obj) {
	if (type(obj) === 'object') {
		const out = {};
		for (let k in obj) {
			if (match('' + k, SECRET_KEY_RE))
				out[k] = '[REDACTED]';
			else
				out[k] = redact_object(obj[k]);
		}
		return out;
	}
	if (type(obj) === 'array') {
		const out = [];
		for (let v in obj)
			push(out, redact_object(v));
		return out;
	}
	if (type(obj) === 'string')
		return redact_line(obj);
	return obj;
}

/* Многострочный текст → построчный redact_line (ip/nft/логи — не JSON). */
function redact_text_blob(text) {
	let out = [];
	for (let line in split('' + text, /[\r\n]/))
		push(out, redact_line(line));
	return join('\n', out) + '\n';
}

/* Любой файл → sanitized-текст: если это валидный JSON — redact_object,
 * иначе построчный redact_line. */
function sanitize_content(text) {
	let doc = null;
	try { doc = json('' + text); } catch (e) { doc = null; }
	if (doc !== null && (type(doc) === 'object' || type(doc) === 'array'))
		return sprintf('%.J', redact_object(doc)) + '\n';
	return redact_text_blob(text);
}

/* ── сбор реальных секретов для selftest (ДО сборки бандла) ────────────── */

function collect_secret_values() {
	/* Значения (строки ≥6 символов) всех секретных опций homeproxy +
	 * homecontrol из committed UCI. index()-поиск — не регэксп, спецсимволы
	 * значения безопасны. Одновременно наполняет SECRETS для value-based
	 * редакции (redact_line). */
	const vals = [];
	const seen = {};
	SECRETS = [];   /* идемпотентно: вызов может повторяться (build + selftest) */
	const uc = cursor();
	const configs = ['homeproxy', 'homecontrol'];
	for (let cfg in configs) {
		let sections = null;
		try { sections = uc.get_all(cfg); } catch (e) { sections = null; }
		if (sections == null || type(sections) !== 'object')
			continue;
		for (let sid in sections) {
			const sec = sections[sid];
			if (type(sec) !== 'object')
				continue;
			for (let opt in sec) {
				if (substr(opt, 0, 1) === '.')
					continue;
				if (!match('' + opt, SECRET_KEY_RE))
					continue;
				const v = sec[opt];
				const strs = (type(v) === 'array') ? v : [v];
				for (let x in strs) {
					const s = '' + x;
					if (length(s) >= 6 && !seen[s]) { seen[s] = 1; push(vals, s); push(SECRETS, s); }
				}
			}
		}
	}
	return vals;
}

/* ── builders стейджа ──────────────────────────────────────────────────── */

function dfrow(mp) {
	const raw = trim(capture(`df -h ${shellquote(mp)} 2>/dev/null | tail -n 1`));
	const m = match(raw, / +([0-9.]+[KMGT]?) +([0-9.]+[KMGT]?) +([0-9.]+[KMGT]?) +[0-9]+% +(.+)$/);
	return (m) ? { total: m[1], used: m[2], avail: m[3], on: m[4] } : null;
}

function build_metadata(stage) {
	const mem = {};
	for (let line in split(readfile('/proc/meminfo') || '', '\n')) {
		const m = match(trim(line), /^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):[ \t]+([0-9]+)/);
		if (m) mem[m[1]] = int(m[2]);
	}
	let upt = null;
	const um = match(trim(readfile('/proc/uptime') || ''), /^([0-9]+)/);
	if (um) upt = int(um[1]);
	let load = null;
	const lm = match(trim(readfile('/proc/loadavg') || ''), /^([0-9.]+) +([0-9.]+) +([0-9.]+)/);
	if (lm) load = { load1: lm[1], load5: lm[2], load15: lm[3] };

	const meta = {
		generated: now_str(),
		app: app_version(),
		openwrt: trim(readfile('/etc/openwrt_release') || ''),
		uname: trim(capture('uname -a 2>/dev/null')),
		uptime_s: upt,
		load: load,
		mem_kb: mem,
		df: { root: dfrow('/'), tmp: dfrow('/tmp') },
		core_version_cache: read_json_safe(RUN_DIR + '/core_versions.json') || {},
		engines: {
			mosdns_version: first_line(capture('mosdns version 2>/dev/null')),
			nfqws2_bin: !!access('/opt/zapret2/nfq2/nfqws2'),
			ciadpi_bin: !!access('/usr/bin/ciadpi')
		}
	};
	writefile(stage + '/metadata.json', sprintf('%.J', meta) + '\n');
}

function build_service_status(stage) {
	/* Только инстансы службы homeproxy из ubus service list + sanitized
	 * секция config (main_node/режим/стратегии/флаги). */
	let svc = null;
	try { svc = json(capture('ubus call service list 2>/dev/null')); } catch (e) { svc = null; }
	let instances = {};
	if (svc && type(svc) === 'object' && svc.homeproxy && type(svc.homeproxy.instances) === 'object')
		instances = svc.homeproxy.instances;

	let cfgsec = {};
	const uc = cursor();
	try { cfgsec = uc.get_all('homeproxy', 'config'); } catch (e) { cfgsec = {}; }

	const doc = {
		generated: now_str(),
		instances: redact_object(instances),
		config: redact_object(cfgsec)
	};
	writefile(stage + '/service_status.json', sprintf('%.J', doc) + '\n');
}

function build_configs(stage) {
	/* UCI-конфиги текстом + сгенерированный конфиг ядра, всё sanitized. */
	const uci_files = [
		['homeproxy', 'config_homeproxy.txt'],
		['homecontrol', 'config_homecontrol.txt'],
		['network', 'config_network.txt'],
		['firewall', 'config_firewall.txt'],
		['dhcp', 'config_dhcp.txt'],
		['wireless', 'config_wireless.txt']
	];
	for (let f in uci_files) {
		const raw = capture(`cat /etc/config/${shellquote(f[0])} 2>/dev/null`);
		writefile(stage + '/' + f[1], length(trim(raw)) ? redact_uci_text(raw) : '(absent)\n');
	}
	const hc = read_json_safe(RUN_DIR + '/hiddify-c.json');
	writefile(stage + '/config_hiddify_c.json',
		hc ? (sprintf('%.J', redact_object(hc)) + '\n') : '(absent)\n');
	const hlg = read_json_safe(RUN_DIR + '/hiddify-c.json.lastgood');
	if (hlg)
		writefile(stage + '/config_hiddify_c_lastgood.json', sprintf('%.J', redact_object(hlg)) + '\n');
}

function build_states(stage) {
	const states = [
		[RUN_DIR + '/automation_state.json', 'state_automation.json'],
		[RUN_DIR + '/automation_stats.json', 'state_automation_stats.json'],
		[RUN_DIR + '/zapret_autopilot.json', 'state_zapret_autopilot.json'],
		[RUN_DIR + '/zapret_autopilot_manual.json', 'state_zapret_autopilot_manual.json'],
		[RUN_DIR + '/hotswap_state.json', 'state_hotswap.json'],
		[RUN_DIR + '/hotswap.json', 'state_hotswap_core.json'],
		[RUN_DIR + '/urltest_dead', 'state_urltest_dead.txt'],
		[RUN_DIR + '/core_skipped.json', 'state_core_skipped.json'],
		[RUN_DIR + '/multidns/multidns_state.json', 'state_multidns.json']
	];
	let written = 0;
	for (let s in states) {
		if (!access(s[0]))
			continue;
		writefile(stage + '/' + s[1], sanitize_content(readfile(s[0]) || ''));
		written++;
	}
	return written;
}

function build_network(stage) {
	writefile(stage + '/net_ip_addr.txt', redact_text_blob(capture('ip addr 2>/dev/null')));
	writefile(stage + '/net_ip_route.txt', redact_text_blob(capture('ip route 2>/dev/null')));
	writefile(stage + '/net_ip_rule.txt', redact_text_blob(capture('ip rule 2>/dev/null')));
	writefile(stage + '/net_nft_fw4.txt', redact_text_blob(capture('nft list table inet fw4 2>/dev/null')));

	/* conntrack: сводка без полного дампа — объём, по протоколам, топ-10 src/dst. */
	let ct = '';
	if (access('/proc/net/nf_conntrack')) {
		ct += '# total tcp udp other\n';
		ct += trim(capture(`awk '{ c++; if ($3 == "tcp") t++; else if ($3 == "udp") u++; else o++ } END { printf "%d %d %d %d\\n", c+0, t+0, u+0, o+0 }' /proc/net/nf_conntrack 2>/dev/null`)) + '\n';
		ct += '# top src (count ip)\n';
		ct += trim(capture(`awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^src=/) { sub(/^src=/, "", $i); print $i } }' /proc/net/nf_conntrack 2>/dev/null | sort | uniq -c | sort -rn | head -n 10`)) + '\n';
		ct += '# top dst (count ip)\n';
		ct += trim(capture(`awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^dst=/) { sub(/^dst=/, "", $i); print $i } }' /proc/net/nf_conntrack 2>/dev/null | sort | uniq -c | sort -rn | head -n 10`)) + '\n';
	} else {
		ct = 'conntrack unavailable\n';
	}
	writefile(stage + '/net_conntrack_summary.txt', ct + '\n');
}

function daemon_info(name, pid) {
	const st = readfile('/proc/' + pid + '/status') || '';
	const rss = match(st, /VmRSS:[ \t]+([0-9]+) kB/);
	const fdn = trim(capture(`ls /proc/${pid}/fd 2>/dev/null | wc -l`));
	return { name: name, pid: pid,
		rss_kb: rss ? int(rss[1]) : null,
		fds: match(fdn, /^[0-9]+$/) ? int(fdn) : null };
}

function build_logs(stage) {
	/* logread tail 500 (redact) — системный контекст. */
	writefile(stage + '/log_logread.txt', redact_text_blob(capture(`logread 2>/dev/null | tail -n ${TEXT_LOG_TAIL}`)));

	/* Собственные журналы: хвост + honest-размер. */
	const app_logs = [
		[RUN_DIR + '/homeproxy.log', 'log_homeproxy_service.txt'],
		[RUN_DIR + '/hiddify-c.log', 'log_core.txt'],
		[RUN_DIR + '/automation.log', 'log_automation.txt'],
		[RUN_DIR + '/control.log', 'log_control.txt'],
		[RUN_DIR + '/multidns/multidns.log', 'log_multidns.txt'],
		[RUN_DIR + '/telegram.log', 'log_telegram.txt']
	];
	const sizes = {};
	for (let l in app_logs) {
		const src = l[0];
		const st = access(src) ? stat(src) : null;
		sizes[l[1]] = { path: src, size: st ? st.size : null, mtime: st ? int(st.mtime) : null };
		if (access(src))
			writefile(stage + '/' + l[1], redact_text_blob(capture(`tail -n ${APP_TAIL} ${shellquote(src)} 2>/dev/null`)));
	}

	/* daemon RSS/fd — ключевое для «зависаний»: утечка памяти/дескрипторов.
	 * Ф1.4b: источник — РЕЕСТР ПРОЦЕССОВ (pmgr scan): одна сводка покрывает
	 * и бинарные демоны, и ucode-скрипты (busybox pidof скрипты НЕ матчит —
	 * урок 23), каждое вхождение проверено по (pid, starttime). */
	let daemons = [];
	const reg = pm_scan();
	const want = [
		'core', 'mosdns', 'nfqws2', 'ciadpi',
		'sni_sniffer', 'probe_pool',
		'automation', 'telegram_bot', 'control', 'multidns',
		'urltest_watchdog', 'zapret_autopilot', 'hotswap', 'metrics'
	];
	for (let name in want) {
		/* for-in по массиву даёт ЭЛЕМЕНТ (урок 20) — name и есть имя записи. */
		const e = reg.daemons[name];
		if (e == null || !pm_entry_alive(e)) {
			push(daemons, { name: name, running: false });
			continue;
		}
		const di = daemon_info(name, e.pid);
		di.running = true;
		di.script = (e.script != null && length('' + e.script)) ? e.script : null;
		di.started = (int(e.started) > 0) ? int(e.started) : null;
		di.hb = (int(e.hb) > 0) ? int(e.hb) : null;
		if (e.extra_pids != null && length(e.extra_pids))
			di.extra_pids = e.extra_pids;
		push(daemons, di);
	}

	writefile(stage + '/daemons.json', sprintf('%.J', { generated: now_str(), daemons: daemons }) + '\n');
	writefile(stage + '/logs_sizes.json', sprintf('%.J', { generated: now_str(), logs: sizes }) + '\n');
}

/* ── selftest: секреты ОТСУТСТВУЮТ в артефакте ─────────────────────────── */

function run_selftest(stage, secrets) {
	const checks = [];
	const check = function(name, ok, detail) {
		push(checks, { check: name, ok: ok, detail: detail || null });
	};
	/* Синтетика: сама redact_line обязана убивать образцы. */
	const samples = [
		['tg_token', '123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678'],
		['bearer', 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9zzz'],
		['userpass', 'http://alice:s3cretPw@sub.example.com/dl'],
		['sharelink', 'vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@host:443?x=1'],
		['querytoken', 'https://sub.example.com/dl?token=DEADBEEF123&f=x']
	];
	for (let s in samples) {
		const red = redact_line(s[1]);
		check('redact_' + s[0], index(red, '[REDACTED') >= 0, substr(red, 0, 48));
	}
	/* Реальные секреты UCI не появляются НИ В ОДНОМ стейдж-файле. */
	const files = [];
	const fd = popen(`cd ${shellquote(stage)} && find . -type f | sort`);
	if (fd) {
		for (let line = fd.read('line'); length(line); line = fd.read('line'))
			push(files, stage + '/' + replace(trim(line), /^\.\//, ''));
		fd.close();
	}
	const longvals = filter(secrets, (v) => length(v) >= 6);
	check('secrets_collected', length(longvals) > 0, sprintf('%d values', length(longvals)));
	let leaks = [];
	for (let f in files) {
		const content = readfile(f) || '';
		for (let v in longvals) {
			if (index(content, v) >= 0)
				push(leaks, replace(f, stage + '/', '') + ' <- ' + substr(v, 0, 6) + '...');
		}
	}
	check('no_secrets_in_artifact', length(leaks) === 0, join('; ', leaks));
	/* Чексуммы внутри бандла сходятся (тахион-паттерн). */
	const sums = readfile(stage + '/checksums.sha256') || '';
	let bad = 0;
	let lines_n = 0;
	for (let line in split(sums, '\n')) {
		const m = match(trim(line), /^([0-9a-f]{64})[ \t]+(.+)$/);
		if (!m) continue;
		lines_n++;
		const got = trim(capture(`sha256sum ${shellquote(stage + '/' + m[2])} 2>/dev/null | awk '{ print $1 }'`));
		if (got !== m[1]) bad++;
	}
	check('checksums_match', lines_n > 0 && bad === 0, sprintf('%d files, %d bad', lines_n, bad));
	return checks;
}

function selftest_failed(checks) {
	for (let c in checks)
		if (c.ok === false) return true;
	return false;
}

/* ── быстрый текст-отчёт (RU; для <pre> в UI и фолбэка TG) ──────────────── */

function do_text_report() {
	const L = [];
	const add = (s) => push(L, s);

	/* value-based редакция работает и здесь (chat_id/URL в хвостах). */
	collect_secret_values();
	add('ОТЧЁТ ДЛЯ ПОДДЕРЖКИ Ravnex');
	add('Сгенерирован: ' + now_str());
	const av = app_version();
	add('Приложение: ' + (av ? ('v' + av) : 'версия не определена'));
	add('');

	add('[Система]');
	add(trim(readfile('/etc/openwrt_release') || ''));
	add(trim(capture('uname -a 2>/dev/null')));
	const um = match(trim(readfile('/proc/uptime') || ''), /^([0-9]+)/);
	if (um) add(sprintf('Аптайм: %d с (~%.1f ч)', int(um[1]), int(um[1]) / 3600.0));
	const lm = match(trim(readfile('/proc/loadavg') || ''), /^([0-9.]+) +([0-9.]+)/);
	if (lm) add('Load: ' + lm[1] + ' ' + lm[2]);
	const mm = match(readfile('/proc/meminfo') || '', /MemAvailable:[ \t]+([0-9]+) kB/);
	const mt = match(readfile('/proc/meminfo') || '', /MemTotal:[ \t]+([0-9]+) kB/);
	if (mm && mt) add(sprintf('Память занято: %d из %d МБ', (int(mt[1]) - int(mm[1])) / 1024, int(mt[1]) / 1024));
	add(trim(capture('df -h / 2>/dev/null | tail -n 1')));
	add(trim(capture('df -h /tmp 2>/dev/null | tail -n 1')));
	add('');

	add('[Службы]');
	let svcj = null;
	try { svcj = json(capture('ubus call service list 2>/dev/null')); } catch (e) { svcj = null; }
	if (svcj && type(svcj) === 'object' && svcj.homeproxy && type(svcj.homeproxy.instances) === 'object') {
		for (let k in svcj.homeproxy.instances) {
			const inst = svcj.homeproxy.instances[k];
			add(sprintf('%s: %s%s', k, inst.running ? 'работает' : 'остановлен',
				inst.pid ? (' (pid ' + inst.pid + ')') : ''));
		}
	}
	/* Ф1.4b: liveness from the process registry (identity = pid + starttime),
	 * with an exact /proc fallback for binaries; mosdns only counts as up
	 * when the instance runs OUR config (audit 11). */
	const up = function(name, exe_spec) {
		const e = pm_reg_get(name);
		if (e != null && pm_entry_alive(e))
			return true;
		if (exe_spec != null)
			return length(pm_find(exe_spec)) > 0;
		return false;
	};
	add('');

	add('[Ядро и движки]');
	const cv = read_json_safe(RUN_DIR + '/core_versions.json') || {};
	for (let bin in cv)
		if (cv[bin] && cv[bin].info && cv[bin].info.version)
			add(bin + ': v' + cv[bin].info.version);
	add('mosdns: ' + (up('mosdns', { exe: '/usr/bin/mosdns', arg: [
			'/var/run/homeproxy/multidns/mosdns.yaml',
			'/var/run/homeproxy/multidns/mosdns.candidate.yaml'
		] }) ? 'работает' : 'не запущен') +
		(first_line(capture('mosdns version 2>/dev/null')) ? ' · ' + first_line(capture('mosdns version 2>/dev/null')) : ''));
	add('nfqws2: ' + (up('nfqws2', { exe: 'nfqws2' }) ? 'работает' : 'не запущен'));
	add('ciadpi: ' + (up('ciadpi', { exe: 'ciadpi' }) ? 'работает' : 'не запущен'));
	add('');

	add('[Состояния (sanitized)]');
	const st_map = [
		[RUN_DIR + '/hotswap_state.json', 'hotswap'],
		[RUN_DIR + '/zapret_autopilot.json', 'автопилот Zapret'],
		[RUN_DIR + '/automation_state.json', 'автоматизация'],
		[RUN_DIR + '/multidns/multidns_state.json', 'MultiDNS'],
		[RUN_DIR + '/urltest_dead', 'URLTest dead'],
		[RUN_DIR + '/core_skipped.json', 'core_skipped']
	];
	for (let s in st_map) {
		if (!access(s[0])) continue;
		add('— ' + s[1] + ':');
		const lines = split(trim(sanitize_content(readfile(s[0]) || '')), '\n');
		const cap = 12;
		for (let i = 0; i < length(lines) && i < cap; i++)
			add('  ' + lines[i]);
		if (length(lines) > cap)
			add(sprintf('  … (+%d строк, полный вид в бандле)', length(lines) - cap));
	}
	add('');

	add('[Хвост журнала ядра]');
	const core_tail = trim(redact_text_blob(capture(`tail -n 30 ${shellquote(RUN_DIR + '/hiddify-c.log')} 2>/dev/null`)));
	if (length(core_tail))
		for (let line in split(core_tail, '\n'))
			add('  ' + line);
	else
		add('  (журнал ядра пуст или отсутствует)');
	add('');

	add('[Системный журнал: ошибки/предупреждения]');
	const errs = trim(redact_text_blob(capture('logread 2>/dev/null | grep -iE "err|warn|fail|crash|oom" | tail -n 30')));
	if (length(errs))
		for (let line in split(errs, '\n'))
			add('  ' + line);
	else
		add('  (ошибок в системном журнале не видно)');
	add('');
	add('Полный бандл (конфиги/сеть/логи/чексуммы) — «Центр здоровья» → вкладка «Проверка и ремонт» → «Отчёт для поддержки».');
	return join('\n', L) + '\n';
}

/* ── сборка полного бандла ─────────────────────────────────────────────── */

function write_meta(doc) {
	watomic(META_FILE, sprintf('%.J', doc) + '\n');
	return doc;
}

function do_build(with_tar) {
	const secrets = collect_secret_values();
	/* Чистим прошлый бандл: хранится только последний. */
	system('rm -f /tmp/ravnex_bundle_*.tar.gz /tmp/ravnex_bundle_*.tar 2>/dev/null');
	system(`rm -rf ${shellquote(STAGE_BASE)} 2>/dev/null`);
	mkdir(STAGE_BASE);

	write_meta({ running: true, ts: time(), stage: STAGE_BASE });

	const t0 = time();
	build_metadata(STAGE_BASE);
	build_service_status(STAGE_BASE);
	build_configs(STAGE_BASE);
	const states_n = build_states(STAGE_BASE);
	build_network(STAGE_BASE);
	build_logs(STAGE_BASE);

	/* Чексуммы стейджа (без самого файла чексумм). */
	writefile(STAGE_BASE + '/checksums.sha256',
		capture(`cd ${shellquote(STAGE_BASE)} && find . -type f ! -name checksums.sha256 | sort | xargs sha256sum 2>/dev/null`));

	const checks = run_selftest(STAGE_BASE, secrets);
	const failed = selftest_failed(checks);

	let files_n = 0;
	const fd = popen(`cd ${shellquote(STAGE_BASE)} && find . -type f | wc -l`);
	if (fd) { files_n = int(trim(fd.read('all'))) || 0; fd.close(); }

	let path = null;
	let size = null;
	if (with_tar && !failed) {
		const ts = ts14();
		if (!length(ts))
			return write_meta({ running: false, ts: time(), ok: false, error: 'date failed', selftest: checks, files: files_n, states_written: states_n });
		path = `/tmp/ravnex_bundle_${ts}.tar.gz`;
		const rc = system(`cd ${shellquote(STAGE_BASE)} && tar -czf ${shellquote(path)} . 2>/dev/null`);
		if (rc !== 0 || !access(path)) {
			path = `/tmp/ravnex_bundle_${ts}.tar`;
			system(`cd ${shellquote(STAGE_BASE)} && tar -cf ${shellquote(path)} . 2>/dev/null`);
		}
		if (!access(path))
			return write_meta({ running: false, ts: time(), ok: false, error: 'tar failed', selftest: checks, files: files_n, states_written: states_n });
		size = fsize(path);
		system(`rm -rf ${shellquote(STAGE_BASE)} 2>/dev/null`);
	}

	return write_meta({
		running: false,
		ts: time(),
		took_s: time() - t0,
		ok: !failed,
		error: failed ? 'selftest FAILED — секрет найден в артефакте; бандл не отдан' : null,
		selftest: checks,
		files: files_n,
		states_written: states_n,
		path: path,
		name: path ? substr(path, 5) : null,
		size: size,
		stage: failed ? STAGE_BASE : null
	});
}

/* ── CLI ───────────────────────────────────────────────────────────────── */

const mode = length(ARGV) ? ARGV[0] : 'build';

if (mode === 'text') {
	printf('%s', do_text_report());
	exit(0);
}

if (mode === 'selftest') {
	const meta = do_build(false);   /* стейдж остаётся на диске для осмотра */
	if (meta && type(meta.selftest) === 'array')
		for (let c in meta.selftest)
			printf('%s %s%s\n', c.ok ? 'PASS' : 'FAIL', c.check, c.detail ? (' — ' + c.detail) : '');
	printf('secrets checked: %d\n', length(filter(collect_secret_values(), (v) => length(v) >= 6)));
	exit((meta && meta.ok) ? 0 : 1);
}

/* build (default) */
do_build(true);
exit(0);
