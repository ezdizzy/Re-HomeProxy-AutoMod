#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 ImmortalWrt.org
 */

'use strict';

import { open } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';

import { init_action } from 'luci.sys';

import {
	wGET, decodeBase64Str, getTime, isEmpty, parseURL,
	validation, validate_node_config, shellQuote, HP_DIR, RUN_DIR
} from 'homeproxy';

import { access, stat, popen } from 'fs';

import { emit as ev_emit } from 'eventbus';

/* Single shared parser set (Ф9.11): parse_uri for share links (and the
 * passthrough/validation of pre-parsed objects) + parse_content for whole
 * subscription bodies (sing-box JSON, Xray JSON, SIP008, clash/mihomo YAML,
 * base64 batches, plain URI lists). The UI import RPC uses the SAME
 * implementations — no second copy to drift. */
import { parse_uri, parse_content } from 'node_parse';

/* The ucode 'digest' module is deliberately NOT used: the package must not
 * depend on it (it is absent on some OpenWrt builds). Use the same
 * dependency-free FNV-1a hash as import_link: collision-safe for realistic
 * node counts and stable across runs. NOTE: hash values differ from the old
 * md5 ones — the first update after that switch re-created subscription node
 * sections once (user tweaks on them were lost). */
function strhash(s) {
	let h = 2166136261;
	const n = length(s);
	for (let i = 0; i < n; i++) {
		h = (h ^ ord(s, i)) & 0xFFFFFFFF;
		h = (h * 16777619) & 0xFFFFFFFF;
	}
	return sprintf('%08x', h);
}

/* UCI config start */
const uci = cursor();

const uciconfig = 'ravnex';
uci.load(uciconfig);

const ucimain = 'config',
      ucinode = 'node',
      ucisubscription = 'subscription';

const allow_insecure = uci.get(uciconfig, ucisubscription, 'allow_insecure') || '0',
      filter_mode = uci.get(uciconfig, ucisubscription, 'filter_nodes') || 'disabled',
      filter_keywords = uci.get(uciconfig, ucisubscription, 'filter_keywords') || [],
      packet_encoding = uci.get(uciconfig, ucisubscription, 'packet_encoding') || 'xudp',
      subscription_urls = uci.get(uciconfig, ucisubscription, 'subscription_url') || [],
      user_agent = uci.get(uciconfig, ucisubscription, 'user_agent'),
      via_proxy = uci.get(uciconfig, ucisubscription, 'update_via_proxy') || '0';

const routing_mode = uci.get(uciconfig, ucimain, 'routing_mode') || 'proxy_banned_ru';
/* Ф3.1: legacy custom/custom_json читается как рабочий режим (D23) —
 * routing_mode_eff здесь уже никогда не 'custom', поэтому main_node
 * читается безусловно (Ф9.8: мёртвое условие снято). */
const routing_mode_eff = (routing_mode === 'custom' || routing_mode === 'custom_json')
	? 'proxy_banned_ru' : routing_mode;
let main_node, main_udp_node;
main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';
main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
/* UCI config end */

/* Ф9.11: an optional single-URL argument limits the run to ONE subscription
 * (the per-subscription «Обновить» card button). Empty = every URL (cron). */
const only_url = (length(ARGV) && type(ARGV[0]) === 'string' && length(trim(ARGV[0])))
	? trim(ARGV[0]) : null;

/* String helper start */
function filter_check(name) {
	if (isEmpty(name) || filter_mode === 'disabled' || isEmpty(filter_keywords))
		return false;

	let ret = false;
	for (let i in filter_keywords) {
		const patten = regexp(i);
		if (match(name, patten))
			ret = true;
	}
	if (filter_mode === 'whitelist')
		ret = !ret;

	return ret;
}
/* String helper end */

/* ── Canonical node fingerprint (Ф9.11: rename + duplicate protection) ─────
 * Sorted "k=v" pairs of a node config, label and auto-applied globals
 * excluded. The freshly parsed config and the existing UCI section are
 * fingerprinted the SAME way, so a user RENAME (label change only) still
 * matches its source node and survives a subscription update instead of
 * being re-added as a duplicate. tls_insecure/packet_encoding are excluded
 * too: they are re-applied from the global subscription settings on every
 * run and must never break the match. bind_interface is a user field. */
const FP_SKIP = {
	label: true, grouphash: true, isExisting: true,
	bind_interface: true, tls_insecure: true, packet_encoding: true
};

function node_fingerprint(obj) {
	const ks = sort(filter(keys(obj || {}), (k) =>
		!(k in FP_SKIP) && substr(k, 0, 1) !== '.' &&
		obj[k] != null && ('' + obj[k]) !== ''));
	const parts = [];
	for (let k in ks) {
		const v = obj[k];
		const s = (type(v) === 'array') ? join(',', map(v, (x) => '' + x)) : '' + v;
		push(parts, k + '=' + s);
	}
	return join('|', parts);
}

/* Common var start */
const node_cache = {},
      node_result = [];

const ubus = connect();
const sing_features = ubus.call('luci.ravnex', 'singbox_get_features', {}) || {};
/* Common var end */

/* Log */
system(`mkdir -p ${RUN_DIR}`);
function log(...args) {
	const logfile = open(`${RUN_DIR}/ravnex.log`, 'a');
	logfile.write(`${getTime()} [SUBSCRIBE] ${join(' ', args)}\n`);
	logfile.close();
}

/* ── Ф5.1 (аудит «подписки и rule-set»): безопасный цикл обновления ────────
 * Статус-файл /var/run/ravnex/subscription_update.json (атомарно tmp+mv,
 * полируется RPC app_subscription_status и UI), бекап подписочных узлов
 * ПЕРЕД мутацией (ротация 5), гвард «обновление не имеет права оставить
 * НОЛЬ подписочных узлов» и пост-верификация старта с откатом UCI из бекапа
 * (LKG-механика Ф1.2 — init.d сам откатывает живой конфиг, здесь откатываем
 * UCI, чтобы следующий рестарт не воспроизводил битый набор узлов). */
const ST_FILE = `${RUN_DIR}/subscription_update.json`;
const BK_DIR = `${HP_DIR}/backups`;
const CORE_INSTANCE = 'hiddify-c';

function wstatus(o) {
	const tmp = ST_FILE + '.tmp';
	const fd = open(tmp, 'w');
	if (fd) {
		fd.write(sprintf('%J\n', o));
		fd.close();
	}
	system(`mv -f ${shellQuote(tmp)} ${shellQuote(ST_FILE)}`);
}

/* Snapshot of every subscription node section (grouphash) + the config node
 * pointers, BEFORE any mutation. Atomically written JSON; restore recreates
 * the SAME section names and fields (the cursor's set() writes arrays as
 * list options — the shipped update loop already relies on that). */
function backup_nodes() {
	const sections = [];
	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (!cfg.grouphash)
			return null;
		const copy = {};
		map(keys(cfg), (k) => {
			const v = cfg[k];
			copy[k] = (type(v) === 'array') ? map(v, (x) => '' + x) : v;
		});
		push(sections, copy);
	});
	if (!length(sections))
		return null;
	const lt = localtime(time());
	const stamp = sprintf('%d%02d%02d-%02d%02d%02d',
		lt.year, lt.mon, lt.mday, lt.hour, lt.min, lt.sec);
	const doc = {
		created: time(),
		main_node: uci.get(uciconfig, ucimain, 'main_node'),
		main_udp_node: uci.get(uciconfig, ucimain, 'main_udp_node'),
		main_urltest_nodes: uci.get(uciconfig, ucimain, 'main_urltest_nodes') || [],
		main_udp_urltest_nodes: uci.get(uciconfig, ucimain, 'main_udp_urltest_nodes') || [],
		main_urltest_preferred: uci.get(uciconfig, ucimain, 'main_urltest_preferred'),
		main_udp_urltest_preferred: uci.get(uciconfig, ucimain, 'main_udp_urltest_preferred'),
		exit_mode: uci.get(uciconfig, ucimain, 'exit_mode'),
		exit_preferred: uci.get(uciconfig, ucimain, 'exit_preferred'),
		exit_udp_preferred: uci.get(uciconfig, ucimain, 'exit_udp_preferred'),
		exit_reserves: uci.get(uciconfig, ucimain, 'exit_reserves') || [],
		sections: sections
	};
	system(`mkdir -p ${shellQuote(BK_DIR)}`);
	const path = `${BK_DIR}/sub-nodes-${stamp}.json`;
	const tmp = path + '.tmp';
	const fd = open(tmp, 'w');
	if (!fd)
		return null;
	fd.write(sprintf('%.J\n', doc));
	fd.close();
	system(`mv -f ${shellQuote(tmp)} ${shellQuote(path)}`);
	if (!access(path))
		return null;
	/* Rotate: keep the newest 5 sub-nodes backups. */
	const lfd = popen(`ls -1t ${shellQuote(BK_DIR)}/sub-nodes-*.json 2>/dev/null`);
	if (lfd) {
		const lines = filter(split(lfd.read('all') || '', '\n'), (x) => length(trim(x)));
		lfd.close();
		for (let i = 5; i < length(lines); i++)
			system(`rm -f ${shellQuote(lines[i])}`);
	}
	return path;
}

function restore_nodes(path) {
	let doc = null;
	const fd = open(path, 'r');
	if (!fd)
		return false;
	try { doc = json(fd.read('all') || ''); } catch (e) { doc = null; }
	fd.close();
	if (!doc || type(doc.sections) !== 'array')
		return false;
	/* Remove every CURRENT subscription node (they are the suspect set), then
	 * recreate the backup verbatim. User-created nodes (no grouphash) are
	 * never touched. */
	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (cfg.grouphash)
			uci.delete(uciconfig, cfg['.name']);
		return null;
	});
	for (let s in doc.sections) {
		const sid = '' + (s['.name'] || '');
		if (!length(sid) || !match(sid, /^[A-Za-z0-9_]+$/))
			continue;   /* uci -q silently rejects names with '-' (lesson 248) */
		uci.set(uciconfig, sid, 'node');
		for (let k in s) {
			if (substr(k, 0, 1) === '.')
				continue;
			if (k === 'grouphash' || k === 'isExisting')
				continue;
			const v = s[k];
			if (v != null && ('' + v) !== '')
				uci.set(uciconfig, sid, k, v);
		}
	}
	const ptrs = [
		['main_node', 'main_node'], ['main_udp_node', 'main_udp_node'],
		['main_urltest_preferred', 'main_urltest_preferred'],
		['main_udp_urltest_preferred', 'main_udp_urltest_preferred'],
		['exit_mode', 'exit_mode'],
		['exit_preferred', 'exit_preferred'],
		['exit_udp_preferred', 'exit_udp_preferred']
	];
	for (let p in ptrs) {
		if (doc[p[0]] != null)
			uci.set(uciconfig, ucimain, p[1], '' + doc[p[0]]);
	}
	const lists = [['main_urltest_nodes'], ['main_udp_urltest_nodes'], ['exit_reserves']];
	for (let l in lists) {
		uci.delete(uciconfig, ucimain, l[0]);
		if (type(doc[l[0]]) === 'array' && length(doc[l[0]]))
			uci.set(uciconfig, ucimain, l[0], doc[l[0]]);
	}
	uci.commit(uciconfig);
	return true;
}

/* Core alive check — same primitive hp_instance_running uses: the service
 * list instance object carries "running". */
function core_running() {
	const res = ubus.call('service', 'list', {});
	const inst = (res && res[uciconfig] && res[uciconfig].instances)
		? res[uciconfig].instances[CORE_INSTANCE] : null;
	return !!(inst && inst.running);
}

/* Post-start verification (Ф5.1): poll the core up to ~40 s (outlasts the
 * init.d LKG verifier's 8 s cycle + its restart). Returns
 * 'ok' | 'lkg_rollback' | 'dead'. */
function verify_core(deadline_s) {
	const started = time();
	let alive = false;
	while (time() - started < deadline_s) {
		system('sleep 2');
		if (core_running()) { alive = true; break; }
	}
	if (alive) {
		/* LKG rollback marker newer than our start = the NEW config failed
		 * validation and init.d restored the previous one. */
		const marker = `${RUN_DIR}/.lkg_rollback`;
		const st = access(marker) ? stat(marker) : null;
		if (st && st.mtime >= started - 2)
			return 'lkg_rollback';
		return 'ok';
	}
	return 'dead';
}

/* Per-group bookkeeping — one entry per subscription URL. */
function new_group(gid, url) {
	return { hash: gid, url: url, before: 0, parsed: 0, invalid: 0,
		added: 0, removed: 0, kept: 0, status: 'pending' };
}

const ST = { running: true, ts: time(), action: 'running', reason: '',
	groups: [], totals: null, backup: null, verify: null };
const group_index = {};

function main() {
	/* Per-group «before» counts — read-only, BEFORE any mutation (Ф5.1). */
	const before_by_group = {};
	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (!cfg.grouphash)
			return null;
		const g = '' + cfg.grouphash;
		before_by_group[g] = (before_by_group[g] || 0) + 1;
		return null;
	});

	/* Groups taking part in THIS run (all, or only the per-URL target). */
	const run_groups = {};
	let before_total = 0;

	let service_was_stopped = false;
	if (via_proxy !== '1') {
		log('Stopping service...');
		init_action('ravnex', 'stop');
		service_was_stopped = true;
	}
	wstatus(ST);

	/* UA ladder (Ф9.11): panels serve the format BY User-Agent (proven live:
	 * UA «sing-box» → full sing-box JSON, other UAs → base64 link list).
	 * 1) Hiddify app UA (sing-box JSON on Hiddify Manager panels),
	 * 2) sing-box UA (sing-box JSON on sub-store/marzban-style panels),
	 * 3) the configured user_agent (base64/URI lists, clash YAML). */
	const ladder = ['HiddifyNext/2.0.0', 'sing-box/1.11.0'];
	const cfg_ua = user_agent || 'Wget/1.21 (HomeProxy, like v2rayN)';
	if (cfg_ua !== 'HiddifyNext/2.0.0' && cfg_ua !== 'sing-box/1.11.0')
		push(ladder, cfg_ua);

	for (let url in subscription_urls) {
		if (only_url != null && url != only_url)
			continue;

		/* App share-wrappers pasted as subscription URLs (clash://install-config?url=…,
		 * sing-box://import-remote?url=…) — unwrap the real subscription link. */
		const wrapped_q = index(url, '?url=');
		if (wrapped_q > 0 && match(url, /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//)) {
			const wrapped_url = substr(url, wrapped_q + 5);
			if (!isEmpty(wrapped_url)) {
				log(sprintf('Unwrapping subscription URL from %s link.', split(url, '://')[0]));
				url = urldecode(wrapped_url);
			}
		}

		const groupHash = strhash(url);
		node_cache[groupHash] = {};
		run_groups[groupHash] = true;
		/* Ф5.1: честная книжка группы — до/после, статусы ответа. */
		let grp = group_index[groupHash];
		if (!grp) {
			grp = { hash: groupHash, url: url,
				before: before_by_group[groupHash] || 0,
				parsed: 0, invalid: 0, added: 0, removed: 0, kept: 0,
				status: 'fetch_failed', full_replace: false };
			group_index[groupHash] = grp;
			push(ST.groups, grp);
		}

		/* UA ladder: panels serve the format BY User-Agent (proven live:
		 * UA «sing-box» → full sing-box JSON, other UAs → base64 link list).
		 * A structured format (sing-box/Xray/SIP008/clash) wins at once;
		 * line-based results (base64/URI) are provisional — the next UA may
		 * still upgrade to a richer structured format. */
		const STRUCTURED = ['singbox', 'xray', 'sip008', 'clash'];
		let res = null, nodes = null, fmt = null, res_html = false;
		for (let ua in ladder) {
			res = wGET(url, ua);
			if (isEmpty(res))
				continue;
			const pc = parse_content(res, log, sing_features);
			if (length(pc.nodes)) {
				if (nodes == null || (pc.format in STRUCTURED && !(fmt in STRUCTURED))) {
					nodes = pc.nodes;
					fmt = pc.format;
				}
				if (fmt in STRUCTURED)
					break;
			} else if (pc.format === 'html') {
				res_html = true;
			}
		}

		/* Empty or HTML response: server may require /raw suffix (e.g. HAPP-style
		 * subscription servers that serve a web page by default). */
		if (isEmpty(nodes)) {
			const rawUrl = replace(url, /\/*$/, '') + '/raw';
			const probe = wGET(url, cfg_ua);
			if (isEmpty(probe) || match(probe, /^\s*</)) {
				log(sprintf('%s from %s, retrying with /raw.',
					isEmpty(probe) ? 'Empty response' : 'HTML response', url));
				const rawRes = wGET(rawUrl, cfg_ua);
				if (!isEmpty(rawRes) && !match(rawRes, /^\s*</)) {
					const pc = parse_content(rawRes, log, sing_features);
					if (length(pc.nodes)) {
						nodes = pc.nodes;
						fmt = pc.format;
						res = rawRes;
					} else if (pc.format === 'html')
						res_html = true;
				}
			} else {
				const pc = parse_content(probe, log, sing_features);
				if (length(pc.nodes)) {
					nodes = pc.nodes;
					fmt = pc.format;
					res = probe;
				} else if (pc.format === 'html')
					res_html = true;
			}
		}

		if (isEmpty(nodes)) {
			log(sprintf('Failed to fetch resources from %s.', url));
			grp.status = res_html ? 'html' : 'no_valid';
			continue;
		}
		if (fmt)
			log(sprintf('Received %s subscription from %s.', fmt, url));

		const res_html_keep = res_html;
		let count = 0;
		for (let node in nodes) {
			let config;
			if (!isEmpty(node))
				config = parse_uri(node, log);
			if (isEmpty(config))
				continue;

			/* Ф5.3 (аудит 51): единый валидатор — битый узел отбрасывается
			 * С ПРИЧИНОЙ (адрес/порт/ключи), а не молча попадает в UCI,
			 * откуда он валит валидацию конфига ядра. */
			const verrs = validate_node_config(config);
			if (verrs) {
				grp.invalid++;
				log(sprintf('Skipping invalid node (%s): %s.',
					join('; ', verrs),
					(type(config.label) === 'string' && length(config.label)) ?
						config.label : (config.address || '?')));
				continue;
			}

			/* Normalize: some parsers yield label:null — string concat with null
			 * is a fatal in this ucode build. */
			let label = config.label;
			if (type(label) !== 'string')
				label = '';
			config.label = null;
			const fpHash = node_fingerprint(config),
			      nameHash = strhash(groupHash + '|' + label);
			config.label = label;

			if (filter_check(config.label))
				log(sprintf('Skipping blacklist node: %s.', config.label));
			else if (node_cache[groupHash]['fp:' + fpHash] || node_cache[groupHash][nameHash])
				log(sprintf('Skipping duplicate node: %s.', config.label));
			else {
				if (config.tls === '1' && allow_insecure === '1')
					config.tls_insecure = '1';
				if (config.type in ['vless', 'vmess'])
					config.packet_encoding = packet_encoding;

				config.grouphash = groupHash;
				push(node_result, []);
				push(node_result[length(node_result)-1], config);
				/* Keyed BOTH by the canonical fingerprint (rename-proof match)
				 * and by the natural section id (label-based, unchanged). The
				 * fingerprint key is namespaced 'fp:' — section ids share the
				 * plain-key space. */
				node_cache[groupHash]['fp:' + fpHash] = config;
				node_cache[groupHash][nameHash] = config;

				count++;
			}
		}

		grp.parsed = count;
		grp.status = (count > 0) ? 'ok' : (res_html_keep ? 'html' : 'no_valid');
		grp.format = fmt;
		if (count == 0)
			log(sprintf('No valid node found in %s.', url));
		else
			log(sprintf('Successfully fetched %s nodes of total %s from %s.', count, length(nodes), url));
	}

	if (isEmpty(node_result)) {
		log('Failed to update subscriptions: no valid node found.');
		/* Ф5.1: мутаций не было — существующие подписочные узлы нетронуты. */
		ST.action = 'aborted';
		ST.reason = 'ни одна подписка не дала ни одного валидного узла — UCI не изменялся';
		ST.totals = { before: before_total, after: before_total,
			kept: before_total, added: 0, removed: 0 };
		ST.running = false;
		if (service_was_stopped) {
			log('Starting service...');
			init_action('ravnex', 'start');
		}
		wstatus(ST);
		try { ev_emit('subscribe', 'aborted', '',
			'обновление отклонено: ни один узел не распознан — узлы не тронуты'); } catch (e) {}
		return false;
	}

	/* Ф9.11 pass 1 (read-only): match every existing subscription section of
	 * the run groups — by its section id (label-based) or, when the user
	 * RENAMED the node, by the canonical fingerprint; duplicates collapse. */
	let kept_total = 0, removed_total = 0;
	const plan_remove = [], plan_update = [];
	const run_group_list = keys(run_groups) || [];

	for (let g in run_group_list) {
		const gh = '' + g;
		before_total += (before_by_group[gh] || 0);
	}

	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (!cfg.grouphash)
			return null;
		const gh = '' + cfg.grouphash;
		if (!(gh in run_groups))
			return null;
		if (length(node_cache[gh]) === 0)
			return null;   /* failed fetch — leave the group alone */

		const cache = node_cache[gh];
		let cached = cache[cfg['.name']] || null;
		if (cached && cached.isExisting) {
			/* Two sections matched the SAME parsed node → duplicate collapse
			 * (Ф9.11: защита от дубля при обновлении подписки) */
			cached = null;
			push(plan_remove, { sid: cfg['.name'],
				label: (cfg.label || cfg.name || cfg['.name']) + ' (дубль — совпадает с другим узлом)',
				ghash: gh });
			removed_total++;
			const gr = group_index[gh];
			if (gr) gr.removed++;
			return null;
		}
		if (!cached) {
			const fp = node_fingerprint(cfg);
			if (length(fp) && cache['fp:' + fp]) {
				const cand = cache['fp:' + fp];
				if (cand && !cand.isExisting) {
					cached = cand;
					log(sprintf('Node matched by fingerprint after a rename: %s.', cfg['.name']));
				}
			}
		}
		if (cached) {
			cached.isExisting = true;
			push(plan_update, { sid: cfg['.name'], cached: cached, ghash: gh });
			kept_total++;
			const gr = group_index[gh];
			if (gr) gr.kept++;
		} else {
			push(plan_remove, { sid: cfg['.name'],
				label: cfg.label || cfg.name || cfg['.name'],
				ghash: gh });
			removed_total++;
			const gr = group_index[gh];
			if (gr) gr.removed++;
		}
		return null;
	});

	let added_total = 0;
	for (let nodes in node_result)
		map(nodes, (node) => {
			if (!node.isExisting)
				added_total++;
			return null;
		});

	/* 🔴 Ф5.1: обновление НИКОГДА не имеет права оставить ноль подписочных
	 * узлов при ненулевом «до» — применить НЕТ (бекап даже не нужен: до
	 * мутаций дело не доходит). Scoped to the run's groups (Ф9.11: a
	 * single-URL run must not abort because OTHER groups are fine). */
	if (before_total > 0 && kept_total === 0 && added_total === 0) {
		log(sprintf('ABORT: the update would leave 0 of %d subscription nodes.', before_total));
		ST.action = 'aborted';
		ST.reason = sprintf('обновление удалило бы все %d подписочных узлов — применено НЕТ', before_total);
		ST.totals = { before: before_total, after: before_total,
			kept: before_total, added: 0, removed: 0 };
		ST.running = false;
		if (service_was_stopped) {
			log('Starting service...');
			init_action('ravnex', 'start');
		}
		wstatus(ST);
		try { ev_emit('subscribe', 'aborted', '',
			'обновление отклонено: остался бы 0 узлов подписок'); } catch (e) {}
		return false;
	}

	/* Бекап ПЕРЕД мутацией (Ф5.1): датированный снимок подписочных секций. */
	ST.backup = backup_nodes();
	if (ST.backup)
		log(sprintf('Backup written: %s.', ST.backup));
	else if (before_total > 0)
		log('Backup FAILED — continuing without a rollback copy');

	/* Pass 2: мутации (план уже сверен гвардом). */
	for (let r in plan_remove) {
		uci.delete(uciconfig, r.sid);
		const grp2 = group_index[r.ghash];
		if (grp2) grp2.removed = (grp2.removed || 0);
		log(sprintf('Removing node: %s.', r.label));
	}
	for (let up in plan_update) {
		const sid = up.sid, cached = up.cached;
		/* Field sync EXCEPT label (a user rename wins, Ф9.11) and except the
		 * user's own fields (bind_interface). New parser fields are pushed. */
		const cfg = uci.get_all(uciconfig, sid) || {};
		map(keys(cfg), (v) => {
			if (substr(v, 0, 1) === '.' || v === 'label')
				return null;
			if (v in cached) {
				if (cached[v] !== null)
					uci.set(uciconfig, sid, v, cached[v]);
				else
					uci.delete(uciconfig, sid, v);
			} else if (v !== 'bind_interface')
				uci.delete(uciconfig, sid, v);
			return null;
		});
		map(keys(cached), (v) => {
			if (v === 'label' || v === 'grouphash' || v === 'isExisting')
				return null;
			if (!(v in cfg) && cached[v] !== null)
				uci.set(uciconfig, sid, v, cached[v]);
			return null;
		});
	}
	for (let nodes in node_result)
		map(nodes, (node) => {
			if (node.isExisting)
				return null;

			/* Section id includes the group hash: two subscriptions shipping the
			 * same label ("Server1" from template providers) previously produced
			 * the SAME section id — the second silently overwrote the first's
			 * node while "added" counted both. NOTE: each parsed node carries
			 * its own .grouphash (set when queued). */
			const ghash = node.grouphash || '';
			const nlabel = (type(node.label) === 'string') ? node.label : '';
			const nameHash = strhash(ghash + '|' + nlabel);
			uci.set(uciconfig, nameHash, 'node');
			map(keys(node), (v) => uci.set(uciconfig, nameHash, v, node[v]));

			const grp3 = group_index[ghash];
			if (grp3) grp3.added++;
			log(sprintf('Adding node: %s.', node.label));
			return null;
		});
	uci.commit(uciconfig);

	let need_restart = (via_proxy !== '1');
	if (!isEmpty(main_node)) {
		const first_server = uci.get_first(uciconfig, ucinode);
		if (first_server) {
			/* Exit Engine (Ф9.16): резервы exit_reserves чистятся от исчезнувших
			 * узлов при любом main_node (urltest и конкретный узел); preferred
			 * (exit_preferred/exit_udp_preferred + легаси) чистится, когда узел
			 * исчез. Легаси-списки main_urltest_nodes/main_udp_urltest_nodes
			 * чистятся как раньше — генератор читает их как фолбэк до миграции.
			 * Пул kernel-группы теперь = все узлы, поэтому «пустой список» больше
			 * НЕ переключает main_node (пул опустевает только при 0 узлов, а тогда
			 * first_server и так null). 🔴 ucode-uci: list-опция пишется ТОЛЬКО
			 * set'ом С МАССИВОМ — скалярный set заменяет список одним элементом,
			 * цикл скалярных set схлопывается в один (поймано живьём в Ф9.11). */
			const pruned_reserves = map(uci.get(uciconfig, ucimain, 'exit_reserves') || [], (v) => '' + v);
			const kept_reserves = filter(pruned_reserves, (v) => {
				if (!uci.get(uciconfig, v)) {
					log(sprintf('Node %s is gone, removing from exit reserves.', v));
					return false;
				}
				return true;
			});
			if (length(kept_reserves))
				uci.set(uciconfig, ucimain, 'exit_reserves', kept_reserves);
			else
				uci.delete(uciconfig, ucimain, 'exit_reserves');
			const gone_pref = uci.get(uciconfig, ucimain, 'main_urltest_preferred');
			if (gone_pref && !uci.get(uciconfig, gone_pref)) {
				log(sprintf('Preferred node %s is gone, clearing preference.', gone_pref));
				uci.delete(uciconfig, ucimain, 'main_urltest_preferred');
			}
			const gone_epref = uci.get(uciconfig, ucimain, 'exit_preferred');
			if (gone_epref && !uci.get(uciconfig, gone_epref)) {
				log(sprintf('Preferred node %s is gone, clearing exit preference.', gone_epref));
				uci.delete(uciconfig, ucimain, 'exit_preferred');
			}
			const gone_upref = uci.get(uciconfig, ucimain, 'main_udp_urltest_preferred');
			if (gone_upref && !uci.get(uciconfig, gone_upref)) {
				log(sprintf('Preferred UDP node %s is gone, clearing preference.', gone_upref));
				uci.delete(uciconfig, ucimain, 'main_udp_urltest_preferred');
			}
			const gone_eupref = uci.get(uciconfig, ucimain, 'exit_udp_preferred');
			if (gone_eupref && !uci.get(uciconfig, gone_eupref)) {
				log(sprintf('Preferred UDP node %s is gone, clearing exit UDP preference.', gone_eupref));
				uci.delete(uciconfig, ucimain, 'exit_udp_preferred');
			}
			if (main_node === 'urltest') {
				const ut_mode = uci.get(uciconfig, ucimain, 'main_urltest_mode') || 'manual';
				if (ut_mode === 'manual') {
					const kept = filter(map(uci.get(uciconfig, ucimain, 'main_urltest_nodes') || [], (v) => '' + v), (v) => {
						if (!uci.get(uciconfig, v)) {
							log(sprintf('Node %s is gone, removing from urltest list.', v));
							return false;
						}
						return true;
					});
					if (length(kept))
						uci.set(uciconfig, ucimain, 'main_urltest_nodes', kept);
					else
						uci.delete(uciconfig, ucimain, 'main_urltest_nodes');
				}
			}

			/* Synthetic tags are not node sections and must not be treated as
			 * missing nodes. 🔴 Ф9.16: 'urltest' is the ENGINE-OWNED selector
			 * (caught live: this check switched main_node=urltest to the first
			 * node on every update, breaking the exit-engine contract) — the
			 * engine owns the pick, the update must not touch it. 'nil' = the
			 * explicit no-node choice; 'same' = UDP follows main. */
			const synthetic = ['direct-out', 'byedpi-out', 'zapret-out', 'urltest', 'nil', 'same'];
			if (!(main_node in synthetic) && !uci.get(uciconfig, main_node)) {
				uci.set(uciconfig, ucimain, 'main_node', first_server);
				uci.commit(uciconfig);
				need_restart = true;

				log('Main node is gone, switching to the first node.');
			}

			if (!isEmpty(main_udp_node) && main_udp_node !== 'same') {
				if (main_udp_node === 'urltest') {
					const ut_mode = uci.get(uciconfig, ucimain, 'main_udp_urltest_mode') || 'manual';
					if (ut_mode === 'manual') {
						const kept_udp = filter(map(uci.get(uciconfig, ucimain, 'main_udp_urltest_nodes') || [], (v) => '' + v), (v) => {
							if (!uci.get(uciconfig, v)) {
								log(sprintf('Node %s is gone, removing from UDP urltest list.', v));
								return false;
							}
							return true;
						});
						if (length(kept_udp))
							uci.set(uciconfig, ucimain, 'main_udp_urltest_nodes', kept_udp);
						else
							uci.delete(uciconfig, ucimain, 'main_udp_urltest_nodes');
					}
				}

				if (!(main_udp_node in synthetic) && !uci.get(uciconfig, main_udp_node)) {
					uci.set(uciconfig, ucimain, 'main_udp_node', first_server);
					uci.commit(uciconfig);
					need_restart = true;

					log('Main UDP node is gone, switching to the first node.');
				}
			}
		} else {
			uci.set(uciconfig, ucimain, 'main_node', 'nil');
			uci.set(uciconfig, ucimain, 'main_udp_node', 'nil');
			uci.commit(uciconfig);
			need_restart = true;

			log('No available node, disable tproxy.');
		}
	}

	let verify = null;
	if (need_restart) {
		/* Двойной stop — шум «Not found» в логе: сервис уже стоит, если мы
		 * сами его остановили в начале (via_proxy!=='1'). */
		if (!service_was_stopped) {
			log('Stopping service...');
			init_action('ravnex', 'stop');
		}
		log('Starting service...');
		init_action('ravnex', 'start');
		/* Ф5.1 пост-верификация: ядро обязано подняться на новом наборе
		 * узлов; lkg_rollback = init.d уже вернул прошлый конфиг (битый
		 * набор узлов отвергнут валидацией ядра), dead = не поднялось вовсе. */
		verify = verify_core(40);
		ST.verify = { restarted: true, verdict: verify };
		if (verify !== 'ok') {
			log(sprintf('Verification: %s — restoring node sections from the backup.', verify));
			const rb = ST.backup ? restore_nodes(ST.backup) : false;
			log(rb ? 'Node sections restored from the backup.'
			       : 'Restore FAILED (no/failed backup) — check the node list manually.');
			if (verify === 'dead' && rb) {
				log('Restarting the service with the restored node set...');
				init_action('ravnex', 'stop');
				init_action('ravnex', 'start');
			}
			ST.action = 'rolled_back';
		}
	} else {
		/* via_proxy=1 без смены главного узла: рестарта не было — новые узлы
		 * вступят в силу при следующем рестарте; верифицировать нечего. */
		ST.verify = { restarted: false, verdict: null,
			note: 'сервис не перезапускался — новые узлы применятся при следующем рестарте' };
	}

	const added = added_total;
	log(sprintf('%s nodes added, %s removed.', added, removed_total));
	log('Successfully updated subscriptions.');

	ST.totals = { before: before_total, after: kept_total + added_total,
		kept: kept_total, added: added, removed: removed_total };
	if (ST.action !== 'rolled_back')
		ST.action = 'applied';
	ST.running = false;
	wstatus(ST);
	const ev_sum = sprintf('узлов: было %d, стало %d (+%d/−%d)',
		before_total, kept_total + added_total, added, removed_total);
	if (ST.action === 'rolled_back')
		try { ev_emit('subscribe', 'rolled_back', '',
			ev_sum + ' — новый набор узлов не прошёл проверку старта, узлы восстановлены из бекапа'); } catch (e) {}
	else
		try { ev_emit('subscribe', 'done', '',
			ev_sum + ((ST.verify && ST.verify.restarted === false) ?
				' (применится при следующем рестарте)' : '')); } catch (e) {}
}

if (!isEmpty(subscription_urls))
	try {
		call(main);
	} catch(e) {
		log('[FATAL ERROR] An error occurred during updating subscriptions:');
		log(sprintf('%s: %s', e.type, e.message));
		log(e.stacktrace[0].context);

		ST.running = false;
		ST.action = 'failed';
		ST.reason = sprintf('%s: %s', e.type, e.message);
		wstatus(ST);
		try { ev_emit('subscribe', 'failed', '',
			'ошибка обновления подписок: ' + sprintf('%s: %s', e.type, e.message)); } catch (x) {}

		log('Restarting service...');
		init_action('ravnex', 'stop');
		init_action('ravnex', 'start');
	}
