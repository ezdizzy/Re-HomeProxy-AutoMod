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

import { urldecode, urlencode, urldecode_params } from 'luci.http';
import { init_action } from 'luci.sys';

import {
	wGET, decodeBase64Str, getTime, isEmpty, parseURL,
	validation, validate_node_config, shellQuote, HP_DIR, RUN_DIR
} from 'homeproxy';

import { access, stat, popen } from 'fs';

import { emit as ev_emit } from 'eventbus';

/* Single shared share-link parser (also used by import_link.uc) — replacing the
 * drifted embedded copy that used to lose new features (e.g. hysteria2 port
 * hopping) whenever only one of the two copies was updated. */
import { parse_uri } from 'node_parse';

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

/* Some exports put scalars where sing-box/Xray schemas expect objects (mieru
 * "transport": "UDP", hysteria2 "obfs": "salamander", ...) — property access on
 * a scalar is a fatal "left-hand side expression is not an array or object". */
function as_obj(v) {
	return (type(v) === 'object') ? v : {};
}

/* UCI config start */
const uci = cursor();

const uciconfig = 'homeproxy';
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
/* Ф3.1: legacy custom/custom_json read as the working mode (D23). */
const routing_mode_eff = (routing_mode === 'custom' || routing_mode === 'custom_json')
	? 'proxy_banned_ru' : routing_mode;
let main_node, main_udp_node;
if (routing_mode_eff !== 'custom') {
	main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';
	main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
}
/* UCI config end */

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

/* Common var start */
const node_cache = {},
      node_result = [];

const ubus = connect();
const sing_features = ubus.call('luci.homeproxy', 'singbox_get_features', {}) || {};
/* Common var end */

/* Log */
system(`mkdir -p ${RUN_DIR}`);
function log(...args) {
	const logfile = open(`${RUN_DIR}/homeproxy.log`, 'a');
	logfile.write(`${getTime()} [SUBSCRIBE] ${join(' ', args)}\n`);
	logfile.close();
}

/* ── Ф5.1 (аудит «подписки и rule-set»): безопасный цикл обновления ────────
 * Статус-файл /var/run/homeproxy/subscription_update.json (атомарно tmp+mv,
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
		['main_udp_urltest_preferred', 'main_udp_urltest_preferred']
	];
	for (let p in ptrs) {
		if (doc[p[0]] != null)
			uci.set(uciconfig, ucimain, p[1], '' + doc[p[0]]);
	}
	const lists = [['main_urltest_nodes'], ['main_udp_urltest_nodes']];
	for (let l in lists) {
		uci.delete(uciconfig, ucimain, l[0]);
		if (type(doc[l[0]]) === 'array')
			map(doc[l[0]], (x) => uci.set(uciconfig, ucimain, l[0], '' + x));
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

function parse_singbox_outbound(ob, companion_map) {
	const proxy_types = ['vless', 'vmess', 'trojan', 'shadowsocks', 'naive',
	                     'tuic', 'hysteria', 'hysteria2', 'wireguard', 'ssh', 'mieru', 'anytls',
	                     'trusttunnel', 'socks', 'http'];
	if (type(ob) !== 'object' || !(ob.type in proxy_types)) return null;
	/* Skip hidden companion outbounds (e.g. ShadowTLS wrappers tagged §hide§) */
	if (ob.tag && match(ob.tag, /§hide§/)) return null;

	const tls = as_obj(ob.tls);
	const utls = as_obj(tls.utls);
	const reality = as_obj(tls.reality);
	/* mieru (and some panels) use a STRING transport ("UDP"/"TCP"/"ws") — it is
	 * read as mieru_protocol below; only an object carries V2Ray transport. */
	const tr = as_obj(ob.transport);

	let config = {
		label: ob.tag || null,
		type: ob.type,
		address: ob.server || null,
		port: (ob.server_port != null) ? '' + ob.server_port : null,
		username: ob.username || ob.user || null,
		password: ob.password || null,
		tls: tls.enabled ? '1' : '0',
		tls_sni: tls.server_name || null,
		tls_insecure: tls.insecure ? '1' : null,
		tls_alpn: tls.alpn || null,
		tls_reality: reality.enabled ? '1' : null,
		tls_reality_public_key: reality.enabled ? (reality.public_key || null) : null,
		tls_reality_short_id: reality.enabled ? (reality.short_id || null) : null,
		tls_utls: (sing_features.with_utls && utls.enabled) ? (utls.fingerprint || null) : null,
	};

	/* V2Ray transport (vless / vmess / trojan) */
	if (tr.type) {
		config.transport = tr.type;
		switch (tr.type) {
		case 'grpc':
			config.grpc_servicename = tr.service_name || null;
			break;
		case 'ws':
			config.ws_host = (type(tr.headers) === 'object' && tr.headers.Host) ? tr.headers.Host : null;
			config.ws_path = tr.path || null;
			break;
		case 'httpupgrade':
			config.httpupgrade_host = tr.host || null;
			config.http_path = tr.path || null;
			break;
		case 'http':
			config.http_host = tr.host ? [tr.host] : null;
			config.http_path = tr.path || null;
			break;
		case 'xhttp':
			config.http_path = tr.path || null;
			config.http_host = tr.host || null;
			config.xhttp_mode = tr.mode || null;
			/* Accept both dialects: hiddify camelCase (what the Hiddify app exports) and
			 * sing-box snake_case. */
			config.xhttp_padding_bytes = tr.xPaddingBytes || tr.x_padding_bytes || null;
			config.xhttp_sc_max_each_post_bytes = tr.scMaxEachPostBytes || tr.sc_max_each_post_bytes || null;
			config.xhttp_sc_min_posts_interval_ms = tr.scMinPostsIntervalMs || tr.sc_min_posts_interval_ms || null;
			if (!isEmpty(tr.headers))
				config.xhttp_headers = sprintf('%J', tr.headers);
			/* Split download — hiddify `downloadSettings` or sing-box `download`. */
			let dl = tr.downloadSettings || tr.download;
			if (type(dl) === 'object') {
				let dl_tls = as_obj(dl.tls);
				config.xhttp_download_path = dl.path || null;
				config.xhttp_download_host = dl.host || null;
				config.xhttp_download_server = dl.server || dl.address || null;
				config.xhttp_download_port = (dl.server_port != null && dl.server_port !== 0) ? ('' + dl.server_port) :
				                             (dl.port != null ? ('' + dl.port) : null);
				if (dl_tls.enabled) {
					config.xhttp_download_security = 'tls';
					config.xhttp_download_sni = dl_tls.server_name || null;
					config.xhttp_download_alpn = (type(dl_tls.alpn) === 'array') ? join(',', dl_tls.alpn) : (dl_tls.alpn || null);
					const dl_utls = dl_tls.utls || {};
					config.xhttp_download_fp = dl_utls.fingerprint || null;
				}
			}
			break;
		}
	}

	switch (ob.type) {
	case 'vless':
		config.uuid = ob.uuid || null;
		config.vless_flow = ob.flow || null;
		config.packet_encoding = ob.packet_encoding || null;
		break;
	case 'vmess':
		config.uuid = ob.uuid || null;
		config.vmess_alterid = ob.alter_id || null;
		break;
	case 'shadowsocks':
		config.shadowsocks_encrypt_method = ob.method || null;
		if (ob.detour && companion_map[ob.detour]) {
			const stls = as_obj(companion_map[ob.detour]);
			config.address = stls.server || null;
			config.port = (stls.server_port != null) ? '' + stls.server_port : null;
			config.shadowtls_enabled = '1';
			config.shadowtls_password = stls.password || null;
			config.shadowtls_version = (stls.version != null) ? '' + stls.version : '3';
			const stls_tls = as_obj(stls.tls);
			const stls_utls = as_obj(stls_tls.utls);
			config.tls = stls_tls.enabled ? '1' : '0';
			config.tls_sni = stls_tls.server_name || null;
			config.tls_insecure = stls_tls.insecure ? '1' : null;
			config.tls_utls = (sing_features.with_utls && stls_utls.enabled) ? (stls_utls.fingerprint || null) : null;
		}
		break;
	case 'naive':
		config.naive_quic = ob.quic ? '1' : null;
		config.naive_extra_headers = !isEmpty(ob.extra_headers) ? sprintf('%J', ob.extra_headers) : null;
		break;
	case 'tuic':
		config.uuid = ob.uuid || null;
		config.tuic_congestion_control = ob.congestion_control || null;
		config.tuic_udp_relay_mode = ob.udp_relay_mode || null;
		/* UCI key is tuic_enable_zero_rtt — what the config generator reads */
		config.tuic_enable_zero_rtt = ob.zero_rtt_handshake ? '1' : null;
		config.tuic_udp_over_stream = ob.udp_over_stream ? '1' : null;
		config.tuic_heartbeat = ob.heartbeat || null;
		break;
	case 'hysteria':
		/* Hysteria v1 (sing-box-extended / hiddify-core) */
		config.hysteria_protocol = ob.protocol || 'udp';
		config.hysteria_auth_type = (ob.auth || ob.auth_str) ? 'string' : null;
		config.hysteria_auth_payload = ob.auth_str || ob.auth || null;
		config.hysteria_obfs_password = (type(ob.obfs) === 'string') ? ob.obfs : null;
		config.hysteria_up_mbps = (ob.up_mbps != null) ? '' + ob.up_mbps : null;
		config.hysteria_down_mbps = (ob.down_mbps != null) ? '' + ob.down_mbps : null;
		config.hysteria_recv_window_conn = (ob.recv_window_conn != null) ? '' + ob.recv_window_conn : null;
		config.hysteria_revc_window = (ob.recv_window != null) ? '' + ob.recv_window : null;
		config.hysteria_disable_mtu_discovery = ob.disable_mtu_discovery ? '1' : null;
		break;
	case 'hysteria2':
		config.hysteria_up_mbps = (ob.up_mbps != null) ? '' + ob.up_mbps : null;
		config.hysteria_down_mbps = (ob.down_mbps != null) ? '' + ob.down_mbps : null;
		if (type(ob.obfs) === 'object') {
			config.hysteria_obfs_type = ob.obfs.type || null;
			config.hysteria_obfs_password = ob.obfs.password || null;
		} else if (ob.obfs)
			/* String shorthand ("obfs": "salamander") used by some panels */
			config.hysteria_obfs_type = '' + ob.obfs;
		/* Port hopping: server_ports entries are "min:max"; hop_interval is a
		 * duration string ("30s") which strToTime() passes through untouched.
		 * Hopping-only nodes ship NO server_port — the first range's floor
		 * becomes the primary port (the core still requires one). */
		if (type(ob.server_ports) === 'array' && length(ob.server_ports)) {
			config.hysteria_hopping_port = ob.server_ports;
			if (isEmpty(config.port)) {
				const hy2_first = replace('' + ob.server_ports[0], /:.*$/, '');
				if (match(hy2_first, /^\d+$/))
					config.port = hy2_first;
			}
		}
		if (ob.hop_interval != null)
			config.hysteria_hop_interval = '' + ob.hop_interval;
		break;
	case 'wireguard':
		config.wireguard_private_key = ob.private_key || null;
		/* Ф5.3 (аудит 51): the generator reads PEER public key from
		 * wireguard_peer_public_key — the old wireguard_public_key name was
		 * silently ignored by the schema (peer key lost on every imported WG
		 * subscription node; stale field is dropped by the update loop). */
		config.wireguard_peer_public_key = ob.peer_public_key || null;
		config.wireguard_pre_shared_key = ob.pre_shared_key || null;
		config.wireguard_local_address = ob.local_address || null;
		config.wireguard_mtu = (ob.mtu != null) ? '' + ob.mtu : null;
		if (type(ob.reserved) === 'array')
			config.wireguard_reserved = map(ob.reserved, s => '' + s);
		break;
	case 'ssh':
		config.ssh_host_key = ob.host_key || null;
		config.ssh_host_key_algo = (type(ob.host_key_algorithms) === 'array') ?
			((length(ob.host_key_algorithms) > 1) ? ob.host_key_algorithms : ob.host_key_algorithms[0]) :
			(ob.host_key_algorithms || null);
		config.ssh_priv_key = ob.private_key || null;
		config.ssh_priv_key_pp = ob.private_key_passphrase || null;
		/* Only honored on hiddify-core (see generate_client); harmless on sing-box-extended */
		config.ssh_udp_over_tcp = (ob.udp_over_tcp != null) ? (ob.udp_over_tcp ? '1' : '0') : null;
		break;
	case 'anytls':
		config.anytls_padding_scheme = ob.padding_scheme || null;
		break;
	case 'trusttunnel':
		/* TrustTunnel (AdGuard's obfuscated VPN; sing-box-extended only). The
		 * node is ALWAYS imported (data survives a core switch); generate_client
		 * skips it when the running build has no with_trusttunnel tag.
		 * username/password land in the generic fields (emitted for non-ssh). */
		config.trusttunnel_congestion_controller = ob.congestion_controller || null;
		/* NetworkList: JSON array ["tcp","udp"] or a string ("tcp" / "tcp\nudp"). */
		if (type(ob.network) === 'array')
			config.trusttunnel_network = map(ob.network, (n) => '' + n);
		else if (!isEmpty(ob.network))
			config.trusttunnel_network = filter(split(replace('' + ob.network, /[,\n\r]+/g, ' '), ' '), (n) => length(n));
		config.trusttunnel_quic = ob.quic ? '1' : null;
		config.trusttunnel_health_check = ob.health_check ? '1' : null;
		config.trusttunnel_cwnd = (ob.cwnd != null) ? '' + ob.cwnd : null;
		if (type(as_obj(ob.multiplex).enabled) === 'boolean' && ob.multiplex.enabled) {
			config.trusttunnel_multiplex = '1';
			config.trusttunnel_mp_max_connections = (ob.multiplex.max_connections != null) ? '' + ob.multiplex.max_connections : null;
			config.trusttunnel_mp_min_streams = (ob.multiplex.min_streams != null) ? '' + ob.multiplex.min_streams : null;
			config.trusttunnel_mp_max_streams = (ob.multiplex.max_streams != null) ? '' + ob.multiplex.max_streams : null;
		}
		break;
	case 'socks':
		config.socks_version = (ob.version != null) ? '' + ob.version : null;
		break;
	case 'mieru':
		/* The generator forces server_port=0 for mieru and passes the port ONLY
		 * via mieru_port_range — every imported mieru needs that range set. */
		config.port = '0';
		if (type(ob.portBindings) === 'array' && type(ob.portBindings[0]) === 'object') {
			/* Hiddify format */
			config.mieru_protocol = ob.portBindings[0].protocol || null;
			config.mieru_port_range = ob.portBindings[0].portRange || null;
		} else if (type(ob.server_ports) === 'array' && ob.server_ports[0]) {
			/* sing-box multi-port format */
			config.mieru_port_range = ob.server_ports[0] || null;
		}
		/* Protocol: sing-box schema carries it as a STRING transport ("UDP"/"TCP");
		 * absent → infer from the tag. */
		config.mieru_protocol = (type(ob.transport) === 'string') ? ob.transport :
			((ob.tag && match(ob.tag, /UDP/i)) ? 'UDP' : ((ob.tag && match(ob.tag, /TCP/i)) ? 'TCP' : null));
		/* Single-port mieru (server + server_port, no ranges): synthesize the
		 * "min:max" range so the generator emits a usable outbound. */
		if (isEmpty(config.mieru_port_range) && ob.server_port != null && ob.server_port !== 0)
			config.mieru_port_range = ob.server_port + ':' + ob.server_port;
		config.mieru_multiplexing = ob.multiplexing || null;
		config.mieru_handshake_mode = ob.handshake_mode || null;
		break;
	}

	return config;
}

/* Parse ONE Xray/V2Ray outbound object (settings.vnext|servers + streamSettings)
 * into a HomeProxy node config. `remarks` is the config-level friendly name (Xray
 * outbounds don't carry it). Mirrors parse_singbox_outbound for the Xray schema. */
function parse_xray_outbound(ob, remarks) {
	const proxy_types = ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria'];
	if (type(ob) !== 'object') return null;
	const proto = ob.protocol;
	if (!(proto in proxy_types)) return null;

	const st = as_obj(ob.settings);
	const ss = as_obj(ob.streamSettings);
	const net = ss.network || 'tcp';
	const security = ss.security || 'none';
	const tls_s = as_obj(ss.tlsSettings);
	const reality = as_obj(ss.realitySettings);

	/* Hysteria (v1/v2): non-standard Xray shape — server is in settings.{address,port}
	 * and auth in streamSettings.hysteriaSettings. Needs QUIC support in sing-box. */
	if (proto === 'hysteria') {
		if (!sing_features.with_quic) {
			log(sprintf('Skipping hysteria node (sing-box has no QUIC): %s.', remarks || st.address));
			return null;
		}
		const hyS = as_obj(ss.hysteriaSettings);
		const is_v2 = (('' + (st.version || hyS.version || '2')) === '2');
		let hcfg = {
			label: remarks || null,
			type: is_v2 ? 'hysteria2' : 'hysteria',
			address: st.address || null,
			port: (st.port != null) ? ('' + st.port) : null,
			tls: '1',
			tls_sni: tls_s.serverName || null,
			tls_insecure: tls_s.allowInsecure ? '1' : null,
			tls_alpn: (type(tls_s.alpn) === 'array') ? tls_s.alpn : (tls_s.alpn ? [tls_s.alpn] : null),
			tls_utls: sing_features.with_utls ? (tls_s.fingerprint || null) : null
		};
		if (is_v2) {
			hcfg.password = hyS.auth || null;
			if (type(hyS.obfs) === 'object') {
				hcfg.hysteria_obfs_type = hyS.obfs.type || null;
				hcfg.hysteria_obfs_password = hyS.obfs.password || null;
			} else if (hyS.obfs) {
				/* Xray shorthand: "obfs": "salamander" + "obfsPassword": "..." */
				hcfg.hysteria_obfs_type = '' + hyS.obfs;
				hcfg.hysteria_obfs_password = hyS.obfsPassword || null;
			}
		} else {
			hcfg.hysteria_protocol = 'udp';
			hcfg.hysteria_auth_type = hyS.auth ? 'string' : null;
			hcfg.hysteria_auth_payload = hyS.auth || null;
		}
		return hcfg;
	}

	const vnext = (st.vnext && st.vnext[0]) ? st.vnext[0] : null;
	const server = (st.servers && st.servers[0]) ? st.servers[0] : null;
	const user = (vnext && vnext.users && vnext.users[0]) ? vnext.users[0] : {};

	let config = {
		label: remarks || null,
		type: proto,
		address: vnext ? vnext.address : (server ? server.address : null),
		port: vnext ? ('' + vnext.port) : (server ? ('' + server.port) : null),
		tls: (security in ['tls', 'xtls', 'reality']) ? '1' : '0',
		tls_sni: tls_s.serverName || reality.serverName || null,
		tls_insecure: (tls_s.allowInsecure || reality.allowInsecure) ? '1' : null,
		tls_alpn: (type(tls_s.alpn) === 'array') ? tls_s.alpn : (tls_s.alpn ? [tls_s.alpn] : null),
		tls_reality: (security === 'reality') ? '1' : null,
		tls_reality_public_key: (security === 'reality') ? (reality.publicKey || null) : null,
		tls_reality_short_id: (security === 'reality') ? (reality.shortId || null) : null,
		tls_utls: sing_features.with_utls ? (tls_s.fingerprint || reality.fingerprint || null) : null
	};

	switch (proto) {
	case 'vless':
		config.uuid = user.id || null;
		config.vless_flow = user.flow || null;
		break;
	case 'vmess':
		config.uuid = user.id || null;
		config.vmess_alterid = (user.alterId != null) ? ('' + user.alterId) : null;
		config.vmess_encrypt = user.security || 'auto';
		config.vmess_global_padding = '1';
		break;
	case 'trojan':
		config.password = server ? server.password : null;
		break;
	case 'shadowsocks':
		config.shadowsocks_encrypt_method = server ? server.method : null;
		config.password = server ? server.password : null;
		break;
	case 'socks':
	case 'http':
		const su = (server && server.users && server.users[0]) ? server.users[0] : {};
		config.username = su.user || null;
		config.password = su.pass || null;
		if (proto === 'socks')
			config.socks_version = '5';
		break;
	}

	/* V2Ray transport */
	if (net && net !== 'tcp') {
		config.transport = (net === 'h2') ? 'http' : net;
		switch (config.transport) {
		case 'ws':
			const wsS = as_obj(ss.wsSettings);
			config.ws_host = (type(wsS.headers) === 'object' && wsS.headers.Host) ? wsS.headers.Host : (wsS.host || null);
			config.ws_path = wsS.path || null;
			break;
		case 'grpc':
			const grpcS = as_obj(ss.grpcSettings);
			config.grpc_servicename = grpcS.serviceName || null;
			break;
		case 'httpupgrade':
			const huS = as_obj(ss.httpupgradeSettings);
			config.httpupgrade_host = huS.host || null;
			config.http_path = huS.path || null;
			break;
		case 'http':
			const hS = as_obj(ss.httpSettings);
			config.http_host = hS.host ? ((type(hS.host) === 'array') ? hS.host : [hS.host]) : null;
			config.http_path = hS.path || null;
			break;
		case 'xhttp':
			const xS = as_obj(ss.xhttpSettings);
			config.http_path = xS.path || null;
			config.http_host = xS.host || null;
			config.xhttp_mode = xS.mode || null;
			break;
		}
	} else if (net === 'tcp' && type(ss.tcpSettings) === 'object' &&
	           type(ss.tcpSettings.header) === 'object' &&
	           ss.tcpSettings.header.type === 'http') {
		config.transport = 'http';
		const req = as_obj(ss.tcpSettings.header.request);
		config.http_host = (type(req.headers) === 'object' && req.headers.Host) ?
			((type(req.headers.Host) === 'array') ? req.headers.Host : [req.headers.Host]) : null;
		config.http_path = (type(req.path) === 'array') ? req.path[0] : (req.path || null);
	}

	return config;
}

/* Parse ONE full Xray config object (an element of the subscription array): pick
 * its proxy outbound (the one tagged "proxy", else the first real proxy outbound
 * that isn't an internal helper like direct/block/dns or a routing upstream). */
function parse_xray_config(cfg) {
	if (type(cfg) !== 'object' || type(cfg.outbounds) !== 'array')
		return null;

	const skip = ['freedom', 'blackhole', 'dns', 'loopback'];
	let chosen = null;
	for (let ob in cfg.outbounds) {
		if (type(ob) !== 'object')
			continue;
		if (ob.tag === 'proxy') {
			chosen = ob;
			break;
		}
	}
	if (!chosen)
		for (let ob in cfg.outbounds) {
			if (type(ob) !== 'object')
				continue;
			if (ob.protocol in skip)
				continue;
			if (ob.tag && match(ob.tag, /upstream/))
				continue;
			chosen = ob;
			break;
		}
	if (!chosen)
		return null;

	return parse_xray_outbound(chosen, cfg.remarks);
}

const ST = { running: true, ts: time(), action: 'running', reason: '',
	groups: [], totals: null, backup: null, verify: null };
const group_index = {};

function main() {
	/* Per-group «before» counts — read-only, BEFORE any mutation (Ф5.1 diff). */
	const before_by_group = {};
	let before_total = 0;
	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (!cfg.grouphash)
			return null;
		const g = '' + cfg.grouphash;
		before_by_group[g] = (before_by_group[g] || 0) + 1;
		before_total++;
		return null;
	});

	let service_was_stopped = false;
	if (via_proxy !== '1') {
		log('Stopping service...');
		init_action('homeproxy', 'stop');
		service_was_stopped = true;
	}
	wstatus(ST);

	for (let url in subscription_urls) {
		url = replace(url, /#.*$/, '');

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

		/* Try Hiddify JSON format first: User-Agent triggers sing-box JSON on Hiddify Manager servers */
		let res = wGET(url, 'HiddifyNext/2.0.0');
		let nodes;

		if (!isEmpty(res) && match(trim(res), /^\s*\{/)) {
			let sub_json;
			try { sub_json = json(res); } catch(e) {}
			if (sub_json && type(sub_json.outbounds) === 'array') {
				const companion_map = {};
				for (let ob in sub_json.outbounds) {
					if (type(ob) === 'object' && ob.tag && match(ob.tag, /§hide§/))
						companion_map[ob.tag] = ob;
				}
				nodes = filter(
					map(sub_json.outbounds, ob => parse_singbox_outbound(ob, companion_map)),
					c => !isEmpty(c)
				);
				log(sprintf('Received sing-box JSON subscription from %s.', url));
			}
		}

		/* Xray/V2Ray JSON config array (e.g. connliberty): an ARRAY of full Xray
		 * configs, each with .outbounds and a .remarks name. The first fetch above
		 * (HiddifyNext UA) already returns it on app-gated servers. */
		if (isEmpty(nodes) && !isEmpty(res) && match(trim(res), /^\s*\[/)) {
			let xray_arr;
			try { xray_arr = json(res); } catch(e) {}
			if (type(xray_arr) === 'array' && length(xray_arr) &&
			    type(xray_arr[0]) === 'object' && xray_arr[0].outbounds) {
				nodes = filter(
					map(xray_arr, cfg => parse_xray_config(cfg)),
					c => !isEmpty(c)
				);
				log(sprintf('Received Xray JSON subscription from %s.', url));
			}
		}

		if (isEmpty(nodes)) {
			/* Fallback: fetch with configured user_agent */
			res = wGET(url, user_agent);

			/* Empty or HTML response: server may require /raw suffix (e.g. HAPP-style
			 * subscription servers that serve a web page by default). */
			if (isEmpty(res) || match(res, /^\s*</)) {
				const rawUrl = replace(url, /\/*$/, '') + '/raw';
				log(sprintf('%s from %s, retrying with /raw.',
					isEmpty(res) ? 'Empty response' : 'HTML response', url));
				const rawRes = wGET(rawUrl, user_agent);
				if (!isEmpty(rawRes) && !match(rawRes, /^\s*</))
					res = rawRes;
			}

			if (isEmpty(res)) {
				log(sprintf('Failed to fetch resources from %s.', url));
				grp.status = 'fetch_failed';
				continue;
			}

			try {
				const parsed = json(res);
				if (type(parsed) === 'array' && length(parsed) &&
				    type(parsed[0]) === 'object' && parsed[0].outbounds) {
					/* Xray/V2Ray JSON config array */
					nodes = filter(map(parsed, cfg => parse_xray_config(cfg)), c => !isEmpty(c));
				} else if (type(parsed) === 'object' && type(parsed.servers) === 'array') {
					/* Shadowsocks SIP008 format — index-guarded: an arbitrary JSON
					 * object used to fall through here and crash on nodes[0] of a
					 * non-array, masking the real "unsupported format" error. */
					nodes = parsed.servers;
					if (length(nodes) && type(nodes[0]) === 'object' &&
					    nodes[0].server && nodes[0].method)
						map(nodes, (_, i) => nodes[i].nodetype = 'sip008');
				} else {
					log(sprintf('Unsupported subscription JSON from %s.', url));
					nodes = [];
				}
			} catch(e) {
				/* Base64 (or plain link-list). Strip ALL whitespace first: CRLF
				 * line endings left a trailing \r on every link (broken ports,
				 * whole subscription rejected), and inner spaces broke the decode.
				 * The old `replace(decoded,/ /g,'_')` corrupted decoded LABELS. */
				const b64 = replace(res, /[ \t\r\n]+/g, '');
				const decoded = decodeBase64Str(b64);
				if (decoded && match(trim(decoded), /^(ss|ssr|vmess|vless|trojan|hysteria2?|tuic|socks|http|ssh|wireguard|mieru|anytls):\/\//))
					nodes = filter(split(decoded, /[\r\n]+/), (l) => length(trim(l)));
				else
					nodes = filter(split(trim(res), /[\r\n]+/), (l) => length(trim(l)));
			}
		}

		const res_html = !isEmpty(res) && match(res, /^\s*</);
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
			const confHash = strhash(sprintf('%J', config)),
			      nameHash = strhash(groupHash + '|' + label);
			config.label = label;

			if (filter_check(config.label))
				log(sprintf('Skipping blacklist node: %s.', config.label));
			else if (node_cache[groupHash][confHash] || node_cache[groupHash][nameHash])
				log(sprintf('Skipping duplicate node: %s.', config.label));
			else {
				if (config.tls === '1' && allow_insecure === '1')
					config.tls_insecure = '1';
				if (config.type in ['vless', 'vmess'])
					config.packet_encoding = packet_encoding;

				config.grouphash = groupHash;
				push(node_result, []);
				push(node_result[length(node_result)-1], config);
				node_cache[groupHash][confHash] = config;
				node_cache[groupHash][nameHash] = config;

				count++;
			}
		}

		grp.parsed = count;
		grp.status = (count > 0) ? 'ok' : (res_html ? 'html' : 'no_valid');
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
			init_action('homeproxy', 'start');
		}
		wstatus(ST);
		try { ev_emit('subscribe', 'aborted', '',
			'обновление отклонено: ни один узел не распознан — узлы не тронуты'); } catch (e) {}
		return false;
	}

	/* Ф5.1 pass 1 (read-only): план удалений и число выживающих. */
	let kept_total = 0, removed_total = 0;
	const plan_remove = [];
	uci.foreach(uciconfig, ucinode, (cfg) => {
		/* Nodes created by the user */
		if (!cfg.grouphash)
			return null;

		/* Empty object - failed to fetch nodes */
		if (length(node_cache[cfg.grouphash]) === 0)
			return null;

		if (!node_cache[cfg.grouphash] || !node_cache[cfg.grouphash][cfg['.name']]) {
			push(plan_remove, { sid: cfg['.name'],
				label: cfg.label || cfg.name || cfg['.name'],
				ghash: '' + cfg.grouphash });
			removed_total++;
			const gr = group_index['' + cfg.grouphash];
			if (gr) gr.removed++;
		} else {
			node_cache[cfg.grouphash][cfg['.name']].isExisting = true;
			kept_total++;
			const gr = group_index['' + cfg.grouphash];
			if (gr) gr.kept++;
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
	 * мутаций дело не доходит). */
	if (before_total > 0 && kept_total === 0 && added_total === 0) {
		log(sprintf('ABORT: the update would leave 0 of %d subscription nodes.', before_total));
		ST.action = 'aborted';
		ST.reason = sprintf('обновление удалило бы все %d подписочных узлов — применено НЕТ', before_total);
		ST.totals = { before: before_total, after: before_total,
			kept: before_total, added: 0, removed: 0 };
		ST.running = false;
		if (service_was_stopped) {
			log('Starting service...');
			init_action('homeproxy', 'start');
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
	let added = 0, removed = 0;
	for (let r in plan_remove) {
		uci.delete(uciconfig, r.sid);
		removed++;
		const grp2 = group_index[r.ghash];
		if (grp2) grp2.removed++;
		log(sprintf('Removing node: %s.', r.label));
	}
	uci.foreach(uciconfig, ucinode, (cfg) => {
		/* Nodes created by the user */
		if (!cfg.grouphash)
			return null;

		/* Empty object - failed to fetch nodes */
		if (length(node_cache[cfg.grouphash]) === 0)
			return null;

		if (!node_cache[cfg.grouphash] || !node_cache[cfg.grouphash][cfg['.name']])
			return null;

		const cached = node_cache[cfg.grouphash][cfg['.name']];
		const user_fields = ['bind_interface'];
		map(keys(cfg), (v) => {
			if (v in cached)
				uci.set(uciconfig, cfg['.name'], v, cached[v]);
			else if (!(v in user_fields))
				uci.delete(uciconfig, cfg['.name'], v);
		});
		/* Also push new fields added by updated parsers to existing nodes */
		map(keys(cached), (v) => {
			if (!(v in cfg) && cached[v] !== null)
				uci.set(uciconfig, cfg['.name'], v, cached[v]);
		});
	});
	for (let nodes in node_result)
		map(nodes, (node) => {
			if (node.isExisting)
				return null;

			/* Section id includes the group hash: two subscriptions shipping the
			 * same label ("Server1" from template providers) previously produced
			 * the SAME section id — the second silently overwrote the first's
			 * node while "added" counted both. NOTE: the loop variable groupHash
			 * is const INSIDE the per-URL loop above and out of scope here —
			 * each parsed node carries its own .grouphash (set when queued). */
			const ghash = node.grouphash || '';
			const nlabel = (type(node.label) === 'string') ? node.label : '';
			const nameHash = strhash(ghash + '|' + nlabel);
			uci.set(uciconfig, nameHash, 'node');
			map(keys(node), (v) => uci.set(uciconfig, nameHash, v, node[v]));

			added++;
			const grp3 = group_index[ghash];
			if (grp3) grp3.added++;
			log(sprintf('Adding node: %s.', node.label));
		});
	uci.commit(uciconfig);

	let need_restart = (via_proxy !== '1');
	if (!isEmpty(main_node)) {
		const first_server = uci.get_first(uciconfig, ucinode);
		if (first_server) {
			let main_urltest_nodes;
			let urltest_empty = false;
			if (main_node === 'urltest') {
				const ut_mode = uci.get(uciconfig, ucimain, 'main_urltest_mode') || 'manual';
				if (ut_mode === 'manual') {
					main_urltest_nodes = filter(uci.get(uciconfig, ucimain, 'main_urltest_nodes'), (v) => {
						if (!uci.get(uciconfig, v)) {
							log(sprintf('Node %s is gone, removing from urltest list.', v));
							return false;
						}
						return true;
					});
					if (!length(main_urltest_nodes)) {
						/* An EMPTY list must be deleted, not set([]): an empty UCI
						 * list write leaves a stale/absent value mismatch behind. */
						uci.delete(uciconfig, ucimain, 'main_urltest_nodes');
						urltest_empty = true;
					}
				} else if (ut_mode === 'prefer') {
					/* Preferred node gone → clear it; the pool falls back to the rest. */
					const pref = uci.get(uciconfig, ucimain, 'main_urltest_preferred');
					if (pref && !uci.get(uciconfig, pref)) {
						log(sprintf('Preferred node %s is gone, clearing preference.', pref));
						uci.delete(uciconfig, ucimain, 'main_urltest_preferred');
					}
				}
				/* auto: implicit pool — nothing to maintain */
			}

			/* Synthetic tags (direct/ByeDPI/Zapret) are not node sections and must not
			 * be treated as missing nodes. */
			const synthetic = ['direct-out', 'byedpi-out', 'zapret-out'];
			if ((main_node === 'urltest') ? urltest_empty :
			    (!(main_node in synthetic) && !uci.get(uciconfig, main_node))) {
				uci.set(uciconfig, ucimain, 'main_node', first_server);
				uci.commit(uciconfig);
				need_restart = true;

				log('Main node is gone, switching to the first node.');
			}

			if (!isEmpty(main_udp_node) && main_udp_node !== 'same') {
				let main_udp_urltest_nodes;
				let udp_urltest_empty = false;
				if (main_udp_node === 'urltest') {
					const ut_mode = uci.get(uciconfig, ucimain, 'main_udp_urltest_mode') || 'manual';
					if (ut_mode === 'manual') {
						main_udp_urltest_nodes = filter(uci.get(uciconfig, ucimain, 'main_udp_urltest_nodes'), (v) => {
							if (!uci.get(uciconfig, v)) {
								log(sprintf('Node %s is gone, removing from UDP urltest list.', v));
								return false;
							}
							return true;
						});
						if (!length(main_udp_urltest_nodes)) {
							uci.set(uciconfig, ucimain, 'main_udp_urltest_nodes', main_udp_urltest_nodes);
							udp_urltest_empty = true;
						}
					} else if (ut_mode === 'prefer') {
						const pref = uci.get(uciconfig, ucimain, 'main_udp_urltest_preferred');
						if (pref && !uci.get(uciconfig, pref)) {
							log(sprintf('Preferred UDP node %s is gone, clearing preference.', pref));
							uci.delete(uciconfig, ucimain, 'main_udp_urltest_preferred');
						}
					}
				}

				if ((main_udp_node === 'urltest') ? udp_urltest_empty :
				    (!(main_udp_node in synthetic) && !uci.get(uciconfig, main_udp_node))) {
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
			init_action('homeproxy', 'stop');
		}
		log('Starting service...');
		init_action('homeproxy', 'start');
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
				init_action('homeproxy', 'stop');
				init_action('homeproxy', 'start');
			}
			ST.action = 'rolled_back';
		}
	} else {
		/* via_proxy=1 без смены главного узла: рестарта не было — новые узлы
		 * вступят в силу при следующем рестарте; верифицировать нечего. */
		ST.verify = { restarted: false, verdict: null,
			note: 'сервис не перезапускался — новые узлы применятся при следующем рестарте' };
	}

	log(sprintf('%s nodes added, %s removed.', added, removed));
	log('Successfully updated subscriptions.');

	ST.totals = { before: before_total, after: kept_total + added_total,
		kept: kept_total, added: added, removed: removed };
	if (ST.action !== 'rolled_back')
		ST.action = 'applied';
	ST.running = false;
	wstatus(ST);
	const ev_sum = sprintf('узлов: было %d, стало %d (+%d/−%d)',
		before_total, kept_total + added_total, added, removed);
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
		init_action('homeproxy', 'stop');
		init_action('homeproxy', 'start');
	}
