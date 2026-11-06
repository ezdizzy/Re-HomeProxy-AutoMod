/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Shared node parsers (Ф9.11): ONE implementation set for the subscription
 * importer, the standalone link importer (import_link.uc) and the UI import
 * RPC (luci.homeproxy app_import_nodes) — no second copy to drift.
 *
 *   parse_uri(uri, log)            — a single share-link (or a pre-parsed
 *                                    sing-box/SIP008 object passthrough)
 *   parse_singbox_outbound(ob, cm, feats) — one sing-box JSON outbound
 *   parse_xray_outbound(ob, remarks, feats) — one Xray/V2Ray outbound
 *   parse_xray_config(cfg, feats)  — one full Xray config (proxy pick)
 *   parse_clash_yaml(text)         — clash/mihomo YAML proxies section
 *   parse_content(res, log, feats) — whole-body format dispatcher
 *
 * Multi-core rule (D34c): nodes of types the RUNNING core cannot load are
 * still imported — the data must survive a core switch; generate_client
 * skips them (core_skipped.json) and the UI shows «Unsupported by core».
 * Only formats sing-box has never supported are rejected outright (vless
 * kcp, encrypted QUIC transport, hysteria wechat-video/faketcp).
 *
 * `log` is an injected callback (no-op by default) so callers can route
 * diagnostics where they like.
 */
'use strict';

import { urldecode, urlencode, urldecode_params } from 'luci.http';
import { parseURL, decodeBase64Str, validation, isEmpty } from 'homeproxy';
import { connect } from 'ubus';

/* Core capabilities are fetched LAZILY (first use): the module is imported
 * by rpcd's luci.homeproxy too, where a module-level ubus self-call would
 * run before the object is registered and could kill the whole object
 * load. A failed call degrades to {} — every capability reads as off.
 * Embedding hosts (rpcd) should push their LOCAL feature map through
 * set_features() instead: a nested ubus self-call from inside an rpcd
 * handler deadlocks (the single-threaded handler waits for itself — caught
 * live, the first app_import_nodes smoke timed out exactly there). */
let sing_features_cache = null;
function sing_features() {
	if (sing_features_cache == null) {
		sing_features_cache = {};
		try {
			sing_features_cache = connect().call('luci.homeproxy', 'singbox_get_features', {}) || {};
		} catch (e) {
			sing_features_cache = {};
		}
	}
	return sing_features_cache;
};

/* Push a precomputed feature map (rpcd embeds singbox_features_local). */
export function set_features(f) {
	sing_features_cache = (type(f) === 'object') ? f : {};
};

/* Hysteria2 port-hopping spec: "443", "443-8443", "443,5000-6000" (colon ranges
 * accepted too) → sing-box server_ports entries ("min:max"); null on garbage. */
export function parse_port_list(list) {
	let ports = [];
	for (let tok in split('' + list, ',')) {
		tok = trim(tok);
		if (match(tok, /^\d+$/))
			push(ports, tok + ':' + tok);
		else if (match(tok, /^\d+-\d+$/))
			push(ports, replace(tok, /-/, ':'));
		else if (match(tok, /^\d+:\d+$/))
			push(ports, tok);
		else
			return null;
	}
	return length(ports) ? ports : null;
};

/* Some exports put scalars where sing-box/Xray schemas expect objects (mieru
 * "transport": "UDP", hysteria2 "obfs": "salamander", ...) — property access on
 * a scalar is a fatal "left-hand side expression is not an array or object". */
function as_obj(v) {
	return (type(v) === 'object') ? v : {};
};

/* ── Clash/mihomo YAML (Ф9.11) ─────────────────────────────────────────────
 * Panels emit the `proxies:` section in two shapes: inline flow maps
 * ("- {name: x, type: ss, ...}") and block entries ("- name: x" plus deeper
 * "key: value" lines with nested maps/lists). Anchors, multi-line scalars and
 * tags are outside the clash dialect and are skipped with a reason. */

function yaml_unquote(s) {
	s = trim(s);
	const n = length(s);
	if (n >= 2 && ((substr(s, 0, 1) === '"' && substr(s, n - 1, 1) === '"') ||
	               (substr(s, 0, 1) === "'" && substr(s, n - 1, 1) === "'")))
		return substr(s, 1, n - 2);
	return s;
};

/* Split "a: 1, b: [x, y], c: {d: e}" on top-level commas (quotes/depth aware). */
function flow_split(s) {
	const parts = [];
	let depth = 0, quote = null, cur = '';
	for (let i = 0; i < length(s); i++) {
		const c = substr(s, i, 1);
		if (quote != null) {
			cur = cur + c;
			if (c === quote)
				quote = null;
		} else if (c === '"' || c === "'") {
			quote = c;
			cur = cur + c;
		} else if (c === '{' || c === '[') {
			depth++;
			cur = cur + c;
		} else if (c === '}' || c === ']') {
			depth--;
			cur = cur + c;
		} else if (c === ',' && depth === 0) {
			push(parts, cur);
			cur = '';
		} else
			cur = cur + c;
	}
	if (trim(cur) !== '')
		push(parts, cur);
	return parts;
};

/* "key: value" → [key, rawValue] (null when no top-level colon; a colon
 * followed by a non-space — an URL — belongs to the value). */
function flow_kv(tok) {
	let depth = 0, quote = null;
	for (let i = 0; i < length(tok); i++) {
		const c = substr(tok, i, 1);
		if (quote != null) {
			if (c === quote)
				quote = null;
		} else if (c === '"' || c === "'")
			quote = c;
		else if (c === '{' || c === '[')
			depth++;
		else if (c === '}' || c === ']')
			depth--;
		else if (c === ':' && depth === 0) {
			const rest = substr(tok, i + 1);
			if (rest === '' || substr(rest, 0, 1) === ' ')
				return [trim(substr(tok, 0, i)), trim(rest)];
		}
	}
	return null;
};

/* Flow value: "[a, b]" → array, "{...}" → object, else unquoted scalar. */
function yaml_scalar(s) {
	s = trim(s);
	if (length(s) >= 2 && substr(s, 0, 1) === '[' && substr(s, length(s) - 1, 1) === ']') {
		const inner = substr(s, 1, length(s) - 2);
		return (length(trim(inner))) ? map(flow_split(inner), (x) => yaml_unquote(x)) : [];
	}
	if (length(s) >= 2 && substr(s, 0, 1) === '{' && substr(s, length(s) - 1, 1) === '}') {
		const inner = substr(s, 1, length(s) - 2);
		const obj = {};
		for (let tok in flow_split(inner)) {
			const kv = flow_kv(tok);
			if (kv)
				obj[kv[0]] = yaml_scalar(kv[1]);
		}
		return obj;
	}
	return yaml_unquote(s);
};

/* Parse lines[i..] (indent ≥ base) as a block map into `out`; returns the
 * index of the first line NOT consumed. Handles nested block maps ("key:"
 * with deeper lines) and block lists ("- item" for the pending key). */
function yaml_block_map(lines, i, base, out) {
	let pending = null;
	while (i < length(lines)) {
		const raw = replace(lines[i], /\r$/, '');
		if (!length(trim(raw))) {
			i++;
			continue;
		}
		if (!match(raw, /^[ \t]/))
			break;
		const ind = length(raw) - length(replace(raw, /^[ \t]+/, ''));
		if (ind < base)
			break;
		const body = trim(raw);
		if (match(body, /^- /)) {
			if (pending != null) {
				const cur = out[pending];
				const arr = (type(cur) === 'array') ? cur : [];
				push(arr, yaml_scalar(substr(body, 2)));
				out[pending] = arr;
				pending = null;
			}
			i++;
			continue;
		}
		const kv = flow_kv(body);
		if (!kv) {
			i++;
			continue;
		}
		if (kv[1] === '') {
			/* "key:" — nested map or block list on the deeper lines */
			pending = kv[0];
			i++;
			if (i < length(lines)) {
				const raw2 = replace(lines[i], /\r$/, '');
				if (!match(raw2, /^[ \t]/))
					continue;
				const ind2 = length(raw2) - length(replace(raw2, /^[ \t]+/, ''));
				if (ind2 > base && !match(trim(raw2), /^- /)) {
					const sub = {};
					i = yaml_block_map(lines, i, ind2, sub);
					out[pending] = sub;
					pending = null;
				}
			}
		} else {
			out[kv[0]] = yaml_scalar(kv[1]);
			pending = null;
			i++;
		}
	}
	return i;
};

/* Parse the `proxies:` section of a clash/mihomo document. Returns null when
 * the text has no proxies section, [] when the section is empty. */
export function parse_clash_yaml(text) {
	if (type(text) !== 'string')
		return null;
	const lines = split(text, '\n');
	let start = -1;
	for (let i = 0; i < length(lines); i++) {
		if (match(replace(lines[i], /\r$/, ''), /^proxies:\s*$/)) {
			start = i + 1;
			break;
		}
	}
	if (start < 0)
		return null;

	/* the section runs until the first non-indented (top-level) line */
	const sec = [];
	for (let i = start; i < length(lines); i++) {
		const l = replace(lines[i], /\r$/, '');
		if (!length(trim(l)))
			continue;
		if (!match(l, /^[ \t]/))
			break;
		push(sec, l);
	}

	const out = [];
	let i = 0;
	while (i < length(sec)) {
		const l = sec[i];
		const indent = length(l) - length(replace(l, /^[ \t]+/, ''));
		const body = trim(l);
		if (!match(body, /^- /)) {
			i++;
			continue;
		}
		const item = substr(body, 2);
		const obj = {};
		if (match(item, /^\{/) && match(item, /\}\s*$/)) {
			/* inline flow map (single line — the panel shape) */
			const inner = substr(item, 1, length(item) - length(match(item, /\}\s*$/)[0]) - 1);
			for (let tok in flow_split(inner)) {
				const kv = flow_kv(tok);
				if (kv)
					obj[kv[0]] = yaml_scalar(kv[1]);
			}
			push(out, obj);
			i++;
		} else {
			/* block entry: first key on the "- " line, deeper lines follow */
			const kv0 = flow_kv(item);
			if (kv0)
				obj[kv0[0]] = yaml_scalar(kv0[1]);
			i++;
			i = yaml_block_map(sec, i, indent + 2, obj);
			push(out, obj);
		}
	}
	return out;
};

const CLASH_TRANSPORTS = ['ws', 'grpc', 'http', 'h2', 'httpupgrade', 'xhttp'];

function clash_truthy(v) {
	return (v === 'true' || v === '1');
};

function clash_mbps(v) {
	const m = match('' + (v == null ? '' : v), /(\d+)/);
	return m ? m[1] : null;
};

/* Map ONE clash/mihomo proxy object to a homeproxy node config (null + log on
 * unsupported types). The result goes through the same parse_uri passthrough
 * and validate_node_config as every other node. */
function map_clash_proxy(p, log) {
	if (type(p) !== 'object')
		return null;
	const t = lc(trim('' + (p.type == null ? '' : p.type)));
	const label = (type(p.name) === 'string' && length(trim(p.name))) ? trim(p.name) : null;
	const tag = label || t || '?';
	const tr = ('' + (p.network == null ? 'tcp' : p.network));
	const transport = (tr in CLASH_TRANSPORTS) ? ((tr === 'h2') ? 'http' : tr) : null;
	const insecure = clash_truthy(p['skip-cert-verify']) ? '1' : null;
	const utls = (sing_features().with_utls && !isEmpty(p['client-fingerprint'])) ? ('' + p['client-fingerprint']) : null;
	const ws = as_obj(p['ws-opts']);
	const ws_headers = as_obj(ws.headers);
	const grpc = as_obj(p['grpc-opts']);
	const h2 = as_obj(p['h2-opts']);
	const hto = as_obj(p['http-opts']);
	const reality = as_obj(p['reality-opts']);
	const alpn = (type(p.alpn) === 'array' && length(p.alpn)) ?
		map(p.alpn, (a) => '' + a) : null;

	let config = null;
	switch (t) {
	case 'ss':
		config = {
			label: label,
			type: 'shadowsocks',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			password: p.password,
			shadowsocks_encrypt_method: p.cipher || null,
		};
		if (!isEmpty(p.plugin)) {
			const pl = lc(trim('' + p.plugin));
			const po = as_obj(p['plugin-opts']);
			if (pl === 'obfs' || pl === 'obfs-local') {
				config.shadowsocks_plugin = 'obfs-local';
				let opts = 'obfs=' + (po.mode || 'http');
				if (!isEmpty(po.host))
					opts += ';obfs-host=' + po.host;
				config.shadowsocks_plugin_opts = opts;
			} else if (pl === 'v2ray-plugin') {
				config.shadowsocks_plugin = 'v2ray-plugin';
				let opts = (clash_truthy(po.tls) ? 'tls;' : '') +
					(!isEmpty(po.host) ? 'host=' + po.host + ';' : '') +
					(!isEmpty(po.path) ? 'path=' + po.path : '');
				config.shadowsocks_plugin_opts = replace(opts, /;+$/, '');
			} else {
				log(sprintf('Clash: unsupported %s plugin on %s — skipped.', pl, tag));
				return null;
			}
		}
		break;
	case 'vmess':
		config = {
			label: label,
			type: 'vmess',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			uuid: p.uuid,
			vmess_alterid: (p.alterId != null) ? '' + p.alterId : null,
			vmess_encrypt: p.cipher || 'auto',
			vmess_global_padding: '1',
			transport: transport,
			tls: clash_truthy(p.tls) ? '1' : '0',
			tls_sni: p.servername || null,
			tls_alpn: alpn,
			tls_insecure: insecure,
			tls_utls: utls,
		};
		break;
	case 'vless':
		config = {
			label: label,
			type: 'vless',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			uuid: p.uuid,
			vless_flow: p.flow || null,
			transport: transport,
			tls: (clash_truthy(p.tls) || !isEmpty(p['reality-opts'])) ? '1' : '0',
			tls_sni: p.servername || null,
			tls_alpn: alpn,
			tls_reality: !isEmpty(p['reality-opts']) ? '1' : null,
			tls_reality_public_key: reality['public-key'] || null,
			tls_reality_short_id: reality['short-id'] || null,
			tls_insecure: insecure,
			tls_utls: utls,
		};
		break;
	case 'trojan':
		config = {
			label: label,
			type: 'trojan',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			password: p.password,
			transport: transport,
			tls: '1',
			tls_sni: p.sni || null,
			tls_alpn: alpn,
			tls_insecure: insecure,
			tls_utls: utls,
		};
		break;
	case 'hysteria2':
	case 'hy2':
		config = {
			label: label,
			type: 'hysteria2',
			address: p.server,
			port: (p.port != null) ? '' + p.port : '443',
			password: p.password || p.auth || null,
			hysteria_obfs_type: (type(p.obfs) === 'string' && !isEmpty(p.obfs)) ? p.obfs : null,
			hysteria_obfs_password: p['obfs-password'] || null,
			hysteria_up_mbps: clash_mbps(p.up),
			hysteria_down_mbps: clash_mbps(p.down),
			hysteria_hopping_port: !isEmpty(p.ports) ? parse_port_list(p.ports) : null,
			tls: '1',
			tls_sni: p.sni || null,
			tls_alpn: alpn,
			tls_insecure: insecure,
		};
		break;
	case 'hysteria':
		config = {
			label: label,
			type: 'hysteria',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			hysteria_protocol: 'udp',
			hysteria_auth_type: !isEmpty(p['auth-str']) ? 'string' : null,
			hysteria_auth_payload: p['auth-str'] || p.auth || null,
			hysteria_obfs_password: (type(p.obfs) === 'string') ? p.obfs : null,
			hysteria_up_mbps: clash_mbps(p.up),
			hysteria_down_mbps: clash_mbps(p.down),
			tls: '1',
			tls_sni: p.sni || null,
			tls_alpn: alpn,
			tls_insecure: insecure,
		};
		break;
	case 'tuic':
		config = {
			label: label,
			type: 'tuic',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			uuid: p.uuid,
			password: p.password || null,
			tuic_congestion_control: p['congestion-controller'] || null,
			tuic_udp_relay_mode: p['udp-relay-mode'] || null,
			tuic_enable_zero_rtt: clash_truthy(p['reduce-rtt']) ? '1' : null,
			tls: '1',
			tls_sni: p.sni || null,
			tls_alpn: alpn,
			tls_insecure: insecure,
		};
		break;
	case 'socks5':
	case 'socks5-tls':
		config = {
			label: label,
			type: 'socks',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			username: p.username || null,
			password: p.password || null,
			socks_version: '5',
			tls: (clash_truthy(p.tls) || t === 'socks5-tls') ? '1' : '0',
			tls_sni: p.sni || null,
			tls_insecure: insecure,
		};
		break;
	case 'http':
		config = {
			label: label,
			type: 'http',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			username: p.username || null,
			password: p.password || null,
			tls: clash_truthy(p.tls) ? '1' : '0',
			tls_sni: p.sni || null,
			tls_insecure: insecure,
		};
		break;
	case 'anytls':
		config = {
			label: label,
			type: 'anytls',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			password: p.password || null,
			tls: '1',
			tls_sni: p.sni || null,
			tls_insecure: insecure,
			tls_utls: utls,
		};
		break;
	case 'wireguard':
		config = {
			label: label,
			type: 'wireguard',
			address: p.server,
			port: (p.port != null) ? '' + p.port : null,
			wireguard_private_key: p['private-key'] || null,
			wireguard_peer_public_key: p['public-key'] || null,
			wireguard_pre_shared_key: p['pre-shared-key'] || null,
			wireguard_local_address: (p.ip || p.ipv6) ?
				filter([(p.ip != null) ? '' + p.ip : null, (p.ipv6 != null) ? '' + p.ipv6 : null],
					(x) => !isEmpty(x)) : null,
			wireguard_mtu: (p.mtu != null) ? '' + p.mtu : null,
			wireguard_reserved: (type(p.reserved) === 'array') ?
				map(p.reserved, (r) => '' + r) :
				(!isEmpty(p.reserved) ? split('' + p.reserved, ',') : null),
		};
		break;
	case 'mieru':
		config = {
			label: label,
			type: 'mieru',
			address: p.server,
			port: '0',
			username: p.username || null,
			password: p.password || null,
			mieru_protocol: (type(p.protocol) === 'string') ? p.protocol : null,
			mieru_port_range: (p.port != null && '' + p.port !== '0') ?
				(match('' + p.port, /^\d+$/) ? ('' + p.port + ':' + p.port) : '' + p.port) : null,
			mieru_multiplexing: p.multiplexing || null,
		};
		break;
	default:
		log(sprintf('Clash: unsupported proxy type %s (%s) — skipped.', t, tag));
		return null;
	}

	/* V2Ray transport details (shared by vmess/vless/trojan) */
	if (transport === 'ws') {
		config.ws_path = ws.path || null;
		config.ws_host = (!isEmpty(ws_headers.Host)) ? '' + ws_headers.Host : null;
		if (ws['max-early-data'] != null)
			config.websocket_early_data = '' + ws['max-early-data'];
		if (!isEmpty(ws['early-data-header-name']))
			config.websocket_early_data_header = '' + ws['early-data-header-name'];
	} else if (transport === 'grpc') {
		config.grpc_servicename = grpc['grpc-service-name'] || null;
	} else if (transport === 'http') {
		const hpath = hto.path || h2.path || null;
		config.http_path = (type(hpath) === 'array') ? (length(hpath) ? hpath[0] : null) : hpath;
		config.http_host = (type(hto.host) === 'array') ? hto.host :
			((type(h2.host) === 'array') ? h2.host :
				(!isEmpty(h2.host) ? ['' + h2.host] : null));
	} else if (transport === 'httpupgrade') {
		config.httpupgrade_host = ws_headers.Host || ws.host || null;
		config.http_path = ws.path || null;
	}

	return config;
};

/* ── sing-box JSON outbound (moved verbatim from update_subscriptions.uc) ── */
export function parse_singbox_outbound(ob, companion_map, feats) {
	feats = (type(feats) === 'object') ? feats : sing_features();
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
		tls_utls: (feats.with_utls && utls.enabled) ? (utls.fingerprint || null) : null,
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
			config.tls_utls = (feats.with_utls && stls_utls.enabled) ? (stls_utls.fingerprint || null) : null;
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
};

/* ── Xray/V2Ray outbound (moved verbatim from update_subscriptions.uc) ───── */
export function parse_xray_outbound(ob, remarks, feats) {
	feats = (type(feats) === 'object') ? feats : sing_features();
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
	 * and auth in streamSettings.hysteriaSettings. */
	if (proto === 'hysteria') {
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
			tls_utls: feats.with_utls ? (tls_s.fingerprint || null) : null
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
		tls_utls: feats.with_utls ? (tls_s.fingerprint || reality.fingerprint || null) : null
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
};

/* Parse ONE full Xray config object (an element of the subscription array): pick
 * its proxy outbound (the one tagged "proxy", else the first real proxy outbound
 * that isn't an internal helper like direct/block/dns or a routing upstream). */
export function parse_xray_config(cfg, feats) {
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

	return parse_xray_outbound(chosen, cfg.remarks, feats);
};

/* ── Whole-body format dispatcher (Ф9.11) ──────────────────────────────────
 * Dispatch ONE subscription/import body into a node list: sing-box JSON
 * (object or full client config), Xray JSON array, SIP008, clash/mihomo
 * YAML, base64 batch or plain URI lines. Returns { format, nodes } where
 * nodes is a MIXED array of pre-parsed config objects and share-link
 * strings — the caller runs every element through parse_uri (object
 * passthrough validates host/port) and then validate_node_config. */
export function parse_content(res, log, feats) {
	if (type(log) != 'function') log = function() {};
	feats = (type(feats) === 'object') ? feats : sing_features();
	const out = { format: null, nodes: [] };
	if (type(res) !== 'string' || isEmpty(trim(res)))
		return out;

	/* JSON first: an object with outbounds (sing-box, full configs included),
	 * an array of Xray configs, or a SIP008 server list. */
	let j = null, j_ok = false;
	try { j = json(res); j_ok = true; } catch (e) { j = null; }
	if (j_ok) {
		if (type(j) === 'object' && type(j.outbounds) === 'array') {
			const companion_map = {};
			for (let ob in j.outbounds) {
				if (type(ob) === 'object' && ob.tag && match(ob.tag, /§hide§/))
					companion_map[ob.tag] = ob;
			}
			out.nodes = filter(map(j.outbounds, (ob) => parse_singbox_outbound(ob, companion_map, feats)),
				(c) => !isEmpty(c));
			out.format = (length(out.nodes)) ? 'singbox' : 'singbox_empty';
			return out;
		}
		if (type(j) === 'array' && length(j) && type(j[0]) === 'object' &&
		    type(j[0].outbounds) === 'array') {
			out.nodes = filter(map(j, (cfg) => parse_xray_config(cfg, feats)), (c) => !isEmpty(c));
			out.format = (length(out.nodes)) ? 'xray' : 'xray_empty';
			return out;
		}
		if (type(j) === 'object' && type(j.servers) === 'array' && length(j.servers) &&
		    type(j.servers[0]) === 'object' && j.servers[0].server && j.servers[0].method) {
			out.nodes = j.servers;
			for (let k = 0; k < length(out.nodes); k++)
				out.nodes[k].nodetype = 'sip008';
			out.format = 'sip008';
			return out;
		}
		/* valid JSON of another shape — do NOT feed it to the link parser */
		out.format = 'json_unknown';
		return out;
	}

	/* clash/mihomo YAML */
	const yprox = parse_clash_yaml(res);
	if (yprox != null) {
		out.nodes = filter(map(yprox, (p) => map_clash_proxy(p, log)), (c) => !isEmpty(c));
		out.format = (length(out.nodes)) ? 'clash' : 'clash_empty';
		return out;
	}

	/* HTML (a panel web page) is never a link list */
	if (match(res, /^\s*</)) {
		out.format = 'html';
		return out;
	}

	/* base64 (or plain link list). Strip ALL whitespace first: CRLF line
	 * endings left a trailing \r on every link (broken ports, whole
	 * subscription rejected), and inner spaces broke the decode. */
	const b64 = replace(res, /[ \t\r\n]+/g, '');
	const decoded = decodeBase64Str(b64);
	let body = null, is_b64 = false;
	if (decoded && match(trim(decoded), /^(ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|socks|https?|ssh|wireguard|wg|mierus?|anytls|naive|shadowtls):\/\//)) {
		body = decoded;
		is_b64 = true;
	} else if (!match(res, /^\s*</)) {
		body = res;
	}
	if (body != null) {
		out.nodes = filter(split(trim(body), /[\r\n]+/), (l) => length(trim(l)));
		out.format = (length(out.nodes)) ? (is_b64 ? 'base64' : 'uri') : 'empty';
	}
	return out;
};

export function parse_uri(uri, log) {
	if (type(log) != 'function') log = function() {};
	let config, url, params;

	if (type(uri) === 'object') {
		if (uri.nodetype === 'sip008') {
			/* https://shadowsocks.org/guide/sip008.html */
			config = {
				label: uri.remarks,
				type: 'shadowsocks',
				address: uri.server,
				port: uri.server_port,
				shadowsocks_encrypt_method: uri.method,
				password: uri.password,
				shadowsocks_plugin: uri.plugin,
				shadowsocks_plugin_opts: uri.plugin_opts
			};
		} else {
			/* Pre-parsed sing-box JSON outbound from parse_singbox_outbound()
			 * (or a clash/mihomo YAML mapping) — validate host/port and pass on. */
			config = uri;
		}
	} else if (type(uri) === 'string') {
		uri = split(trim(uri), '://');

		switch (uri[0]) {
		case 'anytls':
			/* https://github.com/anytls/anytls-go/blob/v0.0.8/docs/uri_scheme.md */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'anytls',
				address: url.hostname,
				port: url.port,
				password: urldecode(url.username),
				tls: '1',
				tls_sni: params.sni,
				tls_insecure: (params.insecure === '1') ? '1' : '0'
			};

			break;
		case 'http':
		case 'https':
			url = parseURL('http://' + uri[1]) || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'http',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				tls: (uri[0] === 'https') ? '1' : '0'
			};

			break;
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			/* WeChat-Video / FakeTCP are unsupported by sing-box AT ALL —
			 * a true format reject, not a core-capability one (D34c). */
			if (params.protocol && params.protocol !== 'udp') {
				log(sprintf('Skipping unsupported %s protocol node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'hysteria',
				address: url.hostname,
				port: url.port,
				hysteria_protocol: params.protocol || 'udp',
				hysteria_auth_type: params.auth ? 'string' : null,
				hysteria_auth_payload: params.auth,
				hysteria_obfs_password: params.obfsParam,
				hysteria_down_mbps: params.downmbps,
				hysteria_up_mbps: params.upmbps,
				tls: '1',
				tls_insecure: (params.insecure in ['true', '1']) ? '1' : '0',
				tls_sni: params.peer,
				tls_alpn: params.alpn
			};

			break;
		case 'hysteria2':
		case 'hy2':
			/* https://v2.hysteria.network/docs/developers/URI-Scheme/
			 * Manual parse: the official URI carries port hopping in the PORT
			 * component (hysteria2://pass@host:443,5000-6000/) which parseURL
			 * rejects as a non-numeric port (dropping the whole node), and
			 * third-party links may use ?mport= instead. */
			let hy2_str = trim(uri[1]);
			let hy2_label = null;

			const hy2_hash = index(hy2_str, '#');
			if (hy2_hash >= 0) {
				hy2_label = urldecode(substr(hy2_str, hy2_hash + 1));
				hy2_str = substr(hy2_str, 0, hy2_hash);
			}

			let hy2_params = {};
			const hy2_q = index(hy2_str, '?');
			if (hy2_q >= 0) {
				hy2_params = urldecode_params(substr(hy2_str, hy2_q + 1)) || {};
				hy2_str = substr(hy2_str, 0, hy2_q);
			}
			hy2_str = replace(hy2_str, /\/+$/, '');

			let hy2_pass = null;
			const hy2_at = index(hy2_str, '@');
			if (hy2_at >= 0) {
				hy2_pass = urldecode(substr(hy2_str, 0, hy2_at));
				hy2_str = substr(hy2_str, hy2_at + 1);
			}

			/* host:ports — the host may be a bracketed IPv6 */
			let hy2_host = hy2_str, hy2_portlist = null;
			if (substr(hy2_str, 0, 1) === '[') {
				const hy2_close = index(hy2_str, ']');
				if (hy2_close >= 0) {
					hy2_host = substr(hy2_str, 1, hy2_close - 1);
					if (substr(hy2_str, hy2_close + 1, 1) === ':')
						hy2_portlist = substr(hy2_str, hy2_close + 2);
				}
			} else {
				const hy2_colon = index(hy2_str, ':');
				if (hy2_colon >= 0) {
					hy2_host = substr(hy2_str, 0, hy2_colon);
					hy2_portlist = substr(hy2_str, hy2_colon + 1);
				}
			}

			let hy2_hop = null, hy2_port = hy2_portlist;
			if (hy2_portlist && match(hy2_portlist, /[,-]/)) {
				/* Official multi-port: first port is primary, all listed ports hop */
				hy2_hop = parse_port_list(hy2_portlist);
				hy2_port = replace(split(hy2_portlist, ',')[0], /[-:].*/, '');
			}
			if (!hy2_hop && hy2_params.mport) {
				/* Third-party (v2rayN et al.): hopping rides in ?mport= */
				hy2_hop = parse_port_list(hy2_params.mport);
				hy2_port = hy2_port || replace(split('' + hy2_params.mport, ',')[0], /[-:].*/, '');
			}

			config = {
				label: hy2_label,
				type: 'hysteria2',
				address: hy2_host,
				port: hy2_port || '443',
				password: hy2_pass,
				hysteria_obfs_type: hy2_params.obfs || null,
				hysteria_obfs_password: hy2_params['obfs-password'] || hy2_params.obfsPassword || null,
				hysteria_hopping_port: hy2_hop,
				tls: '1',
				tls_insecure: (hy2_params.insecure in ['1', 'true'] || hy2_params.allow_insecure in ['1', 'true']) ? '1' : '0',
				tls_sni: hy2_params.sni
			};

			break;
		case 'naive':
		case 'naive+http':
		case 'naive+https':
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			let naive_extra_headers = null;
			if (params.header) {
				const hdr = split(params.header, ':', 2);
				if (length(hdr) === 2) {
					let hdrs = {};
					hdrs[trim(hdr[0])] = trim(hdr[1]);
					naive_extra_headers = sprintf('%J', hdrs);
				}
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'naive',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				tls: (uri[0] === 'naive+https' || params.security === 'tls') ? '1' : '0',
				tls_sni: params.sni || url.hostname,
				naive_udp_over_tcp: (params.uot === '1') ? '1' : null,
				naive_quic: (params.quic === '1') ? '1' : null,
				naive_extra_headers: naive_extra_headers
			};

			break;
		case 'socks':
		case 'socks4':
		case 'socks4a':
		case 'socks5':
		case 'socsk5':
		case 'socks5h':
			url = parseURL('http://' + uri[1]) || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'socks',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				socks_version: (match(uri[0], /4/)) ? '4' : '5'
			};

			break;
		case 'ss':
			/* "Lovely" Shadowrocket format */
			const ss_suri = split(uri[1], '#');
			let ss_slabel = '';
			if (length(ss_suri) <= 2) {
				if (length(ss_suri) === 2)
					ss_slabel = '#' + urlencode(ss_suri[1]);
				if (decodeBase64Str(ss_suri[0]))
					uri[1] = decodeBase64Str(ss_suri[0]) + ss_slabel;
			}

			/* Legacy format is not supported, it should be never appeared in modern subscriptions */
			/* https://github.com/shadowsocks/shadowsocks-org/commit/78ca46cd6859a4e9475953ed34a2d301454f579e */

			/* SIP002 format https://shadowsocks.org/guide/sip002.html */
			url = parseURL('http://' + uri[1]) || {};

			let ss_userinfo = {};
			if (url.username && url.password)
				/* User info encoded with URIComponent */
				ss_userinfo = [url.username, urldecode(url.password)];
			else if (url.username)
				/* User info encoded with base64 */
				ss_userinfo = split(decodeBase64Str(urldecode(url.username)), ':', 2);

			let ss_plugin, ss_plugin_opts;
			if (url.search && url.searchParams.plugin) {
				const ss_plugin_info = split(url.searchParams.plugin, ';', 2);
				ss_plugin = ss_plugin_info[0];
				if (ss_plugin === 'simple-obfs')
					/* Fix non-standard plugin name */
					ss_plugin = 'obfs-local';
				ss_plugin_opts = ss_plugin_info[1];
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'shadowsocks',
				address: url.hostname,
				port: url.port,
				shadowsocks_encrypt_method: ss_userinfo[0],
				password: ss_userinfo[1],
				shadowsocks_plugin: ss_plugin,
				shadowsocks_plugin_opts: ss_plugin_opts
			};

			break;
		case 'shadowtls':
			/* shadowtls://STLS_PASS@HOST:PORT?version=V&sni=SNI&fp=FP&method=SS_METHOD&password=SS_PASS#Label
			 * Represents a Shadowsocks 2022 connection wrapped in ShadowTLS transport. */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'shadowsocks',
				address: url.hostname,
				port: url.port,
				shadowsocks_encrypt_method: params.method || '2022-blake3-aes-256-gcm',
				password: params.password ? urldecode(params.password) : null,
				shadowtls_enabled: '1',
				shadowtls_password: url.username ? urldecode(url.username) : null,
				shadowtls_version: params.version || '3',
				tls_sni: params.sni || null,
				tls_utls: params.fp || null
			};

			break;
		case 'ssh':
			/* Manual parse to avoid parseURL corruption on long base64 query values */
			let ssh_str = trim(uri[1]);
			let ssh_label = null;

			const ssh_hash_idx = index(ssh_str, '#');
			if (ssh_hash_idx >= 0) {
				ssh_label = urldecode(substr(ssh_str, ssh_hash_idx + 1));
				ssh_str = substr(ssh_str, 0, ssh_hash_idx);
			}

			let ssh_params = {};
			const ssh_q = index(ssh_str, '?');
			if (ssh_q >= 0) {
				ssh_params = urldecode_params(substr(ssh_str, ssh_q + 1)) || {};
				ssh_str = substr(ssh_str, 0, ssh_q);
			}
			ssh_str = replace(ssh_str, /\/+$/, '');

			const ssh_at = index(ssh_str, '@');
			let ssh_user = null, ssh_pass = null, ssh_host = null, ssh_port = null;
			if (ssh_at >= 0) {
				const ssh_userinfo = substr(ssh_str, 0, ssh_at);
				const ssh_hostport = substr(ssh_str, ssh_at + 1);
				const ssh_colon = index(ssh_userinfo, ':');
				if (ssh_colon >= 0) {
					ssh_user = urldecode(substr(ssh_userinfo, 0, ssh_colon));
					ssh_pass = urldecode(substr(ssh_userinfo, ssh_colon + 1));
				} else {
					ssh_user = urldecode(ssh_userinfo);
				}
				const ssh_hp = split(ssh_hostport, ':');
				ssh_port = pop(ssh_hp);
				ssh_host = join(':', ssh_hp) || null;
			}

			let ssh_host_key = null;
			/* Hiddify: hk=key1\n,key2\n,key3\n — urldecode_params already decodes values */
			const raw_hk = ssh_params.hk || ssh_params.host_key || ssh_params.hostKey;
			if (raw_hk) {
				const ssh_hk_lines = filter(split(raw_hk, ','), (l) => length(trim(l)) > 0);
				ssh_host_key = length(ssh_hk_lines) ? ssh_hk_lines : null;
			}

			config = {
				label: ssh_label,
				type: 'ssh',
				address: ssh_host,
				port: ssh_port,
				username: ssh_user,
				password: length(ssh_pass) ? ssh_pass : null,
				/* Hiddify uses pk= (short) or private_key= ; urldecode_params already decoded */
				ssh_priv_key: ssh_params.pk || ssh_params.private_key || ssh_params.privateKey || null,
				ssh_priv_key_pp: length(ssh_params.passphrase) ? ssh_params.passphrase : null,
				ssh_host_key: ssh_host_key,
				/* Hiddify always enables udp_over_tcp for SSH; only disable if explicitly set to 0 */
				ssh_udp_over_tcp: (ssh_params.uot === '0' || ssh_params.udp_over_tcp in ['0', 'false']) ? null : '1'
			};

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'trojan',
				address: url.hostname,
				port: url.port,
				password: urldecode(url.username),
				transport: (params.type && params.type !== 'tcp') ? params.type : null,
				tls: '1',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
				tls_reality: (params.security === 'reality') ? '1' : '0',
				tls_reality_public_key: params.pbk ? urldecode(params.pbk) : null,
				tls_reality_short_id: params.sid,
				tls_utls: sing_features().with_utls ? params.fp : null
			};
			switch(params.type) {
			case 'grpc':
				config.grpc_servicename = params.serviceName;
				break;
			case 'http':
			case 'tcp':
				if (params.type === 'http' || params.headerType === 'http') {
					config.http_host = params.host ? split(urldecode(params.host), ',') : null;
					config.http_path = params.path ? urldecode(params.path) : null;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = params.host ? urldecode(params.host) : null;
				config.http_path = params.path ? urldecode(params.path) : null;
				break;
			case 'ws':
				config.ws_host = params.host ? urldecode(params.host) : null;
				config.ws_path = params.path ? urldecode(params.path) : null;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			case 'xhttp':
				config.http_path = params.path ? urldecode(params.path) : null;
				config.http_host = params.host ? urldecode(params.host) : null;
				config.xhttp_mode = params.mode || null;
				break;
			}

			if (params.hiddify === '1') {
				if (params.fragment) {
					const fparts = split(urldecode(params.fragment), ',');
					if (length(fparts) >= 2) {
						config.tls_fragment = '1';
						config.tls_fragment_size = fparts[0];
						config.tls_fragment_sleep = fparts[1];
						config.tls_fragment_type = fparts[2] || null;
					}
				}
				if (params.allowInsecure === 'true' || params.insecure === 'true')
					config.tls_insecure = '1';
			}

			break;
		case 'tuic':
			/* https://github.com/daeuniverse/dae/discussions/182 */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'tuic',
				address: url.hostname,
				port: url.port,
				uuid: url.username,
				password: url.password ? urldecode(url.password) : null,
				tuic_congestion_control: params.congestion_control,
				tuic_udp_relay_mode: params.udp_relay_mode,
				tuic_enable_zero_rtt: params.zero_rtt_handshake || null,
				tuic_heartbeat: params.heartbeat || null,
				tls: '1',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
				tls_insecure: (params.allow_insecure in ['1', 'true'] || params.insecure in ['1', 'true']) ? '1' : '0',
			};

			break;
		case 'vless':
			/* https://github.com/XTLS/Xray-core/discussions/716 */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			/* Unsupported protocol (sing-box has no kcp at all) */
			if (params.type === 'kcp') {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				return null;
			} else if (params.type === 'quic' && params.quicSecurity && params.quicSecurity !== 'none') {
				/* Encrypted QUIC transport — unsupported by sing-box, period */
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'vless',
				address: url.hostname,
				port: url.port,
				uuid: url.username,
				transport: (params.type !== 'tcp') ? params.type : null,
				tls: (params.security in ['tls', 'xtls', 'reality']) ? '1' : '0',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
				tls_reality: (params.security === 'reality') ? '1' : '0',
				tls_reality_public_key: params.pbk ? urldecode(params.pbk) : null,
				tls_reality_short_id: params.sid,
				tls_utls: sing_features().with_utls ? params.fp : null,
				vless_flow: (params.security in ['tls', 'reality']) ? params.flow : null
			};
			switch(params.type) {
			case 'grpc':
				config.grpc_servicename = params.serviceName;
				break;
			case 'http':
			case 'tcp':
				if (params.type === 'http' || params.headerType === 'http') {
					config.http_host = params.host ? split(urldecode(params.host), ',') : null;
					config.http_path = params.path ? urldecode(params.path) : null;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = params.host ? urldecode(params.host) : null;
				config.http_path = params.path ? urldecode(params.path) : null;
				break;
			case 'ws':
				config.ws_host = params.host ? urldecode(params.host) : null;
				config.ws_path = params.path ? urldecode(params.path) : null;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			case 'xhttp':
				config.http_path = params.path ? urldecode(params.path) : null;
				config.http_host = params.host ? urldecode(params.host) : null;
				config.xhttp_mode = params.mode || null;
				break;
			}

			if (params.hiddify === '1') {
				if (params.fragment) {
					const fparts = split(urldecode(params.fragment), ',');
					if (length(fparts) >= 2) {
						config.tls_fragment = '1';
						config.tls_fragment_size = fparts[0];
						config.tls_fragment_sleep = fparts[1];
						config.tls_fragment_type = fparts[2] || null;
					}
				}
				if (params.allowInsecure === 'true' || params.insecure === 'true')
					config.tls_insecure = '1';
				if (params.extra) {
					try {
						const extra = json(urldecode(params.extra));
						if (extra.headers && length(keys(extra.headers)) > 0)
							config.xhttp_headers = sprintf('%J', extra.headers);
						if (extra.downloadSettings) {
							const dl = extra.downloadSettings;
							config.xhttp_download_server = dl.address;
							config.xhttp_download_port = '' + dl.port;
							if (dl.xhttpSettings) {
								config.xhttp_download_path = dl.xhttpSettings.path;
								config.xhttp_download_host = dl.xhttpSettings.host;
								config.xhttp_download_mode = dl.xhttpSettings.mode;
							}
							config.xhttp_download_security = dl.security;
							if (dl.security === 'reality' && dl.realitySettings) {
								config.xhttp_download_sni = dl.realitySettings.serverName;
								config.xhttp_download_fp = dl.realitySettings.fingerprint;
								config.xhttp_download_pbk = dl.realitySettings.publicKey;
								config.xhttp_download_sid = dl.realitySettings.shortId;
							} else if (dl.security === 'tls' && dl.tlsSettings) {
								config.xhttp_download_sni = dl.tlsSettings.serverName;
								config.xhttp_download_alpn = dl.tlsSettings.alpn;
							}
						}
					} catch(e) {}
				}
			}

			break;
		case 'vmess':
			/* "Lovely" shadowrocket format */
			if (match(uri, /&/)) {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			}

			/* https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link */
			try {
				uri = json(decodeBase64Str(uri[1])) || {};
			} catch(e) {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			}

			if (uri.v != '2') {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			/* Unsupported protocol */
			} else if (uri.net === 'kcp') {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
				return null;
			} else if (uri.net === 'quic' && uri.type && uri.type !== 'none') {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
				return null;
			}
			/*
			 * https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			 * else if (uri.aid && int(uri.aid) !== 0) {
			 * 	log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
			 * 	return null;
			 * }
			 */

			config = {
				label: uri.ps ? urldecode(uri.ps) : null,
				type: 'vmess',
				address: uri.add,
				port: uri.port,
				uuid: uri.id,
				vmess_alterid: uri.aid,
				vmess_encrypt: uri.scy || 'auto',
				vmess_global_padding: '1',
				transport: (uri.net !== 'tcp') ? uri.net : null,
				tls: (uri.tls === 'tls') ? '1' : '0',
				tls_sni: uri.sni || uri.host,
				tls_alpn: uri.alpn ? split(uri.alpn, ',') : null,
				tls_utls: sing_features().with_utls ? uri.fp : null
			};
			switch (uri.net) {
			case 'grpc':
				config.grpc_servicename = uri.path;
				break;
			case 'h2':
			case 'tcp':
				if (uri.net === 'h2' || uri.type === 'http') {
					config.transport = 'http';
					config.http_host = uri.host ? split(uri.host, ',') : null;
					config.http_path = uri.path;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = uri.host;
				config.http_path = uri.path;
				break;
			case 'ws':
				config.ws_host = uri.host;
				config.ws_path = uri.path;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			}

			break;
		case 'mieru':
		case 'mierus':
			/* https://github.com/enfein/mieru — mierus:// is the TLS-carrying
			 * scheme the Hiddify panel exports; the mieru protocol encrypts on
			 * its own, so it maps onto the same node shape (Ф9.11). */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			let mieru_range = params.port || null;
			if (mieru_range && match(mieru_range, /^\d+$/))
				mieru_range = mieru_range + ':' + mieru_range;

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'mieru',
				address: url.hostname,
				port: '0',
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				mieru_protocol: params.protocol || null,
				mieru_port_range: mieru_range,
				mieru_multiplexing: params.multiplexing || null,
				mieru_handshake_mode: params['handshake-mode'] || null
			};

			break;
		case 'wg':
		case 'wireguard':
			/* Manual parse: WireGuard private key may contain URL-encoded chars
			 * incompatible with parseURL's userinfo regex */
			let wg_str = trim(uri[1]);
			let wg_label = null;

			const wg_hash = index(wg_str, '#');
			if (wg_hash >= 0) {
				wg_label = urldecode(substr(wg_str, wg_hash + 1));
				wg_str = substr(wg_str, 0, wg_hash);
			}

			let wg_params = {};
			const wg_q = index(wg_str, '?');
			if (wg_q >= 0) {
				wg_params = urldecode_params(substr(wg_str, wg_q + 1)) || {};
				wg_str = substr(wg_str, 0, wg_q);
			}

			/* Strip trailing slash left by "KEY@HOST:PORT/?params" format */
			wg_str = replace(wg_str, /\/+$/, '');

			const wg_at = index(wg_str, '@');
			let wg_priv_key = null, wg_host = null, wg_port = null;
			if (wg_at >= 0) {
				wg_priv_key = urldecode(substr(wg_str, 0, wg_at));
				const wg_hp_parts = split(substr(wg_str, wg_at + 1), ':');
				wg_port = pop(wg_hp_parts);
				wg_host = join(':', wg_hp_parts) || null;
			} else {
				/* wg://HOST:PORT?privateKey=...&publicKey=... format (no userinfo) */
				const wg_hp_parts = split(wg_str, ':');
				wg_port = pop(wg_hp_parts);
				wg_host = join(':', wg_hp_parts) || null;
				wg_priv_key = wg_params.privateKey || wg_params.privatekey || null;
			}

			const wg_local_addr = wg_params.address || wg_params.ip || null;
			config = {
				label: wg_label,
				type: 'wireguard',
				address: wg_host,
				port: wg_port,
				wireguard_private_key: wg_priv_key,
				wireguard_peer_public_key: wg_params.publicKey || wg_params.publickey || null,
				wireguard_pre_shared_key: wg_params.presharedKey || wg_params.presharedkey || null,
				wireguard_local_address: wg_local_addr ? split(wg_local_addr, ',') : null,
				wireguard_mtu: wg_params.mtu || null,
				wireguard_reserved: wg_params.reserved ? split(wg_params.reserved, ',') : null
			};

			break;
		}
	}

	if (!isEmpty(config)) {
		if (config.address)
			config.address = replace(config.address, /\[|\]/g, '');

		if (!validation('host', config.address) || (config.type !== 'mieru' && !validation('port', config.port))) {
			log(sprintf('Skipping invalid %s node: %s.', config.type, config.label || 'NULL'));
			return null;
		} else if (!config.label)
			config.label = (validation('ip6addr', config.address) ?
				`[${config.address}]` : config.address) + ':' + config.port;
	} else if (type(uri) === 'array' && !isEmpty(uri[0]) &&
	           match(uri[0], /^[a-zA-Z][a-zA-Z0-9+.-]{0,15}$/)) {
		/* Looks like a link scheme we have no parser for (ssr://, snell://, …) —
		 * say so instead of silently dropping the line. */
		log(sprintf('Skipping unsupported link scheme: %s://', uri[0]));
	}

	return config;
};
