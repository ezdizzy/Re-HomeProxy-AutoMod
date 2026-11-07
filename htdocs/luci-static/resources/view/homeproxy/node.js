/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 *
 * Ravnex — Servers (Ф9.11, D34a): the page reworked to the v3 design system
 * WITHOUT tab archaics — a subscription panel (per-subscription cards with
 * their own update/remove and the honest last-cycle verdict), subscription
 * settings, own nodes and one panel per subscription group. The update runs
 * ASYNC (start + status poll — lesson 294) and the smart import parses
 * through the SAME server-side parser set the subscription importer uses
 * (URI lists, base64, sing-box JSON, Xray JSON, SIP008, clash/mihomo YAML —
 * node_parse.uc via app_import_nodes). No core-capability filtering anywhere
 * (D34c multi-core): a node the running core cannot load is still saved,
 * the generator skips it and the Live status shows the honest badge.
 */

'use strict';
'require dom';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

'require homeproxy as hp';
'require tools.widgets as widgets';

function allowInsecureConfirm(ev, _section_id, value) {
	if (value !== '1')
		return;
	hp.confirmModal(_('Allow insecure'), _('Are you sure to allow insecure?'), _('Allow')).then(function(ok) {
		if (!ok)
			ev.target.firstElementChild.checked = null;
	});
}

function parseWireGuardConf(text) {
	const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
	let section = null;
	const iface = {}, peer = {};

	for (const line of lines) {
		if (line === '[Interface]') { section = 'interface'; continue; }
		if (line === '[Peer]')      { section = 'peer';      continue; }
		const eq = line.indexOf('=');
		if (eq < 0) continue;
		const key = line.slice(0, eq).trim();
		const val = line.slice(eq + 1).trim();
		if (section === 'interface') iface[key] = val;
		else if (section === 'peer') peer[key] = val;
	}

	if (!iface.PrivateKey || !peer.PublicKey || !peer.Endpoint) return null;

	const lastColon = peer.Endpoint.lastIndexOf(':');
	const host = peer.Endpoint.slice(0, lastColon);
	const port = peer.Endpoint.slice(lastColon + 1);

	const isAWG = !!(iface.Jc || iface.Jmin || iface.Jmax || iface.H1);

	const node = {
		label:                   isAWG ? 'AmneziaWG' : 'WireGuard',
		type:                    isAWG ? 'amneziawg' : 'wireguard',
		address:                 host.replace(/^\[|\]$/g, ''),
		port:                    port,
		wireguard_private_key:   iface.PrivateKey,
		wireguard_peer_public_key: peer.PublicKey,
		wireguard_pre_shared_key:  peer.PresharedKey || null,
		wireguard_local_address: iface.Address ? iface.Address.split(',').map(a => a.trim()) : null,
		wireguard_mtu:           iface.MTU || null,
		/* Ф5.3 (аудит 51): PersistentKeepalive больше не теряется — зеркало
		 * import_conf.uc (поле читает генератор). */
		wireguard_persistent_keepalive_interval: peer.PersistentKeepalive || null,
	};

	if (isAWG) {
		node.amnezia_jc   = iface.Jc   || null;
		node.amnezia_jmin = iface.Jmin  || null;
		node.amnezia_jmax = iface.Jmax  || null;
		node.amnezia_s1   = iface.S1   || null;
		node.amnezia_s2   = iface.S2   || null;
		node.amnezia_s3   = iface.S3   || null;
		node.amnezia_s4   = iface.S4   || null;
		node.amnezia_h1   = iface.H1   || null;
		node.amnezia_h2   = iface.H2   || null;
		node.amnezia_h3   = iface.H3   || null;
		node.amnezia_h4   = iface.H4   || null;
		node.amnezia_i1   = iface.I1   || null;
		node.amnezia_i2   = iface.I2   || null;
		node.amnezia_i3   = iface.I3   || null;
		node.amnezia_i4   = iface.I4   || null;
		node.amnezia_i5   = iface.I5   || null;
	}

	return node;
}

/* Ф5.3 (аудит 51): зеркало валидатора импортёров для wireguard/amneziawg —
 * ДЕРЖАТЬ СИНХРОННО с validate_node_config() в homeproxy.uc (ключи — 44
 * символа base64, порт 1–65535, PersistentKeepalive — число 0–65535,
 * локальные адреса — IP/подсети). Возвращает null (OK) или массив строк. */
function validateWireGuardNode(node) {
	const errs = [];
	const normB64 = s => String(s).replace(/-/g, '+').replace(/_/g, '/');
	const b64key = s => typeof s === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(normB64(s));
	const portOk = (s, lo) => /^\d+$/.test(String(s)) && +s >= (lo || 1) && +s <= 65535;
	const addrOk = s => {
		if (!s) return false;
		if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) {
			const parts = s.split('/')[0].split('.');
			if (parts.some(p => +p > 255 || (p.length > 1 && p[0] === '0'))) return false;
			if (s.includes('/')) {
				const pre = +s.split('/')[1];
				return pre >= 1 && pre <= 32;
			}
			return true;
		}
		return /^[a-zA-Z0-9]([a-zA-Z0-9_\-.]*[a-zA-Z0-9])?$/.test(s) && /[^0-9.]/.test(s);
	};

	if (!addrOk(node.address))
		errs.push(_('адрес отсутствует или невалиден'));
	if (!portOk(node.port, 1))
		errs.push(_('порт отсутствует или вне диапазона 1–65535'));
	if (!b64key(node.wireguard_private_key))
		errs.push(_('wireguard: private_key не base64-ключ (44 символа)'));
	if (!b64key(node.wireguard_peer_public_key))
		errs.push(_('wireguard: public_key пира не base64-ключ (44 символа)'));
	if (node.wireguard_pre_shared_key && !b64key(node.wireguard_pre_shared_key))
		errs.push(_('wireguard: pre_shared_key не base64-ключ (44 символа)'));
	if (node.wireguard_local_address) {
		const ok = Array.isArray(node.wireguard_local_address) && node.wireguard_local_address.length > 0 &&
			node.wireguard_local_address.every(a => {
				const m = String(a).match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
				if (!m) return false;
				if (m[1].split('.').some(p => +p > 255 || (p.length > 1 && p[0] === '0'))) return false;
				if (m[2] != null) { const pre = +m[2]; return pre >= 1 && pre <= 32; }
				return true;
			});
		if (!ok)
			errs.push(_('wireguard: локальный адрес должен быть списком IP/подсетей'));
	}
	if (node.wireguard_persistent_keepalive_interval != null &&
	    String(node.wireguard_persistent_keepalive_interval) !== '' &&
	    !portOk(node.wireguard_persistent_keepalive_interval, 0))
		errs.push(_('wireguard: persistent_keepalive «%s» не число 0–65535').format(node.wireguard_persistent_keepalive_interval));

	return errs.length ? errs : null;
}

/* ── Live node statuses (R3 v3e «Серверы») ──────────────────────────────
 * The grid shows what the RUNNING CORE currently thinks of every node:
 * measured delay / timeout / not in the generated config / unsupported by
 * the core (+ In pool / Active chips). ONE status source — the same
 * monitor_nodes RPC the Monitoring page uses, no new computation
 * (19-UX_REDESIGN §7). The poll re-renders the cells in place via the
 * tr[data-sid] attribute every grid row carries. */
const callMonitorNodes = rpc.declare({
	object: 'luci.homeproxy',
	method: 'monitor_nodes',
	expect: { '': {} }
});

/* Ф5.1: итог последнего цикла обновления подписок — статус-файл пишет
 * update_subscriptions.uc, RPC читает его + живую книжку узлов. */
const callSubscriptionStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_subscription_status',
	expect: { '': {} }
});

let NODE_STATUS = {};

function renderNodeLive(sid) {
	const n = NODE_STATUS[sid];
	const parts = [];
	if (!n)
		parts.push(E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ '…' ]));
	else if (n.status === 'not_in_config')
		parts.push(E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ _('Not in config') ]));
	else if (n.status === 'unsupported')
		parts.push(E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('Unsupported by core') ]));
	else
		parts.push(hp.delayBadge(n.delay));
	if (n && n.in_pool)
		parts.push(E('span', { 'class': 'hpui-badge hpui-b-blue', 'style': 'margin-left:4px' }, [ _('In pool') ]));
	if (n && n.selected)
		parts.push(E('span', { 'class': 'hpui-badge hpui-b-green', 'style': 'margin-left:4px' }, [ _('Active') ]));
	return E('span', { 'style': 'white-space:nowrap' }, parts);
}

function refreshNodeStatuses() {
	return L.resolveDefault(callMonitorNodes(), null).then(function(res) {
		NODE_STATUS = {};
		(res && res.nodes ? res.nodes : []).forEach(function(n) { NODE_STATUS[n.sid] = n; });
		document.querySelectorAll('tr.cbi-section-table-row[data-sid]').forEach(function(tr) {
			const td = tr.querySelector('td[data-name="_hp_live"]');
			if (td)
				dom.content(td, renderNodeLive(tr.getAttribute('data-sid')));
		});
	});
}

function renderNodeSettings(section, data, features, main_node, routing_mode) {
	let s = section, o;
	s.rowcolors = true;
	s.sortable = true;
	s.nodescriptions = true;
	s.modaltitle = L.bind(hp.loadModalTitle, this, _('Node'), _('Add a node'), data[0]);
	s.sectiontitle = L.bind(hp.loadDefaultLabel, this, data[0]);


	o = s.option(form.Value, 'label', _('Label'));
	o.load = L.bind(hp.loadDefaultLabel, this, data[0]);
	o.validate = L.bind(hp.validateUniqueValue, this, data[0], 'node', 'label');
	o.modalonly = true;

	/* Type list: NO feature gating (D34c multi-core) — node DATA must survive
	 * a core switch; the generator skips what the running core cannot load
	 * (core_skipped.json) and the Live status column shows the honest badge. */
	o = s.option(form.ListValue, 'type', _('Type'));
	o.value('direct', _('Direct'));
	o.value('anytls', _('AnyTLS'));
	o.value('http', _('HTTP'));
	o.value('hysteria', _('Hysteria'));
	o.value('hysteria2', _('Hysteria2'));
	o.value('mieru', _('Mieru'));
	o.value('shadowsocks', _('Shadowsocks'));
	o.value('shadowtls', _('ShadowTLS'));
	o.value('naive', _('NaïveProxy'));
	o.value('socks', _('Socks'));
	o.value('ssh', _('SSH'));
	o.value('trojan', _('Trojan'));
	o.value('tuic', _('Tuic'));
	o.value('trusttunnel', _('TrustTunnel'));
	o.value('wireguard', _('WireGuard'));
	o.value('amneziawg', _('AmneziaWG'));
	o.value('vless', _('VLESS'));
	o.value('vmess', _('VMess'));
	o.rmempty = false;

	o = s.option(form.Value, 'address', _('Address'));
	o.datatype = 'host';
	o.depends({'type': 'direct', '!reverse': true});
	o.rmempty = false;

	o = s.option(form.Value, 'port', _('Port'));
	o.datatype = 'port';
	o.depends('type', 'anytls');
	o.depends('type', 'http');
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.depends('type', 'naive');
	o.depends('type', 'shadowsocks');
	o.depends('type', 'shadowtls');
	o.depends('type', 'socks');
	o.depends('type', 'ssh');
	o.depends('type', 'trojan');
	o.depends('type', 'trusttunnel');
	o.depends('type', 'tuic');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.rmempty = false;

	/* Grid table cell: show the port the node ACTUALLY uses. Mieru imports with
	 * port=0 (the real port is carried by mieru_port_range — the generator forces
	 * server_port=0 and passes only the range), and hysteria(2) port hopping
	 * ranges live in hysteria_hopping_port, so print them instead of the bare
	 * (derived or zero) primary port. The edit modal is unaffected. */
	o.textvalue = function(section_id) {
		const ntype = uci.get(data[0], section_id, 'type'),
		      p = uci.get(data[0], section_id, 'port'),
		      hop = uci.get(data[0], section_id, 'hysteria_hopping_port'),
		      mieru_range = uci.get(data[0], section_id, 'mieru_port_range');
		if (ntype === 'mieru' && mieru_range != null && mieru_range !== '')
			return '' + (Array.isArray(mieru_range) ? mieru_range.join(', ') : mieru_range);
		if ((ntype === 'hysteria2' || ntype === 'hysteria') && hop != null &&
		    (!Array.isArray(hop) || hop.length)) {
			const ranges = Array.isArray(hop) ? hop.join(', ') : '' + hop;
			if (ranges)
				return (p ? p + ' ' : '') + '(' + ranges + ')';
		}
		return (p != null && p !== '') ? '' + p : null;
	};

	/* Live status column (R3 v3e): what the running core currently measures
	 * for this node, updated by the 5 s monitor_nodes poll in render(). The
	 * same chip renders inside the edit modal (renderWidget), so the user
	 * sees the live state while editing the node. */
	o = s.option(form.DummyValue, '_hp_live', _('Live status'));
	o.textvalue = function(section_id) {
		return renderNodeLive(section_id);
	};
	o.renderWidget = function(section_id) {
		return renderNodeLive(section_id);
	};

	o = s.option(form.Value, 'username', _('Username'));
	o.depends('type', 'http');
	o.depends('type', 'mieru');
	o.depends('type', 'naive');
	o.depends('type', 'socks');
	o.depends('type', 'ssh');
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.Value, 'password', _('Password'));
	o.password = true;
	o.depends('type', 'anytls');
	o.depends('type', 'http');
	o.depends('type', 'hysteria2');
	o.depends('type', 'mieru');
	o.depends('type', 'naive');
	o.depends('type', 'shadowsocks');
	o.depends('type', 'ssh');
	o.depends('type', 'trojan');
	o.depends('type', 'trusttunnel');
	o.depends('type', 'tuic');
	o.depends({'type': 'shadowtls', 'shadowtls_version': '2'});
	o.depends({'type': 'shadowtls', 'shadowtls_version': '3'});
	o.depends({'type': 'socks', 'socks_version': '5'});
	o.validate = function(section_id, value) {
		if (section_id) {
			let type = this.section.formvalue(section_id, 'type');
			let required_type = [ 'anytls', 'shadowsocks', 'shadowtls', 'trojan' ];

			if (required_type.includes(type)) {
				if (type === 'shadowsocks') {
					let encmode = this.section.formvalue(section_id, 'shadowsocks_encrypt_method');
					if (encmode === 'none')
						return true;
				}
				if (!value)
					return _('Expecting: %s').format(_('non-empty value'));
			}
		}

		return true;
	}
	o.modalonly = true;

	/* Direct config */
	o = s.option(form.ListValue, 'proxy_protocol', _('Proxy protocol'),
		_('Write proxy protocol in the connection header.'));
	o.value('', _('Disable'));
	o.value('1', _('v1'));
	o.value('2', _('v2'));
	o.depends('type', 'direct');
	o.modalonly = true;

	/* AnyTLS config start */
	o = s.option(form.Value, 'anytls_idle_session_check_interval', _('Idle session check interval'),
		_('Interval checking for idle sessions, in seconds.'));
	o.datatype = 'uinteger';
	o.placeholder = '30';
	o.depends('type', 'anytls');
	o.modalonly = true;

	o = s.option(form.Value, 'anytls_idle_session_timeout', _('Idle session check timeout'),
		_('In the check, close sessions that have been idle for longer than this, in seconds.'));
	o.datatype = 'uinteger';
	o.placeholder = '30';
	o.depends('type', 'anytls');
	o.modalonly = true;

	o = s.option(form.Value, 'anytls_min_idle_session', _('Minimum idle sessions'),
		_('In the check, at least the first <code>n</code> idle sessions are kept open.'));
	o.datatype = 'uinteger';
	o.placeholder = '0';
	o.depends('type', 'anytls');
	o.modalonly = true;
	/* AnyTLS config end */

	/* Hysteria (2) config start */
	o = s.option(form.DynamicList, 'hysteria_hopping_port', _('Hopping port'));
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.validate = hp.validatePortRange;
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_hop_interval', _('Hop interval'),
		_('Port hopping interval in seconds.'));
	o.datatype = 'uinteger';
	o.placeholder = '30';
	o.depends({'type': 'hysteria', 'hysteria_hopping_port': /[\s\S]/});
	o.depends({'type': 'hysteria2', 'hysteria_hopping_port': /[\s\S]/});
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
	o.value('udp');
	/* WeChat-Video / FakeTCP are unsupported by sing-box currently
	 * o.value('wechat-video');
	 * o.value('faketcp');
	 */
	o.default = 'udp';
	o.depends('type', 'hysteria');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria_auth_type', _('Authentication type'));
	o.value('', _('Disable'));
	o.value('base64', _('Base64'));
	o.value('string', _('String'));
	o.depends('type', 'hysteria');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_auth_payload', _('Authentication payload'));
	o.password = true
	o.depends({'type': 'hysteria', 'hysteria_auth_type': /[\s\S]/});
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria_obfs_type', _('Obfuscate type'));
	o.value('', _('Disable'));
	o.value('salamander', _('Salamander'));
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_obfs_password', _('Obfuscate password'));
	o.password = true;
	o.depends('type', 'hysteria');
	o.depends({'type': 'hysteria2', 'hysteria_obfs_type': /[\s\S]/});
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_down_mbps', _('Max download speed'),
		_('Max download speed in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_up_mbps', _('Max upload speed'),
		_('Max upload speed in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'),
		_('The QUIC stream-level flow control window for receiving data.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_revc_window', _('QUIC connection receive window'),
		_('The QUIC connection-level flow control window for receiving data.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.modalonly = true;

	o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'),
		_('Disables Path MTU Discovery (RFC 8899). Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.'));
	o.depends('type', 'hysteria');
	o.modalonly = true;
	/* Hysteria (2) config end */

	/* Shadowsocks config start */
	o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
	for (let i of hp.shadowsocks_encrypt_methods)
		o.value(i);
	/* Stream ciphers */
	o.value('aes-128-ctr');
	o.value('aes-192-ctr');
	o.value('aes-256-ctr');
	o.value('aes-128-cfb');
	o.value('aes-192-cfb');
	o.value('aes-256-cfb');
	o.value('chacha20');
	o.value('chacha20-ietf');
	o.value('rc4-md5');
	o.default = 'aes-128-gcm';
	o.depends('type', 'shadowsocks');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'shadowsocks_plugin', _('Plugin'));
	o.value('', _('none'));
	o.value('obfs-local');
	o.value('v2ray-plugin');
	o.depends('type', 'shadowsocks');
	o.modalonly = true;

	o = s.option(form.Value, 'shadowsocks_plugin_opts', _('Plugin opts'));
	o.depends('shadowsocks_plugin', 'obfs-local');
	o.depends('shadowsocks_plugin', 'v2ray-plugin');
	o.modalonly = true;
	/* Shadowsocks config end */

	/* ShadowTLS transport (overlay for Shadowsocks) */
	o = s.option(form.Flag, 'shadowtls_enabled', _('ShadowTLS transport'),
		_('Wrap this Shadowsocks connection in ShadowTLS for TLS camouflage.'));
	o.depends('type', 'shadowsocks');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'shadowtls_password', _('ShadowTLS password'));
	o.password = true;
	o.depends({'type': 'shadowsocks', 'shadowtls_enabled': '1'});
	o.modalonly = true;

	/* ShadowTLS config */
	o = s.option(form.ListValue, 'shadowtls_version', _('ShadowTLS version'));
	o.value('1', _('v1'));
	o.value('2', _('v2'));
	o.value('3', _('v3'));
	o.default = '1';
	o.depends('type', 'shadowtls');
	o.depends({'type': 'shadowsocks', 'shadowtls_enabled': '1'});
	o.rmempty = false;
	o.modalonly = true;

	/* Socks config */
	o = s.option(form.ListValue, 'socks_version', _('Socks version'));
	o.value('4', _('Socks4'));
	o.value('4a', _('Socks4A'));
	o.value('5', _('Socks5'));
	o.default = '5';
	o.depends('type', 'socks');
	o.rmempty = false;
	o.modalonly = true;

	/* SSH config start */
	o = s.option(form.Value, 'ssh_client_version', _('Client version'),
		_('Random version will be used if empty.'));
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'ssh_host_key', _('Host key'),
		_('Accept any if empty.'));
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'ssh_host_key_algo', _('Host key algorithms'))
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'ssh_priv_key', _('Private key'));
	o.password = true;
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.Value, 'ssh_priv_key_pp', _('Private key passphrase'));
	o.password = true;
	o.depends('type', 'ssh');
	o.modalonly = true;
	/* SSH config end */

	/* Mieru config start */
	o = s.option(form.ListValue, 'mieru_protocol', _('Protocol'));
	o.value('TCP', _('TCP'));
	o.value('UDP', _('UDP'));
	o.value('TCP_AND_UDP', _('TCP and UDP'));
	o.depends('type', 'mieru');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'mieru_port_range', _('Port range'),
		_('Port range for the Mieru connection, e.g. %s.').format('<code>8080-8180</code>'));
	o.depends('type', 'mieru');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'mieru_multiplexing', _('Multiplexing'));
	o.value('', _('Default'));
	o.value('MULTIPLEXING_OFF', _('Off'));
	o.value('MULTIPLEXING_LOW', _('Low'));
	o.value('MULTIPLEXING_MIDDLE', _('Middle'));
	o.value('MULTIPLEXING_HIGH', _('High'));
	o.depends('type', 'mieru');
	o.modalonly = true;

	o = s.option(form.Value, 'mieru_handshake_mode', _('Handshake mode'));
	o.depends('type', 'mieru');
	o.modalonly = true;
	/* Mieru config end */

	/* TUIC config start */
	o = s.option(form.Value, 'uuid', _('UUID'));
	o.password = true;
	o.depends('type', 'tuic');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.validate = hp.validateUUID;
	o.modalonly = true;

	o = s.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'),
		_('QUIC congestion control algorithm.'));
	o.value('cubic', _('CUBIC'));
	o.value('new_reno', _('New Reno'));
	o.value('bbr', _('BBR'));
	o.default = 'cubic';
	o.depends('type', 'tuic');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'tuic_udp_relay_mode', _('UDP relay mode'),
		_('UDP packet relay mode.'));
	o.value('', _('Default'));
	o.value('native', _('Native'));
	o.value('quic', _('QUIC'));
	o.depends('type', 'tuic');
	o.modalonly = true;

	o = s.option(form.Flag, 'tuic_udp_over_stream', _('UDP over stream'),
		_('This is the TUIC port of the UDP over TCP protocol, designed to provide a QUIC stream based UDP relay mode that TUIC does not provide.'));
	o.depends({'type': 'tuic','tuic_udp_relay_mode': ''});
	o.modalonly = true;

	o = s.option(form.Flag, 'tuic_enable_zero_rtt', _('Enable 0-RTT handshake'),
		_('Enable 0-RTT QUIC connection handshake on the client side. This is not impacting much on the performance, as the protocol is fully multiplexed.<br/>' +
			'Disabling this is highly recommended, as it is vulnerable to replay attacks.'));
	o.depends('type', 'tuic');
	o.modalonly = true;

	o = s.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval'),
		_('Interval for sending heartbeat packets for keeping the connection alive (in seconds).'));
	o.datatype = 'uinteger';
	o.default = '10';
	o.depends('type', 'tuic');
	o.modalonly = true;
	/* Tuic config end */

	/* TrustTunnel config start (sing-box-extended) */
	o = s.option(form.ListValue, 'trusttunnel_congestion_controller', _('Congestion control algorithm'),
		_('QUIC congestion control algorithm used by TrustTunnel.'));
	o.value('', _('Default'));
	o.value('bbr', _('BBR'));
	o.value('bbr2', _('BBRv2'));
	o.value('new_reno', _('New Reno'));
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.MultiValue, 'trusttunnel_network', _('Network'),
		_('Transports to relay through the tunnel. Empty = the server default.'));
	o.value('tcp', 'TCP');
	o.value('udp', 'UDP');
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.Flag, 'trusttunnel_quic', _('QUIC transport'),
		_('Run TrustTunnel over QUIC instead of plain TCP.'));
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.Value, 'trusttunnel_cwnd', _('Congestion window'),
		_('Custom congestion control window (advanced; leave empty for the default).'));
	o.datatype = 'uinteger';
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.Flag, 'trusttunnel_health_check', _('Health check'),
		_('Periodically verify the tunnel is alive.'));
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.Flag, 'trusttunnel_multiplex', _('Multiplex'),
		_('Stream multiplexing over a single connection.'));
	o.depends('type', 'trusttunnel');
	o.modalonly = true;

	o = s.option(form.Value, 'trusttunnel_mp_max_connections', _('Maximum connections'),
		_('Maximum TLS/QUIC connections for multiplexing.'));
	o.datatype = 'uinteger';
	o.depends({'type': 'trusttunnel', 'trusttunnel_multiplex': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'trusttunnel_mp_min_streams', _('Minimum streams'),
		_('Minimum multiplexed streams to keep open per connection.'));
	o.datatype = 'uinteger';
	o.depends({'type': 'trusttunnel', 'trusttunnel_multiplex': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'trusttunnel_mp_max_streams', _('Maximum streams'),
		_('Maximum multiplexed streams per connection before a new one is opened.'));
	o.datatype = 'uinteger';
	o.depends({'type': 'trusttunnel', 'trusttunnel_multiplex': '1'});
	o.modalonly = true;
	/* TrustTunnel config end */

	/* VMess / VLESS config start */
	o = s.option(form.ListValue, 'vless_flow', _('Flow'));
	o.value('', _('None'));
	o.value('xtls-rprx-vision');
	o.depends('type', 'vless');
	o.modalonly = true;

	o = s.option(form.Value, 'vmess_alterid', _('Alter ID'),
		_('Legacy protocol support (VMess MD5 Authentication) is provided for compatibility purposes only, use of alterId > 1 is not recommended.'));
	o.datatype = 'uinteger';
	o.depends('type', 'vmess');
	o.modalonly = true;

	o = s.option(form.ListValue, 'vmess_encrypt', _('Encrypt method'));
	o.value('auto');
	o.value('none');
	o.value('zero');
	o.value('aes-128-gcm');
	o.value('chacha20-poly1305');
	o.default = 'auto';
	o.depends('type', 'vmess');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Flag, 'vmess_global_padding', _('Global padding'),
		_('Protocol parameter. Will waste traffic randomly if enabled (enabled by default in v2ray and cannot be disabled).'));
	o.default = o.enabled;
	o.depends('type', 'vmess');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Flag, 'vmess_authenticated_length', _('Authenticated length'),
		_('Protocol parameter. Enable length block encryption.'));
	o.depends('type', 'vmess');
	o.modalonly = true;
	/* VMess config end */

	/* Transport config start */
	o = s.option(form.ListValue, 'transport', _('Transport'),
		_('No TCP transport, plain HTTP is merged into the HTTP transport.'));
	o.value('', _('None'));
	o.value('grpc', _('gRPC'));
	o.value('http', _('HTTP'));
	o.value('httpupgrade', _('HTTPUpgrade'));
	o.value('quic', _('QUIC'));
	o.value('ws', _('WebSocket'));
	o.value('xhttp', _('XHTTP'));
	o.depends('type', 'trojan');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.onchange = function(ev, section_id, value) {
		let desc = this.map.findElement('id', 'cbid.homeproxy.%s.transport'.format(section_id)).nextElementSibling;
		if (value === 'http')
			desc.innerHTML = _('TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.');
		else if (value === 'quic')
			desc.innerHTML = _('No additional encryption support: It\'s basically duplicate encryption.');
		else
			desc.innerHTML = _('No TCP transport, plain HTTP is merged into the HTTP transport.');

		let tls = this.map.findElement('id', 'cbid.homeproxy.%s.tls'.format(section_id)).firstElementChild;
		if ((value === 'http' && tls.checked) || (value === 'grpc' && !features.with_grpc)) {
			this.map.findElement('id', 'cbid.homeproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('Specifies the period of time (in seconds) after which a health check will be performed using a ping frame if no frames have been received on the connection.<br/>' +
					'Please note that a ping response is considered a received frame, so if there is no other traffic on the connection, the health check will be executed every interval.');

			this.map.findElement('id', 'cbid.homeproxy.%s.http_ping_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('Specifies the timeout duration (in seconds) after sending a PING frame, within which a response must be received.<br/>' +
					'If a response to the PING frame is not received within the specified timeout duration, the connection will be closed.');
		} else if (value === 'grpc' && features.with_grpc) {
			this.map.findElement('id', 'cbid.homeproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('If the transport doesn\'t see any activity after a duration of this time (in seconds), it pings the client to check if the connection is still active.');

			this.map.findElement('id', 'cbid.homeproxy.%s.http_ping_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('The timeout (in seconds) that after performing a keepalive check, the client will wait for activity. If no activity is detected, the connection will be closed.');
		}
	}
	o.modalonly = true;

	/* gRPC config start */
	o = s.option(form.Value, 'grpc_servicename', _('gRPC service name'));
	o.depends('transport', 'grpc');
	o.modalonly = true;

	if (features.with_grpc) {
		o = s.option(form.Flag, 'grpc_permit_without_stream', _('gRPC permit without stream'),
			_('If enabled, the client transport sends keepalive pings even with no active connections.'));
		o.depends('transport', 'grpc');
		o.modalonly = true;
	}
	/* gRPC config end */

	/* HTTP(Upgrade) config start */
	o = s.option(form.DynamicList, 'http_host', _('Host'));
	o.datatype = 'hostname';
	o.depends('transport', 'http');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'httpupgrade_host', _('Host'));
	o.datatype = 'hostname';
	o.depends('transport', 'httpupgrade');
	o.modalonly = true;

	o = s.option(form.Value, 'http_path', _('Path'));
	o.depends('transport', 'http');
	o.depends('transport', 'httpupgrade');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'http_method', _('Method'));
	o.value('GET', _('GET'));
	o.value('PUT', _('PUT'));
	o.depends('transport', 'http');
	o.modalonly = true;

	o = s.option(form.Value, 'http_idle_timeout', _('Idle timeout'),
		_('Specifies the period of time (in seconds) after which a health check will be performed using a ping frame if no frames have been received on the connection.<br/>' +
			'Please note that a ping response is considered a received frame, so if there is no other traffic on the connection, the health check will be executed every interval.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'grpc');
	o.depends({'transport': 'http', 'tls': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'http_ping_timeout', _('Ping timeout'),
		_('Specifies the timeout duration (in seconds) after sending a PING frame, within which a response must be received.<br/>' +
			'If a response to the PING frame is not received within the specified timeout duration, the connection will be closed.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'grpc');
	o.depends({'transport': 'http', 'tls': '1'});
	o.modalonly = true;
	/* HTTP config end */

	/* WebSocket config start */
	o = s.option(form.Value, 'ws_host', _('Host'));
	o.depends('transport', 'ws');
	o.modalonly = true;

	o = s.option(form.Value, 'ws_path', _('Path'));
	o.depends('transport', 'ws');
	o.modalonly = true;

	o = s.option(form.Value, 'websocket_early_data', _('Early data'),
		_('Allowed payload size is in the request.'));
	o.datatype = 'uinteger';
	o.value('2048');
	o.depends('transport', 'ws');
	o.modalonly = true;

	o = s.option(form.Value, 'websocket_early_data_header', _('Early data header name'));
	o.value('Sec-WebSocket-Protocol');
	o.depends('transport', 'ws');
	o.modalonly = true;
	/* WebSocket config end */

	/* XHTTP config start */
	o = s.option(form.ListValue, 'xhttp_mode', _('XHTTP mode'));
	o.value('auto', _('Auto'));
	o.value('packet-up', _('Packet up'));
	o.value('packet-down', _('Packet down'));
	o.value('stream-up', _('Stream up'));
	o.value('stream-down', _('Stream down'));
	o.value('bidi', _('Bidi'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_headers', _('Extra headers'),
		_('JSON object, e.g. {"X-Header": "value"}. Leave empty for none.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_padding_bytes', _('Padding bytes'),
		_('Random padding length range, e.g. 100-1000. Leave empty for the core default.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_sc_max_each_post_bytes', _('Max bytes per POST'),
		_('packet-up mode: max body size of each upload POST, e.g. 1000000-1000000.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_sc_min_posts_interval_ms', _('Min POST interval (ms)'),
		_('packet-up mode: minimum interval between upload POSTs in ms, e.g. 30-30.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	/* XHTTP split download ("dl=h2"/"dl=h3"): the download direction may use a
	 * separate host/path/server and TLS (different SNI/ALPN) from the upload.
	 * Leave these empty to use a single bidirectional stream. */
	o = s.option(form.Value, 'xhttp_download_host', _('Download host'),
		_('Split download: host (Host header / :authority) for the download direction. Leave empty to reuse the upload host.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_path', _('Download path'),
		_('Split download: path for the download direction. Leave empty to reuse the upload path.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_server', _('Download server'),
		_('Optional separate server address for the download direction. Empty reuses the main server (works on hiddify-core; set explicitly for sing-box).'));
	o.datatype = 'host';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_port', _('Download port'));
	o.datatype = 'port';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_sni', _('Download TLS server name'),
		_('TLS SNI for the download direction (often a different CDN/edge host than the upload).'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_alpn', _('Download ALPN'));
	o.value('', _('Default'));
	o.value('h2');
	o.value('h3');
	o.value('http/1.1');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_download_insecure', _('Download allow insecure'),
		_('Allow insecure TLS for the download direction. Use only for testing.'));
	o.default = o.disabled;
	o.depends('transport', 'xhttp');
	o.modalonly = true;
	/* XHTTP config end */

	o = s.option(form.ListValue, 'packet_encoding', _('Packet encoding'));
	o.value('', _('none'));
	o.value('packetaddr', _('packet addr (v2ray-core v5+)'));
	o.value('xudp', _('Xudp (Xray-core)'));
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.modalonly = true;
	/* Transport config end */

	/* Wireguard config start */
	o = s.option(form.DynamicList, 'wireguard_local_address', _('Local address'),
		_('List of IP (v4 or v6) addresses prefixes to be assigned to the interface.'));
	o.datatype = 'cidr';
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_private_key', _('Private key'),
		_('WireGuard requires base64-encoded private keys.'));
	o.password = true;
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.validate = L.bind(hp.validateBase64Key, this, 44);
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_peer_public_key', _('Peer public key'),
		_('WireGuard peer public key.'));
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.validate = L.bind(hp.validateBase64Key, this, 44);
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_pre_shared_key', _('Pre-shared key'),
		_('WireGuard pre-shared key.'));
	o.password = true;
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.validate = L.bind(hp.validateBase64Key, this, 44);
	o.modalonly = true;

	o = s.option(form.DynamicList, 'wireguard_reserved', _('Reserved field bytes'));
	o.datatype = 'integer';
	o.depends('type', 'wireguard');
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_mtu', _('MTU'));
	o.datatype = 'range(0,9000)';
	o.placeholder = '1408';
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_persistent_keepalive_interval', _('Persistent keepalive interval'),
		_('In seconds. Disabled by default.'));
	o.datatype = 'uinteger';
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	/* GitHub issue #3: the WG/AWG network stack is a real choice — lite
	 * sing-box builds ship without gVisor ("gVisor is not included") and the
	 * kernel stack needs its kmod; several WG/AWG endpoints also need the
	 * unique per-endpoint TUN name the generator emits on the system stack. */
	o = s.option(form.ListValue, 'wireguard_backend', _('Network stack'),
		_('auto (default) uses the userspace gVisor stack only when the core binary ships it, otherwise the kernel stack — the wireguard/amneziawg kernel module must be installed (lite sing-box builds have no gVisor and the endpoint fails with "gVisor is not included"). The kernel stack creates a real TUN interface per endpoint; a unique interface name is emitted automatically, so several WG/AWG endpoints can run at once. system forces the kernel stack (faster on ARM routers), gvisor forces the userspace stack.'));
	o.value('', _('Auto'));
	o.value('system', _('system (kernel)'));
	o.value('gvisor', _('gvisor (userspace)'));
	o.depends('type', 'wireguard');
	o.depends('type', 'amneziawg');
	o.modalonly = true;
	/* Wireguard config end */

	/* AmneziaWG config start */
	o = s.option(form.Value, 'amnezia_jc', _('Jc'),
		_('Junk packet count.'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_jmin', _('Jmin'),
		_('Junk packet minimum size.'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_jmax', _('Jmax'),
		_('Junk packet maximum size.'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_s1', _('S1'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_s2', _('S2'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_s3', _('S3'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_s4', _('S4'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_h1', _('H1'),
		_('Magic header range, e.g. 426560850-1096521767'));
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_h2', _('H2'),
		_('Magic header range, e.g. 1603445073-1836768565'));
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_h3', _('H3'),
		_('Magic header range, e.g. 2047861992-2141668339'));
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_h4', _('H4'),
		_('Magic header range, e.g. 2141792848-2142674170'));
	o.depends('type', 'amneziawg');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_i1', _('I1'),
		_('Optional cookie byte sequence in &lt;b 0x...&gt; format.'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_i2', _('I2'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_i3', _('I3'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_i4', _('I4'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_i5', _('I5'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_j1', _('J1'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_j2', _('J2'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_j3', _('J3'));
	o.depends('type', 'amneziawg');
	o.modalonly = true;

	o = s.option(form.Value, 'amnezia_itime', _('ITime'));
	o.datatype = 'uinteger';
	o.depends('type', 'amneziawg');
	o.modalonly = true;
	/* AmneziaWG config end */

	/* Mux config start */
	o = s.option(form.Flag, 'multiplex', _('Multiplex'));
	o.depends('type', 'shadowsocks');
	o.depends('type', 'trojan');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.modalonly = true;

	o = s.option(form.ListValue, 'multiplex_protocol', _('Protocol'),
		_('Multiplex protocol.'));
	o.value('h2mux');
	o.value('smux');
	o.value('yamux');
	o.default = 'h2mux';
	o.depends('multiplex', '1');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_max_connections', _('Maximum connections'));
	o.datatype = 'uinteger';
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_min_streams', _('Minimum streams'),
		_('Minimum multiplexed streams in a connection before opening a new connection.'));
	o.datatype = 'uinteger';
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_max_streams', _('Maximum streams'),
		_('Maximum multiplexed streams in a connection before opening a new connection.<br/>' +
			'Conflict with <code>%s</code> and <code>%s</code>.').format(
				_('Maximum connections'), _('Minimum streams')));
	o.datatype = 'uinteger';
	o.depends({'multiplex': '1', 'multiplex_max_connections': '', 'multiplex_min_streams': ''});
	o.modalonly = true;

	o = s.option(form.Flag, 'multiplex_padding', _('Enable padding'));
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Flag, 'multiplex_brutal', _('Enable TCP Brutal'),
		_('Enable TCP Brutal congestion control algorithm'));
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_brutal_down', _('Download bandwidth'),
		_('Download bandwidth in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('multiplex_brutal', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_brutal_up', _('Upload bandwidth'),
		_('Upload bandwidth in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('multiplex_brutal', '1');
	o.modalonly = true;
	/* Mux config end */

	/* TLS config start */
	o = s.option(form.Flag, 'tls', _('TLS'));
	o.depends('type', 'anytls');
	o.depends('type', 'http');
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.depends('type', 'naive');
	o.depends('type', 'shadowtls');
	o.depends('type', 'trojan');
	o.depends('type', 'trusttunnel');
	o.depends('type', 'tuic');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.validate = function(section_id, _value) {
		if (section_id) {
			let type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
			let tls = this.map.findElement('id', 'cbid.homeproxy.%s.tls'.format(section_id)).firstElementChild;

			if (['anytls', 'hysteria', 'hysteria2', 'shadowtls', 'trusttunnel', 'tuic'].includes(type)) {
				tls.checked = true;
				tls.disabled = true;
			} else {
				tls.disabled = null;
			}
		}

		return true;
	}
	o.modalonly = true;

	o = s.option(form.Value, 'tls_sni', _('TLS SNI'),
		_('Used to verify the hostname on the returned certificates unless insecure is given.'));
	o.depends('tls', '1');
	o.depends({'type': 'shadowsocks', 'shadowtls_enabled': '1'});
	o.modalonly = true;

	o = s.option(form.DynamicList, 'tls_alpn', _('TLS ALPN'),
		_('List of supported application level protocols, in order of preference.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_insecure', _('Allow insecure'),
		_('Allow insecure connection at TLS client.') +
		'<br/>' +
		_('This is <strong>DANGEROUS</strong>, your traffic is almost like <strong>PLAIN TEXT</strong>! Use at your own risk!'));
	o.depends('tls', '1');
	o.depends({'type': 'shadowsocks', 'shadowtls_enabled': '1'});
	o.onchange = allowInsecureConfirm;
	o.modalonly = true;

	o = s.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'),
		_('The minimum TLS version that is acceptable.'));
	o.value('', _('default'));
	for (let i of hp.tls_versions)
		o.value(i);
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
		_('The maximum TLS version that is acceptable.'));
	o.value('', _('default'));
	for (let i of hp.tls_versions)
		o.value(i);
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(hp.CBIStaticList, 'tls_cipher_suites', _('Cipher suites'),
		_('The elliptic curves that will be used in an ECDHE handshake, in preference order. If empty, the default will be used.'));
	for (let i of hp.tls_cipher_suites)
		o.value(i);
	o.depends('tls', '1');
	o.optional = true;
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_self_sign', _('Append self-signed certificate'),
		_('If you have the root certificate, use this option instead of allowing insecure.'));
	o.depends('tls_insecure', '0');
	o.modalonly = true;

	o = s.option(form.Value, 'tls_cert_path', _('Certificate path'),
		_('The path to the server certificate, in PEM format.'));
	o.value('/etc/homeproxy/certs/client_ca.pem');
	o.depends('tls_self_sign', '1');
	o.validate = hp.validateCertificatePath;
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
		_('<strong>Save your configuration before uploading files!</strong>'));
	o.inputstyle = 'action';
	o.inputtitle = _('Upload...');
	o.depends({'tls_self_sign': '1', 'tls_cert_path': '/etc/homeproxy/certs/client_ca.pem'});
	o.onclick = L.bind(hp.uploadCertificate, this, _('certificate'), 'client_ca');
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_ech', _('Enable ECH'),
		_('ECH (Encrypted Client Hello) is a TLS extension that allows a client to encrypt the first part of its ClientHello message.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'tls_ech_config_path', _('ECH config path'),
		_('The path to the ECH config, in PEM format. If empty, load from DNS will be attempted.'));
	o.value('/etc/homeproxy/certs/client_ech_conf.pem');
	o.depends('tls_ech', '1');
	o.modalonly = true;

	o = s.option(form.Button, '_upload_ech_config', _('Upload ECH config'),
		_('<strong>Save your configuration before uploading files!</strong>'));
	o.inputstyle = 'action';
	o.inputtitle = _('Upload...');
	o.depends({'tls_ech': '1', 'tls_ech_config_path': '/etc/homeproxy/certs/client_ech_conf.pem'});
	o.onclick = L.bind(hp.uploadCertificate, this, _('ECH config'), 'client_ech_conf');
	o.modalonly = true;

	if (features.with_utls) {
		o = s.option(form.ListValue, 'tls_utls', _('uTLS fingerprint'),
			_('uTLS is a fork of "crypto/tls", which provides ClientHello fingerprinting resistance.'));
		o.value('', _('Disable'));
		o.value('360');
		o.value('android');
		o.value('chrome');
		o.value('edge');
		o.value('firefox');
		o.value('ios');
		o.value('qq');
		o.value('random');
		o.value('randomized');
		o.value('safari');
		o.depends({'tls': '1', 'type': /^((?!hysteria2?|tuic$).)+$/});
		o.depends({'type': 'shadowsocks', 'shadowtls_enabled': '1'});
		o.validate = function(section_id, value) {
			if (section_id) {
				let tls_reality = this.map.findElement('id', 'cbid.homeproxy.%s.tls_reality'.format(section_id)).firstElementChild;
				if (tls_reality.checked && !value)
					return _('Expecting: %s').format(_('non-empty value'));

				let vless_flow = this.map.lookupOption('vless_flow', section_id)[0].formvalue(section_id);
				if ((tls_reality.checked || vless_flow) && ['360', 'android'].includes(value))
					return _('Unsupported fingerprint!');
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_reality', _('REALITY'));
		o.depends({'tls': '1', 'type': 'anytls'});
		o.depends({'tls': '1', 'type': 'vless'});
		o.modalonly = true;

		o = s.option(form.Value, 'tls_reality_public_key', _('REALITY public key'));
		o.password = true;
		o.depends('tls_reality', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_reality_short_id', _('REALITY short ID'));
		o.password = true;
		o.depends('tls_reality', '1');
		o.modalonly = true;
	}
	/* TLS config end */

	/* Extra settings start */
	o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'));
	o.modalonly = true;

	o = s.option(form.Flag, 'tcp_multi_path', _('MultiPath TCP'));
	o.modalonly = true;

	o = s.option(form.Flag, 'udp_fragment', _('UDP Fragment'),
		_('Enable UDP fragmentation.'));
	o.modalonly = true;

	o = s.option(widgets.DeviceSelect, 'bind_interface', _('Binded interface'),
		_('The network interface to bind to.'));
	o.multiple = false;
	o.noaliases = true;
	o.modalonly = true;

	o = s.option(form.Flag, 'udp_over_tcp', _('UDP over TCP'),
		_('Enable the SUoT protocol, requires server support. Conflict with multiplex.'));
	o.depends('type', 'socks');
	o.depends({'type': 'shadowsocks', 'multiplex': '0'});
	o.modalonly = true;

	o = s.option(form.ListValue, 'udp_over_tcp_version', _('SUoT version'));
	o.value('1', _('v1'));
	o.value('2', _('v2'));
	o.default = '2';
	o.depends('udp_over_tcp', '1');
	o.modalonly = true;
	/* Extra settings end */

	return s;
}

/* ── RPCs (Ф9.11) ─────────────────────────────────────────────────────────
 * The subscription update is ASYNC (lesson 294: a sync RPC longer than ~30 s
 * breaks the shared ubus stream — the update cycle with fetch + verify runs
 * 40+ s): start spawns the detached runner, the status file is polled. The
 * smart import is a read-only server-side parse through the SAME parser set
 * the subscription importer uses. */
const callSubUpdateStart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_subscription_update_start',
	params: [ 'url' ],
	expect: { '': {} }
});

const callSubAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_subscription_add',
	params: [ 'url' ],
	expect: { '': {} }
});

const callSubRemove = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_subscription_remove',
	params: [ 'url' ],
	expect: { '': {} }
});

const callImportNodes = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_import_nodes',
	params: [ 'text' ],
	expect: { '': {} }
});

const callServiceRestart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_service_restart',
	expect: { '': {} }
});

const callOpStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

const NODE_CSS = `
	.node-sum { margin: 10px 0 14px; }
	.node-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 10px; margin-top: 10px; }
	.node-sub-card { display: flex; flex-direction: column; gap: 7px; padding: 12px 14px; flex: none; }
	.node-sub-top { display: flex; align-items: baseline; gap: 7px; flex-wrap: wrap; }
	.node-sub-title { font-weight: 700; font-size: 1.02em; overflow: hidden; text-overflow: ellipsis; }
	.node-sub-host { font-size: .82em; opacity: .7; word-break: break-all; }
	.node-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: auto; padding-top: 8px; border-top: 1px solid var(--hp-panel-line); }
	.node-actions .hpui-btn { padding: 4px 10px; font-size: .84em; flex: none; }
	.node-addrow { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; align-items: center; }
	.node-addrow > input { flex: 1 1 320px; }
	.node-urls { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
	.node-url-row { display: flex; align-items: center; gap: 8px; padding: 7px 10px;
		border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius-lg);
		background: var(--hp-panel-bg-2); }
	.node-url-text { flex: 1 1 auto; min-width: 0; font-family: var(--hp-font-mono);
		font-size: .84em; opacity: .85; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.node-url-row .hpui-btn { flex: none; }
	.node-url-hint { margin: 6px 0 0; }
	.node-result { margin-top: 10px; padding: 10px 12px; border: 1px solid var(--hp-panel-line); border-radius: 8px; background: var(--background-color-low); }
	.node-result p { margin: 2px 0; }
	.node-panel-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
`;

/* Verdict vocabulary of the update cycle (update_subscriptions.uc actions
 * and per-group statuses) — rendered in ONE place (the panel result area). */
const SUB_ACT = {
	applied: _('Nodes updated'),
	aborted: _('Update declined — nodes untouched'),
	rolled_back: _('Update rolled back — nodes restored from the backup'),
	failed: _('Update failed')
};

const SUB_GST = {
	ok: _('OK'),
	html: _('server returned an HTML page — skipped'),
	no_valid: _('no valid node in the response — skipped'),
	fetch_failed: _('fetch failed — skipped')
};

const SUB_CHIP = {
	ok: [ 'hpui-b-green', _('OK') ],
	html: [ 'hpui-b-amber', _('HTML page') ],
	no_valid: [ 'hpui-b-amber', _('No valid nodes') ],
	fetch_failed: [ 'hpui-b-red', _('Fetch failed') ]
};

return view.extend({
	load() {
		return Promise.all([
			uci.load('homeproxy'),
			hp.getBuiltinFeatures(),
			L.resolveDefault(callSubscriptionStatus(), null)
		]);
	},

	render(data) {
		hp.uiShell();

		const stEl = document.getElementById('hp-node-style');
		if (!stEl)
			document.head.appendChild(E('style', { id: 'hp-node-style' }, [ NODE_CSS ]));

		const features = data[1];
		const main_node = uci.get(data[0], 'config', 'main_node');
		const routing_mode = uci.get(data[0], 'config', 'routing_mode');
		let subStatus = data[2] || { last: null, groups: {}, node_total: 0 };

		/* Subscription info from the UCI list — hash with the SAME FNV-1a the
		 * subscription daemon uses (the old MD5 here made group matching break). */
		function subInfoList() {
			const v = uci.get(data[0], 'subscription', 'subscription_url');
			const list = (v == null) ? [] : (Array.isArray(v) ? v : [ v ]);
			return list.map(function(suburl) {
				let url = null;
				try { url = new URL(suburl); } catch (e) { url = null; }
				const urlhash = hp.calcStringFNV(suburl.replace(/#.*$/, ''));
				const title = (url && url.hash) ? decodeURIComponent(url.hash.slice(1)) :
					(url ? url.hostname : suburl);
				return { url: suburl, hash: urlhash, title: title, host: url ? url.hostname : suburl };
			});
		}

		function groupCount(hash) {
			return (subStatus.groups && subStatus.groups[hash]) || 0;
		}

		function groupLine(hash) {
			const last = subStatus.last;
			if (!last || !last.groups)
				return null;
			for (let i = 0; i < last.groups.length; i++)
				if (last.groups[i].hash === hash)
					return last.groups[i];
			return null;
		}

		/* ── Summary cards — built once, the poll updates numbers IN PLACE ── */
		const sumDefs = [
			{ l: _('Nodes'), c: '' },
			{ l: _('Own nodes'), c: 'hpui-c-blue' },
			{ l: _('From subscriptions'), c: '' },
			{ l: _('Active'), c: 'hpui-c-green' }
		];
		const sumNums = sumDefs.map(function(d) {
			return E('div', { 'class': 'hpui-num ' + d.c }, [ '—' ]);
		});
		const sumBox = E('div', { 'class': 'hpui-cards hpui-stagger node-sum' },
			sumDefs.map(function(d, i) {
				return E('div', { 'class': 'hpui-card' }, [
					sumNums[i],
					E('div', { 'class': 'hpui-cap' }, [ d.l ])
				]);
			}));

		function updateSummary() {
			const sections = uci.sections(data[0], 'node');
			let mine = 0, sub = 0, active = 0;
			sections.forEach(function(s) {
				if (s.grouphash)
					sub++;
				else
					mine++;
			});
			Object.keys(NODE_STATUS).forEach(function(sid) {
				if (NODE_STATUS[sid] && NODE_STATUS[sid].selected)
					active++;
			});
			const vals = [ sections.length, mine, sub, active ];
			sumDefs.forEach(function(d, i) { sumNums[i].textContent = String(vals[i]); });
		}

		/* ── Result area: ONE place for every panel action outcome ── */
		const subResult = E('div', { 'class': 'node-result', 'style': 'display:none' }, []);

		function note(ok, text) {
			subResult.style.display = '';
			dom.content(subResult, E('p', { 'class': 'hpui-hint' }, [
				E('span', { 'class': ok ? 'hpui-c-green' : 'hpui-c-red' }, [ text ])
			]));
		}

		function busy(text) {
			subResult.style.display = '';
			dom.content(subResult, E('p', { 'class': 'hpui-hint' }, [ text ]));
		}

		function renderVerdict(last) {
			const body = [];
			body.push(E('p', { style: 'font-weight:bold' }, [ SUB_ACT[last.action] || last.action ]));
			if (last.totals)
				body.push(E('p', {}, _('Nodes: %s before, %s after (+%s/−%s; kept unchanged: %s)')
					.format(last.totals.before, last.totals.after, last.totals.added,
						last.totals.removed, last.totals.kept)));
			const hostOf = (u) => String(u || '').replace(/^https?:\/\//, '').split(/[#/]/)[0];
			(last.groups || []).forEach(function(g) {
				body.push(E('p', { style: 'margin:2px 0; font-size:.9em' }, [
					_('%s · %s → %s (+%s/−%s, unchanged %s)').format(
						hostOf(g.url), SUB_GST[g.status] || g.status,
						g.parsed, g.added, g.removed, g.kept)
				]));
			});
			if (last.reason)
				body.push(E('p', { style: 'color:#d99a1b' }, [ last.reason ]));
			if (last.backup)
				body.push(E('p', { style: 'font-size:.9em; opacity:.8' }, _('Backup') + ': ' + last.backup));
			if (last.verify && last.verify.restarted === false) {
				body.push(E('p', { style: 'font-size:.9em; opacity:.8' },
					[_('The service was not restarted — new nodes apply on the next restart.')]));
				body.push(E('div', { style: 'margin-top:6px' }, [
					E('button', { 'class': 'hpui-btn hpui-btn-primary hpui-btn-sm', 'click': applyNow },
						[ _('Apply now') ])
				]));
			}
			subResult.style.display = '';
			dom.content(subResult, body);
		}

		/* ── Async subscription update (start + status poll) ── */
		let updating = false;

		function startUpdate(url) {
			if (updating) {
				note(false, _('An update is already running'));
				return;
			}
			updating = true;
			busy(_('Fetching nodes, please wait...'));
			/* The runner overwrites the status file a few seconds AFTER the
			 * spawn (the service stop comes first) — poll for the ts CHANGE
			 * before trusting running:false, or the PREVIOUS run's verdict
			 * is rendered (caught live: the panel showed the old cycle). */
			const prevTs = (subStatus.last && subStatus.last.ts) ? subStatus.last.ts : 0;
			const tsDeadline = Date.now() + 45000;
			L.resolveDefault(callSubUpdateStart(url || ''), null).then(function(r) {
				if (!r || r.result === false) {
					updating = false;
					note(false, (r && r.error) ? r.error : _('Failed to start the update'));
					return;
				}
				const deadline = Date.now() + 600000;
				const tick = function() {
					return L.resolveDefault(callSubscriptionStatus(), null).then(function(st) {
						const last = st && st.last;
						if (!last || (('' + (last.ts || 0)) === ('' + prevTs))) {
							if (Date.now() > tsDeadline) {
								updating = false;
								note(false, _('The update did not report its start — see the log on the router.'));
								return;
							}
							return new Promise(function(res) { setTimeout(res, 2000); }).then(tick);
						}
						if (last.running && Date.now() < deadline)
							return new Promise(function(res) { setTimeout(res, 2000); }).then(tick);
						updating = false;
						if (st) {
							subStatus = st;
							rebuildSubCards();
						}
						if (last) {
							renderVerdict(last);
							return refreshNodeStatuses();
						}
						note(false, _('Update finished (no status report — it was produced before this feature existed).'));
					});
				};
				return tick();
			}).catch(function(e) {
				updating = false;
				note(false, _('Failed to start the update') + ': ' + (e && e.message ? e.message : ''));
			});
		}

		/* Apply now: restart the service so subscription-fetched nodes go
		 * live at once (a tracked operation, polled to the honest verdict).
		 * `after` runs once the verdict is in (click events pass an Event —
		 * guard by type). */
		function applyNow(after) {
			busy(_('Restarting the service…'));
			L.resolveDefault(callServiceRestart(), null).then(function(r) {
				if (!r || (r.result === false && !r.op_id)) {
					note(false, _('Restart failed: ') + ((r && r.error) || _('rpc error')));
					return;
				}
				const deadline = Date.now() + 150000;
				const tick = function() {
					return L.resolveDefault(callOpStatus(r.op_id), {}).then(function(st) {
						const op = st && st.op;
						if (op && op.status !== 'completed' && op.status !== 'failed' &&
						    Date.now() < deadline)
							return new Promise(function(res) { setTimeout(res, 2000); }).then(tick);
						if (op && op.status === 'completed') {
							note(true, _('Service restarted — the new nodes are live.'));
							subStatus = { last: null, groups: {}, node_total: 0 };
							rebuildSubCards();
							if (typeof after === 'function')
								after();
							return refreshNodeStatuses();
						}
						note(false, _('The restart is still running — see the operations journal on the Health center page.'));
					});
				};
				return tick();
			});
		}

		/* ── Subscription cards ── */
		const subCards = E('div', { 'class': 'node-cards' }, []);
		/* The raw subscription links (the former cbi DynamicList — it looked
		 * alien next to the cards and its client-side edit fought the RPC
		 * add/remove): one line per URL, hpui buttons, under the add row. */
		const subUrls = E('div', { 'class': 'node-urls', 'style': 'display:none' }, []);

		function statusChip(hash) {
			const last = subStatus.last;
			const g = groupLine(hash);
			if (!g)
				/* the group simply did not take part in the LAST run (a
				 * single-URL update touches only its own group) — that is
				 * honest-neutral, not «never updated» */
				return E('span', { 'class': 'hpui-badge hpui-b-grey' },
					[ (last && last.ts) ? _('Not in the last run') : _('Not updated yet') ]);
			const m = SUB_CHIP[g.status] || [ 'hpui-b-grey', g.status ];
			return E('span', { 'class': 'hpui-badge ' + m[0] }, [ m[1] ]);
		}

		function rebuildSubCards() {
			const infos = subInfoList();
			dom.content(subCards, infos.map(function(info) {
				return E('div', { 'class': 'hpui-card node-sub-card' }, [
					E('div', { 'class': 'node-sub-top' }, [
						E('span', { 'class': 'node-sub-title' }, [ info.title ]),
						statusChip(info.hash),
						E('span', { 'class': 'hpui-badge hpui-b-blue' },
							[ _('%s nodes').format(groupCount(info.hash)) ])
					]),
					E('div', { 'class': 'node-sub-host' }, [ info.host ]),
					E('div', { 'class': 'node-actions' }, [
						E('button', { 'class': 'hpui-btn hpui-btn-sm hpui-btn-ghost',
							'click': function() { startUpdate(info.url); } }, [ _('Update') ]),
						E('button', { 'class': 'hpui-btn hpui-btn-sm hpui-btn-danger',
							'click': function() { removeSubscription(info); } }, [ _('Remove') ])
					])
				]);
			}));
			if (!infos.length)
				dom.content(subCards,
					E('p', { 'class': 'hpui-hint' }, [ _('No subscriptions yet — add a provider link below.') ]));

			/* The raw links, one line each: the same Update/Remove actions as
			 * the cards, but on the address itself. */
			subUrls.style.display = infos.length ? '' : 'none';
			dom.content(subUrls, infos.map(function(info) {
				return E('div', { 'class': 'node-url-row', 'title': info.url }, [
					E('span', { 'class': 'node-url-text' }, [ info.url ]),
					E('button', { 'class': 'hpui-btn hpui-btn-sm hpui-btn-ghost',
						'click': function() { startUpdate(info.url); } }, [ _('Update') ]),
					E('button', { 'class': 'hpui-btn hpui-btn-sm hpui-btn-danger',
						'click': function() { removeSubscription(info); } }, [ _('Remove') ])
				]);
			}));
		}

		/* Remove a subscription SERVER-SIDE (Ф9.11): the URL leaves the list
		 * AND its nodes are cleaned up with the same pointer pruning the
		 * update cycle does. Client-side uci.set is NOT used here — the
		 * form's own save overwrites client-staged deltas with the form
		 * values (caught live: a removed subscription returned to UCI).
		 * When nodes were removed the kernel config changes too: the modal
		 * says so up front and the verified restart runs right away. */
		function removeSubscription(info) {
			const cnt = groupCount(info.hash);
			const lines = [
				E('p', {}, _('Remove the subscription «%s» and its %s nodes? The subscription URL is deleted from the settings.').format(info.title, cnt))
			];
			if (cnt > 0)
				lines.push(E('p', { 'class': 'hpui-hint' },
					[ _('The service will be restarted to remove them from the core.') ]));
			lines.push(E('div', { 'class': 'right', 'style': 'display:flex;gap:8px;justify-content:flex-end;margin-top:10px' }, [
				E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal },
					[ _('Cancel') ]),
				E('button', { 'class': 'hpui-btn hpui-btn-danger', 'click': function() {
					ui.hideModal();
					busy(_('Removing the subscription…'));
					L.resolveDefault(callSubRemove(info.url), null).then(function(r) {
						if (!r || r.result === false) {
							note(false, (r && r.error) || _('Operation failed'));
							return;
						}
					if (r.need_restart)
						return applyNow(function() {
							setTimeout(function() { location.reload(); }, 1500);
						});
					note(true, _('Subscription removed (no nodes — nothing to apply).'));
					setTimeout(function() { location.reload(); }, 1500);
					});
				} }, [ _('Remove') ])
			]));
			ui.showModal(_('Remove subscription'), lines);
		}

		/* Add a subscription URL (the #fragment becomes the display title). */
		const subUrlInput = E('input', {
			'type': 'text', 'class': 'cbi-input-text',
			'placeholder': 'https://provider.example/sub/token#Title'
		});

		function addSubscription() {
			const raw = String(subUrlInput.value || '').trim();
			if (!raw) {
				note(false, _('Enter the subscription URL'));
				return;
			}
			let parsed = null;
			try { parsed = new URL(raw); } catch (e) { parsed = null; }
			if (!parsed || !parsed.hostname) {
				note(false, _('Expecting: %s').format(_('valid URL')));
				return;
			}
			/* Server-side add (client-side uci.set would be overwritten by the
			 * form's own save — caught live). The page reloads after the
			 * verdict so every widget (cards + the settings form) is fresh. */
			L.resolveDefault(callSubAdd(raw), null).then(function(r) {
				if (!r || r.result === false) {
					note(false, (r && r.error) || _('Operation failed'));
					return;
				}
				subUrlInput.value = '';
				note(true, _('Subscription added.'));
				setTimeout(function() { location.reload(); }, 1500);
			});
		}

		/* ── Smart import (Ф9.11): the SERVER parses — one parser set for
		 * links, base64 batches, sing-box JSON, clash/mihomo YAML. Feature
		 * gates are gone (D34c): a node the running core cannot load is
		 * imported anyway and shows the honest «Unsupported by core». ── */
		function showImport() {
			const textarea = new ui.Textarea();
			const fileInput = E('input', { 'type': 'file', 'style': 'display:block;margin:8px 0' });
			const summary = E('div', {});

			function parseText(text) {
				const t = String(text || '').trim();
				if (!t) {
					dom.content(summary, E('p', { 'class': 'hpui-hint' }, [ _('Nothing to parse') ]));
					return;
				}
				dom.content(summary, E('p', { 'class': 'hpui-hint' }, [ _('Parsing…') ]));
				L.resolveDefault(callImportNodes(t), null).then(function(r) {
					if (!r || r.result === false) {
						dom.content(summary, E('p', { 'class': 'hpui-hint' }, [
							E('span', { 'class': 'hpui-c-red' }, [ (r && r.error) || _('Parse failed') ])
						]));
						return;
					}
					const lines = [];
					lines.push(E('p', { 'class': 'hpui-hint' }, [
						E('span', { 'class': r.nodes.length ? 'hpui-c-green' : 'hpui-c-red' },
							[ _('%s node(s) recognized (%s), %s skipped.').format(
								r.nodes.length, r.format || '?', r.skipped.length) ])
					]));
					r.skipped.slice(0, 5).forEach(function(sk) {
						lines.push(E('p', { 'class': 'hpui-hint', 'style': 'opacity:.75' }, [ sk ]));
					});
					if (r.nodes.length)
						lines.push(E('div', { 'class': 'right', 'style': 'margin-top:8px' }, [
							E('button', { 'class': 'hpui-btn hpui-btn-primary', 'click': function() {
								const existing = new Set(
									uci.sections(data[0], 'node').map(function(s) { return s.label; })
										.filter(Boolean));
								r.nodes.forEach(function(cfg) {
									let label = cfg.label;
									if (existing.has(label)) {
										const base = label;
										let n = 2;
										while (existing.has(base + '-' + n)) n++;
										label = base + '-' + n;
									}
									existing.add(label);
									cfg.label = label;
									const sid = uci.add(data[0], 'node');
									Object.keys(cfg).forEach(function(k) {
										if (cfg[k] != null)
											uci.set(data[0], sid, k,
												Array.isArray(cfg[k]) ? cfg[k] : String(cfg[k]));
									});
								});
								ui.hideModal();
								return m.save(null, true)
									.then(function() { return ui.changes.apply(true); })
									.then(function() { location.reload(); });
							} }, [ _('Import %s nodes').format(r.nodes.length) ])
						]));
					dom.content(summary, lines);
				});
			}

			ui.showModal(_('Import nodes'), [
				E('p', _('Paste share links, a base64 batch, sing-box JSON or clash/mihomo YAML — or pick a file. The server parses the SAME formats as subscriptions (no core-capability filtering: a node the current core cannot load is still saved).')),
				textarea.render(),
				fileInput,
				summary,
				E('div', { 'class': 'right', 'style': 'display:flex;gap:8px;justify-content:flex-end;margin-top:10px' }, [
					E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal },
						[ _('Cancel') ]),
					E('button', { 'class': 'hpui-btn hpui-btn-primary', 'click': function() {
						const file = fileInput.files[0];
						if (file) {
							const reader = new FileReader();
							reader.onload = function(ev) { parseText(ev.target.result); };
							reader.readAsText(file);
						} else
							parseText(textarea.getValue());
					} }, [ _('Parse') ])
				])
			]);
		}

		/* WireGuard/AmneziaWG .conf import (client-side — the one format the
		 * server parser set does not carry). */
		function showConfImport() {
			const fileInput = E('input', { 'type': 'file', 'accept': '.conf', 'style': 'display:block;margin:8px 0' });
			ui.showModal(_('Import .conf file'), [
				E('p', _('Select a WireGuard or AmneziaWG .conf file.')),
				fileInput,
				E('div', { 'class': 'right', 'style': 'display:flex;gap:8px;justify-content:flex-end;margin-top:10px' }, [
					E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal },
						[ _('Cancel') ]),
					E('button', { 'class': 'hpui-btn hpui-btn-primary', 'click': function() {
						const file = fileInput.files[0];
						if (!file)
							return ui.hideModal();

						new Promise(function(resolve) {
							const reader = new FileReader();
							reader.onload = function(ev) { resolve(ev.target.result); };
							reader.readAsText(file);
						}).then(function(text) {
							const config = parseWireGuardConf(text);
							if (!config) {
								ui.hideModal();
								return note(false, _('No valid WireGuard/AmneziaWG config found.'));
							}

							/* Ф5.3 (аудит 51): та же планка, что у серверных
							 * импортёров — битый узел не создаётся. */
							const verrs = validateWireGuardNode(config);
							if (verrs) {
								ui.hideModal();
								return note(false,
									_('Node failed validation: %s').format(verrs.join('; ')));
							}

							const existing = new Set(
								uci.sections(data[0], 'node').map(function(s) { return s.label; })
									.filter(Boolean));
							if (existing.has(config.label)) {
								const base = config.label;
								let n = 2;
								while (existing.has(base + '-' + n)) n++;
								config.label = base + '-' + n;
							}

							const sid = uci.add(data[0], 'node');
							for (const k in config)
								if (config[k] != null)
									uci.set(data[0], sid, k,
										Array.isArray(config[k]) ? config[k] : String(config[k]));

							ui.hideModal();
							note(true, _('Successfully imported node: %s').format(config.label));
							return m.save(null, true)
								.then(function() { return ui.changes.apply(true); })
								.then(function() { location.reload(); });
						});
					} }, [ _('Import') ])
				])
			]);
		}

		/* ── The form: subscription settings + node grids (NO tabs — Ф9.11) ── */
		let m, s, o, ss;

		m = new form.Map('homeproxy');

		s = m.section(form.NamedSection, 'subscription', 'homeproxy');
		s.title = _('Subscription settings');
		s.description = _('Auto update, the fetch path (direct or via proxy), filters and defaults for imported nodes.');

		o = s.option(form.Flag, 'auto_update', _('Auto update'),
			_('Auto update subscriptions and geodata.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'auto_update_time', _('Update time'));
		for (let i = 0; i < 24; i++)
			o.value(i, i + ':00');
		o.default = '2';
		o.depends('auto_update', '1');

		o = s.option(form.Flag, 'update_via_proxy', _('Update via proxy'),
			_('Update subscriptions via proxy: the fetch goes through the running proxy and the service is NOT stopped (no internet gap), but the new nodes apply on the next restart — the panel shows an «Apply now» button then.'));
		o.rmempty = false;

		/* The subscription_url list itself is NOT a form option anymore: it
		 * lives in the panel above (one line per URL) and is mutated ONLY by
		 * the server-side RPCs (app_subscription_add/remove) — the old cbi
		 * DynamicList both looked stale and let the form's save fight the
		 * RPC changes (lesson 323 shape). */

		o = s.option(form.ListValue, 'filter_nodes', _('Filter nodes'),
			_('Drop/keep specific nodes from subscriptions.'));
		o.value('disabled', _('Disable'));
		o.value('blacklist', _('Blacklist mode'));
		o.value('whitelist', _('Whitelist mode'));
		o.default = 'disabled';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'filter_keywords', _('Filter keywords'),
			_('Drop/keep nodes that contain the specific keywords. <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions">Regex</a> is supported.'));
		o.depends({'filter_nodes': 'disabled', '!reverse': true});
		o.rmempty = false;

		o = s.option(form.Value, 'user_agent', _('User-Agent'));
		o.placeholder = 'Wget/1.21 (HomeProxy, like v2rayN)';

		o = s.option(form.Flag, 'allow_insecure', _('Allow insecure'),
			_('Allow insecure connection by default when add nodes from subscriptions.') +
			'<br/>' +
			_('This is <strong>DANGEROUS</strong>, your traffic is almost like <strong>PLAIN TEXT</strong>! Use at your own risk!'));
		o.rmempty = false;
		o.onchange = allowInsecureConfirm;

		o = s.option(form.ListValue, 'packet_encoding', _('Default packet encoding'));
		o.value('', _('none'));
		o.value('packetaddr', _('packet addr (v2ray-core v5+)'));
		o.value('xudp', _('Xudp (Xray-core)'));

		o = s.option(form.Button, '_save_subscriptions', _('Save subscriptions settings'),
			_('NOTE: Save current settings before updating subscriptions.'));
		o.inputstyle = 'apply';
		o.inputtitle = _('Save current settings');
		o.onclick = function() {
			return this.map.save(null, true).then(() => {
				ui.changes.apply(true);
			});
		}

		/* ── Own nodes ── */
		o = s.option(form.SectionValue, '_node', form.GridSection, 'node');
		ss = o.subsection;
		ss.title = _('Own nodes');
		ss.description = _('Your own servers: import share links, a base64 batch, sing-box JSON, clash YAML or a WireGuard .conf file, or add a node manually. Click a row to edit it. The Live status column shows what the running core currently measures.');
		renderNodeSettings(ss, data, features, main_node, routing_mode);
		ss.addremove = true;
		ss.filter = function(section_id) {
			return !uci.get(data[0], section_id, 'grouphash');
		}
		ss.renderSectionAdd = function(/* ... */) {
			let el = form.GridSection.prototype.renderSectionAdd.apply(this, arguments),
				nameEl = el.querySelector('.cbi-section-create-name');

			ui.addValidator(nameEl, 'uciname', true, (v) => {
				let button = el.querySelector('.cbi-section-create > .cbi-button-add');
				let uciconfig = this.uciconfig || this.map.config;

				if (!v) {
					button.disabled = true;
					return true;
				} else if (uci.get(uciconfig, v)) {
					button.disabled = true;
					return _('Expecting: %s').format(_('unique UCI identifier'));
				} else {
					button.disabled = null;
					return true;
				}
			}, 'blur', 'keyup');

			el.appendChild(E('button', {
				'class': 'hpui-btn hpui-btn-sm hpui-btn-primary',
				'title': _('Import nodes'),
				'click': showImport
			}, [ _('Import nodes') ]));

			el.appendChild(E('button', {
				'class': 'hpui-btn hpui-btn-sm hpui-btn-ghost',
				'title': _('Import .conf file'),
				'click': showConfImport
			}, [ _('Import .conf') ]));

			return el;
		}

		/* ── Subscription node groups ── */
		subInfoList().forEach(function(info) {
			o = s.option(form.SectionValue, '_sub_' + info.hash, form.GridSection, 'node');
			ss = o.subsection;
			ss.title = _('Subscription: %s').format(info.title);
			ss.description = info.host;
			renderNodeSettings(ss, data, features, main_node, routing_mode);
			ss.filter = function(section_id) {
				return (uci.get(data[0], section_id, 'grouphash') === info.hash);
			}
		});

		/* ── Live statuses: one immediate refresh, then every 5 s (same RPC
		 * as the Monitoring page — one status source for the whole app). ── */
		poll.add(function() {
			return refreshNodeStatuses().then(updateSummary);
		}, hp.pollSec(5));
		refreshNodeStatuses().then(updateSummary);

		rebuildSubCards();

		/* Panel header actions (one result area below the cards) */
		const panelHead = E('div', { 'class': 'node-panel-head' }, [
			E('button', { 'class': 'hpui-btn hpui-btn-primary', 'click': function() { startUpdate(''); } },
				[ subInfoList().length > 1 ? _('Update all') : _('Update') ]),
			E('button', {
				'class': 'hpui-btn hpui-btn-ghost',
				'style': ((subStatus.last && subStatus.last.verify &&
				           subStatus.last.verify.restarted === false) ? '' : 'display:none'),
				'click': applyNow
			}, [ _('Apply now') ])
		]);

		const subPanel = E('div', { 'class': 'hpui-card', 'style': 'padding:14px 16px; margin-top:6px' }, [
			panelHead,
			subCards,
			E('div', { 'class': 'node-addrow' }, [
				subUrlInput,
				E('button', { 'class': 'hpui-btn hpui-btn-primary', 'click': addSubscription },
					[ _('Add subscription') ])
			]),
			subUrls,
			E('p', { 'class': 'hpui-hint node-url-hint' },
				[ _('Formats served by panels: URI lists, base64 batches, sing-box JSON (User-Agent «sing-box»), Xray JSON, SIP008, clash/mihomo YAML. The #fragment becomes the display title.') ]),
			subResult
		]);

		return m.render().then(function(node) {
			return E('div', {}, [
				hp.pageIntro(_('Servers'),
					_('The servers the connection runs through: your own nodes (share link, base64 batch, sing-box JSON, clash YAML, .conf file or by hand) and provider subscriptions with automatic updates. The Live status column shows what the running core currently measures for every node. Which server is used as the main one — on the Connection page.')),
				sumBox,
				subPanel,
				node
			]);
		});
	}
});

