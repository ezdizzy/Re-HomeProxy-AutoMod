/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Devices (R3 v3d, 19-UX_REDESIGN §5): the ONE home page for
 * devices. Two former places are merged here:
 *  - the homecontrol registry (the "Devices" pane of Parental control):
 *    add devices from the live network (MAC identity), rename/remove,
 *    per-device internet actions (block/temp/wifi) shared with the
 *    control engine and the Telegram bot;
 *  - the proxy policy (the former "Devices & interfaces" page): per-device
 *    LAN mode, WAN IP policy and interface binding.
 * Every device row is a card with the three honest states: online /
 * internet / proxy. The registry view in Parental control keeps only a
 * link here.
 */

'use strict';
'require dom';
'require form';
'require network';
'require poll';
'require rpc';
'require ui';
'require uci';
'require view';

'require homeproxy as hp';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';

const callStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_status',
	expect: { '': {} }
});

const callDevices = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_devices',
	expect: { '': {} }
});

const callClientAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_add',
	params: [ 'name', 'mac', 'ip' ],
	expect: { '': {} }
});

const callClientDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_delete',
	params: [ 'id' ],
	expect: { '': {} }
});

const callClientRename = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_rename',
	params: [ 'id', 'name' ],
	expect: { '': {} }
});

const callClientBlock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_block',
	params: [ 'id', 'blocked' ],
	expect: { '': {} }
});

const callClientTempBlock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_temp_block',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callClientTempUnblock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_temp_unblock',
	params: [ 'id' ],
	expect: { '': {} }
});

const callClientTempAllow = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_temp_allow',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callClientWifiBlock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_wifi_block',
	params: [ 'id', 'blocked' ],
	expect: { '': {} }
});

const CSS = `
	.dev-field { display: flex; flex-direction: column; gap: 4px; min-width: 160px; flex: 1 1 160px; }
	.dev-field > label { font-size: .82em; font-weight: 600; opacity: .75; }
	.dev-field > input, .dev-field > select { width: 100%; max-width: 420px; box-sizing: border-box; }
	.dev-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; }
	.dev-form .dev-wide { flex: 3 1 320px; }
	.dev-actions { display: flex; gap: 6px; flex-wrap: wrap; }
	.dev-actions .btn { flex: none; }
	.dev-result-wrap { margin-top: 6px; }
	.dev-badge-wifi { margin-left: 6px; }
	.dev-sum { margin: 10px 0 16px; }
`;

/* ── formatting helpers (shared with control.js, same shapes) ────────── */

function fmtRemaining(untilSec) {
	const ms = untilSec * 1000 - Date.now();
	const m = Math.max(0, Math.round(ms / 60000));
	if (m < 60)
		return m + ' ' + _('min');
	const h = Math.floor(m / 60), mm = m % 60;
	if (h < 24)
		return h + ' ' + _('h') + (mm ? (' ' + mm + ' ' + _('min')) : '');
	const d = Math.floor(h / 24);
	return d + ' ' + _('d') + ' ' + (h % 24) + ' ' + _('h');
}

function fmtMinutesHuman(mins) {
	if (mins >= 1440 && (mins % 1440) === 0)
		return (mins / 1440) + ' ' + _('d');
	if (mins >= 60 && (mins % 60) === 0)
		return (mins / 60) + ' ' + _('h');
	return mins + ' ' + _('min');
}

function clientName(c) {
	return c.name || c.hostname || c.ip || c.mac || '?';
}

function stateBadge(c) {
	if (!c.blocked)
		return E('span', { 'class': 'hpui-badge hpui-b-green' }, [ _('Allowed') ]);
	if (c.reason === 'temp')
		return E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('Temp block') ]);
	if (c.reason === 'schedule')
		return E('span', { 'class': 'hpui-badge hpui-b-blue' }, [ _('Schedule') ]);
	return E('span', { 'class': 'hpui-badge hpui-b-red' }, [ _('Blocked') ]);
}

function stateText(c) {
	if (!c.blocked) {
		if (c.allow_until)
			return _('temporarily allowed until') + ' ' + fmtRemaining(c.allow_until);
		return _('allowed now');
	}
	if (c.reason === 'temp')
		return _('temporarily blocked until') + ' ' + fmtRemaining(c.until || 0);
	if (c.reason === 'schedule')
		return _('blocked by a schedule window');
	return _('blocked manually');
}

/* Shared custom-time modal (minutes/hours/days). onOk(minutes). */
function customTimeModal(title, defMinutes, onOk) {
	const inVal = E('input', { 'type': 'number', 'min': '1', 'class': 'cbi-input-text', 'value': String(defMinutes) });
	const selUnit = E('select', { 'class': 'cbi-input-select' }, [
		E('option', { 'value': '1' }, [ _('minutes') ]),
		E('option', { 'value': '60', 'selected': 'selected' }, [ _('hours') ]),
		E('option', { 'value': '1440' }, [ _('days') ])
	]);
	const row = E('div', { 'style': 'display:flex; gap:8px; align-items:center' }, [ inVal, selUnit ]);

	ui.showModal(title, [
		E('p', {}, [ _('Access will be restored automatically when the time is up.') ]),
		row,
		E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
			E('button', {
				'class': 'btn cbi-button-positive important',
				'click': function() {
					const v = parseInt(inVal.value, 10);
					const u = parseInt(selUnit.value, 10);
					if (!v || v < 1) {
						ui.addNotification('error', _('Enter a positive number'));
						return;
					}
					ui.hideModal();
					onOk(v * u);
				}
			}, [ _('Apply') ])
		])
	]);
}

/* ── proxy badge: how the proxy serves this device right now ─────────── */

function proxyBadge(c) {
	const mode = uci.get('homeproxy', 'config', 'lan_proxy_mode') || 'disabled';
	const routing = uci.get('homeproxy', 'config', 'routing_mode');

	function inList(opt) {
		const v = uci.get('homeproxy', 'config', opt);
		if (!v)
			return false;
		const arr = Array.isArray(v) ? v : [ v ];
		for (let i = 0; i < arr.length; i++) {
			const item = String(arr[i] || '').toLowerCase();
			if (c.mac && item === String(c.mac).toLowerCase())
				return true;
			if (c.ip && item === String(c.ip).toLowerCase())
				return true;
		}
		return false;
	}

	/* Ф3.1: in the direct mode («Напрямую») NOTHING is proxied — the honest
	 * badge is "No proxy" no matter what the per-device policy says (the
	 * policies keep their values and apply again after switching back). */
	if (routing === 'direct')
		return E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ _('No proxy') ]);

	const isGlobal = inList('lan_global_proxy_mac_addrs') || inList('lan_global_proxy_ipv4_ips');

	let cls, label;
	if (isGlobal) {
		cls = 'hpui-b-blue';
		label = _('Global proxy');
	} else if (isGaming) {
		cls = 'hpui-b-amber';
		label = _('Gaming mode (TCP only)');
	} else if (mode === 'disabled') {
		cls = 'hpui-b-grey';
		label = _('No proxy');
	} else if (mode === 'listed_only') {
		const on = inList('lan_proxy_mac_addrs') || inList('lan_proxy_ipv4_ips');
		cls = on ? 'hpui-b-green' : 'hpui-b-grey';
		label = on ? _('Proxied') : _('Direct');
	} else { /* except_listed */
		const off = inList('lan_direct_mac_addrs') || inList('lan_direct_ipv4_ips');
		cls = off ? 'hpui-b-grey' : 'hpui-b-green';
		label = off ? _('Direct') : _('Proxied');
	}
	return E('span', { 'class': 'hpui-badge ' + cls }, [ label ]);
}

return view.extend({
	load() {
		return Promise.all([
			uci.load('homeproxy'),
			uci.load('luci'),
			hp.getBuiltinFeatures(),
			network.getHostHints(),
			L.resolveDefault(callStatus(), null),
			L.resolveDefault(callDevices(), null)
		]);
	},

	render(data) {
		hp.uiShell();

		const st = document.getElementById('hp-dev-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-dev-style' }, [ CSS ]));

		const hosts = data[3]?.hosts;

		/* Shared live state (updated by the 4 s poll). */
		const S = {
			status: data[4] || { result: false, clients: [], schedules: [], rules: [], stats: {}, dns_filters: {}, wifi_temps: {} },
			devices: (data[5] && data[5].devices) || []
		};

		/* Every action shows its outcome in ONE place (below the registry). */
		function resultBlock(el) {
			return E('div', { 'class': 'dev-result-wrap', 'style': 'display:none' }, [
				E('h4', {}, [ _('Results') ]),
				el
			]);
		}

		const devResult = E('div', {});

		function showResult(el) {
			const w = el.closest('.dev-result-wrap');
			if (w)
				w.style.display = '';
		}

		function note(el, ok, text) {
			showResult(el);
			dom.content(el, E('p', { 'class': 'hpui-hint' }, [
				E('span', { 'class': ok ? 'hpui-c-green' : 'hpui-c-red' }, [ text ])
			]));
		}

		function busy(el, text) {
			showResult(el);
			dom.content(el, E('p', { 'class': 'hpui-hint' }, [ text || _('Please wait…') ]));
		}

		/* Generic act(): RPC call → refresh → one-place result. A double click
		 * must not fire the call twice (a toggle would flip back): the source
		 * button is disabled for the duration. */
		function act(el, promise, okText, btn) {
			if (btn) {
				btn.disabled = true;
				promise.finally(function() { btn.disabled = false; });
			}
			busy(el);
			promise.then(function(r) {
				if (r && r.result === false) {
					note(el, false, (r.error != null) ? String(r.error) : _('Operation failed'));
				} else {
					note(el, true, okText);
				}
				return refreshStatus();
			}).catch(function(e) {
				note(el, false, _('Operation failed') + ': ' + (e && e.message ? e.message : ''));
			});
		}

		/* ── Registry: add a device ─────────────────────────────────── */

		const devPicker = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:260px' }, [
			E('option', { 'value': '' }, [ '— ' + _('Pick a device from the network') + ' —' ])
		]);
		const devName = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('Alias (e.g. Kid tablet)') });
		const devMac = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'AA:BB:CC:DD:EE:FF' });
		const devIp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': '192.168.1.0 (optional)' });
		const devTable = E('table', { 'class': 'hpui-table' });

		devPicker.addEventListener('change', function() {
			const val = devPicker.value;
			if (!val)
				return;
			for (let i = 0; i < S.devices.length; i++) {
				const d = S.devices[i];
				if ((d.mac || d.ip) !== val)
					continue;
				/* alias never overwrites what the user already typed */
				if (!devName.value)
					devName.value = d.alias || d.hostname || '';
				devMac.value = d.mac || '';
				devIp.value = d.ip || '';
				break;
			}
		});

		function rebuildPicker() {
			const cur = devPicker.value;
			dom.content(devPicker, [
				E('option', { 'value': '' }, [ '— ' + _('Pick a device from the network') + ' —' ])
			]);
			for (let i = 0; i < S.devices.length; i++) {
				const d = S.devices[i];
				const base = d.alias || d.hostname || d.ip || d.mac;
				const label = base + (d.ip && base !== d.ip ? ' (' + d.ip + ')' : '') + (d.configured ? ' ✓' : '');
				devPicker.appendChild(E('option', { 'value': d.mac || d.ip || '' }, [ label ]));
			}
			devPicker.value = (devPicker.querySelector('option[value="' + cur.replace(/"/g, '\\"') + '"]')) ? cur : '';
		}

		const devAddBtn = E('button', { 'class': 'btn cbi-button cbi-button-important', type: 'button' }, [ _('Add device') ]);
		devAddBtn.addEventListener('click', function() {
			const mac = String(devMac.value || '').trim();
			const ip = String(devIp.value || '').trim();
			const name = String(devName.value || '').trim();
			if (!mac && !ip) {
				note(devResult, false, _('MAC or IP is required'));
				return;
			}
			act(devResult, callClientAdd(name, mac, ip), _('Device added'));
			devName.value = ''; devMac.value = ''; devIp.value = ''; devPicker.value = '';
		});

		/* ── Registry: the unified device list ──────────────────────── */

		function renderDevices() {
			rebuildPicker();
			const clients = (S.status && S.status.clients) || [];
			const stats = (S.status && S.status.stats) || {};

			let proxied = 0;
			for (let i = 0; i < clients.length; i++) {
				const b = proxyBadge(clients[i]);
				if (b && b.className.indexOf('hpui-b-green') !== -1)
					proxied++;
			}
			const summary = [
				{ n: (stats.devices_total != null) ? stats.devices_total : '—', l: _('Devices on the network'), c: 'hpui-c-blue' },
				{ n: clients.length, l: _('Managed'), c: '' },
				{ n: (stats.blocked != null) ? stats.blocked : '—', l: _('Blocked now'), c: 'hpui-c-red' },
				{ n: proxied, l: _('Proxied now'), c: 'hpui-c-green' }
			];
			const sumBox = document.getElementById('hp-dev-sum');
			if (sumBox)
				dom.content(sumBox, summary.map(function(x) {
					return E('div', { 'class': 'hpui-card' }, [
						E('div', { 'class': 'hpui-num ' + x.c }, [ String(x.n) ]),
						E('div', { 'class': 'hpui-cap' }, [ x.l ])
					]);
				}));

			const head = [ _('Device'), _('MAC'), _('IP'), _('Online'), _('Internet'), _('Proxy'), _('Actions') ];
			const thead = E('thead', {}, [ E('tr', {}, head.map(function(h) { return E('th', {}, [ h ]); })) ]);
			const tbody = E('tbody', {});
			if (!clients.length) {
				tbody.appendChild(E('tr', {}, [ E('td', { 'colspan': '7' }, [ _('No managed devices yet — add one from the network above.') ]) ]));
			}
			for (let i = 0; i < clients.length; i++) {
				const c = clients[i];
				const tdActions = E('td');
				const wrap = E('div', { 'class': 'dev-actions' });
				const blk = E('button', { 'class': 'btn cbi-button-' + (c.blocked ? 'positive' : 'negative'), type: 'button',
					title: c.blocked ? _('Allow internet access again') : _('Full internet block for this device (firewall drop)') },
					[ c.blocked ? _('Allow') : _('Block') ]);
				blk.addEventListener('click', function() {
					act(devResult, callClientBlock(c.id, c.blocked ? '0' : '1'),
						c.blocked ? _('Allowed') : _('Blocked'));
				});
				wrap.appendChild(blk);
				const tmp = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Temporary block') }, [ '⏱' ]);
				tmp.addEventListener('click', function() {
					customTimeModal(_('Temporary block') + ' — ' + clientName(c), 60, function(mins) {
						act(devResult, callClientTempBlock(c.id, String(mins)), _('Temporary block set'));
					});
				});
				wrap.appendChild(tmp);
				if (c.reason === 'temp') {
					const un = E('button', { 'class': 'btn cbi-button-positive', type: 'button', title: _('Remove temporary block') }, [ '↩' ]);
					un.addEventListener('click', function() {
						act(devResult, callClientTempUnblock(c.id), _('Temporary block removed'));
					});
					wrap.appendChild(un);
				}
				const tal = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Temporary allow (pokes a hole in the schedule)') }, [ '✅' ]);
				tal.addEventListener('click', function() {
					customTimeModal(_('Temporary allow') + ' — ' + clientName(c), 60, function(mins) {
						act(devResult, callClientTempAllow(c.id, String(mins)), _('Temporarily allowed'));
					});
				});
				wrap.appendChild(tal);
				if (c.mac) {
					const wfb = E('button', {
						'class': 'btn cbi-button' + (c.wifi_blocked ? ' cbi-button-negative' : ''),
						type: 'button',
						title: c.wifi_blocked ? _('Wi-Fi block is on — click to allow') : _('Block Wi-Fi for this device (wired stays online)')
					}, [ '📶' ]);
					wfb.addEventListener('click', function() {
						act(devResult, callClientWifiBlock(c.id, c.wifi_blocked ? '0' : '1'),
							c.wifi_blocked ? _('Wi-Fi block removed') : _('Wi-Fi blocked for this device'));
					});
					wrap.appendChild(wfb);
				}
				const ren = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Rename') }, [ '✎' ]);
				ren.addEventListener('click', function() {
					const inp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'value': c.name || '' });
					const go = function() {
						const v = String(inp.value || '').trim();
						if (!v) {
							ui.addNotification('error', _('Enter a name'));
							return;
						}
						ui.hideModal();
						act(devResult, callClientRename(c.id, v), _('Renamed'));
					};
					inp.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') go(); });
					ui.showModal(_('Rename device') + ' — ' + clientName(c), [
						inp,
						E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
							E('button', { 'class': 'btn cbi-button-positive important', 'click': go }, [ _('Apply') ])
						])
					]);
				});
				wrap.appendChild(ren);
				const del = E('button', { 'class': 'btn cbi-button-remove', type: 'button', title: _('Remove') }, [ '✖' ]);
				del.addEventListener('click', function() {
					ui.showModal(_('Remove device'), [
						E('p', {}, [ _('Remove') + ' «' + clientName(c) + '» ' + _('from control?') ]),
						E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
							E('button', { 'class': 'btn cbi-button-negative important', 'click': function() { ui.hideModal(); act(devResult, callClientDelete(c.id), _('Device removed')); } }, [ _('Remove') ])
						])
					]);
				});
				wrap.appendChild(del);
				tdActions.appendChild(wrap);

				tbody.appendChild(E('tr', {}, [
					E('td', {}, [ String(clientName(c)) + (c.hostname && c.name && c.hostname !== c.name ? ' (' + c.hostname + ')' : '') ]),
					E('td', {}, [ c.mac || '—' ]),
					E('td', {}, [ c.ip || '—' ]),
					E('td', {}, [ c.online ? '🟢' : '—' ]),
					E('td', {}, [ stateBadge(c), ' ', stateText(c),
						c.wifi_blocked ? E('span', { 'class': 'hpui-badge hpui-b-amber dev-badge-wifi' }, [ '📶 ' + _('Wi-Fi off') ]) : '' ]),
					E('td', {}, [ proxyBadge(c) ]),
					tdActions
				]));
			}
			dom.content(devTable, [ thead, tbody ]);
		}

		/* ── Proxy policy (the former "Devices & interfaces") ───────── */

		const m = new form.Map('homeproxy');
		let so;
		const s = m.section(form.NamedSection, 'control', 'homeproxy');

		s.tab('lan_ip_policy', _('LAN IP Policy'));

		so = s.taboption('lan_ip_policy', form.ListValue, 'lan_proxy_mode', _('Proxy mode for devices'));
		so.value('disabled', _('Disable'));
		so.value('listed_only', _('Proxy listed only'));
		so.value('except_listed', _('Proxy all except listed'));
		so.default = 'disabled';
		so.rmempty = false;

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_direct_ipv4_ips', _('Direct IPv4 IP-s'), null, 'ipv4', hosts, true);
		so.depends('lan_proxy_mode', 'except_listed');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_direct_ipv6_ips', _('Direct IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends({'lan_proxy_mode': 'except_listed', 'homeproxy.config.ipv6_support': '1'});

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_direct_mac_addrs', _('Direct MAC-s'), null, hosts);
		so.depends('lan_proxy_mode', 'except_listed');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'), null, 'ipv4', hosts, true);
		so.depends('lan_proxy_mode', 'listed_only');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends({'lan_proxy_mode': 'listed_only', 'homeproxy.config.ipv6_support': '1'});

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_proxy_mac_addrs', _('Proxy MAC-s'), null, hosts);
		so.depends('lan_proxy_mode', 'listed_only');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_gaming_mode_ipv4_ips', _('Gaming mode IPv4 IP-s'), _('In gaming mode, only TCP traffic from the selected device is proxied.'), 'ipv4', hosts, true);

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_gaming_mode_ipv6_ips', _('Gaming mode IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends('homeproxy.config.ipv6_support', '1');

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_gaming_mode_mac_addrs', _('Gaming mode MAC-s'), null, hosts);

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_global_proxy_ipv4_ips', _('Global proxy IPv4 IP-s'), _('In global proxy mode, all traffic from the selected device goes through the proxy.'), 'ipv4', hosts, true);

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_global_proxy_ipv6_ips', _('Global proxy IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends('homeproxy.config.ipv6_support', '1');

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_global_proxy_mac_addrs', _('Global proxy MAC-s'), null, hosts);

		s.tab('wan_ip_policy', _('WAN IP Policy'));

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'));
		so.datatype = 'or(ip4addr, cidr4)';

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'));
		so.datatype = 'or(ip6addr, cidr6)';
		so.depends('homeproxy.config.ipv6_support', '1');

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_direct_ipv4_ips', _('Direct IPv4 IP-s'));
		so.datatype = 'or(ip4addr, cidr4)';

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_direct_ipv6_ips', _('Direct IPv6 IP-s'));
		so.datatype = 'or(ip6addr, cidr6)';
		so.depends('homeproxy.config.ipv6_support', '1');

		s.tab('interface', _('Interface Control'));

		so = s.taboption('interface', widgets.DeviceSelect, 'listen_interfaces', _('Listen interfaces'),
			_('Only process traffic from specific interfaces. Leave empty for all.'));
		so.multiple = true;
		so.noaliases = true;

		so = s.taboption('interface', widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
			_('Bind outbound traffic to specific interface. Leave empty to auto detect.'));
		so.multiple = false;
		so.noaliases = true;

		const policyBox = E('div', {});
		/* form.Map.render() is ASYNC — embed the finished node when it lands. */
		m.render().then(function(node) {
			if (node)
				policyBox.appendChild(node);
		});

		/* ── poll ───────────────────────────────────────────────────── */

		function refreshStatus() {
			return Promise.all([
				L.resolveDefault(callStatus(), null),
				L.resolveDefault(callDevices(), null)
			]).then(function(d) {
				if (d[0])
					S.status = d[0];
				if (d[1] && d[1].devices)
					S.devices = d[1].devices;
				renderDevices();
			});
		}

		poll.add(refreshStatus, 4);
		refreshStatus();

		return E('div', {}, [
			E('h2', {}, _('Devices')),
			E('p', { 'class': 'hpui-hint', style: 'margin-top:2px' },
				[ _('Who is connected to the router, which devices have internet right now and how the proxy serves their traffic. Add devices to the registry (they are shared with Parental control and the Telegram bot); the Proxy policy at the bottom decides how the traffic of each device is served.') ]),
			E('div', { 'class': 'hpui-cards dev-sum', id: 'hp-dev-sum' }, []),
			E('h4', {}, [ _('Registry') ]),
			E('p', { 'class': 'hpui-hint' }, [
				_('Devices are identified by MAC: when the DHCP address changes the block follows the device automatically. The current IP is resolved from the DHCP lease file at every apply.')
			]),
			E('div', { 'class': 'dev-form' }, [
				E('div', { 'class': 'dev-field dev-wide' }, [ E('label', {}, [ _('From the network') ]), devPicker ]),
				E('div', { 'class': 'dev-field' }, [ E('label', {}, [ _('Alias') ]), devName ]),
				E('div', { 'class': 'dev-field' }, [ E('label', {}, [ _('MAC') ]), devMac ]),
				E('div', { 'class': 'dev-field' }, [ E('label', {}, [ _('IP (static, optional)') ]), devIp ]),
				E('div', { 'class': 'dev-field', 'style': 'flex:0 0 auto' }, [ E('label', {}, [ ' ' ]), devAddBtn ])
			]),
			E('h4', {}, [ _('Managed devices') ]),
			E('div', { 'class': 'hpui-wrap' }, [ devTable ]),
			resultBlock(devResult),
			E('h4', {}, [ _('Proxy policy') ]),
			E('p', { 'class': 'hpui-hint' }, [
				_('Per-device policy for the LAN, upstream IP policy for the WAN and interface binding. This does not change WHAT is proxied — the service rules and lists live on the Service rules and Blocking bypass pages. The Apply button at the bottom of the page saves these settings.')
			]),
			policyBox
		]);
	}
});
