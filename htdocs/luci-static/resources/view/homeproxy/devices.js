/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Devices (R3 v3d, 19-UX_REDESIGN §5; Ф9.3 v3 rework): the ONE
 * home page for devices. Two former places are merged here:
 *  - the homecontrol registry (the "Devices" pane of Parental control):
 *    add devices from the live network (MAC identity), rename/remove,
 *    per-device internet actions (block/temp/wifi) shared with the
 *    control engine and the Telegram bot;
 *  - the proxy policy (the former "Devices & interfaces" page): per-device
 *    LAN mode, WAN IP policy and interface binding.
 * Every managed device is a CARD with the three honest states (online /
 * internet / proxy); actions use the Ф9.2 hpui-btn family and pass their
 * button to act() so a double click cannot flip a toggle twice; ALL action
 * results render in ONE place at the bottom of the device panel
 * (ui.action_buttons_result_placement). The registry view in Parental
 * control keeps only a link here.
 *
 * AUDIT (D32, first Ф9.3 block): every backend option of the Proxy policy
 * zone is consumed and live — lan_proxy_mode with the direct/proxy/gaming/
 * global device lists and listen_interfaces gate the nft lanac/redirect
 * chains (firewall_post.ut), wan_proxy/wan_direct render the WAN daddr
 * sets (firewall_post.ut), bind_interface becomes the core
 * default_interface (generate_client.uc). FIX found by the audit: since
 * Ф3.1 proxyBadge referenced an UNDEFINED isGaming (the gaming badge
 * branch survived while its computation was dropped) — any managed device
 * outside the global lists threw a ReferenceError and the registry
 * table/summary never rendered (proven live before the fix).
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
	.dev-result-wrap { margin-top: 8px; }
	.dev-badge-wifi { margin-left: 6px; }
	.dev-sum { margin: 10px 0 14px; }
	.dev-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 10px; margin-top: 10px; }
	.dev-card { display: flex; flex-direction: column; gap: 8px; padding: 12px 14px; flex: none; }
	.dev-card-top { display: flex; align-items: baseline; gap: 7px; min-width: 0; }
	.dev-name { font-weight: 700; font-size: 1.02em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.dev-host { font-size: .82em; opacity: .7; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.dev-meta { font-size: .8em; opacity: .65; word-break: break-all; }
	.dev-states { display: flex; flex-direction: column; gap: 6px; }
	.dev-state { display: flex; align-items: center; gap: 8px; min-height: 21px; }
	.dev-state-k { width: 64px; flex: none; font-size: .8em; opacity: .7; }
	.dev-state-v { display: flex; align-items: center; gap: 6px; min-width: 0; flex-wrap: wrap; }
	.dev-state-t { font-size: .8em; opacity: .75; }
	.dev-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: auto; padding-top: 9px; border-top: 1px solid var(--hp-panel-line); }
	.dev-actions .hpui-btn { padding: 4px 10px; font-size: .84em; flex: none; }
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
		E('div', { 'class': 'right', 'style': 'margin-top:14px; display:flex; gap:8px; justify-content:flex-end' }, [
			E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal }, [ _('Cancel') ]),
			E('button', {
				'class': 'hpui-btn hpui-btn-primary',
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

	const isGaming = inList('lan_gaming_mode_mac_addrs') || inList('lan_gaming_mode_ipv4_ips');
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

		/* Every action shows its outcome in ONE place, replacing the
		 * previous (below the device grid). */
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

		/* ── Summary: four cards built ONCE (static container — hpui-stagger
		 * per Ф9.2) and the poll updates the numbers IN PLACE: a poll
		 * re-render must never replay the entrance. ──────────────────── */

		const sumDefs = [
			{ l: _('Devices on the network'), c: 'hpui-c-blue' },
			{ l: _('Managed'), c: '' },
			{ l: _('Blocked now'), c: 'hpui-c-red' },
			{ l: _('Proxied now'), c: 'hpui-c-green' }
		];
		const sumNums = sumDefs.map(function(d) {
			return E('div', { 'class': 'hpui-num ' + d.c }, [ '—' ]);
		});
		const sumBox = E('div', { 'class': 'hpui-cards hpui-stagger dev-sum' },
			sumDefs.map(function(d, i) {
				return E('div', { 'class': 'hpui-card' }, [
					sumNums[i],
					E('div', { 'class': 'hpui-cap' }, [ d.l ])
				]);
			}));

		/* ── Registry: add a device ─────────────────────────────────── */

		const devPicker = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:260px' }, [
			E('option', { 'value': '' }, [ '— ' + _('Pick a device from the network') + ' —' ])
		]);
		const devName = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('Alias (e.g. Kid tablet)') });
		const devMac = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'AA:BB:CC:DD:EE:FF' });
		const devIp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': '192.168.1.0 (optional)' });

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

		const devAddBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' }, [ _('Add device') ]);
		devAddBtn.addEventListener('click', function() {
			const mac = String(devMac.value || '').trim();
			const ip = String(devIp.value || '').trim();
			const name = String(devName.value || '').trim();
			if (!mac && !ip) {
				note(devResult, false, _('MAC or IP is required'));
				return;
			}
			act(devResult, callClientAdd(name, mac, ip), _('Device added'), devAddBtn);
			devName.value = ''; devMac.value = ''; devIp.value = ''; devPicker.value = '';
		});

		/* ── Registry: the unified device card grid ─────────────────── */

		function iconBtn(cls, glyph, title, onClick) {
			const b = E('button', { 'class': 'hpui-btn ' + cls, 'type': 'button', 'title': title }, [ glyph ]);
			b.addEventListener('click', onClick);
			return b;
		}

		function deviceCard(c) {
			const actions = E('div', { 'class': 'dev-actions' });

			const blk = E('button', { 'class': 'hpui-btn ' + (c.blocked ? 'hpui-btn-primary' : 'hpui-btn-danger'), type: 'button',
				title: c.blocked ? _('Allow internet access again') : _('Full internet block for this device (firewall drop)') },
				[ c.blocked ? _('Allow') : _('Block') ]);
			blk.addEventListener('click', function() {
				act(devResult, callClientBlock(c.id, c.blocked ? '0' : '1'),
					c.blocked ? _('Allowed') : _('Blocked'), blk);
			});
			actions.appendChild(blk);

			actions.appendChild(iconBtn('hpui-btn-ghost', '⏱', _('Temporary block'), function() {
				customTimeModal(_('Temporary block') + ' — ' + clientName(c), 60, function(mins) {
					act(devResult, callClientTempBlock(c.id, String(mins)), _('Temporary block set'));
				});
			}));

			if (c.reason === 'temp') {
				actions.appendChild(iconBtn('hpui-btn-ghost', '↩', _('Remove temporary block'), function() {
					act(devResult, callClientTempUnblock(c.id), _('Temporary block removed'));
				}));
			}

			actions.appendChild(iconBtn('hpui-btn-ghost', '✅', _('Temporary allow (pokes a hole in the schedule)'), function() {
				customTimeModal(_('Temporary allow') + ' — ' + clientName(c), 60, function(mins) {
					act(devResult, callClientTempAllow(c.id, String(mins)), _('Temporarily allowed'));
				});
			}));

			if (c.mac) {
				actions.appendChild(iconBtn('hpui-btn-ghost', '📶',
					c.wifi_blocked ? _('Wi-Fi block is on — click to allow') : _('Block Wi-Fi for this device (wired stays online)'),
					function() {
						act(devResult, callClientWifiBlock(c.id, c.wifi_blocked ? '0' : '1'),
							c.wifi_blocked ? _('Wi-Fi block removed') : _('Wi-Fi blocked for this device'));
					}));
			}

			actions.appendChild(iconBtn('hpui-btn-ghost', '✎', _('Rename'), function() {
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
					E('div', { 'class': 'right', 'style': 'margin-top:14px; display:flex; gap:8px; justify-content:flex-end' }, [
						E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal }, [ _('Cancel') ]),
						E('button', { 'class': 'hpui-btn hpui-btn-primary', 'click': go }, [ _('Apply') ])
					])
				]);
			}));

			actions.appendChild(iconBtn('hpui-btn-danger', '✖', _('Remove'), function() {
				ui.showModal(_('Remove device'), [
					E('p', {}, [ _('Remove') + ' «' + clientName(c) + '» ' + _('from control?') ]),
					E('div', { 'class': 'right', 'style': 'margin-top:14px; display:flex; gap:8px; justify-content:flex-end' }, [
						E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal }, [ _('Cancel') ]),
						E('button', { 'class': 'hpui-btn hpui-btn-danger', 'click': function() { ui.hideModal(); act(devResult, callClientDelete(c.id), _('Device removed')); } }, [ _('Remove') ])
					])
				]);
			}));

			const hostExtra = (c.hostname && c.name && c.hostname !== c.name) ? c.hostname : '';

			return E('div', { 'class': 'hpui-card dev-card' }, [
				E('div', { 'class': 'dev-card-top' }, [
					E('span', { 'class': 'dev-name' }, [ clientName(c) ]),
					hostExtra ? E('span', { 'class': 'dev-host' }, [ hostExtra ]) : ''
				]),
				E('div', { 'class': 'dev-meta' }, [ (c.mac || '—') + (c.ip ? ' · ' + c.ip : '') ]),
				E('div', { 'class': 'dev-states' }, [
					E('div', { 'class': 'dev-state' }, [
						E('span', { 'class': 'dev-state-k' }, [ _('Online') ]),
						E('span', { 'class': 'dev-state-v' }, [
							E('span', { 'class': 'hpui-dot' + (c.online ? ' ok' : '') }),
							E('span', { 'class': 'dev-state-t' }, [ c.online ? _('Online') : _('Offline') ])
						])
					]),
					E('div', { 'class': 'dev-state' }, [
						E('span', { 'class': 'dev-state-k' }, [ _('Internet') ]),
						E('span', { 'class': 'dev-state-v' }, [
							stateBadge(c),
							E('span', { 'class': 'dev-state-t' }, [ stateText(c) ]),
							c.wifi_blocked ? E('span', { 'class': 'hpui-badge hpui-b-amber dev-badge-wifi' }, [ '📶 ' + _('Wi-Fi off') ]) : ''
						])
					]),
					E('div', { 'class': 'dev-state' }, [
						E('span', { 'class': 'dev-state-k' }, [ _('Proxy') ]),
						E('span', { 'class': 'dev-state-v' }, [ proxyBadge(c) ])
					])
				]),
				actions
			]);
		}

		const devGrid = E('div', { 'class': 'dev-grid' });

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
			const nums = [
				(stats.devices_total != null) ? String(stats.devices_total) : '—',
				String(clients.length),
				(stats.blocked != null) ? String(stats.blocked) : '—',
				String(proxied)
			];
			for (let i = 0; i < sumNums.length; i++)
				sumNums[i].textContent = nums[i];

			const cards = [];
			if (!clients.length)
				cards.push(E('div', { 'class': 'hpui-hint' },
					[ _('No managed devices yet — add one from the network above.') ]));
			for (let i = 0; i < clients.length; i++)
				cards.push(deviceCard(clients[i]));
			dom.content(devGrid, cards);
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
			hp.pageIntro(_('Devices'),
				_('Who is connected to the router, which devices have internet right now and how the proxy serves their traffic. Add devices to the registry (they are shared with Parental control and the Telegram bot); the Proxy policy at the bottom decides how the traffic of each device is served.')),
			sumBox,
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('database'), _('Registry') ]),
				E('p', { 'class': 'hpui-hint' }, [
					_('Devices are identified by MAC: when the DHCP address changes the block follows the device automatically. The current IP is resolved from the DHCP lease file at every apply.')
				]),
				E('div', { 'class': 'dev-form' }, [
					E('div', { 'class': 'dev-field dev-wide' }, [ E('label', {}, [ _('From the network') ]), devPicker ]),
					E('div', { 'class': 'dev-field' }, [ E('label', {}, [ _('Alias') ]), devName ]),
					E('div', { 'class': 'dev-field' }, [ E('label', {}, [ _('MAC') ]), devMac ]),
					E('div', { 'class': 'dev-field' }, [ E('label', {}, [ _('IP (static, optional)') ]), devIp ]),
					E('div', { 'class': 'dev-field', 'style': 'flex:0 0 auto' }, [ E('label', {}, [ ' ' ]), devAddBtn ])
				])
			]),
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('devices'), _('Managed devices') ]),
				devGrid,
				resultBlock(devResult)
			]),
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('layers'), _('Proxy policy') ]),
				E('p', { 'class': 'hpui-hint' }, [
					_('Per-device policy for the LAN, upstream IP policy for the WAN and interface binding. This does not change WHAT is proxied — the service rules and lists live on the Service rules and Blocking bypass pages. The Apply button at the bottom of the page saves these settings.')
				]),
				policyBox
			])
		]);
	}
});
