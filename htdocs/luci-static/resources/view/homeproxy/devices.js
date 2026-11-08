/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Devices (R3 v3d, 19-UX_REDESIGN §5; Ф9.3 v3 rework; Ф9.14/D34d):
 * the ONE home page for devices. Two former places are merged here:
 *  - the ravcontrol registry (the "Devices" pane of Parental control):
 *    add devices from the live network (MAC identity), rename/remove,
 *    per-device internet actions (block/temp/wifi) shared with the
 *    control engine and the Telegram bot;
 *  - the proxy policy (the former "Devices & interfaces" page).
 * Every managed device is a CARD with the three honest states (online /
 * internet / proxy) — and since Ф9.14 the proxy MODE lives ON the card:
 * Auto («как у всех») / Direct / Proxied / Gaming / Global, written to the
 * SAME UCI lists the nft lanac chains consume, through the server-side
 * control_proxy_* RPCs (lesson 323: client-side uci.set loses to the form
 * — and there is no form on this page at all anymore). The global filter
 * mode (what «Auto» means) and the raw expert IP/MAC lists (a chips
 * editor) sit in the policy panel; WAN IP Policy and Interface Control
 * moved to the Connection page (D34d). The legacy global mode «disabled»
 * («all through proxy, lists ignored») is GONE: migrate_lan_mode.uc
 * rewrites it to except_listed at service start. All action results
 * render in ONE place per panel (ui.action_buttons_result_placement);
 * actions use the Ф9.2 hpui-btn family and pass their button to act() so
 * a double click cannot flip a toggle twice.
 *
 * Backend contract (audit D32 + Ф9.14): lan_proxy_mode (except_listed /
 * listed_only) gates the lanac admission chains; the direct/proxy/gaming/
 * global MAC+IP lists filter inside them (firewall_post.ut); the gaming
 * list proxies ALL TCP for the device, the global list even overrides the
 * WAN direct set. The resolved badge derives the HONEST outcome from the
 * same model (the old badge treated «disabled» as "no proxy" — wrong).
 */

'use strict';
'require dom';
'require poll';
'require rpc';
'require ui';
'require uci';
'require view';

'require homeproxy as hp';

const callStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_status',
	expect: { '': {} }
});

const callDevices = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_devices',
	expect: { '': {} }
});

const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

const callProxyGlobal = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_proxy_global',
	params: [ 'mode' ],
	expect: { '': {} }
});

const callProxyMode = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_proxy_mode',
	params: [ 'id', 'mode' ],
	expect: { '': {} }
});

const callProxyLists = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_proxy_lists',
	params: [ 'lists' ],
	expect: { '': {} }
});

const callClientAdd = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_add',
	params: [ 'name', 'mac', 'ip' ],
	expect: { '': {} }
});

const callClientDelete = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_delete',
	params: [ 'id' ],
	expect: { '': {} }
});

const callClientRename = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_rename',
	params: [ 'id', 'name' ],
	expect: { '': {} }
});

const callClientBlock = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_block',
	params: [ 'id', 'blocked' ],
	expect: { '': {} }
});

const callClientTempBlock = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_temp_block',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callClientTempUnblock = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_temp_unblock',
	params: [ 'id' ],
	expect: { '': {} }
});

const callClientTempAllow = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_client_temp_allow',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callClientWifiBlock = rpc.declare({
	object: 'luci.ravnex',
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
	.dev-mode-select { max-width: 190px; font-size: .9em; padding: 2px 6px; }
	.dev-expert { margin-top: 10px; }
	.dev-expert summary { cursor: pointer; font-weight: 600; opacity: .8; padding: 6px 0; user-select: none; }
	.dev-expert summary:hover { opacity: 1; }
	.dev-lst-group { margin: 12px 0 4px; font-weight: 600; font-size: .92em; }
	.dev-lst-row { display: flex; align-items: flex-start; gap: 6px; flex-wrap: wrap; margin: 5px 0; }
	.dev-lst-cap { width: 52px; flex: none; font-size: .8em; opacity: .65; padding-top: 4px; }
	.dev-chips { display: flex; flex-wrap: wrap; gap: 6px; flex: 1 1 auto; min-width: 120px; }
	.dev-chip { display: inline-flex; align-items: center; gap: 5px; border: 1px solid var(--hp-panel-line-strong);
		border-radius: 12px; background: var(--hp-panel-bg-2); padding: 2px 4px 2px 10px;
		font-family: var(--hp-font-mono); font-size: .82em; }
	.dev-chip button { border: 0; background: transparent; color: inherit; cursor: pointer; opacity: .6;
		padding: 0 4px; font-size: 1em; line-height: 1; }
	.dev-chip button:hover { opacity: 1; color: var(--hp-red); }
	.dev-lst-add { display: flex; gap: 6px; margin: 3px 0 0 58px; flex-wrap: wrap; }
	.dev-lst-add input { flex: 0 1 240px; font-family: var(--hp-font-mono); font-size: .84em; }
	.dev-policy-actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
	.dev-mode-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
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

/* ── Ф9.14: honest proxy state — derived from the SAME model the firewall
 * walks (lanac admission by the global mode, then the global/gaming lists
 * inside the redirect chain). The lists live in a page-local mirror
 * (LANVAL), initialized from UCI and refreshed from the RPC replies (the
 * control_proxy_* RPCs return the final lists — one honest round-trip, no
 * client-side uci cache games, lesson 323). ──────────────────────────── */

const LAN_OPTS = {
	direct: { mac: 'lan_direct_mac_addrs', ip4: 'lan_direct_ipv4_ips', ip6: 'lan_direct_ipv6_ips' },
	proxy: { mac: 'lan_proxy_mac_addrs', ip4: 'lan_proxy_ipv4_ips', ip6: 'lan_proxy_ipv6_ips' },
	gaming: { mac: 'lan_gaming_mode_mac_addrs', ip4: 'lan_gaming_mode_ipv4_ips', ip6: 'lan_gaming_mode_ipv6_ips' },
	global: { mac: 'lan_global_proxy_mac_addrs', ip4: 'lan_global_proxy_ipv4_ips', ip6: 'lan_global_proxy_ipv6_ips' }
};
const LAN_KINDS = [ 'mac', 'ip4', 'ip6' ];
const LAN_MODES = [ 'direct', 'proxy', 'gaming', 'global' ];

const LANVAL = {};
let globalMode = 'except_listed';

function lanLoad() {
	/* The policy options live in the UCI section 'control' — the section
	 * firewall_post.ut reads (writing them to 'config' is invisible to the
	 * template; caught live in the Ф9.14 acceptance). */
	for (let i = 0; i < LAN_MODES.length; i++)
		for (let k = 0; k < LAN_KINDS.length; k++) {
			const opt = LAN_OPTS[LAN_MODES[i]][LAN_KINDS[k]];
			const v = uci.get('ravnex', 'control', opt);
			LANVAL[opt] = (v == null) ? [] : (Array.isArray(v) ? v.map(String) : [ String(v) ]);
		}
	const m = uci.get('ravnex', 'control', 'lan_proxy_mode');
	/* The legacy «disabled» (before migrate_lan_mode.uc ran) displays as
	 * except_listed: with an empty Direct list the nft behavior is identical. */
	globalMode = (m === 'listed_only') ? 'listed_only' : 'except_listed';
}

function lanApplyView(view) {
	if (!view || !view.lists)
		return;
	const keys = Object.keys(view.lists);
	for (let i = 0; i < keys.length; i++)
		LANVAL[keys[i]] = (view.lists[keys[i]] || []).map(String);
	if (view.global_mode)
		globalMode = view.global_mode;
}

function inModeList(c, mode) {
	const o = LAN_OPTS[mode];
	const hay = (LANVAL[o.mac] || []).concat(LANVAL[o.ip4] || []);
	const mac = String(c.mac || '').toLowerCase();
	const ip = String(c.ip || '').toLowerCase();
	for (let i = 0; i < hay.length; i++) {
		const v = String(hay[i] || '').toLowerCase();
		if (mac && v === mac)
			return true;
		if (ip && v === ip)
			return true;
	}
	return false;
}

/* The card's chosen mode = which list holds the device (priority as the
 * firewall walks them: global, gaming, proxy, direct), none → Auto. */
function deviceMode(c) {
	if (inModeList(c, 'global'))
		return 'global';
	if (inModeList(c, 'gaming'))
		return 'gaming';
	if (inModeList(c, 'proxy'))
		return 'proxy';
	if (inModeList(c, 'direct'))
		return 'direct';
	return 'auto';
}

/* The resolved outcome for the device RIGHT NOW (honest badge). */
function proxyState(c) {
	if (uci.get('ravnex', 'config', 'routing_mode') === 'direct')
		return { cls: 'hpui-b-grey', label: _('No proxy') };
	if (inModeList(c, 'global'))
		return { cls: 'hpui-b-blue', label: _('Global proxy') };
	if (inModeList(c, 'gaming'))
		return { cls: 'hpui-b-amber', label: _('Gaming mode (TCP only)') };
	if (globalMode === 'listed_only')
		return inModeList(c, 'proxy')
			? { cls: 'hpui-b-green', label: _('Proxied') }
			: { cls: 'hpui-b-grey', label: _('Direct') };
	/* except_listed (the only global mode since Ф9.14) */
	if (inModeList(c, 'direct'))
		return { cls: 'hpui-b-grey', label: _('Direct') };
	return { cls: 'hpui-b-green', label: _('Proxied') };
}

return view.extend({
	/* UCI is driven through the control_proxy_* RPCs — the LuCI save footer
	 * has nothing to act on here; suppress it (control.js pattern). */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load() {
		return Promise.all([
			uci.load('ravnex'),
			uci.load('luci'),
			hp.getBuiltinFeatures(),
			L.resolveDefault(callStatus(), null),
			L.resolveDefault(callDevices(), null)
		]);
	},

	render(data) {
		hp.uiShell();

		const st = document.getElementById('hp-dev-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-dev-style' }, [ CSS ]));

		/* Shared live state (updated by the 4 s poll). */
		const S = {
			status: data[3] || { result: false, clients: [], schedules: [], rules: [], stats: {}, dns_filters: {}, wifi_temps: {} },
			devices: (data[4] && data[4].devices) || []
		};

		lanLoad();

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

		/* Ф9.14: the tracked op door — poll the apply to its honest verdict
		 * (the RPC commits UCI at once, the nft reload follows as an op). */
		function pollOp(apply, el, okText, done) {
			if (!apply || !apply.op_id) {
				note(el, true, okText);
				if (done)
					done();
				return;
			}
			if (apply.busy) {
				note(el, false, _('Another apply is running — try again in a moment.'));
				return;
			}
			note(el, true, _('Saved — applying (rules reload)…'));
			const deadline = Date.now() + 120000;
			const tick = function() {
				L.resolveDefault(callOpStatus(apply.op_id), {}).then(function(st) {
					const op = st && st.op;
					if (op && op.status !== 'completed' && op.status !== 'failed' &&
					    Date.now() < deadline)
						return new Promise(function(res) { setTimeout(res, 2000); }).then(tick);
					if (op && op.status === 'completed') {
						note(el, true, okText);
						if (done)
							done();
					} else if (op && op.status === 'failed') {
						note(el, false, _('Apply failed — see the operations journal.'));
					} else {
						note(el, false, _('The apply is still running — see the operations journal on the Health center page.'));
					}
				});
			};
			tick();
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
			/* Ф9.14: the per-device proxy mode lives ON the card. Auto means
			 * «like everyone else» — the global policy in the panel below. */
			const modeSel = E('select', { 'class': 'cbi-input-select dev-mode-select',
				'title': _('Device proxy mode — Auto follows the common policy') }, [
				E('option', { 'value': 'auto' }, [ _('Auto') ]),
				E('option', { 'value': 'direct' }, [ _('Direct') ]),
				E('option', { 'value': 'proxy' }, [ _('Proxied') ]),
				E('option', { 'value': 'gaming' }, [ _('Gaming mode (TCP only)') ]),
				E('option', { 'value': 'global' }, [ _('Global proxy') ])
			]);
			modeSel.value = deviceMode(c);
			modeSel.addEventListener('change', function() {
				const target = modeSel.value;
				if (target === deviceMode(c))
					return;
				modeSel.disabled = true;
				busy(devResult, _('Saving…'));
				L.resolveDefault(callProxyMode(c.id, target), null).then(function(r) {
					if (!r || r.result === false) {
						note(devResult, false, (r && r.error) ? String(r.error) : _('Operation failed'));
						modeSel.disabled = false;
						return;
					}
					lanApplyView(r);
					modeSel.disabled = false;
					invalidateCard(c.id);
					refreshStatus();
					pollOp(r.apply, devResult, _('Proxy mode saved and applied.'), function() {
						refreshStatus();
					});
				}).catch(function(e) {
					modeSel.disabled = false;
					note(devResult, false, _('Operation failed') + ': ' + (e && e.message ? e.message : ''));
				});
			});

			const ps = proxyState(c);
			const proxyRow = E('div', { 'class': 'dev-state' }, [
				E('span', { 'class': 'dev-state-k' }, [ _('Proxy') ]),
				E('span', { 'class': 'dev-state-v dev-mode-row' }, [
					modeSel,
					E('span', { 'class': 'hpui-badge ' + ps.cls }, [ ps.label ])
				])
			]);

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
					proxyRow
				]),
				actions
			]);
		}

		const devGrid = E('div', { 'class': 'dev-grid' });

		/* Card stability: the poll re-renders every 4 s, but a card whose
		 * visible state did not change keeps its DOM node — an open mode
		 * dropdown must not be destroyed under the user's cursor. */
		let prevCards = {};

		function invalidateCard(id) {
			if (id)
				delete prevCards[id];
		}

		function cardSig(c) {
			const ps = proxyState(c);
			return [ c.id, c.online ? 1 : 0, c.blocked ? 1 : 0, c.reason || '',
				c.allow_until || 0, c.until || 0, c.wifi_blocked ? 1 : 0,
				c.name || '', c.hostname || '', c.ip || '', c.mac || '',
				deviceMode(c), ps.cls, ps.label ].join('|');
		}

		function renderDevices() {
			rebuildPicker();
			const clients = (S.status && S.status.clients) || [];
			const stats = (S.status && S.status.stats) || {};

			let proxied = 0;
			for (let i = 0; i < clients.length; i++) {
				if (proxyState(clients[i]).cls === 'hpui-b-green')
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
			const next = {};
			if (!clients.length)
				cards.push(E('div', { 'class': 'hpui-hint' },
					[ _('No managed devices yet — add one from the network above.') ]));
			for (let i = 0; i < clients.length; i++) {
				const c = clients[i];
				const sig = cardSig(c);
				const prev = prevCards[c.id];
				let node;
				if (prev && prev.sig === sig)
					node = prev.node;
				else
					node = deviceCard(c);
				next[c.id] = { sig: sig, node: node };
				cards.push(node);
			}
			prevCards = next;
			dom.content(devGrid, cards);
		}

		/* ── Proxy policy (Ф9.14): the global mode + the expert chips
		 * editor — everything through the server-side RPCs. There is NO
		 * form (and no Apply footer) on this page anymore: the card modes,
		 * the policy switch and the lists apply at once, each verdict lands
		 * in ONE result area of this panel. ───────────────────────────── */

		const polResult = E('div', {});

		const globalSel = E('select', { 'class': 'cbi-input-select dev-mode-select',
			'title': _('What the "Auto" mode on the cards means') }, [
			E('option', { 'value': 'except_listed' }, [ _('Proxy all except the "Direct" ones') ]),
			E('option', { 'value': 'listed_only' }, [ _('Proxy the "Proxied" ones only') ])
		]);
		globalSel.value = globalMode;
		globalSel.addEventListener('change', function() {
			const target = globalSel.value;
			if (target === globalMode)
				return;
			globalSel.disabled = true;
			busy(polResult, _('Saving…'));
			L.resolveDefault(callProxyGlobal(target), null).then(function(r) {
				globalSel.disabled = false;
				if (!r || r.result === false) {
					note(polResult, false, (r && r.error) ? String(r.error) : _('Operation failed'));
					return;
				}
				lanApplyView(r);
				globalSel.value = globalMode;
				prevCards = {};
				refreshStatus();
				pollOp(r.apply, polResult, _('The device policy is applied.'), function() {
					refreshStatus();
				});
			}).catch(function(e) {
				globalSel.disabled = false;
				note(polResult, false, _('Operation failed') + ': ' + (e && e.message ? e.message : ''));
			});
		});

		/* Expert chips editor: staged locally, saved as ONE batch RPC. The
		 * server re-validates every value (the ONE classifier) — the client
		 * checks are convenience only. */
		const ipv6 = (uci.get('ravnex', 'config', 'ipv6_support') === '1');
		const EXPERT = {};

		function expertReset() {
			for (let i = 0; i < LAN_MODES.length; i++)
				for (let k = 0; k < LAN_KINDS.length; k++) {
					const opt = LAN_OPTS[LAN_MODES[i]][LAN_KINDS[k]];
					EXPERT[opt] = (LANVAL[opt] || []).slice();
				}
		}

		function expertDiff() {
			const out = {};
			for (let i = 0; i < LAN_MODES.length; i++)
				for (let k = 0; k < LAN_KINDS.length; k++) {
					const opt = LAN_OPTS[LAN_MODES[i]][LAN_KINDS[k]];
					if (String((EXPERT[opt] || []).slice().sort()) !== String((LANVAL[opt] || []).slice().sort()))
						out[opt] = EXPERT[opt].slice();
				}
			return out;
		}

		function expertValid(kind, v) {
			if (kind === 'mac')
				return /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(v);
			if (kind === 'ip4') {
				const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/);
				if (!m)
					return false;
				for (let i = 1; i <= 4; i++)
					if (parseInt(m[i], 10) > 255)
						return false;
				if (m[6] != null && parseInt(m[6], 10) > 32)
					return false;
				return true;
			}
			/* ip6: a light shape check — the server (the ONE classifier) is
			 * the authority and reports honest errors back. */
			return /^[0-9a-fA-F:]+$/.test(v) && v.indexOf(':') !== -1;
		}

		function expertRow(mode, kind) {
			const opt = LAN_OPTS[mode][kind];
			const cap = (kind === 'mac') ? _('MAC') : ((kind === 'ip4') ? _('IPv4') : _('IPv6'));
			const chips = E('span', { 'class': 'dev-chips' });

			function rebuild() {
				const nodes = [];
				const vals = EXPERT[opt] || [];
				for (let i = 0; i < vals.length; i++) {
					(function(idx) {
						const x = E('button', { 'type': 'button', 'title': _('Remove') }, [ '✕' ]);
						x.addEventListener('click', function() {
							EXPERT[opt].splice(idx, 1);
							rebuild();
						});
						nodes.push(E('span', { 'class': 'dev-chip' }, [ vals[idx], x ]));
					})(i);
				}
				if (!nodes.length)
					nodes.push(E('span', { 'class': 'hpui-cap' }, [ '—' ]));
				dom.content(chips, nodes);
			}

			const inp = E('input', { 'type': 'text', 'class': 'cbi-input-text',
				'placeholder': (kind === 'mac') ? 'AA:BB:CC:DD:EE:FF'
					: ((kind === 'ip4') ? '192.168.1.10 or 192.168.1.0/24' : '2001:db8::/32') });
			const add = E('button', { 'class': 'hpui-btn hpui-btn-sm hpui-btn-ghost', 'type': 'button' }, [ _('Add') ]);

			function addValue() {
				const v = String(inp.value || '').trim();
				if (!v)
					return;
				if (!expertValid(kind, v)) {
					note(polResult, false, (kind === 'mac')
						? _('Not a valid MAC address.')
						: _('Not a valid IP address or CIDR.'));
					return;
				}
				if ((EXPERT[opt] || []).some(function(x) { return x.toLowerCase() === v.toLowerCase(); })) {
					inp.value = '';
					return;
				}
				EXPERT[opt].push(v);
				inp.value = '';
				rebuild();
			}

			add.addEventListener('click', addValue);
			inp.addEventListener('keydown', function(ev) {
				if (ev.key === 'Enter') {
					ev.preventDefault();
					addValue();
				}
			});
			rebuild();

			return E('div', {}, [
				E('div', { 'class': 'dev-lst-row' }, [
					E('span', { 'class': 'dev-lst-cap' }, [ cap ]),
					chips
				]),
				E('div', { 'class': 'dev-lst-add' }, [ inp, add ])
			]);
		}

		const expertBody = E('div', {});

		function expertRender() {
			expertReset();
			const titles = {
				direct: _('Direct'),
				proxy: _('Proxied'),
				gaming: _('Gaming mode (TCP only)'),
				global: _('Global proxy')
			};
			const nodes = [];
			for (let i = 0; i < LAN_MODES.length; i++) {
				const mode = LAN_MODES[i];
				nodes.push(E('div', { 'class': 'dev-lst-group' }, [ titles[mode] ]));
				nodes.push(expertRow(mode, 'mac'));
				nodes.push(expertRow(mode, 'ip4'));
				if (ipv6)
					nodes.push(expertRow(mode, 'ip6'));
			}
			dom.content(expertBody, nodes);
		}
		expertRender();

		const expSave = E('button', { 'class': 'hpui-btn hpui-btn-primary', 'type': 'button' }, [ _('Save the lists') ]);
		const expDiscard = E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'type': 'button' }, [ _('Discard changes') ]);

		expSave.addEventListener('click', function() {
			const diff = expertDiff();
			if (!Object.keys(diff).length) {
				note(polResult, true, _('No changes to save.'));
				return;
			}
			expSave.disabled = true;
			busy(polResult, _('Saving…'));
			L.resolveDefault(callProxyLists(JSON.stringify(diff)), null).then(function(r) {
				expSave.disabled = false;
				if (!r || r.result === false) {
					note(polResult, false, (r && r.error) ? String(r.error) : _('Operation failed'));
					return;
				}
				lanApplyView(r);
				expertRender();
				prevCards = {};
				refreshStatus();
				pollOp(r.apply, polResult, _('The device lists are saved and applied.'), function() {
					refreshStatus();
				});
			}).catch(function(e) {
				expSave.disabled = false;
				note(polResult, false, _('Operation failed') + ': ' + (e && e.message ? e.message : ''));
			});
		});

		expDiscard.addEventListener('click', function() {
			expertRender();
			note(polResult, true, _('The edits are discarded — the lists show the applied state.'));
		});

		const expert = E('details', { 'class': 'dev-expert' }, [
			E('summary', {}, [ _('Expert IP/MAC lists') + ' · ' + _('hidden by default — open only if needed') ]),
			E('p', { 'class': 'hpui-hint' }, [
				_('Lists shared by the whole home network: an entry here applies no matter what the card modes say. The device cards above manage the MAC/IPv4 membership of single devices.')
			]),
			expertBody,
			E('div', { 'class': 'dev-policy-actions' }, [ expSave, expDiscard ])
		]);

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

		poll.add(refreshStatus, hp.pollSec(4));
		refreshStatus();

		return E('div', {}, [
			hp.pageIntro(_('Devices'),
				_('Who is connected to the router, which devices have internet right now and how the proxy serves their traffic. Add devices to the registry (they are shared with Access control and the Telegram bot); every card carries its own proxy mode, the common policy and the expert lists live at the bottom.')),
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
					_('«Auto» on a device card means «like everyone else» — this policy. A card mode (Direct/Proxied/Gaming/Global) overrides it for that one device. What is proxied for the whole home is decided on the Service rules and Blocking bypass pages.')
				]),
				E('div', { 'class': 'dev-field', 'style': 'max-width:480px' }, [
					E('label', {}, [ _('Common policy for "Auto" devices') ]),
					globalSel
				]),
				expert,
				resultBlock(polResult)
			])
		]);
	}
});
