/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — Overview (Главная) tab (Ф4, ч.76).
 *
 * One page answering "what state is everything in, right now":
 *   - status cards: core (+version, running), active node (+delay),
 *     routing mode, Zapret / ByeDPI engines (+strategy, NFQUEUE counters),
 *     MultiDNS, Automation (+learned records), Telegram bot;
 *   - charts: inline SVG built on the CLIENT from the metrics ring the
 *     always-on `metrics` procd instance collects (overview_metrics RPC,
 *     ≤120 points ≈ 10 min of history) — CPU %, RAM %, temperature,
 *     connections, active-node delay, learned-records growth. NO external
 *     libraries: on the router there is no CDN, and the D5 hard condition
 *     requires everything to work locally on the device;
 *   - system parameters: uptime, load, flash (/) and /tmp usage, app
 *     version (update availability stays ON DEMAND — D6);
 *   - quick actions: Restart service, Snapshot, Restore internet — the
 *     existing RPCs. Every result is rendered in ONE result area at the
 *     bottom (ui.action_buttons_result_placement).
 *
 * D5 hard conditions honored: everything local on the device, UI polling
 * every 4 s (≤5 s), static SVG renders with NO animations, and no
 * polling-driven layout churn (signatures + text-only updates).
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

const callMetrics = rpc.declare({
	object: 'luci.homeproxy',
	method: 'overview_metrics',
	expect: { '': {} }
});

const callSys = rpc.declare({
	object: 'luci.homeproxy',
	method: 'overview_sys',
	expect: { '': {} }
});

/* 'main-out' resolves the group chain (main-out → main-out-auto → leaf),
 * the same call diagnostics.js makes. In Custom routing main-out does not
 * exist — the RPC answers an error and the card shows "—". */
const callActiveNode = rpc.declare({
	object: 'luci.homeproxy',
	method: 'clash_active_node',
	params: ['tag'],
	expect: { '': {} }
});

const callDpiStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_dpi_status',
	expect: { '': {} }
});

const callMultidnsStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'multidns_status',
	expect: { '': {} }
});

/* Quick actions — existing RPCs (unchanged). */
const callServiceRestart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_service_restart',
	expect: { '': {} }
});

const callSnapshotCreate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_snapshot_create',
	expect: { '': {} }
});

const callRestoreInternet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_restore_internet',
	expect: { '': {} }
});

/* Update check stays ON DEMAND (D6): the version is always visible, the
 * GitHub query only fires when the user asks for it. */
const callAppCheckUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_check_update',
	expect: { '': {} }
});

/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label —
 * human-readable names, never raw cfg-ids (hotswap lesson). */
function resolveTag(tag) {
	const m = tag && String(tag).match(/^cfg-(.+)-out$/);
	if (m) {
		const label = uci.get('homeproxy', m[1], 'label');
		if (label) return label;
	}
	return tag;
}

/* Routing mode → display label (same names the Client tab uses). */
function routingModeLabel(mode) {
	switch (mode) {
		case 'proxy_banned_ru': return _('Bypass blocking (rule lists)');
		case 'global': return _('Global');
		case 'custom': return _('Custom routing');
		case 'custom_json': return _('Custom JSON');
		default: return mode || '—';
	}
}

function fmtUptime(s) {
	s = parseInt(s, 10) || 0;
	const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
	if (d > 0) return _('%d day(s), %d h %d m').format(d, h, m);
	if (h > 0) return _('%d h %d m').format(h, m);
	return _('%d m').format(m);
}

function fmtK(k) {
	k = parseInt(k, 10) || 0;
	if (k > 1048576) return (k / 1048576).toFixed(1) + ' GB';
	if (k > 1024) return (k / 1024).toFixed(1) + ' MB';
	return k + ' KB';
}

/* ── Charts: the shared hp.chartSvg helper (homeproxy.js, Ф8-F5) ──────────
 * The local duplicate (blue variant, ×1.35 headroom, onScale) moved into
 * homeproxy.js — Automation used a red ×1.15 copy of the same code (B2).
 * Overview now calls hp.chartSvg too: one implementation, one visual
 * language (the Automation red), the "scale up to N" caption logic stays
 * in renderCharts() below. */

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy'),
			hp.getBuiltinFeatures()
		]);
	},

	render: function(data) {
		const features = data[1] || {};
		hp.uiStyle();

		const OV_CSS = `
.ov-charts { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0; }
.ov-chart { flex: 1 1 220px; min-width: 190px; max-width: 330px; }
.ov-chart-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.ov-chart-title { font-size: .85em; opacity: .8; }
.ov-chart-num { font-weight: 700; }
.ov-chart-svg { width: 100%; height: 84px; display: block; margin-top: 2px; border-bottom: 1px solid rgba(128,128,128,.3); }
.ov-chart-cap { display: flex; justify-content: space-between; font-size: .78em; opacity: .65; margin: 2px 0 0 0; }
.ov-chart-max { font-size: .74em; opacity: .6; text-align: right; margin: 0; }
.ov-note { font-size: .88em; opacity: .8; margin: 2px 0 0 0; }
.ov-num { font-size: 1.22em; line-height: 1.3; word-break: break-word; }
.ov-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.ov-result { margin-top: 8px; }
.ov-strat { font-family: monospace; font-size: .8em; opacity: .85; word-break: break-all; }
.ov-pairs { display: flex; flex-wrap: wrap; gap: 4px 22px; margin: 6px 0; font-size: .92em; }
.ov-pairs > div { display: flex; gap: 6px; align-items: baseline; }
.ov-pairs .k { opacity: .75; font-size: .92em; }
.ov-pairs .v { font-weight: 600; }
`;

		const st = document.getElementById('hp-ov-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-ov-style' }, [ OV_CSS ]));

		let metrics = { interval: 5, updated: 0, points: [] };
		const state = { chartSig: null };

		/* ── Cards frame (built once, texts replaced on poll) ──────────── */

		const CARD_DEFS = [
			[ 'core',     _('Core') ],
			[ 'node',     _('Active node') ],
			[ 'mode',     _('Routing mode') ],
			[ 'zapret',   'Zapret (nfqws2)' ],
			[ 'byedpi',   'ByeDPI (ciadpi)' ],
			[ 'multidns', 'MultiDNS' ],
			[ 'automation', _('Automation') ],
			[ 'telegram', _('Telegram bot') ]
		];
		const cards = {};
		const cardsEl = E('div', { 'class': 'hpui-cards' });
		for (let c in CARD_DEFS) {
			const el = E('div', { 'class': 'hpui-card' }, [
				E('div', { 'class': 'hpui-cap' }, [ CARD_DEFS[c][1] ]),
				E('div', { 'class': 'hpui-num ov-num' }, [ '—' ]),
				E('div', { 'class': 'ov-note' }, [ '' ])
			]);
			cards[CARD_DEFS[c][0]] = { num: el.children[1], note: el.children[2] };
			cardsEl.appendChild(el);
		}

		function cardNum(card, text, cls) {
			card.num.textContent = text;
			card.num.className = 'hpui-num ov-num' + (cls ? ' ' + cls : '');
		}

		/* ── Charts frame ───────────────────────────────────────────────── */

		const CHART_DEFS = [
			[ 'cpu',     _('CPU'),             { max: 100, fmt: (v) => v + '%' } ],
			[ 'ram',     _('RAM'),             { max: 100, fmt: (v) => v + '%' } ],
			[ 'temp',    _('Temperature'),     { fmt: (v) => v + ' °C' } ],
			[ 'conns',   _('Connections'),     { fmt: (v) => String(Math.floor(v) || 0) } ],
			[ 'delay',   _('Node delay'),      { fmt: (v) => v + ' ms' } ],
			[ 'learned', _('Learned records'), { fmt: (v) => String(Math.floor(v) || 0) } ]
		];
		const chartsEl = E('div', { 'class': 'ov-charts' });
		for (let c in CHART_DEFS) {
			chartsEl.appendChild(E('div', { 'class': 'ov-chart' }, [
				E('div', { 'class': 'ov-chart-head' }, [
					E('span', { 'class': 'ov-chart-title' }, [ CHART_DEFS[c][1] ]),
					E('span', { 'class': 'ov-chart-num' }, [ '—' ])
				]),
				hp.chartSvg([], CHART_DEFS[c][0],
					Object.assign({ className: 'ov-chart-svg' }, CHART_DEFS[c][2])),
				E('div', { 'class': 'ov-chart-max' }, [ '' ])
			]));
		}
		const chartsCap = E('div', { 'class': 'ov-chart-cap' }, [
			E('span', {}, [ '—' ]),
			E('span', {}, [ '—' ])
		]);

		/* ── System frame (static pairs, values replaced on poll) ──────── */

		const sysPairs = E('div', { 'class': 'ov-pairs' });
		const SYS_DEFS = [
			[ 'uptime', _('Uptime') ],
			[ 'load',   _('Load (1/5/15 min)') ],
			[ 'flash',  _('Flash (/)') ],
			[ 'tmp',    _('Memory (/tmp)') ]
		];
		const sysV = {};
		for (let p in SYS_DEFS) {
			const pair = E('div', {}, [
				E('span', { 'class': 'k' }, [ SYS_DEFS[p][1] + ':' ]),
				E('span', { 'class': 'v' }, [ '—' ])
			]);
			sysV[SYS_DEFS[p][0]] = pair.children[1];
			sysPairs.appendChild(pair);
		}

		/* ── System panel: pairs + app version + update check ──────────── */

		const appVerEl = E('span', { 'class': 'v' }, [ '—' ]);
		const updateBtn = E('button', { 'class': 'btn cbi-button' }, [ _('Check update') ]);
		const sysEl = E('div', { 'class': 'hpui-panel' }, [
			E('h4', {}, [ _('System parameters') ]),
			sysPairs,
			E('div', { 'class': 'ov-actions', 'style': 'margin-top:6px' }, [
				E('span', { 'class': 'k', 'style': 'opacity:.75' }, [ _('App') + ':' ]),
				appVerEl,
				updateBtn
			]),
			E('p', { 'class': 'hpui-hint' },
				[ _('Update availability is checked on demand — the Overview page never queries external resources on its own.') ])
		]);

		/* ── Quick actions panel ───────────────────────────────────────── */

		const restartBtn = E('button', { 'class': 'btn cbi-button cbi-button-action' },
			[ _('Restart service') ]);
		const snapshotBtn = E('button', { 'class': 'btn cbi-button' }, [ _('Snapshot') ]);
		const restoreBtn = E('button', { 'class': 'btn cbi-button-negative' },
			[ _('Restore internet (direct)') ]);
		const actionsEl = E('div', { 'class': 'hpui-panel' }, [
			E('h4', {}, [ _('Quick actions') ]),
			E('div', { 'class': 'ov-actions' }, [ restartBtn, snapshotBtn, restoreBtn ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('The service restart re-routes every connection ("Core & Tools" carries start/stop); a snapshot copies the app configuration and the routing lists; "Restore internet" is the emergency switch for a plain direct connection.') ])
		]);

		/* ONE result area at the bottom for ALL button results. */
		const resultEl = E('div', { 'class': 'ov-result' }, []);

		function setResult(content, ok) {
			dom.content(resultEl, content);
			resultEl.style.color = (ok === true) ? '#3fbf5f' : (ok === false ? '#e05252' : '');
		}

		function noteResult(text, ok) {
			setResult(E('p', { 'class': 'hpui-hint' }, [ text ]), ok);
		}

		restartBtn.addEventListener('click', function() {
			restartBtn.disabled = true;
			noteResult(_('Restarting the service…'), null);
			L.resolveDefault(callServiceRestart(), {}).then(function(r) {
				restartBtn.disabled = false;
				noteResult(r.result ? _('Service restarted.') : ((r && r.error) || _('Restart failed')),
					!!r.result);
			});
		});

		snapshotBtn.addEventListener('click', function() {
			snapshotBtn.disabled = true;
			noteResult(_('Creating a snapshot…'), null);
			L.resolveDefault(callSnapshotCreate(), {}).then(function(r) {
				snapshotBtn.disabled = false;
				noteResult(r.result ? _('Snapshot created: %s').format(r.snapshot) : ((r && r.error) || _('Failed')),
					!!r.result);
			});
		});

		restoreBtn.addEventListener('click', function() {
			if (!window.confirm(_('Stop the proxy stack and restore DIRECT internet? DNS interception is removed; the proxy comes back with "Service start" or a router reboot.')))
				return;
			restoreBtn.disabled = true;
			noteResult(_('Stopping the proxy stack…'), null);
			L.resolveDefault(callRestoreInternet(), {}).then(function(r) {
				restoreBtn.disabled = false;
				noteResult(r.result ? _('Direct internet restored — run "Service start" to bring the proxy back.')
					: ((r && r.error) || _('Failed')), !!r.result);
			});
		});

		updateBtn.addEventListener('click', function() {
			updateBtn.disabled = true;
			noteResult(_('Checking the latest release…'), null);
			L.resolveDefault(callAppCheckUpdate(), {}).then(function(r) {
				updateBtn.disabled = false;
				if (!r || r.error)
					return noteResult(_('Update check failed: %s').format((r && r.error) || _('rpc error')), false);
				noteResult(r.update_available
					? _('Update available: %s → %s (install it on the "Core & Tools" page).').format(r.installed_version, r.latest_version)
					: _('The installed version %s is the latest.').format(r.installed_version || _('unknown')), true);
			});
		});

		/* ── Live render helpers ───────────────────────────────────────── */

		function renderCards(sys, node, dpi, mdns) {
			const z = (dpi && dpi.zapret) || {}, b = (dpi && dpi.byedpi) || {};
			const cfgMode = uci.get('homeproxy', 'config', 'routing_mode') || 'proxy_banned_ru';
			const cfgMainNode = uci.get('homeproxy', 'config', 'main_node') || '';
			const last = (metrics.points.length) ? metrics.points[metrics.points.length - 1] : null;

			/* Core */
			const coreType = features.core_type || null;
			const coreName = coreType === 'hiddify' ? 'hiddify-core' :
				coreType === 'singbox' ? 'sing-box-extended' : _('not installed');
			const coreVer = features.version ? 'v' + features.version : '';
			cardNum(cards.core, coreName, sys.clash_ok ? '' : (coreType ? 'hpui-c-red' : ''));
			cards.core.note.textContent = (coreVer ? coreVer : '') +
				(sys.clash_ok ? ' · ' + _('running') : (coreType ? ' · ' + _('not responding') : ''));

			/* Active node */
			if (node && node.node) {
				const special = { 'main-out': _('Main node'), 'zapret-out': 'Zapret',
					'byedpi-out': 'ByeDPI', 'direct-out': _('Direct'), 'block-out': _('Block') };
				const shown = special[node.node] || resolveTag(node.node);
				cardNum(cards.node, shown, node.delay ? 'hpui-c-green' : '');
				cards.node.note.textContent = (node.delay != null) ? (node.delay + ' ms') : '—';
			} else {
				cardNum(cards.node, '—', 'hpui-c-grey');
				cards.node.note.textContent = (cfgMode === 'custom' || cfgMode === 'custom_json')
					? _('Custom routing — no main node')
					: (cfgMainNode === 'direct-out' ? _('Direct') : _('no node'));
			}

			/* Routing mode */
			cardNum(cards.mode, routingModeLabel(cfgMode), '');
			const proxyMode = uci.get('homeproxy', 'config', 'proxy_mode') || '';
			const pmLabels = { redirect: _('Redirect TCP'), redirect_tproxy: _('Redirect TCP + TProxy UDP'),
				redirect_tun: _('Redirect TCP + Tun UDP'), tun: _('Tun TCP/UDP') };
			cards.mode.note.textContent = pmLabels[proxyMode] || proxyMode;

			/* Zapret / ByeDPI (engines, strategy, NFQUEUE counters). The raw
			 * strategy args are a dump nobody should read in a tile (Ф7):
			 * show the corpus NAME when known ("StressOzz Yv09"), a short
			 * "custom options" marker otherwise, and keep the full args in
			 * the tooltip. */
			const zState = (!z.installed) ? _('not installed') : (!z.enabled) ? _('disabled')
				: (z.running ? _('running') : _('enabled, not running'));
			cardNum(cards.zapret, zState, (z.installed && z.enabled) ? (z.running ? 'hpui-c-green' : 'hpui-c-red') : '');
			const zq = z.nfqueue || {};
			const zName = z.strategy_name ? String(z.strategy_name) :
				z.strategy ? _('custom options') : null;
			cards.zapret.note.textContent = (z.enabled && z.running)
				? ((zName ? zName + ' · ' : '') + 'NFQUEUE: ' + (zq.packets || 0) + ' pkts')
				: (z.enabled && zName ? zName : '—');
			cards.zapret.note.setAttribute('title',
				(z.strategy ? String(z.strategy) + (zq.bytes ? (' · ' + (zq.bytes / 1024).toFixed(0) + ' KB') : '') : ''));

			const bState = (!b.installed) ? _('not installed') : (!b.enabled) ? _('disabled')
				: (b.running ? _('running') : _('enabled, not running'));
			cardNum(cards.byedpi, bState, (b.installed && b.enabled) ? (b.running ? 'hpui-c-green' : 'hpui-c-red') : '');
			cards.byedpi.note.textContent = (b.enabled && b.opts) ? _('custom options') : '—';
			cards.byedpi.note.setAttribute('title', (b.enabled && b.opts) ? String(b.opts) : '');

			/* MultiDNS */
			const mdEnabled = (mdns && mdns.enabled === '1') || (uci.get('homeproxy', 'multidns', 'enabled') === '1');
			const mdRunning = !!(mdEnabled && mdns && mdns.mosdns);
			cardNum(cards.multidns, mdEnabled ? (mdRunning ? _('running') : _('enabled, not running')) : _('disabled'),
				mdEnabled ? (mdRunning ? 'hpui-c-green' : 'hpui-c-red') : '');
			const mdRu = (mdEnabled && mdns && mdns.active && mdns.active.ru) ? mdns.active.ru.length : 0;
			const mdSec = (mdEnabled && mdns && mdns.active && mdns.active.secure) ? mdns.active.secure.length : 0;
			cards.multidns.note.textContent = mdEnabled
				? _('RU: %d · Secure: %d').format(mdRu, mdSec)
				: '—';

			/* Automation */
			const auEnabled = (uci.get('homeproxy', 'automation', 'enabled') === '1');
			const auRunning = !!sys.automation_running;
			cardNum(cards.automation, auEnabled ? (auRunning ? _('running') : _('enabled, not running')) : _('disabled'),
				auEnabled ? (auRunning ? 'hpui-c-green' : 'hpui-c-red') : '');
			cards.automation.note.textContent = (last && last.learned != null)
				? _('Learned records: %d').format(last.learned)
				: '—';

			/* Telegram */
			const tgEnabled = !!(sys.telegram && sys.telegram.enabled === true);
			const tgRunning = !!(sys.telegram && sys.telegram.running);
			cardNum(cards.telegram, tgEnabled ? (tgRunning ? _('running') : _('enabled, not running')) : _('disabled'),
				tgEnabled ? (tgRunning ? 'hpui-c-green' : 'hpui-c-red') : '');
			cards.telegram.note.textContent = tgEnabled ? (tgRunning ? _('long-poll getUpdates') : _('daemon not alive')) : '—';
		}

		function renderCharts() {
			const points = metrics.points || [];
			/* Current values update text-only EVERY poll; the SVG is
			 * rebuilt only when the ring data changed (anti-flicker). */
			for (let i = 0; i < CHART_DEFS.length; i++) {
				const key = CHART_DEFS[i][0];
				const block = chartsEl.children[i];
				const cur = (points.length && points[points.length - 1][key] != null)
					? points[points.length - 1][key] : null;
				block.children[0].children[1].textContent =
					cur != null ? CHART_DEFS[i][2].fmt(cur) : '—';
			}
			const sig = points.length
				? ('' + points[points.length - 1].t + ':' + points.length)
				: 'none';
			if (sig === state.chartSig)
				return;
			state.chartSig = sig;
			for (let i = 0; i < CHART_DEFS.length; i++) {
				const block = chartsEl.children[i];
				const def = CHART_DEFS[i];
				const maxEl = block.children[2];
				/* Auto-scaled charts get an honest "max N" caption (the scale
				 * is peak×1.35); fixed-scale charts (CPU/RAM: 0–100) need no
				 * label — the % is self-evident. */
				const opts = Object.assign({ className: 'ov-chart-svg' }, def[2], {
					onScale: (mx) => {
						maxEl.textContent = (def[2].max == null)
							? _('scale up to %s').format(def[2].fmt(Math.round(mx)))
							: '';
					}
				});
				block.replaceChild(hp.chartSvg(points, def[0], opts), block.children[1]);
			}
			const span = points.length ? points.length * (metrics.interval || 5) : 0;
			const upd = metrics.updated ? new Date(metrics.updated * 1000) : null;
			chartsCap.children[0].textContent = (points.length)
				? _('%d points · ~%d min').format(points.length, Math.ceil(span / 60))
				: _('collecting…');
			chartsCap.children[1].textContent = (upd)
				? upd.toLocaleTimeString()
				: '—';
		}

		function renderSys(sys) {
			sysV.uptime.textContent = (sys.uptime != null) ? fmtUptime(sys.uptime) : '—';
			sysV.load.textContent = (sys.load1 != null)
				? sys.load1 + ' / ' + sys.load5 + ' / ' + sys.load15 : '—';
			sysV.flash.textContent = (sys.root && sys.root.total)
				? _('%s used of %s').format(fmtK(sys.root.used), fmtK(sys.root.total)) : '—';
			sysV.tmp.textContent = (sys.tmp && sys.tmp.total)
				? _('%s used of %s').format(fmtK(sys.tmp.used), fmtK(sys.tmp.total)) : '—';
			appVerEl.textContent = sys.app_version ? ('v' + sys.app_version) : '—';
		}

		/* ── Poll (4 s ≤ 5 s, D5) ──────────────────────────────────────── */

		function refresh() {
			return Promise.all([
				L.resolveDefault(callMetrics(), {}),
				L.resolveDefault(callSys(), {}),
				L.resolveDefault(callActiveNode('main-out'), {}),
				L.resolveDefault(callDpiStatus(), {}),
				L.resolveDefault(callMultidnsStatus(), {})
			]).then(function(data) {
				metrics = (data[0] && typeof data[0] === 'object' && data[0].points)
					? data[0] : { interval: 5, updated: 0, points: [] };
				const sys = data[1] || {};
				const node = (data[2] && data[2].node) ? data[2] : null;
				const dpi = data[3] || {};
				const mdns = data[4] || {};
				renderSys(sys);
				renderCards(sys, node, dpi, mdns);
				renderCharts();
			});
		}

		poll.add(refresh, 4);
		refresh();

		return E('div', {}, [
			E('h4', { 'style': 'margin:6px 0 0 0' }, [ _('Status') ]),
			cardsEl,
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', {}, [ _('Performance') ]),
				chartsEl,
				chartsCap
			]),
			sysEl,
			actionsEl,
			resultEl
		]);
	}
});
