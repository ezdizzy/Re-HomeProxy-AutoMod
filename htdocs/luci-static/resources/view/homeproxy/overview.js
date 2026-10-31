/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Overview (Главная) tab (Ф4, ч.76; Р3: бренд-блок + статус-лента;
 * Р3 v2: app shell (hp.uiShell) + headline metric cards with sparklines).
 *
 * One page answering "what state is everything in, right now":
 *   - subsystem status ribbon (8 chips: icon + ok/bad/warn/off dot) fed by
 *     the same render pass as the metrics;
 *   - headline metric cards (tachyon-style): core, RAM, active node,
 *     connections, VPN speed — each with a mini sparkline from the metrics
 *     ring (overview_metrics RPC, ≤120 points ≈ 10 min of history);
 *   - secondary charts (temperature, learned records, direct/bypass speed)
 *     built as inline SVG on the CLIENT — NO external libraries (D5);
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

/* Traffic speed (bytes/s → human) and volume (bytes → human) — the
 * per-exit sensors (Ф8-F7 T2). */
function fmtBps(v) {
	v = Math.round(v || 0);
	if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB/s';
	if (v >= 1024) return (v / 1024).toFixed(1) + ' KB/s';
	return v + ' B/s';
}

function fmtBytes(v) {
	v = Math.round(v || 0);
	if (v >= 1073741824) return (v / 1073741824).toFixed(2) + ' GB';
	if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
	if (v >= 1024) return (v / 1024).toFixed(1) + ' KB';
	return v + ' B';
}

/* ── Charts: the shared hp.chartSvg helper (homeproxy.js, Ф8-F5) ──────────
 * The local duplicate (blue variant, ×1.35 headroom, onScale) moved into
 * homeproxy.js — Automation used a red ×1.15 copy of the same code (B2).
 * Overview now calls hp.chartSvg too: one implementation, one visual
 * language (the Automation red), the "scale up to N" caption logic stays
 * in renderCharts() below. */

return view.extend({
	/* Pure-RPC, read-only view: the LuCI save footer (Apply/Save/Reset) has
	 * nothing to act on here (lesson 114 precedent — telegram.js). */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return Promise.all([
			uci.load('homeproxy'),
			hp.getBuiltinFeatures()
		]);
	},

	render: function(data) {
		const features = data[1] || {};
		hp.uiShell();

		const OV_CSS = `
.ov-charts { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0; }
.ov-chart { flex: 1 1 220px; min-width: 190px; max-width: 330px; }
.ov-chart-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.ov-chart-title { font-size: .85em; opacity: .8; }
.ov-chart-num { font-weight: 700; }
.ov-chart-svg { width: 100%; height: 84px; display: block; margin-top: 2px; border-bottom: 1px solid var(--hp-panel-line); }
.ov-chart-cap { display: flex; justify-content: space-between; font-size: .78em; opacity: .65; margin: 2px 0 0 0; }
.ov-chart-max { font-size: .74em; opacity: .6; text-align: right; margin: 0; }
.ov-note { font-size: .88em; opacity: .8; margin: 2px 0 0 0; }
.ov-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.ov-result { margin-top: 8px; }
.ov-strat { font-family: var(--hp-font-mono); font-size: .8em; opacity: .85; word-break: break-all; }
.ov-pairs { display: flex; flex-wrap: wrap; gap: 4px 22px; margin: 6px 0; font-size: .92em; }
.ov-pairs > div { display: flex; gap: 6px; align-items: baseline; }
.ov-pairs .k { opacity: .75; font-size: .92em; }
.ov-pairs .v { font-weight: 600; }
.hpui-cap .hpui-ic { margin-right: 5px; opacity: .9; }
/* Brand block (Р3): raven icon + wordmark/slogan + subsystem status ribbon. */
.hpui-brand { display: flex; align-items: center; gap: 14px; padding: 12px 16px; margin: 2px 0 12px; border: 1px solid var(--hp-panel-line); border-left: 4px solid var(--hp-accent); border-radius: var(--hp-radius-lg); background: linear-gradient(90deg, var(--hp-accent-soft), transparent 55%), var(--hp-panel-bg); box-shadow: var(--hp-shadow); }
.hpui-brand-ic { width: 52px; height: 52px; border-radius: 12px; flex: none; box-shadow: 0 2px 8px rgba(0,0,0,.28); }
.hpui-brand-name { font-size: 1.45em; font-weight: 800; line-height: 1.25; display: flex; align-items: baseline; gap: 8px; }
.hpui-brand-slogan { color: var(--hp-accent-strong); font-weight: 700; font-size: .58em; letter-spacing: .06em; white-space: nowrap; }
.hpui-brand-ver { margin-left: auto; align-self: flex-start; font-size: .84em; opacity: .85; border: 1px solid var(--hp-panel-line); border-radius: 999px; padding: 2px 10px; background: var(--hp-panel-bg-2); white-space: nowrap; }
.hpui-brand-ribbon { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.hpui-chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--hp-panel-line); background: var(--hp-panel-bg-2); border-radius: 999px; padding: 2px 10px 2px 9px; font-size: .84em; line-height: 1.55; max-width: 100%; }
.hpui-chip .hpui-ic { width: 1.05em; height: 1.05em; opacity: .8; }
.hpui-chip-name { font-weight: 600; white-space: nowrap; }
.hpui-chip-state { opacity: .85; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 190px; }
.hpui-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; background: var(--hp-grey); }
.hpui-dot.ok { background: var(--hp-accent); box-shadow: 0 0 4px var(--hp-accent-glow); }
.hpui-dot.bad { background: var(--hp-red); box-shadow: 0 0 4px var(--hp-red-line); }
.hpui-dot.warn { background: var(--hp-amber); box-shadow: 0 0 4px rgba(217,154,27,.5); }
/* Metric cards with sparklines (Р3 v2, reference: the tachyon dashboard):
 * caption + big number + note + a mini chart of the same series. */
.hpui-mcards { display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap: 10px; margin: 10px 0; }
.hpui-mcard { border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); box-shadow: var(--hp-shadow); padding: 10px 12px 8px; min-width: 0; }
.hpui-mcap { display: flex; align-items: center; gap: 6px; font-size: .76em; letter-spacing: .04em; opacity: .72; }
.hpui-mcap .hpui-ic { width: 1.05em; height: 1.05em; }
.hpui-mbody { display: flex; gap: 8px; margin-top: 3px; }
.hpui-mtxt { flex: 1 1 auto; min-width: 0; }
.hpui-mnum { font-size: 1.28em; font-weight: 700; line-height: 1.3; word-break: break-word; }
.hpui-mnote { font-size: .78em; opacity: .7; margin-top: 1px; }
.hpui-mnote:empty { display: none; }
.hpui-mspark-slot { flex: none; align-self: flex-end; }
.hpui-mspark { width: 82px; height: 34px; display: block; }
/* Two-column layout: charts on the left, system + actions on the right. */
.ov-grid { display: grid; grid-template-columns: minmax(0, 2.1fr) minmax(0, 1fr); gap: 12px; align-items: start; margin: 0; }
.ov-col { display: flex; flex-direction: column; min-width: 0; }
.ov-col > .hpui-panel { margin: 0 0 12px 0; }
@media (max-width: 1150px) { .ov-grid { grid-template-columns: 1fr; } }
`;

		const st = document.getElementById('hp-ov-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-ov-style' }, [ OV_CSS ]));

		let metrics = { interval: 5, updated: 0, points: [] };
		const state = { chartSig: null };

		/* ── Brand block (Р3): raven icon + wordmark/slogan + subsystem
		 * status ribbon. The ribbon mirrors the card states (same renderCards
		 * pass — one source of truth); chips update text/dot only (anti-
		 * flicker, same rule as the cards). Brand name/slogan are NOT
		 * translated (brand line, same as the menu title). */
		const RIBBON_DEFS = [
			[ 'core',       'cpu',     _('Core') ],
			[ 'node',       'server',  _('Active node') ],
			[ 'mode',       'shuffle', _('Routing mode') ],
			[ 'zapret',     'shield',  'Zapret' ],
			[ 'byedpi',     'zap',     'ByeDPI' ],
			[ 'multidns',   'globe',   'MultiDNS' ],
			[ 'automation', 'refresh', _('Automation') ],
			[ 'telegram',   'send',    _('Telegram bot') ]
		];
		const ribbon = {};
		const ribbonEl = E('div', { 'class': 'hpui-brand-ribbon' });
		for (let r in RIBBON_DEFS) {
			const chip = E('span', { 'class': 'hpui-chip' }, [
				hp.icon(RIBBON_DEFS[r][1]),
				E('span', { 'class': 'hpui-chip-name' }, [ RIBBON_DEFS[r][2] ]),
				E('span', { 'class': 'hpui-dot' }),
				E('span', { 'class': 'hpui-chip-state' }, [ '—' ])
			]);
			ribbon[RIBBON_DEFS[r][0]] = { dot: chip.children[2], state: chip.children[3] };
			ribbonEl.appendChild(chip);
		}

		const brandVer = E('span', { 'class': 'hpui-brand-ver' }, [ '—' ]);
		const brandEl = E('div', { 'class': 'hpui-brand' }, [
			E('img', { 'class': 'hpui-brand-ic', 'src': L.resource('ravnex-raven-192.png'), 'alt': 'Ravnex' }),
			E('div', {}, [
				E('div', { 'class': 'hpui-brand-name' }, [
					E('span', {}, [ 'Ravnex' ]),
					E('span', { 'class': 'hpui-brand-slogan' }, [ '· Own the Route.' ])
				]),
				ribbonEl
			]),
			brandVer
		]);

		function rib(key, dot, text, title) {
			const r = ribbon[key];
			if (!r)
				return;
			r.dot.className = 'hpui-dot' + (dot ? ' ' + dot : '');
			r.state.textContent = text;
			r.state.setAttribute('title', title || text);
		}

		/* ── Metric cards (Р3 v2, tachyon-style): caption + big number +
		 * note + a mini sparkline of the same series. The 8 subsystem
		 * states live in the ribbon above; these cards carry the LIVE
		 * metrics only. Sparklines render from the same ring as the
		 * charts (one render pass, anti-flicker). ───────────────────── */

		const MCARD_DEFS = [
			[ 'core',  'cpu',      _('Core'),           'cpu',    { max: 100, color: hp.PALETTE.blue, fill: hp.PALETTE.blueFill } ],
			[ 'ram',   'activity', _('RAM'),            'ram',    { max: 100, color: hp.PALETTE.blue, fill: hp.PALETTE.blueFill } ],
			[ 'node',  'server',   _('Active node'),    'delay',  { color: hp.PALETTE.accent, fill: hp.PALETTE.accentFill } ],
			[ 'conns', 'shuffle',  _('Connections'),    'conns',  { color: hp.PALETTE.accent, fill: hp.PALETTE.accentFill } ],
			[ 'vpn',   'trend',    _('VPN speed'),      'vpn_b',  { color: hp.PALETTE.accent, fill: hp.PALETTE.accentFill } ]
		];
		const mcards = {};
		const mcardsEl = E('div', { 'class': 'hpui-mcards' });
		for (let c in MCARD_DEFS) {
			const cap = E('div', { 'class': 'hpui-mcap' }, [
				hp.icon(MCARD_DEFS[c][1]),
				E('span', {}, [ MCARD_DEFS[c][2] ])
			]);
			const sparkSlot = E('div', { 'class': 'hpui-mspark-slot' });
			const el = E('div', { 'class': 'hpui-mcard' }, [
				cap,
				E('div', { 'class': 'hpui-mbody' }, [
					E('div', { 'class': 'hpui-mtxt' }, [
						E('div', { 'class': 'hpui-mnum' }, [ '—' ]),
						E('div', { 'class': 'hpui-mnote' }, [ '' ])
					]),
					sparkSlot
				])
			]);
			mcards[MCARD_DEFS[c][0]] = {
				num: el.children[1].children[0].children[0],
				note: el.children[1].children[0].children[1],
				slot: sparkSlot,
				key: MCARD_DEFS[c][3],
				sopts: MCARD_DEFS[c][4]
			};
			mcardsEl.appendChild(el);
		}

		function mcardNum(card, text, cls) {
			card.num.textContent = text;
			card.num.className = 'hpui-mnum' + (cls ? ' ' + cls : '');
		}

		/* ── Charts frame (secondary series; the five headline metrics live
		 * in the metric cards above as sparklines) ─────────────────────── */

		const CHART_DEFS = [
			[ 'temp',    _('Temperature'),     { fmt: (v) => v + ' °C', color: hp.PALETTE.amberHot, fill: hp.PALETTE.amberFill } ],
			[ 'learned', _('Learned records'), { fmt: (v) => String(Math.floor(v) || 0), color: hp.PALETTE.accent, fill: hp.PALETTE.accentFill } ],
			/* Per-exit traffic speed (Ф8-F7 T2): B/s deltas from the
			 * /connections sampler. byp = Zapret + ByeDPI + tg-ws.
			 * Keys match the sampler point fields (dir_b/byp_b).
			 * Colors are semantic (Р3): direct = grey, bypass engines =
			 * amber; VPN speed is a headline metric (metric card). */
			[ 'dir_b',   _('Direct speed'),    { fmt: (v) => fmtBps(v), color: hp.PALETTE.grey, fill: hp.PALETTE.greyFill } ],
			[ 'byp_b',   _('Bypass speed'),    { fmt: (v) => fmtBps(v), color: hp.PALETTE.amberHot, fill: hp.PALETTE.amberFill } ]
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

		/* ── Traffic by exit panel (Ф8-F7 T2): cumulative per-exit volume ── */

		const TRAFFIC_DEFS = [
			[ 'vpn',    _('VPN (main node)') ],
			[ 'node',   _('Node (rule)') ],
			[ 'direct', _('Direct') ],
			[ 'zapret', 'Zapret (nfqws2)' ],
			[ 'byedpi', 'ByeDPI (ciadpi)' ],
			[ 'tgws',   _('tg-ws bridge') ],
			[ 'block',  _('Blocked') ],
			[ 'other',  _('Other') ]
		];
		const trPairs = E('div', { 'class': 'ov-pairs' });
		const trV = {};
		for (let p in TRAFFIC_DEFS) {
			const pair = E('div', {}, [
				E('span', { 'class': 'k' }, [ TRAFFIC_DEFS[p][1] + ':' ]),
				E('span', { 'class': 'v' }, [ '—' ])
			]);
			trV[TRAFFIC_DEFS[p][0]] = pair.children[1];
			trPairs.appendChild(pair);
		}
		const trSince = E('span', { 'class': 'k', 'style': 'opacity:.75' }, [ '' ]);
		const trafficEl = E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('repeat'), _('Traffic by exit') ]),
			trPairs,
			E('div', { 'class': 'ov-actions', 'style': 'margin-top:6px' }, [ trSince ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('Volumes count LAN-client traffic through the core, split by the exit it used; the router\'s own traffic (DNS, system, probes) is not counted. Counters live from the metrics daemon start — they survive service restarts and reset on reboot.') ])
		]);

		function renderTraffic(totals) {
			totals = totals || {};
			for (let p in TRAFFIC_DEFS) {
				const k = TRAFFIC_DEFS[p][0];
				const v = (typeof totals[k] === 'number') ? totals[k] : null;
				trV[k].textContent = (v != null) ? fmtBytes(v) : '—';
			}
			trSince.textContent = (totals.since > 0)
				? _('Since: %s').format(new Date(totals.since * 1000).toLocaleTimeString())
				: '';
		}

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
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('clock'), _('System parameters') ]),
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
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('tool'), _('Quick actions') ]),
			E('div', { 'class': 'ov-actions' }, [ restartBtn, snapshotBtn, restoreBtn ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('The service restart re-routes every connection ("Core & Tools" carries start/stop); a snapshot copies the app configuration and the routing lists; "Restore internet" is the emergency switch for a plain direct connection.') ])
		]);

		/* ONE result area at the bottom for ALL button results. */
		const resultEl = E('div', { 'class': 'ov-result' }, []);

		function setResult(content, ok) {
			dom.content(resultEl, content);
			resultEl.style.color = (ok === true) ? 'var(--hp-accent-strong)' : (ok === false ? 'var(--hp-red)' : '');
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

			/* Core (ribbon + metric card) */
			const coreType = features.core_type || null;
			const coreName = coreType === 'hiddify' ? 'hiddify-core' :
				coreType === 'singbox' ? 'sing-box-extended' : _('not installed');
			const coreVer = features.version ? 'v' + features.version : '';
			mcardNum(mcards.core, coreName, sys.clash_ok ? '' : (coreType ? 'hpui-c-red' : ''));
			mcards.core.note.textContent = (coreVer ? coreVer : '') +
				(sys.clash_ok ? ' · ' + _('running') : (coreType ? ' · ' + _('not responding') : ''));
			rib('core', coreType ? (sys.clash_ok ? 'ok' : 'bad') : '',
				coreType ? (sys.clash_ok ? _('running') : _('not responding')) : _('not installed'));

			/* RAM metric card (the spark scale is fixed 0-100%). */
			mcardNum(mcards.ram, (last && last.ram != null) ? (last.ram + '%') : '—', '');
			mcards.ram.note.textContent = (last && last.ram != null) ? _('scale 0-100%') : '';

			/* Active node (ribbon + metric card) */
			if (node && node.node) {
				const special = { 'main-out': _('Main node'), 'zapret-out': 'Zapret',
					'byedpi-out': 'ByeDPI', 'direct-out': _('Direct'), 'block-out': _('Block') };
				const shown = special[node.node] || resolveTag(node.node);
				mcardNum(mcards.node, shown, node.delay ? 'hpui-c-green' : '');
				mcards.node.note.textContent = (node.delay != null) ? (node.delay + ' ms') : '—';
				rib('node', node.delay ? 'ok' : '', shown,
					(node.delay != null) ? (shown + ' · ' + node.delay + ' ms') : shown);
			} else {
				mcardNum(mcards.node, '—', 'hpui-c-grey');
				mcards.node.note.textContent = (cfgMode === 'custom' || cfgMode === 'custom_json')
					? _('Custom routing — no main node')
					: (cfgMainNode === 'direct-out' ? _('Direct') : _('no node'));
				rib('node', '', mcards.node.note.textContent);
			}

			/* Connections + VPN speed metric cards (sparkline series). */
			mcardNum(mcards.conns, (last && last.conns != null) ? String(Math.floor(last.conns)) : '—', '');
			mcardNum(mcards.vpn, (last && last.vpn_b != null) ? fmtBps(last.vpn_b) : '—',
				(last && last.vpn_b > 0) ? 'hpui-c-green' : '');

			/* Routing mode (ribbon only). */
			const proxyMode = uci.get('homeproxy', 'config', 'proxy_mode') || '';
			const pmLabels = { redirect: _('Redirect TCP'), redirect_tproxy: _('Redirect TCP + TProxy UDP'),
				redirect_tun: _('Redirect TCP + Tun UDP'), tun: _('Tun TCP/UDP') };
			rib('mode', '', routingModeLabel(cfgMode), pmLabels[proxyMode] || proxyMode);

			/* Zapret / ByeDPI (engines, strategy, NFQUEUE counters). The raw
			 * strategy args are a dump nobody should read in a chip (Ф7):
			 * show the corpus NAME when known ("StressOzz Yv09"), a short
			 * "custom options" marker otherwise, and keep the full args in
			 * the tooltip. */
			const zState = (!z.installed) ? _('not installed') : (!z.enabled) ? _('disabled')
				: (z.running ? _('running') : _('enabled, not running'));
			const zq = z.nfqueue || {};
			const zName = z.strategy_name ? String(z.strategy_name) :
				z.strategy ? _('custom options') : null;
			const zNote = (z.enabled && z.running)
				? ((zName ? zName + ' · ' : '') + 'NFQUEUE: ' + (zq.packets || 0) + ' pkts')
				: (z.enabled && zName ? zName : '—');
			rib('zapret', (z.installed && z.enabled) ? (z.running ? 'ok' : 'bad') : '',
				zState, zNote);

			const bState = (!b.installed) ? _('not installed') : (!b.enabled) ? _('disabled')
				: (b.running ? _('running') : _('enabled, not running'));
			rib('byedpi', (b.installed && b.enabled) ? (b.running ? 'ok' : 'bad') : '',
				bState, (b.enabled && b.opts) ? _('custom options') : '—');

			/* MultiDNS. "restarting..." is the routine quality-cycle rebuild
			 * window (the daemon rebuilds mosdns.yaml and bounces the instance,
			 * ~1-4 s): neutral grey, NOT the alarming red "enabled, not
			 * running" which is reserved for a genuinely dead resolver. */
			const mdEnabled = (mdns && mdns.enabled === '1') || (uci.get('homeproxy', 'multidns', 'enabled') === '1');
			const mdRunning = !!(mdEnabled && mdns && mdns.mosdns);
			const mdRestart = !!(mdEnabled && !mdRunning && mdns && mdns.restarting);
			const mdRu = (mdEnabled && mdns && mdns.active && mdns.active.ru) ? mdns.active.ru.length : 0;
			const mdSec = (mdEnabled && mdns && mdns.active && mdns.active.secure) ? mdns.active.secure.length : 0;
			const mdNote = mdEnabled ? _('RU: %d · Secure: %d').format(mdRu, mdSec) : '—';
			rib('multidns', mdEnabled ? (mdRunning ? 'ok' : (mdRestart ? 'warn' : 'bad')) : '',
				mdEnabled ? (mdRunning ? _('running') : (mdRestart ? _('restarting...') : _('enabled, not running'))) : _('disabled'),
				mdNote);

			/* Automation */
			const auEnabled = (uci.get('homeproxy', 'automation', 'enabled') === '1');
			const auRunning = !!sys.automation_running;
			rib('automation', auEnabled ? (auRunning ? 'ok' : 'bad') : '',
				auEnabled ? (auRunning ? _('running') : _('enabled, not running')) : _('disabled'),
				(last && last.learned != null) ? _('Learned records: %d').format(last.learned) : '—');

			/* Telegram */
			const tgEnabled = !!(sys.telegram && sys.telegram.enabled === true);
			const tgRunning = !!(sys.telegram && sys.telegram.running);
			rib('telegram', tgEnabled ? (tgRunning ? 'ok' : 'bad') : '',
				tgEnabled ? (tgRunning ? _('running') : _('enabled, not running')) : _('disabled'),
				tgEnabled ? (tgRunning ? _('long-poll getUpdates') : _('daemon not alive')) : '—');
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
			/* Metric card sparklines — same ring, same signature guard. */
			for (let k in mcards) {
				const c = mcards[k];
				c.slot.replaceChildren(hp.chartSvg(points, c.key,
					Object.assign({ className: 'hpui-mspark' }, c.sopts)));
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
			brandVer.textContent = appVerEl.textContent;
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
			renderTraffic(metrics.totals);
			});
		}

		poll.add(refresh, 4);
		refresh();

		/* Р3 v2 layout: brand + subsystem ribbon → headline metric cards →
		 * two-column grid (charts | system + quick actions) → traffic by
		 * exit → ONE result area at the bottom. */
		return E('div', {}, [
			brandEl,
			mcardsEl,
			E('div', { 'class': 'ov-grid' }, [
				E('div', { 'class': 'ov-col' }, [
					E('div', { 'class': 'hpui-panel' }, [
						E('h4', { 'class': 'hpui-h4' }, [ hp.icon('activity'), _('Performance') ]),
						chartsEl,
						chartsCap
					])
				]),
				E('div', { 'class': 'ov-col' }, [ sysEl, actionsEl ])
			]),
			trafficEl,
			resultEl
		]);
	}
});
