/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Home (Главная) tab (Ф4, ч.76; Р3: бренд-блок + метрик-карточки;
 * Р3 v2: app shell + sparklines; Р3 v3: the HUB — hero status + concern
 * cards with transitions + quick setup, per 19-UX_REDESIGN §6).
 *
 * The page answers, top to bottom:
 *   - "Is everything working?" — the hero: big human status + a
 *     "Check now" jump to Check & repair; routing mode and MultiDNS
 *     chips keep the two technical facts visible;
 *   - "What do I want to do?" — six concern cards (traffic exit, blocking
 *     bypass, auto-bypass sites, home devices, parental control, phone
 *     control), each = the question + live state + one-line description
 *     + a jump button; statuses come from the SAME poll data as the
 *     metric cards (one render pass, no extra RPC storm);
 *   - "Am I set up yet?" — the quick setup strip appears until the main
 *     servers are configured (4 steps with done-states);
 *   - metric cards with sparklines, performance charts, system
 *     parameters, quick actions (results in ONE area, D6 on-demand
 *     update check) — unchanged from Р3 v2.
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
	object: 'luci.ravnex',
	method: 'overview_metrics',
	expect: { '': {} }
});

const callSys = rpc.declare({
	object: 'luci.ravnex',
	method: 'overview_sys',
	expect: { '': {} }
});

/* 'main-out' resolves the group chain (main-out → main-out-auto → leaf),
 * the same call diagnostics.js makes. In Custom routing main-out does not
 * exist — the RPC answers an error and the card shows "—". */
const callActiveNode = rpc.declare({
	object: 'luci.ravnex',
	method: 'clash_active_node',
	params: ['tag'],
	expect: { '': {} }
});

const callDpiStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_dpi_status',
	expect: { '': {} }
});

const callMultidnsStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'multidns_status',
	expect: { '': {} }
});

/* The hub "Home devices" / "Parental control" cards need the Control
 * engine summary (enabled/paused/device counts) — the same RPC the
 * control.js page polls every 4 s; here it rides the shared poll. */
const callControlStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_status',
	expect: { '': {} }
});

/* The "Subscriptions" hub card: the last update cycle + the live book of
 * subscription nodes (the same RPC the Servers page uses — a cheap file
 * read; polled once a minute, subscriptions change rarely). */
const callSubsStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_subscription_status',
	expect: { '': {} }
});

/* Quick actions — existing RPCs (unchanged). */
const callServiceRestart = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_service_restart',
	expect: { '': {} }
});

/* Ф9.1 (§A.4): the Dashboard shows the tail of the SAME unified event
 * journal the Health center renders in full (Event Bus → UI) — critical
 * events are visible where the user looks every day. */
const callEvents = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_events',
	params: [ 'limit' ],
	expect: { '': {} }
});

/* Ф9.1/Ф10: resource profile visibility — the hardware fact base
 * (RAM/CPU/flash) + the auto-detected profile class. Static per boot:
 * polled once + every 60 s, not with the 4 s refresh. */
const callResProfile = rpc.declare({
	object: 'luci.ravnex',
	method: 'res_profile',
	expect: { '': {} }
});

/* Ф1.1 Operation/Apply Manager: applies run as tracked operations
 * (stages + server-side verified flag) — poll until completed/failed. */
const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

const callSnapshotCreate = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_snapshot_create',
	expect: { '': {} }
});

const callRestoreInternet = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_restore_internet',
	expect: { '': {} }
});

/* Update check stays ON DEMAND (D6): the version is always visible, the
 * GitHub query only fires when the user asks for it. */
const callAppCheckUpdate = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_check_update',
	expect: { '': {} }
});

/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label —
 * human-readable names, never raw cfg-ids (hotswap lesson). */
function resolveTag(tag) {
	const m = tag && String(tag).match(/^cfg-(.+)-out$/);
	if (m) {
		const label = uci.get('ravnex', m[1], 'label');
		if (label) return label;
	}
	return tag;
}

/* Routing mode → display label (Ф3.1: the three-mode model; legacy custom
 * values still read honestly as the working mode). */
function routingModeLabel(mode) {
	switch (mode) {
		case 'proxy_banned_ru': return _('Bypass blocking (rule lists)');
		case 'global': return _('Everything through node');
		case 'direct': return _('Direct (all mechanisms off)');
		case 'custom':
		case 'custom_json': return _('Bypass blocking (rule lists)') + ' (' + _('legacy mode') + ')';
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
			uci.load('ravnex'),
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
/* Brand block (Р3): raven icon + wordmark/slogan. */
.hpui-brand { display: flex; align-items: center; flex-wrap: wrap; gap: 14px; padding: 12px 16px; margin: 2px 0 12px; border: 1px solid var(--hp-panel-line); border-left: 4px solid var(--hp-accent); border-radius: var(--hp-radius-lg); background: linear-gradient(90deg, var(--hp-accent-soft), transparent 55%), var(--hp-panel-bg); box-shadow: var(--hp-shadow); }
.hpui-brand-ic { width: 52px; height: 52px; border-radius: 12px; flex: none; box-shadow: 0 2px 8px rgba(0,0,0,.28); }
.hpui-brand-name { font-size: 1.45em; font-weight: 800; line-height: 1.25; display: flex; align-items: baseline; gap: 8px; }
.hpui-brand-slogan { color: var(--hp-accent-strong); font-weight: 700; font-size: .58em; letter-spacing: .06em; white-space: nowrap; }
/* One auto-margin ONLY (hero-right): the version pill sits at the FAR right
 * with a fixed gap, so status-text width changes cannot shift it or the
 * check button — the old double margin-left:auto split the free space and
 * everything "jumped around" on every poll (user note 2026-11-07). */
.hpui-brand-ver { margin-left: 12px; align-self: flex-start; font-size: .84em; opacity: .85; border: 1px solid var(--hp-panel-line); border-radius: 999px; padding: 2px 10px; background: var(--hp-panel-bg-2); white-space: nowrap; }
/* Р3 v3 hub: hero status on the right side of the brand block. */
.hpui-hero-right { margin-left: auto; display: flex; flex-direction: column; align-items: flex-end; gap: 7px; padding-left: 14px; }
.hpui-hero-status { font-size: 1.08em; font-weight: 800; white-space: nowrap; max-width: 44vw; overflow: hidden; text-overflow: ellipsis; }
.hpui-hero-status.ok { color: var(--hp-accent-strong); }
.hpui-hero-status.bad { color: var(--hp-red); }
.hpui-brand-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.hpui-chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--hp-panel-line); background: var(--hp-panel-bg-2); border-radius: 999px; padding: 2px 10px 2px 9px; font-size: .84em; line-height: 1.55; max-width: 100%; }
.hpui-chip .hpui-ic { width: 1.05em; height: 1.05em; opacity: .8; }
.hpui-chip-name { font-weight: 600; white-space: nowrap; }
.hpui-chip-state { opacity: .85; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 190px; }
/* .hpui-dot base + ok/bad/warn variants moved into the design system
 * (homeproxy.js uiStyle, Ф9.2) — the shell sidebar uses them on EVERY page. */
/* Concern cards (Р3 v3 §6): question + live state + description + jump. */
.hpui-hub { display: grid; grid-template-columns: repeat(auto-fit, minmax(215px, 1fr)); gap: 10px; margin: 0 0 12px; }
.hpui-hub-card { display: flex; flex-direction: column; gap: 5px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius-lg); background: var(--hp-panel-bg); box-shadow: var(--hp-shadow); padding: 12px 14px; min-width: 0; }
.hpui-hub-title { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 1.0em; }
.hpui-hub-title .hpui-ic { color: var(--hp-accent-strong); width: 1.15em; height: 1.15em; }
.hpui-hub-state { font-size: .93em; font-weight: 600; display: flex; align-items: center; gap: 7px; min-height: 1.45em; overflow: hidden; }
.hpui-hub-state .hpui-dot { flex: none; }
.hpui-hub-state span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hpui-hub-desc { font-size: .8em; opacity: .72; line-height: 1.45; flex: 1 1 auto; }
.hpui-hub-card .btn, .hpui-hub-card .cbi-button { align-self: flex-start; margin-top: 2px; }
/* Quick setup strip (Р3 v3 §6): visible until the main path is set up. */
.hpui-qs { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 20px; border: 1px solid var(--hp-accent-line); background: var(--hp-accent-soft); border-radius: var(--hp-radius-lg); padding: 12px 16px; margin: 0 0 12px; box-shadow: var(--hp-shadow); }
.hpui-qs-t { font-weight: 800; width: 100%; }
.hpui-qs-hint { width: 100%; font-size: .84em; opacity: .8; margin: -4px 0 0; }
.hpui-qs-step { display: inline-flex; align-items: center; gap: 8px; font-size: .92em; font-weight: 600; }
.hpui-qs-num { width: 22px; height: 22px; border-radius: 50%; background: var(--hp-panel-bg-2); border: 1px solid var(--hp-panel-line-strong); display: inline-flex; align-items: center; justify-content: center; font-weight: 700; font-size: .82em; flex: none; }
.hpui-qs-step.done { opacity: .78; font-weight: 500; }
.hpui-qs-step.done .hpui-qs-num { background: var(--hp-accent-strong); border-color: var(--hp-accent-strong); color: #fff; }
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
		/* Utility band at the bottom: THREE EQUAL cards in one row (user
		 * note 2026-11-07 — the old 2.1fr/1fr split with stacked right
		 * column produced uneven card heights). auto-fit gives every card
		 * the same width and the grid stretch equalizes heights; panels are
		 * flex columns with the hint pinned to the bottom so the three
		 * cards read as one level. */
		.ov-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; align-items: stretch; margin: 0; }
		.ov-grid > .hpui-panel { margin: 0; display: flex; flex-direction: column; min-width: 0; }
		.ov-grid > .hpui-panel > .hpui-hint { margin-top: auto; padding-top: 6px; }
		.ov-grid .ov-pairs { flex: 1 1 auto; align-content: start; }
		/* Ф9.1: the Dashboard events strip — a compact tail of the unified journal. */
		.ov-grid .ov-evlist { flex: 1 1 auto; max-height: 300px; min-height: 130px; }
.hpui-h4 .hpui-cap-link { margin-left: auto; font-size: .84em; color: var(--hp-accent-strong); }
@media (max-width: 1150px) { .ov-grid { grid-template-columns: 1fr; } }
`;

		const st = document.getElementById('hp-ov-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-ov-style' }, [ OV_CSS ]));

		let metrics = { interval: 5, updated: 0, points: [] };
		const state = { chartSig: null };

		/* ── Hero (Р3 v3 §6): brand on the left; on the right the big human
		 * status ("Everything is running" / the problem) + a "Check now"
		 * jump to Check & repair. The routing-mode chip stays under the
		 * wordmark; MultiDNS moved to its own hub card (D35 block E — the
		 * card covers the state, the chip would duplicate it). */
		const heroStatus = E('div', { 'class': 'hpui-hero-status' }, [ '…' ]);
		const heroBtn = E('button', { 'class': 'btn cbi-button' }, [ _('Check now') ]);
		const modeChipState = E('span', { 'class': 'hpui-chip-state' }, [ '—' ]);
		const heroChips = E('div', { 'class': 'hpui-brand-chips' }, [
			E('span', { 'class': 'hpui-chip', 'id': 'hp-hero-mode' }, [
				hp.icon('shuffle'),
				E('span', { 'class': 'hpui-chip-name' }, [ _('Routing mode') ]),
				modeChipState
			])
		]);
		const brandVer = E('span', { 'class': 'hpui-brand-ver' }, [ '—' ]);
		const brandEl = E('div', { 'class': 'hpui-brand' }, [
			E('img', { 'class': 'hpui-brand-ic', 'src': L.resource('ravnex-raven-192.png'), 'alt': 'Ravnex' }),
			E('div', {}, [
				E('div', { 'class': 'hpui-brand-name' }, [
					E('span', {}, [ 'Ravnex' ]),
					E('span', { 'class': 'hpui-brand-slogan' }, [ '· Own the Route.' ])
				]),
				heroChips
			]),
			E('div', { 'class': 'hpui-hero-right' }, [ heroStatus, heroBtn ]),
			brandVer
		]);

		heroBtn.addEventListener('click', function() {
			/* D32: Check & repair lives on the Health center (repair tab).
			 * In embed mode this mounts in place (hp.embedGo); the hash
			 * keeps the deep-link. */
			hp.embedGo('health', 'repair');
		});

		/* D32 deep links: L.url() TRUNCATES at '#' (path() joins parts and the
		 * fragment never survives), so split it here: L.url() for the path,
		 * the raw '#tab' appended. */
		function hpHref(p) {
			const h = p.indexOf('#');
			return (h < 0) ? L.url(p) : L.url(p.slice(0, h)) + p.slice(h);
		}

		/* ── Concern cards (Р3 v3 §6): the six human questions. Every card
		 * = title (the question) + live state (from the shared poll data)
		 * + one-line "how it works" description + a jump button. No action
		 * is duplicated here — the buttons NAVIGATE, the target page owns
		 * the functionality. */
		const HUB_DEFS = [
			[ 'exit',   'shuffle', _('Where your traffic goes'),
				_('The server your devices use to reach the internet right now.'),
				_('Change server'), 'admin/services/ravnex/client' ],
			[ 'bypass', 'shield',   _('Strategy master'),
				_('Zapret and ByeDPI open blocked sites without a VPN subscription.'),
				_('Configure'), 'admin/services/ravnex/bypass' ],
			[ 'learn',  'refresh',  _('Auto-bypass'),
				_('The engine finds blocked sites itself and sends them around the block.'),
				_('Open'), 'admin/services/ravnex/automation' ],
			[ 'dns',    'globe',    _('DNS & MultiDNS'),
				_('Two DNS pools — plain for Russian sites, encrypted for blocked ones — and the racing engine that keeps them fast.'),
				_('Configure'), 'admin/services/ravnex/dns' ],
			[ 'subs',   'server',   _('Subscriptions'),
				_('The server lists your nodes come from — updated on a schedule or by hand.'),
				_('Open'), 'admin/services/ravnex/node' ],
			[ 'home',   'monitor',  _('Devices at home'),
				_('Who is connected to the router and what they can open.'),
				_('Open'), 'admin/services/ravnex/devices' ],
			[ 'family', 'shield',   _('Access Control'),
				_('Site rules, schedules and Wi-Fi limits per device.'),
				_('Configure'), 'admin/services/ravnex/control' ],
			[ 'phone',  'send',     _('Phone control'),
				_('Status, server switching and control — right from Telegram.'),
				_('Connect'), 'admin/services/ravnex/telegram' ],
			[ 'diag',   'sensors',  _('Check & repair'),
				_('One click runs the health checks and repairs the routing.'),
				_('Check now'), 'admin/services/ravnex/health#repair' ],
			[ 'health', 'heart',    _('Health center'),
				_('Live status of every subsystem, the automatic repair log and the event feed.'),
				_('Open'), 'admin/services/ravnex/health' ],
			[ 'load',   'trend',    _('Resources & load'),
				_('RAM, CPU load and flash usage — how heavy the box is right now.'),
				_('Open'), 'admin/services/ravnex/monitor' ],
			[ 'maint',  'cpu',      _('Maintenance'),
				_('Core version, snapshots, update checks and service management.'),
				_('Open'), 'admin/services/ravnex/status' ]
		];
		const hub = {};
		const hubEl = E('div', { 'class': 'hpui-hub' });
		for (let h in HUB_DEFS) {
			const dot = E('span', { 'class': 'hpui-dot' });
			const state = E('span', {}, [ '…' ]);
			const btn = E('a', { 'class': 'btn cbi-button hpui-hub-btn',
				'href': hpHref(HUB_DEFS[h][5]) }, [ HUB_DEFS[h][4] ]);
			const el = E('div', { 'class': 'hpui-hub-card' }, [
				E('div', { 'class': 'hpui-hub-title' }, [ hp.icon(HUB_DEFS[h][1]), HUB_DEFS[h][2] ]),
				E('div', { 'class': 'hpui-hub-state' }, [ dot, state ]),
				E('div', { 'class': 'hpui-hub-desc' }, [ HUB_DEFS[h][3] ]),
				btn
			]);
			hub[HUB_DEFS[h][0]] = { dot: dot, state: state, btn: btn };
			hubEl.appendChild(el);
		}

		/* ── Quick setup strip (Р3 v3 §6): four steps with done-states,
		 * visible until the main path is configured (servers + main node).
		 * Buttons navigate to the owning page; no logic is duplicated. */
		function qsBtn(url, label) {
			return E('a', { 'class': 'btn cbi-button', 'href': hpHref(url) }, [ label ]);
		}
		const qsSteps = [
			[ 'nodes', '1', _('Add servers'), 'admin/services/ravnex/node', _('Import a subscription or paste a share link.') ],
			[ 'main',  '2', _('Choose the main node'), 'admin/services/ravnex/client', null ],
			[ 'byp',   '3', _('Turn on the bypass'), 'admin/services/ravnex/bypass', null ],
			[ 'net',   '4', _('Check the internet'), 'admin/services/ravnex/health#repair', null ]
		];
		const qsEls = {};
		const qsEl = E('div', { 'class': 'hpui-qs' }, [
			E('div', { 'class': 'hpui-qs-t' }, [ _('Quick setup') ]),
			E('div', { 'class': 'hpui-qs-hint' },
				[ _('Three steps and Ravnex starts routing your traffic.') ])
		]);
		for (let s in qsSteps) {
			const num = E('span', { 'class': 'hpui-qs-num' }, [ qsSteps[s][1] ]);
			const lbl = E('span', { 'class': 'hpui-qs-lbl' }, [ qsSteps[s][2] ]);
			const btn = qsBtn(qsSteps[s][3], qsSteps[s][2]);
			btn.style.display = 'none';
			const el = E('span', { 'class': 'hpui-qs-step', 'title': qsSteps[s][4] || '' }, [ num, lbl, btn ]);
			qsEls[qsSteps[s][0]] = { el: el, num: num, lbl: lbl, btn: btn,
				num0: qsSteps[s][1], lbl0: qsSteps[s][2] };
			qsEl.appendChild(el);
		}

		function setQs(key, done) {
			const q = qsEls[key];
			if (!q)
				return;
			q.el.classList.toggle('done', !!done);
			if (done) {
				q.num.textContent = '✓';
				q.lbl.textContent = _('Done');
				q.btn.style.display = 'none';
			} else {
				q.num.textContent = q.num0;
				q.lbl.textContent = q.lbl0;
				q.btn.textContent = q.lbl0;
				q.btn.style.display = '';
			}
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
			 * /connections sampler. byp = Zapret + ByeDPI (ч.200, D34b:
			 * tg-ws удалён).
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
			E('h4', { 'class': 'hpui-h4' }, [
				hp.icon('repeat'), _('Traffic by exit'),
				E('a', { 'class': 'hpui-cap-link', 'href': hpHref('admin/services/ravnex/monitor') },
					[ _('Monitoring') ])
			]),
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
		/* Ф9.1/Ф10: the resource profile rides the System panel (the value
		 * is filled by the 60 s profile poll, not the 4 s refresh). */
		const profV = E('span', { 'class': 'v' }, [ '—' ]);
		sysPairs.appendChild(E('div', {}, [
			E('span', { 'class': 'k' }, [ _('Resource profile') + ':' ]),
			profV
		]));

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
				[ _('Update availability is checked on demand — the Home page never queries external resources on its own.') ])
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
				[ _('The service restart re-routes every connection ("Maintenance" carries start/stop); a snapshot copies the app configuration and the routing lists; "Restore internet" is the emergency switch for a plain direct connection.') ])
		]);

		/* ── Events strip (Ф9.1, §A.4: critical events on the Dashboard) ──
		 * The tail of the SAME unified journal the Health center renders in
		 * full — the Home page does not fork a second feed, it just shows
		 * the last entries where the user looks every day. */
		const evStrip = E('div', { 'class': 'hpui-log ov-evlist' }, []);
		const eventsEl = E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [
				hp.icon('activity'), _('Events'),
				E('a', { 'class': 'hpui-cap-link', 'href': hpHref('admin/services/ravnex/health#journal') },
					[ _('All events') ])
			]),
			E('p', { 'class': 'hpui-hint' }, [ _('What the system has just done or noticed — the tail of the journal the event center in the Health center keeps.') ]),
			evStrip
		]);

		function renderEvents(events) {
			const srcMap = hp.EV_SRC();
			const out = [];
			for (let i = (events || []).length - 1; i >= 0 && out.length < 6; i--) {
				const ev = events[i];
				const t = new Date(ev.ts * 1000);
				const hh = ('0' + t.getHours()).slice(-2) + ':' + ('0' + t.getMinutes()).slice(-2);
				const icon = hp.EV_ICONS[ev.type] || '•';
				const src = srcMap[ev.src || 'control'] || (ev.src || 'control');
				out.push(E('div', {}, [
					E('span', { 'class': hp.EV_COLORS[ev.type] || 'hpui-c-grey' },
						[ hh + ' ' + icon + ' ' + (ev.who || '') ]),
					(ev.detail ? ' — ' + ev.detail : ''),
					E('span', { 'class': 'hpui-cap', 'style': 'margin-left:8px' }, [ '[' + src + ']' ])
				]));
			}
			dom.content(evStrip, out.length ? out : [ _('The journal is empty.') ]);
		}

		function renderProfile(p) {
			p = p || {};
			const names = { lite: _('Lite'), balanced: _('Balanced'), performance: _('Performance') };
			const src = (p.source === 'auto') ? ' · ' + _('auto')
				: (p.source === 'manual' ? ' · ' + _('manual') : '');
			profV.textContent = p.profile ? ((names[p.profile] || p.profile) + src) : '—';
		}

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
			noteResult(_('Applying configuration…'), null);
			L.resolveDefault(callServiceRestart(), {}).then(function(r) {
				if (r && r.op_id && r.result !== false)
					return pollOp(r.op_id);
				restartBtn.disabled = false;
				noteResult((r && r.error) || _('Restart failed'), false);
			});
		});

		/* Ф1.1: honest result — the badge flips only when the operation has
		 * completed AND the backend verified the service is actually up. */
		function pollOp(opId) {
			const deadline = Date.now() + 120000;
			const tick = function() {
				L.resolveDefault(callOpStatus(opId), {}).then(function(st) {
					/* Audit B3 class (с.193): the watcher dies with the section. */
					if (!resultEl.isConnected)
						return;
					const op = st && st.op;
					if (!op) {
						restartBtn.disabled = false;
						noteResult(_('Operation status unavailable'), false);
						return;
					}
					if (op.status === 'completed' || op.status === 'failed') {
						restartBtn.disabled = false;
						const ok = (op.status === 'completed') && op.verified;
						noteResult(ok ? _('Service restarted.') :
							((op.detail || _('Apply failed'))), ok);
						return;
					}
					if (Date.now() > deadline) {
						restartBtn.disabled = false;
						noteResult(_('The operation is still running — check the operation journal'), false);
						return;
					}
					window.setTimeout(tick, 2000);
				});
			};
			tick();
		}

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
			hp.confirmModal(_('Restore internet'),
				_('Stop the proxy stack and restore DIRECT internet? DNS interception is removed; the proxy comes back with "Service start" or a router reboot.'), _('Stop proxy'))
				.then(function(ok) {
					if (!ok)
						return;
					restoreBtn.disabled = true;
					noteResult(_('Stopping the proxy stack…'), null);
					L.resolveDefault(callRestoreInternet(), {}).then(function(r) {
						restoreBtn.disabled = false;
						noteResult(r.result ? _('Direct internet restored — run "Service start" to bring the proxy back.')
							: ((r && r.error) || _('Failed')), !!r.result);
					});
				});
		});

		updateBtn.addEventListener('click', function() {
			updateBtn.disabled = true;
			noteResult(_('Checking the latest release…'), null);
			L.resolveDefault(callAppCheckUpdate(), {}).then(function(r) {
				updateBtn.disabled = false;
				if (!r || r.error)
					return noteResult(_('Update check failed: %s').format((r && r.error) || _('rpc error')), false);
				if (r.update_available)
					setResult(E('p', { 'class': 'hpui-hint' }, [
						_('Update available: %s → %s.').format(r.installed_version, r.latest_version) + ' ',
						E('a', { 'class': 'hpui-cap-link', 'href': hpHref('admin/services/ravnex/status') },
							[ _('Install it on the Maintenance page') ])
					]), true);
				else
					noteResult(_('The installed version %s is the latest.').format(r.installed_version || _('unknown')), true);
			});
		});

		/* ── Live render helpers ───────────────────────────────────────── */

		function renderCards(sys, node, dpi, mdns, ctl) {
			const z = (dpi && dpi.zapret) || {}, b = (dpi && dpi.byedpi) || {};
			const cfgMode = uci.get('ravnex', 'config', 'routing_mode') || 'proxy_banned_ru';
			const cfgMainNode = uci.get('ravnex', 'config', 'main_node') || '';
			const last = (metrics.points.length) ? metrics.points[metrics.points.length - 1] : null;

			/* Core (hero + metric card). */
			const coreType = features.core_type || null;
			const coreName = coreType === 'hiddify' ? 'hiddify-core' :
				coreType === 'singbox' ? 'sing-box-extended' : _('not installed');
			const coreVer = features.version ? 'v' + features.version : '';
			mcardNum(mcards.core, coreName, sys.clash_ok ? '' : (coreType && cfgMode !== 'direct' ? 'hpui-c-red' : ''));
			mcards.core.note.textContent = (coreVer ? coreVer : '') +
				(sys.clash_ok ? ' · ' + _('running')
					: (coreType ? ' · ' + ((cfgMode === 'direct') ? _('off (direct mode)') : _('not responding')) : ''));
			/* Ф3.1: in the direct mode («Напрямую») the core being down is the
			 * CHOSEN state, not a fault — the hero says so instead of alarming. */
			if (cfgMode === 'direct') {
				heroStatus.className = 'hpui-hero-status ok';
				heroStatus.textContent = _('Direct mode is on — bypass is off');
			} else if (!coreType) {
				heroStatus.className = 'hpui-hero-status bad';
				heroStatus.textContent = _('Core is not installed');
			} else if (!sys.clash_ok) {
				heroStatus.className = 'hpui-hero-status bad';
				heroStatus.textContent = _('Core is not responding');
			} else {
				heroStatus.className = 'hpui-hero-status ok';
				heroStatus.textContent = _('Everything is running');
			}

			/* RAM metric card (the spark scale is fixed 0-100%). */
			mcardNum(mcards.ram, (last && last.ram != null) ? (last.ram + '%') : '—', '');
			mcards.ram.note.textContent = (last && last.ram != null) ? _('scale 0-100%') : '';

			/* Active node (concern card 1 + metric card). */
			let exitText = '—', exitDot = '';
			if (node && node.node) {
				const special = { 'main-out': _('Main node'), 'zapret-out': 'Zapret',
					'byedpi-out': 'ByeDPI', 'direct-out': _('Direct'), 'block-out': _('Block') };
				const shown = special[node.node] || resolveTag(node.node);
				mcardNum(mcards.node, shown, node.delay ? 'hpui-c-green' : '');
				mcards.node.note.textContent = (node.delay != null) ? (node.delay + ' ms') : '—';
				exitText = shown + ((node.delay != null) ? (' · ' + node.delay + ' ms') : '');
				exitDot = node.delay ? 'ok' : '';
			} else {
				mcardNum(mcards.node, '—', 'hpui-c-grey');
				mcards.node.note.textContent = (cfgMode === 'direct')
					? _('Direct mode — bypass is off')
					: (cfgMainNode === 'direct-out' ? _('Direct') : _('no node'));
				exitText = (cfgMode === 'direct')
					? _('Direct mode — bypass is off')
					: (cfgMainNode === 'direct-out' ? _('Direct') : _('Proxy is not configured'));
				exitDot = (cfgMainNode === 'direct-out') ? 'warn' : '';
			}
			hub.exit.dot.className = 'hpui-dot' + (exitDot ? ' ' + exitDot : '');
			hub.exit.state.textContent = exitText;

			/* Connections + VPN speed metric cards (sparkline series). */
			mcardNum(mcards.conns, (last && last.conns != null) ? String(Math.floor(last.conns)) : '—', '');
			mcardNum(mcards.vpn, (last && last.vpn_b != null) ? fmtBps(last.vpn_b) : '—',
				(last && last.vpn_b > 0) ? 'hpui-c-green' : '');

			/* Routing mode chip (hero). */
			const proxyMode = uci.get('ravnex', 'config', 'proxy_mode') || '';
			const pmLabels = { redirect: _('Redirect TCP'), redirect_tproxy: _('Redirect TCP + TProxy UDP'),
				redirect_tun: _('Redirect TCP + Tun UDP'), tun: _('Tun TCP/UDP') };
			modeChipState.textContent = routingModeLabel(cfgMode);
			modeChipState.setAttribute('title', pmLabels[proxyMode] || proxyMode);

			/* Zapret / ByeDPI (concern card 2). The corpus NAME (when known)
			 * rides in the tooltip, not in the state line. */
			const zState = (!z.installed) ? _('not installed') : (!z.enabled) ? _('disabled')
				: (z.running ? _('running') : _('enabled, not running'));
			const bState = (!b.installed) ? _('not installed') : (!b.enabled) ? _('disabled')
				: (b.running ? _('running') : _('enabled, not running'));
			const zName = z.strategy_name ? String(z.strategy_name) :
				z.strategy ? _('custom options') : null;
			const zq = z.nfqueue || {};
			hub.bypass.dot.className = 'hpui-dot' +
				((z.enabled && z.running) || (b.enabled && b.running) ? ' ok'
					: (z.enabled || b.enabled) ? ' bad' : '');
			hub.bypass.state.textContent = 'Zapret: ' + zState + ' · ByeDPI: ' + bState;
			hub.bypass.state.setAttribute('title', (zName ? 'Zapret: ' + zName + ' · NFQUEUE: ' + (zq.packets || 0) + ' pkts' : ''));

			/* DNS & MultiDNS (hub card): the same poll data the hero chip
			 * carried before — now a full card with a jump. "restarting..."
			 * is the routine quality-cycle rebuild window — neutral, NOT the
			 * alarming red. */
			const mdEnabled = (mdns && mdns.enabled === '1') || (uci.get('ravnex', 'multidns', 'enabled') === '1');
			const mdRunning = !!(mdEnabled && mdns && mdns.mosdns);
			const mdRestart = !!(mdEnabled && !mdRunning && mdns && mdns.restarting);
			const mdRu = (mdEnabled && mdns && mdns.active && mdns.active.ru) ? mdns.active.ru.length : 0;
			const mdSec = (mdEnabled && mdns && mdns.active && mdns.active.secure) ? mdns.active.secure.length : 0;
			hub.dns.dot.className = 'hpui-dot' +
				(mdEnabled ? (mdRunning ? ' ok' : (mdRestart ? ' warn' : ' bad')) : '');
			hub.dns.state.textContent = mdEnabled
				? ((mdRunning ? _('running') : (mdRestart ? _('restarting...') : _('enabled, not running')))
					+ ' · ' + _('RU: %d · Secure: %d').format(mdRu, mdSec))
				: _('MultiDNS off');
			hub.dns.state.setAttribute('title', mdEnabled ? _('RU: %d · Secure: %d').format(mdRu, mdSec) : '—');

			/* Auto-bypass (concern card 3) + the automation-family monitors
			 * (Ф7.4): the health-doc pass-through gives the live status of
			 * the four automation services — data here, polish in Ф9. */
			const auEnabled = (uci.get('ravnex', 'automation', 'enabled') === '1');
			const auRunning = !!sys.automation_running;
			const learned = (last && last.learned != null) ? Math.floor(last.learned) : null;
			hub.learn.dot.className = 'hpui-dot' + (auEnabled ? (auRunning ? ' ok' : ' bad') : '');
			hub.learn.state.textContent = auEnabled
				? ((auRunning ? _('running') : _('enabled, not running'))
					+ ((learned != null) ? (' · ' + _('Learned sites: %d').format(learned)) : ''))
				: _('disabled');
			const fam = sys.automation_family || null;
			if (fam) {
				const words = { ok: _('running'), off: _('off'), down: _('down'), degraded: _('degraded') };
				/* The autopilot daemon idles by design when disabled — the
				 * card must show the FUNCTION, not the idle process. */
				const apOn = (uci.get('ravnex', 'autopilot', 'enabled') === '1');
				const bit = (k) => (fam[k] ? (words[fam[k].status] || '—') : '—');
				hub.learn.state.textContent += ' · ' + _('DPI auto-pilot') + ': ' +
					(apOn ? bit('autopilot') : _('off')) +
					' · Hot Swap: ' + bit('hotswap') + ' · URLTest: ' + bit('urltest');
			}

			/* Home devices + Parental control (concern cards 4-5, Control
			 * engine summary). */
			const ctlS = (ctl && ctl.stats) || {};
			const ctlEnabled = !!(ctl && ctl.enabled === true);
			const ctlPaused = !!(ctl && ctl.paused === true);
			hub.home.dot.className = 'hpui-dot' + (ctlEnabled ? ' ok' : '');
			hub.home.state.textContent = (ctlS.devices_total != null)
				? _('In network: %d').format(ctlS.devices_total) : '—';
			hub.family.dot.className = 'hpui-dot' + (ctlEnabled ? (ctlPaused ? 'warn' : 'ok') : '');
			hub.family.state.textContent = ctlEnabled
				? (ctlPaused ? _('Paused') : _('Active')) : _('Off');

			/* Phone control (concern card 6). Honesty: when the Telegram
			 * daemon is up and enabled the bot IS connected — the action is
			 * then «Open», not «Connect» (user note, 2026-11-07). */
			const tgEnabled = !!(sys.telegram && sys.telegram.enabled === true);
			const tgRunning = !!(sys.telegram && sys.telegram.running);
			hub.phone.dot.className = 'hpui-dot' + (tgEnabled ? (tgRunning ? ' ok' : ' bad') : '');
			hub.phone.state.textContent = tgEnabled
				? (tgRunning ? _('running') : _('enabled, not running')) : _('disabled');
			if (hub.phone.btn)
				hub.phone.btn.textContent = (tgEnabled && tgRunning) ? _('Open') : _('Connect');

			/* Check & repair + Maintenance (concern cards 7-8): the health
			 * verdict repeats the fact the hero states; the version rides
			 * the same poll — no extra RPC. */
			const diagOk = !!sys.clash_ok;
			const diagSeen = !!sys.app_version;
			/* Ф3.1: direct mode — the core being down is the chosen state. */
			const directNow = (cfgMode === 'direct');
			hub.diag.dot.className = 'hpui-dot' + (diagSeen ? ((diagOk || directNow) ? ' ok' : ' bad') : '');
			hub.diag.state.textContent = !diagSeen ? _('not installed')
				: (directNow ? _('Direct mode is on — bypass is off')
					: (diagOk ? _('Everything is running') : _('Core is not responding')));
			hub.maint.dot.className = 'hpui-dot' + (diagSeen ? ((diagOk || directNow) ? ' ok' : ' bad') : '');
			hub.maint.state.textContent = diagSeen
				? 'Ravnex v' + sys.app_version : _('not installed');

			/* Health center (concern card 9): the health doc summary rides
			 * overview_sys (one extra readfile on the poll, no forks). A
			 * stale doc is shown honestly as "no fresh data" — the daemon
			 * rewrites it every tick. */
			const hs = (sys && sys.health) || null;
			let hText = _('no fresh data'), hDot = '';
			if (hs && hs.fresh) {
				if (hs.overall === 'ok') {
					hText = _('All subsystems are running');
					hDot = 'ok';
				} else if (hs.overall === 'off') {
					hText = _('The service is stopped');
					hDot = '';
				} else {
					const dn = (hs.counts && hs.counts.down) || 0;
					const dg = (hs.counts && hs.counts.degraded) || 0;
					hText = ((dn > 0) ? _('Down: %d · ').format(dn) : '') +
						_('Degraded: %d').format(dg);
					hDot = (dn > 0) ? 'bad' : 'warn';
				}
			}
			hub.health.dot.className = 'hpui-dot' + (hDot ? ' ' + hDot : '');
			hub.health.state.textContent = hText;

			/* Resources & load (hub card): RAM from the metrics ring, the
			 * 1-minute load from the same poll. >=90% RAM is a warn — the
			 * OOM edge (Ф10) matters on small boxes. */
			const ramNow = (last && last.ram != null) ? Math.round(last.ram) : null;
			hub.load.dot.className = 'hpui-dot' + (ramNow != null && ramNow >= 90 ? ' warn' : '');
			hub.load.state.textContent = (ramNow != null)
				? _('RAM %s · load %s').format(ramNow + '%',
					(sys.load1 != null) ? Number(sys.load1).toFixed(2) : '—')
				: '—';

			/* Quick setup strip: visible until servers + main node exist. */
			let nodeCount = 0;
			uci.sections('ravnex', 'node', function() { nodeCount++; });
			const doneNodes = nodeCount > 0;
			const doneMain = !!cfgMainNode;
			const doneByp = (z.enabled === true) || (b.enabled === true) || auEnabled;
			const doneNet = !!sys.clash_ok;
			setQs('nodes', doneNodes);
			setQs('main', doneMain);
			setQs('byp', doneByp);
			setQs('net', doneNet);
			qsEl.style.display = (doneNodes && doneMain) ? 'none' : '';
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
				L.resolveDefault(callMultidnsStatus(), {}),
				L.resolveDefault(callControlStatus(), {}),
				L.resolveDefault(callEvents('12'), {})
			]).then(function(data) {
				metrics = (data[0] && typeof data[0] === 'object' && data[0].points)
					? data[0] : { interval: 5, updated: 0, points: [] };
				const sys = data[1] || {};
				const node = (data[2] && data[2].node) ? data[2] : null;
				const dpi = data[3] || {};
				const mdns = data[4] || {};
				const ctl = (data[5] && data[5].result !== false) ? data[5] : {};
			renderSys(sys);
			renderCards(sys, node, dpi, mdns, ctl);
			renderCharts();
			renderTraffic(metrics.totals);
			renderEvents((data[6] && data[6].events) || []);
			});
		}

		/* Ф9.1/Ф10: the profile is a per-boot fact — polled once + every
		 * 60 s, NOT with the 4 s refresh. */
		function profileRefresh() {
			return L.resolveDefault(callResProfile(), {}).then(renderProfile);
		}

		/* Subscriptions (hub card): the last cycle + node book — a cheap
		 * file-read RPC, polled once a minute (subscriptions change rarely;
		 * an update run carries the running flag with a fresh ts). */
		function subsRefresh() {
			return L.resolveDefault(callSubsStatus(), {}).then(function(st) {
				st = st || {};
				const groups = st.groups || {};
				let gcount = 0;
				for (let g in groups) gcount++;
				const total = parseInt(st.node_total, 10) || 0;
				const last = st.last || null;
				const fresh = !!(last && last.running &&
					((Date.now() / 1000) - (parseInt(last.ts, 10) || 0) < 900));
				let text = '—', dot = '', tip = '';
				if (!gcount && !total) {
					text = _('No subscriptions yet');
				} else if (fresh) {
					text = _('Updating subscriptions…');
					dot = 'warn';
				} else if (last && last.action === 'failed') {
					text = _('Last update failed');
					dot = 'bad';
					tip = last.reason || '';
				} else if (last && last.action === 'rolled_back') {
					text = _('Rolled back — new nodes rejected');
					dot = 'bad';
				} else {
					text = _('nodes: %d · subscriptions: %d').format(total, gcount);
					dot = 'ok';
					tip = st.auto_update ? _('Auto-update is on') : '';
				}
				hub.subs.dot.className = 'hpui-dot' + (dot ? ' ' + dot : '');
				hub.subs.state.textContent = text;
				if (tip)
					hub.subs.state.setAttribute('title', tip);
				else
					hub.subs.state.removeAttribute('title');
			});
		}

		poll.add(hp.vpoll(refresh), hp.pollSec(4));
		refresh();
		poll.add(hp.vpoll(profileRefresh), hp.pollSec(60));
		profileRefresh();
		poll.add(hp.vpoll(subsRefresh), hp.pollSec(60));
		subsRefresh();

		/* Р3 v3 hub layout: hero (brand + status) → quick setup (until set
		 * up) → concern cards → headline metric cards → two-column grid
		 * (charts | system + quick actions) → traffic by exit → ONE result
		 * area at the bottom. */
		return E('div', {}, [
			brandEl,
			qsEl,
			hubEl,
			mcardsEl,
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [
					hp.icon('activity'), _('Performance'),
					E('a', { 'class': 'hpui-cap-link', 'href': hpHref('admin/services/ravnex/monitor') },
						[ _('Monitoring') ])
				]),
				chartsEl,
				chartsCap
			]),
			trafficEl,
			/* Utility band: THREE EQUAL cards in one row (user note 2026-11-07).
			 * Utilities live at the BOTTOM of the hub — away from the concern
			 * cards; the events strip is Dashboard material (§A.4). */
			E('div', { 'class': 'ov-grid' }, [ sysEl, eventsEl, actionsEl ]),
			resultEl
		]);
	}
});
