/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — Automation tab.
 *
 * Internal tabs: Overview (status cards + the Ф5 "Engine overview" panel:
 * cycle/probe/RAM/entries cards, inline-SVG sparklines, verdict
 * distribution, source activity and a recent-events feed, all fed by the
 * light automation_stats RPC), Sites (table with
 * sticky header, search, filters, add/delete, manual "always proxy"/"always
 * direct" pins), RU-geo databases (freshness + update), Settings (UCI form),
 * Engine log. The detection only ADDS sites proven unreachable directly yet
 * reachable via the proxy, and routes them through the user's configured main
 * path — so it stays fully compatible with ByeDPI and Zapret. Russian
 * networks/domains are hard-excluded from learning and from proxying
 * (RU-geo databases + TLD guards + manual pins).
 */

'use strict';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';
'require homeproxy as hp';

const callStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_status',
	expect: { '': {} }
});

/* Ф5 (ч.77): engine counters for the "Engine overview" panel. LIGHT RPC —
 * the daemon writes a small stats file each cycle; this never parses the
 * heavy automation_state.json. */
const callStats = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_stats',
	expect: { '': {} }
});

const callEntryAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_entry_add',
	params: [ 'entry', 'action' ],
	expect: { '': {} }
});

const callEntryDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_entry_delete',
	params: [ 'entry' ],
	expect: { '': {} }
});

const callEntryAction = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_entry_action',
	params: [ 'entry', 'action' ],
	expect: { '': {} }
});

const callGeoUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_geo_update',
	expect: { '': {} }
});

const callClear = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_clear',
	expect: { '': {} }
});

const callClearLog = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_clear_log',
	expect: { '': {} }
});

const callTestNow = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_test_now',
	expect: { '': {} }
});

const callHelpersInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_helpers_install',
	expect: { '': {} }
});

const callBackup = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_backup',
	expect: { '': {} }
});

const callRestore = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_restore',
	params: ['content'],
	expect: { '': {} }
});

const callRestart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_service_restart',
	expect: { '': {} }
});

function downloadList(content) {
	const blob = new Blob([content || ''], { type: 'text/plain' });
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'homeproxy_learned_list.txt';
	document.body.appendChild(a);
	a.click();
	a.remove();
	URL.revokeObjectURL(a.href);
}

function btn(label, handler) {
	return E('button', {
		'class': 'btn',
		click: function() {
			const el = this;
			el.disabled = true;
			Promise.resolve(handler()).finally(function() { el.disabled = false; });
		}
	}, [ label ]);
}

/* ── Inline SVG sparkline (Ф5): the shared hp.chartSvg helper ─────────────
 * The local red copy (chartSvgEng, ×1.15 auto-scale, no scale caption)
 * moved into homeproxy.js (Ф8-F5 dedup, B2): Overview and Automation now
 * render the same implementation — red, ×1.35 headroom, optional
 * "scale up to N" caption via opts.onScale (renderStats adds it below).
 * ⚠ Browser JS `for…in` over an array yields STRING INDICES (the reverse
 * of the ucode lesson 20) — the helper iterates by index (lesson 59). */

/* ── Styling (scoped, theme-agnostic translucent colors) ─────────────── */

const CSS = `
.hpauto-tabs { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px 0; border-bottom: 2px solid rgba(128,128,128,.3); }
.hpauto-tab { appearance: none; border: 1px solid transparent; background: rgba(128,128,128,.10); color: inherit; padding: 7px 16px; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 1em; font-weight: 500; }
.hpauto-tab:hover { background: rgba(128,128,128,.20); }
.hpauto-tab.active { background: rgba(128,128,128,.26); border-color: rgba(128,128,128,.4); font-weight: 700; }
.hpauto-pane { display: none; }
.hpauto-pane.active { display: block; }
.hpauto-cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }
.hpauto-card { flex: 1 1 140px; min-width: 130px; padding: 10px 14px; border: 1px solid rgba(128,128,128,.3); border-radius: 8px; background: rgba(128,128,128,.07); }
.hpauto-num { font-size: 1.7em; font-weight: 700; line-height: 1.25; }
.hpauto-cap { font-size: .85em; opacity: .75; }
.c-red { color: #e05252; } .c-green { color: #3fbf5f; }
.c-blue { color: #4d8fe0; } .c-grey { color: #9a9a9a; }
.c-amber { color: #d99a1b; }
.hpauto-banner { margin: 8px 0; padding: 8px 12px; border-radius: 6px; border: 1px solid #b8860b; background: rgba(184,134,11,.15); }
.hpauto-banner-ok { border-color: #3fbf5f; background: rgba(63,191,95,.12); }
.hpauto-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.hpauto-toolbar input[type="text"] { flex: 1 1 200px; min-width: 150px; }
.hpauto-wrap { max-height: 62vh; overflow: auto; border: 1px solid rgba(128,128,128,.35); border-radius: 6px; margin-top: 6px; }
table.hpauto-table { border-collapse: separate; border-spacing: 0; width: 100%; }
table.hpauto-table thead th { position: sticky; top: 0; z-index: 2; background: #757575; color: #f5f5f5; text-align: left; font-weight: 600; padding: 8px 10px; white-space: nowrap; border-bottom: 1px solid rgba(0,0,0,.35); }
table.hpauto-table thead th.hpsort { cursor: pointer; }
table.hpauto-table tbody td { padding: 6px 10px; border-bottom: 1px solid rgba(128,128,128,.18); vertical-align: middle; }
table.hpauto-table tbody tr:hover td { background: rgba(128,128,128,.13); }
tr.hpsrc-manual td:first-child { box-shadow: inset 3px 0 0 #4d8fe0; }
tr.hpsrc-manual.hpsrc-manual-direct td:first-child { box-shadow: inset 3px 0 0 #b0b0b0; }
.hpbadge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: .82em; font-weight: 600; white-space: nowrap; border: 1px solid transparent; }
.hpb-blocked { background: rgba(224,82,82,.16); color: #e05252; border-color: rgba(224,82,82,.45); }
.hpb-direct { background: rgba(63,191,95,.15); color: #2e9e55; border-color: rgba(63,191,95,.45); }
.hpb-pending { background: rgba(255,193,7,.18); color: #b8860b; border-color: rgba(255,193,7,.5); }
.hpb-noproxy { background: rgba(255,128,0,.14); color: #e07b00; border-color: rgba(255,128,0,.45); }
.hpb-mproxy { background: rgba(77,143,224,.16); color: #4d8fe0; border-color: rgba(77,143,224,.5); }
.hpb-mdirect { background: rgba(154,154,154,.18); color: #8a8a8a; border-color: rgba(154,154,154,.5); }
.hpb-type { background: rgba(128,128,128,.13); border-color: rgba(128,128,128,.28); color: inherit; opacity: .85; }
.hpauto-why { color: #777; font-size: .88em; }
.hpchip { appearance: none; border: 1px solid rgba(128,128,128,.4); background: transparent; color: inherit; border-radius: 8px; padding: 2px 8px; margin-right: 4px; font-size: .8em; cursor: pointer; opacity: .7; }
.hpchip:hover { opacity: 1; background: rgba(128,128,128,.15); }
.hpchip.on { background: rgba(77,143,224,.22); border-color: #4d8fe0; color: #4d8fe0; font-weight: 700; opacity: 1; }
.hpchip.on.hpc-direct { background: rgba(154,154,154,.25); border-color: #8a8a8a; color: inherit; }
.hpdel { appearance: none; border: none; background: transparent; color: #e05252; font-weight: 700; cursor: pointer; font-size: 1.05em; padding: 2px 8px; border-radius: 6px; opacity: .55; }
.hpdel:hover { opacity: 1; background: rgba(224,82,82,.14); }
.hpgeo-cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }
.hpgeo-card { flex: 1 1 280px; border: 1px solid rgba(128,128,128,.3); border-radius: 8px; padding: 12px 14px; background: rgba(128,128,128,.07); }
.hpgeo-card h4 { margin: 0 0 8px 0; }
.hpgeo-meta { font-size: .88em; opacity: .85; margin: 4px 0; }
.hpgeo-age-fresh { color: #2e9e55; }
.hpgeo-age-stale { color: #e07b00; font-weight: 600; }
.hpauto-log { max-height: 420px; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 0; padding: 8px; background: #1e1e1e; color: #ddd; border: 1px solid #333; border-radius: 6px; font-size: 0.85em; }
.hpauto-hint { font-size: .88em; opacity: .8; margin: 8px 0; }
.hpauto-panel { border: 1px solid rgba(128,128,128,.3); border-radius: 8px; padding: 12px 14px; background: rgba(128,128,128,.07); margin: 10px 0; }
.hpauto-panel h4 { margin: 0 0 8px 0; }
.hpauto-eng-charts { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0; }
.hpauto-eng-chart { flex: 1 1 220px; min-width: 190px; max-width: 330px; }
.hpauto-eng-chart-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.hpauto-eng-chart-title { font-size: .85em; opacity: .8; }
.hpauto-eng-chart-num { font-weight: 700; }
.hpauto-eng-svg { width: 100%; height: 84px; display: block; margin-top: 2px; border-bottom: 1px solid rgba(128,128,128,.3); }
.hpauto-eng-chart-max { font-size: .74em; opacity: .6; text-align: right; margin: 0; }
.hpauto-eng-note { font-size: .8em; opacity: .7; margin: 4px 0 0 0; }
.hpauto-eng-kinds { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 8px 0 2px 0; }
.hpauto-eng-ev { display: flex; gap: 8px; font-size: .85em; margin: 2px 0; align-items: baseline; }
.hpauto-eng-ev .t { opacity: .6; white-space: nowrap; font-size: .92em; }
.hpauto-eng-ev .m { word-break: break-word; }
`;

function injectStyle() {
	const st = document.getElementById('hpauto-style');
	if (!st) {
		const el = E('style', { id: 'hpauto-style' }, [ CSS ]);
		document.head.appendChild(el);
	}
}

/* ── View ─────────────────────────────────────────────────────────────── */
return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function(data) {
		const m = new form.Map('homeproxy', _('Automation'));
		const s = m.section(form.NamedSection, 'automation', 'homeproxy', _('Auto blocked-site detection'));

		let o = s.option(form.Flag, 'enabled', _('Enable automation'),
			_('Automatically learn blocked sites: traffic that fails directly but works through the proxy is added to the Routing Rules lists. Fully compatible with ByeDPI and Zapret — learned sites simply use your configured main path.<br>'
			+ '<b>Mode notes:</b> active only in "Bypass blocking". Automatically paused in Global (everything tunnels anyway, nothing to learn), while the Main node is Direct (no proxy side to verify against), and in Custom routing / Custom JSON. After toggling, press "Restart service" on the Overview tab.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('balanced', _('Balanced'));
		o.value('aggressive', _('Aggressive (also re-verifies learned sites)'));
		o.default = 'balanced';

		o = s.option(form.ListValue, 'performance', _('Performance profile'),
			_('eco: serial probing for weak routers (still uses the native probe_pool batch when the helper is installed, capped at 8 concurrent probes). perf: up to 64 domains / 32 IPs per pass in parallel batches (16 at once) — for multi-core routers (e.g. GL.iNet Flint 2). auto: detected from CPU cores and memory.'));
		o.value('auto', _('Auto (detect by hardware)'));
		o.value('eco', _('Eco — serial, weak routers'));
		o.value('perf', _('Performance — parallel, strong routers'));
		o.default = 'auto';

		o = s.option(form.MultiValue, 'discover', _('Discover candidates from'),
			_('Domain-name sources to watch for candidates. Raw-IP destinations are a separate switch below (“Learn IP destinations”).'));
		o.value('dns', _('DNS query log (captures domain at DNS time — most transparent)'));
		o.value('clash', _('Clash API (connections, domain names)'));
		o.value('sni', _('TLS SNI capture (ClientHello — DoH clients, hardcoded-IP apps, games)'));
		o.default = [ 'dns', 'clash', 'sni' ];
		o.rmempty = false;
		/* Legacy configs store a single string ('all' | 'both' | 'clash' | ...) — map
		 * it to the equivalent checkbox set for display, so nothing looks unchecked. */
		o.cfgvalue = function() {
			let v = uci.get('homeproxy', 'automation', 'discover');
			if (v == null) return this.default;
			if (!Array.isArray(v)) v = [ v ];
			if (v.length === 0 || v.includes('all')) return [ 'dns', 'clash', 'sni' ];
			if (v.includes('both')) v = v.filter(function(x) { return x !== 'both'; }).concat([ 'dns', 'clash' ]);
			return v.filter(function(x) { return [ 'dns', 'clash', 'sni' ].includes(x); });
		};

		o = s.option(form.Value, 'max_entries', _('Maximum learned entries'));
		o.datatype = 'uinteger';
		o.placeholder = '2000';

		/* ч.69: engine-internal knobs are gone from the UI (probe timeout,
		 * confirmations, adaptive flags, discovery weights, helper toggles,
		 * CDN exclusion, HTTP/2 probing — all are autonomous now). Only the
		 * genuinely behavioral choices remain. */

		o = s.option(form.Value, 'reeval_interval', _('Re-evaluate learned interval (seconds)'));
		o.datatype = 'uinteger';
		o.placeholder = '3600';

		o = s.option(form.TextValue, 'exclude', _('Never auto-learn'),
			_('Domains / IPs excluded from learning (substring & domain match). One entry per line or comma-separated; lines starting with # are comments, blank lines allowed - organize the list as you like.') + ' '
			+ _('Defaults when empty: localhost, local, lan, in-addr.arpa, ip6.arpa.'));
		o.placeholder = 'localhost\nlocal\nlan\n# my own notes:\n# example.com\nin-addr.arpa,ip6.arpa';
		o.rows = 8;
		o.monospace = true;
		o.wrap = false;

		o = s.option(form.Flag, 'ip_learn', _('Learn IP destinations'),
			_('Watch recurring conntrack destinations (games, Telegram data centers, apps without SNI) and learn those that fail directly but answer through the proxy. Off by default — enable if you use such apps.'));
		o.default = o.disabled;

		o = s.option(form.Flag, 'geo_protect', _('RU-protect: Russian internet never via proxy'),
			_('Hard guard: traffic matching the RU-geo databases (networks + domains, see the “RU-geo databases” tab) and .ru/.su/.рф domains is always routed DIRECT, even if it matches a learned or static proxy list entry. RU services (banks, marketplaces, delivery) flag VPN exits — this keeps them off the tunnel.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'sni_sniffer_interface', _('SNI capture interface'),
			_('Network interface the SNI capture (native sniffer or tcpdump) listens on.'));
		o.datatype = 'string';
		o.placeholder = 'br-lan';

		o = s.option(form.Flag, 'geo_auto_update', _('Update RU-geo databases automatically'),
			_('The engine daemon checks the database age hourly and re-downloads it in the background when it is older than the interval below. Manual updates are always available on the “RU-geo databases” tab.'));
		o.default = o.disabled;

		o = s.option(form.Value, 'geo_update_hours', _('RU-geo update interval (hours)'));
		o.datatype = 'uinteger';
		o.placeholder = '24';
		o.depends('geo_auto_update', '1');

		/* NOTE: legacy UCI keys reload_interval / flush_min_entries are intentionally
		 * NOT exposed: learned entries hot-reload into the running core with no restart
		 * and no dropped connections, so batching windows serve no purpose. The daemon
		 * keeps honoring the defaults for old configs. */

		/* ── Custom tabbed UI ──────────────────────────────────────────── */

		injectStyle();

		const TABS = [
			[ 'overview', _('Overview') ],
			[ 'list', _('Sites') ],
			[ 'geo', _('RU-geo databases') ],
			[ 'settings', _('Settings') ],
			[ 'log', _('Engine log') ]
		];

		const panes = {};
		for (let t in TABS)
			panes[TABS[t][0]] = E('div', { 'class': 'hpauto-pane' });

		const tabBar = E('div', { 'class': 'hpauto-tabs' });
		for (let i in TABS) {
			const idx = parseInt(i, 10);
			const key = TABS[i][0];
			const b = E('button', {
				'class': 'hpauto-tab' + (idx === 0 ? ' active' : ''),
				type: 'button'
			}, [ TABS[i][1] ]);
			b.addEventListener('click', function() {
				for (let k in panes)
					panes[k].classList.toggle('active', k === key);
				for (let j = 0; j < tabBar.children.length; j++)
					tabBar.children[j].classList.toggle('active', j === idx);
			});
			tabBar.appendChild(b);
		}
		panes.overview.classList.add('active');

		const state = { data: null, search: '', filter: 'all', sortKey: 'added', sortDir: -1, sig: null,
			stats: null, statsRun: false, statsFresh: false, engSig: null, evSig: null, kdSig: null };

		const pauseReasons = {
			disabled: _('Automation is disabled — enable it in Settings to start learning.'),
			custom: _('Automation is paused: Custom routing is active — the engine has no preset pools to learn from. Switch to "Bypass blocking" to resume.'),
			global: _('Automation is paused: Global mode tunnels everything — there is nothing left to learn. Switch to "Bypass blocking" to resume.'),
			direct: _('Automation is paused: Main node is Direct (no proxy) — there is no proxy side to verify against. Choose URLTest or a node as Main node to resume.')
		};

		function fmtTime(ts) {
			if (!ts) return '—';
			try { return new Date(Number(ts) * 1000).toLocaleString(); }
			catch (e) { return String(ts); }
		}

		function fmtAge(ts) {
			if (!ts) return null;
			const d = Math.floor((Date.now() / 1000 - Number(ts)) / 86400);
			if (d <= 0) return _('updated today');
			if (d === 1) return _('updated yesterday');
			return _('updated %d days ago').format(d);
		}

		function validEntry(v) {
			v = String(v || '').trim().toLowerCase();
			if (!v.length || v.length > 253) return null;
			if (/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/\d{1,2})?$/.test(v)) {
				const parts = v.split('/')[0].split('.');
				for (let i = 0; i < 4; i++) if (parseInt(parts[i], 10) > 255) return null;
				return v;
			}
			if (v.indexOf(':') >= 0 && /^[0-9a-f:]+(\/\d{1,3})?$/.test(v)) return v;
			if (/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(v) && v.indexOf('.') > 0 && v.indexOf('..') < 0) return v;
			return null;
		}

		/* ── Overview pane ─────────────────────────────────────────────── */
		const ovCards = E('div', { 'class': 'hpauto-cards' });
		const pauseEl = E('div', { 'class': 'hpauto-banner', style: 'display:none' });
		const geoLine = E('div', { 'class': 'hpauto-hint' });
		const helperLine = E('div', { 'class': 'hpauto-hint' });
		panes.overview.appendChild(ovCards);
		panes.overview.appendChild(pauseEl);
		panes.overview.appendChild(geoLine);
		panes.overview.appendChild(helperLine);

		/* ── Engine overview panel (Ф5, ч.77) — the graphical engine view
		 * that replaced the removed exit-health card (decision D2). Cards +
		 * inline-SVG sparklines (no external libraries, D5), verdict
		 * distribution, discovery-source activity and a recent-events
		 * feed. Data: the small automation_stats file the daemon writes
		 * every cycle (read via the light automation_stats RPC). ──────── */
		const engHint = E('div', { 'class': 'hpauto-hint', style: 'margin:0 0 6px 0' });
		/* Ф8-F3: Master-rule protection transparency — the user must see that
		 * resources covered by their configured rules never enter learning. */
		const engProtect = E('div', { 'class': 'hpauto-eng-note', style: 'margin:0 0 6px 0' });
		const engCards = E('div', { 'class': 'hpauto-cards' });
		const ENG_CARD_DEFS = [
			[ 'cycles',  _('Cycles') ],
			[ 'probes',  _('Probes') ],
			[ 'ram',     _('Daemon RAM') ],
			[ 'entries', _('Entries') ]
		];
		const engCard = {};
		for (let c in ENG_CARD_DEFS) {
			const el = E('div', { 'class': 'hpauto-card' }, [
				E('div', { 'class': 'hpauto-cap' }, [ ENG_CARD_DEFS[c][1] ]),
				E('div', { 'class': 'hpauto-num' }, [ '—' ]),
				E('div', { 'class': 'hpauto-eng-note' }, [ '' ])
			]);
			engCard[ENG_CARD_DEFS[c][0]] = { num: el.children[1], note: el.children[2] };
			engCards.appendChild(el);
		}
		const ENG_CHART_DEFS = [
			[ 'learned', _('Learned growth'),   { fmt: function(v) { return String(Math.floor(v) || 0); } } ],
			[ 'probes',  _('Probes per cycle'), { fmt: function(v) { return String(Math.floor(v) || 0); } } ],
			[ 'dur',     _('Cycle duration'),   { fmt: fmtDur } ],
			[ 'ram',     _('Daemon RAM'),       { fmt: function(v) { return (v / 1024).toFixed(1) + ' MB'; } } ]
		];
		const engCharts = E('div', { 'class': 'hpauto-eng-charts' });
		for (let c in ENG_CHART_DEFS) {
			engCharts.appendChild(E('div', { 'class': 'hpauto-eng-chart' }, [
				E('div', { 'class': 'hpauto-eng-chart-head' }, [
					E('span', { 'class': 'hpauto-eng-chart-title' }, [ ENG_CHART_DEFS[c][1] ]),
					E('span', { 'class': 'hpauto-eng-chart-num' }, [ '—' ])
				]),
				/* Ф8-F5 (B2): third child = the "scale up to N" caption,
				 * filled by the onScale callback in renderStats. */
				hp.chartSvg([], ENG_CHART_DEFS[c][0],
					Object.assign({ className: 'hpauto-eng-svg' }, ENG_CHART_DEFS[c][2])),
				E('div', { 'class': 'hpauto-eng-chart-max' }, [ '' ])
			]));
		}
		const engCap = E('div', { 'class': 'hpauto-eng-note' }, [ '—' ]);
		const engKinds = E('div', { 'class': 'hpauto-eng-kinds' });
		const engSrc = E('div', { 'class': 'hpauto-eng-note' });
		const engEvents = E('div', { style: 'margin-top:4px' });
		const engPanel = E('div', { 'class': 'hpauto-panel' }, [
			E('h4', {}, [ _('Engine overview') ]),
			engHint,
			engProtect,
			engCards,
			engCharts,
			engCap,
			engKinds,
			engSrc,
			E('div', { 'class': 'hpauto-eng-note', style: 'font-weight:600; margin-top:10px' }, [ _('Recent events') ]),
			engEvents
		]);
		panes.overview.appendChild(engPanel);

		panes.overview.appendChild(E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Test now'), function() { return callTestNow().then(refresh); }),
			btn(_('Install helpers'), function() {
				return callHelpersInstall().then(function(r) {
					if (!r || r.error)
						return ui.addNotification(null, E('p', {}, _('Helpers install failed: ') + ((r && r.error) || '')), 'error');
					const line = (t) => {
						const d = r[t] || {};
						return t + ' — ' + (d.installed ? _('installed') : _('failed') + ': ' + (d.error || ''));
					};
					ui.addNotification(null, E('p', {}, _('Native helpers') + ': ' + line('probe_pool') + ' · ' + line('sni_sniffer')),
						(r.probe_pool && r.probe_pool.installed) || (r.sni_sniffer && r.sni_sniffer.installed) ? 'info' : 'error');
					return refresh();
				});
			}),
			btn(_('Restart service'), function() { return callRestart(); })
		]));

		/* ── List pane ─────────────────────────────────────────────────── */
		const searchEl = E('input', { type: 'text', placeholder: _('Search by name or IP…'), 'class': 'cbi-input-text' });
		searchEl.addEventListener('input', function() {
			state.search = this.value.toLowerCase();
			renderTable();
		});

		const filterEl = E('select', { 'class': 'cbi-input-select' });
		const filters = [
			[ 'all', _('All entries') ],
			[ 'learned', _('Learned (engine)') ],
			[ 'manual', _('Manual pins') ],
			[ 'blocked', _('Blocked only') ],
			[ 'direct', _('Direct only') ]
		];
		for (let f in filters)
			filterEl.appendChild(E('option', { value: filters[f][0] }, [ filters[f][1] ]));
		filterEl.addEventListener('change', function() {
			state.filter = this.value;
			renderTable();
		});

		const addInput = E('input', { type: 'text', placeholder: _('example.com or 1.2.3.4'), 'class': 'cbi-input-text', style: 'flex:0 1 240px; min-width:170px' });
		const addAction = E('select', { 'class': 'cbi-input-select' });
		addAction.appendChild(E('option', { value: 'proxy' }, [ _('Always via proxy') ]));
		addAction.appendChild(E('option', { value: 'direct' }, [ _('Always direct') ]));
		const addBtn = btn(_('+ Add'), function() {
			const v = validEntry(addInput.value);
			if (!v) {
				ui.addNotification('error', _('Invalid entry: use a domain name or an IP address.'));
				return Promise.resolve();
			}
			return callEntryAdd(v, addAction.value).then(function(r) {
				if (r && r.result === false)
					ui.addNotification('error', _('Add failed: ') + (r.error || ''));
				else
					ui.addNotification('info', _('Entry added: %s.').format(v));
				addInput.value = '';
				return refresh();
			});
		});

		const fileInput = E('input', { type: 'file', accept: '.txt,text/plain', style: 'display:none' });
		fileInput.addEventListener('change', function() {
			const file = fileInput.files[0];
			if (!file) return;
			const reader = new FileReader();
			reader.onload = function() {
				callRestore(String(reader.result)).then(function(r) {
					if (!r || r.result === false)
						ui.addNotification('error', _('Restore failed: ') + ((r && r.error) || ''));
					else
						ui.addNotification('info', _('Restore complete — added %d site(s).').format(r.added || 0));
					return refresh();
				}).catch(function(e) {
					ui.addNotification('error', _('Restore failed: ') + e);
				});
			};
			reader.readAsText(file);
			fileInput.value = '';
		});

		const tableEl = E('div', {});
		const tableMeta = E('div', { 'class': 'hpauto-hint' });
		panes.list.appendChild(E('div', { 'class': 'hpauto-toolbar' }, [
			searchEl, filterEl,
			E('span', { style: 'flex:1' }),
			addInput, addAction, addBtn
		]));
		panes.list.appendChild(tableEl);
		panes.list.appendChild(tableMeta);
		panes.list.appendChild(E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Backup list'), function() {
				return callBackup().then(function(r) {
					if (!r || r.result === false) {
						ui.addNotification('error', _('Backup failed: ') + ((r && r.error) || _('no learned list yet')));
						return;
					}
					downloadList(r.content || '');
				});
			}),
			btn(_('Restore list'), function() { fileInput.click(); }),
			btn(_('Clear learned'), function() {
				if (!window.confirm(_('Delete ALL learned sites? The engine will re-learn them from scratch.')))
					return Promise.resolve();
				return callClear().then(refresh);
			})
		]));
		panes.list.appendChild(fileInput);
		panes.list.appendChild(E('p', { 'class': 'hpauto-hint' },
			[ _('Manual status: “Always via proxy” keeps the site on the proxy and protects it from automatic un-learning; “Always direct” removes it from the learned lists and forces the direct path; “Auto” returns the entry to the engine. A deleted entry may be re-learned later if it is genuinely blocked — pin it “Always direct” to prevent that.') ]));

		/* ── Geo pane ──────────────────────────────────────────────────── */
		const geoCards = E('div', { 'class': 'hpgeo-cards' });
		panes.geo.appendChild(geoCards);
		panes.geo.appendChild(E('div', { 'class': 'automation-actions' }, [
			btn(_('Update now'), function() {
				return callGeoUpdate().then(function(r) {
					if (r && r.result === false)
						ui.addNotification('error', _('Update failed to start: ') + (r.error || ''));
					else
						ui.addNotification('info', _('RU-geo update started in the background — this page will show the new date in a minute.'));
					return refresh();
				});
			})
		]));
		panes.geo.appendChild(E('p', { 'class': 'hpauto-hint' },
			[ _('The databases list all Russian networks and the domains of major RU services (whitelist of the Ministry of Digital Development + banks, marketplaces, Yandex/VK/Mail.ru stacks). They exclude the whole Russian internet from learning and proxying (RU-protect) and purge poisoned entries. Sources: GrimbirdUsers/ru-routing-dat via GitHub / jsDelivr mirrors, ipdeny.com fallback.') ]));

		/* ── Log pane ──────────────────────────────────────────────────── */
		const logEl = E('pre', { 'class': 'hpauto-log' });
		panes.log.appendChild(logEl);
		panes.log.appendChild(E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Clear log'), function() { return callClearLog().then(refresh); })
		]));

		/* ── Table rendering ───────────────────────────────────────────── */

		function statusBadge(e) {
			if (e.src === 'manual_proxy')
				return E('span', { 'class': 'hpbadge hpb-mproxy' }, [ _('Always proxy') ]);
			if (e.src === 'manual_direct')
				return E('span', { 'class': 'hpbadge hpb-mdirect' }, [ _('Always direct') ]);
			if (e.status === 'geo')
				return E('span', { 'class': 'hpbadge hpb-mproxy' }, [ _('Geo (proxied)') ]);
			if (e.status === 'geo_blocked')
				return E('span', { 'class': 'hpbadge hpb-noproxy' }, [ _('Geo-blocked (node)') ]);
			if (e.status === 'blocked')
				return E('span', { 'class': 'hpbadge hpb-blocked' },
					[ e.kind === 'dns_poison' ? _('Blocked (DNS)') :
					  e.kind === 'stub' ? _('Blocked (stub)') :
					  e.kind === 'tls_dpi' ? _('Blocked (DPI)') :
					  e.kind ? _('Blocked (refusal)') : _('Blocked') ]);
			if (e.status === 'direct')
				return E('span', { 'class': 'hpbadge hpb-direct' }, [ _('Direct') ]);
			if (e.status === 'direct_pending')
				return E('span', { 'class': 'hpbadge hpb-pending' }, [ _('Direct (pending)') ]);
			if (e.status === 'blocked_no_proxy')
				return E('span', { 'class': 'hpbadge hpb-noproxy' }, [ _('Unreachable') ]);
			return E('span', { 'class': 'hpbadge hpb-type' }, [ e.status || '—' ]);
		}

		function reasonText(e) {
			if (e.status === 'geo')
				return _('geo-sensitive service — always routed via proxy');
			if (e.status === 'geo_blocked')
				return _('the service refuses the current exit node — switch node and re-test');
			if (e.src !== 'learned')
				return _('pinned by user');
			if (e.status === 'blocked') {
				/* ч.68: censorship-mechanism verdict from the probe signals. */
				const KINDS = {
					dns_poison: _('DNS poisoning: the ISP resolver served a fake address (confirmed via secure DNS)'),
					stub:       _('ISP block page: the connection is redirected to the provider stub'),
					sigpage:    _('block page served with HTTP 200 (body signature match)'),
					tls_dpi:    _('TLS DPI: the handshake is reset right after ClientHello (SNI filtering)'),
					hardcode:   _('censorship refusal code (403/406/451) — direct is refused, proxy works')
				};
				let kind = KINDS[e.kind] || null;
				if (!e.direct && !e.proxy)
					return kind || _('blocked (details not recorded)');
				let d = e.direct || '✗', p = e.proxy || '✓';
				return (kind ? (kind + ' · ') : '') + _('direct %s ✗ / proxy %s ✓').format(d, p);
			}
			if (e.status === 'blocked_no_proxy') return _('blocked both ways');
			if (e.status === 'unknown') return _('uncertain');
			return e.status || '—';
		}

		function chips(entry) {
			const mk = (mode, label, active, cls) => {
				const TIPS = {
					auto:   _('Auto mode: entry status is determined automatically'),
					proxy:  _('Always via proxy'),
					direct: _('Always direct')
				};
				const b = E('button', {
					'class': 'hpchip' + (active ? (' on' + (cls ? ' ' + cls : '')) : ''),
					type: 'button', title: TIPS[mode] || entry.host
				}, [ label ]);
				b.addEventListener('click', function() {
					if (this.classList.contains('on')) return;
					this.disabled = true;
					callEntryAction(entry.host, mode).then(function() { return refresh(); })
						.finally(function() { b.disabled = false; });
				});
				return b;
			};
			const wrap = E('span', { style: 'white-space:nowrap' });
			wrap.appendChild(mk('auto', _('Auto'), entry.src === 'learned'));
			wrap.appendChild(mk('proxy', '⇄', entry.src === 'manual_proxy'));
			wrap.appendChild(mk('direct', '⛔', entry.src === 'manual_direct', 'hpc-direct'));
			return wrap;
		}

		function renderTable() {
			const entries = (state.data && state.data.entries) || [];
			let rows = entries;
			if (state.filter === 'learned') rows = rows.filter(function(e) { return e.src === 'learned'; });
			else if (state.filter === 'manual') rows = rows.filter(function(e) { return e.src !== 'learned'; });
			else if (state.filter === 'blocked') rows = rows.filter(function(e) { return e.src === 'learned' && e.status === 'blocked'; });
			else if (state.filter === 'direct') rows = rows.filter(function(e) { return e.src === 'learned' && (e.status === 'direct' || e.status === 'direct_pending'); });
			if (state.search.length)
				rows = rows.filter(function(e) { return e.host.toLowerCase().indexOf(state.search) >= 0; });

			const dir = state.sortDir;
			const key = state.sortKey;
			rows = rows.slice().sort(function(a, b) {
				const va = (key === 'host') ? String(a.host) : (Number(a[key]) || 0);
				const vb = (key === 'host') ? String(b.host) : (Number(b[key]) || 0);
				if (va < vb) return -1 * dir;
				if (va > vb) return 1 * dir;
				return 0;
			});

			const MAX = 1000;
			const shown = Math.min(rows.length, MAX);
			tableMeta.textContent = _('Showing %d of %d entries.').format(shown, rows.length) +
				(state.search.length ? (' ' + _('Search: “%s”.').format(state.search)) : '');

			const thead = E('thead', {});
			const htr = E('tr', {});
			const headers = [
				[ _('Resource'), 'host' ],
				[ _('Type'), null ],
				[ _('Status'), null ],
				[ _('Added'), 'added' ],
				[ _('Last check'), 'last_probe' ],
				[ _('Why'), null ],
				[ _('Mode'), null ],
				[ '', null ]
			];
			for (let h in headers) {
				const hd = headers[h];
				const th = E('th', { 'class': hd[1] ? 'hpsort' : '' }, [ hd[0] ]);
				if (hd[1]) {
					th.addEventListener('click', function() {
						if (state.sortKey === hd[1]) state.sortDir = -state.sortDir;
						else { state.sortKey = hd[1]; state.sortDir = -1; }
						renderTable();
					});
				}
				htr.appendChild(th);
			}
			thead.appendChild(htr);

			const tbody = E('tbody', {});
			for (let i = 0; i < shown; i++) {
				const e = rows[i];
				const rowCls = (e.src !== 'learned') ? ('hpsrc-manual' + (e.src === 'manual_direct' ? ' hpsrc-manual-direct' : '')) : '';
				const tr = E('tr', { 'class': rowCls });
				const delBtn = E('button', { 'class': 'hpdel', type: 'button', title: _('Delete entry') }, [ '✕' ]);
				delBtn.addEventListener('click', function() {
					if (!window.confirm(_('Delete entry %s?').format(e.host)))
						return;
					delBtn.disabled = true;
					callEntryDelete(e.host).then(function() { return refresh(); })
						.finally(function() { delBtn.disabled = false; });
				});
				const cells = [
					E('span', { style: 'font-weight:600' }, [ String(e.host || '') ]),
					E('span', { 'class': 'hpbadge hpb-type' }, [ e.type === 'ip' ? _('IP') : _('Domain') ]),
					statusBadge(e),
					E('span', { style: 'white-space:nowrap; opacity:.8' }, [ fmtTime(e.added) ]),
					E('span', { style: 'white-space:nowrap; opacity:.8' }, [ fmtTime(e.last_probe) ]),
					E('span', { 'class': 'hpauto-why' }, [ String(reasonText(e)) ]),
					chips(e),
					delBtn
				];
				for (let c in cells)
					tr.appendChild(E('td', {}, [ cells[c] ]));
				tbody.appendChild(tr);
			}
			if (!rows.length) {
				tbody.appendChild(E('tr', {}, [
					E('td', { colspan: '8', style: 'padding:14px; text-align:center; opacity:.7' },
						[ entries.length ? _('Nothing matches the search / filter.') : _('Nothing learned yet. Browse the web or press “Test now”.') ])
				]));
			}

			const table = E('table', { 'class': 'hpauto-table' }, [ thead, tbody ]);
			/* Preserve the scroll position across poll rebuilds. */
			const prevWrap = tableEl.firstElementChild;
			const scrollTop = (prevWrap && prevWrap.classList && prevWrap.classList.contains('hpauto-wrap')) ? prevWrap.scrollTop : 0;
			tableEl.innerHTML = '';
			const wrap = E('div', { 'class': 'hpauto-wrap' });
			wrap.appendChild(table);
			tableEl.appendChild(wrap);
			wrap.scrollTop = scrollTop;
		}

		/* ── Geo cards ─────────────────────────────────────────────────── */

		function renderGeo(geo) {
			geoCards.innerHTML = '';
			const stale = (!geo.updated || (Date.now() / 1000 - Number(geo.updated)) > 30 * 86400);
			const ageEl = geo.updated
				? E('span', { 'class': stale ? 'hpgeo-age-stale' : 'hpgeo-age-fresh' }, [ fmtAge(geo.updated) || '—' ])
				: E('span', { 'class': 'hpgeo-age-stale' }, [ _('never updated') ]);

			const mkCard = (title, lines) => {
				const c = E('div', { 'class': 'hpgeo-card' }, [ E('h4', {}, [ title ]) ]);
				for (let it in lines)
					c.appendChild(E('div', { 'class': 'hpgeo-meta' }, [ lines[it] ]));
				return c;
			};
			const entryLine = (n) => (geo.installed
				? E('span', {}, [ _('Entries') + ': ' + (n || 0) ])
				: E('span', { 'class': 'hpgeo-age-stale' }, [ _('not downloaded') ]));

			geoCards.appendChild(mkCard(_('RU networks (geoip)'), [
				entryLine(geo.geoip),
				E('span', {}, [ geo.installed ? ('IPv4: ' + (geo.geoip_v4 || 0) + ' · IPv6: ' + (geo.geoip_v6 || 0)) : '' ]),
				ageEl
			]));
			geoCards.appendChild(mkCard(_('RU domains (geosite)'), [
				entryLine(geo.geosite),
				E('span', {}, [ geo.installed ? (_('categories') + ': ' + (geo.categories || 0)) : '' ]),
				ageEl.cloneNode ? ageEl.cloneNode(true) : ageEl
			]));
			geoCards.appendChild(mkCard(_('RU-protect'), [
				E('span', { 'class': 'hpbadge ' + (geo.protect === '0' ? 'hpb-mdirect' : 'hpb-direct') },
					[ geo.protect === '0' ? _('disabled (switch in Settings)') : _('enabled') ]),
				E('span', {}, [ geo.updating ? ' · ' + _('updating…') : '' ])
			]));
		}

		/* ── Engine overview panel rendering (Ф5) ──────────────────────── */

		const KIND_BADGES = [
			[ 'tls_dpi',    _('Blocked (DPI)') ],
			[ 'dns_poison', _('Blocked (DNS)') ],
			[ 'stub',       _('Blocked (stub)') ],
			[ 'sigpage',    _('Block page') ],
			[ 'hardcode',   _('Blocked (refusal)') ]
		];
		const STATUS_BADGES = [
			[ 'blocked',          _('Blocked') ],
			[ 'direct',           _('Direct') ],
			[ 'direct_pending',   _('Direct (pending)') ],
			[ 'blocked_no_proxy', _('Unreachable') ],
			[ 'geo_blocked',      _('Geo-blocked (node)') ],
			[ 'geo',              _('Geo (proxied)') ]
		];
		const EV_LABELS = {
			learn:  _('Learned'),
			heal:   _('Self-healed'),
			reload: _('Applied to core'),
			poison: _('DNS poison detected'),
			pause:  _('Learning paused'),
			resume: _('Learning resumed'),
			clear:  _('Learned list cleared'),
			warn:   _('Warning')
		};

		function fmtClock(ts) {
			try { return new Date(Number(ts) * 1000).toLocaleTimeString(); }
			catch (e) { return ''; }
		}

		/* Cycle durations range from ~0 ms (paused pass) to minutes — a raw
		 * millisecond number is unreadable ("216540 ms"). */
		function fmtDur(ms) {
			ms = Number(ms) || 0;
			if (ms >= 60000) return (ms / 60000).toFixed(1) + ' min';
			if (ms >= 10000) return (ms / 1000).toFixed(1) + ' s';
			return Math.round(ms) + ' ms';
		}

		function renderStats() {
			const st = state.stats || {};
			const hist = (st.hist && st.hist.length) ? st.hist : [];

			/* Honest state line: daemon dead vs. counters still warming up. */
			if (!state.statsRun)
				engHint.textContent = '⚠ ' + _('Engine daemon is not running.');
			else if (!state.statsFresh)
				engHint.textContent = '… ' + _('collecting…');
			else
				engHint.textContent = '';

			/* Ф8-F3: Master-rule protection scope — '—' when the daemon has no
			 * data yet (old stats file), honest zero-line when nothing covers. */
			const pt = st.protected;
			if (pt && pt.sources != null) {
				engProtect.textContent = pt.sources
					? _('Protected by Master rules: %d source(s), %d host(s)').format(pt.sources, pt.hosts) +
						(pt.direct ? ' · ' + _('%d routed Direct').format(pt.direct) : '')
					: _('No Master rules protect resources from learning.');
			} else
				engProtect.textContent = '';

			/* Cards (text-only every tick — anti-flicker). */
			const c = st.cycle || {};
			const pr = st.probes || {};
			const lr = st.learned || {};
			engCard.cycles.num.textContent = (c.count != null) ? String(c.count) : '—';
			engCard.cycles.note.textContent =
				(st.interval ? _('every %ss').format(st.interval) + ' · ' : '') +
				(c.last_ms != null ? _('last: %s').format(fmtDur(c.last_ms)) : '');
			engCard.probes.num.textContent = (pr.last_total != null) ? String(pr.last_total) : '—';
			engCard.probes.note.textContent = (pr.per_sec != null && pr.last_total)
				? _('~%s probes/s').format(Math.round(pr.per_sec * 10) / 10) : '';
			engCard.ram.num.textContent = st.ram_kb ? (st.ram_kb / 1024).toFixed(1) + ' MB' : '—';
			engCard.ram.note.textContent = st.profile ? _('Profile: %s').format(st.profile) : '';
			engCard.entries.num.textContent = (lr.domains != null)
				? String((lr.domains || 0) + (lr.ips || 0)) : '—';
			engCard.entries.note.textContent = (lr.domains != null)
				? _('domains %s · IPs %s').format(lr.domains || 0, lr.ips || 0) : '';

			/* Sparklines: current value text-only, SVG rebuilt on ring change. */
			for (let i = 0; i < ENG_CHART_DEFS.length; i++) {
				const key = ENG_CHART_DEFS[i][0];
				const block = engCharts.children[i];
				const cur = (hist.length && hist[hist.length - 1][key] != null)
					? hist[hist.length - 1][key] : null;
				block.children[0].children[1].textContent =
					(cur != null) ? ENG_CHART_DEFS[i][2].fmt(cur) : '—';
			}
			const sig = hist.length ? ('' + hist[hist.length - 1].t + ':' + hist.length) : 'none';
			if (sig !== state.engSig) {
				state.engSig = sig;
				for (let i = 0; i < ENG_CHART_DEFS.length; i++) {
					const block = engCharts.children[i];
					const def = ENG_CHART_DEFS[i];
					const maxEl = block.children[2];
					/* Ф8-F5 (B2): honest "scale up to N" caption on the
					 * auto-scaled engine sparklines (the ×1.35 headroom of
					 * the shared helper replaced the ×1.15 overshoot). */
					const opts = Object.assign({ className: 'hpauto-eng-svg' }, def[2], {
						onScale: function(mx) {
							maxEl.textContent = (def[2].max == null)
								? _('scale up to %s').format(def[2].fmt(Math.round(mx)))
								: '';
						}
					});
					block.replaceChild(hp.chartSvg(hist, def[0], opts),
						block.children[1]);
				}
				engCap.textContent = (hist.length)
					? _('%d points · ~%d min').format(hist.length, Math.ceil(hist.length / 2))
					: _('collecting…');
			}

			/* Verdict distribution: statuses + block-kind counts. */
			const v = st.verdicts || {};
			const kinds = v.kinds || {};
			const parts = [];
			for (let s in STATUS_BADGES) {
				const n = v[STATUS_BADGES[s][0]] || 0;
				if (n > 0) parts.push(STATUS_BADGES[s][0] + ':' + n);
			}
			for (let k in KIND_BADGES) {
				const n = kinds[KIND_BADGES[k][0]] || 0;
				if (n > 0) parts.push(KIND_BADGES[k][0] + ':' + n);
			}
			const kdSig = parts.join('|');
			if (kdSig !== state.kdSig) {
				state.kdSig = kdSig;
				engKinds.innerHTML = '';
				engKinds.appendChild(E('span', { 'class': 'hpauto-cap' }, [ _('Verdicts') + ':' ]));
				for (let s in STATUS_BADGES) {
					const n = v[STATUS_BADGES[s][0]] || 0;
					if (n > 0)
						engKinds.appendChild(E('span', { 'class': 'hpbadge ' + (
							STATUS_BADGES[s][0] === 'blocked' ? 'hpb-blocked' :
							STATUS_BADGES[s][0] === 'direct' ? 'hpb-direct' :
							STATUS_BADGES[s][0] === 'direct_pending' ? 'hpb-pending' :
							STATUS_BADGES[s][0] === 'geo' ? 'hpb-mproxy' : 'hpb-noproxy') },
							[ STATUS_BADGES[s][1] + ' ' + n ]));
				}
				for (let k in KIND_BADGES) {
					const n = kinds[KIND_BADGES[k][0]] || 0;
					if (n > 0)
						engKinds.appendChild(E('span', { 'class': 'hpbadge hpb-type' },
							[ KIND_BADGES[k][1] + ' ' + n ]));
				}
				if (!parts.length)
					engKinds.appendChild(E('span', { 'class': 'hpauto-cap' }, [ _('no data yet') ]));
			}

			/* Discovery-source activity of the last pass. */
			const src = st.sources || {};
			engSrc.textContent = (st.sources)
				? _('Sources (last cycle)') + ': DNS ' + (src.dns || 0) + ' · Clash ' + (src.clash || 0) +
				  ' · SNI ' + (src.sni || 0)
				: '';

			/* Recent events feed (newest first, ≤12 shown). */
			const evs = (st.events && st.events.length) ? st.events : [];
			const evSig = evs.length ? ('' + evs.length + ':' + evs[evs.length - 1].t) : 'none';
			if (evSig !== state.evSig) {
				state.evSig = evSig;
				engEvents.innerHTML = '';
				const show = evs.slice(-12).reverse();
				for (let i = 0; i < show.length; i++) {
					const ev = show[i];
					engEvents.appendChild(E('div', { 'class': 'hpauto-eng-ev' }, [
						E('span', { 'class': 't' }, [ fmtClock(ev.t) ]),
						E('span', { 'class': 'm' }, [
							E('b', {}, [ (EV_LABELS[ev.k] || ev.k || '?') + ':' ]),
							document.createTextNode(' ' + (ev.m || ''))
						])
					]));
				}
				if (!evs.length)
					engEvents.appendChild(E('span', { 'class': 'hpauto-cap' }, [ _('no events yet') ]));
			}
		}

		function refreshStats() {
			return L.resolveDefault(callStats(), {}).then(function(r) {
				state.stats = (r && r.stats) || {};
				state.statsRun = !!(r && r.running);
				state.statsFresh = !!(r && r.fresh);
				renderStats();
			});
		}

		/* ── Poll ──────────────────────────────────────────────────────── */

		function refresh() {
			/* Engine counters ride the same 5 s poll (light RPC, ≤5 s — D5). */
			refreshStats();
			return callStatus().then(function(st) {
				state.data = st;
				const c = st.counts || {};
				ovCards.innerHTML = '';
				const mk = (num, cap, cls) => E('div', { 'class': 'hpauto-card' }, [
					E('div', { 'class': 'hpauto-num ' + (cls || '') }, [ String(num) ]),
					E('div', { 'class': 'hpauto-cap' }, [ cap ])
				]);
				ovCards.appendChild(mk(st.enabled === '1' ? _('yes') : _('no'), _('Enabled'), st.enabled === '1' ? 'c-green' : 'c-grey'));
				ovCards.appendChild(mk(c.learned || 0, _('Learned (blocked)'), 'c-red'));
				ovCards.appendChild(mk(c.manual || 0, _('Manual pins'), 'c-blue'));
				ovCards.appendChild(mk(c.direct || 0, _('Direct verdicts'), 'c-amber'));
				const reason = pauseReasons[st.paused];
				if (reason) {
					pauseEl.textContent = '⏸ ' + reason;
					pauseEl.style.display = 'block';
					pauseEl.classList.remove('hpauto-banner-ok');
				} else {
					pauseEl.textContent = '✔ ' + _('Automation is active — learning blocked sites.');
					pauseEl.style.display = 'block';
					pauseEl.classList.add('hpauto-banner-ok');
				}
				const g = st.geo || {};
				geoLine.innerHTML = _('RU-geo databases:') + ' ' + (g.installed
					? _('networks %s, domains %s, %s').format(g.geoip || 0, g.geosite || 0, fmtAge(g.updated) || '—')
					: _('not installed — update on the “RU-geo databases” tab'))
					+ (g.updating ? ' · <b>' + _('updating…') + '</b>' : '');
				/* Native helpers + engine profile (like the mosdns card on Core
				 * & Tools, but inline where the engine is configured). probe_pool
				 * is a one-shot batch prober — only presence applies; sni_sniffer
				 * is a resident daemon — running state applies. DOM building:
				 * colored E() spans must not be stringified into innerHTML. */
				const h = st.helpers || {};
				const prof = (st.profile === 'perf');
				const hspan = (ok, txt) => E('span', { style: 'color:' + (ok ? '#3fbf5f' : (ok === false ? '#9a9a9a' : '#d99a1b')) }, [ txt ]);
				helperLine.innerHTML = '';
				helperLine.appendChild(document.createTextNode(_('Engine profile') + ': '));
				helperLine.appendChild(E('b', {}, [ prof ? _('performance (parallel)') : _('eco (serial)') ]));
				helperLine.appendChild(document.createTextNode(' · ' + _('Native helpers') + ': probe_pool — '));
				helperLine.appendChild(hspan(!!h.probe_pool, h.probe_pool ? _('installed') : _('not installed')));
				helperLine.appendChild(document.createTextNode(' · sni_sniffer — '));
				helperLine.appendChild(h.sni_running ? hspan(true, _('running'))
					: (h.sni_sniffer ? hspan(null, _('stopped')) : hspan(false, _('not installed'))));
				helperLine.appendChild(document.createTextNode('.'));
				renderTable();
				renderGeo(g);
				logEl.textContent = st.log || '';
			}).catch(function(e) {
				ovCards.textContent = _('Status unavailable: ') + e;
			});
		}

		poll.add(refresh, 5);
		refresh();

		return Promise.all([ m.render(), Promise.resolve(panes) ]).then(function(nodes) {
			const mapNode = nodes[0];
			const ps = nodes[1];
			/* The UCI form lives on its own tab. */
			ps.settings.appendChild(mapNode);
			return E('div', {}, [ tabBar, ps.overview, ps.list, ps.geo, ps.settings, ps.log ]);
		});
	}
});
