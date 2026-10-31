/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Blocking bypass page (R3 v3c, 19-UX_REDESIGN стр. 4).
 *
 * ONE page for the whole «how do the blocked sites open» concern. The four
 * zones moved here 1:1 from the Routing Wizard DPI section (the wizard is
 * abolished — its presets went to Service rules in v3b, provider
 * diagnostics to Check & repair, the tg-ws bridge to Phone control; the
 * wizard_* ubus method names are KEPT — lesson 149):
 *   «Working right now» — engine cards (wizard_dpi_status), the Serving map
 *   (rule → engine → strategy → last check, ч.109) and the measured quality
 *   panel (ч.123). No actions here — the honest state only.
 *   «Auto-pilot» — the one-click per-resource pick (wizard_auto_pick_start)
 *   and the scheduled auto-pilot (wizard_autopilot_set/status, ч.97).
 *   «Strategy Lab» — the fuzzer (zapret_fuzz_*), deep battery, the ranking
 *   table, the external catalog importer (wizard_strategy_update/status/
 *   apply via wizard_strategies.uc) and the mutation generator
 *   (wizard_fuzz_generate).
 *   «Manual & compositions» — the global Zapret strategy, the ByeDPI card
 *   with its presets and flags (wizard_byedpi_set), the per-resource
 *   Composition of both engines (wizard_compose_*) and the
 *   «apply strategy → service rule → live check» chain (wizard_preset_apply).
 *
 * The result area is ONE shared node that follows the active zone — results
 * stay in one place, replacing the previous (ui.action_buttons_result_
 * placement). Checks are on-demand (D6 pattern): nothing monitors
 * permanently here except the poll-driven state panels.
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

const callPresetList = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_preset_list',
	expect: { '': {} }
});

const callPresetApply = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_preset_apply',
	params: [ 'source', 'node', 'urltest_nodes' ],
	expect: { '': {} }
});

const callRouteExplain = rpc.declare({
	object: 'luci.homeproxy',
	method: 'route_explain',
	params: [ 'host' ],
	expect: { '': {} }
});

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

/* ── DPI section (Ф3): engines, Strategy Lab, corpus tools ─────────────── */

const callDpiStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_dpi_status',
	expect: { '': {} }
});

const callStrategyList = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_strategy_list',
	expect: { '': {} }
});

const callStrategyUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_strategy_update',
	expect: { '': {} }
});

const callStrategyStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_strategy_status',
	expect: { '': {} }
});

const callStrategyApply = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_strategy_apply',
	expect: { '': {} }
});

const callFuzzGenerate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_fuzz_generate',
	expect: { '': {} }
});

/* ч.123: local strategies import (share the corpus between routers). The
 * payload crosses as a JSON-encoded STRING (issue #11 string-policy). */
const callCorpusImport = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_corpus_import',
	params: [ 'candidates' ],
	expect: { '': {} }
});

/* The Strategy Lab backend RPCs are UNCHANGED (ч.69/70) — the panel moved
 * here from node.js, the server side did not. */
const callZapretTest = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_strategy_test',
	params: [ 'cmd_opts', 'ips' ],
	expect: { '': {} }
});

const callZapretResolve = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_resolve_hosts',
	expect: { '': {} }
});

const callFuzzStart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_fuzz_start',
	params: [ 'mode', 'rounds' ],
	expect: { '': {} }
});

const callFuzzStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_fuzz_status',
	expect: { '': {} }
});

const callFuzzApply = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_fuzz_apply',
	params: [ 'strategy' ],
	expect: { '': {} }
});

/* сеанс 24 (user wish): the node.js ByeDPI/Zapret tabs moved into the
 * Wizard DPI pane — Save writes the whole ByeDPI card (strategy args +
 * the option flags that used to live on those tabs); Test / Test-all
 * reuse the existing byedpi_strategy_test tester. */
const callByedpiSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_byedpi_set',
	params: [ 'cmd_opts', 'udp_over_tcp', 'block_quic', 'zapret_voice' ],
	expect: { '': {} }
});

const callByedpiTest = rpc.declare({
	object: 'luci.homeproxy',
	method: 'byedpi_strategy_test',
	params: [ 'cmd_opts', 'port' ],
	expect: { '': {} }
});

/* Ф8-F7 T3: one-click strategy auto-pick — fuzz → pick per resource →
 * rule (optional) → apply (server snapshot) → live verify. ч.109: an
 * explicit `strategy` skips the fuzz+pick stages (the «apply from the
 * ranking table» flow reuses the same rule/apply/verify machinery). */
const callAutoPickStart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_auto_pick_start',
	params: [ 'resource', 'mode', 'set_rule', 'strategy' ],
	expect: { '': {} }
});

/* ч.109: composition DRAFT persistence — the server keeps the per-resource
 * profile list, so the builder survives page reloads. */
const callComposeSave = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_compose_save',
	params: [ 'profiles' ],
	expect: { '': {} }
});

/* ч.109: router-originated live probe of a DPI resource through the
 * configured path — the Serving map «Check» button (YouTube is probed
 * on the page, the thumbnail CDN and the video-stream edge). */
const callDpiProbe = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_dpi_probe',
	params: [ 'resource' ],
	expect: { '': {} }
});

const callAutoPickStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_auto_pick_status',
	expect: { '': {} }
});

/* ч.97: the scheduled strategy auto-pilot — config (hot-read by the daemon
 * every tick) + the live status/journal from its state file. */
const callAutoPilotStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_autopilot_status',
	expect: { '': {} }
});

const callAutoPilotSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_autopilot_set',
	params: [ 'enabled', 'resources', 'set_rules', 'interval_h', 'check_min', 'window', 'fuzz_mode', 'fail_strikes' ],
	expect: { '': {} }
});

/* Ф8-F4: Composition Builder v2 — server-side build/test/apply. Apply
 * snapshots the previous strategies on the SERVER, so the rollback button
 * reads the snapshot back on every page load (no JS-memory rollback). */
const callComposeRun = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_compose_run',
	params: [ 'profiles' ],
	expect: { '': {} }
});

const callComposeStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_compose_status',
	expect: { '': {} }
});

const callComposeApply = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_compose_apply',
	params: [ 'zapret', 'byedpi' ],
	expect: { '': {} }
});

const callComposeRollback = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_compose_rollback',
	expect: { '': {} }
});

/* ── R3 v3b: the manual domain lists moved to Service rules, the TG WS
 * Proxy bridges to Phone control — their RPC declarations moved with
 * them. ──────────────────────────────────────────────────────────────── */
/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label
 * (same logic as diagnostics.js). */
function resolveTag(tag) {
	const m = tag && String(tag).match(/^cfg-(.+)-out$/);
	if (m) {
		const label = uci.get('homeproxy', m[1], 'label');
		if (label) return label;
	}
	const specials = { 'main-out': 'main_node', 'main-udp-out': 'main_udp_node' };
	if (specials[tag]) {
		const v = uci.get('homeproxy', 'config', specials[tag]);
		if (v === 'byedpi-out') return 'ByeDPI';
		if (v === 'zapret-out') return 'Zapret';
		if (v && ![ 'urltest', 'same', 'nil', '' ].includes(v)) {
			const label = uci.get('homeproxy', v, 'label');
			if (label) return label;
		}
	}
	/* Bare node section id (rules written by the advanced editor store the
	 * plain section name) — resolve its label, never show a raw cfg-id
	 * (hotswap.messages_node_names_not_cfg_ids). */
	const label = tag ? uci.get('homeproxy', String(tag), 'label') : null;
	if (label) return label;
	return tag;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function() {
		hp.uiShell();

		/* The chain's source list («send a service through the engine»):
		 * the same sources the Service rules presets write (no new
		 * hardcode); `hosts` are the route_explain targets of the
		 * follow-up live check. The full preset editor lives on the
		 * Service rules page (v3b). */
		const PRESETS = [
			{ source: 'google_ai', title: _('Google AI (Gemini, AI Studio)'), check: 'google_ai',
				hosts: [ 'gemini.google.com', 'generativelanguage.googleapis.com' ] },
			{ source: 'youtube', title: _('YouTube'), hosts: [ 'www.youtube.com' ] },
			{ source: 'discord', title: _('Discord'), hosts: [ 'discord.com' ] },
			{ source: 'telegram', title: _('Telegram'), hosts: [ 'web.telegram.org' ] },
			{ source: 'openai', title: _('OpenAI (ChatGPT)'), check: 'openai',
				hosts: [ 'chatgpt.com', 'api.openai.com' ] },
			{ source: 'anthropic', title: _('Claude / Anthropic'),
				hosts: [ 'claude.ai', 'api.anthropic.com' ] },
			{ source: 'whatsapp', title: _('WhatsApp'),
				hosts: [ 'web.whatsapp.com' ] },
			{ source: 'twitch', title: _('Twitch'),
				hosts: [ 'www.twitch.tv' ] },
			{ source: 'meta', title: _('Meta (Facebook, Instagram)'), hosts: [ 'instagram.com' ] },
			{ source: 'twitter', title: _('Twitter / X'), hosts: [ 'x.com' ] },
			{ source: 'tiktok', title: _('TikTok'), hosts: [] },
			{ source: 'roblox', title: _('Roblox'), hosts: [ 'roblox.com' ] },
			{ source: 'google_play', title: _('Google Play'), hosts: [] },
			{ source: 'google-meet', title: _('Google Meet'), hosts: [] }
		];

		const WIZ_CSS = `
.wiz-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.wiz-toolbar input[type="text"] { flex: 1 1 260px; min-width: 200px; }
.wiz-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); margin: 6px 0; }
.wiz-title { flex: 1 1 220px; font-weight: 600; }
.wiz-select { min-width: 190px; max-width: 320px; }
.wiz-note { font-size: .88em; opacity: .8; margin: 8px 0; }
.wiz-strat { flex: 1 1 380px; min-width: 260px; font-family: monospace; font-size: .82em; }
`;

		const st = document.getElementById('hp-byp-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-byp-style' }, [ WIZ_CSS ]));

		/* ── Zone frame (R3 v3c) ───────────────────────────────────────── */
		/* The wizard DPI section moved here as FOUR human zones
		 * (19-UX_REDESIGN стр. 4): what works now, the automatic side, the
		 * Lab, and everything applied by hand. The result area is ONE
		 * shared node that moves under the active zone — results stay in
		 * one place, replacing the previous. */
		const dpiBanner = E('div', {});
		const dpiCards = E('div', { 'class': 'hpui-cards' });
		/* ч.109: the Serving map — what actually serves each resource right
		 * now (rule → engine → strategy → last check), the user complaint
		 * «не видно какие реально сейчас используются стратегии». */
		const dpiMap = E('div', {});
		const dpiQuality = E('div', {});
		const dpiStrategy = E('div', {});
		const dpiLab = E('div', {});
		const dpiCorpus = E('div', {});
		const dpiResult = E('div', {});
		const DPI_TABS = [
			[ 'dpiOv',  _('Working right now') ],
			[ 'dpiAp',  _('Auto-pilot') ],
			[ 'dpiLab', _('Strategy Lab') ],
			[ 'dpiMan', _('Manual & compositions') ]
		];
		const dpiPanes = {};
		for (let t in DPI_TABS)
			dpiPanes[DPI_TABS[t][0]] = E('div', { 'class': 'hpui-pane' });
		const dpiTabBar = E('div', { 'class': 'hpui-tabs', style: 'margin:8px 0 10px 0' });
		const dpiResultRow = E('div', {}, [
			E('h4', { style: 'margin-top:14px' }, [ _('Results') ]),
			dpiResult
		]);
		for (let i in DPI_TABS) {
			const idx = parseInt(i, 10);
			const key = DPI_TABS[i][0];
			const b = E('button', {
				'class': 'hpui-tab' + (idx === 0 ? ' active' : ''),
				type: 'button'
			}, [ DPI_TABS[i][1] ]);
			b.addEventListener('click', function() {
				for (let k in dpiPanes)
					dpiPanes[k].classList.toggle('active', k === key);
				for (let j = 0; j < dpiTabBar.children.length; j++)
					dpiTabBar.children[j].classList.toggle('active', j === idx);
				/* the ONE result area follows the user — always visible at
				 * the bottom of the active zone */
				dpiPanes[key].appendChild(dpiResultRow);
			});
			dpiTabBar.appendChild(b);
		}
		dpiPanes.dpiOv.classList.add('active');

		/* «Working right now» zone — the honest state, no actions here. */
		dpiPanes.dpiOv.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('The live state of the bypass: which engines are running, which strategy serves each resource right now, and the measured quality of the desync path. Actions live on the other tabs; the results area follows you to every tab.') ]));
		dpiPanes.dpiOv.appendChild(dpiBanner);
		dpiPanes.dpiOv.appendChild(dpiCards);
		dpiPanes.dpiOv.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('What serves what right now') ]));
		dpiPanes.dpiOv.appendChild(dpiMap);
		dpiPanes.dpiOv.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Quality now') ]));
		dpiPanes.dpiOv.appendChild(dpiQuality);

		/* «Auto-pilot» zone — the automatic side (settings + one-click). */
		dpiPanes.dpiAp.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('The bypass maintains itself: the scheduled auto-pilot re-ranks the strategies and applies the best one without attention, and immediately picks an alternative when a resource stops working. One click picks the best strategy for a single resource. Every apply takes a server snapshot (Restore stays available) and verifies the resource live.') ]));

		/* «Strategy Lab» zone — measure, then decide. */
		dpiPanes.dpiLab.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Measure, not guesswork: the Lab tests the strategy catalog against your provider and ranks honestly — the fresh-connection start first, then the video flow. Apply a winner for one resource right from the table, generate mutations, or import and share catalogs.') ]));
		dpiPanes.dpiLab.appendChild(dpiLab);
		dpiPanes.dpiLab.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Strategy catalog') ]));
		dpiPanes.dpiLab.appendChild(dpiCorpus);

		/* «Manual & compositions» zone — everything applied by hand. */
		dpiPanes.dpiMan.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Everything applied by hand: the global Zapret strategy, the ByeDPI card with its presets and flags, the per-resource composition of both engines, and the "send a service through the engine" chain. Automatic selection lives on the Auto-pilot tab.') ]));
		dpiPanes.dpiMan.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Strategy') ]));
		dpiPanes.dpiMan.appendChild(dpiStrategy);

		dpiPanes.dpiOv.appendChild(dpiResultRow);
		const bypRoot = E('div', {});
		bypRoot.appendChild(dpiTabBar);
		for (let t in DPI_TABS)
			bypRoot.appendChild(dpiPanes[DPI_TABS[t][0]]);
		/* Badge / text helpers ─────────────────────────────────────────── */
		const badge = (cls, text) => E('span', { 'class': 'hpui-badge ' + cls }, [ text ]);


		const state = { dpiSig: null, stratSig: null, fuzzSig: null, corpusSig: null, prevSig: null,
			dpiPendingCheck: null,
			/* Ф8-F4 composition builder: the profile draft is PERSISTED on the
			 * server (ч.109) — compDirty guards the one-time seed from it. */
			compProfiles: [ { engine: 'zapret', resource: 'youtube', domains: '', strategy: '' } ],
			compBuilt: null, composeSig: null, composeSeeded: false, rbSig: null,
			compSeeded: false, compDirty: false, compSaveError: null,
			mapSig: null, fuzzShownSig: null };

		function nodeText(node) {
			if (node === 'main-out') return _('Same as main node');
			if (node === 'byedpi-out') return 'ByeDPI';
			if (node === 'zapret-out') return 'Zapret';
			if (node === 'tgws-out') return _('tg-ws (transparent)');
			if (node === 'urltest') return _('URLTest pool');
			return resolveTag(node);
		}

		function ruleStateText(rule, count) {
			if (!rule)
				return E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ _('no rule') ]);
			const parts = [];
			parts.push(rule.enabled
				? badge('hpui-b-blue', '→ ' + nodeText(rule.node))
				: badge('hpui-b-grey', _('disabled') + ' (→ ' + nodeText(rule.node) + ')'));
			if (rule.node === 'urltest' && rule.urltest_nodes && rule.urltest_nodes.length)
				parts.push(E('span', { 'class': 'wiz-note', style: 'margin:0' },
					[ _('pool: %d node(s)').format(rule.urltest_nodes.length) ]));
			if (count > 1)
				parts.push(E('span', { 'class': 'wiz-note', style: 'margin:0' },
					[ _('+%d more rule(s) of this service — see the manual editor').format(count - 1) ]));
			return E('span', {}, parts);
		}

		let lastEnv = null;

		/* ── Short trace (the DPI chain check renders routes with it) ──── */
		function shortTrace(t) {
			if (!t || t.error)
				return E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ (t && t.error) || '—' ]);
			const label = t.outbound ? resolveTag(t.outbound) : (t.action || '?');
			return E('span', {}, [
				E('strong', {}, [ label ]),
				E('span', { style: 'opacity:.75' }, [ (t.match ? (' ← ' + t.match) : '') + (t.fallback ? (' · ' + _('default route')) : '') ])
			]);
		}

		/* ── DPI section (Ф3): engine status, strategy, Lab, corpus ────── */

		const DPI_GROUPS = [
			[ 'recommended', _('Recommended') ],
			[ 'imported', _('Imported (catalog)') ],
			[ 'generated', _('Generated') ],
			[ 'auto', _('Full-test pool') ]
		];

		function fmtBytes(n) {
			n = Number(n) || 0;
			if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB';
			if (n > 1024) return (n / 1024).toFixed(1) + ' KB';
			return String(n);
		}

		function shortStrategy(s, n) {
			s = String(s || '');
			return (s.length > (n || 60)) ? s.slice(0, n || 60) + '…' : s;
		}

		/* Engine cards — built once, texts replaced on poll (anti-flicker). */
		dpiCards.appendChild(E('div', { 'class': 'hpui-card' }, [
			E('div', { 'class': 'hpui-cap' }, [ 'Zapret (nfqws2)' ]),
			E('div', { 'class': 'hpui-num', id: 'wiz-zapnum' }, [ '—' ]),
			E('div', { 'class': 'wiz-note', style: 'margin:2px 0 0 0' }, [
				E('span', { id: 'wiz-zapnote' }, [ '' ]),
				E('span', { id: 'wiz-zapq', style: 'opacity:.75' }, [ '' ])
			])
		]));
		dpiCards.appendChild(E('div', { 'class': 'hpui-card' }, [
			E('div', { 'class': 'hpui-cap' }, [ 'ByeDPI (ciadpi)' ]),
			E('div', { 'class': 'hpui-num', id: 'wiz-bnum' }, [ '—' ]),
			E('div', { 'class': 'wiz-note', style: 'margin:2px 0 0 0' }, [
				E('span', { id: 'wiz-bnote' }, [ '' ])
			])
		]));

		function engineText(e) {
			if (!e.installed) return _('not installed');
			if (!e.enabled) return _('disabled');
			return e.running ? _('running') : _('enabled, not running');
		}

		function engineClass(e) {
			if (!e.installed || !e.enabled) return '';
			return e.running ? 'hpui-c-green' : 'hpui-c-red';
		}

		function renderDpi(st) {
			if (!st || !st.result) return;
			const z = st.zapret || {}, b = st.byedpi || {};
			const sig = JSON.stringify([ z.enabled, z.installed, z.running,
				(z.strategy || ''), b.enabled, b.installed, b.running, (b.opts || '') ]);
			if (sig !== state.dpiSig) {
				state.dpiSig = sig;
				const zn = document.getElementById('wiz-zapnum');
				zn.textContent = engineText(z);
				zn.className = 'hpui-num ' + engineClass(z);
				/* ч.109: the NAME first («какая стратегия работает»), the raw
				 * args stay one click away in the title tooltip. */
				const znTitle = z.strategy
					? ((z.strategy_name ? z.strategy_name + '\n' : '') + z.strategy)
					: '';
				const znSpan = document.getElementById('wiz-zapnote');
				znSpan.textContent = z.strategy
					? ((z.strategy_name ? z.strategy_name + ' · ' : '') + shortStrategy(z.strategy, 90))
					: '—';
				znSpan.title = znTitle;
				const bn = document.getElementById('wiz-bnum');
				bn.textContent = engineText(b);
				bn.className = 'hpui-num ' + engineClass(b);
				document.getElementById('wiz-bnote').textContent =
					b.opts ? shortStrategy(b.opts, 110) : '—';

				dpiBanner.innerHTML = '';
				if (!z.installed || !b.installed) {
					const miss = [];
					if (!z.installed) miss.push('Zapret (zapret2)');
					if (!b.installed) miss.push('ByeDPI (ciadpi)');
					dpiBanner.appendChild(E('div', { 'class': 'hpui-banner' },
						[ _('%s is not installed — install it on the "Core & Tools" page first.').format(miss.join(', ')) ]));
				}
				/* Seed the strategy input once. */
				if (!state.stratInit) {
					state.stratInit = true;
					stratInput.value = z.strategy || '';
				}
			}
			/* NFQUEUE counters change every poll — update text only. */
			const q = (z.nfqueue || {});
			document.getElementById('wiz-zapq').textContent = z.enabled
				? (' · NFQUEUE: ' + (q.packets || 0) + ' pkts / ' + fmtBytes(q.bytes))
				: '';
		}

		/* ── ч.109: Serving map — per-resource live view: rule → engine →
		 * strategy → last health check. Everything the user complained was
		 * invisible («какая стратегия работает, какая нет»). Data is merged
		 * from dpi_status + preset rules + the auto-pilot probe journal. */
		const MAP_ROWS = [
			[ 'youtube', 'YouTube' ],
			[ 'discord', 'Discord' ],
			[ 'telegram', _('Telegram (TLS)') ],
			[ 'general', _('General (catch-all)') ]
		];
		const mapBody = E('tbody', {});
		const mapWrap = E('div', { 'class': 'hpui-wrap' });
		mapWrap.appendChild(E('table', { 'class': 'hpui-table' }, [
			E('thead', {}, E('tr', {}, [
				E('th', {}, [ _('Resource') ]),
				E('th', {}, [ _('Rule') ]),
				E('th', {}, [ _('Serving strategy') ]),
				E('th', {}, [ _('Last check') ]),
				E('th', {}, [ '' ])
			])),
			mapBody
		]));
		dpiMap.appendChild(mapWrap);
		dpiMap.appendChild(E('p', { 'class': 'wiz-note', style: 'margin-top:2px' },
			[ _('The map is live: the rule column shows where the resource is routed, the strategy column — the engine profile actually serving it now (an own scoped profile, the general tail, or a global strategy). «Check» probes the resource through the configured path (YouTube: the page, the thumbnail CDN, the video edge AND the real video stream measured in KB/s).') ]));

		function servingText(rk, rule, dpiSt) {
			const z = dpiSt.zapret || {}, b = dpiSt.byedpi || {};
			if (rule && rule.node === 'byedpi-out')
				return (b.opts) ? 'ByeDPI: ' + shortStrategy(b.opts, 60) : 'ByeDPI: ' + _('no strategy set');
			if (rule && rule.node === 'zapret-out') {
				/* ч.116: the map reads the parsed profile blocks — the user
				 * complaint «применить для YouTube применило и к Discord» was
				 * the GLOBAL strategy written on every Zapret-routed row with
				 * no scope shown. Own block → its strategy; no own block →
				 * the general tail; no hostlists at all → the honest
				 * «the strategy is global for the engine». */
				const blocks = z.blocks || [];
				if (blocks.length) {
					const scoped = blocks.filter(function(bk) { return bk.scope === rk; });
					if (scoped.length) {
						/* A resource may have several scoped blocks (http + tls);
						 * the TLS one is what actually serves the flow to :443 —
						 * show it (the raw http fragment's name misleads). */
						const tls = scoped.filter(function(bk) { return /--filter-tcp=443/.test(bk.base || ''); });
						const bk = tls.length ? tls[0] : scoped[0];
						return 'Zapret: ' + (bk.name || shortStrategy(bk.base, 60)) +
							' — ' + _('own profile');
					}
					const tail = blocks[blocks.length - 1];
					if (tail.scope == null)
						return 'Zapret: ' + (tail.name || shortStrategy(tail.base, 60)) +
							' — ' + _('general profile (catch-all)');
					return _('Zapret: no general profile — this traffic passes WITHOUT desync.');
				}
				return (z.strategy)
					? 'Zapret: ' + (z.strategy_name ? z.strategy_name + ' · ' : '') +
						shortStrategy(z.strategy, 60) + ' — ' +
						_('global strategy (serves every flow routed to Zapret)')
					: 'Zapret: ' + _('no strategy set');
			}
			if (rule && rule.node)
				return _('Rides %s — no DPI strategy applies.').format(nodeText(rule.node));
			return (rk === 'general')
				? _('Catch-all: main path / mass lists.')
				: _('No rule — rides the main path or the mass lists.');
		}

		function renderServingMap(dpiSt, presets, apSt) {
			const rules = (presets && presets.rules) || {};
			const counts = (presets && presets.rule_counts) || {};
			const st = (apSt && apSt.status) || null;
			const apOk = !!(apSt && apSt.daemon_ok && st);
			const sig = JSON.stringify([
				dpiSt && dpiSt.zapret, dpiSt && dpiSt.byedpi, rules, counts,
				apOk, apOk ? st.resources : null
			]);
			if (sig === state.mapSig)
				return;
			state.mapSig = sig;
			mapBody.innerHTML = '';
			for (let r in MAP_ROWS) {
				const rk = MAP_ROWS[r][0], label = MAP_ROWS[r][1];
				const rule = rules[rk] || null;
				const tr = E('tr', {});
				tr.appendChild(E('td', { style: 'font-weight:600; white-space:nowrap' }, [ label ]));
				const ruleTd = E('td', {});
				if (rk === 'general') {
					const env = lastEnv || {};
					ruleTd.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ _('catch-all — unmatched traffic') ]));
				} else
					ruleTd.appendChild(ruleStateText(rule, counts[rk] || 0));
				tr.appendChild(ruleTd);
				tr.appendChild(E('td', { style: 'font-size:.85em' },
					[ servingText(rk, rule, dpiSt || {}) ]));
				const lastTd = E('td', { style: 'white-space:nowrap' }, [ '—' ]);
				if (apOk && st.resources && st.resources[rk]) {
					const p = st.resources[rk].probe || {};
					const w = st.resources[rk].winner || {};
					lastTd.innerHTML = '';
					if (p && p.ts)
						lastTd.appendChild(p.ok
							? badge('hpui-b-green', '✓ ' + (p.code || '') + ((p.tsec != null) ? (' · ' + p.tsec + ' s') : ''))
							: badge('hpui-b-red', '✗ ' + (p.code || '000')));
					if (w && w.name)
						lastTd.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0 0 0 4px' },
							[ _('pilot: %s').format(w.name) ]));
					if (!lastTd.firstChild)
						lastTd.textContent = '—';
				}
				tr.appendChild(lastTd);
				const chk = E('button', { 'class': 'btn cbi-button', type: 'button',
					'style': 'font-size:.82em; padding:0 8px' }, [ _('Check') ]);
				chk.addEventListener('click', function() {
					chk.disabled = true;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Probing %s through the configured path…').format(label) ]));
					L.resolveDefault(callDpiProbe(rk), {}).then(function(pr) {
						chk.disabled = false;
						if (!pr || pr.result === false) {
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ (pr && pr.error) || _('rpc error') ]));
							return;
						}
						const box = E('div', {});
						box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
							[ _('Live check — %s:').format(label) ]));
						(pr.probes || []).forEach(function(pb) {
							const line = E('div', { 'class': 'wiz-note' });
							line.appendChild(pb.ok
								? badge('hpui-b-green', '✓ ' + (pb.code || ''))
								: badge('hpui-b-red', '✗ ' + (pb.code || '000')));
							line.appendChild(document.createTextNode(' ' +
								pb.url.replace(/^https?:\/\//, '') +
								(pb.tsec != null ? (' · ' + pb.tsec + ' s') : '') +
								(pb.bytes > 0 ? (' · ' + fmtBytes(pb.bytes)) : '') +
								(pb.speed > 0 ? (' · ' + Math.round(pb.speed / 1024) + ' KB/s') : '')));
							box.appendChild(line);
						});
						if (pr.stream_note)
							box.appendChild(E('p', { 'class': 'hpui-hint' },
								[ _('The video-stream probe was skipped: the test stream URL is unavailable (%s) — the rest of the check still decided.').format(pr.stream_note) ]));
						if (!pr.ok)
							box.appendChild(E('p', { 'class': 'hpui-hint' },
								[ _('A failed sub-check means the resource does NOT work entirely — pick another strategy for it in the Strategy Lab below.') ]));
						dom.content(dpiResult, box);
					});
				});
				tr.appendChild(E('td', {}, [ chk ]));
				mapBody.appendChild(tr);
			}
		}

		/* ── ч.123: Quality now — the MEASURED state of the desync path in
		 * one panel: the last video-flow speed (the auto-pilot's health
		 * journal, or the last fuzz winner when the daemon is off), the
		 * sweep-level QUIC verdict, the applied strategy and the last fuzz
		 * winner. Nothing here is assumed — every number came from a probe
		 * through the configured path. */
		function renderDpiQuality(dpiSt, apSt, fz) {
			const res = (fz && fz.result) || null;
			const sig = JSON.stringify([
				apSt && apSt.status, (res ? res.ts : null),
				dpiSt && dpiSt.zapret ? dpiSt.zapret.strategy : null
			]);
			if (sig === state.dpiqSig)
				return;
			state.dpiqSig = sig;
			dpiQuality.innerHTML = '';
			const aps = (apSt && apSt.status && apSt.status.resources &&
				apSt.status.resources.youtube) || null;
			let flow = 0, flowWhen = '', flowStart = 0;
			if (aps && aps.probe && Number(aps.probe.speed || 0) > 0) {
				flow = Number(aps.probe.speed);
				flowStart = Number(aps.probe.start_ms || 0);
				flowWhen = aps.probe.ts
					? new Date(Number(aps.probe.ts) * 1000).toLocaleString() : '';
			} else if (res && res.strategies && res.strategies.length &&
				Number(res.strategies[0].stream || 0) > 0) {
				flow = Number(res.strategies[0].stream);
				flowStart = Number(res.strategies[0].start_ms || 0);
				flowWhen = res.ts
					? new Date(Number(res.ts) * 1000).toLocaleString() : '';
			}
			const flowLine = E('div', { 'class': 'wiz-note' },
				[ _('Video flow (24 thumbnails, one TLS flow):') ]);
			if (flow > 0)
				flowLine.appendChild(badge('hpui-b-green', Math.round(flow / 1024) + ' KB/s'));
			else
				flowLine.appendChild(E('span', { style: 'opacity:.5' },
					[ _('not measured yet') ]));
			/* ч.127: the fresh-connection START — the hover-preview latency. */
			if (flowStart > 0)
				flowLine.appendChild(E('span', { title: _('fresh-connection start ~%d ms (hover-preview latency)').format(flowStart) },
					[ ' · ' + _('start ~%d ms').format(flowStart) ]));
			if (flowWhen)
				flowLine.appendChild(document.createTextNode(' · ' + flowWhen));
			dpiQuality.appendChild(flowLine);
			if (res && res.quic && res.quic.verdict != null) {
				const qv = '' + res.quic.verdict;
				dpiQuality.appendChild(E('div', { 'class': 'wiz-note' }, [
					_('QUIC (UDP 443) to the video edge:'),
					(qv === 'vn')
						? badge('hpui-b-green', 'open')
						: badge('hpui-b-red', (qv === 'icmp') ? 'rejected' : 'no answer')
				]));
			}
			const z = (dpiSt && dpiSt.zapret) || {};
			if (z.strategy)
				dpiQuality.appendChild(E('div', { 'class': 'wiz-note' }, [
					_('Applied Zapret strategy:'),
					E('span', { title: z.strategy },
						[ (z.strategy_name || shortStrategy(z.strategy, 70)) ])
				]));
			if (res && res.strategies && res.strategies.length &&
				Number(res.strategies[0].ok || 0) > 0) {
				const b = res.strategies[0];
				dpiQuality.appendChild(E('div', { 'class': 'wiz-note' }, [
					_('Last fuzz winner: %s (flow %s).').format(b.name || _('custom args'),
						(Number(b.stream || 0) > 0)
							? (Math.round(b.stream / 1024) + ' KB/s') : _('n/a'))
				]));
			}
			dpiQuality.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:2px 0 0 0; opacity:.8' },
				[ _('Every number here was measured through your real path. The flow speed refreshes on every auto-pilot health check; without the auto-pilot it comes from the last fuzz ranking.') ]));
		}

		/* Strategy row — persistent elements, options rebuilt on corpus change. */
		const stratSel = E('select', { 'class': 'cbi-input-select wiz-select' });
		const stratInput = E('input', { type: 'text', 'class': 'cbi-input-text wiz-strat',
			placeholder: 'nfqws2 --lua-desync=… args' });
		const stratRow = E('div', { 'class': 'wiz-row' });
		stratRow.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Zapret strategy') ]));
		stratRow.appendChild(stratSel);
		stratRow.appendChild(stratInput);
		const applyStratBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Apply strategy') ]);
		const testStratBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Test strategy') ]);
		stratRow.appendChild(applyStratBtn);
		stratRow.appendChild(testStratBtn);
		dpiStrategy.appendChild(stratRow);
		dpiStrategy.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('The global "Apply strategy" serves EVERY flow routed to Zapret (one engine strategy, no hostlists — the routing rules select the traffic). A per-resource apply (Strategy Lab rows, auto-pick) builds a SCOPED profile instead — other managed resources keep their strategies; the Composition below edits the same blocks manually. Applying also enables Zapret and restarts the service; testing runs the strategy on an isolated queue over 4 test sites (YouTube, Telegram, Discord, Speedtest).') ]));

		function renderStrategySel(cands) {
			state.cands = cands || [];
			const sig = JSON.stringify((cands || []).map(function(c) { return c.name; }));
			/* ч.123: the honest FULL-sweep duration follows the corpus size. */
			if (autFullTxt)
				autFullTxt.textContent = _('Thorough (full corpus, ~%d min)').format(fuzzEtaMin(state.cands.length || 13));
			if (sig !== state.stratSig) {
				/* Corpus changed (first poll included): rebuild the composition
				 * rows so their catalog selects pick up the candidates. */
				renderCompProfiles();
			}
			if (sig === state.stratSig)
				return;
			state.stratSig = sig;
			const cur = stratSel.value;
			stratSel.innerHTML = '';
			stratSel.appendChild(E('option', { value: '' }, [ _('— pick from the catalog —') ]));
			for (let g in DPI_GROUPS) {
				const og = E('optgroup', { label: DPI_GROUPS[g][1] });
				for (let c in (cands || []))
					if ((cands[c].group || 'recommended') === DPI_GROUPS[g][0])
						og.appendChild(E('option', { value: String(cands[c].args) }, [ cands[c].name ]));
				if (og.children.length)
					stratSel.appendChild(og);
			}
			if (cur)
				stratSel.value = cur;
		}

		stratSel.addEventListener('change', function() {
			if (stratSel.value)
				stratInput.value = stratSel.value;
		});

		applyStratBtn.addEventListener('click', function() {
			const s = String(stratInput.value || '').trim();
			if (!s) {
				ui.addNotification(null, E('p', {}, _('No strategy set — pick one from the catalog or enter the options first.')), 'error');
				return;
			}
			applyStratBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Applying the strategy — the service restarts…') ]));
			L.resolveDefault(callFuzzApply(s), {}).then(function(r) {
				applyStratBtn.disabled = false;
				if (!r || r.result === false) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				dom.content(dpiResult, E('div', {}, [
					E('p', { 'class': 'hpui-hint' },
						[ _('Strategy applied — Zapret is enabled (it was off) and the service restarts.') ]),
					E('p', { 'class': 'hpui-hint' },
						[ _('Run "Test strategy" in ~30 seconds to confirm it works on your ISP, then create a service rule below.') ])
				]));
			});
		});

		testStratBtn.addEventListener('click', function() {
			const s = String(stratInput.value || '').trim();
			if (!s) {
				ui.addNotification(null, E('p', {}, _('No strategy set — pick one from the catalog or enter the options first.')), 'error');
				return;
			}
			testStratBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ _('Testing…') ]));
			L.resolveDefault(callZapretResolve(), {}).then(function(ret) {
				let d = {};
				try { d = JSON.parse(ret.output || '{}'); } catch (e) {}
				if (!d.ok || !d.ips) {
					testStratBtn.disabled = false;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ d.error || _('DNS not ready — wait a few seconds after Apply and retry') ]));
					return;
				}
				const ips = Object.keys(d.ips).map(function(k) { return k + '=' + d.ips[k]; }).join(' ');
				return L.resolveDefault(callZapretTest(s, ips), {}).then(function(ret2) {
					testStratBtn.disabled = false;
					let data = {};
					try { data = JSON.parse(ret2.output || '{}'); } catch (e) {}
					if (data.error) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ data.error ]));
						return;
					}
					const box = E('div', {});
					box.appendChild(E('div', { 'class': 'wiz-note' },
						[ _('TLS handshake on the 4 test sites (isolated queue, live traffic untouched):') ]));
					const row = E('div', { 'class': 'wiz-row' });
					(data.results || []).forEach(function(r2, i) {
						if (i) row.appendChild(document.createTextNode(' · '));
						row.appendChild(E('span', {
							style: 'font-weight:600;color:' + (r2.ok ? 'var(--hp-accent-strong)' : 'var(--hp-red)')
						}, [ (r2.label || r2.tag) + (r2.ok ? ' ✓ ' + r2.tls + 's' : ' ✗ ' + (r2.reason || 'fail')) ]));
					});
					row.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ '(' + (data.ok || 0) + '/' + (data.total || 0) + ')' ]));
					box.appendChild(row);
					dom.content(dpiResult, box);
				});
			});
		});

		/* ── ByeDPI strategy card — the node.js ByeDPI/Zapret tabs moved here
		 * (user wish, сеанс 24): strategy presets + custom args + the engine
		 * option flags + the preset sweep. Save writes the whole card through
		 * wizard_byedpi_set (the server snapshot is written first, so Restore
		 * covers the previous strategy; the service restarts). Test / Test-all
		 * probe through byedpi_strategy_test on a temporary port. Results land
		 * in dpiResult (ONE place). ───────────────────────────────────────── */
		const BYEDPI_PRESETS = [
			/* A — Community-contributed strategies (from issues / community testing) */
			{ name: 'A1 — YouTube 1',                  args: '-o1 -r-5+se -a1 -At,r,s -d1 -n google.com -Qr -f-1' },
			{ name: 'A2 — YouTube 2',                  args: '-d1 -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -d25+s -s30+s -d35+s -r1+s -S -a1 -As -d1 -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -d25+s -s30+s -d35+s -S -a1' },
			{ name: 'A3 — General 1',                  args: '-d1+s -O1 -s29+s -t 5 -An -Ku -a5 -s443+s -d80+s -d443+s -s80+s -s443+s -d53+s -s53+s -d443+s -An' },
			{ name: 'A4 — YouTube 3',                  args: '-H:"youtube.com googlevideo.com ggpht.com ytimg.com googleapis.com googleusercontent.com youtube-ui.l.google.com yt4.ggpht.com" -o1 -a1 -r-5+se -t6 -n rutube.com -An -f-1 -t8 -n www.google.com -d1 -s1+s -d1+s -s3+s -d6+s -s12+s -d14+s -s20+s -d24+s -s30+s -a1' },
			{ name: 'A5 — General 2',                  args: '-H:"youtube.com googlevideo.com ytimg.com ggpht.com youtu.be youtubei.googleapis.com" -Kt,h -d1 -s1+s -s3+s -s6+s -s9+s -s12+s -s15+s -s20+s -s30+s -a1 -An -H:"soundcloud.com api.soundcloud.com api-v2.soundcloud.com m.soundcloud.com eventgateway.soundcloud.com api-partners.soundcloud.com api-mobile.soundcloud.com wis.sndcdn.com va.sndcdn.com invite.soundcloud.com events.soundcloud.com" -Kth -Qorig -n "www.google.com" -f-1 -t5 -d1 -s1+s -s3+s -s6+s -s9+s -s12+s -s15+s -s20+s -s30+s -Mh,d,r -An -H:"sndcdn.com a-v2.sndcdn.com cf-hls-media.sndcdn.com cf-media.sndcdn.com cf-preview-media.sndcdn.com cf-hls-opus-media.sndcdn.com i1.sndcdn.com i2.sndcdn.com i3.sndcdn.com i4.sndcdn.com assets.soundcloud.com playback.media-streaming.soundcloud.cloud" -Kth -Qorig -n "www.google.com" -f-1 -t5 -s1 -d2 -Mh,d,r -An -H:"discord.com discord.gg discord.media discordapp.com cdn.discordapp.com media.discordapp.net images-ext-1.discordapp.net images-ext-2.discordapp.net images.discordapp.net gateway.discord.gg status.discord.com api.discord.com discord-attachments-uploads-prd.storage.googleapis.com hcaptcha.com recaptcha.net accounts.google.com appleid.apple.com" -Kth -Qorig -n "www.google.com" -f-1 -t5 -o1 -s1+s -s2+s -s5+s -d3+s -s7+s -s10+s -s15+s -An -Ku' },
			{ name: 'A6 — General 3',                  args: '-H:"youtube.com googlevideo.com ggpht.com ytimg.com googleapis.com googleusercontent.com youtube-ui.l.google.com yt4.ggpht.com" -o1 -a1 -r-5+se -t6 -n rutube.com -An -H:"cdn.discordapp.com canary.discord.com vdis.gd ptb.discord.com discord-attachments-uploads-prd.storage.googleapis.com discord-activities.com discord.co discord.com discord.design discord.dev discord.gg discord.gift discord.gifts discord.media discord.new discord.store discord.tools discordactivities.com discordapp.com discordapp.net media.discordapp.net images-ext-1.discordapp.net images-ext-2.discordapp.net stable.dl2.discordapp.net discordcdn.com discordmerch.com discordpartygames.com discordsays.com discordsez.com discordstatus.com" -f-1 -t8 -n www.google.com -s1+s -a5 -An -H:"soundcloud.com sndcdn.com soundcloud.app.goo.gl" -f-1 -T0.5 -Ars -d0+sm -At -r1+s -An -f-200 -s2 -s5+hm -t6 -Qr -n wb.ru' },
			/* B — Disorder — most effective on Linux */
			{ name: 'B1 — Disorder Basic',             args: '--disorder 1' },
			{ name: 'B2 — Disorder at SNI',            args: '--disorder 1+s' },
			{ name: 'B3 — Disorder TLS+HTTP',          args: '--proto tls,http --disorder 1' },
			{ name: 'B4 — Split + Disorder',           args: '--split 1 --disorder 3' },
			{ name: 'B5 — Disorder + Auto TLS Record', args: '--disorder 1 --auto=torst --tlsrec 1+s' },
			/* C — Fake TTL */
			{ name: 'C1 — Fake TTL=6',                 args: '--fake -1 --ttl 6' },
			{ name: 'C2 — Fake TTL=8',                 args: '--fake -1 --ttl 8' },
			{ name: 'C3 — Fake TTL=10',                args: '--fake -1 --ttl 10' },
			{ name: 'C4 — Fake TTL=12',                args: '--fake -1 --ttl 12' },
			{ name: 'C5 — Fake TTL=15',                args: '--fake -1 --ttl 15' },
			/* D — Fake MD5 — Linux-only TCP option */
			{ name: 'D1 — Fake MD5',                   args: '--fake -1 --md5sig' },
			{ name: 'D2 — Disorder + Fake MD5',        args: '--disorder 1 --fake -1 --md5sig' },
			{ name: 'D3 — Fake MD5 TLS+HTTP',          args: '--proto tls,http --fake -1 --md5sig' },
			/* E — TLS Record split */
			{ name: 'E1 — TLS Record Split',           args: '--tlsrec 1+s' },
			{ name: 'E2 — TLS Record + Auto',          args: '--auto=torst --tlsrec 1+s' },
			{ name: 'E3 — TLS Record + Timeout',       args: '--auto=torst --timeout 3 --tlsrec 1+s' },
			{ name: 'E4 — Disorder + TLS Record',      args: '--disorder 1 --tlsrec 1+s' },
			/* F — OOB */
			{ name: 'F1 — OOB at SNI',                 args: '--oob 1+s' },
			{ name: 'F2 — OOB at SNI+3',               args: '--oob 3+s' },
			{ name: 'F3 — DisoOB at SNI',              args: '--disoob 1+s' },
			{ name: 'F4 — DisoOB + Fake MD5',          args: '--disoob 1+s --fake -1 --md5sig' },
			/* G — Split */
			{ name: 'G1 — Split at SNI',               args: '--split 1+s' },
			{ name: 'G2 — Split at SNI Middle',        args: '--split 0+sm' },
			{ name: 'G3 — Split at 2',                 args: '--split 2' },
			{ name: 'G4 — Split + OOB',                args: '--split 1+s --oob 2+s' },
			/* H — HTTP modification */
			{ name: 'H1 — HTTP Host Case Mix',         args: '--proto http --mod-http hcsmix' },
			{ name: 'H2 — HTTP Host Double Mix',       args: '--proto http --mod-http hcsmix,dcsmix' },
			{ name: 'H3 — HTTP Full Mix',              args: '--proto http --mod-http hcsmix,dcsmix,rmspace' },
			{ name: 'H4 — HTTP Mix + Disorder',        args: '--proto tls,http --mod-http hcsmix --disorder 1' },
			/* I — Auto-mode */
			{ name: 'I1 — Auto SSL Error Fallback',    args: '--fake -1 --ttl 8 --auto=ssl_err --fake -1 --ttl 5' },
			{ name: 'I2 — Auto Reset Fallback',        args: '--fake -1 --md5sig --auto=torst --disorder 1' },
			/* J — Fake TLS modification */
			{ name: 'J1 — Random TLS Fake',            args: '--fake -1 --fake-tls-mod rand' },
			{ name: 'J2 — Original TLS Fake',          args: '--fake -1 --fake-tls-mod orig' },
			/* K — Aggressive combos */
			{ name: 'K1 — Aggressive Split',           args: '--split 1+s --disorder 3+s' },
			{ name: 'K2 — Aggressive OOB + MD5',       args: '--oob 1+s --disorder 1 --fake -1 --md5sig' },
			{ name: 'K3 — Aggressive DisoOB',          args: '--disoob 1+s --disorder 3+s' },
			{ name: 'K4 — Aggressive Combo',           args: '--split 1+s --oob 2+s --disorder 3+s' },
			{ name: 'K5 — TLS+HTTP Disorder + Record', args: '--proto tls,http --disorder 1 --tlsrec 1+s' },
			/* L — UDP */
			{ name: 'L1 — UDP Fake',                   args: '--proto udp --udp-fake 5' },
			{ name: 'L2 — TLS+UDP Fake MD5',           args: '--proto tls,udp --fake -1 --md5sig --udp-fake 5' },
			/* M — Full combo */
			{ name: 'M1 — Full TLS Bypass',            args: '--proto tls --fake -1 --md5sig --tlsrec 1+s' }
		];

		/* Groups are matched to presets by the letter prefix of the preset name
		 * (A1 → group A, B3 → group B, …). */
		const BYEDPI_GROUPS = [
			{ key: 'A', label: _('Community') },
			{ key: 'B', label: _('Disorder — reorders TCP segments') },
			{ key: 'C', label: _('Fake TTL') },
			{ key: 'D', label: _('Fake MD5') },
			{ key: 'E', label: _('TLS Record Split') },
			{ key: 'F', label: _('OOB') },
			{ key: 'G', label: _('Split') },
			{ key: 'H', label: _('HTTP Modification') },
			{ key: 'I', label: _('Auto-mode') },
			{ key: 'J', label: _('TLS Modification') },
			{ key: 'K', label: _('Aggressive') },
			{ key: 'L', label: _('UDP') },
			{ key: 'M', label: _('Full Combo') },
		];

		const bStratInput = E('input', { type: 'text', 'class': 'cbi-input-text wiz-strat',
			placeholder: 'ciadpi args, e.g. --disorder 1' });
		bStratInput.value = uci.get('homeproxy', 'config', 'byedpi_cmd_opts') || '--disorder 1';
		const bPresetSel = E('select', { 'class': 'cbi-input-select wiz-select' });
		bPresetSel.appendChild(E('option', { value: '' }, [ _('— select a preset —') ]));
		for (let g of BYEDPI_GROUPS) {
			const og = E('optgroup', { label: g.label });
			for (let i = 0; i < BYEDPI_PRESETS.length; i++)
				if (BYEDPI_PRESETS[i].name.charAt(0) === g.key)
					og.appendChild(E('option', { value: String(i) }, [ BYEDPI_PRESETS[i].name ]));
			if (og.children.length)
				bPresetSel.appendChild(og);
		}
		bPresetSel.addEventListener('change', function() {
			const p = BYEDPI_PRESETS[parseInt(bPresetSel.value, 10)];
			if (p) bStratInput.value = p.args;
		});
		const bSave = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' }, [ _('Save ByeDPI') ]);
		const bTest = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Test') ]);
		const bTestAll = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Test all presets') ]);
		const bRow = E('div', { 'class': 'wiz-row' });
		bRow.appendChild(E('span', { 'class': 'wiz-title' }, [ _('ByeDPI strategy') ]));
		bRow.appendChild(bPresetSel);
		bRow.appendChild(bStratInput);
		bRow.appendChild(bSave);
		bRow.appendChild(bTest);
		bRow.appendChild(bTestAll);
		dpiStrategy.appendChild(E('div', { style: 'margin-top:10px' }, [ bRow ]));

		const bUot = E('input', { type: 'checkbox' });
		bUot.checked = (uci.get('homeproxy', 'config', 'byedpi_udp_over_tcp') !== '0');
		const bQuic = E('input', { type: 'checkbox' });
		bQuic.checked = (uci.get('homeproxy', 'config', 'byedpi_block_quic') === '1');
		const bVoice = E('input', { type: 'checkbox' });
		bVoice.checked = (uci.get('homeproxy', 'config', 'zapret_voice') === '1');
		const bFlag = (input, text) => E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
			[ input, ' ' + text ]);
		dpiStrategy.appendChild(E('div', { 'class': 'wiz-row' },
			[ bFlag(bUot, _('UDP over TCP')),
			  bFlag(bQuic, _('Block QUIC (UDP port 443)') + ' ⚠️'),
			  bFlag(bVoice, _('Discord calls via Zapret')) ]));
		dpiStrategy.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('The strategy serves the flows routed to ByeDPI (Main node = ByeDPI, service rules, or the Composition profiles below). Save writes the strategy and the flags and restarts the service; ByeDPI itself is enabled on the Connection page. UDP over TCP wraps UDP traffic into the ByeDPI TCP stream; Block QUIC drops outgoing UDP 443 so browsers fall back to TCP where the strategy works; Discord calls via Zapret routes the Discord voice UDP ports to Zapret (needs Zapret enabled).') ]));
		const bDesc = E('p', { 'class': 'wiz-note' });
		/* innerHTML: the description contains HTML links E() would escape */
		bDesc.innerHTML = _('Grouped by technique. Based on <a href="https://github.com/hufrea/byedpi" target="_blank">hufrea/byedpi</a> and community testing. See also <a href="https://github.com/fatyzzz/Byedpi-Setup" target="_blank">fatyzzz/Byedpi-Setup</a>.');
		dpiStrategy.appendChild(bDesc);

		bSave.addEventListener('click', function() {
			bSave.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Saving the ByeDPI options — the service restarts…') ]));
			L.resolveDefault(callByedpiSet(String(bStratInput.value || '').trim(),
				bUot.checked ? '1' : '0', bQuic.checked ? '1' : '0',
				bVoice.checked ? '1' : '0'), {}).then(function(r) {
				bSave.disabled = false;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ (r && r.result)
						? _('ByeDPI options saved — the service restarts; the engine card above reflects the new state.')
						: _('Save failed: ') + ((r && r.error) || _('rpc error')) ]));
			});
		});

		bTest.addEventListener('click', function() {
			const s = String(bStratInput.value || '').trim();
			if (!s) {
				ui.addNotification(null, E('p', {}, _('No strategy set — pick a preset or enter the options first.')), 'error');
				return;
			}
			bTest.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Testing the ByeDPI strategy on a temporary port (LAN traffic untouched)…') ]));
			L.resolveDefault(callByedpiTest(s, '15335'), {}).then(function(r) {
				bTest.disabled = false;
				if (!r || (!r.results && !r.result)) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ (r && r.error) || _('Test failed') ]));
					return;
				}
				const box = E('div', {});
				const row = E('div', { 'class': 'wiz-row' });
				(r.results || []).forEach(function(t, i) {
					if (i) row.appendChild(document.createTextNode(' · '));
					row.appendChild(E('span', {
						style: 'font-weight:600;color:' + (t.ok ? 'var(--hp-accent-strong)' : 'var(--hp-red)'),
						title: t.host + ' → ' + (t.ok ? t.code : (t.reason || 'fail'))
					}, [ (t.label || t.tag) + (t.ok ? ' ✓' : ' ✗') ]));
				});
				if (r.results)
					row.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ '(' + (r.passed || 0) + '/' + (r.total || 0) + ')' ]));
				box.appendChild(row);
				if (!r.results && r.result)
					box.appendChild(E('div', { 'class': 'wiz-note' },
						[ _('✓ ByeDPI started (install curl for full test)') ]));
				box.appendChild(E('p', { 'class': 'hpui-hint' },
					[ _('The strategy was NOT saved — press "Save ByeDPI" to apply it.') ]));
				dom.content(dpiResult, box);
			});
		});

		/* Preset sweep — the node.js "Test all strategies" moved here: each
		 * preset is probed on a temporary port, the table renders in dpiResult
		 * (ONE place); a row's button fills the strategy input (Save applies). */
		bTestAll.addEventListener('click', function() {
			if (!window.confirm(_('Test all ByeDPI presets? Each is probed against 4 sites (~12 min total). LAN clients are not affected. You can stop it at any point.')))
				return;
			bTestAll.disabled = true;
			const stop = { on: false };
			const stopBtn = E('button', { 'class': 'btn cbi-button', type: 'button', style: 'margin-left:6px' }, [ _('Stop') ]);
			stopBtn.addEventListener('click', function() { stop.on = true; stopBtn.disabled = true; });
			const box = E('div', {});
			const prog = E('p', { 'class': 'hpui-hint' }, [ _('Preparing…') ]);
			const wrap = E('div', { 'class': 'hpui-wrap' });
			const tbody = E('tbody', {});
			const thead = E('thead', {}, E('tr', {}, [
				E('th', {}, [ '#' ]), E('th', {}, [ _('Preset') ]),
				E('th', {}, [ _('Passed') ]), E('th', {}, [ '' ])
			]));
			wrap.appendChild(E('table', { 'class': 'hpui-table' }, [ thead, tbody ]));
			box.appendChild(prog);
			box.appendChild(wrap);
			box.appendChild(stopBtn);
			dom.content(dpiResult, box);

			let fullPass = 0, partial = 0;
			let chain = Promise.resolve();
			for (let i = 0; i < BYEDPI_PRESETS.length; i++) {
				const idx = i;
				const dots = E('td', { style: 'white-space:nowrap; opacity:.75' }, [ '–' ]);
				const pick = E('button', { 'class': 'btn cbi-button cbi-button-apply', style: 'font-size:.82em; padding:0 8px; visibility:hidden' },
					[ _('Fill input') ]);
				pick.addEventListener('click', function() {
					bStratInput.value = BYEDPI_PRESETS[idx].args;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Preset filled into the strategy input — press "Save ByeDPI" to apply it.') ]));
				});
				tbody.appendChild(E('tr', {}, [
					E('td', { style: 'opacity:.7' }, [ String(idx + 1) ]),
					E('td', { style: 'font-size:.85em; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap', title: BYEDPI_PRESETS[idx].args },
						[ BYEDPI_PRESETS[idx].name ]),
					dots,
					E('td', {}, [ pick ])
				]));
				chain = chain.then(function() {
					if (stop.on) return;
					prog.textContent = (idx + 1) + ' / ' + BYEDPI_PRESETS.length + ': ' + BYEDPI_PRESETS[idx].name;
					dots.textContent = '⏳';
					return L.resolveDefault(callByedpiTest(BYEDPI_PRESETS[idx].args, '15335'), {}).then(function(r) {
						dots.innerHTML = '';
						if (r && r.results && r.results.length) {
							r.results.forEach(function(t) {
								dots.appendChild(E('span', {
									style: 'font-weight:600; margin-right:3px; color:' + (t.ok ? 'var(--hp-accent-strong)' : 'var(--hp-red)'),
									title: (t.label || t.tag) + ' (' + t.host + ') → ' + (t.ok ? t.code : (t.reason || 'fail'))
								}, [ t.ok ? '●' : '○' ]));
							});
							dots.appendChild(E('span', { style: 'opacity:.7' },
								[ ' ' + (r.passed || 0) + '/' + (r.total || 0) ]));
							if (r.passed === r.total) { fullPass++; pick.style.visibility = ''; }
							else if (r.passed > 0) { partial++; pick.style.visibility = ''; }
						} else {
							dots.textContent = (r && r.result) ? '✓' : '✗';
						}
					});
				});
			}
			chain.then(function() {
				bTestAll.disabled = false;
				stopBtn.parentNode.removeChild(stopBtn);
				prog.textContent = stop.on
					? _('Stopped') + ' — ' + fullPass + ' ' + _('work on all sites') + ((partial > 0) ? (', ' + partial + ' ' + _('partial')) : '')
					: _('Done') + ': ' + fullPass + ' / ' + BYEDPI_PRESETS.length + ' ' + _('work on all sites') +
						(((fullPass + partial) > 0) ? (' — ' + _('fill a preset into the input and press "Save ByeDPI"')) : '');
			});
		});

		/* ── W3 v2 (Ф8-F4): Composition Builder — per-resource profiles of
		 * BOTH engines, built and tested on the SERVER. The old client-side
		 * string-join (and its JS-memory-only rollback) is gone: the server
		 * builds the final args, tests them (Zapret on the isolated queue,
		 * ByeDPI through the local tester), and apply snapshots the previous
		 * strategies server-side — Restore survives page reloads. ──── */
		const COMP_RESOURCES = [
			[ 'youtube', 'YouTube' ],
			[ 'discord', 'Discord' ],
			[ 'telegram', _('Telegram (TLS)') ],
			[ 'general', _('General (catch-all)') ],
			[ 'custom', _('Custom list') ]
		];
		const FUZZ_TAGS = [ [ 'yt', 'YouTube' ], [ 'tg', 'Telegram' ],
			[ 'dc', 'Discord' ], [ 'st', 'Speedtest' ] ];

		const compRowsBox = E('div', { id: 'wiz-comp-rows', style: 'margin:2px 0 6px 0' });
		const compAddBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Add profile') ]);
		const compTestBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' }, [ _('Test composition') ]);
		const compApplyBtn = E('button', { 'class': 'btn cbi-button cbi-button-negative', type: 'button' }, [ _('Apply composition') ]);
		const compClearBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Clear') ]);
		const restoreRow = E('div', { 'class': 'wiz-note', style: 'margin:4px 0' }, [ '' ]);
		dpiStrategy.appendChild(E('div', { 'class': 'wiz-row' },
			[ E('span', { 'class': 'wiz-title' }, [ _('Composition') ]) ]));
		dpiStrategy.appendChild(compRowsBox);
		dpiStrategy.appendChild(E('div', { 'class': 'wiz-toolbar' },
			[ compAddBtn, compTestBtn, compApplyBtn, compClearBtn ]));
		dpiStrategy.appendChild(restoreRow);
		dpiStrategy.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('Profiles are matched in order (first match wins): scoped profiles run first, the general profile last. The server builds the final args, tests them on the isolated queue (Zapret) and through the local tester (ByeDPI); applying snapshots the previous strategies on the server, so Restore survives page reloads. ByeDPI scoped profiles are exact-domain and TCP-only (SNI in TLS-CHello/HTTP); QUIC/UDP is not domain-scoped and falls to the fallback group.') ]));

		function compCandidateByArgs(args) {
			const cands = state.cands || [];
			for (let i = 0; i < cands.length; i++)
				if (cands[i].args === args)
					return cands[i];
			return null;
		}

		function fuzzHintText(c) {
			if (!c || !c.fuzz)
				return _('No fuzz data for this strategy yet.');
			const parts = [];
			for (let t in FUZZ_TAGS)
				if (c.fuzz[FUZZ_TAGS[t][0]] != null)
					parts.push(FUZZ_TAGS[t][1] + (c.fuzz[FUZZ_TAGS[t][0]] ? ' ✓' : ' ✗'));
			return parts.length ? (_('Last fuzz:') + ' ' + parts.join(' · '))
				: _('No fuzz data for this strategy yet.');
		}

		function buildCompRow(p, idx) {
			const engSel = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:118px' });
			engSel.appendChild(E('option', { value: 'zapret' }, [ 'Zapret (nfqws2)' ]));
			engSel.appendChild(E('option', { value: 'byedpi' }, [ 'ByeDPI (ciadpi)' ]));
			engSel.value = p.engine || 'zapret';
			engSel.addEventListener('change', function() {
				p.engine = engSel.value;
				saveComposeDraft();
				renderCompProfiles();
			});

			const resSel = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:132px' });
			for (let r in COMP_RESOURCES)
				resSel.appendChild(E('option', { value: COMP_RESOURCES[r][0] }, [ COMP_RESOURCES[r][1] ]));
			resSel.value = p.resource || 'general';
			resSel.addEventListener('change', function() {
				p.resource = resSel.value;
				saveComposeDraft();
				renderCompProfiles();
			});

			const domTitle = _('Domains: a.com, b.com (comma or space separated)');
			const domInput = E('input', {
				type: 'text', 'class': 'cbi-input-text', 'style': 'max-width:250px',
				placeholder: domTitle, title: domTitle
			});
			domInput.value = p.domains || '';
			domInput.addEventListener('change', function() {
				p.domains = String(domInput.value || '');
				saveComposeDraft();
			});

			const stratSel = E('select', { 'class': 'cbi-input-select wiz-select', 'style': 'min-width:190px' });
			stratSel.appendChild(E('option', { value: '' }, [ _('— pick from the catalog —') ]));
			const cands = state.cands || [];
			for (let g in DPI_GROUPS) {
				const og = E('optgroup', { label: DPI_GROUPS[g][1] });
				for (let c in cands)
					if ((cands[c].group || 'recommended') === DPI_GROUPS[g][0])
						og.appendChild(E('option', { value: String(cands[c].args) }, [ cands[c].name ]));
				if (og.children.length)
					stratSel.appendChild(og);
			}
			stratSel.value = compCandidateByArgs(p.strategy) ? (p.strategy || '') : '';
			stratSel.addEventListener('change', function() {
				if (stratSel.value) {
					p.strategy = stratSel.value;
					saveComposeDraft();
				}
				renderCompProfiles();
			});

			const stratInput = E('input', {
				type: 'text', 'class': 'cbi-input-text wiz-strat',
				placeholder: (p.engine === 'byedpi') ? 'ciadpi args, e.g. --disorder 1'
					: 'nfqws2 --lua-desync=… args (or pick from the catalog)'
			});
			stratInput.value = p.strategy || '';
			stratInput.addEventListener('change', function() {
				p.strategy = String(stratInput.value || '').trim();
				saveComposeDraft();
				renderCompProfiles();
			});

			const hint = E('div', { 'class': 'wiz-note', 'style': 'margin:0' }, [ '' ]);
			const eng = p.engine || 'zapret';
			const res = p.resource || 'general';
			let hintText;
			if (res === 'general')
				hintText = _('Catch-all — keep it last; unmatched traffic lands here.');
			else if (res === 'custom')
				hintText = _('Exact domains from your list; a general profile must follow.');
			else if (eng === 'byedpi')
				hintText = _('Exact domains, TCP only (SNI in TLS-CHello/HTTP); QUIC/UDP is not scoped.');
			else
				hintText = _('Limited to the resource domains (--hostlist-domains).');
			hint.appendChild(E('span', { 'style': 'opacity:.7' }, [ hintText ]));
			/* ч.109 (user report): the picked catalog strategy must show its
			 * NAME — the raw args alone read like noise. The name is resolved
			 * from the corpus by the args, so a page reload keeps it too. */
			if (eng === 'zapret' && p.strategy) {
				const cand = compCandidateByArgs(p.strategy);
				hint.appendChild(document.createTextNode(' · '));
				hint.appendChild(E('span', { 'style': 'font-weight:600' },
					[ cand ? cand.name : _('Custom args (not in the catalog)') ]));
				hint.appendChild(document.createTextNode(' · '));
				hint.appendChild(E('span', { 'style': 'opacity:.7' },
					[ fuzzHintText(cand) ]));
			}

			const rm = E('button', { 'class': 'btn cbi-button', type: 'button',
				'style': 'padding:0 6px', title: _('Remove') }, [ '×' ]);
			rm.addEventListener('click', function() {
				state.compProfiles.splice(idx, 1);
				saveComposeDraft();
				renderCompProfiles();
			});

			const row = E('div', { 'class': 'wiz-row', 'style': 'align-items:flex-start;margin:3px 0' });
			row.appendChild(E('b', { style: 'min-width:20px;opacity:.6' }, [ '#' + (idx + 1) ]));
			row.appendChild(engSel);
			row.appendChild(resSel);
			if (res === 'custom')
				row.appendChild(domInput);
			if (eng === 'zapret')
				row.appendChild(stratSel);
			row.appendChild(stratInput);
			row.appendChild(rm);
			return E('div', { style: 'margin:2px 0' }, [
				row,
				E('div', { style: 'margin-left:22px' }, [ hint ])
			]);
		}

		function renderCompProfiles() {
			compRowsBox.innerHTML = '';
			if (state.compSaveError)
				compRowsBox.appendChild(E('div', { 'class': 'hpui-banner', style: 'margin:0 0 4px 0' },
					[ _('Saving the composition draft failed: %s — the builder still works, the draft just will not survive a reload.').format(state.compSaveError) ]));
			if (!state.compProfiles.length) {
				compRowsBox.appendChild(E('span', { 'style': 'opacity:.6' },
					[ _('(empty — add a profile)') ]));
				return;
			}
			for (let i = 0; i < state.compProfiles.length; i++)
				compRowsBox.appendChild(buildCompRow(state.compProfiles[i], i));
		}
		renderCompProfiles();

		compAddBtn.addEventListener('click', function() {
			if (state.compProfiles.length >= 8) {
				ui.addNotification(null, E('p', {}, _('Too many profiles (max 8).')), 'error');
				return;
			}
			state.compProfiles.push({ engine: 'zapret', resource: 'youtube', domains: '', strategy: '' });
			saveComposeDraft();
			renderCompProfiles();
		});

		compClearBtn.addEventListener('click', function() {
			state.compProfiles = [];
			saveComposeDraft();
			renderCompProfiles();
		});

		/* ч.109: the composition draft persists on the SERVER (survives page
		 * reloads and reboots — «выбранная композиция пропадает» fixed). The
		 * save is fire-and-forget: edits are user-rate, failures surface in
		 * the next dpi poll as a hint. */
		function saveComposeDraft() {
			state.compDirty = true;
			/* profiles cross as a JSON-encoded STRING (issue #11). */
			L.resolveDefault(callComposeSave(JSON.stringify(state.compProfiles)), {}).then(function(r) {
				if (r && r.result === false)
					state.compSaveError = (r && r.error) || _('rpc error');
				else
					state.compSaveError = null;
			});
		}

		/* Seed the builder once from the server draft (first dpi poll): the
		 * user's saved profiles beat the empty default; nothing overwrites
		 * unsaved local edits (compDirty). */
		function seedCompProfiles(server) {
			if (state.compSeeded || state.compDirty || !server || !server.length)
				return;
			state.compSeeded = true;
			const arr = [];
			for (let i = 0; i < server.length; i++) {
				const p = server[i];
				if (p && (p.engine === 'zapret' || p.engine === 'byedpi'))
					arr.push({
						engine: p.engine, resource: p.resource || 'general',
						domains: '' + (p.domains || ''), strategy: '' + (p.strategy || '')
					});
			}
			if (arr.length) {
				state.compProfiles = arr;
				renderCompProfiles();
			}
		}

		compTestBtn.addEventListener('click', function() {
			if (!state.compProfiles.length) {
				ui.addNotification(null, E('p', {}, _('Composition is empty — add at least one profile.')), 'error');
				return;
			}
			compTestBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Building and testing the composition on the router…') ]));
			/* profiles cross as a JSON-encoded STRING (issue #11). */
			L.resolveDefault(callComposeRun(JSON.stringify(state.compProfiles)), {}).then(function(r) {
				compTestBtn.disabled = false;
				if (!r || r.result === false) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Compose failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				state.compBuilt = { zapret: r.zapret || '', byedpi: r.byedpi || '' };
				/* The compose status poll (renderCompose) takes over the
				 * result area: stage progress first, then the final table. */
			});
		});

		compApplyBtn.addEventListener('click', function() {
			const cb = state.compBuilt || {};
			if (!cb.zapret && !cb.byedpi) {
				ui.addNotification(null, E('p', {},
					_('Run "Test composition" first — Apply uses the server-built args.')), 'error');
				return;
			}
			compApplyBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Applying composition — the service restarts…') ]));
			L.resolveDefault(callComposeApply(cb.zapret || '', cb.byedpi || ''), {}).then(function(r) {
				compApplyBtn.disabled = false;
				if (!r || r.result === false) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				const box = E('div', {});
				box.appendChild(E('p', { 'class': 'hpui-hint' },
					[ _('Composition applied — the engine(s) are enabled and the service restarts.') ]));
				const rbBtn = E('button', { 'class': 'btn cbi-button', type: 'button' },
					[ _('Restore previous') ]);
				rbBtn.addEventListener('click', function() {
					rbBtn.disabled = true;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Restoring the previous strategies — the service restarts…') ]));
					L.resolveDefault(callComposeRollback(), {}).then(function(r2) {
						rbBtn.disabled = false;
						if (!r2 || r2.result === false) {
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('Restore failed: ') + ((r2 && r2.error) || _('rpc error')) ]));
							return;
						}
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Previous strategies restored — the service restarts.') ]));
					});
				});
				box.appendChild(rbBtn);
				box.appendChild(E('p', { 'class': 'hpui-hint' },
					[ _('The same Restore stays available below and after a page reload (server snapshot).') ]));
				dom.content(dpiResult, box);
			});
		});

		/* Compose status poll: progress while running, the final result table
		 * once — sig-guarded, and the FIRST seen "done" is seeded (lesson 71:
		 * a stale result from before the page load must not render as fresh). */
		function renderCompose(data) {
			const st = (data && data.status) || null;
			if (!st) return;
			if (st.running) {
				state.composeSig = 'run';
				const txt = (st.stage === 'zapret') ? _('Testing the Zapret part (isolated queue)…')
					: (st.stage === 'byedpi') ? _('Testing the ByeDPI part (local tester)…')
					: _('Building and testing the composition on the router…');
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ txt ]));
				return;
			}
			const sig = 'done:' + (st.ts || 0);
			if (!state.composeSeeded) {
				state.composeSeeded = true;
				state.composeSig = sig;
				return;
			}
			if (sig === state.composeSig)
				return;
			if (st.stage !== 'done' && st.stage !== 'error')
				return;
			state.composeSig = sig;
			const box = E('div', {});
			if (st.stage === 'error') {
				box.appendChild(E('p', { 'class': 'hpui-hint' }, [ (st.error || _('rpc error')) ]));
				dom.content(dpiResult, box);
				return;
			}
			box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
				[ _('Composition test results') ]));
			(st.notes || []).forEach(function(n) {
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [ '· ' + n ]));
			});
			const zt = st.zapret || {};
			if (zt.args) {
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'margin-top:4px' },
					[ _('Zapret part (isolated queue):') ]));
				const t = zt.test;
				if (!t || t.error) {
					box.appendChild(E('div', { 'class': 'wiz-note' },
						[ (t && t.error) || _('no test data') ]));
				} else {
					const row = E('div', { 'class': 'wiz-row' });
					(t.results || []).forEach(function(r2, i) {
						if (i) row.appendChild(document.createTextNode(' · '));
						row.appendChild(E('span', {
							style: 'font-weight:600;color:' + (r2.ok ? 'var(--hp-accent-strong)' : 'var(--hp-red)')
						}, [ (r2.label || r2.tag) + (r2.ok ? ' ✓ ' + r2.tls + 's' : ' ✗ ' + (r2.reason || 'fail')) ]));
					});
					row.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ '(' + (t.ok || 0) + '/' + (t.total || 0) + ')' ]));
					box.appendChild(row);
				}
			}
			const bt = st.byedpi || {};
			if (bt.args) {
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'margin-top:4px' },
					[ _('ByeDPI part (local tester):') ]));
				const t = bt.test;
				if (!t || t.error) {
					box.appendChild(E('div', { 'class': 'wiz-note' },
						[ (t && t.error) || _('no test data') ]));
				} else {
					const row = E('div', { 'class': 'wiz-row' });
					(t.results || []).forEach(function(r2, i) {
						if (i) row.appendChild(document.createTextNode(' · '));
						row.appendChild(E('span', {
							style: 'font-weight:600;color:' + (r2.ok ? 'var(--hp-accent-strong)' : 'var(--hp-red)')
						}, [ (r2.label || r2.tag) + (r2.ok ? ' ✓ ' + (r2.tls || '') + 's' : ' ✗ ' + (r2.reason || 'fail')) ]));
					});
					row.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ '(' + (t.passed || 0) + '/' + (t.total || 0) + ')' ]));
					box.appendChild(row);
				}
			}
			box.appendChild(E('details', { style: 'margin-top:4px' }, [
				E('summary', { style: 'cursor:pointer' }, [ _('Built args') ]),
				E('pre', { style: 'white-space:pre-wrap;margin:4px 0 0 12px;font-size:.85em' },
					[ ((zt.args ? ('Zapret: ' + zt.args + '\n') : '') + (bt.args ? ('ByeDPI: ' + bt.args) : '')).trim() ])
			]));
			box.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('Press "Apply composition" to activate the tested args.') ]));
			dom.content(dpiResult, box);
		}

		/* Persistent Restore row — rendered ONLY from the server snapshot
		 * (wizard_dpi_status.rollback), so it survives page reloads and also
		 * covers plain strategy applies. */
		function renderRollback(prev) {
			const sig = prev ? JSON.stringify([ prev.ts || 0,
				prev.zapret && prev.zapret.cmd_opts, prev.zapret && prev.zapret.enabled,
				prev.byedpi && prev.byedpi.cmd_opts, prev.byedpi && prev.byedpi.enabled ]) : 'none';
			if (sig === state.rbSig)
				return;
			state.rbSig = sig;
			restoreRow.innerHTML = '';
			if (!prev || !prev.ts) {
				restoreRow.appendChild(E('span', { 'style': 'opacity:.6' },
					[ _('No server snapshot yet — apply a strategy or a composition first.') ]));
				return;
			}
			const when = new Date(Number(prev.ts) * 1000).toLocaleString();
			const zopts = (prev.zapret && prev.zapret.cmd_opts) || '';
			const bopts = (prev.byedpi && prev.byedpi.cmd_opts) || '';
			const sum = E('span', { title: ((zopts ? 'Zapret: ' + zopts + '\n' : '') +
				(bopts ? 'ByeDPI: ' + bopts : '')).trim() },
				[ shortStrategy(zopts || bopts || _('(disabled)'), 80) ]);
			restoreRow.appendChild(document.createTextNode(_('Server snapshot (%s): ').format(when)));
			restoreRow.appendChild(sum);
			const rb = E('button', { 'class': 'btn cbi-button', type: 'button', 'style': 'margin-left:8px' },
				[ _('Restore') ]);
			rb.addEventListener('click', function() {
				rb.disabled = true;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Restoring the previous strategies — the service restarts…') ]));
				L.resolveDefault(callComposeRollback(), {}).then(function(r) {
					rb.disabled = false;
					if (!r || r.result === false) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Restore failed: ') + ((r && r.error) || _('rpc error')) ]));
						return;
					}
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Previous strategies restored — the service restarts.') ]));
				});
			});
			restoreRow.appendChild(rb);
		}

		/* Strategy Lab — the ported panel (node.js): quick/full fuzz buttons,
		 * rounds, live progress. ч.109: the RANKING lives in its own
		 * persistent block (labBest — it never disappears when an action
		 * result renders); action results stay in dpiResult (ONE place). */
		const labRounds = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto' });
		for (const n of [ 1, 2, 3 ]) {
			const op = E('option', { value: String(n), selected: (n === 2) ? '' : null },
				_('%d round(s)').format(n));
			labRounds.appendChild(op);
		}
		const labStatus = E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ '' ]);
		const labBest = E('div', { style: 'margin-top:6px' });
		const labHist = E('div', {});
		const labRow = E('div', { 'class': 'wiz-row' });
		const labQuick = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' }, [ _('Fuzz (quick)') ]);
		const labFull = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Full fuzz') ]);
		labRow.appendChild(labQuick);
		labRow.appendChild(labFull);
		labRow.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ _('Rounds') ]));
		labRow.appendChild(labRounds);
		labRow.appendChild(labStatus);
		dpiLab.appendChild(labRow);
		dpiLab.appendChild(E('div', { 'class': 'wiz-note', style: 'margin:4px 0 0 0; font-weight:600' },
			[ _('Best strategies (last fuzz)') ]));
		dpiLab.appendChild(labBest);
		dpiLab.appendChild(labHist);
		dpiLab.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('The fuzzer batch-tests every strategy from the catalog on an isolated NFQUEUE (YouTube / Telegram / Discord / Speedtest TLS handshakes), then deep-checks the best strategy of EVERY technique family (multisplit, disorder, hostfakesplit, fakesplit, syndata, …), the best imported/generated strategies and your CURRENT strategy with REAL content fetches — measuring the fresh-connection start (the hover-preview latency, median of several fresh connections) and the sustained video flow in KB/s (a handshake cannot see TSPU throttling). The ranking: a >25% better start wins first, then a >10% better flow, then the handshake — a fast bulk with a slow start loses. Probes that all deep-tested strategies pass or fail identically do not rank (non-differential): the Resource loads column then shows ≈ with the raw pass count. A no-desync baseline marks hosts your ISP does not block; each host must pass the majority of rounds. Live traffic is untouched. A quick sweep takes ~15–30 minutes; a full one scales with the corpus (the label above computes it).') ]));

		let labPollId = null;
		function labStopPoll() { if (labPollId) { window.clearInterval(labPollId); labPollId = null; } }
		function labStartPoll() {
			if (labPollId) return;
			/* window.setInterval survives view teardown (unlike poll.add) — the
			 * tick self-cancels once the element is detached (user left the
			 * page), otherwise it would keep 10 RPCs/5 s forever. */
			labPollId = window.setInterval(function() {
				if (!labStatus || !labStatus.isConnected) { labStopPoll(); return; }
				refresh();
			}, 5000);
		}

		function renderLab(r, dpiSt) {
			const st = (r && r.status) || {};
			const res = (r && r.result) || null;
			const hist = (r && r.history && r.history.runs) || [];
			if (st.running) {
				labStatus.textContent = (st.stage === 'deep')
					? _('Deep-checking the top strategies (page/CDN/media fetches)… %d of %d').format(st.done2 || 0, st.total2 || 0)
					: _('Fuzzing… %d of %d').format(st.done || 0, st.total || 0) +
						(st.current ? (' · ' + st.current) : '');
				labStartPoll();
				return;
			}
			labStopPoll();
			if (st.error) {
				labStatus.textContent = _('Fuzz failed: %s').format(st.error);
				return;
			} else
				labStatus.textContent = '';
			/* Result table — ч.109: lives in its OWN persistent container
			 * (labBest) instead of the shared result area. Picking a strategy
			 * used to WIPE the ranking (the user complaint) — now the action
			 * result goes to dpiResult (ONE place) while the table stays and
			 * the picked row is marked. */
			const sig = res ? ('' + (res.ts || 0)) : 'none';
			if (sig === state.fuzzShownSig)
				return;
			state.fuzzShownSig = sig;
			labBest.innerHTML = '';
			if (!res || !res.strategies || !res.strategies.length) {
				labBest.appendChild(E('span', { 'class': 'wiz-note', style: 'opacity:.6' },
					[ _('No fuzz ranking yet — run the fuzzer above; the ranked list stays here until the next run.') ]));
				return;
			}
			const box = E('div', {});
			const bl = res.baseline || [];
			const blParts = bl.map(function(b2) { return (b2.label || b2.tag) + ' ' + (b2.ok ? '✓' : '✗'); });
			const blFree = bl.filter(function(b2) { return b2.ok; }).map(function(b2) { return (b2.label || b2.tag); });
			box.appendChild(E('div', { 'class': 'wiz-note' }, [
				_('Baseline (no desync):') + ' ' + blParts.join(' · ') +
				(blFree.length ? ' — ' + _('%s pass without a strategy (free pass, not measured).').format(blFree.join(', ')) : '')
			]));
			const best = res.strategies[0];
			if (best && best.ok > 0)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
					[ _('Recommended: %s — %d of %d distinguishing hosts pass (avg %d ms)').format(
						best.name, best.dist_ok || 0, best.dist_total || 0, best.avg_tls_ms || 0) ]));
			else
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
					[ _('No strategy passes the distinguishing hosts — try the full fuzz, the strategy generator, or check your ISP blocking.') ]));
			/* ч.123: the sweep-level QUIC verdict — measured UDP/443
			 * passability to the YouTube video edge, once per sweep. */
			if (res.quic && res.quic.verdict != null) {
				const qv = '' + res.quic.verdict;
				const qtxt = (qv === 'vn')
					? _('QUIC (UDP 443) to the YouTube video edge is OPEN (measured) — the browser may pick QUIC for some flows; strategies without fake-QUIC leave those attempts unserved.')
					: (qv === 'icmp')
						? _('QUIC (UDP 443) to the YouTube video edge is REJECTED (measured) — the browser falls back to TCP quickly; TCP-only strategies serve the whole resource.')
						: _('QUIC (UDP 443) to the YouTube video edge gets NO answer (measured) — typically a silent provider cut; the browser falls back to TCP, TCP-only strategies serve the whole resource.');
				box.appendChild(E('div', { 'class': 'wiz-note', title: 'probe_pool -quic-check (Version Negotiation, UDP/443)' },
					[ (qv === 'vn')
						? badge('hpui-b-green', 'QUIC: open')
						: badge('hpui-b-red', 'QUIC: ' + qv),
					  ' ' + qtxt ]));
			}
			/* ч.123: the honest duration line — the corpus size decides. */
			box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' },
				[ _('This sweep: %d strategies — the deep battery measured %d of %d selected (family-diverse leaders, the best imported/generated strategies and your current strategy). A quick sweep takes ~%d min, a full one ~%d min on this corpus.').format(
					res.total || res.strategies.length, res.deep_count || 0,
					res.deep_selected || res.deep_count || 0,
					fuzzEtaMin(13), fuzzEtaMin(res.total || res.strategies.length)) ]));
			if (res.deep_failed && res.deep_failed.length)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.75' },
					[ _('Deep check failed (retried once, no verdict): %s — these strategies rank as untested.').format(res.deep_failed.join(', ')) ]));
			const thead = E('thead', {}, E('tr', {}, [
				E('th', {}, [ '#' ]),
				E('th', {}, [ _('Strategy') ]),
				E('th', {}, [ _('Passed') ]),
				E('th', {}, [ _('Avg TLS, ms') ]),
				E('th', { title: _('The sustained video-flow speed measured in the deep battery (KB/s through the configured path) — a fast handshake does not predict a fast flow.') },
					[ _('Flow, KB/s') ]),
				E('th', { title: _('The fresh-connection START latency (the hover-preview experience): the median time-to-first-byte of fresh connections measured in the deep battery. A >25% better start outranks a better bulk flow.') },
					[ _('Start, ms') ]),
				E('th', {}, [ _('Resource loads') ]),
				E('th', {}, [ _('Apply for') ])
			]));
			/* ч.123: the current strategy's OWN measured flow — the honest
			 * comparison point for the «быстрее текущей» hint. */
			const curArgs = dpiSt && dpiSt.zapret ? ('' + (dpiSt.zapret.strategy || '')) : '';
			const curRow = (curArgs && res.strategies.filter(function(x) { return x.args === curArgs; })[0]) || null;
			const curStream = (curRow && Number(curRow.stream || 0)) || 0;
			const tbody = E('tbody', {});
			res.strategies.slice(0, 15).forEach(function(s, i) {
				const hostsTip = (s.hosts || []).map(function(h) {
					return (h.label || h.tag) + ' ' +
						(h.ok ? '✓ ' + h.votes + '/' + h.rounds + ' · ' + (h.tls_ms || 0) + ' ms'
						      : '✗ ' + (h.reason || 'fail')) +
						(h.dist ? '' : ' (' + _('free pass') + ')');
				}).join(' · ');
				/* ч.109 (user request): pick THIS strategy for ONE resource —
				 * the rule/apply/verify chain of the auto-pick runs for the
				 * chosen resource with the table's strategy (no re-fuzz). */
				const resSel = E('select', { 'class': 'cbi-input-select',
					'style': 'width:auto; font-size:.85em; padding:0' });
				resSel.appendChild(E('option', { value: '' }, [ _('— whole Zapret —') ]));
				[ ['youtube', _('YouTube')], ['discord', _('Discord')],
				  ['telegram', _('Telegram')], ['general', _('General')] ]
					.forEach(function(o) { resSel.appendChild(E('option', { value: o[0] }, [ o[1] ])); });
				const ab = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'style': 'font-size:.82em; padding:0 8px' },
					[ _('Apply') ]);
				ab.addEventListener('click', function() {
					const target = resSel.value;
					const targetLabel = resSel.options[resSel.selectedIndex].text;
					if (!target) {
						if (!window.confirm(_('Apply this Zapret strategy globally (every flow routed to Zapret) and restart the service?')))
							return;
						ab.disabled = true;
						L.resolveDefault(callFuzzApply(s.args), {}).then(function(r2) {
							ab.disabled = false;
							ab.textContent = (r2 && r2.result) ? '✓' : '✗';
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ r2 && r2.result
								? _('Strategy applied — the service restarts; run "Test strategy" in ~30 s to confirm.')
								: ((r2 && r2.error) || _('Apply failed')) ]));
						});
						return;
					}
					if (!window.confirm(_('Apply this strategy for %s: a SCOPED profile is built (other managed resources keep their strategies), the rule goes to Zapret, then the resource is checked live — page, CDN and the REAL video stream. Continue?').format(targetLabel)))
						return;
					ab.disabled = true;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Applying %s for %s — progress below…').format(s.name || _('custom args'), targetLabel) ]));
					/* set_rule crosses as a STRING (issue #11). */
					L.resolveDefault(callAutoPickStart(target, 'quick', '1', s.args), {}).then(function(r2) {
						ab.disabled = false;
						if (!r2 || r2.result !== true) {
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('Auto-pick failed to start: %s').format((r2 && r2.error) || _('rpc error')) ]));
							return;
						}
						refresh();
					});
				});
				/* ч.109: the deep verdict — did the resource LOAD (page/CDN/
				 * media fetches), not only the handshake. ч.117: a fully
				 * NON-DIFFERENTIAL battery (every probe passes or fails
				 * identically on all deep-tested strategies — live run: all
				 * 5 passed the whole YouTube battery) leaves the differential
				 * counters at 0/0; the RAW fetches still say whether the
				 * resource loads, so the cell shows an honest '≈' verdict
				 * (identical for everyone, not ranked) instead of the old red
				 * '✗ 0/0' or a bare '—'. */
				let deepTd;
				if (s.deep) {
					const dhosts = s.deep.hosts || [];
					let rawOk = 0, rawTot = 0;
					dhosts.forEach(function(hd) {
						(hd.items || []).forEach(function(it) {
							rawTot++;
							if (it.ok == 1) rawOk++;
						});
					});
					deepTd = E('td', { style: 'white-space:nowrap',
						title: dhosts.map(function(hd) {
							const items = hd.items || [];
							const hAll = items.length && items.every(function(it) { return it.ok == 1; });
							return (hd.label || hd.tag) + ': ' +
								(hd.deep_total > 0
									? ((hd.deep_pass || 0) + '/' + hd.deep_total + (hd.deep_ok ? ' ✓' : ' ✗'))
									: ((hAll ? '✓ loads' : '✗ stalled') + ' (' + _('identical for all') + ')')) +
								(items.length ? ' — ' + items.map(function(it) {
									return (it.code || '000') +
										(it.bytes > 0 ? ('/' + Math.round(it.bytes / 1024) + 'KB') : '') +
										(it.speed > 0 ? ('@' + Math.round(it.speed / 1024) + 'KB/s') : '');
								}).join(', ') : '');
						}).join(' · ') },
						[ (s.deep.total > 0)
							? (((s.deep.ok === s.deep.total) && s.deep.total > 0)
								? E('span', { style: 'color:var(--hp-accent-strong); font-weight:600' }, [ '✓ ' + s.deep.ok + '/' + s.deep.total ])
								: E('span', { style: 'color:var(--hp-red); font-weight:600' }, [ '△ ' + s.deep.ok + '/' + s.deep.total ]))
							: ((rawTot > 0)
								? ((rawOk === rawTot)
									? E('span', { style: 'color:var(--hp-accent-strong); font-weight:600' }, [ '≈ ' + rawOk + '/' + rawTot ])
									: E('span', { style: 'color:var(--hp-grey); font-weight:600' }, [ '≈ ' + rawOk + '/' + rawTot ]))
								: E('span', { style: 'opacity:.5' }, [ '—' ])) ]);
				}
				else
					deepTd = E('td', { style: 'opacity:.5' }, [ '—' ]);
				/* ч.123: QUIC badge (TCP-only vs QUIC-capable) + the MEASURED
				 * flow column — the metric the user actually feels (a fast
				 * handshake does not predict a fast flow, ч.116). A row whose
				 * flow beats the currently applied strategy by >25% is marked
				 * honestly (the auto-pilot uses the same margin). */
				const quicCapable = /--filter-udp=443/.test(s.args || '');
				const flowKb = Math.round((s.stream || 0) / 1024);
				const flowParts = [];
				if (flowKb > 0) {
					flowParts.push(flowKb + ' KB/s');
					const curKb = Math.round(curStream / 1024);
					if (curKb > 0 && s.args !== curArgs && flowKb > Math.round(curKb * 1.25))
						flowParts.push(_('↑ +%d KB/s vs current').format(flowKb - curKb));
				}
				/* ч.127: the fresh-connection START latency — the hover-preview
				 * experience the user pointed at. ч.129: a FIRST-CLASS column
				 * (the ranking: START >25% decides first, then the flow). */
				const startMs = Number(s.start_ms || 0);
				const startTd = E('td', { style: 'white-space:nowrap' },
					(startMs > 0)
						? [ E('span', { style: 'color:var(--hp-accent-strong); font-weight:600',
							title: _('fresh-connection start ~%d ms (hover-preview latency)').format(startMs) },
							[ String(startMs) ]) ]
						: [ E('span', { style: 'opacity:.35' }, [ '—' ]) ]);
				const flowTd = E('td', {
					style: 'white-space:nowrap',
					title: (startMs > 0) ? _('fresh-connection start ~%d ms (hover-preview latency)').format(startMs) : ''
				}, (flowParts.length)
					? [ E('span', { style: 'color:var(--hp-accent-strong); font-weight:600' }, [ flowParts.join(' ') ]) ]
					: [ E('span', { style: 'opacity:.35' }, [ '—' ]) ]);
				const row = E('tr', { 'data-fuzz-args': s.args }, [
					E('td', { style: 'opacity:.7' }, [ String(i + 1) ]),
					E('td', { style: 'font-size:.85em; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap', title: (s.args + ' — ' + hostsTip) },
						[ s.name || s.args, ' ',
						  quicCapable
							? badge('hpui-b-green', 'QUIC')
							: E('span', { 'class': 'hpui-badge', style: 'opacity:.7' }, [ 'TCP' ]) ]),
					E('td', { style: 'white-space:nowrap' }, [ '%d / %d'.format(s.ok || 0, s.total || 0) ]),
					E('td', {}, [ String(s.avg_tls_ms || 0) ]),
					flowTd,
					startTd,
					deepTd,
					E('td', { style: 'white-space:nowrap' }, [ resSel, ' ', ab ])
				]);
				tbody.appendChild(row);
			});
			const wrap = E('div', { 'class': 'hpui-wrap' });
			wrap.appendChild(E('table', { 'class': 'hpui-table' }, [ thead, tbody ]));
			box.appendChild(wrap);
			labBest.appendChild(box);
			/* History — persistent info under the Lab row. */
			labHist.innerHTML = '';
			if (hist.length) {
				const rows = hist.slice(-5).reverse().map(function(h) {
					const d = new Date(Number(h.ts) * 1000);
					const fmt = ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ' ' + d.toLocaleDateString();
					return E('div', { style: 'margin:1px 0' }, [
						fmt + ' · ' + (h.mode || '?') + ' · ' + _('%d round(s)').format(h.rounds || 2) +
						(h.best && h.best.name
							? ' → ' + _('winner: %s (%d/%d, distinguishing %d/%d)')
								.format(h.best.name, h.best.ok, h.best.total, h.best.dist_ok, h.best.dist_total)
							: '')
					]);
				});
				labHist.appendChild(E('details', {}, [
					E('summary', { style: 'cursor:pointer' }, [ _('Last runs') ]),
					E('div', { style: 'margin:4px 0 0 12px' }, rows)
				]));
			}
		}

		const labStart = function(mode) {
			labStatus.textContent = _('Starting…');
			L.resolveDefault(callFuzzStart(mode, labRounds.value || '2'), {}).then(function(r) {
				if (!r || r.result === false) {
					labStatus.textContent = (r && r.error) || _('rpc error');
					return;
				}
				refresh();
			});
		};
		labQuick.addEventListener('click', function() { labStart('quick'); });
		labFull.addEventListener('click', function() {
			if (!window.confirm(_('Run the FULL strategy sweep? Every candidate is measured in turn (temp NFQUEUE, live traffic untouched) — this takes up to ~15 minutes.')))
				return;
			labStart('full');
		});

		/* Auto-tune (Ф8-F7 T3): ONE click — fuzz (reused when fresh) → best
		 * strategy for the resource → optional rule → apply with the server
		 * snapshot → live check of the configured path. Progress and the
		 * result render into dpiResult (ONE place). */
		const autSel = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto' });
		[ ['youtube', _('YouTube')], ['discord', _('Discord')],
		  ['telegram', _('Telegram')], ['general', _('General (best overall)')] ]
			.forEach(function(o) { autSel.appendChild(E('option', { value: o[0] }, [ o[1] ])); });
		const autFull = E('input', { type: 'checkbox' });
		/* ч.123: honest sweep duration — computed from the corpus size
		 * (resolve+baseline + strategies×rounds×~55 s + the deep tail), the
		 * old «up to ~15 min» hid how long a FULL sweep really takes. */
		function fuzzEtaMin(total) {
			return Math.max(5, Math.ceil((60 + total * 2 * 55 + 600) / 60));
		}
		const autFullTxt = E('span', {}, [ '' ]);
		autFullTxt.textContent = _('Thorough (full corpus, ~%d min)').format(fuzzEtaMin(13));
		const autSetRule = E('input', { type: 'checkbox', checked: '' });
		const autSetRuleWrap = E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
			[ autSetRule, ' ' + _('Also set the rule to Zapret (the strategy serves the resource through its rule)') ]);
		const autFullWrap = E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
			[ autFull, ' ', autFullTxt ]);
		const autStatus = E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ '' ]);
		const autBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Auto-pick strategy') ]);
		const autRow = E('div', { 'class': 'wiz-row' },
			[ autBtn, autSel, autFullWrap, autSetRuleWrap, autStatus ]);
		dpiPanes.dpiAp.appendChild(autRow);
		dpiPanes.dpiAp.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('One click: the fuzzer ranks the corpus (reused when fresh), the best strategy for the resource is applied as a scoped profile with a server snapshot, and the resource is then checked through the configured path (page, CDN, the REAL video stream in KB/s). Zapret only — ByeDPI strategies are configured on the Manual & compositions tab.') ]));
		autSel.addEventListener('change', function() {
			autSetRuleWrap.style.display = (autSel.value === 'general') ? 'none' : '';
		});
		autBtn.addEventListener('click', function() {
			const resource = autSel.value;
			const mode = autFull.checked ? 'full' : 'quick';
			const eta = fuzzEtaMin(state.cands && state.cands.length ? state.cands.length : 87);
			const what = (mode === 'full')
				? _('Auto-pick the best strategy for %s? This may first run the FULL fuzz (~%d min), then applies the winner with a server snapshot (Restore stays available) and checks the resource live.').format(autSel.options[autSel.selectedIndex].text, eta)
				: _('Auto-pick the best strategy for %s? It uses the recent fuzz ranking (or runs a quick fuzz first), applies the winner with a server snapshot (Restore stays available) and checks the resource live.');
			if (!window.confirm(what.format(autSel.options[autSel.selectedIndex].text)))
				return;
			autBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Starting the auto-pick…') ]));
				/* set_rule crosses as a STRING (issue #11). */
				L.resolveDefault(callAutoPickStart(resource, mode, autSetRule.checked ? '1' : '0'), {}).then(function(r) {
				autBtn.disabled = false;
				if (!r || r.result !== true) {
					const emsg = (r && r.error === 'rules_mode')
						? _('Routing rules apply ONLY in "Bypass blocking" mode — the rule cannot be set here.')
						: ((r && r.error) || _('rpc error'));
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Auto-pick failed to start: %s').format(emsg) ]));
					return;
				}
				autStatus.textContent = _('Auto-pick started — the progress shows up in one place below.');
				refresh();
			});
		});

		/* ── ч.97: strategy auto-pilot (scheduled) — the keeper mode ─────
		 * Configures itself from the corpus: a scheduled re-rank rebuilds the
		 * per-resource composition; failed health probes re-pick immediately.
		 * Settings save through wizard_autopilot_set; the daemon hot-reads
		 * them every tick (no service restart). */
		const apRes = { youtube: E('input', { type: 'checkbox' }),
			discord: E('input', { type: 'checkbox' }),
			telegram: E('input', { type: 'checkbox' }),
			general: E('input', { type: 'checkbox' }) };
		const apEnabled = E('input', { type: 'checkbox' });
		const apRules = E('input', { type: 'checkbox', checked: '' });
		const apMode = E('select', { 'class': 'cbi-input-select', style: 'width:auto' });
		[ ['quick', _('Quick fuzz')], ['full', _('Full fuzz')] ]
			.forEach(function(o) { apMode.appendChild(E('option', { value: o[0] }, [ o[1] ])); });
		const apInterval = E('input', { type: 'number', min: '1', max: '168', 'class': 'cbi-input-text', style: 'width:70px', value: '6' });
		const apCheck = E('input', { type: 'number', min: '5', max: '180', 'class': 'cbi-input-text', style: 'width:70px', value: '15' });
		const apWin = E('input', { type: 'text', 'class': 'cbi-input-text', style: 'width:150px',
			placeholder: _('empty — any time') });
		const apSave = E('button', { 'class': 'btn cbi-button cbi-button-apply', type: 'button' }, [ _('Save auto-pilot') ]);
		const apAlive = E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ '' ]);
		const apNames = { youtube: _('YouTube'), discord: _('Discord'),
			telegram: _('Telegram'), general: _('General (best overall)') };
		const apStatus = E('div', {});
		const apHead = E('div', { 'class': 'wiz-row', style: 'margin-top:8px' },
			[ E('strong', {}, [ _('Auto-pilot (scheduled)') ]), apAlive ]);
		const apRow1 = E('div', { 'class': 'wiz-row' },
			[ E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer; font-weight:600' },
				[ apEnabled, ' ' + _('Enable the auto-pilot') ]), apSave ]);
		const apResWrap = E('div', { 'class': 'wiz-row' });
		/* The Telegram checkbox is the frequent confusion (issue feedback):
		 * a Zapret strategy serves a resource ONLY through its rule → Zapret,
		 * and Telegram is served by the tg-ws bridge whenever it is enabled. */
		const apHints = {
			telegram: _('A Zapret strategy serves Telegram only when its rule leads to Zapret. With the tg-ws bridge Telegram is served by the bridge and the auto-pilot leaves it alone — the checkbox can stay off. Without the bridge it works the same way as for YouTube, which only helps where the provider\'s Telegram block is DPI-shaped rather than a hard cut.')
		};
		[ ['youtube', _('YouTube')], ['discord', _('Discord')],
		  ['telegram', _('Telegram')], ['general', _('General (best overall)')] ]
			.forEach(function(o) {
				apResWrap.appendChild(E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer',
					title: apHints[o[0]] || '' },
					[ apRes[o[0]], ' ' + o[1] ]));
			});
		const apRow3 = E('div', { 'class': 'wiz-row' },
			[ E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
				[ apRules, ' ' + _('Keep the rules on Zapret') ]),
			  apMode,
			  E('label', { 'class': 'wiz-note', style: 'margin:0' }, [ _('Re-rank every') ]),
			  apInterval, E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ 'h' ]),
			  E('label', { 'class': 'wiz-note', style: 'margin:0' }, [ _('check every') ]),
			  apCheck, E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ 'min' ]),
			  E('label', { 'class': 'wiz-note', style: 'margin:0' }, [ _('apply in window') ]),
			  apWin ]);
		dpiPanes.dpiAp.appendChild(E('div', { style: 'margin-top:14px; border-top:1px solid var(--hp-panel-line); padding-top:8px' },
			[ apHead, apRow1, apResWrap, apRow3, E('p', { 'class': 'wiz-note' },
				[ _('The auto-pilot keeps the strategies working without attention: on schedule it re-ranks the corpus and applies the best strategy per resource (a >10% win replaces the current one); when a resource fails the checks repeatedly, the next alternative applies immediately. The "apply in window" time gate applies to the scheduled re-rank only — health checks and repairs run around the clock. With "Keep the rules on Zapret" the managed resources get their rule pointed at Zapret — a strategy serves a resource only through its rule, and the Telegram rule is left alone while the tg-ws bridge serves it. Every apply takes a server snapshot — Restore always reverts. ByeDPI strategies are not managed.') ]), apStatus ]));
		let apDirty = false;
		let apSig = null;
		for (let k in apRes)
			apRes[k].addEventListener('change', function() { apDirty = true; });
		apEnabled.addEventListener('change', function() { apDirty = true; });
		apRules.addEventListener('change', function() { apDirty = true; });
		apMode.addEventListener('change', function() { apDirty = true; });
		apInterval.addEventListener('input', function() { apDirty = true; });
		apCheck.addEventListener('input', function() { apDirty = true; });
		apWin.addEventListener('input', function() { apDirty = true; });
		apSave.addEventListener('click', function() {
			const res = [];
			for (let k in apRes)
				if (apRes[k].checked)
					res.push(k);
			if (apEnabled.checked && !res.length) {
				ui.addNotification(null, E('p', {}, _('Select at least one resource for the auto-pilot.')), 'error');
				return;
			}
			const turningOn = apEnabled.checked;
			if (turningOn && !window.confirm(_('Enable the strategy auto-pilot? It will manage the Zapret strategies of the selected resources automatically (scheduled re-ranks, immediate re-picks on failures) and — with the rules option — keep their rules on Zapret.')))
				return;
			apSave.disabled = true;
			L.resolveDefault(callAutoPilotSet(
				apEnabled.checked ? '1' : '0', res.join(' '),
				apRules.checked ? '1' : '0',
				String(parseInt(apInterval.value, 10) || 6),
				String(parseInt(apCheck.value, 10) || 15),
				apWin.value || '', apMode.value || 'quick',
				'2'), {}).then(function(r) {
				apSave.disabled = false;
				if (!r || r.result !== true) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Auto-pilot save failed: %s').format((r && r.error) || _('rpc error')) ]));
					return;
				}
				apDirty = false;
				apSig = null;   /* refill from the saved config */
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ (turningOn)
						? _('Auto-pilot enabled — the daemon picks it up within a minute (first re-rank right away).')
						: _('Auto-pilot settings saved — the daemon reads them on its next tick.') ]));
				refresh();
			});
		});

		function renderAutoPilot(data) {
			const cfg = (data && data.config) || null;
			const st = (data && data.status) || null;
			const ok = !!(data && data.daemon_ok);
			apAlive.textContent = ok ? '' : '— ' + _('daemon is not responding');
			if (cfg && (apSig == null || (!apDirty && apSig !== JSON.stringify(cfg)))) {
				apSig = JSON.stringify(cfg);
				apEnabled.checked = !!cfg.enabled;
				apRules.checked = (cfg.set_rules !== false);
				apMode.value = (cfg.fuzz_mode === 'full') ? 'full' : 'quick';
				for (let k in apRes)
					apRes[k].checked = ((cfg.resources || '').split(/\s+/).indexOf(k) >= 0);
				apInterval.value = cfg.interval_h || 6;
				apCheck.value = cfg.check_min || 15;
				apWin.value = cfg.window || '';
			}
			apStatus.innerHTML = '';
			if (!ok) {
				apStatus.appendChild(E('div', { 'class': 'wiz-note' },
					[ '— ' + _('no data (the daemon is not responding)') ]));
				return;
			}
			const head = E('div', { 'class': 'wiz-row', style: 'margin-top:4px' });
			const stMap = { idle: _('idle'), watch: _('watching'), fuzz: _('re-ranking the corpus…'),
				rule: _('setting the rules…'), apply: _('applying…'), verify: _('verifying…'),
				resume: _('resuming after a restart…'), error: _('error') };
			head.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0; font-weight:600' },
				[ (st && st.enabled) ? _('active') : _('disabled'), ' · ',
				  (stMap[st && st.stage] || (st && st.stage) || '—') ]));
			if (st && st.stage_note)
				head.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0; opacity:.8' },
					[ ' · ' + st.stage_note ]));
			apStatus.appendChild(head);
			if (st && st.resources) {
				const grid = E('div', { style: 'margin:4px 0 0 12px' });
				for (let rk in apRes) {
					const r = st.resources[rk];
					if (!r)
						continue;
					const line = E('div', { 'class': 'wiz-note' });
					const w = r.winner || {};
					line.appendChild(document.createTextNode(
						apNames[rk] + ': ' + ((st.enabled && r.mgmt === false && rk !== 'general')
							? _('not managed (the rule does not lead to Zapret)')
							: (w.name || '—'))));
					if (w.name)
						line.appendChild(document.createTextNode(
							(w.tls_ms > 0 ? ' · ' + _('~%d ms TLS').format(w.tls_ms) : '') +
							(w.stream > 0 ? ' · ' + Math.round(w.stream / 1024) + ' KB/s' : '') +
							(w.start_ms > 0 ? ' · ' + _('start ~%d ms').format(w.start_ms) : '')));
					const p = r.probe || {};
					if (p && p.ts)
						line.appendChild(document.createTextNode(' '));
					if (p && p.ts) {
						/* ч.127 three-state: green = alive, amber = degraded
						 * (slow but working — NO switch happens), red = dead.
						 * The raw note carries the measured detail. */
						line.appendChild(p.ok
							? badge('hpui-b-green', '✓ ' + (p.code || '') + ((p.tsec != null) ? (' · ' + p.tsec + ' s') : ''))
							: (p.slow
								? E('span', { 'class': 'hpui-badge hpui-b-amber', title: (p.note || '') },
									[ '⚠ ' + (p.code || '') + ((p.tsec != null) ? (' · ' + p.tsec + ' s') : '') + (p.speed > 0 ? (' · ' + Math.round(p.speed / 1024) + ' KB/s') : '') ])
								: badge('hpui-b-red', '✗ ' + (p.code || '000'))));
					}
					if (r.strikes > 0)
						line.appendChild(badge('hpui-b-red', '⚠ ' + _('%d failed check(s)').format(r.strikes)));
					if (r.rule_node != null && rk !== 'general')
						line.appendChild(document.createTextNode(
							' · ' + _('rule: %s').format(r.rule_node || _('none'))));
					grid.appendChild(line);
				}
				apStatus.appendChild(grid);
			}
			const times = [];
			if (st && st.next_cycle_ts > 0)
				times.push(_('next re-rank: %s').format(new Date(st.next_cycle_ts * 1000).toLocaleString()));
			if (st && st.next_check_ts > 0)
				times.push(_('next check: %s').format(new Date(st.next_check_ts * 1000).toLocaleTimeString()));
			if (times.length)
				apStatus.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.8' }, [ times.join(' · ') ]));
			if (st && st.log && st.log.length) {
				const rows = st.log.slice(-6).reverse().map(function(l) {
					const d = new Date(Number(l.ts) * 1000);
					const fmt = ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
					return E('div', { style: 'margin:1px 0' }, [ fmt + ' · ' + l.m ]);
				});
				apStatus.appendChild(E('details', { style: 'margin:4px 0 0 12px' }, [
					E('summary', { style: 'cursor:pointer' }, [ _('Last events') ]),
					E('div', { style: 'margin:4px 0 0 12px' }, rows)
				]));
			}
		}

		function renderAutoPick(st) {
			st = (st && st.status) || null;
			if (st && st.running) {
				const txt = (st.stage === 'fuzz') ? _('Auto-pick: preparing the fuzz ranking…')
					: (st.stage === 'pick') ? _('Auto-pick: choosing the best strategy…')
					: (st.stage === 'apply') ? _('Auto-pick: applying — the service restarts…')
					: (st.stage === 'verify') ? _('Auto-pick: verifying the live path…')
					: _('Auto-pick is running…');
				autStatus.textContent = txt;
				state.autopickSig = 'run';
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ txt ]));
				return;
			}
			autStatus.textContent = '';
			if (!st || st.stage === 'started')
				return;
			/* Seed rule: a finished run from BEFORE this page load is not
			 * re-shown (same contract as the compose test). */
			if (!state.autopickSeeded) {
				state.autopickSeeded = true;
				return;
			}
			const sig = 'done:' + (st.ts || 0) + ':' + (st.stage || '');
			if (sig === state.autopickSig)
				return;
			state.autopickSig = sig;
			if (st.stage === 'error') {
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Auto-pick failed: %s').format(st.error || _('rpc error')) ]));
				return;
			}
			if (st.stage !== 'done')
				return;
			const box = E('div', {});
			const ch = st.chosen || {};
			const resName = autSel.options[autSel.selectedIndex]
				? autSel.options[autSel.selectedIndex].text : (st.resource || '');
			box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
				[ _('Auto-pick results — %s').format(resName) ]));
			box.appendChild(E('div', { 'class': 'wiz-note' },
				[ _('Best strategy: %s (%s).').format(ch.name || _('custom args'),
					(ch.avg_tls_ms > 0) ? _('avg TLS %d ms').format(ch.avg_tls_ms) : _('custom args')) ]));
			if (ch.args)
				box.appendChild(E('details', {}, [
					E('summary', { style: 'cursor:pointer' }, [ _('Strategy args') ]),
					E('div', { 'class': 'ov-strat', style: 'margin:4px 0 0 12px' }, [ String(ch.args) ])
				]));
			if (ch.runners && ch.runners.length)
				box.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('Runner-ups: %s.').format(ch.runners.join(' · ')) ]));
			const v = st.verify || {};
			box.appendChild(E('div', { 'class': 'wiz-note' }, [
				_('Live check (%s): ').format(v.host || '—'),
				v.ok
					? badge('hpui-b-green', '✓ ' + (v.code || '') + ((v.tsec != null) ? (' · ' + v.tsec + ' s') : ''))
					: badge('hpui-b-red', '✗ ' + (v.code || '000') + ((v.tsec != null) ? (' · ' + v.tsec + ' s') : ''))
			]));
			/* ч.109: the deep battery — every resource host must answer. */
			if (st.verify_multi && st.verify_multi.length > 1) {
				const deepBox = E('div', { 'class': 'wiz-note' });
				deepBox.appendChild(document.createTextNode(_('Resource loads as a whole: ') + ' '));
				st.verify_multi.forEach(function(vm, vi) {
					if (vi) deepBox.appendChild(document.createTextNode(' · '));
					deepBox.appendChild(vm.ok
						? badge('hpui-b-green', '✓ ' + (vm.code || ''))
						: badge('hpui-b-red', '✗ ' + (vm.code || '000')));
					deepBox.appendChild(document.createTextNode(' ' +
						'' + (vm.host || '').replace(/^https?:\/\//, '') +
						((vm.tsec != null) ? (' (' + vm.tsec + ' s)') : '') +
						((vm.speed > 0) ? (' · ' + Math.round(vm.speed / 1024) + ' KB/s') : '')));
				});
				box.appendChild(deepBox);
			}
			/* Honest rule state: the strategy serves the resource only
			 * through its rule. */
			const rule = st.rule || {};
			box.appendChild(E('div', { 'class': 'wiz-note' },
				[ (rule.node === 'zapret-out')
					? _('The %s rule leads to Zapret — the strategy serves the resource.').format(st.resource)
					: (rule.node
						? _('The %s rule leads to %s — a Zapret strategy does NOT affect this resource (set the rule to Zapret to use it here).').format(st.resource, nodeText(rule.node))
						: _('No %s rule — the resource may ride the mass lists/VPN; the Zapret strategy is applied but not serving it yet.').format(st.resource)) ]));
			for (let n in (st.notes || []))
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.8' }, [ String(st.notes[n]) ]));
			const rb = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Restore previous') ]);
			rb.addEventListener('click', function() {
				rb.disabled = true;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Restoring the previous strategies — the service restarts…') ]));
				L.resolveDefault(callComposeRollback(), {}).then(function(r2) {
					rb.disabled = false;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ (r2 && r2.result)
							? _('Previous strategies restored — the service restarts.')
							: _('Restore failed: ') + ((r2 && r2.error) || _('rpc error')) ]));
				});
			});
			box.appendChild(rb);
			dom.content(dpiResult, box);
		}

		/* Service rule through the engine: the «apply → rule → verify» chain.
		 * The engine select rebuilds with the environment; results land in
		 * dpiResult (ONE place). */
		const chainRow = E('div', { 'class': 'wiz-row' });
		const chainSel = E('select', { 'class': 'cbi-input-select wiz-select' });
		const chainEngine = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:120px' });
		const chainBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Create rule and verify') ]);
		chainRow.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Send a service through the engine') ]));
		chainRow.appendChild(chainSel);
		chainRow.appendChild(chainEngine);
		chainRow.appendChild(chainBtn);
		dpiStrategy.appendChild(E('div', { style: 'margin-top:10px' }, [ chainRow ]));

		function renderChain() {
			const env = lastEnv || {};
			const sig = JSON.stringify([ env.zapret_enabled, env.byedpi_enabled ]);
			if (sig === state.chainSig)
				return;
			state.chainSig = sig;
			chainSel.innerHTML = '';
			for (let p in PRESETS)
				chainSel.appendChild(E('option', { value: PRESETS[p].source }, [ PRESETS[p].title ]));
			chainEngine.innerHTML = '';
			if (env.zapret_enabled)
				chainEngine.appendChild(E('option', { value: 'zapret-out' }, [ 'Zapret' ]));
			if (env.byedpi_enabled)
				chainEngine.appendChild(E('option', { value: 'byedpi-out' }, [ 'ByeDPI' ]));
			if (!env.zapret_enabled && !env.byedpi_enabled)
				chainEngine.appendChild(E('option', { value: '' }, [ _('— no engine enabled —') ]));
		}

		chainBtn.addEventListener('click', function() {
			const src = chainSel.value;
			const eng = chainEngine.value;
			if (!src || !eng) {
				ui.addNotification(null, E('p', {}, _('Enable Zapret or ByeDPI on the Connection page first.')), 'error');
				return;
			}
			chainBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Applying the rule — the route check follows…') ]));
					/* set_rule + urltest_nodes cross as STRINGS (issue #11). */
					L.resolveDefault(callPresetApply(src, eng, '[]'), {}).then(function(r) {
				chainBtn.disabled = false;
				if (!r || r.result === false) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				if (r.unchanged)
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Rule is already in place — running the route check…') ]));
				let hosts = [];
				for (let p in PRESETS)
					if (PRESETS[p].source === src)
						hosts = PRESETS[p].hosts || [];
				state.dpiPendingCheck = { source: src, hosts: hosts, since: Date.now() };
				refresh();
			});
		});

		function runChainCheck(dc) {
			const hosts = dc.hosts || [];
			if (!hosts.length) {
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Rule applied. Run the "Provider" check to verify reachability.') ]));
				return;
			}
			Promise.all(hosts.map(function(h) {
				return L.resolveDefault(callRouteExplain(h), {}).then(function(t) {
					return { host: h, trace: t };
				});
			})).then(function(results) {
				const box = E('div', {});
				box.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('Live route for %s:').format(dc.source) ]));
				for (let i in results) {
					const line = E('div', { 'class': 'wiz-note' });
					line.appendChild(document.createTextNode(results[i].host + ': '));
					line.appendChild(shortTrace(results[i].trace));
					box.appendChild(line);
				}
				dom.content(dpiResult, box);
			});
		}

		/* Strategy catalog: refresh from the external source + the generator. */
		const corpusLine = E('div', { 'class': 'wiz-note' });
		const corpusBtns = E('div', { 'class': 'wiz-row' });
		const updBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Update from catalog') ]);
		const genBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Generate mutations') ]);
		corpusBtns.appendChild(updBtn);
		corpusBtns.appendChild(genBtn);
		/* ч.123: share strategies between routers (the same user runs TWO
		 * with different ISPs): export the corpus as JSON, import a file with
		 * the same merge rules as the catalog (no duplicate args, cap 240).
		 * The RANKING itself is ISP-specific and is never exported — the note
		 * says so explicitly. */
		const expBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Export strategies') ]);
		const impBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Import strategies') ]);
		const impFile = E('input', { type: 'file', accept: '.json,application/json', style: 'display:none' });
		expBtn.addEventListener('click', function() {
			const cands = (state.cands || []).map(function(c) {
				return { name: c.name, args: c.args, group: c.group || 'imported' };
			});
			if (!cands.length) {
				ui.addNotification(null, E('p', {}, _('Nothing to export — the corpus is empty.')), 'error');
				return;
			}
			const doc = { format: 're-homeproxy-strategies', version: 1,
				exported: new Date().toISOString(),
				note: _('Strategies are ISP-specific: the RANKING does not transfer between providers — import and re-run the fuzz.'),
				candidates: cands };
			const blob = new Blob([ JSON.stringify(doc, null, 2) ], { type: 'application/json' });
			const a = E('a', { href: URL.createObjectURL(blob), download: 'homeproxy-zapret-strategies.json' });
			document.body.appendChild(a);
			a.click();
			a.remove();
		});
		impBtn.addEventListener('click', function() { impFile.click(); });
		impFile.addEventListener('change', function() {
			const f = impFile.files && impFile.files[0];
			impFile.value = '';
			if (!f)
				return;
			const rd = new FileReader();
			rd.onload = function() {
				let doc = null;
				try { doc = JSON.parse('' + rd.result); } catch (e) {
					ui.addNotification(null, E('p', {}, _('Not a valid strategies JSON file.')), 'error');
					return;
				}
				const list = (doc && doc.candidates) ? doc.candidates : (Array.isArray(doc) ? doc : null);
				if (!list) {
					ui.addNotification(null, E('p', {}, _('Not a valid strategies JSON file.')), 'error');
					return;
				}
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Importing %d strategies…').format(list.length) ]));
				L.resolveDefault(callCorpusImport(JSON.stringify(list)), {}).then(function(r) {
					if (!r || r.result === false) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Import failed: ') + ((r && r.error) || _('rpc error')) ]));
						return;
					}
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Corpus updated: +%d imported, %d already present, %d invalid — %d strategies total. Run a fuzz to rank the new entries.').format(r.added || 0, r.skipped || 0, r.bad || 0, r.total || 0) ]));
					refresh();
				});
			};
			rd.readAsText(f);
		});
		corpusBtns.appendChild(expBtn);
		corpusBtns.appendChild(impBtn);
		corpusBtns.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0', id: 'wiz-corpus-status' }, [ '' ]));
		const prevBox = E('div', {});
		dpiCorpus.appendChild(corpusLine);
		dpiCorpus.appendChild(corpusBtns);
		dpiCorpus.appendChild(prevBox);
		dpiCorpus.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('Update downloads the StressOzz/Zapret-Manager strategy catalog, converts it to nfqws2, tests every converted strategy on the router and shows the diff before applying anything. The generator derives new strategies from the best fuzz results when nothing works.') ]));

		function renderCorpus(meta, strat) {
			const sig = JSON.stringify([ meta.count, meta.groups, meta.updated ]);
			if (sig !== state.corpusSig) {
				state.corpusSig = sig;
				const g = meta.groups || {};
				const parts = [ _('corpus: %d strategies').format(meta.count || 0) ];
				for (let gg in DPI_GROUPS)
					if (g[DPI_GROUPS[gg][0]])
						parts.push(DPI_GROUPS[gg][1] + ': ' + g[DPI_GROUPS[gg][0]]);
				if (meta.updated)
					parts.push(_('updated %s').format(new Date(Number(meta.updated) * 1000).toLocaleString()));
				corpusLine.textContent = parts.join(' · ');
			}
			const st = (strat && strat.status) || {};
			const pv = (strat && strat.preview) || null;
			const box = document.getElementById('wiz-corpus-status');
			if (st.running) {
				let txt = _('Working…');
				if (st.stage === 'download') txt = _('Downloading the catalog…');
				else if (st.stage === 'parse') txt = _('Parsing…');
				else if (st.stage === 'convert') txt = _('Converting %d of %d…').format(st.done || 0, st.total || 0);
				else if (st.stage === 'validate') txt = _('Testing strategies %d of %d…').format(st.done || 0, st.total || 0);
				if (st.current) txt += ' ' + st.current;
				box.textContent = txt;
				return;
			}
			if (st.stage === 'error') {
				box.textContent = _('failed: %s').format(st.error || '');
				return;
			} else if (st.stage === 'done' && !pv)
				box.textContent = _('done');
			const pSig = pv ? ('' + (pv.ts || 0) + ':' + (pv.applied ? 'a' : '')) : 'none';
			if (pSig === state.prevSig)
				return;
			state.prevSig = pSig;
			prevBox.innerHTML = '';
			if (!pv || pv.running || pv.applied)
				return;
			const sum = E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
				[ _('Catalog: %d parsed, %d usable — new: %d, updated: %d, already present: %d, dropped: %d').format(
					pv.parsed || 0, pv.valid || 0, pv.added_new || 0, pv.added_changed || 0, pv.exists || 0,
					(pv.dropped || []).length) ]);
			prevBox.appendChild(sum);
			if ((pv.dropped || []).length) {
				const dl = E('details', {}, [
					E('summary', { style: 'cursor:pointer' }, [ _('Dropped entries (%d)').format(pv.dropped.length) ])
				]);
				const wrap = E('div', { style: 'margin:4px 0 0 12px' });
				for (let i in pv.dropped.slice(0, 20)) {
					const d = E('div', {}, [ pv.dropped[i].name + ' — ' + pv.dropped[i].reason ]);
					wrap.appendChild(d);
				}
				dl.appendChild(wrap);
				prevBox.appendChild(dl);
			}
			const applyImport = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
				[ _('Apply import') ]);
			applyImport.addEventListener('click', function() {
				applyImport.disabled = true;
				L.resolveDefault(callStrategyApply(), {}).then(function(r) {
					applyImport.disabled = false;
					if (!r || r.result === false) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
						return;
					}
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Corpus updated: +%d new, %d refreshed, %d skipped — %d strategies total. Run a fuzz to rank the new entries.').format(
							r.added || 0, r.updated || 0, r.skipped || 0, r.total || 0) ]));
				});
			});
			prevBox.appendChild(applyImport);
		}

		updBtn.addEventListener('click', function() {
			updBtn.disabled = true;
			L.resolveDefault(callStrategyUpdate(), {}).then(function(r) {
				updBtn.disabled = false;
				if (!r || r.result === false)
					ui.addNotification(null, E('p', {}, (r && r.error) || _('rpc error')), 'error');
				else
					refresh();
			});
		});

		genBtn.addEventListener('click', function() {
			genBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Generating mutations from the best strategies, testing them, then a full fuzz starts…') ]));
			L.resolveDefault(callFuzzGenerate(), {}).then(function(r) {
				genBtn.disabled = false;
				if (!r || r.result === false) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Generator failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				refresh();
			});
		});

		/* ── Poll ──────────────────────────────────────────────────────── */
		/* v3b/v3c history: presets moved to Service rules, provider
		 * diagnostics to Check & repair, tg-ws to Phone control — this
		 * page polls the DPI engine state + the preset LIST (rules are
		 * the serving map's source of truth; env feeds the chain row). */
		function refresh() {
			return Promise.all([
				L.resolveDefault(callPresetList(), {}),
				L.resolveDefault(callDpiStatus(), {}),
				L.resolveDefault(callStrategyList(), {}),
				L.resolveDefault(callStrategyStatus(), {}),
				L.resolveDefault(callFuzzStatus(), {}),
				L.resolveDefault(callComposeStatus(), {}),
				L.resolveDefault(callAutoPickStatus(), {}),
				L.resolveDefault(callAutoPilotStatus(), {})
			]).then(function(data) {
				if (data[0] && data[0].env) {
					lastEnv = data[0].env;
					renderChain();
				}
				renderDpi(data[1] || {});
				seedCompProfiles((data[1] || {}).comp_profiles);
				renderStrategySel((data[2] && data[2].candidates) || []);
				renderCorpus(data[1] ? (data[1].corpus || {}) : {}, data[3] || {});
				renderLab(data[4] || {}, data[1] || {});
				/* Ф8-F4: compose test progress/result + the server-snapshot
				 * restore row (covers composition AND plain strategy applies). */
				renderCompose(data[5] || {});
				/* Ф8-F7 T3: auto-pick progress/result (same ONE place). */
				renderAutoPick(data[6] || {});
				/* ч.97: the scheduled auto-pilot card (settings + live state). */
				renderAutoPilot(data[7] || {});
				/* ч.109: the Serving map (rule → engine → strategy → check). */
				renderServingMap(data[1] || {}, (data[0] && data[0].rules) ? data[0] : null, data[7] || {});
				/* ч.123: the Overview «Quality now» panel. */
				renderDpiQuality(data[1] || {}, data[7] || {}, data[4] || {});
				renderRollback((data[1] && data[1].rollback) || null);

				/* The DPI chain (strategy → rule → verify) waits the same way
				 * as the presets did: fire once the core is running again
				 * after the apply-triggered reload (min 8 s after apply). */
				const dc = state.dpiPendingCheck;
				if (dc && (Date.now() - dc.since > 8000)) {
					state.dpiPendingCheck = null;
					callServiceList('homeproxy').then(function(res) {
						let running = false;
						try { running = !!res['homeproxy']['instances']['hiddify-c']['running']; } catch (e) {}
						if (running)
							runChainCheck(dc);
						else
							state.dpiPendingCheck = dc;
					}).catch(function() {
						state.dpiPendingCheck = dc;
					});
				}
			});
		}

		poll.add(refresh, 4);
		refresh();

		return bypRoot;
	}
});
