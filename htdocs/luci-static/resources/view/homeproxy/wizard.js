/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — Routing Wizard (Ф2 MVP + Ф3 DPI section).
 *
 * Three sections:
 *   «Диагностика провайдера» — a background probe matrix (wizard_scan.uc via
 *   wizard_provider_scan) answers "what is blocked for me": direct path
 *   (pinned auto-direct-in :5336, plain-resolver DNS view), main path
 *   (auto-proxy-in :5337 → main-out), DNS view comparison, per-host verdict
 *   and recommendation.
 *   «Сервисы → выходы» — per-service presets that write ONLY regular
 *   proxy_ru_rule sections (the same UCI the manual editor uses), one rule
 *   per source; every apply is followed by an automatic live check
 *   (wizard_service_check for Google AI / OpenAI, route_explain for the
 *   rest) rendered in ONE result area. URLTest pool exit creates a
 *   dedicated per-source urltest group (urltest_nodes on the rule).
 *   «Обход DPI» (Ф3) — engine statuses (wizard_dpi_status), the Strategy
 *   Lab panel moved here from node.js (the zapret_fuzz_* / zapret_strategy_
 *   test RPCs are UNCHANGED), the external strategy catalog importer
 *   (wizard_strategy_update/status/apply via wizard_strategies.uc) and the
 *   mutation generator (wizard_fuzz_generate), plus the
 *   «apply strategy → service rule → live check» chain.
 *
 * Checks are on-demand (D6 pattern): nothing monitors permanently here —
 * the user runs the diagnostics when they need an answer.
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

const callScanStart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_provider_scan',
	params: [ 'hosts' ],
	expect: { '': {} }
});

const callScanStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_scan_status',
	expect: { '': {} }
});

const callServiceCheck = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_service_check',
	params: [ 'service' ],
	expect: { '': {} }
});

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
	return tag;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function() {
		hp.uiStyle();

		/* Service presets — service presets over the itdoginfo/allow-domains
		 * sources the generator already consumes (no new hardcode). The two
		 * bulk lists (refilter / russia-inside) are NOT presets: they are
		 * shown as info rows instead. `check` selects the RPC-backed live
		 * check; `hosts` are the route_explain targets for the rest. */
		const PRESETS = [
			{ source: 'google_ai', title: _('Google AI (Gemini, AI Studio)'), check: 'google_ai',
				hosts: [ 'gemini.google.com', 'generativelanguage.googleapis.com' ] },
			{ source: 'youtube', title: _('YouTube'), hosts: [ 'www.youtube.com' ] },
			{ source: 'discord', title: _('Discord'), hosts: [ 'discord.com' ] },
			{ source: 'telegram', title: _('Telegram'), hosts: [ 'web.telegram.org' ] },
			{ source: 'meta', title: _('Meta (Facebook, Instagram)'), hosts: [ 'instagram.com' ] },
			{ source: 'twitter', title: _('Twitter / X'), hosts: [ 'x.com' ] },
			{ source: 'tiktok', title: _('TikTok'), hosts: [] },
			{ source: 'roblox', title: _('Roblox'), hosts: [ 'roblox.com' ] },
			{ source: 'hdrezka', title: _('HDRezka'), hosts: [] },
			{ source: 'anime', title: _('Anime streaming'), hosts: [] },
			{ source: 'news', title: _('International news sites'), hosts: [] },
			{ source: 'google_play', title: _('Google Play'), hosts: [] },
			{ source: 'google-meet', title: _('Google Meet'), hosts: [] },
			{ source: 'geoblock', title: _('Geo-blocked services'), hosts: [] },
			{ source: 'porn', title: _('Adult content'), hosts: [] }
		];

		const WIZ_CSS = `
.wiz-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.wiz-toolbar input[type="text"] { flex: 1 1 260px; min-width: 200px; }
.wiz-progress { margin: 6px 0; }
.wiz-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid rgba(128,128,128,.3); border-radius: 8px; background: rgba(128,128,128,.07); margin: 6px 0; }
.wiz-title { flex: 1 1 220px; font-weight: 600; }
.wiz-state { flex: 1 1 240px; font-size: .88em; }
.wiz-select { min-width: 190px; max-width: 320px; }
.wiz-note { font-size: .88em; opacity: .8; margin: 8px 0; }
.wiz-hosts { color: #999; font-size: .82em; }
.wiz-strat { flex: 1 1 380px; min-width: 260px; font-family: monospace; font-size: .82em; }
.wiz-pool { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 6px 10px; margin: 4px 0 0 0; font-size: .88em; border: 1px dashed rgba(128,128,128,.4); border-radius: 8px; }
.wiz-pool label { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
`;

		const st = document.getElementById('hp-wiz-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-wiz-style' }, [ WIZ_CSS ]));

		/* ── Tab frame ─────────────────────────────────────────────────── */
		const TABS = [
			[ 'diag', _('Provider diagnostics') ],
			[ 'services', _('Services → exits') ],
			[ 'dpi', _('DPI bypass') ]
		];
		const panes = {};
		for (let t in TABS)
			panes[TABS[t][0]] = E('div', { 'class': 'hpui-pane' });
		const tabBar = E('div', { 'class': 'hpui-tabs' });
		for (let i in TABS) {
			const idx = parseInt(i, 10);
			const key = TABS[i][0];
			const b = E('button', {
				'class': 'hpui-tab' + (idx === 0 ? ' active' : ''),
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
		panes.diag.classList.add('active');

		/* ── Diagnostics pane ──────────────────────────────────────────── */
		const scanBanner = E('div', { 'class': 'hpui-banner', style: 'display:none' });
		const scanResult = E('div', {});
		const customHosts = E('input', {
			type: 'text', 'class': 'cbi-input-text',
			placeholder: _('extra hosts: example.com, 1.2.3.4 (optional)')
		});
		const startBtn = E('button', {
			'class': 'btn cbi-button cbi-button-action', type: 'button'
		}, [ _('Start diagnostics') ]);
		startBtn.addEventListener('click', function() {
			startBtn.disabled = true;
			callScanStart(String(customHosts.value || '').trim()).then(function(r) {
				if (!r || r.result === false)
					ui.addNotification(null, E('p', {}, _('Scan failed to start: ') + ((r && r.error) || '')), 'error');
				return refresh();
			}).finally(function() { startBtn.disabled = false; });
		});

		panes.diag.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Checks a set of test services (YouTube, Discord, Telegram, Google AI, OpenAI…) through your real paths: DIRECT with a plain-resolver DNS view, and through the Main node. Verdicts tell you what needs a proxy rule, what needs a Zapret/ByeDPI strategy, and what is DNS-poisoned. RU services (rutube, gosuslugi) are control hosts — they must always open directly.') ]));
		panes.diag.appendChild(E('div', { 'class': 'wiz-toolbar' }, [ customHosts, startBtn ]));
		panes.diag.appendChild(scanBanner);
		panes.diag.appendChild(scanResult);

		/* ── Services pane ─────────────────────────────────────────────── */
		const envBanners = E('div', {});
		const presetRows = E('div', {});
		const checkResult = E('div', {});

		panes.services.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Pick an exit for each service — the Wizard maintains ONE routing rule per service (the same proxy_ru_rule records as the manual editor on the Client Settings page). "Direct" removes the rule: in "Bypass blocking" mode everything unmatched goes directly anyway. After applying, the service restarts once and the check runs automatically — the result appears below, in one place.') ]));
		panes.services.appendChild(envBanners);
		panes.services.appendChild(presetRows);
		panes.services.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Check results') ]));
		panes.services.appendChild(checkResult);

		/* ── DPI pane ──────────────────────────────────────────────────── */
		const dpiBanner = E('div', {});
		const dpiCards = E('div', { 'class': 'hpui-cards' });
		const dpiStrategy = E('div', {});
		const dpiLab = E('div', {});
		const dpiCorpus = E('div', {});
		const dpiResult = E('div', {});

		panes.dpi.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Zapret (nfqws2) and ByeDPI fragment or fake the traffic of the services routed to them — pick a strategy, test it against your ISP in the Strategy Lab, then send a service through the engine and verify live. Everything here runs on the router; results appear below, in one place.') ]));
		panes.dpi.appendChild(dpiBanner);
		panes.dpi.appendChild(dpiCards);
		panes.dpi.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Strategy') ]));
		panes.dpi.appendChild(dpiStrategy);
		panes.dpi.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Strategy Lab') ]));
		panes.dpi.appendChild(dpiLab);
		panes.dpi.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Strategy catalog') ]));
		panes.dpi.appendChild(dpiCorpus);
		panes.dpi.appendChild(E('h4', { style: 'margin-top:14px' }, [ _('Results') ]));
		panes.dpi.appendChild(dpiResult);

		/* ── Badge / text helpers ──────────────────────────────────────── */
		const badge = (cls, text) => E('span', { 'class': 'hpui-badge ' + cls }, [ text ]);

		const VERDICTS = {
			opens_direct:   [ 'hpui-b-green', _('Opens directly') ],
			needs_proxy:    [ 'hpui-b-red', _('Needs proxy — create a rule') ],
			needs_strategy: [ 'hpui-b-amber', _('Needs Zapret/ByeDPI strategy') ],
			dns_poison:     [ 'hpui-b-amber', _('DNS poisoning (fake answers)') ],
			geo_blocked:    [ 'hpui-b-red', _('Service refuses the exit node') ],
			main_path_fail: [ 'hpui-b-red', _('Main path fails (check the node)') ],
			control_fail:   [ 'hpui-b-red', _('RU site unreachable directly — anomaly') ],
			down:           [ 'hpui-b-grey', _('Unreachable both ways') ],
			partial:        [ 'hpui-b-grey', _('Only the main path was measured') ],
			unknown:        [ 'hpui-b-grey', _('No data') ]
		};

		const KINDS = {
			tls_dpi:   _('TLS DPI (SNI reset)'),
			tcp:       _('TCP unreachable'),
			timeout:   _('Timeout (dropped?)'),
			resolve:   _('DNS resolve failed'),
			sigpage:   _('Block page served as 200'),
			hardcode:  _('Refusal code (403/406/451)'),
			waf:       _('WAF challenge (path is open)'),
			transport: _('Transport error')
		};

		const RECOMMEND = {
			dns:       _('Secure DNS (MultiDNS) usually fixes this; a routing rule also helps'),
			rule:      _('Create a rule in the "Services → exits" tab'),
			strategy:  _('Pick a working Zapret/ByeDPI strategy (Strategy Lab)'),
			node:      _('Switch to a different node — the service refuses this exit region'),
			main_path: _('The Main node is not serving this site — check the node'),
			anomaly:   _('Anomaly: RU services must open directly — check RU-protect / the internet'),
			none:      _('—')
		};

		function probeCell(p) {
			if (p == null)
				return E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ _('n/a') ]);
			if (p.ok)
				return badge('hpui-b-green', '✓ ' + (p.code || ''));
			const why = p.geo_refused ? _('geo-refused') : (KINDS[p.kind] || (p.kind || 'fail'));
			return badge('hpui-b-red', '✗ ' + why + ' (' + (p.code || '000') + ')');
		}

		function verdictCell(v) {
			const spec = VERDICTS[v] || VERDICTS.unknown;
			return badge(spec[0], spec[1]);
		}

		/* ── Scan rendering ────────────────────────────────────────────── */
		function renderScan(status, result) {
			scanBanner.style.display = (status && status.running) ? 'block' : 'none';
			if (status && status.running) {
				scanBanner.textContent = _('Scanning %d of %d…').format(status.done || 0, status.total || 0) +
					(status.current ? (' ' + status.current) : '');
				return;
			}
			/* Same anti-flicker rule as the presets: rebuild only when a NEW
			 * result arrived. */
			const sig = result ? ('' + (result.ts || 0)) : 'none';
			if (sig === state.scanSig)
				return;
			state.scanSig = sig;
			scanResult.innerHTML = '';
			if (!result || !result.hosts || !result.hosts.length) {
				scanResult.appendChild(E('p', { 'class': 'hpui-hint' },
					[ _('No scan results yet — press "Start diagnostics".') ]));
				return;
			}
			const cards = E('div', { 'class': 'hpui-cards' });
			const s = result.summary || {};
			const mk = (num, cap, cls) => E('div', { 'class': 'hpui-card' }, [
				E('div', { 'class': 'hpui-num ' + (cls || '') }, [ String(num) ]),
				E('div', { 'class': 'hpui-cap' }, [ cap ])
			]);
			cards.appendChild(mk(s.opens_direct || 0, _('open directly'), 'hpui-c-green'));
			cards.appendChild(mk(s.needs_proxy || 0, _('need a proxy rule'), 'hpui-c-red'));
			cards.appendChild(mk(s.needs_strategy || 0, _('need a strategy'), 'hpui-c-amber'));
			cards.appendChild(mk(s.dns_poison || 0, _('DNS-poisoned'), 'hpui-c-amber'));
			scanResult.appendChild(cards);

			if (!result.proxy_in && !result.mixed_in)
				scanResult.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('The diagnostic inbounds are unavailable (Custom routing / Custom JSON) — only a partial picture is possible.') ]));

			const thead = E('thead', {}, E('tr', {}, [
				E('th', {}, [ _('Resource') ]),
				E('th', {}, [ _('Direct') ]),
				E('th', {}, [ _('Via main path') ]),
				E('th', {}, [ _('DNS') ]),
				E('th', {}, [ _('Verdict') ]),
				E('th', {}, [ _('Recommendation') ])
			]));
			const tbody = E('tbody', {});
			for (let h in result.hosts) {
				const r = result.hosts[h];
				const dnsCell = r.dns_poison
					? badge('hpui-b-red', _('poisoned'))
					: (r.dns_differs
						? badge('hpui-b-amber', _('differs'))
						: E('span', { style: 'opacity:.6' }, [ _('same') ]));
				const rec = (r.recommend && RECOMMEND[r.recommend]) ? RECOMMEND[r.recommend] : '—';
				const tr = E('tr', {}, [
					E('td', {}, [ E('span', { style: 'font-weight:600' }, [ String(r.host) ]) ]),
					E('td', {}, [ probeCell(r.direct) ]),
					E('td', {}, [ probeCell(r.proxy) ]),
					E('td', {}, [ dnsCell ]),
					E('td', {}, [ verdictCell(r.verdict) ]),
					E('td', { 'class': 'wiz-note', style: 'margin:0' }, [ rec ])
				]);
				tbody.appendChild(tr);
			}
			const wrap = E('div', { 'class': 'hpui-wrap' });
			wrap.appendChild(E('table', { 'class': 'hpui-table' }, [ thead, tbody ]));
			scanResult.appendChild(wrap);
			scanResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('Scan from %s').format(new Date(Number(result.ts) * 1000).toLocaleString()) ]));
		}

		/* ── Presets rendering ─────────────────────────────────────────── */
		const state = { data: null, pendingCheck: null, presetsSig: null, scanSig: null,
			dpiSig: null, stratSig: null, fuzzSig: null, corpusSig: null, prevSig: null,
			dpiPendingCheck: null };

		function nodeText(node) {
			if (node === 'main-out') return _('Same as main node');
			if (node === 'byedpi-out') return 'ByeDPI';
			if (node === 'zapret-out') return 'Zapret';
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
		function renderPresets(list) {
			/* Rebuild the rows ONLY when the underlying state changed: a 4s
			 * poll rebuild would reset the exit <select> the user is working
			 * with (the Automation table rebuilds wholesale; a form-ish row
			 * must not). */
			const env = (list && list.env) || {};
			lastEnv = env;
			const sig = JSON.stringify([ env, list.rules || {}, list.rule_counts || {},
				((list.nodes || []).map(function(n) { return n.id; })) ]);
			if (sig === state.presetsSig)
				return;
			state.presetsSig = sig;

			envBanners.innerHTML = '';
			if (env.routing_mode && env.routing_mode !== 'proxy_banned_ru')
				envBanners.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('Routing rules apply ONLY in "Bypass blocking" mode — the current mode is "%s", so preset rules would have no effect.').format(env.routing_mode) ]));
			if (env.main_is_direct)
				envBanners.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('Main node is Direct: rules pointing at "Same as main node" would egress directly. Choose Zapret/ByeDPI or a real node, or switch the Main node first.') ]));
			if (!env.proxy_in && !env.direct_in)
				envBanners.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('The pinned diagnostic inbounds are not listening (Custom routing / Custom JSON) — path checks are limited.') ]));

			/* Bulk lists are not presets — just show their state. */
			const bulk = E('div', { 'class': 'wiz-row' });
			bulk.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Bulk lists') ]));
			bulk.appendChild(E('span', { 'class': 'wiz-state' },
				[ _('Russia Inside: %s · Re-filter: %s').format(
					list.rules['russia-inside'] ? nodeText(list.rules['russia-inside'].node) : _('no rule'),
					list.rules['refilter'] ? nodeText(list.rules['refilter'].node) : _('no rule')) ]));
			bulk.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
				[ _('These lists already cover YouTube/Discord/Telegram and most blocked resources — presets below add per-service overrides.') ]));
			presetRows.innerHTML = '';
			presetRows.appendChild(bulk);

			for (let p in PRESETS) {
				const preset = PRESETS[p];
				const rule = (list.rules || {})[preset.source];
				const count = (list.rule_counts || {})[preset.source] || 0;

				const row = E('div', { 'class': 'wiz-row' });
				const titleWrap = E('span', { 'class': 'wiz-title' }, [ preset.title ]);
				if (preset.hosts && preset.hosts.length)
					titleWrap.appendChild(E('span', { 'class': 'wiz-hosts' }, [ ' · ' + preset.hosts.join(', ') ]));
				row.appendChild(titleWrap);

				const stateEl = E('span', { 'class': 'wiz-state' }, [ ruleStateText(rule, count) ]);
				row.appendChild(stateEl);

			const sel = E('select', { 'class': 'cbi-input-select wiz-select' });
			sel.appendChild(E('option', { value: '' }, [ _('Direct (remove rule)') ]));
			if (!env.main_is_direct)
				sel.appendChild(E('option', { value: 'main-out' }, [ _('Same as main node') ]));
			if (env.byedpi_enabled)
				sel.appendChild(E('option', { value: 'byedpi-out' }, [ 'ByeDPI' ]));
			if (env.zapret_enabled)
				sel.appendChild(E('option', { value: 'zapret-out' }, [ 'Zapret' ]));
			sel.appendChild(E('option', { value: 'urltest' }, [ _('URLTest pool') ]));
			for (let n in (list.nodes || []))
				sel.appendChild(E('option', { value: list.nodes[n].id },
					[ list.nodes[n].label ]));
			sel.value = (rule && rule.node) ? rule.node : '';
			if (sel.selectedIndex < 0)
				sel.value = '';

			/* URLTest pool picker — revealed when the exit is "URLTest pool":
			 * the generator builds a dedicated hp-ru-<source>-out urltest group
			 * from the ticked nodes (the manual editor exposes the same list). */
			const poolBox = E('div', { 'class': 'wiz-pool', style: 'display:none' });
			const poolChecks = [];
			let poolTouched = false;
			const proxyNodes = (list.nodes || []).filter(function(n) { return n.type !== 'direct'; });
			for (let n in proxyNodes) {
				const cb = E('input', { type: 'checkbox', value: proxyNodes[n].id });
				const lb = E('label', {}, [ cb, ' ' + proxyNodes[n].label ]);
				poolChecks.push({ id: proxyNodes[n].id, cb: cb });
				poolBox.appendChild(lb);
			}
			const syncPool = function() {
				const show = (sel.value === 'urltest');
				poolBox.style.display = show ? 'flex' : 'none';
				if (show && !poolTouched) {
					const cur = (rule && rule.urltest_nodes) || [];
					for (let c in poolChecks)
						poolChecks[c].cb.checked = (cur.indexOf(poolChecks[c].id) >= 0);
				}
			};
			sel.addEventListener('change', function() { poolTouched = false; syncPool(); });
			poolBox.addEventListener('change', function() { poolTouched = true; });
			syncPool();

			const applyBtn = E('button', {
				'class': 'btn cbi-button cbi-button-action', type: 'button'
			}, [ _('Apply') ]);
			applyBtn.addEventListener('click', function() {
				const ids = [];
				for (let c in poolChecks)
					if (poolChecks[c].cb.checked)
						ids.push(poolChecks[c].id);
				if (sel.value === 'urltest' && !ids.length) {
					ui.addNotification(null, E('p', {}, _('Pick at least one node for the URLTest pool.')), 'error');
					return;
				}
				applyBtn.disabled = true;
				callPresetApply(preset.source, String(sel.value || ''), sel.value === 'urltest' ? ids : []).then(function(r) {
					if (!r || r.result === false) {
						const ERRS = {
							main_is_direct: _('Main node is Direct — this rule would have no effect. Pick Zapret/ByeDPI or a real node.'),
							byedpi_disabled: _('ByeDPI is not enabled — enable it on the Node Settings page first.'),
							zapret_disabled: _('Zapret is not enabled — enable it on the Node Settings page first.'),
							urltest_pool_empty: _('Pick at least one node for the URLTest pool.'),
							unknown_node: _('Unknown node — refresh the page.'),
							unknown_source: _('Unknown service.'),
							'config generation failed': _('Config generation failed — the previous config stays active.')
						};
							const msg = ERRS[(r && r.error)] || ((r && r.error) || _('RPC error'));
							ui.addNotification(null, E('p', {}, msg), 'error');
							return;
						}
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
							[ _('Rule applied — the service is restarting, the check will run automatically…') ]));
						/* The service reload takes a few seconds; the poll loop
						 * fires the live check as soon as the core is back. */
						state.pendingCheck = { preset: preset, since: Date.now() };
						return refresh();
					}).finally(function() { applyBtn.disabled = false; });
				});

			row.appendChild(sel);
			row.appendChild(poolBox);
			row.appendChild(applyBtn);

				if (preset.check) {
					const checkBtn = E('button', {
						'class': 'btn cbi-button', type: 'button'
					}, [ _('Check now') ]);
					checkBtn.addEventListener('click', function() {
						checkBtn.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking…') ]));
						runServiceCheck(preset.check).finally(function() { checkBtn.disabled = false; });
					});
					row.appendChild(checkBtn);
				}
				presetRows.appendChild(row);
			}

			/* OpenAI has no dedicated itdoginfo list — a check-only row. */
			const oai = E('div', { 'class': 'wiz-row' });
			oai.appendChild(E('span', { 'class': 'wiz-title' }, [ _('OpenAI (ChatGPT)') ]));
			oai.appendChild(E('span', { 'class': 'wiz-state wiz-note', style: 'margin:0' },
				[ _('No dedicated list — OpenAI domains ride the main path / Re-filter. This button only checks whether the current exit region is accepted.') ]));
			const oaiBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Check now') ]);
			oaiBtn.addEventListener('click', function() {
				oaiBtn.disabled = true;
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking…') ]));
				runServiceCheck('openai').finally(function() { oaiBtn.disabled = false; });
			});
			oai.appendChild(oaiBtn);
			presetRows.appendChild(oai);
		}

		/* ── Live checks (results in ONE place below the presets) ──────── */
		function shortTrace(t) {
			if (!t || t.error)
				return E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ (t && t.error) || '—' ]);
			const label = t.outbound ? resolveTag(t.outbound) : (t.action || '?');
			return E('span', {}, [
				E('strong', {}, [ label ]),
				E('span', { style: 'opacity:.75' }, [ (t.match ? (' ← ' + t.match) : '') + (t.fallback ? (' · ' + _('default route')) : '') ])
			]);
		}

		function checkBadge(obj, okText, badText) {
			const v = obj && obj.verdict;
			const code = (obj && obj.code) || '—';
			if (v === 'ok' || v === 'served') return badge('hpui-b-green', '✓ ' + okText);
			if (v === 'refused') return badge('hpui-b-red', '✗ ' + badText);
			return badge('hpui-b-amber', '? ' + _('uncertain') + ' (' + _('code') + ' ' + code + ')');
		}

		function renderServiceCheck(r) {
			checkResult.innerHTML = '';
			if (!r || r.result === false) {
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
					[ _('Check failed: ') + ((r && r.error) || _('RPC error')) ]));
				return;
			}
			const exitLine = E('div', { 'class': 'wiz-note' });
			exitLine.appendChild(document.createTextNode(_('Main-path exit') + ': '));
			exitLine.appendChild(E('b', {}, [ (r.exit && (r.exit.country || r.exit.ip)) || _('no data') ]));
			if (r.exit && r.exit.asn)
				exitLine.appendChild(document.createTextNode(' · ' + r.exit.asn));
			if (r.exit_direct && r.exit_direct.country_code !== (r.exit && r.exit.country_code))
				exitLine.appendChild(document.createTextNode(' · ' + _('direct exit') + ': ' + (r.exit_direct.country || r.exit_direct.ip || '—')));
			checkResult.appendChild(exitLine);

			if (r.exit_verdict === 'unsupported_country')
				checkResult.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('The exit country is on the service blocklist (RU/BY/CN/HK/MO/IR/KP) — switch the node.') ]));

			const row = E('div', { 'class': 'wiz-row' });
			if (r.service === 'google_ai') {
				row.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Google AI API') ]));
				row.appendChild(checkBadge(r.api, _('region passes'), _('region refused')));
				row.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Gemini web') ]));
				row.appendChild(checkBadge(r.web, _('served'), _('refused')));
			} else {
				row.appendChild(E('span', { 'class': 'wiz-title' }, [ _('OpenAI API') ]));
				row.appendChild(checkBadge(r.api, _('region passes'), _('region refused')));
			}
			checkResult.appendChild(row);

			const routes = r.route || {};
			for (let h in routes) {
				const line = E('div', { 'class': 'wiz-note' });
				line.appendChild(document.createTextNode(h + ': '));
				line.appendChild(shortTrace(routes[h]));
				checkResult.appendChild(line);
			}
		}

		function renderPathCheck(preset, results) {
			checkResult.innerHTML = '';
			checkResult.appendChild(E('div', { 'class': 'wiz-note' },
				[ _('Live route for %s:').format(preset.title) ]));
			for (let i in results) {
				const line = E('div', { 'class': 'wiz-note' });
				line.appendChild(document.createTextNode(results[i].host + ': '));
				line.appendChild(shortTrace(results[i].trace));
				checkResult.appendChild(line);
			}
			checkResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('Full reachability probing lives in the "Provider diagnostics" tab.') ]));
		}

		function runServiceCheck(service) {
			return L.resolveDefault(callServiceCheck(service), {}).then(function(r) {
				if (r && r.error) {
					dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
						[ _('Check failed: ') + r.error ]));
					return;
				}
				renderServiceCheck(r);
			});
		}

		function runPathCheck(preset) {
			const hosts = (preset.hosts && preset.hosts.length) ? preset.hosts : [];
			if (!hosts.length) {
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
					[ _('Rule applied. Run "Provider diagnostics" to verify reachability.') ]));
				return Promise.resolve();
			}
			return Promise.all(hosts.map(function(h) {
				return L.resolveDefault(callRouteExplain(h), {}).then(function(t) {
					return { host: h, trace: t };
				});
			})).then(function(results) {
				renderPathCheck(preset, results);
			});
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
				document.getElementById('wiz-zapnote').textContent =
					z.strategy ? shortStrategy(z.strategy, 110) : '—';
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
						[ _('%s is not installed — install it on the "Core & Tools" page (Services tab) first.').format(miss.join(', ')) ]));
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
			[ _('The strategy applies to every flow routed to Zapret (no hostlists — the routing rules select the traffic). Applying also enables Zapret and restarts the service; testing runs the strategy on an isolated queue over 4 test sites (YouTube, Telegram, Discord, Speedtest).') ]));

		function renderStrategySel(cands) {
			const sig = JSON.stringify((cands || []).map(function(c) { return c.name; }));
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
							style: 'font-weight:600;color:' + (r2.ok ? '#3fbf5f' : '#e05252')
						}, [ (r2.label || r2.tag) + (r2.ok ? ' ✓ ' + r2.tls + 's' : ' ✗ ' + (r2.reason || 'fail')) ]));
					});
					row.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ '(' + (data.ok || 0) + '/' + (data.total || 0) + ')' ]));
					box.appendChild(row);
					dom.content(dpiResult, box);
				});
			});
		});

		/* Strategy Lab — the ported panel (node.js): quick/full fuzz buttons,
		 * rounds, live progress. The RESULT table renders into dpiResult
		 * (results live in ONE place); history stays here as a details block. */
		const labRounds = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto' });
		for (const n of [ 1, 2, 3 ]) {
			const op = E('option', { value: String(n), selected: (n === 2) ? '' : null },
				_('%d round(s)').format(n));
			labRounds.appendChild(op);
		}
		const labStatus = E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ '' ]);
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
		dpiLab.appendChild(labHist);
		dpiLab.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('The fuzzer batch-tests every strategy from the catalog on an isolated NFQUEUE (YouTube / Telegram / Discord / Speedtest TLS handshakes). A no-desync baseline marks hosts your ISP does not block; each host must pass the majority of rounds. Live traffic is untouched. A full sweep takes up to ~15 minutes.') ]));

		let labPollId = null;
		function labStopPoll() { if (labPollId) { window.clearInterval(labPollId); labPollId = null; } }

		function renderLab(r) {
			const st = (r && r.status) || {};
			const res = (r && r.result) || null;
			const hist = (r && r.history && r.history.runs) || [];
			if (st.running) {
				labStatus.textContent = _('Fuzzing… %d of %d').format(st.done || 0, st.total || 0) +
					(st.current ? (' · ' + st.current) : '');
				if (!labPollId) labPollId = window.setInterval(refresh, 5000);
				return;
			}
			labStopPoll();
			if (st.error) {
				labStatus.textContent = _('Fuzz failed: %s').format(st.error);
				return;
			} else
				labStatus.textContent = '';
			/* Result table — rebuilt only when a NEW result arrived. */
			const sig = res ? ('' + (res.ts || 0)) : 'none';
			if (sig === state.fuzzSig)
				return;
			state.fuzzSig = sig;
			if (!res || !res.strategies || !res.strategies.length)
				return;
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
			const thead = E('thead', {}, E('tr', {}, [
				E('th', {}, [ '#' ]),
				E('th', {}, [ _('Strategy') ]),
				E('th', {}, [ _('Passed') ]),
				E('th', {}, [ _('Avg TLS, ms') ]),
				E('th', {}, [ '' ])
			]));
			const tbody = E('tbody', {});
			res.strategies.slice(0, 15).forEach(function(s, i) {
				const hostsTip = (s.hosts || []).map(function(h) {
					return (h.label || h.tag) + ' ' +
						(h.ok ? '✓ ' + h.votes + '/' + h.rounds + ' · ' + (h.tls_ms || 0) + ' ms'
						      : '✗ ' + (h.reason || 'fail')) +
						(h.dist ? '' : ' (' + _('free pass') + ')');
				}).join(' · ');
				const ab = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'style': 'font-size:.82em; padding:0 8px' },
					[ _('Apply') ]);
				ab.addEventListener('click', function() {
					if (!window.confirm(_('Apply this Zapret strategy and restart the service?')))
						return;
					ab.disabled = true;
					L.resolveDefault(callFuzzApply(s.args), {}).then(function(r2) {
						ab.disabled = false;
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ r2 && r2.result
							? _('Strategy applied — the service restarts; run "Test strategy" in ~30 s to confirm.')
							: ((r2 && r2.error) || _('Apply failed')) ]));
					});
				});
				tbody.appendChild(E('tr', {}, [
					E('td', { style: 'opacity:.7' }, [ String(i + 1) ]),
					E('td', { style: 'font-size:.85em; max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap', title: s.args },
						[ s.name || s.args ]),
					E('td', { style: 'white-space:nowrap' }, [ '%d / %d'.format(s.ok || 0, s.total || 0) ]),
					E('td', {}, [ String(s.avg_tls_ms || 0) ]),
					E('td', {}, [ ab ])
				]));
			});
			const wrap = E('div', { 'class': 'hpui-wrap' });
			wrap.appendChild(E('table', { 'class': 'hpui-table' }, [ thead, tbody ]));
			box.appendChild(wrap);
			dom.content(dpiResult, box);
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
				ui.addNotification(null, E('p', {}, _('Enable Zapret or ByeDPI on the Node Settings page first.')), 'error');
				return;
			}
			chainBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Creating the rule — the service restarts, the route check follows…') ]));
			L.resolveDefault(callPresetApply(src, eng, []), {}).then(function(r) {
				chainBtn.disabled = false;
				if (!r || r.result === false) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
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
					[ _('Rule applied. Run "Provider diagnostics" to verify reachability.') ]));
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
		function refresh() {
			return Promise.all([
				L.resolveDefault(callScanStatus(), {}),
				L.resolveDefault(callPresetList(), {}),
				L.resolveDefault(callDpiStatus(), {}),
				L.resolveDefault(callStrategyList(), {}),
				L.resolveDefault(callStrategyStatus(), {}),
				L.resolveDefault(callFuzzStatus(), {})
			]).then(function(data) {
				const scan = data[0] || {};
				renderScan(scan.status, scan.result);
				if (data[1] && data[1].rules) {
					renderPresets(data[1]);
					renderChain();
				}
				renderDpi(data[2] || {});
				renderStrategySel((data[3] && data[3].candidates) || []);
				renderCorpus(data[2] ? (data[2].corpus || {}) : {}, data[4] || {});
				renderLab(data[5] || {});

				/* Deferred live check: fire once the core is running again
				 * after the apply-triggered reload (min 8 s after apply). */
				const pc = state.pendingCheck;
				if (pc && (Date.now() - pc.since > 8000)) {
					state.pendingCheck = null;
					callServiceList('homeproxy').then(function(res) {
						let running = false;
						try { running = !!res['homeproxy']['instances']['hiddify-c']['running']; } catch (e) {}
						if (running) {
							if (pc.preset.check)
								return runServiceCheck(pc.preset.check);
							return runPathCheck(pc.preset);
						}
						/* Still restarting — retry on the next poll tick. */
						state.pendingCheck = pc;
					}).catch(function() {
						state.pendingCheck = pc;
					});
				}

				/* The DPI chain (strategy → rule → verify) waits the same way. */
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

		return E('div', {}, [ tabBar, panes.diag, panes.services, panes.dpi ]);
	}
});
