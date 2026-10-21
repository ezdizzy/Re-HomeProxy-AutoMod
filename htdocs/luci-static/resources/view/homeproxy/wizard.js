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
 *   «Дополнительно» (Ф6) — the Telegram bot v2 (settings/status/test via
 *   telegram_status/set/test RPCs; the always-on telegram.uc daemon
 *   hot-reloads UCI, so saving never restarts the service) and (Ф7, D8)
 *   the TG WS Proxy card: READ-ONLY detection of the third-party
 *   tg-ws-proxy-rs bridge (and the d0mhate Go variant), its --check
 *   self-diagnostics, the official installer (digests verified by the
 *   installer from the GitHub release API) and the tg:// link.
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

/* Ф8-F1: dpi-detect seeds (splify2-lists) — update runs as a background
 * runner; the poll shows its progress in the diag pane row. */
const callDpiUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_dpidetect_update',
	expect: { '': {} }
});

const callServiceCheck = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_service_check',
	params: [ 'service' ],
	expect: { '': {} }
});

const callAiNodesCheck = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_ai_nodes_check',
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
 * rule (optional) → apply (server snapshot) → live verify. */
const callAutoPickStart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_auto_pick_start',
	params: [ 'resource', 'mode', 'set_rule' ],
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

/* ── Telegram bot v2 (Ф6): settings/status/test — on demand (D6) ────────── */

const callTelegramStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_status',
	expect: { '': {} }
});

const callTelegramSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_set',
	params: [ 'enabled', 'token', 'chat_id', 'mute', 'push_hotswap', 'push_watchdog',
		'push_learn', 'push_service', 'poll_timeout', 'push_interval' ],
	expect: { '': {} }
});

const callTelegramTest = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_test',
	expect: { '': {} }
});

/* Custom domain lists (Ф7/D6): the manual proxy/direct domain lists —
 * routing inputs the generator merges with the learned lists. Formerly
 * buried in Client Settings → Access Control; the Wizard is their single
 * editor now. */
const callAclListRead = rpc.declare({
	object: 'luci.homeproxy',
	method: 'acllist_read',
	params: [ 'type' ],
	expect: { '': {} }
});

const callAclListWrite = rpc.declare({
	object: 'luci.homeproxy',
	method: 'acllist_write',
	params: [ 'type', 'content' ],
	expect: { '': {} }
});

/* ── TG WS Proxy (D8): third-party Telegram bridge — detect/check/install ── */

const callTgwspStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_tgwsp_status',
	expect: { '': {} }
});

const callTgwspCheck = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_tgwsp_check',
	expect: { '': {} }
});

const callTgwspInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_tgwsp_install',
	expect: { '': {} }
});

const callTgwspLink = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_tgwsp_link',
	params: [ ]
});

/* F8-F2: the transparent SOCKS5 bridge (tg-ws-proxy-go) install — procd
 * instance managed by the app, loopback-only listener. */
const callTgwsInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_tgws_install',
	params: [ ]
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
		hp.uiStyle();

		/* Service presets — service presets over the itdoginfo/allow-domains
		 * sources the generator already consumes (no new hardcode).
		 * `check` selects the RPC-backed live check; `hosts` are the
		 * route_explain targets for the rest. */
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

		/* A1: every rpcd SOURCE becomes an editable row, grouped. The mass
		 * lists use the same select/Apply path as presets — the RPC accepts
		 * any source. Titles reuse the manual editor wording (client.js). */
		const BULK_PRESETS = [
			{ source: 'russia-inside', title: _('itdoginfo/allow-domains - Russia Inside (1000+ entries)') },
			{ source: 'refilter', title: _('Re-filter (Russia blocklist: 60000+ banned domains + 25000+ IPs)') },
			{ source: 'block', title: _('Block (core RKN-blocked resources)') },
			{ source: 'russia-outside', title: _('Russia Outside (RU-only services — for use abroad)') },
			{ source: 'ukraine-inside', title: _('Ukraine Inside (resources blocked in UA)') }
		];
		const CDN_PRESETS = [
			{ source: 'cloudflare', title: _('Cloudflare CDN') },
			{ source: 'cloudfront', title: _('CloudFront CDN') },
			{ source: 'digitalocean', title: _('DigitalOcean cloud hosting') },
			{ source: 'hetzner', title: _('Hetzner (Germany cloud hosting)') },
			{ source: 'ovh', title: _('OVH (France cloud hosting)') },
			{ source: 'hodca', title: _('HODCA') }
		];
		const MISC_PRESETS = [
			{ source: 'news', title: _('International news sites') },
			{ source: 'porn', title: _('Adult content') },
			{ source: 'anime', title: _('Anime streaming') },
			{ source: 'geoblock', title: _('Geo-blocked services') },
			{ source: 'hdrezka', title: _('HDRezka') }
		];
		/* W4: b4geoip gaming IP sets — IP-only, no domains. */
		const GAMING_PRESETS = [
			{ source: 'valve', title: _('Valve / Steam') },
			{ source: 'epicgames', title: _('Epic Games') },
			{ source: 'riot', title: _('Riot Games') },
			{ source: 'sony', title: _('Sony / PlayStation') },
			{ source: 'electronicarts', title: _('EA / Electronic Arts') },
			{ source: 'ubisoft', title: _('Ubisoft') },
			{ source: 'blizzard', title: _('Blizzard') },
			{ source: 'nintendo', title: _('Nintendo') },
			{ source: 'wargaming', title: _('Wargaming') },
			{ source: 'xbox', title: _('Xbox') }
		];

		const WIZ_CSS = `
.wiz-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.wiz-toolbar input[type="text"] { flex: 1 1 260px; min-width: 200px; }
.wiz-progress { margin: 6px 0; }
.wiz-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid rgba(128,128,128,.3); border-radius: 8px; background: rgba(128,128,128,.07); margin: 6px 0; }
.wiz-title { flex: 1 1 220px; font-weight: 600; }
.wiz-state { flex: 1 1 240px; font-size: .88em; }
.wiz-select { min-width: 190px; max-width: 320px; }
/* Ф8-F5 (D.2): service rows use a FIXED grid — name | state | select |
 * buttons on one line, hints/pool on sub-rows below the card — so the
 * control columns line up across all 26 rows regardless of hint length
 * (the old flex rows had drifting columns and uneven heights). The button
 * column is a FIXED width: every row is its own grid, so an auto-sized last
 * column would shift the select column on rows that carry the extra Check
 * button. The button GROUP wraps as a fallback: the shortened RU label
 * («Применить» + «Проверить») fits the 210px track on one line, but an
 * overflowing locale must stay INSIDE the card, not spill out of it. */
.wiz-svc { border: 1px solid rgba(128,128,128,.3); border-radius: 8px; background: rgba(128,128,128,.07); margin: 6px 0; padding: 8px 10px; }
.wiz-svc-grid { display: grid; grid-template-columns: minmax(140px, 230px) minmax(180px, 1fr) minmax(190px, 300px) 210px; align-items: center; gap: 6px 10px; }
.wiz-svc-btns { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 8px; }
.wiz-svc-grid > .wiz-title, .wiz-svc-grid > .wiz-state { flex: none; }
.wiz-svc-grid > .wiz-select { width: 100%; }
.wiz-svc .wiz-pool { margin: 6px 0 0 0; }
.wiz-svc .wiz-note { margin: 6px 0 0 0; }
@media (max-width: 900px) {
	/* Narrow screens fall back to the old wrapping flex row. */
	.wiz-svc-grid { display: flex; flex-wrap: wrap; }
	.wiz-svc-grid > .wiz-title { flex: 1 1 220px; }
	.wiz-svc-grid > .wiz-state { flex: 1 1 240px; }
	.wiz-svc-grid > .wiz-select { width: auto; }
}
.wiz-note { font-size: .88em; opacity: .8; margin: 8px 0; }
.wiz-hosts { color: #999; font-size: .82em; }
.wiz-strat { flex: 1 1 380px; min-width: 260px; font-family: monospace; font-size: .82em; }
.wiz-pool { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 6px 10px; margin: 4px 0 0 0; font-size: .88em; border: 1px dashed rgba(128,128,128,.4); border-radius: 8px; }
.wiz-pool label { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
.wiz-group { flex-basis: 100%; font-weight: 600; font-size: .95em; margin: 14px 0 2px 0; padding-top: 10px; border-top: 1px solid rgba(128,128,128,.25); }
.wiz-group:first-child { border-top: 0; padding-top: 0; margin-top: 0; }
.wiz-full { flex-basis: 100%; }
`;

		const st = document.getElementById('hp-wiz-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-wiz-style' }, [ WIZ_CSS ]));

		/* ── Tab frame ─────────────────────────────────────────────────── */
		const TABS = [
			[ 'diag', _('Provider diagnostics') ],
			[ 'services', _('Services → exits') ],
			[ 'dpi', _('DPI bypass') ],
			[ 'extra', _('Advanced') ]
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
			[ _('Checks a set of test services (YouTube, Discord, Telegram, WhatsApp, Google AI, OpenAI, Claude, Twitch…) through your real paths. The VERDICT speaks about your CONFIGURED routing (rules, learned lists and Zapret/ByeDPI desync) — the way LAN clients are actually served; the Direct column is reference: it shows whether the resource could open with no VPN at all. A response whose redirect chain is reset mid-way is not a success, and a 200 with an application-level refusal (geo, Gemini "something went wrong") is not either. When a refusal is about the remote region rather than the local provider, the verdict says so (geo-block) — a routing strategy cannot fix a region refusal, a node with a supported region can. RU services (rutube, gosuslugi) are control hosts — they must always open directly.') ]));
		panes.diag.appendChild(E('div', { 'class': 'wiz-toolbar' }, [ customHosts, startBtn ]));
		/* dpi-detect seeds (Ф8-F1): the splify2-lists watchlist of domains the
		 * provider's TSPU is confirmed cutting (upstream rechecks every 6 h).
		 * "Update" downloads + RU-filters the list (.ru/.su/.рф never probed);
		 * up to 12 of the hosts join the NEXT scan as diagnostic probes. The
		 * row shows the seed count / progress; scan outcomes stay in the ONE
		 * result area below. */
		const dpiStatus = E('span', { style: 'opacity:.75' }, [ _('not loaded') ]);
		const dpiBtn = E('button', {
			'class': 'btn cbi-button cbi-button-action', type: 'button'
		}, [ _('Update TSPU list') ]);
		dpiBtn.addEventListener('click', function() {
			dpiBtn.disabled = true;
			callDpiUpdate().then(function(r) {
				if (!r || r.result === false)
					ui.addNotification(null, E('p', {}, _('List update failed: ') + ((r && r.error) || '')), 'error');
				return refresh();
			}).finally(function() { dpiBtn.disabled = false; });
		});
		function updateDpiStatus(scan) {
			const dd = (scan && scan.dpi_detect) || {};
			const st = dd.status || null;
			const running = st && st.stage === 'run' &&
				(Date.now() / 1000 - Number(st.ts || 0)) < 180;
			if (running) {
				dpiStatus.textContent = _('updating…');
				return;
			}
			if (st && st.stage === 'error') {
				dpiStatus.textContent = _('error: %s').format(st.error || _('unknown'));
				return;
			}
			const n = Number(dd.count || 0);
			if (!n)
				dpiStatus.textContent = _('not loaded');
			else
				dpiStatus.textContent = _('%s domains').format(String(n)) +
					(st && st.ts ? ' · ' + new Date(Number(st.ts) * 1000).toLocaleString() : '');
		}
		panes.diag.appendChild(E('div', { 'class': 'wiz-toolbar' }, [
			E('span', { 'class': 'wiz-note', style: 'margin:0' },
				[ _('TSPU watchlist (dpi-detect):'), ' ', dpiStatus ]),
			dpiBtn
		]));
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

		/* Custom domain lists (Ф7/D6) — collapsed so they do not clutter the
		 * everyday flow; a save reports into the ONE result area below. */
		const dListProxy = E('textarea', {
			'rows': '6', 'spellcheck': 'false',
			'style': 'width:100%; font-family:monospace; font-size:.85em'
		});
		const dListDirect = E('textarea', {
			'rows': '6', 'spellcheck': 'false',
			'style': 'width:100%; font-family:monospace; font-size:.85em'
		});
		const dListSave = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Save domain lists') ]);
		dListSave.addEventListener('click', function() {
			dListSave.disabled = true;
			dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Saving…') ]));
			Promise.all([
				L.resolveDefault(callAclListWrite('proxy_list', dListProxy.value || ''), {}),
				L.resolveDefault(callAclListWrite('direct_list', dListDirect.value || ''), {})
			]).then(function(res) {
				const bad = (!res[0] || res[0].result === false || !res[1] || res[1].result === false);
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ bad
					? _('Saving the domain lists failed.')
					: _('Domain lists saved — the proxy list merges with the learned records on the next config reload (the service reloads it automatically).') ]));
			}).finally(function() { dListSave.disabled = false; });
		});
		L.resolveDefault(callAclListRead('proxy_list'), {}).then(function(r) {
			dListProxy.value = (r && r.content) ? String(r.content) : '';
		});
		L.resolveDefault(callAclListRead('direct_list'), {}).then(function(r) {
			dListDirect.value = (r && r.content) ? String(r.content) : '';
		});
		panes.services.appendChild(E('details', { style: 'margin:10px 0' }, [
			E('summary', { style: 'cursor:pointer; font-weight:600' },
				[ _('Custom domain lists (advanced)') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('One host per line. The proxy list is merged with the engine-learned records (one watched rule-set); the direct list wins over the proxy list for matching domains. These are the manual routing inputs — presets above cover the known services.') ]),
			E('div', { 'class': 'wiz-row' }, [
				E('span', { 'class': 'wiz-title' }, [ _('Proxy domains') ]),
				dListProxy
			]),
			E('div', { 'class': 'wiz-row' }, [
				E('span', { 'class': 'wiz-title' }, [ _('Direct domains') ]),
				dListDirect
			]),
			E('div', { 'class': 'wiz-toolbar' }, [ dListSave ])
		]));
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

		/* ── Advanced pane (Ф6): Telegram bot v2 — on-demand checks ────── */
		const tgStatus = E('div', { 'class': 'wiz-row' });
		const tgResult = E('div', {});

		const tgEnabled = E('input', { type: 'checkbox' });
		const tgMute = E('input', { type: 'checkbox' });
		const tgToken = E('input', {
			type: 'password', 'class': 'cbi-input-text', style: 'flex:1 1 260px',
			placeholder: _('BotFather token (kept if left empty)')
		});
		const tgClearToken = E('input', { type: 'checkbox' });
		const tgChat = E('input', {
			type: 'text', 'class': 'cbi-input-text', style: 'flex:1 1 260px',
			placeholder: _('chat_id (leave empty — the first message to the bot pins the chat)')
		});
		const tgPushHs = E('input', { type: 'checkbox' });
		const tgPushWd = E('input', { type: 'checkbox' });
		const tgPushLr = E('input', { type: 'checkbox' });
		const tgPushSv = E('input', { type: 'checkbox' });
		const tgPoll = E('input', { type: 'number', min: '5', max: '60', style: 'width:90px', 'class': 'cbi-input-text' });
		const tgPival = E('input', { type: 'number', min: '1', max: '30', style: 'width:90px', 'class': 'cbi-input-text' });

		const tgU = (opt, def) => {
			const v = uci.get('homeproxy', 'telegram', opt);
			return (v != null && String(v).length && String(v) !== '0') ? String(v) : def;
		};
		tgEnabled.checked = (tgU('enabled', '0') === '1');
		tgMute.checked = (tgU('mute', '0') === '1');
		tgPushHs.checked = (tgU('push_hotswap', '1') === '1');
		tgPushWd.checked = (tgU('push_watchdog', '1') === '1');
		tgPushLr.checked = (tgU('push_learn', '1') === '1');
		tgPushSv.checked = (tgU('push_service', '1') === '1');
		tgPoll.value = tgU('poll_timeout', '25');
		tgPival.value = tgU('push_interval', '2');
		tgChat.value = tgU('chat_id', '');

		const tgLabel = (input, text) => E('label', {
			style: 'display:inline-flex;align-items:center;gap:5px;white-space:nowrap'
		}, [ input, E('span', {}, [ text ]) ]);

		function renderTelegramStatus(st) {
			st = st || {};
			let state;
			if (st.running && st.enabled)
				state = badge('hpui-b-green', _('Bot is running'));
			else if (st.running && !st.enabled)
				state = badge('hpui-b-grey', _('Daemon idle — bot disabled'));
			else
				state = badge('hpui-b-red', _('Daemon is not running'));
			const bits = [
				state,
				' ',
				st.chat_id ? E('span', {}, [ _('Chat: ') + String(st.chat_id) ])
					: E('span', { style: 'opacity:.8' }, [ _('Chat: not bound yet') ]),
				st.muted ? E('span', {}, [ ' · ', _('pushes muted') ]) : E('span', {}, [ ' · ', _('pushes on') ]),
				E('span', {}, [ ' · ' + _('long-poll') + ' ' + (st.poll_timeout || 25) + ' s · ' +
					_('push gap') + ' ' + (st.push_interval || 2) + ' s' ])
			];
			dom.content(tgStatus, E('span', {}, bits));
		}

		function checkTelegram() {
			return L.resolveDefault(callTelegramStatus(), {}).then(function(st) {
				renderTelegramStatus(st);
			});
		}

		const tgSaveBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' }, [ _('Save bot settings') ]);
		const tgTestBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Send test message') ]);
		const tgCheckBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Check status') ]);

		tgSaveBtn.addEventListener('click', function() {
			tgSaveBtn.disabled = true;
			callTelegramSet(
				tgEnabled.checked ? '1' : '0',
				tgClearToken.checked ? '!' : String(tgToken.value || '').trim(),
				String(tgChat.value || '').trim(),
				tgMute.checked ? '1' : '0',
				tgPushHs.checked ? '1' : '0',
				tgPushWd.checked ? '1' : '0',
				tgPushLr.checked ? '1' : '0',
				tgPushSv.checked ? '1' : '0',
				String(tgPoll.value || '25'),
				String(tgPival.value || '2')
			).then(function(r) {
				dom.content(tgResult, E('p', { 'class': 'hpui-hint' },
					(!r || r.result === false)
						? [ _('Save failed: ') + ((r && r.error) || _('rpc error')) ]
						: [ _('Saved. The bot re-reads its settings within ~15 s — no service restart needed.') ]));
				return checkTelegram();
			}).finally(function() { tgSaveBtn.disabled = false; });
		});

		tgTestBtn.addEventListener('click', function() {
			tgTestBtn.disabled = true;
			dom.content(tgResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking...') ]));
			L.resolveDefault(callTelegramTest(), {}).then(function(r) {
				let txt;
				if (r && r.bot_username)
					txt = _('Bot: @') + r.bot_username;
				else
					txt = _('Bot check failed');
				if (r && r.result !== false) {
					if (r.sent === true)
						txt += ' · ' + _('test message sent — check your chat');
					else if (r.error === 'no chat yet')
						txt += ' · ' + _('no chat bound yet — send any message to the bot first');
					else if (r.sent === false)
						txt += ' · ' + _('test message NOT sent');
				} else {
					txt += ((r && r.error) ? (' · ' + r.error) : '');
				}
				dom.content(tgResult, E('p', { 'class': 'hpui-hint' }, [ txt ]));
				return checkTelegram();
			}).finally(function() { tgTestBtn.disabled = false; });
		});

		tgCheckBtn.addEventListener('click', function() {
			tgCheckBtn.disabled = true;
			checkTelegram().finally(function() { tgCheckBtn.disabled = false; });
		});

		const tgRow1 = E('div', { 'class': 'wiz-row' }, [
			tgLabel(tgEnabled, _('Enable Telegram bot')),
			tgLabel(tgMute, _('Mute push notifications'))
		]);
		const tgRow2 = E('div', { 'class': 'wiz-row' }, [
			tgToken,
			tgLabel(tgClearToken, _('remove stored token'))
		]);
		const tgRow3 = E('div', { 'class': 'wiz-row' }, [ tgChat ]);
		const tgRow4 = E('div', { 'class': 'wiz-row' }, [
			tgLabel(tgPushHs, _('Hot Swap node changes / failback')),
			tgLabel(tgPushWd, _('URLTest dead nodes')),
			tgLabel(tgPushLr, _('Automation learned blocks')),
			tgLabel(tgPushSv, _('Service faults'))
		]);
		const tgRow5 = E('div', { 'class': 'wiz-row' }, [
			E('span', {}, [ _('Long-poll timeout, s') + ' ' ]), tgPoll,
			E('span', {}, [ _('Min gap between pushes, s') + ' ' ]), tgPival
		]);
		const tgRow6 = E('div', { 'class': 'wiz-toolbar' }, [ tgSaveBtn, tgTestBtn, tgCheckBtn ]);

		panes.extra.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Remote control from your Telegram chat: /status, /nodes, /switch N (switches the exit without a restart), /service, /snapshot, /status_engine, /mute. Push notifications watch the router state files — Hot Swap node changes, dead URLTest nodes, automation learning and service faults. The daemon always runs and re-reads these settings on its own, so saving never restarts the service. Get the token from @BotFather; the first message to the bot binds your chat.') ]));
		panes.extra.appendChild(tgStatus);
		panes.extra.appendChild(tgRow1);
		panes.extra.appendChild(tgRow2);
		panes.extra.appendChild(tgRow3);
		panes.extra.appendChild(tgRow4);
		panes.extra.appendChild(tgRow5);
		panes.extra.appendChild(tgRow6);
		panes.extra.appendChild(tgResult);
		checkTelegram();

		/* Badge / text helpers ─────────────────────────────────────────── */
		const badge = (cls, text) => E('span', { 'class': 'hpui-badge ' + cls }, [ text ]);

		const VERDICTS = {
			opens_direct:   [ 'hpui-b-green', _('Opens directly') ],
			works_live:     [ 'hpui-b-green', _('Works via the configured path') ],
			needs_proxy:    [ 'hpui-b-red', _('Needs proxy — create a rule') ],
			needs_strategy: [ 'hpui-b-amber', _('Provider cuts the path (DPI)') ],
			dns_poison:     [ 'hpui-b-amber', _('DNS poisoning (fake answers)') ],
			geo_blocked:    [ 'hpui-b-red', _('Blocked on the remote side (geo)') ],
			main_path_fail: [ 'hpui-b-red', _('Main path fails (check the node)') ],
			config_broken:  [ 'hpui-b-amber', _('Configured path fails — check the rule/strategy') ],
			control_fail:   [ 'hpui-b-red', _('RU site unreachable directly — anomaly') ],
			down:           [ 'hpui-b-grey', _('Unreachable both ways') ],
			partial:        [ 'hpui-b-grey', _('Only the main path was measured') ],
			unknown:        [ 'hpui-b-grey', _('No data') ]
		};

		/* The scanner sees no rules; the client remaps the verdict to what the
		 * user configured (Ф8-W2): with an enabled rule for the service the
		 * configured path IS the rule, so "opens directly + live works" reads
		 * as "works via the configured path (→ node)", not as "no VPN needed". */
		function effVerdict(r, rule) {
			if (r.verdict === 'opens_direct' && rule && rule.enabled && r.svc !== 'ru_control')
				return 'works_live';
			return r.verdict;
		}

		function verdictCell(r, rule) {
			const v = effVerdict(r, rule);
			const spec = VERDICTS[v] || VERDICTS.unknown;
			let label = spec[1];
			if (v === 'works_live' && rule && rule.enabled)
				label = _('Works via the configured path') + ' (→ ' + nodeText(rule.node) + ')';
			if (v === 'geo_blocked') {
				const side = r.geo_side || 'remote';
				if (side === 'both')
					label = _('Cut on both sides (provider + remote)');
				else if (side === 'exit')
					label = _('The service refuses the exit node region');
				else
					label = _('Blocked on the remote side (geo)');
			}
			return badge(spec[0], label);
		}

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
			dns:       _('The provider tampers with DNS — Secure DNS (MultiDNS/DoH) usually fixes it'),
			rule:      _('Create a rule in the "Services → exits" tab'),
			strategy:  _('The provider cuts the path (DPI) — pick a working Zapret/ByeDPI strategy (Strategy Lab)'),
			node:      _('Blocked on the remote side (geo) — a node in a supported region fixes it'),
			node_both: _('Cut on both sides — a node in a supported region; the path to it may also need a working strategy'),
			node_exit: _('The service refuses this exit region — switch to another node (full check: the "Google AI" button below)'),
			main_path: _('The Main node is not serving this site — check the node'),
			anomaly:   _('Anomaly: RU services must open directly — check RU-protect / the internet'),
			config_broken: _('Bare paths work but the configured path does not — check the rule target or run the Strategy Lab'),
			ai_full:   _('Pages open, but the model request can still be refused by the exit region/IP — run the full check with the "Google AI" button below (Services → exits).'),
			none:      _('—')
		};

		/* Honest scope notes (R4): an HTTP probe cannot see UDP voice calls
		 * or streaming quality — say so instead of implying a verdict. */
		const SVC_NOTES = {
			telegram: _('Voice calls (UDP) are not measured by an HTTP probe.'),
			whatsapp: _('Voice calls (UDP) are not measured by an HTTP probe.'),
			twitch:   _('Page probe only — streaming quality is not measured.')
		};
		/* TSPU watchlist notes are VERDICT-AWARE: the upstream list flags
		 * domains cut by SOME provider's TSPU — the note must not claim a cut
		 * the scan just disproved (a "bare paths work" row would contradict
		 * its own recommendation column). */
		const DPI_NOTES = {
			strategy: _('TSPU watchlist (dpi-detect): the provider is confirmed cutting this resource — a Zapret/ByeDPI strategy is the candidate fix.'),
			open:     _('TSPU watchlist (dpi-detect): the upstream list flags this domain, but it opens fine here — this provider is not cutting it.'),
			config:   _('TSPU watchlist (dpi-detect): the upstream list flags this domain, and bare paths work here — the configured path itself is failing: check the rule target or the strategy.'),
			other:    _('TSPU watchlist (dpi-detect): the upstream list reports confirmed provider cuts — see the measured verdict of this row.')
		};
		function dpiDetectNote(v) {
			if (v === 'needs_strategy') return DPI_NOTES.strategy;
			if (v === 'opens_direct' || v === 'works_live') return DPI_NOTES.open;
			if (v === 'config_broken') return DPI_NOTES.config;
			return DPI_NOTES.other;
		}

		/* ── TG WS Proxy card (D8, Ф7): «Telegram без прокси» ─────────────
		 * Third-party component (valnesfjord/tg-ws-proxy-rs). Detection is
		 * read-only; the component's own LuCI page stays the configuration
		 * point. Results of all buttons land in twResult (ONE place). */
		const twRow = E('div', { 'class': 'wiz-row' });
		const twResult = E('div', {});
		let twRsPresent = false;
		let twGoManaged = false;
		/* Poll-friendly result area: check/install outcomes are shown ONCE
		 * (per signature) and never clobber a button answer the user is
		 * reading (ui.action_buttons_result_placement). */
		const twState = { insSig: null, ckSig: null, goSig: null, manual: false, seeded: false };
		const twCheckBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Check now') ]);
		const twLinkBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Show tg:// link') ]);
		const twInstallBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Install / update') ]);
		const twGoInstallBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Install tg-ws bridge') ]);

		function renderTgwsp(st) {
			st = st || {};
			const rs = st.rs || {}, go = st.go || {}, ck = st.check || {}, ins = st.install || {},
				goIns = st.go_install || {};
			twRsPresent = !!rs.present;
			twGoManaged = !!go.managed;
			const parts = [];
			if (rs.present) {
				const ver = rs.version ? String(rs.version).trim().split(' ').pop() : '';
				parts.push(badge('hpui-b-green', 'tg-ws-proxy-rs' + (ver ? ' ' + ver : '')));
				parts.push(rs.running
					? badge('hpui-b-blue', _('running'))
					: badge('hpui-b-grey', _('stopped')));
				if (rs.port)
					parts.push(E('span', { 'style': 'opacity:.8' },
						[ _('Port') + ' ' + String(rs.port) + (rs.listening ? ' ✓' : ' · ' + _('not listening')) ]));
				if (rs.faketls)
					parts.push(E('span', { 'style': 'opacity:.8' }, [ 'FakeTLS: ' + String(rs.faketls) ]));
			} else {
				parts.push(E('span', { 'style': 'opacity:.7' }, [ _('tg-ws-proxy-rs is not installed') ]));
			}
			if (go.managed) {
				/* Our procd instance — the transparent bridge of the tgws exit. */
				parts.push(badge('hpui-b-green', 'tg-ws bridge (SOCKS5)'));
				parts.push(go.running
					? badge('hpui-b-blue', _('running') +
						(go.port ? ' · 127.0.0.1:' + go.port : ''))
					: badge('hpui-b-red', _('stopped')));
			} else if (go.present)
				parts.push(badge('hpui-b-amber',
					_('variant 2 (Go manager) detected — managed by its own tgm tool')));
			if (st.conflict)
				parts.push(badge('hpui-b-red',
					_('the port collides with the app ports (%s)').format((st.our_ports || []).join(', '))));
			if (ins.running)
				parts.push(badge('hpui-b-amber', _('installer running (%s)…').format(ins.stage || '')));
			else if (ck.running)
				parts.push(badge('hpui-b-amber', _('Checking...')));
			dom.content(twRow, E('span', {}, parts));
			/* First render seeds the signatures: operations already finished
			 * before this page opened are old news, the status line already
			 * shows their outcome, never surface them as fresh results. */
			if (!twState.seeded) {
				twState.seeded = true;
				if (!ins.running && ins.stage && ins.stage !== 'fetch')
					twState.insSig = 'i' + ins.stage + ':' + (ins.rc == null ? '' : ins.rc) + ':' + (ins.error || '');
				if (!ck.running && ck.stage === 'done')
					twState.ckSig = 'c' + ck.stage + ':' + (ck.rc == null ? '' : ck.rc) + ':' + (ck.ok || 0) + ':' + (ck.fail || 0);
				else if (!ck.running && ck.stage === 'error')
					twState.ckSig = 'c' + ck.stage + ':' + (ck.rc == null ? '' : ck.rc);
				if (!goIns.running && goIns.stage)
					twState.goSig = 'g' + goIns.stage + ':' + (goIns.rc == null ? '' : goIns.rc) + ':' + (goIns.error || '');
			}
			/* Finished operations — report ONCE per signature, and never
			 * overwrite a button answer the user is currently reading. */
			if (ins.running || ck.running || goIns.running)
				twState.manual = false;
			if (!ins.running && ins.stage && ins.stage !== 'fetch') {
				const sig = 'i' + ins.stage + ':' + (ins.rc == null ? '' : ins.rc) + ':' + (ins.error || '');
				if (sig !== twState.insSig) {
					twState.insSig = sig;
					if (!twState.manual) {
						twState.manual = true;
						if (ins.stage === 'done')
							dom.content(twResult, E('p', { 'class': 'hpui-hint' },
								[ _('Installation finished — the status line above reflects the new state.') ]));
						else
							dom.content(twResult, E('p', { 'class': 'hpui-hint' },
								[ _('Installation failed (see /var/run/homeproxy/tgwsp_install.log on the router).') ]));
					}
				}
			}
			if (!ck.running && ck.stage === 'done') {
				const sig = 'c' + ck.stage + ':' + (ck.rc == null ? '' : ck.rc) + ':' + (ck.ok || 0) + ':' + (ck.fail || 0);
				if (sig !== twState.ckSig) {
					twState.ckSig = sig;
					if (!twState.manual) {
						twState.manual = true;
						if ((ck.ok || 0) === 0 && (ck.fail || 0) === 0)
							dom.content(twResult, E('p', { 'class': 'hpui-hint' },
								[ _('Nothing to check yet — add CF domains or an upstream on the component\'s own page, then run the check again.') ]));
						else
							dom.content(twResult, E('p', { 'class': 'hpui-hint' },
								[ _('Check finished: %d OK, %d FAIL (exit code %d).').format(ck.ok || 0, ck.fail || 0, ck.rc || 0) ]));
					}
				}
			} else if (!ck.running && ck.stage === 'error') {
				const sig = 'c' + ck.stage + ':' + (ck.rc == null ? '' : ck.rc);
				if (sig !== twState.ckSig) {
					twState.ckSig = sig;
					if (!twState.manual)
						dom.content(twResult, E('p', { 'class': 'hpui-hint' },
							[ _('Check failed (exit code %s — see /var/run/homeproxy/tgwsp_check.log on the router).').format(String(ck.rc || '?')) ]));
				}
			}
			/* F8-F2: bridge install outcome — same ONE-place rule. */
			if (!goIns.running && goIns.stage && goIns.stage !== 'api' && goIns.stage !== 'download') {
				const gsig = 'g' + goIns.stage + ':' + (goIns.rc == null ? '' : goIns.rc) + ':' + (goIns.error || '');
				if (gsig !== twState.goSig) {
					twState.goSig = gsig;
					if (!twState.manual) {
						twState.manual = true;
						if (goIns.stage === 'done')
							dom.content(twResult, E('p', { 'class': 'hpui-hint' },
								[ _('Bridge installed and running — the exit "tg-ws (transparent)" is now available for the Telegram preset (the select re-checks the bridge on every poll).') ]));
						else
							dom.content(twResult, E('p', { 'class': 'hpui-hint' },
								[ _('Bridge installation failed: %s (see /var/run/homeproxy/tgwsp_go_install.log on the router).').format(goIns.error || _('rpc error')) ]));
					}
				}
			}
		}

		twCheckBtn.addEventListener('click', function() {
			twCheckBtn.disabled = true;
			twState.ckSig = null;
			twState.manual = false;
			L.resolveDefault(callTgwspCheck(), {}).then(function(r) {
				if (!r || r.result === false)
					dom.content(twResult, E('p', { 'class': 'hpui-hint' },
						[ _('Check failed to start: ') + ((r && r.error) || _('rpc error')) ]));
				else
					dom.content(twResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking...') ]));
				return refresh();
			}).finally(function() { twCheckBtn.disabled = false; });
		});

		twLinkBtn.addEventListener('click', function() {
			twLinkBtn.disabled = true;
			L.resolveDefault(callTgwspLink(), {}).then(function(r) {
				if (!r || r.result === false) {
					dom.content(twResult, E('p', { 'class': 'hpui-hint' },
						[ _('No link: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				const box = E('div', {});
				box.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('Add an MTProto proxy in Telegram with this link (one per user secret):') ]));
				const links = (r.links || []);
				for (let i = 0; i < links.length; i++) {
					const inp = E('input', {
						'type': 'text', readonly: 'readonly',
						'style': 'width:100%; margin:4px 0; font-size:.85em',
						onclick: function() { this.select(); }
					});
					inp.value = links[i];
					box.appendChild(inp);
				}
				if ((r.links || []).length === 1 && navigator.clipboard) {
					const cp = E('button', { 'class': 'btn cbi-button cbi-button-apply', type: 'button' },
						[ _('Copy link') ]);
					cp.addEventListener('click', function() {
						navigator.clipboard.writeText(links[0]);
					});
					box.appendChild(cp);
				}
				if (r.server)
					box.appendChild(E('div', { 'class': 'wiz-note' },
						[ _('Server %s, port %s — LAN clients only, nothing is exposed to the WAN.').format(String(r.server), String(r.port || '')) ]));
				dom.content(twResult, box);
				twState.manual = true;
			}).finally(function() { twLinkBtn.disabled = false; });
		});

		twInstallBtn.addEventListener('click', function() {
			const warn = twRsPresent
				? _('Run the OFFICIAL tg-ws-proxy-rs installer again? It upgrades the third-party component (SHA-256 digests are verified from the GitHub release API).')
				: _('Install the THIRD-PARTY component tg-ws-proxy-rs (valnesfjord, MIT)? The official installer downloads the release binary and its LuCI page and verifies digests from the GitHub release API. Nothing is packed into this app; the configuration stays on the component\'s own page. LAN-only — no WAN port is opened.');
			if (!window.confirm(warn))
				return;
			twInstallBtn.disabled = true;
			twState.insSig = null;
			twState.manual = false;
			dom.content(twResult, E('p', { 'class': 'hpui-hint' }, [ _('Downloading and running the official installer…') ]));
			L.resolveDefault(callTgwspInstall(), {}).then(function(r) {
				if (!r || r.result === false)
					dom.content(twResult, E('p', { 'class': 'hpui-hint' },
						[ _('Installation failed to start: ') + ((r && r.error) || _('rpc error')) ]));
				return refresh();
			}).finally(function() { twInstallBtn.disabled = false; });
		});

		twGoInstallBtn.addEventListener('click', function() {
			const warn = twGoManaged
				? _('Re-run the tg-ws bridge installer? It re-downloads the release binary (SHA-256 verified from the GitHub release API) and restarts the local instance.')
				: _('Install the THIRD-PARTY tg-ws bridge (tg-ws-proxy-go, d0mhate, MIT)? It downloads the release binary (SHA-256 verified from the GitHub release API), installs a local procd instance listening on 127.0.0.1 only, and enables the "tg-ws (transparent)" exit for the Telegram preset. Voice calls (UDP) are not carried by the bridge.');
			if (!window.confirm(warn))
				return;
			twGoInstallBtn.disabled = true;
			twState.goSig = null;
			twState.manual = false;
			dom.content(twResult, E('p', { 'class': 'hpui-hint' }, [ _('Downloading and installing the bridge…') ]));
			L.resolveDefault(callTgwsInstall(), {}).then(function(r) {
				if (!r || r.result === false)
					dom.content(twResult, E('p', { 'class': 'hpui-hint' },
						[ _('Bridge installation failed to start: ') + ((r && r.error) || _('rpc error')) ]));
				return refresh();
			}).finally(function() { twGoInstallBtn.disabled = false; });
		});

		const twBtnRow = E('div', { 'class': 'wiz-toolbar' }, [ twCheckBtn, twLinkBtn, twInstallBtn, twGoInstallBtn ]);

		/* DOM order: the card lands right after the Telegram bot block. */
		panes.extra.appendChild(E('h4', { style: 'margin-top:16px' },
			[ _('Telegram without a proxy (TG WS Proxy)') ]));
		panes.extra.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Third-party bridges (MIT) carry Telegram over a WebSocket path DPI does not block — a way to use Telegram WITHOUT a VPN, not a separate service. The rs variant is MTProto-only (clients connect by a tg:// link); the Go bridge (installed by the button) adds the transparent "tg-ws" exit: LAN apps need NO proxy settings, and if the bridge dies, messaging falls back to the node — calls (UDP) keep riding the VPN. The bridge exits through a relay abroad, so Telegram shows that relay country instead of your home IP — expected for such a path. Detection of foreign installs is read-only; nothing is exposed to LAN/WAN, and neither bridge ships with this app.') ]));
		panes.extra.appendChild(twRow);
		panes.extra.appendChild(twBtnRow);
		panes.extra.appendChild(twResult);


		function probeCell(p) {
			if (p == null)
				return E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ _('n/a') ]);
			const title = ((p.tsec != null) ? (String(p.tsec) + ' s') : '') +
				(p.kind ? (' · ' + p.kind) : '');
			const slowHint = p.slow ? (' ' + _('slow %s s').format(String(p.tsec || '?'))) : '';
			if (p.ok)
				return E('span', { title: title }, [ badge('hpui-b-green', '✓ ' + (p.code || '')), slowHint ]);
			const why = p.geo_refused ? _('geo-refused') : (KINDS[p.kind] || (p.kind || 'fail'));
			return badge('hpui-b-red', '✗ ' + why + ' (' + (p.code || '000') + ')');
		}

		/* ── Scan rendering ────────────────────────────────────────────── */
		function renderScan(status, result, rules) {
			rules = rules || {};
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
			/* Recount client-side with the rule-aware mapping so the cards
			 * always agree with the table below (the scanner itself does not
			 * know the rules). */
			const counts = { opens_direct: 0, works_live: 0, needs_proxy: 0,
				needs_strategy: 0, dns_poison: 0, geo_blocked: 0 };
			for (let h in result.hosts) {
				const r0 = result.hosts[h];
				const v0 = effVerdict(r0, rules[r0.svc] || null);
				if (counts[v0] != null)
					counts[v0]++;
			}
			const mk = (num, cap, cls) => E('div', { 'class': 'hpui-card' }, [
				E('div', { 'class': 'hpui-num ' + (cls || '') }, [ String(num) ]),
				E('div', { 'class': 'hpui-cap' }, [ cap ])
			]);
			cards.appendChild(mk(counts.works_live, _('work via the configured path'), 'hpui-c-green'));
			cards.appendChild(mk(counts.opens_direct, _('open directly'), 'hpui-c-green'));
			cards.appendChild(mk(counts.needs_proxy, _('need a proxy rule'), 'hpui-c-red'));
			cards.appendChild(mk(counts.needs_strategy, _('need a strategy'), 'hpui-c-amber'));
			cards.appendChild(mk(counts.geo_blocked, _('geo-blocked'), 'hpui-c-red'));
			cards.appendChild(mk(counts.dns_poison, _('DNS-poisoned'), 'hpui-c-amber'));
			scanResult.appendChild(cards);

			if (!result.proxy_in && !result.mixed_in)
				scanResult.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('The diagnostic inbounds are unavailable (Custom routing / Custom JSON) — only a partial picture is possible.') ]));

			/* Column order follows the verdict (Ф8-W2): the CONFIGURED path
			 * and its verdict first; the direct/main-path probes are the
			 * reference diagnostics. */
			const thead = E('thead', {}, E('tr', {}, [
				E('th', {}, [ _('Resource') ]),
				E('th', {}, [ _('Configured path') ]),
				E('th', {}, [ _('Verdict') ]),
				E('th', {}, [ _('Configured') ]),
				E('th', {}, [ _('Direct') ]),
				E('th', {}, [ _('Via main path') ]),
				E('th', {}, [ _('DNS') ]),
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
				/* What already covers this resource (proxy_ru_rule by source).
				 * The scan's live column shows whether that configured path
				 * actually delivers it. */
				const rule = rules[r.svc] || null;
				const ruleCell = r.svc === 'dpi_detect'
					? E('span', { style: 'opacity:.55' }, [ _('diagnostic seed') ])
					: (rule
						? (rule.enabled
							? badge('hpui-b-blue', '→ ' + nodeText(rule.node))
							: badge('hpui-b-grey', _('disabled') + ' (→ ' + nodeText(rule.node) + ')'))
						: E('span', { style: 'opacity:.55' }, [ _('no rule') ]));
				const ev = effVerdict(r, rule);
				let rec = (r.recommend && RECOMMEND[r.recommend]) ? RECOMMEND[r.recommend] : '—';
				/* A rule already covers a "needs proxy" resource — say so. */
				if (r.verdict === 'needs_proxy' && rule)
					rec = _('Rule configured (→ %s) — the resource is covered by it.').format(nodeText(rule.node));
				/* The tg-ws bridge is MTProto-only (ch.91, lesson 95): this
				 * row's WEB probe cannot pass the bridge, so a needs_proxy
				 * verdict here does NOT mean "create a rule" — the rule is
				 * in place and serves the messaging apps, while the web
				 * version rides the group fallback (node). */
				if (r.verdict === 'needs_proxy' && rule && rule.enabled && rule.node === 'tgws-out')
					rec = _('Rule configured (→ %s) — it serves the Telegram apps (MTProto); the web version rides the node (group fallback).').format(nodeText(rule.node));
				if (r.verdict === 'needs_strategy' && rule && (rule.node === 'zapret-out' || rule.node === 'byedpi-out'))
					rec = _('The rule already leads to %s — run the Strategy Lab: the current strategy may not handle this resource.').format(nodeText(rule.node));
				/* google_ai (C2): the page shell opens everywhere; say plainly
				 * that the model goes through the configured node and what to
				 * do when the model itself refuses. */
				if (r.svc === 'google_ai' && (ev === 'works_live' || (r.verdict === 'opens_direct' && !rule)))
					rec = (rule && rule.enabled)
						? _('The page opens; the model goes through the configured node (→ %s). If the model refuses — check other nodes (the button in the Google AI check result below).').format(nodeText(rule.node))
						: _('The page opens; the model goes through the configured routing. If the model refuses — check other nodes or run the full check below (Services → exits).');
				/* opens_direct without a rule: mention the mass-list coverage
				 * when one is enabled (same honesty as the Services rows). */
				if (ev === 'opens_direct' && r.svc !== 'ru_control' && r.svc !== 'dpi_detect') {
					const mass = (rules['russia-inside'] && rules['russia-inside'].enabled) ? _('Russia Inside')
						: ((rules['refilter'] && rules['refilter'].enabled) ? _('Re-filter') : null);
					if (mass)
						rec = _('Covered by the mass list (%s) — it opens via the main node; a rule here overrides the list.').format(mass);
				}
				const hostCell = E('div', {}, [ E('span', { style: 'font-weight:600' }, [ String(r.host) ]) ]);
				const svcNote = (r.svc === 'dpi_detect') ? dpiDetectNote(ev) : SVC_NOTES[r.svc];
				if (svcNote) {
					const note = E('div', { 'class': 'wiz-note', style: 'margin:0' }, [ svcNote ]);
					hostCell.appendChild(note);
				}
				/* tg-ws rows (rule → tgws-out): the WEB probe result depends
				 * on which urltest member serves it — the MTProto-only bridge
				 * stalls on the web version (expected timeout), the node
				 * serves it. Messaging apps are unaffected either way; a
				 * timeout on this row does NOT mean the bridge is broken
				 * (the bridge has its own check in the Advanced tab). */
				if (r.svc === 'telegram' && rule && rule.enabled && rule.node === 'tgws-out')
					hostCell.appendChild(E('div', { 'class': 'wiz-note', style: 'margin:0' },
						[ _('The probe checks the WEB version through the configured path; the tg-ws bridge carries the Telegram apps (MTProto) only — the web check may time out while the group sits on the bridge, messaging clients are unaffected. Bridge status and check: the Advanced tab.') ]));
				const tr = E('tr', {}, [
					E('td', {}, [ hostCell ]),
					E('td', {}, [ probeCell(r.live) ]),
					E('td', {}, [ verdictCell(r, rule) ]),
					E('td', {}, [ ruleCell ]),
					E('td', {}, [ probeCell(r.direct) ]),
					E('td', {}, [ probeCell(r.proxy) ]),
					E('td', {}, [ dnsCell ]),
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
			dpiPendingCheck: null,
			/* Ф8-F4 composition builder: session-local profile draft (the
			 * APPLIED state lives on the server), the built args of the last
			 * server test, poll signatures. */
			compProfiles: [ { engine: 'zapret', resource: 'youtube', domains: '', strategy: '' } ],
			compBuilt: null, composeSig: null, composeSeeded: false, rbSig: null };

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

			/* A1: grouped rows — mass lists / services / CDN / other. Every
			 * rpcd SOURCE gets the SAME editable row (select + pool + Apply,
			 * one source = one rule, the RPC keeps that invariant); the mass
			 * lists are no longer view-only. */
			presetRows.innerHTML = '';
			presetRows.appendChild(E('div', { 'class': 'wiz-note' },
				[ _('The mass lists below already cover YouTube/Discord/Telegram and most blocked resources — a per-service rule overrides the mass list.') ]));

			function buildServiceRow(preset) {
				const rule = (list.rules || {})[preset.source];
				const count = (list.rule_counts || {})[preset.source] || 0;

				/* Ф8-F5 (D.2): a card with the fixed control grid on top
				 * (name | state | select | buttons) and the hints/pool as
				 * sub-rows below — columns line up across every row. */
				const wrap = E('div', { 'class': 'wiz-svc' });
				const row = E('div', { 'class': 'wiz-svc-grid' });

				const titleWrap = E('span', { 'class': 'wiz-title' }, [ preset.title ]);
				if (preset.hosts && preset.hosts.length)
					titleWrap.appendChild(E('span', { 'class': 'wiz-hosts' }, [ ' · ' + preset.hosts.join(', ') ]));
				row.appendChild(titleWrap);

				row.appendChild(E('span', { 'class': 'wiz-state' }, [ ruleStateText(rule, count) ]));

				const sel = E('select', { 'class': 'cbi-input-select wiz-select' });
				sel.appendChild(E('option', { value: '' }, [ _('Direct (remove rule)') ]));
				if (!env.main_is_direct)
					sel.appendChild(E('option', { value: 'main-out' }, [ _('Same as main node') ]));
				if (env.byedpi_enabled)
					sel.appendChild(E('option', { value: 'byedpi-out' }, [ 'ByeDPI' ]));
				if (env.zapret_enabled)
					sel.appendChild(E('option', { value: 'zapret-out' }, [ 'Zapret' ]));
				/* F8-F2: the transparent tg-ws exit — offered for Telegram only
				 * and only while the bridge is running (rpcd re-checks both). */
				if (preset.source === 'telegram' && env.tgws_ok)
					sel.appendChild(E('option', { value: 'tgws-out' },
						[ _('tg-ws (transparent)') ]));
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
				/* A1: the pool is the resilient exit for a secondary route —
				 * a single node defeats the purpose. */
				poolBox.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0; flex-basis:100%' },
					[ _('For a resilient secondary route pick a pool of at least 2 nodes.') ]));
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
							byedpi_disabled: _('ByeDPI is not enabled — enable it on the Client Settings page first.'),
							zapret_disabled: _('Zapret is not enabled — enable it on the Client Settings page first.'),
							tgws_not_running: _('The tg-ws bridge is not running — install/start it in the Advanced tab first.'),
							tgws_telegram_only: _('The tg-ws bridge carries Telegram traffic only.'),
							urltest_pool_empty: _('Pick at least one node for the URLTest pool.'),
							unknown_node: _('Unknown node — refresh the page.'),
							unknown_source: _('Unknown service.'),
							'config generation failed': _('Config generation failed — the previous config stays active.')
						};
							const msg = ERRS[(r && r.error)] || ((r && r.error) || _('RPC error'));
							ui.addNotification(null, E('p', {}, msg), 'error');
							return;
						}
						if (r && r.unchanged) {
							/* Nothing changed — no restart, no auto-check, no
							 * refresh (a refresh would wipe this message). */
							dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
								[ _('Rule is already in place — nothing to apply.') ]));
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

				/* Apply (+ optional Check) share ONE grid column, so the
				 * select column stays aligned across rows with and without
				 * the Check button (Ф8-F5 D.2). */
				const btns = E('span', { 'class': 'wiz-svc-btns' });
				btns.appendChild(applyBtn);

				if (preset.check) {
					const checkBtn = E('button', {
						'class': 'btn cbi-button', type: 'button'
					}, [ _('Check') ]);
					checkBtn.addEventListener('click', function() {
						checkBtn.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking…') ]));
						runServiceCheck(preset.check).finally(function() { checkBtn.disabled = false; });
					});
					btns.appendChild(checkBtn);
				}
				row.appendChild(btns);
				wrap.appendChild(row);

				/* Pool picker + hints live BELOW the grid line (D.2). */
				wrap.appendChild(poolBox);

				/* A2: a row without its own rule is still covered by the mass
				 * lists — name what covers it and that a rule here overrides. */
				if (!rule) {
					const cov = [];
					if (list.rules['russia-inside'] && list.rules['russia-inside'].enabled)
						cov.push({ name: _('Russia Inside'), node: list.rules['russia-inside'].node });
					if (list.rules['refilter'] && list.rules['refilter'].enabled)
						cov.push({ name: _('Re-filter'), node: list.rules['refilter'].node });
					if (cov.length) {
						const names = [];
						for (let c in cov)
							names.push(cov[c].name);
						wrap.appendChild(E('div', { 'class': 'wiz-note', style: 'margin:0' },
							[ _('Covered by the mass list (%s) → %s — a rule here overrides the list.').format(names.join(', '), nodeText(cov[0].node)) ]));
					}
				}

			/* T1 (G1): a SHORT, provider-independent hint — the exit country of
			 * the bridge differs per user, so no measured locations here. */
			if (preset.source === 'telegram')
				wrap.appendChild(E('div', { 'class': 'wiz-note', style: 'margin:0' },
					[ _('tg-ws (transparent) lets Telegram work WITHOUT a VPN — it is not a direct connection: messaging rides a local WS bridge (no proxy setup on devices) and falls back to the node automatically if the bridge dies; calls (UDP) stay on the VPN. Telegram will show the bridge relay\'s country instead of your home IP — expected for such a path. The rule routes both Telegram domains and MTProto DC IPs.') ]));

				return wrap;
			}

			const GROUPS = [
				[ _('Mass lists'), BULK_PRESETS ],
				[ _('Services'), PRESETS ],
				[ _('Games (IP-only)'), GAMING_PRESETS,
					_('Matched by destination IP (no domains) — a rule routes the game networks (launchers, match servers, voice) to the chosen exit.') ],
				[ _('CDN and hosting'), CDN_PRESETS ],
				[ _('Other'), MISC_PRESETS ]
			];
			for (let g in GROUPS) {
				presetRows.appendChild(E('div', { 'class': 'wiz-group' }, [ GROUPS[g][0] ]));
				if (GROUPS[g][2])
					presetRows.appendChild(E('div', { 'class': 'wiz-note' }, [ GROUPS[g][2] ]));
				const items = GROUPS[g][1];
				for (let p in items)
					presetRows.appendChild(buildServiceRow(items[p]));
			}
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

			/* Ф8-W2 (approved): when the current exit refuses the Google AI
			 * region gate, cycle the OTHER nodes — one API probe per node
			 * through a throwaway probe core; the result lands here, in the
			 * ONE result area (ui.action_buttons_result_placement). */
			if (r.service === 'google_ai') {
				const aiBtn = E('button', { 'class': 'btn cbi-button', type: 'button' },
					[ _('Check other nodes') ]);
				aiBtn.addEventListener('click', function() {
					aiBtn.disabled = true;
					dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
						[ _('Checking every node against the Google AI region gate (about 20 s)…') ]));
					L.resolveDefault(callAiNodesCheck(), {}).then(function(nr) {
						renderAiNodes(nr);
					}).finally(function() { aiBtn.disabled = false; });
				});
				checkResult.appendChild(aiBtn);
			}

			const routes = r.route || {};
			for (let h in routes) {
				const line = E('div', { 'class': 'wiz-note' });
				line.appendChild(document.createTextNode(h + ': '));
				line.appendChild(shortTrace(routes[h]));
				checkResult.appendChild(line);
			}
		}

		function renderAiNodes(r) {
			checkResult.innerHTML = '';
			if (!r || r.result === false) {
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
					[ _('Node check failed: ') + ((r && r.error) || _('RPC error')) ]));
				return;
			}
			checkResult.appendChild(E('div', { 'class': 'wiz-note' },
				[ _('Google AI — candidate nodes (one API probe per node):') ]));
			const nodes = r.nodes || [];
			for (let i = 0; i < nodes.length; i++) {
				const n = nodes[i];
				const line = E('div', { 'class': 'wiz-note' });
				line.appendChild(document.createTextNode(resolveTag(n.node) +
					((n.node === r.current) ? (' · ' + _('current node')) : '') + ': '));
				if (n.verdict === 'passes')
					line.appendChild(badge('hpui-b-green', '✓ ' + _('region passes')));
				else if (n.verdict === 'refused')
					line.appendChild(badge('hpui-b-red', '✗ ' + _('region refused')));
				else if (n.verdict === 'unreachable')
					line.appendChild(badge('hpui-b-grey', '✗ ' + _('unreachable')));
				else
					line.appendChild(badge('hpui-b-amber', '? ' + _('uncertain')));
				checkResult.appendChild(line);
			}
			if (!nodes.length)
				checkResult.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('No nodes found in the running config.') ]));
			if (r.truncated)
				checkResult.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('Some nodes were not checked (limit 12).') ]));
			checkResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('To switch the exit: Services → exits → Google AI → pick this node.') ]));
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
			state.cands = cands || [];
			const sig = JSON.stringify((cands || []).map(function(c) { return c.name; }));
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
			[ _('The strategy serves the flows routed to ByeDPI (Main node = ByeDPI, service rules, or the Composition profiles below). Save writes the strategy and the flags and restarts the service; ByeDPI itself is enabled on the Client Settings page. UDP over TCP wraps UDP traffic into the ByeDPI TCP stream; Block QUIC drops outgoing UDP 443 so browsers fall back to TCP where the strategy works; Discord calls via Zapret routes the Discord voice UDP ports to Zapret (needs Zapret enabled).') ]));
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
						style: 'font-weight:600;color:' + (t.ok ? '#3fbf5f' : '#e05252'),
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
									style: 'font-weight:600; margin-right:3px; color:' + (t.ok ? '#3fbf5f' : '#e05252'),
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
				renderCompProfiles();
			});

			const resSel = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:132px' });
			for (let r in COMP_RESOURCES)
				resSel.appendChild(E('option', { value: COMP_RESOURCES[r][0] }, [ COMP_RESOURCES[r][1] ]));
			resSel.value = p.resource || 'general';
			resSel.addEventListener('change', function() {
				p.resource = resSel.value;
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
			stratSel.value = (p.strategy && p.strategy.indexOf('--') === 0) ? '' : (p.strategy || '');
			stratSel.addEventListener('change', function() {
				if (stratSel.value)
					p.strategy = stratSel.value;
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
			if (eng === 'zapret' && p.strategy && p.strategy.indexOf('--') === 0) {
				hint.appendChild(document.createTextNode(' · '));
				hint.appendChild(E('span', { 'style': 'opacity:.7' },
					[ fuzzHintText(compCandidateByArgs(p.strategy)) ]));
			}

			const rm = E('button', { 'class': 'btn cbi-button', type: 'button',
				'style': 'padding:0 6px', title: _('Remove') }, [ '×' ]);
			rm.addEventListener('click', function() {
				state.compProfiles.splice(idx, 1);
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
			renderCompProfiles();
		});

		compClearBtn.addEventListener('click', function() {
			state.compProfiles = [];
			renderCompProfiles();
		});

		compTestBtn.addEventListener('click', function() {
			if (!state.compProfiles.length) {
				ui.addNotification(null, E('p', {}, _('Composition is empty — add at least one profile.')), 'error');
				return;
			}
			compTestBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Building and testing the composition on the router…') ]));
			L.resolveDefault(callComposeRun(state.compProfiles), {}).then(function(r) {
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
							style: 'font-weight:600;color:' + (r2.ok ? '#3fbf5f' : '#e05252')
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
							style: 'font-weight:600;color:' + (r2.ok ? '#3fbf5f' : '#e05252')
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

		/* Auto-tune (Ф8-F7 T3): ONE click — fuzz (reused when fresh) → best
		 * strategy for the resource → optional rule → apply with the server
		 * snapshot → live check of the configured path. Progress and the
		 * result render into dpiResult (ONE place). */
		const autSel = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto' });
		[ ['youtube', _('YouTube')], ['discord', _('Discord')],
		  ['telegram', _('Telegram')], ['general', _('General (best overall)')] ]
			.forEach(function(o) { autSel.appendChild(E('option', { value: o[0] }, [ o[1] ])); });
		const autFull = E('input', { type: 'checkbox' });
		const autSetRule = E('input', { type: 'checkbox', checked: '' });
		const autSetRuleWrap = E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
			[ autSetRule, ' ' + _('Also set the rule to Zapret (the strategy serves the resource through its rule)') ]);
		const autFullWrap = E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
			[ autFull, ' ' + _('Thorough (full corpus, up to ~15 min)') ]);
		const autStatus = E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ '' ]);
		const autBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Auto-pick strategy') ]);
		const autRow = E('div', { 'class': 'wiz-row' },
			[ autBtn, autSel, autFullWrap, autSetRuleWrap, autStatus ]);
		dpiLab.appendChild(autRow);
		dpiLab.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('One click: the fuzzer ranks the corpus (reused when fresh), the best strategy for the resource is applied with a server snapshot, and the resource is then checked through the configured path (code + seconds). Zapret only — ByeDPI strategies are configured in the ByeDPI card above.') ]));
		autSel.addEventListener('change', function() {
			autSetRuleWrap.style.display = (autSel.value === 'general') ? 'none' : '';
		});
		autBtn.addEventListener('click', function() {
			const resource = autSel.value;
			const mode = autFull.checked ? 'full' : 'quick';
			const what = (mode === 'full')
				? _('Auto-pick the best strategy for %s? This may first run the FULL fuzz (up to ~15 min), then applies the winner with a server snapshot (Restore stays available) and checks the resource live.')
				: _('Auto-pick the best strategy for %s? It uses the recent fuzz ranking (or runs a quick fuzz first), applies the winner with a server snapshot (Restore stays available) and checks the resource live.');
			if (!window.confirm(what.format(autSel.options[autSel.selectedIndex].text)))
				return;
			autBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Starting the auto-pick…') ]));
			L.resolveDefault(callAutoPickStart(resource, mode, autSetRule.checked), {}).then(function(r) {
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
		const apInterval = E('input', { type: 'number', min: '1', max: '24', 'class': 'cbi-input-text', style: 'width:70px', value: '6' });
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
		[ ['youtube', _('YouTube')], ['discord', _('Discord')],
		  ['telegram', _('Telegram')], ['general', _('General (best overall)')] ]
			.forEach(function(o) {
				apResWrap.appendChild(E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
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
		dpiLab.appendChild(E('div', { style: 'margin-top:14px; border-top:1px solid rgba(127,127,127,.25); padding-top:8px' },
			[ apHead, apRow1, apResWrap, apRow3, E('p', { 'class': 'wiz-note' },
				[ _('The auto-pilot keeps the strategies working without attention: on schedule it re-ranks the corpus and applies the best strategy per resource (a >10% win replaces the current one); when a resource fails the checks repeatedly, the next alternative applies immediately. With "Keep the rules on Zapret" the managed resources get their rule pointed at Zapret — a strategy serves a resource only through its rule, and the Telegram rule is left alone while the tg-ws bridge serves it. Every apply takes a server snapshot — Restore always reverts. ByeDPI strategies are not managed.') ]), apStatus ]));
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
							(w.tls_ms > 0 ? ' · ' + _('~%d ms TLS').format(w.tls_ms) : '')));
					const p = r.probe || {};
					if (p && p.ts)
						line.appendChild(document.createTextNode(' '));
					if (p && p.ts)
						line.appendChild(p.ok
							? badge('hpui-b-green', '✓ ' + (p.code || '') + ((p.tsec != null) ? (' · ' + p.tsec + ' s') : ''))
							: badge('hpui-b-red', '✗ ' + (p.code || '000')));
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
				ui.addNotification(null, E('p', {}, _('Enable Zapret or ByeDPI on the Client Settings page first.')), 'error');
				return;
			}
			chainBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Applying the rule — the route check follows…') ]));
			L.resolveDefault(callPresetApply(src, eng, []), {}).then(function(r) {
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
				L.resolveDefault(callFuzzStatus(), {}),
				L.resolveDefault(callTgwspStatus(), {}),
				L.resolveDefault(callComposeStatus(), {}),
				L.resolveDefault(callAutoPickStatus(), {}),
				L.resolveDefault(callAutoPilotStatus(), {})
			]).then(function(data) {
				const scan = data[0] || {};
				updateDpiStatus(scan);
				renderScan(scan.status, scan.result, scan.rules);
				if (data[1] && data[1].rules) {
					renderPresets(data[1]);
					renderChain();
				}
				renderDpi(data[2] || {});
				renderStrategySel((data[3] && data[3].candidates) || []);
				renderCorpus(data[2] ? (data[2].corpus || {}) : {}, data[4] || {});
				renderLab(data[5] || {});
				renderTgwsp(data[6] || {});
				/* Ф8-F4: compose test progress/result + the server-snapshot
				 * Restore row (covers composition AND plain strategy applies). */
				renderCompose(data[7] || {});
				/* Ф8-F7 T3: auto-pick progress/result (same ONE place). */
				renderAutoPick(data[8] || {});
				/* ч.97: the scheduled auto-pilot card (settings + live state). */
				renderAutoPilot(data[9] || {});
				renderRollback((data[2] && data[2].rollback) || null);

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

		return E('div', {}, [ tabBar, panes.diag, panes.services, panes.dpi, panes.extra ]);
	}
});
