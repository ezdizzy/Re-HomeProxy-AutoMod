/* Ravnex — Service rules (R3 v3b, 19-UX_REDESIGN p.5; Ф9.3 v3 rework)
 * The SINGLE place "which service exits through what". D29 (the user's
 * "most important point"): the page MAKES THE MODEL VISIBLE — the rule
 * ORDER map mirrors generate_client.uc in "Bypass blocking" mode, and
 * route_explain is the MAIN instrument (check the route, then assign an
 * exit). Preset rows keep the proven fixed control grid; the whole page
 * rides the v3 design system. One result area per zone; the expert grid
 * is gone (rules live only in the preset rows). */

'require dom';
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

/* Routing mode → display label (Ф3.1: the three-mode model). */
function routingModeLabelOf(mode) {
	switch (mode) {
		case 'proxy_banned_ru': return _('Bypass blocking (rule lists)');
		case 'global': return _('Everything through node');
		case 'direct': return _('Direct (all mechanisms off)');
		case 'custom':
		case 'custom_json': return _('legacy custom routing');
		default: return mode || '—';
	}
}

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

const callPresetDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_preset_delete',
	params: [ 'section_id' ],
	expect: { '': {} }
});

/* Ф4.2 (U7): the "add a rule" master — ALWAYS creates a NEW rule section
 * (an extra exit for the same service is a legitimate shape). */
const callPresetAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_preset_add',
	params: [ 'source', 'node', 'urltest_nodes' ],
	expect: { '': {} }
});

/* ── User lists (менеджер списков, U7) ─────────────────────────────────── */
const callListsList = rpc.declare({
	object: 'luci.homeproxy',
	method: 'lists_list',
	expect: { '': {} }
});
const callListCreate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_create',
	params: [ 'name', 'kind', 'ctype', 'node', 'urltest_nodes', 'content' ],
	expect: { '': {} }
});
const callListRead = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_read',
	params: [ 'id' ],
	expect: { '': {} }
});
const callListWrite = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_write',
	params: [ 'id', 'content', 'mode' ],
	expect: { '': {} }
});
const callListImport = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_import',
	params: [ 'id', 'url', 'mode' ],
	expect: { '': {} }
});
const callListUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_update',
	params: [ 'id', 'name', 'node', 'enabled', 'urltest_nodes' ],
	expect: { '': {} }
});
const callListDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_delete',
	params: [ 'id' ],
	expect: { '': {} }
});
const callListExport = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_export',
	params: [ 'id' ],
	expect: { '': {} }
});
const callListBackupList = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_backup_list',
	expect: { '': {} }
});
const callListBackupCreate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_backup_create',
	expect: { '': {} }
});
const callListBackupRestore = rpc.declare({
	object: 'luci.homeproxy',
	method: 'list_backup_restore',
	params: [ 'dir' ],
	expect: { '': {} }
});

/* Ф1.1b: applies run as tracked operations — poll app_op_status until the
 * server-side verified verdict. */
const callOpStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label
 * (same logic as wizard.js/diagnostics.js). */
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

const CSS = `
.wiz-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.wiz-toolbar input[type="text"] { flex: 1 1 260px; min-width: 200px; }
.wiz-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); margin: 6px 0; }
.wiz-title { flex: 1 1 220px; font-weight: 600; }
.wiz-state { flex: 1 1 240px; font-size: .88em; }
.wiz-select { min-width: 190px; max-width: 320px; }
/* Service rows use a FIXED grid — name | state | select | buttons on one
 * line, hints/pool on sub-rows below the card — so the control columns
 * line up across every row regardless of hint length (Ф8-F5 D.2). */
.wiz-svc { border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); margin: 6px 0; padding: 8px 10px; }
.wiz-svc-grid { display: grid; grid-template-columns: minmax(140px, 230px) minmax(180px, 1fr) minmax(190px, 300px) 210px; align-items: center; gap: 6px 10px; }
.wiz-svc-btns { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 8px; }
.wiz-svc-grid > .wiz-title, .wiz-svc-grid > .wiz-state { flex: none; }
.wiz-svc-grid > .wiz-select { width: 100%; }
.wiz-svc .wiz-pool { margin: 6px 0 0 0; }
.wiz-svc .hpui-hint { margin: 6px 0 0 0; }
@media (max-width: 900px) {
	.wiz-svc-grid { display: flex; flex-wrap: wrap; }
	.wiz-svc-grid > .wiz-title { flex: 1 1 220px; }
	.wiz-svc-grid > .wiz-state { flex: 1 1 240px; }
	.wiz-svc-grid > .wiz-select { width: auto; }
}
.wiz-hosts { color: var(--hp-grey); font-size: .82em; }
.wiz-pool { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 6px 10px; margin: 4px 0 0 0; font-size: .88em; border: 1px dashed var(--hp-panel-line-strong); border-radius: var(--hp-radius); }
.wiz-pool label { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
/* Ф9.3/D29: the rule-ORDER map — the model made visible. Static content
 * (rendered once), so hpui-stagger on the container is safe. */
.rmap { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 2px; }
.rmap-step { flex: 1 1 100%; display: flex; align-items: flex-start; gap: 10px; padding: 8px 12px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius-sm); background: var(--hp-panel-bg-2); }
.rmap-n { flex: none; width: 22px; height: 22px; border-radius: 50%; background: var(--hp-accent-fill, rgba(34,197,94,.12)); color: var(--hp-accent-strong); font-weight: 700; font-size: .82em; display: flex; align-items: center; justify-content: center; margin-top: 1px; }
.rmap-t { flex: 1 1 auto; font-size: .92em; }
.rmap-t b { display: block; }
.rmap-t .hpui-ic { color: var(--hp-accent-strong); width: 1.05em; height: 1.05em; flex: none; margin-right: 5px; vertical-align: -0.15em; }
.rmap-t em { display: block; opacity: .75; font-size: .95em; font-style: normal; }
.rmap-step.hpui-here { border-color: var(--hp-accent-strong); }
@media (min-width: 1100px) {
	.rmap-step { flex: 1 1 46%; }
}
/* Ф9.3: dense buttons (hpui-btn is sized for forms). */
.hpui-btn-sm { padding: 2px 10px; font-size: .84em; white-space: nowrap; }
`;

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
		? E('span', { 'class': 'hpui-badge hpui-b-blue' }, [ '→ ' + nodeText(rule.node) ])
		: E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ _('disabled') + ' (→ ' + nodeText(rule.node) + ')' ]));
	if (rule.node === 'urltest' && rule.urltest_nodes && rule.urltest_nodes.length)
		parts.push(E('span', { 'class': 'hpui-hint', style: 'margin:0' },
			[ _('pool: %d node(s)').format(rule.urltest_nodes.length) ]));
	/* Ф4.2: extra exits are shown in-row now — the stale "see the manual
	 * editor" pointer is gone. */
	if (count > 1)
		parts.push(E('span', { 'class': 'hpui-hint', style: 'margin:0' },
			[ _('+%d more rule(s) of this service — shown below').format(count - 1) ]));
	return E('span', {}, parts);
}

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
	if (v === 'ok' || v === 'served') return E('span', { 'class': 'hpui-badge hpui-b-green' }, [ '✓ ' + okText ]);
	if (v === 'refused') return E('span', { 'class': 'hpui-badge hpui-b-red' }, [ '✗ ' + badText ]);
	return E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ '? ' + _('uncertain') + ' (' + _('code') + ' ' + code + ')' ]);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function() {
		hp.uiShell();
		document.head.appendChild(E('style', {}, [ CSS ]));

		/* Service presets over the itdoginfo/allow-domains sources the
		 * generator already consumes (no new hardcode). `check` selects
		 * the RPC-backed live check; `hosts` are the route_explain
		 * targets for the rest (Ф4.4: every domain-shaped list gets a
		 * VERIFIED representative host so the live route check works
		 * right after the rule is applied; IP-only lists — the gaming
		 * group — get none by design: a hostname cannot match an
		 * ip_cidr ruleset). */
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
			{ source: 'tiktok', title: _('TikTok'), hosts: [ 'www.tiktok.com' ] },
			{ source: 'roblox', title: _('Roblox'), hosts: [ 'roblox.com' ] },
			{ source: 'google_play', title: _('Google Play'), hosts: [ 'play.google.com' ] },
			{ source: 'google-meet', title: _('Google Meet'), hosts: [ 'meet.google.com' ] }
		];

		/* A1: every rpcd SOURCE becomes an editable row, grouped. The mass
		 * lists use the same select/Apply path as presets — the RPC accepts
		 * any source. */
		const BULK_PRESETS = [
			{ source: 'russia-inside', title: _('itdoginfo/allow-domains - Russia Inside (1000+ entries)'), hosts: [ '4pda.to' ] },
			{ source: 'refilter', title: _('Re-filter (mass list of blocked domains/IPs — a base, coverage is NOT exhaustive)'), hosts: [ 'instagram.com' ] },
			{ source: 'block', title: _('Block (core RKN-blocked resources)'), hosts: [ 'signal.org' ] },
			{ source: 'russia-outside', title: _('Russia Outside (RU-only services — for use abroad)') },
			{ source: 'ukraine-inside', title: _('Ukraine Inside (resources blocked in UA)') }
		];
		const CDN_PRESETS = [
			{ source: 'cloudflare', title: _('Cloudflare CDN'), hosts: [ 'www.cloudflare.com' ] },
			{ source: 'cloudfront', title: _('CloudFront CDN') },
			{ source: 'digitalocean', title: _('DigitalOcean cloud hosting') },
			{ source: 'hetzner', title: _('Hetzner (Germany cloud hosting)') },
			{ source: 'ovh', title: _('OVH (France cloud hosting)') },
			{ source: 'hodca', title: _('HODCA') }
		];
		const MISC_PRESETS = [
			{ source: 'news', title: _('International news sites'), hosts: [ 'kasparov.ru' ] },
			{ source: 'porn', title: _('Adult content') },
			{ source: 'anime', title: _('Anime streaming') },
			{ source: 'geoblock', title: _('Geo-blocked services') },
			{ source: 'hdrezka', title: _('HDRezka'), hosts: [ 'hdrezka.ag' ] }
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

		/* D29 (refines D27): preset rows are NOT always visible. A row shows
		 * when it has a rule (main or extra), when it is Re-filter and any VPN
		 * node exists, or when it was revealed via the catalog. The old
		 * per-browser Hiding is GONE: hiding kept the rule working while the
		 * page pretended the service was unmanaged — the honest exit is a real
		 * "Delete rule" (wizard_preset_delete); the stale hiding key is
		 * dropped so previously hidden rows come back. */
		try { window.localStorage.removeItem('hp_rules_hidden_presets'); } catch (e) {}
		const state = { presetsSig: null, pendingCheck: null, lastList: null, visRev: 0, revealed: {} };
		let lastEnv = null;

		/* ── Base zone: presets ───────────────────────────────────────── */
		const envBanners = E('div', {});
		const presetRows = E('div', {});
		const checkResult = E('div', {});
		/* Ф9.3 v3: the ONE result area of the preset zone becomes a panel;
		 * actions (apply/delete/check/extra) replace the previous verdict
		 * here — ui.action_buttons_result_placement. */
		const checkPanel = E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('check'), _('Check results') ])
		]);
		checkPanel.appendChild(checkResult);
		dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
			[ _('Action results and live checks of the rows appear here.') ]));

		/* ── D29: the rule-ORDER map — the model made visible ────────────
		 * First match wins. The chain mirrors generate_client.uc in
		 * "Bypass blocking" mode (B6.9, lesson 201: the map MUST stay in
		 * sync with the generator — the old text note it replaces lived in
		 * renderPresets). Static content rendered once → stagger is safe.
		 * This map IS the D29 answer: "everything direct, lists and rules
		 * are the exceptions" is the tail step + the guard in the middle. */
		const ORDER_MAP = [
			[ 'tool', _('Pin "Always direct"'), _('A host pinned in the Automation table — outranks every list: one host forced to direct wins over everything.') ],
			[ 'activity', _('Service ports'), _('Torrents stay direct, calls ride the voice ports — port-scoped rules, not tied to a domain.') ],
			[ 'send', _('Service rules — THIS page'), _('Preset rows for services and mass lists (Services, Russia Inside, Re-filter). The rows below edit exactly this tier.') ],
			[ 'refresh', _('OAuth stability'), _('Login/auth domains ride the main exit together with their service — a proxy switch never breaks a login.') ],
			[ 'compass', _('Your "Direct" lists'), _('The "My lists" zone below with the "direct" action — the explicit "not through the node" intent.') ],
			[ 'shield', _('RU-guard'), _('RU-geo hosts NEVER go through the proxy — a mass or learned list cannot tunnel RU infrastructure. Always on (invariant).') ],
			[ 'database', _('Your "Proxy" lists'), _('The "My lists" zone with the "via proxy" action — checked AFTER the RU-guard: a RU domain in a proxy list stays direct.') ],
			[ 'globe', _('Mass pins + learned'), _('The proxy-domain list (your "Always via proxy" pins + sites the system learned) routes to the main node; manual and learned IPs follow.') ],
			[ 'ban', _('Everything else — DIRECT'), _('A host no rule matched egresses directly: the whole internet is direct by default, lists and rules are the exceptions. DNS mirrors this order.') ]
		];
		const orderMapBox = E('div', { 'class': 'hpui-cards hpui-stagger rmap' });
		for (let om = 0; om < ORDER_MAP.length; om++) {
			orderMapBox.appendChild(E('div', { 'class': 'rmap-step' + (ORDER_MAP[om][0] === 'send' ? ' hpui-here' : '') }, [
				E('span', { 'class': 'rmap-n' }, [ '' + (om + 1) ]),
				E('span', { 'class': 'rmap-t' }, [
					hp.icon(ORDER_MAP[om][0]),
					E('b', {}, [ ORDER_MAP[om][1] ]),
					E('em', {}, [ ORDER_MAP[om][2] ])
				])
			]));
		}
		const orderMapPanel = E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('layers'),
				_('How a route is decided — first match wins') ]),
			E('p', { 'class': 'hpui-hint' }, [
				_('The whole internet goes DIRECT by default; lists and rules are the exceptions that route traffic through a node or an engine. This is the exact order the running config follows — the first rule that matches decides. Keep it in mind while editing the rows below.')
			]),
			orderMapBox
		]);

		/* ── D29: route_explain — the MAIN instrument of the page ────────
		 * Check BEFORE you edit: the checker shows which rule of the RUNNING
		 * config matches first, the outbound chain, and the RU-guard / Master
		 * coverage verdict. Result replaces itself in ONE place (this panel).
		 * Quick chips = the services currently on the page (filled by
		 * renderPresets) + one RU example to see the guard at work. */
		const routePanel = E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('crosshair'), _('Check a route') ])
		]);
		const routeInput = E('input', { type: 'text', 'class': 'cbi-input-text',
			placeholder: _('example.com or 1.2.3.4'), style: 'flex:1 1 260px; min-width:220px' });
		const routeBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
			[ _('Check') ]);
		const routeChips = E('div', { 'class': 'wiz-toolbar', style: 'margin:2px 0 0' });
		const routeResult = E('div', { style: 'margin-top:6px' });
		routePanel.appendChild(E('p', { 'class': 'hpui-hint' }, [
			_('Enter a site — the checker answers with the winning rule of the LIVE config, the exit chain and the protection verdict. Remote rule-sets are matched by the core itself, so their exact membership is reported honestly as "probable".')
		]));
		routePanel.appendChild(E('div', { 'class': 'wiz-toolbar' }, [ routeInput, routeBtn ]));
		routePanel.appendChild(routeChips);
		routePanel.appendChild(routeResult);

		function routeChip(host, title) {
			const c = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button',
				title: title || host }, [ host ]);
			c.addEventListener('click', function() {
				routeInput.value = host;
				runRouteCheck();
			});
			return c;
		}

		function fillRouteChips(chips) {
			/* Rebuild only on a real change (the poll must not steal clicks). */
			const sig = JSON.stringify(chips);
			if (sig === routeChips._sig)
				return;
			routeChips._sig = sig;
			dom.content(routeChips, [ E('span', { 'class': 'hpui-hint', style: 'margin:0' },
				[ _('Quick check:') ]) ].concat(chips.map(function(ch) {
					return routeChip(ch[0], ch[1]);
				})));
		}

		function renderRouteVerdict(ret) {
			dom.content(routeResult, (function() {
				if (!ret || ret.error)
					return [ E('p', { 'class': 'hpui-hint' },
						[ _('Check failed: ') + ((ret && ret.error) || _('RPC error')) ]) ];
				const parts = [];
				/* The honest remote ambiguity (lesson 203): no outbound is
				 * claimed when remote lists are in play unconfirmed. */
				if (ret.remote && ret.remote.confirmed == null) {
					parts.push(E('div', { style: 'color:var(--hp-amber); margin:4px 0' },
						[ ret.match || _('Remote lists in play — exact match unavailable locally.') ]));
				} else {
					const probable = !!(ret.remote && ret.remote.confirmed != null);
					let outLabel;
					if (ret.outbound === 'direct-out')
						outLabel = _('Direct (no bypass engine)');
					else
						outLabel = ret.outbound ? resolveTag(ret.outbound) : (ret.action || '?');
					parts.push(E('div', { style: 'margin:4px 0' }, [
						E('strong', {}, [ outLabel ]),
						E('span', { style: 'opacity:.75' }, ' ← ' + (ret.match || '') +
							(ret.rule_index ? (' · ' + (probable ? _('probable winning rule') : _('winning rule')) + ' #' + ret.rule_index) : '') +
							(ret.fallback ? ' · ' + _('default route (no rule matched)') : ''))
					]));
				}
				if (ret.chain)
					parts.push(E('div', { style: 'opacity:.75; font-size:.88em; margin:2px 0' }, [ ret.chain ]));
				const cov = ret.coverage;
				if (cov && cov.status === 'protected_by_master')
					parts.push(E('div', { style: 'color:var(--hp-accent-strong); font-size:.88em' }, [ cov.note ]));
				else if (cov && cov.status === 'coverage_unknown')
					parts.push(E('div', { style: 'color:var(--hp-amber); font-size:.88em' }, [ cov.note ]));
				for (let t in (ret.trace || []))
					if (t.action === 'reject')
						parts.push(E('div', { style: 'color:var(--hp-amber); font-size:.88em' },
							[ _('rejects UDP/443 (QUIC escape)') + ' — ' + (t.match || '') ]));
				return parts;
			})());
		}

		function runRouteCheck() {
			const h = String(routeInput.value || '').trim().toLowerCase();
			if (!h) {
				dom.content(routeResult, E('p', { 'class': 'hpui-hint' },
					[ _('Enter a site or an IP to check.') ]));
				return;
			}
			dom.content(routeResult, E('p', { 'class': 'hpui-hint' }, [ _('Tracing…') ]));
			L.resolveDefault(callRouteExplain(h), {}).then(renderRouteVerdict);
		}
		routeBtn.addEventListener('click', runRouteCheck);
		routeInput.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') runRouteCheck(); });

	/* ── User lists (Ф4.2 менеджер списков) ──────────────────────────────
	 * The former two static textareas (proxy/direct) grow into a full list
	 * manager: named lists created with their kind (proxy/direct) and content
	 * type (domains/IPs) and an ACTION picked at creation — a list without a
	 * rule is a dead list (U6 honesty). Entries are validated and normalized
	 * through the ONE classifier at input; import sources (URL with an honest
	 * HTML-gate, pasted text, file) dedup and report accepted/dropped counts;
	 * snapshots live outside the snapshot-* rotation. */
	const listsZone = E('div', {});
	const listsResult = E('div', {});
	const listsState = { env: null, nodes: [], data: [], editId: null };
	/* Ф9.3 v3: the lists manager rides one hpui-panel (icon header). */
	const listsPanel = E('div', { 'class': 'hpui-panel' }, [
		E('h4', { 'class': 'hpui-h4' }, [ hp.icon('hardrive'), _('My lists') ])
	]);

	function listArea(text) {
		dom.content(listsResult, E('p', { 'class': 'hpui-hint' }, [ text ]));
	}

	/* One result area for the whole lists zone: every action replaces the
	 * previous verdict here (ui.action_buttons_result_placement). */
	function pollListOp(desc, okText, failText) {
		if (!desc || desc.hot || !desc.op_id) {
			listArea(okText);
			return;
		}
		const deadline = Date.now() + 150000;
		const tick = function() {
			return L.resolveDefault(callOpStatus(desc.op_id), {}).then(function(st) {
				const op = st && st.op;
				if (op && op.status !== 'completed' && op.status !== 'failed') {
					if (Date.now() > deadline) {
						listArea(_('The apply operation is still running — check the operations journal on the Health center page.'));
						return;
					}
					window.setTimeout(tick, 2000);
					return;
				}
				const ok = !!op && op.status === 'completed' && op.verified;
				listArea(ok ? okText : (failText + ((op && op.detail) ? (' — ' + op.detail) : '')));
			});
		};
		tick();
	}

	function listCounterLine(accepted, dropped) {
		let s = _('Entries accepted: %s').format('' + accepted);
		if (dropped > 0)
			s += ' · ' + _('rejected: %s (not a valid domain/IP for this list type)').format('' + dropped);
		return s;
	}

	function listExitLabel(node) {
		if (node === 'main-out') return _('Same as main node');
		if (node === 'direct-out') return _('Direct (no bypass engine)');
		if (node === 'byedpi-out') return 'ByeDPI';
		if (node === 'zapret-out') return 'Zapret';
		if (node === 'urltest') return _('URLTest pool');
		return resolveTag(node);
	}

	/* Exit <select> for a list kind: proxy lists ride a real exit (main node /
	 * URLTest pool / a node); direct lists ride direct-out or an engine
	 * (desync WITHOUT the VPN). Dead exits are not offered (the RPC re-checks). */
	function listExitSelect(kind, current, poolChecks, poolBox) {
		const sel = E('select', { 'class': 'cbi-input-select' });
		const env = listsState.env || {};
		if (kind === 'proxy') {
			if (!env.main_is_direct)
				sel.appendChild(E('option', { value: 'main-out' }, [ _('Same as main node') ]));
			sel.appendChild(E('option', { value: 'urltest' }, [ _('URLTest pool') ]));
			for (let n in (listsState.nodes || []))
				if (listsState.nodes[n].type !== 'direct')
					sel.appendChild(E('option', { value: listsState.nodes[n].id },
						[ listsState.nodes[n].label ]));
		} else {
			sel.appendChild(E('option', { value: 'direct-out' }, [ _('Direct (no bypass engine)') ]));
			if (env.zapret_enabled)
				sel.appendChild(E('option', { value: 'zapret-out' }, [ 'Zapret' ]));
			if (env.byedpi_enabled)
				sel.appendChild(E('option', { value: 'byedpi-out' }, [ 'ByeDPI' ]));
		}
		sel.value = current || sel.options[0].value;
		if (sel.selectedIndex < 0)
			sel.value = sel.options[0].value;
		sel.addEventListener('change', function() {
			if (poolBox)
				poolBox.style.display = (sel.value === 'urltest') ? 'flex' : 'none';
		});
		return sel;
	}

	function listPoolPicker(currentNodes) {
		const box = E('div', { 'class': 'wiz-pool', style: 'display:none; flex-wrap:wrap' });
		const checks = [];
		for (let n in (listsState.nodes || [])) {
			if (listsState.nodes[n].type === 'direct')
				continue;
			const cb = E('input', { type: 'checkbox', value: listsState.nodes[n].id });
			cb.checked = (currentNodes || []).indexOf(listsState.nodes[n].id) >= 0;
			checks.push(cb);
			box.appendChild(E('label', {}, [ cb, ' ' + listsState.nodes[n].label ]));
		}
		box.appendChild(E('span', { 'class': 'hpui-hint', style: 'margin:0; flex-basis:100%' },
			[ _('For a resilient secondary route pick a pool of at least 2 nodes.') ]));
		box._checks = checks;
		return box;
	}

	/* The lists zone: table + create master + editor + snapshots. */
	function renderListsZone() {
		listsZone.innerHTML = '';
		const data = listsState.data || [];
		const env = listsState.env || {};

		/* Table of existing lists. */
		const tbl = E('table', { 'class': 'hpui-table', style: 'margin:8px 0' });
		tbl.appendChild(E('thead', {}, [ E('tr', {}, [
			E('th', {}, [ _('Name') ]),
			E('th', {}, [ _('Direction') ]),
			E('th', {}, [ _('Entries') ]),
			E('th', {}, [ _('Action') ]),
			E('th', {}, [ _('Source') ]),
			E('th', {}, [ _('Actions') ])
		]) ]));
		const tb = E('tbody', {});
		for (let i = 0; i < data.length; i++) {
			const l = data[i];
			const tr = E('tr', {});
			tr.appendChild(E('td', {}, [ (l.enabled ? '' : '⏸ ') + (l.name || l.id) ]));
			tr.appendChild(E('td', {}, [
				E('span', { 'class': 'hpui-badge ' + (l.kind === 'direct' ? 'hpui-b-grey' : 'hpui-b-blue') },
					[ l.kind === 'direct' ? _('direct') : _('via proxy') ]),
				' ' + (l.ctype === 'ips' ? _('IP addresses') : _('domains'))
			]));
			tr.appendChild(E('td', {}, [
				'' + l.entries +
					((l.dropped > 0) ? (' · ' + _('rejected: %s').format('' + l.dropped)) : '')
			]));
			tr.appendChild(E('td', {}, [ listExitLabel(l.node) ]));
			tr.appendChild(E('td', { style: 'font-size:.85em' }, [ l.source_url || '—' ]));
			const btns = E('td', {}, [ E('span', { 'class': 'wiz-svc-btns' }, (function() {
				const arr = [];
				const eb = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' }, [ _('Edit') ]);
				eb.addEventListener('click', function() { listsState.editId = l.id; renderListsZone(); });
				arr.push(eb);
				const tb2 = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' },
					[ l.enabled ? _('Disable') : _('Enable') ]);
				tb2.addEventListener('click', function() {
					tb2.disabled = true;
					listArea(_('Applying…'));
					L.resolveDefault(callListUpdate(l.id, '', '', l.enabled ? '0' : '1', ''), {})
						.then(function(r) {
							if (!r || r.result === false)
								listArea(_('Failed: ') + ((r && r.error) || _('RPC error')));
							else if (r.unchanged)
								listArea(_('Nothing to change.'));
							else
								pollListOp(r.apply, _('The list state is applied.'), _('The list state failed to apply'));
							refreshLists();
						}).finally(function() { tb2.disabled = false; });
				});
				arr.push(tb2);
				const xb = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' }, [ _('Export') ]);
				xb.addEventListener('click', function() {
					xb.disabled = true;
					L.resolveDefault(callListExport(l.id), {}).then(function(r) {
						if (!r || r.result === false) {
							listArea(_('Export failed: ') + ((r && r.error) || _('RPC error')));
							return;
						}
						const blob = new Blob([ r.content || '' ], { type: 'text/plain;charset=utf-8' });
						const a = E('a', { href: URL.createObjectURL(blob),
							download: 'ravnex-list-' + l.id + '.txt' });
						document.body.appendChild(a);
						a.click();
						document.body.removeChild(a);
						window.setTimeout(function() { URL.revokeObjectURL(a.href); }, 5000);
						listArea(_('The list is exported (what actually routes, with a source comment).'));
					}).finally(function() { xb.disabled = false; });
				});
				arr.push(xb);
				const db = E('button', { 'class': 'hpui-btn hpui-btn-danger hpui-btn-sm', type: 'button' },
					[ _('Delete') ]);
				db.addEventListener('click', function() {
					hp.confirmModal(_('Delete list'), _('Delete the list "%s"? A snapshot is taken automatically before the deletion.').format(l.name || l.id), _('Delete'))
						.then(function(ok) {
							if (!ok) return;
							db.disabled = true;
							listArea(_('Deleting…'));
							L.resolveDefault(callListDelete(l.id), {}).then(function(r) {
								if (!r || r.result === false)
									listArea(_('Failed: ') + ((r && r.error) || _('RPC error')));
								else
									pollListOp(r.apply, _('The list is deleted (a snapshot was taken first).'), _('The list deletion failed to apply'));
								refreshLists();
							}).finally(function() { db.disabled = false; });
						});
				});
				arr.push(db);
				return arr;
			})()) ]);
			tr.appendChild(btns);
			tb.appendChild(tr);
		}
		if (!data.length)
			tb.appendChild(E('tr', {}, [ E('td', { colspan: '6', style: 'opacity:.7' },
				[ _('No lists yet — create one below (a single domain or IP is enough).') ]) ]));
		tbl.appendChild(tb);
		listsZone.appendChild(tbl);

		/* Editor (opened by Edit). */
		if (listsState.editId) {
			const cur = null;
			for (let i = 0; i < data.length; i++)
				if (data[i].id === listsState.editId)
					listsState.editData = data[i];
			const ed = listsState.editData;
			if (!ed) {
				listsState.editId = null;
			} else {
				const card = E('div', { 'class': 'wiz-svc', style: 'margin:10px 0' });
				card.appendChild(E('div', { 'class': 'wiz-title', style: 'margin-bottom:6px' },
					[ _('Edit list: %s').format(ed.name || ed.id) ]));
				const nameIn = E('input', { type: 'text', 'class': 'cbi-input-text',
					value: ed.name || '', style: 'width:280px' });
				const selRow = E('div', { 'class': 'wiz-row', style: 'margin:6px 0' }, [
					E('span', { 'class': 'wiz-title', style: 'flex:none; width:160px' }, [ _('Name') ]), nameIn ]);
				card.appendChild(selRow);
				const poolBox2 = listPoolPicker(null);
				const exitSel = listExitSelect(ed.kind, ed.node, null, poolBox2);
				exitSel.value = ed.node || exitSel.value;
				card.appendChild(E('div', { 'class': 'wiz-row', style: 'margin:6px 0' }, [
					E('span', { 'class': 'wiz-title', style: 'flex:none; width:160px' }, [ _('Action') ]), exitSel ]));
				card.appendChild(poolBox2);
				const ta = E('textarea', { rows: '8', spellcheck: 'false',
					style: 'width:100%; font-family:monospace; font-size:.85em' });
				ta.value = _('Loading…');
				L.resolveDefault(callListRead(ed.id), {}).then(function(r) {
					ta.value = (r && r.content != null) ? String(r.content) : '';
				});
				card.appendChild(ta);
				/* Import row: URL (replace / append) + local file. */
				const urlIn = E('input', { type: 'text', 'class': 'cbi-input-text',
					placeholder: 'https://…', style: 'flex:1 1 260px; min-width:200px' });
				const impRep = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' }, [ _('Replace from URL') ]);
				const impApp = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' }, [ _('Append from URL') ]);
				const fileIn = E('input', { type: 'file', 'class': 'cbi-input-file' });
				fileIn.addEventListener('change', function() {
					const f = fileIn.files && fileIn.files[0];
					if (!f) return;
					const rd = new FileReader();
					rd.onload = function() {
						ta.value = String(rd.result || '');
						listArea(_('File loaded into the editor — press Save to apply (entries are validated at save).'));
					};
					rd.readAsText(f);
				});
				function doImport(mode) {
					if (!urlIn.value) {
						listArea(_('Enter the source URL first.'));
						return;
					}
					impRep.disabled = true; impApp.disabled = true;
					listArea(_('Importing…'));
					L.resolveDefault(callListImport(ed.id, urlIn.value, mode), {}).then(function(r) {
						if (!r || r.result === false) {
							listArea(_('Import failed: ') + ((r && r.error) || _('RPC error')));
							return;
						}
							listArea(listCounterLine(r.accepted, r.dropped) + ' · ' + (r.apply && r.apply.hot ? _('applied live (hot reload).') : _('Applying…')));
						pollListOp(r.apply, listCounterLine(r.accepted, r.dropped) + ' · ' + _('applied — the core runs the updated list.'),
							_('The import failed to apply'));
						refreshLists();
					}).finally(function() { impRep.disabled = false; impApp.disabled = false; });
				}
				impRep.addEventListener('click', function() { doImport('replace'); });
				impApp.addEventListener('click', function() { doImport('append'); });
				card.appendChild(E('div', { 'class': 'wiz-row', style: 'margin:6px 0' }, [
					E('span', { 'class': 'wiz-title', style: 'flex:none; width:160px' }, [ _('Import') ]),
					urlIn, impRep, impApp, fileIn ]));
				card.appendChild(E('div', { 'class': 'hpui-hint' },
					[ _('One host per line; # lines are comments. Entries are validated and normalized at input: a /33 or garbage is rejected with a counter, a bare IP is accepted and normalized (/32, /128). Import never applies an empty/HTML answer.') ]));
				const saveBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
					[ _('Save list') ]);
				saveBtn.addEventListener('click', function() {
					saveBtn.disabled = true;
					listArea(_('Saving…'));
					L.resolveDefault(callListUpdate(ed.id, nameIn.value, exitSel.value, '', ''), {}).then(function(r1) {
						if (!r1 || r1.result === false) {
							listArea(_('Failed: ') + ((r1 && r1.error) || _('RPC error')));
							return null;
						}
						return L.resolveDefault(callListWrite(ed.id, ta.value, 'replace'), {}).then(function(r2) {
							if (!r2 || r2.result === false) {
								listArea(_('Failed: ') + ((r2 && r2.error) || _('RPC error')));
								return;
							}
							listArea(listCounterLine(r2.accepted, r2.dropped) + ' · ' + (r2.apply && r2.apply.hot ? _('applied live (hot reload).') : _('Applying…')));
							pollListOp(r2.apply, listCounterLine(r2.accepted, r2.dropped) + ' · ' + _('applied — the core runs the updated list.'),
								_('The list save failed to apply'));
							refreshLists();
						});
					}).finally(function() { saveBtn.disabled = false; });
				});
				const closeBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Close') ]);
				closeBtn.addEventListener('click', function() { listsState.editId = null; renderListsZone(); });
				card.appendChild(E('div', { 'class': 'wiz-toolbar' }, [ saveBtn, closeBtn ]));
				listsZone.appendChild(card);
			}
		}

		/* Create master — the action is picked HERE, at creation. */
		const mk = E('div', { 'class': 'wiz-svc', style: 'margin:10px 0' });
		mk.appendChild(E('div', { 'class': 'wiz-title' }, [ _('Create a list') ]));
		const nameIn2 = E('input', { type: 'text', 'class': 'cbi-input-text',
			placeholder: _('List name'), style: 'width:220px' });
		const kindSel = E('select', { 'class': 'cbi-input-select' });
		kindSel.appendChild(E('option', { value: 'proxy' }, [ _('via proxy') ]));
		kindSel.appendChild(E('option', { value: 'direct' }, [ _('direct') ]));
		const ctypeSel = E('select', { 'class': 'cbi-input-select' });
		ctypeSel.appendChild(E('option', { value: 'domains' }, [ _('domains') ]));
		ctypeSel.appendChild(E('option', { value: 'ips' }, [ _('IP addresses') ]));
		const poolBox3 = listPoolPicker(null);
		const exitSel3 = listExitSelect('proxy', '', null, poolBox3);
		kindSel.addEventListener('change', function() {
			const nv = kindSel.value;
			const nb = listExitSelect(nv, '', null, poolBox3);
			exitSel3.parentNode.replaceChild(nb, exitSel3);
			exitSel3 = nb;
			poolBox3.style.display = (nv === 'proxy' && nb.value === 'urltest') ? 'flex' : 'none';
		});
		mk.appendChild(E('div', { 'class': 'wiz-row', style: 'margin:6px 0' }, [
			nameIn2, kindSel, ctypeSel, exitSel3 ]));
		mk.appendChild(poolBox3);
		const ta2 = E('textarea', { rows: '4', spellcheck: 'false',
			placeholder: _('Entries — one per line (optional; you can import later)'),
			style: 'width:100%; font-family:monospace; font-size:.85em' });
		mk.appendChild(ta2);
			const createBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
			[ _('Create') ]);
		createBtn.addEventListener('click', function() {
			const name = (nameIn2.value || '').trim();
			if (!name) {
				listArea(_('Enter the list name first.'));
				return;
			}
			const ids = [];
			for (let c in poolBox3._checks)
				if (poolBox3._checks[c].checked)
					ids.push(poolBox3._checks[c].value);
			createBtn.disabled = true;
			listArea(_('Creating…'));
			L.resolveDefault(callListCreate(name, kindSel.value, ctypeSel.value, exitSel3.value,
				JSON.stringify(exitSel3.value === 'urltest' ? ids : []), ta2.value), {}).then(function(r) {
				if (!r || r.result === false) {
					const ERRS = {
						main_is_direct: _('Main node is Direct — a proxy list would have no effect. Pick Zapret/ByeDPI for a direct list, or choose a real main node.'),
						byedpi_disabled: _('ByeDPI is not enabled — enable it on the Connection page first.'),
						zapret_disabled: _('Zapret is not enabled — enable it on the Connection page first.'),
						urltest_pool_empty: _('Pick at least one node for the URLTest pool.'),
						'unknown node': _('Unknown node — refresh the page.')
					};
					listArea(_('Creation failed: ') + (ERRS[(r && r.error)] || ((r && r.error) || _('RPC error'))));
					return;
				}
				listArea(listCounterLine(r.accepted, r.dropped));
				pollListOp(r.apply, _('The list is created and applied — route_explain and real traffic can verify it.'),
					_('The list creation failed to apply'));
				refreshLists();
			}).finally(function() { createBtn.disabled = false; });
		});
		mk.appendChild(E('div', { 'class': 'wiz-toolbar' }, [ createBtn ]));
		mk.appendChild(E('div', { 'class': 'hpui-hint' },
			[ _('A list is created WITH its action — a list without a rule would be a dead list. Proxy lists route AFTER the RU-protection guard (a RU domain in a proxy list stays direct — the invariant holds); direct lists are checked right after the per-service rules.') ]));
		listsZone.appendChild(mk);

		/* Snapshots: manual snapshot + restore (a dated family outside the
		 * snapshot-* rotation — user snapshots are never evicted). */
		const snapRow = E('div', { 'class': 'wiz-row', style: 'margin:6px 0' });
		const snapSel = E('select', { 'class': 'cbi-input-select', style: 'max-width:420px' });
		snapSel.appendChild(E('option', { value: '' }, [ _('Snapshots: none yet') ]));
		L.resolveDefault(callListBackupList(), {}).then(function(r) {
			const snaps = (r && r.snapshots) || [];
			snapSel.innerHTML = '';
			if (!snaps.length) {
				snapSel.appendChild(E('option', { value: '' }, [ _('Snapshots: none yet') ]));
				return;
			}
			for (let i = 0; i < snaps.length; i++)
				snapSel.appendChild(E('option', { value: snaps[i].dir },
					[ snaps[i].dir + (snaps[i].reason ? (' — ' + snaps[i].reason) : '') + ' (' + snaps[i].counts + ')' ]));
		});
		const snapBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Snapshot all lists') ]);
		snapBtn.addEventListener('click', function() {
			snapBtn.disabled = true;
			listArea(_('Taking a snapshot…'));
			L.resolveDefault(callListBackupCreate(), {}).then(function(r) {
				if (!r || r.result === false)
					listArea(_('Snapshot failed: ') + ((r && r.error) || _('RPC error')));
				else
					listArea(_('Snapshot saved: %s').format(r.dir));
				refreshLists();
			}).finally(function() { snapBtn.disabled = false; });
		});
		const restBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Restore') ]);
		restBtn.addEventListener('click', function() {
			if (!snapSel.value) {
				listArea(_('Pick a snapshot to restore first.'));
				return;
			}
			hp.confirmModal(_('Restore lists'), _('Restore all lists from the snapshot %s? The CURRENT state is snapshotted first.').format(snapSel.value), _('Restore'))
				.then(function(ok) {
					if (!ok) return;
					restBtn.disabled = true;
					listArea(_('Restoring…'));
					L.resolveDefault(callListBackupRestore(snapSel.value), {}).then(function(r) {
						if (!r || r.result === false)
							listArea(_('Restore failed: ') + ((r && r.error) || _('RPC error')));
						else {
							listArea(_('Restored %s list(s) from %s.').format('' + r.restored, snapSel.value));
							pollListOp(r.apply, _('The restore is applied — the core runs the restored lists.'),
								_('The restore failed to apply'));
						}
						refreshLists();
					}).finally(function() { restBtn.disabled = false; });
				});
		});
		snapRow.appendChild(snapSel);
		snapRow.appendChild(snapBtn);
		snapRow.appendChild(restBtn);
		listsZone.appendChild(snapRow);
	}

	function refreshLists() {
		return L.resolveDefault(callListsList(), {}).then(function(r) {
			listsState.env = (r && r.env) || {};
			listsState.nodes = (r && r.env && r.env.proxy_nodes) || [];
			listsState.data = (r && r.lists) || [];
			renderListsZone();
		});
	}
	refreshLists();

		function renderPresets(list) {
			/* Rebuild the rows ONLY when the underlying state changed: a 4s
			 * poll rebuild would reset the exit <select> the user is working
			 * with (a form-ish row must not). */
			const env = (list && list.env) || {};
			lastEnv = env;
			state.lastList = list;
			const sig = JSON.stringify([ env, list.rules || {}, list.rule_counts || {},
				((list.nodes || []).map(function(n) { return n.id; })), state.visRev ]);
			if (sig === state.presetsSig)
				return;
			state.presetsSig = sig;

			envBanners.innerHTML = '';
			if (env.routing_mode && env.routing_mode !== 'proxy_banned_ru')
				envBanners.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('Routing rules apply ONLY in "Bypass blocking" mode — the current mode is "%s", so preset rules would have no effect.').format(routingModeLabelOf(env.routing_mode)) ]));
			if (env.main_is_direct)
				envBanners.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('Main node is Direct: rules pointing at "Same as main node" would egress directly. Choose Zapret/ByeDPI or a real node, or switch the Main node first.') ]));
			if (!env.proxy_in && !env.direct_in)
				envBanners.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('The pinned diagnostic inbounds are not listening (the core is off or in "Direct" mode) — path checks are limited.') ]));

			/* D29: which rows show on the page — see the comment at `state`.
			 * The YouTube/Discord "installed and configured strategy" gates
			 * are a separate plan item; for now a no-rule row shows only via
			 * the catalog reveal (Re-filter — via the VPN-node check). */
			const hasVpnNode = (list.nodes || []).some(function(n) { return n.type !== 'direct'; });
			const hasRuleOf = function(src) {
				const r = (list.rules || {})[src];
				const ex = (list.rule_extras || {})[src] || [];
				return !!(r || ex.length);
			};
			const rowVisible = function(src) {
				if (hasRuleOf(src))
					return true;
				if (src === 'refilter')
					return hasVpnNode;
				return !!state.revealed[src];
			};

			presetRows.innerHTML = '';
			presetRows.appendChild(E('div', { 'class': 'hpui-hint' },
				[ _('The mass lists below already cover YouTube/Discord/Telegram and most blocked resources — a per-service rule overrides the mass list.') ]));
			/* U6/D20 honesty: "direct" wording made users read the empty action
			 * as "this list goes into the Russian internet" — say what really
			 * happens: no rule, general routing decides. */
			presetRows.appendChild(E('div', { 'class': 'hpui-hint' },
				[ _('"No rule" does NOT mean "straight into the Russian internet": it only removes the rule — the domains are not added to any proxy list and follow the GENERAL routing rules (mass lists like Russia Inside / Re-filter and learned records may still send them through the node). Only traffic unmatched by every rule egresses directly.') ]));
			/* B6.9: the ONE documented priority order used to live here as a
			 * text note — D29 moved it into the VISIBLE order map at the top
			 * of the page (orderMapPanel, kept in sync with
			 * generate_client.uc; first match wins in both lists). */

			function buildServiceRow(preset) {
				const rule = (list.rules || {})[preset.source];
				const count = (list.rule_counts || {})[preset.source] || 0;
				/* Ф4.2: extra rules (2nd..Nth exit of the same service) render
				 * INSIDE the preset row — there is no duplicate editor below. */
				const extras = ((list.rule_extras || {})[preset.source]) || [];

				/* A card with the fixed control grid on top (name | state |
				 * select | buttons) and the hints/pool as sub-rows below. */
				const wrap = E('div', { 'class': 'wiz-svc' });
				const row = E('div', { 'class': 'wiz-svc-grid' });

				const titleWrap = E('span', { 'class': 'wiz-title' }, [ preset.title ]);
				if (preset.hosts && preset.hosts.length)
					titleWrap.appendChild(E('span', { 'class': 'wiz-hosts' }, [ ' · ' + preset.hosts.join(', ') ]));
				row.appendChild(titleWrap);

				row.appendChild(E('span', { 'class': 'wiz-state' }, [ ruleStateText(rule, count) ]));

				const sel = E('select', { 'class': 'cbi-input-select wiz-select' });
				/* D20/Ф3.3: the former "Direct (remove rule)" lied by accident —
				 * "Direct" made users expect a guaranteed direct egress, while the
				 * empty value only DELETES the rule (rpcd wizard_preset_apply) and
				 * the domain then follows the general routing rules. */
				sel.appendChild(E('option', { value: '' }, [ _('No rule') ]));
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

				/* URLTest pool picker — revealed when the exit is "URLTest pool". */
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
				poolBox.appendChild(E('span', { 'class': 'hpui-hint', style: 'margin:0; flex-basis:100%' },
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
					'class': 'hpui-btn hpui-btn-primary', type: 'button'
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
					/* urltest_nodes crosses as a JSON-encoded STRING: rpcd's ucode
					 * plugin maps a string typehint to BLOBMSG_TYPE_STRING, and
					 * native array typehints crash strict new rpcd (issue #11). */
					callPresetApply(preset.source, String(sel.value || ''), JSON.stringify(sel.value === 'urltest' ? ids : [])).then(function(r) {
						if (!r || r.result === false) {
							const ERRS = {
								main_is_direct: _('Main node is Direct — this rule would have no effect. Pick Zapret/ByeDPI or a real node.'),
								byedpi_disabled: _('ByeDPI is not enabled — enable it on the Connection page first.'),
							zapret_disabled: _('Zapret is not enabled — enable it on the Connection page first.'),
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
						/* Ф1.1b: the apply rides a tracked operation — the live
						 * check waits for the op verdict before probing (the
						 * reload may not even have started when the 8 s guard
						 * fires). */
						state.pendingCheck = { preset: preset, since: Date.now(),
							op_id: (r.apply && r.apply.op_id) || '' };
						return refresh();
					}).finally(function() { applyBtn.disabled = false; });
				});

				row.appendChild(sel);

				/* Apply (+ optional Check) share ONE grid column, so the
				 * select column stays aligned across rows with and without
				 * the Check button. */
				const btns = E('span', { 'class': 'wiz-svc-btns' });
				btns.appendChild(applyBtn);

				if (preset.check) {
					const checkBtn = E('button', {
						'class': 'hpui-btn hpui-btn-ghost', type: 'button'
					}, [ _('Check') ]);
					checkBtn.addEventListener('click', function() {
						checkBtn.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking…') ]));
						runServiceCheck(preset.check).finally(function() { checkBtn.disabled = false; });
					});
					btns.appendChild(checkBtn);
				}
				/* D27: a rule-bearing row can grow a SECOND exit of the same
				 * service (rpcd wizard_preset_add is unchanged) — the form
				 * opens in the row; the catalog no longer creates rules. */
				let exZone = null;
				if (rule) {
					exZone = E('div', {});
					const exBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' },
						[ _('Add a second exit') ]);
					exBtn.addEventListener('click', function() {
						if (exZone.childNodes.length)
							exZone.innerHTML = '';
						else
							exZone.appendChild(buildExtraForm(preset));
					});
					btns.appendChild(exBtn);
				}

				/* D29: the honest exit for the SOURCE rule — a real delete via
				 * wizard_preset_delete (config regenerates through the opman
				 * door). The row itself is a catalog preset: with no rule it
				 * drops off the page (comes back via the catalog), the state
				 * becomes D20 "No rule" — the service follows the general
				 * routing rules. Extra exits keep their own delete buttons. */
				if (rule) {
					const delBtn = E('button', { 'class': 'hpui-btn hpui-btn-danger', type: 'button' },
						[ _('Delete rule') ]);
					delBtn.addEventListener('click', function() {
						delBtn.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Deleting…') ]));
						L.resolveDefault(callPresetDelete(rule.section_id), {}).then(function(r) {
							if (!r || r.result === false)
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
									[ _('Failed: ') + ((r && r.error) || _('RPC error')) ]));
							else
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
									[ _('Rule deleted — the service follows the general routing rules again ("No rule").') ]));
							refresh();
						}).finally(function() { delBtn.disabled = false; });
					});
					btns.appendChild(delBtn);
				}
				row.appendChild(btns);
				wrap.appendChild(row);

				/* Pool picker + hints live BELOW the grid line. */
				wrap.appendChild(poolBox);

				/* Extra exits of the same service (added by the master) —
				 * shown here with their own remove buttons. */
				for (let e in extras) {
					const ex = extras[e];
					const exRow = E('div', { 'class': 'hpui-hint', style: 'margin:2px 0 0 12px' });
					exRow.appendChild(document.createTextNode(
						_('Also routed through %s').format(nodeText(ex.node)) +
						(ex.enabled ? '' : (' (' + _('disabled') + ')')) + '  '));
					const exDel = E('button', {
						'class': 'hpui-btn hpui-btn-danger hpui-btn-sm', type: 'button'
					}, [ _('Delete') ]);
					exDel.addEventListener('click', function() {
						exDel.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Deleting…') ]));
						L.resolveDefault(callPresetDelete(ex.section_id), {}).then(function(r) {
							if (!r || r.result === false)
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
									[ _('Failed: ') + ((r && r.error) || _('RPC error')) ]));
							else
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
									[ _('The extra rule is deleted.') ]));
							refresh();
						}).finally(function() { exDel.disabled = false; });
					});
					exRow.appendChild(exDel);
					wrap.appendChild(exRow);
				}

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
						wrap.appendChild(E('div', { 'class': 'hpui-hint', style: 'margin:0' },
							[ _('Covered by the mass list (%s) → %s — a rule here overrides the list.').format(names.join(', '), nodeText(cov[0].node)) ]));
					}
				}

				/* T1 (G1): a SHORT, provider-independent hint — the exit country
				 * of the exit differs per user, so no measured locations here.
				 * ч.200, D34b: прежняя подсказка про выход tg-ws удалена вместе
				 * с мостом. */

				if (exZone)
					wrap.appendChild(exZone);

				return wrap;
			}

			/* D27: the form for a SECOND exit of the same service — the old
			 * add-master moved into the row; the RPC and the validation are
			 * unchanged. */
			function buildExtraForm(preset) {
				const poolBox = E('div', { 'class': 'wiz-pool', style: 'display:none; flex-wrap:wrap' });
				const mChecks = [];
				for (let n in (list.nodes || [])) {
					if (list.nodes[n].type === 'direct')
						continue;
					const cb = E('input', { type: 'checkbox', value: list.nodes[n].id });
					mChecks.push(cb);
					poolBox.appendChild(E('label', {}, [ cb, ' ' + list.nodes[n].label ]));
				}
				const mNode = E('select', { 'class': 'cbi-input-select', style: 'min-width:190px' });
				if (!env.main_is_direct)
					mNode.appendChild(E('option', { value: 'main-out' }, [ _('Same as main node') ]));
				mNode.appendChild(E('option', { value: 'urltest' }, [ _('URLTest pool') ]));
				for (let n in (list.nodes || []))
					if (list.nodes[n].type !== 'direct')
						mNode.appendChild(E('option', { value: list.nodes[n].id }, [ list.nodes[n].label ]));
				if (env.byedpi_enabled)
					mNode.appendChild(E('option', { value: 'byedpi-out' }, [ 'ByeDPI' ]));
				if (env.zapret_enabled)
					mNode.appendChild(E('option', { value: 'zapret-out' }, [ 'Zapret' ]));
				mNode.addEventListener('change', function() {
					poolBox.style.display = (mNode.value === 'urltest') ? 'flex' : 'none';
				});
				const mAdd = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
					[ _('Add') ]);
				mAdd.addEventListener('click', function() {
					const ids = [];
					for (let c in mChecks)
						if (mChecks[c].checked)
							ids.push(mChecks[c].value);
					if (mNode.value === 'urltest' && !ids.length) {
						ui.addNotification(null, E('p', {}, _('Pick at least one node for the URLTest pool.')), 'error');
						return;
					}
					mAdd.disabled = true;
					dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Adding…') ]));
					callPresetAdd(preset.source, String(mNode.value || ''), JSON.stringify(mNode.value === 'urltest' ? ids : []))
						.then(function(r) {
							if (!r || r.result === false) {
								const ERRS = {
									main_is_direct: _('Main node is Direct — this rule would have no effect. Pick Zapret/ByeDPI or a real node.'),
									byedpi_disabled: _('ByeDPI is not enabled — enable it on the Connection page first.'),
									zapret_disabled: _('Zapret is not enabled — enable it on the Connection page first.'),
									urltest_pool_empty: _('Pick at least one node for the URLTest pool.'),
									'unknown node': _('Unknown node — refresh the page.'),
									'unknown source': _('Unknown service.'),
									'duplicate rule': _('This exact rule already exists.')
								};
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
									[ ERRS[(r && r.error)] || ((r && r.error) || _('RPC error')) ]));
								return;
							}
							dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
								[ _('The rule is added — it now shows in its service row. The apply is running…') ]));
							state.pendingCheck = null;
							pollListOp((r.apply && r.apply.op_id) ? { op_id: r.apply.op_id } : null,
								_('The rule is applied.'), _('The rule apply failed'));
							refresh();
						}).finally(function() { mAdd.disabled = false; });
				});
				const box = E('div', { 'class': 'hpui-hint', style: 'margin:2px 0 0 12px' });
				box.appendChild(E('div', { 'class': 'wiz-row' }, [
					E('span', { 'class': 'wiz-title', style: 'flex:none; width:110px' }, [ _('Node') ]),
					mNode ]));
				box.appendChild(poolBox);
				box.appendChild(E('div', { 'class': 'wiz-toolbar' }, [ mAdd ]));
				return box;
			}

			/* Ф9.3 v3: each group renders as an hpui-panel with an icon
			 * header; entries carry the icon at [3]. */
			const GROUPS = [
				[ _('Mass lists'), BULK_PRESETS, null, 'database' ],
				[ _('Services'), PRESETS, null, 'send' ],
				[ _('Games (IP-only)'), GAMING_PRESETS,
					_('Matched by destination IP (no domains) — a rule routes the game networks (launchers, match servers, voice) to the chosen exit.'), 'activity' ],
				[ _('CDN and hosting'), CDN_PRESETS, null, 'globe' ],
				[ _('Other'), MISC_PRESETS, null, 'layers' ]
			];

			/* D27: the "add a rule" master becomes the CATALOG of lists —
			 * picking a list reveals its row on the page. Rules are still
			 * created and edited IN the row; a second exit of the same
			 * service is added by the button inside its row (rpcd
			 * wizard_preset_add is unchanged). */
			const mBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button', style: 'margin:2px 0' },
				[ _('Add a rule') ]);
			const mForm = E('div', { 'class': 'wiz-svc', style: 'display:none; margin:8px 0' });
			const mSrc = E('select', { 'class': 'cbi-input-select', style: 'min-width:260px' });
			const mShow = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
				[ _('Show') ]);
			const fillCatalog = function() {
				/* B6.6: a list without its own rule may still be covered by an
				 * enabled mass list — the honest catalog marker says
				 * "possibly covered" instead of implying the list is dead. */
				const massCovered = !!((list.rules || {})['russia-inside'] && list.rules['russia-inside'].enabled) ||
					!!((list.rules || {})['refilter'] && list.rules['refilter'].enabled);
				dom.content(mSrc, [ E('option', { value: '' }, [ _('Pick a list…') ]) ]);
				let any = false;
				for (let g2 in GROUPS) {
					const opts = [];
					for (let p2 in GROUPS[g2][1]) {
						const it = GROUPS[g2][1][p2];
						if (rowVisible(it.source))
							continue;
						any = true;
						opts.push(E('option', { value: it.source },
							[ it.title + (massCovered
								? (' — ' + _('no rule (possibly covered by a mass list)'))
								: (' — ' + _('no rule'))) ]));
					}
					if (opts.length)
						mSrc.appendChild(E('optgroup', { label: GROUPS[g2][0] }, opts));
				}
				if (!any)
					mSrc.appendChild(E('option', { value: '' }, [ _('All lists are already on the page.') ]));
				mShow.disabled = !any;
			};
			mShow.addEventListener('click', function() {
				const src = String(mSrc.value || '');
				if (!src)
					return;
				state.revealed[src] = true;
				state.visRev++;
				mForm.style.display = 'none';
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
					[ _('The row is on the page.') ]));
				renderPresets(state.lastList);
			});
			mBtn.addEventListener('click', function() {
				if (mForm.style.display === 'none') {
					fillCatalog();
					mForm.style.display = 'block';
				} else
					mForm.style.display = 'none';
			});
			mForm.appendChild(E('div', { 'class': 'wiz-row' }, [ mSrc, mShow ]));
			presetRows.appendChild(E('div', { 'class': 'hpui-hint', style: 'margin:0 0 4px' },
				[ _('Pick a list in the catalog — its row appears on the page; a row without a rule disappears after a reload.') ]));
			presetRows.appendChild(mBtn);
			presetRows.appendChild(mForm);

			for (let g in GROUPS) {
				const items = [];
				for (let p in GROUPS[g][1])
					if (rowVisible(GROUPS[g][1][p].source))
						items.push(GROUPS[g][1][p]);
				if (!items.length)
					continue;
				const gpanel = E('div', { 'class': 'hpui-panel' }, [
					E('h4', { 'class': 'hpui-h4' }, [ hp.icon(GROUPS[g][3]), GROUPS[g][0] ])
				]);
				if (GROUPS[g][2])
					gpanel.appendChild(E('p', { 'class': 'hpui-hint' }, [ GROUPS[g][2] ]));
				for (let p2 in items)
					gpanel.appendChild(buildServiceRow(items[p2]));
				presetRows.appendChild(gpanel);
			}

			/* D29: quick-check chips of the route checker = the services
			 * currently on the page (their verified representative host) + one
			 * RU example to see the guard at work. Deduped — a host may
			 * represent several sources (instagram.com: refilter AND meta). */
			const chips = [];
			const seenHosts = {};
			for (let g3 in GROUPS)
				for (let p3 in GROUPS[g3][1]) {
					const it3 = GROUPS[g3][1][p3];
					if (!rowVisible(it3.source) || !it3.hosts || !it3.hosts.length)
						continue;
					if (seenHosts[it3.hosts[0]])
						continue;
					seenHosts[it3.hosts[0]] = true;
					chips.push([ it3.hosts[0], it3.title ]);
				}
			chips.push([ 'ya.ru', _('RU-guard example — stays direct') ]);
			fillRouteChips(chips);
		}

		/* ── Live checks (results in ONE place below the presets) ──────── */
		function renderServiceCheck(r) {
			checkResult.innerHTML = '';
			if (!r || r.result === false) {
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
					[ _('Check failed: ') + ((r && r.error) || _('RPC error')) ]));
				return;
			}
			const exitLine = E('div', { 'class': 'hpui-hint' });
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
			 * through a throwaway probe core; the result lands in the ONE
			 * result area. */
			if (r.service === 'google_ai') {
				const aiBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' },
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
				const line = E('div', { 'class': 'hpui-hint' });
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
			checkResult.appendChild(E('div', { 'class': 'hpui-hint' },
				[ _('Google AI — candidate nodes (one API probe per node):') ]));
			const nodes = r.nodes || [];
			for (let i = 0; i < nodes.length; i++) {
				const n = nodes[i];
				const line = E('div', { 'class': 'hpui-hint' });
				line.appendChild(document.createTextNode(resolveTag(n.node) +
					((n.node === r.current) ? (' · ' + _('current node')) : '') + ': '));
				if (n.verdict === 'passes')
					line.appendChild(E('span', { 'class': 'hpui-badge hpui-b-green' }, [ '✓ ' + _('region passes') ]));
				else if (n.verdict === 'refused')
					line.appendChild(E('span', { 'class': 'hpui-badge hpui-b-red' }, [ '✗ ' + _('region refused') ]));
				else if (n.verdict === 'unreachable')
					line.appendChild(E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ '✗ ' + _('unreachable') ]));
				else
					line.appendChild(E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ '? ' + _('uncertain') ]));
				checkResult.appendChild(line);
			}
			if (!nodes.length)
				checkResult.appendChild(E('div', { 'class': 'hpui-hint' },
					[ _('No nodes found in the running config.') ]));
			if (r.truncated)
				checkResult.appendChild(E('div', { 'class': 'hpui-hint' },
					[ _('Some nodes were not checked (limit 12).') ]));
			checkResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('To switch the exit: pick the node in the service row above and press Apply.') ]));
		}

		function renderPathCheck(preset, results) {
			checkResult.innerHTML = '';
			checkResult.appendChild(E('div', { 'class': 'hpui-hint' },
				[ _('Live route for %s:').format(preset.title) ]));
			for (let i in results) {
				const line = E('div', { 'class': 'hpui-hint' });
				line.appendChild(document.createTextNode(results[i].host + ': '));
				line.appendChild(shortTrace(results[i].trace));
				checkResult.appendChild(line);
			}
			checkResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('Full reachability probing lives on the "Provider" tab of Check & repair.') ]));
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
					[ _('Rule applied. Run the "Provider" check to verify reachability.') ]));
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

		function refresh() {
			return Promise.all([
				L.resolveDefault(callPresetList(), {})
			]).then(function(data) {
				if (data[0] && data[0].rules)
					renderPresets(data[0]);

				/* Deferred live check: fire once the core is running again
				 * after the apply-triggered reload (min 8 s after apply).
				 * Ф1.1b: when the apply spawned an operation, the op verdict
				 * comes first — probing mid-reload would read the OLD config. */
				const pc = state.pendingCheck;
				if (pc && (Date.now() - pc.since > 8000)) {
					const proceed = function() {
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
					};
					if (pc.op_id) {
						L.resolveDefault(callOpStatus(pc.op_id), {}).then(function(st) {
							const op = st && st.op;
							if (!op || op.status === 'completed' || op.status === 'failed')
								proceed();
						});
					} else {
						proceed();
					}
				}
			});
		}

		poll.add(refresh, 4);
		refresh();

		/* ── Мой списки (Ф4.2): the former two static textareas are now the
		 * full user-list manager; the duplicate proxy_ru_rule editor grid is
		 * GONE — rules live only in the preset rows above, new ones are added
		 * by the master button. */
		const listsIntro = E('div', {}, [
			E('p', { 'class': 'hpui-hint', style: 'margin:2px 0' },
				[ _('Your own lists: named, with the direction (proxy/direct), the content type (domains/IPs) and the ACTION picked at creation — a single domain or IP is enough. Import from a URL (an HTML answer is never applied), pasted text or a file; entries are validated at input; snapshots outside the rotation; export shows what actually routes.') ])
		]);
		listsPanel.appendChild(listsIntro);
		listsPanel.appendChild(listsZone);
		listsPanel.appendChild(listsResult);

		/* Ф9.3/D29: v3 page skeleton — intro, the order map, the route
		 * checker (the main instrument), then the editable rows and the
		 * per-zone result/list surfaces. */
		return E('div', {}, [
			hp.pageIntro(_('Service rules'),
				_('Which service exits through what: the order map shows how a route is decided, the checker shows any site\'s live route, and the rows below assign exits. Routing applies in "Bypass blocking" mode; everything unmatched goes directly.')),
			envBanners,
			orderMapPanel,
			routePanel,
			presetRows,
			checkPanel,
			listsPanel
		]);
	}
});
