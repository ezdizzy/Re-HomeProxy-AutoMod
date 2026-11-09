/* Ravnex — Service rules (R3 v3b, 19-UX_REDESIGN p.5; Ф9.3 v3 rework)
 * The SINGLE place "which service exits through what". D29 (the user's
 * "most important point"): the page MAKES THE MODEL VISIBLE — the rule
 * ORDER map mirrors generate_client.uc in "Bypass blocking" mode, and
 * route_explain is the MAIN instrument (check the route, then assign an
 * exit). Preset rows keep the proven fixed control grid; the whole page
 * rides the v3 design system. One result area per zone; the expert grid
 * is gone (rules live only in the preset rows).
 *
 * D35b: the advanced tabs moved HERE from the Connection page as the
 * collapsed expert group — Routing Nodes (the generator now emits them
 * by EXISTENCE, enabled=1, no flag) and the raw sing-box Custom Rules
 * behind an explicit expert toggle living next to the editor. */

'require dom';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';
'require validation';
'require view';
'require tools.widgets as widgets';
'require homeproxy as hp';

/* Validation without a form context (the node-label builder checks raw
 * address strings) — the same stub the Connection page uses. */
let stubValidator = {
	factory: validation,
	apply(type, value, args) {
		if (value != null)
			this.value = value;

		return validation.types[type].apply(this, args);
	},
	assert(condition) {
		return !!condition;
	}
};

const callPresetList = rpc.declare({
	object: 'luci.ravnex',
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
	object: 'luci.ravnex',
	method: 'wizard_preset_apply',
	params: [ 'source', 'node', 'urltest_nodes' ],
	expect: { '': {} }
});

const callRouteExplain = rpc.declare({
	object: 'luci.ravnex',
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
	object: 'luci.ravnex',
	method: 'wizard_service_check',
	params: [ 'service' ],
	expect: { '': {} }
});

const callAiNodesCheck = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_ai_nodes_check',
	expect: { '': {} }
});

const callPresetDelete = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_preset_delete',
	params: [ 'section_id' ],
	expect: { '': {} }
});

/* s179: the catalog "Add" pin — keeps a row WITHOUT a rule ("undecided");
 * a plain UCI list write, never a core restart. */
const callPresetPinSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'preset_pin_set',
	params: [ 'source', 'pinned' ],
	expect: { '': {} }
});

/* Ф4.2 (U7): the "add a rule" master — ALWAYS creates a NEW rule section
 * (an extra exit for the same service is a legitimate shape). */
const callPresetAdd = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_preset_add',
	params: [ 'source', 'node', 'urltest_nodes' ],
	expect: { '': {} }
});

/* ── User lists (менеджер списков, U7) ─────────────────────────────────── */
const callListsList = rpc.declare({
	object: 'luci.ravnex',
	method: 'lists_list',
	expect: { '': {} }
});
const callListCreate = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_create',
	params: [ 'name', 'kind', 'ctype', 'node', 'urltest_nodes', 'content' ],
	expect: { '': {} }
});
const callListRead = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_read',
	params: [ 'id' ],
	expect: { '': {} }
});
const callListWrite = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_write',
	params: [ 'id', 'content', 'mode' ],
	expect: { '': {} }
});
const callListImport = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_import',
	params: [ 'id', 'url', 'mode' ],
	expect: { '': {} }
});
const callListUpdate = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_update',
	params: [ 'id', 'name', 'node', 'enabled', 'urltest_nodes' ],
	expect: { '': {} }
});
const callListDelete = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_delete',
	params: [ 'id' ],
	expect: { '': {} }
});
const callListExport = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_export',
	params: [ 'id' ],
	expect: { '': {} }
});
const callListBackupList = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_backup_list',
	expect: { '': {} }
});
const callListBackupCreate = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_backup_create',
	expect: { '': {} }
});
const callListBackupRestore = rpc.declare({
	object: 'luci.ravnex',
	method: 'list_backup_restore',
	params: [ 'dir' ],
	expect: { '': {} }
});

/* Ф1.1b: applies run as tracked operations — poll app_op_status until the
 * server-side verified verdict. */
const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label
 * (same logic as wizard.js/diagnostics.js). */
function resolveTag(tag) {
	const m = tag && String(tag).match(/^cfg-(.+)-out$/);
	if (m) {
		const label = uci.get('ravnex', m[1], 'label');
		if (label) return label;
	}
	const specials = { 'main-out': 'main_node', 'main-udp-out': 'main_udp_node' };
	if (specials[tag]) {
		const v = uci.get('ravnex', 'config', specials[tag]);
		if (v === 'byedpi-out') return 'ByeDPI';
		if (v === 'zapret-out') return 'Zapret';
		if (v && ![ 'urltest', 'same', 'nil', '' ].includes(v)) {
			const label = uci.get('ravnex', v, 'label');
			if (label) return label;
		}
	}
	/* Bare node section id (rules written by the advanced editor store the
	 * plain section name) — resolve its label, never show a raw cfg-id
	 * (hotswap.messages_node_names_not_cfg_ids). */
	const label = tag ? uci.get('ravnex', String(tag), 'label') : null;
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
 * line up across every row regardless of hint length (Ф8-F5 D.2).
 * Block E: the row buttons live in ONE row (the 3-floor wrap is gone —
 * the actions column sizes to its content; below 1150px it may wrap). */
.wiz-svc { border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); margin: 6px 0; padding: 8px 10px; }
/* Track 3 is FIXED (select 190-210 + gap + «Check» ~92 ≈ 308): rows with and
 * without the Check button share the SAME column widths, so the select and
 * the actions stay aligned across every row. */
.wiz-svc-grid { display: grid; grid-template-columns: minmax(140px, 210px) minmax(160px, 1fr) 312px max-content; align-items: center; gap: 6px 10px; }
.wiz-svc-sel { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; min-width: 0; }
.wiz-svc-sel .wiz-select { flex: 0 1 auto; min-width: 190px; max-width: 210px; }
.wiz-svc-sel .hpui-btn { font-size: .92em; padding-left: 10px; padding-right: 10px; }
.wiz-svc-btns { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 8px; }
.wiz-svc-grid > .wiz-svc-btns { flex-wrap: nowrap; }
.wiz-svc-btns .hpui-btn, .wiz-svc-btns .btn { font-size: .92em; padding-left: 10px; padding-right: 10px; }
.wiz-svc-btns .wiz-del { min-width: 30px; padding-left: 8px; padding-right: 8px; }
.wiz-svc-grid > .wiz-title, .wiz-svc-grid > .wiz-state { flex: none; }
.wiz-svc .wiz-pool { margin: 6px 0 0 0; }
.wiz-svc .hpui-hint { margin: 6px 0 0 0; }
@media (max-width: 1150px) {
	.wiz-svc-grid > .wiz-svc-btns { flex-wrap: wrap; }
}
@media (max-width: 900px) {
	.wiz-svc-grid { display: flex; flex-wrap: wrap; }
	.wiz-svc-grid > .wiz-title { flex: 1 1 220px; }
	.wiz-svc-grid > .wiz-state { flex: 1 1 240px; }
	.wiz-svc-grid > .wiz-svc-sel { flex: 1 1 auto; }
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

/* Gemini-web honesty (Блок 1 сеанса 138): the SPA refusal is rendered by
 * page JS after the shell loads, so a body probe can never PROVE "served" —
 * green only for a legacy backend that still sends it, red only with a real
 * refusal marker in the body, amber otherwise. */
function webBadge(w) {
	const v = w && w.verdict;
	if (v === 'refused') return E('span', { 'class': 'hpui-badge hpui-b-red' }, [ '✗ ' + _('refused') ]);
	if (v === 'served') return E('span', { 'class': 'hpui-badge hpui-b-green' }, [ '✓ ' + _('served') ]);
	return E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ '? ' + _('unknown (SPA page)') ]);
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('ravnex')
		]);
	},

	/* RPC-driven page with ONE explicit door (the expert panel's
	 * Save & Apply button): the standard LuCI save footer has nothing
	 * to act on for the rest of the page and would only add a second,
	 * confusing door (telegram.js/devices.js pattern). */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

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
			{ source: 'google-meet', title: _('Google Meet'), hosts: [ 'meet.google.com' ] },
			/* Lists conveyor (seance 178): new per-service categories. */
			{ source: 'netflix', title: _('Netflix (SURROGATE — no dedicated RU list exists)'),
				hosts: [ 'www.netflix.com' ] },
			{ source: 'spotify', title: _('Spotify (SURROGATE — no dedicated RU list exists)'),
				hosts: [ 'open.spotify.com' ] },
			{ source: 'signal', title: _('Signal'), hosts: [ 'signal.org' ] },
			{ source: 'rutracker', title: _('RuTracker'), hosts: [ 'rutracker.org' ] },
			{ source: 'linkedin', title: _('LinkedIn'), hosts: [ 'www.linkedin.com' ] },
			{ source: 'vk', title: _('VK'), hosts: [ 'vk.com' ] },
			{ source: 'ok', title: _('OK (Odnoklassniki)'), hosts: [ 'ok.ru' ] },
			{ source: 'mailru', title: _('Mail.ru'), hosts: [ 'mail.ru' ] },
			{ source: 'dzen', title: _('Dzen'), hosts: [ 'dzen.ru' ] },
			{ source: 'steam', title: _('Steam (store/client domains)'), hosts: [ 'store.steampowered.com' ] },
			{ source: 'gemini', title: _('Google Gemini / AI Studio'),
				hosts: [ 'gemini.google.com', 'aistudio.google.com' ] },
			{ source: 'deepseek', title: _('DeepSeek'), hosts: [ 'chat.deepseek.com' ] },
			{ source: 'perplexity', title: _('Perplexity'), hosts: [ 'www.perplexity.ai' ] },
			{ source: 'huggingface', title: _('Hugging Face'), hosts: [ 'huggingface.co' ] },
			{ source: 'ai-chat', title: _('AI chatbots (aggregated, non-CN)'),
				hosts: [ 'chatgpt.com' ] },
			{ source: 'antifilter-community', title: _('Antifilter community (user-reported restricted sites)'),
				hosts: [ 'kinozal.tv' ] }
		];

		/* A1: every rpcd SOURCE becomes an editable row, grouped. The mass
		 * lists use the same select/Apply path as presets — the RPC accepts
		 * any source. */
		const BULK_PRESETS = [
			{ source: 'russia-inside', title: _('itdoginfo/allow-domains - Russia Inside (1000+ entries)'), hosts: [ '4pda.to' ] },
			{ source: 'refilter', title: _('Re-filter (mass list of blocked domains/IPs — a base, coverage is NOT exhaustive)'), hosts: [ 'instagram.com' ] },
			{ source: 'block', title: _('Block (core RKN-blocked resources)'), hosts: [ 'signal.org' ] },
			{ source: 'russia-outside', title: _('Russia Outside (RU-only services — for use abroad)') },
			{ source: 'ukraine-inside', title: _('Ukraine Inside (resources blocked in UA)') },
			/* Lists conveyor: the opt-in MASS layer — big aggregated lists
			 * that cost real router memory; precision-first keeps them off. */
			{ source: 'rublocked', title: _('RunetFreedom ru-blocked (mass, 🜚 opt-in)'), hosts: [ 'instagram.com' ] },
			{ source: 'rublocked-all', title: _('Antifilter download FULL (700k+ domains, 🜚 heavy)'), hosts: [ 'kinozal.tv' ] },
			{ source: 'antifilter-domains', title: _('Antifilter domains.lst (raw feed, 🜚 opt-in)'), hosts: [ 'kinozal.tv' ] },
			{ source: 'antifilter-ip', title: _('Antifilter ipsum.lst (blocked networks, 🜚 opt-in)') },
			{ source: 'rublocked-ip-agg', title: _('Aggregated blocked IPs (~146 sources, 🜚 opt-in)') }
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
		 * node exists, or when it is PINNED from the catalog (s179, user
		 * decision «добавил — путь не выбрал»: the pin survives reloads in
		 * UCI, a row without a rule generates nothing). The old per-browser
		 * reveal/hiding is gone for good. */
		try { window.localStorage.removeItem('hp_rules_hidden_presets'); } catch (e) {}
		const state = { presetsSig: null, pendingCheck: null, lastList: null, visRev: 0, pins: [] };
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
			state.pins = (list && list.pins) || [];
			const sig = JSON.stringify([ env, list.rules || {}, list.rule_counts || {},
				((list.nodes || []).map(function(n) { return n.id; })), state.visRev, state.pins ]);
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
				return state.pins.indexOf(src) >= 0;
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

				row.appendChild(E('span', { 'class': 'wiz-state' }, [
					(rule || state.pins.indexOf(preset.source) < 0)
						? ruleStateText(rule, count)
						: E('span', { 'class': 'hpui-b-grey hpui-badge' },
							[ _('not routed') ]) ]));

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

				/* The Check button audits the CURRENT rule, while the actions
				 * row (Apply / second exit / delete) MUTATES it — so Check
				 * sits next to the exit (right of it), and every row keeps
				 * ONE uniform actions composition. */
				const selCell = E('span', { 'class': 'wiz-svc-sel' });
				selCell.appendChild(sel);

				if (preset.check) {
					const checkBtn = E('button', {
						'class': 'hpui-btn hpui-btn-ghost', type: 'button'
					}, [ _('Check') ]);
					checkBtn.addEventListener('click', function() {
						checkBtn.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking…') ]));
						runServiceCheck(preset.check).finally(function() { checkBtn.disabled = false; });
					});
					selCell.appendChild(checkBtn);
				}
				row.appendChild(selCell);

				const btns = E('span', { 'class': 'wiz-svc-btns' });
				btns.appendChild(applyBtn);
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

				/* D29 + s179: the honest exit is a REAL delete (wizard_preset_
				 * delete; the last section of a source also drops the catalog
				 * pin). A pinned row without a rule has no section — its ✕
				 * just unpins (instant, no restart), the row is gone for
				 * good and can be re-added from the catalog. Extra exits keep
				 * their own delete buttons. */
				const pinned = state.pins.indexOf(preset.source) >= 0;
				if (rule || pinned) {
					/* Block E: the delete is a compact ✕ (the row keeps all
					 * its actions in ONE row); the tooltip carries the name. */
					const delBtn = E('button', {
						'class': 'hpui-btn hpui-btn-danger wiz-del', type: 'button',
						'title': _('Delete the row (rules do not linger anywhere)')
					}, [ '✕' ]);
					delBtn.addEventListener('click', function() {
						delBtn.disabled = true;
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Deleting…') ]));
						const unpinAfter = !rule || (count <= 1 && !(extras && extras.length));
						const fin = function(r, okMsg) {
							if (!r || r.result === false)
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
									[ _('Failed: ') + ((r && r.error) || _('RPC error')) ]));
							else if (unpinAfter)
								callPresetPinSet(preset.source, '0').then(function() {
									dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ okMsg ]));
									refresh();
								});
							else {
								dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ okMsg ]));
								refresh();
							}
						};
						if (rule)
							L.resolveDefault(callPresetDelete(rule.section_id), {}).then(function(r) {
								fin(r, unpinAfter
									? _('The row is deleted — add the list from the catalog to bring it back.')
									: _('Rule deleted — the service follows the general routing rules again ("No rule").'));
							}).finally(function() { delBtn.disabled = false; });
						else
							L.resolveDefault(callPresetPinSet(preset.source, '0'), {}).then(function(r) {
								fin(r, _('The row is deleted — add the list from the catalog to bring it back.'));
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

			/* D27 + s179 (user decision): the catalog lists the presets as
			 * PLAIN NAMES (the mass titles already carry the size caveat in
			 * parentheses) — the "rules none / possibly covered" suffix that
			 * was glued to every option confused more than it explained.
			 * "Add" PINS the list: its row appears in the rows below and
			 * STAYS there (UCI pin, survives reloads) until the user picks
			 * the route in the row or deletes the row. */
			const mBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button', style: 'margin:2px 0' },
				[ _('Add a rule') ]);
			const mForm = E('div', { 'class': 'wiz-svc', style: 'display:none; margin:8px 0' });
			const mSrc = E('select', { 'class': 'cbi-input-select', style: 'min-width:260px' });
			const mShow = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
				[ _('Add') ]);
			const fillCatalog = function() {
				dom.content(mSrc, [ E('option', { value: '' }, [ _('Pick a list…') ]) ]);
				let any = false;
				for (let g2 in GROUPS) {
					const isMass = (GROUPS[g2][0] === _('Mass lists'));
					const opts = [];
					for (let p2 in GROUPS[g2][1]) {
						const it = GROUPS[g2][1][p2];
						if (rowVisible(it.source))
							continue;
						any = true;
						opts.push(E('option', { value: it.source, 'data-mass': isMass ? '1' : '0' },
							[ it.title ]));
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
				const opt = mSrc.querySelector('option[value="' + src + '"]');
				const mass = !!(opt && opt.getAttribute('data-mass') === '1');
				/* Mass layer opt-in (user decision): one honest confirmation —
				 * big aggregates cost real memory on the router. */
				if (mass && !window.confirm(_('Mass list: big aggregates (hundreds of thousands of entries) cost real router memory and are never enabled by default. Add the row anyway?')))
					return;
				mShow.disabled = true;
				callPresetPinSet(src, '1').then(function(r) {
					mShow.disabled = false;
					if (!r || r.result === false) {
						dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
							[ _('Failed: ') + ((r && r.error) || _('RPC error')) ]));
						return;
					}
					if (state.pins.indexOf(src) < 0)
						state.pins.push(src);
					mForm.style.display = 'none';
					dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
						[ _('The list is in the rows below — pick the route there. While "No rule" is picked, nothing is routed for it.') ]));
					renderPresets(state.lastList);
					fillCatalog();
				}).catch(function() { mShow.disabled = false; });
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
				[ _('Pick a list in the catalog and press "Add" — its row appears in the rows below and stays. A rule appears only after you pick the route in the row; "No rule" just means the route is not decided yet, and ✕ deletes the row for good.') ]));
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

			/* Lesson 355 honesty: the probes now ride the FULL routing path
			 * (mixed inbound) — the same path the devices use — so a dead
			 * rule-set shows up as a refusal instead of a false green. */
			if (r.probe_path === 'mixed')
				checkResult.appendChild(E('div', { 'class': 'hpui-hint' },
					[ _('Probes run through the FULL routing path (mixed port) — the same path your devices use.') ]));
			else
				checkResult.appendChild(E('div', { 'class': 'hpui-banner' },
					[ _('The mixed port is not listening — probes run through the service-check loopback and test only the main exit.') ]));

			const row = E('div', { 'class': 'wiz-row' });
			if (r.service === 'google_ai') {
				row.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Google AI API') ]));
				row.appendChild(checkBadge(r.api, _('region passes'), _('region refused')));
				row.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Gemini web') ]));
				row.appendChild(webBadge(r.web));
			} else {
				row.appendChild(E('span', { 'class': 'wiz-title' }, [ _('OpenAI API') ]));
				row.appendChild(checkBadge(r.api, _('region passes'), _('region refused')));
			}
			checkResult.appendChild(row);

			/* Honest web verdict (Блок 1 сеанса 138): the SPA shell cannot be
			 * judged by a body probe — say so explicitly instead of the old
			 * false green, and point at the API verdict + the device test. */
			if (r.service === 'google_ai' && r.web && r.web.verdict === 'unknown') {
				const kb = (r.web.size_kb != null) ? (' (~' + r.web.size_kb + ' KB)') : '';
				checkResult.appendChild(E('div', { 'class': 'hpui-hint' },
					[ _('The Gemini page is a SPA shell%s — the refusal is rendered by page scripts after load, so a body probe cannot read the verdict; "unknown" is the honest web answer here. The region signal is the API verdict above, but the WEB gate is stricter and may reject hosting-provider IPs even when the API passes. Final proof: open gemini.google.com on the device in a fresh tab.').format(kb) ]));
			}

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
				/* Egress (what IP/ASN Google sees behind the node) — the web
				 * gate rejects hosting IPs, this is the user's picking hint
				 * (data only, no translatable text). */
				if (n.egress && n.egress.ip)
					line.appendChild(document.createTextNode(' · ' + (n.egress.country || '??') +
						((n.egress.asn) ? (' · AS' + n.egress.asn) : '') +
						((n.egress.org) ? (' ' + n.egress.org) : '') +
						' · ' + n.egress.ip));
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
			checkResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('The node probe covers the API gate only — the Gemini WEB gate is stricter and may reject hosting-provider IPs. If a node "passes" here but the device still refuses, the web gate is the reason; verify on the device.') ]));
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
						callServiceList('ravnex').then(function(res) {
							let running = false;
							try { running = !!res['ravnex']['instances']['hiddify-c']['running']; } catch (e) {}
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

		poll.add(hp.vpoll(refresh), hp.pollSec(4));
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

		/* ── D35b: the expert group — Routing Nodes + raw Custom Rules ─────
		 * The two advanced tabs moved here from the Connection page: a hidden
		 * flag on the WRONG page both obscured the feature and silently
		 * dropped routing_node sections from the generated config when off.
		 * The generator now emits routing_node sections by EXISTENCE
		 * (enabled=1, no flag — data = behavior); the raw sing-box rules keep
		 * an explicit expert switch living HERE, next to the editor it gates.
		 * The editors ride an embedded form.Map with its own Save & Apply
		 * footer; the rest of the page stays RPC-only. The map is rendered
		 * asynchronously into a host node (form.Map.render() is a Promise —
		 * lesson 148). */
		const proxyNodes = {};
		uci.sections('ravnex', 'node', function(res) {
			const nodeaddr = ((res.type === 'direct') ? res.override_address : res.address) || '',
			    nodeport = ((res.type === 'direct') ? res.override_port : res.port) || '';
			proxyNodes[res['.name']] = String.format('[%s] %s', res.type, res.label ||
				((stubValidator.apply('ip6addr', nodeaddr)) ?
					String.format('[%s]', nodeaddr) : nodeaddr) + ':' + nodeport);
		});

		const advMap = new form.Map('ravnex');
		const advSec = advMap.section(form.NamedSection, 'config', 'ravnex', null);
		advSec.addremove = false;

		let av, ag, ags, ar, ars, so;
		av = advSec.option(form.Flag, 'show_advanced_rules', _('Raw custom rules (expert)') + ' 👨‍💻',
			_('Emit the raw sing-box routing rules below with the HIGHEST priority (above every preset row and user list). These are for shapes the preset rows and routing nodes do not build — write them only if you know the sing-box rule schema. The switch takes effect on Save & Apply.'));
		av.default = av.disabled;
		av.rmempty = false;
		av.retain = true;

		/* Routing nodes editor: ALWAYS visible — the generator honors these
		 * sections by existence, so the editor is honest without any flag. */
		ag = advSec.option(form.SectionValue, '_routing_node', form.GridSection, 'routing_node');
		ags = ag.subsection;
		ags.addremove = true;
		ags.rowcolors = true;
		ags.sortable = true;
		ags.nodescriptions = true;
		ags.modaltitle = L.bind(hp.loadModalTitle, this, _('Routing node'), _('Add a routing node'), 'ravnex');
		ags.sectiontitle = L.bind(hp.loadDefaultLabel, this, 'ravnex');
		ags.renderSectionAdd = L.bind(hp.renderSectionAdd, this, ags);

		so = ags.option(form.Value, 'label', _('Label'));
		so.load = L.bind(hp.loadDefaultLabel, this, 'ravnex');
		so.validate = L.bind(hp.validateUniqueValue, this, 'ravnex', 'routing_node', 'label');
		so.modalonly = true;

		so = ags.option(form.Flag, 'enabled', _('Enable'));
		so.default = so.enabled;
		so.rmempty = false;
		so.editable = true;

		so = ags.option(form.ListValue, 'node', _('Node'),
			_('Outbound node'));
		/* "Same as main node" exists in every app-managed mode (Ф3.1: there are
		 * no custom modes anymore). Built in .load() so a mode switch refreshes
		 * the list immediately instead of keeping the render-time view. */
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;
			this.value('main-out', _('Same as main node') + ' 🔗');
			this.value('urltest', _('URLTest'));
			for (let i in proxyNodes)
				this.value(i, proxyNodes[i]);
			return this.super('load', section_id);
		};
		so.validate = L.bind(hp.validateUniqueValue, this, 'ravnex', 'routing_node', 'node');
		so.editable = true;

		so = ags.option(form.ListValue, 'domain_resolver', _('Domain resolver'),
			_('For resolving domain name in the server address.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			this.value('', _('Default'));
			this.value('default-dns', _('Default DNS (issued by WAN)'));
			this.value('system-dns', _('System DNS'));
			const _rm = uci.get('ravnex', 'config', 'routing_mode');
			if (_rm === 'proxy_banned_ru') {
				this.value('russia-dns', _('Russia DNS server') + ' 🔓');
				this.value('secure-dns', _('Secure DNS server') + ' 🔒');
			}

			uci.sections('ravnex', 'dns_server', function(res) {
				if (res.enabled === '1')
					this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		so.depends({'node': 'urltest', '!reverse': true});
		so.modalonly = true;

		so = ags.option(form.ListValue, 'domain_strategy', _('Domain strategy'),
			_('The domain strategy for resolving the domain name in the address.'));
		for (let i in hp.dns_strategy)
			so.value(i, hp.dns_strategy[i]);
		so.depends({'node': 'urltest', '!reverse': true});
		so.modalonly = true;

		so = ags.option(widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
			_('The network interface to bind to.'));
		so.multiple = false;
		so.noaliases = true;
		so.depends({'outbound': '', 'node': /^((?!urltest$).)+$/});
		so.modalonly = true;

		so = ags.option(form.ListValue, 'outbound', _('Outbound'),
			_('The tag of the upstream outbound.<br/>Other dial fields will be ignored when enabled.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			this.value('', _('Direct'));
			if (uci.get('ravnex', 'config', 'routing_mode') === 'proxy_banned_ru')
				this.value('main-out', _('Same as main node') + ' 🔗');
			uci.sections('ravnex', 'routing_node', function(res) {
				if (res['.name'] !== section_id && res.enabled === '1')
					this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		/* The recursion guard takes BOTH arguments — the old one-argument
		 * signature read an undeclared `value` (a ReferenceError inside the
		 * validator, so the chain check never really ran). */
		so.validate = function(section_id, value) {
			if (section_id && value) {
				let node = this.section.formvalue(section_id, 'node');

				let conflict = false;
				uci.sections('ravnex', 'routing_node', function(res) {
					if (res['.name'] !== section_id) {
						if (res.outbound === section_id && res['.name'] == value)
							conflict = true;
						else if (res.node === 'urltest' && res.urltest_nodes?.includes(node) && res['.name'] == value)
							conflict = true;
					}
				});
				if (conflict)
					return _('Recursive outbound detected!');
			}

			return true;
		}
		so.depends({'node': 'urltest', '!reverse': true});
		so.editable = true;

		so = ags.option(hp.CBIStaticList, 'urltest_nodes', _('URLTest nodes'),
			_('List of nodes to test.'));
		for (let i in proxyNodes)
			so.value(i, proxyNodes[i]);
		so.depends('node', 'urltest');
		so.validate = function(section_id) {
			let value = this.section.formvalue(section_id, 'urltest_nodes') || [];
			if (section_id && !value.length)
				return _('Expecting: %s').format(_('non-empty value'));

			return true;
		}
		so.modalonly = true;

		so = ags.option(form.Value, 'urltest_url', _('Test URL'),
			_('The URL to test.'));
		so.placeholder = 'https://www.gstatic.com/generate_204';
		so.validate = function(section_id, value) {
			if (section_id && value) {
				try {
					let url = new URL(value);
					if (!url.hostname)
						return _('Expecting: %s').format(_('valid URL'));
				}
				catch(e) {
					return _('Expecting: %s').format(_('valid URL'));
				}
			}

			return true;
		}
		so.depends('node', 'urltest');
		so.modalonly = true;

		so = ags.option(form.Value, 'urltest_interval', _('Test interval'),
			_('The test interval in seconds.'));
		so.datatype = 'uinteger';
		so.placeholder = '180';
		so.validate = function(section_id, value) {
			/* The sibling option is 'urltest_idle_timeout' — 'idle_timeout'
			 * never existed, so the comparison always ran against the
			 * fallback and user-set idle timeouts were ignored. */
			let idle_timeout = this.section.formvalue(section_id, 'urltest_idle_timeout') || '1800';
			if (section_id && value) {
				if (parseInt(value) > parseInt(idle_timeout))
					return _('Test interval must be less or equal than idle timeout.');
			}

			return true;
		}
		so.depends('node', 'urltest');
		so.modalonly = true;

		so = ags.option(form.Value, 'urltest_tolerance', _('Test tolerance'),
			_('The test tolerance in milliseconds.'));
		so.datatype = 'uinteger';
		so.placeholder = '50';
		so.depends('node', 'urltest');
		so.modalonly = true;

		so = ags.option(form.Value, 'urltest_idle_timeout', _('Idle timeout'),
			_('The idle timeout in seconds.'));
		so.datatype = 'uinteger';
		so.placeholder = '1800';
		so.depends('node', 'urltest');
		so.modalonly = true;

		so = ags.option(form.Flag, 'urltest_interrupt_exist_connections', _('Interrupt existing connections'),
			_('Interrupt existing connections when the selected outbound has changed.'));
		so.depends('node', 'urltest');
		so.modalonly = true;

		/* Raw sing-box rules editor: visible only with the expert switch on
		 * (checkDepends hides it live on toggle; hidden = nothing written). */
		ar = advSec.option(form.SectionValue, '_routing_rule', form.GridSection, 'routing_rule');
		ar.depends('show_advanced_rules', '1');
		ars = ar.subsection;
		ars.addremove = true;
		ars.rowcolors = true;
		ars.sortable = true;
		ars.nodescriptions = true;
		ars.modaltitle = L.bind(hp.loadModalTitle, this, _('Routing rule'), _('Add a routing rule'), 'ravnex');
		ars.sectiontitle = L.bind(hp.loadDefaultLabel, this, 'ravnex');
		ars.renderSectionAdd = L.bind(hp.renderSectionAdd, this, ars);

		ars.tab('field_other', _('Other fields'));
		ars.tab('field_host', _('Host/IP fields'));
		ars.tab('field_port', _('Port fields'));
		ars.tab('fields_process', _('Process fields'));

		so = ars.taboption('field_other', form.Value, 'label', _('Label'));
		so.load = L.bind(hp.loadDefaultLabel, this, 'ravnex');
		so.validate = L.bind(hp.validateUniqueValue, this, 'ravnex', 'routing_rule', 'label');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'enabled', _('Enable'));
		so.default = so.enabled;
		so.rmempty = false;
		so.editable = true;

		so = ars.taboption('field_other', form.ListValue, 'mode', _('Mode'),
			_('The default rule uses the following matching logic:<br/>' +
			'<code>(domain || domain_suffix || domain_keyword || domain_regex || ip_cidr || ip_is_private)</code> &&<br/>' +
			'<code>(port || port_range)</code> &&<br/>' +
			'<code>(source_ip_cidr || source_ip_is_private)</code> &&<br/>' +
			'<code>(source_port || source_port_range)</code> &&<br/>' +
			'<code>other fields</code>.<br/>' +
			'Additionally, included rule sets can be considered merged rather than as a single rule sub-item.'));
		so.value('default', _('Default'));
		so.default = 'default';
		so.rmempty = false;
		so.readonly = true;

		so = ars.taboption('field_other', form.ListValue, 'ip_version', _('IP version'),
			_('4 or 6. Not limited if empty.'));
		so.value('4', _('IPv4'));
		so.value('6', _('IPv6'));
		so.value('', _('Both'));
		so.modalonly = true;

		so = ars.taboption('field_other', form.MultiValue, 'protocol', _('Protocol'),
			_('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		so.value('bittorrent', _('BitTorrent'));
		so.value('dns', _('DNS'));
		so.value('dtls', _('DTLS'));
		so.value('http', _('HTTP'));
		so.value('quic', _('QUIC'));
		so.value('rdp', _('RDP'));
		so.value('ssh', _('SSH'));
		so.value('stun', _('STUN'));
		so.value('tls', _('TLS'));

		so = ars.taboption('field_other', form.Value, 'client', _('Client'),
			_('Sniffed client type (QUIC client type or SSH client name).'));
		so.value('chromium', _('Chromium / Cronet'));
		so.value('firefox', _('Firefox / uquic firefox'));
		so.value('quic-go', _('quic-go / uquic chrome'));
		so.value('safari', _('Safari / Apple Network API'));
		so.depends('protocol', 'quic');
		so.depends('protocol', 'ssh');
		so.modalonly = true;

		so = ars.taboption('field_other', form.ListValue, 'network', _('Network'));
		so.value('tcp', _('TCP'));
		so.value('udp', _('UDP'));
		so.value('', _('Both'));

		so = ars.taboption('field_other', hp.CBIStaticList, 'inbound', _('Inbound'),
			_('Match inbound tag.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			this.value('dns-in', _('DNS inbound'));
			this.value('mixed-in', _('Mixed (SOCKS/HTTP) inbound'));
			this.value('redirect-in', _('Redirect inbound'));
			this.value('tproxy-in', _('TProxy inbound'));
			this.value('tun-in', _('TUN inbound'));

			uci.sections('ravnex', 'server', function(res) {
				if (res.enabled === '1')
					this.value('cfg-' + res['.name'] + '-in', res.label || res['.name']);
			});

			return this.super('load', section_id);
		}
		so.modalonly = true;

		so = ars.taboption('field_other', form.DynamicList, 'user', _('User'),
			_('Match user name.'));
		so.modalonly = true;

		so = ars.taboption('field_other', hp.CBIStaticList, 'rule_set', _('Rule set'),
			_('Match rule set.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			uci.sections('ravnex', 'ruleset', function(res) {
				if (res.enabled === '1')
					this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'rule_set_ip_cidr_match_source', _('Rule set IP CIDR as source IP'),
			_('Make IP CIDR in rule set used to match the source IP.'));
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'invert', _('Invert'),
			_('Invert match result.'));
		so.modalonly = true;

		so = ars.taboption('field_other', form.ListValue, 'action', _('Action'));
		so.value('route', _('Route'));
		so.value('route-options', _('Route options'));
		so.value('reject', _('Reject'));
		so.value('resolve', _('Resolve'));
		so.default = 'route';
		so.rmempty = false;
		so.editable = true;

		so = ars.taboption('field_other', form.ListValue, 'outbound', _('Outbound'),
			_('Tag of the target outbound.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			this.value('direct-out', _('Direct'));
			/* "Same as main node" (main-out) exists in every app-managed mode (Ф3.1);
			 * gate it on the main-node VALUE being set, not on a mode, to avoid
			 * offering a tag that won't exist. */
			if (uci.get('ravnex', 'config', 'main_node'))
				this.value('main-out', _('Same as main node') + ' 🔗');
			/* byedpi-out IS emitted in every routing mode whenever ByeDPI is
			 * enabled — a rule can target it directly, no routing node needed. */
			if (uci.get('ravnex', 'config', 'byedpi_enabled') === '1')
				this.value('byedpi-out', _('ByeDPI'));
			if (uci.get('ravnex', 'config', 'zapret_enabled') === '1')
				this.value('zapret-out', _('Zapret'));
			uci.sections('ravnex', 'routing_node', function(res) {
				if (res.enabled === '1')
					this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		so.rmempty = false;
		so.depends('action', 'route');
		so.editable = true;

		so = ars.taboption('field_other', form.Value, 'override_address', _('Override address'),
			_('Override the connection destination address.'));
		so.datatype = 'ipaddr';
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Value, 'override_port', _('Override port'),
			_('Override the connection destination port.'));
		so.datatype = 'port';
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'udp_disable_domain_unmapping', _('Disable UDP domain unmapping'),
			_('If enabled, for UDP proxy requests addressed to a domain, the original packet address will be sent in the response instead of the mapped domain.'));
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'udp_connect', _('connect UDP connections'),
			_('If enabled, attempts to connect UDP connection to the destination instead of listen.'));
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Value, 'udp_timeout', _('UDP timeout'),
			_('Timeout for UDP connections.<br/>Setting a larger value than the UDP timeout in inbounds will have no effect.'));
		so.datatype = 'uinteger';
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'tls_record_fragment', _('TLS record fragment'),
			_('Fragment TLS handshake into multiple TLS records.'));
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'tls_fragment', _('TLS fragment'),
			_('Fragment TLS handshakes. Due to poor performance, try <code>%s</code> first.').format(
				_('TLS record fragment')));
		so.depends('action', 'route');
		so.depends('action', 'route-options');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Value, 'tls_fragment_fallback_delay', _('Fragment fallback delay'),
			_('The fallback value in milliseconds used when TLS segmentation cannot automatically determine the wait time.'));
		so.datatype = 'uinteger';
		so.placeholder = '500';
		so.depends('tls_fragment', '1');
		so.modalonly = true;

		so = ars.taboption('field_other', form.ListValue, 'resolve_server', _('DNS server'),
			_('Specifies DNS server tag to use instead of selecting through DNS routing.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			this.value('', _('Default'));
			this.value('default-dns', _('Default DNS (issued by WAN)'));
			this.value('system-dns', _('System DNS'));
			uci.sections('ravnex', 'dns_server', function(res) {
				if (res.enabled === '1')
					this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		so.depends('action', 'resolve');
		so.modalonly = true;

		so = ars.taboption('field_other', form.ListValue, 'reject_method', _('Method'));
		so.value('default', _('Reply with TCP RST / ICMP port unreachable'));
		so.value('drop', _('Drop packets'));
		so.depends('action', 'reject');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'reject_no_drop', _('Don\'t drop packets'),
			_('<code>%s</code> will be temporarily overwritten to <code>%s</code> after 50 triggers in 30s if not enabled.').format(
			_('Method'), _('Drop packets')));
		so.depends('reject_method', 'default');
		so.modalonly = true;

		so = ars.taboption('field_other', form.ListValue, 'resolve_strategy', _('Resolve strategy'),
			_('Domain strategy for resolving the domain names.'));
		for (let i in hp.dns_strategy)
			so.value(i, hp.dns_strategy[i]);
		so.depends('action', 'resolve');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Flag, 'resolve_disable_cache', _('Disable DNS cache'),
			_('Disable DNS cache in this query.'));
		so.depends('action', 'resolve');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Value, 'resolve_rewrite_ttl', _('Rewrite TTL'),
			_('Rewrite TTL in DNS responses.'));
		so.datatype = 'uinteger';
		so.depends('action', 'resolve');
		so.modalonly = true;

		so = ars.taboption('field_other', form.Value, 'resolve_client_subnet', _('EDNS Client subnet'),
			_('Append a <code>edns0-subnet</code> OPT extra record with the specified IP prefix to every query by default.<br/>' +
			'If value is an IP address instead of prefix, <code>/32</code> or <code>/128</code> will be appended automatically.'));
		so.datatype = 'or(cidr, ipaddr)';
		so.depends('action', 'resolve');
		so.modalonly = true;

		so = ars.taboption('field_host', form.DynamicList, 'domain', _('Domain name'),
			_('Match full domain.'));
		so.datatype = 'hostname';
		so.modalonly = true;

		so = ars.taboption('field_host', form.DynamicList, 'domain_suffix', _('Domain suffix'),
			_('Match domain suffix.'));
		so.modalonly = true;

		so = ars.taboption('field_host', form.DynamicList, 'domain_keyword', _('Domain keyword'),
			_('Match domain using keyword.'));
		so.modalonly = true;

		so = ars.taboption('field_host', form.DynamicList, 'domain_regex', _('Domain regex'),
			_('Match domain using regular expression.'));
		so.modalonly = true;

		so = ars.taboption('field_host', form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
			_('Match source IP CIDR.'));
		so.datatype = 'or(cidr, ipaddr)';
		so.modalonly = true;

		so = ars.taboption('field_host', form.Flag, 'source_ip_is_private', _('Match private source IP'));
		so.modalonly = true;

		so = ars.taboption('field_host', form.DynamicList, 'ip_cidr', _('IP CIDR'),
			_('Match IP CIDR.'));
		so.datatype = 'or(cidr, ipaddr)';
		so.modalonly = true;

		so = ars.taboption('field_host', form.Flag, 'ip_is_private', _('Match private IP'));
		so.modalonly = true;

		so = ars.taboption('field_port', form.DynamicList, 'source_port', _('Source port'),
			_('Match source port.'));
		so.datatype = 'port';
		so.modalonly = true;

		so = ars.taboption('field_port', form.DynamicList, 'source_port_range', _('Source port range'),
			_('Match source port range. Format as START:/:END/START:END.'));
		so.validate = hp.validatePortRange;
		so.modalonly = true;

		so = ars.taboption('field_port', form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		so.datatype = 'port';
		so.modalonly = true;

		so = ars.taboption('field_port', form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:/:END/START:END.'));
		so.validate = hp.validatePortRange;
		so.modalonly = true;

		so = ars.taboption('fields_process', form.DynamicList, 'process_name', _('Process name'),
			_('Match process name.'));
		so.modalonly = true;

		so = ars.taboption('fields_process', form.DynamicList, 'process_path', _('Process path'),
			_('Match process path.'));
		so.modalonly = true;

		so = ars.taboption('fields_process', form.DynamicList, 'process_path_regex', _('Process path (regex)'),
			_('Match process path using regular expression.'));
		so.modalonly = true;

		const advHost = E('div', {});
		advMap.render().then(function(node) {
			advHost.appendChild(node);
		}).catch(function(e) {
			advHost.appendChild(E('p', { 'class': 'hpui-hint hpui-c-red' },
				[ _('The expert editor failed to render: ') + e ]));
		});

		/* ONE door for the whole expert group (the standard tracked-apply
		 * flow): the map saves into the UCI session, then the LuCI apply
		 * (rollback protected) commits and the changes module ITSELF
		 * reloads the page after the confirm — a manual reload here would
		 * kill the in-flight confirm and the rollback timer would undo the
		 * commit (caught live twice in the acceptance). The 6 s re-enable
		 * covers the "no changes" case where no reload happens. */
		const advResult = E('span', { 'class': 'hpui-hint' });
		const advSaveBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply' },
			[ _('Save & Apply') ]);
		advSaveBtn.addEventListener('click', function() {
			advSaveBtn.disabled = true;
			advResult.textContent = '';
			Promise.resolve(advMap.save(null, true))
				.then(function() { return ui.changes.apply(true); })
				.then(function() {
					window.setTimeout(function() { advSaveBtn.disabled = false; }, 6000);
				})
				.catch(function(e) {
					advSaveBtn.disabled = false;
					advResult.textContent = _('Save failed: ') + ((e && e.message) || e);
				});
		});

		const expertPanel = E('details', { 'class': 'hpui-panel', style: 'margin:12px 0 0 0' }, [
			E('summary', { style: 'cursor:pointer; font-weight:600; user-select:none; padding:2px 0' }, [
				hp.icon('crosshair'), ' ',
				_('Expert: routing nodes & raw rules') + ' · ' + _('hidden by default — open only if needed')
			]),
			E('p', { 'class': 'hpui-hint', style: 'margin:10px 0 4px 0' },
				[ _('Routing nodes are custom chains and URLTest sub-groups rules can point at; they apply as soon as they exist (enabled) — no extra switch. The raw sing-box rules below are the expert level: they emit with the highest priority and need the switch above.') ]),
			advHost,
			E('div', { style: 'display:flex; align-items:center; gap:10px; margin-top:10px' }, [
				advSaveBtn,
				advResult
			])
		]);

		/* Ф9.3/D29: v3 page skeleton — intro, the order map, the route
		 * checker (the main instrument), then the editable rows and the
		 * per-zone result/list surfaces; the collapsed expert group last. */
		return E('div', {}, [
			hp.pageIntro(_('Service rules'),
				_('Which service exits through what: the order map shows how a route is decided, the checker shows any site\'s live route, and the rows below assign exits. Routing applies in "Bypass blocking" mode; everything unmatched goes directly.')),
			envBanners,
			orderMapPanel,
			routePanel,
			presetRows,
			checkPanel,
			listsPanel,
			expertPanel
		]);
	}
});
