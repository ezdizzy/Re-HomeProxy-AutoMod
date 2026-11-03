/* Ravnex — Service rules (R3 v3b, 19-UX_REDESIGN p.5)
 * The SINGLE place "which service exits through what": preset rows
 * (base zone, from the former Wizard "Services → exits" pane) + the
 * advanced proxy_ru_rule editor (moved from the Client page) + the
 * manual domain lists. One result area below the presets; the expert
 * grid saves through the standard LuCI form flow. */

'require dom';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';
'require form';
'require validation';
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
.wiz-svc .wiz-note { margin: 6px 0 0 0; }
@media (max-width: 900px) {
	.wiz-svc-grid { display: flex; flex-wrap: wrap; }
	.wiz-svc-grid > .wiz-title { flex: 1 1 220px; }
	.wiz-svc-grid > .wiz-state { flex: 1 1 240px; }
	.wiz-svc-grid > .wiz-select { width: auto; }
}
.wiz-note { font-size: .88em; opacity: .8; margin: 8px 0; }
.wiz-hosts { color: var(--hp-grey); font-size: .82em; }
.wiz-pool { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 6px 10px; margin: 4px 0 0 0; font-size: .88em; border: 1px dashed var(--hp-panel-line-strong); border-radius: var(--hp-radius); }
.wiz-pool label { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
.wiz-group { flex-basis: 100%; font-weight: 600; font-size: .95em; margin: 14px 0 2px 0; padding-top: 10px; border-top: 1px solid var(--hp-panel-line); }
.wiz-group:first-child { border-top: 0; padding-top: 0; margin-top: 0; }
`;

/* Minimal validation stub (same as client.js) for the node label builder. */
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
		? E('span', { 'class': 'hpui-badge hpui-b-blue' }, [ '→ ' + nodeText(rule.node) ])
		: E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ _('disabled') + ' (→ ' + nodeText(rule.node) + ')' ]));
	if (rule.node === 'urltest' && rule.urltest_nodes && rule.urltest_nodes.length)
		parts.push(E('span', { 'class': 'wiz-note', style: 'margin:0' },
			[ _('pool: %d node(s)').format(rule.urltest_nodes.length) ]));
	if (count > 1)
		parts.push(E('span', { 'class': 'wiz-note', style: 'margin:0' },
			[ _('+%d more rule(s) of this service — see the manual editor').format(count - 1) ]));
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
		 * targets for the rest. */
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
		 * any source. */
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

		const state = { presetsSig: null, pendingCheck: null };
		let lastEnv = null;

		/* ── Base zone: presets ───────────────────────────────────────── */
		const envBanners = E('div', {});
		const presetRows = E('div', {});
		const checkResult = E('div', {});

		/* ── Expert zone: manual domain lists ─────────────────────────── */
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
		/* Ф1.1b: the direct-list save spawns a tracked reload operation —
		 * poll app_op_status until the honest verified verdict; a hot apply
		 * (proxy list file sync) resolves at once. */
		function pollListApply(desc, okText, failText) {
			if (!desc || desc.hot || !desc.op_id) {
				dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ okText ]));
				return;
			}
			const deadline = Date.now() + 150000;
			const tick = function() {
				return L.resolveDefault(callOpStatus(desc.op_id), {}).then(function(st) {
					const op = st && st.op;
					if (op && op.status !== 'completed' && op.status !== 'failed') {
						if (Date.now() > deadline) {
							dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
								[ _('The apply operation is still running — check the operation journal on the Diagnostics page.') ]));
							return;
						}
						window.setTimeout(tick, 2000);
						return;
					}
					const ok = !!op && op.status === 'completed' && op.verified;
					dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [
						ok ? okText : (failText + ((op && op.detail) ? (' — ' + op.detail) : ''))
					]));
				});
			};
			tick();
		}

		dListSave.addEventListener('click', function() {
			dListSave.disabled = true;
			dom.content(checkResult, E('p', { 'class': 'hpui-hint' }, [ _('Saving…') ]));
			Promise.all([
				L.resolveDefault(callAclListWrite('proxy_list', dListProxy.value || ''), {}),
				L.resolveDefault(callAclListWrite('direct_list', dListDirect.value || ''), {})
			]).then(function(res) {
				const bad = (!res[0] || res[0].result === false || !res[1] || res[1].result === false);
				if (bad) {
					dom.content(checkResult, E('p', { 'class': 'hpui-hint' },
						[ _('Saving the domain lists failed.') ]));
					return;
				}
				/* The direct-list write carries the tracked reload op; the
				 * proxy list rides the watched-file hot sync. */
				pollListApply((res[1] && res[1].apply) || (res[0] && res[0].apply),
					_('Domain lists saved and applied — the core is running the new lists.'),
					_('Domain lists saved, but the apply failed'));
			}).finally(function() { dListSave.disabled = false; });
		});
		L.resolveDefault(callAclListRead('proxy_list'), {}).then(function(r) {
			dListProxy.value = (r && r.content) ? String(r.content) : '';
		});
		L.resolveDefault(callAclListRead('direct_list'), {}).then(function(r) {
			dListDirect.value = (r && r.content) ? String(r.content) : '';
		});

		function renderPresets(list) {
			/* Rebuild the rows ONLY when the underlying state changed: a 4s
			 * poll rebuild would reset the exit <select> the user is working
			 * with (a form-ish row must not). */
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

			presetRows.innerHTML = '';
			presetRows.appendChild(E('div', { 'class': 'wiz-note' },
				[ _('The mass lists below already cover YouTube/Discord/Telegram and most blocked resources — a per-service rule overrides the mass list.') ]));

			function buildServiceRow(preset) {
				const rule = (list.rules || {})[preset.source];
				const count = (list.rule_counts || {})[preset.source] || 0;

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
				sel.appendChild(E('option', { value: '' }, [ _('Direct (remove rule)') ]));
				if (!env.main_is_direct)
					sel.appendChild(E('option', { value: 'main-out' }, [ _('Same as main node') ]));
				if (env.byedpi_enabled)
					sel.appendChild(E('option', { value: 'byedpi-out' }, [ 'ByeDPI' ]));
				if (env.zapret_enabled)
					sel.appendChild(E('option', { value: 'zapret-out' }, [ 'Zapret' ]));
				/* The transparent tg-ws exit — offered for Telegram only and
				 * only while the bridge is running (rpcd re-checks both). */
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
					/* urltest_nodes crosses as a JSON-encoded STRING: rpcd's ucode
					 * plugin maps a string typehint to BLOBMSG_TYPE_STRING, and
					 * native array typehints crash strict new rpcd (issue #11). */
					callPresetApply(preset.source, String(sel.value || ''), JSON.stringify(sel.value === 'urltest' ? ids : [])).then(function(r) {
						if (!r || r.result === false) {
							const ERRS = {
								main_is_direct: _('Main node is Direct — this rule would have no effect. Pick Zapret/ByeDPI or a real node.'),
								byedpi_disabled: _('ByeDPI is not enabled — enable it on the Connection page first.'),
								zapret_disabled: _('Zapret is not enabled — enable it on the Connection page first.'),
								tgws_not_running: _('The tg-ws bridge is not running — install/start it on the Phone control page first.'),
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

				/* Pool picker + hints live BELOW the grid line. */
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

				/* T1 (G1): a SHORT, provider-independent hint — the exit country
				 * of the bridge differs per user, so no measured locations here. */
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
			 * through a throwaway probe core; the result lands in the ONE
			 * result area. */
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
				checkResult.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('No nodes found in the running config.') ]));
			if (r.truncated)
				checkResult.appendChild(E('div', { 'class': 'wiz-note' },
					[ _('Some nodes were not checked (limit 12).') ]));
			checkResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('To switch the exit: pick the node in the service row above and press Apply.') ]));
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

		/* ── Expert zone: the manual rule editor (moved from the Client
		 * page) + the manual domain lists, collapsed so the everyday flow
		 * stays clean. The grid reads uci at page open — after applying
		 * presets offer an explicit reload so it never saves stale state. */
		const m = new form.Map('homeproxy');
		const s = m.section(form.TypedSection, 'proxy_ru_rule', null);
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.description = _('Default route is Direct. Added rules are proxied, with automatic priority:<br>1. Smaller lists (YouTube, Discord etc.)<br>2. <b>Russia Inside</b> (1000+ domains, itdoginfo) — the in-Russia must-have set (YouTube, Discord, Telegram, Meta…) routed through the proxy<br>3. <b>Re-filter</b> (60000+ domains + 25000+ IPs) — community blocklist of domains and IPs banned in Russia (Roskomnadzor)<br><br><em>Note: the Zapret installer may add a "YouTube → Zapret" rule here automatically. Combining engines works by rules: "YouTube → Zapret" + everything else on the Main node, or Main node = Direct with only some services via an engine.</em>');
		/* Honest-state hint: with Main node = Direct every "Same as main node"
		 * rule still matches but egresses directly — say so, hide the pointless
		 * option for NEW rules, and point at the engines. */
		if (uci.get('homeproxy', 'config', 'main_node') === 'direct-out')
			s.description += '<br><b>' + _('Main node is Direct: rules pointing at "Same as main node" currently egress directly (no tunnel). Switch them to Zapret/ByeDPI, or choose a real main node / URLTest.') + '</b>';

		/* Per-rule Delete placement: LuCI renders each remove button on its own
		 * line ABOVE the rule block — visually detached from the rule it removes.
		 * Relocate it into the rule's first option row, right next to the
		 * "Enable" checkbox, so the association is obvious. Pure DOM reshuffle:
		 * the button (with its LuCI click handler) is moved as-is and the
		 * now-empty .cbi-section-remove wrapper is dropped; the stock layout is
		 * kept as fallback if the expected nodes are not found. */
		const origRenderContents = s.renderContents;
		s.renderContents = function(cfgsections, nodes) {
			const relocate = function(sectionEl) {
				for (const sid of cfgsections) {
					const btn = sectionEl.querySelector('.cbi-section-remove button[data-section-id="%s"]'.format(sid));
					if (!btn)
						continue;
					const wrap = btn.closest('.cbi-section-remove');
					const nodeEl = sectionEl.querySelector('.cbi-section-node[data-section-id="%s"]'.format(sid));
					const field = nodeEl ? nodeEl.querySelector('.cbi-value-field') : null;
					if (!field)
						continue;
					btn.classList.add('hp-rule-delete');
					field.appendChild(btn);
					wrap.parentNode.removeChild(wrap);
				}
				return sectionEl;
			};
			const res = origRenderContents.apply(this, arguments);
			return (res && typeof res.then === 'function') ? res.then(relocate) : relocate(res);
		};

		/* Cache all configured proxy nodes (same wording as the Client
		 * page grids). */
		let proxy_nodes = {};
		uci.sections('homeproxy', 'node', function(res) {
			let nodeaddr = ((res.type === 'direct') ? res.override_address : res.address) || '',
			    nodeport = ((res.type === 'direct') ? res.override_port : res.port) || '';

			proxy_nodes[res['.name']] =
				String.format('[%s] %s', res.type, res.label || ((stubValidator.apply('ip6addr', nodeaddr) ?
					String.format('[%s]', nodeaddr) : nodeaddr) + ':' + nodeport));
		});

		let so = null;
		so = s.option(form.Flag, 'enabled', _('Enable'));
		so.default = so.enabled;
		so.rmempty = false;
		so.editable = true;

		so = s.option(form.ListValue, 'source', _('Source') + ' ⤵️');
		/* Russia bulk lists are RU-forward only; CN/IR get geosite/geoip baked into the
		 * engine baseline, so here they only need per-service overrides. Built in
		 * .load() so a mode switch (silent-save + re-render) refreshes the list
		 * IMMEDIATELY — reading persisted UCI at view-render time left Re-filter
		 * missing until the user manually reloaded the page. */
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;
			if (uci.get('homeproxy', 'config', 'routing_mode') === 'proxy_banned_ru') {
				this.value('refilter', _('Re-filter (Russia blocklist: 60000+ banned domains + 25000+ IPs)'));
				this.value('russia-inside', _('itdoginfo/allow-domains - Russia Inside (1000+ entries)'));
			}
			this.value('block', _('Block (core RKN-blocked resources)'));
			this.value('russia-outside', _('Russia Outside (RU-only services — for use abroad)'));
			this.value('ukraine-inside', _('Ukraine Inside (resources blocked in UA)'));
			this.value('youtube', _('YouTube'));
			this.value('twitter', _('Twitter/X'));
			this.value('tiktok', _('TikTok'));
			this.value('telegram', _('Telegram'));
			this.value('roblox', _('Roblox'));
			this.value('porn', _('Adult content'));
			this.value('ovh', _('OVH (France cloud hosting)'));
			this.value('news', _('International news sites'));
			this.value('meta', _('Meta (Facebook, Instagram)'));
			this.value('hodca', _('HODCA'));
			this.value('hetzner', _('Hetzner (Germany cloud hosting)'));
			this.value('hdrezka', _('HDRezka'));
			this.value('google_ai', _('Google AI services'));
			this.value('google-meet', _('Google Meet'));
			this.value('google_play', _('Google Play'));
			this.value('geoblock', _('GeoBlock services'));
			this.value('anime', _('Anime streaming'));
			this.value('cloudflare', _('Cloudflare CDN'));
			this.value('cloudfront', _('CloudFront CDN'));
			this.value('discord', _('Discord'));
			this.value('digitalocean', _('DigitalOcean cloud hosting'));
			/* W4: MetaCubeX geosite sources + b4geoip gaming IP sets (the
			 * generator's SOURCE_URL_MAP / SOURCE_IP_MAP consume these). */
			this.value('openai', _('OpenAI (ChatGPT)'));
			this.value('anthropic', _('Claude / Anthropic'));
			this.value('whatsapp', _('WhatsApp'));
			this.value('twitch', _('Twitch'));
			this.value('valve', _('Valve / Steam'));
			this.value('epicgames', _('Epic Games'));
			this.value('riot', _('Riot Games'));
			this.value('sony', _('Sony / PlayStation'));
			this.value('electronicarts', _('EA / Electronic Arts'));
			this.value('ubisoft', _('Ubisoft'));
			this.value('blizzard', _('Blizzard'));
			this.value('nintendo', _('Nintendo'));
			this.value('wargaming', _('Wargaming'));
			this.value('xbox', _('Xbox'));
			return this.super('load', section_id);
		};
		so.rmempty = false;
		so.editable = true;
		/* The source validator needs the sibling `node` option; it is assigned right
		 * after the node option is created below. */
		let ruleNodeOption = null;
		const validateSourceUnique = function(section_id, value) {
			for (const sid of this.section.cfgsections()) {
				if (sid === section_id) continue;
				/* Compare against PENDING form values first: two freshly added
				 * duplicates must be caught before save, not after. Only an
				 * identical (source, node) PAIR is a real duplicate — the same
				 * source via different outbounds (e.g. YouTube via Zapret AND
				 * YouTube via the VPN) is a legitimate combination. */
				let other;
				try { other = this.formvalue(sid); } catch(e) {}
				if (other == null)
					other = this.cfgvalue(sid);
				if (other !== value)
					continue;
				if (!ruleNodeOption)
					return _('Duplicate rule — a rule with the same service and target already exists');
				let otherNode, myNode;
				try { otherNode = ruleNodeOption.formvalue(sid); } catch(e) {}
				if (otherNode == null) otherNode = ruleNodeOption.cfgvalue(sid);
				try { myNode = ruleNodeOption.formvalue(section_id); } catch(e) {}
				if (myNode == null) myNode = ruleNodeOption.cfgvalue(section_id);
				if (otherNode === myNode || otherNode == null || myNode == null)
					return _('Duplicate rule — a rule with the same service and target already exists');
			}
			return true;
		};
		so.validate = validateSourceUnique;

		so = s.option(form.ListValue, 'node', _('Node') + ' 🔗');
		/* Dynamic for the same reason as `source`: silent-saved main node / engine
		 * toggles must reflect here without a manual page reload. "Same as main
		 * node" is hidden while the main node is Direct — it would just egress
		 * directly; engines appear only while enabled. */
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;
			if (uci.get('homeproxy', 'config', 'main_node') !== 'direct-out')
				this.value('main-out', _('Same as main node'));
			else if (section_id && uci.get('homeproxy', section_id, 'node') === 'main-out')
				/* Direct mode: keep main-out selectable ONLY for rules that already
				 * store it — hiding it entirely made those rules render a blank
				 * selection while UCI still said main-out. */
				this.value('main-out', _('Same as main node'));
			this.value('urltest', _('Separate URLTest'));
			for (let i in proxy_nodes)
				this.value(i, proxy_nodes[i]);
			if (uci.get('homeproxy', 'config', 'byedpi_enabled') === '1')
				this.value('byedpi-out', _('ByeDPI'));
			if (uci.get('homeproxy', 'config', 'zapret_enabled') === '1')
				this.value('zapret-out', _('Zapret'));
			return this.super('load', section_id);
		};
		ruleNodeOption = so;
		so.rmempty = false;
		so.editable = true;

		so = s.option(hp.CBIStaticList, 'urltest_nodes', _('URLTest nodes'),
			_('List of nodes to test.'));
		for (let i in proxy_nodes)
			so.value(i, proxy_nodes[i]);
		so.depends('node', 'urltest');
		so.rmempty = false;
		so.modalonly = true;

		so = s.option(form.Value, 'urltest_interval', _('Test interval'),
			_('The test interval in seconds.'));
		so.datatype = 'uinteger';
		so.placeholder = '180';
		so.depends('node', 'urltest');
		so.modalonly = true;

		so = s.option(form.Value, 'urltest_tolerance', _('Test tolerance'),
			_('The test tolerance in milliseconds.'));
		so.datatype = 'uinteger';
		so.placeholder = '150';
		so.depends('node', 'urltest');
		so.modalonly = true;

		const expertDetails = E('details', { style: 'margin:14px 0' }, [
			E('summary', { style: 'cursor:pointer; font-weight:600' },
				[ _('Advanced: manual rules and domain lists') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('The manual editor works with the same rules as the presets above (one page, one store). Use it for shapes the presets do not build — e.g. the same service through two different exits, or custom port/process matches.') ]),
			E('div', { 'class': 'wiz-row' }, [
				E('span', { 'class': 'wiz-title' }, [ _('Proxy domains') ]),
				dListProxy
			]),
			E('div', { 'class': 'wiz-row' }, [
				E('span', { 'class': 'wiz-title' }, [ _('Direct domains') ]),
				dListDirect
			]),
			E('div', { 'class': 'wiz-toolbar' }, [ dListSave ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('One host per line. The proxy list is merged with the engine-learned records (one watched rule-set); the direct list wins over the proxy list for matching domains. These are the manual routing inputs — presets above cover the known services.') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('The editor reads the rules when the page opens — after applying presets reload the page so it shows the fresh list.') ])
		]);
		/* form.Map.render() is ASYNC — embed the finished node when it lands. */
		m.render().then(function(node) {
			if (node)
				expertDetails.appendChild(node);
		});

		return E('div', {}, [
			E('h2', {}, _('Service rules')),
			E('p', { 'class': 'hpui-hint', style: 'margin-top:2px' },
				[ _('Which service exits through what: pick an exit for each known service — YouTube, Discord, Telegram, AI, games and the mass lists — and check the live route right here. Routing applies in "Bypass blocking" mode; everything unmatched goes directly.') ]),
			envBanners,
			presetRows,
			E('h4', { style: 'margin-top:14px' }, [ _('Check results') ]),
			checkResult,
			expertDetails
		]);
	}
});
