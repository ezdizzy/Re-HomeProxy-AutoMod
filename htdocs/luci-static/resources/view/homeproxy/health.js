/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex -- Health center (plan 20 s3 F2.6, D21) merged with Check & repair
 * per D32 (session 116): one page, four tabs.
 *   Overview           -- live status of every subsystem (Health), the
 *                         system attention list (Sentinel) and the actions.
 *   Check & repair     -- the actual probes: core, config, DNS tests,
 *                         network interception, connectivity, support report.
 *   Operations journal -- the repair history (Recovery) + the unified event
 *                         feed (Event Bus).
 *   Provider           -- what the provider blocks and how the services
 *                         behave: provider scan, service profiles, route
 *                         optimizer, discovery snapshot.
 * The center stays a separate page (D21 not violated); the former standalone
 * diagnostics page is gone (menu item removed, overview.js links point to
 * the tabs). Every action result renders in ONE place per zone
 * (ui.action_buttons_result_placement).
 */

'use strict';
'require dom';
'require homeproxy as hp';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';
/* LuCI's rpc.js aborts every XHR after L.env.rpctimeout ?? 20 seconds —
 * the text support report legitimately builds for ~25 s (log tails, UCI
 * scans), so the browser killed the call and the card showed «Пустой
 * отчёт». Raise THIS PAGE's client timeout; the server path is proven
 * fine (the same ubus call answers in full over the CLI). */
L.env.rpctimeout = 60;

/* Diagnostics-specific additions on top of the shared hpui design system
 * (hp.uiStyle() — same visual language as the Automation tab). */
const css = '\
.diag-section { margin: 0; }\
.diag-row { display:flex; align-items:baseline; margin:.35em 0; gap:.6em; }\
.diag-label { min-width:11em; opacity:.75; font-size:.9em; flex-shrink:0; }\
.diag-ok   { color: #3fbf5f; font-weight: bold; }\
.diag-fail { color: #e05252; font-weight: bold; }\
.diag-warn { color: #d99a1b; font-weight: bold; }\
.diag-gray { color: #9a9a9a; }\
.diag-port-line { font-family:monospace; font-size:.82em; margin:.1em 0; }\
.hpui-btn-sm { padding: 2px 10px; font-size: .84em; white-space: nowrap; }\
.wiz-note { font-size:.88em; opacity:.8; margin:.3em 0; }\
.diag-row .cbi-input-text { flex:1 1 260px; }\
#diag-bundle-text { width:100%; max-height:22em; overflow:auto; white-space:pre;\
  font-family:monospace; font-size:.8em; }\
';

/* ── RPC declarations ─────────────────────────────────────────────────── */

const callCoreCheck = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_core_check',
	expect: { '': {} }
});
const callConfigCheck = rpc.declare({
	object: 'luci.ravnex',

	method: 'diag_config_check',

	expect: { '': {} }
});

const callConfigHeal = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_config_heal',
	params: [ 'repair' ],
	expect: { '': {} }
});
const callDnsRu = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_dns_ru',
	expect: { '': {} }
});

const callDnsMultidns = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_dns_multidns',
	expect: { '': {} }
});

const callNftables = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_nftables',
	expect: { '': {} }
});


const callServiceRestart = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_service_restart',
	expect: { '': {} }
});

/* Ф1.1 Operation/Apply Manager: операции применения выполняются асинхронно
 * (стадии Applying→Verifying→Completed/Failed, verified только по живой
 * проверке) — статус опрашивается до завершения. */
const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

/* Support Bundle (Р4): сбор приватно-безопасного отчёта. */
const callBundleStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_support_bundle_start',
	expect: { '': {} }
});

const callBundleStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_support_bundle_status',
	expect: { '': {} }
});

const callBundleChunk = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_support_bundle_chunk',
	params: [ 'offset', 'kind' ],
	expect: { '': {} }
});

/* Text report rides the SAME async pattern as the archive (lesson 294: the
 * sync popen inside the rpcd loop tore the shared ubus stream). */
const callBundleTextStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_support_bundle_text_start',
	expect: { '': {} }
});

const callBundleTextStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_support_bundle_text_status',
	expect: { '': {} }
});

const callConnCheck = rpc.declare({
	object: 'luci.ravnex',
	method: 'connection_check',
	params: ['site'],
	expect: { '': {} }
});

const callIpInfo = rpc.declare({
	object: 'luci.ravnex',
	method: 'clash_ip_info',
	expect: { '': {} }
});

const callActiveNode = rpc.declare({
	object: 'luci.ravnex',
	method: 'clash_active_node',
	params: ['tag'],
	expect: { '': {} }
});

const callRouteExplain = rpc.declare({
	object: 'luci.ravnex',
	method: 'route_explain',
	params: ['host'],
	expect: { '': {} }
});

/* ── Provider diagnostics (R3 v3b: moved from the Wizard «Provider
 * diagnostics» pane — same RPC, same ONE result area). ────────────────── */

const callScanStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_provider_scan',
	params: [ 'hosts' ],
	expect: { '': {} }
});

const callScanStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_scan_status',
	expect: { '': {} }
});

/* Ф8-F1: dpi-detect seeds (splify2-lists) — update runs as a background
 * runner; the poll shows its progress in the provider pane row. */
const callDpiUpdate = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_dpidetect_update',
	expect: { '': {} }
});

const callPresetList = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_preset_list',
	expect: { '': {} }
});

/* Human name of a rule outbound (same wording as wizard.js). */
function nodeText(node) {
	if (node === 'main-out') return _('Same as main node');
	if (node === 'byedpi-out') return 'ByeDPI';
	if (node === 'zapret-out') return 'Zapret';
	if (node === 'urltest') return _('URLTest pool');
	return resolveTag(node);
}

/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label. */
function resolveTag(tag) {
	const m = tag && tag.match(/^cfg-(.+)-out$/);
	if (m) {
		const label = uci.get('homeproxy', m[1], 'label');
		if (label) return label;
	}
	/* Fixed aggregate tags → name the configured node behind them. */
	const specials = { 'main-out': 'main_node', 'main-udp-out': 'main_udp_node' };
	if (specials[tag]) {
		const v = uci.get('homeproxy', 'config', specials[tag]);
		if (v === 'byedpi-out') return 'ByeDPI';
		if (v === 'zapret-out') return 'Zapret';
		if (v && !['urltest', 'same', 'nil', ''].includes(v)) {
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

/* ── Provider pane (R3 v3b): what exactly the provider blocks, through
 * the user's REAL configured paths. Verdicts speak about the configured
 * routing; the Direct column is reference. ONE result area. ───────────── */

const PROV_VERDICTS = {
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
	partial:        [ 'hpui-b-grey', _('Partial picture — not all paths were measured') ],
	unknown:        [ 'hpui-b-grey', _('No data') ]
};

/* Ф6.1 Diagnostic Core: the ONE cause taxonomy (backend diag_core.uc).
 * The routing verdict above says WHICH path is better; the cause line says
 * WHY the resource is unavailable — with an explicit confidence level. */
const PROV_CAUSES = {
	isp_interference:       _('Cause: the provider cuts the connection (DPI)'),
	origin_geo_restriction: _('Cause: the origin refuses the region (geo)'),
	origin_waf:             _('Cause: origin WAF/protection challenge'),
	origin_ip_policy:       _('Cause: origin IP/ASN policy'),
	dns_interference:       _('Cause: DNS tampering'),
	client_filtering:       _('Cause: own rules/lists'),
	remote_failure:         _('Cause: remote-side failure'),
	inconclusive:           _('Cause not established')
};
const PROV_CONF = {
	high:   _('high confidence'),
	medium: _('medium confidence'),
	low:    _('low confidence')
};

function causeLine(r) {
	const c = r.cause;
	if (!c || !c.type)
		return null;
	const base = PROV_CAUSES[c.type] || c.type;
	const conf = PROV_CONF[c.confidence] || '';
	const evj = (c.evidence && c.evidence.length) ? c.evidence.join('\n') : '';
	return E('div', { 'class': 'wiz-note', style: 'margin:2px 0 0', title: evj },
		[ base + (conf ? (' · ' + conf) : '') ]);
}

/* The scanner sees no rules; the client remaps the verdict to what the
 * user configured (Ф8-W2). */
function effVerdict(r, rule) {
	if (r.verdict === 'opens_direct' && rule && rule.enabled && r.svc !== 'ru_control')
		return 'works_live';
	return r.verdict;
}

function verdictCell(r, rule) {
	const v = effVerdict(r, rule);
	const spec = PROV_VERDICTS[v] || PROV_VERDICTS.unknown;
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
	const badge = E('span', { 'class': 'hpui-badge ' + spec[0] }, [ label ]);
	/* Ф6.1: причина (почему недоступен) живёт РЯДОМ с routing-вердиктом —
	 * одно место, без отдельных колонок. */
	const cl = causeLine(r);
	return cl ? E('div', {}, [ badge, cl ]) : badge;
}

const PROV_KINDS = {
	tls_dpi:   _('TLS DPI (SNI reset)'),
	tcp:       _('TCP unreachable'),
	timeout:   _('Timeout (dropped?)'),
	resolve:   _('DNS resolve failed'),
	sigpage:   _('Block page served as 200'),
	hardcode:  _('Refusal code (403/406/451)'),
	waf:       _('WAF challenge (path is open)'),
	waf_rl:    _('Rate limited (429)'),
	server:    _('Server error (5xx)'),
	transport: _('Transport error')
};

const PROV_RECOMMEND = {
	dns:       _('The provider tampers with DNS — Secure DNS (MultiDNS/DoH) usually fixes it'),
	rule:      _('Create a rule on the Service rules page'),
	strategy:  _('The provider cuts the path (DPI) — pick a working Zapret/ByeDPI strategy (Strategy Lab)'),
	node:      _('Blocked on the remote side (geo) — a node in a supported region fixes it'),
	node_both: _('Cut on both sides — a node in a supported region; the path to it may also need a working strategy'),
	node_exit: _('The service refuses this exit region — switch to another node (full check: the Service rules page, the Google AI row)'),
	main_path: _('The Main node is not serving this site — check the node'),
	anomaly:   _('Anomaly: RU services must open directly — check RU-protect / the internet'),
	config_broken: _('Bare paths work but the configured path does not — check the rule target or run the Strategy Lab'),
	ai_full:   _('Pages open, but the model request can still be refused by the exit region/IP — run the full check with the "Check" button on the Google AI row (Service rules).'),
	none:      _('—')
};

/* Honest scope notes (R4): an HTTP probe cannot see UDP voice calls
 * or streaming quality — say so instead of implying a verdict. */
const PROV_SVC_NOTES = {
	telegram: _('Voice calls (UDP) are not measured by an HTTP probe.'),
	whatsapp: _('Voice calls (UDP) are not measured by an HTTP probe.'),
	twitch:   _('Page probe only — streaming quality is not measured.')
};
/* TSPU watchlist notes are VERDICT-AWARE (see wizard ч.Ф8 notes). */
const PROV_DPI_NOTES = {
	strategy: _('TSPU watchlist (dpi-detect): the provider is confirmed cutting this resource — a Zapret/ByeDPI strategy is the candidate fix.'),
	open:     _('TSPU watchlist (dpi-detect): the upstream list flags this domain, but it opens fine here — this provider is not cutting it.'),
	config:   _('TSPU watchlist (dpi-detect): the upstream list flags this domain, and bare paths work here — the configured path itself is failing: check the rule target or the strategy.'),
	other:    _('TSPU watchlist (dpi-detect): the upstream list reports confirmed provider cuts — see the measured verdict of this row.')
};
function dpiDetectNote(v) {
	if (v === 'needs_strategy') return PROV_DPI_NOTES.strategy;
	if (v === 'opens_direct' || v === 'works_live') return PROV_DPI_NOTES.open;
	if (v === 'config_broken') return PROV_DPI_NOTES.config;
	return PROV_DPI_NOTES.other;
}

function probeCell(p) {
	if (p == null)
		return E('span', { 'class': 'hpui-b-grey hpui-badge' }, [ _('n/a') ]);
	const title = ((p.tsec != null) ? (String(p.tsec) + ' s') : '') +
		(p.kind ? (' · ' + p.kind) : '');
	const slowHint = p.slow ? (' ' + _('slow %s s').format(String(p.tsec || '?'))) : '';
	if (p.ok) {
		/* Ф6.1: путь открыт — но приложение не отдало контент (challenge/5xx):
		 * жёлтый честный бейдж вместо зелёного «работает». */
		if (p.waf === 'waf_challenge')
			return E('span', { title: title }, [ E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('WAF challenge') ]) ]);
		if (p.waf === 'waf_rate_limit')
			return E('span', { title: title }, [ E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('Rate limited (429)') ]) ]);
		if (p.app_state === 'server_error')
			return E('span', { title: title }, [ E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ '✓ ' + _('Server error (5xx)') + ' (' + (p.code || '') + ')' ]) ]);
		return E('span', { title: title }, [ E('span', { 'class': 'hpui-badge hpui-b-green' }, [ '✓ ' + (p.code || '') ]), slowHint ]);
	}
	const why = p.geo_refused ? _('geo-refused') : (PROV_KINDS[p.kind] || (p.kind || 'fail'));
	return E('span', { 'class': 'hpui-badge hpui-b-red' }, [ '✗ ' + why + ' (' + (p.code || '000') + ')' ]);
}

function buildProviderSection() {
	const provState = { scanSig: null };
	const scanBanner = E('div', { 'class': 'hpui-banner', style: 'display:none' });
	const scanResult = E('div', {});
	const customHosts = E('input', {
		type: 'text', 'class': 'cbi-input-text',
		placeholder: _('extra hosts: example.com, 1.2.3.4 (optional)')
	});
	const startBtn = E('button', {
		'class': 'hpui-btn hpui-btn-primary', type: 'button'
	}, [ _('Start diagnostics') ]);
	startBtn.addEventListener('click', function() {
		startBtn.disabled = true;
		callScanStart(String(customHosts.value || '').trim()).then(function(r) {
			if (!r || r.result === false)
				ui.addNotification(null, E('p', {}, _('Scan failed to start: ') + ((r && r.error) || '')), 'error');
			return pollScan();
		}).finally(function() { startBtn.disabled = false; });
	});

	const dpiStatus = E('span', { style: 'opacity:.75' }, [ _('not loaded') ]);
	const dpiBtn = E('button', {
		'class': 'hpui-btn hpui-btn-primary', type: 'button'
	}, [ _('Update TSPU list') ]);
	dpiBtn.addEventListener('click', function() {
		dpiBtn.disabled = true;
		callDpiUpdate().then(function(r) {
			if (!r || r.result === false)
				ui.addNotification(null, E('p', {}, _('List update failed: ') + ((r && r.error) || '')), 'error');
			return pollScan();
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
		if (sig === provState.scanSig)
			return;
		provState.scanSig = sig;
		scanResult.innerHTML = '';
		if (!result || !result.hosts || !result.hosts.length) {
			scanResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('No scan results yet — press "Start diagnostics".') ]));
			return;
		}
		const cards = E('div', { 'class': 'hpui-cards' });
		/* Recount client-side with the rule-aware mapping so the cards
		 * always agree with the table below. */
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
				[ _('The diagnostic inbounds are unavailable (the core is off or in "Direct" mode) — only a partial picture is possible.') ]));

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
				? E('span', { 'class': 'hpui-badge hpui-b-red' }, [ _('poisoned') ])
				: (r.dns_differs
					? E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('differs') ])
					: E('span', { style: 'opacity:.6' }, [ _('same') ]));
			/* What already covers this resource (proxy_ru_rule by source). */
			const rule = rules[r.svc] || null;
			const ruleCell = r.svc === 'dpi_detect'
				? E('span', { style: 'opacity:.55' }, [ _('diagnostic seed') ])
				: (rule
					? (rule.enabled
						? E('span', { 'class': 'hpui-badge hpui-b-blue' }, [ '→ ' + nodeText(rule.node) ])
						: E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ _('disabled') + ' (→ ' + nodeText(rule.node) + ')' ]))
					: E('span', { style: 'opacity:.55' }, [ _('no rule') ]));
			const ev = effVerdict(r, rule);
			let rec = (r.recommend && PROV_RECOMMEND[r.recommend]) ? PROV_RECOMMEND[r.recommend] : '—';
		/* A rule already covers a "needs proxy" resource — say so. */
		if (r.verdict === 'needs_proxy' && rule)
			rec = _('Rule configured (→ %s) — the resource is covered by it.').format(nodeText(rule.node));
		if (r.verdict === 'needs_strategy' && rule && (rule.node === 'zapret-out' || rule.node === 'byedpi-out'))
				rec = _('The rule already leads to %s — run the Strategy Lab: the current strategy may not handle this resource.').format(nodeText(rule.node));
			/* google_ai (C2): the page shell opens everywhere. */
			if (r.svc === 'google_ai' && (ev === 'works_live' || (r.verdict === 'opens_direct' && !rule)))
				rec = (rule && rule.enabled)
					? _('The page opens; the model goes through the configured node (→ %s). If the model refuses — check other nodes (the button in the Google AI check result on the Service rules page).').format(nodeText(rule.node))
					: _('The page opens; the model goes through the configured routing. If the model refuses — check other nodes or run the full check on the Service rules page.');
			/* opens_direct without a rule: mention the mass-list coverage. */
			if (ev === 'opens_direct' && r.svc !== 'ru_control' && r.svc !== 'dpi_detect') {
				const mass = (rules['russia-inside'] && rules['russia-inside'].enabled) ? _('Russia Inside')
					: ((rules['refilter'] && rules['refilter'].enabled) ? _('Re-filter') : null);
				if (mass)
					rec = _('Covered by the mass list (%s) — it opens via the main node; a rule here overrides the list.').format(mass);
			}
			const hostCell = E('div', {}, [ E('span', { style: 'font-weight:600' }, [ String(r.host) ]) ]);
			const svcNote = (r.svc === 'dpi_detect') ? dpiDetectNote(ev) : PROV_SVC_NOTES[r.svc];
			if (svcNote) {
				const note = E('div', { 'class': 'wiz-note', style: 'margin:0' }, [ svcNote ]);
				hostCell.appendChild(note);
			}
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

	function pollScan() {
		return Promise.all([
			L.resolveDefault(callScanStatus(), {}),
			L.resolveDefault(callPresetList(), {})
		]).then(function(data) {
			const scan = data[0] || {};
			updateDpiStatus(scan);
			renderScan(scan.status, scan.result, (data[1] && data[1].rules) || {});
		});
	}
	poll.add(pollScan, hp.pollSec(4));
	pollScan();

	return {
		el: sectionCard('sensors', _('Provider'), 'diag-provider', [
			E('p', { 'class': 'hpui-hint' },
				[ _('Checks a set of test services (YouTube, Discord, Telegram, WhatsApp, Google AI, OpenAI, Claude, Twitch…) through your real paths. The VERDICT speaks about your CONFIGURED routing (rules, learned lists and Zapret/ByeDPI desync) — the way LAN clients are actually served; the Direct column is reference: it shows whether the resource could open with no VPN at all. A response whose redirect chain is reset mid-way is not a success, and a 200 with an application-level refusal (geo, Gemini "something went wrong") is not either. When a refusal is about the remote region rather than the local provider, the verdict says so (geo-block) — a routing strategy cannot fix a region refusal, a node with a supported region can. RU services (rutube, gosuslugi) are control hosts — they must always open directly. The Cause line under the verdict explains WHY the resource fails (provider DPI, origin geo/WAF, DNS tampering, own rules) with a confidence level — hover it for the measured evidence.') ]),
			E('div', { 'class': 'diag-row' }, [ customHosts, startBtn ]),
			E('div', { 'class': 'diag-row' }, [
				E('span', { 'class': 'wiz-note', style: 'margin:0' },
					[ _('TSPU watchlist (dpi-detect):'), ' ', dpiStatus ]),
				dpiBtn
			]),
			scanBanner,
			scanResult
		]),
		run: function() { return pollScan(); }
	};
}

/* ── Ф6.3 Service Profiles: проверяется СЕРВИС, а не главная страница
 * (аудит 62/74). Батарея компонентов одного профиля через LIVE-путь;
 * классификация — Diagnostic Core на сервере, причины — та же таксономия
 * Ф6.1. Один результат в одном месте. ─────────────────────────────────── */

const callProfileRun = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_service_profile_run',
	params: [ 'profile' ],
	expect: { '': {} }
});

const callProfileStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_service_profile_status',
	expect: { '': {} }
});

/* Ф6.2 Discovery Engine: пассивный снимок обнаружения (без проб). */
const callDiscovery = rpc.declare({
	object: 'luci.ravnex',
	method: 'discovery_snapshot',
	expect: { '': {} }
});

const PROFILE_STATE = {
	working:  [ 'hpui-b-green', '✓ ' ],
	degraded: [ 'hpui-b-amber', '~ ' ],
	unusable: [ 'hpui-b-amber', '~ ' ],
	refused:  [ 'hpui-b-red',   '✗ ' ],
	broken:   [ 'hpui-b-red',   '✗ ' ],
	unprobed: [ 'hpui-b-grey',  '' ]
};

function buildProfilesSection() {
	const profState = { sig: null };
	const profBanner = E('div', { 'class': 'hpui-banner', style: 'display:none' });
	const profResult = E('div', {});

	const sel = E('select', { 'class': 'cbi-input-select', style: 'min-width:14em' }, [
		E('option', { value: 'all' }, [ _('All profiles') ]),
		E('option', { value: 'youtube' }, [ 'YouTube' ]),
		E('option', { value: 'discord' }, [ 'Discord' ]),
		E('option', { value: 'telegram' }, [ 'Telegram' ]),
		E('option', { value: 'whatsapp' }, [ 'WhatsApp' ]),
		E('option', { value: 'games' }, [ _('Games and launchers') ])
	]);
	const runBtn = E('button', {
		'class': 'hpui-btn hpui-btn-primary', type: 'button'
	}, [ _('Run check') ]);
	runBtn.addEventListener('click', function() {
		runBtn.disabled = true;
		callProfileRun(String(sel.value || 'all')).then(function(r) {
			if (!r || r.result === false)
				ui.addNotification(null, E('p', {}, _('Check failed to start: ') + ((r && r.error) || '')), 'error');
			return pollProfiles();
		}).finally(function() { runBtn.disabled = false; });
	});

	function renderProfiles(status, result) {
		profBanner.style.display = (status && status.running) ? 'block' : 'none';
		if (status && status.running) {
			profBanner.textContent = _('Checking %d of %d…').format(status.done || 0, status.total || 0) +
				(status.current ? (' ' + status.current) : '');
			return;
		}
		const sig = result ? ('' + (result.ts || 0)) : 'none';
		if (sig === profState.sig)
			return;
		profState.sig = sig;
		profResult.innerHTML = '';
		if (!result || !result.components || !result.components.length) {
			profResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('No profile results yet — press "Run check".') ]));
			return;
		}
		/* Сводные карточки — те же состояния, что в таблице. */
		const s = result.summary || {};
		const cards = E('div', { 'class': 'hpui-cards' });
		const mk = (num, cap, cls) => E('div', { 'class': 'hpui-card' }, [
			E('div', { 'class': 'hpui-num ' + (cls || '') }, [ String(num) ]),
			E('div', { 'class': 'hpui-cap' }, [ cap ])
		]);
		cards.appendChild(mk(s.working || 0, _('components work'), 'hpui-c-green'));
		cards.appendChild(mk(s.degraded || 0, _('degraded (path is open)'), 'hpui-c-amber'));
		cards.appendChild(mk(s.refused || 0, _('refused by the origin'), 'hpui-c-red'));
		cards.appendChild(mk(s.broken || 0, _('not delivered'), 'hpui-c-red'));
		cards.appendChild(mk(s.unprobed || 0, _('not probed'), ''));
		profResult.appendChild(cards);

		let lastProfile = null;
		const tbody = E('tbody', {});
		for (let i in result.components) {
			const r = result.components[i];
			if (r.profile !== lastProfile) {
				lastProfile = r.profile;
				tbody.appendChild(E('tr', { 'class': 'hpui-group' }, [
					E('td', { colspan: '3', style: 'font-weight:600; opacity:.85' },
						[ String(r.profile || '') ])
				]));
			}
			const spec = PROFILE_STATE[r.state] || PROFILE_STATE.unprobed;
			const badge = E('span', { 'class': 'hpui-badge ' + spec[0] },
				[ spec[1] + (r.state === 'working' ? _('works') :
					r.state === 'degraded' ? _('degraded') :
					r.state === 'unusable' ? _('unusable') :
					r.state === 'refused' ? _('refused') :
					r.state === 'broken' ? _('broken') : _('not probed')) ]);
			const level = (r.level) ? E('div', { 'class': 'wiz-note', style: 'margin:0' },
				[ _('Video quality: %s (%s)').format(r.level, r.plays || '') +
					(r.speed_bps ? (' · ' + Math.round(r.speed_bps / 125) + ' kbit/s') : '') ]) : null;
			const cl = causeLine(r);
			const main = E('div', {}, [ badge ]);
			if (level) main.appendChild(level);
			if (cl) main.appendChild(cl);
			tbody.appendChild(E('tr', {}, [
				E('td', { style: 'font-weight:600' }, [ String(r.label || r.id) ]),
				E('td', {}, [ main ]),
				E('td', { 'class': 'wiz-note', style: 'margin:0' },
					[ String(r.note || '') + ((r.code && r.code !== '000') ? (' · HTTP ' + r.code) : '') ])
			]));
		}
		const wrap = E('div', { 'class': 'hpui-wrap' });
		wrap.appendChild(E('table', { 'class': 'hpui-table' }, [
			E('thead', {}, E('tr', {}, [
				E('th', {}, [ _('Component') ]),
				E('th', {}, [ _('Verdict') ]),
				E('th', {}, [ _('Details') ])
			])), tbody
		]));
		profResult.appendChild(wrap);
		profResult.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Battery from %s · probes: %s (the base battery stays within the Keenetic probe budget; the differential of a failing component adds up to two more).')
				.format(new Date(Number(result.ts) * 1000).toLocaleString(), String(result.probes_used || 0)) ]));
	}

	function pollProfiles() {
		return L.resolveDefault(callProfileStatus(), {}).then(function(d) {
			renderProfiles(d.status, d.result);
		});
	}
	poll.add(pollProfiles, hp.pollSec(4));
	pollProfiles();

	return {
		el: sectionCard('trend', _('Service profiles'), 'diag-profiles', [
			E('p', { 'class': 'hpui-hint' },
				[ _('Checks the SERVICE, not the front page: YouTube (web/API/CDN/real video stream/QUIC), Discord (web/API/gateway WebSocket/CDN/Voice UDP/STUN/stability), Telegram (web/MTProto datacenters/calls), WhatsApp (web client/calls), games and launchers. The video level is judged bitrate-relative — from 360p to 4K — not by a fixed speed bar. The QUIC component is passive observation (the Discovery engine); active HTTP/3 probing stays off. Voice calls ride UDP relays that no tool on this router can probe — they are reported as not-probed, never as passed. Not-probed is never reported as passed.') ]),
			E('div', { 'class': 'diag-row' }, [ sel, runBtn ]),
			profBanner,
			profResult
		]),
		run: function() { return pollProfiles(); }
	};
}

/* ── Ф6.2 Discovery Engine: пассивный снимок обнаружения — conntrack
 * (TCP+UDP, оригинальный tuple, IPv4/IPv6 явно), Clash-соединения, SNI,
 * QUIC/STUN классификация, словарь IP↔DNS. Слепые зоны названы честно. ── */

function buildDiscoverySection() {
	const discResult = E('div', {});
	const discBtn = E('button', {
		'class': 'hpui-btn hpui-btn-primary', type: 'button'
	}, [ _('Take snapshot') ]);
	discBtn.addEventListener('click', function() {
		discBtn.disabled = true;
		discResult.innerHTML = '';
		discResult.appendChild(E('p', { 'class': 'hpui-hint' }, [ _('Taking a passive snapshot…') ]));
		callDiscovery().then(function(r) {
			renderDiscovery(r && r.snapshot);
		}).catch(function() {
			discResult.innerHTML = '';
			discResult.appendChild(E('p', { 'class': 'diag-fail' },
				[ _('Snapshot failed — the Discovery engine is unavailable.') ]));
		}).finally(function() { discBtn.disabled = false; });
	});

	function renderDiscovery(snap) {
		discResult.innerHTML = '';
		if (!snap || !snap.counts) {
			discResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('No snapshot yet — press "Take snapshot".') ]));
			return;
		}
		const c = snap.counts;
		discResult.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:0 0 .4em' },
			[ _('Flows: %s (TCP %s · UDP %s · QUIC %s · STUN %s · other UDP %s) · IPv4 %s · IPv6 %s · LAN/self %s')
				.format(String(c.flows || 0), String(c.tcp || 0), String(c.udp || 0),
					String(c.udp_quic || 0), String(c.udp_stun || 0), String(c.udp_other || 0),
					String(c.v4 || 0), String(c.v6 || 0), String(c.local || 0)) ]));
		if (snap.clash)
			discResult.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:0 0 .4em' },
				[ _('Clash connections: %s (UDP %s) · SNI hosts (tail): %s · IP↔DNS pairs: %s')
					.format(String(snap.clash.conns || 0), String(snap.clash.udp || 0),
						String((snap.sni || []).length), String(((snap.maps || {}).clash_pairs || 0) + ((snap.maps || {}).state_pairs || 0))) ]));
		const top = snap.top || [];
		if (top.length) {
			const tbody = E('tbody', {});
			for (let i in top) {
				const f = top[i];
				tbody.appendChild(E('tr', {}, [
					E('td', { style: 'font-family:monospace' }, [ String(f.ip) ]),
					E('td', {}, [ f.host ? String(f.host) : E('span', { style: 'opacity:.5' }, [ _('—') ]) ]),
					E('td', {}, [ (f.v6 ? 'IPv6 ' : 'IPv4 ') + String(f.proto) +
						(f.udp_kind && f.udp_kind !== 'other' ? (' · ' + f.udp_kind) : '') ]),
					E('td', {}, [ String(f.dport || '') ]),
					E('td', {}, [ String(f.hits || 0) ])
				]));
			}
			const wrap = E('div', { 'class': 'hpui-wrap' });
			wrap.appendChild(E('table', { 'class': 'hpui-table' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, [ _('Destination') ]),
					E('th', {}, [ _('Host (IP↔DNS)') ]),
					E('th', {}, [ _('Transport') ]),
					E('th', {}, [ _('Port') ]),
					E('th', {}, [ _('Flows') ])
				])), tbody
			]));
			discResult.appendChild(wrap);
		} else {
			discResult.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('No public destinations in this snapshot — LAN traffic only, or conntrack is unavailable.') ]));
		}
		const sni = snap.sni || [];
		if (sni.length)
			discResult.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:.4em 0 0' },
				[ _('Recent SNI: %s').format(sni.join(', ')) ]));
		const bz = snap.blind_zones || [];
		if (bz.length) {
			const ul = E('ul', { 'class': 'wiz-note', style: 'margin:.4em 0 0 1.2em' });
			for (let b in bz)
				ul.appendChild(E('li', {}, [ String(bz[b]) ]));
			discResult.appendChild(ul);
		}
		discResult.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Passive snapshot from %s · zero probes spent · budgets: conntrack ≤ %s lines, Clash API %s s, SNI tail %s.')
				.format(new Date(Number(snap.ts) * 1000).toLocaleString(),
					String((snap.budgets || {}).conntrack_lines || ''),
					String((snap.budgets || {}).clash_timeout_s || ''),
					String((snap.budgets || {}).sni_tail || '')) ]));
	}

	return {
		el: sectionCard('monitor', _('Discovery'), 'diag-discovery', [
			E('p', { 'class': 'hpui-hint' },
				[ _('What the router SEES right now: live flows (conntrack, TCP and UDP — including QUIC and STUN classes, IPv6 explicitly), Clash connections with hostnames, recent TLS SNI names, and the IP↔DNS mapping. This is the shared source the automation engine learns from and the Service profiles use for passive QUIC observation. Blind zones are listed honestly below the snapshot.') ]),
			E('div', { 'class': 'diag-row' }, [ discBtn ]),
			discResult
		]),
		run: function() { return Promise.resolve(); }
	};
}

/* ── Ф6.5 Service Path Optimizer: план цепочки Service→Route→Engine→
 * Strategy→Transport→Exit для КАЖДОГО сервиса независимо (аудит 70).
 * План читает ТОЛЬКО измеренные факты: вердикты Лаборатории стратегий
 * (Ф6.4), сводки батарей профилей (Ф6.3), правила и режим. Применение —
 * существующий автоподбор с ОБЯЗАТЕЛЬНЫМ авто-rollback при провале живой
 * проверки (аудит 78); best_available применяется только вручную
 * (аудит 92); матрица движков учитывается ДО подбора (аудит 93). Один
 * результат в одном месте. ───────────────────────────────────────────── */

const callOptimizerPlan = rpc.declare({
	object: 'luci.ravnex',
	method: 'service_optimizer_plan',
	expect: { '': {} }
});

const callPickStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_auto_pick_start',
	params: [ 'resource', 'mode', 'set_rule' ],
	expect: { '': {} }
});

const callPickStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_auto_pick_status',
	expect: { '': {} }
});

const OPT_VERDICT = {
	ok:           [ 'hpui-b-green', '✓ ' ],
	apply:        [ 'hpui-b-amber', '▶ ' ],
	manual_only:  [ 'hpui-b-amber', '✋ ' ],
	no_candidate: [ 'hpui-b-red',   '✗ ' ],
	via_node:     [ 'hpui-b-grey',  '⇄ ' ],
	no_lab:       [ 'hpui-b-grey',  '' ],
	unknown:      [ 'hpui-b-grey',  '' ]
};

function optVerdictLabel(v) {
	return v === 'ok' ? _('Served — no changes needed') :
		v === 'apply' ? _('Verified strategy ready to apply') :
		v === 'manual_only' ? _('Manual apply only (auto is forbidden)') :
		v === 'no_candidate' ? _('NO VIABLE STRATEGY') :
		v === 'via_node' ? _('Served via node rule — lab verdict not applicable') :
		v === 'no_lab' ? _('Not measured by the Strategy Lab') :
		_('—');
}

function optServiceLabel(k) {
	return k === 'youtube' ? 'YouTube' :
		k === 'discord' ? 'Discord' :
		k === 'telegram' ? 'Telegram' :
		k === 'whatsapp' ? 'WhatsApp' : String(k);
}

function buildOptimizerSection() {
	const state = { plan: null, sig: null };
	const pickBanner = E('div', { 'class': 'hpui-banner', style: 'display:none' });
	const pickResult = E('div', {});
	const tableWrap = E('div', {});
	const pickState = { running: false };

	function chainLine(svc) {
		const c = svc.chain;
		if (c != null && c.route != null)
			return (c.route || '') + (c.engine ? (' · движок: ' + c.engine) : '') +
				(c.strategy ? (' · «' + c.strategy + '»') : '');
		return null;
	}

	function renderPlan(d) {
		const plan = (d && d.services) ? d.services : null;
		if (plan == null)
			return;
		state.plan = plan;
		const sig = JSON.stringify(Object.keys(plan).sort().map(function(k) {
			return [ k, plan[k].verdict, plan[k].chain ? plan[k].chain.strategy : null,
				plan[k].rule ? plan[k].rule.node : null ];
		}));
		if (sig === state.sig)
			return;
		state.sig = sig;
		tableWrap.innerHTML = '';
		const tbody = E('tbody', {});
		for (const key of [ 'youtube', 'discord', 'telegram', 'whatsapp' ]) {
			const svc = plan[key];
			if (svc == null)
				continue;
			const spec = OPT_VERDICT[svc.verdict] || OPT_VERDICT.unknown;
			const badge = E('span', { 'class': 'hpui-badge ' + spec[0] },
				[ spec[1] + optVerdictLabel(svc.verdict) ]);
			const cl = chainLine(svc);
			const notes = [];
			for (let i in (svc.reasons || []))
				notes.push(String(svc.reasons[i]));
			for (let i in (svc.notes || []))
				notes.push(String(svc.notes[i]));
			const detail = notes.length ?
				E('div', { 'class': 'wiz-note', style: 'margin:0' },
					[ notes.join(' · ') ]) : null;
			const main = E('div', {}, [ badge ]);
			if (detail) main.appendChild(detail);
			/* Действие: автоподбор — только для сервисов с фаззинг-корпусом
			 * и разрешённым автоподбором; WhatsApp лаборатория не измеряет
			 * (честно), у Telegram автоподбор УБРАН решением ч.233
			 * (RPC wizard_auto_pick_start отклоняет tg) — кнопка ч.234
			 * скрыта: она предлагала то, что RPC отклоняет. */
			let act = null;
			if (key !== 'whatsapp' && key !== 'telegram') {
				act = E('button', {
					'class': 'hpui-btn hpui-btn-primary hpui-btn-sm', type: 'button'
				}, [ _('Auto-pick') ]);
				act.addEventListener('click', function() {
					act.disabled = true;
					callPickStart(key, 'quick', '1').then(function(r) {
						if (!r || r.result === false)
							ui.addNotification(null, E('p', {},
								_('Auto-pick failed to start: ') + ((r && r.error) || '')), 'error');
						pickState.running = true;
						return pollPick();
					}).finally(function() { act.disabled = false; });
				});
			}
			tbody.appendChild(E('tr', {}, [
				E('td', { style: 'font-weight:600' }, [ optServiceLabel(key) ]),
				E('td', {}, [ main ]),
				E('td', { 'class': 'wiz-note', style: 'margin:0' }, [ cl || _('—') ]),
				E('td', {}, [ act || E('span', { style: 'opacity:.5' }, [ _('—') ]) ])
			]));
		}
		const wrap = E('div', { 'class': 'hpui-wrap' });
		wrap.appendChild(E('table', { 'class': 'hpui-table' }, [
			E('thead', {}, E('tr', {}, [
				E('th', {}, [ _('Popular service') ]),
				E('th', {}, [ _('Verdict') ]),
				E('th', {}, [ _('Chain (route · engine · strategy)') ]),
				E('th', {}, [ _('Action') ])
			])), tbody
		]));
		tableWrap.appendChild(wrap);
		if (d && d.lab_ts)
			tableWrap.appendChild(E('p', { 'class': 'hpui-hint' },
				[ _('Lab verdicts from %s · profile battery from %s · plan is read-only: applying runs the auto-pick with a mandatory rollback on a failed live check.')
					.format(d.lab_ts ? new Date(Number(d.lab_ts) * 1000).toLocaleString() : '—',
						d.profile_ts ? new Date(Number(d.profile_ts) * 1000).toLocaleString() : '—') ]));
	}

	function renderPick(st) {
		pickBanner.style.display = (st && st.running) ? 'block' : 'none';
		if (st && st.running) {
			pickBanner.textContent = _('Auto-pick: %s…').format(String(st.stage || ''));
			return;
		}
		if (!st || st.stage == null || st.stage === 'started') {
			pickResult.innerHTML = '';
			return;
		}
		const lines = [];
		if (st.error != null && String(st.error).length)
			lines.push(_('Error: %s').format(String(st.error)));
		if (st.verdict != null)
			lines.push(_('Verdict: %s').format(optVerdictLabel(String(st.verdict))));
		if (st.chosen != null && st.chosen.name != null && String(st.chosen.name).length)
			lines.push(_('Strategy: %s').format(String(st.chosen.name)));
		if (st.verify != null)
			lines.push(_('Live check: %s · %s s · deep %s/%s').format(
				st.verify.ok ? _('works') : _('failed'),
				String(st.verify.tsec || '?'),
				String(st.verify.deep_ok != null ? st.verify.deep_ok : '?'),
				String(st.verify.deep_total != null ? st.verify.deep_total : '?')));
		if (st.rolled_back === true)
			lines.push(_('Rolled back automatically — the previous state is restored.'));
		else if (st.rolled_back === false)
			lines.push(_('NOT rolled back — use Restore (the snapshot is kept).'));
		for (let i in (st.notes || []))
			lines.push(String(st.notes[i]));
		pickResult.innerHTML = '';
		if (!lines.length)
			return;
		const ul = E('ul', { 'class': 'wiz-note', style: 'margin:.4em 0 0 1.2em' });
		for (let i in lines)
			ul.appendChild(E('li', {}, [ lines[i] ]));
		pickResult.appendChild(ul);
	}

	function pollPick() {
		return L.resolveDefault(callPickStatus(), {}).then(function(d) {
			const st = d && d.status;
			pickState.running = !!(st && st.running);
			renderPick(st);
			return st;
		});
	}

	function pollPlan() {
		return L.resolveDefault(callOptimizerPlan(), {}).then(function(d) {
			renderPlan(d);
		});
	}

	poll.add(pollPlan, hp.pollSec(8));
	poll.add(pollPick, hp.pollSec(4));
	pollPlan();
	pollPick();

	return {
		el: sectionCard('crosshair', _('Route optimizer'), 'diag-optimizer', [
			E('p', { 'class': 'hpui-hint' },
				[ _('Chooses the full chain for EACH popular service independently: route rule → engine (Zapret/ByeDPI/proxy) → strategy → transport → exit. The plan reads only measured facts — the Strategy Lab verdicts, the service profile batteries and your routing rules. An auto-pick applies a VERIFIED strategy with the rule set to Zapret and ROLLS BACK AUTOMATICALLY if the live check fails afterwards; a strategy that only passed the handshake is offered manually with a warning; when nothing works, the plan says WHAT exactly fails. WhatsApp is measured by its profile battery and the provider scan only — the Strategy Lab has no fuzz corpus for it.') ]),
			tableWrap,
			pickBanner,
			pickResult
		]),
		run: function() { return Promise.all([ pollPlan(), pollPick() ]); }
	};
}

/* ── DOM helpers ──────────────────────────────────────────────────────── */

function statusBadge(ok, text) {
	/* ucode serialises booleans as integers 0/1 — use loose checks so both
	   JS booleans and integers work. null/undefined → "uncertain" (amber ?).
	   Rendered as a badge chip — same look as the Automation tables. */
	const isOk   = !!ok;
	const isWarn = ok == null;    /* catches null AND undefined */
	const icon   = isOk ? '✓ ' : isWarn ? '? ' : '✗ ';
	const cls    = isOk ? 'hpui-b-green' : isWarn ? 'hpui-b-amber' : 'hpui-b-red';
	const label  = text || (isOk ? _('OK') : isWarn ? '?' : _('FAIL'));
	return E('span', { 'class': 'hpui-badge ' + cls }, icon + label);
}

function row(label, value) {
	return E('div', { 'class': 'diag-row' }, [
		E('span', { 'class': 'diag-label' }, label),
		E('span', {}, value)
	]);
}

function pre(text) {
	return E('div', { 'class': 'hpui-pre' }, text || _('(empty)'));
}

function sectionCard(icon, title, id, rows) {
	return E('div', { 'class': 'hpui-panel diag-section' }, [
		E('h4', { 'class': 'hpui-h4' }, [ hp.icon(icon), title ]),
		E('div', { 'id': id }, rows)
	]);
}

function spinner(el, label) {
	dom.content(el, E('em', { 'class': 'diag-gray' }, label || _('Testing…')));
}

/* ── Section builders ─────────────────────────────────────────────────── */

function buildConnectivitySection(view, coreType) {
	const items = [];   /* manual checks; the section's run() fires them together */

	function siteRow(label, site) {
		const resultEl = E('strong', { 'class': 'diag-gray' }, _('unchecked'));
		function run() {
			dom.content(resultEl, E('em', { 'class': 'diag-gray' }, _('Testing…')));
			return L.resolveDefault(callConnCheck(site), {}).then(function(ret) {
				dom.content(resultEl, statusBadge(!!ret.result, ret.result ? _('passed') : _('failed')));
			});
		}
		items.push(run);
		const btn = E('button', { 'class': 'hpui-btn hpui-btn-primary',
			'click': ui.createHandlerFn(view, run) }, [ _('Check') ]);
		return E('div', { 'class': 'diag-row' }, [ E('span', { 'class': 'diag-label' }, label), btn, resultEl ]);
	}

	/* Route explanation (ч.69): why does a host route the way it does. */
	function routeExplainRow() {
		const input = E('input', {
			'type': 'text', 'class': 'cbi-input-text',
			'placeholder': _('example.com or 1.2.3.4'),
			'style': 'min-width:220px; flex:0 1 260px'
		});
		const resultEl = E('div', { 'class': 'diag-gray', 'style': 'font-size:.88em; margin-top:.3em' }, '');
		function run() {
			const h = String(input.value || '').trim().toLowerCase();
			if (!h) return;
			dom.content(resultEl, E('em', { 'class': 'diag-gray' }, _('Tracing…')));
			return L.resolveDefault(callRouteExplain(h), {}).then(function(ret) {
				if (!ret || ret.error) {
					dom.content(resultEl, E('span', { 'class': 'diag-fail' }, (ret && ret.error) || _('RPC error')));
					return;
				}
				const parts = [];
				/* B6.5/B6.6: an unresolved remote ambiguity is shown as its own
				 * honest verdict (the backend's match text lists the ordered
				 * candidates; no outbound is claimed). A companion-confirmed
				 * candidate renders like a normal winning rule — its match
				 * text already marks it "вероятный победитель". */
				if (ret.remote && ret.remote.confirmed == null) {
					parts.push(E('div', { 'style': 'color:#d99a1b' }, [ ret.match || _('Remote lists in play — exact match unavailable locally.') ]));
				} else {
					const probable = !!(ret.remote && ret.remote.confirmed != null);
					parts.push(E('div', {}, [
						E('strong', {}, [ ret.outbound ? resolveTag(ret.outbound) : (ret.action || '?') ]),
						E('span', { 'class': 'diag-gray' }, ' ← ' + (ret.match || '') +
							(ret.rule_index ? (' · ' + (probable ? _('probable winning rule') : _('winning rule')) + ' #' + ret.rule_index) : '') +
							(ret.fallback ? ' · ' + _('default route (no rule matched)') : ''))
					]));
				}
				if (ret.chain)
					parts.push(E('div', { 'class': 'diag-gray' }, ret.chain));
				/* B6.6: the honest Master-protection verdict rides with the trace. */
				const cov = ret.coverage;
				if (cov && cov.status === 'protected_by_master')
					parts.push(E('div', { 'style': 'color:#3a9c5c' }, [ cov.note ]));
				else if (cov && cov.status === 'coverage_unknown')
					parts.push(E('div', { 'style': 'color:#d99a1b' }, [ cov.note ]));
				for (let t in (ret.trace || []))
					if (t.action === 'reject')
						parts.push(E('div', { 'style': 'color:#d99a1b' },
							_('rejects UDP/443 (QUIC escape)') + ' — ' + (t.match || '')));
				dom.content(resultEl, parts);
			});
		}
		const btn = E('button', { 'class': 'hpui-btn hpui-btn-primary',
			'click': ui.createHandlerFn(view, function() { input.value = input.value; return run(); }) }, [ _('Explain route') ]);
		input.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') run(); });
		const wrap = E('div', { 'class': 'diag-row', 'style': 'flex-wrap:wrap' },
			[ E('span', { 'class': 'diag-label' }, _('Route explanation')), input, btn, resultEl ]);
		resultEl.style.flexBasis = '100%';
		return wrap;
	}

	/* Exit IP / geo — only hiddify-core's Clash API reports it. */
	function ipRow(label, type) {
		const resultEl = E('strong', { 'class': 'diag-gray' }, _('unchecked'));
		function run() {
			dom.content(resultEl, E('em', { 'class': 'diag-gray' }, _('Testing…')));
			return L.resolveDefault(callIpInfo(), {}).then(function(ret) {
				if (ret.error) { dom.content(resultEl, E('span', { 'class': 'diag-fail' }, ret.error)); return; }
				const entry = ret[type];
				if (!entry || !entry.ip) { dom.content(resultEl, E('span', { 'class': 'diag-gray' }, _('No data'))); return; }
				const meta  = [entry.country, entry.org].filter(Boolean).join(', ');
				const delay = (entry.delay && entry.delay !== 65535) ? ' — ' + entry.delay + ' ms' : '';
				const node  = (type === 'proxy' && entry.node) ? resolveTag(entry.node) + ': ' : '';
				dom.content(resultEl, E('strong', { 'class': 'diag-ok' },
					node + entry.ip + (meta ? ' (' + meta + ')' : '') + delay));
			});
		}
		items.push(run);
		const btn = E('button', { 'class': 'hpui-btn hpui-btn-primary',
			'click': ui.createHandlerFn(view, run) }, [ _('Check') ]);
		return E('div', { 'class': 'diag-row' }, [ E('span', { 'class': 'diag-label' }, label), btn, resultEl ]);
	}

	/* Active node — live status (which node sing-box has selected), auto-updating;
	 * sing-box can't report exit IP, so this stands in for the IP rows. */
	/* Live active-node row. `tag` selects which outbound group to resolve:
	   'main-out' (default) → the main (TCP) node — the focused query follows the
	   group chain (incl. nested prefer-mode pools); 'main-udp-out' → the dedicated UDP node. */
	function activeNodeRow(labelText, tag) {
		const resultEl = E('span', { 'class': 'diag-gray' }, '—');
		poll.add(L.bind(function() {
			return L.resolveDefault(callActiveNode(tag || 'main-out'), {}).then(function(ret) {
				if (ret && !ret.error && ret.node) {
					const type  = ret.type ? ' (' + ret.type + ')' : '';
					/* Same 4-colour scheme as the status/client pages: 65535 ms is the
					   URLTest timeout sentinel (confirmed dead → red); >=3000 ms is
					   working-but-slow (orange); a real low latency is green; no delay
					   is unmeasured (gray, no number). */
					let cls, dStr = '';
					if (ret.delay === 65535) { cls = 'diag-fail'; dStr = ' — ' + _('timeout'); }
					else if (ret.delay >= 3000) { cls = 'diag-warn'; dStr = ' — ' + ret.delay + ' ms'; }
					else if (ret.delay) { cls = 'diag-ok'; dStr = ' — ' + ret.delay + ' ms'; }
					else cls = 'diag-gray';
					dom.content(resultEl, E('strong', { 'class': cls }, resolveTag(ret.node) + type + dStr));
				} else {
					dom.content(resultEl, E('span', { 'class': 'diag-gray' }, _('No active node')));
				}
			});
		}, this), hp.pollSec(5));
		return E('div', { 'class': 'diag-row' }, [ E('span', { 'class': 'diag-label' }, labelText), resultEl ]);
	}

	const rows = [
		routeExplainRow(),
		siteRow(_('Baidu'),     'baidu'),
		siteRow(_('Google'),    'google'),
		siteRow(_('YouTube'),   'youtube'),
		siteRow(_('Yandex'),    'yandex'),
		siteRow(_('Speedtest'), 'speedtest')
	];

	/* hiddify → exit-IP rows; sing-box → live Active Node (it can't report exit IP). */
	if (coreType === 'hiddify') {
		rows.push(ipRow(_('Direct IP'), 'direct'));
		rows.push(ipRow(_('Proxy IP'),  'proxy'));
	} else if (coreType === 'singbox') {
		rows.push(activeNodeRow(_('Active Node')));
	}

	/* Dedicated UDP node — only the modes that expose "Main UDP node" in the UI set it
	   (Global + the bypass_cn/bypass_ir reverse modes; proxy_banned_ru doesn't, and
	   'redirect' proxy mode has no UDP path). Show which node currently carries UDP. */
	const udpNode   = uci.get('homeproxy', 'config', 'main_udp_node');
	const proxyMode = uci.get('homeproxy', 'config', 'proxy_mode');
	if (udpNode && !['nil', 'same', ''].includes(udpNode) && proxyMode !== 'redirect')
		rows.push(activeNodeRow(_('Active UDP Node'), 'main-udp-out'));

	return {
		el: sectionCard('wifi', _('Connectivity'), 'diag-connectivity', rows),
		run: function() { return Promise.all(items.map(function(fn) { return fn(); })); }
	};
}

function buildCoreSection(view) {
	const resultsEl   = E('div', {});
	const restartMsgEl = E('span', { 'class': 'diag-gray', 'style': 'font-size:.9em' });

	function run() {
		spinner(resultsEl, _('Checking core…'));
		return L.resolveDefault(callCoreCheck(), {}).then(function(ret) {
			if (!ret || ret.error) {
				dom.content(resultsEl, E('span', { 'class': 'diag-fail' }, ret ? ret.error : _('RPC error')));
				return;
			}

			const portLines = (ret.listen_ports && ret.listen_ports.length)
				? ret.listen_ports.map(function(l) { return E('div', { 'class': 'diag-port-line' }, l); })
				: [ E('em', { 'class': 'diag-gray' }, _('none detected')) ];

			dom.content(resultsEl, [
				row(_('Hiddify-core'),    statusBadge(ret.hiddify_installed, ret.hiddify_installed ? _('installed') : _('not found'))),
				row(_('sing-box'),        statusBadge(ret.singbox_installed,  ret.singbox_installed  ? _('installed') : _('not found'))),
				row(_('ByeDPI'),          statusBadge(ret.byedpi_installed,   ret.byedpi_installed   ? _('installed') : _('not found'))),
				row(_('Zapret 2'),        statusBadge(ret.zapret_installed,   ret.zapret_installed   ? _('installed') : _('not found'))),
				row(_('mosdns'),          statusBadge(ret.mosdns_installed,  ret.mosdns_installed  ? _('installed') : _('not found'))),
				ret.binary ? row(_('Active binary'), E('code', {}, ret.binary)) : null,
				ret.version ? row(_('Version'), E('span', { 'class': 'hpui-pre', 'style': 'max-height:5em' }, ret.version)) : null,
				row(_('Running'),         statusBadge(ret.running, ret.running ? _('yes') + (ret.pid ? ' (PID ' + ret.pid + ')' : '') : _('no'))),
				ret.byedpi_installed ? row(_('ByeDPI running'), statusBadge(ret.byedpi_running, ret.byedpi_running ? _('yes') + (ret.byedpi_pid ? ' (PID ' + ret.byedpi_pid + ')' : '') : _('no'))) : null,
				ret.zapret_installed ? row(_('Zapret 2 running'), statusBadge(ret.zapret_running, ret.zapret_running ? _('yes') + (ret.zapret_pid ? ' (PID ' + ret.zapret_pid + ')' : '') : _('no'))) : null,
				ret.mosdns_installed ? row(_('mosdns running'), statusBadge(ret.mosdns_running, ret.mosdns_running ? _('yes') + (ret.mosdns_pid ? ' (PID ' + ret.mosdns_pid + ')' : '') : _('no'))) : null,
				row(_('Listening ports'), E('div', {}, portLines))
			].filter(Boolean));
		});
	}

	/* Ф1.1: bounded poll of one operation until completed/failed; the result
	 * badge is driven by the server-side verified flag, not by wishful
	 * thinking (audit 1.7: never report success before verification). */
	function pollOpResult(opId, el, doneText, after) {
		const deadline = Date.now() + 120000;
		const tick = function() {
			return L.resolveDefault(callOpStatus(opId), {}).then(function(st) {
				const op = st && st.op;
				if (!op) {
					dom.content(el, statusBadge(false, _('Operation status unavailable')));
					if (after) after();
					return;
				}
				if (op.status === 'completed' || op.status === 'failed') {
					const ok = (op.status === 'completed') && op.verified;
					dom.content(el, statusBadge(ok,
						ok ? doneText : ((op.detail || _('Apply failed')))));
					if (after) after();
					return;
				}
				if (Date.now() > deadline) {
					dom.content(el, statusBadge(false, _('The operation is still running — check the operation journal')));
					if (after) after();
					return;
				}
				window.setTimeout(tick, 2000);
			});
		};
		return tick();
	}

	function restart() {
		dom.content(restartMsgEl, E('em', { 'class': 'diag-gray' }, _('Applying configuration…')));
		return L.resolveDefault(callServiceRestart(), {}).then(function(ret) {
			if (ret && ret.op_id && ret.result !== false)
				return pollOpResult(ret.op_id, restartMsgEl, _('Service restarted'), run);
			if (ret && ret.busy && ret.op_id)
				/* Another apply holds the lock — attach to ITS result instead
				 * of a wishful success. */
				return pollOpResult(ret.op_id, restartMsgEl, _('Service restarted'), run);
			dom.content(restartMsgEl, statusBadge(false,
				_('Restart failed') + (ret && ret.error ? ' (' + ret.error + ')' : '')));
		});
	}

	return {
		el: sectionCard('cpu', _('Core & System'), 'diag-core', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'hpui-btn hpui-btn-primary',
					'click': ui.createHandlerFn(view, run)
				}, _('Check')),
				E('button', {
					'class': 'hpui-btn hpui-btn-danger',
					'click': ui.createHandlerFn(view, restart)
				}, _('Restart service')),
				restartMsgEl
			]),
			resultsEl
		]),
		run: run
	};
}

function buildConfigSection(view) {
	/* All three buttons share one results area below the row: whichever
	 * check runs last replaces the previous output there. */
	const resultsEl = E('div', {});

	function run() {
		spinner(resultsEl, _('Checking config…'));
		return L.resolveDefault(callConfigCheck(), { error: _('RPC error') }).then(function(ret) {
			if (!ret || ret.error) {
				dom.content(resultsEl, E('span', { 'class': 'diag-fail' }, ret ? ret.error : _('RPC error')));
				return;
			}

			dom.content(resultsEl, [
				row(_('Valid'),       statusBadge(ret.valid)),
				ret.size_bytes != null ? row(_('Size'), (ret.size_bytes / 1024).toFixed(1) + ' KB') : null,
				ret.stats ? row(_('Inbounds'),    String(ret.stats.inbounds)) : null,
				ret.stats ? row(_('Outbounds'),   String(ret.stats.outbounds)) : null,
				ret.stats ? row(_('Rules'),       String(ret.stats.rules)) : null,
				ret.stats ? row(_('DNS servers'), String(ret.stats.dns_servers)) : null,
				ret.check_output ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, _('Check output')),
					pre(ret.check_output)
				]) : null
			].filter(Boolean));
		});
	}

	function heal(repair) {
		dom.content(resultsEl, E('em', { 'class': 'diag-gray' },
			repair ? _('Verifying and repairing configuration…') : _('Verifying configuration…')));
		/* The arg crosses as a '1'/'0' STRING: rpcd's ucode plugin maps a
		 * string typehint to BLOBMSG_TYPE_STRING, and native-boolean typehints
		 * crash strict new rpcd at registration (GitHub issue #11). */
		return L.resolveDefault(callConfigHeal(repair ? '1' : '0'), { error: _('RPC error') })
			.then(function(ret) {
				if (!ret || ret.error) {
					dom.content(resultsEl, E('span', { 'class': 'diag-fail' }, ret ? ret.error : _('RPC error')));
					return;
				}

				const itemRow = function(item, cls) {
					return E('div', { 'class': cls }, '• ' + item);
				};

				dom.content(resultsEl, [
					row(_('Integrity'), statusBadge(ret.ok,
						ret.ok ? _('OK') : _('issues found'))),
					ret.repaired && ret.repaired.length ? E('div', {}, [
						E('div', { 'class': 'diag-label' }, _('Repaired')),
						ret.repaired.map(function(i) { return itemRow(i, 'diag-ok'); })
					]) : null,
					ret.issues && ret.issues.length ? E('div', {}, [
						E('div', { 'class': 'diag-label' }, _('Issues')),
						ret.issues.map(function(i) { return itemRow(i, 'diag-fail'); })
					]) : null,
					ret.warnings && ret.warnings.length ? E('div', {}, [
						E('div', { 'class': 'diag-label' }, _('Warnings')),
						ret.warnings.map(function(w) { return itemRow(w, 'diag-warn'); })
					]) : null,
					ret.ok ? E('div', { 'class': 'diag-ok' }, _('All critical configuration is intact')) : null,
					ret.checked && ret.checked.length ? E('div', {}, [
						E('div', { 'class': 'diag-label' }, _('Checked')),
						pre(ret.checked.join('\n'))
					]) : null,
					ret.service_restarted ? E('div', { 'class': 'diag-gray' }, _('Service restart initiated')) : null
				].filter(Boolean));
			});
	}

	return {
		el: sectionCard('hardrive', _('Configuration'), 'diag-config', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'hpui-btn hpui-btn-primary',
					'click': ui.createHandlerFn(view, run)
				}, _('Check')),
				E('button', {
					'class': 'hpui-btn hpui-btn-ghost',
					'click': ui.createHandlerFn(view, function() { return heal(false); }),
					'title': _('Verify critical configuration files and firewall includes')
				}, _('Verify Configuration')),
				E('button', {
					'class': 'hpui-btn hpui-btn-danger',
					'click': ui.createHandlerFn(view, function() { return heal(true); }),
					'title': _('Restore damaged critical configuration (firewall includes, app config)')
				}, _('Repair Configuration'))
			]),
			resultsEl
		]),
		run: run
	};
}

function buildDnsSection(view) {
	const resultsEl = E('div', {});

	const cardEl = sectionCard('globe', _('DNS Tests'), 'diag-dns', [
		E('div', { 'class': 'diag-row' }, [
			E('button', {
				'class': 'hpui-btn hpui-btn-primary',
				'click': ui.createHandlerFn(view, run)
			}, _('Test'))
		]),
		resultsEl
	]);
	cardEl.style.display = 'none';

	function run() {
		spinner(resultsEl, _('Testing DNS…'));
		return L.resolveDefault(callDnsRu(), {}).then(function(ret) {

			if (ret.skip) {
				cardEl.style.display = 'none';
				return;
			}
			cardEl.style.display = '';
			if (ret.error) {
				dom.content(resultsEl, E('span', { 'class': 'diag-fail' }, ret.error));
				return;
			}

			const regionDomain = ret.region_domain || '?';
			dom.content(resultsEl, [
				E('div', { 'style': 'font-weight:bold; margin:.4em 0 .2em' },
					(ret.region_label ? ret.region_label + ' ' : '') + _('DNS (direct)')),
				row(_('Server'), E('code', {}, ret.region_server || '?')),
				row(regionDomain, statusBadge(ret.region_ok,
					ret.region_ok ? _('Resolved') : _('No answer — check server address'))),
				ret.region_output ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, 'nslookup ' + regionDomain),
					pre(ret.region_output)
				]) : null,

				E('div', { 'style': 'font-weight:bold; margin:.8em 0 .2em' }, _('Secure DNS')),
				ret.secure_server ? row(_('Server'), E('code', {}, ret.secure_server)) : null,
				row(_('Bootstrap'), E('code', {}, ret.bootstrap || '?')),
				row('andrevi.ch', statusBadge(ret.secure_ok,
					ret.secure_ok ? _('Resolved via proxy') : _('No answer — check proxy and proxy list'))),
				ret.secure_output ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, 'nslookup andrevi.ch'),
					pre(ret.secure_output)
				]) : null
			].filter(Boolean));
		});
	}

	return { el: cardEl, run: run };
}

function buildMultidnsDnsSection(view) {
	const resultsEl = E('div', {});

	const cardEl = sectionCard('globe', _('MultiDNS DNS Tests'), 'diag-mdns-dns', [
		E('div', { 'class': 'diag-row' }, [
			E('button', {
				'class': 'hpui-btn hpui-btn-primary',
				'click': ui.createHandlerFn(view, run)
			}, _('Test'))
		]),
		resultsEl
	]);
	cardEl.style.display = 'none';

	function run() {
		spinner(resultsEl, _('Testing MultiDNS DNS…'));
		return L.resolveDefault(callDnsMultidns(), {}).then(function(ret) {
			if (!ret.enabled) {
				cardEl.style.display = 'none';
				return;
			}
			cardEl.style.display = '';

			dom.content(resultsEl, [
				E('div', { 'style': 'font-weight:bold; margin:.4em 0 .2em' }, _('mosdns')),
				row(_('Status'), statusBadge(ret.mosdns,
					ret.mosdns ? _('running — racing all pool servers') : _('not running'))),

				E('div', { 'style': 'font-weight:bold; margin:.8em 0 .2em' },
					_('Plain pool (Russia) — %s').format(ret.plain_port || '5453')),
				row('example.com', statusBadge(ret.plain_ok,
					ret.plain_ok ? (_('Resolved via fastest live server: ') + (ret.plain_ip || ''))
					             : _('No answer — mosdns may be down'))),
				ret.plain_output ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, 'nslookup -port=' + (ret.plain_port || '5453') + ' example.com 127.0.0.1'),
					pre(ret.plain_output)
				]) : null,

				E('div', { 'style': 'font-weight:bold; margin:.8em 0 .2em' },
					_('Secure pool — %s').format(ret.secure_port || '5454')),
				row('cloudflare.com', statusBadge(ret.secure_ok,
					ret.secure_ok ? (_('Resolved via fastest live server: ') + (ret.secure_ip || ''))
					              : _('No answer — mosdns may be down'))),
				ret.secure_output ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, 'nslookup -port=' + (ret.secure_port || '5454') + ' cloudflare.com 127.0.0.1'),
					pre(ret.secure_output)
				]) : null,

				ret.direct_output ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, _('Direct control (bypassing MultiDNS)')),
					pre(ret.direct_output)
				]) : null
			].filter(Boolean));
		});
	}

	return { el: cardEl, run: run };
}

function buildNftSection(view) {
	const resultsEl = E('div', {});

	function run() {
		spinner(resultsEl, _('Reading nftables…'));
		return L.resolveDefault(callNftables(), {}).then(function(ret) {
			if (ret.error) {
				dom.content(resultsEl, E('span', { 'class': 'diag-fail' }, ret.error));
				return;
			}

			dom.content(resultsEl, [
				row(_('Ravnex chains'), statusBadge(ret.nft_present,
				    ret.nft_present ? _('found') : _('not found — firewall rules may be missing'))),
				ret.nft_rules ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, _('Matched lines in fw4')),
					pre(ret.nft_rules)
				]) : null,
				ret.udp_tproxy ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, _('UDP TPROXY counters (UDP into HomeProxy)')),
					pre(ret.udp_tproxy)
				]) : null,
				ret.uci_firewall ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, _('UCI firewall settings')),
					pre(ret.uci_firewall)
				]) : null,
				ret.zapret_enabled ? row(_('Zapret (nfqws2)'), statusBadge(ret.zapret_running,
					ret.zapret_running ? _('running') : _('enabled, but nfqws2 not running'))) : null,
				(ret.zapret_enabled && ret.zapret_queue) ? E('div', {}, [
					E('div', { 'class': 'diag-label' }, _('Zapret NFQUEUE counters (mark 110 → queue)')),
					pre(ret.zapret_queue)
				]) : null
			].filter(Boolean));
		});
	}

	return {
		el: sectionCard('router', _('Network Intercept'), 'diag-nft', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'hpui-btn hpui-btn-primary',
					'click': ui.createHandlerFn(view, run)
				}, _('Check'))
			]),
			resultsEl
		]),
		run: run
	};
}


function saveBlob(blob, name) {
	const url  = URL.createObjectURL(blob);
	const a    = E('a', { href: url, download: name });
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}

function fileStamp() {
	const now = new Date();
	const pad = (n) => String(n).padStart(2, '0');
	return now.getFullYear() + '-' + pad(now.getMonth()+1) + '-' + pad(now.getDate()) +
		'_' + pad(now.getHours()) + '-' + pad(now.getMinutes()) + '-' + pad(now.getSeconds());
}

/* ── Support Bundle (Р4): сбор → прогресс → скачивание; текст-отчёт.
 * Единая результат-область карточки — все действия пишут в один place. ── */

function buildSupportSection(view) {
	const resultEl = E('div', {});
	const state = { sig: null, busy: false };

	const startBtn = E('button', {
		'class': 'hpui-btn hpui-btn-primary', type: 'button'
	}, [ _('Collect full report') ]);

	const textBtn = E('button', {
		'class': 'hpui-btn hpui-btn-ghost', type: 'button'
	}, [ _('Text report') ]);

	function busy(on) {
		state.busy = on;
		startBtn.disabled = on;
		textBtn.disabled = on;
	}

	function failedChecksLine(selftest) {
		const bad = (selftest || []).filter(function(c) { return c.ok === false; });
		if (!bad.length) return null;
		return bad.map(function(c) { return c.check + ((c.detail) ? (' — ' + c.detail) : ''); }).join('; ');
	}

	/* Скачивание base64-чанками в Blob (cap ~8 МБ — ubus-чанки по 32 КиБ). */
	function downloadBundle(meta, progressEl) {
		const MAX = 8 * 1024 * 1024;
		const size = Number(meta.size || 0);
		if (!size) { ui.addNotification(null, E('p', {}, _('Empty bundle — collect again')), 'error'); return; }
		if (size > MAX) {
			ui.addNotification(null, E('p', {}, _('The archive is larger than 8 MB — use the text report or Telegram /logs')), 'error');
			return;
		}
		const parts = [];
		let off = 0;
		function next() {
			return L.resolveDefault(callBundleChunk(String(off)), {}).then(function(r) {
				if (!r || r.error) throw new Error((r && r.error) || 'rpc error');
				if (r.b64) {
					const bin = atob(r.b64);
					const u8 = new Uint8Array(bin.length);
					for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
					parts.push(u8);
					off = Number(r.next || off);
					if (progressEl)
						progressEl.textContent = _('Downloading… %s%').format(String(Math.min(99, Math.floor(off * 100 / size))));
				}
				if (r.done) {
					if (progressEl) progressEl.textContent = '';
					saveBlob(new Blob(parts, { type: 'application/gzip' }),
						meta.name || ('ravnex-bundle-' + fileStamp() + '.tar.gz'));
					return;
				}
				return next();
			});
		}
		next().catch(function(e) {
			if (progressEl) progressEl.textContent = '';
			ui.addNotification(null, E('p', {}, _('Download failed: ') + e.message), 'error');
		});
	}

	/* Урок 294: текст-отчёт собирается фоном; готовый файл забирается теми же
	 * base64-чанками (chunk kind='text') и декодируется в UTF-8 строку. */
	function concatU8(parts) {
		let n = 0;
		for (const p of parts) n += p.length;
		const out = new Uint8Array(n);
		let o = 0;
		for (const p of parts) { out.set(p, o); o += p.length; }
		return out;
	}

	function fetchReportText(meta, progressEl) {
		const size = Number(meta.size || 0) || 1;
		const parts = [];
		let off = 0;
		function next() {
			return L.resolveDefault(callBundleChunk(String(off), 'text'), {}).then(function(r) {
				if (!r || r.error) throw new Error((r && r.error) || 'rpc error');
				if (r.b64) {
					const bin = atob(r.b64);
					const u8 = new Uint8Array(bin.length);
					for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
					parts.push(u8);
					off = Number(r.next || off);
					if (progressEl)
						progressEl.textContent = _('Downloading… %s%').format(String(Math.min(99, Math.floor(off * 100 / size))));
				}
				if (r.done) {
					if (progressEl) progressEl.textContent = '';
					return new TextDecoder().decode(concatU8(parts));
				}
				return next();
			});
		}
		return next();
	}

	function renderText(text, tookS) {
		resultEl.innerHTML = '';
		const pre = E('pre', { 'id': 'diag-bundle-text' }, [ text ]);
		resultEl.appendChild(pre);
		const dl = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' },
			[ _('Download .txt') ]);
		dl.addEventListener('click', function() {
			saveBlob(new Blob([ text ], { type: 'text/plain' }),
				'ravnex-report-' + fileStamp() + '.txt');
		});
		resultEl.appendChild(E('div', { 'class': 'diag-row' }, [
			dl,
			E('span', { 'class': 'diag-gray', 'style': 'font-size:.85em; margin-left:.6em' },
				[ (tookS != null) ? _('Text report ready in %s s').format(String(tookS)) : '' ])
		]));
	}

	function renderReady(meta) {
		resultEl.innerHTML = '';
		const dlBtn = E('button', {
			'class': 'hpui-btn hpui-btn-primary', type: 'button'
		}, [ _('Download archive') ]);
		const prog = E('span', { 'class': 'diag-gray', 'style': 'font-size:.85em; margin-left:.6em' });
		dlBtn.addEventListener('click', ui.createHandlerFn(view, function() {
			dlBtn.disabled = true;
			downloadBundle(meta, prog);
		}));
		const st = (meta.selftest || []);
		const stOk = st.filter(function(c) { return c.ok !== false; }).length;
		const sizeKb = meta.size ? Math.ceil(meta.size / 1024) : null;
		resultEl.appendChild(E('div', { 'class': 'diag-ok' },
			[ _('Report ready: %s files, self-check %s/%s passed, %s KB, %s s').format(
				String(meta.files || 0), String(stOk), String(st.length),
				String(sizeKb != null ? sizeKb : '?'), String(meta.took_s != null ? meta.took_s : '?')) ]));
		resultEl.appendChild(E('div', { 'class': 'diag-row' }, [ dlBtn, prog ]));
	}

	function renderFailed(meta) {
		resultEl.innerHTML = '';
		resultEl.appendChild(E('div', { 'class': 'diag-fail' },
			[ _('Collection failed: %s').format(meta.error || '?') ]));
		const line = failedChecksLine(meta.selftest);
		if (line)
			resultEl.appendChild(E('div', { 'class': 'wiz-note' }, [ line ]));
	}

	/* Poll: беглый статус сборки; перерисовка только на смену сигнатуры. */
	function pollBundle() {
		if (state.busy) return;
		return L.resolveDefault(callBundleStatus(), {}).then(function(meta) {
			if (!meta || meta.exists === false)
				return;
			if (meta.running) {
				const sig = 'run';
				if (sig === state.sig) return;
				state.sig = sig;
				resultEl.innerHTML = '';
				resultEl.appendChild(E('em', { 'class': 'diag-gray' }, [ _('Collecting…') ]));
				return;
			}
			const sig = 'done:' + (meta.ts || 0) + ':' + (meta.ok ? 1 : 0);
			if (sig === state.sig) return;
			state.sig = sig;
			if (meta.gone) {
				resultEl.innerHTML = '';
				resultEl.appendChild(E('span', { 'class': 'diag-gray' },
					[ _('The archive expired (router rebooted) — collect it again') ]));
				return;
			}
			if (meta.ok === false) { renderFailed(meta); return; }
			if (meta.path) { renderReady(meta); return; }
		});
	}

	/* Poll фонового текст-отчёта (урок 294): running → Collecting…, готово →
	 * забрать текст чанками и отрисовать. Сигнатуры 'text:*' не конфликтуют
	 * с сигнатурами бандла в одном state.sig. */
	function pollText() {
		if (state.busy) return;
		return L.resolveDefault(callBundleTextStatus(), {}).then(function(meta) {
			if (!meta || meta.exists === false)
				return;
			if (meta.running) {
				if (state.sig === 'text-run') return;
				state.sig = 'text-run';
				resultEl.innerHTML = '';
				resultEl.appendChild(E('em', { 'class': 'diag-gray' }, [ _('Collecting…') ]));
				return;
			}
			const sig = 'text:' + (meta.ts || 0);
			if (sig === state.sig) return;
			state.sig = sig;
			if (meta.gone) {
				resultEl.innerHTML = '';
				resultEl.appendChild(E('span', { 'class': 'diag-gray' },
					[ _('The report expired (router rebooted) — collect it again') ]));
				return;
			}
			if (meta.ok === false) { renderFailed(meta); return; }
			if (meta.path) {
				const prog = E('span', { 'class': 'diag-gray', 'style': 'font-size:.85em' });
				resultEl.appendChild(prog);
				fetchReportText(meta, prog).then(function(text) {
					renderText(text, meta.took_s);
				}).catch(function(e) {
					resultEl.innerHTML = '';
					resultEl.appendChild(E('span', { 'class': 'diag-fail' },
						[ _('Failed: %s').format(e.message) ]));
				});
			}
		});
	}

	startBtn.addEventListener('click', ui.createHandlerFn(view, function() {
		busy(true);
		resultEl.innerHTML = '';
		resultEl.appendChild(E('em', { 'class': 'diag-gray' }, [ _('Collecting…') ]));
		return L.resolveDefault(callBundleStart(), {}).then(function(r) {
			if (!r || r.result === false)
				ui.addNotification(null, E('p', {}, _('Failed to start: ') + ((r && r.error) || '')), 'error');
			/* Сбор занимает секунды — дождаться завершения и показать карточку. */
			return poll.add(pollBundle, 2);
		}).finally(function() { busy(false); });
	}));

	textBtn.addEventListener('click', ui.createHandlerFn(view, function() {
		busy(true);
		resultEl.innerHTML = '';
		resultEl.appendChild(E('em', { 'class': 'diag-gray' }, [ _('Collecting…') ]));
		state.sig = 'text-run';
		return L.resolveDefault(callBundleTextStart(), {}).then(function(r) {
			if (!r || r.result === false)
				ui.addNotification(null, E('p', {}, _('Failed to start: ') + ((r && r.error) || '')), 'error');
			/* Сбор занимает ~минуту (урок 294) — поллинг статуса, стрим не трогаем. */
			return poll.add(pollText, 2);
		}).finally(function() { busy(false); });
	}));

	poll.add(pollBundle, hp.pollSec(4));
	poll.add(pollText, hp.pollSec(4));

	return {
		el: sectionCard('database', _('Support report'), 'diag-support', [
			E('p', { 'class': 'hpui-hint' },
				[ _('A privacy-safe diagnostics archive for an issue or Telegram: service states, redacted configs, network, logs and checksums — everything needed to see WHAT hangs, without SSH. Secrets are redacted and a built-in self-check verifies tokens and passwords are absent before the archive is produced.') ]),
			E('div', { 'class': 'diag-row' }, [ startBtn, textBtn ]),
			E('p', { 'class': 'wiz-note', 'style': 'margin:.2em 0 .4em' },
				[ _('What never enters the report: node passwords and keys, tokens, subscription URLs, Wi-Fi passwords, chat ids. Everything else (network addresses, DNS, configs with secrets masked) stays — it is needed to diagnose.') ]),
			resultEl
		]),
		run: function() { return pollBundle(); }
	};
}


const callExplain = rpc.declare({
	object: 'luci.ravnex',
	method: 'health_explain',
	expect: { '': {} }
});

const callEvents = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_events',
	params: [ 'limit' ],
	expect: { '': {} }
});

/* Ф9.14 (D34d): the ONE clear button for the ONE journal — the Parental
 * control duplicate (tab + clear) is gone. */
const callEventsClear = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_events_clear',
	expect: { '': {} }
});

const callRepair = rpc.declare({
	object: 'luci.ravnex',
	method: 'recovery_action',
	params: [ 'action', 'target', 'note' ],
	expect: { '': {} }
});

/* Group captions and their render order (mirrors explain.uc GROUP_ORDER). */
const GROUP_ORDER = [ 'core', 'dpi', 'dns', 'automation', 'telegram',
	'failover', 'access', 'net', 'config', 'system' ];

const STATUS_VIEW = {
	ok:       { cls: 'hpui-b-green', text: _('OK') },
	degraded: { cls: 'hpui-b-amber', text: _('Degraded') },
	down:     { cls: 'hpui-b-red', text: _('Down') },
	off:      { cls: 'hpui-b-grey', text: _('Off') }
};

/* The unified feed: Ф9.1 — ONE icon/color/source set for the whole app
 * (hp.EV_* — Home strip, Control journal and this event center). */
const evIcons = hp.EV_ICONS;
const evColors = hp.EV_COLORS;
const srcLabels = hp.EV_SRC();

function fmtClock(ts) {
	const t = new Date(ts * 1000);
	return ('0' + t.getHours()).slice(-2) + ':' + ('0' + t.getMinutes()).slice(-2) + ':' +
		('0' + t.getSeconds()).slice(-2);
}

function lines(parent, arr, cls) {
	for (let i = 0; i < (arr || []).length; i++) {
		const item = arr[i];
		const text = (item && item.text != null) ? item.text : item;
		const row = E('div', { 'class': cls }, [ '· ' + text ]);
		if (item && item.ts > 0)
			row.appendChild(E('span', { 'class': 'hpui-cap', 'style': 'margin-left:6px' },
				[ fmtClock(item.ts) ]));
		parent.appendChild(row);
	}
}

function actionButtons(ex, onRepair, onUnblock) {
	const box = E('div', { 'class': 'hc-actions' });
	if (ex.repairable && ex.status !== 'ok') {
		const b = E('button', { 'class': 'hpui-btn hpui-btn-primary hpui-btn-sm', 'type': 'button' }, [ _('Repair') ]);
		b.addEventListener('click', function() { onRepair(ex); });
		box.appendChild(b);
	}
	if (ex.unblockable) {
		const b = E('button', { 'class': 'hpui-btn hpui-btn-danger hpui-btn-sm', 'type': 'button' }, [ _('Unblock') ]);
		b.addEventListener('click', function() { onUnblock(ex); });
		box.appendChild(b);
	}
	return box;
}

function explainCell(ex) {
	const cell = E('div', { 'class': 'hc-explain' });
	if (ex.reason)
		cell.appendChild(E('div', {}, [ ex.reason ]));
	if (ex.alert)
		cell.appendChild(E('div', { 'class': 'hpui-c-amber' }, [ '⚠ ' + ex.alert ]));
	if ((ex.done || []).length) {
		const cap = E('div', { 'class': 'hpui-cap', 'style': 'margin-top:4px' }, [ _('What the system did') + ':' ]);
		cell.appendChild(cap);
		lines(cell, ex.done, 'hc-line');
	}
	if ((ex.next || []).length) {
		const cap = E('div', { 'class': 'hpui-cap', 'style': 'margin-top:4px' }, [ _('What happens next') + ':' ]);
		cell.appendChild(cap);
		lines(cell, ex.next, 'hc-line hc-next');
	}
	return cell;
}


return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(hp.getBuiltinFeatures(), {}),
			uci.load('homeproxy')
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	render: function(data) {
		const features = (data && data[0]) || {};

		/* App shell + the page style blocks: the shared hpui system, the
		 * health banner/explain CSS and the diag-* additions that came
		 * over with the merged zones (D32). */
		hp.uiShell();
		const HC_CSS = `
.hc-banner { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 18px; padding: 10px 14px; margin: 6px 0 10px; border: 1px solid var(--hp-panel-line); border-left: 4px solid var(--hp-grey); border-radius: var(--hp-radius-lg); background: var(--hp-panel-bg); box-shadow: var(--hp-shadow); }
.hc-banner.ok { border-left-color: var(--hp-accent); }
.hc-banner.warn { border-left-color: var(--hp-amber); }
.hc-banner.bad { border-left-color: var(--hp-red); }
.hc-verdict { font-size: 1.05em; font-weight: 800; }
.hc-chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--hp-panel-line); background: var(--hp-panel-bg-2); border-radius: 999px; padding: 2px 10px; font-size: .84em; }
.hc-fresh { font-size: .82em; opacity: .75; }
.hc-actions { display: flex; flex-wrap: wrap; gap: 6px; }
.hc-explain div { margin: 1px 0; }
.hc-line { font-size: .88em; opacity: .82; }
.hc-next { opacity: .68; }
.hc-group td { padding: 7px 10px 4px; font-weight: 700; font-size: .88em; color: var(--hp-accent-strong); border-bottom: 1px solid var(--hp-panel-line); background: var(--hp-panel-bg-2); }
.hc-result { margin-top: 8px; }
`;
		const styleEl = E('style', { 'type': 'text/css' }, [ HC_CSS ]);
		document.head.appendChild(E('style', {}, [ css ]));
		document.head.appendChild(styleEl);

		/* ── Check & repair + Provider zones (built once; their polls and
		 * their ONE-result areas live inside the panels) ────────────── */
		const core   = buildCoreSection(this);
		const config = buildConfigSection(this);
		const dns    = buildDnsSection(this);
		const mdns   = buildMultidnsDnsSection(this);
		const nft    = buildNftSection(this);
		const conn   = buildConnectivitySection(this, features.core_type || null);
		const report = buildSupportSection(this);
		const prov   = buildProviderSection();
		const profs  = buildProfilesSection();
		const opt    = buildOptimizerSection();
		const disc   = buildDiscoverySection();

		dns.run();
		mdns.run();

		const runAll = ui.createHandlerFn(this, function() {
			return Promise.all([
				core.run(),
				config.run(),
				nft.run(),
				conn.run()
			]);
		});

		/* ── Overview zone: the banner ───────────────────────────────── */
		const verdictEl = E('span', { 'class': 'hc-verdict' }, [ '…' ]);
		const countEl = E('span', { 'class': 'hc-fresh' }, [ '' ]);
		const chipHealth = E('span', { 'class': 'hc-chip' }, [ '' ]);
		const chipSentinel = E('span', { 'class': 'hc-chip' }, [ '' ]);
		const chipRecovery = E('span', { 'class': 'hc-chip' }, [ '' ]);
		const banner = E('div', { 'class': 'hc-banner', 'id': 'hc-banner' }, [
			verdictEl, countEl, chipHealth, chipSentinel, chipRecovery
		]);

		/* ── Overview + journal zone holders ─────────────────────────── */
		const svcWrap = E('div', {}, []);
		const attentionEl = E('div', {}, []);
		const historyEl = E('div', {}, []);
		const evList = E('div', { 'class': 'hpui-log', 'style': 'max-height:300px' }, []);
		const restartBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', 'type': 'button' },
			[ _('Restart service') ]);
		const resultEl = E('div', { 'class': 'hc-result' }, []);

		function setResult(content, ok) {
			dom.content(resultEl, content);
			resultEl.style.color = (ok === true) ? 'var(--hp-accent-strong)' :
				(ok === false ? 'var(--hp-red)' : '');
		}
		function noteResult(text, ok) {
			setResult(E('p', { 'class': 'hpui-hint' }, [ text ]), ok);
		}

		function sendRepair(ex) {
			noteResult(_('Sending the repair request…'), null);
			L.resolveDefault(callRepair('repair', ex.campaign ? ex.campaign.key : ex.name, ''), {})
				.then(function(r) {
					if (r && r.result !== false)
						noteResult(_('Manual request sent to the coordinator — it executes in the next tick.'), true);
					else
						noteResult((r && r.error) || _('Failed'), false);
					window.setTimeout(refreshAll, 2500);
				});
		}
		function sendUnblock(ex) {
			const key = ex.campaign ? ex.campaign.key : ex.name;
			noteResult(_('Sending the unblock request…'), null);
			L.resolveDefault(callRepair('unblock', key, ''), {}).then(function(r) {
				if (r && r.result !== false)
					noteResult(_('The campaign is reset — the coordinator will confirm in the next tick.'), true);
				else
					noteResult((r && r.error) || _('Failed'), false);
				window.setTimeout(refreshAll, 2500);
			});
		}

		function pollOp(opId) {
			const deadline = Date.now() + 120000;
			const tick = function() {
				L.resolveDefault(callOpStatus(opId), {}).then(function(st) {
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
						window.setTimeout(refreshAll, 4000);
						return;
					}
					if (Date.now() > deadline) {
						restartBtn.disabled = false;
						noteResult(_('The operation is still running — check the Operations journal tab.'), false);
						return;
					}
					window.setTimeout(tick, 2000);
				});
			};
			tick();
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

		/* ── render helpers ─────────────────────────────────────────── */

		function renderBanner(d) {
			const s = (d && d.explains && d.explains.summary) || null;
			if (!s) {
				verdictEl.textContent = _('No data from the health monitor yet — refresh in a minute.');
				dom.content(countEl, []);
				chipHealth.textContent = '';
				chipSentinel.textContent = '';
				chipRecovery.textContent = '';
				banner.className = 'hc-banner';
				return;
			}
			const counts = s.counts || { ok: 0, degraded: 0, down: 0, off: 0 };
			const overall = s.overall || 'off';
			if (overall === 'ok' && counts.degraded === 0 && counts.down === 0) {
				verdictEl.textContent = _('All subsystems are running');
				banner.className = 'hc-banner ok';
			} else if (counts.down > 0) {
				verdictEl.textContent = _('%d subsystem(s) down').format(counts.down);
				banner.className = 'hc-banner bad';
			} else if (counts.degraded > 0) {
				verdictEl.textContent = _('%d subsystem(s) degraded').format(counts.degraded);
				banner.className = 'hc-banner warn';
			} else {
				verdictEl.textContent = _('The service is stopped');
				banner.className = 'hc-banner';
			}
			dom.content(countEl, [ E('span', {}, [
				_('Running: %d').format(counts.ok) + ' · ' +
				_('Degraded: %d').format(counts.degraded) + ' · ' +
				_('Down: %d').format(counts.down) + ' · ' +
				_('Off: %d').format(counts.off)
			]) ]);

			const h = d.health || {};
			chipHealth.textContent = h.computed === 'rpc'
				? _('Health data recomputed honestly (the monitor daemon has not written yet)')
				: (h.fresh ? _('Health data is fresh (%d s old)').format(h.age || 0)
					: _('Health data is stale'));
			const sn = d.sentinel || {};
			chipSentinel.textContent = !sn.fresh
				? _('Sentinel: no fresh data — the guard may be silent')
				: (sn.data && sn.data.coordinator === 'live')
					? 'Sentinel: ' + _('coordinator alive, the guard only detects')
					: 'Sentinel: ' + _('fallback mode (the coordinator is dead)') +
						((sn.data && sn.data.findings) ? ' · ' + _('findings: %d').format(sn.data.findings) : '');
			const rc = d.recovery || {};
			let rcText = !rc.fresh
				? _('Recovery: no fresh data — the coordinator may be dead')
				: (s.recovery.active_keys > 0)
					? _('Recovery: %d campaign(s) in progress').format(s.recovery.active_keys)
					: _('Recovery: nothing in progress');
			if (s.recovery.manual_queue > 0)
				rcText += ' · ' + _('manual requests queued: %d').format(s.recovery.manual_queue);
			if (s.recovery.freeze_left > 0)
				rcText += ' · ' + _('auto-repairs frozen for %d min').format(Math.ceil(s.recovery.freeze_left / 60));
			chipRecovery.textContent = rcText;
		}

		function renderServices(d) {
			const explains = (d && d.explains && d.explains.entries) || null;
			svcWrap.innerHTML = '';
			if (!explains) {
				svcWrap.appendChild(E('em', {}, [ _('No data from the health monitor yet — refresh in a minute.') ]));
				return;
			}
			const byGroup = {};
			for (const name in explains) {
				const ex = explains[name];
				if (!byGroup[ex.group])
					byGroup[ex.group] = [];
				byGroup[ex.group].push(ex);
			}
			const table = E('table', { 'class': 'hpui-table' });
			table.appendChild(E('thead', {}, [ E('tr', {}, [
				E('th', {}, [ _('Service') ]),
				E('th', {}, [ _('Status') ]),
				E('th', {}, [ _('What the system did and will do') ]),
				E('th', {}, [ _('Actions') ])
			]) ]));
			const tbody = E('tbody', {});
			for (const g of GROUP_ORDER) {
				const list = byGroup[g];
				if (!list || !list.length)
					continue;
				tbody.appendChild(E('tr', { 'class': 'hc-group' },
					[ E('td', { 'colspan': '4' }, [ groupLabel(g) ]) ]));
				list.sort(function(a, b) { return (a.label < b.label) ? -1 : 1; });
				for (const ex of list) {
					const sv = STATUS_VIEW[ex.status] || STATUS_VIEW.off;
					const statusCell = E('div', {}, [
						E('span', { 'class': 'hpui-badge ' + sv.cls }, [ sv.text ]),
						E('div', { 'class': 'hpui-cap', 'style': 'margin-top:3px' },
							[ ex.confidence === 'certain' ? _('Verified now') : _('Inferred') ])
					]);
					tbody.appendChild(E('tr', {}, [
						E('td', { 'style': 'font-weight:600; white-space:nowrap' }, [ ex.label ]),
						E('td', {}, [ statusCell ]),
						E('td', {}, [ explainCell(ex) ]),
						E('td', {}, [ actionButtons(ex, sendRepair, sendUnblock) ])
					]));
				}
			}
			table.appendChild(tbody);
			svcWrap.appendChild(table);
		}

		function groupLabel(g) {
			switch (g) {
				case 'core': return _('Core');
				case 'dpi': return _('DPI engines');
				case 'dns': return 'DNS';
				case 'automation': return _('Auto-bypass');
				case 'telegram': return 'Telegram';
				case 'failover': return _('Failover');
				case 'access': return _('Access Control');
				case 'net': return _('Interception');
				case 'config': return _('Configuration');
				default: return _('System');
			}
		}

		function renderAttention(d) {
			const extra = (d && d.explains && d.explains.extra) || [];
			const s = (d && d.explains && d.explains.summary) || null;
			attentionEl.innerHTML = '';
			const items = [];
			for (const ex of extra) {
				const titleParts = [
					E('span', { 'class': 'hpui-badge ' + ((STATUS_VIEW[ex.status] || STATUS_VIEW.off).cls) },
						[ (STATUS_VIEW[ex.status] || STATUS_VIEW.off).text ]),
					' ' + ex.label
				];
				if (ex.carried)
					titleParts.push(E('span', { 'class': 'hpui-cap', 'style': 'margin-left:8px' },
						[ '(' + _('carried by the light pass') + ')' ]));
				const box = E('div', { 'class': 'hpui-panel', 'style': 'margin:8px 0' }, [
					E('div', { 'style': 'font-weight:700' }, titleParts),
					E('div', { 'style': 'margin-top:3px' }, [ ex.reason ]),
					E('div', { 'class': 'hc-explain', 'style': 'margin-top:4px' }, [])
				]);
				const body = box.children[2];
				lines(body, ex.done, 'hc-line');
				lines(body, ex.next, 'hc-line hc-next');
				for (const m of (ex.manual || []))
					body.appendChild(E('div', { 'class': 'hc-line hpui-c-amber' }, [ '· ' + m ]));
				const btns = actionButtons(ex, sendRepair, sendUnblock);
				if (btns.children.length)
					box.appendChild(E('div', { 'style': 'margin-top:6px' }, [ btns ]));
				items.push(box);
			}
			if (s && s.recovery.watch_op) {
				items.push(E('div', { 'class': 'hpui-banner' }, [
					_('A configuration apply is in progress ("%s") — the coordinator waits for the verdict and then resets the auto-campaigns.')
						.format(s.recovery.watch_op.action || '')
				]));
			}
			if (!items.length)
				attentionEl.appendChild(E('em', {},
					[ _('Nothing needs attention — the watchdogs are quiet.') ]));
			for (const it of items)
				attentionEl.appendChild(it);
		}

		function renderHistory(d) {
			const hist = (d && d.explains && d.explains.history) || [];
			historyEl.innerHTML = '';
			if (!hist.length) {
				historyEl.appendChild(E('em', {},
					[ _('No repairs yet — the coordinator has not executed anything.') ]));
				return;
			}
			const table = E('table', { 'class': 'hpui-table' });
			table.appendChild(E('thead', {}, [ E('tr', {}, [
				E('th', {}, [ _('Time') ]), E('th', {}, [ _('What happened') ])
			]) ]));
			const tbody = E('tbody', {});
			for (let i = hist.length - 1; i >= 0; i--) {
				tbody.appendChild(E('tr', {}, [
					E('td', { 'style': 'white-space:nowrap; color:var(--hp-ink-grey)' },
						[ fmtClock(hist[i].ts) ]),
					E('td', {}, [ hist[i].text ])
				]));
			}
			table.appendChild(tbody);
			historyEl.appendChild(table);
		}

		function renderEvents(events) {
			const out = [];
			for (let i = (events || []).length - 1; i >= 0 && out.length < 80; i--) {
				const ev = events[i];
				const icon = evIcons[ev.type] || '•';
				const src = srcLabels[ev.src || 'control'] || (ev.src || 'control');
				out.push(E('div', {}, [
					E('span', { 'class': evColors[ev.type] || 'hpui-c-grey' },
						[ fmtClock(ev.ts) + ' ' + icon + ' ' + (ev.who || '') ]),
					(ev.detail ? ' — ' + ev.detail : ''),
					E('span', { 'class': 'hpui-cap', 'style': 'margin-left:8px' }, [ '[' + src + ']' ])
				]));
			}
			dom.content(evList, out.length ? out : [ _('The journal is empty.') ]);
		}

		/* Ф9.14 (D34d): the ONE clear button for the ONE journal (the
		 * Parental control duplicate is gone). The repair history and the
		 * service log are NOT touched — only the event feed. */
		const evClearBtn = E('button', { 'class': 'hpui-btn hpui-btn-sm hpui-btn-danger', type: 'button' },
			[ _('Clear the journal') ]);
		evClearBtn.addEventListener('click', function() {
			ui.showModal(_('Clear the journal'), [
				E('p', {}, [ _('Clear the events journal? The repair history and the service log are not touched.') ]),
				E('div', { 'class': 'right', 'style': 'margin-top:14px; display:flex; gap:8px; justify-content:flex-end' }, [
					E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'click': ui.hideModal }, [ _('Cancel') ]),
					E('button', { 'class': 'hpui-btn hpui-btn-danger', 'click': function() {
						ui.hideModal();
						evClearBtn.disabled = true;
						L.resolveDefault(callEventsClear(), {}).finally(function() {
							evClearBtn.disabled = false;
							refreshAll();
						});
					} }, [ _('Clear') ])
				])
			]);
		});

		function refreshAll() {
			return Promise.all([
				L.resolveDefault(callExplain(), null),
				L.resolveDefault(callEvents('80'), null)
			]).then(function(d) {
				const r = d[0];
				renderBanner(r);
				renderServices(r);
				renderAttention(r);
				renderHistory(r);
				renderEvents((d[1] && d[1].events) || []);
			}).catch(function(e) {
				noteResult(_('The health data is unavailable: %s').format(String(e || 'rpc error')), false);
			});
		}

		poll.add(refreshAll, hp.pollSec(10));
		refreshAll();


		/* ── Tabbed layout (D32): Overview / Check & repair / Operations
		 * journal / Provider. Deep links from the Home page: #repair,
		 * #journal, #provider (overview.js hero, hub card, quick setup). */
		const TABS = [
			[ 'overview', _('Overview') ],
			[ 'repair',   _('Check & repair') ],
			[ 'journal',  _('Operations journal') ],
			[ 'provider', _('Provider') ]
		];
		const panes = {};
		for (let t in TABS)
			panes[TABS[t][0]] = E('div', { 'class': 'hpui-pane' });

		const tabBar = E('div', { 'class': 'hpui-tabs' });
		function activateTab(key) {
			for (let k in panes)
				panes[k].classList.toggle('active', k === key);
			for (let j = 0; j < tabBar.children.length; j++)
				tabBar.children[j].classList.toggle('active', TABS[j][0] === key);
		}
		for (let i in TABS) {
			const key = TABS[i][0];
			const b = E('button', { 'class': 'hpui-tab', type: 'button' }, [ TABS[i][1] ]);
			b.addEventListener('click', function() {
				activateTab(key);
				try { history.replaceState(null, '', '#' + key); } catch (e) {}
			});
			tabBar.appendChild(b);
		}
		const wanted = String(location.hash || '').replace('#', '');
		activateTab(TABS.some(function(t) { return t[0] === wanted; }) ? wanted : 'overview');

		/* ── Overview: status + attention + manual actions ───────────── */
		panes.overview.appendChild(banner);
		panes.overview.appendChild(E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('heart'), _('Services') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('Every status carries an honest explanation: why it is what it is, what the watchdogs and the recovery coordinator have already done, what happens next — and what you can do by hand.') ]),
			svcWrap
		]));
		panes.overview.appendChild(E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('alert'), _('System attention') ]),
			attentionEl
		]));
		panes.overview.appendChild(E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('repeat'), _('Actions') ]),
			E('div', { 'class': 'hc-actions' }, [ restartBtn ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('The service restart re-routes every connection and goes through the verified apply door; a verified apply also resets every automatic repair campaign.') ]),
			resultEl
		]));

		/* ── Check & repair: the actual probes (the former diagnostics
		 * page, flattened into panels; nothing dropped) ─────────────── */
		panes.repair.appendChild(E('div', { 'class': 'cbi-section', 'style': 'padding-bottom:.5em' }, [
			E('button', {
				'class': 'hpui-btn hpui-btn-primary',
				'click': runAll
			}, _('Run All Tests')),
			E('em', { 'class': 'diag-gray', 'style': 'margin-left:.8em; font-size:.9em' },
				_('Runs Core, Config, Network, and Connectivity checks simultaneously.'))
		]));
		panes.repair.appendChild(E('p', { 'class': 'hpui-hint', 'style': 'margin:0 0 .5em' },
			[ _('When something does not work: this tab runs the actual probes — the core, the config, DNS and the network — and reports the findings. Start with Run All Tests, then read the panel the problem points to.') ]));
		panes.repair.appendChild(core.el);
		panes.repair.appendChild(conn.el);
		panes.repair.appendChild(config.el);
		panes.repair.appendChild(dns.el);
		panes.repair.appendChild(mdns.el);
		panes.repair.appendChild(nft.el);
		panes.repair.appendChild(report.el);

		/* ── Operations journal: what the system did over time ───────── */
		panes.journal.appendChild(E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('tool'), _('Repair history') ]),
			historyEl
		]));
		panes.journal.appendChild(E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('activity'), _('Event center') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('The single event feed of the whole system: routing, bypass engines, automation, health, recovery, Safe Mode, updates and security all write to this one journal.') ]),
			E('div', { 'style': 'margin:0 0 6px' }, [ evClearBtn ]),
			evList
		]));

		/* ── Provider: what the provider blocks, how services behave ─── */
		panes.provider.appendChild(prov.el);
		panes.provider.appendChild(profs.el);
		panes.provider.appendChild(opt.el);
		panes.provider.appendChild(disc.el);

		return E('div', {}, [
			styleEl,
			hp.pageIntro(_('Health center'),
				_('Live status of every Ravnex subsystem, the full check & repair toolkit and the operations journal — one page. Overview watches the subsystems; Check & repair runs the actual probes; the journal shows what the system did; Provider measures what the provider blocks.')),
			tabBar,
			panes.overview,
			panes.repair,
			panes.journal,
			panes.provider
		]);
	}
});
