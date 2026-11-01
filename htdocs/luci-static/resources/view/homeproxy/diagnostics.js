/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023-2025 ImmortalWrt.org
 */

'use strict';
'require dom';
'require homeproxy as hp';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

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
.diag-btn { margin-right:.4em; }\
.wiz-note { font-size:.88em; opacity:.8; margin:.3em 0; }\
.diag-row .cbi-input-text { flex:1 1 260px; }\
#diag-report-area { width:100%; height:22em; font-family:monospace; font-size:.8em;\
  white-space:pre; overflow:auto; background:#1e1e1e; color:#ddd; border:1px solid #333;\
  border-radius:6px; padding:.5em; }\
';

/* ── RPC declarations ─────────────────────────────────────────────────── */

const callCoreCheck = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_core_check',
	expect: { '': {} }
});
const callConfigCheck = rpc.declare({
	object: 'luci.homeproxy',

	method: 'diag_config_check',

	expect: { '': {} }
});

const callConfigHeal = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_config_heal',
	params: [ 'repair' ],
	expect: { '': {} }
});
const callDnsRu = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_dns_ru',
	expect: { '': {} }
});

const callDnsMultidns = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_dns_multidns',
	expect: { '': {} }
});

const callNftables = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_nftables',
	expect: { '': {} }
});


const callReport = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_report',
	expect: { '': {} }
});

const callServiceRestart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_service_restart',
	expect: { '': {} }
});

const callConnCheck = rpc.declare({
	object: 'luci.homeproxy',
	method: 'connection_check',
	params: ['site'],
	expect: { '': {} }
});

const callIpInfo = rpc.declare({
	object: 'luci.homeproxy',
	method: 'clash_ip_info',
	expect: { '': {} }
});

const callActiveNode = rpc.declare({
	object: 'luci.homeproxy',
	method: 'clash_active_node',
	params: ['tag'],
	expect: { '': {} }
});

const callRouteExplain = rpc.declare({
	object: 'luci.homeproxy',
	method: 'route_explain',
	params: ['host'],
	expect: { '': {} }
});

/* ── Provider diagnostics (R3 v3b: moved from the Wizard «Provider
 * diagnostics» pane — same RPC, same ONE result area). ────────────────── */

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
 * runner; the poll shows its progress in the provider pane row. */
const callDpiUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_dpidetect_update',
	expect: { '': {} }
});

const callPresetList = rpc.declare({
	object: 'luci.homeproxy',
	method: 'wizard_preset_list',
	expect: { '': {} }
});

/* Human name of a rule outbound (same wording as wizard.js). */
function nodeText(node) {
	if (node === 'main-out') return _('Same as main node');
	if (node === 'byedpi-out') return 'ByeDPI';
	if (node === 'zapret-out') return 'Zapret';
	if (node === 'tgws-out') return _('tg-ws (transparent)');
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
	partial:        [ 'hpui-b-grey', _('Only the main path was measured') ],
	unknown:        [ 'hpui-b-grey', _('No data') ]
};

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
	return E('span', { 'class': 'hpui-badge ' + spec[0] }, [ label ]);
}

const PROV_KINDS = {
	tls_dpi:   _('TLS DPI (SNI reset)'),
	tcp:       _('TCP unreachable'),
	timeout:   _('Timeout (dropped?)'),
	resolve:   _('DNS resolve failed'),
	sigpage:   _('Block page served as 200'),
	hardcode:  _('Refusal code (403/406/451)'),
	waf:       _('WAF challenge (path is open)'),
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
	if (p.ok)
		return E('span', { title: title }, [ E('span', { 'class': 'hpui-badge hpui-b-green' }, [ '✓ ' + (p.code || '') ]), slowHint ]);
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
		'class': 'btn cbi-button cbi-button-action', type: 'button'
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
		'class': 'btn cbi-button cbi-button-action', type: 'button'
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
			/* The tg-ws bridge is MTProto-only (ch.91, lesson 95): a web
			 * probe cannot pass the bridge, a needs_proxy verdict here does
			 * NOT mean "create a rule". */
			if (r.verdict === 'needs_proxy' && rule && rule.enabled && rule.node === 'tgws-out')
				rec = _('Rule configured (→ %s) — it serves the Telegram apps (MTProto); the web version rides the node (group fallback).').format(nodeText(rule.node));
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
			/* tg-ws rows (rule → tgws-out): the WEB probe result depends on
			 * which urltest member serves it; messaging apps are unaffected. */
			if (r.svc === 'telegram' && rule && rule.enabled && rule.node === 'tgws-out')
				hostCell.appendChild(E('div', { 'class': 'wiz-note', style: 'margin:0' },
					[ _('The probe checks the WEB version through the configured path; the tg-ws bridge carries the Telegram apps (MTProto) only — the web check may time out while the group sits on the bridge, messaging clients are unaffected. Bridge status and check: the Phone control page.') ]));
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
	poll.add(pollScan, 4);
	pollScan();

	return {
		el: sectionCard(_('Provider'), 'diag-provider', [
			E('p', { 'class': 'hpui-hint' },
				[ _('Checks a set of test services (YouTube, Discord, Telegram, WhatsApp, Google AI, OpenAI, Claude, Twitch…) through your real paths. The VERDICT speaks about your CONFIGURED routing (rules, learned lists and Zapret/ByeDPI desync) — the way LAN clients are actually served; the Direct column is reference: it shows whether the resource could open with no VPN at all. A response whose redirect chain is reset mid-way is not a success, and a 200 with an application-level refusal (geo, Gemini "something went wrong") is not either. When a refusal is about the remote region rather than the local provider, the verdict says so (geo-block) — a routing strategy cannot fix a region refusal, a node with a supported region can. RU services (rutube, gosuslugi) are control hosts — they must always open directly.') ]),
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

function sectionCard(title, id, rows) {
	return E('div', { 'class': 'hpui-panel diag-section' }, [
		E('h4', {}, title),
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
		const btn = E('button', { 'class': 'btn cbi-button cbi-button-action diag-btn',
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
				parts.push(E('div', {}, [
					E('strong', {}, [ ret.outbound ? resolveTag(ret.outbound) : (ret.action || '?') ]),
					E('span', { 'class': 'diag-gray' }, ' ← ' + (ret.match || '') +
						(ret.rule_index ? (' · ' + _('rule') + ' #' + ret.rule_index) : '') +
						(ret.fallback ? ' · ' + _('default route (no rule matched)') : ''))
				]));
				if (ret.chain)
					parts.push(E('div', { 'class': 'diag-gray' }, ret.chain));
				for (let t in (ret.trace || []))
					if (t.action === 'reject')
						parts.push(E('div', { 'style': 'color:#d99a1b' },
							_('rejects UDP/443 (QUIC escape)') + ' — ' + (t.match || '')));
				dom.content(resultEl, parts);
			});
		}
		const btn = E('button', { 'class': 'btn cbi-button cbi-button-action diag-btn',
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
		const btn = E('button', { 'class': 'btn cbi-button cbi-button-action diag-btn',
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
		}));
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
	   (Global + the bypass_cn/bypass_ir reverse modes; proxy_banned_ru/custom don't, and
	   'redirect' proxy mode has no UDP path). Show which node currently carries UDP. */
	const udpNode   = uci.get('homeproxy', 'config', 'main_udp_node');
	const proxyMode = uci.get('homeproxy', 'config', 'proxy_mode');
	if (udpNode && !['nil', 'same', ''].includes(udpNode) && proxyMode !== 'redirect')
		rows.push(activeNodeRow(_('Active UDP Node'), 'main-udp-out'));

	return {
		el: sectionCard(_('Connectivity'), 'diag-connectivity', rows),
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

	function restart() {
		dom.content(restartMsgEl, E('em', { 'class': 'diag-gray' }, _('Restarting… (may take ~5 s)')));
		return L.resolveDefault(callServiceRestart(), {}).then(function(ret) {
			if (ret && ret.result) {
				dom.content(restartMsgEl, statusBadge(true, _('Service restarted')));
				/* Refresh core status after restart */
				return run();
			} else {
				dom.content(restartMsgEl, statusBadge(false,
					_('Restart failed') + (ret && ret.exit_code != null ? ' (exit ' + ret.exit_code + ')' : '')));
			}
		});
	}

	return {
		el: sectionCard(_('Core & System'), 'diag-core', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-action diag-btn',
					'click': ui.createHandlerFn(view, run)
				}, _('Check')),
				E('button', {
					'class': 'btn cbi-button cbi-button-negative diag-btn',
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
		el: sectionCard(_('Configuration'), 'diag-config', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-action diag-btn',
					'click': ui.createHandlerFn(view, run)
				}, _('Check')),
				E('button', {
					'class': 'btn cbi-button diag-btn',
					'click': ui.createHandlerFn(view, function() { return heal(false); }),
					'title': _('Verify critical configuration files and firewall includes')
				}, _('Verify Configuration')),
				E('button', {
					'class': 'btn cbi-button cbi-button-negative diag-btn',
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

	const cardEl = sectionCard(_('DNS Tests'), 'diag-dns', [
		E('div', { 'class': 'diag-row' }, [
			E('button', {
				'class': 'btn cbi-button cbi-button-action diag-btn',
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

	const cardEl = sectionCard(_('MultiDNS DNS Tests'), 'diag-mdns-dns', [
		E('div', { 'class': 'diag-row' }, [
			E('button', {
				'class': 'btn cbi-button cbi-button-action diag-btn',
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
		el: sectionCard(_('Network Intercept'), 'diag-nft', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-action diag-btn',
					'click': ui.createHandlerFn(view, run)
				}, _('Check'))
			]),
			resultsEl
		]),
		run: run
	};
}


function buildReportSection(view) {
	const textArea = E('textarea', {
		'id': 'diag-report-area',
		'readonly': true,
		'placeholder': _('Click Generate to collect diagnostics…')
	});

	function run() {
		textArea.value = _('Collecting diagnostics — this may take a few seconds…');
		return L.resolveDefault(callReport(), {}).then(function(ret) {
			textArea.value = ret.report || _('(empty)');
		});
	}

	function copy() {
		textArea.select();
		document.execCommand('copy');
	}

	function download() {
		const text = textArea.value;
		if (!text || text === _('Click Generate to collect diagnostics…')) return;
		const now = new Date();
		const pad = (n) => String(n).padStart(2, '0');
		const stamp = now.getFullYear() + '-' + pad(now.getMonth()+1) + '-' + pad(now.getDate()) +
		              '_' + pad(now.getHours()) + '-' + pad(now.getMinutes()) + '-' + pad(now.getSeconds());
		const blob = new Blob([text], { type: 'text/plain' });
		const url  = URL.createObjectURL(blob);
		const a    = E('a', { href: url, download: 'homeproxy-diagnostics-' + stamp + '.txt' });
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	return {
		el: sectionCard(_('Diagnostics Report'), 'diag-report', [
			E('div', { 'class': 'diag-row' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-action diag-btn',
					'click': ui.createHandlerFn(view, run)
				}, _('Generate')),
				E('button', {
					'class': 'btn cbi-button diag-btn',
					'click': ui.createHandlerFn(view, copy)
				}, _('Copy')),
				E('button', {
					'class': 'btn cbi-button diag-btn',
					'click': ui.createHandlerFn(view, download)
				}, _('Download')),
				E('em', { 'class': 'diag-gray', 'style': 'font-size:.85em' },
					_('Sensitive values (passwords, keys, UUIDs) are redacted.'))
			]),
			textArea
		])
	};
}

/* ── View ─────────────────────────────────────────────────────────────── */

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(hp.getBuiltinFeatures(), {}),
			uci.load('homeproxy')
		]);
	},

	render: function(data) {
		const features = (data && data[0]) || {};

		/* App shell (R3 v2) + page-specific tweaks. */
		hp.uiShell();
		document.head.appendChild(E('style', {}, [ css ]));

		const core   = buildCoreSection(this);
		const config = buildConfigSection(this);
		const dns    = buildDnsSection(this);
		const mdns   = buildMultidnsDnsSection(this);
		const nft    = buildNftSection(this);
		const conn   = buildConnectivitySection(this, features.core_type || null);
		const report = buildReportSection(this);
		const prov   = buildProviderSection();

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

		/* ── Tabbed layout (same interaction as the Automation tab) ────── */
		const TABS = [
			[ 'overview', _('Overview') ],
			[ 'provider', _('Provider') ],
			[ 'config',   _('Configuration') ],
			[ 'dns',      _('DNS') ],
			[ 'network',  _('Network') ],
			[ 'report',   _('Report') ]
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
		panes.overview.classList.add('active');

		panes.overview.appendChild(core.el);
		panes.overview.appendChild(conn.el);
		panes.provider.appendChild(prov.el);
		panes.config.appendChild(config.el);
		panes.dns.appendChild(dns.el);
		panes.dns.appendChild(mdns.el);
		panes.network.appendChild(nft.el);
		panes.report.appendChild(report.el);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('Ravnex Diagnostics')),
			E('p', { 'class': 'hpui-hint', 'style': 'margin-top:2px' },
				_('When something does not work: this page runs the actual probes — the core, the config, DNS, the network, and what exactly the provider blocks — and reports the findings. Start with Run All Tests, then read the tab the problem points to.')),
			E('div', { 'class': 'cbi-section', 'style': 'padding-bottom:.5em' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-action important',
					'click': runAll
				}, _('Run All Tests')),
				E('em', { 'class': 'diag-gray', 'style': 'margin-left:.8em; font-size:.9em' },
					_('Runs Core, Config, Network, and Connectivity checks simultaneously.'))
			]),
			tabBar,
			panes.overview,
			panes.provider,
			panes.config,
			panes.dns,
			panes.network,
			panes.report
		]);
	},

	handleSaveApply: null,
	handleSave:      null,
	handleReset:     null
});
