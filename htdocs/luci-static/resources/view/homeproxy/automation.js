/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Automation tab (Ф7.1: THREE logical levels, not a settings zoo).
 *
 * Level "Auto-bypass" (D13 «Автообход блокировок»): the site-learning
 * engine — master switch, status cards, the Sites table (search/filters/
 * add/delete/pins), the Ф5 "Engine overview" panel (cycle/probe/RAM/entries
 * cards, inline-SVG sparklines, verdict distribution, source activity and
 * a recent-events feed, fed by the light automation_stats RPC) and the
 * EXPERT settings collapsed into a <details> (U4: the less the user sees
 * by default, the better). Level "DPI auto-pilot": the scheduled strategy
 * auto-pilot (moved here from the Strategy master page — its natural home
 * is automation; the one-click auto-pick stays with the Strategy Lab).
 * Level "Logs": the engine log + the automation-family Event Bus feed
 * (learn/heal/outage + Hot Swap switches + URLTest watchdog + autopilot
 * decisions). The detection only ADDS sites proven unreachable directly yet
 * reachable via the proxy, and routes them through the user's configured main
 * path — so it stays fully compatible with ByeDPI and Zapret. Russian
 * networks/domains are hard-excluded from learning and from proxying
 * (RU-geo databases + TLD guards + manual pins); the RU-PROTECTION card
 * itself (guarantee + databases) lives on the Connection page (Ф7.2) —
 * it is a routing invariant, not an automation setting.
 */

'use strict';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';
'require homeproxy as hp';

/* Сеанс 191: тоггл стиринга мёртвых YouTube-пулов и «Забыть выученные
 * пулы» переехали сюда с Мастера стратегий (поведение системы, а не
 * состояние; RPC-двери те же — yt_steer_set / yt_steer_learned_clear). */
const callYtSteerSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'yt_steer_set',
	params: [ 'value' ],
	expect: { '': {} }
});

const callYtSteerLearnedClear = rpc.declare({
	object: 'luci.ravnex',
	method: 'yt_steer_learned_clear',
	expect: { '': {} }
});

const callStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_status',
	expect: { '': {} }
});

/* Ф5 (ч.77): engine counters for the "Engine overview" panel. LIGHT RPC —
 * the daemon writes a small stats file each cycle; this never parses the
 * heavy automation_state.json. */
const callStats = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_stats',
	expect: { '': {} }
});

const callEntryAdd = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_entry_add',
	params: [ 'entry', 'action' ],
	expect: { '': {} }
});

const callEntryDelete = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_entry_delete',
	params: [ 'entry' ],
	expect: { '': {} }
});

const callEntryAction = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_entry_action',
	params: [ 'entry', 'action' ],
	expect: { '': {} }
});

/* Ф7.1: the scheduled DPI auto-pilot moved here from the Blocking bypass
 * page (its logical home is automation). Same RPCs, same contract. */
const callAutoPilotStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_autopilot_status',
	expect: { '': {} }
});

const callAutoPilotSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_autopilot_set',
	params: [ 'enabled', 'resources', 'set_rules', 'interval_h', 'check_min', 'window', 'fuzz_mode', 'fail_strikes', 'night_pick' ],
	expect: { '': {} }
});

/* Сеанс 158/Б8: явное снятие удержания Hot Swap (плановая переразметка). */
const callAutoPilotHoldRelease = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_autopilot_hold_release',
	expect: { '': {} }
});

/* Ф7.3: the automation-family Event Bus feed (Журналы level) — the same
 * journal the Health center renders, filtered to the automation family. */
const callEvents = rpc.declare({
	object: 'luci.ravnex',
	method: 'control_events',
	params: [ 'limit' ],
	expect: { '': {} }
});

const callClear = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_clear',
	expect: { '': {} }
});

const callClearLog = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_clear_log',
	expect: { '': {} }
});

const callTestNow = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_test_now',
	expect: { '': {} }
});

/* Outage guard (2026-11-03): manual accelerated re-check of the whole
 * learned list — entries answering directly are unlearned within minutes. */
const callRecheck = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_recheck',
	expect: { '': {} }
});

const callHelpersInstall = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_helpers_install',
	expect: { '': {} }
});

const callBackup = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_backup',
	expect: { '': {} }
});

const callRestore = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_restore',
	params: ['content'],
	expect: { '': {} }
});

const callRestart = rpc.declare({
	object: 'luci.ravnex',
	method: 'diag_service_restart',
	expect: { '': {} }
});

/* Ф1.1b: applies run as tracked operations (stages + server-side verified
 * flag) — poll app_op_status until completed/failed. */
const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

function downloadList(content) {
	const blob = new Blob([content || ''], { type: 'text/plain' });
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'ravnex_learned_list.txt';
	document.body.appendChild(a);
	a.click();
	a.remove();
	URL.revokeObjectURL(a.href);
}

/* Ф1.1b: an apply descriptor from the list-edit RPCs ({hot:true} = instant
 * watched-file sync, {op_id} = a tracked operation). Hot applies resolve at
 * once; operations are polled to the honest verdict (busy attaches to the
 * holder — its restart carries our already-committed change). `after` runs
 * once the apply is settled (refresh etc.); okText overrides the success
 * line (the same helper also polls the Restart-service operation). The
 * verdict lands in the ONE result area of the level via `sink(ok, text)`
 * (ui.action_buttons_result_placement) — the global toast is the fallback. */
function applyLearnedOp(desc, after, okText, sink, el) {
	const report = (ok, text) => {
		/* Audit B3 class (с.193): a watcher that outlived its section
		 * stays silent — the verdict goes nowhere. */
		if (el && !el.isConnected)
			return;
		if (sink)
			sink(ok, text);
		else
			ui.addNotification(null, E('p', {}, text), ok ? 'info' : 'error');
	};
	if (!desc || desc.hot || !desc.op_id) {
		/* Hot applies commit instantly (watched-file sync): a caller that
		 * named its success (okText) gets the verdict at once — silence only
		 * when nothing was actually applied (no descriptor). */
		if (okText && sink && desc && desc.hot)
			sink(true, okText);
		if (after) after();
		return;
	}
	const doneText = okText || _('Learned lists applied and verified.');
	const deadline = Date.now() + 150000;
	const tick = function() {
		return L.resolveDefault(callOpStatus(desc.op_id), {}).then(function(st) {
			/* Audit B3 class: the recursive watcher dies with the section. */
			if (el && !el.isConnected)
				return;
			const op = st && st.op;
			if (op && op.status !== 'completed' && op.status !== 'failed') {
				if (Date.now() > deadline) {
					report(false, _('The apply operation is still running — check the operations journal on the Health center page.'));
					if (after) after();
					return;
				}
				window.setTimeout(tick, 2000);
				return;
			}
			const ok = !!op && op.status === 'completed' && op.verified;
			report(ok, ok ? doneText : _('Apply failed: ') + ((op && (op.detail || op.error)) || _('rpc error')));
			if (after) after();
		});
	};
	tick();
}

/* v3 action button (Ф9.2 hpui family). variant: 'primary' | 'ghost' |
 * 'danger' | '' (plain). A double click must not fire the call twice. */
function btn(label, handler, variant) {
	return E('button', {
		'class': 'hpui-btn' + (variant ? ' hpui-btn-' + variant : ''),
		type: 'button',
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
.hpauto-tabs { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px 0; border-bottom: 2px solid var(--hp-panel-line); }
.hpauto-tab { appearance: none; border: 1px solid transparent; background: var(--hp-panel-bg-2); color: inherit; padding: 7px 16px; border-radius: var(--hp-radius-sm) var(--hp-radius-sm) 0 0; cursor: pointer; font-size: 1em; font-weight: 500; }
.hpauto-tab:hover { background: rgba(128,128,128,.20); }
.hpauto-tab.active { background: var(--hp-accent-soft); border-color: var(--hp-accent-line); color: var(--hp-accent-strong); font-weight: 700; }
.hpauto-pane { display: none; }
.hpauto-pane.active { display: block; }
.hpauto-cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }
.hpauto-card { flex: 1 1 140px; min-width: 130px; padding: 10px 14px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); }
.hpauto-num { font-size: 1.7em; font-weight: 700; line-height: 1.25; }
.hpauto-cap { font-size: .85em; opacity: .75; }
.c-red { color: var(--hp-red); } .c-green { color: var(--hp-accent-strong); }
.c-blue { color: var(--hp-blue); } .c-grey { color: var(--hp-grey); }
.c-amber { color: var(--hp-amber); }
.hpauto-banner { margin: 8px 0; padding: 8px 12px; border-radius: var(--hp-radius-sm); border: 1px solid var(--hp-amber-line); background: var(--hp-amber-soft); }
.hpauto-banner-ok { border-color: var(--hp-accent-line); background: var(--hp-accent-soft); }
.hpauto-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.hpauto-toolbar input[type="text"] { flex: 1 1 200px; min-width: 150px; }
.hpauto-wrap { max-height: 62vh; overflow: auto; border: 1px solid var(--hp-panel-line-strong); border-radius: var(--hp-radius-sm); margin-top: 6px; }
table.hpauto-table { border-collapse: separate; border-spacing: 0; width: 100%; }
table.hpauto-table thead th { position: sticky; top: 0; z-index: 2; background: var(--hp-table-head); color: #f5f5f5; text-align: left; font-weight: 600; padding: 8px 10px; white-space: nowrap; border-bottom: 1px solid rgba(0,0,0,.35); }
table.hpauto-table thead th.hpsort { cursor: pointer; }
table.hpauto-table tbody td { padding: 6px 10px; border-bottom: 1px solid rgba(128,128,128,.18); vertical-align: middle; }
table.hpauto-table tbody tr:hover td { background: rgba(128,128,128,.13); }
tr.hpsrc-manual td:first-child { box-shadow: inset 3px 0 0 var(--hp-blue); }
tr.hpsrc-manual.hpsrc-manual-direct td:first-child { box-shadow: inset 3px 0 0 #b0b0b0; }
.hpbadge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: .82em; font-weight: 600; white-space: nowrap; border: 1px solid transparent; }
.hpb-blocked { background: var(--hp-red-soft); color: var(--hp-red); border-color: var(--hp-red-line); }
.hpb-direct { background: var(--hp-accent-soft); color: var(--hp-ink-green); border-color: var(--hp-accent-line); }
.hpb-pending { background: var(--hp-amber-soft); color: var(--hp-ink-amber); border-color: var(--hp-amber-line); }
.hpb-noproxy { background: rgba(255,128,0,.14); color: var(--hp-amber-hot); border-color: rgba(255,128,0,.45); }
.hpb-mproxy { background: var(--hp-blue-soft); color: var(--hp-blue); border-color: var(--hp-blue-line); }
.hpb-mdirect { background: var(--hp-grey-soft); color: var(--hp-ink-grey); border-color: var(--hp-grey-line); }
.hpb-type { background: rgba(128,128,128,.13); border-color: rgba(128,128,128,.28); color: inherit; opacity: .85; }
.hpauto-why { font-size: .88em; opacity: .65; }
.hpchip { appearance: none; border: 1px solid var(--hp-panel-line-strong); background: transparent; color: inherit; border-radius: 8px; padding: 2px 8px; margin-right: 4px; font-size: .8em; cursor: pointer; opacity: .7; }
.hpchip:hover { opacity: 1; background: rgba(128,128,128,.15); }
.hpchip.on { background: var(--hp-blue-soft); border-color: var(--hp-blue); color: var(--hp-blue); font-weight: 700; opacity: 1; }
.hpchip.on.hpc-direct { background: rgba(154,154,154,.25); border-color: #8a8a8a; color: inherit; }
.hpdel { appearance: none; border: none; background: transparent; color: var(--hp-red); font-weight: 700; cursor: pointer; font-size: 1.05em; padding: 2px 8px; border-radius: var(--hp-radius-sm); opacity: .55; }
.hpdel:hover { opacity: 1; background: var(--hp-red-soft); }
/* Action rows: buttons in ONE row (Ф9.3/D34e), compact card-tool sizing. */
.automation-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.automation-actions .hpui-btn { padding: 5px 12px; font-size: .88em; }
.hpauto-result { margin: 8px 0 0; min-height: 1em; }
.hpauto-panel { border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); padding: 12px 14px; background: var(--hp-panel-bg); margin: 10px 0; box-shadow: var(--hp-shadow); }
.hpauto-panel h4 { margin: 0 0 8px 0; }
.hpauto-eng-charts { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0; }
.hpauto-eng-chart { flex: 1 1 220px; min-width: 190px; max-width: 330px; }
.hpauto-eng-chart-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.hpauto-eng-chart-title { font-size: .85em; opacity: .8; }
.hpauto-eng-chart-num { font-weight: 700; }
.hpauto-eng-svg { width: 100%; height: 84px; display: block; margin-top: 2px; border-bottom: 1px solid var(--hp-panel-line); }
.hpauto-eng-chart-max { font-size: .74em; opacity: .6; text-align: right; margin: 0; }
.hpauto-eng-note { font-size: .8em; opacity: .7; margin: 4px 0 0 0; }
.hpauto-eng-kinds { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 8px 0 2px 0; }
.hpauto-eng-ev { display: flex; gap: 8px; font-size: .85em; margin: 2px 0; align-items: baseline; }
.hpauto-eng-ev .t { opacity: .6; white-space: nowrap; font-size: .92em; }
.hpauto-eng-ev .m { word-break: break-word; }
.hpauto-expert { margin: 12px 0; }
.hpauto-expert summary { cursor: pointer; font-weight: 600; opacity: .8; padding: 6px 0; user-select: none; }
.hpauto-expert summary:hover { opacity: 1; }
.hpauto-feed { margin: 6px 0; }
.hpauto-feed-ev { display: flex; gap: 8px; font-size: .85em; margin: 2px 0; align-items: baseline; }
.hpauto-feed-ev .t { opacity: .6; white-space: nowrap; font-size: .92em; }
.hpauto-feed-ev .m { word-break: break-word; }
/* The DPI auto-pilot block moved from the Strategy master page (Ф7.1) —
 * same visual language, the wiz-* classes live here now too. */
.wiz-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); margin: 6px 0; }
.wiz-note { font-size: .88em; opacity: .8; margin: 8px 0; }
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
			uci.load('ravnex')
		]);
	},

	render: function(data) {
		/* App shell (R3 v2): sidebar + topbar + dual theme (implies uiStyle). */
		hp.uiShell();

		const m = new form.Map('ravnex');
		/* Ф7.1/U4: TWO sections over the SAME UCI section — the master switch
		 * stays visible on the level, every other knob is EXPERT (collapsed
		 * into a <details> after render). The geo/RU-protection options moved
		 * to the Connection page card (Ф7.2 — a routing invariant, not an
		 * automation setting; the UCI keys stay automation.*). */
		const s = m.section(form.NamedSection, 'automation', 'ravnex', '');

		let o = s.option(form.Flag, 'enabled', _('Enable automation'),
			_('Automatically learn blocked sites: traffic that fails directly but works through the proxy is added to the Routing Rules lists. Fully compatible with ByeDPI and Zapret — learned sites simply use your configured main path.<br>'
			+ '<b>Mode notes:</b> active only in "Bypass blocking". Automatically paused in "Everything through node" (everything tunnels anyway, nothing to learn), while the Main node is Direct (no proxy side to verify against), and in "Direct" mode (all mechanisms are off).<br>'
			+ '<b>How saving works here:</b> this switch and the expert settings apply after «Save & Apply» at the bottom of the page; the auto-pilot panel and the steering toggle below save instantly with their own buttons.'));
		o.rmempty = false;

		/* The expert section: SAME UCI section, every knob hidden by default. */
		const sx = m.section(form.NamedSection, 'automation', 'ravnex', _('Expert settings'));

		o = sx.option(form.ListValue, 'mode', _('Mode'));
		o.value('balanced', _('Balanced'));
		o.value('aggressive', _('Aggressive (also re-verifies learned sites)'));
		o.default = 'balanced';

		o = sx.option(form.ListValue, 'performance', _('Performance profile'),
			_('eco: serial probing for weak routers (still uses the native probe_pool batch when the helper is installed, capped at 8 concurrent probes). perf: up to 64 domains / 32 IPs per pass in parallel batches (16 at once) — for multi-core routers (e.g. GL.iNet Flint 2). auto: detected from CPU cores and memory.'));
		o.value('auto', _('Auto (detect by hardware)'));
		o.value('eco', _('Eco — serial, weak routers'));
		o.value('perf', _('Performance — parallel, strong routers'));
		o.default = 'auto';

		o = sx.option(form.MultiValue, 'discover', _('Discover candidates from'),
			_('Domain-name sources to watch for candidates. Raw-IP destinations are a separate switch below (“Learn IP destinations”).'));
		o.value('dns', _('DNS query log (captures domain at DNS time — most transparent)'));
		o.value('clash', _('Clash API (connections, domain names)'));
		o.value('sni', _('TLS SNI capture (ClientHello — DoH clients, hardcoded-IP apps, games)'));
		o.default = [ 'dns', 'clash', 'sni' ];
		o.rmempty = false;
		/* Legacy configs store a single string ('all' | 'both' | 'clash' | ...) — map
		 * it to the equivalent checkbox set for display, so nothing looks unchecked. */
		o.cfgvalue = function() {
			let v = uci.get('ravnex', 'automation', 'discover');
			if (v == null) return this.default;
			if (!Array.isArray(v)) v = [ v ];
			if (v.length === 0 || v.includes('all')) return [ 'dns', 'clash', 'sni' ];
			if (v.includes('both')) v = v.filter(function(x) { return x !== 'both'; }).concat([ 'dns', 'clash' ]);
			return v.filter(function(x) { return [ 'dns', 'clash', 'sni' ].includes(x); });
		};

		o = sx.option(form.Value, 'max_entries', _('Maximum learned entries'));
		o.datatype = 'uinteger';
		o.placeholder = '2000';

		/* ч.69: engine-internal knobs are gone from the UI (probe timeout,
		 * confirmations, adaptive flags, discovery weights, helper toggles,
		 * CDN exclusion, HTTP/2 probing — all are autonomous now). Only the
		 * genuinely behavioral choices remain. */

		o = sx.option(form.Value, 'reeval_interval', _('Re-evaluate learned interval (seconds)'));
		o.datatype = 'uinteger';
		o.placeholder = '3600';

		o = sx.option(form.TextValue, 'exclude', _('Never auto-learn'),
			_('Domains / IPs excluded from learning (substring & domain match). One entry per line or comma-separated; lines starting with # are comments, blank lines allowed - organize the list as you like.') + ' '
			+ _('Defaults when empty: localhost, local, lan, in-addr.arpa, ip6.arpa.'));
		o.placeholder = 'localhost\nlocal\nlan\n# my own notes:\n# example.com\nin-addr.arpa,ip6.arpa';
		o.rows = 8;
		o.monospace = true;
		o.wrap = false;

		o = sx.option(form.Flag, 'ip_learn', _('Learn IP destinations'),
			_('Watch recurring conntrack destinations (games, Telegram data centers, apps without SNI) and learn those that fail directly but answer through the proxy. Off by default — enable if you use such apps.'));
		o.default = o.disabled;

		o = sx.option(form.Flag, 'poison_verify', _('Verify DNS-poison verdicts by the plain answer'),
			_('Before a plain-vs-DoH mismatch is treated as DNS poisoning, the direct probe answer from the plain-view IP must be a real site response (no block/stub page, no TLS anomaly, no cross-host redirect). Anycast/geo divergence on CDN hosts (github.com, google.com, dl.google.com…) then no longer produces false “Blocked (DNS)” verdicts, while a real ISP stub — which never answers cleanly — is still learned instantly. Applied after Restart service.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = sx.option(form.Flag, 'poison_asn_check', _('Cymru origin-ASN check (second layer)'),
			_('For mismatches the first layers cannot classify: the plain-view IP is looked up via Team Cymru origin ASN (TXT over DoH through the tunnel) and cached by network prefix — one answer covers the whole range. If the ASN belongs to a CDN/anycast network (Google, Cloudflare, Microsoft, Akamai, Amazon, Fastly…), the mismatch is not poisoning. Adds an external lookup only for candidates that stayed ambiguous; extend the list via /etc/ravnex/resources/cdn_asn.txt (one ASN number per line). Applied after Restart service.'));
		o.default = o.disabled;

		o = sx.option(form.Value, 'sni_sniffer_interface', _('SNI capture interface'),
			_('Network interface the SNI capture (native sniffer or tcpdump) listens on.'));
		o.datatype = 'string';
		o.placeholder = 'br-lan';

		/* NOTE: legacy UCI keys reload_interval / flush_min_entries are intentionally
		 * NOT exposed: learned entries hot-reload into the running core with no restart
		 * and no dropped connections, so batching windows serve no purpose. The daemon
		 * keeps honoring the defaults for old configs.
		 * NOTE (Ф7.2): geo_protect / geo_auto_update / geo_update_hours moved to the
		 * RU-protection card on the Connection page (a routing invariant — the UCI
		 * keys stay homeproxy.automation.*, only the UI home changed). */

		/* ── Custom tabbed UI ──────────────────────────────────────────── */

		injectStyle();

		/* v3 result placement: every action answers in ONE place per level
		 * (a line under the level's action row, replacing the previous
		 * verdict) — no scattered global toasts (D34e). */
		function resultNote(el, ok, text) {
			el.replaceChildren(E('p', { 'class': 'hpauto-result' }, [
				E('span', { 'class': ok ? 'hpui-c-green' : 'hpui-c-red' }, [ text ])
			]));
		}
		function resultBusy(el, text) {
			el.replaceChildren(E('p', { 'class': 'hpauto-result hpui-hint', 'style': 'margin:8px 0 0' },
				[ text || _('Please wait…') ]));
		}

		/* Ф7.1: THREE logical levels instead of the settings zoo (U4). */
		const TABS = [
			[ 'engine', _('Auto-bypass') ],
			[ 'dpi', _('DPI auto-pilot') ],
			[ 'logs', _('Logs') ]
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
		panes.engine.classList.add('active');

		const state = { data: null, search: '', filter: 'all', sortKey: 'added', sortDir: -1, sig: null,
			stats: null, statsRun: false, statsFresh: false, engSig: null, evSig: null, kdSig: null,
			apSig: null, feedSig: null };

		const pauseReasons = {
			disabled: _('Automation is disabled — turn on the switch above to start learning.'),
			custom: _('Automation is paused: a legacy custom routing mode is active — the engine has no preset pools to learn from. Switch to "Bypass blocking" to resume.'),
			global: _('Automation is paused: "Everything through node" tunnels everything — there is nothing left to learn. Switch to "Bypass blocking" to resume.'),
			direct_mode: _('Automation is paused: "Direct" mode is on — all bypass mechanisms are off. Switch back to "Bypass blocking" to resume.'),
			direct: _('Automation is paused: Main node is Direct (no proxy) — there is no proxy side to verify against. Choose URLTest or a node as Main node to resume.'),
			outage: _('Automation is paused: network outage — the direct-path baseline (control sites) does not answer, so failed probes are NOT recorded as blocks. Learning resumes automatically once the connection is back.')
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

		/* ── Engine level: status + sites (Ф7.1 merge of Overview+Sites) ── */
		const ovCards = E('div', { 'class': 'hpauto-cards' });
		const pauseEl = E('div', { 'class': 'hpauto-banner', style: 'display:none' });
		const geoLine = E('div', { 'class': 'hpui-hint' });
		const helperLine = E('div', { 'class': 'hpui-hint' });
		panes.engine.appendChild(ovCards);
		panes.engine.appendChild(pauseEl);
		panes.engine.appendChild(geoLine);
		panes.engine.appendChild(helperLine);
		/* The Sites table (the RESULT of learning) follows the status. */
		const sitesBox = E('div', {});
		panes.engine.appendChild(sitesBox);

		/* ── Engine overview panel (Ф5, ч.77) — the graphical engine view
		 * that replaced the removed exit-health card (decision D2). Cards +
		 * inline-SVG sparklines (no external libraries, D5), verdict
		 * distribution, discovery-source activity and a recent-events
		 * feed. Data: the small automation_stats file the daemon writes
		 * every cycle (read via the light automation_stats RPC). ──────── */
		const engHint = E('div', { 'class': 'hpui-hint', style: 'margin:0 0 6px 0' });
		/* Ф8-F3: Master-rule protection transparency — the user must see that
		 * resources covered by their configured rules never enter learning. */
		const engProtect = E('div', { 'class': 'hpauto-eng-note', style: 'margin:0 0 6px 0' });
		/* Outage guard (2026-11-03): network-outage / re-check state line. */
		const engOutage = E('div', { 'class': 'hpauto-eng-note', style: 'display:none; margin:0 0 6px 0' });
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
			engOutage,
			engCards,
			engCharts,
			engCap,
			engKinds,
			engSrc,
			E('div', { 'class': 'hpauto-eng-note', style: 'font-weight:600; margin-top:10px' }, [ _('Recent events') ]),
			engEvents
		]);
		panes.engine.appendChild(engPanel);

		const engResult = E('div', { 'class': 'hpauto-result' });
		const engActions = E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Test now'), function() {
				resultBusy(engResult, _('Probing…'));
				return callTestNow().then(function() {
					resultNote(engResult, true, _('Probe pass started — fresh results land in the table and the engine cards.'));
					return refresh();
				});
			}),
			btn(_('Install helpers'), function() {
				resultBusy(engResult);
				return callHelpersInstall().then(function(r) {
					if (!r || r.error) {
						resultNote(engResult, false, _('Helpers install failed: ') + ((r && r.error) || ''));
						return;
					}
					const line = (t) => {
						const d = r[t] || {};
						return t + ' — ' + (d.installed ? _('installed') : _('failed') + ': ' + (d.error || ''));
					};
					const ok = (r.probe_pool && r.probe_pool.installed) || (r.sni_sniffer && r.sni_sniffer.installed);
					resultNote(engResult, !!ok,
						_('Native helpers') + ': ' + line('probe_pool') + ' · ' + line('sni_sniffer'));
					return refresh();
				});
			}),
			btn(_('Restart service'), function() {
				/* Ф1.1b: the restart is a tracked operation — poll to the
				 * honest verified verdict instead of a wishful no-op. */
				resultBusy(engResult);
				return callRestart().then(function(r) {
					if (!r || (r.result === false && !r.op_id)) {
						resultNote(engResult, false, _('Restart failed: ') + ((r && r.error) || _('rpc error')));
						return;
					}
					return applyLearnedOp({ op_id: r.op_id }, function() {},
						_('Service restarted and verified.'),
						function(ok, text) { resultNote(engResult, ok, text); },
						engResult);
				});
			})
		]);
		panes.engine.appendChild(engActions);
		panes.engine.appendChild(engResult);

		/* ── Sites (the RESULT of learning — inside the engine level) ──── */
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
		/* ONE result area of the Sites level: every action here (add, pins,
		 * delete, backup/restore/clear/re-check) answers in this line. */
		const sitesResult = E('div', { 'class': 'hpauto-result' });
		const addBtn = btn(_('+ Add'), function() {
			const v = validEntry(addInput.value);
			if (!v) {
				resultNote(sitesResult, false, _('Invalid entry: use a domain name or an IP address.'));
				return Promise.resolve();
			}
			return callEntryAdd(v, addAction.value).then(function(r) {
				if (r && r.result === false)
					resultNote(sitesResult, false, _('Add failed: ') + (r.error || ''));
				else
					resultNote(sitesResult, true, _('Entry added: %s.').format(v));
				addInput.value = '';
				return refresh();
			});
		}, 'primary');

		const sitesSink = function(ok, text) { resultNote(sitesResult, ok, text); };

		const fileInput = E('input', { type: 'file', accept: '.txt,text/plain', style: 'display:none' });
		fileInput.addEventListener('change', function() {
			const file = fileInput.files[0];
			if (!file) return;
			const reader = new FileReader();
			reader.onload = function() {
				callRestore(String(reader.result)).then(function(r) {
					if (!r || r.result === false)
						resultNote(sitesResult, false, _('Restore failed: ') + ((r && r.error) || ''));
					else
						resultNote(sitesResult, true, _('Restore complete — added %d site(s).').format(r.added || 0));
					return applyLearnedOp(r && r.apply, refresh, null, sitesSink, sitesResult);
				}).catch(function(e) {
					resultNote(sitesResult, false, _('Restore failed: ') + e);
				});
			};
			reader.readAsText(file);
			fileInput.value = '';
		});

		const tableEl = E('div', {});
		const tableMeta = E('div', { 'class': 'hpui-hint' });
		sitesBox.appendChild(E('div', { 'class': 'hpauto-toolbar' }, [
			searchEl, filterEl,
			E('span', { style: 'flex:1' }),
			addInput, addAction, addBtn
		]));
		sitesBox.appendChild(tableEl);
		sitesBox.appendChild(tableMeta);
		sitesBox.appendChild(E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Backup list'), function() {
				return callBackup().then(function(r) {
					if (!r || r.result === false) {
						resultNote(sitesResult, false, _('Backup failed: ') + ((r && r.error) || _('no learned list yet')));
						return;
					}
					downloadList(r.content || '');
					resultNote(sitesResult, true, _('Backup downloaded.'));
				});
			}),
			btn(_('Restore list'), function() { fileInput.click(); }),
			btn(_('Clear learned'), function() {
				return hp.confirmModal(_('Clear learned'),
					_('Delete ALL learned sites? The engine will re-learn them from scratch.'), _('Delete all'))
					.then(function(ok) {
						if (!ok)
							return null;
						return callClear().then(function(r) {
							if (r && r.result === false)
								resultNote(sitesResult, false, _('Clear failed: ') + ((r && r.error) || ''));
							return applyLearnedOp(r && r.apply, refresh, null, sitesSink, sitesResult);
						});
					});
			}, 'danger'),
			btn(_('Re-check learned'), function() {
				return callRecheck().then(function(r) {
					if (r && r.result === false)
						resultNote(sitesResult, false, _('Re-check failed to start: ') + ((r && r.error) || ''));
					else
						resultNote(sitesResult, true, _('Re-check started: %d entries queued — entries that answer directly will be removed from the learned list within a few minutes.').format((r && r.queued) || 0));
					return refresh();
				});
			})
		]));
		sitesBox.appendChild(sitesResult);
		sitesBox.appendChild(fileInput);
		sitesBox.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Pins are the manual exceptions of the automation: “Always direct” is the only per-host override that outranks ALL rules (service rules included) — applied instantly, no core restart; “Always proxy” keeps the site on the proxy, protects it from automatic un-learning and re-checks, and works even with the automation toggle off. “Auto” returns the entry to the engine; a deleted entry may be re-learned later if it is genuinely blocked — pin it “Always direct” to prevent that. The engine itself always follows the service rules: hosts covered by a service rule are never learned — see the Master-rule protection line on the Engine level.') ]));
		/* U6 (Ф4.3) + variant A: the honest scope and precedence of a pin. */
		sitesBox.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('A pin covers exactly this host and its subdomains — not the whole service: CDN, API and other service domains are not covered and follow their own rules. “Always via proxy” rides the main node BELOW the service rules (an enabled service rule wins — such a pin is refused), while “Always direct” rides the direct path ABOVE everything. Verify the real route on the Service rules page, "Check a route".') ]));

		/* ── Logs level (Ф7.1): the engine log + the automation-family
		 * Event Bus feed (Ф7.3 — the same journal the Health center renders,
		 * filtered to the automation family: learn/heal/outage, Hot Swap
		 * switches, URLTest watchdog, DPI auto-pilot decisions). ───────── */
		const logEl = E('pre', { 'class': 'hpui-log' });
		const logsResult = E('div', { 'class': 'hpauto-result' });
		panes.logs.appendChild(E('h4', {}, [ _('Engine log') ]));
		panes.logs.appendChild(logEl);
		panes.logs.appendChild(E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Clear log'), function() {
				return callClearLog().then(function() {
					resultNote(logsResult, true, _('Log cleared.'));
					return refresh();
				});
			}, 'danger')
		]));
		panes.logs.appendChild(logsResult);
		panes.logs.appendChild(E('h4', { style: 'margin-top:16px' }, [ _('Automation events') ]));
		const feedEl = E('div', { 'class': 'hpauto-feed' });
		panes.logs.appendChild(feedEl);
		panes.logs.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('The shared event journal of the automation family — learning, self-heals, Hot Swap switches, the URLTest watchdog and the DPI auto-pilot. The full feed of every subsystem lives on the Health center page.') ]));

		/* ── DPI auto-pilot level (Ф7.1): the scheduled strategy auto-pilot
		 * moved here from the Strategy master page — an always-on keeper is
		 * automation, not a strategy-setting. Same RPCs, same save contract;
		 * the one-click auto-pick and the Strategy Lab stay on the bypass
		 * page (they belong to measuring). ────────────────────────────── */
		const apBadge = (cls, text) => E('span', { 'class': 'hpui-badge ' + cls }, [ text ]);
		/* ч.233: Telegram убран из автопилота (решение пользователя — без
		 * VPN/туннеля tg в РФ не поднимается; автоперебор лишь тратит время). */
		const apRes = { youtube: E('input', { type: 'checkbox' }),
			discord: E('input', { type: 'checkbox' }),
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
		/* Ф6.7: ночной автоподбор (01:00–06:00, только если лучше) — опция. */
		const apNight = E('input', { type: 'checkbox' });
		const apSave = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' }, [ _('Save auto-pilot') ]);
		const apAlive = E('span', { 'class': 'wiz-note', style: 'margin:0' }, [ '' ]);
		const apNames = { youtube: _('YouTube'), discord: _('Discord'),
			general: _('General (best overall)') };
		const apStatus = E('div', {});
		const apSaveMsg = E('div', { 'class': 'wiz-note', style: 'margin:4px 0 0 0' }, [ '' ]);
		const apHead = E('div', { 'class': 'wiz-row', style: 'margin-top:8px' },
			[ E('strong', {}, [ _('Auto-pilot (scheduled)') ]), apAlive ]);
		const apRow1 = E('div', { 'class': 'wiz-row' },
			[ E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer; font-weight:600' },
				[ apEnabled, ' ' + _('Enable the auto-pilot') ]), apSave ]);
		const apResWrap = E('div', { 'class': 'wiz-row' });
		/* ч.233: Telegram убран из автопилота — чекбокс, hint и имя не нужны
		 * (статус-грид ниже идёт по ключам apRes, строка tg исчезает сама). */
		const apHints = {};
		[ ['youtube', _('YouTube')], ['discord', _('Discord')],
		  ['general', _('General (best overall)')] ]
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
			  apWin,
			  E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer',
				title: _('Night auto-pick (01:00–06:00): a scheduled re-rank is allowed at night even outside the maintenance window — it applies only a strategy that is measurably better.') },
				[ apNight, ' ' + _('Night auto-pick') ]) ]);
		panes.dpi.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('The DPI auto-pilot keeps the bypass strategies working without attention: on schedule it re-ranks the tested strategies and applies the best one per resource; when a resource stops answering, the next alternative applies immediately. Every apply takes a server snapshot (Restore stays available) and verifies the resource live. One-click picks and fresh measurements live on the Strategy master page — the Strategy Lab.') ]));
		/* ч.274 (user decision): the ghost lab-link is gone — the hint above is
		 * the pointer, and the nav card/sidebar already lead to the page. */
		panes.dpi.appendChild(E('div', { style: 'margin-top:10px; border-top:1px solid var(--hp-panel-line); padding-top:8px' },
			[ apHead, apRow1, apResWrap, apRow3, apSaveMsg, E('p', { 'class': 'wiz-note' },
				[ _('The auto-pilot keeps the strategies working without attention: on schedule it re-ranks the corpus and applies the best strategy per resource (a >10% win replaces the current one); when a resource fails the checks repeatedly, the next alternative applies immediately. The "apply in window" time gate applies to the scheduled re-rank only — health checks and repairs run around the clock. With "Keep the rules on Zapret" the managed resources get their rule pointed at Zapret — a strategy serves a resource only through its rule. Every apply takes a server snapshot — Restore always reverts. ByeDPI strategies are not managed.') ]), apStatus ]));
		/* Сеанс 191: стиринг мёртвых пулов — ПОВЕДЕНИЕ системы, место на
		 * Автообходе (панель после «DPI auto-pilot», до остального контента). */
		const steerBox = E('input', { type: 'checkbox' });
		steerBox.checked = (uci.get('ravnex', 'config', 'yt_steer_dead') === '1');
		const steerNote = E('p', { 'class': 'wiz-note', style: 'margin:4px 0 0 0' });
		const steerClear = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' },
			[ _('Forget learned pools') ]);
		steerClear.addEventListener('click', function() {
			/* сеанс 198 (audit tail): the themed modal (one modal pattern)
			 * replaces the native confirm; a dismiss takes no action. */
			hp.confirmModal(_('Forget learned pools'),
				_('Forget the learned dead YouTube pools? The core config regenerates (a short connection blip); an ALIVE pool will not be re-learned (the content guard), a dead one returns on its own within minutes.'), _('Forget'))
				.then(function(ok) {
					if (!ok)
						return;
					steerClear.disabled = true;
					resultNote(steerNote, true, _('Applying…'));
					L.resolveDefault(callYtSteerLearnedClear(), {}).then(function(r) {
						steerClear.disabled = false;
						if (r && r.result === true) {
							resultNote(steerNote, true, _('Learned pools forgotten — the config is regenerated.'));
							return;
						}
						resultNote(steerNote, false, _('Failed: ') + ((r && r.error) || _('rpc error')));
					});
				});
		});
		steerBox.addEventListener('click', function() {
			const want = steerBox.checked ? '1' : '0';
			resultNote(steerNote, true, _('Saving…'));
			L.resolveDefault(callYtSteerSet(want), {}).then(function(r) {
				if (r && r.result === true) {
					resultNote(steerNote, true, (r.unchanged ? _('Steering already in this state.') :
						((want === '1') ? _('Steering ON — MultiDNS picks it up on its next tick (dead pools answer 0.0.0.0).')
							: _('Steering OFF — the refuse set is cleared on the next MultiDNS tick.'))));
					return;
				}
				steerBox.checked = !steerBox.checked;
				resultNote(steerNote, false, _('Save failed: ') + ((r && r.error) || _('rpc error')));
			});
		});
		panes.dpi.appendChild(E('div', { style: 'margin-top:10px; border-top:1px solid var(--hp-panel-line); padding-top:8px' },
			[ E('div', { 'class': 'wiz-row' },
				[ E('strong', {}, [ _('Dead-pool steering') ]),
				  E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
					[ steerBox, ' ' + _('Steer dead YouTube pools (DNS refuse)') ]), steerClear ]),
			  E('p', { 'class': 'wiz-note' },
				[ _('Pools that never delivered a single alive edge under ANY measured strategy (dead whole, fresh ≤48 h) are DNS-REJECTED in the core config: instant refusal, the player switches to a live edge in milliseconds instead of hanging 5–10 s. The pool catalog is maintained by the Strategy Lab sweeps; the pool currently serving the stream is never refused; an empty catalog means nothing is refused. Toggling regenerates the core config (verified apply). The catalog feeder runs inside MultiDNS (mosdns).') ]),
			  steerNote ]));

		let apDirty = false;
		for (let k in apRes)
			apRes[k].addEventListener('change', function() { apDirty = true; });
		apEnabled.addEventListener('change', function() { apDirty = true; });
		apRules.addEventListener('change', function() { apDirty = true; });
		apMode.addEventListener('change', function() { apDirty = true; });
		apInterval.addEventListener('input', function() { apDirty = true; });
		apCheck.addEventListener('input', function() { apDirty = true; });
		apWin.addEventListener('input', function() { apDirty = true; });
		apNight.addEventListener('change', function() { apDirty = true; });
		apSave.addEventListener('click', function() {
			const res = [];
			for (let k in apRes)
				if (apRes[k].checked)
					res.push(k);
			if (apEnabled.checked && !res.length) {
				resultNote(apSaveMsg, false, _('Select at least one resource for the auto-pilot.'));
				return;
			}
			const turningOn = apEnabled.checked;
			const doSave = function() {
				apSave.disabled = true;
				L.resolveDefault(callAutoPilotSet(
					apEnabled.checked ? '1' : '0', res.join(' '),
					apRules.checked ? '1' : '0',
					String(parseInt(apInterval.value, 10) || 6),
					String(parseInt(apCheck.value, 10) || 15),
					apWin.value || '', apMode.value || 'quick',
					'2', apNight.checked ? '1' : '0'), {}).then(function(r) {
					apSave.disabled = false;
					if (!r || r.result !== true) {
						resultNote(apSaveMsg, false, _('Auto-pilot save failed: %s').format((r && r.error) || _('rpc error')));
						return;
					}
					apDirty = false;
					state.apSig = null;   /* refill from the saved config */
					resultNote(apSaveMsg, true, (turningOn)
						? _('Auto-pilot enabled — the daemon picks it up within a minute (first re-rank right away).')
						: _('Auto-pilot settings saved — the daemon reads them on its next tick.'));
					refresh();
				});
			};
			if (turningOn) {
				hp.confirmModal(_('Enable auto-pilot'),
					_('Enable the strategy auto-pilot? It will manage the Zapret strategies of the selected resources automatically (scheduled re-ranks, immediate re-picks on failures) and — with the rules option — keep their rules on Zapret.'), _('Enable'))
					.then(function(ok) { if (ok) doSave(); });
				return;
			}
			doSave();
		});

		function renderAutoPilot(data) {
			const cfg = (data && data.config) || null;
			const st = (data && data.status) || null;
			const ok = !!(data && data.daemon_ok);
			apAlive.textContent = ok ? '' : '— ' + _('daemon is not responding');
			if (cfg && (state.apSig == null || (!apDirty && state.apSig !== JSON.stringify(cfg)))) {
				state.apSig = JSON.stringify(cfg);
				apEnabled.checked = !!cfg.enabled;
				apRules.checked = (cfg.set_rules !== false);
				apMode.value = (cfg.fuzz_mode === 'full') ? 'full' : 'quick';
				for (let k in apRes)
					apRes[k].checked = ((cfg.resources || '').split(/\s+/).indexOf(k) >= 0);
				apInterval.value = cfg.interval_h || 6;
				apCheck.value = cfg.check_min || 15;
				apWin.value = cfg.window || '';
				apNight.checked = (cfg.night_pick === true);
			}
			apStatus.textContent = '';
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
			if (st && st.manual_hold) {
				/* Сеанс 158/Б8: возраст удержания + явное снятие из интерфейса
				 * (Ф6.7: ремонт мёртвого ресурса и успешная переразметка снимают
				 * автоматически; теперь и кнопка — решение пользователя). */
				const holdAge = (st.manual_hold.ts > 0)
					? Math.max(0, Math.round((st.stage_ts > 0 ? st.stage_ts : Date.now() / 1000) - st.manual_hold.ts)) : -1;
				const holdAgeText = (holdAge >= 2880)
					? _('for %d days').format(Math.round(holdAge / 1440))
					: (holdAge >= 120) ? _('for %d hours').format(Math.round(holdAge / 60))
					: (holdAge >= 0) ? _('for %d min').format(holdAge) : '';
				const holdLine = E('div', { 'class': 'wiz-note', style: 'opacity:.9' },
					[ '✋ ' + _('Manual composition hold is active (Hot Swap): the scheduled re-rank is suspended — live checks and dead-resource repairs continue.') +
					  (holdAgeText !== '' ? ' (' + holdAgeText + ')' : '') ]);
				apStatus.appendChild(holdLine);
				apStatus.appendChild(E('div', { style: 'margin:2px 0 0 12px' }, [
					E('button', {
						'class': 'cbi-button cbi-button-negative',
						click: function() {
							this.disabled = true;
							L.resolveDefault(callAutoPilotHoldRelease(), {}).then(function(r) {
								if (r && r.result === true) {
									resultNote(apSaveMsg, true, r.unchanged
										? _('The hold was not active — nothing to release.')
										: _('Hold released — the scheduled re-rank resumes on its schedule (the daemon picks it up within a minute).'));
								} else {
									resultNote(apSaveMsg, false, _('Hold release failed: %s').format((r && r.error) || _('rpc error')));
								}
								refresh();
							});
						}
					}, [ _('Release hold') ])
				]));
			}
			if (st && st.resources) {
				const grid = E('div', { style: 'margin:4px 0 0 12px' });
				/* Сеанс 158/Б8: применённая составная (паритет с ч.231-фиксом
				 * оптимизатора) — «Общий» без победителя автопилота честно
				 * показывает текущую композицию из UCI вместо «—». */
				const curZ = (data && data.current_zapret) || '';
				for (let rk in apRes) {
					const r = st.resources[rk];
					if (!r)
						continue;
					const line = E('div', { 'class': 'wiz-note' });
					const w = r.winner || {};
					let nameText;
					if (st.enabled && r.mgmt === false && rk !== 'general')
						nameText = _('not managed (the rule does not lead to Zapret)');
					else if (w.name)
						nameText = w.name;
					else if (rk === 'general' && curZ.length)
						nameText = _('applied composite (outside the auto-pilot — your choice)');
					else
						nameText = '—';
					line.appendChild(document.createTextNode(apNames[rk] + ': ' + nameText));
					if (rk === 'general' && !w.name && curZ.length)
						line.appendChild(E('span', { 'class': 'wiz-note', style: 'opacity:.75', title: curZ },
							[ ' · ' + curZ.slice(0, 60) + (curZ.length > 60 ? '…' : '') ]));
					if (w.name)
						line.appendChild(document.createTextNode(
							(w.tls_ms > 0 ? ' · ' + _('~%d ms TLS').format(w.tls_ms) : '') +
							(w.stream > 0 ? ' · ' + Math.round(w.stream / 1024) + ' KB/s' : '') +
							(w.start_ms > 0 ? ' · ' + _('start ~%d ms').format(w.start_ms) : '')));
					/* ч.249 honesty (report а/б): a manual pick adopted via Hot Swap 9
					 * stays on the resource until the user changes it — the line must
					 * say so, otherwise the old pick masquerades as the autopilot's
					 * current best (the user compared it with a fresh fuzz run). */
					if (w.name && w.manual)
						line.appendChild(E('span', { 'class': 'wiz-note', style: 'opacity:.75' },
							[ ' · ' + _('manual pick (Hot Swap)') ]));
					const p = r.probe || {};
					if (p && p.ts) {
						/* ч.127 three-state: green = alive, amber = degraded
						 * (slow but working — NO switch happens), red = dead.
						 * The raw note carries the measured detail. */
						line.appendChild(p.ok
							? apBadge('hpui-b-green', '✓ ' + (p.code || '') + ((p.tsec != null) ? (' · ' + p.tsec + ' s') : ''))
							: (p.slow
								? E('span', { 'class': 'hpui-badge hpui-b-amber', title: (p.note || '') },
									[ '⚠ ' + (p.code || '') + ((p.tsec != null) ? (' · ' + p.tsec + ' s') : '') + (p.speed > 0 ? (' · ' + Math.round(p.speed / 1024) + ' KB/s') : '') ])
								: apBadge('hpui-b-red', '✗ ' + (p.code || '000'))));
					}
					if (r.strikes > 0)
						line.appendChild(apBadge('hpui-b-red', '⚠ ' + _('%d failed check(s)').format(r.strikes)));
					if (r.rule_node != null && rk !== 'general')
						line.appendChild(document.createTextNode(
							' · ' + _('rule: %s').format(r.rule_node || _('none'))));
					grid.appendChild(line);
					/* Ф6.7: объяснимый вердикт решения (не чёрный ящик). */
					if (r.explain && r.explain.text)
						grid.appendChild(E('div', { 'class': 'wiz-note', style: 'margin:1px 0 0 12px; opacity:.75' },
							[ '↳ ' + r.explain.text ]));
				}
				apStatus.appendChild(grid);
			}
			/* ч.249 honesty (reports а/б): the freshest LAB measurement + the age
			 * of the autopilot's own verdict — the panel shows both, so the old
			 * pick (often a manual one) is never presented as "the best". One
			 * result place: this line sits under the resource grid, before times. */
			if (data && data.lab_fuzz && data.lab_fuzz.ts) {
				const lv = data.lab_fuzz.verdicts || {};
				const parts = [];
				for (let rk2 in apRes) {
					const v2 = lv[rk2];
					if (v2 == null)
						continue;
					const vt = (v2.verdict === 'best_verified') ? _('verified')
						: (v2.verdict === 'best_available') ? _('available') : v2.verdict;
					/* ч.274 dedgu: the browser sign rides beside the verdict —
					 * absent = the probe class was not measured (honest nothing). */
					const brow = (v2.brow_total > 0)
						? ' · ' + _('browser: %s/%s').format(v2.brow_ok, v2.brow_total) : '';
					parts.push(apNames[rk2] + ' → ' + (v2.name || '—') + ' (' + vt + brow + ')');
				}
				if (parts.length) {
					const ageTxt = (data.lab_fuzz.age >= 6 * 3600)
						? ' · ' + _('older than 6 h — the next re-rank takes a fresh one') : '';
					apStatus.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.8' }, [
						_('Lab measurement from %s: %s').format(
							new Date(data.lab_fuzz.ts * 1000).toLocaleString(),
							parts.join(' · ')) + ageTxt
					]));
				}
			}
			if (st && st.last_apply && st.last_apply.ts > 0)
				apStatus.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.8' },
					[ _('last auto-apply: %s').format(new Date(st.last_apply.ts * 1000).toLocaleString()) ]));
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

		/* ── Table rendering ───────────────────────────────────────────── */

		function statusBadgeBase(e) {
			if (e.src === 'manual_proxy')
				return E('span', { 'class': 'hpbadge hpb-mproxy' }, [ _('Always proxy') ]);
			if (e.src === 'manual_direct')
				return E('span', { 'class': 'hpbadge hpb-mdirect' }, [ _('Always direct') ]);
			/* Ф6.6/B5.17: недавно снятая запись — серый бейдж, причина в «Почему». */
			if (e.src === 'dropped')
				return E('span', { 'class': 'hpbadge hpb-type' }, [ _('Removed') ]);
			if (e.status === 'geo')
				return E('span', { 'class': 'hpbadge hpb-mproxy' }, [ _('Geo (proxied)') ]);
			if (e.status === 'geo_blocked')
				return E('span', { 'class': 'hpbadge hpb-noproxy' }, [ _('Geo-blocked (node)') ]);
			if (e.status === 'upstream_blocked')
				return E('span', { 'class': 'hpbadge hpb-noproxy' }, [ _('Upstream-blocked') ]);
			if (e.status === 'blocked')
				return E('span', { 'class': 'hpbadge hpb-blocked' }, [
					/* сеанс 187 G2: транспортные подп-kind'ы + G1 RKN-подсказка. */
					e.kind === 'dns_poison' ? _('Blocked (DNS)') :
					e.kind === 'stub' ? _('Blocked (stub)') :
					e.kind === 'tls_dpi' ? _('Blocked (DPI)') :
					e.kind === 'tcp_refused' ? _('Blocked (TCP refused)') :
					e.kind === 'connect_timeout' ? _('Blocked (connect timeout)') :
					e.kind === 'tls_timeout' ? _('Blocked (TLS timeout)') :
					e.kind === 'tls_mitm' ? _('Blocked (TLS MITM)') :
					e.kind ? _('Blocked (refusal)') :
					e.rkn_hint ? _('Blocked (listed?)') : _('Blocked') ]);
			if (e.status === 'direct')
				return E('span', { 'class': 'hpbadge hpb-direct' }, [ _('Direct') ]);
			if (e.status === 'direct_pending')
				return E('span', { 'class': 'hpbadge hpb-pending' }, [ _('Direct (pending)') ]);
			if (e.status === 'blocked_no_proxy')
				return E('span', { 'class': 'hpbadge hpb-noproxy' }, [ _('Unreachable') ]);
			return E('span', { 'class': 'hpbadge hpb-type' }, [ e.status || '—' ]);
		}

		/* сеанс 198 G5: активный флап-эпизод — честный оверлей поверх
		 * последнего устойчивого вердикта (вместо мигания alive/dead);
		 * в титуле — число подавленных событий эпизода. */
		function statusBadge(e) {
			const base = statusBadgeBase(e);
			if (e.flapping && int(e.flapping.since) > 0) {
				const wrap = E('span', {});
				wrap.appendChild(base);
				wrap.appendChild(E('span', { 'class': 'hpbadge hpb-pending', style: 'margin-left:4px',
					title: _('Flapping: the verdict flipped repeatedly; it follows the confirmation series, %d events suppressed').format(int(e.flapping.suppressed) || 0) },
					[ _('Flapping') ]));
				return wrap;
			}
			return base;
		}

		/* G4 (REPORT_s188_g4_design.md): провенанс вердикта — ЧЕРЕЗ ЧЬЁ владение
		 * контура он измерен (exit_ctx: узел и/или ISP). Поле отсутствует =
		 * не измерено — строка не рисуется (честная неполнота, не фейк). */
		function provText(e) {
			const c = e.exit_ctx;
			if (!c || (!c.main && !c.isp))
				return '';
			const bits = [];
			if (c.main)
				bits.push('«' + c.main + '»');
			if (c.isp)
				bits.push('ISP ' + c.isp);
			return ' · ' + _('measured via: %s').format(bits.join(', '));
		}

		/* сеанс 198 G3: QUIC-контраст — вторая лейна правды (UDP/443 через
		 * probe_pool -quic-check). Поле отсутствует = не измерено — строка
		 * не рисуется (честная неполнота, никогда не фейк-ноль). silence —
		 * ВЕРОЯТНЫЙ срез (сервер может игнорировать пробу); ctrl='spoofed'
		 * (контроль-проба) помечает недостоверность. */
		function quicText(e) {
			if (!e.quic || !e.quic.v)
				return '';
			const V = { alive: _('QUIC: reachable'), cut: _('QUIC: likely cut'), reject: _('QUIC: rejected') };
			let s = V[e.quic.v] || null;
			if (!s)
				return '';
			if (e.quic_kind === 'tcp_only_block')
				s += ' — ' + _('TCP is blocked but QUIC is alive — the browser may ride HTTP/3');
			else if (e.quic_kind === 'blocked_both')
				s += ' — ' + _('nothing works: neither TCP nor QUIC (likely cut)');
			else if (e.quic_kind === 'quic_dead')
				s += ' — ' + _('QUIC is already cut by the provider — a QUIC reject adds nothing');
			if (e.quic_note === 'unverified')
				s += ' · ' + _('unverified: the control probe says QUIC answers are forged on this path');
			return ' · ' + s;
		}

		function reasonText(e) {
			/* Ф6.6/B5.17: причина снятия записи (единая валидация IP). */
			if (e.src === 'dropped') {
				const DROPS = {
					invalid: _('invalid entry format'),
					private_range: _('private/special-purpose range (IANA registry)'),
					shared_cdn: _('shared CDN address (never learned)'),
					resolver_infrastructure: _('DNS resolver/anycast infrastructure'),
					local: _('the router own address'),
					ru_network: _('RU network (always direct)'),
					ru_ptr: _('RU-TLD reverse DNS (always direct)')
				};
				return _('removed from the lists: %s').format(DROPS[e.drop_reason] || (e.drop_reason || '—'));
			}
			if (e.status === 'geo')
				return _('geo-sensitive service — always routed via proxy');
			if (e.status === 'geo_blocked')
				return _('the service refuses the current exit node — switch node and re-test') + provText(e);
			if (e.status === 'upstream_blocked')
				return _('blocked by your own DNS blocker (0.0.0.0-style answers) — deliberately not learned into the proxy list');
			if (e.src !== 'learned')
				return _('pinned by user');
			if (e.status === 'blocked') {
				/* ч.68: censorship-mechanism verdict from the probe signals. */
				const KINDS = {
					dns_poison: _('DNS poisoning: the ISP resolver served a fake address (confirmed via secure DNS)'),
					stub:       _('ISP block page: the connection is redirected to the provider stub'),
					sigpage:    _('block page served with HTTP 200 (body signature match)'),
					tls_dpi:    _('TLS DPI: the handshake is reset right after ClientHello (SNI filtering)'),
					hardcode:   _('censorship refusal code (403/406/451) — direct is refused, proxy works'),
					/* сеанс 187 G2: транспортные подп-kind'ы (только из полей
					 * щупа; tls_mitm — спящая ветка, на текущей сборке щупа
					 * недостижима — держим честную подпись на будущее). */
					tcp_refused:      _('the TCP dial is refused outright (connection refused / unreachable)'),
					connect_timeout:  _('the TCP dial times out — nothing answers on the direct path'),
					tls_timeout:      _('the TLS handshake is silently dropped after ClientHello (no server reply)'),
					tls_mitm:         _('a TLS certificate substitute answered (MITM shape) — probe class for future probe builds')
				};
				let kind = KINDS[e.kind] || null;
				/* сеанс 198 G5: кандидат в окне тормоза — честная строка
				 * «переход: подтверждено N/2» вместо тихого ожидания. */
				const pend = (e.pending && e.pending.v === 'blocked' && int(e.pending.n) > 0)
					? ' · ' + _('hold: %d/%d confirmations after a recent flip').format(int(e.pending.n), 2)
					: '';
				const flap = (e.flapping && int(e.flapping.since) > 0)
					? ' · ' + _('unstable: %d flips recorded, %d events suppressed').format(int(e.flap_flips) || 0, int(e.flapping.suppressed) || 0)
					: '';
				if (!e.direct && !e.proxy)
					return (kind || _('blocked (details not recorded)')) +
						(e.rkn_hint ? ' · ' + _('also present in the local registry lists (%s) — likely a registry block, not necessarily DPI').format(e.rkn_hint) : '') +
						(e.learn_method === 'tcp' ? ' · ' + _('learned via TCP probe') : '') +
						provText(e) + quicText(e) + pend + flap;
				let d = e.direct || '✗', p = e.proxy || '✓';
				return (kind ? (kind + ' · ') : '') + _('direct %s ✗ / proxy %s ✓').format(d, p) +
					(e.rkn_hint ? ' · ' + _('also present in the local registry lists (%s) — likely a registry block, not necessarily DPI').format(e.rkn_hint) : '') +
					(e.learn_method === 'tcp' ? ' · ' + _('learned via TCP probe') : '') +
					provText(e) + quicText(e) + pend + flap;
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
					callEntryAction(entry.host, mode).then(function(r) {
						return applyLearnedOp(r && r.apply, refresh, null, sitesSink, sitesResult);
					}).finally(function() { b.disabled = false; });
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
			/* Sig-guard: the entries array only changes when the daemon learns/
			 * unlearns or a manual edit happened — rebuilding ~700 rows × 8
			 * cells (fresh listeners) on EVERY 5 s tick for identical data was
			 * the heaviest DOM churn in the app. The view controls (filter/
			 * search/sort) are part of the signature: changing one of them must
			 * still re-render through the early-return path. */
			const sig = JSON.stringify([entries, state.filter, state.search, state.sortKey, state.sortDir]);
			if (sig === state.tableSig)
				return;
			state.tableSig = sig;
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
					delBtn.disabled = true;
					hp.confirmModal(_('Delete entry'), _('Delete entry %s?').format(e.host), _('Delete'))
						.then(function(ok) {
							if (!ok) { delBtn.disabled = false; return; }
							callEntryDelete(e.host).then(function(r) {
								return applyLearnedOp(r && r.apply, refresh, _('Entry deleted.'), sitesSink, sitesResult);
							}).finally(function() { delBtn.disabled = false; });
						});
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

		/* ── Geo cards: REMOVED (Ф7.2) — the RU-protection card (guarantee +
		 * databases + update) lives on the Connection page now. ───────── */

		/* ── Engine overview panel rendering (Ф5) ──────────────────────── */

		const KIND_BADGES = [
			[ 'tls_dpi',    _('Blocked (DPI)') ],
			[ 'dns_poison', _('Blocked (DNS)') ],
			[ 'stub',       _('Blocked (stub)') ],
			[ 'sigpage',    _('Block page') ],
			[ 'hardcode',   _('Blocked (refusal)') ],
			/* сеанс 187 G2: транспортные подп-kind'ы в панели «Вердикты». */
			[ 'tcp_refused',     _('Blocked (TCP refused)') ],
			[ 'connect_timeout', _('Blocked (connect timeout)') ],
			[ 'tls_timeout',     _('Blocked (TLS timeout)') ],
			[ 'tls_mitm',        _('Blocked (TLS MITM)') ]
		];
		/* сеанс 198 G3: QUIC-контраст — счётные классы второй лейны. */
		const QUIC_BADGES = [
			[ 'tcp_only_block', _('QUIC alive, TCP cut') ],
			[ 'blocked_both',   _('cut both (likely)') ],
			[ 'quic_dead',      _('QUIC already dead') ]
		];
		const STATUS_BADGES = [
			[ 'blocked',          _('Blocked') ],
			[ 'direct',           _('Direct') ],
			[ 'direct_pending',   _('Direct (pending)') ],
			[ 'blocked_no_proxy', _('Unreachable') ],
			[ 'geo_blocked',      _('Geo-blocked (node)') ],
			[ 'upstream_blocked', _('Upstream-blocked') ],
			[ 'geo',              _('Geo (proxied)') ]
		];
		const EV_LABELS = {
			learn:  _('Learned'),
			heal:   _('Self-healed'),
			reload: _('Applied to core'),
			poison: _('DNS poison detected'),
			ublock: _('Upstream-blocked detected'),
			pause:  _('Learning paused'),
			resume: _('Learning resumed'),
			clear:  _('Learned list cleared'),
			outage: _('Network outage'),
			outage_end: _('Direct path recovered'),
			recheck: _('Re-check'),
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

			/* Outage guard (2026-11-03): honest engine state while the direct
			 * path is down (learning suspended, nothing poisoned) and while
			 * the accelerated re-check queue drains. One line, one place. */
			const og = st.outage || {};
			const rcq = (st.recheck && st.recheck.pending) || 0;
			let ogText = '';
			if (og.active)
				ogText = '⚠ ' + _('Network outage: the direct-path baseline failed — learning is suspended so failed probes cannot poison the learned list.');
			else if (rcq > 0)
				ogText = '↻ ' + _('Re-check in progress: %d entries left.').format(rcq);
			if (ogText !== state.ogSig) {
				state.ogSig = ogText;
				engOutage.textContent = ogText;
				engOutage.style.display = ogText ? 'block' : 'none';
			}

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
			const quicKinds = v.quic_kinds || {};
			const parts = [];
			for (let s in STATUS_BADGES) {
				const n = v[STATUS_BADGES[s][0]] || 0;
				if (n > 0) parts.push(STATUS_BADGES[s][0] + ':' + n);
			}
			for (let k in KIND_BADGES) {
				const n = kinds[KIND_BADGES[k][0]] || 0;
				if (n > 0) parts.push(KIND_BADGES[k][0] + ':' + n);
			}
			/* сеанс 198 G3: QUIC-классы + честная доля измеренных. */
			let quicParts = [];
			for (let qk in QUIC_BADGES) {
				const qn = quicKinds[QUIC_BADGES[qk][0]] || 0;
				if (qn > 0) quicParts.push(QUIC_BADGES[qk][0] + ':' + qn);
			}
			if ((v.quic_measured || 0) > 0)
				quicParts.unshift('measured:' + v.quic_measured);
			const quicSig = quicParts.join('|');
			parts.push.apply(parts, quicParts);
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
				/* сеанс 198 G3: QUIC-классы — с честной пометкой метода. */
				for (let qk in QUIC_BADGES) {
					const qn = quicKinds[QUIC_BADGES[qk][0]] || 0;
					if (qn > 0)
						engKinds.appendChild(E('span', { 'class': 'hpbadge hpb-type',
							title: _('QUIC lane (UDP/443), probe_pool -quic-check; silence is a LIKELY cut, not proof') },
							[ QUIC_BADGES[qk][1] + ' ' + qn ]));
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
			/* Ф7.1: the DPI auto-pilot rides the same poll. */
			L.resolveDefault(callAutoPilotStatus(), {}).then(renderAutoPilot);
			/* Ф7.3: the automation-family Event Bus feed (the journal is a
			 * tmpfs readfile, not a fork-heavy RPC). The limit travels as a
			 * STRING — rpcd rejects a native number for a string typehint
			 * (lessons 105/132; the Health center does the same). */
			L.resolveDefault(callEvents('60'), {}).then(renderFeed);
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
				/* Ф7.2: the RU-protection card (guarantee + databases + update)
				 * lives on the Connection page now — this line only points
				 * there honestly. */
				geoLine.textContent = '';
				geoLine.appendChild(document.createTextNode(_('RU-protect') + ': '));
				geoLine.appendChild(E('b', {}, [ g.installed
					? _('networks %s, domains %s, %s').format(g.geoip || 0, g.geosite || 0, fmtAge(g.updated) || '—')
					: _('databases not installed') ]));
				if (g.updating)
					geoLine.appendChild(document.createTextNode(' · ' + _('updating…')));
				geoLine.appendChild(document.createTextNode(' — '));
				geoLine.appendChild(E('a', { 'href': L.url('admin/services/ravnex/client') },
					[ _('the RU-protection card on the Connection page') ]));
				/* Native helpers + engine profile (like the mosdns card on Core
				 * & Tools, but inline where the engine is configured). probe_pool
				 * is a one-shot batch prober — only presence applies; sni_sniffer
				 * is a resident daemon — running state applies. DOM building:
				 * colored E() spans must not be stringified into innerHTML. */
				const h = st.helpers || {};
				const prof = (st.profile === 'perf');
				const hspan = (ok, txt) => E('span', { style: 'color:' + (ok ? 'var(--hp-accent-strong)' : (ok === false ? 'var(--hp-grey)' : 'var(--hp-amber)')) }, [ txt ]);
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
				logEl.textContent = st.log || '';
			}).catch(function(e) {
				ovCards.textContent = _('Status unavailable: ') + e;
			});
		}

		/* ── Event Bus feed (Журналы level, Ф7.3) ──────────────────────── */
		const FEED_SOURCES = { automation: _('Auto-bypass'), hotswap: _('Exit engine'),
			urltest: 'URLTest', autopilot: _('DPI auto-pilot') };
		function renderFeed(r) {
			const evs = ((r && r.events) || []).filter(function(ev) {
				return !!FEED_SOURCES[ev.src];
			});
			const sig = evs.length ? ('' + evs[0].ts + ':' + evs.length) : 'none';
			if (sig === state.feedSig)
				return;
			state.feedSig = sig;
			feedEl.textContent = '';
			const show = evs.slice(-30).reverse();
			for (let i = 0; i < show.length; i++) {
				const ev = show[i];
				const d = new Date(Number(ev.ts) * 1000);
				const fmt = ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
				feedEl.appendChild(E('div', { 'class': 'hpauto-feed-ev' }, [
					E('span', { 'class': 't' }, [ fmt ]),
					E('span', { 'class': 'hpbadge hpb-type' }, [ FEED_SOURCES[ev.src] ]),
					E('span', { 'class': 'm' }, [
						E('b', {}, [ (ev.who || ev.type || '') ]),
						document.createTextNode(((ev.who && ev.type) ? ' · ' : ' ') + (ev.detail || ''))
					])
				]));
			}
			if (!show.length)
				feedEl.appendChild(E('span', { 'class': 'hpauto-cap' }, [ _('no events yet') ]));
		}

		poll.add(hp.vpoll(refresh), hp.pollSec(5));
		refresh();

		/* Ф7.1/U4: the expert knobs collapse into a <details> — the level
		 * shows the master switch and the RESULTS by default. The expert
		 * section node is moved into the details after the map renders
		 * (the form save flow is untouched — one map, one Save & Apply). */
		const expertDetails = E('details', { 'class': 'hpauto-expert' }, [
			E('summary', {}, [ _('Expert settings') + ' · ' + _('hidden by default — open only if needed') ])
		]);
		panes.engine.appendChild(expertDetails);

		return m.render().then(function(mapNode) {
			/* Locate the expert NamedSection (its title is unique) and move
			 * it into the details; the master switch stays at the top of the
			 * level. LuCI relocates the map footer to the page bottom itself
			 * (known behavior). */
			const sections = mapNode.querySelectorAll('.cbi-section');
			for (let i = 0; i < sections.length; i++) {
				const hd = sections[i].querySelector('.cbi-section-title') ||
					sections[i].querySelector('h3');
				if (hd && hd.textContent.indexOf(_('Expert settings')) === 0) {
					expertDetails.appendChild(sections[i]);
					break;
				}
			}
			/* The remaining map node (master switch + footer) leads the level. */
			panes.engine.insertBefore(mapNode, panes.engine.firstChild);
			return E('div', {}, [
				hp.pageIntro(_('Auto-bypass'),
					_('The engine learns which sites your provider blocks and sends them around the block automatically: traffic that fails directly but works through the proxy is added to the lists. Three levels: this one is the site learning itself, the DPI auto-pilot keeps the bypass strategies fresh on its own, the Logs level shows the engine log and the automation event journal.')),
				tabBar, panes.engine, panes.dpi, panes.logs
			]);
		});
	}
});
