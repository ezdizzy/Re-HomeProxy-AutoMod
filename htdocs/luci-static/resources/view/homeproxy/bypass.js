/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — Strategy master page (R3 v3c, 19-UX_REDESIGN стр. 4).
 *
 * ONE page for the whole «how do the blocked sites open» concern. The four
 * zones moved here 1:1 from the Routing Wizard DPI section (the wizard is
 * abolished — its presets went to Service rules in v3b, provider
 * diagnostics to Check & repair; the
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
	 *   «Application» — the global Zapret strategy (or scoped for one
	 *   resource via strategy_apply_scoped), the ByeDPI card
 *   with its presets and flags (wizard_byedpi_set), the per-resource
 *   Composition of both engines (wizard_compose_*) and the
 *   «apply strategy → service rule → live check» chain (wizard_preset_apply).
 *
 * The result area is ONE shared node that follows the active zone — results
 * stay in one place, replacing the previous (ui.action_buttons_result_
 * placement). Checks are on-demand (D6 pattern): nothing monitors
 * permanently here except the poll-driven state panels.
 *
 * Ф9.3 v3 rework: hp.pageIntro on top; every zone is an hpui-panel with an
 * icon header (the four manual subsections each get their own panel);
 * stagger on the STATIC engine cards only; table buttons use the hpui-btn
 * family (sm size for dense tables). Logic, RPCs and the tab structure are
 * untouched.
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

const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

const callPresetList = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_preset_list',
	expect: { '': {} }
});

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

/* ── DPI section (Ф3): engines, Strategy Lab, corpus tools ─────────────── */

const callDpiStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_dpi_status',
	expect: { '': {} }
});

const callStrategyList = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_strategy_list',
	expect: { '': {} }
});

const callStrategyUpdate = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_strategy_update',
	expect: { '': {} }
});

const callStrategyStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_strategy_status',
	expect: { '': {} }
});

const callStrategyApply = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_strategy_apply',
	expect: { '': {} }
});

const callFuzzGenerate = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_fuzz_generate',
	expect: { '': {} }
});

/* ч.123: local strategies import (share the corpus between routers). The
 * payload crosses as a JSON-encoded STRING (issue #11 string-policy). */
const callCorpusImport = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_corpus_import',
	params: [ 'candidates' ],
	expect: { '': {} }
});

/* The Strategy Lab backend RPCs are UNCHANGED (ч.69/70) — the panel moved
 * here from node.js, the server side did not. */
const callZapretTest = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_strategy_test',
	params: [ 'cmd_opts', 'ips' ],
	expect: { '': {} }
});

const callZapretResolve = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_resolve_hosts',
	expect: { '': {} }
});

const callFuzzStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_fuzz_start',
	params: [ 'mode', 'rounds' ],
	expect: { '': {} }
});

const callFuzzStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_fuzz_status',
	expect: { '': {} }
});

/* Lists conveyor (seance 178): per-provider nfqws2 strategies (zemidala
 * index republished by the validated hub). Import = an opman op; strategies
 * land in the corpus group 'recommended' with traceable names zmd-AS<n>-*,
 * the origin and the no-license attribution are recorded. */
const callStrategySourceStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'lab_strategy_source_status',
	expect: { '': {} }
});
const callStrategyImportStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'lab_strategy_import_start',
	params: [ 'asn' ],
	expect: { '': {} }
});

const callFuzzApply = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_fuzz_apply',
	params: [ 'strategy' ],
	expect: { '': {} }
});

/* сеанс 24 (user wish): the node.js ByeDPI/Zapret tabs moved into the
 * Wizard DPI pane — Save writes the whole ByeDPI card (strategy args +
 * the option flags that used to live on those tabs); Test / Test-all
 * reuse the existing byedpi_strategy_test tester. */
const callByedpiSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_byedpi_set',
	params: [ 'cmd_opts', 'udp_over_tcp', 'block_quic', 'zapret_voice' ],
	expect: { '': {} }
});

/* Session 187: negative steering of dead YouTube pools (DNS refuse).
 * The daemon (multidns) picks the UCI flag up on its next tick. */
const callYtSteerSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'yt_steer_set',
	params: [ 'value' ],
	expect: { '': {} }
});

/* Session 189: manual forget of the auto-learned dead pools (tmpfs state
 * cleared + verified regen; the content guard keeps an ALIVE pool from
 * being re-learned, a dead one returns on its own within minutes). */
const callYtSteerLearnedClear = rpc.declare({
	object: 'luci.ravnex',
	method: 'yt_steer_learned_clear',
	expect: { '': {} }
});

const callByedpiTest = rpc.declare({
	object: 'luci.ravnex',
	method: 'byedpi_strategy_test',
	params: [ 'cmd_opts', 'port' ],
	expect: { '': {} }
});

/* Ф8-F7 T3: one-click strategy auto-pick — fuzz → pick per resource →
 * rule (optional) → apply (server snapshot) → live verify. ч.109: an
 * explicit `strategy` skips the fuzz+pick stages (the «apply from the
 * ranking table» flow reuses the same rule/apply/verify machinery). */
const callAutoPickStart = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_auto_pick_start',
	params: [ 'resource', 'mode', 'set_rule', 'strategy' ],
	expect: { '': {} }
});

/* ч.109: composition DRAFT persistence — the server keeps the per-resource
 * profile list, so the builder survives page reloads. */
const callComposeSave = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_compose_save',
	params: [ 'profiles' ],
	expect: { '': {} }
});

/* ч.109: router-originated live probe of a DPI resource through the
 * configured path — the Serving map «Check» button (YouTube is probed
 * on the page, the thumbnail CDN and the video-stream edge). */
const callDpiProbe = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_dpi_probe',
	params: [ 'resource' ],
	expect: { '': {} }
});

const callAutoPickStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_auto_pick_status',
	expect: { '': {} }
});

/* ч.232: метки С УСТРОЙСТВА — единственный канал, который видит то же, что
 * телефон (лабораторные пробы — curl: свой ClientHello, нет QUIC-фоллбека).
 * 'works' поднимает стратегию во всех выборщиках, 'broken' исключает её из
 * автоподбора и опускает в таблице. */
const callDeviceVerdicts = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_device_verdicts',
	expect: { '': {} }
});

const callDeviceVerdictSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_device_verdict_set',
	params: [ 'resource', 'strategy', 'verdict' ],
	expect: { '': {} }
});

/* ч.97 → Ф7.1: the scheduled strategy auto-pilot lives on the Automation
 * page now (level «DPI auto-pilot»); the STATUS still rides this page for
 * the Serving map and the Quality panels. Only the status RPC stays. */
const callAutoPilotStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_autopilot_status',
	expect: { '': {} }
});

/* Ф8-F4: Composition Builder v2 — server-side build/test/apply. Apply
 * snapshots the previous strategies on the SERVER, so the rollback button
 * reads the snapshot back on every page load (no JS-memory rollback). */
const callComposeRun = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_compose_run',
	params: [ 'profiles' ],
	expect: { '': {} }
});

const callComposeStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_compose_status',
	expect: { '': {} }
});

const callComposeApply = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_compose_apply',
	params: [ 'zapret', 'byedpi', 'profiles' ],
	expect: { '': {} }
});

/* Сеанс 191: честное «применить стратегию X к ресурсу Y» одним действием —
 * scoped-профиль в UCI-профили (источник истины), rebuild остальных из
 * живого набора, валидация бинарником, свет-рестарт движка. */
const callStrategyScoped = rpc.declare({
	object: 'luci.ravnex',
	method: 'strategy_apply_scoped',
	params: [ 'resource', 'strategy', 'domains', 'label', 'verify' ],
	expect: { '': {} }
});

/* Сеанс 191: посев — текущая строка становится одним общим профилем. */
const callStrategyProfileSeed = rpc.declare({
	object: 'luci.ravnex',
	method: 'strategy_profile_seed',
	expect: { '': {} }
});

const callComposeRollback = rpc.declare({
	object: 'luci.ravnex',
	method: 'wizard_compose_rollback',
	expect: { '': {} }
});

/* ── R3 v3b: the manual domain lists moved to Service rules (their RPC
 * declarations moved with them). ─────────────────────────────────────── */
/* Resolve a sing-box outbound tag (cfg-<section>-out) to its UCI label
 * (same logic as diagnostics.js). */
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

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('ravnex')
		]);
	},

	render: function() {
		hp.uiShell();

		/* Сеанс 191: панель «Send a service through the engine» УДАЛЕНА —
		 * устаревший дубль «Правил для сервисов» (14 vs 28 сервисов,
		 * пустые hosts). Маршрутизацией сервисов ведает только страница
		 * правил; отсюда на неё ведёт навигационная подсказка. */

		const WIZ_CSS = `
.wiz-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }
.wiz-toolbar input[type="text"] { flex: 1 1 260px; min-width: 200px; }
.wiz-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); margin: 6px 0; }
.wiz-title { flex: 1 1 220px; font-weight: 600; }
.wiz-select { min-width: 190px; max-width: 320px; }
.wiz-note { font-size: .88em; opacity: .8; margin: 8px 0; }
.wiz-strat { flex: 1 1 380px; min-width: 260px; font-family: monospace; font-size: .82em; }
/* Ф9.3: dense table buttons (hpui-btn is sized for forms). */
.hpui-btn-sm { padding: 2px 10px; font-size: .84em; white-space: nowrap; }
`;

		const st = document.getElementById('hp-byp-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-byp-style' }, [ WIZ_CSS ]));

		/* ── Zone frame (R3 v3c, сеанс 191: 4 вкладки → 3 ЗОНЫ) ─────────── */
		/* Аудит сеанса 191: вкладка «Strategy picking» (1 ряд) слита с
		 * Лабораторией (автоподбор = действие над ранжированием), панель
		 * «Send a service» удалена (дубль «Правил для сервисов»), тоггл
		 * стиринга/«Забыть пулы» переехали на Автообход (поведение системы,
		 * а не состояние). Зоны: Обзор / Лаборатория / Применение. */
		const dpiBanner = E('div', {});
		/* Static container (built once, poll updates texts IN PLACE) — the
		 * hpui-stagger entrance is safe here (Ф9.2/Ф9.3). */
		const dpiCards = E('div', { 'class': 'hpui-cards hpui-stagger' });
		/* ч.109: the Serving map — what actually serves each resource right
		 * now (rule → engine → strategy → last check), the user complaint
		 * «не видно какие реально сейчас используются стратегии». */
		const dpiMap = E('div', {});
		const dpiSync = E('div', {});
		const dpiQuality = E('div', {});
		const dpiLab = E('div', {});
		const dpiCorpus = E('div', {});
		const dpiResult = E('div', {});
		/* Ф9.3: the manual zone splits into four panels; each subsection
		 * appends into its own holder (assembly wraps the holders). */
		const dpiPick = E('div', {});
		const zapBox = E('div', {});
		const byeBox = E('div', {});
		const compBox = E('div', {});
		const DPI_TABS = [
			[ 'dpiOv',  _('Overview') ],
			[ 'dpiLab', _('Strategy Lab') ],
			[ 'dpiMan', _('Manual apply') ]
		];
		const dpiPanes = {};
		for (let t in DPI_TABS)
			dpiPanes[DPI_TABS[t][0]] = E('div', { 'class': 'hpui-pane' });
		const dpiTabBar = E('div', { 'class': 'hpui-tabs', style: 'margin:8px 0 10px 0' });
		const dpiResultRow = E('div', { 'class': 'hpui-panel' }, [
			E('h4', { 'class': 'hpui-h4' }, [ hp.icon('check'), _('Results') ]),
			dpiResult
		]);

		/* Ф1.1b: engine applies run as tracked operations (opman + apply_runner:
		 * stages Applying→Verifying→Completed/Failed, verified only after a live
		 * engine check). Poll app_op_status until the honest verdict — never
		 * report success before verification (audit 1.7). busy attaches to the
		 * holder op ONLY when it coalesced onto ours; a foreign holder means our
		 * UCI write is saved and lands with the next restart. */
		function pollApply(desc, okText, after) {
			if (!desc || desc.hot) {
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ okText ]));
				if (after) after(true);
				return;
			}
			if (desc.busy && !desc.coalesced) {
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Another apply is running — the change is saved and will take effect with the next service restart.') ]));
				if (after) after(false);
				return;
			}
			if (!desc.op_id) {
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Apply failed: ') + (desc.error || _('rpc error')) ]));
				if (after) after(false);
				return;
			}
			const deadline = Date.now() + 150000;
			const tick = function() {
				return L.resolveDefault(callOpStatus(desc.op_id), {}).then(function(st2) {
					/* Audit B3 (с.193): the recursive watcher dies with the
					 * section — no detached writes, no dead-DOM retention. */
					if (!dpiResult.isConnected)
						return;
					const op = st2 && st2.op;
					if (op && op.status !== 'completed' && op.status !== 'failed') {
						if (Date.now() > deadline) {
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('The operation is still running — check the operations journal on the Health center page.') ]));
							if (after) after(false);
							return;
						}
						window.setTimeout(tick, 2000);
						return;
					}
					const ok = !!op && op.status === 'completed' && op.verified;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [
						ok ? okText : ((op && (op.detail || op.error)) || _('Apply failed'))
					]));
					if (after) after(ok);
				});
			};
			tick();
		}
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

		/* Ф9.3: zones are hpui-panels with an icon header (the devices.js
		 * pattern); the holders keep their node references — the poll
		 * renders fill them IN PLACE after the assembly. */
		const panelOf = function(icon, title, children) {
			const p = E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon(icon), title ])
			]);
			(children || []).forEach(function(ch) { p.appendChild(ch); });
			return p;
		};

		/* «Обзор» — честное состояние (сеанс 191: заголовок новый, действий
		 * больше нет на вкладке — тоггл стиринга/«Забыть пулы» на Автообходе). */
		dpiPanes.dpiOv.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('The live state of the bypass: which engines are running, which strategy serves each resource right now, and the measured quality of the desync path. Actions live on the other tabs; the results area follows you to every tab.') ]));
		dpiPanes.dpiOv.appendChild(panelOf('zap', _('Engines'), [ dpiBanner, dpiCards ]));
		dpiPanes.dpiOv.appendChild(panelOf('shuffle', _('What serves what right now'), [ dpiMap ]));
		dpiPanes.dpiOv.appendChild(panelOf('layers', _('Profiles: source of truth'), [ dpiSync ]));
		dpiPanes.dpiOv.appendChild(panelOf('trend', _('Quality now'), [ dpiQuality ]));

		/* «Лаборатория» (сеанс 191): автоподбор СЛИТ с фаззингом — действие
		 * над ранжированием, корпус и импорты в той же зоне. */
		dpiPanes.dpiLab.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Measure, then decide: auto-pick or pick from the ranking table, fuzz the catalog against your provider, import and share catalogs. Apply a winner for one resource right from the table.') ]));
		dpiPanes.dpiLab.appendChild(panelOf('crosshair', _('Strategy picking'), [ dpiPick ]));
		dpiPanes.dpiLab.appendChild(panelOf('activity', _('Fuzzing'), [ dpiLab ]));
		dpiPanes.dpiLab.appendChild(panelOf('database', _('Strategy catalog'), [ dpiCorpus ]));

		/* «Применение» — всё, что накладывается руками (сеанс 191: цепочка
		 * «Отправить сервис» удалена — дубль «Правил для сервисов»; в
		 * карточке Zapret явный выбор уровня: для всего движка / для ресурса). */
		dpiPanes.dpiMan.appendChild(E('p', { 'class': 'hpui-hint' },
			[ _('Everything applied by hand: the global Zapret strategy (or a scoped one for a single resource), the ByeDPI card with its presets and flags, and the per-resource composition of both engines. To route a SERVICE through an engine, use the Service rules page.') ]));
		dpiPanes.dpiMan.appendChild(panelOf('shuffle', _('Zapret strategy'), [ zapBox ]));
		dpiPanes.dpiMan.appendChild(panelOf('zap', _('ByeDPI strategy'), [ byeBox ]));
		dpiPanes.dpiMan.appendChild(panelOf('layers', _('Composition'), [ compBox ]));

		dpiPanes.dpiOv.appendChild(dpiResultRow);
		const bypRoot = E('div', {});
		bypRoot.appendChild(hp.pageIntro(_('Strategy master'),
			_('How the blocked sites open: what works right now (the Serving map), the Strategy Lab and the manual application. Work top to bottom — check the state, pick or test a strategy, apply it.')));
		bypRoot.appendChild(dpiTabBar);
		for (let t in DPI_TABS)
			bypRoot.appendChild(dpiPanes[DPI_TABS[t][0]]);
		/* Badge / text helpers ─────────────────────────────────────────── */
		const badge = (cls, text) => E('span', { 'class': 'hpui-badge ' + cls }, [ text ]);


		const state = { dpiSig: null, stratSig: null, fuzzSig: null, corpusSig: null, prevSig: null,
			profilesSyncSig: null,
			/* Ф8-F4 composition builder: the profile draft is PERSISTED on the
			 * server (ч.109) — compDirty guards the one-time seed from it. */
			compProfiles: [ { engine: 'zapret', resource: 'youtube', domains: '', strategy: '' } ],
			compBuilt: null, composeSig: null, composeSeeded: false, rbSig: null,
			compSeeded: false, compDirty: false, compSaveError: null, compStale: false,
			mapSig: null, fuzzShownSig: null,
			/* ч.232: метки с устройства { resource: { args: {verdict, ts} } }. */
			dev: {} };

		/* ── ч.232: device-verdict helpers ─────────────────────────────── */
		/* Метка одной стратегии по ресурсу: 'works'|'broken'|'' (live map). */
		function devMark(resource, args) {
			const dm = state.dev && state.dev[resource];
			const mv = dm && dm[args];
			return (mv && mv.verdict) ? String(mv.verdict) : '';
		}
		/* Все метки стратегии (для бейджа в строке таблицы). */
		function devMarksOf(args) {
			const out = [];
			const RMAP = { youtube: 'YT', discord: 'DC', telegram: 'TG', general: 'GEN' };
			Object.keys(RMAP).forEach(function(rn) {
				const v = devMark(rn, args);
				if (v)
					out.push({ res: rn, short: RMAP[rn], verdict: v });
			});
			return out;
		}
		/* Пара кнопок «работает / не работает на устройстве» + текущие метки.
		 * Одно место результата (client-правило: результат внизу, заменяя
		 * предыдущий) — сюда пользователь приходит ПОСЛЕ проверки на телефоне.
		 * title — подпись «<Ресурс> · <имя стратегии>» (согласовано ч.233:
		 * одна подписанная группа на ресурс). */
		function devButtons(resource, args, title) {
			if (!resource || !args)
				return null;
			const wrap = E('span', { 'class': 'wiz-note', style: 'display:inline-flex; gap:6px; align-items:center; margin:4px 0' });
			const set = function(v) {
				wrap.querySelectorAll('button').forEach(function(b) { b.disabled = true; });
				L.resolveDefault(callDeviceVerdictSet(resource, args, v), {}).then(function(r) {
					if (r && r.device)
						state.dev = r.device;
					refresh();
				});
			};
			const mk = function(label, v, cls) {
				const b = E('button', { 'class': 'hpui-btn ' + cls + ' hpui-btn-sm', type: 'button' }, [ label ]);
				b.addEventListener('click', function() { set(v); });
				return b;
			};
			const cur = devMark(resource, args);
			wrap.appendChild(E('span', { style: 'opacity:.75' },
				[ _('Device check') + (title ? (' — ' + title) : '') + ':' ]));
			wrap.appendChild(mk(_('works on my device'), 'works',
				cur === 'works' ? 'hpui-btn-primary' : 'hpui-btn'));
			wrap.appendChild(mk(_('broken on my device'), 'broken',
				cur === 'broken' ? 'hpui-btn-danger' : 'hpui-btn'));
			if (cur === 'works')
				wrap.appendChild(badge('hpui-b-green', _('confirmed on device')));
			else if (cur === 'broken')
				wrap.appendChild(badge('hpui-b-red', _('refuted on device')));
			return wrap;
		}

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

		/* ── DPI section (Ф3): engine status, strategy, Lab, corpus ────── */

		/* ч.183: the group vocabulary is EXTENSIBLE — a corpus import that
		 * carries an unknown group (tachyon/community lived INVISIBLE in the
		 * pickers and the count line until now) must still surface. The
		 * optgroup order follows the array; renderCorpus additionally prints
		 * leftover group counts verbatim. */
		const DPI_GROUPS = [
			[ 'recommended', _('Recommended') ],
			[ 'imported', _('Imported (catalog)') ],
			[ 'generated', _('Generated') ],
			[ 'tachyon', _('Tachyon (import)') ],
			[ 'community', _('Community') ],
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

		/* ── ч.109 → сеанс 191: Serving map — ДИНАМИЧЕСКИЕ строки.
		 * Раньше: жёсткие 4 ресурса (карта врала при 28 возможных правилах).
		 * Теперь: известные ресурсы + ресурсы UCI-профилей (custom-метки)
		 * + источники правил, пришедшие с сервера. */
		const MAP_LABELS = function() {
			return {
				youtube: 'YouTube',
				discord: 'Discord',
				telegram: _('Telegram (TLS)'),
				general: _('Everything else')
			};
		};
		function buildMapRows(presets, dpiSt) {
			const seen = {}, rows = [];
			const add = function(key, label) {
				if (seen[key]) return;
				seen[key] = true;
				rows.push([ key, label ]);
			};
			add('youtube', 'YouTube');
			add('discord', 'Discord');
			add('telegram', _('Telegram (TLS)'));
			/* Ресурсы UCI-профилей (custom — по метке или ресурсу). */
			const ps = (dpiSt && dpiSt.profiles_sync && dpiSt.profiles_sync.profiles) || [];
			for (let i = 0; i < ps.length; i++) {
				const p = ps[i];
				if (p.resource === 'custom')
					add('custom:' + (p.label || p.domains), p.label || p.domains);
				else
					add(p.resource, (MAP_LABELS()[p.resource] != null)
						? MAP_LABELS()[p.resource] : p.resource);
			}
			/* Правила сервера — всё, чего ещё нет на карте. */
			const rules = (presets && presets.rules) || {};
			for (const rk in rules) {
				const lbl = (MAP_LABELS()[rk] != null) ? MAP_LABELS()[rk] : rk;
				add(rk, lbl);
			}
			add('general', _('Everything else'));
			return rows;
		}
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

		/* Сеанс 191: тоггл стиринга мёртвых пулов и «Забыть выученные пулы»
		 * ПЕРЕЕХАЛИ на «Автообход» (поведение системы, а не состояние;
		 * был противоречием «на вкладке-обзоре действий нет»). */

		function servingText(rk, rule, dpiSt, isCustom) {
			const z = dpiSt.zapret || {}, b = dpiSt.byedpi || {};
			const blocks = z.blocks || [];
			if (rule && rule.node === 'byedpi-out')
				return (b.opts) ? 'ByeDPI: ' + shortStrategy(b.opts, 60) : 'ByeDPI: ' + _('no strategy set');
			if (rule && rule.node === 'zapret-out') {
				/* ч.116: the map reads the parsed profile blocks — the user
				 * complaint «применить для YouTube применило и к Discord» was
				 * the GLOBAL strategy written on every Zapret-routed row with
				 * no scope shown. Own block → its strategy; no own block →
				 * the general tail; no hostlists at all → the honest
				 * «the strategy is global for the engine». */
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
			/* сеанс 194: у custom-профиля нет СВОЕГО правила маршрутизации —
			 * его домены едут тем путём, который их уже несёт (например,
			 * правило YouTube), и внутри nfqws2 их обслуживает его блок
			 * по hostlist. Показываем блок честно, а не «правила нет». */
			if (!rule && isCustom && blocks.length) {
				const scoped2 = blocks.filter(function(sbk) { return sbk.scope === rk; });
				if (scoped2.length) {
					const tls2 = scoped2.filter(function(tb) { return /--filter-tcp=443/.test(tb.base || ''); });
					const cbk = tls2.length ? tls2[0] : scoped2[0];
					return 'Zapret: ' + (cbk.name || shortStrategy(cbk.base, 60)) +
						' — ' + _('own profile');
				}
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
			const rows = buildMapRows(presets, dpiSt || {});
			for (let r in rows) {
				const rk = rows[r][0], label = rows[r][1];
				/* custom-строки карты: 'custom:<метка>' — скоуп у блока = метка. */
				const isCustom = (rk.indexOf('custom:') === 0);
				const scopedKey = isCustom ? rk.substring('custom:'.length) : rk;
				const rule = rules[rk] || rules[scopedKey] || null;
				const tr = E('tr', {});
				tr.appendChild(E('td', { style: 'font-weight:600; white-space:nowrap' }, [ label ]));
				const ruleTd = E('td', {});
				if (rk === 'general') {
					ruleTd.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ _('catch-all — unmatched traffic') ]));
				} else if (isCustom && !rule) {
					ruleTd.appendChild(E('span', { 'class': 'wiz-note', style: 'margin:0' },
						[ _('own profile — no rule (the profile serves the domains it carries)') ]));
				} else
					ruleTd.appendChild(ruleStateText(rule, counts[scopedKey] || counts[rk] || 0));
				tr.appendChild(ruleTd);
				tr.appendChild(E('td', { style: 'font-size:.85em' },
					[ servingText(scopedKey, rule, dpiSt || {}, isCustom) ]));
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
				const chk = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', type: 'button' },
					[ _('Check') ]);
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

		/* ── Сеанс 191: карточка «Профили: источник истины» (Обзор) ──────
		 * UCI-профили = источник, строка zapret_cmd_opts — производная.
		 * Дрейф = честная карточка с кнопкой пересборки; посев — кнопка
		 * «из текущей строки». */
		function renderProfilesSync(dpiSt) {
			const ps = dpiSt && dpiSt.profiles_sync;
			if (!ps)
				return;
			const list = ps.profiles || [];
			const sig = JSON.stringify([ ps.drift, ps.seed_needed,
				list.map(function(p) {
					return p.section + ':' + p.enabled + ':' + p.resource + ':' +
						p.label + ':' + p.strategy;
				}) ]);
			if (sig === state.profilesSyncSig)
				return;
			state.profilesSyncSig = sig;
			dpiSync.innerHTML = '';
			if (list.length) {
				const tb = E('tbody', {});
				const labels = MAP_LABELS();
				for (let i = 0; i < list.length; i++) {
					const p = list[i];
					const tr = E('tr', {});
					tr.appendChild(E('td', { style: 'white-space:nowrap' },
						[ p.enabled ? badge('hpui-b-green', _('enabled')) : badge('hpui-b-grey', _('disabled')) ]));
					const resTxt = (p.resource === 'custom')
						? ((_('Custom list') + ': ' + (p.label || p.domains)))
						: ((labels[p.resource] != null) ? labels[p.resource] : p.resource);
					tr.appendChild(E('td', { style: 'font-weight:600; white-space:nowrap' }, [ resTxt ]));
					tr.appendChild(E('td', { style: 'font-size:.85em' },
						[ shortStrategy(p.strategy, 70) ]));
					tb.appendChild(tr);
				}
				dpiSync.appendChild(E('div', { 'class': 'hpui-wrap' }, E('table', { 'class': 'hpui-table' }, [
					E('thead', {}, E('tr', {}, [
						E('th', {}, [ _('State') ]),
						E('th', {}, [ _('Resource') ]),
						E('th', {}, [ _('Strategy') ])
					])),
					tb
				])));
				dpiSync.appendChild(E('p', { 'class': 'wiz-note', style: 'margin-top:2px' },
					[ _('Profiles apply in order (first match wins): scoped ones first, «everything else» last. The Composition editor below edits this list; the applied line is built from it.') ]));
			}
			if (ps.drift) {
				const box = E('div', {});
				box.appendChild(E('p', { 'class': 'hpui-banner' },
					[ _('The applied line diverged from the profiles (an external/manual edit). Rebuilding from profiles restores the source of truth.') ]));
				const rb = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
					[ _('Rebuild the line from profiles') ]);
				rb.addEventListener('click', function() {
					rb.disabled = true;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Rebuilding — the service restarts…') ]));
					L.resolveDefault(callComposeApply('', '', JSON.stringify(
						list.map(function(p) {
							return { engine: p.engine, resource: p.resource,
								label: p.label, domains: p.domains, strategy: p.strategy };
						}))), {}).then(function(r) {
						rb.disabled = false;
						if (!r || (r.result === false && !r.op_id)) {
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('Rebuild failed: ') + ((r && r.error) || _('rpc error')) ]));
							return;
						}
						pollApply(r, _('The line was rebuilt from the profiles and verified.'));
					});
				});
				box.appendChild(rb);
				dpiSync.appendChild(box);
			} else if (ps.seed_needed) {
				const box2 = E('div', {});
				box2.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:4px 0' },
					[ _('An applied line exists, but no profiles yet — the line can become the first («everything else») profile without losing service.') ]));
				const sb = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' },
					[ _('Make the current line the first profile') ]);
				sb.addEventListener('click', function() {
					sb.disabled = true;
					L.resolveDefault(callStrategyProfileSeed(), {}).then(function(r) {
						sb.disabled = false;
						state.profilesSyncSig = null;
						if (r && r.result === true)
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ (r.seeded === 1) ? _('Profile created from the current line.') : ((r.note) || _('Nothing to seed.')) ]));
						else
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('Failed: ') + ((r && r.error) || _('rpc error')) ]));
					});
				});
				box2.appendChild(sb);
				dpiSync.appendChild(box2);
			} else if (list.length) {
				dpiSync.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:4px 0' },
					[ badge('hpui-b-green', _('in sync')) ]));
			} else {
				dpiSync.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:4px 0' },
					[ _('No profiles yet — the strategy applies globally (everything routed to the engine).') ]));
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
				Number((res.strategies.filter(function(x) { return x.name !== 'current (applied)'; })[0] || {}).stream || 0) > 0) {
				const bf = res.strategies.filter(function(x) { return x.name !== 'current (applied)'; })[0];
				flow = Number(bf.stream);
				flowStart = Number(bf.start_ms || 0);
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
			if (res && res.strategies && res.strategies.length) {
				/* ч.236: exclude the «current (applied)» row — it is prepended
				 * at [0] with 0/0 (quick battery does not measure it), which
				 * hid the real winner line entirely. */
				const b = res.strategies.filter(function(x) { return x.name !== 'current (applied)'; })[0];
				if (b && Number(b.ok || 0) > 0)
					dpiQuality.appendChild(E('div', { 'class': 'wiz-note' }, [
						_('Last fuzz winner: %s (flow %s).').format(b.name || _('custom args'),
							(Number(b.stream || 0) > 0)
								? (Math.round(b.stream / 1024) + ' KB/s') : _('n/a'))
					]));
			}
			dpiQuality.appendChild(E('p', { 'class': 'wiz-note', style: 'margin:2px 0 0 0; opacity:.8' },
				[ _('Every number here was measured through your real path. The flow speed refreshes on every auto-pilot health check; without the auto-pilot it comes from the last fuzz ranking.') ]));
		}

		/* Strategy row — persistent elements, options rebuilt on corpus change.
		 * Сеанс 191: явный выбор уровня — «для всего движка» / «для ресурса»
		 * (пер-ресурсный путь БЕЗ тяжёлого конвейера автоподбора). */
		let zapLevel = 'global';
		const lvlGlobalBtn = E('button', { 'class': 'hpui-tab active', type: 'button' }, [ _('For the whole engine') ]);
		const lvlScopedBtn = E('button', { 'class': 'hpui-tab', type: 'button' }, [ _('For one resource') ]);
		const lvlBar = E('div', { 'class': 'hpui-tabs', style: 'margin:2px 0' });
		lvlBar.appendChild(lvlGlobalBtn);
		lvlBar.appendChild(lvlScopedBtn);
		/* Live report s196: the level buttons had NO click wiring — green
		 * never moved (the highlight the user saw on «For one resource» was
		 * the focus ring) and the scoped row never opened. Wire them like
		 * the DPI tab bar above. */
		lvlGlobalBtn.addEventListener('click', function() { setZapLevel('global'); });
		lvlScopedBtn.addEventListener('click', function() { setZapLevel('scoped'); });
		function setZapLevel(v) {
			zapLevel = v;
			lvlGlobalBtn.classList.toggle('active', v === 'global');
			lvlScopedBtn.classList.toggle('active', v === 'scoped');
			scopedRow.style.display = (v === 'scoped') ? '' : 'none';
			if (v === 'scoped')
				scopedSeed();
		}
		/* Bug (а), с.193: the scoped editor INHERITS the existing UCI
		 * profile for the picked resource (strategy + domains) instead of
		 * inviting a blind apply over it. The hint says what happened. */
		function scopedSeed() {
			const ps = (state.lastDpi && state.lastDpi.profiles_sync &&
				state.lastDpi.profiles_sync.profiles) || [];
			const res = scopedResSel.value;
			let p = null;
			for (let i = 0; i < ps.length; i++) {
				if (ps[i] && ps[i].enabled !== false && ps[i].engine === 'zapret' &&
				    ('' + (ps[i].resource || '')) === res)
					p = ps[i];
			}
			if (res === 'custom') {
				/* Custom resources live under custom:<name> — inherit the
				 * MOST RECENT one (highest order) so the editor starts from
				 * something real. */
				for (let i = 0; i < ps.length; i++) {
					if (ps[i] && ps[i].enabled !== false && ps[i].engine === 'zapret' &&
					    /^custom:/.test('' + (ps[i].resource || '')))
						p = ps[i];
				}
			}
			if (!p)
				return;
			const st = '' + (p.strategy || '');
			const dm = '' + (p.domains || '');
			if (st)
				stratInput.value = st;
			if (res === 'custom' && dm)
				scopedDomainsInp.value = dm;
			scopedSeedNote();
		}
		function scopedSeedNote() {
			const old = scopedRow.querySelector('.hp-scoped-seed');
			if (old)
				old.parentNode.removeChild(old);
			scopedRow.appendChild(E('span', { 'class': 'wiz-note hp-scoped-seed', style: 'margin:0; width:100%' },
				[ _('Inherited from the current UCI profile: the strategy and domains above are what serves this resource now.') ]));
		}
		/* Scoped-ряд: ресурс + (custom: имя + домены). */
		const scopedResSel = E('select', { 'class': 'cbi-input-select wiz-select' });
		[ ['youtube', 'YouTube'], ['discord', 'Discord'], ['telegram', _('Telegram (TLS)')], ['custom', _('Custom list')] ]
			.forEach(function(o) { scopedResSel.appendChild(E('option', { value: o[0] }, [ o[1] ])); });
		const scopedLabelInp = E('input', { type: 'text', 'class': 'cbi-input-text wiz-select',
			placeholder: _('Resource name (e.g. Steam)'), style: 'display:none' });
		const scopedDomainsInp = E('input', { type: 'text', 'class': 'cbi-input-text wiz-strat',
			placeholder: _('Domains: a.com, b.com (comma or space separated)'), style: 'display:none' });
		const scopedRow = E('div', { 'class': 'wiz-row' });
		scopedRow.appendChild(scopedResSel);
		scopedRow.appendChild(scopedLabelInp);
		scopedRow.appendChild(scopedDomainsInp);
		scopedRow.style.display = 'none';
		scopedResSel.addEventListener('change', function() {
			const isCustom = (scopedResSel.value === 'custom');
			scopedLabelInp.style.display = isCustom ? '' : 'none';
			scopedDomainsInp.style.display = isCustom ? '' : 'none';
			scopedSeed();
		});
		const stratSel = E('select', { 'class': 'cbi-input-select wiz-select' });
		const stratInput = E('input', { type: 'text', 'class': 'cbi-input-text wiz-strat',
			placeholder: 'nfqws2 --lua-desync=… args' });
		const stratRow = E('div', { 'class': 'wiz-row' });
		stratRow.appendChild(E('span', { 'class': 'wiz-title' }, [ _('Zapret strategy') ]));
		stratRow.appendChild(lvlBar);
		stratRow.appendChild(stratSel);
		stratRow.appendChild(stratInput);
		const applyStratBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
			[ _('Apply strategy') ]);
		const testStratBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Test strategy') ]);
		stratRow.appendChild(applyStratBtn);
		stratRow.appendChild(testStratBtn);
		zapBox.appendChild(stratRow);
		zapBox.appendChild(scopedRow);
		zapBox.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('«For the whole engine» serves EVERY flow routed to Zapret and replaces the profile set with one general profile (a confirmation appears when scoped profiles exist). «For one resource» adds/replaces a scoped profile for that resource and keeps everything else — the applied line is rebuilt from the profiles automatically. Applying also enables Zapret and restarts the engine; testing runs the strategy on an isolated queue over 4 test sites (YouTube, Telegram, Discord, Speedtest).') ]));

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
			/* Сеанс 191: уровень применения. Для всего движка — прежний
			 * глобальный apply с ПОДТВЕРЖДЕНИЕМ затирания scoped-профилей
			 * (мина, найденная аудитом, обезврежена); для ресурса —
			 * strategy_apply_scoped одним действием. */
			function scopedCount() {
				const ps = (state.lastDpi && state.lastDpi.profiles_sync &&
					state.lastDpi.profiles_sync.profiles) || [];
				let n = 0;
				for (let i = 0; i < ps.length; i++)
					if (ps[i].enabled && ps[i].resource !== 'general')
						n++;
				return n;
			}
			if (zapLevel === 'scoped') {
				const resource = scopedResSel.value;
				const label = String(scopedLabelInp.value || '').trim();
				const domains = String(scopedDomainsInp.value || '').trim();
				if (resource === 'custom' && (!label || !domains)) {
					ui.addNotification(null, E('p', {}, _('A custom resource needs a name and at least one domain.')), 'error');
					return;
				}
				const resText = (resource === 'custom')
					? label
					: scopedResSel.options[scopedResSel.selectedIndex].text;
				hp.confirmModal(_('Apply for one resource'),
					_('Apply this strategy to %s? Other resources keep their profiles, the applied line is rebuilt from them automatically (a short engine restart).').format(resText),
					_('Apply')).then(function(ok) {
					if (!ok)
						return;
					applyStratBtn.disabled = true;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Applying the scoped profile — the engine restarts…') ]));
					L.resolveDefault(callStrategyScoped(resource, s, domains, label, 'light'), {}).then(function(r) {
						applyStratBtn.disabled = false;
						if (!r || (r.result === false && !r.op_id)) {
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
							return;
						}
						pollApply(r, _('Scoped profile applied and verified — the line was rebuilt from the profiles.'));
					});
				});
				return;
			}
			const sN = scopedCount();
			const warnTxt = (sN > 0)
				? _('Apply globally? This REPLACES the whole profile set: %d scoped profile(s) for other resources will be lost (their resources fall back to this one strategy). Restore stays available.').format(sN)
				: _('Apply globally? The strategy serves EVERY flow routed to Zapret (the applied line becomes one general profile).');
			hp.confirmModal(_('Apply strategy'), warnTxt, _('Apply')).then(function(ok) {
				if (!ok)
					return;
				applyStratBtn.disabled = true;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Applying the strategy — the service restarts…') ]));
				L.resolveDefault(callFuzzApply(s), {}).then(function(r) {
					applyStratBtn.disabled = false;
					if (!r || (r.result === false && !r.op_id)) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
						return;
					}
					pollApply(r, _('Strategy applied and verified — Zapret serves it now. Run "Test strategy" to confirm it works on your ISP, then create a service rule on the Service rules page.'));
				});
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
		bStratInput.value = uci.get('ravnex', 'config', 'byedpi_cmd_opts') || '--disorder 1';
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
		const bSave = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' }, [ _('Save ByeDPI') ]);
		const bTest = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Test') ]);
		const bTestAll = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Test all presets') ]);
		const bRow = E('div', { 'class': 'wiz-row' });
		bRow.appendChild(E('span', { 'class': 'wiz-title' }, [ _('ByeDPI strategy') ]));
		bRow.appendChild(bPresetSel);
		bRow.appendChild(bStratInput);
		bRow.appendChild(bSave);
		bRow.appendChild(bTest);
		bRow.appendChild(bTestAll);
		byeBox.appendChild(E('div', { style: 'margin-top:10px' }, [ bRow ]));

		const bUot = E('input', { type: 'checkbox' });
		bUot.checked = (uci.get('ravnex', 'config', 'byedpi_udp_over_tcp') !== '0');
		/* сеанс 187: Block QUIC переехал в отдельный блок «QUIC» на странице
		 * «Подключение» (это сетевой глобальный режим, не настройка движка).
		 * Save передаёт ТЕКУЩЕЕ UCI-значение без изменения — флаг не теряется. */
		const bQuicCur = (uci.get('ravnex', 'config', 'byedpi_block_quic') === '1') ? '1' : '0';
		const bVoice = E('input', { type: 'checkbox' });
		bVoice.checked = (uci.get('ravnex', 'config', 'zapret_voice') === '1');
		const bFlag = (input, text) => E('label', { 'class': 'wiz-note', style: 'margin:0; cursor:pointer' },
			[ input, ' ' + text ]);
		byeBox.appendChild(E('div', { 'class': 'wiz-row' },
			[ bFlag(bUot, _('UDP over TCP')),
			  bFlag(bVoice, _('Discord calls via Zapret')) ]));
		byeBox.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('The strategy serves the flows routed to ByeDPI (Main node = ByeDPI, service rules, or the Composition profiles below). Save writes the strategy and the flags and restarts the service; ByeDPI itself is enabled on the Connection page. UDP over TCP wraps UDP traffic into the ByeDPI TCP stream; Discord calls via Zapret routes the Discord voice UDP ports to Zapret (needs Zapret enabled).') ]));
		const bDesc = E('p', { 'class': 'wiz-note' });
		/* innerHTML: the description contains HTML links E() would escape */
		bDesc.innerHTML = _('Grouped by technique. Based on <a href="https://github.com/hufrea/byedpi" target="_blank">hufrea/byedpi</a> and community testing. See also <a href="https://github.com/fatyzzz/Byedpi-Setup" target="_blank">fatyzzz/Byedpi-Setup</a>.');
		byeBox.appendChild(bDesc);

		bSave.addEventListener('click', function() {
			/* сеанс 194: parity with Apply strategy / composition — «Save»
			 * here is an APPLY that restarts the service, so it confirms when
			 * anything actually changes (an unchanged form skips the modal
			 * and the RPC answers honestly). */
			const sNew = String(bStratInput.value || '').trim();
			const sCur = String(uci.get('ravnex', 'config', 'byedpi_cmd_opts') || '').trim();
			const uotCur = (uci.get('ravnex', 'config', 'byedpi_udp_over_tcp') !== '0');
			const vocCur = (uci.get('ravnex', 'config', 'zapret_voice') === '1');
			const doSave = function() {
				bSave.disabled = true;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Saving the ByeDPI options — the service restarts…') ]));
				L.resolveDefault(callByedpiSet(String(bStratInput.value || '').trim(),
					bUot.checked ? '1' : '0', bQuicCur,
					bVoice.checked ? '1' : '0'), {}).then(function(r) {
					bSave.disabled = false;
					if (r && r.unchanged) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('ByeDPI options saved — nothing changed, no restart needed.') ]));
						return;
					}
					if (!r || (r.result === false && !r.op_id)) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Save failed: ') + ((r && r.error) || _('rpc error')) ]));
						return;
					}
					pollApply(r, _('ByeDPI options applied and verified — the engine card above reflects the new state.'));
				});
			};
			if (sNew === sCur && bUot.checked === uotCur && bVoice.checked === vocCur) {
				doSave();
				return;
			}
			hp.confirmModal(_('Save ByeDPI'),
				_('Save and restart ByeDPI? The new strategy and flags apply at once — live connections through the engine drop for a moment.'),
				_('Save and restart')).then(function(ok) {
					if (ok)
						doSave();
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
			hp.confirmModal(_('Test all presets'),
				_('Test all ByeDPI presets? Each is probed against 4 sites (~12 min total). LAN clients are not affected. You can stop it at any point.'), _('Start'))
				.then(function(ok) {
					if (!ok)
						return;
					bTestAll.disabled = true;
			const stop = { on: false };
			const stopBtn = E('button', { 'class': 'hpui-btn hpui-btn-danger', type: 'button', style: 'margin-left:6px' }, [ _('Stop') ]);
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
				const pick = E('button', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm', style: 'visibility:hidden' },
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
					/* Audit B4 (с.193): leaving the page aborts the ~12-min
					 * chain instead of writing dots into a dead DOM. */
					if (stop.on || !tbody.isConnected) return;
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
				if (!prog.isConnected)
					return;
				bTestAll.disabled = false;
				stopBtn.parentNode.removeChild(stopBtn);
				prog.textContent = stop.on
					? _('Stopped') + ' — ' + fullPass + ' ' + _('work on all sites') + ((partial > 0) ? (', ' + partial + ' ' + _('partial')) : '')
					: _('Done') + ': ' + fullPass + ' / ' + BYEDPI_PRESETS.length + ' ' + _('work on all sites') +
						(((fullPass + partial) > 0) ? (' — ' + _('fill a preset into the input and press "Save ByeDPI"')) : '');
			});
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
			[ 'general', _('Everything else') ],
			[ 'custom', _('Custom list') ]
		];
		const FUZZ_TAGS = [ [ 'yt', 'YouTube' ], [ 'tg', 'Telegram' ],
			[ 'dc', 'Discord' ], [ 'st', 'Speedtest' ] ];

		const compRowsBox = E('div', { id: 'wiz-comp-rows', style: 'margin:2px 0 6px 0' });
		const compAddBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Add profile') ]);
		const compTestBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' }, [ _('Test composition') ]);
		const compApplyBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' }, [ _('Apply composition') ]);
		const compClearBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Clear') ]);
		/* сеанс 198 (audit tail): edits after a test make the tested args
		 * stale — the badge says so, and Apply refuses honestly (the server
		 * rebuild check would fail the stale args anyway, but silently). */
		const compStaleBadge = E('span', { 'class': 'hpui-badge hpui-b-amber', style: 'display:none' },
			[ _('The composition changed since the test — run "Test composition" again.') ]);
		const restoreRow = E('div', { 'class': 'wiz-note', style: 'margin:4px 0' }, [ '' ]);
		compBox.appendChild(compRowsBox);
		compBox.appendChild(E('div', { 'class': 'wiz-toolbar' },
			[ compAddBtn, compTestBtn, compApplyBtn, compClearBtn, compStaleBadge ]));
		compBox.appendChild(restoreRow);
		function updateCompStale() {
			compStaleBadge.style.display = state.compStale ? '' : 'none';
		}
		compBox.appendChild(E('p', { 'class': 'wiz-note' },
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

			const rm = E('button', { 'class': 'hpui-btn hpui-btn-danger hpui-btn-sm', type: 'button',
				title: _('Remove') }, [ '×' ]);
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
			/* сеанс 198: any draft edit invalidates the tested args — the
			 * badge shows it and Apply refuses (the server rebuild check
			 * would fail the stale args anyway, but silently). */
			if (state.compBuilt)
				state.compStale = true;
			updateCompStale();
			/* profiles cross as a JSON-encoded STRING (issue #11). */
			L.resolveDefault(callComposeSave(JSON.stringify(state.compProfiles)), {}).then(function(r) {
				if (r && r.result === false)
					state.compSaveError = (r && r.error) || _('rpc error');
				else
					state.compSaveError = null;
			});
		}

		/* Seed the builder once (first dpi poll): the user's saved draft
		 * beats the empty default. Bug (а), с.193: when the DRAFT is empty
		 * but UCI already carries profiles (источник истины), the editor
		 * must INHERIT them — the old «общего профиля нет» blind apply is
		 * gone. Unsaved local edits still win (compDirty). */
		function seedCompProfiles(dpi) {
			if (state.compSeeded || state.compDirty)
				return;
			const uciProf = (dpi && dpi.profiles_sync && dpi.profiles_sync.profiles) || null;
			const server = (dpi && dpi.comp_profiles) || null;
			let src = null, kind = null;
			if (server && server.length) { src = server; kind = 'draft'; }
			else if (uciProf && uciProf.length) { src = uciProf; kind = 'uci'; }
			if (!src)
				return;
			state.compSeeded = true;
			const arr = [];
			for (let i = 0; i < src.length; i++) {
				const p = src[i];
				if (!p || !(p.engine === 'zapret' || p.engine === 'byedpi'))
					continue;
				if (kind === 'uci' && p.enabled === false)
					continue;
				let res = '' + (p.resource || 'general');
				/* UCI custom profiles («custom:<имя>») map to the builder's
				 * Custom list — the domains carry the identity. */
				const cm = res.match(/^custom:(.+)$/);
				if (cm)
					res = 'custom';
				if (!['youtube', 'discord', 'telegram', 'general', 'custom'].some(function(x) { return x === res; }))
					continue;
				arr.push({
					engine: p.engine, resource: res,
					domains: '' + (p.domains || ''), strategy: '' + (p.strategy || '')
				});
			}
			if (arr.length) {
				state.compProfiles = arr;
				if (kind === 'uci')
					state.compFromUci = true;
				renderCompProfiles();
			}
		}

		/* Bug (б), с.193: the long check is watched by a DEDICATED tiny
		 * poller (ONLY the status file read — a few hundred bytes, far
		 * under the 20 s XHR window) instead of piggybacking on the
		 * 10-RPC page refresh, where one stalled call froze the whole
		 * stage display intermittently (observed live, 1 of 2 runs). */
		let composeJobTimer = null;
		function composeJobStop() {
			if (composeJobTimer) {
				window.clearInterval(composeJobTimer);
				composeJobTimer = null;
			}
		}
		function composeJobStart() {
			composeJobStop();
			const t0 = Date.now();
			composeJobTimer = window.setInterval(function() {
				if (!dpiResult.isConnected) {
					composeJobStop();
					return;
				}
				L.resolveDefault(callComposeStatus(), {}).then(function(r) {
					if (!dpiResult.isConnected) {
						composeJobStop();
						return;
					}
					const st = (r && r.status) || null;
					if (!st) {
						composeJobStop();
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Composition test status lost — check the operations journal.') ]));
						compTestBtn.disabled = false;
						return;
					}
					renderCompose({ status: st });
					if (st.running) {
						if (Date.now() - t0 > 600000) {
							composeJobStop();
							compTestBtn.disabled = false;
							dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
								[ _('The test is still running after 10 minutes — the stage display stopped; the result will surface in the status card.') ]));
						}
						return;
					}
					composeJobStop();
					compTestBtn.disabled = false;
				});
			}, 2500);
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
				if (!r || r.result === false) {
					compTestBtn.disabled = false;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Compose failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				state.compBuilt = { zapret: r.zapret || '', byedpi: r.byedpi || '' };
				state.compStale = false;
				updateCompStale();
				/* This run's DONE verdict is FRESH, not stale-from-before-
				 * page-load: pre-arm the seed guard so the result renders. */
				state.composeSeeded = true;
				state.composeSig = 'run';
				/* The run RPC returns AT ONCE (the worker tests in the
				 * background) — the tiny status poller takes over. */
				composeJobStart();
			});
		});

		compApplyBtn.addEventListener('click', function() {
			const cb = state.compBuilt || {};
			if (!cb.zapret && !cb.byedpi) {
				ui.addNotification(null, E('p', {},
					_('Run "Test composition" first — Apply uses the server-built args.')), 'error');
				return;
			}
			/* сеанс 198 (audit tail): a stale test must not pass silently —
			 * Apply refuses in the result area (the honest one place). */
			if (state.compStale) {
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('The composition changed since the test — run "Test composition" again: Apply uses the tested server-built args, and a stale test fails the server-side rebuild check.') ]));
				return;
			}
			/* Bug (в), с.193: the SAME overwrite contract as the global
			 * apply — the composition REPLACES the whole UCI profile set;
			 * the user confirms it explicitly (counting what is replaced). */
			const ps = (state.lastDpi && state.lastDpi.profiles_sync &&
				state.lastDpi.profiles_sync.profiles) || [];
			let nNow = 0;
			for (let i = 0; i < ps.length; i++)
				if (ps[i] && ps[i].enabled !== false)
					nNow++;
			hp.confirmModal(_('Apply composition'),
				(nNow > 0)
					? _('Apply this composition? It REPLACES the whole profile set: %d profile(s) live now, their strategies go to the server snapshot (Restore stays available) and the applied line is rebuilt from the composition. A short engine restart follows.').format(nNow)
					: _('Apply this composition? The applied line is rebuilt from the composition and a short engine restart follows (the previous strategies go to the server snapshot — Restore stays available).'),
				_('Apply')).then(function(ok) {
				if (!ok)
					return;
			compApplyBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Applying composition — the service restarts…') ]));
			/* Сеанс 191: профили едут в apply — сервер сверяет пересборку и
			 * пишет зеркало UCI-профилей одним коммитом. */
			L.resolveDefault(callComposeApply(cb.zapret || '', cb.byedpi || '',
				JSON.stringify(state.compProfiles)), {}).then(function(r) {
				compApplyBtn.disabled = false;
				if (!r || (r.result === false && !r.op_id)) {
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Apply failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
				pollApply(r, _('Composition applied and verified — the engine(s) are enabled.'), function(ok) {
					if (!ok)
						return;
					const box = E('div', {});
					box.appendChild(E('p', { 'class': 'hpui-hint' },
						[ _('Composition applied and verified — the engine(s) are enabled.') ]));
					const rbBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' },
						[ _('Restore previous') ]);
					rbBtn.addEventListener('click', function() {
						rbBtn.disabled = true;
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Restoring the previous strategies — the service restarts…') ]));
						L.resolveDefault(callComposeRollback(), {}).then(function(r2) {
							rbBtn.disabled = false;
							if (!r2 || (r2.result === false && !r2.op_id)) {
								dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
									[ _('Restore failed: ') + ((r2 && r2.error) || _('rpc error')) ]));
								return;
							}
							pollApply(r2, _('Previous strategies restored and verified.'));
						});
					});
					box.appendChild(rbBtn);
					box.appendChild(E('p', { 'class': 'hpui-hint' },
						[ _('The same Restore stays available below and after a page reload (server snapshot).') ]));
					dom.content(dpiResult, box);
				});
			});
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
			const rb = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button', 'style': 'margin-left:8px' },
				[ _('Restore') ]);
			rb.addEventListener('click', function() {
				rb.disabled = true;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Restoring the previous strategies — the service restarts…') ]));
				L.resolveDefault(callComposeRollback(), {}).then(function(r) {
					rb.disabled = false;
					if (!r || (r.result === false && !r.op_id)) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Restore failed: ') + ((r && r.error) || _('rpc error')) ]));
						return;
					}
					pollApply(r, _('Previous strategies restored and verified.'));
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
		const labQuick = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' }, [ _('Fuzz (quick)') ]);
		const labFull = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Full fuzz') ]);
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
			/* Honest probe mode (skuid|fallback): the fallback warning lives in
			 * the RESULT box (amber badge, res.probe_mode) — an early return on
			 * st.probe_mode here hid the whole ranking forever, because the
			 * final status file ALSO carries probe_mode (the live "strategies
			 * never appeared" report 2026-11-07). */
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
			/* ч.236: same exclusion as the ranking table (ч.232) — «current
			 * (applied)» is prepended at [0] by the builder and holds 0/0
			 * (quick battery does not measure it by design), so taking [0]
			 * verbatim showed «No strategy passes…» over a green 3/3 table. */
			const best = res.strategies.filter(function(x) { return x.name !== 'current (applied)'; })[0];
			if (best && best.ok > 0)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
					[ _('Recommended: %s — %d of %d distinguishing hosts pass (avg %d ms)').format(
						best.name, best.dist_ok || 0, best.dist_total || 0, best.avg_tls_ms || 0) ]));
			else
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'font-weight:600' },
					[ _('No strategy passes the distinguishing hosts — try the full fuzz, the strategy generator, or check your ISP blocking.') ]));
			/* Audit 2026-11-07: the probe-honesty boundary — the user report
			 * («probe says Default, real devices say Hostfakesplit»): the
			 * verdict is a measurement, not a guarantee. */
			if (res.probe_mode === 'fallback')
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'color:var(--hp-warn,#b60)' }, [
					badge('hpui-b-amber', _('Fallback probe mode')),
					' ' + _('The isolated probe user is unavailable — the ranking is noisier than usual, and the sweep may briefly disturb the router\'s own connections to the test hosts.')
				]));
			box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' },
				[ _('The verdict is a measurement on THIS router at THIS moment: DPI regimes change over the day, phone clients ride QUIC (only strategies with a UDP profile touch it), and a browser opens many parallel connections. Margins under ~25% are noise — verify the winner on your real devices before trusting it.') ]));
			/* Ф6.4 (аудит 84): baseline-СЕРИЯ — дрейф между первым и
			 * контрольным проходом показывается честно. */
			if (res.baseline_series && res.baseline_series.drift && res.baseline_series.drift.length)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' },
					[ _('Baseline drift detected on: %s — the free-pass credit requires BOTH baseline passes (conservative).').format(
						res.baseline_series.drift.map(function(d) { return d.tag; }).join(', ')) ]));
			/* Ф6.4 (аудит 58/83): расхождение наборов DNS — честно, без
			 * «подмены» без дифференциальной пробы. */
			if (res.dns_sets) {
				const dnsParts = Object.keys(res.dns_sets).map(function(t) {
					const d = res.dns_sets[t];
					return t + ': ' + (d.verdict || '?');
				}).join(' · ');
				const dnsBad = Object.keys(res.dns_sets).filter(function(t) {
					return res.dns_sets[t] && res.dns_sets[t].verdict === 'divergence';
				});
				if (dnsBad.length)
					box.appendChild(E('div', { 'class': 'wiz-note', title: _('Sets compared: the device resolver path vs independent resolvers (direct UDP 8.8.8.8 / 1.1.1.1 and independent DoH). A divergence is geo-balancing/anycast/CDN policy — NOT a proof of poisoning without the differential probe.') },
						[ badge('hpui-b-amber', _('DNS sets diverge')), ' ' + dnsParts ]));
			}
			/* Ф6.4 (аудит 67/92): вердикты ресурсов — NO VIABLE STRATEGY
			 * называет, ЧТО не работает; best_available — только вручную.
			 * ч.231: рядом с best_verified честно отмечается, что ТЕКУЩАЯ
			 * применённая стратегия тоже прошла deep-батарею — замена
			 * подтверждённой в пределах шума прогона не обязательна. */
			if (res.verdicts) {
				const RESL = { youtube: _('YouTube'), discord: _('Discord'), telegram: _('Telegram'), general: _('General') };
				const curA0 = dpiSt && dpiSt.zapret ? ('' + (dpiSt.zapret.strategy || '')) : '';
				const DTAG = { youtube: 'yt', discord: 'dc', telegram: 'tg' };
				Object.keys(res.verdicts).forEach(function(rn) {
					const v = res.verdicts[rn];
					if (!v || !v.verdict)
						return;
					if (v.verdict === 'unmeasured') {
						/* ч.234: измерение невозможно (мёртвый тег: ни одна
						 * стратегия не прошла + оба контрола провалены) —
						 * СЕРЫЙ «не удалось измерить» вместо красного
						 * «ни одна стратегия не прошла»; works-метка выше
						 * этого отказа и дала бы best_verified серверно. */
						box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [
							badge('hpui-b-grey', _('MEASUREMENT UNAVAILABLE')),
							' ' + (RESL[rn] || rn) + ': ' +
							_('the test host did not answer for ANY strategy and in both control passes — a measurement failure (network drift/TSPU), not a strategy verdict; re-run the sweep later.')
						]));
					} else if (v.verdict === 'no_candidate') {
						box.appendChild(E('div', { 'class': 'wiz-note', style: 'color:var(--hp-danger,#c00)' }, [
							badge('hpui-b-red', _('NO VIABLE STRATEGY')),
							' ' + (RESL[rn] || rn) + ': ' +
							((v.what_failed && v.what_failed.length)
								? v.what_failed.join(' · ')
								: _('no strategy passes the mandatory checks'))
						]));
					} else if (v.verdict === 'best_available') {
						box.appendChild(E('div', { 'class': 'wiz-note' }, [
							badge('hpui-b-amber', _('BEST AVAILABLE (manual only)')),
							' ' + (RESL[rn] || rn) + ': ' + ((v.chosen && v.chosen.name) || '') + ' — ' +
							_('the handshake passes but the mandatory component tests are unconfirmed; auto-pick will NOT apply it — pick it manually if it suits you.')
						]));
						/* ч.233 (согласовано с пользователем): кнопок у
						 * НЕприменённого выбора нет — маркируется то, что реально
						 * обслуживает трафик (группа ниже, у current). */
					} else if (v.verdict === 'best_verified' && v.chosen && v.chosen.name) {
						box.appendChild(E('div', { 'class': 'wiz-note' }, [
							badge('hpui-b-green', _('BEST VERIFIED')),
							' ' + (RESL[rn] || rn) + ': ' + v.chosen.name
						]));
						/* ч.274 dedgu: the browser sign of the winner — did the
						 * browser-class ClientHello survive the dead edges this
						 * strategy revived? Absent = probe class unmeasured. */
						const dbt = (v.chosen.dead_browser_total > 0) ? v.chosen.dead_browser_total : 0;
						if (dbt > 0) {
							const dbo = v.chosen.dead_browser_ok || 0;
							box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [
								badge(dbo > 0 ? 'hpui-b-green' : 'hpui-b-amber',
									_('browser: %s/%s').format(dbo, dbt)),
								' ' + _('Browser-ClientHello class on the dead edges this strategy revived — the curl class and the browser class can disagree.')
							]));
						}
						/* ч.235 (вариант (i), согласован с пользователем): честная
						 * current-ремарка вместо утверждения «прошла». Полный
						 * проход — серый бейдж и прежний текст; частичный —
						 * янтарный бейдж с реальным счётом; ресурс батарей не
						 * измерялся — серое «deep не измерялась» (не измерено
						 * ≠ провал). Сама строка из таблицы убрана ч.232 —
						 * этот блок единственная поверхность этих данных. */
						if (curA0 && DTAG[rn]) {
							const cRow = res.strategies.filter(function(x) { return x.args === curA0; })[0] || null;
							const cHosts = (cRow && cRow.deep && cRow.deep.hosts) || [];
							let cItem = null;
							cHosts.forEach(function(hd) { if (hd.tag === DTAG[rn]) cItem = hd; });
							if (cItem && cItem.deep_total > 0 && (cItem.deep_pass || 0) === cItem.deep_total)
								box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [
									badge('hpui-b-grey', _('current (applied)')),
									' ' + _('The currently applied strategy also passed the deep battery (%s) — replacing it within the run noise is optional, not required.').format(
										(cItem.deep_pass || 0) + '/' + cItem.deep_total)
								]));
							else if (cItem && cItem.deep_total > 0)
								box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [
									badge('hpui-b-amber', _('current (applied)')),
									' ' + _('The deep battery measured the current strategy at %s — not all components passed; keeping or replacing it is your call.').format(
										(cItem.deep_pass || 0) + '/' + cItem.deep_total)
								]));
							else if (cRow)
								box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [
									badge('hpui-b-grey', _('current (applied)')),
									' ' + _('The deep battery did not measure this resource for the current strategy — no verdict is claimed (unmeasured is not a failure).')
								]));
							/* ч.233 (согласовано): ОДНА кнопочная группа на ресурс —
							 * у ПРИМЕНЁННОЙ стратегии (chosen == curA0 → одна группа,
							 * задвоение убрано; подпись несёт ресурс и имя). */
							const dbc = devButtons(rn, curA0, (RESL[rn] || rn) + ' · ' +
								((cRow && cRow.name) || _('custom args')));
							if (dbc)
								box.appendChild(dbc);
						}
					}
					(v.notes || []).forEach(function(nn) {
						box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.8' }, [ '· ' + nn ]));
					});
				});
			}
			/* ч.123: the sweep-level QUIC verdict — measured UDP/443
			 * passability to the YouTube video edge, once per sweep. Ф6.4:
			 * only the three honest verdicts render — a garbage token
			 * (the live «NaN» fact) reads as unmeasured, no badge.
			 * ч.234: формулировки явно называют это СОСТОЯНИЕМ ПРОВАЙДЕРА
			 * в момент свипа, не вердиктом стратегий (пользователь читал
			 * «QUIC отрезан» как «в v3 сломалось»; до v3 QUIC не измерялся
			 * вовсе — «работал всегда» это браузерный TCP-фоллбек). */
			if (res.quic && res.quic.verdict != null &&
				[ 'vn', 'icmp', 'silence' ].indexOf('' + res.quic.verdict) >= 0) {
				const qv = '' + res.quic.verdict;
				const qtxt = (qv === 'vn')
					? _('QUIC (UDP 443) to the YouTube video edge is OPEN (measured) — provider state at the sweep moment, NOT a strategy verdict: strategies without fake-QUIC leave browser QUIC attempts unserved (the browser falls back to TCP).')
					: (qv === 'icmp')
						? _('QUIC (UDP 443) to the YouTube video edge is REJECTED (measured) — provider state at the sweep moment, NOT a strategy verdict: the browser falls back to TCP quickly; TCP-only strategies serve the whole resource.')
						: _('QUIC (UDP 443) to the YouTube video edge got NO answer (measured) — provider state at the sweep moment, NOT a strategy verdict: the browser falls back to TCP; TCP-only strategies serve the whole resource.');
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
			/* ч.235 (решение пользователя): load average свипа — отличает
			 * «хост умер» от «роутер задыхался» (прод-nfqws2 + кандидат +
			 * пробы одновременно) в ретроспективе. */
			if (res.loads != null && res.load_now != null) {
				let lmax = 0;
				for (const lk in res.loads) {
					const lv = parseFloat(res.loads[lk]);
					if (!isNaN(lv) && lv > lmax) lmax = lv;
				}
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.75' },
					[ _('Router load during the sweep (1-min avg): max %s, at finish %s.').format(
						lmax.toFixed(2), ('' + res.load_now).split(' ')[0] || '0') ]));
			}
			if (res.deep_failed && res.deep_failed.length)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.75' },
					[ _('Deep check failed (retried once, no verdict): %s — these strategies rank as untested.').format(res.deep_failed.join(', ')) ]));
			/* ч.232: honest probe-class note — without utls_probe the Passed
			 * column measures only the curl class (no browser ClientHello). */
			if (res.utls_probe === false)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.75' },
					[ _('The browser ClientHello probe (utls_probe) is not installed — "Passed" measures only the curl class. Install native helpers to measure what TSPU actually sees.') ]));
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
			/* ч.232 (просьба пользователя): строка «current (applied)» — это
			 * ТЕКУЩАЯ применённая композиция, а не кандидат; в таблице
			 * ранжирования она только путает. Её данные остаются в результате
			 * (вердикт «текущая тоже прошла» выше, оптимизатор, метки
			 * устройства) — из таблицы она убрана. */
			const tableRows = res.strategies.filter(function(x) { return x.name !== 'current (applied)'; });
			tableRows.slice(0, 15).forEach(function(s, i) {
				const hostsTip = (s.hosts || []).map(function(h) {
					return (h.label || h.tag) + ' ' +
						(h.ok ? '✓ ' + h.votes + '/' + h.rounds + ' · median ' + (h.median_ms || 0) + ' ms · jitter ' + (h.jitter_ms || 0) + ' ms'
						      : '✗ ' + (h.reason || 'fail')) +
						(h.dist ? '' : ' (' + _('free pass') + ')') +
						/* ч.232: браузерный ClientHello-класс (utls_probe). */
						(h.uok === true ? ' · uTLS ✓ ' + (h.utls_ms || 0) + ' ms'
							: (h.uok === false ? ' · uTLS ✗ ' + (h.u_reason || 'fail') : '')) +
						(h.ip2 ? (h.alt_ok ? ' · IP2 ✓' : ' · IP2 ✗ ' + (h.alt_reason || 'fail')) : '');
				}).join(' · ');
				/* ч.232: метки с устройства — бейджи у имени (живые, не
				 * снапшот свипа). */
				const devBadges = devMarksOf(s.args).map(function(m) {
					return badge(m.verdict === 'works' ? 'hpui-b-green' : 'hpui-b-red',
						m.short + ' ' + (m.verdict === 'works' ? '✓' : '✗'));
				});
				/* Ф6.4 (аудит 92): вердикт стратегии по ресурсам — бейджем у
				 * имени (проверен/доступен), как назвал Strategy Lab v3. */
				let vBadge = null;
				if (res.verdicts) {
					Object.keys(res.verdicts).forEach(function(rn) {
						const v = res.verdicts[rn];
						if (v && v.chosen && v.chosen.args && v.chosen.args === s.args) {
							if (v.verdict === 'best_verified')
								vBadge = badge('hpui-b-green', _('verified'));
							else if (v.verdict === 'best_available' && !vBadge)
								vBadge = badge('hpui-b-amber', _('available'));
						}
					});
				}
				/* ч.109 (user request): pick THIS strategy for ONE resource —
				 * the rule/apply/verify chain of the auto-pick runs for the
				 * chosen resource with the table's strategy (no re-fuzz). */
				const resSel = E('select', { 'class': 'cbi-input-select',
					'style': 'width:auto; font-size:.85em; padding:0' });
				resSel.appendChild(E('option', { value: '' }, [ _('— whole Zapret —') ]));
				[ ['youtube', _('YouTube')], ['discord', _('Discord')],
				  ['telegram', _('Telegram')], ['general', _('General')] ]
					.forEach(function(o) { resSel.appendChild(E('option', { value: o[0] }, [ o[1] ])); });
				const ab = E('button', { 'class': 'hpui-btn hpui-btn-primary hpui-btn-sm', type: 'button' },
					[ _('Apply') ]);
				ab.addEventListener('click', function() {
					const target = resSel.value;
					const targetLabel = resSel.options[resSel.selectedIndex].text;
					if (!target) {
						hp.confirmModal(_('Apply strategy'),
							_('Apply this Zapret strategy globally (every flow routed to Zapret) and restart the service?'), _('Apply'))
							.then(function(ok) {
								if (!ok)
									return;
								ab.disabled = true;
								L.resolveDefault(callFuzzApply(s.args), {}).then(function(r2) {
									ab.disabled = false;
									if (!r2 || (r2.result === false && !r2.op_id)) {
										ab.textContent = '✗';
										dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
											[ (r2 && r2.error) || _('Apply failed') ]));
										return;
									}
									ab.textContent = '…';
									pollApply(r2, _('Strategy applied and verified — the service serves it now; run "Test strategy" to confirm.'),
										function(ok) { ab.textContent = ok ? '✓' : '✗'; });
								});
							});
						return;
					}
					hp.confirmModal(_('Apply strategy'),
						_('Apply this strategy for %s: a SCOPED profile is built (other managed resources keep their strategies), the rule goes to Zapret, then the resource is checked live — page, CDN and the REAL video stream. Continue?').format(targetLabel), _('Apply'))
						.then(function(ok) {
							if (!ok)
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
							: E('span', { 'class': 'hpui-badge', style: 'opacity:.7' }, [ 'TCP' ]) ]
							.concat(vBadge ? [ ' ', vBadge ] : [])
							.concat(devBadges.length ? [ ' ' ].concat(devBadges) : [])),
					E('td', { style: 'white-space:nowrap',
						title: (s.total === 0) ? _('no handshake rounds for this entry — it is measured by the deep battery only') : '' },
					[ (s.total === 0)
						? E('span', { style: 'opacity:.55' }, [ _('deep only') ])
						: '%d / %d'.format(s.ok || 0, s.total || 0) ]),
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
			/* ч.231: хосты, недоступные ВСЕМ стратегиям и обоим baseline,
			 * исключены из счёта Passed — они меряют сеть, не стратегии. */
			if (res.dead_hosts && res.dead_hosts.length)
				box.appendChild(E('div', { 'class': 'wiz-note', style: 'opacity:.85' }, [
					badge('hpui-b-grey', _('excluded')),
					' ' + _('Hosts that failed for EVERY strategy and both baseline passes are excluded from the Passed column — they measure the network, not the strategies: %s.').format(
						res.dead_hosts.map(function(d) { return (d.label || d.tag) + ' (' + (d.host || '?') + ')'; }).join(', '))
				]));
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
			hp.confirmModal(_('Full sweep'),
				_('Run the FULL strategy sweep? Every candidate is measured in turn (temp NFQUEUE, live traffic untouched) — this takes up to ~15 minutes.'), _('Start'))
				.then(function(ok) { if (ok) labStart('full'); });
		});

		/* Auto-tune (Ф8-F7 T3): ONE click — fuzz (reused when fresh) → best
		 * strategy for the resource → optional rule → apply with the server
		 * snapshot → live check of the configured path. Progress and the
		 * result render into dpiResult (ONE place). */
		const autSel = E('select', { 'class': 'cbi-input-select', 'style': 'width:auto' });
		/* ч.233: Telegram убран из автоподбора (решение пользователя — без
		 * VPN/туннеля tg в РФ не поднимается; стратегии пробуются вручную). */
		[ ['youtube', _('YouTube')], ['discord', _('Discord')],
		  ['general', _('General (best overall)')] ]
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
		const autBtn = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
			[ _('Auto-pick strategy') ]);
		const autRow = E('div', { 'class': 'wiz-row' },
			[ autBtn, autSel, autFullWrap, autSetRuleWrap, autStatus ]);
		dpiPick.appendChild(autRow);
		dpiPick.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('One click: the fuzzer ranks the corpus (reused when fresh), the best strategy for the resource is applied as a scoped profile with a server snapshot, and the resource is then checked through the configured path (page, CDN, the REAL video stream in KB/s). Zapret only — ByeDPI strategies are configured on the Application tab.') ]));
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
			hp.confirmModal(_('Auto-pick strategy'), what.format(autSel.options[autSel.selectedIndex].text), _('Start'))
				.then(function(ok) {
					if (!ok)
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
		});

		/* ── ч.97 → Ф7.1: the SCHEDULED strategy auto-pilot moved to the
		 * Automation page (level «DPI auto-pilot») — an always-on keeper is
		 * automation, not a strategy setting. The live status still feeds
		 * the Serving map and Quality panels here (wizard_autopilot_status).
		 * The one-click auto-pick stays: it belongs to the Lab/measure flow. */
		dpiPick.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('The scheduled auto-pilot (enable, resources, re-rank interval, night auto-pick) lives on the Auto-bypass page, "DPI auto-pilot" level — an always-on keeper belongs to automation. The daemon hot-reads its settings every tick.') ]));
		/* D32: the pointer button "Open the DPI auto-pilot settings" is GONE —
		 * out of place here; the settings live on the Auto-bypass page (Ф7.1)
		 * and the note above says so in words. */

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
			 * re-shown (same contract as the compose test). ч.249: the seed ALSO
			 * records the sig — the old code seeded without it, so the SECOND
			 * poll tick rendered the stale done-box anyway (the session-163
			 * report: yesterday's pre-ч.236 run with the dead redirector row
			 * popped up under every page load). */
			if (!state.autopickSeeded) {
				state.autopickSeeded = true;
				state.autopickSig = 'done:' + ((st && st.ts) || 0) + ':' + ((st && st.stage) || '');
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
			/* ч.232: проверьте на устройстве (телефон/ПК) и отметьте — метка
			 * сильнее лаборатории: «работает» поднимает стратегию во всех
			 * выборщиках, «не работает» исключает из автоподбора. ч.233:
			 * подпись «Ресурс · имя стратегии» — тот же формат, что в
			 * вердиктах Лаборатории. */
			const dbr = devButtons(st.resource || resource, ch.args,
				resName + ' · ' + (ch.name || _('custom args')));
			if (dbr)
				box.appendChild(dbr);
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
			const rb = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Restore previous') ]);
			rb.addEventListener('click', function() {
				rb.disabled = true;
				dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
					[ _('Restoring the previous strategies — the service restarts…') ]));
				L.resolveDefault(callComposeRollback(), {}).then(function(r2) {
					rb.disabled = false;
					if (!r2 || (r2.result === false && !r2.op_id)) {
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Restore failed: ') + ((r2 && r2.error) || _('rpc error')) ]));
						return;
					}
					pollApply(r2, _('Previous strategies restored and verified.'));
				});
			});
			box.appendChild(rb);
			dom.content(dpiResult, box);
		}

		/* Сеанс 191: цепочка «apply → rule → verify» удалена вместе с
		 * панелью-дублем (см. шапку render()). Маршрутизация сервисов —
		 * на «Правилах для сервисов». */

		/* Strategy catalog: refresh from the external source + the generator. */
		const corpusLine = E('div', { 'class': 'wiz-note' });
		const corpusBtns = E('div', { 'class': 'wiz-row' });
		const updBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Update from catalog') ]);
		const genBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Generate mutations') ]);
		corpusBtns.appendChild(updBtn);
		corpusBtns.appendChild(genBtn);
		/* ч.123: share strategies between routers (the same user runs TWO
		 * with different ISPs): export the corpus as JSON, import a file with
		 * the same merge rules as the catalog (no duplicate args, cap 240).
		 * The RANKING itself is ISP-specific and is never exported — the note
		 * says so explicitly. */
		const expBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Export strategies') ]);
		const impBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Import strategies') ]);
		const impFile = E('input', { type: 'file', accept: '.json,application/json', style: 'display:none' });
		expBtn.addEventListener('click', function() {
			const cands = (state.cands || []).map(function(c) {
				return { name: c.name, args: c.args, group: c.group || 'imported' };
			});
			if (!cands.length) {
				ui.addNotification(null, E('p', {}, _('Nothing to export — the corpus is empty.')), 'error');
				return;
			}
			const doc = { format: 're-ravnex-strategies', version: 1,
				exported: new Date().toISOString(),
				note: _('Strategies are ISP-specific: the RANKING does not transfer between providers — import and re-run the fuzz.'),
				candidates: cands };
			const blob = new Blob([ JSON.stringify(doc, null, 2) ], { type: 'application/json' });
			const a = E('a', { href: URL.createObjectURL(blob), download: 'ravnex-zapret-strategies.json' });
			document.body.appendChild(a);
			a.click();
			a.remove();
			/* сеанс 198 (audit tail): the download answers in the result area —
			 * the button never stays silent. */
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
				[ _('Exported %d strategies — the file %s is downloaded.').format(cands.length, 'ravnex-zapret-strategies.json') ]));
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
			[ _('The catalog gathers strategies from several public sources: the StressOzz/Zapret-Manager catalogs (converted to nfqws2 by the update), the imported Tachyon corpus, the provider-community index (republished by our validated lists hub) and the built-in generator that derives new strategies from the best fuzz results when nothing works. Every strategy is tested on the router and shows the diff before anything is applied.') ]));

		/* Per-provider strategies (zemidala via the lists hub): pick YOUR
		 * provider ASN, import the community-verified strategies into the
		 * corpus; the Strategy Lab measures them like everything else. */
		const zemiLine = E('div', { 'class': 'wiz-note' });
		const zemiSel = E('select', { 'class': 'hpui-select', 'style': 'max-width:100%' });
		const zemiBtn = E('button', { 'class': 'hpui-btn hpui-btn-ghost', type: 'button' }, [ _('Import provider strategies') ]);
		const zemiRow = E('div', { 'class': 'wiz-row' }, [ zemiSel, zemiBtn ]);
		dpiCorpus.appendChild(E('div', { 'style': 'margin-top:6px; font-weight:bold' },
			[ _('Strategies by provider (community index)') ]));
		dpiCorpus.appendChild(zemiRow);
		dpiCorpus.appendChild(zemiLine);
		dpiCorpus.appendChild(E('p', { 'class': 'wiz-note' },
			[ _('Community-verified nfqws2 strategies for YOUR provider ASN (zemidala/nfqws2-strategies, republished by the validated lists hub — no license upstream: consumed over the network with attribution). Imported strategies join the corpus as measured candidates; the Lab ranks them like any other.') ]));
		function renderZemi(z) {
			const sel = (z && z.zemidala && z.zemidala.index && z.zemidala.index.providers) || null;
			zemiSel.innerHTML = '';
			if (!sel) {
				zemiSel.appendChild(E('option', {}, [ _('(updating the provider index…)') ]));
				zemiBtn.disabled = true;
				zemiLine.textContent = (z && z.imported && z.imported.asns && Object.keys(z.imported.asns).length)
					? _('Imported: %s. The index is being refreshed in the background.').format(
						Object.keys(z.imported.asns).map(function(a) { return 'AS' + a; }).join(', '))
					: _('The provider index is being refreshed in the background — reopen the page in a minute.');
				return;
			}
			zemiBtn.disabled = false;
			sel.sort(function(a, b) { return (b.reports || 0) - (a.reports || 0); });
			for (let p of sel)
				zemiSel.appendChild(E('option', { value: '' + p.asn },
					[ 'AS' + p.asn + ' — ' + (p.provider || '') + ' (' + (p.count || 0) + ', ' + (p.reports || 0) + ')' ]));
			const imp = (z && z.imported && z.imported.asns) || {};
			const zmd = (z && z.corpus_zmd) || {};
			const parts = [];
			for (let a in imp)
				parts.push(_('AS%s (%s): %d strategies in the corpus').format(a, imp[a].provider || '', zmd[a] || 0));
			zemiLine.textContent = parts.length ? parts.join(' · ') : _('Nothing imported yet — pick your provider and import.');
		}

		zemiBtn.addEventListener('click', function() {
			const asn = zemiSel.value;
			if (!asn)
				return;
			zemiBtn.disabled = true;
			dom.content(dpiResult, E('p', { 'class': 'hpui-hint' }, [ _('Importing AS%s strategies…').format(asn) ]));
			L.resolveDefault(callStrategyImportStart(asn), {}).then(function(r) {
				if (!r || r.result === false) {
					zemiBtn.disabled = false;
					dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
						[ _('Import failed: ') + ((r && r.error) || _('rpc error')) ]));
					return;
				}
			const oid = r.op_id;
			/* Audit B2 (с.193): the interval MUST die with the section
			 * (isConnected gate) and must not loop forever when the op
			 * registry is lost (rpcd restart mid-import) — cap the watch. */
			const deadline = Date.now() + 600000;
			const poll = window.setInterval(function() {
				if (!dpiResult.isConnected) {
					window.clearInterval(poll);
					return;
				}
				L.resolveDefault(callOpStatus(oid), {}).then(function(o) {
					if (!dpiResult.isConnected) {
						window.clearInterval(poll);
						return;
					}
					const op = (o && o.op) || null;
					if (!op || Date.now() > deadline) {
						window.clearInterval(poll);
						zemiBtn.disabled = false;
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ _('Import status lost — check the operation journal.') ]));
						return;
					}
					if (op.status === 'completed' || op.status === 'failed') {
						window.clearInterval(poll);
						zemiBtn.disabled = false;
						dom.content(dpiResult, E('p', { 'class': 'hpui-hint' },
							[ (op.status === 'completed')
								? _('Imported: %s. Run a fuzz to measure the new strategies.').format(op.detail || '')
								: _('Import failed: %s').format(op.detail || '') ]));
						refresh();
					}
				});
			}, 2000);
			});
		});

		function renderCorpus(meta, strat) {
			const sig = JSON.stringify([ meta.count, meta.groups, meta.updated ]);
			if (sig !== state.corpusSig) {
				state.corpusSig = sig;
				const g = meta.groups || {};
				const parts = [ _('corpus: %d strategies').format(meta.count || 0) ];
				const known = {};
				for (let gg in DPI_GROUPS) {
					known[DPI_GROUPS[gg][0]] = true;
					if (g[DPI_GROUPS[gg][0]])
						parts.push(DPI_GROUPS[gg][1] + ': ' + g[DPI_GROUPS[gg][0]]);
				}
				/* ч.183: ANY group not in DPI_GROUPS still shows its count —
				 * a future import must never silently vanish from the line
				 * (the whole-project rule: added somewhere → check the rest). */
				for (let gk in g)
					if (!known[gk])
						parts.push(gk + ': ' + g[gk]);
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
			const applyImport = E('button', { 'class': 'hpui-btn hpui-btn-primary', type: 'button' },
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
		 * diagnostics to Check & repair (ч.200, D34b: tg-ws удалён) — this
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
				L.resolveDefault(callAutoPilotStatus(), {}),
				L.resolveDefault(callDeviceVerdicts(), {}),
				L.resolveDefault(callStrategySourceStatus(), {})
		]).then(function(data) {
			/* Audit B1 (с.193): one gate for the WHOLE paint phase — RPC
			 * continuations (button handlers, op polls) resolve after the
			 * section is gone; painting by id into the next mount's nodes
			 * (same ids) or into null is exactly the renderDpi crash class. */
			if (!bypRoot.isConnected)
				return;
			if (data[0] && data[0].env)
					lastEnv = data[0].env;
				/* ч.232: live device marks (fresher than any sweep snapshot). */
				state.dev = (data[8] && data[8].device) || state.dev || {};
				renderDpi(data[1] || {});
				state.lastDpi = data[1] || {};
				seedCompProfiles(data[1] || {});
				renderStrategySel((data[2] && data[2].candidates) || []);
				renderCorpus(data[1] ? (data[1].corpus || {}) : {}, data[3] || {});
				renderZemi(data[9] || {});
				renderLab(data[4] || {}, data[1] || {});
				/* Ф8-F4: compose test progress/result + the server-snapshot
				 * restore row (covers composition AND plain strategy applies). */
				renderCompose(data[5] || {});
				/* Ф8-F7 T3: auto-pick progress/result (same ONE place). */
				renderAutoPick(data[6] || {});
				/* ч.109: the Serving map (rule → engine → strategy → check). */
				renderServingMap(data[1] || {}, (data[0] && data[0].rules) ? data[0] : null, data[7] || {});
				/* ч.123: the Overview «Quality now» panel. */
				renderDpiQuality(data[1] || {}, data[7] || {}, data[4] || {});
				renderRollback((data[1] && data[1].rollback) || null);
				/* Сеанс 191: карточка синхрона профилей (дрейф/посев). */
				renderProfilesSync(data[1] || {});
			});
		}

		poll.add(hp.vpoll(refresh), hp.pollSec(4));
		refresh();

		return bypRoot;
	}
});
