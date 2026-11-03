/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex — Health center (plan 20 §3 Ф2.6, D21; design polish lands in Ф9.1).
 * One page for the whole Ф2 loop: live status of every subsystem (Health),
 * honest per-entry explanations (Ф2.5 explain composer), the "system
 * attention" list (Sentinel findings that do not map to a Health entry),
 * the repair history (Recovery) and the unified event feed (Event Bus).
 * Actions: per-key manual repair / unblock (recovery_action) and the service
 * restart through the apply door (diag_service_restart + op polling).
 * ALL action results render in ONE bottom area (ui.action_buttons_result_placement).
 */

'use strict';
'require dom';
'require homeproxy as hp';
'require poll';
'require rpc';
'require ui';
'require view';

const callExplain = rpc.declare({
	object: 'luci.homeproxy',
	method: 'health_explain',
	expect: { '': {} }
});

const callEvents = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_events',
	params: [ 'limit' ],
	expect: { '': {} }
});

const callRepair = rpc.declare({
	object: 'luci.homeproxy',
	method: 'recovery_action',
	params: [ 'action', 'target', 'note' ],
	expect: { '': {} }
});

const callServiceRestart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_service_restart',
	expect: { '': {} }
});

const callOpStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_op_status',
	params: [ 'op_id' ],
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

/* The unified feed: same icons and source labels as the Control journal. */
const evIcons = { block: '🔒', allow: '🔓', temp: '⏱', wifi: '📶', schedule: '📅', system: '⚙️', update: '⬆️',
	learn: '🧠', heal: '✅', outage: '⚠️', outage_end: '✅', clear: '🗑️', recheck: '🔁',
	switch: '🔄', dead: '⛔', recovered: '✅', reload: '♻️', down: '⛔', degraded: '⚠️',
	repair: '🛠️', stale: '⏳', loop: '🔁', blocked: '⛔', unblocked: '✅',
	manual: '🖐️', proposal: '💡' };
const evColors = { down: 'hpui-c-red', degraded: 'hpui-c-amber', repair: 'hpui-c-green',
	loop: 'hpui-c-red', blocked: 'hpui-c-red', proposal: 'hpui-c-amber',
	unblocked: 'hpui-c-green', recovered: 'hpui-c-green' };
const srcLabels = { control: _('Access Control'), automation: _('Auto-bypass'),
	hotswap: 'Hot Swap', urltest: 'URLTest', health: _('Health'),
	sentinel: 'Sentinel', recovery: 'Recovery' };

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
		const b = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button' }, [ _('Repair') ]);
		b.addEventListener('click', function() { onRepair(ex); });
		box.appendChild(b);
	}
	if (ex.unblockable) {
		const b = E('button', { 'class': 'btn cbi-button-negative', 'type': 'button' }, [ _('Unblock') ]);
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
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	render: function() {
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
		document.head.appendChild(styleEl);

		/* ── banner ─────────────────────────────────────────────────── */
		const verdictEl = E('span', { 'class': 'hc-verdict' }, [ '…' ]);
		const countEl = E('span', { 'class': 'hc-fresh' }, [ '' ]);
		const chipHealth = E('span', { 'class': 'hc-chip' }, [ '' ]);
		const chipSentinel = E('span', { 'class': 'hc-chip' }, [ '' ]);
		const chipRecovery = E('span', { 'class': 'hc-chip' }, [ '' ]);
		const banner = E('div', { 'class': 'hc-banner', 'id': 'hc-banner' }, [
			verdictEl, countEl, chipHealth, chipSentinel, chipRecovery
		]);

		/* ── services table ─────────────────────────────────────────── */
		const svcWrap = E('div', {}, []);

		/* ── system attention ───────────────────────────────────────── */
		const attentionEl = E('div', {}, []);

		/* ── repair history ─────────────────────────────────────────── */
		const historyEl = E('div', {}, []);

		/* ── event feed ─────────────────────────────────────────────── */
		const evList = E('div', { 'class': 'hpui-log', 'style': 'max-height:300px' }, []);

		/* ── actions + ONE result area ──────────────────────────────── */
		const restartBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', 'type': 'button' },
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
						noteResult(_('The operation is still running — check the operation journal on the Diagnostics page.'), false);
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

		poll.add(refreshAll, 10);
		refreshAll();

		return E('div', {}, [
			styleEl,
			hp.pageIntro(_('Health center'),
				_('Live status of every Ravnex subsystem: what is running, what the automatic recovery has done and will do next, and what you can do by hand. The feed below is the same event journal the system writes for itself.')),
			banner,
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('heart'), _('Services') ]),
				E('p', { 'class': 'hpui-hint' },
					[ _('Every status carries an honest explanation: why it is what it is, what the watchdogs and the recovery coordinator have already done, what happens next — and what you can do by hand.') ]),
				svcWrap
			]),
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('alert'), _('System attention') ]),
				attentionEl
			]),
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('tool'), _('Repair history') ]),
				historyEl
			]),
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('activity'), _('Events') ]),
				E('p', { 'class': 'hpui-hint' },
					[ _('The unified event feed of all subsystems. The full journal with the clear button lives in Access control → Journal.') ]),
				evList
			]),
			E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('repeat'), _('Actions') ]),
				E('div', { 'class': 'hc-actions' }, [ restartBtn ]),
				E('p', { 'class': 'hpui-hint' },
					[ _('The service restart re-routes every connection and goes through the verified apply door; a verified apply also resets every automatic repair campaign.') ])
			]),
			resultEl
		]);
	}
});
