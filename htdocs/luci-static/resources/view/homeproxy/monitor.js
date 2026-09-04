/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Node Monitoring dashboard (Forkop/Podkop-style): engine & core status cards,
 * per-node latency table and an active-connections monitor, powered by the
 * monitor_* RPCs (Clash API snapshot + UCI state).
 */

'use strict';
'require dom';
'require homeproxy as hp';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

const callMonitorNodes = rpc.declare({
	object: 'luci.homeproxy',
	method: 'monitor_nodes',
	expect: { '': {} }
});

const callMonitorConnections = rpc.declare({
	object: 'luci.homeproxy',
	method: 'monitor_connections',
	expect: { '': {} }
});

const callMonitorConnectionsClose = rpc.declare({
	object: 'luci.homeproxy',
	method: 'monitor_connections_close',
	expect: { '': {} }
});

/* Same 4-colour scheme as the "Active URLTest node" line in Client Settings —
 * palette matches the Automation tab: red = confirmed dead (65535 timeout
 * sentinel), orange = slow (>=3000 ms), green = healthy, gray = unmeasured. */
const C_RED = '#e05252', C_GREEN = '#3fbf5f', C_AMBER = '#e07b00', C_GREY = '#9a9a9a';

function delayView(delay) {
	if (delay === 65535)
		return { color: C_RED, text: _('Timeout') };
	if (delay == null)
		return { color: C_GREY, text: '—' };
	if (delay >= 3000)
		return { color: C_AMBER, text: delay + ' ms' };
	return { color: C_GREEN, text: delay + ' ms' };
}

function statusView(status) {
	switch (status) {
		case 'alive':         return { color: C_GREEN, text: _('Alive') };
		case 'timeout':       return { color: C_RED,   text: _('Timeout') };
		case 'unmeasured':    return { color: C_GREY,  text: _('Unmeasured') };
		case 'unsupported':   return { color: C_AMBER, text: _('Unsupported by core') };
		case 'not_in_config': return { color: C_GREY,  text: _('Not in config') };
	}
	return { color: C_GREY, text: status || '—' };
}

function fmtBytes(n) {
	n = Number(n) || 0;
	if (n >= 1073741824) return (n / 1073741824).toFixed(2) + ' GB';
	if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
	if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
	return n + ' B';
}

function chainLabel(tag) {
	const m = (tag || '').match(/^cfg-(.+)-out$/);
	if (m) {
		const label = uci.get('homeproxy', m[1], 'label');
		if (label) return label;
	}
	return tag;
}

function imp(node, styles) {
	for (const k in styles) node.style.setProperty(k, styles[k], 'important');
}

function cardWrap(titleEl, bodyEl) {
	/* Same translucent card as the Automation stat cards (hpui-card). */
	return E('div', { 'class': 'hpui-card', 'style': 'min-width:170px' }, [
		E('div', { 'style': 'font-weight:bold; margin-bottom:4px' }, [ titleEl ]),
		E('div', {}, [ bodyEl ])
	]);
}

function makeTable(headers) {
	const table = E('table', { 'class': 'hpui-table' });
	const tr = E('tr', {});
	for (const h of headers)
		tr.appendChild(E('th', {}, [ h ]));
	table.appendChild(E('thead', {}, [ tr ]));
	table._tbody = E('tbody', {});
	table.appendChild(table._tbody);
	return table;
}

function addRow(table, cells) {
	const tr = E('tr', {});
	for (const c of cells) {
		const td = E('td', { 'style': 'white-space:nowrap' });
		if (c.el) td.appendChild(c.el);
		else {
			const span = E('span', { 'style': 'color:' + (c.color || 'inherit') }, [ c.text == null ? '—' : String(c.text) ]);
			td.appendChild(span);
		}
		tr.appendChild(td);
	}
	table._tbody.appendChild(tr);
	return tr;
}

return view.extend({
	load: function() {
		return Promise.all([ uci.load('homeproxy') ]);
	},

	render: function() {
		/* Shared design system (Automation look): cards, table, palette. */
		hp.uiStyle();

		const coreBody = E('div', {}, [ '—' ]);
		const activeBody = E('div', {}, [ '—' ]);
		const zapretBody = E('div', {}, [ '—' ]);
		const byedpiBody = E('div', {}, [ '—' ]);
		const nodesBody = E('div', {}, [ '—' ]);

		const cards = E('div', {
			'style': 'display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; margin:6px 0 14px'
		}, [
			cardWrap(_('Core'), coreBody),
			cardWrap(_('Active node'), activeBody),
			cardWrap(_('Zapret'), zapretBody),
			cardWrap(_('ByeDPI'), byedpiBody),
			cardWrap(_('Nodes'), nodesBody)
		]);

		const nodeTableWrap = E('div', {});
		const connTableWrap = E('div', {});
		const connHead = E('div', { 'style': 'margin:6px 0' }, [ '—' ]);

		const closeBtn = E('button', {
			'class': 'btn cbi-button cbi-button-negative',
			'click': ui.createHandlerFn(this, function() {
				return L.resolveDefault(callMonitorConnectionsClose(), {}).then(function(r) {
					if (r && r.result === false)
						ui.addNotification('error', _('Failed to close connections'));
					return refreshConnections();
				});
			})
		}, [ _('Close all connections') ]);

		const panelNodes = E('div', { 'class': 'monitor-panel cbi-section' }, [
			E('h3', {}, [ _('Nodes') ]),
			cards,
			nodeTableWrap
		]);

		const panelConn = E('div', { 'class': 'monitor-panel cbi-section' }, [
			E('h3', {}, [ _('Connections') ]),
			E('div', { 'style': 'display:flex; align-items:center; gap:12px; flex-wrap:wrap' }, [ connHead, closeBtn ]),
			connTableWrap
		]);

		function modeText(mode) {
			if (mode === 'auto') return _('Auto — all nodes (recommended)');
			if (mode === 'prefer') return _('Preferred node + auto');
			return _('Manual node list');
		}

		function serverText(n) {
			let port = n.port || '';
			if (n.port_range)
				port = n.port_range;
			else if (n.hopping && n.hopping.length)
				port = port + ' (' + n.hopping.join(', ') + ')';
			return n.address + (port ? ':' + port : '');
		}

		function renderNodeTable(st) {
			const nodes = st.nodes || [];
			/* Counts line */
			let alive = 0, down = 0;
			for (const n of nodes) {
				if (n.status === 'alive') alive++;
				else if (n.status === 'timeout') down++;
			}
			nodesBody.innerHTML = '';
			nodesBody.appendChild(E('span', { 'style': 'font-weight:bold; color:' + (alive ? C_GREEN : C_RED) },
				[ _('%d alive, %d down, %d total').format(alive, down, nodes.length) ]));

			if (!st.clash_ok) {
				nodeTableWrap.innerHTML = '';
				nodeTableWrap.appendChild(E('em', { 'style': 'color:#e05252' }, [ _('Node monitoring is unavailable') ]));
				return;
			}
			if (!nodes.length) {
				nodeTableWrap.innerHTML = '';
				nodeTableWrap.appendChild(E('em', {}, [ _('No nodes configured') ]));
				return;
			}

			const sig = JSON.stringify(nodes);
			if (sig === renderNodeTable._sig)
				return;
			renderNodeTable._sig = sig;

			const prevWrap = nodeTableWrap.firstElementChild;
			const scrollTop = (prevWrap && prevWrap.tagName === 'DIV') ? prevWrap.scrollTop : 0;

			const table = makeTable([ _('Node'), _('Type'), _('Server'), _('Pool'), _('Delay'), _('Status') ]);
			for (const n of nodes) {
				const dv = delayView(n.delay);
				const sv = statusView(n.status);
				const nameEl = E('span', {}, [ n.label ]);
				if (n.selected) {
					nameEl.appendChild(document.createTextNode(' '));
					nameEl.appendChild(E('span', { 'style': 'color:goldenrod' }, [ '★' ]));
				}
				const tr = addRow(table, [
					{ el: nameEl },
					{ text: n.type, color: 'inherit' },
					{ text: serverText(n), color: 'inherit' },
					{ text: n.in_pool ? '✓' : '—', color: n.in_pool ? C_GREEN : C_GREY },
					{ text: dv.text, color: dv.color },
					{ text: sv.text, color: sv.color }
				]);
				if (n.selected)
					imp(tr, { background: 'rgba(218,165,32,.10)' });
			}

			nodeTableWrap.innerHTML = '';
			const wrap = E('div', { 'class': 'hpui-wrap' });
			imp(wrap, { 'max-height': '420px' });
			wrap.appendChild(table);
			nodeTableWrap.appendChild(wrap);
			wrap.scrollTop = scrollTop;
		}

		function engineBody(st, key) {
			const e = st[key] || {};
			let color, text;
			if (!e.installed) { color = C_GREY;  text = _('Not installed'); }
			else if (!e.enabled) { color = C_GREY; text = _('Disabled'); }
			else if (e.running) { color = C_GREEN; text = _('Running'); }
			else { color = C_RED; text = _('Stopped'); }
			const el = E('div', {}, [ E('span', { 'style': 'color:' + color, 'font-weight': 'bold' }, [ text ]) ]);
			if (e.version)
				el.appendChild(document.createTextNode(' ' + e.version));
			return el;
		}

		function refreshNodes() {
			return L.resolveDefault(callMonitorNodes(), {}).then(function(st) {
				if (!st || st.error || !st.nodes) {
					coreBody.textContent = '—';
					activeBody.textContent = '—';
					zapretBody.textContent = '—';
					byedpiBody.textContent = '—';
					nodesBody.innerHTML = '';
					nodesBody.appendChild(E('em', { 'style': 'color:#e05252' }, [ _('Node monitoring is unavailable') ]));
					return;
				}

				/* Core card */
				coreBody.innerHTML = '';
				if (st.core) {
					coreBody.appendChild(E('span', {
						'style': 'color:' + (st.core.running ? C_GREEN : C_RED) + '; font-weight:bold'
					}, [ st.core.running ? _('Running') : _('Stopped') ]));
					coreBody.appendChild(document.createTextNode(
						' ' + (st.core.type || '') + (st.core.version ? ' ' + st.core.version : '')));
				} else {
					coreBody.appendChild(E('span', { 'style': 'color:#e05252' }, [ _('Not installed') ]));
				}

				/* Active node card */
				activeBody.innerHTML = '';
				const selected = (st.nodes || []).filter(function(n) { return n.selected; })[0];
				if (selected) {
					const dv = delayView(selected.delay);
					activeBody.appendChild(E('span', { 'style': 'color:' + dv.color, 'font-weight': 'bold' },
						[ selected.label + (dv.text === '—' ? '' : ' — ' + dv.text) ]));
					activeBody.appendChild(E('div', { 'style': 'color:#9a9a9a; font-size:.85em' },
						[ (st.main_node === 'urltest') ? _('URLTest') + ' · ' + modeText(st.urltest_mode) : _('Main node') ]));
				} else {
					activeBody.appendChild(E('span', { 'style': 'color:#9a9a9a' }, [ _('No active node') ]));
					activeBody.appendChild(E('div', { 'style': 'color:#9a9a9a; font-size:.85em' },
						[ (st.main_node === 'urltest') ? _('URLTest') + ' · ' + modeText(st.urltest_mode) : _('Main node') ]));
				}

				zapretBody.innerHTML = '';
				zapretBody.appendChild(engineBody(st, 'zapret'));
				byedpiBody.innerHTML = '';
				byedpiBody.appendChild(engineBody(st, 'byedpi'));

				renderNodeTable(st);
			}).catch(function(e) {
				nodesBody.innerHTML = '';
				nodesBody.appendChild(E('em', { 'style': 'color:#e05252' }, [ _('Node monitoring is unavailable') ]));
			});
		}

		function renderConnTable(r) {
			const conns = r.connections || [];
			connHead.innerHTML = '';
			connHead.appendChild(E('span', {}, [
				_('Downloaded') + ': ' + fmtBytes(r.download_total) + ' · ' +
				_('Uploaded') + ': ' + fmtBytes(r.upload_total) +
				(r.count ? ' (' + r.count + ')' : '')
			]));

			if (r.error) {
				connTableWrap.innerHTML = '';
				connTableWrap.appendChild(E('em', { 'style': 'color:#e05252' }, [ _('Connections monitoring is unavailable') ]));
				return;
			}
			if (!conns.length) {
				connTableWrap.innerHTML = '';
				connTableWrap.appendChild(E('em', {}, [ _('No active connections') ]));
				return;
			}

			const prevWrap = connTableWrap.firstElementChild;
			const scrollTop = (prevWrap && prevWrap.tagName === 'DIV') ? prevWrap.scrollTop : 0;

			const table = makeTable([ _('Host'), _('Network'), _('Chain'), _('Rule'), _('Downloaded'), _('Uploaded') ]);
			for (const c of conns) {
				const chain = (c.chain || []).map(chainLabel).join(' → ');
				addRow(table, [
					{ text: c.host || c.destination || '—', color: 'inherit' },
					{ text: (c.network || '').toUpperCase(), color: C_GREY },
					{ text: chain || '—', color: 'inherit' },
					{ text: c.rule || '—', color: C_GREY },
					{ text: fmtBytes(c.download), color: 'inherit' },
					{ text: fmtBytes(c.upload), color: 'inherit' }
				]);
			}

			connTableWrap.innerHTML = '';
			const wrap = E('div', { 'class': 'hpui-wrap' });
			imp(wrap, { 'max-height': '380px' });
			wrap.appendChild(table);
			connTableWrap.appendChild(wrap);
			wrap.scrollTop = scrollTop;
		}

		function refreshConnections() {
			return L.resolveDefault(callMonitorConnections(), {}).then(function(r) {
				renderConnTable(r || { error: 'no data' });
			}).catch(function(e) {
				connTableWrap.innerHTML = '';
				connTableWrap.appendChild(E('em', { 'style': 'color:#e05252' }, [ _('Connections monitoring is unavailable') ]));
			});
		}

		poll.add(refreshNodes, 5);
		poll.add(refreshConnections, 5);
		refreshNodes();
		refreshConnections();

		return E('div', {}, [ panelNodes, panelConn ]);
	}
});
