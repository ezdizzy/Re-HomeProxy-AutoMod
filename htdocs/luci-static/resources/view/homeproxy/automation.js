/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — Automation tab.
 * Settings for the auto blocked-site detection engine plus a live monitor of what it
 * has learned. The detection only ADDS sites proven unreachable directly yet reachable
 * via the proxy, and routes them through the user's configured main path — so it stays
 * fully compatible with ByeDPI and Zapret (those engines ARE the main path).
 */

'use strict';
'require dom';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

const callStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_status',
	expect: { '': {} }
});

const callListRead = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_list_read',
	expect: { '': {} }
});

const callListWrite = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_list_write',
	params: ['content'],
	expect: { '': {} }
});

const callClear = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_clear',
	expect: { '': {} }
});

const callClearLog = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_clear_log',
	expect: { '': {} }
});

const callTestNow = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_test_now',
	expect: { '': {} }
});

const callBackup = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_backup',
	expect: { '': {} }
});

const callRestore = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_restore',
	params: ['content'],
	expect: { '': {} }
});

function downloadList(content) {
	const blob = new Blob([content || ''], { type: 'text/plain' });
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'homeproxy_learned_list.txt';
	document.body.appendChild(a);
	a.click();
	a.remove();
	URL.revokeObjectURL(a.href);
}

const callRestart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'diag_service_restart',
	expect: { '': {} }
});

function btn(label, handler) {
	return E('button', {
		'class': 'btn',
		click: function() {
			const el = this;
			el.disabled = true;
			Promise.resolve(handler()).finally(function() { el.disabled = false; });
		}
	}, [ label ]);
}

return view.extend({
	render: function() {
		const m = new form.Map('homeproxy', _('Automation'));
		const s = m.section(form.NamedSection, 'automation', 'homeproxy', _('Auto blocked-site detection'));

		let o = s.option(form.Flag, 'enabled', _('Enable automation'),
			_('Automatically learn blocked sites: traffic that fails directly but works through the proxy is added to the Routing Rules lists. Fully compatible with ByeDPI and Zapret — learned sites simply use your configured main path.<br>'
			+ '<b>Mode notes:</b> active only in "Bypass blocking". Automatically paused in Global (everything tunnels anyway, nothing to learn), while the Main node is Direct (no proxy side to verify against), and in Custom routing / Custom JSON. After toggling, press "Restart service" below.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('balanced', _('Balanced'));
		o.value('aggressive', _('Aggressive (also re-verifies learned sites)'));
		o.default = 'balanced';

		o = s.option(form.ListValue, 'performance', _('Performance profile'),
			_('eco: classic serial probing for weak routers. perf: up to 64 domains / 32 IPs per pass probed in parallel batches (16 at once) — needs a multi-core router with 1 GB RAM (e.g. GL.iNet Flint 2). auto: detected from CPU cores and memory.'));
		o.value('auto', _('Auto (detect by hardware)'));
		o.value('eco', _('Eco — serial, weak routers'));
		o.value('perf', _('Performance — parallel, strong routers'));
		o.default = 'auto';

		o = s.option(form.MultiValue, 'discover', _('Discover candidates from'),
			_('Domain-name sources to watch for candidates. Raw-IP destinations are a separate switch below (“Learn IP destinations”).'));
		o.value('dns', _('DNS query log (captures domain at DNS time — most transparent)'));
		o.value('clash', _('Clash API (connections, domain names)'));
		o.value('sni', _('TLS SNI capture (ClientHello — DoH clients, hardcoded-IP apps, games)'));
		o.default = [ 'dns', 'clash', 'sni' ];
		o.rmempty = false;
		/* Legacy configs store a single string ('all' | 'both' | 'clash' | ...) — map
		 * it to the equivalent checkbox set for display, so nothing looks unchecked. */
		o.cfgvalue = function() {
			let v = uci.get('homeproxy', 'automation', 'discover');
			if (v == null) return this.default;
			if (!Array.isArray(v)) v = [ v ];
			if (v.length === 0 || v.includes('all')) return [ 'dns', 'clash', 'sni' ];
			if (v.includes('both')) v = v.filter(function(x) { return x !== 'both'; }).concat([ 'dns', 'clash' ]);
			return v.filter(function(x) { return [ 'dns', 'clash', 'sni' ].includes(x); });
		};

		o = s.option(form.Value, 'timeout', _('Probe timeout (seconds)'));
		o.datatype = 'uinteger';
		o.placeholder = '6';

		o = s.option(form.Value, 'max_entries', _('Maximum learned entries'));
		o.datatype = 'uinteger';
		o.placeholder = '2000';

		o = s.option(form.Value, 'min_confirm', _('Confirmations required before learning'));
		o.datatype = 'uinteger';
		o.placeholder = '1';

		o = s.option(form.Value, 'reeval_interval', _('Re-evaluate learned interval (seconds)'));
		o.datatype = 'uinteger';
		o.placeholder = '3600';

		/* NOTE: legacy UCI keys reload_interval / flush_min_entries are intentionally
		 * NOT exposed: learned entries hot-reload into the running core with no restart
		 * and no dropped connections, so batching windows serve no purpose. The daemon
		 * keeps honoring the defaults for old configs. */
		o = s.option(form.TextValue, 'exclude', _('Never auto-learn'),
			_('Domains / IPs excluded from learning (substring & domain match). One entry per line or comma-separated; lines starting with # are comments, blank lines allowed - organize the list as you like.') + ' '
			+ _('Defaults when empty: localhost, local, lan, in-addr.arpa, ip6.arpa.'));
		o.placeholder = 'localhost\nlocal\nlan\n# my own notes:\n# example.com\nin-addr.arpa,ip6.arpa';
		o.rows = 8;
		o.monospace = true;
		o.wrap = false;

		o = s.option(form.Flag, 'ip_learn', _('Learn IP destinations'),
			_('Watch recurring conntrack destinations (games, Telegram data centers, apps without SNI) and learn those that fail directly but answer through the proxy. Off by default — enable if you use such apps.'));
		o.default = o.disabled;

		/* ── Live monitor ──────────────────────────────────────────────── */
		const countsEl = E('div', { 'class': 'automation-counts' });
		const tableEl = E('div', { 'class': 'automation-table' });
		const logEl = E('pre', { 'class': 'automation-log', style: 'max-height:300px; overflow:auto; white-space:pre-wrap; word-break:break-word; margin:0; padding:8px; background:#1e1e1e; color:#ddd; border:1px solid #333; border-radius:4px; font-size:0.85em' });

		const fileInput = E('input', {
			type: 'file',
			accept: '.txt,text/plain',
			style: 'display:none'
		});
		fileInput.addEventListener('change', function() {
			const file = fileInput.files[0];
			if (!file) return;
			const reader = new FileReader();
			reader.onload = function() {
				callRestore(String(reader.result)).then(function(r) {
					if (!r || r.result === false)
						ui.addNotification('error', _('Restore failed: ') + ((r && r.error) || ''));
					else
						ui.addNotification('info', _('Restore complete — added %d site(s).').format(r.added || 0));
					return refresh();
				}).catch(function(e) {
					ui.addNotification('error', _('Restore failed: ') + e);
				});
			};
			reader.readAsText(file);
			fileInput.value = '';
		});

		const actions = E('div', { 'class': 'automation-actions', 'style': 'margin-top:10px' }, [
			btn(_('Test now'), function() { return callTestNow().then(refresh); }),
			btn(_('Backup list'), function() {
				return callBackup().then(function(r) {
					if (!r || r.result === false) {
						ui.addNotification('error', _('Backup failed: ') + ((r && r.error) || _('no learned list yet')));
						return;
					}
					downloadList(r.content || '');
				});
			}),
			btn(_('Restore list'), function() { fileInput.click(); }),
			btn(_('Clear learned'), function() {
				if (!window.confirm(_('Delete ALL learned sites? The engine will re-learn them from scratch.')))
					return Promise.resolve();
				return callClear().then(refresh);
			}),
			btn(_('Clear log'), function() {
				return callClearLog().then(refresh);
			}),
			btn(_('Restart service'), function() { return callRestart(); })
		]);

		const panel = E('div', { 'class': 'automation-panel cbi-section' }, [
			E('h3', {}, [ _('Monitor') ]),
			countsEl,
			E('h4', {}, [ _('Learned sites') ]),
			tableEl,
			actions,
			E('p', { 'class': 'automation-hint' }, [ _('Backup list downloads the learned sites to your computer. Restore list uploads a file and adds any missing sites (existing ones are kept). Use this to avoid re-learning from scratch after a router reset.') ]),
			fileInput,
			E('h4', {}, [ _('Engine log') ]),
			logEl
		]);

		function fmtTime(ts) {
			if (!ts) return '—';
			try { return new Date(Number(ts) * 1000).toLocaleString(); }
			catch (e) { return String(ts); }
		}

		function reasonText(e) {
			if (e.status === 'blocked') {
				/* Restored/imported entries (or records from older daemon versions)
				 * carry no probe codes — show a plain verdict instead of empty ✗✗/✓✓. */
				if (!e.direct && !e.proxy)
					return _('blocked (details not recorded)');
				let d = e.direct || '✗', p = e.proxy || '✓';
				return _('direct %s ✗ / proxy %s ✓').format(d, p);
			}
			if (e.status === 'blocked_no_proxy') return _('blocked both ways');
			if (e.status === 'unknown') return _('uncertain');
			return e.status || '—';
		}

		function renderTable(learned) {
			if (!learned || !learned.length) {
				tableEl.innerHTML = '';
				tableEl.appendChild(E('em', {}, [ _('Nothing learned yet. Browse the web or press “Test now”.') ]));
				return;
			}
			if (!learned.every(function(e) { return e && (e.host || e.ip); })) {
				return;
			}
			function imp(node, styles) {
				for (var k in styles) node.style.setProperty(k, styles[k], 'important');
			}
			const table = E('table', { 'class': 'table cbi-section-table' });
			imp(table, { width: '100%', 'border-collapse': 'collapse' });
			const thead = E('thead', {});
			const htr = E('tr', {});
			const headers = [
				[ _('Resource'), 'left' ],
				[ _('Type'), 'center' ],
				[ _('Added'), 'left' ],
				[ _('Last check'), 'left' ],
				[ _('Why'), 'left' ]
			];
			headers.forEach(function(h) {
				const th = E('th', {}, [ h[0] ]);
				imp(th, { background: '#707070', 'font-weight': '600', color: '#f2f2f2', 'text-align': h[1], border: '1px solid #555' });
				htr.appendChild(th);
			});
			thead.appendChild(htr);
			table.appendChild(thead);
			const tbody = E('tbody', {});
			const maxRows = 500;
			for (let i = 0; i < learned.length && i < maxRows; i++) {
				const e = learned[i];
				const cells = [
					String(e.host || ''),
					e.type === 'ip' ? _('IP') : _('Domain'),
					String(fmtTime(e.added)),
					String(fmtTime(e.last_probe)),
					String(reasonText(e))
				];
				const aligns = ['left', 'center', 'left', 'left', 'left'];
				const tr = E('tr', {});
				for (let c = 0; c < cells.length; c++) {
					const td = E('td', {}, [ cells[c] ]);
					const s = { 'text-align': aligns[c], border: '1px solid #d0d0d0' };
					if (c === 2 || c === 3) { s['white-space'] = 'nowrap'; s.color = '#555'; }
					imp(td, s);
					td._origColor = s.color || '';
					tr.appendChild(td);
				}
				tr.addEventListener('mouseenter', (function(row) {
					return function() { for (var j = 0; j < row.children.length; j++) { row.children[j].style.setProperty('background', '#707070', 'important'); row.children[j].style.setProperty('color', '#f2f2f2', 'important'); } };
				})(tr));
				tr.addEventListener('mouseleave', (function(row) {
					return function() { for (var j = 0; j < row.children.length; j++) { row.children[j].style.setProperty('background', '', 'important'); row.children[j].style.setProperty('color', row.children[j]._origColor || '', 'important'); } };
				})(tr));
				tbody.appendChild(tr);
			}
			table.appendChild(tbody);
			tableEl.innerHTML = '';
			const wrap = E('div', {});
			imp(wrap, { 'max-height': '340px', overflow: 'auto', 'margin-top': '4px' });
			wrap.appendChild(table);
			tableEl.appendChild(wrap);
		}

		function refresh() {
			return callStatus().then(function(st) {
				const c = st.counts || {};
				countsEl.innerHTML =
					_('Enabled') + ': <b>' + (st.enabled === '1' ? _('yes') : _('no')) + '</b> &nbsp;|&nbsp; ' +
					_('Learned (blocked)') + ': <b>' + (c.learned || 0) + '</b> &nbsp;|&nbsp; ' +
					_('Direct') + ': <b>' + (c.direct || 0) + '</b> &nbsp;|&nbsp; ' +
					_('Unknown') + ': <b>' + (c.unknown || 0) + '</b>';
				renderTable(st.learned);
				logEl.textContent = st.log || '';
			}).catch(function(e) {
				countsEl.textContent = _('Status unavailable: ') + e;
			});
		}

		poll.add(refresh, 5);
		refresh();

		return Promise.all([ m.render(), Promise.resolve(panel) ]).then(function(nodes) {
			return E('div', {}, nodes);
		});
	}
});
