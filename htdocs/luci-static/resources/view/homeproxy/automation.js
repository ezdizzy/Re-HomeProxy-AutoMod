/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy — Automation tab.
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

const callTestNow = rpc.declare({
	object: 'luci.homeproxy',
	method: 'automation_test_now',
	expect: { '': {} }
});

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
			_('Automatically learn blocked sites: traffic that fails directly but works through the proxy is added to the proxy list. Fully compatible with ByeDPI and Zapret — learned sites simply use your configured main path. After toggling, press “Restart service” below.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('balanced', _('Balanced'));
		o.value('aggressive', _('Aggressive (also re-verifies learned sites)'));
		o.default = 'balanced';

		o = s.option(form.ListValue, 'discover', _('Discover candidates from'));
		o.value('clash', _('Clash API (connections, domain names)'));
		o.value('dns', _('DNS query log (captures domain at DNS time — most transparent)'));
		o.value('conntrack', _('conntrack (destinations by IP — for apps/games without SNI)'));
		o.value('both', _('Clash API + DNS log'));
		o.value('all', _('Clash API + DNS log + conntrack'));
		o.default = 'clash';

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

		o = s.option(form.Value, 'reload_interval', _('Config reload throttle (seconds)'));
		o.datatype = 'uinteger';
		o.placeholder = '300';

		o = s.option(form.Value, 'exclude', _('Never auto-learn (comma-separated)'),
			_('Domains / IPs excluded from learning (substring & domain match). Defaults cover LAN and local names.'));
		o.placeholder = 'localhost,local,lan,in-addr.arpa,ip6.arpa';

		o = s.option(form.Flag, 'ip_learn', _('Learn IP destinations (conntrack)'),
			_('Also learn destinations reached by raw IP (games/apps without SNI). Routes the IP via the proxy. Off by default — enable if you run such apps.'));
		o.default = o.disabled;

		o = s.option(form.Flag, 'preload_enabled', _('Preload blocked-domain list at startup'),
			_('Fetch a plaintext domain list once at start (and daily) and seed it as learned, so popular blocked sites work on the very first visit.'));
		o.rmempty = false;

		o = s.option(form.Value, 'preload_url', _('Preload list URL'),
			_('Plaintext list, one domain per line. Default points at the Re-filter publication list.'));
		o.depends('preload_enabled', '1');

		/* ── DNS failover (C) — lives in the `config` section ─────────────── */
		const sf = m.section(form.NamedSection, 'config', 'homeproxy', _('DNS failover'));
		let fo = sf.option(form.Flag, 'dns_failover', _('Enable DNS failover'),
			_('Monitor the primary DNS; if it becomes unreachable, switch to a healthy server from the list below and regenerate. Only plain (UDP/Do53) servers are health-checked; DoH/DoT are assumed always up.'));
		fo.rmempty = false;

		fo = sf.option(form.DynamicList, 'alt_dns_servers', _('Alternate DNS servers'),
			_('Add/remove fallback DNS servers (IP, hostname, or DoH/DoT URL). Used by failover and shown alongside the main DNS choice.'));
		fo.depends('dns_failover', '1');
		fo.placeholder = '1.1.1.1';

		/* ── Live monitor ──────────────────────────────────────────────── */
		const countsEl = E('div', { 'class': 'automation-counts' });
		const tableEl = E('div', { 'class': 'automation-table' });
		const logEl = E('pre', { 'class': 'automation-log' });
		const ta = new ui.Textarea('learned', _('Learned proxy list (editable)'));
		ta.rows = 10;

		const actions = E('div', { 'class': 'automation-actions' }, [
			btn(_('Test now'), function() { return callTestNow(); }),
			btn(_('Clear learned'), function() {
				return callClear().then(function() { return callListRead(); }).then(function(r) {
					ta.setValue(r.content || '');
				});
			}),
			btn(_('Save list'), function() {
				return callListWrite(ta.getValue());
			}),
			btn(_('Restart service'), function() { return callRestart(); })
		]);

		const panel = E('div', { 'class': 'automation-panel cbi-section' }, [
			E('h3', {}, [ _('Monitor') ]),
			countsEl,
			tableEl,
			E('div', { 'class': 'automation-actions' }, [ actions ]),
			ta,
			E('h4', {}, [ _('Engine log') ]),
			logEl
		]);

		function renderTable(learned) {
			tableEl.innerHTML = '';
			if (!learned || !learned.length) {
				tableEl.appendChild(E('em', {}, [ _('Nothing learned yet. Browse the web or press “Test now”.') ]));
				return;
			}
			for (let i = 0; i < learned.length && i < 500; i++)
				tableEl.appendChild(E('div', { 'class': 'automation-row' }, [ learned[i] ]));
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
				if (ta.getValue() === '' || ta.getValue() == null)
					ta.setValue((st.learned || []).join('\n'));
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
