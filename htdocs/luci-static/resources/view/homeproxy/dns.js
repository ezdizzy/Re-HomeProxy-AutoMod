/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — DNS Settings page.
 *
 * Layout mirrors the actual engine semantics:
 *   Tab "DNS servers"       — the two POOLS used by Russia/bypass split routing
 *                             (plain "Russia" pool resolves domestic domains directly,
 *                              encrypted "Secure" pool resolves blocked domains through
 *                              the proxy). Both pools are what MultiDNS races.
 *   Tab "Single DNS & reserve" — the Global-routing-mode scheme: ONE primary server,
 *                             plus the legacy reserve-DNS failover (switch to one of
 *                             the alternate servers when the primary dies). The
 *                             alternates/preset only matter while failover is ON,
 *                             so they stay hidden otherwise.
 *   Tab "MultiDNS"          — the racing engine + live quality monitor.
 *
 * This page only MOVES options between views: every UCI name is identical to what
 * the scripts consume — no backend/script logic is affected.
 */

'use strict';
'require view';
'require form';
'require poll';
'require rpc';
'require validation';
'require homeproxy as hp';

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

return view.extend({
	render: function() {
		/* Shared design system (Automation look) for the quality monitor. */
		hp.uiStyle();

		const m = new form.Map('homeproxy', _('DNS Settings'));

		const mdDisable = rpc.declare({ object: 'luci.homeproxy', method: 'multidns_disable', expect: { '': {} } });

		const s = m.section(form.NamedSection, 'config', 'homeproxy', null);
		s.addremove = false;

		s.tab('pools', _('DNS servers'));
		s.tab('reserve', _('Reserve DNS'));
		s.tab('multidns', _('MultiDNS'));
		let o;

		/* ── Tab: DNS servers (the split-routing pools) ─────────────────── */
		o = s.taboption('pools', form.DynamicList, 'russia_dns_server', _('Russia DNS server') + ' 🔓',
			_('Resolves Russian domains directly, without going through the proxy. You may add several — MultiDNS races all of them, without it the first entry is used. A bare IP is queried over UDP with TCP fallback; entries may force a transport: tcp://IP, or an encrypted direct DoH URL like https://1.1.1.1/dns-query (never proxied).'));
		o.value('77.88.8.8', _('Yandex DNS (77.88.8.8)'));
		o.value('193.58.251.251', _('SkyDNS (193.58.251.251)'));
		o.value('83.220.169.155', _('Comss.one (83.220.169.155)'));
		o.value('https://1.1.1.1/dns-query', _('Cloudflare DoH direct by IP (1.1.1.1)'));
		o.value('https://8.8.8.8/resolve', _('Google DoH direct by IP (8.8.8.8)'));
		o.value('tcp://8.8.8.8', _('Google DNS TCP (tcp://8.8.8.8)'));
		o.value('1.1.1.1', _('Cloudflare DNS UDP (1.1.1.1)'));
		o.value('8.8.8.8', _('Google DNS UDP (8.8.8.8)'));
		o.value('9.9.9.9', _('Quad9 DNS UDP (9.9.9.9)'));
		o.value('208.67.222.222', _('OpenDNS (208.67.222.222)'));
		o.value('84.200.69.80', _('DNS.WATCH (84.200.69.80)'));
		o.value('116.202.176.26', _('LibreDNS (116.202.176.26)'));
		o.value('195.46.39.39', _('SafeDNS (195.46.39.39)'));
		o.value('94.140.14.14', _('AdGuard DNS UDP (94.140.14.14)'));
		o.value('https://cloudflare-dns.com/dns-query', _('Cloudflare DoH'));
		o.value('https://dns.quad9.net/dns-query', _('Quad9 DoH'));
		o.value('https://dns.adguard-dns.com/dns-query', _('AdGuard DoH'));
		o.value('https://dns.google/dns-query', _('Google DoH'));
		o.value('https://freedns.controld.com/p0', _('ControlD DoH'));
		o.value('https://doh.dns.sb/dns-query', _('DNS.SB DoH'));
		o.value('https://doh.libredns.gr/dns-query', _('LibreDNS DoH'));
		o.value('https://dns.mullvad.net/dns-query', _('Mullvad DoH'));
		o.value('tls://cloudflare-dns.com', _('Cloudflare DoT'));
		o.value('tls://dns.quad9.net', _('Quad9 DoT'));
		o.value('tls://dns.google', _('Google DoT'));
		o.value('tls://dns.adguard-dns.com', _('AdGuard DoT'));
		o.value('tls://dot.libredns.gr', _('LibreDNS DoT'));
		o.value('tls://dns.mullvad.net', _('Mullvad DoT'));
		o.default = '77.88.8.8';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			let list = Array.isArray(value) ? value : (value ? [ value ] : []);
			for (let v in list) {
				if (!list[v]) continue;
				let host = String(list[v]).replace(/^[a-z]+:\/\//i, '').split(/[/:]/)[0];
				if (stubValidator.apply('ip4addr', host) || stubValidator.apply('ip6addr', host) || stubValidator.apply('hostname', host))
					continue;
				return _('Expecting: %s').format(_('valid DNS server address'));
			}
			return true;
		}

		o = s.taboption('pools', form.DynamicList, 'secure_dns_server', _('Secure DNS server') + ' 🔒',
			_('Resolves blocked domains via proxy — your ISP cannot see which sites you look up. Uses encrypted DNS (DoH/DoT). You may add several — MultiDNS races all of them, without it the first entry is used.'));
		o.value('https://cloudflare-dns.com/dns-query', _('Cloudflare DoH'));
		o.value('https://dns.quad9.net/dns-query', _('Quad9 DoH'));
		o.value('https://dns.adguard-dns.com/dns-query', _('AdGuard DoH'));
		o.value('https://dns.google/dns-query', _('Google DoH'));
		o.value('https://freedns.controld.com/p0', _('ControlD DoH'));
		o.value('https://doh.dns.sb/dns-query', _('DNS.SB DoH'));
		o.value('https://doh.libredns.gr/dns-query', _('LibreDNS DoH'));
		o.value('https://dns.mullvad.net/dns-query', _('Mullvad DoH'));
		o.value('tls://cloudflare-dns.com', _('Cloudflare DoT'));
		o.value('tls://dns.quad9.net', _('Quad9 DoT'));
		o.value('tls://dns.google', _('Google DoT'));
		o.value('tls://dns.adguard-dns.com', _('AdGuard DoT'));
		o.value('tls://dot.libredns.gr', _('LibreDNS DoT'));
		o.value('tls://dns.mullvad.net', _('Mullvad DoT'));
		o.value('quic://dns.adguard-dns.com', _('AdGuard DoQ'));
		o.default = 'https://cloudflare-dns.com/dns-query';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			let list = Array.isArray(value) ? value : (value ? [ value ] : []);
			for (let v in list) {
				if (!list[v]) continue;
				try {
					let url = new URL(list[v].replace(/^.*:\/\//, 'http://'));
					if (stubValidator.apply('hostname', url.hostname) || stubValidator.apply('ipaddr', url.hostname))
						continue;
				} catch(e) {}
				return _('Expecting: %s').format(_('valid DNS server address'));
			}
			return true;
		}

		o = s.taboption('pools', form.Flag, 'russia_dns_use_wan', _('Provider (WAN) DNS') + ' 🔓',
			_('Automatically detect the DNS servers your provider assigns on the WAN interface and race them together with the "Russia DNS server" list above. No manual setup on any router or ISP: MultiDNS measures quality continuously and prunes this server automatically if it is dead, slow or returns forged answers.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('pools', form.Flag, 'russia_dns_auto_doh', _('Direct DoH fallback'),
			_('For ISPs that BLOCK or FORGE all plaintext port-53 traffic (UDP swallowed, TCP answered with garbage): two direct encrypted DoH upstreams — Cloudflare 1.1.1.1 and Google 8.8.8.8, queried straight from the router without the proxy — are added to the racing pool automatically so names keep resolving. Leave OFF on a normal network: enabled only after two consecutive verification cycles prove every plaintext answer unverifiable.'));
		o.default = '0';
		o.rmempty = false;


		/* ── Tab: Reserve DNS (legacy failover for setups WITHOUT MultiDNS) ──────
		 * Works ON THE POOL LISTS ABOVE: watches the FIRST entry of each list and,
		 * when that server stops answering, moves a healthy one to the front of the
		 * SAME list. The single-server trio (dns_server/preset/alternates) belongs
		 * to Global routing mode and lives on Client Settings ▸ Routing. */
		o = s.taboption('reserve', form.Flag, 'dns_failover', _('Enable DNS failover'),
			_('For setups WITHOUT MultiDNS: watch the first server of each pool list (Russia / Secure above); when it stops answering, move a healthy one from the same list to the front. Every transport is health-checked for real — plain UDP/53, DoH over HTTPS, DoT over TCP:853; only QUIC is assumed always up (no probe tooling). Ignored while MultiDNS is enabled — it already races every server.'));
		o.rmempty = false;

		o = s.taboption('reserve', form.Flag, 'dns_failover_plain', _('Plain (Russia) pool'),
			_('Health-check and rotate the “Russia DNS server” list.'));
		o.depends('dns_failover', '1');

		o = s.taboption('reserve', form.Flag, 'dns_failover_secure', _('Secure (encrypted) pool'),
			_('Health-check and rotate the “Secure DNS server” list.'));
		o.depends('dns_failover', '1');

		let fon = s.taboption('reserve', form.DummyValue, '_failover_note');
		fon.rawhtml = true;
		fon.cfgvalue = function() { return ''; };
		fon.write = function() { return undefined; };
		fon.renderWidget = function(section_id, option_index, cfgvalue) {
			return E('div', { 'class': 'hpui-banner', 'style': 'margin-bottom:8px' }, [
				_('Redundant with MultiDNS: when MultiDNS is enabled it already races every server in each pool and returns the fastest live answer, so a single failed primary is bypassed automatically. Reserve DNS is therefore ignored while MultiDNS is on — use one or the other.')
			]);
		};

		/* ── Tab: MultiDNS (embedded exactly like the previous Client-tab layout) ── */
		o = s.taboption('multidns', form.SectionValue, '_multidns', form.NamedSection, 'multidns', 'homeproxy');

		let ss = o.subsection;
		let so = ss.option(form.Flag, 'enabled', _('Enable MultiDNS'),
			_('Race several servers in each DNS pool at once (every query) and return the fastest valid answer. Plain “Russia” pool and encrypted “Secure” pool are raced independently, mirroring split routing. A quality daemon verifies over HTTPS that each server’s returned IP actually opens the site, scores servers by latency + open-ratio + trend and prunes dead/polluted ones. Requires the mosdns engine (installed by install.sh).<br>'
			+ '<b>Wired into:</b> "Bypass blocking" and region preset modes, whose DNS pools it accelerates. In Global / Custom routing / Custom JSON nothing queries its listeners — mosdns is not started there, so leave this off in those modes.'));
		so.rmempty = false;
		/* Safety switch: when the user disables MultiDNS, hard-stop the racing
		 * resolver so DNS reverts to the standard upstreams. Ask first — this
		 * kills the running resolver IMMEDIATELY (before any save/apply), so an
		 * accidental toggle must be revertible. */
		so.onchange = function(ev, section_id, value) {
			if (!value || value === '0') {
				if (!window.confirm(_('Disable MultiDNS? The racing resolver will be stopped immediately.')))
					return false;
				mdDisable().catch(function() {});
			}
		};

		so = ss.option(form.Flag, 'use_plain', _('Race plain (Russia) DNS pool'),
			_('Query every entry of the plain DNS-server list in parallel and pick the fastest live IP. Unblocks speed and reliability for non-proxied sites.'));
		so.default = '1';
		so.rmempty = false;
		so.depends('enabled', '1');

		so = ss.option(form.Flag, 'use_secure', _('Race secure (encrypted) DNS pool'),
			_('Query every DoH/DoT entry in the secure pool in parallel and pick the fastest live IP for blocked / proxied domains.'));
		so.default = '1';
		so.rmempty = false;
		so.depends('enabled', '1');

		so = ss.option(form.Flag, 'secure_via_proxy', _('Tunnel secure-pool queries through the proxy'),
			_('Send the secure pool’s DoH/DoT queries through the proxy tunnel (SOCKS5) so your ISP cannot see which sites you look up. Disable to resolve them directly (still encrypted).'));
		so.default = '1';
		so.rmempty = false;
		/* One object = AND (multiple .depends() calls would be OR). */
		so.depends({ 'enabled': '1', 'use_secure': '1' });

		so = ss.option(form.Value, 'bench_interval', _('Quality check interval (seconds)'),
			_('How often the analyzer probes each server for latency / liveness / poisoning and updates trends. Default 120s — lower reacts faster to a bad server but verifies sites more often.'));
		so.datatype = 'uinteger';
		so.default = '120';
		so.placeholder = '120';
		so.rmempty = false;
		/* Visible with EITHER pool: single-pool setups still run the analyzer. */
		so.depends({ 'enabled': '1', 'use_plain': '1' });
		so.depends({ 'enabled': '1', 'use_secure': '1' });

		/* Live quality monitor — hosted by a dummy option inside the MultiDNS tab
		 * (same pattern the Client page used), so it never leaks into other tabs. */
		function mdBtn(label, handler) {
			return E('button', {
				'class': 'btn cbi-button',
				'click': function() {
					const el = this;
					el.disabled = true;
					Promise.resolve(handler()).finally(function() { el.disabled = false; });
				}
			}, [ label ]);
		}
		const mdStatus = rpc.declare({ object: 'luci.homeproxy', method: 'multidns_status', expect: { '': {} } });
		const mdReload = rpc.declare({ object: 'luci.homeproxy', method: 'multidns_reload', expect: { '': {} } });
		const mdReset = rpc.declare({ object: 'luci.homeproxy', method: 'multidns_reset', expect: { '': {} } });

		const mdStatusEl = E('div', { 'class': 'hpui-hint' });
		const mdTableEl = E('div', {});

		function mdRefresh() {
			return mdStatus().then(function(st) {
				const en = st.enabled === '1';
				mdStatusEl.innerHTML =
					_('Enabled') + ': <b>' + (en ? _('yes') : _('no')) + '</b> &nbsp;|&nbsp; ' +
					_('mosdns') + ': <b>' + (st.mosdns ? _('running') : _('stopped')) + '</b> &nbsp;|&nbsp; ' +
					_('Plain pool') + ': <b>' + (st.active && st.active.ru ? st.active.ru.length : 0) + '</b> &nbsp;|&nbsp; ' +
					_('Secure pool') + ': <b>' + (st.active && st.active.secure ? st.active.secure.length : 0) + '</b>';
				mdRenderTable(st.servers);
			}).catch(function(e) {
				mdStatusEl.textContent = _('MultiDNS status unavailable: ') + e;
			});
		}

		const mdActions = E('div', { 'style': 'margin-top:10px' }, [
			mdBtn(_('Rebuild pools'), function() { return mdReload(); }),
			mdBtn(_('Reset trends'), function() { return mdReset().then(mdRefresh); }),
			mdBtn(_('Disable & restore DNS'), function() { return mdDisable().then(mdRefresh); })
		]);

		const mdPanel = E('div', { 'class': 'hpui-panel' }, [
			E('h4', {}, [ _('DNS quality monitor') ]),
			mdStatusEl,
			mdTableEl,
			mdActions,
			E('p', { 'class': 'hpui-hint' }, [ _('MultiDNS races all configured DNS servers and shows their measured latency / success / open-ratio. A server that consistently fails (dead, or returns IPs that do not open the site) is pruned from the live pool and re-checked; the others race on every query (mosdns picks the fastest valid answer).') ])
		]);

		so = ss.option(form.Flag, 'verify_user_domains', _('Verify real user domains'),
			_('Sample the domains your clients actually query (from the dnsmasq log, stays on this router) and cross-check the racing pool\'s answers against direct encrypted DoH references. A domain whose answers persistently disagree with every reference is quarantined to the secure pool automatically, so forged answers stop reaching clients. Costs a few extra HTTPS checks per quality cycle.'));
		so.default = '1';
		so.rmempty = false;
		so.depends('enabled', '1');
		so.depends('use_plain', '1');

		so = ss.option(form.Value, 'http_budget', _('HTTP check budget per cycle'),
			_('Total HTTPS verification checks the quality daemon may spend per cycle (split equally between the pools). Higher = fresher open-ratio data on big pools, at the cost of more background requests. Default 24.'));
		so.datatype = 'range(4, 96)';
		so.default = '24';
		so.placeholder = '24';
		so.rmempty = false;
		so.depends('enabled', '1');

		so = ss.option(form.DummyValue, '_md_monitor');
		so.rawhtml = true;
		so.rmempty = true;
		(function(opt) {
			const _super = opt.renderWidget.bind(opt);
			opt.renderWidget = function(section_id, option_index, cfgvalue) {
				return Promise.resolve(_super(section_id, option_index, cfgvalue)).then(function(node) {
					node.appendChild(mdPanel);
					return node;
				});
			};
		})(so);
		so.write = function() { return undefined; };

		function mdRenderTable(servers) {
			if (!servers || !servers.length) {
				mdTableEl.innerHTML = '';
				mdTableEl.appendChild(E('em', {}, [ _('No data yet — enable MultiDNS and wait for the first quality check.') ]));
				return;
			}
			/* Shared design system table (Automation look): sticky grey header,
			 * translucent row hover. */
			const table = E('table', { 'class': 'hpui-table' });
			const headers = [ _('Server'), _('Pool'), _('Score'), _('Latency'), _('Open %'), _('Live %'), _('Success %'), _('Trend'), _('Status') ];
			const thead = E('thead', {});
			const htr = E('tr', {});
			for (let h of headers)
				htr.appendChild(E('th', {}, [ h ]));
			thead.appendChild(htr);
			table.appendChild(thead);
			const tbody = E('tbody', {});
			for (let e of servers) {
				let pool = e.pool || '—';
				/* pool is inferred from active lists sent by RPC; fall back to '—' */
				let lat = (e.latency != null) ? (e.latency + ' ms') : '—';
				let open = (e.open != null) ? (e.open + '%') : '—';
				let live = (e.live != null) ? (e.live + '%') : '—';
				let succ = (e.success != null) ? (e.success + '%') : '—';
				let trend = '';
				if (e.samples >= 2) trend = '≈'; /* trend history shown via score stability */
				const cells = [ String(e.server), pool, String(e.score != null ? e.score : '—'), lat, open, live, succ, trend ];
				const tr = E('tr', {});
				for (let i = 0; i < cells.length; i++)
					tr.appendChild(E('td', {}, [ cells[i] ]));
				tr.appendChild(E('td', {}, [
					E('span', { 'class': 'hpui-badge ' + (e.pruned ? 'hpui-b-grey' : 'hpui-b-green') },
						[ e.pruned ? _('pruned') : _('active') ])
				]));
				tbody.appendChild(tr);
			}
			table.appendChild(tbody);
			mdTableEl.innerHTML = '';
			const wrap = E('div', { 'class': 'hpui-wrap' });
			wrap.appendChild(table);
			mdTableEl.appendChild(wrap);
		}

		poll.add(mdRefresh, 10);
		mdRefresh();

		return m.render().then(function(node) {
			return node;
		});
	}
});
