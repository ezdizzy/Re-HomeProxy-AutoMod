/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 *
 * Re:HomeProxy AutoMod — Device policy (Ф7, D6 reorganization).
 *
 * The former "Access Control" tab inside Client Settings — moved to its own
 * menu page and renamed to what it actually is: WHICH devices, IPs and
 * interfaces the proxy serves. The domain allow/deny lists that used to live
 * in the same tab are NOT here: they are routing inputs, now edited in the
 * Routing Wizard (Services → exits, custom domain lists).
 */

'use strict';
'require form';
'require network';
'require uci';
'require view';

'require homeproxy as hp';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';

return view.extend({
	load() {
		return Promise.all([
			uci.load('homeproxy'),
			uci.load('luci'),
			hp.getBuiltinFeatures(),
			network.getHostHints()
		]);
	},

	render(data) {
		let s, so;

		hp.uiStyle();

		const hosts = data[3]?.hosts;

		const m = new form.Map('homeproxy', _('Re:HomeProxy AutoMod'),
			_('Which devices, addresses and interfaces the proxy serves: per-device policy for the LAN, upstream IP policy for the WAN, and interface binding. This page does not change WHAT is proxied — the service rules and lists live in the Routing Wizard.'));

		s = m.section(form.NamedSection, 'control', 'homeproxy');

		/* LAN IP policy start */
		s.tab('lan_ip_policy', _('LAN IP Policy'));

		so = s.taboption('lan_ip_policy', form.ListValue, 'lan_proxy_mode', _('Proxy mode for devices'));
		so.value('disabled', _('Disable'));
		so.value('listed_only', _('Proxy listed only'));
		so.value('except_listed', _('Proxy all except listed'));
		so.default = 'disabled';
		so.rmempty = false;

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_direct_ipv4_ips', _('Direct IPv4 IP-s'), null, 'ipv4', hosts, true);
		so.depends('lan_proxy_mode', 'except_listed');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_direct_ipv6_ips', _('Direct IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends({'lan_proxy_mode': 'except_listed', 'homeproxy.config.ipv6_support': '1'});

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_direct_mac_addrs', _('Direct MAC-s'), null, hosts);
		so.depends('lan_proxy_mode', 'except_listed');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'), null, 'ipv4', hosts, true);
		so.depends('lan_proxy_mode', 'listed_only');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends({'lan_proxy_mode': 'listed_only', 'homeproxy.config.ipv6_support': '1'});

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_proxy_mac_addrs', _('Proxy MAC-s'), null, hosts);
		so.depends('lan_proxy_mode', 'listed_only');

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_gaming_mode_ipv4_ips', _('Gaming mode IPv4 IP-s'), _('In gaming mode, only TCP traffic from the selected device is proxied.'), 'ipv4', hosts, true);

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_gaming_mode_ipv6_ips', _('Gaming mode IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends('homeproxy.config.ipv6_support', '1');

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_gaming_mode_mac_addrs', _('Gaming mode MAC-s'), null, hosts);

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_global_proxy_ipv4_ips', _('Global proxy IPv4 IP-s'), _('In global proxy mode, all traffic from the selected device goes through the proxy.'), 'ipv4', hosts, true);
		so.depends({'homeproxy.config.routing_mode': 'custom', '!reverse': true});

		so = fwtool.addIPOption(s, 'lan_ip_policy', 'lan_global_proxy_ipv6_ips', _('Global proxy IPv6 IP-s'), null, 'ipv6', hosts, true);
		so.depends({'homeproxy.config.routing_mode': /^((?!custom).)+$/, 'homeproxy.config.ipv6_support': '1'});

		so = fwtool.addMACOption(s, 'lan_ip_policy', 'lan_global_proxy_mac_addrs', _('Global proxy MAC-s'), null, hosts);
		so.depends({'homeproxy.config.routing_mode': 'custom', '!reverse': true});
		/* LAN IP policy end */

		/* WAN IP policy start */
		s.tab('wan_ip_policy', _('WAN IP Policy'));

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'));
		so.datatype = 'or(ip4addr, cidr4)';

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'));
		so.datatype = 'or(ip6addr, cidr6)';
		so.depends('homeproxy.config.ipv6_support', '1');

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_direct_ipv4_ips', _('Direct IPv4 IP-s'));
		so.datatype = 'or(ip4addr, cidr4)';

		so = s.taboption('wan_ip_policy', form.DynamicList, 'wan_direct_ipv6_ips', _('Direct IPv6 IP-s'));
		so.datatype = 'or(ip6addr, cidr6)';
		so.depends('homeproxy.config.ipv6_support', '1');
		/* WAN IP policy end */

		/* Interface control start */
		s.tab('interface', _('Interface Control'));

		so = s.taboption('interface', widgets.DeviceSelect, 'listen_interfaces', _('Listen interfaces'),
			_('Only process traffic from specific interfaces. Leave empty for all.'));
		so.multiple = true;
		so.noaliases = true;

		so = s.taboption('interface', widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
			_('Bind outbound traffic to specific interface. Leave empty to auto detect.'));
		so.multiple = false;
		so.noaliases = true;
		/* Interface control end */

		return m.render().then(function(node) {
			return node;
		});
	}
});
