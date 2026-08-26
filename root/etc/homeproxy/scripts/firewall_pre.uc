#!/usr/bin/ucode

'use strict';

import { writefile } from 'fs';
import { cursor } from 'uci';
import { isEmpty, RUN_DIR } from 'homeproxy';

const cfgname = 'homeproxy';
const uci = cursor();
uci.load(cfgname);

const proxy_mode = uci.get(cfgname, 'config', 'proxy_mode') || 'redirect_tproxy';

let tun_name;
if (match(proxy_mode, /tun/)) {
	/* No main_node gate here: generate_client maps nil → direct-out and still
	 * brings up the TUN device — skipping the fw4 accept rules left traffic
	 * entering the tun interface with no forward/input allowance (black hole
	 * on NO-PROXY + TUN). */
	tun_name = uci.get(cfgname, 'infra', 'tun_name') || 'singtun0';
}

const server_enabled = uci.get(cfgname, 'server', 'enabled');

let forward = [],
    input = [];

if (tun_name) {
	push(forward, `oifname ${tun_name} counter accept comment "!${cfgname}: accept tun forward"`);
	push(input ,`iifname ${tun_name} counter accept comment "!${cfgname}: accept tun input"`);
}

if (server_enabled === '1') {
	uci.foreach(cfgname, 'server', (s) => {
		if (s.enabled !== '1' || s.firewall !== '1')
			return;

		let proto = s.network || '{ tcp, udp }';
		push(input, `meta l4proto ${proto} th dport ${s.port} counter accept comment "!${cfgname}: accept server ${s['.name']}"`);
	});
}

if (!isEmpty(forward))
	writefile(RUN_DIR + '/fw4_forward.nft', join('\n', forward) + '\n');

if (!isEmpty(input))
	writefile(RUN_DIR + '/fw4_input.nft', join('\n', input) + '\n');
