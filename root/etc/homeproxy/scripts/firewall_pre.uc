#!/usr/bin/ucode

'use strict';

/* Ф1.2 (аудит 26): the fw4 include fragments are validated BEFORE they replace
 * the live files — per-rule field validation (one raw UCI value used to be able
 * to break the WHOLE fw4 ruleset) plus an `nft -c` syntax check of the
 * assembled fragment. A failing candidate never touches the live include file:
 * the previous fragment IS the last-known-good include. */

import { writefile, access } from 'fs';
import { cursor } from 'uci';
import { isEmpty, RUN_DIR } from 'homeproxy';

function shellq(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

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
	/* Audit 26: a garbage interface name must not poison the fragment. */
	if (!match(tun_name, /^[a-zA-Z0-9_.-]{1,15}$/)) {
		warn('homeproxy: fw4 include - ignoring invalid tun_name "' + tun_name + '"\n');
		tun_name = null;
	}
}

const server_enabled = uci.get(cfgname, 'server', 'enabled');

/* The nft l4proto selector for `th dport` must be exactly one of these forms;
 * anything else from UCI is skipped with a warning (not interpolated raw). */
const proto_ok = (p) => (p === 'tcp' || p === 'udp' || p === 'sctp' ||
	p === '{ tcp, udp }' || p === '{tcp,udp}');

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
		let port = '' + (s.port || '');
		if (!proto_ok(proto) || !match(port, /^[0-9]{1,5}$/) || int(port) < 1 || int(port) > 65535) {
			warn('homeproxy: fw4 include - skipping server ' + (s['.name'] || '?')
				+ ' (invalid proto "' + proto + '" / port "' + port + '")\n');
			return;
		}
		push(input, `meta l4proto ${proto} th dport ${port} counter accept comment "!${cfgname}: accept server ${s['.name']}"`);
	});
}

/* Validate + promote one fragment. Empty rules = untouched live file (the
 * original behaviour — an empty fragment must not delete a still-referenced
 * include). */
const promote = (name, rules) => {
	if (isEmpty(rules))
		return;
	const live = RUN_DIR + '/' + name;
	const cand = live + '.candidate';
	const wrap = '/tmp/hp_fw4_chk.nft';
	writefile(cand, join('\n', rules) + '\n');
	writefile(wrap, 'table inet hp_lkgchk {\n\tchain chk {\n'
		+ join('\n', map(rules, (r) => '\t\t' + r)) + '\n\t}\n}\n');
	const rc = system(`nft -c -f ${shellq(wrap)} >/dev/null 2>&1`);
	system(`rm -f ${shellq(wrap)}`);
	if (rc == 0) {
		system(`mv -f ${shellq(cand)} ${shellq(live)}`);
	} else if (!access('/usr/sbin/nft') && !access('/usr/bin/nft')) {
		/* nft itself is absent — fw4 cannot work anyway; keep old behaviour. */
		warn('homeproxy: fw4 include - nft binary not found, promoting unvalidated fragment\n');
		system(`mv -f ${shellq(cand)} ${shellq(live)}`);
	} else {
		system(`rm -f ${shellq(cand)}`);
		warn('homeproxy: fw4 include - ' + name
			+ ' failed nft -c validation, keeping the previous fragment (LKG)\n');
	}
};

promote('fw4_forward.nft', forward);
promote('fw4_input.nft', input);
