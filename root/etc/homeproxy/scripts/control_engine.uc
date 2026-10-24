// SPDX-License-Identifier: GPL-2.0-only
//
// Re:HomeProxy AutoMod — «Контроль» watcher ("engine", plan 14; adapted
// from luci-app-homecontrol engine.uc).
//
// ALWAYS-ON procd instance (init.d spawns it unconditionally, like the
// telegram bot): the daemon gates itself on homecontrol.main.enabled every
// tick, so toggling/renaming never restarts the service. A lightweight
// 60-second loop watches the EFFECTIVE enforcement state (signature) and
// re-runs control_apply.uc only when something changed — schedule
// boundaries, temporary block expiry, DHCP address changes (the resolved
// client IP/MAC is part of the signature), Wi-Fi markers, rule windows.
//
// The engine also journals schedule-driven client transitions
// ("blocked by schedule" / "allowed again") — the events journal feeds the
// Telegram pushes; manual/temp actions are logged by the RPC layer and the
// expired-temp pruning lives in control_apply.uc.

'use strict';

import {
	client_states, active_rules, wifi_off_map, read_wifi_temps,
	read_temps, main_opt, log, add_event
} from 'control';

const TICK = 60; /* seconds per check */

/* Module-level state — must be declared BEFORE the closures that capture
 * it (ucode: no forward references, lesson ч.49). */
let last_sig = null;
let prev_states = null;

function state_signature(now) {
	const parts = [];

	push(parts, 'en=' + (main_opt('enabled', '0') === '1' ? 1 : 0));
	push(parts, 'pz=' + (main_opt('paused', '0') === '1' ? 1 : 0));

	const states = client_states(now);
	for (let i = 0; i < length(states); i++) {
		const c = states[i];
		/* ip/mac included: a DHCP change must re-render nft/redirect rules;
		 * allow_until + wifi_blocked: plan-15 state (temp allow / Wi-Fi block) */
		push(parts, `${c.id}=${c.blocked ? c.reason : '0'}@${c.until || 0}@${c.ip || ''}@${c.mac || ''}@${c.allow_until || 0}@${c.wifi_blocked ? 1 : 0}`);
	}

	const rules = active_rules(now);
	for (let i = 0; i < length(rules); i++)
		push(parts, `r:${rules[i].id}:${join(',', rules[i].client_ids || [])}:${join(',', rules[i].target || [])}=1`);

	const temps = read_temps();
	for (let k in temps)
		push(parts, `tmp:${k}@${temps[k].mode || 'block'}@${temps[k].until || 0}`);

	const woff = wifi_off_map(now);
	const wkeys = [];
	for (let k in woff)
		push(wkeys, k);
	sort(wkeys);
	push(wkeys, 'n=' + length(wkeys));
	push(parts, 'w:' + join(',', wkeys));

	const wtemps = read_wifi_temps();
	for (let k in wtemps)
		push(parts, `wt:${k}@${wtemps[k]}`);

	return join('|', parts);
}

/* Journal schedule-driven transitions (blocked by schedule / allowed back).
 * Manual and temp transitions are logged elsewhere (RPC / apply pruning). */
function log_transitions(states) {
	if (prev_states == null) {
		prev_states = {};
		for (let i = 0; i < length(states); i++)
			prev_states[states[i].id] = states[i].blocked ? states[i].reason : '';
		return;
	}
	for (let i = 0; i < length(states); i++) {
		const c = states[i];
		const was = (c.id in prev_states) ? prev_states[c.id] : '';
		const cur = c.blocked ? c.reason : '';
		if (was === cur)
			continue;
		prev_states[c.id] = cur;
		if (cur === 'schedule')
			add_event('block', c.name, 'blocked by schedule window');
		else if (was === 'schedule')
			add_event('allow', c.name, 'schedule window ended — allowed again');
	}
	/* drop transitions of deleted clients */
	const alive = {};
	for (let i = 0; i < length(states); i++)
		alive[states[i].id] = true;
	for (let k in prev_states)
		if (!(k in alive))
			delete prev_states[k];
}

function tick(now) {
	const sig = state_signature(now);
	if (sig === last_sig)
		return;
	if (last_sig != null)
		log('state changed, re-applying.');
	try {
		log_transitions(client_states(now));
	} catch (e) {
		log('transitions: ' + e);
	}
	last_sig = sig;
	system(`/usr/bin/ucode -L /etc/homeproxy/scripts /etc/homeproxy/scripts/control_apply.uc >/dev/null 2>&1`);
}

/* Main loop inside main(): executable logic NEVER lives at script
 * top level (ucode script-level let/const scoping is fragile — see
 * control_apply.uc). */
function main() {
	log('control engine started (always-on instance; idle while disabled)');
	while (true) {
		const now = time();
		try {
			tick(now);
		} catch (e) {
			log('tick error: ' + e);
		}
		sleep(TICK * 1000);
	}
}

main();
