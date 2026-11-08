/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require form';
'require fs';
'require network';
'require poll';
'require rpc';
'require ui';
'require uci';
'require validation';
'require view';

'require homeproxy as hp';
'require tools.widgets as widgets';

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

const callActiveNode = rpc.declare({
	object: 'luci.ravnex',
	method: 'clash_active_node',
	params: ['tag'],
	expect: { '': {} }
});

const callHotswapStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'hotswap_status',
	expect: { '': {} }
});

/* Ф7.2: the RU-protection card (guarantee + RU-geo databases). The guard is
 * a routing invariant of the "Bypass blocking" mode — its card lives on the
 * Connection page, NOT in the automation settings. UCI keys stay
 * homeproxy.automation.*; the save goes through the tracked-op RPC. */
const callGeoStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_geo_status',
	expect: { '': {} }
});

const callGeoUpdate = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_geo_update',
	expect: { '': {} }
});

const callGeoProtectSet = rpc.declare({
	object: 'luci.ravnex',
	method: 'automation_geo_protect_set',
	params: [ 'protect', 'auto_update', 'hours' ],
	expect: { '': {} }
});

const callOpStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

const CORE_MGMT = '/usr/share/homeproxy/scripts/core_mgmt.uc';

const callByeDPIStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'byedpi_status',
	expect: { '': {} }
});

const callByeDPIPrepareInstall = rpc.declare({
	object: 'luci.ravnex',
	method: 'byedpi_prepare_install',
	expect: { '': {} }
});

const callByeDPIInstallPkg = rpc.declare({
	object: 'luci.ravnex',
	method: 'byedpi_install_pkg',
	params: ['tmp_path', 'pkg_manager'],
	expect: { '': {} }
});

const callZapretStatus = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_status',
	expect: { '': {} }
});

const callZapretPrepareInstall = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_prepare_install',
	expect: { '': {} }
});

const callZapretInstallPkg = rpc.declare({
	object: 'luci.ravnex',
	method: 'zapret_install_pkg',
	params: ['tmp_path', 'pkg_manager'],
	expect: { '': {} }
});

function callCoreDownload(url, tmpPath) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'download_pkg', url, tmpPath], 'json');
}

function getServiceStatus() {
	return L.resolveDefault(callServiceList('ravnex'), {}).then((res) => {
		let isRunning = false;
		try {
			isRunning = res['ravnex']['instances']['hiddify-c']['running'];
		} catch (e) { }
		return isRunning;
	});
}

function renderStatus(isRunning, features) {
	let coreName = features.core_type === 'singbox' ? 'sing-box' :
	               features.core_type === 'hiddify' ? 'hiddify-core' : null;
	let verStr = features.version ? 'v' + features.version : _('unknown');
	let coreStr = coreName ? ('%s %s').format(coreName, verStr) : _('no core installed');
	let spanTemp = '<em><span style="color:%s"><strong>%s (%s) %s</strong></span></em>';
	let renderHTML;
	if (isRunning)
		renderHTML = spanTemp.format('#3fbf5f', _('Ravnex'), coreStr, _('RUNNING'));
	else
		renderHTML = spanTemp.format('#e05252', _('Ravnex'), coreStr, _('NOT RUNNING'));

	return renderHTML;
}

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
	load() {
		return Promise.all([
			uci.load('ravnex'),
			uci.load('luci'),
			hp.getBuiltinFeatures(),
			network.getHostHints()
		]);
	},

	render(data) {
		let m, s, o, ss, so;

		/* App shell (R3 v2): sidebar + topbar + dual theme (implies uiStyle). */
		hp.uiShell();

		let features = data[2],
		    hosts = data[3]?.hosts;

		/* D35b: the advanced Custom Rules / Routing Nodes tabs MOVED to the
		 * Service rules page (the honest expert group, with the expert
		 * toggle living next to the editors it gates). modeNow stays for
		 * the RU-protection card below. */
		const modeNow = uci.get(data[0], 'config', 'routing_mode') || 'proxy_banned_ru';

		/* Cache all configured proxy nodes, they will be called multiple times */
		let proxy_nodes = {};
		uci.sections(data[0], 'node', (res) => {
			let nodeaddr = ((res.type === 'direct') ? res.override_address : res.address) || '',
			    nodeport = ((res.type === 'direct') ? res.override_port : res.port) || '';

			proxy_nodes[res['.name']] =
				String.format('[%s] %s', res.type, res.label || ((stubValidator.apply('ip6addr', nodeaddr) ?
					String.format('[%s]', nodeaddr) : nodeaddr) + ':' + nodeport));
		});

		m = new form.Map('ravnex');

		s = m.section(form.TypedSection);
		s.render = function () {
			poll.add(function () {
				return L.resolveDefault(getServiceStatus()).then((res) => {
					let view = document.getElementById('service_status');
					view.innerHTML = renderStatus(res, features);
				});
			}, hp.pollSec(5));

			return E('div', { class: 'cbi-section', id: 'status_bar' }, [
					E('p', { id: 'service_status' }, _('Collecting data...'))
			]);
		}

		s = m.section(form.NamedSection, 'config', 'ravnex');

		s.tab('routing', _('Routing Settings'),
			_('The main connection: the main server, the routing mode, and what keeps the connection alive when a server dies (URLTest groups, Hot Swap). New servers are added on the Servers page.'));

		if (features.available_cores && features.available_cores.length > 1) {
			o = s.taboption('routing', form.ListValue, 'preferred_core', _('Preferred core'),
				_('Which core to run when several are installed. All run every protocol this app can configure. hiddify-core additionally supports NaïveProxy; sing-box-extended is a newer sing-box base (1.14) with WARP / MASQUE / TrustTunnel, but has no NaïveProxy — such nodes are skipped automatically.'));
			o.value('auto', _('Auto'));
			if (features.available_cores.indexOf('hiddify') >= 0)
				o.value('hiddify', 'hiddify-core');
			if (features.available_cores.indexOf('singbox') >= 0)
				o.value('singbox', 'sing-box-extended');
			o.default = 'auto';
			o.rmempty = false;

			o.onchange = function(ev, section_id, value) {
				return Promise.resolve(this.map.save(null, true)).catch(function() {});
			};

			/* Live compatibility hint: nodes the SELECTED core cannot load. The
			 * generator skips them (they would FATAL the core), so tell the user
			 * instead of silently dropping them from the pools. */
			o = s.taboption('routing', form.DummyValue, '_core_compat', _('Node compatibility'));
			o.rawhtml = true;
			o.cfgvalue = function() {
				const cores = features.cores || {};
				let sel = this.map.data.get('ravnex', 'config', 'preferred_core') || 'auto';
				if (sel === 'auto')
					sel = (cores.hiddify?.installed) ? 'hiddify' :
					      (cores.singbox?.installed) ? 'singbox' : null;
				if (!sel || !cores[sel]?.installed)
					return '';
				const tags = cores[sel].tags || {};
				const REQ = { naive: 'with_naive_outbound', hysteria: 'with_quic', hysteria2: 'with_quic',
				              tuic: 'with_quic', wireguard: 'with_wireguard', amneziawg: 'with_wireguard',
				              trusttunnel: 'with_trusttunnel' };
				const NAME = { naive: 'NaïveProxy', hysteria: 'Hysteria', hysteria2: 'Hysteria2',
				               tuic: 'TUIC', wireguard: 'WireGuard', amneziawg: 'AmneziaWG',
				               trusttunnel: 'TrustTunnel' };
				const selName = sel === 'hiddify' ? 'hiddify-core' : 'sing-box-extended';
				let skipped = {};
				uci.sections(data[0], 'node', (res) => {
					const req = REQ[res.type];
					if (req && !tags[req])
						skipped[res.type] = (skipped[res.type] || 0) + 1;
				});
				const parts = Object.keys(skipped).sort().map((t) =>
					'%d × %s'.format(skipped[t], NAME[t] || t));
				if (!parts.length)
					return '<em><span style="color:#3fbf5f">%s</span></em>'.format(
						_('All configured nodes are supported by the selected core.'));
				return '<em><span style="color:#d99a1b">%s</span></em>'.format(
					_('Not supported by %s and skipped in all pools: %s.').format(selName, parts.join(', ')));
			};
		}

		o = s.taboption('routing', form.ListValue, 'main_node', _('Main node') + ' 🔗',
			_('The exit for traffic matched by Routing Rules.<br>'
			+ '• <b>URLTest</b> — the exit engine owns the pick (Auto / Hold the preferred node / Manual — configured below once selected).<br>'
			+ '• A specific node — that node is always used.<br>'
			+ '• <b>Direct (no proxy)</b> — proxy OFF: nothing is tunneled, everything egresses directly.<br>'
			+ 'ByeDPI / Zapret engines are not chosen here — enable them below and route specific services to them via Routing Rules (e.g. "YouTube → Zapret" while everything else uses the VPN).'));
		o.value('urltest', _('URLTest'));
		for (let i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.value('direct-out', _('Direct (no proxy)'));
		o.default = 'urltest';
		o.depends({'routing_mode': /^((?!custom).)+$/});
		o.rmempty = false;
		o.onchange = function(ev, section_id, value) {
			if (!section_id) return;
			Promise.resolve(this.map.save(null, true)).catch(function() {});
		};

		/* Live: which node URLTest currently has selected. Only shown in URLTest mode
		 * (depends on main_node='urltest'); hidden when a specific node is the main node. */
		o = s.taboption('routing', form.DummyValue, '_active_urltest_node', _('Active URLTest node'));
		o.depends('main_node', 'urltest');
		o.cfgvalue = function() {
			const el = E('span', { 'style': 'color:#9a9a9a' }, '—');
			poll.add(L.bind(function() {
				/* Hidden (depends) / detached after a re-render: skip the RPC
				 * instead of polling for a node nobody can see. */
				if (!el.isConnected)
					return;
				/* Focused query: resolve the main-out group itself (descends nested
				 * urltest pools, e.g. prefer mode's main-out-alt) instead of the
				 * GLOBAL-follow heuristic, which can latch onto a stale group. */
				return L.resolveDefault(callActiveNode('main-out'), {}).then(function(ret) {
					if (ret && !ret.error && ret.node) {
						const m = ret.node.match(/^cfg-(.+)-out$/);
						const name = (m && proxy_nodes[m[1]]) ? proxy_nodes[m[1]] : ret.node;
						const type = ret.type ? ' (' + ret.type + ')' : '';
						/* Same 4-colour scheme as the Core & Tools page: 65535 ms is the
						   URLTest timeout sentinel (confirmed dead → red); >=3000 ms is
						   working-but-slow (orange); a real low latency is green; no
						   delay at all is unmeasured (gray, no number). */
						let dColor, dStr = '';
						if (ret.delay === 65535) { dColor = 'red'; dStr = ' — ' + _('timeout'); }
						else if (ret.delay >= 3000) { dColor = 'orange'; dStr = ' — ' + ret.delay + ' ms'; }
						else if (ret.delay) { dColor = 'green'; dStr = ' — ' + ret.delay + ' ms'; }
						else dColor = 'gray';
						el.textContent = name + type + dStr;
						el.style.color = dColor;
					} else {
						el.textContent = _('No active node');
						el.style.color = 'gray';
					}
				});
			}, this), hp.pollSec(5));
			return el;
		};

		o = s.taboption('routing', form.DummyValue, '_urltest_info', _('Exit engine'),
			_('One engine owns the exit for every mode. <b>Auto</b> keeps the best node and moves only when another stays faster by more than the tolerance for several probe rounds in a row; <b>Preferred node</b> holds your chosen node while it responds and fails over only when it really dies; <b>Manual</b> holds the node you picked. Reserve nodes are probed live (hot dials) and take over in your order; after a restart the engine resumes its last pick.')); 
		o.depends('main_node', 'urltest');
		o.rawhtml = true;
		o.cfgvalue = function() { return ''; };

		o = s.taboption('routing', form.ListValue, 'exit_mode', _('Exit mode'));
		o.value('auto', _('Auto — best node (recommended)'));
		o.value('prefer', _('Hold the preferred node'));
		o.value('manual', _('Manual — hold my pick'));
		o.default = 'auto';
		o.depends('main_node', 'urltest');
		o.rmempty = false;
		/* Retain: without it a save made while the main node is not URLTest
		 * deletes the mode from UCI (rmempty=false + hidden => remove()), and
		 * switching back to URLTest silently reset the user's mode to Auto. */
		o.retain = true;

		o = s.taboption('routing', form.ListValue, 'exit_preferred', _('Preferred node'),
			_('Always used while it responds — the engine leaves it only when it really dies (several dead probes in a row with a live reserve) and returns to it once it recovers. With "Upgrade" enabled the engine may also move to a node that stays faster by more than the tolerance for several probe rounds.'));
		for (let i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.depends({ 'main_node': 'urltest', 'exit_mode': 'prefer' });
		o.retain = true;
		/* No rmempty=false: the framework's own empty check ("Option must not be
		 * empty") ignores custom validators and hard-blocks saving whenever this
		 * field is visible with no selectable nodes. The guarded validate below
		 * keeps a proper error for the actively-misconfigured case instead. */
		o.validate = function(section_id) {
			if (this.map.data.get('ravnex', 'config', 'main_node') !== 'urltest')
				return true;
			if (this.map.data.get('ravnex', 'config', 'exit_mode') !== 'prefer')
				return true;
			let value = this.section.formvalue(section_id, 'exit_preferred');
			if (section_id && !value)
				return _('Expecting: %s').format(_('non-empty value'));

			return true;
		}

		o = s.taboption('routing', form.Value, 'main_urltest_interval', _('Test interval'),
			_('How often each node is tested (seconds). Lower = faster failover, higher = less overhead.'));
		o.datatype = 'uinteger';
		o.placeholder = '30';
		o.default = '30';
		o.depends('main_node', 'urltest');

		o = s.taboption('routing', form.Value, 'exit_tolerance', _('Switch tolerance'),
			_('Minimum latency gap (ms) required to move to a faster node — prevents flapping between nodes with close latency values. In "Hold the preferred node" mode it applies only when Upgrade is enabled.'));
		o.datatype = 'uinteger';
		o.placeholder = '150';
		o.default = '150';
		o.depends('main_node', 'urltest');
		o.retain = true;

		o = s.taboption('routing', form.ListValue, 'main_udp_node', _('Main UDP node'),
			_('Separate exit for UDP traffic (games, calls). "Follows main route" keeps UDP on the same path as TCP.'));
		o.value('nil', _('No separate UDP node (UDP follows the main route)'));
		o.value('same', _('Same as main node'));
		o.value('urltest', _('URLTest'));
		for (let i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		if (uci.get(data[0], 'config', 'byedpi_enabled') === '1')
			o.value('byedpi-out', _('ByeDPI'));
		if (uci.get(data[0], 'config', 'zapret_enabled') === '1')
			o.value('zapret-out', _('Zapret'));
		o.value('direct-out', _('Direct (no proxy)'));
		o.default = 'nil';
		o.depends({'routing_mode': /^((?!custom|proxy_banned_ru).)+$/, 'proxy_mode': /^((?!redirect$).)+$/});
		o.rmempty = false;
		/* Retain (Ф7 fix): the option only RENDERS in Global mode, but a save
		 * from any other mode used to issue uci/delete for it anyway. When the
		 * option is ABSENT from UCI (the "no separate UDP node" state), that
		 * delete answers ubus code 4 "Not found" and ABORTS the whole form
		 * save — every setting on this page silently failed to persist. Retain
		 * keeps unrendered options untouched (lesson 11 pattern). */
		o.retain = true;

		o = s.taboption('routing', form.ListValue, 'exit_udp_preferred', _('Preferred UDP node'),
			_('For the separate UDP exit in "Hold the preferred node" mode: this node is held while it responds. Leave empty to use the main preferred node.'));
		for (let i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.depends({ 'main_udp_node': 'urltest', 'exit_mode': 'prefer' });
		o.retain = true;

		o = s.taboption('routing', form.Value, 'main_udp_urltest_interval', _('Test interval'),
			_('The test interval in seconds.'));
		o.datatype = 'uinteger';
		o.placeholder = '30';
		o.default = '30';
		o.depends('main_udp_node', 'urltest');
		/* Hidden whenever main_udp_node ≠ urltest — a save from that state
		 * used to uci/delete an absent option and abort the whole save
		 * (same trap as main_udp_node above). */
		o.retain = true;

		/* ── Exit Engine (Ф9.16, D35a): единый выход-движок ──────────────────────
		 * Один демон владеет селектором main-out (и main-udp-out при выделенном
		 * UDP-выходе): режимы Автомат / Удержание предпочтительного / Ручной +
		 * сквозной резерв-список. Пробы — реальные dial'ы через ядро (резервы
		 * остаются тёплыми), переключение — чистая Clash API операция БЕЗ
		 * рестарта ядра: direct-трафик и DNS не замечают. Синтетика main
		 * (Direct/ByeDPI/Zapret) не имеет между чем переключать — секции скрыты. */
		const engine_depends = {'routing_mode': /^((?!custom).)+$/, 'main_node': /^(?!direct-out$|nil$|byedpi-out$|zapret-out$)/};

		o = s.taboption('routing', hp.CBIStaticList, 'exit_reserves', _('Reserve nodes') + ' 🔌',
			_('Priority order of the failover reserves: add nodes in order, the topmost is tried first when the active pick dies. Reserves are probed live (this keeps their tunnels warm). Empty = every node may be used as a reserve. In URLTest modes only nodes of the pool are eligible; with a specific main node the main node itself is always first and cannot be removed.'));
		for (let i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.depends(engine_depends);
		o.retain = true;

		o = s.taboption('routing', form.Value, 'exit_probe_interval', _('Probe interval'),
			_('How often the active pick and the reserves are verified (seconds). Lower = faster failover (a dead main is usually replaced within ~10-20 s), higher = less background traffic.'));
		o.datatype = 'range(5,120)';
		o.placeholder = '10';
		o.default = '10';
		o.depends(engine_depends);

		o = s.taboption('routing', form.Flag, 'exit_failback', _('Return after recovery'),
			_('When the held node recovers (or the preferred node is alive again), switch back after it stays stable for a while (3 good probes over 30+ seconds). Turn this off to stay on the failover node until it dies. The engine never overrides your manual pick while it stays alive.'));
		o.default = o.enabled;
		o.depends(engine_depends);
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'exit_upgrade', _('Upgrade on a better node'),
			_('Only in "Hold the preferred node" mode: allow moving to a node that stays faster by more than the Switch tolerance for 3 probe rounds in a row (with a direct probe). Off by default — the preferred node is held regardless of latency.'));
		o.default = o.disabled;
		o.depends({ 'main_node': 'urltest', 'exit_mode': 'prefer' });
		o.rmempty = false;

		o = s.taboption('routing', form.Value, 'exit_dead_after', _('Dead threshold'),
			_('Advanced: how many failed probes in a row declare a node dead (a fast double-check follows the first failure). Default 2.'));
		o.datatype = 'range(1,10)';
		o.placeholder = '2';
		o.default = '2';
		o.depends(engine_depends);
		o.retain = true;

		o = s.taboption('routing', form.Value, 'exit_recovery_oks', _('Recovery probes'),
			_('Advanced: how many good probes a recovered node must collect before the engine returns to it. Default 3.'));
		o.datatype = 'uinteger';
		o.placeholder = '3';
		o.default = '3';
		o.depends(engine_depends);
		o.retain = true;

		o = s.taboption('routing', form.Value, 'exit_recovery_window', _('Recovery window'),
			_('Advanced: the recovery probes must span at least this many seconds (protects from a flapping node). Default 30.'));
		o.datatype = 'uinteger';
		o.placeholder = '30';
		o.default = '30';
		o.depends(engine_depends);
		o.retain = true;

		o = s.taboption('routing', form.Value, 'exit_hysteresis', _('Auto hysteresis'),
			_('Advanced: probe rounds in a row a challenger must stay faster by more than the tolerance before the engine moves in Auto mode (or with Upgrade enabled). Default 3.'));
		o.datatype = 'uinteger';
		o.placeholder = '3';
		o.default = '3';
		o.depends(engine_depends);
		o.retain = true;

		o = s.taboption('routing', form.DummyValue, '_hotswap_status', _('Engine state'));
		o.depends(engine_depends);
		o.cfgvalue = function() {
			/* Live panel (ч.60): header (mode / switches / failback) + a member
			 * table «Node | Role | State | Latency» merged from the selector
			 * view (order, live pick, core delay) and the daemon's probe
			 * state. Replaces the ч.59 single status line. */
			const box = E('div', {}, [ E('span', { 'style': 'color:#9a9a9a' }, '—') ]);
			poll.add(L.bind(function() {
				/* Hidden (depends) / detached after a re-render: skip the RPC. */
				if (!box.isConnected)
					return;
				return L.resolveDefault(callHotswapStatus(), {}).then(function(ret) {
					box.innerHTML = '';
					if (!ret || ret.error || !ret.enabled) {
						box.appendChild(E('span', { 'style': 'color:gray' }, [ _('Inactive') ]));
						return;
					}
					if (!ret.daemon) {
						box.appendChild(E('span', { 'style': 'color:#d99a1b' }, [ _('Waiting for the failover daemon (service reload needed)') ]));
						return;
					}
					const urltestLabel = _('URLTest (kernel selection)');
					const modeLabels = {
						auto: _('Auto — best node'),
						prefer: _('Hold the preferred node'),
						manual: _('Manual — hold my pick'),
						urltest: urltestLabel,
						node: _('Specific node')
					};
					const modeLabel = modeLabels[ret.mode] || (ret.mode || '—');
					const headBits = [ E('span', { 'style': 'font-weight:bold' }, [ _('Mode') + ': ' + modeLabel ]) ];
					headBits.push(document.createTextNode(' · ' + _('Switches') + ': ' + (ret.switches || 0)));
					if (ret.last_switch)
						headBits.push(document.createTextNode(' · ' + _('Last switch') + ': ' + new Date(ret.last_switch * 1000).toLocaleTimeString()));
					if (ret.failback)
						headBits.push(document.createTextNode(' · ' + _('failback on')));
					if (ret.antiflap) {
						headBits.push(document.createTextNode(' · ' + _('anti-flap on')));
						if (ret.suppressed > 0)
							headBits.push(document.createTextNode(' · ' + _('kernel re-ranks absorbed') + ': ' + ret.suppressed));
					}
					box.appendChild(E('div', { 'style': 'margin-bottom:6px' }, headBits));

					const dstate = {};
					const hlist = ret.hot || [];
					for (let hi in hlist)
						dstate[hlist[hi].tag] = hlist[hi];
					const mlist = ret.members || [];
					const rows = [];
					for (let mi in mlist) {
						const m = mlist[mi], d = dstate[m.tag] || {};
						let roleEl, roleColor = 'inherit';
						if (m.now) {
							/* Antiflap (ч.67): the pinned node IS the intended
							 * main pick — present it as the main node, not a
							 * mere "active" member of the group. */
							roleEl = (ret.antiflap && ret.pinned && m.tag === ret.pinned)
								? _('Main node') : _('Active');
							roleColor = 'green';
						} else if (m.tag === ret.primary) {
							roleEl = (m.tag === 'main-out-auto') ? urltestLabel : _('Main node');
						} else if (d.in_hot) {
							roleEl = _('Reserve');
							roleColor = '#d99a1b';
						} else {
							roleEl = _('Spare');
							roleColor = '#9a9a9a';
						}
						const stTxt = (d.state === 'alive') ? _('Alive') : ((d.state === 'down') ? _('Down') : '—');
						const stColor = (d.state === 'alive') ? 'green' : ((d.state === 'down') ? '#e05252' : '#9a9a9a');
						const dly = (d.last_delay > 0) ? d.last_delay :
							((m.delay > 0 && m.delay < 65535) ? m.delay : null);
						rows.push(E('tr', {}, [
							E('td', { 'style': 'white-space:nowrap; padding:2px 14px 2px 0' },
								[ (m.tag === 'main-out-auto') ? urltestLabel : (m.label || m.tag) ]),
							E('td', { 'style': 'white-space:nowrap; padding:2px 14px 2px 0' },
								[ E('span', { 'style': 'color:' + roleColor + ((m.now) ? '; font-weight:bold' : '') }, [ roleEl ]) ]),
							E('td', { 'style': 'white-space:nowrap; padding:2px 14px 2px 0' },
								[ E('span', { 'style': 'color:' + stColor }, [ stTxt ]) ]),
							E('td', { 'style': 'white-space:nowrap; padding:2px 0' }, [ dly ? (dly + ' ms') : '—' ])
						]));
					}
					if (rows.length) {
						const thead = E('tr', {}, [
							E('th', { 'style': 'text-align:left; padding:2px 14px 2px 0' }, [ _('Node') ]),
							E('th', { 'style': 'text-align:left; padding:2px 14px 2px 0' }, [ _('Role') ]),
							E('th', { 'style': 'text-align:left; padding:2px 14px 2px 0' }, [ _('State') ]),
							E('th', { 'style': 'text-align:left; padding:2px 0' }, [ _('Latency') ])
						]);
						const table = E('table', { 'style': 'border-collapse:collapse' }, [ thead ]);
						for (let ri in rows)
							table.appendChild(rows[ri]);
						box.appendChild(table);
					} else
						box.appendChild(E('em', { 'style': 'color:#9a9a9a' }, [ _('The failover group is empty') ]));
					if (ret.last_reason)
						box.appendChild(E('div', { 'style': 'color:#d99a1b; font-size:.9em; margin-top:4px' }, [ ret.last_reason ]));
					/* Antiflap (ч.67): the selector riding the pinned node (≠ the
					 * group "primary") is the DESIGNED steady pick, not a
					 * failover — no scary warning in that state. */
					const antiflap_steady = (ret.antiflap && ret.pinned && ret.active === ret.pinned);
					if (ret.primary && ret.active && ret.active !== ret.primary && !antiflap_steady)
						box.appendChild(E('div', { 'style': 'color:#d99a1b; margin-top:2px' },
							[ _('Traffic currently rides the failover pick') ]));
				});
			}, this), hp.pollSec(5));
			return box;
		};

		o = s.taboption('routing', form.Flag, 'proxy_calls',
			_('Proxy calls') + ' 📞',
			_('Route VoIP call ports (WhatsApp, Telegram, FaceTime, etc.) through the proxy.'));
		/* Hidden while the main node is Direct: the flag promises proxy routing
		 * that cannot happen without a proxy path. */
		o.depends({'routing_mode': 'proxy_banned_ru', 'main_node': /^(?!direct-out$|nil$)/});
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'no_proxy_torrents',
			_('Do not proxify torrents') + ' 🧲',
			_('Force torrent traffic (BitTorrent protocol + common ports) to bypass the proxy.'));
		o.depends({'routing_mode': 'proxy_banned_ru', 'main_node': /^(?!direct-out$|nil$)/});
		o.default = o.enabled;
		o.rmempty = false;

		/* OAuth stability (ч.59): auth providers ride the same exit as the
		 * services that open them instead of the RU-geo "always direct" split. */
		o = s.taboption('routing', form.Flag, 'oauth_stability', _('OAuth sign-in stability') + ' 🔐',
			_('Route authentication providers (accounts.google.com, login.microsoftonline.com, appleid.apple.com, …) — the whole domain family of every learned auth host (accounts.autodesk.com learned → all *.autodesk.com) — and the IP-bound login infrastructure (Clerk bot checks, hCaptcha, reCAPTCHA, Cloudflare Turnstile) through the SAME live exit the service itself uses. DNS goes through the encrypted pool and TCP is forced (QUIC and HTTPS/SVCB records are filtered). Fixes "Sign in with Google" loops on proxied services: every leg of the flow — page, provider, captcha, bot checks — rides one consistent exit instead of bouncing between countries and IPs.'));
		o.depends('routing_mode', 'proxy_banned_ru');
		o.default = o.enabled;
		o.rmempty = false;
		o.retain = true;

		/* WAN-up reload (ч.59): legacy behavior reloaded the whole service on
		 * every WAN up event, tearing down ALL connections on every redial.
		 * The core re-binds on its own, so this is opt-in now. */
		o = s.taboption('routing', form.Flag, 'reload_on_wan', _('Reload on WAN reconnect'),
			_('Reload the whole service when the WAN interface comes up (legacy behavior). Leave this OFF: a reload tears down every connection — including direct ones that never touch the proxy — and drops LAN DNS for a few seconds. The core switches to the new WAN interface on its own.'));
		o.depends({'routing_mode': /^((?!custom).)+$/});
		o.default = o.disabled;
		o.rmempty = false;
		o.retain = true;

		/* Local rule-set fallback (issue #12): a cold start with an empty
		 * cache.db (fresh flash / wiped /var/run) downloads every remote .srs
		 * SYNCHRONOUSLY and dies FATAL on the first failure. With initial_path
		 * the core takes a local copy for the first load and refreshes from
		 * the network afterwards (sing-box 1.14 semantics; the generator emits
		 * the option for the sing-box family only). */
		o = s.taboption('routing', form.Flag, 'ruleset_local', _('Local rule-set fallback'),
			_('Cold-start safety net for the rule lists: when the local folder exists, every remote rule-set also gets a local first-load copy — a cold start without working internet (fresh firmware, wiped cache, DPI-blocked GitHub) no longer kills the core with "FATAL initialize rule-set". The lists still refresh from the network daily in the background, and a missing local file falls back to the normal download. Pre-fill the folder from the Rule-sets card on the Core & Tools page.'));
		o.depends({'routing_mode': /^((?!custom).)+$/});
		o.default = o.enabled;
		o.rmempty = false;
		o.retain = true;

		o = s.taboption('routing', form.Value, 'ruleset_local_path', _('Local rule-sets folder'),
			_('Folder with the local .srs copies, one file per rule-set named by its tag (the Rule-sets card on the Core & Tools page lists the exact names and can download them). Only used when the folder exists; absolute path.'));
		o.placeholder = '/etc/ravnex/rulesets';
		o.rmempty = true;
		o.retain = true;
		o.depends('ruleset_local', '1');

		o = s.taboption('routing', form.ListValue, 'routing_mode', _('Routing mode'),
			_('• <b>Bypass blocking (rule lists)</b> — the everyday WORKING mode: everything stays direct, and traffic matching Routing Rules (YouTube, Russia Inside, Re-filter…) goes through the Main node — that is exactly what opens blocked sites without tunneling the whole connection. The bypass engines (Zapret / ByeDPI) and the Automation engine work here.<br>'
			+ '• <b>Everything through node</b> — ALL traffic goes through the Main node; per-service rules are not used.<br>'
			+ '• <b>Direct (all mechanisms off)</b> — for repairs and diagnostics: interception, engines, the DNS scheme and the core itself are OFF, the router just hands out the internet as the provider gives it.<br>'
			+ 'Changing the mode re-renders the page so only relevant options stay visible'));
		o.value('proxy_banned_ru', _('Bypass blocking (rule lists)'));
		o.value('global', _('Everything through node'));
		o.value('direct', _('Direct (all mechanisms off)'));
		o.default = 'proxy_banned_ru';
		o.rmempty = false;
		/* Silent-save on ANY mode change: the whole view gates its sections on the
		 * persisted routing_mode, so switching modes must persist + re-render
		 * immediately — otherwise Proxy Rules keep a stale source list (Re-filter
		 * vanishing/appearing), main-out gating goes stale and users get locked out
		 * of valid combinations until a manual page reload. The save also arms the
		 * procd reload trigger — the mode applies with the next service restart. */
		o.onchange = function(ev, section_id, value) {
			if (!section_id) return;
			Promise.resolve(this.map.save(null, true)).catch(function() {});
		}

		/* «Напрямую» (Ф3.1): an honest notice INSTEAD of hiding the options —
		 * hiding rmempty=false options would DELETE their UCI values on the next
		 * save (lesson 11/67). The values stay untouched; they simply do not
		 * apply while the mode is direct. */
		o = s.taboption('routing', form.DummyValue, '_direct_notice', _('Direct (all mechanisms off)'));
		o.depends('routing_mode', 'direct');
		o.rawhtml = true;
		o.cfgvalue = function() {
			return '<div class="hpui-banner">' + _('All bypass mechanisms are switched OFF in this mode: interception, the Zapret/ByeDPI engines, the DNS scheme and the core itself are not running — the router hands out the internet exactly as the provider gives it. Use it for repairs and diagnostics. The settings below keep their values and take effect again when you switch back to "Bypass blocking" or "Everything through node".') + '</div>';
		};

		o = s.taboption('routing', form.Value, 'routing_port', _('Routing ports'),
			_('Specify target ports to be proxied. Multiple ports must be separated by commas. Leave empty for all ports.'));
		o.value('', _('All ports'));
		o.value('common', _('Common ports only (bypass P2P traffic)'));
		o.validate = function(section_id, value) {
			/* 'all' is a legacy "all ports" sentinel; treat it as valid (empty). */
			if (section_id && value && value !== 'common' && value !== 'all') {

				let ports = [];
				for (let i of value.split(',')) {
					if (!stubValidator.apply('port', i) && !stubValidator.apply('portrange', i))
						return _('Expecting: %s').format(_('valid port value'));
					if (ports.includes(i))
						return _('Port %s already exists!').format(i);
					ports = ports.concat(i);
				}
			}

			return true;
		}

		o = s.taboption('routing', form.ListValue, 'proxy_mode', _('Proxy mode'));
		o.value('redirect', _('Redirect TCP'));
		if (features.hp_has_tproxy)
			o.value('redirect_tproxy', _('Redirect TCP + TProxy UDP'));
		if (features.hp_has_tun) {
			o.value('redirect_tun', _('Redirect TCP + Tun UDP'));
			o.value('tun', _('Tun TCP/UDP'));
		} else {
			o.description = _('To enable Tun support, you need to install <code>kmod-tun</code>');
		}
		o.default = 'redirect_tproxy';
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'ipv6_support', _('IPv6 support'));
		o.default = o.enabled;
		o.rmempty = false;
		/* Retain: a save made while this flag is hidden must not delete it
		 * from UCI, silently losing the user's IPv6 choice. */
		o.retain = true;
		o.cfgvalue = function(section_id) {
			const stored = uci.get('ravnex', section_id, 'ipv6_support');
			if (stored != null) return stored;
			return (uci.get('ravnex', section_id, 'routing_mode') === 'proxy_banned_ru')
				? this.disabled : this.enabled;
		};

		/* Custom routing settings (Custom routing / Custom JSON) were RETIRED
		 * with Ф3.1/D23 — the whole manual DNS/routing section tree is gone.
		 * A legacy `homeproxy.routing` / `homeproxy.dns` section in UCI stays
		 * as dead data until the Ф3.4 migration cleans it up. */

		o = s.taboption('routing', form.Flag, 'byedpi_enabled', _('Enable ByeDPI'),
			_('A free way to unblock throttled sites (e.g. YouTube) without a VPN subscription. ' +
			  'Works by confusing your ISP\'s traffic analysis — your traffic is NOT encrypted or hidden, your ISP can still see which sites you visit. ' +
			  'Results depend on your ISP and may require trying different strategies on the Blocking bypass page. ' +
			  'ByeDPI will be installed automatically on first enable.'));
		o.default = o.disabled;
		o.rmempty = false;
		(function(opt) {
			const _super = opt.renderWidget.bind(opt);
			opt.renderWidget = function(section_id, option_index, cfgvalue) {
				return Promise.resolve(_super(section_id, option_index, cfgvalue)).then(function(node) {
					node.querySelector('input').addEventListener('change', async function(ev) {
						if (!ev.target.checked) return;
						const status = await L.resolveDefault(callByeDPIStatus(), {});
						if (status.installed) return;

						if (!status.pkg_manager) {
							ui.addNotification(null, E('p', _('No package manager found. Install ciadpi manually on the "Core & Tools" page.')), 'error');
							ev.target.checked = false;
							return;
						}

						const progressEl = E('p', { style: 'margin:8px 0' }, _('Checking requirements...'));
						const cancelBtn  = E('button', { class: 'btn cbi-button' }, _('Cancel'));
						const installBtn = E('button', { class: 'btn cbi-button-action', style: 'margin-left:4px' }, _('Install'));
						const input = ev.target;

						cancelBtn.addEventListener('click', function() {
							input.checked = false;
							ui.hideModal();
						});

						installBtn.addEventListener('click', async function() {
							cancelBtn.disabled = true;
							installBtn.disabled = true;

							progressEl.style.color = '';
							progressEl.textContent = _('Checking requirements...');
							const prep = await L.resolveDefault(callByeDPIPrepareInstall(), {});
							if (prep.error) {
								progressEl.style.color = 'red';
								progressEl.textContent = prep.error;
								cancelBtn.disabled = false;
								input.checked = false;
								return;
							}

							progressEl.textContent = _('Downloading...');
							const dl = await L.resolveDefault(callCoreDownload(prep.dl_url, prep.tmp_path), {});
							if (!dl.result) {
								progressEl.style.color = 'red';
								progressEl.textContent = dl.error || _('Download failed');
								cancelBtn.disabled = false;
								input.checked = false;
								return;
							}

							progressEl.textContent = _('Installing...');
							const inst = await L.resolveDefault(callByeDPIInstallPkg(prep.tmp_path, prep.pkg_manager), {});
							if (!inst.result) {
								progressEl.style.color = 'red';
								progressEl.textContent = inst.error || _('Installation failed');
								cancelBtn.disabled = false;
								input.checked = false;
								return;
							}

							progressEl.style.color = 'green';
							progressEl.textContent = _('Installed successfully');
							setTimeout(() => ui.hideModal(), 1500);
						});

						ui.showModal(_('Install ByeDPI'), [
							E('p', _('ByeDPI (ciadpi) is not installed. Install it now?')),
							progressEl,
							E('div', { class: 'right' }, [cancelBtn, installBtn])
						]);
					});
					return node;
				});
			};
		})(o);

		o = s.taboption('routing', form.Flag, 'zapret_enabled', _('Enable Zapret'),
			_('An alternative to ByeDPI: another free way to unblock throttled or blocked sites (YouTube, Discord…) without a VPN subscription. ' +
			  'Practical difference from ByeDPI: Zapret can work with the QUIC protocol. ' +
			  'Finding a working strategy is individual and depends on your ISP\'s restrictions. ' +
			  'Installed automatically on first enable.'));
		o.default = o.disabled;
		o.rmempty = false;
		(function(opt) {
			const _super = opt.renderWidget.bind(opt);
			opt.renderWidget = function(section_id, option_index, cfgvalue) {
				return Promise.resolve(_super(section_id, option_index, cfgvalue)).then(function(node) {
					node.querySelector('input').addEventListener('change', async function(ev) {
						if (!ev.target.checked) return;
						const status = await L.resolveDefault(callZapretStatus(), {});
						if (status.installed) {
							/* Installed but the NFQUEUE kmod is missing → enabling would emit
							 * `queue num` and nft would reject the whole fw4 set. Block it.
							 * (kmod_ok === false only; undefined = old backend = don't block.) */
							if (status.kmod_ok === false) {
								ui.addNotification(null, E('p', _('Zapret is installed, but the NFQUEUE kernel module (kmod-nft-queue) is missing. Enabling it now could break the firewall. Reinstall Zapret or install kmod-nft-queue first.')), 'error');
								ev.target.checked = false;
							}
							return;
						}

						if (!status.pkg_manager) {
							ui.addNotification(null, E('p', _('No package manager found. Install zapret2 manually on the "Core & Tools" page.')), 'error');
							ev.target.checked = false;
							return;
						}

						const progressEl = E('p', { style: 'margin:8px 0' }, _('Checking requirements...'));
						const cancelBtn  = E('button', { class: 'btn cbi-button' }, _('Cancel'));
						const installBtn = E('button', { class: 'btn cbi-button-action', style: 'margin-left:4px' }, _('Install'));
						const input = ev.target;

						cancelBtn.addEventListener('click', function() {
							input.checked = false;
							ui.hideModal();
						});

						installBtn.addEventListener('click', async function() {
							cancelBtn.disabled = true;
							installBtn.disabled = true;

							progressEl.style.color = '';
							progressEl.textContent = _('Checking requirements...');
							const prep = await L.resolveDefault(callZapretPrepareInstall(), {});
							if (prep.error) {
								progressEl.style.color = 'red';
								progressEl.textContent = prep.error;
								cancelBtn.disabled = false;
								input.checked = false;
								return;
							}

							progressEl.textContent = _('Downloading...');
							const dl = await L.resolveDefault(callCoreDownload(prep.dl_url, prep.tmp_path), {});
							if (!dl.result) {
								progressEl.style.color = 'red';
								progressEl.textContent = dl.error || _('Download failed');
								cancelBtn.disabled = false;
								input.checked = false;
								return;
							}

							progressEl.textContent = _('Installing...');
							const inst = await L.resolveDefault(callZapretInstallPkg(prep.tmp_path, prep.pkg_manager), {});
							if (!inst.result) {
								progressEl.style.color = 'red';
								progressEl.textContent = inst.error || _('Installation failed');
								cancelBtn.disabled = false;
								input.checked = false;
								return;
							}

							progressEl.style.color = 'green';
							progressEl.textContent = _('Installed successfully');
							setTimeout(() => ui.hideModal(), 1500);
						});

						ui.showModal(_('Install Zapret'), [
							E('p', _('Zapret (zapret2/nfqws2) is not installed. Install it now?')),
							progressEl,
							E('div', { class: 'right' }, [cancelBtn, installBtn])
						]);
					});
					return node;
				});
			};
		})(o);

		/* D35b: the old "Routing Rules" bookmark stub tab is gone with the
		 * advanced tabs — the Service rules page is the single home of
		/* D35b: the old "Routing Rules" bookmark stub tab is gone with the
		 * advanced tabs — the Service rules page is the single home of
		 * preset rows, user lists, routing nodes and raw custom rules. */

		/* ── Ф9.14 (D34d): the expert WAN & interface section moved here
		 * from the Devices page (which is card-only now). UCI section
		 * 'control' — the section firewall_post.uc reads for these options
		 * (writing them to 'config' is invisible to the template; caught
		 * live in the Ф9.14 acceptance). The section node is moved into a
		 * collapsed <details> after render (automation.js pattern). */
		const sxw = m.section(form.NamedSection, 'control', 'ravnex', _('Expert: WAN & interfaces'));
		sxw.description = _('WAN-wide destinations and interface binding for the whole service.');

		so = sxw.option(form.DynamicList, 'wan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'),
			_('Force these WAN destinations through the proxy (checked before everything else).'));
		so.datatype = 'or(ip4addr, cidr4)';

		so = sxw.option(form.DynamicList, 'wan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'));
		so.datatype = 'or(ip6addr, cidr6)';
		so.depends('ravnex.config.ipv6_support', '1');

		so = sxw.option(form.DynamicList, 'wan_direct_ipv4_ips', _('Direct IPv4 IP-s'),
			_('Force these WAN destinations direct (the "Global proxy" devices still pass).'));
		so.datatype = 'or(ip4addr, cidr4)';

		so = sxw.option(form.DynamicList, 'wan_direct_ipv6_ips', _('Direct IPv6 IP-s'));
		so.datatype = 'or(ip6addr, cidr6)';
		so.depends('ravnex.config.ipv6_support', '1');

		so = sxw.option(widgets.DeviceSelect, 'listen_interfaces', _('Listen interfaces'),
			_('Only process traffic from specific interfaces. Leave empty for all.'));
		so.multiple = true;
		so.noaliases = true;

		so = sxw.option(widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
			_('Bind outbound traffic to specific interface. Leave empty to auto detect.'));
		so.multiple = false;
		so.noaliases = true;

		/* DNS Servers / DNS Rules / Rule set — the manual custom-DNS scheme —
		 * were RETIRED with Ф3.1/D23 together with Custom routing. A legacy
		 * `dns_server` / `dns_rule` / `ruleset` section in UCI stays as dead
		 * data until the Ф3.4 migration cleans it up. */

		/* ACL settings (Ф7/D6): the device/IP/interface policy moved to its
		 * own "Devices & interfaces" page (access.js), the proxy/direct
		 * DOMAIN lists moved to the Routing Wizard (Services → exits) —
		 * both are routing inputs, and the Wizard is their single editor. */

		/* ── Ф7.2: the RU-protection card (top of the Connection page) ────
		 * The honest place of the guarantee: «RU traffic does NOT go through
		 * the proxy» — a routing invariant, not an automation setting. The
		 * guard sits in the generated config BEFORE the proxy lists; the
		 * RU-geo databases feed it (and the learning exclusion). Shown only
		 * in "Bypass blocking" — the only mode where the invariant rules
		 * exist. ONE result area under the card (ui.action_buttons_result_
		 * placement); saves go through the tracked op with a verified
		 * verdict. */
		function pollGeoOp(desc, after, okText) {
			if (!desc || desc.hot || !desc.op_id) {
				if (after) after();
				return;
			}
			const doneText = okText || _('The change is applied and verified.');
			const deadline = Date.now() + 150000;
			const tick = function() {
				return L.resolveDefault(callOpStatus(desc.op_id), {}).then(function(st) {
					const op = st && st.op;
					if (op && op.status !== 'completed' && op.status !== 'failed') {
						if (Date.now() > deadline) {
							ui.addNotification(null, E('p', {},
								_('The apply operation is still running — check the operations journal on the Health center page.')), 'info');
							if (after) after();
							return;
						}
						window.setTimeout(tick, 2000);
						return;
					}
					const ok = !!op && op.status === 'completed' && op.verified;
					ui.addNotification(null, E('p', {}, ok
						? doneText
						: _('Apply failed: ') + ((op && (op.detail || op.error)) || _('rpc error'))),
						ok ? 'info' : 'error');
					if (after) after();
				});
			};
			tick();
		}

		let ruCard = null;
		if (modeNow === 'proxy_banned_ru') {
			if (!document.getElementById('hp-ru-style')) {
				document.head.appendChild(E('style', { id: 'hp-ru-style' }, [ `
.rurow { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg-2); margin: 6px 0; }
` ]));
			}
			const ruResult = E('div', { 'class': 'hpui-hint', style: 'margin-top:6px' });
			const ruStatus = E('div', { 'class': 'hpui-hint', style: 'margin-top:6px' });
			const geoProtect = E('input', { type: 'checkbox' });
			const geoAuto = E('input', { type: 'checkbox' });
			const geoHours = E('input', { type: 'number', min: '1', max: '720', 'class': 'cbi-input-text', style: 'width:80px' });
			const ruSave = E('button', { 'class': 'btn cbi-button cbi-button-apply', type: 'button' }, [ _('Save RU-protection') ]);
			const ruUpdate = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Update databases now') ]);
			geoProtect.checked = (uci.get('ravnex', 'automation', 'geo_protect') != null)
				? (uci.get('ravnex', 'automation', 'geo_protect') !== '0') : true;
			geoAuto.checked = (uci.get('ravnex', 'automation', 'geo_auto_update') === '1');
			geoHours.value = uci.get('ravnex', 'automation', 'geo_update_hours') || '24';
			const ruRow = E('div', { 'class': 'rurow' }, [
				E('label', { 'class': 'hpui-hint', style: 'margin:0; cursor:pointer; font-weight:600' },
					[ geoProtect, ' ' + _('RU traffic does NOT go through the proxy') ]),
				ruSave
			]);
			const ruExpert = E('details', { style: 'margin:6px 0 0 0' }, [
				E('summary', { style: 'cursor:pointer; opacity:.8' }, [ _('RU-geo databases auto-update') ]),
				E('div', { 'class': 'rurow' }, [
					E('label', { 'class': 'hpui-hint', style: 'margin:0; cursor:pointer' },
						[ geoAuto, ' ' + _('Update the RU-geo databases automatically') ]),
					E('label', { 'class': 'hpui-hint', style: 'margin:0' }, [ _('every') ]),
					geoHours, E('span', { 'class': 'hpui-hint', style: 'margin:0' }, [ 'h' ]),
					ruUpdate
				]),
				E('p', { 'class': 'hpui-hint' },
					[ _('The daemon checks the database age hourly and re-downloads it in the background when it is older than the interval. The databases list all Russian networks and the domains of major RU services (banks, marketplaces, Yandex/VK/Mail.ru stacks); sources: GrimbirdUsers/ru-routing-dat via GitHub / jsDelivr mirrors, ipdeny.com fallback.') ])
			]);
			ruSave.addEventListener('click', function() {
				ruSave.disabled = true;
				const wasProtect = (uci.get('ravnex', 'automation', 'geo_protect') != null)
					? (uci.get('ravnex', 'automation', 'geo_protect') !== '0') : true;
				L.resolveDefault(callGeoProtectSet(
					geoProtect.checked ? '1' : '0',
					geoAuto.checked ? '1' : '0',
					String(parseInt(geoHours.value, 10) || 24)), {}).then(function(r) {
					ruSave.disabled = false;
					if (!r || r.result !== true) {
						ruResult.textContent = _('Save failed: ') + ((r && r.error) || _('rpc error'));
						return;
					}
					if (r.unchanged) {
						ruResult.textContent = _('Saved — the auto-update settings are re-read by the daemon on its own hourly check.');
						return;
					}
					/* The guard changed → generate+reload (tracked op). */
					ruResult.textContent = _('Applying — the core config regenerates…');
					pollGeoOp(r, function() { ruResult.textContent = ''; },
						geoProtect.checked
							? _('RU-protection is ON and verified — RU traffic stays direct.')
							: _('RU-protection is OFF and verified — RU traffic may follow the lists.'));
				}).catch(function(e) {
					ruSave.disabled = false;
					ruResult.textContent = _('Save failed: ') + e;
				});
			});
			ruUpdate.addEventListener('click', function() {
				ruUpdate.disabled = true;
				L.resolveDefault(callGeoUpdate(), {}).then(function(r) {
					ruUpdate.disabled = false;
					if (r && r.result === false)
						ruResult.textContent = _('Update failed to start: ') + (r.error || '');
					else
						ruResult.textContent = _('The RU-geo update started in the background — the status line shows the new date in a minute.');
					refreshRuStatus();
				}).catch(function(e) {
					ruUpdate.disabled = false;
					ruResult.textContent = _('Update failed: ') + e;
				});
			});
			function renderRuStatus(meta) {
				const g = (meta && meta.meta) || meta || {};
				ruStatus.textContent = '';
				ruStatus.appendChild(E('span', { 'class': 'hpui-badge ' + (geoProtect.checked ? 'hpui-b-green' : 'hpui-b-grey') },
					[ geoProtect.checked ? _('Guard is on') : _('Guard is off') ]));
				ruStatus.appendChild(document.createTextNode(' '));
				ruStatus.appendChild(E('b', {}, [ _('RU-geo databases') ]));
				ruStatus.appendChild(document.createTextNode(': ' + (g.installed
					? _('networks %s, domains %s').format(g.geoip || 0, g.geosite || 0)
					: _('not downloaded — press "Update databases now"'))
					+ (g.updated ? (' · ' + (function(ts) {
						const d = Math.floor((Date.now() / 1000 - Number(ts)) / 86400);
						if (d <= 0) return _('updated today');
						if (d === 1) return _('updated yesterday');
						return _('updated %d days ago').format(d);
					})(g.updated)) : '')
					+ (g.updating ? (' · ' + _('updating…')) : '')));
			}
			function refreshRuStatus() {
				return L.resolveDefault(callGeoStatus(), {}).then(renderRuStatus);
			}
			poll.add(refreshRuStatus, hp.pollSec(10));
			refreshRuStatus();
			ruCard = E('div', { 'class': 'hpui-panel', style: 'margin:0 0 14px 0' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('shield'), _('RU-protection') ]),
				E('p', { 'class': 'hpui-hint', style: 'margin:2px 0 8px 0' },
					[ _('RU traffic does NOT go through the proxy: Russian networks and domains (the RU-geo databases, .ru/.su/.рф) are always routed DIRECT — even when a resource sits in the learned, static or your own proxy lists. RU services (banks, marketplaces, government portals) flag VPN exits — the guard keeps them off the tunnel. The check order: service rules → your "Direct" lists → RU-protection → your "Proxy" lists → learned lists.') ]),
				ruRow,
				ruExpert,
				ruStatus,
				ruResult
			]);
		}

		return m.render().then(function(node) {
			/* Ф9.14: collapse the expert WAN & interface section into a
			 * <details> (U4: the less the user sees, the fewer mistakes —
			 * the automation.js move pattern, located by its unique title). */
			const expDetails = E('details', { style: 'margin:10px 0' }, [
				E('summary', { style: 'cursor:pointer; font-weight:600; opacity:.8; padding:6px 0; user-select:none' },
					[ _('Expert: WAN & interfaces') + ' · ' + _('hidden by default — open only if needed') ])
			]);
			const sections = node ? node.querySelectorAll('.cbi-section') : [];
			for (let i = 0; i < sections.length; i++) {
				const hd = sections[i].querySelector('.cbi-section-title') ||
					sections[i].querySelector('h3');
				if (hd && hd.textContent.indexOf(_('Expert: WAN & interfaces')) === 0) {
					const parent = sections[i].parentNode;
					parent.insertBefore(expDetails, sections[i]);
					expDetails.appendChild(sections[i]);
					break;
				}
			}
			return E('div', {}, [
				hp.pageIntro(_('Connection'),
					_('How the traffic leaves your home: which server is the main one, how the routing mode decides what goes through the proxy, and what keeps the connection alive when a server dies. Everyday service→exit rules live on the Service rules page; DNS pools common to all modes — on the DNS settings page.')),
				ruCard,
				node
			].filter(function(x) { return x; }));
		});
	}

});
