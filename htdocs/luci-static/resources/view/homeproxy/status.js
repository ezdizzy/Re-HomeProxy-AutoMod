/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require dom';
'require form';
'require fs';
'require homeproxy as hp';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

/* Ф1.1b: applies run as tracked operations (stages + server-side verified
 * flag) — snapshot restore (and any op-carrying reply) is polled to the
 * honest verdict instead of a wishful success. */
const callOpStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_op_status',
	params: [ 'op_id' ],
	expect: { '': {} }
});

/* The "Resources management" status bar (v3, server.js convention): the
 * running state of the service is polled — the dot and the badge are
 * rebuilt in place via replaceChildren (no innerHTML). */
const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

function getServiceStatus() {
	return L.resolveDefault(callServiceList('homeproxy'), {}).then((res) => {
		let isRunning = false;
		try {
			isRunning = res['homeproxy']['instances']['hiddify-c']['running'];
		} catch (e) { }
		return isRunning;
	});
}

/* Poll one operation to completion; `onDone(ok, detail)` fires exactly once. */
function pollOp(opId, onDone) {
	const deadline = Date.now() + 150000;
	const tick = function() {
		return L.resolveDefault(callOpStatus(opId), {}).then(function(st) {
			const op = st && st.op;
			if (op && op.status !== 'completed' && op.status !== 'failed') {
				if (Date.now() > deadline) {
					onDone(false, _('The operation is still running — check the operations journal on the Health center page.'));
					return;
				}
				window.setTimeout(tick, 2000);
				return;
			}
			const ok = !!op && op.status === 'completed' && op.verified;
			onDone(ok, ok ? '' : ((op && (op.detail || op.error)) || _('Apply failed')));
		});
	};
	tick();
}

/* Ф9.1/Ф10.1 (§A.4): the resource-profile card — the hardware fact base
 * (RAM/CPU/flash) + the Lite/Balanced/Performance class, and (Ф10.1) the
 * MANUAL switch: auto (the §A.4 hardware detection) or a forced class.
 * The profile DRIVES the page-poll factor (Lite ×3, Balanced ×2,
 * Performance ×1) and the observation cadence of the metrics, health and
 * sentinel daemons; reactive passes (incidents, operation progress) are
 * never scaled (D34h). Per-boot facts: fetched once + every 60 s. */
const callResProfile = rpc.declare({
	object: 'luci.homeproxy',
	method: 'res_profile',
	expect: { '': {} }
});

const callResProfileSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'res_profile_set',
	params: [ 'mode' ],
	expect: { '': {} }
});

function fmtKb(kb) {
	kb = parseInt(kb, 10) || 0;
	if (kb > 1048576) return (kb / 1048576).toFixed(1) + ' GB';
	return Math.round(kb / 1024) + ' MB';
}

function buildResProfileCard() {
	const profBadge = E('span', { 'class': 'hpui-badge hpui-b-green' }, [ '—' ]);
	const factsEl = E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' }, [ '' ]);
	/* Ф10.1: ONE verdict line for the whole card — every switch result
	 * replaces the previous one here (mkResult / result-placement rule). */
	const result = mkResult();
	const names = { lite: 'Lite', balanced: 'Balanced', performance: 'Performance' };
	const modeLabel = { auto: _('Auto'), lite: 'Lite', balanced: 'Balanced', performance: 'Performance' };
	const MODES = [ 'auto', 'lite', 'balanced', 'performance' ];
	const modeBtns = {};
	let curMode = 'auto';
	let curProfile = null;

	function markMode(mode) {
		for (let i = 0; i < MODES.length; i++) {
			const m = MODES[i];
			modeBtns[m].className = 'hpui-btn' + (m === mode ? ' hpui-btn-primary' : '');
			modeBtns[m].disabled = false;
		}
	}

	function cacheFactor() {
		/* Ф10.1: refresh the page-poll factor cache right away — the OTHER
		 * pages apply the new intervals on their next navigation. */
		try {
			window.sessionStorage.setItem('hpResProfile', JSON.stringify({
				factor: (curProfile && (parseInt(curProfile.factor, 10) || 1)) || 1,
				profile: (curProfile && curProfile.profile) || '',
				mode: curMode,
				ts: Date.now()
			}));
		} catch (e) {}
	}

	function applyMode(mode) {
		for (let i = 0; i < MODES.length; i++)
			modeBtns[MODES[i]].disabled = true;
		result.setResult(_('Applying…'), 'grey');
		L.resolveDefault(callResProfileSet(mode), {}).then((r) => {
			r = r || {};
			if (!r.result) {
				markMode(curMode);
				result.setResult(r.error || _('Apply failed'), 'red');
				return;
			}
			curMode = mode;
			return refresh().then(() => {
				cacheFactor();
				markMode(mode);
				if (!r.changed)
					result.setResult(_('The profile is already %s — nothing to change.').format(modeLabel[mode] || mode), 'grey');
				else
					result.setResult(_('Profile applied: %s. Daemons follow live; open pages apply the new intervals after navigation.').format(modeLabel[mode] || mode), 'green');
			});
		});
	}

	for (let i = 0; i < MODES.length; i++) {
		const m = MODES[i];
		const b = mkBtn(modeLabel[m], '', {});
		b.style.padding = '4px 10px';
		b.addEventListener('click', () => { applyMode(m); });
		modeBtns[m] = b;
	}

	function render(p) {
		p = p || {};
		curProfile = p;
		if (!p.profile) {
			profBadge.textContent = '—';
			factsEl.textContent = _('The hardware profile is unavailable (the read failed).');
			return;
		}
		curMode = (p.mode === 'lite' || p.mode === 'balanced' || p.mode === 'performance') ? p.mode : 'auto';
		profBadge.textContent = (names[p.profile] || p.profile) +
			(p.source === 'auto' ? ' · ' + _('auto') : (p.source === 'manual' ? ' · ' + _('manual') : ''));
		const parts = [];
		if (p.ram_total_kb != null)
			parts.push(_('RAM') + ': ' + fmtKb(p.ram_total_kb) +
				((p.ram_avail_kb != null) ? ' (' + _('available') + ' ' + fmtKb(p.ram_avail_kb) + ')' : ''));
		if (p.cores != null)
			parts.push(_('CPU cores') + ': ' + p.cores);
		if (p.flash_total_kb != null)
			parts.push(_('Flash') + ': ' + fmtKb(p.flash_total_kb));
		parts.push(_('poll factor') + ': ×' + ((parseInt(p.factor, 10) || 1)));
		factsEl.textContent = parts.join(' · ');
		markMode(curMode);
	}

	function refresh() {
		return L.resolveDefault(callResProfile(), {}).then(render);
	}
	poll.add(refresh, hp.pollSec(60));
	refresh();

	const modeRow = E('div', { style: 'margin-top:8px; display:flex; flex-wrap:wrap; gap:6px; align-items:center' }, []);
	for (let i = 0; i < MODES.length; i++)
		modeRow.appendChild(modeBtns[MODES[i]]);

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:8px' }, [
			E('strong', {}, [ hp.icon('cpu'), ' ', _('Resource profile') ]),
			profBadge
		]),
		factsEl,
		modeRow,
		result,
		E('div', { style: 'margin-top:6px; font-size:0.85em; opacity:.75' },
			[ _('The profile scales the refresh intervals of the app pages (Lite ×3, Balanced ×2, Performance ×1) and the observation cadence of the metrics, health and sentinel daemons; reactive passes (incidents, operation progress) are never scaled. Auto = the hardware detection (RAM). Daemons follow a switch live; open pages apply it after navigation.') ])
	]);
}

/* Thanks to luci-app-aria2 */
const hp_dir = '/var/run/homeproxy';

/* v3 (Ф9.2/Ф9.3): shared card-tool button (hpui family). variant:
 * 'primary' | 'danger' | 'ghost' | '' (plain). Disabled states and click
 * handlers stay with the caller — install/remove flows manage them manually. */
function mkBtn(label, variant, attrs) {
	return E('button', Object.assign({
		'class': 'hpui-btn' + (variant ? ' hpui-btn-' + variant : ''),
		'type': 'button'
	}, attrs || {}), [ label ]);
}

/* v3 result placement (D34e): ONE verdict line per card, under the header
 * row — every action (install/update/check/clean) replaces the previous
 * verdict in the same line instead of scattered inline spans. kind:
 * 'green' | 'red' | 'amber' | 'grey' | '' (plain). */
function mkResult() {
	const el = E('div', { 'class': 'hp-card-result',
		'style': 'margin-top:6px; min-height:1em; font-size:.9em' }, [ '\u00a0' ]);
	el.setResult = function(txt, kind) {
		el.replaceChildren(E('span', { 'class': kind ? 'hpui-c-' + kind : '' }, [ txt || '' ]));
	};
	return el;
}

function getRuntimeLog(o, name, _option_index, section_id, _in_table) {
	const filename = o.option.split('_')[1];

	let section, log_level_el;
	switch (filename) {
	case 'homeproxy':
		section = null;
		break;
	case 'hiddify-c':
		section = 'config';
		break;
	}

	if (section) {
		const selected = uci.get('homeproxy', section, 'log_level') || 'warn';
		const choices = {
			trace: _('Trace'),
			debug: _('Debug'),
			info: _('Info'),
			warn: _('Warn'),
			error: _('Error'),
			fatal: _('Fatal'),
			panic: _('Panic')
		};

		log_level_el = E('select', {
			'id': o.cbid(section_id),
			'class': 'cbi-input-select',
			'style': 'margin-left: 4px; width: 6em;',
			'change': ui.createHandlerFn(this, (ev) => {
				uci.set('homeproxy', section, 'log_level', ev.target.value);
				return o.map.save(null, true).then(() => {
					ui.changes.apply(true);
				});
			})
		});

		Object.keys(choices).forEach((v) => {
			log_level_el.appendChild(E('option', {
				'value': v,
				'selected': (v === selected) ? '' : null
			}, [ choices[v] ]));
		});
	}

	const callLogClean = rpc.declare({
		object: 'luci.homeproxy',
		method: 'log_clean',
		params: ['type'],
		expect: { '': {} }
	});

	const log_textarea = E('div', { 'class': 'hpui-log' },
		[ _('Collecting data...') ]);

	let log;
	poll.add(L.bind(() => {
		return fs.read_direct(String.format('%s/%s.log', hp_dir, filename), 'text')
		.then((res) => {
			/* The content node is rebuilt on every poll; keep the reader's
			 * scroll position so the box does not jump back to the top. */
			const scrollTop = log_textarea.scrollTop;
			log = res.trim() || _('Log is empty.');

			dom.content(log_textarea, [ log ]);
			log_textarea.scrollTop = scrollTop;
		}).catch((err) => {
			if (err.toString().includes('NotFoundError'))
				log = _('Log file does not exist.');
			else
				log = _('Unknown error: %s').format(err);

			dom.content(log_textarea, [ log ]);
		});
	}));

	return E([
		E('div', {'class': 'cbi-map'}, [
			/* User note 2026-11-07: the clear button lived INSIDE the h3 and
			 * inherited its 18px/36px bold typography (~52px tall), crowding
			 * the log box below. The button now sits on its own compact row
			 * above the log; the h3 row keeps title + level select (wrapped). */
			E('h3', {'name': 'content', 'style': 'align-items: center; display: flex; flex-wrap: wrap; gap: 8px;'}, [
				_('%s log').format(name),
				log_level_el || ''
			]),
			E('div', {'style': 'display:flex; justify-content:flex-end; margin:0 0 6px'}, [
				E('button', {
					'class': 'hpui-btn hpui-btn-danger',
					'type': 'button',
					'style': 'padding: 2px 10px; font-size: .84em;',
					'click': ui.createHandlerFn(this, () => {
						return L.resolveDefault(callLogClean(filename), {});
					})
				}, [ _('Clean log') ])
			]),
			E('div', {'class': 'cbi-section'}, [
				log_textarea,
				E('div', {'style': 'text-align:right'},
					E('small', {}, _('Refresh every %s seconds.').format(L.env.pollinterval))
				)
			])
		])
	]);
}

const CORE_MGMT = '/usr/share/homeproxy/scripts/core_mgmt.uc';

const callCurlStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'curl_status',
	expect: { '': {} }
});

const callCurlInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'curl_install',
	expect: { '': {} }
});

const callCurlRemove = rpc.declare({
	object: 'luci.homeproxy',
	method: 'curl_remove',
	expect: { '': {} }
});

const callByeDPIStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'byedpi_status',
	expect: { '': {} }
});

const callByeDPIPrepareInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'byedpi_prepare_install',
	expect: { '': {} }
});

const callByeDPIInstallPkg = rpc.declare({
	object: 'luci.homeproxy',
	method: 'byedpi_install_pkg',
	params: ['tmp_path', 'pkg_manager'],
	expect: { '': {} }
});

const callByeDPIRemove = rpc.declare({
	object: 'luci.homeproxy',
	method: 'byedpi_remove',
	expect: { '': {} }
});

const callZapretStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_status',
	expect: { '': {} }
});

const callZapretPrepareInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_prepare_install',
	expect: { '': {} }
});

const callZapretInstallPkg = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_install_pkg',
	params: ['tmp_path', 'pkg_manager'],
	expect: { '': {} }
});

const callZapretRemove = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_remove',
	expect: { '': {} }
});

const callAppStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_status',
	expect: { '': {} }
});

const callMultidnsStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'multidns_status',
	expect: { '': {} }
});

const callMosdnsStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'mosdns_status',
	expect: { '': {} }
});

const callMosdnsPrepareInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'mosdns_prepare_install',
	expect: { '': {} }
});

const callMosdnsInstallPkg = rpc.declare({
	object: 'luci.homeproxy',
	method: 'mosdns_install_pkg',
	params: ['tmp_path'],
	expect: { '': {} }
});

const callMosdnsRemove = rpc.declare({
	object: 'luci.homeproxy',
	method: 'mosdns_remove',
	expect: { '': {} }
});

const callByeDPICheckUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'byedpi_check_update',
	expect: { '': {} }
});

const callZapretCheckUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'zapret_check_update',
	expect: { '': {} }
});

const callMosdnsCheckUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'mosdns_check_update',
	expect: { '': {} }
});

/* "Check update" button for GitHub-packaged tools (ByeDPI / Zapret / mosdns):
 * asks the backend for the latest release tag and reports it against the
 * installed version (same interaction as the core cards). The verdict lands
 * in the card's ONE result line (resultEl.setResult). */
function buildCheckUpdateBtn(callFn, resultEl) {
	return mkBtn(_('Check update'), 'ghost', {
		click: async function() {
			this.disabled = true;
			resultEl.setResult(_('Checking...'), 'grey');
			const ret = await L.resolveDefault(callFn(), {});
			this.disabled = false;
			if (ret.error)
				return resultEl.setResult(ret.error, 'red');
			resultEl.setResult(_('Latest') + ': v' + ret.latest_version,
				ret.update_available ? 'amber' :
				(ret.installed_version ? 'green' : 'grey'));
		}
	});
}

function buildMosdnsCard(mdns, mos) {
	mdns = mdns || {};
	mos  = mos  || {};
	let installed = !!mos.installed;
	let version   = mos.version || null;
	const running    = !!mos.running;
	/* The routine quality-cycle rebuild bounces mosdns for a few seconds:
	 * show the neutral "restarting..." instead of a bare "stopped". */
	const restarting = !running && !!mos.restarting;
	const enabled    = mdns.enabled === '1';
	const ru         = (mdns.active && mdns.active.ru) ? mdns.active.ru.length : 0;
	const sec        = (mdns.active && mdns.active.secure) ? mdns.active.secure.length : 0;

	const statusEl = E('strong', {
		style: 'color:' + (installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, installed ? (version ? version : _('Installed')) : _('Not installed'));

	const runEl = E('span', {
		style: 'margin-left:6px; font-size:0.9em; color:' + (running ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, running ? _('running') : (restarting ? _('restarting...') : _('stopped')));

	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	const installBtn = mkBtn(installed ? _('Update') : _('Install'), 'primary', {
		style: 'margin-left:4px',
		click: async function() {
			const prevInstalled = installed;
			const prevVersion   = version;
			installBtn.disabled = true;
			removeBtn.disabled  = true;
			statusEl.textContent = _('Installing...');
			statusEl.style.color = 'var(--hp-grey)';

			const fail = (msg) => {
				installed = prevInstalled;
				version   = prevVersion;
				statusEl.textContent = installed ? (version || _('Installed')) : _('Not installed');
				statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
				installBtn.disabled = false;
				removeBtn.disabled  = !installed;
				setMsg(msg, 'red');
			};

			setMsg(_('Checking requirements...'), 'grey');
			const prep = await L.resolveDefault(callMosdnsPrepareInstall(), {});
			if (prep.error) return fail(prep.error);

			setMsg(_('Downloading...'), 'grey');
			const dl = await L.resolveDefault(callCoreDownload(prep.dl_url, prep.tmp_path), {});
			if (!dl.result) return fail(dl.error || _('Download failed'));

			setMsg(_('Installing package...'), 'grey');
			const inst = await L.resolveDefault(callMosdnsInstallPkg(prep.tmp_path), {});
			if (!inst.result) return fail(inst.error || _('Installation failed'));

			const fresh = await L.resolveDefault(callMosdnsStatus(), {});
			installed = fresh.installed || false;
			version   = fresh.version || null;
			statusEl.textContent = installed ? (version || _('Installed')) : _('Unknown');
			statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
			installBtn.textContent = _('Update');
			installBtn.disabled = false;
			removeBtn.disabled  = false;
			setMsg(_('Installed successfully'), 'green');
		}
	});

	const removeBtn = mkBtn(_('Remove'), 'danger', {
		style: 'margin-left:4px',
		disabled: !installed || null,
		click: async function() {
			removeBtn.disabled  = true;
			installBtn.disabled = true;
			setMsg(_('Removing...'), 'grey');
			const ret = await L.resolveDefault(callMosdnsRemove(), {});
			installBtn.disabled = false;
			if (ret.result) {
				installed = false;
				version   = null;
				statusEl.textContent = _('Not installed');
				statusEl.style.color = 'var(--hp-grey)';
				installBtn.textContent = _('Install');
				setMsg(_('Removed successfully — MultiDNS disabled'), 'green');
			} else {
				removeBtn.disabled = false;
				setMsg(ret.error || _('Removal failed'), 'red');
			}
		}
	});

	const checkBtn = buildCheckUpdateBtn(callMosdnsCheckUpdate, resultEl);

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, 'mosdns (MultiDNS)'),
			statusEl,
			runEl,
			checkBtn,
			installBtn,
			removeBtn
		]),
		resultEl,
		/* '\u00a0' — real NBSP: E() escapes strings, a literal '&nbsp;' here would
		 * render as visible text (that exact bug). The description must go through
		 * innerHTML: it contains HTML links E() would also escape. */
		E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' },
			_('MultiDNS') + ': ' + (enabled ? _('Enabled') : _('Disabled')) +
			'\u00a0|\u00a0' + _('Plain pool') + ' (' + _('Russia') + '): ' + ru +
			'\u00a0|\u00a0' + _('Secure pool') + ': ' + sec),
		(() => {
			const el = E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' });
			el.innerHTML = _('Per-query DNS racing engine for MultiDNS: races every server in each pool in parallel and returns the fastest valid answer, while the quality daemon verifies over HTTPS that the returned IPs actually open sites and prunes dead/polluted servers. Binary from <a href="https://github.com/IrineSistiana/mosdns" target="_blank">IrineSistiana/mosdns</a> releases.');
			return el;
		})()
	]);
}

const callAppCheckUpdate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_check_update',
	expect: { '': {} }
});

const callAppPrepareInstall = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_prepare_install',
	expect: { '': {} }
});

const callAppInstallPkg = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_install_pkg',
	params: ['app_path', 'i18n_path', 'pkg_manager'],
	expect: { '': {} }
});

const callCoreSkipped = rpc.declare({
	object: 'luci.homeproxy',
	method: 'core_skipped',
	expect: { '': {} }
});

/* Background core install (hiddify / sing-box / sing-box-lite): the runner
 * does prepare → download → install → kmods detached and writes stage
 * status into /var/run/homeproxy/core_install.json; the card polls it.
 * A ~46-95 MB download used to freeze the tab for minutes. */
const callCoreInstallStart = rpc.declare({
	object: 'luci.homeproxy',
	method: 'core_install_start',
	params: [ 'core', 'variant' ],
	expect: { '': {} }
});

const callCoreInstallStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'core_install_status',
	expect: { '': {} }
});

/* Local rule-set fallback (issue #12): status lists the remote rule-sets of
 * the LIVE config with their local cold-start copies; seed pre-downloads
 * the missing ones (detached runner, progress in the status reply). */
const callRulesetsLocalStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_rulesets_local_status',
	expect: { '': {} }
});

const callRulesetsLocalSeed = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_rulesets_local_seed',
	params: [ 'force' ],
	expect: { '': {} }
});

function buildByeDPICard(byedpi, isMainNode) {
	let installed = byedpi?.installed || false;
	let version   = byedpi?.version   || null;
	const running    = byedpi?.running    || false;
	const pkgMgr     = byedpi?.pkg_manager || null;
	const canInstall = !!pkgMgr;

	const statusEl = E('strong', {
		style: 'color:' + (installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, installed ? (version ? 'v' + version : _('Installed')) : _('Not installed'));

	const runEl = E('span', {
		style: 'margin-left:6px; font-size:0.9em; color:' + (running ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, running ? _('running') : _('stopped'));

	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	const installBtn = mkBtn(installed ? _('Update') : _('Install'), 'primary', {
		style: 'margin-left:4px',
		disabled: !canInstall || null,
		title: canInstall ? '' : _('No supported package manager detected'),
		click: async function() {
			const prevInstalled = installed;
			const prevVersion   = version;
			installBtn.disabled = true;
			removeBtn.disabled  = true;
			statusEl.textContent = _('Installing...');
			statusEl.style.color = 'var(--hp-grey)';

			const fail = (msg) => {
				installed = prevInstalled;
				version   = prevVersion;
				statusEl.textContent = installed ? (version ? 'v' + version : _('Installed')) : _('Not installed');
				statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
				installBtn.disabled = false;
				removeBtn.disabled  = !installed;
				setMsg(msg, 'red');
			};

			setMsg(_('Checking requirements...'), 'grey');
			const prep = await L.resolveDefault(callByeDPIPrepareInstall(), {});
			if (prep.error) return fail(prep.error);

			setMsg(_('Downloading...'), 'grey');
			const dl = await L.resolveDefault(callCoreDownload(prep.dl_url, prep.tmp_path), {});
			if (!dl.result) return fail(dl.error || _('Download failed'));

			setMsg(_('Installing package...'), 'grey');
			const inst = await L.resolveDefault(callByeDPIInstallPkg(prep.tmp_path, prep.pkg_manager), {});
			if (!inst.result) return fail(inst.error || _('Installation failed'));

			const fresh = await L.resolveDefault(callByeDPIStatus(), {});
			installed = fresh.installed || false;
			version   = fresh.version   || null;
			statusEl.textContent = installed ? (version ? 'v' + version : _('Installed')) : _('Unknown');
			statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
			installBtn.textContent = _('Update');
			installBtn.disabled = false;
			removeBtn.disabled  = false;
			setMsg(_('Installed successfully'), 'green');
		}
	});

	const removeBtn = mkBtn(_('Remove'), 'danger', {
		style: 'margin-left:4px',
		disabled: !installed || isMainNode || null,
		title: isMainNode ? _('Cannot remove: ByeDPI is selected as Main Node. Change Main Node first.') : '',
		click: async function() {
			removeBtn.disabled  = true;
			installBtn.disabled = true;
			setMsg(_('Removing...'), 'grey');
			const ret = await L.resolveDefault(callByeDPIRemove(), {});
			installBtn.disabled = false;
			if (ret.result) {
				installed = false;
				version   = null;
				statusEl.textContent = _('Not installed');
				statusEl.style.color = 'var(--hp-grey)';
				installBtn.textContent = _('Install');
				setMsg(_('Removed successfully'), 'green');
			} else {
				removeBtn.disabled = false;
				setMsg(ret.error || _('Removal failed'), 'red');
			}
		}
	});

	const checkBtn = buildCheckUpdateBtn(callByeDPICheckUpdate, resultEl);

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, 'ciadpi (ByeDPI)'),
			statusEl,
			runEl,
			checkBtn,
			installBtn,
			removeBtn
		]),
		resultEl,
		(() => {
			const el = E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' });
			/* innerHTML: the description contains HTML links E() would escape */
			el.innerHTML = _('Local SOCKS5 DPI bypass proxy by <a href="https://github.com/hufrea/byedpi" target="_blank">hufrea</a>. ' +
			'Packages by <a href="https://github.com/1andrevich/ByeDPI-OpenWrt" target="_blank">1andrevich/ByeDPI-OpenWrt</a>. ' +
			'Enable on the Connection page; strategies are configured on the Blocking bypass page.');
			return el;
		})()
	]);
}

function buildZapretCard(zapret, isMainNode) {
	let installed = zapret?.installed || false;
	let version   = zapret?.version   || null;
	const running    = zapret?.running    || false;
	const pkgMgr     = zapret?.pkg_manager || null;
	let kmodOk       = (zapret?.kmod_ok != null) ? zapret.kmod_ok : true;
	const canInstall = !!pkgMgr;

	const statusEl = E('strong', {
		style: 'color:' + (installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, installed ? (version ? 'v' + version : _('Installed')) : _('Not installed'));

	const runEl = E('span', {
		style: 'margin-left:6px; font-size:0.9em; color:' + (running ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, running ? _('running') : _('stopped'));

	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	const installBtn = mkBtn(installed ? _('Update') : _('Install'), 'primary', {
		style: 'margin-left:4px',
		disabled: !canInstall || null,
		title: canInstall ? '' : _('No supported package manager detected'),
		click: async function() {
			const prevInstalled = installed;
			const prevVersion   = version;
			installBtn.disabled = true;
			removeBtn.disabled  = true;
			statusEl.textContent = _('Installing...');
			statusEl.style.color = 'var(--hp-grey)';

			const fail = (msg) => {
				installed = prevInstalled;
				version   = prevVersion;
				statusEl.textContent = installed ? (version ? 'v' + version : _('Installed')) : _('Not installed');
				statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
				installBtn.disabled = false;
				removeBtn.disabled  = !installed;
				setMsg(msg, 'red');
			};

			setMsg(_('Checking requirements...'), 'grey');
			const prep = await L.resolveDefault(callZapretPrepareInstall(), {});
			if (prep.error) return fail(prep.error);

			setMsg(_('Downloading...'), 'grey');
			const dl = await L.resolveDefault(callCoreDownload(prep.dl_url, prep.tmp_path), {});
			if (!dl.result) return fail(dl.error || _('Download failed'));

			setMsg(_('Installing package...'), 'grey');
			const inst = await L.resolveDefault(callZapretInstallPkg(prep.tmp_path, prep.pkg_manager), {});
			if (!inst.result) return fail(inst.error || _('Installation failed'));

			const fresh = await L.resolveDefault(callZapretStatus(), {});
			installed = fresh.installed || false;
			version   = fresh.version   || null;
			kmodOk    = (fresh.kmod_ok != null) ? fresh.kmod_ok : true;
			statusEl.textContent = installed ? (version ? 'v' + version : _('Installed')) : _('Unknown');
			statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
			installBtn.textContent = _('Update');
			installBtn.disabled = false;
			removeBtn.disabled  = false;
			if (installed && !kmodOk)
				setMsg(_('Installed, but kmod-nft-queue is missing — Zapret cannot intercept traffic without it.'), 'red');
			else
				setMsg(_('Installed successfully'), 'green');
		}
	});

	const removeBtn = mkBtn(_('Remove'), 'danger', {
		style: 'margin-left:4px',
		disabled: !installed || isMainNode || null,
		title: isMainNode ? _('Cannot remove: Zapret is selected as Main Node. Change Main Node first.') : '',
		click: async function() {
			removeBtn.disabled  = true;
			installBtn.disabled = true;
			setMsg(_('Removing...'), 'grey');
			const ret = await L.resolveDefault(callZapretRemove(), {});
			installBtn.disabled = false;
			if (ret.result) {
				installed = false;
				version   = null;
				statusEl.textContent = _('Not installed');
				statusEl.style.color = 'var(--hp-grey)';
				installBtn.textContent = _('Install');
				setMsg(_('Removed successfully'), 'green');
			} else {
				removeBtn.disabled = false;
				setMsg(ret.error || _('Removal failed'), 'red');
			}
		}
	});

	/* nfqws2's NFQUEUE rule needs kmod-nft-queue; warn up-front if it's missing. */
	if (installed && !kmodOk)
		setMsg(_('Warning: kmod-nft-queue is not installed — Zapret cannot intercept traffic without it.'), 'red');

	const checkBtn = buildCheckUpdateBtn(callZapretCheckUpdate, resultEl);

	/* ── Strategy Lab link (C4, Ф8-F5) ────────────────────────────────── */
	/* The DPI Strategy Fuzzer first moved to the (now removed) Node
	 * Settings → Zapret tab (ч.70), then into the Routing Wizard DPI pane
	 * (Ф3; the node.js tabs moved there for good in сеанс 24), and since
	 * R3 v3c lives on the Blocking bypass page («Strategy Lab» zone) —
	 * the wizard is abolished. This card keeps only a shortcut there. */
	const labBtn = mkBtn(_('Strategy Lab'), 'ghost', {
		style: 'margin-left:4px'
	});
	labBtn.onclick = () => { location.href = L.url('admin/services/homeproxy/bypass'); };

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, 'nfqws2 (Zapret 2)'),
			statusEl,
			runEl,
			checkBtn,
			installBtn,
			removeBtn
		]),
		resultEl,
		(() => {
			const el = E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' });
			/* innerHTML: the description contains HTML links E() would escape */
			el.innerHTML = _('Packet-level (NFQUEUE) DPI bypass by <a href="https://github.com/bol-van/zapret2" target="_blank">bol-van</a> (nfqws2). ' +
			  'Packages by <a href="https://github.com/1andrevich/zapret2-openwrt" target="_blank">1andrevich/zapret2-openwrt</a>. ' +
			  'Configure on the Blocking bypass page.');
			return el;
		})(),
		E('div', { style: 'margin-top:8px; border-top:1px solid rgba(128,128,128,.25); padding-top:6px; font-size:.9em; opacity:.9' }, [
			E('span', {}, _('Strategy testing (current strategy, batch fuzzing with baseline and history, Apply) lives on the Blocking bypass page — "Strategy Lab".')),
			labBtn
		])
	]);
}

function buildCurlCard(curl) {
	let installed = curl?.installed || false;
	const pkgMgr  = curl?.pkg_manager || null;
	const canInstall = !!pkgMgr;

	const statusEl = E('strong', {
		style: 'color:' + (installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, installed ? _('Installed') : _('Not installed'));

	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	const installBtn = mkBtn(_('Install'), 'primary', {
		style: 'margin-left:4px',
		disabled: !canInstall || null,
		title: canInstall ? '' : _('No supported package manager detected'),
		click: async function() {
			installBtn.disabled = true;
			removeBtn.disabled  = true;
			statusEl.textContent = _('Installing...');
			statusEl.style.color = 'var(--hp-grey)';
			setMsg('', null);
			const ret = await L.resolveDefault(callCurlInstall(), {});
			if (ret.result) {
				installed = true;
				statusEl.textContent = _('Installed');
				statusEl.style.color = 'var(--hp-accent-strong)';
				installBtn.textContent = _('Reinstall');
				removeBtn.disabled  = false;
				setMsg(_('Installed successfully'), 'green');
			} else {
				statusEl.textContent = _('Not installed');
				statusEl.style.color = 'var(--hp-grey)';
				installBtn.disabled = false;
				setMsg(ret.error || _('Installation failed'), 'red');
			}
		}
	});

	const removeBtn = mkBtn(_('Remove'), 'danger', {
		style: 'margin-left:4px',
		disabled: !installed || null,
		click: async function() {
			removeBtn.disabled  = true;
			installBtn.disabled = true;
			setMsg(_('Removing...'), 'grey');
			const ret = await L.resolveDefault(callCurlRemove(), {});
			installBtn.disabled = false;
			if (ret.result) {
				installed = false;
				statusEl.textContent = _('Not installed');
				statusEl.style.color = 'var(--hp-grey)';
				installBtn.textContent = _('Install');
				setMsg(_('Removed successfully'), 'green');
			} else {
				removeBtn.disabled = false;
				setMsg(ret.error || _('Removal failed'), 'red');
			}
		}
	});

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, 'curl'),
			statusEl,
			installBtn,
			removeBtn
		]),
		resultEl,
		E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' },
			_('Enables real HTTP-based ByeDPI strategy testing. Required for the "Test" and "Test all presets" buttons on the Blocking bypass page.'))
	]);
}

function buildAppCard(appStatus) {
	const installed = !!appStatus;
	let version = appStatus?.version || null;
	const pkgMgr = appStatus?.pkg_manager || null;

	const statusEl = E('strong', {
		style: 'color:' + (installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, installed ? (version ? 'Ravnex v' + version : _('Installed')) : _('Not installed'));

	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	let updateAvailable = false;

	const checkBtn = mkBtn(_('Check update'), 'ghost', {
		click: async function() {
			checkBtn.disabled = true;
			setMsg(_('Checking...'), 'grey');
			const ret = await L.resolveDefault(callAppCheckUpdate(), {});
			checkBtn.disabled = false;
			if (ret.error) {
				setMsg(ret.error, 'red');
				updateBtn.disabled = true;
				return;
			}
			updateAvailable = !!ret.update_available;
			setMsg(_('Latest') + ': v' + ret.latest_version +
				(updateAvailable ? ' — ' + _('Update available') : ' — ' + _('Up to date')),
				updateAvailable ? 'amber' : 'green');
			updateBtn.disabled = !updateAvailable;
		}
	});

	const updateBtn = mkBtn(_('Update'), 'primary', {
		disabled: true,
		click: async function() {
			updateBtn.disabled = true;
			checkBtn.disabled = true;
			statusEl.textContent = _('Preparing...');
			statusEl.style.color = 'var(--hp-grey)';
			setMsg('', null);

			const prep = await L.resolveDefault(callAppPrepareInstall(), {});
			if (prep.error) {
				statusEl.textContent = version ? 'Ravnex v' + version : _('Installed');
				statusEl.style.color = 'var(--hp-accent-strong)';
				updateBtn.disabled = false;
				checkBtn.disabled = false;
				setMsg(prep.error, 'red');
				return;
			}

			setMsg(_('Downloading...'), 'grey');
			const dlApp = await L.resolveDefault(callCoreDownload(prep.app.dl_url, prep.app.tmp_path), {});
			if (!dlApp.result) {
				setMsg(dlApp.error || _('Download failed'), 'red');
				updateBtn.disabled = false;
				checkBtn.disabled = false;
				return;
			}
			let i18nPath = '';
			if (prep.i18n) {
				const dlI18n = await L.resolveDefault(callCoreDownload(prep.i18n.dl_url, prep.i18n.tmp_path), {});
				if (dlI18n.result) i18nPath = prep.i18n.tmp_path;
			}

			setMsg(_('Installing...'), 'grey');
			const inst = await L.resolveDefault(
				callAppInstallPkg(prep.app.tmp_path, i18nPath, prep.pkg_manager), {});
			if (!inst.result) {
				setMsg(inst.error || _('Installation failed'), 'red');
				updateBtn.disabled = false;
				checkBtn.disabled = false;
				return;
			}

			setMsg(_('Installed — reloading...'), 'green');
			/* The package postinst restarts rpcd after a short delay; wait long enough
			 * for the new rpcd (with the updated methods) to be serving before reload. */
			setTimeout(() => window.location.reload(), 5000);
		}
	});

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, 'Ravnex'),
			statusEl,
			checkBtn,
			updateBtn
		]),
		resultEl,
		E('div', { style: 'margin-top:4px; font-size:0.9em; opacity:.85' },
			_('The LuCI app itself. "Check update" compares your installed version with the latest GitHub release; "Update" downloads and installs the new app (and the Russian translation) in place.'))
	]);
}

function callCoreInfo() {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'info'], 'json');
}

function callCoreCheckRemote(core) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'check_remote', core], 'json');
}

function callCorePrepare(core, variant) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'prepare_install', core, variant || ''], 'json');
}

function callCoreDownload(url, tmpPath) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'download_pkg', url, tmpPath], 'json');
}

function callCoreInstallPkg(core, tmpPath, pkgManager) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'install_pkg', core, tmpPath, pkgManager], 'json');
}

function callCoreInstallKmods(pkgManager) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'install_kmods', pkgManager], 'json');
}

function callCoreRemove(core) {
	return fs.exec_direct('/usr/bin/ucode', [CORE_MGMT, 'remove', core], 'json');
}

/* ч.69: snapshot + recovery RPCs. */
const callSnapshotCreate = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_snapshot_create',
	expect: { '': {} }
});
const callSnapshotList = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_snapshot_list',
	expect: { '': {} }
});
const callSnapshotRestore = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_snapshot_restore',
	params: [ 'name' ],
	expect: { '': {} }
});
const callRestoreInternet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'app_restore_internet',
	expect: { '': {} }
});

/* The Zapret fuzzer RPCs moved to the Routing Wizard with the Strategy
 * Lab (first to node.js in ч.70, then to the wizard DPI pane in Ф3). */

function buildSnapshotsCard() {
	const listEl = E('div', { style: 'font-size:.9em; margin:4px 0' },
		[ E('em', { 'class': 'hpui-c-grey' }, '—') ]);
	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	const refreshList = () => L.resolveDefault(callSnapshotList(), {}).then((r) => {
		listEl.innerHTML = '';
		const snaps = (r && r.snapshots) || [];
		if (!snaps.length) {
			listEl.appendChild(E('em', { 'class': 'hpui-c-grey' }, [ _('No snapshots yet') ]));
			return;
		}
		for (let i in snaps) {
			const name = snaps[i].name;
			const rowEl = E('div', { style: 'margin:2px 0' }, [
				E('span', { style: 'font-family:monospace' }, [ name ]),
				' ',
				mkBtn(_('Restore'), 'ghost', { 'class': 'hpui-btn hpui-btn-ghost hpui-btn-sm',
					style: 'font-size:.85em; padding:0 8px' })
			]);
			rowEl.lastChild.onclick = () => {
				hp.confirmModal(_('Restore snapshot'),
					_('Restore configuration snapshot %s? The service restarts.').format(name), _('Restore'))
					.then((ok) => {
						if (!ok)
							return;
						setMsg(_('Restoring...'), 'grey');
						return L.resolveDefault(callSnapshotRestore(name), {}).then((r) => {
							/* Ф1.1b: the restore rides a tracked operation —
							 * poll to the verified verdict (the RPC returns
							 * before the restart even starts). */
							if (r && r.op_id)
								return pollOp(r.op_id, (ok2, detail) => {
									setMsg(ok2 ? _('Restored: %s').format(name)
										: ((r.error || _('Restore failed')) + (detail ? (' — ' + detail) : '')),
										ok2 ? 'green' : 'red');
								});
							setMsg(r.result ? _('Restored: %s').format(name) : (r.error || _('Restore failed')),
								r.result ? 'green' : 'red');
						});
					});
			};
			listEl.appendChild(rowEl);
		}
	});

	const createBtn = mkBtn(_('Create snapshot'), 'primary');
	createBtn.onclick = () => {
		setMsg(_('Creating...'), 'grey');
		return L.resolveDefault(callSnapshotCreate(), {}).then((r) => {
			setMsg(r.result ? _('Snapshot created: %s').format(r.snapshot) : (r.error || _('Failed')),
				r.result ? 'green' : 'red');
			return refreshList();
		});
	};

	const restoreBtn = mkBtn(_('Restore internet (direct)'), 'danger', { style: 'margin-left:4px' });
	restoreBtn.onclick = () => {
		hp.confirmModal(_('Restore internet'),
			_('Stop the proxy stack and restore DIRECT internet? DNS interception is removed; the proxy comes back with "Service start" or a router reboot.'), _('Stop proxy'))
			.then((ok) => {
				if (!ok)
					return;
				setMsg(_('Stopping...'), 'grey');
				return L.resolveDefault(callRestoreInternet(), {}).then((r) => {
					setMsg(r.result ? _('Direct internet restored — run "Service start" to bring the proxy back.')
						: (r.error || _('Failed')), r.result ? 'amber' : 'red');
				});
			});
	};

	refreshList();
	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, _('Snapshots & recovery')),
			createBtn,
			restoreBtn
		]),
		resultEl,
		E('div', { style: 'margin-top:4px; font-size:.9em; opacity:.85' },
			_('Point-in-time copies of the app configuration and routing lists. Restore returns both and restarts the service; "Restore internet" is the emergency switch that stops the proxy and DNS interception for a plain direct connection.')),
		listEl
	]);
}

/* Local rule-set fallback (issue #12): cold starts with an empty cache.db
 * download every remote .srs SYNCHRONOUSLY and die FATAL on the first
 * failure. The generator wires <dir>/<tag>.srs as initial_path when the
 * folder exists; this card shows what is present and pre-downloads the
 * missing copies (direct first, then through the main exit). */
function buildRulesetsCard() {
	const listEl = E('div', { style: 'font-size:.9em; margin:4px 0' },
		[ E('em', { 'class': 'hpui-c-grey' }, '—') ]);
	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);
	let pollTimer = null;

	const fmtSize = (n) => (n != null && n >= 1024) ? (n / 1024).toFixed(0) + ' KB' : (n != null ? n + ' B' : '');
	/* Ф5.2: возраст локальной копии — «N мин / N ч / N дн назад». */
	const fmtAge = (sec) => {
		if (sec == null) return '';
		if (sec < 3600) return _('%d min ago').format(Math.max(1, Math.floor(sec / 60)));
		if (sec < 86400) return _('%d h ago').format(Math.floor(sec / 3600));
		return _('%d d ago').format(Math.floor(sec / 86400));
	};

	const render = (r) => {
		listEl.innerHTML = '';
		if (!r || r.error) {
			listEl.appendChild(E('em', { 'class': 'hpui-c-red' }, [ r ? (r.error || _('RPC error')) : _('RPC error') ]));
			return;
		}
		const seed = r.seed || {};
		const head = E('div', { style: 'margin:2px 0' },
			[ _('Folder') + ': ', E('span', { style: 'font-family:monospace' },
				[ r.dir + (r.dir_exists ? '' : ' (' + _('not created yet') + ')') ]),
			' · ' + _('fallback') + ': ' + (r.enabled ? _('on') : _('off')) ]);
		listEl.appendChild(head);
		const sets = r.rulesets || [];
		if (!sets.length) {
			listEl.appendChild(E('em', { 'class': 'hpui-c-grey' }, [ _('The active config has no remote rule-sets') ]));
			return;
		}
		for (let i in sets) {
			const s = sets[i];
			const meta = [];
			if (s.exists) {
				meta.push(fmtSize(s.size));
				if (s.age != null)
					meta.push(fmtAge(s.age));
				meta.push(s.tag + '.srs');
			}
			const line = E('div', { style: 'margin:2px 0' }, [
				E('span', { 'class': s.exists ? 'hpui-c-green' : 'hpui-c-amber', 'style': 'font-weight:bold' },
					[ s.exists ? '✓' : '○' ]),
				' ',
				E('span', { style: 'font-family:monospace' }, [ s.tag ]),
				' ',
				E('span', { style: 'opacity:.7' },
					[ s.exists ? meta.join(' · ') : _('local copy missing') ])
			]);
			line.setAttribute('title', s.url);
			listEl.appendChild(line);
		}
		if (seed && seed.running)
			listEl.appendChild(E('em', { 'class': 'hpui-c-amber' },
				[ _('Downloading: %d of %d…').format(seed.done || 0, seed.total || sets.length) ]));

		/* Ф5.2: версии апстрима (GitHub releases; обновляются в фоне). */
		const fresh = r.fresh;
		if (fresh) {
			const rel = [];
			const repos = fresh.repos || {};
			for (const repo in repos) {
				const fr = repos[repo];
				if (fr && fr.tag) {
					const d = fr.published_at ? fr.published_at.slice(0, 10) : '';
					rel.push(_('%s — release %s%s').format(repo, fr.tag, d ? ' (' + d + ')' : ''));
				} else {
					rel.push(_('%s — %s').format(repo, (fr && fr.error) ? _('GitHub unreachable at the last check') : _('no release info')));
				}
			}
			if (rel.length) {
				const ageTxt = fresh.ts ? fmtAge(fresh.age) : '';
				listEl.appendChild(E('div', { style: 'margin:6px 0 2px; font-size:.9em' }, [
					E('span', { style: 'font-weight:bold' }, _('Upstream releases') + ': '),
					E('span', { style: 'opacity:.85' }, rel.join(' · ')),
					' ', E('span', { style: 'opacity:.55' },
						[ ageTxt ? '(' + _('checked %s').format(ageTxt) + ')' : '' ])
				]));
			}
		}

		/* Ф5.2: манифест базы RU-geo — честно, с нескачанными категориями. */
		const geo = r.ru_geo;
		if (geo && geo.installed) {
			const catTxt = geo.categories_failed
				? _('%d (not downloaded: %d)').format(geo.categories, geo.categories_failed)
				: _('%d, 0 errors').format(geo.categories);
			const when = geo.updated ? new Date(geo.updated * 1000).toLocaleString() : '—';
			listEl.appendChild(E('div', { style: 'margin:2px 0; font-size:.9em' }, [
				E('span', { style: 'font-weight:bold' }, _('RU-geo base') + ': '),
				E('span', { style: 'opacity:.85' },
					_('categories %s · networks %s · domains %s · updated %s').format(
						catTxt, geo.geoip, geo.geosite, when))
			]));
		}
		/* Глобальный маркер: когда ядро последний раз трогало свой кэш rule-set'ов
		 * (по тегам свежесть знать нельзя — cache.db непрозрачен, урок 203). */
		if (r.cache_db_age != null)
			listEl.appendChild(E('div', { style: 'margin:2px 0; font-size:.85em; opacity:.55' },
				[ _('The core refreshed its rule-set cache %s (per-tag detail is not exposed by the core).').format(fmtAge(r.cache_db_age)) ]));
	};

	const refresh = () => L.resolveDefault(callRulesetsLocalStatus(), {}).then((r) => { render(r); return r; });

	const seedBtn = mkBtn(_('Download missing'), 'primary');
	seedBtn.onclick = () => {
		seedBtn.disabled = true;
		setMsg(_('Starting the download…'), 'grey');
		return L.resolveDefault(callRulesetsLocalSeed('0'), {}).then((r) => {
			seedBtn.disabled = false;
			if (!r || r.result === false) {
				setMsg((r && r.error) || _('Failed'), 'red');
				return;
			}
			setMsg(_('Downloading in the background…'), 'grey');
			if (pollTimer) window.clearInterval(pollTimer);
			pollTimer = window.setInterval(() => {
				refresh().then((r) => {
					const seed = r && r.seed;
					if (!seed || !seed.running) {
						window.clearInterval(pollTimer);
						pollTimer = null;
						const failed = (seed && seed.failed) || 0;
						setMsg(failed
							? _('Finished with %d failure(s) — press again to retry.').format(failed)
							: _('All local copies are in place'), failed ? 'amber' : 'green');
					}
				});
			}, 2000);
		});
	};

	const refreshBtn = mkBtn(_('Refresh'), 'ghost', { style: 'margin-left:4px' });
	refreshBtn.onclick = () => { setMsg('', null); return refresh(); };

	refresh();
	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, [
			E('strong', {}, _('Rule-sets (local cold-start copies)')),
			seedBtn,
			refreshBtn
		]),
		resultEl,
		E('div', { style: 'margin-top:4px; font-size:.9em; opacity:.85' },
			_('Local .srs copies of the remote rule lists. The core takes them for the FIRST load when the cache is empty (fresh firmware, wiped cache, no network) instead of dying on a blocked download, then refreshes from the network as usual. Enable the fallback and pick the folder on the Client Settings page; the toggle works for the sing-box family of cores.')),
		listEl
	]);
}

function buildCoreCard(core, coreInfo) {
	const isHiddify = core === 'hiddify';
	const isLite = core === 'singbox-lite';
	const name = isHiddify ? 'hiddify-core' : (isLite ? 'sing-box-extended-lite' : 'sing-box-extended');
	const pkgMgr = coreInfo.pkg_manager;
	/* full and lite SHARE /usr/bin/sing-box: coreInfo.singbox describes the
	 * on-disk binary — each card derives its own "installed" from it. */
	const coreData = (isHiddify ? coreInfo.hiddify : coreInfo.singbox) || {};
	const canInstall = !!pkgMgr;

	const desc = isHiddify
		? _('Fork of sing-box 1.13 by the Hiddify team (HiddifyCli). Runs every protocol this app can configure, including NaïveProxy and Hiddify\'s Mieru dialect. Best compatibility with Hiddify App / Hiddify Manager exports.')
		: isLite
		? _('Lightweight sing-box 1.14 build by MANCrimSon: VLESS Reality, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard/AmneziaWG (kernel stack) and the Clash API — ~46 MB pure ELF / ~10 MB UPX. No NaïveProxy, MASQUE/WARP, Tailscale or gVisor: such nodes are skipped automatically when this core runs. The installer restarts the service.')
		: _('Extended sing-box 1.14 base by shtorm-7. Runs every protocol this app can configure plus WARP / MASQUE / TrustTunnel / MTProxy extras — but no NaïveProxy: such nodes are skipped automatically when this core runs.');

	/* Verified capability line from the core's own build tags. */
	const caps = [];
	if (coreData.naive) caps.push(_('NaïveProxy') + ' ✓');
	if (coreData.extended && !isLite) caps.push('WARP / MASQUE / TrustTunnel ✓');
	const capLine = caps.length
		? E('div', { 'class': 'hpui-c-green', 'style': 'margin-top:2px; font-size:0.9em' }, caps.join(' · '))
		: E('span');

	let installed = coreData.installed && (isHiddify || (isLite ? !!coreData.lite : !coreData.lite));
	let version   = coreData.version   || null;

	const statusEl = E('strong', {
		style: 'color:' + (installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)')
	}, installed ? 'v' + version + (coreData.lite && coreData.variant === 'compressed' ? ' [lite·upx]' : (coreData.lite ? ' [lite]' : '')) : _('Not installed'));

	const resultEl = mkResult();
	const setMsg = (txt, kind) => resultEl.setResult(txt, kind);

	const checkBtn = mkBtn(_('Check update'), 'ghost', {
		click: async function() {
			checkBtn.disabled = true;
			setMsg(_('Checking...'), 'grey');
			const ret = await L.resolveDefault(callCoreCheckRemote(core), {});
			checkBtn.disabled = false;
			if (ret.error)
				setMsg(ret.error, 'red');
			else
				setMsg(_('Latest') + ': v' + ret.version,
					installed && version === ret.version ? 'green' : 'amber');
		}
	});

	/* Build choice (ch.125): the backend's auto-pick stays the DEFAULT, but
	 * the user can now explicitly choose the build — flash vs RAM trade-off.
	 * hiddify-core: standard/upx; sing-box-extended-lite: normal (pure ELF
	 * ~46 MB flash) / compressed (UPX ~10 MB flash, decompresses into RAM at
	 * every launch). The full sing-box-extended ships one build — no select. */
	const variants = isHiddify
		? [ ['', _('Auto (recommended)')], ['standard', _('Full build')], ['upx', _('Compact build (UPX)')] ]
		: isLite
		? [ ['', _('Auto (recommended)')], ['normal', _('Normal build (~46 MB)')], ['compressed', _('Compact build (UPX, ~10 MB)')] ]
		: null;
	const variantSel = variants ? E('select', {
		'class': 'cbi-input-select',
		'style': 'margin-left:4px',
		'title': _('Which core build to install — Auto picks the one that fits this device')
	}, variants.map(function(v) {
		return E('option', { 'value': v[0] }, [ v[1] ]);
	})) : null;

	/* Install button with a build choice: the select picks the build
	 * (Auto default = the backend auto-picks the one that fits this device's
	 * flash and RAM). The heavy work runs in a detached background runner
	 * (prepare → download → install → kmods); this card only starts it and
	 * polls the stage status, so the tab stays responsive and a page reload
	 * resumes watching the running install. */
	let installWatch = null;
	function watchInstall() {
		if (installWatch)
			return;
		const tick = async () => {
			const st = await L.resolveDefault(callCoreInstallStatus(), {});
			if (!st || (st.idle && !st.running)) {
				installWatch = null;
				return;
			}
			if (st.running) {
				if (st.core !== core) {
					setMsg(_('Another core is being installed — waiting for it to finish…'), 'grey');
				} else {
					const stageTxt = {
						prepare: _('Checking requirements...'),
						download: _('Downloading...'),
						install: _('Installing package...'),
						kmods: _('Installing kernel modules...')
					}[st.stage] || st.stage;
					setMsg(st.note ? stageTxt + ' — ' + st.note : stageTxt, st.note ? 'amber' : 'grey');
				}
				installWatch = window.setTimeout(tick, 2000);
				return;
			}
			installWatch = null;
			const fresh = await L.resolveDefault(callCoreInfo(), {});
			const fd = (isHiddify ? fresh.hiddify : fresh.singbox) || {};
			installed = fd.installed && (isHiddify || (isLite ? !!fd.lite : !fd.lite));
			version   = fd.version   || null;
			coreData.lite = fd.lite;
			coreData.variant = fd.variant;
			statusEl.textContent = installed ? 'v' + version + (fd.lite && fd.variant === 'compressed' ? ' [lite·upx]' : (fd.lite ? ' [lite]' : '')) : (st.ok ? _('Not installed') : _('Unknown'));
			statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
			installBtn.textContent = installed ? _('Update') : _('Install');
			installBtn.disabled = !canInstall || null;
			if (variantSel) variantSel.disabled = false;
			removeBtn.disabled  = !installed;
			if (st.ok) {
				let msg = st.note ? _('Installed successfully') + ' — ' + st.note : _('Installed successfully');
				if (st.warning)
					msg += ' — ' + st.warning;
				setMsg(msg, st.warning ? 'amber' : 'green');
			} else {
				setMsg(st.error || _('Installation failed'), 'red');
			}
		};
		installWatch = window.setTimeout(tick, 300);
	}

	const doInstall = async () => {
		installBtn.disabled = true;
		removeBtn.disabled  = true;
		if (variantSel) variantSel.disabled = true;
		statusEl.textContent = _('Installing...');
		statusEl.style.color = 'var(--hp-grey)';
		setMsg(_('Starting the install...'), 'grey');

		const start = await L.resolveDefault(callCoreInstallStart(core, variantSel ? variantSel.value : ''), {});
		if (!start || start.result === false) {
			installBtn.disabled = !canInstall || null;
			removeBtn.disabled  = !installed;
			if (variantSel) variantSel.disabled = false;
			statusEl.textContent = installed ? 'v' + (version || '?') + (coreData.lite && coreData.variant === 'compressed' ? ' [lite·upx]' : (coreData.lite ? ' [lite]' : '')) : _('Not installed');
			statusEl.style.color = installed ? 'var(--hp-accent-strong)' : 'var(--hp-grey)';
			setMsg((start && start.error) ? start.error : _('Failed to start the install'), 'red');
			return;
		}
		/* Resume-safe: the status file outlives the tab (a page reload in the
		 * middle of an install re-attaches the watcher instead of restarting
		 * the whole flow). */
		watchInstall();
	};

	/* Re-attach the watcher when the page (re)loads while an install runs. */
	L.resolveDefault(callCoreInstallStatus(), {}).then(function(st) {
		if (st && st.running) {
			installBtn.disabled = true;
			removeBtn.disabled  = true;
			if (variantSel) variantSel.disabled = true;
			statusEl.textContent = _('Installing...');
			statusEl.style.color = 'var(--hp-grey)';
			watchInstall();
		}
	});

	const installBtn = mkBtn(installed ? _('Update') : _('Install'), 'primary', {
		style: 'margin-left:4px',
		disabled: !canInstall || null,
		title: canInstall ? '' : _('No supported package manager detected'),
		click: function() { return doInstall(); }
	});

	const removeBtn = mkBtn(_('Remove'), 'danger', {
		style: 'margin-left:4px',
		disabled: !installed || null,
		click: async function() {
			removeBtn.disabled  = true;
			installBtn.disabled = true;
			setMsg(_('Removing...'), 'grey');

			const ret = await L.resolveDefault(callCoreRemove(core), {});

			installBtn.disabled = false;
			if (ret.result) {
				installed = false;
				version   = null;
				statusEl.textContent = _('Not installed');
				statusEl.style.color = 'var(--hp-grey)';
				installBtn.textContent = _('Install');
				/* Removing the lite build can leave the service stopped when no
				 * other core exists — the backend says so in `warning`. */
				setMsg(ret.warning || _('Removed successfully'), ret.warning ? 'amber' : 'green');
			} else {
				removeBtn.disabled = false;
				setMsg(ret.error || _('Removal failed'), 'red');
			}
		}
	});

	const row = [ E('strong', {}, name), statusEl, checkBtn ];
	if (variantSel)
		row.push(variantSel);
	row.push(installBtn, removeBtn);

	return E('div', { 'class': 'hpui-panel' }, [
		E('div', { style: 'display:flex; align-items:center; flex-wrap:wrap; gap:6px' }, row),
		resultEl,
		E('div', { 'style': 'margin-top:4px; font-size:0.9em; opacity:.85' }, desc),
		capLine
	]);
}

return view.extend({
	load() {
		return Promise.all([
			hp.getBuiltinFeatures(),
			L.resolveDefault(callCoreInfo(), {}),
			uci.load('homeproxy'),
			L.resolveDefault(callByeDPIStatus(), {}),
			L.resolveDefault(callCurlStatus(), {}),
			L.resolveDefault(callZapretStatus(), {}),
			L.resolveDefault(callAppStatus(), {}),
			L.resolveDefault(callMultidnsStatus(), {}),
			L.resolveDefault(callMosdnsStatus(), {}),
			L.resolveDefault(callCoreSkipped(), {})
		]);
	},

	render([features, coreInfo, _uci, byedpiStatus, curlStatus, zapretStatus, appStatus, mdnsStatus, mosdnsStatus, coreSkipped]) {
		let m, s, o;

		/* App shell (R3 v2): sidebar + topbar + dual theme (implies uiStyle). */
		hp.uiShell();

		m = new form.Map('homeproxy');

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('Resources management'));
		s.anonymous = true;
		s.description = _('What runs on the router right now: the active core and its version. The rest of the page installs and updates the moving parts.');

		o = s.option(form.DummyValue, '_active_core', _('Active core'));
		const coreName = features.core_type === 'hiddify' ? 'hiddify-core' :
		                 features.core_type === 'singbox' ? 'sing-box' : null;
		const coreVer = features.version ? ' v' + features.version : '';
		const coreCustomSuffix = features.core_custom ? ' (custom)' : '';
		/* The active sing-box may be the LITE build (same binary path): mark it
		 * from the capability probe, not from the version string. */
		const coreLiteSuffix = (features.core_type === 'singbox' && coreInfo?.singbox?.lite)
			? (coreInfo.singbox.variant === 'compressed' ? ' [lite·upx]' : ' [lite]') : '';

		/* v3 status bar (server.js convention): dot + core name + RUNNING badge,
		 * polled and rebuilt in place. */
		const coreStateEl = E('div', { 'style': 'display:flex; align-items:center; gap:8px; flex-wrap:wrap' });
		function renderCoreState(isRunning) {
			if (!features.core_type) {
				coreStateEl.replaceChildren(E('strong', { 'class': 'hpui-c-red' }, _('No core installed')));
				return;
			}
			coreStateEl.replaceChildren(
				E('span', { 'class': 'hpui-dot ' + (isRunning ? 'ok' : 'bad') }),
				E('strong', {}, coreName + coreVer + coreCustomSuffix + coreLiteSuffix),
				E('span', { 'class': 'hpui-badge ' + (isRunning ? 'hpui-b-green' : 'hpui-b-red') },
					[ isRunning ? _('RUNNING') : _('NOT RUNNING') ])
			);
		}
		renderCoreState(null);
		const refreshCoreState = () => getServiceStatus().then(renderCoreState);
		refreshCoreState();
		poll.add(refreshCoreState, hp.pollSec(5));

		if (!features.core_type) {
			const callDetectCustomCore = rpc.declare({
				object: 'luci.homeproxy',
				method: 'detect_custom_core',
				params: ['path'],
				expect: { '': {} }
			});

			const savedPath = uci.get('homeproxy', 'config', 'custom_core_path') || '';
			const pathInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': savedPath,
				'placeholder': '/path/to/hiddify-core',
				'style': 'width:260px; margin-right:4px'
			});
			const detectMsg = E('span', { 'class': 'hpui-c-grey',
				'style': 'margin-left:8px; font-size:0.9em' }, '');
			const detectBtn = mkBtn(_('Detect'), 'primary', {
				'click': async function() {
					const path = pathInput.value.trim();
					if (!path) return;
					detectBtn.disabled = true;
					detectMsg.textContent = _('Detecting...');
					detectMsg.className = 'hpui-c-grey';
					const ret = await L.resolveDefault(callDetectCustomCore(path), {});
					detectBtn.disabled = false;
					if (ret.result) {
						const typeName = ret.type === 'hiddify' ? 'hiddify-core' : 'sing-box';
						detectMsg.textContent = _('Detected') + ': ' + typeName + (ret.version ? ' v' + ret.version : '') + ' — ' + _('reload page to apply');
						detectMsg.className = 'hpui-c-green';
					} else {
						detectMsg.textContent = ret.error || _('Detection failed');
						detectMsg.className = 'hpui-c-red';
					}
				}
			});

			o.default = E('div', {}, [
				coreStateEl,
				E('details', { 'style': 'margin-top:6px' }, [
					E('summary', { 'style': 'cursor:pointer; opacity:.75; font-size:0.9em' }, _('I have a custom core path')),
					E('div', { 'style': 'margin-top:6px' }, [ pathInput, detectBtn, detectMsg ])
				])
			]);
		} else {
			o.default = coreStateEl;
		}
		o.description = _('Nodes the active core cannot load are skipped automatically (they would crash the core). Switch Preferred core in Client Settings to run them.');

		/* Nodes the running core cannot load — written by generate_client.uc. */
		if (coreSkipped?.skipped?.length) {
			const NAME = { naive: 'NaïveProxy', hysteria: 'Hysteria', hysteria2: 'Hysteria2',
			               tuic: 'TUIC', wireguard: 'WireGuard', amneziawg: 'AmneziaWG' };
			const parts = coreSkipped.skipped.map((n) =>
				'%s (%s)'.format(n.label || n.sid, NAME[n.type] || n.type));
			o.description += '<br><em><span style="color:var(--hp-amber)">%s</span></em>'.format(
				_('Skipped by this core: %s.').format(parts.join(', ')));
		}

		/* Region rule-sets (geosite/geoip .srs) are versioned and refreshed by the core itself,
		 * so there are no local list-version files to display here. */


		/* The token is needed in EVERY routing mode: the GitHub API rate limit
		 * applies regardless of mode (ByeDPI/Zapret/app update checks run in RU
		 * mode too), so it must not be hidden behind a non-RU gate. */
		o = s.option(form.Value, 'github_token', _('GitHub token'));
			o.description = _('Used to check for ByeDPI and Zapret updates. Without a token, GitHub limits anonymous requests to 60/hour. Create at github.com → Settings → Developer settings → Personal access tokens (no scopes needed).');
			o.password = true;
			o.renderWidget = function() {
				let node = form.Value.prototype.renderWidget.apply(this, arguments);

				(node.querySelector('.control-group') || node).appendChild(mkBtn(_('Save'), 'primary', {
					'title': _('Save'),
					'click': ui.createHandlerFn(this, () => {
						return this.map.save(null, true).then(() => {
							ui.changes.apply(true);
						});
					}, this.option)
				}));

				return node;
			}

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('Application'));
		s.anonymous = true;
		s.description = _('The app itself: check for updates, install or reinstall the package.');

		o = s.option(form.DummyValue, '_app_card');
		o.default = buildAppCard(appStatus);

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('Core management'));
		s.anonymous = true;
		s.description = _('The cores that run the proxy (only one is active at a time), rule-set seeds for a cold boot, configuration snapshots and the emergency internet recovery.');

		o = s.option(form.DummyValue, '_core_env');
		const tmpMB     = coreInfo.tmp_free_kb     != null ? Math.round(coreInfo.tmp_free_kb     / 1024) : '?';
		const overlayMB = coreInfo.overlay_free_kb != null ? Math.round(coreInfo.overlay_free_kb / 1024) : '?';
		o.default = E('div', { style: 'font-size:0.9em; opacity:.85; padding:2px 0 6px' }, [
			_('Package manager') + ': ',
			E('strong', {}, coreInfo.pkg_manager || _('none detected')),
			E('span', { style: 'margin:0 8px' }, '|'),
			_('Architecture') + ': ',
			E('strong', {}, coreInfo.arch || '?'),
			E('span', { style: 'margin:0 8px' }, '|'),
			_('Free /tmp') + ': ',
			E('strong', {
				'class': (coreInfo.tmp_free_kb != null && coreInfo.tmp_free_kb < 30720) ? 'hpui-c-red' : 'hpui-c-green'
			}, tmpMB + ' MB'),
			E('span', { style: 'margin:0 8px' }, '|'),
			_('Free overlay') + ': ',
			E('strong', {
				'class': (coreInfo.overlay_free_kb != null && coreInfo.overlay_free_kb < 30720) ? 'hpui-c-red' : 'hpui-c-green'
			}, overlayMB + ' MB')
		]);

		o = s.option(form.DummyValue, '_core_hiddify');
		o.default = buildCoreCard('hiddify', coreInfo);

		o = s.option(form.DummyValue, '_core_singbox');
		o.default = buildCoreCard('singbox', coreInfo);

		/* sing-box-extended-lite (MANCrimSon) — GitHub issue #4. Shares
		 * /usr/bin/sing-box with the full build; the card derives its own
		 * installed state from coreInfo.singbox.lite. */
		o = s.option(form.DummyValue, '_core_singbox_lite');
		o.default = buildCoreCard('singbox-lite', coreInfo);

		/* Local rule-set fallback (issue #12): pre-seeded .srs copies for the
		 * core's synchronous first-load on a cold boot. */
		o = s.option(form.DummyValue, '_rulesets_card');
		o.default = buildRulesetsCard();

		/* ч.69: snapshots + emergency internet recovery. */
		o = s.option(form.DummyValue, '_snapshots_card');
		o.default = buildSnapshotsCard();

		/* ч.78 (Ф6/D6): the Telegram bot settings moved to the Wizard's
		 * "Advanced" tab (wizard.js) — the Master now covers it; no duplicate
		 * editor here. The status card on the Overview page stays. */

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('AntiDPI'));
		s.anonymous = true;
		s.description = _('Install, update and manage the two bypass engines — ByeDPI and Zapret. Which one actually serves the traffic is configured on the Blocking bypass page.');

		o = s.option(form.DummyValue, '_byedpi_card');
		o.default = buildByeDPICard(byedpiStatus, uci.get('homeproxy', 'config', 'main_node') === 'byedpi-out');

		o = s.option(form.DummyValue, '_curl_card', _('ByeDPI strategy tester'));
		o.default = buildCurlCard(curlStatus);

		o = s.option(form.DummyValue, '_zapret_card');
		o.default = buildZapretCard(zapretStatus, uci.get('homeproxy', 'config', 'main_node') === 'zapret-out');

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('MultiDNS / mosdns'));
		s.anonymous = true;
		s.description = _('Install, update and manage the engines behind MultiDNS — the racing DNS resolver.');

		o = s.option(form.DummyValue, '_multidns_card');
		o.default = buildMosdnsCard(mdnsStatus, mosdnsStatus);

		s = m.section(form.NamedSection, 'config', 'homeproxy');
		s.anonymous = true;

		o = s.option(form.DummyValue, '_homeproxy_logview');
		o.render = L.bind(getRuntimeLog, this, o, _('Ravnex'));

		o = s.option(form.DummyValue, '_hiddify-c_logview');
		o.render = L.bind(getRuntimeLog, this, o, _('core client'));

		return m.render().then(function(node) {
			return E('div', {}, [
				hp.pageIntro(_('Maintenance'),
					_('Installation and updates: the app itself, the cores, the bypass engines and MultiDNS — each in its own card. Also configuration snapshots, emergency internet recovery and the running logs. You need this page rarely: after an update or when something must be reinstalled.')),
				buildResProfileCard(),
				node
			]);
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
