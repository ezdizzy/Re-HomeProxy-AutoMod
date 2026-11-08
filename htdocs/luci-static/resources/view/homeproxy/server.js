/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require form';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

'require homeproxy as hp';
'require tools.widgets as widgets';

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

const CBIGenValue = form.Value.extend({
	__name__: 'CBI.GenValue',

	renderWidget(/* ... */) {
		let node = form.Value.prototype.renderWidget.apply(this, arguments);

		if (!this.password)
			node.classList.add('control-group');

		(node.querySelector('.control-group') || node).appendChild(E('button', {
			class: 'cbi-button cbi-button-add',
			title: _('Generate'),
			click: ui.createHandlerFn(this, handleGenKey, this.hp_options || this.option)
		}, [ _('Generate') ]));

		return node;
	}
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

function renderStatus(isRunning, features) {
	let coreName = features.core_type === 'singbox' ? 'sing-box' :
	               features.core_type === 'hiddify' ? 'hiddify-core' : null;
	let verStr = features.version ? 'v' + features.version : _('unknown');
	let coreStr = coreName ? ('%s %s').format(coreName, verStr) : _('no core installed');
	return E('div', { 'style': 'display:flex; align-items:center; gap:8px; flex-wrap:wrap' }, [
		E('span', { 'class': 'hpui-dot ' + (isRunning ? 'ok' : 'bad') }),
		E('strong', {}, [ _('Ravnex Server') + ' — ' + coreStr ]),
		E('span', { 'class': 'hpui-badge ' + (isRunning ? 'hpui-b-green' : 'hpui-b-red') },
			[ isRunning ? _('RUNNING') : _('NOT RUNNING') ])
	]);
}

function handleGenKey(option) {
	let section_id = this.section.section;
	let type = this.section.getOption('type')?.formvalue(section_id);
	let widget = L.bind((option) => {
		return this.map.findElement('id', 'widget.' + this.cbid(section_id).replace(/\.[^\.]+$/, '.') + option);
	}, this);

	const callSingBoxGenerator = rpc.declare({
		object: 'luci.ravnex',
		method: 'singbox_generator',
		params: ['type', 'params'],
		expect: { '': {} }
	});

	if (typeof option === 'object') {
		return callSingBoxGenerator(option.type, option.params).then((res) => {
			if (res.result)
				option.callback.call(this, res.result).forEach(([k, v]) => {
					widget(k).value = v ?? '';
				});
			else
				ui.addNotification(null, E('p', _('Failed to generate %s, error: %s.').format(type, res.error)));
		});
	} else {
		let password, required_method;

		if (option === 'uuid')
			required_method = 'uuid';
		else if (type === 'shadowsocks')
			required_method = this.section.getOption('shadowsocks_encrypt_method')?.formvalue(section_id);

		switch (required_method) {
			case 'none':
				password = '';
				break;
			case 'uuid':
				password = hp.generateRand('uuid');
				break;
			default:
				password = hp.generateRand('hex', 16);
				break;
		}
		/* AEAD */
		((length) => {
			if (length && length > 0)
				password = hp.generateRand('base64', length);
		})(hp.shadowsocks_encrypt_length[required_method]);

		return widget(option).value = password;
	}
}

/* ── Ф9.6 stage 2 (v3): page-scoped styles ─────────────────────────── */

const CSS = `
.srv-status { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 4px 0 12px; }
.srv-pick { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; }
.srv-card { cursor: pointer; user-select: none; gap: 6px; }
.srv-card:hover { border-color: var(--hp-accent-line); }
.srv-card-t { display: flex; align-items: center; gap: 8px; font-weight: 700; }
.srv-wform { display: grid; grid-template-columns: 170px 1fr; gap: 10px 14px; align-items: center; max-width: 640px; }
.srv-wform > label { opacity: .75; font-size: .92em; }
.srv-cred { display: flex; gap: 8px; align-items: center; }
.srv-cred input { flex: 1; min-width: 0; }
.srv-fwbox { display: flex; flex-direction: column; gap: 4px; }
.srv-fwrow { display: flex; gap: 8px; align-items: center; }
.srv-note { min-height: 1.2em; margin: 10px 0 0; color: var(--hp-ink-red); }
.srv-mfoot { display: flex; gap: 10px; justify-content: flex-end; margin-top: 14px; }
`;

/* ── Wizard: unique listen-port suggestion ─────────────────────────── */

function suggestPort() {
	const used = {};
	uci.sections('homeproxy', 'server', (sec) => {
		if (sec.port)
			used['' + sec.port] = true;
	});
	for (let p = 20001; p <= 20999; p++)
		if (!used[p])
			return p;
	return '20999';
}

/* ── Wizard modal: preset → prefilled section → full review modal ──── */

function openWizard(preset, grid) {
	const callGen = rpc.declare({
		object: 'luci.ravnex',
		method: 'singbox_generator',
		params: ['type', 'params'],
		expect: { '': {} }
	});

	const titles = {
		home: _('Inside your home'),
		net: _('From the internet'),
		anytls: _('From the internet — AnyTLS'),
		ss: _('From the internet — Shadowsocks')
	};

	const wName = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('My server') });
	const wPort = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'inputmode': 'numeric' });
	const wUser = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'value': 'user' });
	const wPass = E('input', { 'type': 'text', 'class': 'cbi-input-text' });
	const wUuid = E('input', { 'type': 'text', 'class': 'cbi-input-text' });
	const wFw = E('input', { 'type': 'checkbox' });

	const note = E('p', { 'class': 'srv-note' }, []);
	const say = (msg) => { note.textContent = msg; };

	/* Shadowsocks AEAD-2022 needs a base64 key of the method's byte length;
	 * the other presets use a plain hex password / UUID. */
	const genPass = (preset === 'ss')
		? () => { wPass.value = hp.generateRand('base64', 16); }
		: () => { wPass.value = hp.generateRand('hex', 16); };
	const genUuid = () => { wUuid.value = hp.generateRand('uuid'); };
	genPass();
	genUuid();
	wPort.value = suggestPort();
	wFw.checked = (preset !== 'home');

	const regenBtn = (fn) => E('button', {
		'class': 'hpui-btn hpui-btn-ghost', 'type': 'button',
		'title': _('Generate'), 'click': fn
	}, [ _('Generate') ]);

	const rows = [
		[ _('Server name'), wName ],
		[ _('Port'), wPort ]
	];

	if (preset === 'home') {
		rows.push([ _('Username'), wUser ]);
		rows.push([ _('Password'), E('div', { 'class': 'srv-cred' }, [ wPass, regenBtn(genPass) ]) ]);
	} else if (preset === 'anytls' || preset === 'ss') {
		rows.push([ _('Password'), E('div', { 'class': 'srv-cred' }, [ wPass, regenBtn(genPass) ]) ]);
	} else {
		rows.push([ 'UUID', E('div', { 'class': 'srv-cred' }, [ wUuid, regenBtn(genUuid) ]) ]);
	}

	rows.push([ _('Firewall'), E('div', { 'class': 'srv-fwbox' }, [
		E('label', { 'class': 'srv-fwrow' }, [
			wFw,
			E('span', {}, [ _('Open the port in the firewall (reachable from the internet)') ])
		]),
		E('div', { 'class': 'hpui-hint' },
			[ _('Each open port is visible to scanners — enable only for servers you actually use.') ])
	]) ]);

	const btnCancel = E('button', { 'class': 'hpui-btn hpui-btn-ghost', 'type': 'button' }, [ _('Cancel') ]);
	const btnCreate = E('button', { 'class': 'hpui-btn hpui-btn-primary', 'type': 'button' }, [ _('Create server') ]);

	btnCancel.addEventListener('click', () => ui.hideModal());

	btnCreate.addEventListener('click', () => {
		const label = (wName.value || '').trim() || _('My server');
		const port = (wPort.value || '').trim();

		if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) {
			say(_('Expecting: %s').format('1-65535'));
			return;
		}

		let dup = false;
		uci.sections('homeproxy', 'server', (sec) => {
			if (('' + sec.port) === port)
				dup = true;
		});
		if (dup) {
			say(_('Port %s is already used by another server — pick a different one.').format(port));
			return;
		}

		btnCreate.disabled = true;
		say('…');

		const prep = (preset === 'net' || preset === 'anytls')
			? L.resolveDefault(callGen('reality-keypair', ''), {}).then((res) =>
				(res && res.result) ? res.result : null)
			: Promise.resolve(null);

		prep.then((keys) => {
			if ((preset === 'net' || preset === 'anytls') && (!keys || !keys.private_key || !keys.public_key)) {
				say(_('Key generation failed — try again.'));
				btnCreate.disabled = null;
				return;
			}

			let sid;
			do {
				sid = 'srv_' + hp.generateRand('hex', 4);
			} while (uci.get('homeproxy', sid));

			uci.add('homeproxy', 'server', sid);
			uci.set('homeproxy', sid, 'label', label);
			uci.set('homeproxy', sid, 'enabled', '1');
			uci.set('homeproxy', sid, 'port', port);
			uci.set('homeproxy', sid, 'firewall', wFw.checked ? '1' : '0');

			if (preset === 'home') {
				uci.set('homeproxy', sid, 'type', 'mixed');
				uci.set('homeproxy', sid, 'username', (wUser.value || '').trim() || 'user');
				uci.set('homeproxy', sid, 'password', wPass.value);
			} else if (preset === 'anytls') {
				uci.set('homeproxy', sid, 'type', 'anytls');
				uci.set('homeproxy', sid, 'password', wPass.value);
				uci.set('homeproxy', sid, 'tls', '1');
				uci.set('homeproxy', sid, 'tls_reality', '1');
				uci.set('homeproxy', sid, 'tls_reality_private_key', keys.private_key);
				uci.set('homeproxy', sid, 'tls_reality_public_key', keys.public_key);
				uci.set('homeproxy', sid, 'tls_reality_short_id', [ hp.generateRand('hex', 4) ]);
				uci.set('homeproxy', sid, 'tls_reality_server_addr', 'www.microsoft.com');
				uci.set('homeproxy', sid, 'tls_reality_server_port', '443');
			} else if (preset === 'ss') {
				uci.set('homeproxy', sid, 'type', 'shadowsocks');
				uci.set('homeproxy', sid, 'shadowsocks_encrypt_method', '2022-blake3-aes-128-gcm');
				uci.set('homeproxy', sid, 'password', wPass.value);
			} else {
				uci.set('homeproxy', sid, 'type', 'vless');
				uci.set('homeproxy', sid, 'uuid', wUuid.value);
				uci.set('homeproxy', sid, 'tls', '1');
				uci.set('homeproxy', sid, 'tls_reality', '1');
				uci.set('homeproxy', sid, 'tls_reality_private_key', keys.private_key);
				uci.set('homeproxy', sid, 'tls_reality_public_key', keys.public_key);
				uci.set('homeproxy', sid, 'tls_reality_short_id', [ hp.generateRand('hex', 4) ]);
				uci.set('homeproxy', sid, 'tls_reality_server_addr', 'www.microsoft.com');
				uci.set('homeproxy', sid, 'tls_reality_server_port', '443');
			}

			/* The framework-native add flow: mark the staged section, close
			 * the wizard, open the FULL review modal. Cancel discards the
			 * staged section (addedSection semantics), Save stages it for
			 * the page-wide «Save & Apply». */
			ui.hideModal();
			grid.map.addedSection = sid;
			return grid.renderMoreOptionsModal(sid);
		}).catch((e) => {
			say((e && e.message) ? e.message : _('Key generation failed — try again.'));
			btnCreate.disabled = null;
		});
	});

	const wHints = {
		home: _('A second router or a trusted device in your LAN. Works out of the box — no certificates, no domain.'),
		net: _('Your phone away from home, or a friend. VLESS + REALITY: looks like normal HTTPS traffic, no certificates and no domain needed.'),
		anytls: _('Your phone away from home, or a friend. AnyTLS + REALITY: also looks like normal HTTPS, with connection multiplexing — no certificates and no domain needed.'),
		ss: _('Your phone away from home, or a friend. Shadowsocks 2022: simple and lightweight — no certificates and no domain needed.')
	};

	ui.showModal(_('Create server: %s').format(titles[preset]), [
		E('p', { 'class': 'hpui-hint' }, [ wHints[preset] || '' ]),
		E('div', { 'class': 'srv-wform' }, rows.flatMap((r) => [ E('label', {}, [ r[0] ]), r[1] ])),
		E('div', { 'class': 'hpui-hint', 'style': 'margin-top:10px' },
			[ _('After you save, set up the client with the SAME parameters (port, keys, passwords) — everything is visible in the server settings.') ]),
		note,
		E('div', { 'class': 'srv-mfoot' }, [ btnCancel, btnCreate ])
	], 'cbi-modal');
}

return view.extend({
	load() {
		return Promise.all([
			uci.load('homeproxy'),
			hp.getBuiltinFeatures()
		]);
	},

	render(data) {
		let m, s, o;
		let features = data[1];
		let srvGrid;

		/* App shell (R3 v2): sidebar + topbar + dual theme (implies uiStyle). */
		hp.uiShell();

		if (!document.getElementById('hp-srv-style'))
			document.head.appendChild(E('style', { 'id': 'hp-srv-style' }, [ CSS ]));

		m = new form.Map('homeproxy');

		/* ── Panel 1: live status + the master switch (+ honest warnings) ── */

		s = m.section(form.NamedSection, 'server', 'homeproxy');

		s.render = function() {
			poll.add(() => {
				return L.resolveDefault(getServiceStatus()).then((res) => {
					let view = document.getElementById('service_status');
					if (view)
						view.replaceChildren(renderStatus(res, features));
				});
			}, hp.pollSec(5));

			return form.NamedSection.prototype.render.apply(this, arguments).then((node) =>
				E('div', { 'class': 'hpui-panel' }, [
					E('h4', { 'class': 'hpui-h4' }, [ hp.icon('server'), _('Status') ]),
					E('p', { 'id': 'service_status', 'class': 'srv-status' }, _('Collecting data...')),
					node,
					E('div', { 'class': 'hpui-banner' }, [
						E('p', { 'style': 'margin:0' },
							[ _('Server endpoints run in the same core as the client proxy: a broken server section stops the WHOLE service (client traffic included) until it is fixed. Change one setting at a time, apply and check the status above.') ])
					]),
					E('p', { 'class': 'hpui-hint' },
						[ _('Applying server settings restarts the whole service — the proxy is offline for a few seconds.') ])
				]));
		};

		o = s.option(form.Flag, 'enabled', _('Enable'),
			_('The main switch: whether Ravnex accepts incoming connections at all. Each server below is one endpoint other devices connect to — your own phone away from home, a friend, or a second router.'));
		o.rmempty = false;
		o.onchange = function(ev, section_id, value) {
			return Promise.resolve(this.map.save(null, true)).catch(function() {});
		};

		/* ── Panel 2: quick server wizard ───────────────────────────────── */

		s = m.section(form.TypedSection);

		s.render = function() {
			return E('div', { 'class': 'hpui-panel' }, [
				E('h4', { 'class': 'hpui-h4' }, [ hp.icon('zap'), _('Quick server') ]),
				E('p', { 'class': 'hpui-hint' },
					[ _('Not sure where to start? Pick what the server is for — the wizard fills in everything else and opens the full settings for review. Fine-tuning is still available via «Add» in the list below.') ]),
				E('div', { 'class': 'hpui-cards srv-pick' }, [
					E('div', { 'class': 'hpui-card srv-card', 'click': () => openWizard('home', srvGrid) }, [
						E('div', { 'class': 'srv-card-t' }, [ hp.icon('router'), _('Inside your home') ]),
						E('div', { 'class': 'hpui-hint' },
							[ _('A second router or a trusted device in your LAN. Works out of the box — no certificates, no domain.') ])
					]),
					E('div', { 'class': 'hpui-card srv-card', 'click': () => openWizard('net', srvGrid) }, [
						E('div', { 'class': 'srv-card-t' }, [ hp.icon('globe'), _('From the internet') ]),
						E('div', { 'class': 'hpui-hint' },
							[ _('Your phone away from home, or a friend. VLESS + REALITY: looks like normal HTTPS traffic, no certificates and no domain needed.') ])
					]),
					E('div', { 'class': 'hpui-card srv-card', 'click': () => openWizard('anytls', srvGrid) }, [
						E('div', { 'class': 'srv-card-t' }, [ hp.icon('shield'), _('From the internet — AnyTLS') ]),
						E('div', { 'class': 'hpui-hint' },
							[ _('AnyTLS + REALITY: also looks like normal HTTPS, with connection multiplexing — no certificates and no domain needed.') ])
					]),
					E('div', { 'class': 'hpui-card srv-card', 'click': () => openWizard('ss', srvGrid) }, [
						E('div', { 'class': 'srv-card-t' }, [ hp.icon('zap'), _('From the internet — Shadowsocks') ]),
						E('div', { 'class': 'hpui-hint' },
							[ _('Shadowsocks 2022: simple and lightweight — no certificates and no domain needed.') ])
					])
				]),
				E('p', { 'class': 'hpui-hint' },
					[ _('Protocols with mandatory TLS (Hysteria2, TUIC, Trojan with TLS) need certificates — set them up via «Add» in the list below. The wizard covers the certificate-free protocols; the generator creates REALITY keys automatically.') ])
			]);
		};

		/* ── Panel 3: the server list ───────────────────────────────────── */

		srvGrid = m.section(form.GridSection, 'server');
		srvGrid.addremove = true;
		srvGrid.rowcolors = true;
		srvGrid.sortable = true;
		srvGrid.nodescriptions = true;
		srvGrid.modaltitle = L.bind(hp.loadModalTitle, this, _('Server'), _('Add a server'), data[0]);
		srvGrid.sectiontitle = L.bind(hp.loadDefaultLabel, this, data[0]);
		srvGrid.renderSectionAdd = L.bind(hp.renderSectionAdd, this, srvGrid);

		srvGrid.render = function() {
			return form.GridSection.prototype.render.apply(this, arguments).then((node) =>
				E('div', { 'class': 'hpui-panel' }, [
					E('h4', { 'class': 'hpui-h4' }, [ hp.icon('layers'), _('My servers') ]),
					E('p', { 'class': 'hpui-hint' },
						[ _('Each row is one server endpoint. The Firewall flag opens the port in the router firewall — only needed for access from the internet. The port must be unique.') ]),
					node
				]));
		};

		o = srvGrid.option(form.Value, 'label', _('Label'));
		o.load = L.bind(hp.loadDefaultLabel, this, data[0]);
		o.validate = L.bind(hp.validateUniqueValue, this, data[0], 'server', 'label');
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.enabled;
		o.rmempty = false;
		o.editable = true;

		o = srvGrid.option(form.Flag, 'firewall', _('Firewall'),
			_('Open the port in the firewall so this server is reachable from the internet. Enable only for servers you actually use — each open port is visible to scanners.'));
		o.editable = true;

		o = srvGrid.option(form.ListValue, 'type', _('Type'));
		o.value('anytls', _('AnyTLS'));
		o.value('http', _('HTTP'));
		if (features.with_quic) {
			o.value('hysteria', _('Hysteria'));
			o.value('hysteria2', _('Hysteria2'));
			o.value('naive', _('NaïveProxy'));
		}
		o.value('mixed', _('Mixed'));
		if (features.core_type === 'singbox')
			o.value('mtproxy', _('MTProxy'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('socks', _('Socks'));
		o.value('trojan', _('Trojan'));
		if (features.with_quic)
			o.value('tuic', _('Tuic'));
		o.value('vless', _('VLESS'));
		o.value('vmess', _('VMess'));
		o.rmempty = false;

		o = srvGrid.option(form.Value, 'address', _('Listen address'));
		o.placeholder = '::';
		o.datatype = 'ipaddr';
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'port', _('Listen port'),
			_('The port must be unique.'));
		o.datatype = 'port';
		o.validate = L.bind(hp.validateUniqueValue, this, data[0], 'server', 'port');

		o = srvGrid.option(form.Value, 'username', _('Username'));
		o.depends('type', 'http');
		o.depends('type', 'mixed');
		o.depends('type', 'naive');
		o.depends('type', 'socks');
		o.modalonly = true;

		o = srvGrid.option(CBIGenValue, 'password', _('Password'));
		o.password = true;
		o.depends('type', 'anytls');
		o.depends({'type': /^(http|mixed|naive|socks)$/, 'username': /[\s\S]/});
		o.depends('type', 'hysteria2');
		o.depends('type', 'shadowsocks');
		o.depends('type', 'trojan');
		o.depends('type', 'tuic');
		o.validate = function(section_id, value) {
			if (section_id) {
				let type = this.section.formvalue(section_id, 'type');
				let required_type = [ 'anytls', 'http', 'mixed', 'naive', 'socks', 'shadowsocks', 'trojan' ];

				if (required_type.includes(type)) {
					if (type === 'shadowsocks') {
						let encmode = this.section.formvalue(section_id, 'shadowsocks_encrypt_method');
						if (encmode === 'none')
							return true;
						else if (encmode === '2022-blake3-aes-128-gcm')
							return hp.validateBase64Key(24, section_id, value);
						else if (['2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].includes(encmode))
							return hp.validateBase64Key(44, section_id, value);
					}

					if (!value)
						return _('Expecting: %s').format(_('non-empty value'));
				}
			}

			return true;
		}
		o.modalonly = true;

		/* AnyTLS config */
		o = srvGrid.option(form.DynamicList, 'anytls_padding_scheme', _('Padding scheme'),
			_('AnyTLS padding scheme in array.'));
		o.depends('type', 'anytls');
		o.modalonly = true;

		/* MTProxy config start */
		o = srvGrid.option(form.DynamicList, 'mtproxy_secrets', _('Secrets'),
			_('List of MTProxy secrets. Each secret is a 32-character hex string (16 bytes). One secret per user.'));
		o.depends('type', 'mtproxy');
		o.validate = function(section_id, value) {
			if (section_id && value && !/^[0-9a-fA-F]{32}$/.test(value))
				return _('Expecting: %s').format(_('32 hex characters'));
			return true;
		};
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'domain_fronting_host', _('Domain fronting host'),
			_('Target hostname for FakeTLS domain fronting. Clients will see TLS to this domain.'));
		o.datatype = 'hostname';
		o.depends('type', 'mtproxy');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'domain_fronting_port', _('Domain fronting port'));
		o.datatype = 'port';
		o.default = '443';
		o.depends({'type': 'mtproxy', 'domain_fronting_host': /[\s\S]/});
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'mtproxy_idle_timeout', _('Idle timeout'),
			_('Close idle connections after this duration (e.g. 5m, 30s).'));
		o.placeholder = '5m';
		o.depends('type', 'mtproxy');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'mtproxy_handshake_timeout', _('Handshake timeout'),
			_('Maximum time to complete handshake (e.g. 10s).'));
		o.placeholder = '10s';
		o.depends('type', 'mtproxy');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'mtproxy_concurrency', _('Concurrency'),
			_('Worker pool size. Leave empty for default.'));
		o.datatype = 'uinteger';
		o.depends('type', 'mtproxy');
		o.modalonly = true;
		/* MTProxy config end */

		/* Hysteria (2) config start */
		o = srvGrid.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
		o.value('udp');
		/* WeChat-Video / FakeTCP are unsupported by sing-box currently
		   o.value('wechat-video');
		   o.value('faketcp');
		*/
		o.default = 'udp';
		o.depends('type', 'hysteria');
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_down_mbps', _('Max download speed'),
			_('Max download speed in Mbps.'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.depends('type', 'hysteria2');
		o.validate = function(section_id, value) {
			/* Lesson 344: Hysteria(1) without bandwidth limits is a core
			 * FATAL ('missing upload speed configuration') — and a broken
			 * server section takes down the WHOLE service (lesson 343). */
			if (section_id && this.section.formvalue(section_id, 'type') === 'hysteria' &&
			    (value == null || value === ''))
				return _('Required for Hysteria: an empty value stops the core from starting (the whole service goes down).');
			return true;
		};
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_up_mbps', _('Max upload speed'),
			_('Max upload speed in Mbps.'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.depends('type', 'hysteria2');
		o.validate = function(section_id, value) {
			if (section_id && this.section.formvalue(section_id, 'type') === 'hysteria' &&
			    (value == null || value === ''))
				return _('Required for Hysteria: an empty value stops the core from starting (the whole service goes down).');
			return true;
		};
		o.modalonly = true;

		o = srvGrid.option(form.ListValue, 'hysteria_auth_type', _('Authentication type'));
		o.value('', _('Disable'));
		o.value('base64', _('Base64'));
		o.value('string', _('String'));
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_auth_payload', _('Authentication payload'));
		o.password = true;
		o.depends({'type': 'hysteria', 'hysteria_auth_type': /[\s\S]/});
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.ListValue, 'hysteria_obfs_type', _('Obfuscate type'),
			_('Not yet verified live against the installed core — enable deliberately and check the service status after applying.'));
		o.value('', _('Disable'));
		o.value('salamander', _('Salamander'));
		o.depends('type', 'hysteria2');
		o.modalonly = true;

		o = srvGrid.option(CBIGenValue, 'hysteria_obfs_password', _('Obfuscate password'));
		o.password = true;
		o.depends('type', 'hysteria');
		o.depends({'type': 'hysteria2', 'hysteria_obfs_type': /[\s\S]/});
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'),
			_('The QUIC stream-level flow control window for receiving data.'));
		o.datatype = 'uinteger';
		o.default = '67108864';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_recv_window_client', _('QUIC connection receive window'),
			_('The QUIC connection-level flow control window for receiving data.'));
		o.datatype = 'uinteger';
		o.default = '15728640';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_max_conn_client', _('QUIC maximum concurrent bidirectional streams'),
			_('The maximum number of QUIC concurrent bidirectional streams that a peer is allowed to open.'));
		o.datatype = 'uinteger';
		o.default = '1024';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'),
			_('Disables Path MTU Discovery (RFC 8899). Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.'));
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'hysteria_ignore_client_bandwidth', _('Ignore client bandwidth'),
			_('Tell the client to use the BBR flow control algorithm instead of Hysteria CC.'));
		o.depends({'type': 'hysteria2', 'hysteria_down_mbps': '', 'hysteria_up_mbps': ''});
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'hysteria_masquerade', _('Masquerade'),
			_('HTTP3 server behavior when authentication fails.<br/>A 404 page will be returned if empty.'));
		o.depends('type', 'hysteria2');
		o.modalonly = true;
		/* Hysteria (2) config end */

		/* Shadowsocks config */
		o = srvGrid.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
		for (let i of hp.shadowsocks_encrypt_methods)
			o.value(i);
		o.default = 'aes-128-gcm';
		o.depends('type', 'shadowsocks');
		o.modalonly = true;

		/* Tuic config start */
		o = srvGrid.option(CBIGenValue, 'uuid', _('UUID'));
		o.password = true;
		o.depends('type', 'tuic');
		o.depends('type', 'vless');
		o.depends('type', 'vmess');
		o.validate = hp.validateUUID;
		o.modalonly = true;

		o = srvGrid.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'),
			_('QUIC congestion control algorithm.'));
		o.value('cubic');
		o.value('new_reno');
		o.value('bbr');
		o.default = 'cubic';
		o.depends('type', 'tuic');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tuic_auth_timeout', _('Auth timeout'),
			_('How long the server should wait for the client to send the authentication command (in seconds).'));
		o.datatype = 'uinteger';
		o.default = '3';
		o.depends('type', 'tuic');
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'tuic_enable_zero_rtt', _('Enable 0-RTT handshake'),
			_('Enable 0-RTT QUIC connection handshake on the client side. This is not impacting much on the performance, as the protocol is fully multiplexed.<br/>' +
				'Disabling this is highly recommended, as it is vulnerable to replay attacks.'));
		o.depends('type', 'tuic');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval'),
			_('Interval for sending heartbeat packets for keeping the connection alive (in seconds).'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.depends('type', 'tuic');
		o.modalonly = true;
		/* Tuic config end */

		/* VLESS / VMess config start */
		o = srvGrid.option(form.ListValue, 'vless_flow', _('Flow'));
		o.value('', _('None'));
		o.value('xtls-rprx-vision');
		o.depends('type', 'vless');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'vmess_alterid', _('Alter ID'),
			_('Legacy protocol support (VMess MD5 Authentication) is provided for compatibility purposes only, use of alterId > 1 is not recommended.'));
		o.datatype = 'uinteger';
		o.depends('type', 'vmess');
		o.modalonly = true;
		/* VMess config end */

		/* Transport config start */
		o = srvGrid.option(form.ListValue, 'transport', _('Transport'),
			_('No TCP transport, plain HTTP is merged into the HTTP transport.'));
		o.value('', _('None'));
		o.value('grpc', _('gRPC'));
		o.value('http', _('HTTP'));
		o.value('httpupgrade', _('HTTPUpgrade'));
		o.value('quic', _('QUIC'));
		o.value('ws', _('WebSocket'));
		o.depends('type', 'trojan');
		o.depends('type', 'vless');
		o.depends('type', 'vmess');
		o.onchange = function(ev, section_id, value) {
			let desc = this.map.findElement('id', 'cbid.homeproxy.%s.transport'.format(section_id)).nextElementSibling;
			if (value === 'http')
				desc.innerHTML = _('TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.');
			else if (value === 'quic')
				desc.innerHTML = _('No additional encryption support: It\'s basically duplicate encryption.');
			else
				desc.innerHTML = _('No TCP transport, plain HTTP is merged into the HTTP transport.');

			let tls_element = this.map.findElement('id', 'cbid.homeproxy.%s.tls'.format(section_id)).firstElementChild;
			if ((value === 'http' && tls_element.checked) || (value === 'grpc' && !features.with_grpc))
				this.map.findElement('id', 'cbid.homeproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
					_('Specifies the time (in seconds) until idle clients should be closed with a GOAWAY frame. PING frames are not considered as activity.');
			else if (value === 'grpc' && features.with_grpc)
				this.map.findElement('id', 'cbid.homeproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
					_('If the transport doesn\'t see any activity after a duration of this time (in seconds), it pings the client to check if the connection is still active.');
		}
		o.modalonly = true;

		/* gRPC config start */
		o = srvGrid.option(form.Value, 'grpc_servicename', _('gRPC service name'));
		o.depends('transport', 'grpc');
		o.modalonly = true;

		/* gRPC config end */

		/* HTTP(Upgrade) config start */
		o = srvGrid.option(form.DynamicList, 'http_host', _('Host'));
		o.datatype = 'hostname';
		o.depends('transport', 'http');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'httpupgrade_host', _('Host'));
		o.datatype = 'hostname';
		o.depends('transport', 'httpupgrade');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'http_path', _('Path'));
		o.depends('transport', 'http');
		o.depends('transport', 'httpupgrade');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'http_method', _('Method'));
		o.depends('transport', 'http');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'http_idle_timeout', _('Idle timeout'),
			_('Specifies the time (in seconds) until idle clients should be closed with a GOAWAY frame. PING frames are not considered as activity.'));
		o.datatype = 'uinteger';
		o.depends('transport', 'grpc');
		o.depends({'transport': 'http', 'tls': '1'});
		o.modalonly = true;

		if (features.with_grpc) {
			o = srvGrid.option(form.Value, 'http_ping_timeout', _('Ping timeout'),
				_('The timeout (in seconds) that after performing a keepalive check, the client will wait for activity. If no activity is detected, the connection will be closed.'));
			o.datatype = 'uinteger';
			o.depends('transport', 'grpc');
			o.modalonly = true;
		}
		/* HTTP config end */

		/* WebSocket config start */
		o = srvGrid.option(form.Value, 'ws_host', _('Host'));
		o.depends('transport', 'ws');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'ws_path', _('Path'));
		o.depends('transport', 'ws');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'websocket_early_data', _('Early data'),
			_('Allowed payload size is in the request.'));
		o.datatype = 'uinteger';
		o.value('2048');
		o.depends('transport', 'ws');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'websocket_early_data_header', _('Early data header name'),
			_('Early data is sent in path instead of header by default.') +
			'<br/>' +
			_('To be compatible with Xray-core, set this to <code>Sec-WebSocket-Protocol</code>.'));
		o.value('Sec-WebSocket-Protocol');
		o.depends('transport', 'ws');
		o.modalonly = true;
		/* WebSocket config end */

		/* Transport config end */

		/* Mux config start */
		o = srvGrid.option(form.Flag, 'multiplex', _('Multiplex'));
		o.depends('type', 'shadowsocks');
		o.depends('type', 'trojan');
		o.depends('type', 'vless');
		o.depends('type', 'vmess');
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'multiplex_padding', _('Enable padding'));
		o.depends('multiplex', '1');
		o.modalonly = true;

		if (features.hp_has_tcp_brutal) {
			o = srvGrid.option(form.Flag, 'multiplex_brutal', _('Enable TCP Brutal'),
				_('Enable TCP Brutal congestion control algorithm'));
			o.depends('multiplex', '1');
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'multiplex_brutal_down', _('Download bandwidth'),
				_('Download bandwidth in Mbps.'));
			o.datatype = 'uinteger';
			o.depends('multiplex_brutal', '1');
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'multiplex_brutal_up', _('Upload bandwidth'),
				_('Upload bandwidth in Mbps.'));
			o.datatype = 'uinteger';
			o.depends('multiplex_brutal', '1');
			o.modalonly = true;
		}
		/* Mux config end */

		/* TLS config start */
		o = srvGrid.option(form.Flag, 'tls', _('TLS'));
		o.depends('type', 'anytls');
		o.depends('type', 'http');
		o.depends('type', 'hysteria');
		o.depends('type', 'hysteria2');
		o.depends('type', 'naive');
		o.depends('type', 'trojan');
		o.depends('type', 'tuic');
		o.depends('type', 'vless');
		o.depends('type', 'vmess');
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (section_id) {
				let type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
				let tls = this.map.findElement('id', 'cbid.homeproxy.%s.tls'.format(section_id)).firstElementChild;

				if (['hysteria', 'hysteria2', 'tuic'].includes(type)) {
					tls.checked = true;
					tls.disabled = true;
				} else {
					tls.disabled = null;
				}
			}

			return true;
		}
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_sni', _('TLS SNI'),
			_('Used to verify the hostname on the returned certificates unless insecure is given.'));
		o.depends('tls', '1');
		o.modalonly = true;

		o = srvGrid.option(form.DynamicList, 'tls_alpn', _('TLS ALPN'),
			_('List of supported application level protocols, in order of preference.'));
		o.depends('tls', '1');
		o.modalonly = true;

		o = srvGrid.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'),
			_('The minimum TLS version that is acceptable.'));
		o.value('', _('default'));
		for (let i of hp.tls_versions)
			o.value(i);
		o.depends('tls', '1');
		o.modalonly = true;

		o = srvGrid.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
			_('The maximum TLS version that is acceptable.'));
		o.value('', _('default'));
		for (let i of hp.tls_versions)
			o.value(i);
		o.depends('tls', '1');
		o.modalonly = true;

		o = srvGrid.option(hp.CBIStaticList, 'tls_cipher_suites', _('Cipher suites'),
			_('The elliptic curves that will be used in an ECDHE handshake, in preference order. If empty, the default will be used.'));
		for (let i of hp.tls_cipher_suites)
			o.value(i);
		o.depends('tls', '1');
		o.optional = true;
		o.modalonly = true;

		if (features.with_acme) {
			o = srvGrid.option(form.Flag, 'tls_acme', _('Enable ACME'),
				_('Use ACME TLS certificate issuer.'));
			o.depends('tls', '1');
			o.modalonly = true;

			o = srvGrid.option(form.DynamicList, 'tls_acme_domain', _('Domains'));
			o.datatype = 'hostname';
			o.depends('tls_acme', '1');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_dsn', _('Default server name'),
				_('Server name to use when choosing a certificate if the ClientHello\'s ServerName field is empty.'));
			o.depends('tls_acme', '1');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_email', _('Email'),
				_('The email address to use when creating or selecting an existing ACME server account.'));
			o.depends('tls_acme', '1');
			o.validate = function(section_id, value) {
				if (section_id) {
					if (!value)
						return _('Expecting: %s').format('non-empty value');
					else if (!value.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/))
						return _('Expecting: %s').format('valid email address');
				}

				return true;
			}
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_provider', _('CA provider'),
				_('The ACME CA provider to use.'));
			o.value('letsencrypt', _('Let\'s Encrypt'));
			o.value('zerossl', _('ZeroSSL'));
			o.depends('tls_acme', '1');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Flag, 'tls_dns01_challenge', _('DNS01 challenge'))
			o.depends('tls_acme', '1');
			o.modalonly = true;

			o = srvGrid.option(form.ListValue, 'tls_dns01_provider', _('DNS provider'));
			o.value('alidns', _('Alibaba Cloud DNS'));
			o.value('cloudflare', _('Cloudflare'));
			o.depends('tls_dns01_challenge', '1');
			o.default = 'cloudflare';
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_dns01_ali_akid', _('Access key ID'));
			o.password = true;
			o.depends('tls_dns01_provider', 'alidns');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_dns01_ali_aksec', _('Access key secret'));
			o.password = true;
			o.depends('tls_dns01_provider', 'alidns');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_dns01_ali_rid', _('Region ID'));
			o.depends('tls_dns01_provider', 'alidns');
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_dns01_cf_api_token', _('API token'));
			o.password = true;
			o.depends('tls_dns01_provider', 'cloudflare');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Flag, 'tls_acme_dhc', _('Disable HTTP challenge'));
			o.depends('tls_dns01_challenge', '0');
			o.modalonly = true;

			o = srvGrid.option(form.Flag, 'tls_acme_dtac', _('Disable TLS ALPN challenge'));
			o.depends('tls_dns01_challenge', '0');
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_ahp', _('Alternative HTTP port'),
				_('The alternate port to use for the ACME HTTP challenge; if non-empty, this port will be used instead of 80 to spin up a listener for the HTTP challenge.'));
			o.datatype = 'port';
			o.depends('tls_dns01_challenge', '0');
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_atp', _('Alternative TLS port'),
				_('The alternate port to use for the ACME TLS-ALPN challenge; the system must forward 443 to this port for challenge to succeed.'));
			o.datatype = 'port';
			o.depends('tls_dns01_challenge', '0');
			o.modalonly = true;

			o = srvGrid.option(form.Flag, 'tls_acme_external_account', _('External Account Binding'),
				_('EAB (External Account Binding) contains information necessary to bind or map an ACME account to some other account known by the CA.' +
				'<br/>External account bindings are "used to associate an ACME account with an existing account in a non-ACME system, such as a CA customer database.'));
			o.depends('tls_acme', '1');
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_ea_keyid', _('External account key ID'));
			o.password = true;
			o.depends('tls_acme_external_account', '1');
			o.rmempty = false;
			o.modalonly = true;

			o = srvGrid.option(form.Value, 'tls_acme_ea_mackey', _('External account MAC key'));
			o.password = true;
			o.depends('tls_acme_external_account', '1');
			o.rmempty = false;
			o.modalonly = true;
		}

		o = srvGrid.option(form.Flag, 'tls_reality', _('REALITY'));
		o.depends({'tls': '1', 'tls_acme': '0', 'type': /^(anytls|vless)$/});
		o.depends({'tls': '1', 'tls_acme': null, 'type': /^(anytls|vless)$/});
		o.modalonly = true;

		o = srvGrid.option(CBIGenValue, 'tls_reality_private_key', _('REALITY private key'));
		o.password = true;
		o.hp_options = {
			type: 'reality-keypair',
			params: '',
			callback: function(result) {
				return [
					[this.option, result.private_key],
					['tls_reality_public_key', result.public_key]
				]
			}
		}
		o.depends('tls_reality', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_reality_public_key', _('REALITY public key'));
		o.depends('tls_reality', '1');
		o.modalonly = true;

		o = srvGrid.option(form.DynamicList, 'tls_reality_short_id', _('REALITY short ID'));
		o.depends('tls_reality', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_reality_max_time_difference', _('Max time difference'),
			_('The maximum time difference between the server and the client.'));
		o.depends('tls_reality', '1');
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_reality_server_addr', _('Handshake server address'));
		o.datatype = 'hostname';
		o.depends('tls_reality', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_reality_server_port', _('Handshake server port'));
		o.datatype = 'port';
		o.depends('tls_reality', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_cert_path', _('Certificate path'),
			_('The server public key, in PEM format.'));
		o.value('/etc/homeproxy/certs/server_publickey.pem');
		o.depends({'tls': '1', 'tls_acme': '0', 'tls_reality': null});
		o.depends({'tls': '1', 'tls_acme': '0', 'tls_reality': '0'});
		o.depends({'tls': '1', 'tls_acme': null, 'tls_reality': '0'});
		o.depends({'tls': '1', 'tls_acme': null, 'tls_reality': null});
		o.validate = hp.validateCertificatePath;
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Button, '_upload_cert', _('Upload certificate'),
			_('<strong>Save your configuration before uploading files!</strong>'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends({'tls': '1', 'tls_cert_path': '/etc/homeproxy/certs/server_publickey.pem'});
		o.onclick = L.bind(hp.uploadCertificate, this, _('certificate'), 'server_publickey');
		o.modalonly = true;

		o = srvGrid.option(form.Button, '_gen_selfsign_cert', _('Self-signed certificate'),
			_('Generate a self-signed certificate and key pair on the router (EC, 10 years) — no domain needed. A self-signed cert is NOT publicly trusted: on the clients enable "Allow insecure TLS" (insecure) or pin the certificate. ACME on this page stays the way to get a publicly-trusted one.'));
		o.inputstyle = 'action';
		o.inputtitle = _('Generate');
		o.depends({'tls': '1', 'tls_cert_path': '/etc/homeproxy/certs/server_publickey.pem'});
		o.onclick = L.bind(function(ev) {
			const callServerCertGenerate = rpc.declare({
				object: 'luci.ravnex',
				method: 'server_cert_generate',
				expect: { '': {} }
			});
			const btn = (ev && ev.target) ? ev.target : null;
			if (btn)
				btn.disabled = true;
			return L.resolveDefault(callServerCertGenerate(), {}).then((ret) => {
				if (btn)
					btn.disabled = false;
				if (ret && ret.result === true)
					ui.addNotification(null, E('p', _('Self-signed certificate generated (%s), valid until %s. The paths above already point to it — save the configuration, then enable "Allow insecure TLS" (or pin the cert) on the clients.').format(ret.generator || '?', ret.expires || '?')));
				else
					ui.addNotification(null, E('p', _('Failed to generate the certificate: %s.').format((ret && ret.error) || _('unknown error'))));
			});
		}, this);
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'tls_key_path', _('Key path'),
			_('The server private key, in PEM format.'));
		o.value('/etc/homeproxy/certs/server_privatekey.pem');
		o.depends({'tls': '1', 'tls_acme': '0', 'tls_reality': '0'});
		o.depends({'tls': '1', 'tls_acme': '0', 'tls_reality': null});
		o.depends({'tls': '1', 'tls_acme': null, 'tls_reality': '0'});
		o.depends({'tls': '1', 'tls_acme': null, 'tls_reality': null});
		o.validate = hp.validateCertificatePath;
		o.rmempty = false;
		o.modalonly = true;

		o = srvGrid.option(form.Button, '_upload_key', _('Upload key'),
			_('<strong>Save your configuration before uploading files!</strong>'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends({'tls': '1', 'tls_key_path': '/etc/homeproxy/certs/server_privatekey.pem'});
		o.onclick = L.bind(hp.uploadCertificate, this, _('private key'), 'server_privatekey');
		o.modalonly = true;

		o = srvGrid.option(form.TextValue, 'tls_ech_key', _('ECH key'));
		o.placeholder = '-----BEGIN ECH KEYS-----\nACBE2+piYBLrOywCbRYU+ZpEkk8keeBlUXbKqLRmQ/68FwBL/g0ARwAAIAAgn8HI\n93RfdV/LaDk+LC9H4h+4WhVBFmWKdhiT3vvpGi8ACAABAAEAAQADABRvdXRlci1z\nbmkuYW55LmRvbWFpbgAA\n-----END ECH KEYS-----';
		o.monospace = true;
		o.cols = 30
		o.rows = 3;
		o.hp_options = {
			type: 'ech-keypair',
			params: '',
			callback: function(result) {
				return [
					[this.option, result.ech_key],
					['tls_ech_config', result.ech_cfg]
				]
			}
		}
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			let node = form.TextValue.prototype.renderWidget.apply(this, arguments);
			const cbid = this.cbid(section_id) + '._outer_sni';

			node.appendChild(E('div',  { 'class': 'control-group' }, [
				E('input', {
					id: cbid,
					class: 'cbi-input-text',
					style: 'width: 10em',
					placeholder: 'outer-sni.any.domain'
				}),
				E('button', {
					class: 'cbi-button cbi-button-add',
					click: ui.createHandlerFn(this, () => {
						this.hp_options.params = document.getElementById(cbid).value;

						return handleGenKey.call(this, this.hp_options);
					})
				}, [ _('Generate') ])
			]));

			return node;
		}
		o.depends('tls', '1');
		o.modalonly = true;

		o = srvGrid.option(form.TextValue, 'tls_ech_config', _('ECH config'));
		o.placeholder = '-----BEGIN ECH CONFIGS-----\nAEv+DQBHAAAgACCfwcj3dF91X8toOT4sL0fiH7haFUEWZYp2GJPe++kaLwAIAAEA\nAQABAAMAFG91dGVyLXNuaS5hbnkuZG9tYWluAAA=\n-----END ECH CONFIGS-----';
		o.monospace = true;
		o.cols = 30
		o.rows = 3;
		o.depends('tls', '1');
		o.modalonly = true;
		/* TLS config end */

		/* Extra settings start */
		o = srvGrid.option(form.Flag, 'tcp_fast_open', _('TCP fast open'),
			_('Enable tcp fast open for listener.'));
		o.depends({'network': 'udp', '!reverse': true});
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'tcp_multi_path', _('MultiPath TCP'));
		o.depends({'network': 'udp', '!reverse': true});
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'udp_fragment', _('UDP Fragment'),
			_('Enable UDP fragmentation.'));
		o.depends({'network': 'tcp', '!reverse': true});
		o.modalonly = true;

		o = srvGrid.option(form.Value, 'udp_timeout', _('UDP NAT expiration time'),
			_('In seconds.'));
		o.datatype = 'uinteger';
		o.placeholder = '300';
		o.depends({'network': 'tcp', '!reverse': true});
		o.modalonly = true;

		o = srvGrid.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('', _('Both'));
		o.depends('type', 'naive');
		o.depends('type', 'shadowsocks');
		o.modalonly = true;

		o = srvGrid.option(widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
			_('The network interface to bind to.'));
		o.multiple = false;
		o.noaliases = true;
		o.modalonly = true;

		o = srvGrid.option(form.Flag, 'reuse_addr', _('Reuse address'),
			_('Reuse listener address.'));
		o.modalonly = true;
		/* Extra settings end */

		return m.render().then(function(node) {
			return E('div', {}, [
				hp.pageIntro(_('Server mode'),
					_('Let OTHER devices connect to THIS router from the internet — your own phone away from home, a friend, or a second router. Each row below is one server endpoint; the Firewall flag decides whether it is reachable from outside.')),
				node
			]);
		});
	}
});
