/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require baseclass';
'require form';
'require fs';
'require rpc';
'require uci';
'require ui';

return baseclass.extend({
	dns_strategy: {
		'': _('Default'),
		'prefer_ipv4': _('Prefer IPv4'),
		'prefer_ipv6': _('Prefer IPv6'),
		'ipv4_only': _('IPv4 only'),
		'ipv6_only': _('IPv6 only')
	},

	shadowsocks_encrypt_length: {
		/* AEAD */
		'aes-128-gcm': 0,
		'aes-192-gcm': 0,
		'aes-256-gcm': 0,
		'chacha20-ietf-poly1305': 0,
		'xchacha20-ietf-poly1305': 0,
		/* AEAD 2022 */
		'2022-blake3-aes-128-gcm': 16,
		'2022-blake3-aes-256-gcm': 32,
		'2022-blake3-chacha20-poly1305': 32
	},

	shadowsocks_encrypt_methods: [
		/* Stream */
		'none',
		/* AEAD */
		'aes-128-gcm',
		'aes-192-gcm',
		'aes-256-gcm',
		'chacha20-ietf-poly1305',
		'xchacha20-ietf-poly1305',
		/* AEAD 2022 */
		'2022-blake3-aes-128-gcm',
		'2022-blake3-aes-256-gcm',
		'2022-blake3-chacha20-poly1305'
	],

	tls_cipher_suites: [
		'TLS_RSA_WITH_AES_128_CBC_SHA',
		'TLS_RSA_WITH_AES_256_CBC_SHA',
		'TLS_RSA_WITH_AES_128_GCM_SHA256',
		'TLS_RSA_WITH_AES_256_GCM_SHA384',
		'TLS_AES_128_GCM_SHA256',
		'TLS_AES_256_GCM_SHA384',
		'TLS_CHACHA20_POLY1305_SHA256',
		'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
		'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
		'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
		'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
		'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
		'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
		'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
		'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
		'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
		'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
	],

	tls_versions: [
		'1.0',
		'1.1',
		'1.2',
		'1.3'
	],

	CBIStaticList: form.DynamicList.extend({
		__name__: 'CBI.StaticList',

		renderWidget: function(/* ... */) {
			let dl = form.DynamicList.prototype.renderWidget.apply(this, arguments);
			dl.querySelector('.add-item ul > li[data-value="-"]')?.remove();
			return dl;
		}
	}),

	/* FNV-1a 32-bit — MUST byte-match strhash() in update_subscriptions.uc /
	 * import_link.uc, or the "Sub (…)" node tabs stop matching their nodes'
	 * grouphash (79971d7 moved the daemon to this hash; node.js still compared
	 * the old MD5). ucode on this build does EXACT 64-bit integer math
	 * (verified live: URL → 32d94a75), so the multiply must be BigInt — plain
	 * JS number math rounds above 2^53 and drifts. charCodeAt equals ucode
	 * ord() for ASCII URLs (all subscription URLs in practice). */
	calcStringFNV(s) {
		let h = 2166136261n;
		for (let i = 0; i < s.length; i++) {
			h = (h ^ BigInt(s.charCodeAt(i))) & 0xFFFFFFFFn;
			h = (h * 16777619n) & 0xFFFFFFFFn;
		}
		return h.toString(16).padStart(8, '0');
	},

	calcStringMD5(e) {
		/* Thanks to https://stackoverflow.com/a/41602636 */
		let h = (a, b) => {
			let c, d, e, f, g;
			c = a & 2147483648;
			d = b & 2147483648;
			e = a & 1073741824;
			f = b & 1073741824;
			g = (a & 1073741823) + (b & 1073741823);
			return e & f ? g ^ 2147483648 ^ c ^ d : e | f ? g & 1073741824 ? g ^ 3221225472 ^ c ^ d : g ^ 1073741824 ^ c ^ d : g ^ c ^ d;
		}, k = (a, b, c, d, e, f, g) => h((a = h(a, h(h(b & c | ~b & d, e), g))) << f | a >>> 32 - f, b),
		l = (a, b, c, d, e, f, g) => h((a = h(a, h(h(b & d | c & ~d, e), g))) << f | a >>> 32 - f, b),
		m = (a, b, c, d, e, f, g) => h((a = h(a, h(h(b ^ c ^ d, e), g))) << f | a >>> 32 - f, b),
		n = (a, b, c, d, e, f, g) => h((a = h(a, h(h(c ^ (b | ~d), e), g))) << f | a >>> 32 - f, b),
		p = a => { let b = '', d = ''; for (let c = 0; c <= 3; c++) d = a >>> 8 * c & 255, d = '0' + d.toString(16), b += d.substr(d.length - 2, 2); return b; };

		let f = [], q, r, s, t, a, b, c, d;
		e = (() => {
			e = e.replace(/\r\n/g, '\n');
			let b = '';
			for (let d = 0; d < e.length; d++) {
				let c = e.charCodeAt(d);
				b += c < 128 ? String.fromCharCode(c) : c < 2048 ? String.fromCharCode(c >> 6 | 192) + String.fromCharCode(c & 63 | 128) :
					String.fromCharCode(c >> 12 | 224) + String.fromCharCode(c >> 6 & 63 | 128) + String.fromCharCode(c & 63 | 128);
			}
			return b;
		})();
		f = (() => {
			let c = e.length, a = c + 8, d = 16 * ((a - a % 64) / 64 + 1), b = Array(d - 1), f = 0, g = 0;
			for (; g < c;) a = (g - g % 4) / 4, f = g % 4 * 8, b[a] |= e.charCodeAt(g) << f, g++;
			a = (g - g % 4) / 4, b[a] |= 128 << g % 4 * 8, b[d - 2] = c << 3, b[d - 1] = c >>> 29;
			return b;
		})();

		a = 1732584193, b = 4023233417, c = 2562383102, d = 271733878;
		for (e = 0; e < f.length; e += 16) {
			q = a, r = b, s = c, t = d;
			a = k(a, b, c, d, f[e +  0],  7, 3614090360), d = k(d, a, b, c, f[e +  1], 12, 3905402710),
			c = k(c, d, a, b, f[e +  2], 17,  606105819), b = k(b, c, d, a, f[e +  3], 22, 3250441966),
			a = k(a, b, c, d, f[e +  4],  7, 4118548399), d = k(d, a, b, c, f[e +  5], 12, 1200080426),
			c = k(c, d, a, b, f[e +  6], 17, 2821735955), b = k(b, c, d, a, f[e +  7], 22, 4249261313),
			a = k(a, b, c, d, f[e +  8],  7, 1770035416), d = k(d, a, b, c, f[e +  9], 12, 2336552879),
			c = k(c, d, a, b, f[e + 10], 17, 4294925233), b = k(b, c, d, a, f[e + 11], 22, 2304563134),
			a = k(a, b, c, d, f[e + 12],  7, 1804603682), d = k(d, a, b, c, f[e + 13], 12, 4254626195),
			c = k(c, d, a, b, f[e + 14], 17, 2792965006), b = k(b, c, d, a, f[e + 15], 22, 1236535329),
			a = l(a, b, c, d, f[e +  1],  5, 4129170786), d = l(d, a, b, c, f[e +  6],  9, 3225465664),
			c = l(c, d, a, b, f[e + 11], 14,  643717713), b = l(b, c, d, a, f[e +  0], 20, 3921069994),
			a = l(a, b, c, d, f[e +  5],  5, 3593408605), d = l(d, a, b, c, f[e + 10],  9,   38016083),
			c = l(c, d, a, b, f[e + 15], 14, 3634488961), b = l(b, c, d, a, f[e +  4], 20, 3889429448),
			a = l(a, b, c, d, f[e +  9],  5,  568446438), d = l(d, a, b, c, f[e + 14],  9, 3275163606),
			c = l(c, d, a, b, f[e +  3], 14, 4107603335), b = l(b, c, d, a, f[e +  8], 20, 1163531501),
			a = l(a, b, c, d, f[e + 13],  5, 2850285829), d = l(d, a, b, c, f[e +  2],  9, 4243563512),
			c = l(c, d, a, b, f[e +  7], 14, 1735328473), b = l(b, c, d, a, f[e + 12], 20, 2368359562),
			a = m(a, b, c, d, f[e +  5],  4, 4294588738), d = m(d, a, b, c, f[e +  8], 11, 2272392833),
			c = m(c, d, a, b, f[e + 11], 16, 1839030562), b = m(b, c, d, a, f[e + 14], 23, 4259657740),
			a = m(a, b, c, d, f[e +  1],  4, 2763975236), d = m(d, a, b, c, f[e +  4], 11, 1272893353),
			c = m(c, d, a, b, f[e +  7], 16, 4139469664), b = m(b, c, d, a, f[e + 10], 23, 3200236656),
			a = m(a, b, c, d, f[e + 13],  4,  681279174), d = m(d, a, b, c, f[e +  0], 11, 3936430074),
			c = m(c, d, a, b, f[e +  3], 16, 3572445317), b = m(b, c, d, a, f[e +  6], 23,   76029189),
			a = m(a, b, c, d, f[e +  9],  4, 3654602809), d = m(d, a, b, c, f[e + 12], 11, 3873151461),
			c = m(c, d, a, b, f[e + 15], 16,  530742520), b = m(b, c, d, a, f[e +  2], 23, 3299628645),
			a = n(a, b, c, d, f[e +  0],  6, 4096336452), d = n(d, a, b, c, f[e +  7], 10, 1126891415),
			c = n(c, d, a, b, f[e + 14], 15, 2878612391), b = n(b, c, d, a, f[e +  5], 21, 4237533241),
			a = n(a, b, c, d, f[e + 12],  6, 1700485571), d = n(d, a, b, c, f[e +  3], 10, 2399980690),
			c = n(c, d, a, b, f[e + 10], 15, 4293915773), b = n(b, c, d, a, f[e +  1], 21, 2240044497),
			a = n(a, b, c, d, f[e +  8],  6, 1873313359), d = n(d, a, b, c, f[e + 15], 10, 4264355552),
			c = n(c, d, a, b, f[e +  6], 15, 2734768916), b = n(b, c, d, a, f[e + 13], 21, 1309151649),
			a = n(a, b, c, d, f[e +  4],  6, 4149444226), d = n(d, a, b, c, f[e + 11], 10, 3174756917),
			c = n(c, d, a, b, f[e +  2], 15,  718787259), b = n(b, c, d, a, f[e +  9], 21, 3951481745),
			a = h(a, q), b = h(b, r), c = h(c, s), d = h(d, t);
		}
		return (p(a) + p(b) + p(c) + p(d)).toLowerCase();
	},

	decodeBase64Str(str) {
		if (!str)
			return null;

		/* Thanks to luci-app-ssr-plus */
		str = str.replace(/-/g, '+').replace(/_/g, '/');
		let padding = (4 - str.length % 4) % 4;
		if (padding)
			str = str + Array(padding + 1).join('=');

		return decodeURIComponent(Array.prototype.map.call(atob(str), (c) =>
			'%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
		).join(''));
	},

	/* Shared visual language (reference: the Automation tab): theme-agnostic
	 * translucent panels/cards/badges, dark console blocks, tab bar with hover
	 * highlight. Injected once per page load; pages opt in by calling this. */
	uiStyle() {
		if (document.getElementById('hp-ui-style'))
			return;

		const css = `
.hpui-cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }
.hpui-card { flex: 1 1 140px; min-width: 130px; padding: 10px 14px; border: 1px solid rgba(128,128,128,.3); border-radius: 8px; background: rgba(128,128,128,.07); }
.hpui-num { font-size: 1.7em; font-weight: 700; line-height: 1.25; }
.hpui-cap { font-size: .85em; opacity: .75; }
.hpui-panel { border: 1px solid rgba(128,128,128,.3); border-radius: 8px; padding: 12px 14px; background: rgba(128,128,128,.07); margin: 10px 0; }
.hpui-panel h4 { margin: 0 0 8px 0; }
.hpui-c-red { color: #e05252; } .hpui-c-green { color: #3fbf5f; }
.hpui-c-blue { color: #4d8fe0; } .hpui-c-grey { color: #9a9a9a; }
.hpui-c-amber { color: #d99a1b; }
.hpui-tabs { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px 0; border-bottom: 2px solid rgba(128,128,128,.3); }
.hpui-tab { appearance: none; border: 1px solid transparent; background: rgba(128,128,128,.10); color: inherit; padding: 7px 16px; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 1em; font-weight: 500; }
.hpui-tab:hover { background: rgba(128,128,128,.20); }
.hpui-tab.active { background: rgba(128,128,128,.26); border-color: rgba(128,128,128,.4); font-weight: 700; }
.hpui-pane { display: none; }
.hpui-pane.active { display: block; }
.hpui-banner { margin: 8px 0; padding: 8px 12px; border-radius: 6px; border: 1px solid #b8860b; background: rgba(184,134,11,.15); }
.hpui-banner-ok { border-color: #3fbf5f; background: rgba(63,191,95,.12); }
.hpui-wrap { max-height: 62vh; overflow: auto; border: 1px solid rgba(128,128,128,.35); border-radius: 6px; margin-top: 6px; }
table.hpui-table { border-collapse: separate; border-spacing: 0; width: 100%; }
table.hpui-table thead th { position: sticky; top: 0; z-index: 2; background: #757575; color: #f5f5f5; text-align: left; font-weight: 600; padding: 8px 10px; white-space: nowrap; border-bottom: 1px solid rgba(0,0,0,.35); }
table.hpui-table tbody td { padding: 6px 10px; border-bottom: 1px solid rgba(128,128,128,.18); vertical-align: middle; }
table.hpui-table tbody tr:hover td { background: rgba(128,128,128,.13); }
.hpui-badge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: .82em; font-weight: 600; white-space: nowrap; border: 1px solid transparent; }
.hpui-b-red { background: rgba(224,82,82,.16); color: #e05252; border-color: rgba(224,82,82,.45); }
.hpui-b-green { background: rgba(63,191,95,.15); color: #2e9e55; border-color: rgba(63,191,95,.45); }
.hpui-b-amber { background: rgba(255,193,7,.18); color: #b8860b; border-color: rgba(255,193,7,.5); }
.hpui-b-grey { background: rgba(154,154,154,.18); color: #8a8a8a; border-color: rgba(154,154,154,.5); }
.hpui-b-blue { background: rgba(77,143,224,.16); color: #4d8fe0; border-color: rgba(77,143,224,.5); }
.hpui-log { max-height: 420px; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 0; padding: 8px; background: #1e1e1e; color: #ddd; border: 1px solid #333; border-radius: 6px; font-size: 0.85em; }
.hpui-pre { font-family: monospace; font-size: .82em; background: #1e1e1e; color: #ddd; border: 1px solid #333; padding: .5em .8em; white-space: pre-wrap; word-break: break-all; border-radius: 6px; margin: .3em 0 0; max-height: 14em; overflow-y: auto; }
.hpui-hint { font-size: .88em; opacity: .8; margin: 8px 0; }
`;

		document.head.appendChild(E('style', { id: 'hp-ui-style' }, [ css ]));
	},

	getBuiltinFeatures() {
		const callGetSingBoxFeatures = rpc.declare({
			object: 'luci.homeproxy',
			method: 'singbox_get_features',
			expect: { '': {} }
		});

		return L.resolveDefault(callGetSingBoxFeatures(), {}).then((features) => {
			/* If RPC failed or returned no core_type, fall back to core.info file */
			if (features.core_type)
				return features;
			return L.resolveDefault(fs.read_direct('/var/run/homeproxy/core.info', 'text'), null)
				.then((text) => {
					if (text) {
						try {
							const info = JSON.parse(text);
							features.core_type = info.core_type || features.core_type;
							features.version   = info.version   || features.version;
						} catch(e) {}
					}
					return features;
				});
		});
	},

	generateRand(type, length) {
		let byteArr;
		if (['base64', 'hex'].includes(type))
			byteArr = crypto.getRandomValues(new Uint8Array(length));
		switch (type) {
			case 'base64':
				/* Thanks to https://stackoverflow.com/questions/9267899 */
				return btoa(String.fromCharCode.apply(null, byteArr));
			case 'hex':
				return Array.from(byteArr, (byte) =>
					(byte & 255).toString(16).padStart(2, '0')
				).join('');
			case 'uuid':
				/* Thanks to https://stackoverflow.com/a/2117523 */
				return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, (c) =>
					(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
				);
			default:
				return null;
		};
	},

	loadDefaultLabel(uciconfig, ucisection) {
		let label = uci.get(uciconfig, ucisection, 'label');
		if (label) {
			return label;
		} else {
			uci.set(uciconfig, ucisection, 'label', ucisection);
			return ucisection;
		}
	},

	loadModalTitle(title, addtitle, uciconfig, ucisection) {
		let label = uci.get(uciconfig, ucisection, 'label');
		return label ? title + ' » ' + label : addtitle;
	},

	renderSectionAdd(section, extra_class) {
		let el = form.GridSection.prototype.renderSectionAdd.apply(section, [ extra_class ]),
			nameEl = el.querySelector('.cbi-section-create-name');
		ui.addValidator(nameEl, 'uciname', true, (v) => {
			let button = el.querySelector('.cbi-section-create > .cbi-button-add');
			let uciconfig = section.uciconfig || section.map.config;

			if (!v) {
				button.disabled = true;
				return true;
			} else if (uci.get(uciconfig, v)) {
				button.disabled = true;
				return _('Expecting: %s').format(_('unique UCI identifier'));
			} else {
				button.disabled = null;
				return true;
			}
		}, 'blur', 'keyup');

		return el;
	},

	uploadCertificate(_option, type, filename, ev) {
		const callWriteCertificate = rpc.declare({
			object: 'luci.homeproxy',
			method: 'certificate_write',
			params: ['filename'],
			expect: { '': {} }
		});

		return ui.uploadFile('/tmp/homeproxy_certificate.tmp', ev.target)
		.then(L.bind((_btn, res) => {
			return L.resolveDefault(callWriteCertificate(filename), {}).then((ret) => {
				if (ret.result === true)
					ui.addNotification(null, E('p', _('Your %s was successfully uploaded. Size: %sB.').format(type, res.size)));
				else
					ui.addNotification(null, E('p', _('Failed to upload %s, error: %s.').format(type, ret.error)));
			});
		}, this, ev.target))
		.catch((e) => { ui.addNotification(null, E('p', e.message)) });
	},

	validateBase64Key(length, section_id, value) {
		/* Thanks to luci-proto-wireguard */
		if (section_id && value)
			if (value.length !== length || !value.match(/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/) || value[length-1] !== '=')
				return _('Expecting: %s').format(_('valid base64 key with %d characters').format(length));

		return true;
	},

	validateCertificatePath(section_id, value) {
		if (section_id && value)
			if (!value.match(/^(\/etc\/homeproxy\/certs\/|\/etc\/acme\/|\/etc\/ssl\/).+$/))
				return _('Expecting: %s').format(_('/etc/homeproxy/certs/..., /etc/acme/..., /etc/ssl/...'));

		return true;
	},

	validatePortRange(section_id, value) {
		if (section_id && value) {
			value = value.match(/^(\d+)?\:(\d+)?$/);
			if (value && (value[1] || value[2])) {
				if (!value[1])
					value[1] = 0;
				else if (!value[2])
					value[2] = 65535;

				if (value[1] < value[2] && value[2] <= 65535)
					return true;
			}

			return _('Expecting: %s').format( _('valid port range (port1:port2)'));
		}

		return true;
	},

	validateUniqueValue(uciconfig, ucisection, ucioption, section_id, value) {
		if (section_id) {
			if (!value)
				return _('Expecting: %s').format(_('non-empty value'));
			if (ucioption === 'node' && value in ['urltest', 'main-out', 'direct-out', 'block-out'])
				return true;

			let duplicate = false;
			uci.sections(uciconfig, ucisection, (res) => {
				if (res['.name'] !== section_id)
					if (res[ucioption] === value)
						duplicate = true
			});
			if (duplicate)
				return _('Expecting: %s').format(_('unique value'));
		}

		return true;
	},

	validateUUID(section_id, value) {
		if (section_id) {
			if (!value)
				return _('Expecting: %s').format(_('non-empty value'));
			else if (value.match('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') === null)
				return _('Expecting: %s').format(_('valid uuid'));
		}

		return true;
	}
});
