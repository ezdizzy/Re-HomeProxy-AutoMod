/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require baseclass';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';

/* R3 v2 theme pre-paint: apply the saved (or system) color scheme to <html>
 * as soon as this module loads and BEFORE the shell builds — no flash of the
 * unthemed page. This resource loads only on the app's pages, so the
 * attribute never leaks to other LuCI views. */
(function() {
	try {
		let t = null;
		try { t = window.localStorage.getItem('hp-theme'); } catch (e) {}
		if (t !== 'dark' && t !== 'light')
			t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
		document.documentElement.setAttribute('data-hp-theme', t);
	} catch (e) {}
})();

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

	/* Р3 design tokens for JS consumers (charts draw stroke/fill as SVG
	 * ATTRIBUTES, where CSS var() does not resolve — so the palette is
	 * duplicated here as literals and MUST stay in sync with the :root
	 * block in uiStyle(). Fill = the same hue at ~.12 alpha. */
	PALETTE: {
		accent: '#22c55e', accentBright: '#4ade80', accentStrong: '#16a34a',
		accentFill: 'rgba(34,197,94,.12)',
		red: '#e05252', redFill: 'rgba(224,82,82,.12)',
		amber: '#d99a1b', amberHot: '#e07b00', amberFill: 'rgba(224,123,0,.12)',
		blue: '#4d8fe0', blueFill: 'rgba(77,143,224,.12)',
		grey: '#9a9a9a', greyFill: 'rgba(154,154,154,.14)'
	},

	/* Р3 icon set — one inline-SVG line-icon language for subsystems
	 * (24×24 viewBox, 2px stroke, currentColor) instead of mixed unicode
	 * symbols. No external resources (D5). hp.icon(name, cls) returns an
	 * <svg class="hpui-ic [cls]"> or null for an unknown name. */
	ICONS: {
		cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
		server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
		layers: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
		shuffle: '<polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/>',
		shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
		router: '<rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="18" r="1"/><circle cx="10" cy="18" r="1"/><path d="M16 18h4"/><path d="M17.5 6.5a5 5 0 0 0-7 0"/><path d="M14.8 9.2a2 2 0 0 0-3.6 0"/>',
		logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
		zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
		globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
		refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
		send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
		activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
		sensors: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
		compass: '<circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>',
		monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
		hardrive: '<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>',
		crosshair: '<circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/>',
		tool: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
		wifi: '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
		clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
		ban: '<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
		repeat: '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
		check: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
		alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
		database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
		trend: '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>',
		/* Shell chrome icons (R3 v2). */
		sun: '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
		moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
		'chev-left': '<polyline points="15 18 9 12 15 6"/>',
		'chev-right': '<polyline points="9 18 15 12 9 6"/>',
		menu: '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>'
	},

	icon(name, cls) {
		const body = this.ICONS[name];
		if (!body)
			return null;
		const NS = 'http://www.w3.org/2000/svg';
		const svg = document.createElementNS(NS, 'svg');
		svg.setAttribute('viewBox', '0 0 24 24');
		svg.setAttribute('aria-hidden', 'true');
		svg.setAttribute('class', 'hpui-ic' + (cls ? ' ' + cls : ''));
		svg.innerHTML = body;
		return svg;
	},

	/* Shared visual language (reference: the Automation tab): theme-agnostic
	 * translucent panels/cards/badges, dark console blocks, tab bar with hover
	 * highlight. Injected once per page load; pages opt in by calling this.
	 *
	 * Р3 (design v3): every visual constant lives in the :root token block
	 * below — the brand accent (#22c55e/#4ade80 from the raven logo), the
	 * semantic status palette, panel/radius/shadow/typography tokens. The
	 * per-view CSS blocks reference the same vars, so a palette change is a
	 * one-place edit. No external fonts/CDN (D5): the font stacks are local
	 * system families only. */
	uiStyle() {
		if (document.getElementById('hp-ui-style'))
			return;

		const css = `
:root {
	/* Ravnex brand accent (the raven logo green). */
	--hp-accent: #22c55e;
	--hp-accent-bright: #4ade80;
	--hp-accent-strong: #16a34a;
	--hp-accent-strong-hover: #15803d;
	--hp-accent-soft: rgba(34,197,94,.12);
	--hp-accent-soft-2: rgba(34,197,94,.22);
	--hp-accent-line: rgba(34,197,94,.45);
	--hp-accent-glow: rgba(34,197,94,.55);
	/* Semantic status palette. */
	--hp-red: #e05252; --hp-red-soft: rgba(224,82,82,.16); --hp-red-line: rgba(224,82,82,.45);
	--hp-amber: #d99a1b; --hp-amber-hot: #e07b00; --hp-amber-soft: rgba(255,193,7,.18); --hp-amber-line: rgba(255,193,7,.5);
	--hp-blue: #4d8fe0; --hp-blue-soft: rgba(77,143,224,.16); --hp-blue-line: rgba(77,143,224,.5);
	--hp-grey: #9a9a9a; --hp-grey-soft: rgba(154,154,154,.18); --hp-grey-line: rgba(154,154,154,.5);
	--hp-ink-green: #16a34a; --hp-ink-red: #e05252; --hp-ink-amber: #b8860b; --hp-ink-blue: #4d8fe0; --hp-ink-grey: #8a8a8a;
	/* Surfaces / shapes / type (D5: local system fonts only). */
	--hp-panel-bg: rgba(128,128,128,.07);
	--hp-panel-bg-2: rgba(127,127,127,.04);
	--hp-panel-line: rgba(128,128,128,.3);
	--hp-panel-line-strong: rgba(128,128,128,.35);
	--hp-radius-sm: 6px; --hp-radius: 8px; --hp-radius-lg: 10px;
	--hp-shadow: 0 1px 2px rgba(0,0,0,.08), 0 2px 10px rgba(0,0,0,.06);
	--hp-console-bg: #1e1e1e; --hp-console-line: #333; --hp-console-fg: #ddd;
	--hp-table-head: #757575;
	--hp-table-head-fg: #f5f5f5;
	--hp-font-mono: ui-monospace, 'Cascadia Mono', Consolas, 'Liberation Mono', Menlo, monospace;
	/* Shell (R3 v2): light defaults — the data-hp-theme blocks below override
	 * them as soon as the pre-paint sets the attribute (always does on app
	 * pages). */
	--hp-shell-bg: #f2f4f8;
	--hp-shell-bg-2: #ffffff;
	--hp-shell-bg-3: #e9edf3;
	--hp-fg: #1b2431;
	--hp-fg-dim: rgba(27,36,49,.64);
	--hp-fg-faint: rgba(27,36,49,.45);
	--hp-hover: rgba(27,36,49,.05);
	--hp-hover-2: rgba(27,36,49,.09);
	--hp-input-bg: #ffffff;
	--hp-input-line: rgba(27,36,49,.25);
	--hp-sb-w: 236px;
	--hp-sb-w-collapsed: 64px;
	--hp-topbar-h: 52px;
}
.hpui-cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }
.hpui-card { flex: 1 1 140px; min-width: 130px; padding: 10px 14px; border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); background: var(--hp-panel-bg); box-shadow: var(--hp-shadow); }
.hpui-num { font-size: 1.7em; font-weight: 700; line-height: 1.25; }
.hpui-cap { font-size: .85em; opacity: .75; }
.hpui-panel { border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); padding: 12px 14px; background: var(--hp-panel-bg); margin: 10px 0; box-shadow: var(--hp-shadow); }
.hpui-panel h4 { margin: 0 0 8px 0; }
.hpui-h4 { display: flex; align-items: center; gap: 8px; }
.hpui-h4 .hpui-ic { color: var(--hp-accent-strong); width: 1.1em; height: 1.1em; flex: none; }
.hpui-c-red { color: var(--hp-red); } .hpui-c-green { color: var(--hp-accent-strong); }
.hpui-c-blue { color: var(--hp-blue); } .hpui-c-grey { color: var(--hp-grey); }
.hpui-c-amber { color: var(--hp-amber); }
.hpui-ic { width: 1.05em; height: 1.05em; stroke: currentColor; fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; vertical-align: -.15em; flex: none; }
.hpui-tabs { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px 0; border-bottom: 2px solid var(--hp-panel-line); }
.hpui-tab { appearance: none; border: 1px solid transparent; background: var(--hp-panel-bg-2); color: inherit; padding: 7px 16px; border-radius: var(--hp-radius-sm) var(--hp-radius-sm) 0 0; cursor: pointer; font-size: 1em; font-weight: 500; }
.hpui-tab:hover { background: rgba(128,128,128,.20); }
.hpui-tab.active { background: var(--hp-accent-soft); border-color: var(--hp-accent-line); color: var(--hp-accent-strong); font-weight: 700; }
.hpui-pane { display: none; }
.hpui-pane.active { display: block; }
.hpui-banner { margin: 8px 0; padding: 8px 12px; border-radius: var(--hp-radius-sm); border: 1px solid var(--hp-amber-line); background: var(--hp-amber-soft); }
.hpui-banner-ok { border-color: var(--hp-accent-line); background: var(--hp-accent-soft); }
.hpui-wrap { max-height: 62vh; overflow: auto; border: 1px solid var(--hp-panel-line-strong); border-radius: var(--hp-radius-sm); margin-top: 6px; }
table.hpui-table { border-collapse: separate; border-spacing: 0; width: 100%; }
table.hpui-table thead th { position: sticky; top: 0; z-index: 2; background: var(--hp-table-head); color: var(--hp-table-head-fg, #f5f5f5); text-align: left; font-weight: 600; padding: 8px 10px; white-space: nowrap; border-bottom: 1px solid rgba(0,0,0,.35); }
table.hpui-table tbody td { padding: 6px 10px; border-bottom: 1px solid rgba(128,128,128,.18); vertical-align: middle; }
table.hpui-table tbody tr:hover td { background: rgba(128,128,128,.13); }
.hpui-badge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: .82em; font-weight: 600; white-space: nowrap; border: 1px solid transparent; }
.hpui-b-red { background: var(--hp-red-soft); color: var(--hp-ink-red); border-color: var(--hp-red-line); }
.hpui-b-green { background: var(--hp-accent-soft); color: var(--hp-ink-green); border-color: var(--hp-accent-line); }
.hpui-b-amber { background: var(--hp-amber-soft); color: var(--hp-ink-amber); border-color: var(--hp-amber-line); }
.hpui-b-grey { background: var(--hp-grey-soft); color: var(--hp-ink-grey); border-color: var(--hp-grey-line); }
.hpui-b-blue { background: var(--hp-blue-soft); color: var(--hp-ink-blue); border-color: var(--hp-blue-line); }
.hpui-log { max-height: 420px; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 0; padding: 8px; background: var(--hp-console-bg); color: var(--hp-console-fg); border: 1px solid var(--hp-console-line); border-radius: var(--hp-radius-sm); font-size: 0.85em; font-family: var(--hp-font-mono); }
.hpui-pre { font-family: var(--hp-font-mono); font-size: .82em; background: var(--hp-console-bg); color: var(--hp-console-fg); border: 1px solid var(--hp-console-line); padding: .5em .8em; white-space: pre-wrap; word-break: break-all; border-radius: var(--hp-radius-sm); margin: .3em 0 0; max-height: 14em; overflow-y: auto; }
.hpui-hint { font-size: .88em; opacity: .8; margin: 8px 0; }
/* LuCI standard tab bars (Client/DNS/Node/Server settings, grid modals) get the
 * same look as the hpui-tabs above. Scoped to pages calling uiStyle(); LuCI
 * navigation is a full page load, so other apps are never affected.
 * NOTE: the bootstrap theme marks inactive tabs as li.cbi-tab-disabled and
 * styles them (incl. :hover) with higher specificity than a plain ul>li rule —
 * so the disabled state MUST be re-styled explicitly or hover/normal states
 * silently fall back to the theme gradient. */
ul.cbi-tabmenu { list-style: none; display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px 0; padding: 0; background: none; border-bottom: 2px solid var(--hp-panel-line); border-radius: 0; }
ul.cbi-tabmenu > li { flex: 0 1 auto; display: flex; align-items: center; height: auto; max-width: none; margin: 0; background: var(--hp-panel-bg-2); border: 1px solid transparent; border-bottom: none; border-radius: var(--hp-radius-sm) var(--hp-radius-sm) 0 0; box-shadow: none; color: inherit; cursor: pointer; transition: background .15s ease, border-color .15s ease, box-shadow .15s ease; }
ul.cbi-tabmenu > li > a, ul.cbi-tabmenu > li > div { display: block; padding: 7px 16px; color: inherit; text-decoration: none; text-shadow: none; font-weight: 500; font-size: 1em; line-height: 1.4; white-space: nowrap; border-radius: var(--hp-radius-sm) var(--hp-radius-sm) 0 0; outline: none; }
ul.cbi-tabmenu > li:hover { background: rgba(128,128,128,.20); }
/* !important guards: the bootstrap theme styles the disabled/hover states via
 * .cbi-tabmenu > .cbi-tab-disabled(:hover) and must never win back these
 * states — belt and suspenders on top of the higher-specificity selectors. */
ul.cbi-tabmenu > li.cbi-tab-disabled { background: var(--hp-panel-bg-2) !important; border-color: transparent !important; color: inherit !important; }
ul.cbi-tabmenu > li.cbi-tab-disabled:hover { background: rgba(128,128,128,.20) !important; }
ul.cbi-tabmenu > li.cbi-tab { background: var(--hp-accent-soft) !important; border-color: var(--hp-accent-line) !important; color: var(--hp-accent-strong) !important; }
ul.cbi-tabmenu > li.cbi-tab > a, ul.cbi-tabmenu > li.cbi-tab > div { font-weight: 700; color: inherit; }
ul.cbi-tabmenu > li > a:hover, ul.cbi-tabmenu > li:hover > a, ul.cbi-tabmenu > li:hover > div { color: inherit; text-decoration: none; }
/* Brand hover glow — the highlight the theme draws around BUTTONS on hover
 * and the active-tab border, now in the Ravnex green instead of the theme
 * blue. MUST stay the LAST cbi-tabmenu rule: its !important border-color
 * overrides the transparent/accent !important borders above on hover/focus. */
ul.cbi-tabmenu > li:hover, ul.cbi-tabmenu > li:focus-within, ul.cbi-tabmenu > li.cbi-tab:hover { box-shadow: 0 0 8px var(--hp-accent-glow); border-color: var(--hp-accent-line) !important; }
/* Primary action buttons carry the brand green (theme-agnostic solid), so
 * every tab speaks one accent. Scoped by page load: only views that call
 * uiStyle() (this app) are affected. NOTE: the background SHORTHAND is
 * required — the Flint theme paints .cbi-button-action with an opaque white
 * background-image gradient, which would sit on top of a background-color. */
.cbi-button-action, .btn.cbi-button-action {
	background: var(--hp-accent-strong) !important;
	border-color: var(--hp-accent-strong) !important;
	color: #fff !important;
	text-shadow: none;
}
.cbi-button-action:hover, .btn.cbi-button-action:hover, .cbi-button-action:focus, .btn.cbi-button-action:focus {
	background: var(--hp-accent-strong-hover) !important;
	border-color: var(--hp-accent-strong-hover) !important;
	color: #fff !important;
}
/* TypedSection "Delete" buttons: LuCI renders each button on its own line
 * ABOVE the rule block. The float puts it on the rule's top line as a
 * fallback; client.js additionally relocates the Routing-Rules buttons into
 * the rule's first option row (next to the Enable checkbox). */
.cbi-section-remove.right { float: right; margin-left: 12px; }
button.hp-rule-delete { margin-left: 12px; vertical-align: middle; }
/* Tabbed content area: a translucent panel right under the tab bar, so the
 * standard settings pages read like the Automation cards. Theme has no rules
 * for .cbi-section-node-tabbed, so this cannot clash; modals inherit it too. */
.cbi-section-node-tabbed { background: var(--hp-panel-bg); border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius); padding: 12px 14px; }
.cbi-tab-descr { opacity: .85; }
`;

		document.head.appendChild(E('style', { id: 'hp-ui-style' }, [ css ]));
	},

	/* ── R3 v2: the app shell («tachyon» layout) ───────────────────────────
	 * Full-page chrome for the 13 app tabs: a left sidebar (brand, grouped
	 * navigation built from the LuCI menu tree, live status line), a top bar
	 * (page title + color-theme toggle) and a re-skinned content area. The
	 * LuCI chrome (header/footer/tab strip) is hidden via body.hp-shell —
	 * page navigation is a full load, so other LuCI apps and the user's
	 * chosen LuCI theme stay untouched.
	 *
	 * Dual theme lives on html[data-hp-theme="dark|light"]: the pre-paint
	 * block at the top of this file sets it from localStorage('hp-theme')
	 * (default = prefers-color-scheme) before anything renders, and the
	 * data-hp-theme blocks below re-tune every --hp-* surface token, so the
	 * existing hpui-* components of all tabs adapt automatically. */
	SHELL_ACTIVE: false,

	/* Р3 v3 IA (19-UX_REDESIGN §4): five human sections. "wizard" (Routing
	 * Wizard) and "access" (device proxy policy) are intentionally NOT in
	 * the sidebar — their content moves to dedicated pages in v3b/v3c/v3d
	 * (the pages themselves stay reachable by URL). */
	NAV_SECTIONS: [
		{ pages: [ 'overview' ], cap: null },
		{ pages: [ 'client', 'dns', 'node' ], cap: 'Connection' },
		{ pages: [ 'rules', 'automation' ], cap: 'Blocking bypass' },
		{ pages: [ 'control', 'telegram' ], cap: 'Home' },
		{ pages: [ 'status', 'monitor', 'diagnostics', 'server' ], cap: 'System section' }
	],

	NAV_ICONS: {
		overview: 'activity', client: 'layers', dns: 'globe',
		node: 'server', rules: 'crosshair', automation: 'refresh', control: 'tool',
		telegram: 'send', status: 'cpu', monitor: 'trend',
		diagnostics: 'sensors', server: 'hardrive'
	},

	NAV_HIDDEN: { wizard: true, access: true },

	themeGet() {
		let t = null;
		try { t = window.localStorage.getItem('hp-theme'); } catch (e) {}
		if (t !== 'dark' && t !== 'light')
			t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
		return t;
	},

	themeSet(t) {
		if (t !== 'dark' && t !== 'light')
			t = 'dark';
		document.documentElement.setAttribute('data-hp-theme', t);
		try { window.localStorage.setItem('hp-theme', t); } catch (e) {}
		const btn = document.getElementById('hp-theme-btn');
		if (btn) {
			btn.replaceChildren(this.icon(t === 'dark' ? 'sun' : 'moon'));
			btn.setAttribute('title', _('Switch color theme'));
		}
	},

	uiShell() {
		if (this.SHELL_ACTIVE)
			return;
		this.SHELL_ACTIVE = true;

		this.uiStyle();

		const t = this.themeGet();
		document.documentElement.setAttribute('data-hp-theme', t);

		document.body.classList.add('hp-shell');

		/* The LuCI menu tree is cached in the tab's sessionStorage — after a
		 * package update users would keep seeing the OLD page names until
		 * the tab closes. One-time flush per IA version: every tab refreshes
		 * its tree once, then the cache works as before. */
		try {
			const MV = 'r3v3b2';
			if (window.localStorage.getItem('hp-menu-ver') !== MV) {
				ui.menu.flushCache();
				window.localStorage.setItem('hp-menu-ver', MV);
			}
		} catch (e) {}
		let collapsed = false;
		try { collapsed = window.localStorage.getItem('hp-shell-collapsed') === '1'; } catch (e) {}
		if (collapsed)
			document.body.classList.add('hp-shell-collapsed');

		document.head.appendChild(E('style', { id: 'hp-shell-style' }, [ this.SHELL_CSS ]));

		/* Sidebar */
		const collapseBtn = E('button', {
			'class': 'hp-sb-collapse', 'type': 'button',
			'title': collapsed ? _('Expand sidebar') : _('Collapse sidebar')
		}, [ this.icon(collapsed ? 'chev-right' : 'chev-left') ]);
		collapseBtn.addEventListener('click', () => {
			const on = document.body.classList.toggle('hp-shell-collapsed');
			collapseBtn.replaceChildren(this.icon(on ? 'chev-right' : 'chev-left'));
			collapseBtn.setAttribute('title', on ? _('Expand sidebar') : _('Collapse sidebar'));
			try { window.localStorage.setItem('hp-shell-collapsed', on ? '1' : '0'); } catch (e) {}
		});

		const brandEl = E('div', { 'class': 'hp-sb-brand' }, [
			E('img', { 'class': 'hp-sb-logo', 'src': L.resource('ravnex-raven-192.png'), 'alt': 'Ravnex' }),
			E('div', { 'class': 'hp-sb-brand-txt' }, [
				E('div', { 'class': 'hp-sb-name' }, [ 'Ravnex' ]),
				E('div', { 'class': 'hp-sb-slogan' }, [ 'Own the Route.' ])
			]),
			collapseBtn
		]);

		const navEl = E('div', { 'class': 'hp-sb-nav', 'id': 'hp-sb-nav' });

		/* Escape hatches: the shell hides the LuCI chrome on app pages by
		 * design (option B, сеанс 54) — but the user must always have a
		 * VISIBLE way back to the router settings and a way to log out
		 * (user request 2026-10-31, ч.138). Full page loads, own pages
		 * stay unaffected. */
		const escEl = E('div', { 'class': 'hp-sb-esc' }, [
			E('a', { 'class': 'hp-sb-item', 'href': L.url('admin/status/overview') }, [
				this.icon('router'),
				E('span', { 'class': 'hp-sb-item-t' }, [ _('Router settings') ])
			]),
			E('a', { 'class': 'hp-sb-item', 'href': L.url('admin/logout') }, [
				this.icon('logout'),
				E('span', { 'class': 'hp-sb-item-t' }, [ _('Log out') ])
			])
		]);

		const sbDot = E('span', { 'class': 'hpui-dot', 'id': 'hp-sb-dot' });
		const sbText = E('div', { 'class': 'hp-sb-status-t' }, [ '…' ]);
		const sbSub = E('div', { 'class': 'hp-sb-status-s' }, [ '' ]);
		const statusEl = E('div', { 'class': 'hp-sb-status' }, [
			sbDot,
			E('div', { 'class': 'hp-sb-status-txt' }, [ sbText, sbSub ])
		]);

		document.body.appendChild(E('nav', { 'id': 'hp-sidebar' }, [ brandEl, navEl, escEl, statusEl ]));

		/* Top bar */
		const burgerBtn = E('button', {
			'class': 'hp-top-btn hp-top-burger', 'type': 'button', 'title': _('Menu')
		}, [ this.icon('menu') ]);
		burgerBtn.addEventListener('click', () => {
			document.body.classList.toggle('hp-shell-sb-open');
		});

		const titleRaw = (document.title || '').split('|');
		const pageTitle = (titleRaw.length > 1 ? titleRaw[titleRaw.length - 1] : titleRaw[0]).trim() || 'Ravnex';

		const themeBtn = E('button', {
			'class': 'hp-top-btn', 'type': 'button', 'id': 'hp-theme-btn',
			'title': _('Switch color theme')
		}, [ this.icon(t === 'dark' ? 'sun' : 'moon') ]);
		themeBtn.addEventListener('click', () => {
			this.themeSet(this.themeGet() === 'dark' ? 'light' : 'dark');
		});

		document.body.appendChild(E('header', { 'id': 'hp-topbar' }, [
			burgerBtn,
			E('div', { 'class': 'hp-top-title' }, [ pageTitle ]),
			E('div', { 'class': 'hp-top-spacer' }),
			themeBtn
		]));

		this.shellNav();
		this.shellStatus(sbDot, sbText, sbSub);
	},

	/* Navigation is built from the LuCI menu tree (ui.menu.load()) — the same
	 * names, order and ACL the tab strip used; only the presentation is ours.
	 * Captions group the pages without reordering them. */
	shellNav() {
		ui.menu.load().then(L.bind(function(tree) {
			try {
				const hpNode = tree && tree.children && tree.children.admin &&
					tree.children.admin.children && tree.children.admin.children.services &&
					tree.children.admin.children.services.children &&
					tree.children.admin.children.services.children.homeproxy;
				if (!hpNode)
					return;
				const kids = ui.menu.getChildren(hpNode);
				if (!kids || !kids.length)
					return;
				const cur = (L.env.dispatchpath || [])[3] || null;
				/* 🔴 L.url() accepts RELATIVE parts only (LuCI path() silently
				 * DROPS any part starting with '/'). Nesting L.url(L.url(base), p)
				 * therefore produced /cgi-bin/luci/<page> → 404 on every item
				 * (found live ч.137). Always pass both parts relatively. */
				const byName = {};
				for (let i = 0; i < kids.length; i++)
					byName[kids[i].name] = kids[i];
				const used = {};
				const nav = document.getElementById('hp-sb-nav');
				if (!nav)
					return;
				for (let s = 0; s < this.NAV_SECTIONS.length; s++) {
					const sec = this.NAV_SECTIONS[s];
					const secEl = E('div', { 'class': 'hp-sb-section' });
					if (sec.cap)
						secEl.appendChild(E('div', { 'class': 'hp-sb-cap' }, [ _(sec.cap) ]));
					for (let p = 0; p < sec.pages.length; p++) {
						const kid = byName[sec.pages[p]];
						if (!kid)
							continue;
						used[sec.pages[p]] = true;
						secEl.appendChild(E('a', {
							'class': 'hp-sb-item' + (sec.pages[p] === cur ? ' active' : ''),
							'href': L.url('admin/services/homeproxy', sec.pages[p])
						}, [
							this.icon(this.NAV_ICONS[sec.pages[p]] || 'compass'),
							E('span', { 'class': 'hp-sb-item-t' }, [ _(kid.title) ])
						]));
					}
					if (secEl.children.length > (sec.cap ? 1 : 0))
						nav.appendChild(secEl);
				}
				/* Pages present in the tree but not covered by NAV_SECTIONS
				 * (future tabs) still get an entry — nothing may be lost,
				 * EXCEPT the NAV_HIDDEN pages whose content is being moved
				 * to dedicated pages (wizard → v3b/v3c, access → v3d); they
				 * stay reachable by URL but are not shown. */
				const extra = E('div', { 'class': 'hp-sb-section' });
				for (let i = 0; i < kids.length; i++) {
					if (used[kids[i].name] || this.NAV_HIDDEN[kids[i].name])
						continue;
					extra.appendChild(E('a', {
						'class': 'hp-sb-item' + (kids[i].name === cur ? ' active' : ''),
						'href': L.url('admin/services/homeproxy', kids[i].name)
					}, [
						this.icon(this.NAV_ICONS[kids[i].name] || 'compass'),
						E('span', { 'class': 'hp-sb-item-t' }, [ _(kids[i].title) ])
					]));
				}
				if (extra.children.length)
					nav.appendChild(extra);
			} catch (e) { /* nav is cosmetic — never break the page */ }
		}, this));
	},

	/* Sidebar status line: one cheap overview_sys poll every 10 s (the
	 * Overview tab polls the same RPC every 4 s anyway; ubus calls are
	 * trivial). */
	shellStatus(dotEl, textEl, subEl) {
		const callShellSys = rpc.declare({
			object: 'luci.homeproxy',
			method: 'overview_sys',
			expect: { '': {} }
		});
		poll.add(L.bind(function() {
			return L.resolveDefault(callShellSys(), {}).then((sys) => {
				const ok = !!(sys && sys.clash_ok);
				const seen = !!(sys && sys.app_version);
				dotEl.className = 'hpui-dot' + (seen ? (ok ? ' ok' : ' bad') : '');
				textEl.textContent = ok ? _('System is running') : _('Core is not responding');
				subEl.textContent = (sys && sys.app_version) ? 'Ravnex v' + sys.app_version : '';
			});
		}, this), 10);
	},

	SHELL_CSS: `
/* ═══ R3 v2 dual theme: token re-tune per color scheme ═══ */
:root[data-hp-theme="dark"] {
	--hp-shell-bg: #0c1117;
	--hp-shell-bg-2: #10161e;
	--hp-shell-bg-3: #17202b;
	--hp-fg: #e2e8f0;
	--hp-fg-dim: rgba(226,232,240,.62);
	--hp-fg-faint: rgba(226,232,240,.40);
	--hp-panel-bg: rgba(255,255,255,.045);
	--hp-panel-bg-2: rgba(255,255,255,.028);
	--hp-panel-line: rgba(255,255,255,.10);
	--hp-panel-line-strong: rgba(255,255,255,.16);
	--hp-table-head: #1b2431;
	--hp-table-head-fg: #c9d3e0;
	--hp-console-bg: #0f151d;
	--hp-console-line: #253040;
	--hp-console-fg: #c7d1de;
	--hp-input-bg: #121a24;
	--hp-input-line: rgba(255,255,255,.16);
	--hp-hover: rgba(255,255,255,.06);
	--hp-hover-2: rgba(255,255,255,.10);
	--hp-shadow: 0 1px 2px rgba(0,0,0,.45), 0 4px 14px rgba(0,0,0,.35);
}
:root[data-hp-theme="light"] {
	--hp-shell-bg: #f2f4f8;
	--hp-shell-bg-2: #ffffff;
	--hp-shell-bg-3: #e9edf3;
	--hp-fg: #1b2431;
	--hp-fg-dim: rgba(27,36,49,.64);
	--hp-fg-faint: rgba(27,36,49,.45);
	--hp-panel-bg: #ffffff;
	--hp-panel-bg-2: rgba(27,36,49,.03);
	--hp-panel-line: rgba(27,36,49,.10);
	--hp-panel-line-strong: rgba(27,36,49,.16);
	--hp-table-head: #dfe5ee;
	--hp-table-head-fg: #38455a;
	--hp-console-bg: #f6f8fb;
	--hp-console-line: #d6dde7;
	--hp-console-fg: #2a3442;
	--hp-input-bg: #ffffff;
	--hp-input-line: rgba(27,36,49,.25);
	--hp-hover: rgba(27,36,49,.05);
	--hp-hover-2: rgba(27,36,49,.09);
	--hp-shadow: 0 1px 2px rgba(16,24,40,.06), 0 4px 14px rgba(16,24,40,.07);
}
/* ═══ Page takeover (app pages only — body.hp-shell) ═══ */
body.hp-shell {
	background: var(--hp-shell-bg) !important;
	color: var(--hp-fg);
}
body.hp-shell > header:not(#hp-topbar) { display: none !important; }
body.hp-shell > footer { display: none !important; }
body.hp-shell #tabmenu { display: none !important; }
body.hp-shell #maincontent {
	max-width: none;
	width: auto; /* bootstrap .container sets width:100% — with our left margin that would overflow horizontally */
	margin: 0 0 0 var(--hp-sb-w);
	padding: calc(var(--hp-topbar-h) + 14px) 22px 30px;
	box-sizing: border-box;
	transition: margin-left .18s ease;
	min-height: 100vh;
	overflow-x: hidden;
}
body.hp-shell.hp-shell-collapsed #maincontent { margin-left: var(--hp-sb-w-collapsed); }
/* ═══ Sidebar ═══ */
#hp-sidebar {
	position: fixed; z-index: 600; top: 0; left: 0; bottom: 0;
	width: var(--hp-sb-w);
	background: var(--hp-shell-bg-2);
	border-right: 1px solid var(--hp-panel-line);
	display: flex; flex-direction: column;
	overflow: hidden;
	transition: width .18s ease;
}
body.hp-shell-collapsed #hp-sidebar { width: var(--hp-sb-w-collapsed); }
.hp-sb-brand { display: flex; align-items: center; gap: 10px; padding: 14px 12px; flex: none; }
.hp-sb-logo { width: 40px; height: 40px; border-radius: 10px; flex: none; }
.hp-sb-brand-txt { min-width: 0; }
.hp-sb-name { font-weight: 800; font-size: 1.12em; line-height: 1.2; white-space: nowrap; }
.hp-sb-slogan { font-size: .66em; color: var(--hp-accent-strong); font-weight: 700; letter-spacing: .05em; white-space: nowrap; }
.hp-sb-collapse { margin-left: auto; flex: none; appearance: none; border: 1px solid var(--hp-panel-line); background: var(--hp-panel-bg-2); color: var(--hp-fg-dim); width: 26px; height: 26px; border-radius: 7px; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; padding: 0; }
.hp-sb-collapse:hover { color: var(--hp-accent-strong); border-color: var(--hp-accent-line); background: var(--hp-accent-soft); }
	.hp-sb-esc { flex: none; border-top: 1px solid var(--hp-panel-line); margin: 2px 10px 6px; padding-top: 6px; display: flex; flex-direction: column; gap: 2px; }
	.hp-sb-esc .hp-sb-item { opacity: .8; }
	.hp-sb-esc .hp-sb-item:hover { opacity: 1; }
	.hp-sb-nav { flex: 1 1 auto; overflow-y: auto; overflow-x: hidden; padding: 2px 10px 10px; scrollbar-width: thin; }
.hp-sb-cap { font-size: .68em; text-transform: uppercase; letter-spacing: .09em; color: var(--hp-fg-faint); margin: 13px 8px 4px; white-space: nowrap; font-weight: 700; }
.hp-sb-section { margin-bottom: 2px; }
.hp-sb-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; margin: 1px 0; border-radius: 8px; color: var(--hp-fg-dim); text-decoration: none; font-size: .93em; white-space: nowrap; border: 1px solid transparent; }
.hp-sb-item:hover { background: var(--hp-hover); color: var(--hp-fg); text-decoration: none; }
.hp-sb-item.active { background: var(--hp-accent-soft); border-color: var(--hp-accent-line); color: var(--hp-accent-strong); font-weight: 600; }
.hp-sb-item .hpui-ic { width: 1.2em; height: 1.2em; flex: none; }
.hp-sb-item-t { overflow: hidden; text-overflow: ellipsis; }
.hp-sb-status { border-top: 1px solid var(--hp-panel-line); padding: 10px 12px; display: flex; gap: 10px; align-items: center; flex: none; }
.hp-sb-status-txt { min-width: 0; }
.hp-sb-status-t { font-size: .88em; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hp-sb-status-s { font-size: .76em; color: var(--hp-fg-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* Collapsed: icons only */
body.hp-shell-collapsed .hp-sb-brand-txt, body.hp-shell-collapsed .hp-sb-cap,
body.hp-shell-collapsed .hp-sb-item-t, body.hp-shell-collapsed .hp-sb-status-txt { display: none; }
body.hp-shell-collapsed .hp-sb-brand { justify-content: center; padding: 14px 8px; flex-wrap: wrap; gap: 8px; }
body.hp-shell-collapsed .hp-sb-item { justify-content: center; padding: 9px 0; }
body.hp-shell-collapsed .hp-sb-status { justify-content: center; }
/* ═══ Top bar ═══ */
#hp-topbar {
	position: fixed; z-index: 590; top: 0; right: 0; left: var(--hp-sb-w);
	height: var(--hp-topbar-h);
	display: flex; align-items: center; gap: 12px;
	padding: 0 20px;
	background: var(--hp-shell-bg-2);
	border-bottom: 1px solid var(--hp-panel-line);
	transition: left .18s ease;
}
body.hp-shell-collapsed #hp-topbar { left: var(--hp-sb-w-collapsed); }
.hp-top-title { font-size: 1.1em; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hp-top-spacer { flex: 1; }
.hp-top-btn { appearance: none; border: 1px solid var(--hp-panel-line); background: var(--hp-panel-bg-2); color: var(--hp-fg-dim); width: 30px; height: 30px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; padding: 0; flex: none; }
.hp-top-btn:hover { color: var(--hp-accent-strong); border-color: var(--hp-accent-line); background: var(--hp-accent-soft); }
.hp-top-burger { display: none; }
/* ═══ Widget re-skins on shell pages (theme-owned colors; background
 * SHORTHAND everywhere — the LuCI theme paints gradients via
 * background-image that would sit on top of background-color) ═══ */
body.hp-shell .cbi-button, body.hp-shell .btn {
	background: var(--hp-shell-bg-3) !important;
	border: 1px solid var(--hp-input-line) !important;
	color: var(--hp-fg) !important;
	text-shadow: none !important;
}
body.hp-shell .cbi-button:hover, body.hp-shell .btn:hover { border-color: var(--hp-accent-line) !important; }
body.hp-shell .cbi-button-action, body.hp-shell .btn.cbi-button-action,
body.hp-shell .cbi-button-positive, body.hp-shell .cbi-button-apply, body.hp-shell .cbi-button-reload {
	background: var(--hp-accent-strong) !important;
	border-color: var(--hp-accent-strong) !important;
	color: #fff !important;
}
body.hp-shell .cbi-button-action:hover, body.hp-shell .btn.cbi-button-action:hover,
body.hp-shell .cbi-button-positive:hover, body.hp-shell .cbi-button-apply:hover, body.hp-shell .cbi-button-reload:hover,
body.hp-shell .cbi-button-action:focus, body.hp-shell .btn.cbi-button-action:focus {
	background: var(--hp-accent-strong-hover) !important;
	border-color: var(--hp-accent-strong-hover) !important;
	color: #fff !important;
}
body.hp-shell .cbi-button-negative, body.hp-shell .btn.cbi-button-negative,
body.hp-shell .cbi-button-remove, body.hp-shell .cbi-button-reset {
	background: var(--hp-red-soft) !important;
	border-color: var(--hp-red-line) !important;
	color: var(--hp-ink-red) !important;
}
body.hp-shell input[type=text], body.hp-shell input[type=password],
body.hp-shell input[type=number], body.hp-shell input[type=file],
body.hp-shell select, body.hp-shell textarea, body.hp-shell .cbi-dropdown {
	background: var(--hp-input-bg);
	color: var(--hp-fg);
	border: 1px solid var(--hp-input-line);
}
/* Headings and option labels: the theme paints them with fixed dark greys
 * that vanish on the dark shell. */
body.hp-shell h1, body.hp-shell h2, body.hp-shell h3, body.hp-shell h4,
body.hp-shell h5, body.hp-shell .cbi-value-title, body.hp-shell legend {
	color: var(--hp-fg);
}
body.hp-shell .cbi-map-descr, body.hp-shell .cbi-section-descr,
body.hp-shell .cbi-value-description, body.hp-shell .cbi-tab-descr {
	color: var(--hp-fg-dim);
}
/* LuCI save footer (Применить/Сохранить/Сброс): the theme paints it with a
 * light grey slab — on the shell it blends into the content instead. */
body.hp-shell .cbi-page-actions {
	background: transparent !important;
	background-image: none !important;
	border: none !important;
	box-shadow: none !important;
	margin: 14px 0 0;
	padding: 0;
}
body.hp-shell .cbi-dropdown > ul.dropdown { background: var(--hp-shell-bg-2); color: var(--hp-fg); border: 1px solid var(--hp-panel-line-strong); }
body.hp-shell .alert-message {
	background: var(--hp-panel-bg) !important;
	border: 1px solid var(--hp-panel-line) !important;
	color: var(--hp-fg) !important;
	box-shadow: var(--hp-shadow);
}
body.hp-shell #modal_overlay .modal {
	background: var(--hp-shell-bg-2) !important;
	color: var(--hp-fg);
	border: 1px solid var(--hp-panel-line-strong);
	box-shadow: 0 12px 48px rgba(0,0,0,.5);
}
body.hp-shell .cbi-tooltip {
	background: var(--hp-shell-bg-3);
	color: var(--hp-fg);
	border: 1px solid var(--hp-panel-line-strong);
}
/* ═══ Mobile: off-canvas sidebar ═══ */
@media (max-width: 920px) {
	#hp-sidebar { transform: translateX(-100%); transition: transform .18s ease; width: var(--hp-sb-w) !important; }
	body.hp-shell-sb-open #hp-sidebar { transform: none; box-shadow: 0 0 60px rgba(0,0,0,.5); }
	#hp-topbar { left: 0 !important; }
	body.hp-shell #maincontent { margin-left: 0 !important; }
	body.hp-shell.hp-shell-collapsed #maincontent { margin-left: 0 !important; }
	.hp-top-burger { display: inline-flex; }
	.hp-sb-collapse { display: none; }
}
`,

	/* Inline SVG line chart shared by the Overview and Automation tabs
	 * (Ф8-F5: one helper instead of the chartSvg/chartSvgEng duplicates).
	 * Area+line of points[key] into a 300×84-unit viewBox (scales with the
	 * container width); no external libraries (D5: everything local). Null
	 * values break the line (data missing because the core was down / the
	 * source absent at that moment). Fixed `max` when given (CPU/RAM: 0-100),
	 * auto-scale otherwise with a 35% headroom so the line never rides the
	 * top edge (×1.15 read as "maxed out" — Ф7, reused for Automation here).
	 * Grid lines at quarters; a static marker on the last point; the
	 * effective scale is reported back via opts.onScale (shown as
	 * "scale up to N" under the chart). opts.color / opts.fill style the
	 * line/marker/area (default: the Automation red); opts.className sets
	 * the CSS class so each page keeps its sizing rules. No animations:
	 * the SVG is a static picture re-rendered only when the ring data
	 * changes (signature-guarded by the caller).
	 * ⚠ Browser JS `for…in` over an array yields STRING INDICES (the exact
	 * reverse of the ucode lesson 20): `p[key]` on the index string is
	 * undefined, every value silently became null and the charts drew only
	 * the grid (found live in the Ф5 warm-up, ч.77). Iterate by index. */
	chartSvg(points, key, opts) {
		const W = 300, H = 84, TOP = 6, BOT = 4;
		const color = (opts && opts.color) || '#e05252';
		const fill = (opts && opts.fill) || 'rgba(224,82,82,.12)';
		const NS = 'http://www.w3.org/2000/svg';

		let vals = [];
		for (let i = 0; i < points.length; i++) {
			const p = points[i];
			vals.push((p != null && p[key] != null) ? Number(p[key]) : null);
		}

		let max = (opts && opts.max != null) ? opts.max : null;
		if (max == null) {
			let hi = 0;
			for (let i = 0; i < vals.length; i++) {
				const v = vals[i];
				if (v != null && v > hi) hi = v;
			}
			max = hi > 0 ? hi * 1.35 : 1;
		}
		if (max <= 0) max = 1;
		if (opts && opts.onScale) opts.onScale(max);

		const y = (v) => (TOP + (H - TOP - BOT) * (1 - (v / max)));
		const x = (i, n) => (n > 1 ? (i * W / (n - 1)) : 0);

		let area = '', line = '', pen = false;
		for (let i = 0; i < vals.length; i++) {
			const v = vals[i];
			if (v == null) {
				if (pen) { line += ' Z'; pen = false; }
				continue;
			}
			const px = x(i, vals.length).toFixed(1), py = y(v).toFixed(1);
			if (!pen) {
				if (line) { area += ' L' + px + ',' + H + ' L' + px + ',' + py; }
				else { area += 'M' + px + ',' + H + ' L' + px + ',' + py; }
				line += (line ? ' ' : '') + 'M' + px + ',' + py;
				pen = true;
			} else {
				area += ' L' + px + ',' + py;
				line += ' L' + px + ',' + py;
			}
		}
		if (pen) area += ' L' + x(vals.length - 1, vals.length).toFixed(1) + ',' + H + ' Z';

		const svg = document.createElementNS(NS, 'svg');
		svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
		svg.setAttribute('preserveAspectRatio', 'none');
		if (opts && opts.className)
			svg.setAttribute('class', opts.className);
		svg.setAttribute('role', 'img');

		if (area) {
			const a = document.createElementNS(NS, 'path');
			a.setAttribute('d', area);
			a.setAttribute('fill', fill);
			svg.appendChild(a);
		}
		for (let q = 1; q <= 3; q++) {
			const g = document.createElementNS(NS, 'path');
			g.setAttribute('d', 'M0,' + (TOP + (H - TOP - BOT) * q / 4).toFixed(1) + ' H' + W);
			g.setAttribute('stroke', 'rgba(128,128,128,.22)');
			g.setAttribute('stroke-width', '.5');
			g.setAttribute('fill', 'none');
			svg.appendChild(g);
		}
		if (line) {
			const l = document.createElementNS(NS, 'path');
			l.setAttribute('d', line);
			l.setAttribute('stroke', color);
			l.setAttribute('stroke-width', '1.4');
			l.setAttribute('fill', 'none');
			l.setAttribute('stroke-linejoin', 'round');
			svg.appendChild(l);
			/* Static marker on the last non-null point. */
			for (let i = vals.length - 1; i >= 0; i--) {
				if (vals[i] != null) {
					const d = document.createElementNS(NS, 'path');
					d.setAttribute('d', 'M' + x(i, vals.length).toFixed(1) + ',' + y(vals[i]).toFixed(1) + ' h.01');
					d.setAttribute('stroke', color);
					d.setAttribute('stroke-width', '3.2');
					d.setAttribute('stroke-linecap', 'round');
					svg.appendChild(d);
					break;
				}
			}
		}
		return svg;
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
