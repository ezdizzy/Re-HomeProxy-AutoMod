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
		trend: '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>'
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
	--hp-font-mono: ui-monospace, 'Cascadia Mono', Consolas, 'Liberation Mono', Menlo, monospace;
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
table.hpui-table thead th { position: sticky; top: 0; z-index: 2; background: var(--hp-table-head); color: #f5f5f5; text-align: left; font-weight: 600; padding: 8px 10px; white-space: nowrap; border-bottom: 1px solid rgba(0,0,0,.35); }
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
