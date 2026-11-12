/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex — app shell, Tachyon model (R3 v3, ч.280).
 *
 * ONE LuCI menu entry renders this view; the router's own chrome (Flint
 * header/menu) stays alive — nothing is overlaid, the «Router settings»
 * escape button of the fullscreen take-over is gone by design. The app
 * navigation is an in-page sidebar CARD (5 categories + Home, collapse,
 * left/right position) exactly like the studied Tachyon layout, and the
 * sections are the REAL view modules mounted in place:
 *
 *   view.homeproxy.<name> — load() then render(), the node goes into the
 *   workspace container; switching tears the section down (polls are gated
 *   by hp.embedPollBegin/end, nodes are dropped wholesale).
 *
 * Legacy URLs (admin/services/ravnex/<page>) remain routable as titleless
 * menu nodes pointed at this same view — the section comes from the URL,
 * so old bookmarks land on the right page. Nothing is lost, СМОТРИ В ЦЕЛОЕ.
 */

'use strict';
'require homeproxy as hp';
'require poll';
'require uci';
'require ui';
'require view';

/* Same msgids the old menu.d used — already translated in ravnex.po. */
const PAGE_TITLES = {
	overview: _('Home page'),
	client: _('Connection'),
	dns: _('DNS settings'),
	node: _('Servers'),
	bypass: _('Strategy master'),
	rules: _('Service rules'),
	automation: _('Auto-bypass'),
	devices: _('Devices'),
	control: _('Access Control'),
	telegram: _('Phone control'),
	status: _('Maintenance'),
	monitor: _('Monitoring'),
	health: _('Health center'),
	server: _('Server mode')
};

function currentSection() {
	/* Children are plain aliases to the root, so the dispatcher rewrites
	 * dispatchpath to the root — the ORIGINAL URL (window.location) is the
	 * only reliable carrier of the section for legacy bookmarks. */
	const m = String(window.location.pathname || '').match(/\/(?:cgi-bin\/luci\/)?admin\/services\/(?:ravnex|homeproxy)\/([a-z]+)/);
	if (m && PAGE_TITLES[m[1]])
		return m[1];
	const path = (L.env.dispatchpath || []);
	for (let i = 0; i < path.length; i++) {
		if (PAGE_TITLES[path[i]])
			return path[i];
	}
	return 'overview';
}

return view.extend({
	load() {
		/* shellStatus() reads routing_mode — the card status needs it up. */
		return uci.load([ 'ravnex' ]);
	},

	render() {
		hp.embedBoot();

		const self = this;

		/* ── Sidebar card ─────────────────────────────────────────── */
		const card = E('aside', { 'id': 'hp-embed-card' });

		const collapseBtn = E('button', {
			'class': 'hp-sb-collapse', 'type': 'button',
			'title': _('Collapse sidebar')
		}, [ hp.icon('chev-left') ]);
		collapseBtn.addEventListener('click', () => {
			const on = card.classList.toggle('collapsed');
			collapseBtn.replaceChildren(hp.icon(on ? 'chev-right' : 'chev-left'));
			collapseBtn.setAttribute('title', on ? _('Expand sidebar') : _('Collapse sidebar'));
			try { window.localStorage.setItem('hp-embed-collapsed', on ? '1' : '0'); } catch (e) {}
		});

		const brandEl = E('div', { 'class': 'hp-sb-brand' }, [
			E('img', { 'class': 'hp-sb-logo', 'src': L.resource('ravnex-raven-192.png'), 'alt': 'Ravnex' }),
			E('div', { 'class': 'hp-sb-brand-txt' }, [
				E('div', { 'class': 'hp-sb-name' }, [ 'Ravnex' ]),
				E('div', { 'class': 'hp-sb-slogan' }, [ 'Own the Route.' ])
			]),
			collapseBtn
		]);

		let collapsed = false;
		try { collapsed = window.localStorage.getItem('hp-embed-collapsed') === '1'; } catch (e) {}
		if (collapsed)
			card.classList.add('collapsed');

		const navEl = E('div', { 'class': 'hp-sb-nav', 'id': 'hp-embed-nav' });
		const sections = {};

		const buildNav = (activeName) => {
			navEl.replaceChildren();
			for (let c = 0; c < hp.APP_CATS.length; c++) {
				const cat = hp.APP_CATS[c];
				const secEl = E('div', { 'class': 'hp-sb-section' });
				if (cat.cap)
					secEl.appendChild(E('div', { 'class': 'hp-sb-cap' }, [ _(cat.cap) ]));
				for (let p = 0; p < cat.pages.length; p++) {
					const name = cat.pages[p];
					const item = E('a', {
						'class': 'hp-sb-item' + (name === activeName ? ' active' : ''),
						'href': L.url('admin/services/ravnex', name === 'overview' ? 'overview' : name)
					}, [
						hp.icon(hp.NAV_ICONS[name] || 'compass'),
						E('span', { 'class': 'hp-sb-item-t' }, [ _(PAGE_TITLES[name]) ])
					]);
					item.addEventListener('click', function(ev) {
						/* In-place mount, no full page load (the whole point of
						 * the Tachyon model). The URL is kept bookable. */
						ev.preventDefault();
						try { window.history.replaceState(null, '', item.href); } catch (e) {}
						self.mount(name);
					});
					sections[name] = item;
					secEl.appendChild(item);
				}
				if (secEl.children.length > (cat.cap ? 1 : 0))
					navEl.appendChild(secEl);
			}
		};

		/* ── Status footer (the same shellStatus as the fullscreen shell) ── */
		const sbDot = E('span', { 'class': 'hpui-dot', 'id': 'hp-embed-dot' });
		const sbText = E('div', { 'class': 'hp-sb-status-t' }, [ '…' ]);
		const sbSub = E('div', { 'class': 'hp-sb-status-s' }, [ '' ]);
		const statusEl = E('div', { 'class': 'hp-sb-status' }, [
			sbDot,
			E('div', { 'class': 'hp-sb-status-txt' }, [ sbText, sbSub ])
		]);

		card.appendChild(brandEl);
		card.appendChild(navEl);
		card.appendChild(statusEl);

		/* ── Workspace ────────────────────────────────────────────── */
		const main = E('div', { 'class': 'hp-embed-main' });
		const titleEl = E('h2', {}, [ '' ]);
		const holder = E('div', { 'id': 'hp-embed-view' });
		main.appendChild(titleEl);
		main.appendChild(holder);

		const root = E('div', { 'class': 'hp-embed-root' }, [ card, main ]);
		this._rootEl = root;

		let mounted = null;

		/* Mount a section view in place: load() → render() → node. Every
		 * poll the section registers is gated (see hp.embedPollBegin) and
		 * released when the section leaves — nothing leaks across switches. */
		this.mount = function(name) {
			if (mounted === name)
				return;
			mounted = name;

			if (self.embedClean) {
				try { self.embedClean.end(); } catch (e) {}
				self.embedClean = null;
			}
			self.embedClean = hp.embedPollBegin();

			for (const k in sections)
				sections[k].classList.toggle('active', k === name);

			titleEl.textContent = _(PAGE_TITLES[name]);
			try { document.title = _(PAGE_TITLES[name]) + ' | Ravnex'; } catch (e) {}

			holder.replaceChildren(E('p', { 'class': 'spinning' }, [ _('Loading…') ]));

			L.resolveDefault(L.require('view.homeproxy.' + name), null).then((mod) => {
				if (!mod || mounted !== name)
					return;
				holder.replaceChildren();
				Promise.resolve(mod.load ? mod.load() : null).then((data) => {
					if (mounted !== name)
						return;
					return Promise.resolve(mod.render(data)).then((node) => {
						if (mounted !== name || !node)
							return;
						/* Self-heal: a stray second LuCI dispatch pass may
						 * replace #view content (observed live, wave A).
						 * This URL owns exactly one view — ours — so the
						 * shell is always re-anchored; the poll keeper above
						 * covers later losses. */
						try {
							const vp = document.getElementById('view');
							const rootLive = vp && vp.querySelector(':scope > .hp-embed-root');
							if (rootLive && rootLive !== root)
								rootLive.replaceWith(root);
							else if (!rootLive && root.isConnected !== true && vp)
								vp.replaceChildren(root);
						} catch (e) {}
						holder.appendChild(node);
					});
				}).catch((e) => {
					holder.replaceChildren(E('p', {}, [
						_('Error') + ': ' + (e && e.message ? e.message : e)
					]));
				});
			});
		};

		buildNav(currentSection());

		/* Section status line poll — lives as long as the app shell does. */
		hp.shellStatus(sbDot, sbText, sbSub);

		/* Left/right position of the card (Tachyon has the same toggle). */
		let pos = 'left';
		try { pos = window.localStorage.getItem('hp-embed-pos') === 'right' ? 'right' : 'left'; } catch (e) {}
		root.setAttribute('data-pos', pos);
		const posBtn = E('button', {
			'class': 'hp-sb-collapse', 'type': 'button',
			'title': _('Move the menu to the other side'),
			'style': 'margin: 6px auto 0; display: block;'
		}, [ pos === 'left' ? '⇥' : '⇤' ]);
		posBtn.addEventListener('click', () => {
			pos = (pos === 'left') ? 'right' : 'left';
			root.setAttribute('data-pos', pos);
			posBtn.replaceChildren(pos === 'left' ? '⇥' : '⇤');
			try { window.localStorage.setItem('hp-embed-pos', pos); } catch (e) {}
		});
		card.appendChild(posBtn);

		this.mount(currentSection());

		/* Anchor keeper: any stray second dispatch pass may swap #view
		 * content (observed live, wave A acceptance). This URL owns exactly
		 * one view — ours — so losing the shell is always wrong. Cheap
		 * idempotent re-anchor; NOT hidden-gated (the shell is structural). */
		poll.add(L.bind(function() {
			try {
				const vp = document.getElementById('view');
				if (vp && !vp.querySelector('.hp-embed-root') && this._rootEl)
					vp.replaceChildren(this._rootEl);
			} catch (e) {}
			return Promise.resolve();
		}, this), hp.pollSec(2));

		try { window.__HP_DEBUG = { rootReturned: true, holderInRoot: root.contains(holder), navItems: navEl.querySelectorAll('.hp-sb-item').length }; } catch (e) { window.__HP_DEBUG = { buildErr: String(e) }; }

		return root;
	}
});
