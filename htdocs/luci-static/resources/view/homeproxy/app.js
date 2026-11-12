/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Ravnex — app shell, Tachyon model (R3 v3e2, ч.280 + с.193).
 *
 * ONE LuCI menu entry renders this view; the router's own chrome (Flint
 * header/menu) stays alive — nothing is overlaid, the «Router settings»
 * escape button of the fullscreen take-over is gone by design. The app
 * navigation is an in-page sidebar CARD (categories + Home, Basic/Expert
 * switch, collapse, left/right position, mobile drawer) built by the ONE
 * factory in homeproxy.js (hp.buildEmbedCard) — the pre-paint boot anchors
 * that same graph at module-eval time and this view ADOPTS it, so entering
 * Services→Ravnex shows the card immediately instead of blinking in 2-3 s
 * later. The sections are the REAL view modules mounted in place:
 *
 *   view.homeproxy.<name> — load() then render(), the node goes into the
 *   workspace container; switching tears the section down (polls are gated
 *   by hp.embedPollBegin/end, nodes are dropped wholesale).
 *
 * Legacy URLs (admin/services/ravnex/<page>) remain routable as titleless
 * menu nodes pointed at this same view — the section comes from the URL,
 * so old bookmarks land on the right page. Every in-page link to one of
 * our sections (Home cards, cross-page links) is intercepted and mounts
 * in place; the href stays bookable. Nothing is lost, СМОТРИ В ЦЕЛОЕ.
 */

'use strict';
'require homeproxy as hp';
'require poll';
'require uci';
'require ui';
'require view';

const PAGE_TITLES = hp.PAGE_TITLES;

return view.extend({
	load() {
		/* shellStatus() reads routing_mode — the card status needs it up. */
		return uci.load([ 'ravnex' ]);
	},

	render() {
		hp.embedBoot();

		const self = this;

		/* Adopt the pre-paint skeleton when it ran (the usual path) — the
		 * card, nav and workspace the user is already looking at; else
		 * build the identical graph fresh. Handlers are wired HERE. */
		const ctx = hp.adoptEmbedSkeleton() || hp.buildEmbedCard();
		const { root, card, navEl, sections, holder } = ctx;

		this._rootEl = root;

		/* ── Card handlers ────────────────────────────────────────── */
		ctx.collapseBtn.addEventListener('click', () => {
			const on = card.classList.toggle('collapsed');
			ctx.collapseBtn.replaceChildren(hp.icon(on ? 'chev-right' : 'chev-left'));
			ctx.collapseBtn.setAttribute('title', on ? _('Expand sidebar') : _('Collapse sidebar'));
			try { window.localStorage.setItem('hp-embed-collapsed', on ? '1' : '0'); } catch (e) {}
		});
		if (window.localStorage.getItem('hp-embed-collapsed') === '1')
			card.classList.add('collapsed');

		ctx.posBtn.addEventListener('click', () => {
			ctx.pos = (ctx.pos === 'left') ? 'right' : 'left';
			root.setAttribute('data-pos', ctx.pos);
			ctx.posBtn.replaceChildren(ctx.pos === 'left' ? '⇥' : '⇤');
			try { window.localStorage.setItem('hp-embed-pos', ctx.pos); } catch (e) {}
		});

		/* Basic/Expert (Tachyon Simple/Advanced): Basic hides the expert
		 * pages, the choice sticks per browser. */
		const setMode = (m) => {
			ctx.mode = m;
			try { window.localStorage.setItem('hp-embed-mode', m); } catch (e) {}
			ctx.segBasic.classList.toggle('on', m === 'basic');
			ctx.segExpert.classList.toggle('on', m === 'expert');
			ctx.rebuildNav(mounted || hp.currentSection());
		};
		ctx.segBasic.addEventListener('click', () => setMode('basic'));
		ctx.segExpert.addEventListener('click', () => setMode('expert'));
		ctx.segBasic.classList.toggle('on', ctx.mode === 'basic');
		ctx.segExpert.classList.toggle('on', ctx.mode === 'expert');

		/* Mobile drawer (burger): the card slides over the content. */
		const closeMobile = () => { root.classList.remove('mobile-open'); };
		ctx.burger.addEventListener('click', () => { root.classList.toggle('mobile-open'); });
		ctx.backdrop.addEventListener('click', closeMobile);

		let mounted = null;

		/* Mount a section view in place: load() → render() → node. Every
		 * poll the section registers is gated (see hp.embedPollBegin) and
		 * released when the section leaves — nothing leaks across switches.
		 * force=true re-runs the CURRENT section (hp.embedRefresh hook). */
		this.mount = function(name, force) {
			if (mounted === name && !force)
				return;

			closeMobile();

			if (self.embedClean) {
				try { self.embedClean.end(); } catch (e) {}
				self.embedClean = null;
			}
			/* A section may have raised the RPC client timeout (health
			 * center); whatever leaves, leaves it as it found it. */
			if (hp.__hpSavedRpcTimeout != null) {
				try { L.env.rpctimeout = hp.__hpSavedRpcTimeout; } catch (e) {}
				hp.__hpSavedRpcTimeout = null;
			}
			self.embedClean = hp.embedPollBegin();

			mounted = name;
			for (const k in sections)
				sections[k].classList.toggle('active', k === name);

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
					/* Audit A3: never paint a DEAD section's error over a
					 * section the user already switched to. */
					if (mounted !== name)
						return;
					holder.replaceChildren(E('p', {}, [
						_('Error') + ': ' + (e && e.message ? e.message : e)
					]));
				});
			});
		};

		/* ONE delegated click handler owns all in-page navigation: the
		 * card items, the Home cards, every cross-section link. Internal
		 * hrefs stay bookable (middle-click/new-tab still full-load). */
		root.addEventListener('click', function(ev) {
			if (ev.defaultPrevented || ev.button !== 0 ||
			    ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey)
				return;
			const a = (ev.target && ev.target.closest) ? ev.target.closest('a[href]') : null;
			if (!a)
				return;
			const href = a.getAttribute('href') || '';
			const m = href.match(/admin\/services\/(?:ravnex|homeproxy)\/([a-z]+)(?:\?[^#]*)?(#.*)?$/);
			if (!m || !PAGE_TITLES[m[1]])
				return;
			ev.preventDefault();
			try { window.history.replaceState(null, '', a.href); } catch (e) {}
			self.mount(m[1]);
		});

		/* Section status line poll — lives as long as the app shell does. */
		hp.shellStatus(ctx.sbDot, ctx.sbText, ctx.sbSub);

		/* In-place refresh hook for the sections (node.js subscriptions
		 * et al.): remount the given section instead of reloading the
		 * whole page. */
		hp.__embedRemount = function(n) { self.mount(n, true); };

		/* Anchor keeper: any stray second dispatch pass may swap #view
		 * content (observed live, wave A acceptance). Registered with the
		 * ORIGINAL poll.add BEFORE the first mount() wraps it (audit A1:
		 * a keeper registered through the wrapper died with the first
		 * section teardown). Cheap idempotent re-anchor; NOT hidden-gated
		 * (the shell is structural). */
		poll.add(L.bind(function() {
			try {
				const vp = document.getElementById('view');
				if (vp && !vp.querySelector('.hp-embed-root') && this._rootEl)
					vp.replaceChildren(this._rootEl);
			} catch (e) {}
			return Promise.resolve();
		}, this), hp.pollSec(2));

		this.mount(hp.currentSection());

		return root;
	}
});
