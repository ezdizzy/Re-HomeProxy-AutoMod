/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — страница «Telegram-бот» (plan 15): all bot settings
 * moved OUT of the Wizard's "Дополнительно" pane into their own main-menu
 * page — the bot keeps growing (router control, parental-control pushes,
 * inline menus) and no longer fits a wizard sub-tab. Same RPC surface as
 * before (telegram_status/set/test); the daemon re-reads UCI every loop, so
 * saving never restarts the service.
 *
 * Design: hpui-* (hp.uiStyle()); card layout (Status / Connection / Pushes /
 * Diagnostics), results of every action render in ONE place (Diagnostics
 * card, below the buttons). No LuCI save-footer: this view drives UCI through
 * RPC only (handleSave* = null).
 */

'use strict';
'require dom';
'require rpc';
'require uci';
'require ui';
'require view';
'require homeproxy as hp';

const callTelegramStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_status',
	expect: { '': {} }
});

const callTelegramSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_set',
	params: [
		'enabled', 'token', 'chat_id', 'mute',
		'push_hotswap', 'push_watchdog', 'push_learn', 'push_service', 'push_control',
		'poll_timeout', 'push_interval'
	],
	expect: { '': {} }
});

const callTelegramTest = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_test',
	expect: { '': {} }
});

const CSS = `
	.tg-card { border: 1px solid rgba(128,128,128,.3); border-radius: 10px; padding: 14px 16px; background: rgba(127,127,127,.04); margin-top: 14px; }
	.tg-card-title { font-weight: 700; font-size: 1.02em; margin-bottom: 10px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
	.tg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px 18px; margin-top: 6px; }
	.tg-field { display: flex; flex-direction: column; gap: 4px; min-width: 200px; }
	.tg-field > label { font-size: .82em; font-weight: 600; opacity: .75; }
	.tg-toggle { display: flex; align-items: center; gap: 8px; font-weight: 600; cursor: pointer; }
	.tg-toggle input { width: 17px; height: 17px; cursor: pointer; }
	.tg-check { display: flex; align-items: flex-start; gap: 7px; cursor: pointer; line-height: 1.35; padding: 3px 0; }
	.tg-check input { margin-top: 2px; cursor: pointer; flex: none; }
	.tg-sub { opacity: .75; font-size: .86em; margin-top: 3px; }
	.tg-inline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
	.tg-inline .cbi-input-text { width: 110px; }
	.tg-status-row { display: flex; flex-wrap: wrap; gap: 6px 22px; align-items: center; }
	.tg-status-item { display: flex; flex-direction: column; gap: 2px; min-width: 150px; }
	.tg-status-item > .tg-k { font-size: .78em; font-weight: 600; opacity: .65; text-transform: uppercase; letter-spacing: .04em; }
	.tg-status-item > .tg-v { font-size: .95em; }
`;

return view.extend({
	load() {
		/* ч.118: uci.load was MISSING — every form field read from an EMPTY
		 * uci store and rendered defaults (enabled unchecked, chat empty,
		 * pushes on); pressing "Save bot settings" on that form sent
		 * enabled='0' and DISABLED the bot while the status card kept
		 * showing live RPC truth — the "settings don't save" report. */
		return Promise.all([
			L.resolveDefault(callTelegramStatus(), null),
			uci.load('homeproxy')
		]);
	},

	/* UCI is driven through RPC (telegram_set) — the LuCI save footer
	 * (Apply/Save/Reset) has nothing to act on here; suppress it. */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	render(data) {
		hp.uiStyle();

		const st0 = data[0] || {};

		const stEl = document.getElementById('hp-tg-style');
		if (!stEl)
			document.head.appendChild(E('style', { id: 'hp-tg-style' }, [ CSS ]));

		const badge = (cls, text) => E('span', { 'class': 'hpui-badge ' + cls }, [ text ]);

		/* ── inputs ─────────────────────────────────────────────────── */
		const tgEnabled = E('input', { type: 'checkbox' });
		const tgMute = E('input', { type: 'checkbox' });
		const tgToken = E('input', {
			type: 'password', 'class': 'cbi-input-text', style: 'width:100%; box-sizing:border-box',
			placeholder: _('BotFather token (kept if left empty)')
		});
		const tgClearToken = E('input', { type: 'checkbox' });
		const tgChat = E('input', {
			type: 'text', 'class': 'cbi-input-text', style: 'width:100%; box-sizing:border-box',
			placeholder: _('chat_id (leave empty — the first message to the bot pins the chat)')
		});
		const tgPushHs = E('input', { type: 'checkbox' });
		const tgPushWd = E('input', { type: 'checkbox' });
		const tgPushLr = E('input', { type: 'checkbox' });
		const tgPushSv = E('input', { type: 'checkbox' });
		const tgPushCt = E('input', { type: 'checkbox' });
		const tgPoll = E('input', { type: 'number', min: '5', max: '60', style: 'width:110px', 'class': 'cbi-input-text' });
		const tgPival = E('input', { type: 'number', min: '1', max: '30', style: 'width:110px', 'class': 'cbi-input-text' });

		const tgU = (opt, def) => {
			const v = uci.get('homeproxy', 'telegram', opt);
			return (v != null && String(v).length && String(v) !== '0') ? String(v) : def;
		};
		/* ч.119: boolean fields need '0' to mean OFF — tgU() was built for
		 * text/number fields and mapped an explicit saved '0' back to the
		 * default, so every push flag saved as disabled re-rendered CHECKED
		 * («Автоматизация: выученные блокировки» re-appeared after save) and
		 * the NEXT save silently re-enabled it. */
		const tgB = (opt, def) => {
			const v = uci.get('homeproxy', 'telegram', opt);
			return (v != null && String(v).length) ? (String(v) === '1') : (def === '1');
		};
		tgEnabled.checked = tgB('enabled', '0');
		tgMute.checked = tgB('mute', '0');
		tgPushHs.checked = tgB('push_hotswap', '1');
		tgPushWd.checked = tgB('push_watchdog', '1');
		tgPushLr.checked = tgB('push_learn', '1');
		tgPushSv.checked = tgB('push_service', '1');
		tgPushCt.checked = tgB('push_control', '1');
		tgPoll.value = tgU('poll_timeout', '25');
		tgPival.value = tgU('push_interval', '2');
		tgChat.value = tgU('chat_id', '');

		/* ч.118: typing a token always means "store THIS token" — the remove
		 * checkbox used to win unconditionally and the save silently
		 * discarded the typed token (the user-visible «Saved., but the bot
		 * answers no token»). Typing unchecks the box; the save also prefers
		 * a typed token and only honors the checkbox when the field is
		 * empty. */
		tgToken.addEventListener('input', function() {
			if (String(tgToken.value || '').trim()) tgClearToken.checked = false;
		});

		/* ── status card ────────────────────────────────────────────── */
		const tgState = E('span', {});
		const tgStatusGrid = E('div', { 'class': 'tg-status-row' });

		const tgStatusCard = E('div', { 'class': 'tg-card' }, [
			E('div', { 'class': 'tg-card-title' }, [ _('Bot status'), tgState ]),
			tgStatusGrid
		]);

		function statusItem(k, v) {
			return E('div', { 'class': 'tg-status-item' }, [
				E('div', { 'class': 'tg-k' }, [ k ]),
				E('div', { 'class': 'tg-v' }, [ v ])
			]);
		}

		function renderTelegramStatus(st) {
			st = st || {};
			if (st.running && st.enabled)
				dom.content(tgState, [ badge('hpui-b-green', _('Bot is running')) ]);
			else if (st.running && !st.enabled)
				dom.content(tgState, [ badge('hpui-b-grey', _('Daemon idle — bot disabled')) ]);
			else
				dom.content(tgState, [ badge('hpui-b-red', _('Daemon is not running')) ]);

			dom.content(tgStatusGrid, [
				statusItem(_('Token'), st.token_set ? badge('hpui-b-green', _('stored')) : badge('hpui-b-amber', _('missing'))),
				statusItem(_('Chat'), st.chat_id ? String(st.chat_id) : E('span', { style: 'opacity:.75' }, [ _('not bound yet — send any message to the bot') ])),
				statusItem(_('Pushes'), st.muted ? badge('hpui-b-amber', _('muted')) : badge('hpui-b-green', _('on'))),
				statusItem(_('Long-poll timeout'), (st.poll_timeout || 25) + ' s'),
				statusItem(_('Push interval'), (st.push_interval || 2) + ' s')
			]);
		}
		renderTelegramStatus(st0);

		function checkTelegram() {
			return L.resolveDefault(callTelegramStatus(), {}).then(function(st) {
				renderTelegramStatus(st);
			});
		}

		/* ── connection card ────────────────────────────────────────── */
		const connCard = E('div', { 'class': 'tg-card' }, [
			E('div', { 'class': 'tg-card-title' }, [ _('Connection') ]),
			E('label', { 'class': 'tg-toggle' }, [ tgEnabled, E('span', {}, [ _('Enable Telegram bot') ]) ]),
			E('p', { 'class': 'hpui-hint tg-sub' }, [ _('The daemon instance is always running; it re-reads these settings on its own — saving never restarts the service.') ]),
			E('div', { 'class': 'tg-grid', style: 'margin-top:12px' }, [
				E('div', { 'class': 'tg-field' }, [
					E('label', {}, [ _('Bot token') ]),
					tgToken,
					E('label', { 'class': 'tg-check' }, [
						tgClearToken,
						E('span', {}, [ _('remove stored token') ])
					])
				]),
				E('div', { 'class': 'tg-field' }, [
					E('label', {}, [ _('Chat ID') ]),
					tgChat,
					E('span', { 'class': 'tg-sub' }, [ _('Leave empty — the first message to the bot binds your chat automatically. Get the token from @BotFather.') ])
				]),
				E('div', { 'class': 'tg-field' }, [
					E('label', {}, [ _('Long-poll timeout, s') ]),
					tgPoll
				])
			])
		]);

		/* ── pushes card ────────────────────────────────────────────── */
		const pushesCard = E('div', { 'class': 'tg-card' }, [
			E('div', { 'class': 'tg-card-title' }, [
				_('Push notifications'),
				E('span', { 'class': 'hpui-hint', style: 'font-weight:400' }, [ _('Pushes watch the router state files; "Mute" silences pushes only — commands keep working.') ])
			]),
			E('label', { 'class': 'tg-toggle' }, [ tgMute, E('span', {}, [ _('Mute push notifications') ]) ]),
			E('div', { 'class': 'tg-grid', style: 'margin-top:10px' }, [
				E('label', { 'class': 'tg-check' }, [ tgPushHs, E('span', {}, [ _('Hot Swap node changes / failback') ]) ]),
				E('label', { 'class': 'tg-check' }, [ tgPushWd, E('span', {}, [ _('URLTest dead nodes') ]) ]),
				E('label', { 'class': 'tg-check' }, [ tgPushLr, E('span', {}, [ _('Automation learned blocks') ]) ]),
				E('label', { 'class': 'tg-check' }, [ tgPushSv, E('span', {}, [ _('Service faults') ]) ]),
				E('label', { 'class': 'tg-check' }, [ tgPushCt, E('span', {}, [ _('Control: blocks, schedules, Wi-Fi, new devices') ]) ])
			]),
			E('div', { 'class': 'tg-inline', style: 'margin-top:10px' }, [
				E('span', { 'class': 'tg-sub' }, [ _('Min gap between pushes, s') ]),
				tgPival
			])
		]);

		/* ── diagnostics card ───────────────────────────────────────── */
		const tgResult = E('div', {});

		const tgSaveBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' }, [ _('Save bot settings') ]);
		const tgTestBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Send test message') ]);
		const tgCheckBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Check status') ]);

		tgSaveBtn.addEventListener('click', function() {
			tgSaveBtn.disabled = true;
			const tokenVal = String(tgToken.value || '').trim();
			callTelegramSet(
				tgEnabled.checked ? '1' : '0',
				(tgClearToken.checked && !tokenVal) ? '!' : tokenVal,
				String(tgChat.value || '').trim(),
				tgMute.checked ? '1' : '0',
				tgPushHs.checked ? '1' : '0',
				tgPushWd.checked ? '1' : '0',
				tgPushLr.checked ? '1' : '0',
				tgPushSv.checked ? '1' : '0',
				tgPushCt.checked ? '1' : '0',
				String(tgPoll.value || '25'),
				String(tgPival.value || '2')
			).then(function(r) {
				dom.content(tgResult, E('p', { 'class': 'hpui-hint' },
					(!r || r.result === false)
						? [ E('span', { 'class': 'hpui-c-red' }, [ _('Save failed: ') + ((r && r.error) || _('rpc error')) ]) ]
						: [ E('span', { 'class': 'hpui-c-green' }, [ _('Saved. The bot re-reads its settings within ~15 s — no service restart needed.') ]) ]));
				if (r && r.result !== false)
					tgClearToken.checked = false;
				return checkTelegram();
			}).finally(function() { tgSaveBtn.disabled = false; });
		});

		tgTestBtn.addEventListener('click', function() {
			tgTestBtn.disabled = true;
			dom.content(tgResult, E('p', { 'class': 'hpui-hint' }, [ _('Checking...') ]));
			L.resolveDefault(callTelegramTest(), {}).then(function(r) {
				let txt;
				if (r && r.bot_username)
					txt = _('Bot: @') + r.bot_username;
				else
					txt = _('Bot check failed');
				if (r && r.result !== false) {
					if (r.sent === true)
						txt += ' · ' + _('test message sent — check your chat');
					else if (r.error === 'no chat yet')
						txt += ' · ' + _('no chat bound yet — send any message to the bot first');
					else if (r.sent === false)
						txt += ' · ' + _('test message NOT sent');
				} else {
					txt += ((r && r.error) ? (' · ' + r.error) : '');
				}
				dom.content(tgResult, E('p', { 'class': 'hpui-hint' }, [ txt ]));
				return checkTelegram();
			}).finally(function() { tgTestBtn.disabled = false; });
		});

		tgCheckBtn.addEventListener('click', function() {
			tgCheckBtn.disabled = true;
			checkTelegram().finally(function() { tgCheckBtn.disabled = false; });
		});

		const diagCard = E('div', { 'class': 'tg-card' }, [
			E('div', { 'class': 'tg-card-title' }, [ _('Diagnostics') ]),
			E('div', { 'class': 'wiz-toolbar', style: 'margin:0' }, [ tgSaveBtn, tgTestBtn, tgCheckBtn ]),
			tgResult
		]);

		/* ── commands hint ──────────────────────────────────────────── */
		const cmdPanel = E('div', { 'class': 'hpui-panel', style: 'margin-top:14px' }, [
			E('p', { 'class': 'hpui-hint' },
				[ _('Remote control from your Telegram chat. Router: /status, /nodes, /switch N (switches the exit without a restart), /service, /snapshot, /status_engine, /connections, /close. Parental control: /menu (everything in buttons), /devices (block / temporary block / temporary allow / Wi-Fi block), /blocksite, /pause, /resume, /wifi. Push notifications watch the router state files; the daemon always runs and re-reads these settings on its own, so saving never restarts the service. Get the token from @BotFather; the first message to the bot binds your chat.') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('Pushes: Hot Swap node changes, dead URLTest nodes (and recoveries), automation learning and self-heals, core faults — and everything of the parental control (blocks, temporary blocks/allow expiries, schedule windows, Wi-Fi, new devices on the network). "Mute" silences pushes only — commands keep working.') ])
		]);

		return E('div', {}, [
			E('h4', { style: 'margin:6px 0 0 0' }, [ _('Telegram Bot') ]),
			tgStatusCard,
			connCard,
			pushesCard,
			diagCard,
			cmdPanel
		]);
	}
});
