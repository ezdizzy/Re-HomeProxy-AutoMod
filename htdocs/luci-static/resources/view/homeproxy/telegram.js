/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Ravnex — страница «Telegram-бот» (plan 15): all bot settings
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
'require poll';
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
		'push_hotswap', 'push_watchdog', 'push_learn', 'push_service', 'push_control', 'push_exec',
		'push_health', 'push_autopilot', 'push_safe', 'push_update', 'push_security',
		'quiet_enabled', 'quiet_from', 'quiet_to',
		'poll_timeout', 'push_interval'
	],
	expect: { '': {} }
});

const callTelegramTest = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_test',
	expect: { '': {} }
});

/* Ф8.7: «прислать пример» категории — rpcd sends an honest sample push. */
const callTelegramPreview = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_preview',
	params: [ 'category' ],
	expect: { '': {} }
});

/* Ф8.1 security core: one-time 60 s pairing code + RBAC user management. */
const callTelegramPairGen = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_pair_generate',
	params: [ 'role' ],
	expect: { '': {} }
});

const callTelegramUserRemove = rpc.declare({
	object: 'luci.homeproxy',
	method: 'telegram_user_remove',
	params: [ 'user' ],
	expect: { '': {} }
});

const CSS = `
	.tg-card { border: 1px solid var(--hp-panel-line); border-radius: var(--hp-radius-lg); padding: 14px 16px; background: var(--hp-panel-bg-2); margin-top: 14px; box-shadow: var(--hp-shadow); }
	.tg-card-title { font-weight: 700; font-size: 1.02em; margin-bottom: 10px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
	.tg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px 18px; margin-top: 6px; }
	.tg-field { display: flex; flex-direction: column; gap: 4px; min-width: 200px; }
	.tg-field > label { font-size: .82em; font-weight: 600; opacity: .75; }
	.tg-toggle { display: flex; align-items: center; gap: 8px; font-weight: 600; cursor: pointer; }
	.tg-toggle input { width: 17px; height: 17px; cursor: pointer; }
	.tg-check { display: flex; align-items: flex-start; gap: 7px; cursor: pointer; line-height: 1.35; padding: 3px 0; }
	.tg-check input { margin-top: 2px; cursor: pointer; flex: none; }
	.tg-push-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
	.tg-push-row .tg-check { flex: 1 1 auto; min-width: 0; }
	.tg-prev-btn { flex: none; padding: 2px 10px; font-size: .86em; }
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
		hp.uiShell();

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
		const tgPushEx = E('input', { type: 'checkbox' });
		/* Ф8.7: новые категории + окно тихих часов. */
		const tgPushHl = E('input', { type: 'checkbox' });
		const tgPushAp = E('input', { type: 'checkbox' });
		const tgPushSf = E('input', { type: 'checkbox' });
		const tgPushUp = E('input', { type: 'checkbox' });
		const tgPushSc = E('input', { type: 'checkbox' });
		const tgQuietEn = E('input', { type: 'checkbox' });
		const tgQFrom = E('input', { type: 'text', 'class': 'cbi-input-text', style: 'width:90px', placeholder: '23:00' });
		const tgQTo = E('input', { type: 'text', 'class': 'cbi-input-text', style: 'width:90px', placeholder: '08:00' });
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
		tgPushEx.checked = tgB('push_exec', '1');
		/* Ф8.7: новые категории (по умолчанию включены) + тихие часы. */
		tgPushHl.checked = tgB('push_health', '1');
		tgPushAp.checked = tgB('push_autopilot', '1');
		tgPushSf.checked = tgB('push_safe', '1');
		tgPushUp.checked = tgB('push_update', '1');
		tgPushSc.checked = tgB('push_security', '1');
		tgQuietEn.checked = tgB('quiet_enabled', '0');
		tgQFrom.value = tgU('quiet_from', '23:00');
		tgQTo.value = tgU('quiet_to', '08:00');
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

	/* ── pushes card ──────────────────────────────────────────────
	 * Ф8.7: 11 категорий, у каждой — «Пример» (честный образец пуша
	 * уходит в чат). Результат действий карточки — в pshResult (одно
	 * место, заменяет предыдущий). Критические алерты проходят любой
	 * тумблер и тихие часы — инвариант безопасности. */
	const pshResult = E('div', {});

	function pushRow(cb, cat, label, hint) {
		const btn = E('button', {
			'class': 'btn cbi-button cbi-button-apply tg-prev-btn',
			type: 'button', title: _('Send a sample push of this category to your chat')
		}, [ _('Sample') ]);
		btn.addEventListener('click', function() {
			btn.disabled = true;
			L.resolveDefault(callTelegramPreview(cat), {}).then(function(r) {
				dom.content(pshResult, E('p', { 'class': 'hpui-hint' },
					(!r || r.result === false)
						? [ E('span', { 'class': 'hpui-c-red' }, [ _('Sample failed: ') + ((r && r.error) || _('rpc error')) ]) ]
						: (r.sent === true)
							? [ E('span', { 'class': 'hpui-c-green' }, [ _('Sample sent — check your chat.') ]) ]
							: [ E('span', { 'class': 'hpui-c-amber' }, [ _('Sample NOT sent: ') + ((r && r.error) || '?') ]) ]));
			}).finally(function() { btn.disabled = false; });
		});
		return E('div', { 'class': 'tg-push-row' }, [
			E('label', { 'class': 'tg-check' }, [ cb, E('span', {}, [ label ]) ]),
			btn
		]);
	}

	const pushesCard = E('div', { 'class': 'tg-card' }, [
		E('div', { 'class': 'tg-card-title' }, [
			_('Push notifications'),
			E('span', { 'class': 'hpui-hint', style: 'font-weight:400' }, [ _('Pushes watch the router state files; "Mute" silences pushes only — commands keep working.') ])
		]),
		E('label', { 'class': 'tg-toggle' }, [ tgMute, E('span', {}, [ _('Mute push notifications') ]) ]),
		E('div', { 'class': 'tg-grid', style: 'margin-top:10px' }, [
			pushRow(tgPushHs, 'hotswap', _('Hot Swap node changes / failback')),
			pushRow(tgPushWd, 'watchdog', _('URLTest dead nodes')),
			pushRow(tgPushLr, 'learn', _('Automation learned blocks')),
			pushRow(tgPushSv, 'service', _('Service faults')),
			pushRow(tgPushCt, 'control', _('Control: blocks, schedules, Wi-Fi, new devices')),
			pushRow(tgPushEx, 'exec', _('Arbitrary commands (/cmd) results')),
			pushRow(tgPushHl, 'health', _('Health & watchdog: subsystem statuses, Sentinel repairs, Recovery')),
			pushRow(tgPushAp, 'autopilot', _('Auto-pilot strategy decisions')),
			pushRow(tgPushSf, 'safe', _('Safe Mode on/off (egress to direct)')),
			pushRow(tgPushUp, 'update', _('Update results (background core install)')),
			pushRow(tgPushSc, 'security', _('Security: pairing codes, RBAC changes'))
		]),
		E('div', { 'class': 'tg-inline', style: 'margin-top:10px' }, [
			E('span', { 'class': 'tg-sub' }, [ _('Min gap between pushes, s') ]),
			tgPival
		]),
		E('div', { 'class': 'tg-quiet', style: 'margin-top:14px; border-top:1px solid var(--hp-panel-line); padding-top:12px' }, [
			E('label', { 'class': 'tg-toggle' }, [ tgQuietEn, E('span', {}, [ _('Quiet hours') ]) ]),
			E('div', { 'class': 'tg-inline', style: 'margin-top:8px' }, [
				E('span', { 'class': 'tg-sub' }, [ _('Window start (HH:MM)') ]),
				tgQFrom,
				E('span', { 'class': 'tg-sub' }, [ _('Window end (HH:MM)') ]),
				tgQTo,
				E('span', { 'class': 'tg-sub' }, [ _('(local router time)') ])
			]),
			E('p', { 'class': 'hpui-hint tg-sub', style: 'margin-top:6px' },
				[ _('During the window normal pushes of ALL categories are held back and counted; they are reported on the next delivered push. CRITICAL alerts (core down, subscription rollback, recovery blocked) always break through — the safety invariant. Equal from/to = window off.') ])
		]),
		pshResult
	]);

		/* ── access card (Ф8.1): pairing + RBAC users ────────────────────
		 * One result area (rbResult) for both actions; the live code and
		 * the user table are status views refreshed by the poll. */
		const tgRole = E('select', { 'class': 'cbi-input-select', style: 'width:auto' });
		const roleOpts = [
			[ 'owner', _('Owner — full access') ],
			[ 'admin', _('Admin — service, snapshots, rules') ],
			[ 'operator', _('Operator — nodes, pause, temporary actions') ],
			[ 'viewer', _('Viewer — status only') ]
		];
		for (let i = 0; i < roleOpts.length; i++)
			tgRole.appendChild(E('option', { value: roleOpts[i][0] }, [ roleOpts[i][1] ]));
		const pairBtn = E('button', { 'class': 'btn cbi-button cbi-button-action', type: 'button' },
			[ _('Generate pairing code') ]);
		const pairLine = E('span', { 'class': 'hpui-hint' });
		const rbUsersBox = E('div', {});
		const rbResult = E('div', {});

		function renderRbac(st) {
			st = st || {};
			const p = st.pair || null;
			if (p && p.code)
				dom.content(pairLine, [
					document.createTextNode(_('Active code: %s · role %s · expires in %d s')
						.format(String(p.code), String(p.role || ''), p.expires_in || 0))
				]);
			else
				dom.content(pairLine, [ _('No active code — generate one to pair a user.') ]);
			const u = st.users || {};
			const rows = [
				[ 'owner', u.owner ], [ 'admin', u.admin ],
				[ 'operator', u.operator ], [ 'viewer', u.viewer ]
			];
			const tbl = E('table', { 'class': 'table', style: 'max-width:560px' });
			let any = false;
			for (let i = 0; i < rows.length; i++) {
				const role = rows[i][0];
				const ids = rows[i][1] || [];
				for (let k = 0; k < ids.length; k++) {
					any = true;
					const idStr = String(ids[k]);
					const del = E('button', { 'class': 'btn cbi-button cbi-button-remove', type: 'button' }, [ '✖' ]);
					del.addEventListener('click', function() {
						del.disabled = true;
						L.resolveDefault(callTelegramUserRemove(idStr), {}).then(function(r) {
							dom.content(rbResult, E('p', { 'class': 'hpui-hint' },
								(!r || r.result === false)
									? [ E('span', { 'class': 'hpui-c-red' }, [ _('Removal failed: ') + ((r && r.error) || _('rpc error')) ]) ]
									: [ E('span', { 'class': 'hpui-c-green' }, [ _('Removed (%d).').format(r.removed || 0) ]) ]));
							return rbRefresh();
						}).finally(function() { del.disabled = false; });
					});
					tbl.appendChild(E('tr', {}, [
						E('td', {}, [ role ]),
						E('td', {}, [ idStr ]),
						E('td', {}, [ del ])
					]));
				}
			}
			if (!any)
				tbl.appendChild(E('tr', {}, [
					E('td', { colspan: '3', style: 'opacity:.75' },
						[ _('No paired users yet — the bound owner chat keeps working (legacy mode).') ])
				]));
			dom.content(rbUsersBox, [ tbl ]);
		}

		function rbRefresh() {
			return L.resolveDefault(callTelegramStatus(), {}).then(function(st) {
				renderTelegramStatus(st || {});
				renderRbac(st || {});
			});
		}

		pairBtn.addEventListener('click', function() {
			pairBtn.disabled = true;
			L.resolveDefault(callTelegramPairGen(String(tgRole.value || 'owner')), {}).then(function(r) {
				if (!r || r.result === false)
					dom.content(rbResult, E('p', { 'class': 'hpui-hint' },
						[ _('Code generation failed: ') + ((r && r.error) || _('rpc error')) ]));
				else
					dom.content(rbResult, E('p', { 'class': 'hpui-hint' },
						[ _('Code %s generated (role %s) — valid 60 s, one-time. The user sends it to the bot as a message: /start %s (or just the code).').format(String(r.code), String(r.role || ''), String(r.code)) ]));
				return rbRefresh();
			}).finally(function() { pairBtn.disabled = false; });
		});

		const rbCard = E('div', { 'class': 'tg-card' }, [
			E('div', { 'class': 'tg-card-title' }, [ _('Access (RBAC)') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('Roles from top to bottom: Owner (everything) → Admin (service, snapshots, rules) → Operator (nodes, pause, temporary actions) → Viewer (status only). Every command and button is checked against the sender\'s user_id; groups and channels are denied by default. Pairing: generate a one-time 60 s code here, the user sends it to the bot from a private chat.') ]),
			E('div', { 'class': 'tg-inline' }, [ tgRole, pairBtn, pairLine ]),
			rbUsersBox,
			rbResult
		]);
		renderRbac(st0);

		poll.add(rbRefresh, 12);

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
				tgPushEx.checked ? '1' : '0',
				/* Ф8.7: новые категории + окно тихих часов. */
				tgPushHl.checked ? '1' : '0',
				tgPushAp.checked ? '1' : '0',
				tgPushSf.checked ? '1' : '0',
				tgPushUp.checked ? '1' : '0',
				tgPushSc.checked ? '1' : '0',
				tgQuietEn.checked ? '1' : '0',
				String(tgQFrom.value || '').trim(),
				String(tgQTo.value || '').trim(),
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
			E('div', { 'class': 'tg-inline', style: 'margin:0' }, [ tgSaveBtn, tgTestBtn, tgCheckBtn ]),
			tgResult
		]);

		/* ── commands hint ──────────────────────────────────────────── */
		const cmdPanel = E('div', { 'class': 'hpui-panel', style: 'margin-top:14px' }, [
			E('p', { 'class': 'hpui-hint' },
				[ _('Remote control from your Telegram chat. Router: /status, /nodes, /switch N (switches the exit without a restart), /service, /snapshot, /status_engine, /connections, /close. Parental control: /menu (everything in buttons), /devices (block / temporary block / temporary allow / Wi-Fi block), /blocksite, /pause, /resume, /wifi. Push notifications watch the router state files; the daemon always runs and re-reads these settings on its own, so saving never restarts the service. Get the token from @BotFather; the first message to the bot binds your chat.') ]),
			E('p', { 'class': 'hpui-hint' },
				[ _('Pushes: Hot Swap node changes, dead URLTest nodes (and recoveries), automation learning and self-heals, core faults — and everything of the parental control (blocks, temporary blocks/allow expiries, schedule windows, Wi-Fi, new devices on the network). Categories also cover health/watchdog repairs, auto-pilot decisions, Safe Mode on/off, background update results and pairing/RBAC security events — each with its own toggle and a "Sample" button. "Mute" silences pushes only — commands keep working.') ])
		]);

		return E('div', {}, [
			hp.pageIntro(_('Phone control'),
				_('Control the router from your Telegram chat: live status, exit switching, snapshots, parental-control actions — with per-category pushes you can mute, quiet-hour or sample first. Pairing codes and roles keep strangers out.')),
			tgStatusCard,
			connCard,
			pushesCard,
			rbCard,
			diagCard,
			cmdPanel
		]);
	}
});
