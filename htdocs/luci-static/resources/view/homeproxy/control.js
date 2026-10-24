/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024-2026 1andrevich
 *
 * Re:HomeProxy AutoMod — вкладка «Контроль» (HomeControl integration,
 * plan 14): advanced parental control for the LAN — client blocks with
 * DHCP-change tracking (identity = MAC, the current IP is resolved from
 * the lease file at apply time), site rules (domains/IPs, whole network
 * or selected clients, time/date windows, temporary pause), schedules
 * (daily/weekly/range/timer for clients and Wi-Fi), Wi-Fi switching and
 * an events journal. Everything is ALSO drivable from the Telegram bot
 * (/control /devices /blocksite /pause /resume /wifi) — this view and
 * the bot share the same UCI state and the same enforcer
 * (control_apply.uc via the always-on control engine).
 *
 * Design: hpui-* (hp.uiStyle()), results of every action render in ONE
 * place per pane (below the actions), live data polls every 4 s.
 */

'use strict';
'require dom';
'require poll';
'require rpc';
'require ui';
'require view';
'require homeproxy as hp';

const callStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_status',
	expect: { '': {} }
});

const callDevices = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_devices',
	expect: { '': {} }
});

const callSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_set',
	params: [ 'enabled' ],
	expect: { '': {} }
});

const callSetPaused = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_set_paused',
	params: [ 'paused' ],
	expect: { '': {} }
});

const callClientAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_add',
	params: [ 'name', 'mac', 'ip' ],
	expect: { '': {} }
});

const callClientDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_delete',
	params: [ 'id' ],
	expect: { '': {} }
});

const callClientRename = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_rename',
	params: [ 'id', 'name' ],
	expect: { '': {} }
});

const callClientBlock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_block',
	params: [ 'id', 'blocked' ],
	expect: { '': {} }
});

const callClientTempBlock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_temp_block',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callClientTempUnblock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_temp_unblock',
	params: [ 'id' ],
	expect: { '': {} }
});

const callClientTempAllow = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_temp_allow',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callClientWifiBlock = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_client_wifi_block',
	params: [ 'id', 'blocked' ],
	expect: { '': {} }
});

const callRuleAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_rule_add',
	params: [ 'name', 'type', 'targets', 'client_ids', 'time_start', 'time_stop', 'days', 'date_start', 'date_stop' ],
	expect: { '': {} }
});

const callRuleDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_rule_delete',
	params: [ 'id' ],
	expect: { '': {} }
});

const callRuleToggle = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_rule_toggle',
	params: [ 'id', 'enabled' ],
	expect: { '': {} }
});

const callRulePause = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_rule_pause',
	params: [ 'id', 'minutes' ],
	expect: { '': {} }
});

const callRuleResume = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_rule_resume',
	params: [ 'id' ],
	expect: { '': {} }
});

const callScheduleAdd = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_schedule_add',
	params: [ 'name', 'type', 'action', 'time_start', 'time_stop', 'days', 'date_start', 'date_stop', 'client_ids', 'wifi_ids' ],
	expect: { '': {} }
});

const callScheduleDelete = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_schedule_delete',
	params: [ 'id' ],
	expect: { '': {} }
});

const callScheduleToggle = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_schedule_toggle',
	params: [ 'id', 'enabled' ],
	expect: { '': {} }
});

const callWifiStatus = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_wifi_status',
	expect: { '': {} }
});

const callWifiSet = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_wifi_set',
	params: [ 'iface', 'disabled' ],
	expect: { '': {} }
});

const callWifiTemp = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_wifi_temp',
	params: [ 'iface', 'minutes' ],
	expect: { '': {} }
});

const callWifiTempClear = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_wifi_temp_clear',
	params: [ 'iface' ],
	expect: { '': {} }
});

const callEvents = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_events',
	params: [ 'limit' ],
	expect: { '': {} }
});

const callEventsClear = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_events_clear',
	expect: { '': {} }
});

const callLogTail = rpc.declare({
	object: 'luci.homeproxy',
	method: 'control_log_tail',
	params: [ 'lines' ],
	expect: { '': {} }
});

/* Offline service catalog for quick site-rule targets (D5: no runtime
 * fetches — plain data shipped with the view). Plan 15: expanded catalog
 * grouped by category, with in-catalog search. */
const SERVICE_GROUPS = [
	{ name: _('Messengers'), items: [
		{ name: 'Telegram', domains: [ 'telegram.org', 't.me', 'web.telegram.org', 'telesco.pe', 'cdn-telegram.org' ] },
		{ name: 'WhatsApp', domains: [ 'whatsapp.com', 'wa.me', 'whatsapp.net' ] },
		{ name: 'Viber', domains: [ 'viber.com', 'viber.net' ] },
		{ name: 'Discord', domains: [ 'discord.com', 'discordapp.com', 'discordapp.net', 'discord.gg', 'discord.media' ] },
		{ name: 'Snapchat', domains: [ 'snapchat.com', 'sc-cdn.net' ] },
		{ name: 'Signal', domains: [ 'signal.org' ] },
		{ name: 'Threads', domains: [ 'threads.net', 'threads.com' ] }
	] },
	{ name: _('Social networks'), items: [
		{ name: 'Instagram', domains: [ 'instagram.com', 'cdninstagram.com', 'instagr.am', 'igcdn.com' ] },
		{ name: 'Facebook', domains: [ 'facebook.com', 'fbcdn.net', 'fb.com', 'messenger.com' ] },
		{ name: 'Twitter / X', domains: [ 'twitter.com', 'x.com', 'twimg.com', 't.co' ] },
		{ name: 'Reddit', domains: [ 'reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com' ] },
		{ name: 'Pinterest', domains: [ 'pinterest.com', 'pinimg.com' ] },
		{ name: 'Tumblr', domains: [ 'tumblr.com' ] }
	] },
	{ name: _('Video & music'), items: [
		{ name: 'YouTube', domains: [ 'youtube.com', 'youtube-nocookie.com', 'googlevideo.com', 'ytimg.com', 'youtu.be' ] },
		{ name: 'TikTok', domains: [ 'tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'muscdn.com', 'musical.ly', 'byteoversea.com' ] },
		{ name: 'Twitch', domains: [ 'twitch.tv', 'twitchcdn.net', 'ttvnw.net', 'jtvnw.net' ] },
		{ name: 'Netflix', domains: [ 'netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxso.net' ] },
		{ name: 'Kick', domains: [ 'kick.com', 'kickcdn.com' ] },
		{ name: 'Spotify', domains: [ 'spotify.com', 'scdn.co', 'spotifycdn.com' ] }
	] },
	{ name: _('Gaming platforms'), items: [
		{ name: 'Steam', domains: [ 'steampowered.com', 'steamcommunity.com', 'steamcontent.com', 'steamstatic.com' ] },
		{ name: 'Epic Games', domains: [ 'epicgames.com', 'epicgames.dev', 'unrealengine.com' ] },
		{ name: 'Roblox', domains: [ 'roblox.com', 'rbxcdn.com', 'robloxcdn.com' ] },
		{ name: 'Minecraft', domains: [ 'minecraft.net', 'mojang.com', 'minecraftservices.com' ] },
		{ name: 'Battle.net', domains: [ 'battle.net', 'blizzard.com', 'battlenet.com' ] },
		{ name: 'Riot Games', domains: [ 'riotgames.com', 'leagueoflegends.com', 'valorant.com' ] },
		{ name: 'EA', domains: [ 'ea.com', 'origin.com' ] },
		{ name: 'Ubisoft', domains: [ 'ubisoft.com', 'ubi.com' ] },
		{ name: 'Rockstar', domains: [ 'rockstargames.com' ] },
		{ name: 'GOG', domains: [ 'gog.com', 'gogstatic.com' ] },
		{ name: 'PlayStation', domains: [ 'playstation.com', 'playstation.net' ] },
		{ name: 'Xbox', domains: [ 'xbox.com', 'xboxlive.com', 'xboxservices.com' ] }
	] },
	{ name: _('Russia: social & video'), items: [
		{ name: 'ВКонтакте', domains: [ 'vk.com', 'userapi.com', 'vkuser.net', 'vk-cdn.net' ] },
		{ name: 'Одноклассники', domains: [ 'ok.ru', 'odnoklassniki.ru', 'mycdn.me' ] },
		{ name: 'Rutube', domains: [ 'rutube.ru' ] },
		{ name: 'Яндекс Музыка', domains: [ 'music.yandex.ru', 'music.yandex.by' ] },
		{ name: 'Звук', domains: [ 'zvuk.com' ] },
		{ name: 'Кинопоиск', domains: [ 'kinopoisk.ru' ] },
		{ name: 'Ivi', domains: [ 'ivi.ru', 'ivi.tv' ] }
	] },
	{ name: _('18+: adult'), items: [
		{ name: 'Pornhub', domains: [ 'pornhub.com', 'phncdn.com' ] },
		{ name: 'XVideos', domains: [ 'xvideos.com', 'xvideos-cdn.com' ] },
		{ name: 'xHamster', domains: [ 'xhamster.com', 'xhcdn.com' ] },
		{ name: 'OnlyFans', domains: [ 'onlyfans.com' ] },
		{ name: 'Chaturbate', domains: [ 'chaturbate.com', 'highwebmedia.com' ] }
	] },
	{ name: _('18+: betting & casinos'), items: [
		{ name: '1xBet', domains: [ '1xbet.com' ] },
		{ name: 'Fonbet', domains: [ 'fonbet.ru', 'fon.bet' ] },
		{ name: 'Bet365', domains: [ 'bet365.com' ] },
		{ name: 'Stake', domains: [ 'stake.com' ] }
	] }
];

const DAYS = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ];

const CSS = `
	.ct-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 12px; margin-top: 10px; }
	.ct-card { border: 1px solid rgba(128,128,128,.3); border-radius: 10px; padding: 12px 14px; background: rgba(127,127,127,.04); }
	.ct-card.ct-blocked { border-left: 5px solid #e05252; }
	.ct-card.ct-allowed { border-left: 5px solid #3fbf5f; }
	.ct-card.ct-offline { opacity: .68; }
	.ct-name { font-weight: 600; font-size: 1.05em; margin-bottom: 2px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
	.ct-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }
	.ct-dot.on { background: #3fbf5f; box-shadow: 0 0 4px #3fbf5f; }
	.ct-dot.off { background: #999; }
	.ct-meta { color: #888; font-size: .85em; margin-bottom: 10px; word-break: break-all; }
	.ct-actions { display: flex; gap: 6px; flex-wrap: wrap; }
	.ct-actions .btn { flex: none; }
	.ct-field { display: flex; flex-direction: column; gap: 4px; min-width: 160px; flex: 1 1 160px; }
	.ct-field > label { font-size: .82em; font-weight: 600; opacity: .75; }
	.ct-field > input, .ct-field > select { width: 100%; max-width: 420px; box-sizing: border-box; }
	.ct-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; }
	.ct-form .ct-wide { flex: 3 1 320px; }
	.ct-chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0; }
	.ct-chip { appearance: none; cursor: pointer; border: 1px solid rgba(128,128,128,.4); border-radius: 12px; background: rgba(128,128,128,.10); color: inherit; padding: 3px 10px; font-size: .85em; }
	.ct-chip:hover { background: rgba(128,128,128,.22); }
	.ct-days { display: flex; gap: 10px; flex-wrap: wrap; }
	.ct-days label { display: inline-flex; align-items: center; gap: 4px; white-space: nowrap; }
	.ct-toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; }
	.ct-targets-row { margin-top: 8px; }
	.ct-targets { width: 100%; min-height: 120px; max-height: 460px; resize: vertical; box-sizing: border-box; display: block; background: rgba(127,127,127,.05); border: 1px solid rgba(128,128,128,.4); border-radius: 8px; color: inherit; padding: 8px 10px; font-size: .95em; line-height: 1.45; }
	.ct-targets:focus { outline: none; border-color: rgba(63,191,95,.6); }
	.ct-catalog { max-height: 320px; overflow-y: auto; border: 1px solid rgba(128,128,128,.25); border-radius: 10px; padding: 6px 12px 10px; background: rgba(127,127,127,.04); }
	.ct-cat-head { font-weight: 600; font-size: .78em; text-transform: uppercase; letter-spacing: .05em; opacity: .6; margin: 10px 0 4px; }
	.ct-search { width: 100%; box-sizing: border-box; margin: 8px 0 2px; }
	.ct-badge-wifi { margin-left: 6px; }
	.ct-result-wrap { margin-top: 6px; }
	.ct-head { display: flex; flex-direction: column; gap: 12px; }
	.ct-head .ct-toolbar { margin-bottom: 0; }
	.ct-head .hpui-banner { margin-top: 0; }
`;

/* ── formatting helpers ──────────────────────────────────────────────── */

function fmtRemaining(untilSec) {
	const ms = untilSec * 1000 - Date.now();
	const m = Math.max(0, Math.round(ms / 60000));
	if (m < 60)
		return m + ' ' + _('min');
	const h = Math.floor(m / 60), mm = m % 60;
	if (h < 24)
		return h + ' ' + _('h') + (mm ? (' ' + mm + ' ' + _('min')) : '');
	const d = Math.floor(h / 24);
	return d + ' ' + _('d') + ' ' + (h % 24) + ' ' + _('h');
}

function fmtMinutesHuman(mins) {
	if (mins >= 1440 && (mins % 1440) === 0)
		return (mins / 1440) + ' ' + _('d');
	if (mins >= 60 && (mins % 60) === 0)
		return (mins / 60) + ' ' + _('h');
	return mins + ' ' + _('min');
}

function dayLabels() {
	return DAYS.map(function(d) { return _(d); });
}

function daysText(days) {
	const labels = dayLabels();
	const out = [];
	for (let i = 0; i < DAYS.length; i++)
		if (days.indexOf(DAYS[i]) !== -1)
			out.push(labels[i]);
	return out.length ? out.join(', ') : _('every day');
}

function clientName(c) {
	return c.name || c.hostname || c.ip || c.mac || '?';
}

function stateBadge(c) {
	if (!c.blocked)
		return E('span', { 'class': 'hpui-badge hpui-b-green' }, [ _('Allowed') ]);
	if (c.reason === 'temp')
		return E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('Temp block') ]);
	if (c.reason === 'schedule')
		return E('span', { 'class': 'hpui-badge hpui-b-blue' }, [ _('Schedule') ]);
	return E('span', { 'class': 'hpui-badge hpui-b-red' }, [ _('Blocked') ]);
}

function stateText(c) {
	if (!c.blocked) {
		if (c.allow_until)
			return _('temporarily allowed until') + ' ' + fmtRemaining(c.allow_until);
		return _('allowed now');
	}
	if (c.reason === 'temp')
		return _('temporarily blocked until') + ' ' + fmtRemaining(c.until || 0);
	if (c.reason === 'schedule')
		return _('blocked by a schedule window');
	return _('blocked manually');
}

/* Shared custom-time modal (minutes/hours/days). onOk(minutes). */
function customTimeModal(title, defMinutes, onOk) {
	const inVal = E('input', { 'type': 'number', 'min': '1', 'class': 'cbi-input-text', 'value': String(defMinutes) });
	const selUnit = E('select', { 'class': 'cbi-input-select' }, [
		E('option', { 'value': '1' }, [ _('minutes') ]),
		E('option', { 'value': '60', 'selected': 'selected' }, [ _('hours') ]),
		E('option', { 'value': '1440' }, [ _('days') ])
	]);
	const row = E('div', { 'style': 'display:flex; gap:8px; align-items:center' }, [ inVal, selUnit ]);

	ui.showModal(title, [
		E('p', {}, [ _('Access will be restored automatically when the time is up.') ]),
		row,
		E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
			E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
			E('button', {
				'class': 'btn cbi-button-positive important',
				'click': function() {
					const v = parseInt(inVal.value, 10);
					const u = parseInt(selUnit.value, 10);
					if (!v || v < 1) {
						ui.addNotification('error', _('Enter a positive number'));
						return;
					}
					ui.hideModal();
					onOk(v * u);
				}
			}, [ _('Apply') ])
		])
	]);
}

return view.extend({
	load() {
		return Promise.all([
			L.resolveDefault(callStatus(), null),
			L.resolveDefault(callDevices(), null),
			L.resolveDefault(callWifiStatus(), null)
		]);
	},

	/* UCI is driven through RPC (control_set, control_client_…, control_rule_…) —
	 * the LuCI save footer (Apply/Save/Reset) has nothing to act on here;
	 * suppress it so it does not dangle under the empty result area. */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	render(data) {
		hp.uiStyle();

		const st = document.getElementById('hp-ctrl-style');
		if (!st)
			document.head.appendChild(E('style', { id: 'hp-ctrl-style' }, [ CSS ]));

		/* Shared live state (updated by the 4 s poll). */
		const S = {
			status: data[0] || { result: false, clients: [], schedules: [], rules: [], stats: {}, dns_filters: {}, wifi_temps: {} },
			devices: (data[1] && data[1].devices) || [],
			wifi: data[2] || { radios: [], temps: {} }
		};

		/* ── Tab frame (wizard pattern) ─────────────────────────────── */
		const TABS = [
			[ 'dash', _('Dashboard') ],
			[ 'devices', _('Devices') ],
			[ 'rules', _('Site rules') ],
			[ 'sched', _('Schedules') ],
			[ 'wifi', _('Wi-Fi') ],
			[ 'journal', _('Journal') ],
			[ 'settings', _('Settings') ]
		];
		const panes = {};
		for (let t in TABS)
			panes[TABS[t][0]] = E('div', { 'class': 'hpui-pane' });
		const tabBar = E('div', { 'class': 'hpui-tabs' });
		for (let i in TABS) {
			const idx = parseInt(i, 10);
			const key = TABS[i][0];
			const b = E('button', {
				'class': 'hpui-tab' + (idx === 0 ? ' active' : ''),
				type: 'button'
			}, [ TABS[i][1] ]);
			b.addEventListener('click', function() {
				for (let k in panes)
					panes[k].classList.toggle('active', k === key);
				for (let j = 0; j < tabBar.children.length; j++)
					tabBar.children[j].classList.toggle('active', j === idx);
				if (key === 'journal')
					refreshJournal();
				if (key === 'wifi')
					refreshWifi();
			});
			tabBar.appendChild(b);
		}
		panes.dash.classList.add('active');

		/* Every pane shows the outcome of its actions in ONE place; the
		 * block stays hidden until the first action (no dead headings). */
		function resultBlock(el) {
			return E('div', { 'class': 'ct-result-wrap', 'style': 'display:none' }, [
				E('h4', {}, [ _('Results') ]),
				el
			]);
		}

		const dashResult = E('div', {});
		const devResult = E('div', {});
		const ruleResult = E('div', {});
		const schedResult = E('div', {});
		const wifiResult = E('div', {});
		const setResult = E('div', {});

		function showResult(el) {
			const w = el.closest('.ct-result-wrap');
			if (w)
				w.style.display = '';
		}

		function note(el, ok, text) {
			showResult(el);
			dom.content(el, E('p', { 'class': 'hpui-hint' }, [
				E('span', { 'class': ok ? 'hpui-c-green' : 'hpui-c-red' }, [ text ])
			]));
		}

		function busy(el, text) {
			showResult(el);
			dom.content(el, E('p', { 'class': 'hpui-hint' }, [ text || _('Please wait…') ]));
		}

		/* Generic act(): RPC call → refresh → one-place result. */
		function act(el, promise, okText) {
			busy(el);
			promise.then(function(r) {
				if (r && r.result === false) {
					note(el, false, (r.error != null) ? String(r.error) : _('Operation failed'));
				} else {
					note(el, true, okText);
				}
				return refreshStatus();
			}).catch(function(e) {
				note(el, false, _('Operation failed') + ': ' + (e && e.message ? e.message : ''));
			});
		}

		/* ── DASHBOARD ──────────────────────────────────────────────── */

		const dashBanner = E('div', { 'class': 'hpui-banner', style: 'display:none' });
		const dashCards = E('div', { 'class': 'hpui-cards' });
		const dashGrid = E('div', { 'class': 'ct-grid' });

		const enableBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', type: 'button' }, [ _('Enable control') ]);
		const pauseBtn = E('button', { 'class': 'btn cbi-button-negative', type: 'button' }, [ _('Pause all (allow everything)') ]);
		enableBtn.addEventListener('click', function() {
			const target = (S.status && S.status.enabled) ? '0' : '1';
			act(dashResult, callSet(target),
				(target === '1') ? _('Control enabled') : _('Control disabled'));
		});
		pauseBtn.addEventListener('click', function() {
			const target = (S.status && S.status.paused) ? '0' : '1';
			act(dashResult, callSetPaused(target),
				(target === '1') ? _('Paused — everything is allowed') : _('Enforcement resumed'));
		});

		function tempBlockModal(c) {
			customTimeModal(_('Temporary block') + ' — ' + clientName(c), 60, function(mins) {
				act(dashResult, callClientTempBlock(c.id, String(mins)),
					_('Temporarily blocked') + ' (' + fmtMinutesHuman(mins) + ')');
			});
		}

		function renderDash() {
			const s = S.status || {};
			const enabled = s.enabled === true;
			const paused = s.paused === true;
			const stats = s.stats || {};

			dashBanner.style.display = '';
			if (!enabled) {
				dashBanner.className = 'hpui-banner';
				dom.content(dashBanner, [ _('Control is disabled — the network is unrestricted.') ]);
			} else if (paused) {
				dashBanner.className = 'hpui-banner hpui-banner-ok';
				dom.content(dashBanner, [ _('PAUSED — everything is allowed. Press "Resume" to re-enable enforcement.') ]);
			} else {
				dashBanner.className = 'hpui-banner hpui-banner-ok';
				dom.content(dashBanner, [ _('Control is active: blocks, site rules and schedules are enforced.') ]);
			}

			enableBtn.textContent = enabled ? _('Disable control') : _('Enable control');
			pauseBtn.textContent = paused ? _('Resume enforcement') : _('Pause all (allow everything)');
			pauseBtn.style.display = enabled ? '' : 'none';

			const cards = [
				{ n: (stats.devices_total != null) ? stats.devices_total : '—', l: _('Devices on the network'), c: 'hpui-c-blue' },
				{ n: (stats.blocked != null) ? stats.blocked : '—', l: _('Blocked now'), c: 'hpui-c-red' },
				{ n: (stats.temp != null) ? stats.temp : '—', l: _('Temporary blocks'), c: 'hpui-c-amber' },
				{ n: (stats.rules != null) ? stats.rules : '—', l: _('Site rules'), c: '' },
				{ n: (stats.schedules != null) ? stats.schedules : '—', l: _('Schedules'), c: '' },
				{ n: (stats.devices_new != null) ? stats.devices_new : '—', l: _('New (unconfigured)'), c: (stats.devices_new > 0) ? 'hpui-c-amber' : 'hpui-c-grey' }
			];
			dom.content(dashCards, cards.map(function(x) {
				return E('div', { 'class': 'hpui-card' }, [
					E('div', { 'class': 'hpui-num ' + x.c }, [ String(x.n) ]),
					E('div', { 'class': 'hpui-cap' }, [ x.l ])
				]);
			}));

			const clients = s.clients || [];
			if (!clients.length) {
				dom.content(dashGrid, E('p', { 'class': 'hpui-hint' }, [
					_('No managed clients yet — add devices on the Devices pane (they can also be picked from the live network list).')
				]));
				return;
			}
			const cards2 = [];
			for (let i = 0; i < clients.length; i++) {
				const c = clients[i];
				const online = c.online === true;
				const card = E('div', { 'class': 'ct-card ' + (c.blocked ? 'ct-blocked' : 'ct-allowed') + (online ? '' : ' ct-offline') });
				card.appendChild(E('div', { 'class': 'ct-name' }, [
					E('span', { 'class': 'ct-dot ' + (online ? 'on' : 'off') }),
					String(clientName(c)),
					stateBadge(c)
				]));
				card.appendChild(E('div', { 'class': 'ct-meta' }, [
					(c.ip ? c.ip : _('no address')) + (c.mac ? ' · ' + c.mac : ''),
					E('br'),
					stateText(c)
				]));
				const actions = E('div', { 'class': 'ct-actions' });
				const blk = E('button', { 'class': 'btn cbi-button-negative', type: 'button',
					title: c.blocked ? _('Allow internet access again') : _('Full internet block for this device (firewall drop)') },
					[ c.blocked ? _('Allow') : _('Block') ]);
				blk.addEventListener('click', function() {
					act(dashResult, callClientBlock(c.id, c.blocked ? '0' : '1'),
						c.blocked ? _('Allowed') : _('Blocked'));
				});
				actions.appendChild(blk);
				const tmp = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Temporary block') }, [ '⏱' ]);
				tmp.addEventListener('click', function() { tempBlockModal(c); });
				actions.appendChild(tmp);
				const alw = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Temporary allow (pokes a hole in the schedule)') }, [ '✅' ]);
				alw.addEventListener('click', function() {
					customTimeModal(_('Temporary allow') + ' — ' + clientName(c), 60, function(mins) {
						act(dashResult, callClientTempAllow(c.id, String(mins)),
							_('Temporarily allowed') + ' (' + fmtMinutesHuman(mins) + ')');
					});
				});
				actions.appendChild(alw);
				if (c.mac) {
					const wfb = E('button', {
						'class': 'btn cbi-button' + (c.wifi_blocked ? ' cbi-button-negative' : ''),
						type: 'button',
						title: c.wifi_blocked ? _('Wi-Fi block is on — click to allow') : _('Block Wi-Fi for this device (wired stays online)')
					}, [ '📶' ]);
					wfb.addEventListener('click', function() {
						act(dashResult, callClientWifiBlock(c.id, c.wifi_blocked ? '0' : '1'),
							c.wifi_blocked ? _('Wi-Fi block removed') : _('Wi-Fi blocked for this device'));
					});
					actions.appendChild(wfb);
				}
				card.appendChild(actions);
				cards2.push(card);
			}
			dom.content(dashGrid, cards2);
		}

		panes.dash.appendChild(E('div', { 'class': 'ct-card ct-head' }, [
			dashBanner,
			E('div', { 'class': 'ct-toolbar' }, [ enableBtn, pauseBtn ])
		]));
		panes.dash.appendChild(dashCards);
		panes.dash.appendChild(E('h4', {}, [ _('Devices') ]));
		panes.dash.appendChild(dashGrid);
		panes.dash.appendChild(resultBlock(dashResult));
		panes.dash.appendChild(E('p', { 'class': 'hpui-hint' }, [
			_('The same actions are available from the Telegram bot: /menu (all in buttons), /devices, /blocksite, /pause, /resume, /wifi. Blocks follow DHCP address changes — devices are tracked by MAC.')
		]));

		/* ── DEVICES ────────────────────────────────────────────────── */

		const devPicker = E('select', { 'class': 'cbi-input-select', 'style': 'min-width:260px' }, [
			E('option', { 'value': '' }, [ '— ' + _('Pick a device from the network') + ' —' ])
		]);
		const devName = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('Alias (e.g. Kid tablet)') });
		const devMac = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'AA:BB:CC:DD:EE:FF' });
		const devIp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': '192.168.1.0 (optional)' });
		const devTable = E('table', { 'class': 'hpui-table' });

		devPicker.addEventListener('change', function() {
			const val = devPicker.value;
			if (!val)
				return;
			for (let i = 0; i < S.devices.length; i++) {
				const d = S.devices[i];
				if ((d.mac || d.ip) !== val)
					continue;
				/* alias never overwrites what the user already typed */
				if (!devName.value)
					devName.value = d.alias || d.hostname || '';
				devMac.value = d.mac || '';
				devIp.value = d.ip || '';
				break;
			}
		});

		function rebuildPicker() {
			const cur = devPicker.value;
			dom.content(devPicker, [
				E('option', { 'value': '' }, [ '— ' + _('Pick a device from the network') + ' —' ])
			]);
			for (let i = 0; i < S.devices.length; i++) {
				const d = S.devices[i];
				const base = d.alias || d.hostname || d.ip || d.mac;
				const label = base + (d.ip && base !== d.ip ? ' (' + d.ip + ')' : '') + (d.configured ? ' ✓' : '');
				devPicker.appendChild(E('option', { 'value': d.mac || d.ip || '' }, [ label ]));
			}
			devPicker.value = (devPicker.querySelector('option[value="' + cur.replace(/"/g, '\\"') + '"]')) ? cur : '';
		}

		const devAddBtn = E('button', { 'class': 'btn cbi-button cbi-button-important', type: 'button' }, [ _('Add device') ]);
		devAddBtn.addEventListener('click', function() {
			const mac = String(devMac.value || '').trim();
			const ip = String(devIp.value || '').trim();
			const name = String(devName.value || '').trim();
			if (!mac && !ip) {
				note(devResult, false, _('MAC or IP is required'));
				return;
			}
			act(devResult, callClientAdd(name, mac, ip), _('Device added'));
			devName.value = ''; devMac.value = ''; devIp.value = ''; devPicker.value = '';
		});

		function renderDevices() {
			rebuildPicker();
			const clients = (S.status && S.status.clients) || [];
			const head = [ _('Device'), _('MAC'), _('IP'), _('State'), _('Online'), _('Actions') ];
			const thead = E('thead', {}, [ E('tr', {}, head.map(function(h) { return E('th', {}, [ h ]); })) ]);
			const tbody = E('tbody', {});
			if (!clients.length) {
				tbody.appendChild(E('tr', {}, [ E('td', { 'colspan': '6' }, [ _('No managed devices yet.') ]) ]));
			}
			for (let i = 0; i < clients.length; i++) {
				const c = clients[i];
				const tdActions = E('td');
				const wrap = E('div', { 'class': 'ct-actions' });
				const blk = E('button', { 'class': 'btn cbi-button-' + (c.blocked ? 'positive' : 'negative'), type: 'button',
					title: c.blocked ? _('Allow internet access again') : _('Full internet block for this device (firewall drop)') },
					[ c.blocked ? _('Allow') : _('Block') ]);
				blk.addEventListener('click', function() {
					act(devResult, callClientBlock(c.id, c.blocked ? '0' : '1'),
						c.blocked ? _('Allowed') : _('Blocked'));
				});
				wrap.appendChild(blk);
				const tmp = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Temporary block') }, [ '⏱' ]);
				tmp.addEventListener('click', function() {
					customTimeModal(_('Temporary block') + ' — ' + clientName(c), 60, function(mins) {
						act(devResult, callClientTempBlock(c.id, String(mins)), _('Temporary block set'));
					});
				});
				wrap.appendChild(tmp);
				if (c.reason === 'temp') {
					const un = E('button', { 'class': 'btn cbi-button-positive', type: 'button', title: _('Remove temporary block') }, [ '↩' ]);
					un.addEventListener('click', function() {
						act(devResult, callClientTempUnblock(c.id), _('Temporary block removed'));
					});
					wrap.appendChild(un);
				}
				const tal = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Temporary allow (pokes a hole in the schedule)') }, [ '✅' ]);
				tal.addEventListener('click', function() {
					customTimeModal(_('Temporary allow') + ' — ' + clientName(c), 60, function(mins) {
						act(devResult, callClientTempAllow(c.id, String(mins)), _('Temporarily allowed'));
					});
				});
				wrap.appendChild(tal);
				if (c.mac) {
					const wfb = E('button', {
						'class': 'btn cbi-button' + (c.wifi_blocked ? ' cbi-button-negative' : ''),
						type: 'button',
						title: c.wifi_blocked ? _('Wi-Fi block is on — click to allow') : _('Block Wi-Fi for this device (wired stays online)')
					}, [ '📶' ]);
					wfb.addEventListener('click', function() {
						act(devResult, callClientWifiBlock(c.id, c.wifi_blocked ? '0' : '1'),
							c.wifi_blocked ? _('Wi-Fi block removed') : _('Wi-Fi blocked for this device'));
					});
					wrap.appendChild(wfb);
				}
				const ren = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Rename') }, [ '✎' ]);
				ren.addEventListener('click', function() {
					const inp = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'value': c.name || '' });
					const go = function() {
						const v = String(inp.value || '').trim();
						if (!v) {
							ui.addNotification('error', _('Enter a name'));
							return;
						}
						ui.hideModal();
						act(devResult, callClientRename(c.id, v), _('Renamed'));
					};
					inp.addEventListener('keydown', function(ev) { if (ev.key === 'Enter') go(); });
					ui.showModal(_('Rename device') + ' — ' + clientName(c), [
						inp,
						E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
							E('button', { 'class': 'btn cbi-button-positive important', 'click': go }, [ _('Apply') ])
						])
					]);
				});
				wrap.appendChild(ren);
				const del = E('button', { 'class': 'btn cbi-button-remove', type: 'button', title: _('Remove') }, [ '✖' ]);
				del.addEventListener('click', function() {
					ui.showModal(_('Remove device'), [
						E('p', {}, [ _('Remove') + ' «' + clientName(c) + '» ' + _('from control?') ]),
						E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
							E('button', { 'class': 'btn cbi-button-negative important', 'click': function() { ui.hideModal(); act(devResult, callClientDelete(c.id), _('Device removed')); } }, [ _('Remove') ])
						])
					]);
				});
				wrap.appendChild(del);
				tdActions.appendChild(wrap);

				tbody.appendChild(E('tr', {}, [
					E('td', {}, [ String(clientName(c)) + (c.hostname && c.name && c.hostname !== c.name ? ' (' + c.hostname + ')' : '') ]),
					E('td', {}, [ c.mac || '—' ]),
					E('td', {}, [ c.ip || '—' ]),
					E('td', {}, [ stateBadge(c), ' ', stateText(c),
						c.wifi_blocked ? E('span', { 'class': 'hpui-badge hpui-b-amber ct-badge-wifi' }, [ '📶 ' + _('Wi-Fi off') ]) : '' ]),
					E('td', {}, [ c.online ? '🟢' : '—' ]),
					tdActions
				]));
			}
			dom.content(devTable, [ thead, tbody ]);
		}

		panes.devices.appendChild(E('p', { 'class': 'hpui-hint' }, [
			_('Devices are identified by MAC: when the DHCP address changes the block follows the device automatically. The current IP is resolved from the DHCP lease file at every apply.')
		]));
		panes.devices.appendChild(E('div', { 'class': 'ct-form' }, [
			E('div', { 'class': 'ct-field ct-wide' }, [ E('label', {}, [ _('From the network') ]), devPicker ]),
			E('div', { 'class': 'ct-field' }, [ E('label', {}, [ _('Alias') ]), devName ]),
			E('div', { 'class': 'ct-field' }, [ E('label', {}, [ _('MAC') ]), devMac ]),
			E('div', { 'class': 'ct-field' }, [ E('label', {}, [ _('IP (static, optional)') ]), devIp ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 auto' }, [ E('label', {}, [ ' ' ]), devAddBtn ])
		]));
		panes.devices.appendChild(E('h4', {}, [ _('Managed devices') ]));
		panes.devices.appendChild(E('div', { 'class': 'hpui-wrap' }, [ devTable ]));
		panes.devices.appendChild(resultBlock(devResult));

		/* ── SITE RULES ─────────────────────────────────────────────── */

		const ruleName = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('Name (optional)') });
		const ruleType = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'domain' }, [ _('Domains') ]),
			E('option', { 'value': 'ip' }, [ _('IP / subnets') ])
		]);
		const ruleTargets = E('textarea', { 'class': 'ct-targets', 'rows': '5', 'placeholder': _('one per line: example.com') + '\n' + _('wildcards: *.example.com') + '\n' + _('for IPs: 1.2.3.4 or 1.2.3.0/24') });
		const ruleT1 = E('input', { 'type': 'time', 'class': 'cbi-input-text', 'value': '' });
		const ruleT2 = E('input', { 'type': 'time', 'class': 'cbi-input-text', 'value': '' });
		const ruleD1 = E('input', { 'type': 'date', 'class': 'cbi-input-text' });
		const ruleD2 = E('input', { 'type': 'date', 'class': 'cbi-input-text' });
		const ruleDaysBox = E('div', { 'class': 'ct-days' });
		const ruleScopeBox = E('div', { 'class': 'ct-days' });
		const ruleTable = E('table', { 'class': 'hpui-table' });

		for (let i = 0; i < DAYS.length; i++) {
			const lbl = E('label', {}, [
				E('input', { 'type': 'checkbox', 'value': DAYS[i], 'data-day': DAYS[i] }),
				_(DAYS[i])
			]);
			ruleDaysBox.appendChild(lbl);
		}

		function scopeCheckboxes() {
			/* rebuilt from the current status */
			dom.content(ruleScopeBox, []);
			const clients = (S.status && S.status.clients) || [];
			for (let i = 0; i < clients.length; i++) {
				const c = clients[i];
				ruleScopeBox.appendChild(E('label', {}, [
					E('input', { 'type': 'checkbox', 'value': c.id }),
					clientName(c)
				]));
			}
		}

		/* Catalog with in-catalog search (plan 15): 45+ services grouped by
		 * category, search filters by name. A tap fills the Targets box. */
		const catSearch = E('input', { type: 'text', 'class': 'cbi-input-text ct-search', 'placeholder': _('Search the service catalog…') });
		const catBox = E('div', { 'class': 'ct-catalog' });
		function renderCatalog() {
			const q = String(catSearch.value || '').trim().toLowerCase();
			dom.content(catBox, []);
			let total = 0;
			for (let g = 0; g < SERVICE_GROUPS.length; g++) {
				const grp = SERVICE_GROUPS[g];
				const chipsRow = E('div', { 'class': 'ct-chips' });
				for (let i = 0; i < grp.items.length; i++) {
					const s = grp.items[i];
					if (q && s.name.toLowerCase().indexOf(q) === -1)
						continue;
					total++;
					const chip = E('button', { 'class': 'ct-chip', 'type': 'button', 'title': s.domains.join(', ') }, [ s.name ]);
					chip.addEventListener('click', function() {
						const cur = String(ruleTargets.value || '').trim();
						ruleTargets.value = (cur ? cur + '\n' : '') + s.domains.join('\n');
						ruleType.value = 'domain';
					});
					chipsRow.appendChild(chip);
				}
				if (!chipsRow.children.length)
					continue;
				catBox.appendChild(E('div', { 'class': 'ct-cat-head' }, [ grp.name ]));
				catBox.appendChild(chipsRow);
			}
			if (!total)
				dom.content(catBox, [ E('p', { 'class': 'hpui-hint' }, [ _('No service matches the search.') ]) ]);
		}
		catSearch.addEventListener('input', renderCatalog);
		renderCatalog();

		const ruleAddBtn = E('button', { 'class': 'btn cbi-button cbi-button-important', type: 'button' }, [ _('Add rule') ]);
		ruleAddBtn.addEventListener('click', function() {
			const targets = String(ruleTargets.value || '').trim();
			if (!targets) {
				note(ruleResult, false, _('Enter at least one domain or IP'));
				return;
			}
			const cids = [];
			const boxes = ruleScopeBox.querySelectorAll('input[type="checkbox"]');
			for (let i = 0; i < boxes.length; i++)
				if (boxes[i].checked)
					cids.push(boxes[i].value);
			const days = [];
			const dboxes = ruleDaysBox.querySelectorAll('input[type="checkbox"]');
			for (let i = 0; i < dboxes.length; i++)
				if (dboxes[i].checked)
					days.push(dboxes[i].getAttribute('data-day'));
			act(ruleResult, callRuleAdd(
				String(ruleName.value || '').trim(),
				ruleType.value, targets, cids.join(','),
				String(ruleT1.value || ''), String(ruleT2.value || ''),
				days.join(','),
				String(ruleD1.value || ''), String(ruleD2.value || '')),
				_('Rule added'));
			ruleTargets.value = ''; ruleName.value = '';
		});

		function renderRules() {
			scopeCheckboxes();
			const rules = (S.status && S.status.rules) || [];
			const clients = (S.status && S.status.clients) || [];
			const cbyid = {};
			for (let i = 0; i < clients.length; i++)
				cbyid[clients[i].id] = clients[i];
			const head = [ _('Rule'), _('Scope'), _('Window'), _('State'), _('Actions') ];
			const thead = E('thead', {}, [ E('tr', {}, head.map(function(h) { return E('th', {}, [ h ]); })) ]);
			const tbody = E('tbody', {});
			if (!rules.length) {
				tbody.appendChild(E('tr', {}, [ E('td', { 'colspan': '5' }, [ _('No site rules yet. Use the service chips above for quick blocks (TikTok, Instagram…).') ]) ]));
			}
			for (let i = 0; i < rules.length; i++) {
				const r = rules[i];
				let scope = _('Whole network');
				if (r.client_ids && r.client_ids.length) {
					const names = [];
					for (let k = 0; k < r.client_ids.length && k < 4; k++) {
						const c = cbyid[r.client_ids[k]];
						names.push(c ? clientName(c) : r.client_ids[k]);
					}
					scope = names.join(', ') + (r.client_ids.length > 4 ? '…' : '');
				}
				let win = _('always');
				if (r.time_start || r.time_stop)
					win = (r.time_start + '–' + r.time_stop) + ((r.days && r.days.length) ? ' · ' + daysText(r.days) : '');
				else if (r.days && r.days.length)
					win = daysText(r.days);
				if (r.date_start || r.date_stop)
					win += (win !== _('always') ? ' · ' : '') + (r.date_start || '…') + ' → ' + (r.date_stop || '…');

				const state = (!r.enabled) ? E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ _('Disabled') ])
					: (r.paused_until ? E('span', { 'class': 'hpui-badge hpui-b-amber' }, [ _('Paused') + ' · ' + fmtRemaining(r.paused_until) ])
						: E('span', { 'class': 'hpui-badge hpui-b-green' }, [ _('Active') ]));

				const tdA = E('td');
				const wrap = E('div', { 'class': 'ct-actions' });
				if (r.paused_until) {
					const res = E('button', { 'class': 'btn cbi-button-positive', type: 'button', title: _('Resume now') }, [ '▶' ]);
					res.addEventListener('click', function() {
						act(ruleResult, callRuleResume(r.id), _('Rule resumed'));
					});
					wrap.appendChild(res);
				} else {
					const ps = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Pause the rule') }, [ '⏸' ]);
					ps.addEventListener('click', function() {
						customTimeModal(_('Pause rule') + ' — ' + (r.name || (r.target[0] || '')), 60, function(mins) {
							act(ruleResult, callRulePause(r.id, String(mins)), _('Rule paused'));
						});
					});
					wrap.appendChild(ps);
				}
				const tg = E('button', { 'class': 'btn cbi-button', type: 'button' },
					[ r.enabled ? _('Off') : _('On') ]);
				tg.addEventListener('click', function() {
					act(ruleResult, callRuleToggle(r.id, r.enabled ? '0' : '1'),
						r.enabled ? _('Rule disabled') : _('Rule enabled'));
				});
				wrap.appendChild(tg);
				const del = E('button', { 'class': 'btn cbi-button-remove', type: 'button', title: _('Remove') }, [ '✖' ]);
				del.addEventListener('click', function() {
					ui.showModal(_('Remove rule'), [
						E('p', {}, [ _('Remove the rule') + ' «' + (r.name || (r.target[0] || '?')) + '»?' ]),
						E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
							E('button', { 'class': 'btn cbi-button-negative important', 'click': function() { ui.hideModal(); act(ruleResult, callRuleDelete(r.id), _('Rule removed')); } }, [ _('Remove') ])
						])
					]);
				});
				wrap.appendChild(del);
				tdA.appendChild(wrap);

				tbody.appendChild(E('tr', {}, [
					E('td', {}, [ String(r.name || r.target[0] || '?'), (r.target.length > 1 ? E('div', { 'class': 'hpui-cap' }, [ '+' + (r.target.length - 1) ]) : '') ]),
					E('td', {}, [ String(scope) ]),
					E('td', {}, [ String(win) ]),
					E('td', {}, [ state ]),
					tdA
				]));
			}
			dom.content(ruleTable, [ thead, tbody ]);
		}

		panes.rules.appendChild(E('p', { 'class': 'hpui-hint' }, [
			_('Domain rules are enforced by DNS (the domain stops resolving) — for the whole network or only for the selected devices. IP rules are enforced by the firewall. Pick a service chip to fill the list, or type your own domains.')
		]));
		panes.rules.appendChild(catSearch);
		panes.rules.appendChild(catBox);
		panes.rules.appendChild(E('div', { 'class': 'ct-form' }, [
			E('div', { 'class': 'ct-field' }, [ E('label', {}, [ _('Name') ]), ruleName ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 140px' }, [ E('label', {}, [ _('Type') ]), ruleType ])
		]));
		panes.rules.appendChild(E('div', { 'class': 'ct-targets-row' }, [
			E('div', { 'class': 'ct-field' }, [ E('label', {}, [ _('Targets (one per line)') ]), ruleTargets ])
		]));
		panes.rules.appendChild(E('div', { 'class': 'ct-field', 'style': 'margin-top:8px' }, [
			E('label', {}, [ _('Days (empty = every day)') ]), ruleDaysBox
		]));
		panes.rules.appendChild(E('div', { 'class': 'ct-form', 'style': 'margin-top:8px' }, [
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 120px' }, [ E('label', {}, [ _('From (time)') ]), ruleT1 ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 120px' }, [ E('label', {}, [ _('To (time)') ]), ruleT2 ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 150px' }, [ E('label', {}, [ _('Date from') ]), ruleD1 ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 150px' }, [ E('label', {}, [ _('Date to') ]), ruleD2 ])
		]));
		panes.rules.appendChild(E('div', { 'class': 'ct-field', 'style': 'margin-top:8px' }, [
			E('label', {}, [ _('Apply to devices (empty = whole network)') ]), ruleScopeBox
		]));
		panes.rules.appendChild(E('div', { 'style': 'margin-top:10px' }, [ ruleAddBtn ]));
		panes.rules.appendChild(E('h4', {}, [ _('Rules') ]));
		panes.rules.appendChild(E('div', { 'class': 'hpui-wrap' }, [ ruleTable ]));
		panes.rules.appendChild(resultBlock(ruleResult));

		/* ── SCHEDULES ──────────────────────────────────────────────── */

		const schName = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': _('Name (e.g. Lessons)') });
		const schType = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'daily' }, [ _('Daily (time window each day)') ]),
			E('option', { 'value': 'weekly' }, [ _('By days of the week') ]),
			E('option', { 'value': 'range' }, [ _('Date range (all day)') ]),
			E('option', { 'value': 'timer' }, [ _('One-shot (date + time)') ])
		]);
		const schAction = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'deny' }, [ _('Block during the window (allowed outside)') ]),
			E('option', { 'value': 'allow' }, [ _('Allow only during the window (blocked outside)') ])
		]);
		const schT1 = E('input', { 'type': 'time', 'class': 'cbi-input-text', 'value': '07:00' });
		const schT2 = E('input', { 'type': 'time', 'class': 'cbi-input-text', 'value': '21:00' });
		const schD1 = E('input', { 'type': 'date', 'class': 'cbi-input-text' });
		const schD2 = E('input', { 'type': 'date', 'class': 'cbi-input-text' });
		const schDays = E('div', { 'class': 'ct-days' });
		const schClients = E('div', { 'class': 'ct-days' });
		const schWifi = E('div', { 'class': 'ct-days' });
		const schHint = E('p', { 'class': 'hpui-hint' });
		const schTable = E('table', { 'class': 'hpui-table' });

		for (let i = 0; i < DAYS.length; i++)
			schDays.appendChild(E('label', {}, [
				E('input', { 'type': 'checkbox', 'value': DAYS[i], 'data-day': DAYS[i] }),
				_(DAYS[i])
			]));

		function schTypeFields() {
			const t = schType.value;
			const showTime = (t === 'daily' || t === 'weekly' || t === 'timer');
			const showDays = (t === 'weekly');
			const showDates = (t === 'range' || t === 'timer');
			schT1.parentNode.style.display = showTime ? '' : 'none';
			schT2.parentNode.style.display = showTime ? '' : 'none';
			schDays.style.display = showDays ? '' : 'none';
			schD1.parentNode.style.display = showDates ? '' : 'none';
			schD2.parentNode.style.display = showDates ? '' : 'none';
			schHint.textContent = (schAction.value === 'deny')
				? _('During the window the bound devices (and Wi-Fi) are BLOCKED; outside it everything is allowed.')
				: _('During the window the bound devices (and Wi-Fi) are ALLOWED; outside it they are blocked.');
		}
		schType.addEventListener('change', schTypeFields);
		schAction.addEventListener('change', schTypeFields);

		function schBindBoxes() {
			dom.content(schClients, []);
			const clients = (S.status && S.status.clients) || [];
			for (let i = 0; i < clients.length; i++)
				schClients.appendChild(E('label', {}, [
					E('input', { 'type': 'checkbox', 'value': clients[i].id }),
					clientName(clients[i])
				]));
			dom.content(schWifi, []);
			const radios = (S.wifi && S.wifi.radios) || [];
			for (let r = 0; r < radios.length; r++) {
				const ifs = radios[r].ifaces || [];
				for (let k = 0; k < ifs.length; k++) {
					if (!ifs[k].id)
						continue;
					schWifi.appendChild(E('label', {}, [
						E('input', { 'type': 'checkbox', 'value': ifs[k].id }),
						ifs[k].ssid || ifs[k].id
					]));
				}
			}
		}

		const templates = [
			{ label: _('Lessons (school hours)'), type: 'daily', action: 'deny', t1: '08:00', t2: '14:00', days: [] },
			{ label: _('Night sleep'), type: 'daily', action: 'deny', t1: '22:00', t2: '07:00', days: [] },
			{ label: _('Evening, weekdays only'), type: 'weekly', action: 'deny', t1: '19:00', t2: '21:30', days: [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri' ] }
		];
		const tplRow = E('div', { 'class': 'ct-chips' });
		for (let i = 0; i < templates.length; i++) {
			const t = templates[i];
			const chip = E('button', { 'class': 'ct-chip', 'type': 'button' }, [ t.label ]);
			chip.addEventListener('click', function() {
				schType.value = t.type;
				schAction.value = t.action;
				schT1.value = t.t1;
				schT2.value = t.t2;
				const dboxes = schDays.querySelectorAll('input[type="checkbox"]');
				for (let k = 0; k < dboxes.length; k++)
					dboxes[k].checked = t.days.indexOf(dboxes[k].getAttribute('data-day')) !== -1;
				schTypeFields();
			});
			tplRow.appendChild(chip);
		}

		const schAddBtn = E('button', { 'class': 'btn cbi-button cbi-button-important', type: 'button' }, [ _('Add schedule') ]);
		schAddBtn.addEventListener('click', function() {
			const cids = [];
			const cb = schClients.querySelectorAll('input[type="checkbox"]');
			for (let i = 0; i < cb.length; i++)
				if (cb[i].checked)
					cids.push(cb[i].value);
			const wids = [];
			const wb = schWifi.querySelectorAll('input[type="checkbox"]');
			for (let i = 0; i < wb.length; i++)
				if (wb[i].checked)
					wids.push(wb[i].value);
			if (!cids.length && !wids.length) {
				note(schedResult, false, _('Bind at least one device or Wi-Fi network'));
				return;
			}
			const days = [];
			const dboxes = schDays.querySelectorAll('input[type="checkbox"]');
			for (let i = 0; i < dboxes.length; i++)
				if (dboxes[i].checked)
					days.push(dboxes[i].getAttribute('data-day'));
			act(schedResult, callScheduleAdd(
				String(schName.value || '').trim(), schType.value, schAction.value,
				String(schT1.value || ''), String(schT2.value || ''), days.join(','),
				String(schD1.value || ''), String(schD2.value || ''),
				cids.join(','), wids.join(',')),
				_('Schedule added'));
			schName.value = '';
		});

		function schedTypeText(t) {
			return {
				daily: _('Daily'),
				weekly: _('By days of the week'),
				range: _('Date range'),
				timer: _('One-shot')
			}[t] || t;
		}

		function renderSchedules() {
			schBindBoxes();
			schTypeFields();
			const scheds = (S.status && S.status.schedules) || [];
			const clients = (S.status && S.status.clients) || [];
			const cbyid = {};
			for (let i = 0; i < clients.length; i++)
				cbyid[clients[i].id] = clients[i];
			const head = [ _('Schedule'), _('Type'), _('Action'), _('Window'), _('Bound to'), _('State'), _('Actions') ];
			const thead = E('thead', {}, [ E('tr', {}, head.map(function(h) { return E('th', {}, [ h ]); })) ]);
			const tbody = E('tbody', {});
			if (!scheds.length) {
				tbody.appendChild(E('tr', {}, [ E('td', { 'colspan': '7' }, [ _('No schedules yet — pick a template above, adjust and bind devices.') ]) ]));
			}
			for (let i = 0; i < scheds.length; i++) {
				const s = scheds[i];
				let win = '';
				if (s.type === 'range')
					win = (s.date_start || '…') + ' → ' + (s.date_stop || '…');
				else if (s.type === 'timer')
					win = (s.date_start || '') + ' ' + (s.time_start || '') + ' → ' + (s.date_stop || '') + ' ' + (s.time_stop || '');
				else {
					win = (s.time_start || '') + '–' + (s.time_stop || '');
					if (s.type === 'weekly')
						win += ' · ' + daysText(s.days);
				}
				const names = [];
				for (let k = 0; k < (s.client_ids || []).length; k++) {
					const c = cbyid[s.client_ids[k]];
					names.push(c ? clientName(c) : s.client_ids[k]);
				}
				const wnames = [];
				const radios = (S.wifi && S.wifi.radios) || [];
				for (let k = 0; k < (s.wifi_ids || []).length; k++) {
					let found = s.wifi_ids[k];
					for (let r = 0; r < radios.length; r++) {
						const ifs = radios[r].ifaces || [];
						for (let q = 0; q < ifs.length; q++)
							if (ifs[q].id === s.wifi_ids[k])
								found = ifs[q].ssid || ifs[q].id;
					}
					wnames.push(found);
				}
				const bound = []
					.concat(names.length ? [ _('Devices') + ': ' + names.join(', ') ] : [])
					.concat(wnames.length ? [ _('Wi-Fi') + ': ' + wnames.join(', ') ] : []);
				const state = (!s.enabled) ? E('span', { 'class': 'hpui-badge hpui-b-grey' }, [ _('Disabled') ])
					: (s.active_now ? E('span', { 'class': 'hpui-badge hpui-b-blue' }, [ _('In window now') ])
						: E('span', { 'class': 'hpui-badge hpui-b-green' }, [ _('Enabled') ]));

				const tdA = E('td');
				const wrap = E('div', { 'class': 'ct-actions' });
				const tg = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ s.enabled ? _('Off') : _('On') ]);
				tg.addEventListener('click', function() {
					act(schedResult, callScheduleToggle(s.id, s.enabled ? '0' : '1'),
						s.enabled ? _('Schedule disabled') : _('Schedule enabled'));
				});
				wrap.appendChild(tg);
				const del = E('button', { 'class': 'btn cbi-button-remove', type: 'button', title: _('Remove') }, [ '✖' ]);
				del.addEventListener('click', function() {
					ui.showModal(_('Remove schedule'), [
						E('p', {}, [ _('Remove the schedule') + ' «' + (s.name || s.type) + '»?' ]),
						E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
							E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
							E('button', { 'class': 'btn cbi-button-negative important', 'click': function() { ui.hideModal(); act(schedResult, callScheduleDelete(s.id), _('Schedule removed')); } }, [ _('Remove') ])
						])
					]);
				});
				wrap.appendChild(del);
				tdA.appendChild(wrap);

				tbody.appendChild(E('tr', {}, [
					E('td', {}, [ String(s.name || '—') ]),
					E('td', {}, [ schedTypeText(s.type) ]),
					E('td', {}, [ s.action === 'allow' ? _('Allow only in window') : _('Block in window') ]),
					E('td', {}, [ String(win) ]),
					E('td', {}, [ bound.join(' · ') || '—' ]),
					E('td', {}, [ state ]),
					tdA
				]));
			}
			dom.content(schTable, [ thead, tbody ]);
		}

		panes.sched.appendChild(E('p', { 'class': 'hpui-hint' }, [
			_('A schedule binds devices and/or Wi-Fi networks to a time window. Templates are prefilled examples — adjust before saving. Windows may cross midnight (22:00 → 07:00).')
		]));
		panes.sched.appendChild(tplRow);
		panes.sched.appendChild(E('div', { 'class': 'ct-form' }, [
			E('div', { 'class': 'ct-field' }, [ E('label', {}, [ _('Name') ]), schName ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 230px' }, [ E('label', {}, [ _('Type') ]), schType ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 320px' }, [ E('label', {}, [ _('Action') ]), schAction ])
		]));
		panes.sched.appendChild(E('div', { 'class': 'ct-form', 'style': 'margin-top:8px' }, [
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 120px' }, [ E('label', {}, [ _('From') ]), schT1 ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 120px' }, [ E('label', {}, [ _('To') ]), schT2 ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 150px' }, [ E('label', {}, [ _('Date from') ]), schD1 ]),
			E('div', { 'class': 'ct-field', 'style': 'flex:0 0 150px' }, [ E('label', {}, [ _('Date to') ]), schD2 ])
		]));
		panes.sched.appendChild(E('div', { 'class': 'ct-field', 'style': 'margin-top:8px' }, [
			E('label', {}, [ _('Days of the week (for the "By days" type)') ]), schDays
		]));
		panes.sched.appendChild(E('div', { 'class': 'ct-field', 'style': 'margin-top:8px' }, [
			E('label', {}, [ _('Devices') ]), schClients
		]));
		panes.sched.appendChild(E('div', { 'class': 'ct-field', 'style': 'margin-top:8px' }, [
			E('label', {}, [ _('Wi-Fi networks') ]), schWifi
		]));
		panes.sched.appendChild(schHint);
		panes.sched.appendChild(E('div', { 'style': 'margin-top:10px' }, [ schAddBtn ]));
		panes.sched.appendChild(E('h4', {}, [ _('Schedules') ]));
		panes.sched.appendChild(E('div', { 'class': 'hpui-wrap' }, [ schTable ]));
		panes.sched.appendChild(resultBlock(schedResult));

		/* ── WI-FI ──────────────────────────────────────────────────── */

		const wifiCards = E('div', { 'class': 'ct-grid' });

		function refreshWifi() {
			return L.resolveDefault(callWifiStatus(), null).then(function(w) {
				if (w) {
					S.wifi = w;
					renderWifi();
					schBindBoxes();
				}
			});
		}

		function renderWifi() {
			const radios = (S.wifi && S.wifi.radios) || [];
			const temps = (S.wifi && S.wifi.temps) || {};
			if (!radios.length) {
				dom.content(wifiCards, E('p', { 'class': 'hpui-hint' }, [ _('Wi-Fi status is unavailable (no radios?).') ]));
				return;
			}
			const out = [];
			for (let r = 0; r < radios.length; r++) {
				const radio = radios[r];
				const ifs = radio.ifaces || [];
				for (let k = 0; k < ifs.length; k++) {
					const w = ifs[k];
					const card = E('div', { 'class': 'ct-card ' + (w.up ? 'ct-allowed' : 'ct-blocked') });
					card.appendChild(E('div', { 'class': 'ct-name' }, [
						(w.ssid || w.id || radio.radio),
						E('span', { 'class': 'hpui-badge ' + (w.up ? 'hpui-b-green' : 'hpui-b-red') },
							[ w.up ? _('On') : _('Off') ])
					]));
					card.appendChild(E('div', { 'class': 'ct-meta' }, [
						radio.radio + (w.id ? ' · ' + w.id : '')
					]));
					const actions = E('div', { 'class': 'ct-actions' });
					const tog = E('button', { 'class': 'btn cbi-button-' + (w.up ? 'negative' : 'positive'), type: 'button' },
						[ w.up ? _('Turn off') : _('Turn on') ]);
					tog.addEventListener('click', function() {
						act(wifiResult, callWifiSet(w.id, w.up ? '1' : '0'),
							w.up ? _('Wi-Fi turned off') : _('Wi-Fi turned on'));
						refreshWifi();
					});
					actions.appendChild(tog);
					if (w.up) {
						const tmp = E('button', { 'class': 'btn cbi-button', type: 'button', title: _('Turn off temporarily') }, [ '⏱' ]);
						tmp.addEventListener('click', function() {
							customTimeModal(_('Wi-Fi off for') + ' — ' + (w.ssid || w.id), 60, function(mins) {
								act(wifiResult, callWifiTemp(w.id, String(mins)), _('Wi-Fi will turn back on automatically'));
								refreshWifi();
							});
						});
						actions.appendChild(tmp);
					} else if (w.id && (w.id in temps)) {
						const un = E('button', { 'class': 'btn cbi-button-positive', type: 'button', title: _('Cancel the temporary off') }, [ '↩' ]);
						un.addEventListener('click', function() {
							act(wifiResult, callWifiTempClear(w.id), _('Temporary off removed'));
							refreshWifi();
						});
						actions.appendChild(un);
					}
					card.appendChild(actions);
					if (w.id && (w.id in temps))
						card.appendChild(E('div', { 'class': 'ct-meta' }, [
							_('Wi-Fi will turn back on automatically') + ' — ' + fmtRemaining(temps[w.id])
						]));
					out.push(card);
				}
			}
			dom.content(wifiCards, out);
		}

		panes.wifi.appendChild(E('p', { 'class': 'hpui-hint' }, [
			_('Manual switching is never overridden by schedules (the enforcer only touches what it switched itself). For time-based Wi-Fi control create a schedule and bind Wi-Fi networks on the Schedules pane.')
		]));
		panes.wifi.appendChild(E('h4', {}, [ _('Wireless networks') ]));
		panes.wifi.appendChild(wifiCards);
		panes.wifi.appendChild(resultBlock(wifiResult));

		/* ── JOURNAL ────────────────────────────────────────────────── */

		const evList = E('div', { 'class': 'hpui-log', 'style': 'max-height:420px' });
		const logBox = E('pre', { 'class': 'hpui-pre hpui-log' }, [ '' ]);

		const evIcons = { block: '🔒', allow: '🔓', temp: '⏱', wifi: '📶', schedule: '📅', system: '⚙️', update: '⬆️' };
		const evColors = { block: 'hpui-c-red', allow: 'hpui-c-green', temp: 'hpui-c-amber', wifi: 'hpui-c-blue' };

		function refreshJournal() {
			return Promise.all([
				L.resolveDefault(callEvents('120'), null),
				L.resolveDefault(callLogTail('80'), null)
			]).then(function(d) {
				const events = (d[0] && d[0].events) || [];
				const lines = [];
				for (let i = events.length - 1; i >= 0 && lines.length < 120; i--) {
					const ev = events[i];
					const t = new Date(ev.ts * 1000);
					const hh = ('0' + t.getHours()).slice(-2) + ':' + ('0' + t.getMinutes()).slice(-2);
					const icon = evIcons[ev.type] || '•';
					lines.push(E('div', {}, [
						E('span', { 'class': evColors[ev.type] || 'hpui-c-grey' }, [ hh + ' ' + icon + ' ' + (ev.who || '') ]),
						(ev.detail ? ' — ' + ev.detail : '')
					]));
				}
				dom.content(evList, lines.length ? lines : [ _('The journal is empty.') ]);
				logBox.textContent = (d[1] && d[1].content) || '';
			});
		}

		const evClearBtn = E('button', { 'class': 'btn cbi-button-remove', type: 'button' }, [ _('Clear the journal') ]);
		evClearBtn.addEventListener('click', function() {
			ui.showModal(_('Clear the journal'), [
				E('p', {}, [ _('Clear the events journal? The service log is not touched.') ]),
				E('div', { 'class': 'right', 'style': 'margin-top:14px' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, [ _('Cancel') ]),
					E('button', { 'class': 'btn cbi-button-negative important', 'click': function() { ui.hideModal(); callEventsClear(); refreshJournal(); } }, [ _('Clear') ])
				])
			]);
		});
		const logRefreshBtn = E('button', { 'class': 'btn cbi-button', type: 'button' }, [ _('Refresh log') ]);
		logRefreshBtn.addEventListener('click', refreshJournal);

		panes.journal.appendChild(E('div', { 'class': 'ct-toolbar' }, [ evClearBtn, logRefreshBtn ]));
		panes.journal.appendChild(E('h4', {}, [ _('Events') ]));
		panes.journal.appendChild(evList);
		panes.journal.appendChild(E('h4', {}, [ _('Service log') ]));
		panes.journal.appendChild(logBox);

		/* ── SETTINGS ───────────────────────────────────────────────── */

		const setEnableBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', type: 'button' });
		setEnableBtn.addEventListener('click', function() {
			const target = (S.status && S.status.enabled) ? '0' : '1';
			act(setResult, callSet(target),
				(target === '1') ? _('Control enabled') : _('Control disabled'));
		});
		panes.settings.appendChild(E('div', { 'class': 'ct-toolbar' }, [ setEnableBtn ]));
		panes.settings.appendChild(resultBlock(setResult));
		panes.settings.appendChild(E('h4', {}, [ _('How it works') ]));
		panes.settings.appendChild(E('div', { 'class': 'hpui-panel' }, [
			E('p', { 'class': 'hpui-hint' }, [ _('Blocked devices lose all internet access (firewall drop, including intercepted traffic). Site rules stop the domain resolving (DNS) or drop the IP — globally, or only for the selected devices.') ]),
			E('p', { 'class': 'hpui-hint' }, [ _('The Wi-Fi button blocks only the Wi-Fi network for that device (wired stays online); a manual block is the FULL internet block. The ✅ button temporarily ALLOWS a device for a while — a hole in the schedule that closes itself. Neither overrides a manual block.') ]),
			E('p', { 'class': 'hpui-hint' }, [ _('Schedules apply blocks during (or only during) a time window; Wi-Fi networks can be scheduled the same way. The watcher re-applies the state every minute — schedule boundaries take effect within a minute.') ]),
			E('p', { 'class': 'hpui-hint' }, [ _('Honest limitations: per-client DNS filtering is IPv4; DNS-over-HTTPS of a savvy child theoretically bypasses domain rules (DoT/DoQ are blocked); a device without MAC/IP cannot be filtered; Windows/MAC randomization changes the MAC — re-add the device then.') ]),
			E('p', { 'class': 'hpui-hint' }, [ _('The Telegram bot controls the same state: /menu (everything in buttons), /devices, /blocksite <domain> [device No], /pause, /resume, /wifi. Pushes: blocks, schedule windows, Wi-Fi events, new devices.') ])
		]));

		/* ── poll ───────────────────────────────────────────────────── */

		function refreshStatus() {
			return Promise.all([
				L.resolveDefault(callStatus(), null),
				L.resolveDefault(callDevices(), null)
			]).then(function(d) {
				if (d[0])
					S.status = d[0];
				if (d[1] && d[1].devices)
					S.devices = d[1].devices;
				setEnableBtn.textContent = (S.status && S.status.enabled) ? _('Disable control') : _('Enable control');
				renderDash();
				renderDevices();
				renderRules();
				renderSchedules();
			});
		}

		poll.add(refreshStatus, 4);
		refreshStatus();
		refreshJournal();
		refreshWifi();
		schTypeFields();

		return E('div', {}, [
			E('h4', { 'style': 'margin:6px 0 0 0' }, [ _('Control') ]),
			tabBar,
			panes.dash, panes.devices, panes.rules, panes.sched,
			panes.wifi, panes.journal, panes.settings
		]);
	}
});
