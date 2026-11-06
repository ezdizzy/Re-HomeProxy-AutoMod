// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — WARP (Cloudflare) registration runner (Ф9.13, D34c).
// Usage: ucode warp_runner.uc <op_id> <action>   # action: register | renew
//
// Cloudflare WARP как WireGuard-endpoint ВНУТРИ живущего ядра (без warp-svc —
// пользователь-согласование D34c: отдельный резидентный демон отклонён).
// Механика wgcf (проверена живьём 2026-11-06 на api.cloudflareclient.com):
//   POST https://api.cloudflareclient.com/<v>/reg  (v0a5641; СТАРЫЙ путь
//   /<v>/register удалён — 404), ключ-пара X25519 генерируется ЛОКАЛЬНО
//   (openssl genpkey; приватный ключ остаётся у нас), тело:
//   {key:<pub>,install_id:"",fcm_token:"",tos:<RFC3339>,model:"PC",locale:
//   "en_US",serial_number:"",os_version:"16.0.0",key_type:"curve25519",
//   tunnel_type:"wireguard"}, заголовки 1.1.1.1/6.38.9-5641 + CF-Client-Version.
//   Ответ — устройство НАПРЯМУЮ (не в обёртке success/result): id, token,
//   account.license, config.client_id (b64 → 3 байта reserved), config.peers[0]
//   (public_key bmXOC+F1… + endpoint{v4 "IP:0", host "engage…:2408", ports
//   [2408,500,1701,4500]}), config.interface.addresses{v4,v6} (БЕЗ префиксов).
// Сеть: прямая попытка → фолбэк через socks5h://127.0.0.1:5337 (auto-proxy-in
// → main-out), чтобы регистрация работала и при полной смерти прямого пути.
//
// Артефакты:
//   /etc/homeproxy/warp_profile.json  — профиль (0600, atomic temp+mv);
//   UCI homeproxy.warp (enabled/ feature) + homeproxy.warp (node-секция
//   type wireguard) — создаётся/обновляется здесь, со снимком /etc/config/
//   homeproxy в /etc/homeproxy/backups/warp-uci-<ts>/ и md5-сводкой в detail.
//   Затем init.d reload (урок 167: фон + rc-файл) и живая верификация:
//   hiddify-c running + слушатель warp-in 127.0.0.1:5339.
//
// Уроки: 106/2/93/126 (логика в main(); хелперы выше), 167 (system(cmd,timeout)
// НЕ ИСПОЛЬЗОВАТЬ), 100/111/113 (никаких fd-локов — opman lease), 169 (честный
// finish при любом крахе), 245/249 (ucode-грамматика), 256 (json() парсит
// голый NaN — ответ валидируется ПРОТИВ известного множества полей), 257/258
// (heredoc — только после mkdir; данные пайпа ASCII), 112 (system() убивает
// только прямого ребёнка — сирот нет: curl с --max-time, apk без &).

'use strict';

import { get_op, stage, heartbeat, finish } from '/etc/homeproxy/scripts/opman.uc';
import { access, readfile, writefile, mkdir, popen, chmod, unlink } from 'fs';
import { cursor } from 'uci';

const HP_DIR = '/etc/homeproxy';
const PROFILE_PATH = HP_DIR + '/warp_profile.json';
const BK_DIR = HP_DIR + '/backups';
const CONF_PATH = '/etc/config/homeproxy';
const API_BASE = 'https://api.cloudflareclient.com';
const API_VERSION = 'v0a5641';
const UA = '1.1.1.1/6.38.9-5641 (Android 16.0.0)';
const CF_VER = 'a-6.38.9-5641';
const PROXY_FALLBACK = 'socks5h://127.0.0.1:5337';   /* auto-proxy-in → main-out */
const WARP_IN_PORT = 5339;                            /* warp-in — синхронно с generate_client.uc */
const VERIFY_SEC = 30;

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) {
		out = fd.read('all') || '';
		fd.close();
	}
	return out;
};

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
};

function mkdir_p(p) {
	let cur = '';
	for (let part in split(p, '/')) {
		if (!length(part))
			continue;
		cur += '/' + part;
		if (!access(cur))
			mkdir(cur);
	}
};

function read_profile() {
	try {
		const d = json(readfile(PROFILE_PATH) || '');
		if (d != null && type(d) === 'object' && length('' + (d.private_key || '')))
			return d;
	} catch (e) { /* нет профиля */ }
	return null;
};

function cf_delete_device(old) {
	try {
		const out = '/tmp/warp_del.json';
		const cmd = `curl -s -o ${shellquote(out)} -w '%{http_code}' --max-time 20` +
			` -x ${shellquote(PROXY_FALLBACK)}` +
			` -A ${shellquote(UA)} -H ${shellquote('CF-Client-Version: ' + CF_VER)}` +
			` -H ${shellquote('Authorization: Bearer ' + old.token)}` +
			` -X DELETE ${shellquote(API_BASE + '/' + API_VERSION + '/reg/' + old.device_id)}`;
		const code = trim(capture(cmd));
		unlink(out);
		return code === '204' || code === '200';
	} catch (e) {
		return false;
	}
};

function svc_instances() {
	let svc = null;
	try { svc = json(capture('ubus call service list 2>/dev/null')); } catch (e) { svc = null; }
	if (svc && type(svc) === 'object' && svc.homeproxy &&
	    type(svc.homeproxy.instances) === 'object')
		return svc.homeproxy.instances;
	return {};
};

function verify_core(op_id) {
	const deadline = time() + VERIFY_SEC;
	while (true) {
		const inst = svc_instances()['hiddify-c'];
		if (inst && inst.running === true)
			return { ok: true, note: 'hiddify-c running' };
		if (time() >= deadline)
			break;
		heartbeat(op_id);
		sleep(2000);
	}
	const inst = svc_instances()['hiddify-c'];
	if (inst && inst.running === true)
		return { ok: true, note: 'hiddify-c running' };
	return {
		ok: false,
		note: inst ? 'hiddify-c exists but not running' : 'hiddify-c instance absent'
	};
};

function run_initd(op_id, action) {
	const rcfile = '/tmp/hp_warp_' + op_id + '.rc';
	system(`( /etc/init.d/homeproxy ${action} >/dev/null 2>&1; echo $? > ${rcfile} ) &`);
	const deadline = time() + 90;
	while (true) {
		if (access(rcfile)) {
			const rc = trim(readfile(rcfile) || '');
			unlink(rcfile);
			return rc;
		}
		if (time() >= deadline) {
			unlink(rcfile);
			finish(op_id, false, false,
				'init.d reload did not report within 90s (it keeps running detached — check the service state)');
			exit(1);
		}
		heartbeat(op_id);
		sleep(1000);
	}
};

/* X25519-пара в формате WireGuard (base64 сырых 32 байт; DER X25519
 * приватного = 16-байтовый заголовок + 32 ключа, публичного = 12 + 32). */
function wg_keygen(workdir) {
	const pem = workdir + '/key.pem';
	const rc = system(`openssl genpkey -algorithm X25519 -out ${shellquote(pem)} 2>/dev/null`);
	if (rc !== 0)
		return null;
	const priv = trim(capture(`openssl pkey -in ${shellquote(pem)} -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A`));
	const pub = trim(capture(`openssl pkey -in ${shellquote(pem)} -pubout -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A`));
	unlink(pem);
	if (length(priv) !== 44 || length(pub) !== 44)
		return null;
	return { priv: priv, pub: pub };
};

/* Регистрация. Возвращает устройство (объект) или null (с detail-ошибкой). */
function cf_register(pub, workdir) {
	const tos = trim(capture('date -u +%Y-%m-%dT%H:%M:%S.000Z'));
	const body = workdir + '/reg.json';
	writefile(body, sprintf('%J', {
		key: pub,
		install_id: '',
		fcm_token: '',
		tos: tos,
		model: 'PC',
		locale: 'en_US',
		serial_number: '',
		os_version: '16.0.0',
		key_type: 'curve25519',
		tunnel_type: 'wireguard'
	}) + '\n');
	chmod(body, 384);
	const urls = [
		`${API_BASE}/${API_VERSION}/reg`,
	];
	for (let u in urls) {
		for (let px in [ '', PROXY_FALLBACK ]) {
			const proxy = length(px) ? ` -x ${shellquote(px)}` : '';
			const out = workdir + '/resp.json';
			const cmd = `curl -s -o ${shellquote(out)} -w '%{http_code}' --max-time 25` +
				proxy +
				` -A ${shellquote(UA)} -H ${shellquote('CF-Client-Version: ' + CF_VER)}` +
				` -H 'Content-Type: application/json; charset=UTF-8'` +
				` -X POST --data-binary @${shellquote(body)} ${shellquote(u)}`;
			const code = trim(capture(cmd));
			let doc = null;
			try { doc = json(readfile(out) || ''); } catch (e) { doc = null; }
			unlink(out);
			if (code === '200' && doc != null && type(doc) === 'object' &&
			    length('' + (doc.id || '')) && length('' + (doc.token || '')) &&
			    doc.config != null && type(doc.config) === 'object')
				return doc;
			/* 400 «Invalid registration request» = запрос дошли и отклонён —
			 * ретраить через прокси бессмысленно. */
			if (code === '400' || code === '403')
				break;
			heartbeat(ARGV[0]);
		}
	}
	return null;
};

/* Вычленение полей профиля с ЖЁСТКОЙ валидацией (урок 256: json() парсит
 * голый NaN — каждое поле проверяется против известного множества). */
function extract_profile(doc, keys, ts) {
	const cfg = doc.config;
	if (cfg == null || type(cfg) !== 'object')
		return { error: 'ответ без config' };
	const ifaces = cfg.interface;
	const addrs = (ifaces != null && type(ifaces) === 'object') ? ifaces.addresses : null;
	const v4 = (addrs != null) ? trim('' + (addrs.v4 || '')) : '';
	const v6 = (addrs != null) ? trim('' + (addrs.v6 || '')) : '';
	if (!length(v4) || !match(v4, /^[0-9a-fA-F.:]+$/))
		return { error: 'в ответе нет валидного v4-адреса' };
	const peers = cfg.peers;
	if (type(peers) !== 'array' || length(peers) < 1)
		return { error: 'в ответе нет peers' };
	const peer = peers[0];
	const peer_pub = trim('' + (peer.public_key || ''));
	if (length(peer_pub) !== 44)
		return { error: 'в ответе нет валидного public_key пира' };
	const ep = (peer.endpoint != null && type(peer.endpoint) === 'object') ? peer.endpoint : {};
	const ports = (type(ep.ports) === 'array' && length(ep.ports)) ? ep.ports : [ 2408 ];
	const eport = int(ports[0]) || 2408;
	/* host: "engage.cloudflareclient.com:2408" предпочтителен wgcf, но для
	 * ядра берём IP (anycast, без DNS-зависимости): v4 "IP:0" → strip. */
	let eip = trim('' + (ep.v4 || ''));
	const m = match(eip, /^(\[[^\]]+\]|[0-9a-fA-F.:]+):[0-9]*$/);
	if (m)
		eip = m[1];
	if (!length(eip) || !match(eip, /^[0-9.]+$/))
		eip = trim('' + (ep.host || ''));
	if (!length(eip))
		return { error: 'в ответе нет endpoint' };
	const cid = trim('' + (cfg.client_id || ''));
	let reserved = [];
	if (length(cid)) {
		try {
			const raw = b64dec(cid);
			/* 🔴 ucode-фен (поймано живьём ч.201): у строк ЭТОЙ сборки НЕТ
			 * charCodeAt и НЕТ индексации (raw[0] = Reference error) — байты
			 * только через ord(substr(raw, i, 1)). */
			for (let i = 0; i < length(raw); i++)
				push(reserved, ord(substr(raw, i, 1)));
		} catch (e) { reserved = []; }
	}
	if (length(reserved) != 3)
		reserved = [];
	const acc = (doc.account != null && type(doc.account) === 'object') ? doc.account : {};
	return {
		profile: {
			device_id: trim('' + (doc.id || '')),
			token: trim('' + (doc.token || '')),
			license: trim('' + (acc.license || '')),
			private_key: keys.priv,
			public_key: keys.pub,
			peer_public_key: peer_pub,
			endpoint_ip: eip,
			endpoint_host: trim('' + (ep.host || '')),
			endpoint_port: eport,
			address_v4: v4,
			address_v6: v6,
			client_id: cid,
			reserved: reserved,
			api_version: API_VERSION,
			registered: ts
		}
	};
};

/* UCI: node-секция 'warp' (type node) из профиля + enabled зеркально фиче. */
function uci_apply(profile, enabled, detail_parts) {
	mkdir_p(BK_DIR);
	const ts = time();
	const snapdir = BK_DIR + '/warp-uci-' + ts;
	mkdir(snapdir);
	const pre_md5 = trim(capture(`md5sum ${shellquote(CONF_PATH)} 2>/dev/null | awk '{print $1}'`));
	system(`cp ${shellquote(CONF_PATH)} ${shellquote(snapdir + '/homeproxy')} 2>/dev/null`);

	const q = shellquote;
	system(`uci -q set homeproxy.warp=node`);
	system(`uci -q set homeproxy.warp.label='WARP'`);
	system(`uci -q set homeproxy.warp.type=wireguard`);
	system(`uci -q set homeproxy.warp.enabled=${enabled ? '1' : '0'}`);
	/* Ф9.13/D34c: маркер «управляемого» узла — пулы urltest/hotswap (и скан
	 * main_has_wg в генераторе) пропускают его: WARP — резервный выход, а не
	 * член главной цепочки. */
	system(`uci -q set homeproxy.warp.warp_managed=1`);
	system(`uci -q set homeproxy.warp.address=${q(profile.endpoint_ip)}`);
	system(`uci -q set homeproxy.warp.port=${q('' + profile.endpoint_port)}`);
	system(`uci -q set homeproxy.warp.wireguard_private_key=${q(profile.private_key)}`);
	system(`uci -q set homeproxy.warp.wireguard_peer_public_key=${q(profile.peer_public_key)}`);
	system(`uci -q set homeproxy.warp.wireguard_mtu=1280`);
	system(`uci -q set homeproxy.warp.wireguard_persistent_keepalive_interval=25`);
	system(`uci -q delete homeproxy.warp.wireguard_local_address 2>/dev/null`);
	system(`uci add_list homeproxy.warp.wireguard_local_address=${q(profile.address_v4 + '/32')}`);
	if (length(profile.address_v6))
		system(`uci add_list homeproxy.warp.wireguard_local_address=${q(profile.address_v6 + '/128')}`);
	if (length(profile.reserved) == 3) {
		system(`uci -q delete homeproxy.warp.wireguard_reserved 2>/dev/null`);
		for (let b in profile.reserved)
			system(`uci add_list homeproxy.warp.wireguard_reserved=${q('' + b)}`);
	}
	system(`uci -q set homeproxy.warp.wireguard_backend=auto`);
	const post_md5 = trim(capture(`md5sum ${shellquote(CONF_PATH)} 2>/dev/null | awk '{print $1}'`));
	system(`uci -q commit homeproxy`);
	push(detail_parts, 'uci md5 ' + pre_md5 + '->' + post_md5 + ' (snapshot ' + snapdir + ')');
};

/* Честная регистрация: профиль пишется ТОЛЬКО при полном успехе. */
function do_register(op_id, action, detail_parts) {
	/* 1. openssl-util (keygen). Отсутствует → apk add (штатный путь установки
	 * пакетов приложением, как curl_install). */
	stage(op_id, 'openssl');
	if (!length(trim(capture('command -v openssl 2>/dev/null')))) {
		const rc = system('apk add openssl-util >/tmp/warp_apk.log 2>&1');
		const ok = length(trim(capture('command -v openssl 2>/dev/null')));
		if (!ok) {
			finish(op_id, false, false, 'openssl-util недоступен (apk rc=' + rc + ') — см. /tmp/warp_apk.log');
			exit(1);
		}
		push(detail_parts, 'openssl-util установлен (apk)');
	}

	/* 2. Ключ-пара. */
	stage(op_id, 'keygen');
	const workdir = '/tmp/warp_reg_' + op_id;
	mkdir_p(workdir);
	const keys = wg_keygen(workdir);
	if (keys == null) {
		finish(op_id, false, false, 'генерация X25519-ключа не удалась (openssl)');
		exit(1);
	}

	/* 3. Регистрация (прямая → через прокси). */
	stage(op_id, 'register');
	const doc = cf_register(keys.pub, workdir);
	if (doc == null) {
		finish(op_id, false, false, 'Cloudflare не ответил (регистрация не удалась — прямая и через прокси)');
		exit(1);
	}

	/* 4. Профиль. */
	stage(op_id, 'profile');
	const ex = extract_profile(doc, keys, time());
	if (ex.error != null) {
		finish(op_id, false, false, 'ответ Cloudflare не разобран: ' + ex.error);
		exit(1);
	}
	const profile = ex.profile;
	/* СТАРЫЙ профиль (renew) — удалить устройство на стороне Cloudflare
	 * (гигиена аккаунтов; best-effort). */
	if (action === 'renew') {
		const old = read_profile();
		if (old != null && length(old.device_id) && length(old.token))
			cf_delete_device(old);
	}
	mkdir_p(HP_DIR);
	const ptmp = PROFILE_PATH + '.tmp';
	writefile(ptmp, sprintf('%J', profile) + '\n');
	chmod(ptmp, 384);
	system(`mv ${shellquote(ptmp)} ${shellquote(PROFILE_PATH)}`);
	push(detail_parts, 'profile записан (0600)');

	/* 5. UCI-узел. */
	stage(op_id, 'uci');
	uci_apply(profile, true, detail_parts);

	/* 6. reload + верификация (hiddify-c + слушатель warp-in). */
	stage(op_id, 'reload');
	const rc = run_initd(op_id, 'reload');
	stage(op_id, 'verifying');
	const v = verify_core(op_id);
	const parts = [];
	if (length(rc) && rc != '0')
		push(parts, 'init.d rc=' + rc);
	if (length(v.note))
		push(parts, v.note);
	let inbound_ok = false;
	for (let i = 0; i < 10; i++) {
		const ns = capture(`netstat -lnt 2>/dev/null | grep ':${WARP_IN_PORT} '`);
		if (length(trim(ns))) { inbound_ok = true; break; }
		heartbeat(op_id);
		sleep(1500);
	}
	if (!inbound_ok)
		push(parts, 'warp-in ' + WARP_IN_PORT + ' не слушается');
	const ok = v.ok && inbound_ok;
	finish(op_id, ok, ok, join('; ', parts));
	system(`rm -rf ${shellquote(workdir)}`);
	if (!ok)
		exit(1);
};

function main() {
	const op_id = '' + (ARGV[0] || '');
	const action = '' + (ARGV[1] || '');
	const op = get_op(op_id);
	if (!op || op.action !== action || (action !== 'register' && action !== 'renew'))
		exit(1);   /* нет записи операции — протоколировать некуда */

	const detail_parts = [];
	try {
		do_register(op_id, action, detail_parts);
	} catch (e) {
		try { finish(op_id, false, false, 'runner crashed: ' + e); } catch (e2) { exit(1); }
		exit(1);
	}
}

main();
