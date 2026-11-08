#!/usr/bin/ucode
/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Р9 ШАГ 3 (план 22, ч.253): мигратор UCI/каталогов homeproxy → ravnex.
 * Вызывается из /etc/uci-defaults/luci-homeproxy-migration ПЕРЕД migrate_config.uc
 * (apk post-install и post-upgrade; ipk postinst).
 *
 * Дизайн (ч.252/ч.253):
 *  - ГЕЙТ: /etc/config/homeproxy отсутствует → выход (свежая установка/уже мигрировано).
 *    НЕ «ravnex есть → выход»: пакет поставил дефолт /etc/config/ravnex, реальный конфиг
 *    пользователя едет СВЕРХУ (перезапись).
 *  - SNAPSHOT 1: apk pre-upgrade скрипт тарит /etc/homeproxy + конфиги в
 *    /root/ravnex-premigrate-<ts>/ ДО распаковки (apk снимет не-conffile'ы старого дерева;
 *    изменённые conffile переживут, не изменённые — нет, overlay берём ИЗ снапшота).
 *  - SNAPSHOT 2: сюда, /etc/ravnex/backups/premigrate-<ts>/ (конфиги + firewall) — виден
 *    в приложении, правило мутаций UCI.
 *  - Config: /etc/config/homeproxy → /etc/config/ravnex (типы секций ^config homeproxy →
 *    ^config ravnex, атомарная запись, перезапись дефолта), homecontrol → ravcontrol
 *    (без типов-переименований: там main/dummy/...).
 *  - Firewall: секции-инклуды homeproxy_{forward,input,post,pre} → ravnex_* + опция path
 *    /var/run/homeproxy/... → /var/run/ravnex/... (курсор: rename + set, commit firewall).
 *  - Overlay состояния пользователя ИЗ снапшота (или живого /etc/homeproxy как фолбэк):
 *    resources/, certs/, ruleset/, backups/ + корневые файлы; scripts/ НЕ переносится —
 *    новый пакетный код побеждает (урок 389).
 *  - /var/run/homeproxy → /var/run/ravnex (tmpfs mv/merge).
 *  - init.d: удалить старый /etc/init.d/homeproxy (+ .apk-new) и rc-линки K10/S99homeproxy,
 *    /etc/init.d/ravnex enable.
 *  - Мусор: dnsmasq-homeproxy.{conf,d}, acl.d/luci-app-re-homeproxy.json.pre237 → /root.
 *  - Идемпотентен: повторный прогон — no-op. Всегда rc=0 (контракт uci-defaults).
 */

'use strict';

import { access, readfile, open, stat, popen } from 'fs';
import { cursor } from 'uci';
import { atomic_write } from '/etc/ravnex/scripts/statestore.uc';
import { emit } from '/etc/ravnex/scripts/eventbus.uc';

const TS = time();

function log(msg) {
	const fd = open('/var/run/ravnex_migrate.log', 'a');
	if (fd) {
		fd.write(sprintf('[%d] %s\n', TS, msg));
		fd.close();
	}
}

function sh(cmd) {
	return system(cmd + ' 2>/dev/null; true');
}

function readtext(path) {
	try {
		const fd = open(path, 'r');
		if (!fd) return null;
		const body = fd.read('all');
		fd.close();
		return (length(body)) ? body : null;
	} catch (e) { return null; }
}


function mkdirs(path) {
	sh('mkdir -p ' + "'" + replace(path, "'", "'\\''") + "'");
}

/* Рекурсивный overlay: каждое содержимое src/. поверх dst/ (merge, файлы src побеждают). */
function overlay_dir(src, dst) {
	if (!access(src)) return 0;
	mkdirs(dst);
	/* busybox cp: -p сохраняет времена/права; /. копирует содержимое */
	return sh('cp -rp ' + "'" + src + "/.'" + " " + "'" + dst + "/'");
}

/* Новейший каталог пре-снапшота с домашним деревом внутри. */
function newest_pre_snapshot() {
	let fd = popen('ls -1d /root/ravnex-premigrate-* 2>/dev/null');
	if (!fd) return null;
	let body = fd.read('all');
	fd.close();
	const lines = split(trim(body || ''), '\n');
	let best = null, best_ts = 0;
	for (let l in lines) {
		const t = trim(l);
		if (!length(t) || !access(t + '/homeproxy'))
			continue;
		const m = match(t, /([0-9]+)$/);
		const ts = m ? int(m[1]) : 0;
		if (ts >= best_ts) {
			best = t;
			best_ts = ts;
		}
	}
	return best;
}

/* ── 1. Гейт ─────────────────────────────────────────────────────────────── */
if (!access('/etc/config/homeproxy')) {
	/* Свежая установка или миграция уже выполнена. */
	log('gate: /etc/config/homeproxy absent — nothing to migrate');
	exit(0);
}

log('migrate: start (homeproxy → ravnex)');

/* ── 2. Snapshot 2 (в приложение) ───────────────────────────────────────── */
const snap_dir = '/etc/ravnex/backups/premigrate-' + TS;
sh('mkdir -p ' + "'" + snap_dir + "'");
sh('cp -p /etc/config/homeproxy /etc/config/homecontrol /etc/config/firewall ' + "'" + snap_dir + "/' 2>/dev/null");
sh('find /etc/homeproxy -maxdepth 1 -type f -exec cp -p {} ' + "'" + snap_dir + "/' \\; 2>/dev/null");

/* ── 3. Конфиги: homeproxy → ravnex (с типами секций) ───────────────────── */
const hp_raw = readtext('/etc/config/homeproxy');
if (hp_raw != null) {
	let out_lines = [];
	for (let line in split(hp_raw, '\n')) {
		if (index(line, 'config homeproxy ') === 0)
			line = 'config ravnex ' + substr(line, length('config homeproxy '));
		push(out_lines, line);
	}
	atomic_write('/etc/config/ravnex', join('\n', out_lines));
	log('uci: /etc/config/ravnex written from user homeproxy (types renamed)');
}

const hc_raw = readtext('/etc/config/homecontrol');
if (hc_raw != null)
	atomic_write('/etc/config/ravcontrol', hc_raw);

/* Удаление старых конфигов (+ apk-хвосты) — ПОСЛЕ записи новых. */
sh('rm -f /etc/config/homeproxy /etc/config/homeproxy.apk-new /etc/config/homecontrol /etc/config/homecontrol.apk-new');

/* ── 4. Firewall-инклуды: rename + path ─────────────────────────────────── */
try {
	const fw = cursor();
	const fw_map = { homeproxy_forward: 'ravnex_forward', homeproxy_input: 'ravnex_input',
	                 homeproxy_post: 'ravnex_post', homeproxy_pre: 'ravnex_pre' };
	for (let old, nu in fw_map) {
		const s = fw.get_all('firewall', old);
		if (type(s) !== 'object')
			continue;
		fw.rename('firewall', old, nu);
		const path = '' + (s.path || '');
		if (index(path, '/var/run/homeproxy/') === 0)
			fw.set('firewall', nu, 'path', '/var/run/ravnex/' + substr(path, length('/var/run/homeproxy/')));
	}
	fw.commit('firewall');
	log('firewall: includes renamed to ravnex_* with /var/run/ravnex paths');
} catch (e) {
	log('firewall: cursor failed (' + e + ') — shell fallback');
	sh('for s in forward input post; do uci -q rename firewall.homeproxy_$s=ravnex_$s 2>/dev/null; done; ' +
	   'uci -q set firewall.ravnex_forward.path=/var/run/ravnex/fw4_forward.nft; ' +
	   'uci -q set firewall.ravnex_input.path=/var/run/ravnex/fw4_input.nft; ' +
	   'uci -q set firewall.ravnex_post.path=/var/run/ravnex/fw4_post.nft; ' +
	   'uci -q delete firewall.homeproxy_pre 2>/dev/null; uci commit firewall');
}

/* ── 5. Overlay пользовательского состояния ─────────────────────────────── */
const snap = newest_pre_snapshot();
let overlay_src = null;
if (snap != null) {
	overlay_src = snap + '/homeproxy';
	log('overlay source: pre-upgrade snapshot ' + overlay_src);
} else if (access('/etc/homeproxy')) {
	overlay_src = '/etc/homeproxy';
	log('overlay source: live /etc/homeproxy (no pre-upgrade snapshot found)');
}
if (overlay_src != null) {
	for (let d in [ 'resources', 'certs', 'ruleset', 'backups' ])
		overlay_dir(overlay_src + '/' + d, '/etc/ravnex/' + d);
	/* Корневые файлы (zapret_candidates.json, device_verdicts.json, ...). */
	sh('find ' + "'" + overlay_src + "'" + ' -maxdepth 1 -type f -exec cp -rp {} /etc/ravnex/ \\;');
	log('overlay: user state copied over fresh /etc/ravnex (scripts/ untouched — package wins)');
} else {
	log('overlay: nothing to overlay (no snapshot, no /etc/homeproxy)');
}

/* ── 6. /var/run: tmpfs состояние демонов ───────────────────────────────── */
if (access('/var/run/homeproxy')) {
	if (!access('/var/run/ravnex')) {
		sh('mv /var/run/homeproxy /var/run/ravnex');
		log('runtime: mv /var/run/homeproxy → /var/run/ravnex');
	} else {
		sh('cp -rp /var/run/homeproxy/. /var/run/ravnex/ && rm -rf /var/run/homeproxy');
		log('runtime: merged /var/run/homeproxy into existing /var/run/ravnex');
	}
}
sh('rm -rf /tmp/dnsmasq.d/dnsmasq-homeproxy.d /tmp/dnsmasq.d/dnsmasq-homeproxy.conf');

/* ── 7. init.d: новый сервис включить, старый убрать ────────────────────── */
sh('rm -f /etc/rc.d/K10homeproxy /etc/rc.d/S99homeproxy /etc/init.d/homeproxy /etc/init.d/homeproxy.apk-new');
if (!access('/etc/rc.d/S99ravnex'))
	sh('/etc/init.d/ravnex enable');
log('init: ravnex enabled, homeproxy init removed');

/* ── 8. ch.255 Р9 (мост переименования пакета): две страховки для бокса,
 * который апгрейдится с до-ренейм сборки, пока СТАРЫЙ руннер обновления ещё
 * жив (его код неизменяем — он целится в легаси-пути):
 *  - симлинк /var/run/homeproxy → ravnex: старый opman пишет журнал оп
 *    СКВОЗЬ него в /var/run/ravnex/ops — новый UI видит оп и его честный
 *    вердикт (tmpfs: симлинк умирает сам после ребута);
 *  - отложенный старт ravnex: старый руннер рестартит /etc/init.d/homeproxy,
 *    которого больше нет — без этого бокс простоял бы с выключенным прокси
 *    до ручного старта/ребута. setsid+sleep: не блокирует apk-транзакцию
 *    (урок ч.250), гвардован статусом (не пересоздаёт живой инстанс).
 * До сюда доходят ТОЛЬКО боксы, прошедшие миграцию (гейт выше) — поведение
 * свежих установок не меняется. */
sh('rm -rf /var/run/homeproxy');
sh('ln -sf /var/run/ravnex /var/run/homeproxy');
sh('command -v setsid >/dev/null 2>&1 && setsid sh -c "sleep 2; /etc/init.d/ravnex status >/dev/null 2>&1 || /etc/init.d/ravnex start" >/dev/null 2>&1 &');
log('bridge: /var/run/homeproxy → /var/run/ravnex symlinked; ravnex start scheduled');

/* Мусор прошлых сессий (ч.251 урок: не держать бэкапы рядом с живыми). */
sh('[ -f /usr/share/rpcd/acl.d/luci-app-re-homeproxy.json.pre237 ] && mv /usr/share/rpcd/acl.d/luci-app-re-homeproxy.json.pre237 /root/ 2>/dev/null; true');

/* Финальный маркер — последующие прогоны увидят отсутствие homeproxy-конфига. */
log('migrate: done; new canon md5:');
let fdm = popen('md5sum /etc/config/ravnex /etc/config/ravcontrol 2>/dev/null');
if (fdm) {
	const body = fdm.read('all');
	fdm.close();
	for (let l in split(trim(body || ''), '\n'))
		if (length(trim(l)))
			log('canon: ' + trim(l));
}
try {
	emit('migrate', 'info', 'uci/catalog', 'homeproxy → ravnex выполнен; снапшот ' + snap_dir);
} catch (e) { /* best-effort */ }
exit(0);
