#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Ф9.14 миграция lan_proxy_mode (D34d, решение пользователя).
//
// Значение «disabled» («Отключён») упразднено: в модели nft оно означало
// «фильтр устройств выключен — ВСЕ устройства идут через прокси, а списки
// «Напрямую»/«Прокси» ИГНОРИРУЮТСЯ» (firewall_post.ut: ветки списков только
// в listed_only/except_listed). Новая модель — режим на карточке устройства:
// «Auto» = глобальный режим, и «Напрямую» обязан работать всегда. Канон:
//   except_listed = «все через прокси, кроме отмеченных „Напрямую"»
//   listed_only   = «только отмеченные „Прокси"»
// except_listed с ПУСТЫМ списком «Напрямую» ведёт себя байт-в-байт как
// старый disabled (все через прокси), поэтому миграция не меняет поведение
// текущих установок. Секция — 'control': firewall_post.ut читает списки
// ИМЕННО из homeproxy.control (probe live ч.207). Мигратор — ЕДИНСТВЕННОЕ
// место, где legacy-значение переписывается: вызывается из init.d
// start_service ДО генерации конфига, идемпотентен (на каноническом
// значении — мгновенный тихий выход).
//
// Протокол миграции (🔴 мутации UCI пользователя — только со снимком):
//   1. Снимок /etc/config/ravnex ЦЕЛИКОМ в
//      /etc/ravnex/backups/lan_mode-migration-<ts>/config — датированный,
//      .tmp-каталог + mv (недописанный снимок не получает финальное имя).
//      Семья lan_mode-migration-* НЕ входит в ротацию app_snapshot_create.
//   2. Снимок не создался → миграция НЕ выполняется (fail closed): значение
//      остаётся прежним, честное событие в шину; nft-семантика disabled и
//      except_listed совпадает при пустом списке «Напрямую», поэтому расхождение
//      окно-в-окно безвредно. Повторная попытка — при следующем старте.
//   3. Снимок создан → lan_proxy_mode = except_listed (set + save + commit,
//      урок 184) → перечитать СВЕЖИМ курсором (урок 119).
//   4. Честное событие в Event Bus (src='init'): старое значение, новое
//      значение, путь снимка, рецепт отката.
//
// Откат (документируется в событии): вернуть значение из снимка
// (uci set ravnex.config.lan_proxy_mode=<старое> + uci commit ravnex)
// или восстановить файл снимка целиком, затем перезапустить службу.
//
// Уроки: 216/78 (top-level const наверх), 2/93/126 (хелперы выше вызывающих),
// 2/111 (fs-функции — только с импортом), 112/167 (system одной строкой +
// shellquote), 90 (strftime в standalone ucode нет — date(1)), 20/249 (for-in
// по массиву = элементы; push/sort — глобальные), 221/207 (try/finally нет —
// try/catch; const в блоке — блочный скоуп), 209 (отсутствие значения здесь
// НЕ «канон»: unset означал disabled = игнор списков, поэтому дописываем).

'use strict';

import { cursor } from 'uci';
import { access, stat, popen } from 'fs';
import { emit } from '/etc/ravnex/scripts/eventbus.uc';

const CONF_FILE = '/etc/config/ravnex';
const BK_DIR = '/etc/ravnex/backups';
const WORKING_MODE = 'except_listed';

/* ── хелперы (выше вызывающих — ucode без hoisting) ────────────────────── */

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function capture(cmd) {
	const fd = popen(cmd);
	let out = '';
	if (fd) { out = fd.read('all') || ''; fd.close(); }
	return out;
}

function ts14() {
	return trim(capture('date +%Y%m%d-%H%M%S 2>/dev/null'));
}

function fail(msg) {
	emit('init', 'warn', 'lan_proxy_mode',
		'Миграция НЕ выполнена: ' + msg + ' Значение lan_proxy_mode оставлено прежним (семантика «disabled» и «except_listed» совпадает при пустом списке «Напрямую»); повторная попытка — при следующем старте службы.');
	print('migration failed: ' + msg + '\n');
	exit(1);
}

/* ── миграция ──────────────────────────────────────────────────────────── */

const uci = cursor();
uci.load('ravnex');

const raw = uci.get('ravnex', 'control', 'lan_proxy_mode');

/* Идемпотентный быстрый путь: цель — ТОЛЬКО legacy (disabled или отсутствие).
 * Канонические except_listed/listed_only не трогаем. */
if (raw != null && raw !== 'disabled')
	exit(0);

const old_label = (raw == null) ? '<не задано (=disabled)>' : 'disabled';

let snap_dir = null;

try {
	/* 1. Снимок ДО мутации. */
	const ts = ts14();
	if (!length(ts))
		fail('date(1) не вернул метку времени.');
	const dir = BK_DIR + '/lan_mode-migration-' + ts;
	const tmpdir = BK_DIR + '/.lanmig-' + ts + '.tmp';
	system('mkdir -p ' + shellquote(BK_DIR) + ' ' + shellquote(tmpdir));
	system('cp ' + shellquote(CONF_FILE) + ' ' + shellquote(tmpdir + '/config'));
	const st = stat(tmpdir + '/config');
	if (!access(tmpdir + '/config') || !st || st.size <= 0) {
		system('rm -rf ' + shellquote(tmpdir));
		fail('снимок ' + CONF_FILE + ' не создан (нет места/прав?).');
	}
	system('mv ' + shellquote(tmpdir) + ' ' + shellquote(dir));
	if (!access(dir + '/config')) {
		system('rm -rf ' + shellquote(tmpdir));
		fail('снимок не получил финальное имя ' + dir + ' (коллизия имени?).');
	}
	snap_dir = dir;

	/* 2. Переписать значение (урок 184: set + save + commit). */
	uci.set('ravnex', 'control', 'lan_proxy_mode', WORKING_MODE);
	uci.save('ravnex');
	uci.commit('ravnex');

	/* 3. Свежим курсором перечитать факт записи (урок 119). */
	const vfy = cursor();
	vfy.load('ravnex');
	const after = '' + (vfy.get('ravnex', 'control', 'lan_proxy_mode') || '');
	if (after !== WORKING_MODE)
		fail('запись UCI не подтвердилась (осталось "' + after + '"); снимок: ' + snap_dir + '/config.');
} catch (e) {
	fail('исключение: ' + ((e != null && e.message != null) ? e.message : '' + e) + '.');
}

/* 4. Честное событие в шину (путь снимка + рецепт отката). */
const ev_id = emit('init', 'warn', 'lan_proxy_mode',
	'Режим устройств «Отключён» (' + old_label + ', D34d) перенесён в «Все через прокси, кроме отмеченных „Напрямую"» (except_listed): поведение прежнее (список «Напрямую» пуст), но карточный режим «Напрямую» теперь работает. Прежняя конфигурация: ' + snap_dir + '/config. Откат: uci set ravnex.control.lan_proxy_mode=disabled + uci commit ravnex (или восстановить файл из снимка), затем перезапустить службу.');

print('migrated: lan_proxy_mode ' + old_label + ' -> "' + WORKING_MODE + '"; snapshot: ' + snap_dir + '/config; event: ' + ((ev_id == null) ? 'none (bus unavailable)' : 'id ' + ev_id) + '\n');
exit(0);
