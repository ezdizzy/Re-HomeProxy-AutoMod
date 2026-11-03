#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Ф3.4 миграция упразднённых значений routing_mode (D23).
//
// Custom routing / Custom JSON упразднены в Ф3.1 (ч.168): генератор, firewall,
// демоны и UI читают только канонические режимы (proxy_banned_ru / global /
// direct + region-режимы bypass_cn/bypass_ir). Этот мигратор — ЕДИНСТВЕННОЕ
// место, где legacy-значение переписывается в UCI: вызывается из init.d
// start_service ДО оценки гейтов, идемпотентен (на каноническом значении —
// мгновенный тихий выход; скрипт выполняется на каждом старте).
//
// Протокол миграции (🔴 мутации UCI пользователя — только со снимком):
//   1. Снимок /etc/config/homeproxy ЦЕЛИКОМ в
//      /etc/homeproxy/backups/routing_mode-migration-<ts>/config —
//      датированный, как у механизма снимков «Обслуживания»; копирование
//      через .tmp-каталог + mv: недописанный снимок не получает финальное
//      имя. Семья routing_mode-migration-* НЕ входит в ротацию
//      app_snapshot_create («новейшие 8» snapshot-*) — снимки пользователя
//      миграционными не вытесняются. Откат — вручную из снимка.
//   2. Снимок не создался → миграция НЕ выполняется (fail closed): значение
//      UCI остаётся прежним, честное событие в шину, а init.d-гейты за этот
//      старт нормализуют режим локально (защитная ветка в start_service).
//      Следующая попытка — при следующем старте службы.
//   3. Снимок создан → routing_mode = proxy_banned_ru (cursor set+save+commit,
//      урок 184) → перечитать СВЕЖИМ курсором и сверить (урок 119: кэш
//      курсора после внешних коммитов доверять нельзя).
//   4. Честное событие в Event Bus (src='init', урок 228: эмиссия живёт в
//      пишущем коде, не в CLI): старое значение, новое значение, ПУТЬ СНИМКА
//      и рецепт отката. Лента LuCI ([Служба]) + Telegram (kind service,
//      toggle push_service).
//
// Откат (документируется в событии): вернуть значение из снимка
// (uci set homeproxy.config.routing_mode=<старое> + uci commit homeproxy)
// или восстановить файл снимка целиком, затем перезапустить службу —
// мигратор сработает снова (идемпотентность = повторная миграция со свежим
// снимком; проверено живьём при приёмке Ф3.4).
//
// Уроки: 216 (top-level const — наверх файла, ниже функций невидима), 2/93/126
// (хелперы выше вызывающих — hoisting отсутствует), 2/111 (fs-функции — popen —
// без импорта не существуют; живой лов приёмки Ф3.4), 112/167 (system() одной
// строкой + shellquote), 90 (strftime в standalone ucode нет — дата через
// date(1)), 209 (отсутствие routing_mode все читатели трактуют одинаково как
// proxy_banned_ru — значение НЕ дописывается), 20 (for-in по массиву даёт
// ЭЛЕМЕНТЫ — здесь явные сравнения вместо цикла), 221/207 (try/finally нет —
// try/catch вокруг мутационной части; const в блоке — блочный скоуп).

'use strict';

import { cursor } from 'uci';
import { access, stat, popen } from 'fs';
import { emit } from '/etc/homeproxy/scripts/eventbus.uc';

const CONF_FILE = '/etc/config/homeproxy';
const BK_DIR = '/etc/homeproxy/backups';
const WORKING_MODE = 'proxy_banned_ru';

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

/* Формат 20260101-123456 — как у снапшотов «Обслуживания» (урок 90). */
function ts14() {
	return trim(capture('date +%Y%m%d-%H%M%S 2>/dev/null'));
}

/* Честный отказ: событие best-effort + строка для init.d-лога, exit 1.
 * Значение UCI не тронуто — гейты этого старта нормализуют локально. */
function fail(msg) {
	emit('init', 'warn', 'routing_mode',
		'Миграция НЕ выполнена: ' + msg + ' Значение routing_mode оставлено прежним; служба запустится в рабочем режиме по защитной нормализации гейтов (ветка legacy в init.d), повторная попытка — при следующем старте.');
	print('migration failed: ' + msg + '\n');
	exit(1);
}

/* ── миграция ──────────────────────────────────────────────────────────── */

const uci = cursor();
uci.load('homeproxy');

const raw = uci.get('homeproxy', 'config', 'routing_mode');
const mode = (raw == null) ? '' : '' + raw;

/* Идемпотентный быстрый путь: цель — ТОЛЬКО упразднённые значения (D23).
 * Отсутствие/пустое значение не дописывается: все читатели (генератор,
 * init.d, RPC, демоны, UI) трактуют его одинаково как рабочий режим
 * (урок 209: один читатель — одна семантика). */
if (mode !== 'custom' && mode !== 'custom_json')
	exit(0);

/* Снимок + перезапись + перечитка — под try/catch (🔴 try/finally на этой
 * сборке нет, урок 221): ЛЮБОЙ сбой (в т.ч. непойманный билтин) обязан дать
 * честное событие и строку в init.d-лог, а не сырой краш. Путь снимка
 * поднимается наверх (const в try-блоке — блочный скоуп, урок 207). */
let snap_dir = null;

try {
	/* 1. Снимок ДО мутации. */
	const ts = ts14();
	if (!length(ts))
		fail('date(1) не вернул метку времени.');
	const dir = BK_DIR + '/routing_mode-migration-' + ts;
	const tmpdir = BK_DIR + '/.rm-mig-' + ts + '.tmp';
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
	uci.set('homeproxy', 'config', 'routing_mode', WORKING_MODE);
	uci.save('homeproxy');
	uci.commit('homeproxy');

	/* 3. Свежим курсором перечитать факт записи (урок 119). */
	const vfy = cursor();
	vfy.load('homeproxy');
	const after = '' + (vfy.get('homeproxy', 'config', 'routing_mode') || '');
	if (after !== WORKING_MODE)
		fail('запись UCI не подтвердилась (осталось "' + after + '"); снимок: ' + snap_dir + '/config.');
} catch (e) {
	fail('исключение: ' + ((e != null && e.message != null) ? e.message : '' + e) + '.');
}

/* 4. Честное событие в шину (путь снимка + рецепт отката). */
const ev_id = emit('init', 'warn', 'routing_mode',
	'Упразднённый режим "' + mode + '" (D23) перенесён в "' + WORKING_MODE + '" («Обход блокировок»). Прежняя конфигурация сохранена: ' + snap_dir + '/config. Откат: вернуть значение routing_mode вручную (uci set homeproxy.config.routing_mode=' + mode + ' + uci commit homeproxy) или восстановить файл из снимка, затем перезапустить службу.');

print('migrated: routing_mode "' + mode + '" -> "' + WORKING_MODE + '"; snapshot: ' + snap_dir + '/config; event: ' + ((ev_id == null) ? 'none (bus unavailable)' : 'id ' + ev_id) + '\n');
exit(0);
