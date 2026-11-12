// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — zapret_profile.uc: единый контракт «стратегия → ресурс» (сеанс 191).
//
// Канонический парсер/сборщик профилей nfqws2/ciadpi. Источник истины —
// UCI-секции `ravnex.profile` (engine/resource/label/domains/strategy/order),
// применённая строка `ravnex.config.zapret_cmd_opts` — ПРОИЗВОДНАЯ (сборка
// из профилей) и всегда зеркалится. Импортируется и rpcd-модулем
// (luci.ravnex — прецедент строк 36–60), и демонами из scripts/.
//
// Правила ucode (уроки 2/20/105/245/402/405/417): без hoisting — хелперы
// ВЫШЕ вызывающих; for..in по массиву = ЭЛЕМЕНТЫ; match() со строковым
// паттерном молча null — только regex-литералы; type() вместо typeof;
// json()/sprintf('%.J') доступны.

import { access, readfile } from 'fs';

export const HP_DIR = '/etc/ravnex';

/* Словарь скоупов КАК ДАННЫЕ (аудит 191 §2.2: раньше — хардкод трёх
 * подстрок в двух местах, любая чужая область молча деградировала в
 * «catch-all»). Расширение нового ресурса = одна запись здесь.
 *   files: канонические hostlist-файлы (точное совпадение хвоста пути);
 *   names: подстроки пути файла (легаси-эвристика);
 *   doms:  отличительные домены для --hostlist-domains=CSV. */
export const SCOPE_RES = {
	youtube:  { files: [ 'resources/zapret-hosts/youtube.txt' ],
	            names: [ 'youtube' ], doms: [ 'googlevideo', 'youtu' ] },
	discord:  { files: [ 'resources/zapret-hosts/discord.txt' ],
	            names: [ 'discord' ], doms: [ 'discord' ] },
	telegram: { files: [ 'resources/engine_telegram.txt' ],
	            names: [ 'telegram' ], doms: [ 'telegram' ] }
};

export const RESOURCES = [ 'youtube', 'discord', 'telegram', 'general', 'custom' ];

/* Валидные ресурсы профиля (аудит: единый словарь — карта/композиция/
 * подбор говорят об «ресурсе» одно и то же). 'custom' без валидных
 * доменов = честная ошибка сборки. */
export function resource_valid(res) {
	/* RESOURCES — МАССИВ (урок 103: индексация массива строкой = null) —
	 * линейный поиск честен и дешевле граблей. */
	for (let i = 0; i < length(RESOURCES); i++)
		if (RESOURCES[i] === res)
			return true;
	return false;
};

/* ── Парс строки стратегии ───────────────────────────────────────────── */

/* Разрез по '--new' (урок 77: никогда по запятым/пробелам — блоки несут
 * собственные многотокен-опции). */
export function split_new(args) {
	const raw = split('' + args, '--new');
	const blocks = [];
	for (let i = 0; i < length(raw); i++) {
		const b = trim(raw[i]);
		if (length(b))
			push(blocks, b);
	}
	return blocks;
};

/* Глобальные --blob токены — общеядровые, обязаны сидеть перед первым
 * профилем; выносятся из блока (probe T8 сеанса 13). */
export function extract_blobs(block) {
	const toks = split(block, ' ');
	const rest = [], blobs = [];
	for (let i = 0; i < length(toks); i++) {
		const t = trim(toks[i]);
		if (!length(t))
			continue;
		if (index(t, '--blob=') === 0)
			push(blobs, t);
		else
			push(rest, t);
	}
	return [ join(' ', rest), blobs ];
};

/* Скоуп блока: youtube|discord|telegram|<custom-label>|null.
 * 1) --hostlist=<путь>: точное совпадение хвоста пути с каноническим
 *    файлом ресурса, затем легаси-эвристика по подстроке имени, затем
 *    метки кастомных профилей;
 * 2) --hostlist-domains=CSV: ТОЧНОЕ нормализованное равенство CSV с
 *    множеством доменов кастомного профиля (идентифицирует блок, собранный
 *    из профиля), затем отличительные домены словаря, затем метки;
 * 3) иначе null (catch-all).
 * labels = { канонический-CSV/домен: 'имя' } — кастомные профили UCI. */

/* Нормализованный CSV доменов: нижний регистр, разделители [пробел/,/;]
 * → ',', пустые выброшены. Это ровно тот вид, который compose кладёт в
 * --hostlist-domains (join(',', domains_for(...))) — ключ идентичности
 * «профиль ↔ блок» для block_scope (с.194). */
export function csv_norm(s) {
	const raw = split('' + (s || ''), /[[:space:],;]+/);
	const out = [];
	for (let i = 0; i < length(raw); i++) {
		const d = lc(trim(raw[i]));
		if (length(d))
			push(out, d);
	}
	return join(',', out);
};

/* ends_with на положительных оффсетах (урок 103: отрицательный substr на
 * этой сборке не проверен — не рискуем, префиксные сравнения честны).
 * ОБЪЯВЛЕНА ВЫШЕ block_scope (урок 405 — лексическая резолюция). */
function ends_with(s, suffix) {
	const l = length(suffix);
	if (!l || length(s) < l)
		return false;
	return substr(s, length(s) - l) === suffix;
}

export function block_scope(block, labels) {
	const raw = '' + block;
	const mh = match(raw, /--hostlist=(\/[^ ]+)/);
	if (mh != null) {
		const f = '' + mh[1];
		for (let res in SCOPE_RES) {
			const fl = SCOPE_RES[res].files;
			for (let i = 0; i < length(fl); i++)
				if (ends_with(f, fl[i]))
					return res;
		}
		for (let res2 in SCOPE_RES) {
			const nm = SCOPE_RES[res2].names;
			for (let j = 0; j < length(nm); j++)
				if (index(f, nm[j]) >= 0)
					return res2;
		}
		if (labels != null)
			for (let key in labels)
				if (index(f, key) >= 0)
					return labels[key];
		return null;
	}
	const md = match(raw, /--hostlist-domains=([^ ]+)/);
	if (md != null) {
		const csv = '' + md[1];
		/* Метки кастомных профилей UCI — ПЕРВЫМИ, по ТОЧНОМУ
		 * нормализованному равенству множества доменов: compose кладёт в
		 * блок ровно CSV профиля, так что равенство ИДЕНТИФИЦИРУЕТ блок.
		 * Без этого CSV известных ресурсов, содержащий их
		 * отличительные домены (youtube-хостлист несёт googlevideo),
		 * затенял кастомный профиль googlevideo.com — его блок
		 * приписывался youtube, а строка карты кастома оставалась без
		 * стратегии (репорт с.194). Отличительные домены — ПОСЛЕ
		 * равенства; подстрочный фолбэк меток — последним. */
		const cn = csv_norm(csv);
		if (labels != null)
			for (let key in labels)
				if (cn == csv_norm(key))
					return labels[key];
		for (let res3 in SCOPE_RES) {
			const dm = SCOPE_RES[res3].doms;
			for (let k = 0; k < length(dm); k++)
				if (index(csv, dm[k]) >= 0)
					return res3;
		}
		if (labels != null)
			for (let key2 in labels)
				if (index(csv, key2) >= 0)
					return labels[key2];
	}
	return null;
};

/* Валидатор домена (умела ≤253, ASCII-набор). */
export function domain_ok(d) {
	return (length(d) >= 3 && length(d) <= 253 && !!match(d, /^[A-Za-z0-9._-]+$/));
};

/* Домены профиля: файловые списки известных ресурсов или строка custom.
 * null = general (catch-all) / нет валидных доменов. */
export function domains_for(resource, custom_domains) {
	if (resource === 'general')
		return null;
	let out = [];
	if (resource === 'custom') {
		const raw = split('' + (custom_domains || ''), /[[:space:],;]+/);
		for (let i = 0; i < length(raw); i++) {
			const d = trim(raw[i]);
			if (length(d) && domain_ok(d))
				push(out, d);
		}
		if (!length(out))
			return null;
	} else {
		const fl = SCOPE_RES[resource];
		if (fl == null)
			return null;
		for (let fi = 0; fi < length(fl.files); fi++) {
			const f = HP_DIR + '/' + fl.files[fi];
			if (!access(f))
				continue;
			const raw2 = split(readfile(f) || '', '\n');
			for (let i = 0; i < length(raw2); i++) {
				const d = trim(raw2[i]);
				if (!length(d) || substr(d, 0, 1) === '#')
					continue;
				if (domain_ok(d))
					push(out, d);
			}
			if (length(out))
				break;
		}
		if (!length(out))
			return null;
	}
	/* Санитарный кап: hostlist-строка обязана остаться sane-опцией. */
	if (length(out) > 128) {
		const capped = [];
		for (let i = 0; i < 128; i++)
			push(capped, out[i]);
		out = capped;
	}
	return out;
};

/* Резолв стратегии профиля: raw-аргументы с '--' либо имя корпуса.
 * null = неразрешимо/запрещённые символы (форма-гвард ЕДИНАЯ для всех
 * вызывающих: длина ≤ 8000, без ` $ ; & | < > \n \r). */
export function resolve_strategy(strategy, corpus) {
	const s = trim('' + (strategy || ''));
	if (!length(s))
		return null;
	if (index(s, '-') === 0) {
		/* nfqws2 ('--...') И ciadpi ('-...') несут raw-аргументы с дефиса
		 * (урок 191-испытания: '--'-гвард ломал все профильные стратегии
		 * ByeDPI). Corpus-имена с дефиса не начинаются. */
		if (length(s) > 8000 || match(s, /[`$;&|<>\n\r]/))
			return null;
		return s;
	}
	const cands = (corpus != null && type(corpus.candidates) === 'array')
		? corpus.candidates : [];
	for (let i = 0; i < length(cands); i++) {
		const c = cands[i];
		if (type(c) === 'object' && c.name === s)
			return '' + c.args;
	}
	return null;
};

/* ciadpi group/instance-опции только от КОНСТРУКТОРА (аудит ч.109). */
export function ciadpi_struct(args) {
	const banned = { '-A': 1, '--auto': 1, '-H': 1, '--hosts': 1, '-K': 1,
		'--proto': 1, '-j': 1, '--ipset': 1, '-V': 1, '--pf': 1,
		'-i': 1, '--ip': 1, '-p': 1, '--port': 1 };
	const prefixes = [ '--auto=', '--hosts=', '--proto=', '--ipset=', '--pf=',
		'--ip=', '--port=', '-A:', '-H:', '-K:', '-j:', '-V:', '-i:', '-p:' ];
	const toks = split('' + args, ' ');
	for (let i = 0; i < length(toks); i++) {
		const t = trim(toks[i]);
		if (!length(t))
			continue;
		if (banned[t])
			return t;
		for (let pi = 0; pi < length(prefixes); pi++)
			if (index(t, prefixes[pi]) === 0)
				return t;
	}
	return null;
};

/* ── Сборка строк из профилей ────────────────────────────────────────── */

/* Zapret-строка из профилей. Порядок: blobs → scoped-блоки → general-хвост
 * (--new между; первое совпадение в nfqws2 выигрывает). ВАЖНО, исправление
 * аудита 191: has_own_hl проверяется НА БЛОК, не на всю стратегию —
 * смешанная стратегия (часть блоков с hostlist, часть без) больше не даёт
 * незаскопленных блоков. Возвращает { zapret, notes } | { error }. */
export function build_zapret(profiles, corpus) {
	const notes = [];
	const blob_map = {};
	const scoped = [], general = [];
	let n = 0;
	for (let i = 0; i < length(profiles); i++) {
		const p = profiles[i];
		if (p == null || type(p) !== 'object')
			return { error: 'плохой профиль #' + (i + 1) };
		if (('' + (p.engine || 'zapret')) !== 'zapret')
			continue;
		const res = trim('' + (p.resource || 'general'));
		if (!resource_valid(res))
			return { error: 'неизвестный ресурс: ' + res };
		const args = resolve_strategy(p.strategy, corpus);
		if (args == null)
			return { error: 'неизвестная или пустая стратегия: ' + trim('' + (p.strategy || '')) };
		if (length(args) > 2000)
			return { error: 'стратегия длиннее 2000 символов' };
		const doms = domains_for(res, p.domains);
		if (res === 'custom' && doms == null)
			return { error: 'у пользовательского профиля нет валидных доменов' };
		if (res !== 'general' && res !== 'custom' && doms == null)
			return { error: 'нет hostlist для ресурса: ' + res };
		n++;
		const blocks = split_new(args);
		for (let bi = 0; bi < length(blocks); bi++) {
			const ex = extract_blobs(blocks[bi]);
			let blk = ex[0];
			for (let k = 0; k < length(ex[1]); k++)
				blob_map[ex[1][k]] = true;
			/* per-block: у ЭТОГО блока свой hostlist? */
			const has_own_hl = !!match(blk, /--hostlist/);
			if (doms != null && !has_own_hl)
				blk += ' --hostlist-domains=' + join(',', doms);
			if (has_own_hl && doms != null) {
				let seen = false;
				for (let ni = 0; ni < length(notes); ni++)
					if (index(notes[ni], 'несёт свой hostlist') >= 0) { seen = true; break; }
				if (!seen)
					push(notes, 'Zapret: стратегия несёт свой hostlist — привязка к ресурсу к ней НЕ применялась.');
			}
			blk = trim(blk);
			if (length(blk))
				push((doms != null) ? scoped : general, blk);
		}
	}
	if (!n)
		return { zapret: '', notes: notes };
	const blob_arr = [];
	for (let b in blob_map)
		push(blob_arr, b);
	const blocks = [];
	for (let i = 0; i < length(scoped); i++)
		push(blocks, scoped[i]);
	for (let i = 0; i < length(general); i++)
		push(blocks, general[i]);
	let zapret = join(' ', blob_arr);
	for (let i = 0; i < length(blocks); i++)
		zapret += ((length(zapret) ? ' ' : '') + blocks[i]) +
			((i < length(blocks) - 1) ? ' --new' : '');
	while (length(zapret) > 6 && substr(zapret, 0, 6) === '--new ')
		zapret = trim(substr(zapret, 6));
	if (length(zapret) > 8000)
		return { error: 'собранная стратегия Zapret длиннее 8000 символов' };
	if (length(scoped) && length(general))
		push(notes, 'Zapret: профили ресурсов идут первыми, общий профиль — последним (первое совпадение срабатывает).');
	else if (length(scoped) && !length(general))
		push(notes, 'Zapret: общего профиля нет — трафик вне сценарных ресурсов идёт без дезинка (nfqws2 не трогает нераспознанные пакеты).');
	return { zapret: zapret, notes: notes };
};

/* ByeDPI-строка из профилей: группы через '-A n', последняя группа без -H.
 * Возвращает { byedpi, notes } | { error }. */
export function build_byedpi(profiles, corpus) {
	const notes = [];
	const scoped = [];
	let fallback = '';
	let n = 0;
	let tg_note = false;
	for (let i = 0; i < length(profiles); i++) {
		const p = profiles[i];
		if (p == null || type(p) !== 'object')
			return { error: 'плохой профиль #' + (i + 1) };
		if (('' + (p.engine || 'zapret')) !== 'byedpi')
			continue;
		const res = trim('' + (p.resource || 'general'));
		if (!resource_valid(res))
			return { error: 'неизвестный ресурс: ' + res };
		const args = resolve_strategy(p.strategy, corpus);
		if (args == null)
			return { error: 'неизвестная или пустая стратегия: ' + trim('' + (p.strategy || '')) };
		const bad = ciadpi_struct(args);
		if (bad)
			return { error: 'аргументы ByeDPI содержат служебную опцию конструктора: ' + bad };
		const doms = domains_for(res, p.domains);
		if (res === 'custom' && doms == null)
			return { error: 'у пользовательского профиля нет валидных доменов' };
		n++;
		if (res === 'telegram' && doms != null && !tg_note) {
			tg_note = true;
			push(notes, 'Telegram: к доменам привязаны только TLS веб-пути; MTProto UDP-трафик — нет.');
		}
		if (doms != null)
			push(scoped, '-H :' + join(',', doms) + ' -K t ' + args);
		else
			fallback = trim(args);
	}
	if (!n)
		return { byedpi: '', notes: notes };
	let byedpi = join(' -A n ', scoped);
	if (length(fallback))
		byedpi = (length(byedpi) ? byedpi + ' -A n ' : '') + fallback;
	else if (length(scoped)) {
		byedpi += ' -A n';
		push(notes, 'ByeDPI: общего профиля нет — добавлена явная пустая резервная группа; домены вне сценариев идут без дезинка.');
	}
	if (length(byedpi) > 8000)
		return { error: 'собранная стратегия ByeDPI длиннее 8000 символов' };
	if (length(scoped))
		push(notes, 'ByeDPI: сценарные группы только TCP (-K t) с точными доменами; QUIC/UDP-трафик к доменам не привязывается и идёт через резервную группу.');
	return { byedpi: byedpi, notes: notes };
};

/* Обе строки сразу ({ zapret, byedpi, notes } | { error }) — контракт
 * прежнего hp_compose_build. */
export function compose_all(profiles, corpus) {
	const notes = [];
	const z = build_zapret(profiles, corpus);
	if (z.error != null)
		return z;
	for (let i = 0; i < length(z.notes); i++)
		push(notes, z.notes[i]);
	const b = build_byedpi(profiles, corpus);
	if (b.error != null)
		return b;
	for (let i = 0; i < length(b.notes); i++)
		push(notes, b.notes[i]);
	return { zapret: z.zapret, byedpi: b.byedpi, notes: notes };
};

/* ── Разбор применённой строки в карту «что чем обслужено» ───────────── */

/* Супerset прежнего hp_zapret_blocks: обогащённый скоуп (модульный
 * block_scope + метки кастомных профилей), имя по корпусу (exact base/raw,
 * затем containment — кратчайший). profile_labels = {подстрока: имя} из
 * UCI-профилей ('custom'-ресурсы). */
export function blocks_from_string(args, corpus, profile_labels) {
	const blocks = [];
	const parts = split_new(args);
	for (let i = 0; i < length(parts); i++) {
		const raw = parts[i];
		const scope = block_scope(raw, profile_labels);
		const base = trim(replace(raw, / --hostlist(-domains)?=[^ ]+/, ''));
		let name = null;
		const cands = (corpus != null && type(corpus.candidates) === 'array')
			? corpus.candidates : [];
		if (length(base))
			for (let ci = 0; ci < length(cands); ci++)
				if (type(cands[ci]) === 'object' && cands[ci].args === base) {
					name = '' + cands[ci].name; break;
				}
		if (name == null && length(raw))
			for (let ci = 0; ci < length(cands); ci++)
				if (type(cands[ci]) === 'object' && cands[ci].args === raw) {
					name = '' + cands[ci].name; break;
				}
		if (name == null && length(base)) {
			let best = null, best_len = 0;
			for (let ci = 0; ci < length(cands); ci++)
				if (type(cands[ci]) === 'object' && index('' + cands[ci].args, base) >= 0) {
					const al = length('' + cands[ci].args);
					if (best == null || al < best_len) { best = cands[ci]; best_len = al; }
				}
			if (best != null)
				name = '' + (best.name || '');
		}
		push(blocks, { scope: scope, name: name, base: base });
	}
	return blocks;
};

/* ── UCI-профили (источник истины) ───────────────────────────────────── */

/* Чтение `ravnex.profile[*]` в порядке `order` (числово, потом секция).
 * cursor передаётся вызывающим (rpcd и демоны живут в своих VM). */
export function profiles_read(cursor) {
	const out = [];
	try {
		cursor.foreach('ravnex', 'profile', (s) => {
			const ord = int(s.order || '100');
			push(out, {
				section: '' + s['.name'],
				enabled: (('' + (s.enabled || '1')) !== '0'),
				engine: '' + (s.engine || 'zapret'),
				resource: '' + (s.resource || 'general'),
				label: '' + (s.label || ''),
				domains: '' + (s.domains || ''),
				strategy: '' + (s.strategy || ''),
				order: ord
			});
		});
	} catch (e) {
		return null;   /* курсор недоступен — окно коммита; честный предел */
	}
	/* Стабильная сортировка: order → имя секции. */
	for (let i = 0; i < length(out); i++)
		for (let j = i + 1; j < length(out); j++) {
			const a = out[i], b = out[j];
			if (b.order < a.order ||
			    (b.order === a.order && b.section < a.section)) {
				out[i] = b; out[j] = a;
			}
		}
	return out;
};

/* Валидация набора профилей (массив объектов). null = ок, иначе строка
 * ошибки. Символьные гарды те же, что у resolve_strategy для строк. */
export function profiles_valid(profiles) {
	if (profiles == null || type(profiles) !== 'array')
		return 'профили не массив';
	if (length(profiles) > 12)
		return 'профилей больше 12';
	let generals = 0;
	for (let i = 0; i < length(profiles); i++) {
		const p = profiles[i];
		if (p == null || type(p) !== 'object')
			return 'плохой профиль #' + (i + 1);
		const engine = trim('' + (p.engine || 'zapret'));
		if (engine !== 'zapret' && engine !== 'byedpi')
			return 'неизвестный движок: ' + engine;
		const res = trim('' + (p.resource || 'general'));
		if (!resource_valid(res))
			return 'неизвестный ресурс: ' + res;
		if (res === 'general')
			generals++;
		const label = trim('' + (p.label || ''));
		if (length(label) > 64 || match(label, /[`$;&|<>\n\r]/))
			return 'плохое имя профиля #' + (i + 1);
		const doms = trim('' + (p.domains || ''));
		if (length(doms) > 2000 || match(doms, /[`$;&|<>\n\r]/))
			return 'плохие домены профиля #' + (i + 1);
		const strat = trim('' + (p.strategy || ''));
		if (!length(strat))
			return 'пустая стратегия профиля #' + (i + 1);
		if (length(strat) > 4000 || match(strat, /[`$;&|<>\n\r]/))
			return 'плохая стратегия профиля #' + (i + 1);
	}
	if (generals > 1)
		return 'общих профилей больше одного';
	return null;
};

/* Атомарная замена всех секций `profile` (курсор — параметр; КОММИТ
 * делает ВЫЗЫВАЮЩИЙ вместе со строкой, одним c.commit('ravnex')). */
export function profiles_replace(cursor, profiles) {
	const olds = [];
	try {
		cursor.foreach('ravnex', 'profile', (s) => {
			push(olds, '' + s['.name']);
		});
	} catch (e) {
		return 'курсор недоступен';
	}
	for (let i = 0; i < length(olds); i++)
		cursor.delete('ravnex', olds[i]);
	for (let i = 0; i < length(profiles); i++) {
		const p = profiles[i];
		/* uci-live микротест (сеанс 191): cursor.add(conf,type,name,values)
		 * на этой сборке МОЛЧА ТЕРЯЕТ values (order=strategy пустые при
		 * чтении) — добавляем секцию, затем каждый ключ через set. */
		const sid = cursor.add('ravnex', 'profile', null);
		if (sid == null || !length('' + sid))
			return 'add не вернул секцию';
		const values = {
			enabled: ((p.enabled === false) ? '0' : '1'),
			engine: trim('' + (p.engine || 'zapret')),
			resource: trim('' + (p.resource || 'general')),
			label: trim('' + (p.label || '')),
			domains: trim('' + (p.domains || '')),
			strategy: trim('' + (p.strategy || '')),
			order: '' + (10 * (i + 1))
		};
		for (let k in values)
			cursor.set('ravnex', '' + sid, k, '' + values[k]);
	}
	return null;
};

/* Синхрон-вид для статуса: rebuilding профилей vs применённая строка.
 * { profiles, string, rebuilt, drift, seed_needed } (profiles = null на
 * недоступном курсоре — окно коммита, честный предел). */
export function sync_view(cursor, corpus, opts) {
	const str = trim('' + (cursor.get('ravnex', 'config', 'zapret_cmd_opts') || ''));
	const prs = profiles_read(cursor);
	if (prs == null)
		return { profiles: null, string: str, rebuilt: null, drift: false,
			seed_needed: false };
	const enabled = [];
	for (let i = 0; i < length(prs); i++)
		if (prs[i].enabled)
			push(enabled, {
				engine: prs[i].engine, resource: prs[i].resource,
				label: prs[i].label, domains: prs[i].domains,
				strategy: prs[i].strategy
			});
	const zapret_on = (('' + (cursor.get('ravnex', 'config', 'zapret_enabled') || '')) === '1');
	if (!length(enabled)) {
		if (length(str) && (zapret_on || (opts != null && opts.force_string)))
			return { profiles: prs, string: str, rebuilt: null, drift: false,
				seed_needed: true };
		return { profiles: prs, string: str, rebuilt: null, drift: false,
			seed_needed: false };
	}
	const built = compose_all(enabled, corpus);
	const rebuilt = (built.error != null) ? null : built.zapret;
	return {
		profiles: prs,
		string: str,
		rebuilt: rebuilt,
		drift: (rebuilt != null && rebuilt !== str),
		seed_needed: false
	};
};
