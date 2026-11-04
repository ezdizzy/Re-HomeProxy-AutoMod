#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — Ф4.2 (U7): one-shot migration of the legacy static textareas
// (resources/proxy_list.txt + resources/direct_list.txt) into NAMED user
// lists (UCI 'user_list' sections + resources/lists/<sid>.txt).
//
// The two legacy textareas were the embryo of the list manager; the full
// manager (create/import/edit/delete/backup/export, kind+ctype+action at
// creation) replaces them on the Service rules page. The legacy files keep
// WORKING (the generator still consumes them), so their content must not
// silently disappear from the UI: this migrator runs at service start
// (BEFORE config generation) and moves the content into real lists, then
// blanks the legacy files with a comment. Both the list rule and the legacy
// rule would otherwise route the same domain twice — after the move the
// legacy files are comment-only, the lists carry the routing.
//
// Protocol (routing_mode-migration recipe, session 89):
//   1. Marker /etc/homeproxy/resources/.lists_migrated → silent exit.
//   2. Nothing to migrate (both legacy files absent or comment-only) →
//      create the marker (the check itself is idempotent) and exit.
//   3. Snapshot FIRST into /etc/homeproxy/backups/user-lists-<ts>/
//      (.tmp + mv, dated like the Maintenance snapshots; the family is
//      OUTSIDE the snapshot-* rotation). A failed snapshot = fail closed:
//      no migration, the marker is NOT created, the next start retries.
//   4. Every non-comment line through classify_entry(): domains → a list of
//      kind=<file direction>, ctype='domains'; IP entries → a second list,
//      ctype='ips'. (The legacy proxy_list had KEYWORD semantics for domain
//      lines; the direct file is plain hosts. The migrated domains are
//      full hosts in practice; a keyword that is not a hostname-shaped line
//      is re-classified as-is — classify_entry REJECTS non-hostname lines
//      and they are reported, never silently lost: the counts are printed
//      and stored in the snapshot meta.)
//   5. The legacy files are blanked to a comment line (the snapshot keeps
//      the original bytes), sync_learned_rulesets() refreshes the watched
//      JSONs, the marker is created. The generation that follows in THIS
//      start picks up the new lists — no extra restart needed.
//
// Уроки: 216 (top-level const наверх), 2/93/126 (хелперы выше), 244 (popen —
// импорт из fs), 245–246 (export function требует }; — здесь программа без
// export), 207/221 (const в блоке — блочный скоуп; try/finally нет),
// 20 (for-in по массиву = элементы), 90 (strftime нет — date(1)).

'use strict';

import { cursor } from 'uci';
import { access, readfile, writefile, stat, popen } from 'fs';
import {
	classify_entry, sync_learned_rulesets, getTime, HP_DIR
} from '/etc/homeproxy/scripts/homeproxy.uc';

const RES = HP_DIR + '/resources';
const LISTS_DIR = RES + '/lists';
const BK_DIR = HP_DIR + '/backups';
const MARKER = RES + '/.lists_migrated';

/* ── хелперы (выше вызывающих) ─────────────────────────────────────────── */

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
	print('user lists migration FAILED: ' + msg + '\n');
	exit(1);
}

/* One named list: UCI set <conf>.<sid>=user_list + options + content. */
function migrate_create(sid, name, kind, ctype, entries, n_entries) {
	const rc = system(`uci -q set homeproxy.${sid}=user_list`);
	if (rc !== 0)
		return false;
	system(`uci -q set homeproxy.${sid}.name=${shellquote(name)}`);
	system(`uci -q set homeproxy.${sid}.kind=${shellquote(kind)}`);
	system(`uci -q set homeproxy.${sid}.ctype=${shellquote(ctype)}`);
	system(`uci -q set homeproxy.${sid}.enabled=1`);
	/* direct lists default to direct-out, proxy lists to main-out — the
	 * action is ALWAYS present (a list without a rule is a dead list). */
	system(`uci -q set homeproxy.${sid}.node=${shellquote(kind === 'direct' ? 'direct-out' : 'main-out')}`);
	/* honest counters — the UI shows what the classifier accepted */
	system(`uci -q set homeproxy.${sid}.entries=${n_entries}`);
	system(`uci -q set homeproxy.${sid}.dropped=0`);
	system('uci -q commit homeproxy');
	system('mkdir -p ' + shellquote(LISTS_DIR));
	writefile(LISTS_DIR + '/' + sid + '.txt', entries);
	return true;
}

/* ── миграция ──────────────────────────────────────────────────────────── */

if (access(MARKER))
	exit(0);

const SOURCES = [
	{ file: 'proxy_list.txt', kind: 'proxy',
		name_dom: 'Прокси — перенесённые домены', name_ip: 'Прокси — перенесённые IP' },
	{ file: 'direct_list.txt', kind: 'direct',
		name_dom: 'Прямой доступ — перенесённые домены', name_ip: 'Прямой доступ — перенесённые IP' }
];

let todo = [];
let empty = true;
for (let s in SOURCES) {
	const f = RES + '/' + s.file;
	if (!access(f))
		continue;
	const raw = readfile(f) ?? '';
	let has_entries = false;
	for (let l in split('' + raw, /[\r\n]/)) {
		l = trim(l);
		if (length(l) && substr(l, 0, 1) !== '#') { has_entries = true; break; }
	}
	if (!has_entries)
		continue;
	empty = false;
	push(todo, { src: s, raw: '' + raw, file: f });
}

if (empty) {
	/* Nothing to migrate — ever. The marker makes future legacy edits (not
	 * possible from the UI anymore) visible at start instead of silent. */
	system('touch ' + shellquote(MARKER));
	exit(0);
}

/* Snapshot first — fail closed without it. */
const ts = ts14();
if (!length(ts))
	fail('date(1) не вернул метку времени.');
const dir = BK_DIR + '/user-lists-' + ts;
const tmpdir = BK_DIR + '/.ul-mig-' + ts + '.tmp';
system('mkdir -p ' + shellquote(BK_DIR) + ' ' + shellquote(tmpdir));
let snap_err = '';
for (let t in todo) {
	system('cp ' + shellquote(t.file) + ' ' + shellquote(tmpdir + '/' + t.src.file));
	if (!access(tmpdir + '/' + t.src.file))
		snap_err = t.src.file;
}
if (length(snap_err)) {
	system('rm -rf ' + shellquote(tmpdir));
	fail('снимок ' + snap_err + ' не создан (нет места/прав?) — миграция отложена до следующего старта.');
}
const st = stat(tmpdir + '/' + todo[0].src.file);
if (!st || st.size <= 0) {
	system('rm -rf ' + shellquote(tmpdir));
	fail('снимок пуст — миграция отложена.');
}
system('mv ' + shellquote(tmpdir) + ' ' + shellquote(dir));
if (!access(dir + '/' + todo[0].src.file))
	fail('снимок не получил финальное имя ' + dir + '.');

let migrated = 0, rejected = 0, created_lists = 0;
const meta = { ts: ts, reason: 'pre-migration (legacy domain lists)', lists: [] };
for (let i, t in todo) {
	let doms = [], ips = [], seen = {};
	for (let l in split(t.raw, /[\r\n]/)) {
		l = trim(l);
		if (!length(l) || substr(l, 0, 1) === '#')
			continue;
		const c = classify_entry(l);
		if (!c) { rejected++; continue; }
		if (c.kind === 'domain') {
			if (!seen[c.value]) { seen[c.value] = true; push(doms, c.value); }
		} else {
			if (!seen[c.value]) { seen[c.value] = true; push(ips, c.value); }
		}
	}
	const base = 'ul_' + replace(ts, '-', '_') + 'm' + (i + 1);
	if (length(doms) && migrate_create(base + 'd', t.src.name_dom, t.src.kind, 'domains',
		join('\n', doms) + '\n', length(doms)))
		created_lists++;
	if (length(ips) && migrate_create(base + 'i', t.src.name_ip, t.src.kind, 'ips',
		join('\n', ips) + '\n', length(ips)))
		created_lists++;
	push(meta.lists, {
		sid: base + 'd',
		name: t.src.name_dom,
		kind: t.src.kind,
		ctype: 'domains',
		node: (t.src.kind === 'direct') ? 'direct-out' : 'main-out',
		enabled: '1'
	});
	push(meta.lists, {
		sid: base + 'i',
		name: t.src.name_ip,
		kind: t.src.kind,
		ctype: 'ips',
		node: (t.src.kind === 'direct') ? 'direct-out' : 'main-out',
		enabled: '1'
	});
	migrated += length(doms) + length(ips);
	/* The legacy file becomes a comment — the snapshot keeps the bytes. */
	writefile(t.file, '# Перенесено в «Мои списки» (Ф4.2) ' + getTime() +
		'; снимок: ' + dir + '\n');
}
writefile(dir + '/meta.json', sprintf('%.J\n', meta));

/* The watched JSONs must reflect the now-empty legacy sources immediately
 * (the core hot-reloads them; the fresh generation follows in this start). */
const rr = sync_learned_rulesets();
writefile(MARKER, 'migrated ' + migrated + ' entries into ' + created_lists +
	' lists at ' + getTime() + '; snapshot: ' + dir + '\n');

print('user lists migration: ' + migrated + ' entries -> ' + created_lists +
	' lists (' + rejected + ' rejected), snapshot: ' + dir +
	'; learned sync now ' + rr.domains + ' dom / ' + rr.manual_ips + '+' + rr.auto_ips + ' ip\n');
exit(0);
