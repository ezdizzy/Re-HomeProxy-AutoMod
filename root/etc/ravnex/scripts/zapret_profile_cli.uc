// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — zapret_profile_cli.uc: селфтест + микротесты zapret_profile.uc
// (сеанс 191). Запуск: ucode /etc/ravnex/scripts/zapret_profile_cli.uc selftest
//   selftest — fixture-векторы чистых функций (не трогает систему);
//   uci-live — микротест UCI-чтения/замены профилей с обязательной чисткой
//              (добавить [general=ZZTEST] → прочитать → sync_view → удалить).

import {
	split_new, extract_blobs, block_scope, domains_for, resolve_strategy,
	ciadpi_struct, build_zapret, build_byedpi, compose_all, blocks_from_string,
	profiles_read, profiles_valid, profiles_replace, sync_view, SCOPE_RES
} from './zapret_profile.uc';
import { access, readfile } from 'fs';
import { cursor } from 'uci';

let ok_n = 0, fail_n = 0;

function check(name, cond, note) {
	if (cond) {
		ok_n++;
		printf('ok   %-40s %s\n', name, (note != null) ? note : '');
	} else {
		fail_n++;
		printf('FAIL %-40s %s\n', name, (note != null) ? note : '');
	}
}

function eqv(a, b) {
	return (sprintf('%.J', a) === sprintf('%.J', b));
}

/* ── fixture-векторы ─────────────────────────────────────────────────── */

function t_split_new() {
	check('split_new_basic', eqv(split_new('a b --new c'), [ 'a b', 'c' ]));
	check('split_new_empty', eqv(split_new(''), [ ]));
	check('split_new_dbl', eqv(split_new('x --new --new y'), [ 'x', 'y' ]));
}

function t_extract_blobs() {
	const ex = extract_blobs('--blob=B1 --filter-tcp=443 tls fake');
	check('extract_blobs_rest', eqv(ex[0], '--filter-tcp=443 tls fake'));
	check('extract_blobs_blobs', eqv(ex[1], [ '--blob=B1' ]));
}

function t_block_scope() {
	check('scope_file_exact',
		block_scope('X --hostlist=/etc/ravnex/resources/zapret-hosts/discord.txt') === 'discord');
	check('scope_name_substr',
		block_scope('X --hostlist=/opt/lists/youtube-extra.txt') === 'youtube');
	check('scope_dom_yt',
		block_scope('X --hostlist-domains=a,googlevideo.com,b') === 'youtube');
	check('scope_dom_unknown',
		block_scope('X --hostlist-domains=example.com') == null);
	check('scope_none',
		block_scope('X --filter-tcp=443 tls') == null);
	check('scope_label',
		block_scope('X --hostlist-domains=example.com', { 'example.com': 'myres' }) === 'myres');
	check('scope_label_path',
		block_scope('X --hostlist=/srv/myres.txt', { myres: 'myres' }) === 'myres');
	/* сеанс 194: кастомный профиль = ТОЧНОЕ множество доменов — его блок
	 * не должен затеняться отличительными доменами ресурса (CSV youtube-
	 * хостлиста несёт 'googlevideo', и блок custom:googlevideo.com
	 * приписывался youtube). Равенство метки — первым; надмножество
	 * остаётся за словарём ресурсов. */
	check('scope_label_eq_beats_res',
		block_scope('X --hostlist-domains=googlevideo.com',
			{ 'googlevideo.com': 'mygv' }) === 'mygv');
	check('scope_res_when_label_other',
		block_scope('X --hostlist-domains=a,googlevideo.com,b',
			{ 'other.net': 'myres' }) === 'youtube');
	check('scope_label_eq_norm_set',
		block_scope('X --hostlist-domains=googlevideo.com,ytimg.com',
			{ 'googlevideo.com, ytimg.com': 'gv2' }) === 'gv2');
	check('scope_superset_stays_res',
		block_scope('X --hostlist-domains=www.youtube.com,googlevideo.com,youtu.be,ytimg.com',
			{ 'googlevideo.com': 'mygv' }) === 'youtube');
}

function t_domains_for() {
	check('domains_general', domains_for('general') == null);
	check('domains_custom', eqv(domains_for('custom', 'a.com, b.com'),
		[ 'a.com', 'b.com' ]));
	check('domains_custom_empty', domains_for('custom', '  ') == null);
	const yf = '/etc/ravnex/resources/zapret-hosts/youtube.txt';
	if (access(yf)) {
		const d = domains_for('youtube');
		check('domains_yt_file', (d != null && length(d) > 0), 'length=' + length(d || []));
	} else
		printf('skip domains_yt_file (нет %s)\n', yf);
}

function t_resolve() {
	const corpus = { candidates: [
		{ name: 'Super', args: '--foo=1' },
		{ name: 'Bad', args: 'not-args' }
	] };
	check('resolve_name', resolve_strategy('Super', corpus) === '--foo=1');
	check('resolve_raw', resolve_strategy('--foo=2', corpus) === '--foo=2');
	check('resolve_meta_reject', resolve_strategy('$(x)', corpus) == null);
	/* честная проверка длины: >8000 отвергается */
	let long_s = '--x=';
	for (let li = 0; li < 8090; li++)
		long_s += 'y';
	check('resolve_len_reject3', resolve_strategy(long_s, corpus) == null);
}

function t_build_zapret() {
	const b1 = build_zapret([
		{ engine: 'zapret', resource: 'custom', domains: 'a.com,b.com', strategy: '--a1' },
		{ engine: 'zapret', resource: 'general', strategy: '--b1' }
	], null);
	check('build_basic', (b1.error == null &&
		b1.zapret === '--a1 --hostlist-domains=a.com,b.com --new --b1'),
		(b1.error || b1.zapret));
	/* per-block hostlist fix (аудит 191): block1 без hostlist получает
	 * домены, блок2 со СВОИМ hostlist — НЕ получает дубль. */
	const b2 = build_zapret([
		{ engine: 'zapret', resource: 'custom', domains: 'a.com',
		  strategy: '--x1 --new --hostlist=/zzz/youtube.txt --x2' },
		{ engine: 'zapret', resource: 'general', strategy: '--gen' }
	], null);
	check('build_perblock_hl', (b2.error == null &&
		b2.zapret === '--x1 --hostlist-domains=a.com --new --hostlist=/zzz/youtube.txt --x2 --new --gen'),
		(b2.error || b2.zapret));
	const b3 = build_zapret([
		{ engine: 'zapret', resource: 'youtube', strategy: 'Super' }
	], { candidates: [ { name: 'Super', args: '--foo=1' } ] });
	check('build_corpus_name', (b3.error == null &&
		index(b3.zapret, '--foo=1 --hostlist-domains=') === 0), (b3.error || b3.zapret));
	const b4 = build_zapret([ { engine: 'zapret', resource: 'nosuch', strategy: '--a' } ], null);
	check('build_bad_resource', (b4.error != null && index(b4.error, 'неизвестный ресурс') === 0));
	const b5 = build_zapret([ { engine: 'zapret', resource: 'custom', strategy: '--a' } ], null);
	check('build_custom_no_doms', (b5.error != null && index(b5.error, 'нет валидных доменов') >= 0));
}

function t_blocks_roundtrip() {
	const labels = { 'a.com': 'myres' };
	const s = 'X1 --hostlist-domains=a.com --new ' +
		'--hostlist=/etc/ravnex/resources/zapret-hosts/discord.txt X2 --new GEN';
	const no_lbl = blocks_from_string(s, null, null);
	check('blocks_unknown_generic', no_lbl[0].scope == null && no_lbl[0].base === 'X1');
	check('blocks_discord', no_lbl[1].scope === 'discord');
	const with_lbl = blocks_from_string(s, null, labels);
	check('blocks_label', with_lbl[0].scope === 'myres');
}

function t_build_byedpi() {
	const b = build_byedpi([
		{ engine: 'byedpi', resource: 'custom', domains: 'a.com', strategy: '-r1' },
		{ engine: 'byedpi', resource: 'general', strategy: '-o1' }
	], null);
	check('byedpi_groups', (b.error == null &&
		b.byedpi === '-H :a.com -K t -r1 -A n -o1'), (b.error || b.byedpi));
	const bad = build_byedpi([ { engine: 'byedpi', resource: 'general', strategy: '-H :x' } ], null);
	check('byedpi_struct_ban', (bad.error != null && index(bad.error, 'служебную опцию') >= 0));
}

function t_compose_all() {
	const r = compose_all([
		{ engine: 'zapret', resource: 'custom', domains: 'a.com', strategy: '--za' },
		{ engine: 'byedpi', resource: 'custom', domains: 'b.com', strategy: '-ba' },
		{ engine: 'zapret', resource: 'general', strategy: '--zg' },
		{ engine: 'byedpi', resource: 'general', strategy: '-o1' }
	], null);
	check('compose_all_both', (r.error == null &&
		r.zapret === '--za --hostlist-domains=a.com --new --zg' &&
		r.byedpi === '-H :b.com -K t -ba -A n -o1'), (r.error || (r.zapret + ' | ' + r.byedpi)));
}

function t_profiles_valid() {
	check('valid_good', profiles_valid([
		{ engine: 'zapret', resource: 'youtube', strategy: 'A' },
		{ engine: 'zapret', resource: 'general', strategy: 'B' }
	]) == null);
	check('valid_two_generals',
		profiles_valid([
			{ engine: 'zapret', resource: 'general', strategy: 'A' },
			{ engine: 'zapret', resource: 'general', strategy: 'B' }
		]) != null);
	check('valid_bad_engine',
		profiles_valid([ { engine: 'x', resource: 'general', strategy: 'A' } ]) != null);
}

/* ── uci-live микротест (исполнитель вызывает осознанно) ─────────────── */

function uci_live() {
	const c = cursor();
	const before = profiles_read(c);
	if (before != null && length(before))
		printf('SKIP: на роутере уже есть %d профилей — микротест не трогает их\n', length(before));
		else {
		const err = profiles_replace(c, [
			{ engine: 'zapret', resource: 'general', strategy: '--zztest --keep' }
		]);
		if (err != null) { printf('FAIL uci_live_replace %s\n', err); fail_n++; return; }
		c.commit('ravnex');
		const now = profiles_read(c);
		check('uci_live_read', (now != null && length(now) === 1 &&
			now[0].resource === 'general' && now[0].strategy === '--zztest --keep'),
			(now != null) ? sprintf('%.J', now[0]) : 'null');
		const sv = sync_view(c, null, { force_string: true });
		check('uci_live_sync_view', (sv != null && sv.rebuilt === '--zztest --keep'),
			(sv != null) ? ('rebuilt=' + sv.rebuilt + ' drift=' + sv.drift) : 'null');
		/* Чистка: убрать секции микротеста. */
		const secs = [];
		c.foreach('ravnex', 'profile', (s) => {
			push(secs, '' + s['.name']);
		});
		for (let i = 0; i < length(secs); i++)
			c.delete('ravnex', secs[i]);
		c.commit('ravnex');
		const after = profiles_read(c);
		check('uci_live_cleanup', (after != null && length(after) === 0));
	}
}

/* ── main ────────────────────────────────────────────────────────────── */

const mode = ARGV[0] || 'selftest';
if (mode === 'uci-live') {
	uci_live();
} else {
	t_split_new();
	t_extract_blobs();
	t_block_scope();
	t_domains_for();
	t_resolve();
	t_build_zapret();
	t_blocks_roundtrip();
	t_build_byedpi();
	t_compose_all();
	t_profiles_valid();
}
printf('\n== %s: ok=%d fail=%d ==\n', mode, ok_n, fail_n);
exit(fail_n ? 1 : 0);
