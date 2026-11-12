/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 ImmortalWrt.org
 */

import { open, readfile, writefile, access, stat } from 'fs';
import { urldecode_params } from 'luci.http';
/* Ф6.6/B5.17: единая валидация выученных IP — третья точка (генератор
 * правилетс-файлов). learn_core ничего не импортирует, discovery — только
 * fs; циклов нет. */
import { validate_learned_ip, is_never_learn_domain } from '/etc/ravnex/scripts/learn_core.uc';
import { is_special_ip } from '/etc/ravnex/scripts/discovery.uc';

/* Global variables start */
export const HP_DIR = '/etc/ravnex';
export const RUN_DIR = '/var/run/ravnex';
/* Global variables end */

/* Utilities start */
/* Kanged from luci-app-commands */
export function shellQuote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
};

export function isBinary(str) {
	for (let off = 0, byte = ord(str); off < length(str); byte = ord(str, ++off))
		if (byte <= 8 || (byte >= 14 && byte <= 31))
			return true;

	return false;
};

let exec_seq = 0;
export function executeCommand(...args) {
	/* Named temp files instead of mkstemp(): mkstemp streams never expose their
	 * path and older ucode lacks fs.remove, so those files leaked into /tmp on
	 * every invocation. Unique per-call names via a sequence counter + rm after
	 * reading keep this leak-free and re-entrant. */
	const uniq = `${time()}.${++exec_seq}`;
	const outf = RUN_DIR + '/exec.' + uniq + '.out';
	const errf = RUN_DIR + '/exec.' + uniq + '.err';

	const exitcode = system(`${join(' ', args)} > ${shellQuote(outf)} 2> ${shellQuote(errf)}`);

	/* Read to EOF, not a fixed 512KB cap: subscription bodies beyond the old cap
	 * were silently truncated mid-line — the parser then dropped the tail nodes
	 * and the removal phase DELETED them from the config as "disappeared". */
	let stdout = '', stderr = '', chunk;
	let outfd = open(outf, 'r');
	if (outfd) {
		while ((chunk = outfd.read(65536)) && length(chunk))
			stdout += chunk;
		outfd.close();
	}
	let errfd = open(errf, 'r');
	if (errfd) {
		while ((chunk = errfd.read(65536)) && length(chunk))
			stderr += chunk;
		errfd.close();
	}

	system(`rm -f ${shellQuote(outf)} ${shellQuote(errf)} 2>/dev/null`);

	const binary = isBinary(stdout);

	return {
		command: join(' ', args),
		stdout: binary ? null : stdout,
		stderr,
		exitcode,
		binary
	};
};

export function getTime(epoch) {
	const local_time = localtime(epoch);
	return replace(replace(sprintf(
		'%d-%2d-%2d@%2d:%2d:%2d',
		local_time.year,
		local_time.mon,
		local_time.mday,
		local_time.hour,
		local_time.min,
		local_time.sec
	), ' ', '0'), '@', ' ');

};

export function wGET(url, ua) {
	if (!url || type(url) !== 'string')
		return null;

	if (!ua)
		ua = 'Wget/1.21 (HomeProxy, like v2rayN)';

	const output = executeCommand(`/usr/bin/wget -qO- --user-agent ${shellQuote(ua)} --timeout=10 ${shellQuote(url)}`) || {};
	return trim(output.stdout);
};
/* Write a rule-set file atomically (temp + rename) so the core's file watcher never
 * reads a half-written JSON: fsnotify can fire mid-write, and a truncated parse error
 * would keep the previous (stale) rules until the next event. rename(2) is atomic on the
 * overlayfs upper layer, and sing-box (>=1.10.0) correctly tracks a file replaced via
 * rename (mv), so the watcher keeps working after the swap. */
function write_ruleset_file(path, obj) {
	let tmp = path + '.tmp';
	writefile(tmp, sprintf('%.J\n', obj));
	system('mv -f ' + shellQuote(tmp) + ' ' + shellQuote(path));
}

/* ── Ф4.1 (аудит B6.1/B6.2/B6.10): ЕДИНЫЙ классификатор записей списков ───
 * Каждый генератор (sync_* здесь, статические списки generate_client, learn-
 * конвейер automation, валидаторы записей RPC) решает «строка = домен или IP?»
 * ТОЛЬКО через classify_entry() — в проекте было несколько несовместимых
 * классификаторов: sync_learned_rulesets отбрасывал голый IPv4 (IP-обучение
 * фактически не маршрутизировало — игры/hardcoded IP), ручные IPv4 проваливались
 * в domain_suffix, а длина префикса CIDR не проверялась вовсе (/33 проходил).
 *
 * classify_entry(raw) → null (запись невалидна — вызывающий ОБЯЗАН отбросить её
 * и посчитать) либо нормализованная запись:
 *   { kind: 'domain'|'ipv4'|'ipv6'|'cidr4'|'cidr6',
 *     value: <форма для эмиссии в rule-set>, prefix: <int|null> }
 * Нормализация value:
 *   - голый IPv4 → '<ip>/32'   (B6.1: выученные IP обязаны маршрутизировать)
 *   - голый IPv6 → '<addr>/128'
 *   - домены     → lowercase, один ведущий и один хвостовой '.', срезаны
 *     ('.Example.COM.' → 'example.com' — сам apex матчится вместе с поддоменами)
 *   - CIDR       → '<base>/<префикс>' (base валиден; префикс 1..32 / 1..128 —
 *     битый префикс НЕ проходит молча; /0 отвергается — «весь интернет» не
 *     может быть намерением одной записи списка)
 * Разбор — арифметикой (разбиение октетов/гекстетов), не одним регэкспом
 * (урок 26: match() со строковым паттерном молча null; 999.1.1.1, 01.2.3.4
 * (восьмеричная ловушка Go net.ParseIP), :::, /33 — всё это invalid). */

function ipv4_parts_ok(s) {
	let p = split(s, '.');
	if (length(p) !== 4)
		return false;
	for (let i, o in p) {
		if (!match(o, /^[0-9]{1,3}$/))
			return false;
		if (length(o) > 1 && substr(o, 0, 1) === '0')
			return false;
		if (int(o) > 255)
			return false;
	}
	return true;
}

/* Expand an IPv6 literal into 8 hextet integers (or null when invalid).
 * Used by classify_entry (validation) and by route_explain (ip_cidr matching). */
export function ipv6_hextets(s) {
	if (index(s, ':') < 0)
		return null;
	let L = length(s);
	/* single leading/trailing colon (not part of '::') is invalid */
	if (substr(s, 0, 1) === ':' && substr(s, 0, 2) !== '::')
		return null;
	if (substr(s, L - 1, 1) === ':' && substr(s, L - 2, 2) !== '::')
		return null;
	/* at most one '::' (':::' counts twice → rejected) */
	let dbl = 0;
	for (let i = 0; i + 1 < L; i++)
		if (substr(s, i, 2) === '::')
			dbl++;
	if (dbl > 1)
		return null;
	let head = s, tail = '';
	if (dbl) {
		let pos = index(s, '::');
		head = substr(s, 0, pos);
		tail = substr(s, pos + 2);
	}
	const HEXD = '0123456789abcdef';
	/* Sums groups of a colon-separated part; the LAST group may be an embedded
	 * IPv4 (counts as 2 hextets, only when it terminates the address). -1 on
	 * any malformed group. */
	let count = (part, allow_v4) => {
		if (!length(part))
			return 0;
		let parts = split(part, ':'), n = 0;
		for (let i, g in parts) {
			if (!length(g))
				return -1;
			if (allow_v4 && i === length(parts) - 1 && index(g, '.') >= 0) {
				if (!ipv4_parts_ok(g))
					return -1;
				n += 2;
				continue;
			}
			if (!match(g, /^[0-9a-fA-F]{1,4}$/))
				return -1;
			n++;
		}
		return n;
	};
	if (dbl) {
		let hn = count(head, false), tn = count(tail, true);
		if (hn < 0 || tn < 0 || hn + tn > 7)
			return null;
	} else {
		let n = count(s, true);
		if (n !== 8)
			return null;
	}
	let out = [];
	let fill = (part, allow_v4, groups) => {
		/* groups: expected hextet count AFTER v4-expansion; left-pad with zeros
		 * (the '::' zero-fill or the exact-8 form needs no padding). Values are
		 * computed directly as integers — no hex-string roundtrip. */
		if (!length(part)) {
			for (let i = 0; i < groups; i++)
				push(out, 0);
			return true;
		}
		let parts = split(part, ':');
		let vals = [];
		for (let i, g in parts) {
			if (allow_v4 && i === length(parts) - 1 && index(g, '.') >= 0) {
				let q = split(g, '.');
				push(vals, int(q[0]) * 256 + int(q[1]));
				push(vals, int(q[2]) * 256 + int(q[3]));
				continue;
			}
			let v = 0;
			for (let c = 0; c < length(g); c++) {
				let d = index(HEXD, lc(substr(g, c, 1)));
				if (d < 0)
					return false;
				v = v * 16 + d;
			}
			push(vals, v);
		}
		if (length(vals) > groups)
			return false;
		for (let i = 0; i < groups - length(vals); i++)
			push(out, 0);
		for (let i, v in vals)
			push(out, v);
		return true;
	};
	if (dbl) {
		let hn = count(head, false), tn = count(tail, true);
		/* zero-fill order: head groups first (left-aligned), zeros, then tail */
		let hp = length(head) ? split(head, ':') : [];
		let hgrp = 0;
		for (let i, g in hp)
			hgrp += (i === length(hp) - 1 && index(g, '.') >= 0) ? 0 : 1;
		if (!fill(head, false, hgrp))
			return null;
		let tp = length(tail) ? split(tail, ':') : [];
		let tgrp = 0;
		for (let i, g in tp)
			tgrp += (i === length(tp) - 1 && index(g, '.') >= 0) ? 2 : 1;
		for (let i = 0; i < 8 - hgrp - tgrp; i++)
			push(out, 0);
		if (!fill(tail, true, tgrp))
			return null;
	} else {
		if (!fill(s, true, 8))
			return null;
	}
	if (length(out) !== 8)
		return null;
	return out;
};

/* classify_entry — see the block comment above. */
export function classify_entry(raw) {
	/* 🔴 this ucode build has NO `undefined` global (lesson 103-class): the bare
	 * name throws "access to undeclared variable" — a missing argument is
	 * detected via type() instead. */
	if (raw === null || type(raw) !== 'string')
		return null;
	let s = trim('' + raw);
	if (!length(s) || length(s) > 253 + 4)
		return null;
	let host = s, plen = null;
	let sl = index(s, '/');
	if (sl >= 0) {
		host = trim(substr(s, 0, sl));
		let ps = trim(substr(s, sl + 1));
		if (!length(host) || !length(ps) || !match(ps, /^[0-9]{1,3}$/))
			return null;
		plen = int(ps);
	}
	if (index(host, ':') >= 0) {
		if (!ipv6_hextets(host))
			return null;
		if (plen === null)
			return { kind: 'ipv6', value: host + '/128', host: host, prefix: 128 };
		if (plen < 1 || plen > 128)
			return null;
		return { kind: 'cidr6', value: host + '/' + sprintf('%d', plen), host: host, prefix: plen };
	}
	if (match(host, /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/)) {
		if (!ipv4_parts_ok(host))
			return null;
		if (plen === null)
			return { kind: 'ipv4', value: host + '/32', host: host, prefix: 32 };
		if (plen < 1 || plen > 32)
			return null;
		return { kind: 'cidr4', value: host + '/' + sprintf('%d', plen), host: host, prefix: plen };
	}
	/* domain (strict, for USER-AUTHORED lists): a '/' entry that is not an IP
	 * family is junk; single labels and empty labels never route. */
	if (plen !== null)
		return null;
	if (substr(host, 0, 1) === '.')
		host = substr(host, 1);
	if (substr(host, length(host) - 1, 1) === '.')
		host = substr(host, 0, length(host) - 1);
	host = lc(host);
	if (length(host) < 3 || index(host, '.') <= 0)
		return null;
	if (!match(host, /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/))
		return null;
	if (match(host, /\.\./))
		return null;
	/* Final label all-digits is junk (the project's own candidate filter,
	 * looks_like_host: '192.100' / '1.2.3' are broken IP fragments, never
	 * real domains — a suffix on them can never match real traffic). */
	let labels = split(host, '.');
	if (match(labels[length(labels) - 1], /^[0-9]+$/))
		return null;
	return { kind: 'domain', value: host, host: host, prefix: null };
};

/* Read a list file into non-comment entries (shared line handling for the
 * sync family: '#' comments, blank lines, per-line trim, tab→space). */
function read_list_entries(res, name) {
	if (!access(res + '/' + name))
		return [];
	let raw = readfile(res + '/' + name);
	if (raw === null || type(raw) !== 'string')
		return [];
	let out = [];
	for (let l in split('' + raw, /[\r\n]/)) {
		l = trim(replace(l, /\t/g, ' '));
		if (!length(l) || substr(l, 0, 1) === '#')
			continue;
		push(out, l);
	}
	return out;
}

/* Learned-list hot reload:
 * Write the auto-detected blocked-site lists as sing-box RuleSet source JSON files so the
 * core can hot-reload them via its LOCAL rule-set file watcher — no service restart, no
 * dropped connections. Both hiddify-core and sing-box-extended are sing-box forks that
 * auto-reload a `type: local` rule-set when its file changes (since sing-box 1.10.0).
 *
 *   resources/proxy_domain.json  = static proxy_list.txt  +  learned auto_proxy_list.txt
 *                                   (domain_keyword)  -> referenced by the 'proxy-domain' ruleset
 *   resources/manual_ip.json     = B6.3: MANUAL IP entries — IP-shaped lines of the static
 *                                   proxy_list.txt + manual_proxy.txt (ip_cidr)
 *                                   -> referenced by the 'manual-ip' ruleset
 *   resources/auto_ip.json       = learned auto_proxy_ip.txt (ip_cidr) ONLY now
 *                                   -> referenced by the 'auto-ip' ruleset
 *
 * B6.3: the IP set used to mix manual entries (static proxy_list + manual pins) with
 * automation-learned IPs in ONE file whose rule the generator emitted ONLY when
 * automation_enabled='1' — a manual IP pin simply did not route with Automation off.
 * Manual IP entries now live in their OWN watched file ('manual-ip' rule is emitted
 * unconditionally, an empty rule-set is a no-op), so hand-pinned IPs route regardless
 * of the Automation toggle, while learned IPs stay behind the Automation gate.
 *
 * Called by generate_client.uc (so the files always exist when the core starts) and by
 * automation.uc on every learn (the hot path — rewrite the file, the core picks it up). */
/* Ф6.6/B5.17: сокращённое окружение валидации для генератора — здесь
 * доступен только реестр IANA Special-Purpose (остальные списки живут
 * в automation.uc; формат проверяет classify_entry выше). */
function learned_ip_env_hp() {
	return { special: is_special_ip };
}

export function sync_learned_rulesets(res_dir) {
	let res = res_dir || (HP_DIR + '/resources');
	system('mkdir -p ' + shellQuote(res));
	/* Ф4.1: every entry decision goes through classify_entry() — one classifier
	 * for all generators. Invalid entries are DROPPED AND COUNTED (never silent:
	 * the counter rides the return value and every caller logs it). */
	let drops = 0;
	/* Static list keeps its upstream KEYWORD semantics (substring match, curated by
	 * the user). Learned entries are EXACT hosts discovered automatically — they must
	 * go out as domain_suffix (suffix-with-dot-boundary match): a keyword like "t.co"
	 * would also match "reddit.com" and silently reroute unrelated sites via proxy.
	 * Manual "always proxy" pins (Automation table) share the learned semantics.
	 * IP-shaped lines of the static list are EXTRACTED to the IP set: an IP can
	 * never match as a domain substring keyword — a dead entry today, a routed
	 * ip_cidr entry after classification. */
	/* B6.8: the manual lists are normalized by a PIPELINE at ruleset build
	 * time (ucode's trim inside a callback never mutates the source array):
	 * keywords are lowercased (hostnames are lowercase — a mixed-case
	 * keyword could never match) and deduplicated; learned domains go
	 * through classify_entry and are written NORMALIZED (c.value), with the
	 * permissive raw fallback so an odd-but-present learned entry never
	 * silently loses its route. Keyword semantics of the static list are
	 * PRESERVED (classify() would reject useful bare keywords like
	 * "youtube" — single labels — so keywords are lc()'d, not classified). */
	let domains = [], learned_domains = [], manual_ips = {}, auto_ips = {};
	let kw_seen = {}, ld_seen = {};
	for (let d in read_list_entries(res, 'proxy_list.txt')) {
		let c = classify_entry(d);
		if (c && c.kind !== 'domain') {
			manual_ips[c.value] = true;
			continue;
		}
		let k = lc(d);
		if (length(k) && !kw_seen[k]) {
			kw_seen[k] = true;
			push(domains, k);
		}
	}
	/* manual_proxy.txt holds user-pinned hosts (always via proxy, protected from
	 * self-healing). B6.2: a manual IPv4 (bare or CIDR) is an IP entry — it goes
	 * to the ip_cidr set normalized (/32 for bare), NEVER to domain_suffix
	 * (a suffix on an IP literal can never match a sniffed hostname — dead). */
	for (let d in read_list_entries(res, 'manual_proxy.txt')) {
		let c = classify_entry(d);
		if (!c) {
			drops++;
			continue;
		}
		if (c.kind === 'domain' && !ld_seen[c.value]) {
			ld_seen[c.value] = true;
			push(learned_domains, c.value);
		}
		else if (c.kind !== 'domain')
			manual_ips[c.value] = true;
	}
	/* Learned hosts keep the permissive domain path (the automation pipeline
	 * already filters candidates upstream; an odd-but-present entry must not
	 * silently lose its route). Only MISPLACEMENTS are fixed here: an IP-shaped
	 * learned entry rides the IP set instead of a dead domain_suffix. */
	for (let d in read_list_entries(res, 'auto_proxy_list.txt')) {
		/* s190: resolver/NTP/DoH entries never route — even a lingering
		 * polluted line in the learned list must not reach the rule-set. */
		if (is_never_learn_domain(d)) {
			drops++;
			continue;
		}
		let c = classify_entry(d);
		if (c && c.kind !== 'domain') {
			auto_ips[c.value] = true;
			continue;
		}
		/* B6.8: normalized when the classifier accepts it, raw fallback
		 * otherwise (the automation pipeline already filtered candidates
		 * upstream — an odd-but-present entry must not silently lose its
		 * route). */
		let v = (c && c.kind === 'domain') ? c.value : d;
		if (length(v) && !ld_seen[v]) {
			ld_seen[v] = true;
			push(learned_domains, v);
		}
	}
	/* B6.1: the learned IP list is written with BARE IPv4 (the automation learn
	 * pipeline keys state by the probe host). The old regex required '/plen' and
	 * silently DROPPED every bare IPv4 — IP learning never routed (games, apps
	 * with hardcoded IPs). classify_entry normalizes bare IPv4 → /32, bare IPv6
	 * → /128, and rejects broken prefixes (/33 never passes silently). */
	for (let d in read_list_entries(res, 'auto_proxy_ip.txt')) {
		let c = classify_entry(d);
		if (!c || c.kind === 'domain') {
			drops++;
			continue;
		}
		/* Ф6.6/B5.17: ТРЕТЬЯ точка единой валидации выученного IP (load и
		 * learn — в automation.uc): формат и IANA Special-Purpose проверяются
		 * и на генераторе — устаревшая/испорченная запись не маршрутизирует
		 * даже между стартами демона. Причина — в счётчике drops. */
		const vdrop = validate_learned_ip(c.value, learned_ip_env_hp());
		if (vdrop != null) {
			drops++;
			continue;
		}
		auto_ips[c.value] = true;
	}

	/* Manual proxy-domain entries (static keywords + learned suffixes) live in ONE
	 * watched rule-set file so a single hot-reload applies static and learned
	 * entries together. Manual proxy pins ride with learned (domain-shaped lines
	 * as suffixes; IP-shaped lines already went to `manual_ips`). */
	/* ч.63: a learned/pinned 'www.X' host implicitly owns the X site. OAuth and
	 * SSO redirect layers bounce through the APEX and sibling subdomains that
	 * never appear in a DNS/SNI capture (tinkercad.com realm redirects,
	 * api-*.tinkercad.com session endpoints) — with only 'www.X' as a suffix
	 * those hops fell to the final (direct) rule while the site rode the proxy.
	 * Derive the apex as a suffix so the whole service family stays on one exit. */
	let apexes = {};
	for (let i, d in learned_domains) {
		const m = match(lc(d), /^www\.([a-z0-9._-]+)$/);
		if (m)
			apexes[m[1]] = true;
	}
	for (let a in keys(apexes))
		if (index(learned_domains, a) < 0)
			push(learned_domains, a);
	let mip_arr = [], aip_arr = [];
	for (let v in keys(manual_ips))
		push(mip_arr, v);
	for (let v in keys(auto_ips))
		push(aip_arr, v);
	sort(mip_arr, (a, b) => (a < b) ? -1 : (a > b) ? 1 : 0);
	sort(aip_arr, (a, b) => (a < b) ? -1 : (a > b) ? 1 : 0);
	let rules = [];
	if (length(domains))
		push(rules, { domain_keyword: domains });
	if (length(learned_domains))
		push(rules, { domain_suffix: learned_domains });
	write_ruleset_file(res + '/proxy_domain.json', {
		version: 1,
		rules: rules
	});
	/* B6.3: MANUAL IPs in their own watched file — the generator emits the
	 * 'manual-ip' rule unconditionally (independent of automation_enabled),
	 * so a hand-pinned IP routes with Automation off too. */
	write_ruleset_file(res + '/manual_ip.json', {
		version: 1,
		rules: length(mip_arr) ? [ { ip_cidr: mip_arr } ] : []
	});
	write_ruleset_file(res + '/auto_ip.json', {
		version: 1,
		rules: length(aip_arr) ? [ { ip_cidr: aip_arr } ] : []
	});

	return { domains: length(domains) + length(learned_domains),
		manual_ips: length(mip_arr), auto_ips: length(aip_arr), dropped: drops };
};

/* ── Ф4.2 (U7) User list sync ────────────────────────────────────────────────
 * One watched rule-set file PER user list: resources/lists/<sid>.json is
 * rewritten from resources/lists/<sid>.txt. The generator emits the rule-set
 * declaration + a routing rule with the list's own outbound; editing the
 * content then hot-reloads without touching the rule. The source .txt holds
 * NORMALIZED values (what the RPC accepted through classify_entry), so the
 * txt and the JSON agree and an export is exactly what routes.
 *
 * ctype selects what a line must be:
 *   'domains' → domain entries → domain_suffix (a host + its subdomains);
 *   'ips'     → ipv4/ipv6/cidr4/cidr6 → ip_cidr.
 * Everything else is DROPPED AND COUNTED (never silent). sid is validated
 * against /^ul_[A-Za-z0-9_]{1,64}$/ — the path can never escape lists/. */
export function sync_user_list(res_dir, sid, ctype) {
	let res = res_dir || (HP_DIR + '/resources');
	if (type(sid) !== 'string' || !match(sid, /^ul_[A-Za-z0-9_]{1,64}$/))
		return { accepted: 0, dropped: 0, error: 'bad list id' };
	if (ctype !== 'ips' && ctype !== 'domains')
		return { accepted: 0, dropped: 0, error: 'bad list type' };
	system('mkdir -p ' + shellQuote(res) + '/lists');
	let vals = {}, drops = 0;
	for (let d in read_list_entries(res + '/lists', sid + '.txt')) {
		let c = classify_entry(d);
		if (!c) { drops++; continue; }
		if (ctype === 'ips') {
			if (c.kind === 'domain') { drops++; continue; }
			vals[c.value] = true;
		} else {
			if (c.kind !== 'domain') { drops++; continue; }
			vals[c.value] = true;
		}
	}
	let arr = [];
	for (let v in keys(vals))
		push(arr, v);
	sort(arr, (a, b) => (a < b) ? -1 : (a > b) ? 1 : 0);
	let rules = [];
	if (length(arr))
		push(rules, (ctype === 'ips') ? { ip_cidr: arr } : { domain_suffix: arr });
	write_ruleset_file(res + '/lists/' + sid + '.json', {
		version: 1,
		rules: rules
	});
	return { accepted: length(arr), dropped: drops };
};

/* Manual "always direct" pins (Automation table): watched local rule-set consumed by
 * the 'auto-direct' route rule, which sits ABOVE the proxy/learned rules so a pinned
 * host always rides direct-out. Regenerated by the RPC that edits manual_direct.txt;
 * here it only guarantees the file exists (an empty rule-set is a no-op). */
export function sync_manual_direct_ruleset(res_dir) {
	let res = res_dir || (HP_DIR + '/resources');
	system('mkdir -p ' + shellQuote(res));
	/* Ф4.1 B6.2: entries decided by classify_entry() — a manual IPv4 (bare or
	 * CIDR) is an ip_cidr entry (normalized /32 when bare), NEVER domain_suffix
	 * (the old classifier dropped bare v4 into the DOMAIN branch — dead entry);
	 * junk is dropped and counted, never silent. */
	let doms = [], ips = {}, drops = 0;
	for (let x in read_list_entries(res, 'manual_direct.txt')) {
		let c = classify_entry(x);
		if (!c) {
			drops++;
			continue;
		}
		if (c.kind === 'domain')
			push(doms, c.value);
		else
			ips[c.value] = true;
	}
	let ip_arr = [];
	for (let v in keys(ips))
		push(ip_arr, v);
	sort(ip_arr, (a, b) => (a < b) ? -1 : (a > b) ? 1 : 0);
	let rules = [];
	if (length(doms))
		push(rules, { domain_suffix: doms });
	if (length(ip_arr))
		push(rules, { ip_cidr: ip_arr });
	write_ruleset_file(res + '/auto_direct.json', {
		version: 1,
		rules: rules
	});
	/* B6.5: DOMAIN-ONLY twin for the DNS rule — sing-box 1.14+ rejects DNS
	 * rules whose rule-set carries ip_cidr entries ("Legacy Address Filter
	 * Fields", FATAL at config validation), so the manual-exclusion DNS rule
	 * must reference a ruleset with domain entries ONLY. Always emitted
	 * (possibly empty) so the watched path is stable for hot reload. */
	write_ruleset_file(res + '/auto_direct_domain.json', {
		version: 1,
		rules: length(doms) ? [ { domain_suffix: doms } ] : []
	});
	return { domains: length(doms), ips: length(ip_arr), dropped: drops };
};

/* OAuth stability (ч.59): watched local rule-set consumed by the 'oauth-domain'
 * route/DNS rules (generate_client.uc, proxy_banned_ru). Auth-provider hosts
 * from resources/oauth_stable.txt ride the SAME exit as the services that open
 * them instead of the RU-geo "always direct" split, resolve through the
 * encrypted pool, and never escape into QUIC. Regenerated by generate_client
 * on every config build; the watched file keeps it hot-reloadable like the
 * other local rule-sets. */
export function sync_oauth_ruleset(res_dir) {
	let res = res_dir || (HP_DIR + '/resources');
	system('mkdir -p ' + shellQuote(res));
	/* Ф4.1: entries through classify_entry() — domains only (an IP or junk
	 * entry is dropped and counted, never silently kept as a dead suffix). */
	let doms = [], drops = 0;
	for (let x in read_list_entries(res, 'oauth_stable.txt')) {
		x = replace(x, /#.*$/, '');
		let c = classify_entry(x);
		if (c && c.kind === 'domain')
			push(doms, c.value);
		else
			drops++;
	}
	write_ruleset_file(res + '/oauth_domain.json', {
		version: 1,
		rules: length(doms) ? [ { domain_suffix: doms } ] : []
	});
	return { domains: length(doms), dropped: drops };
};

/* Auth-family list (ч.61): REGISTERED PARENT domains of learned auth-like
 * hosts (accounts.autodesk.com → autodesk.com), written by the automation
 * daemon. OAuth/session flows touch sibling hosts the engine never learns
 * (profile.*, iam.*, cdn.*) — an unlearned geo-blocked sibling stays DIRECT
 * with a RU IP while the auth host rides the proxy, and the provider's risk
 * engine sees one session hopping countries (Autodesk socialSignInFailed
 * loop). The watched 'auto-auth-domain' rule-set routes the WHOLE family
 * through the dedicated pinned OAuth exit so every identity leg is
 * consistent. */
export function sync_auto_auth_ruleset(res_dir) {
	let res = res_dir || (HP_DIR + '/resources');
	system('mkdir -p ' + shellQuote(res));
	/* Ф4.1: entries through classify_entry() — the parent-domain list is
	 * domains only; an IP/junk entry is dropped and counted. */
	let doms = [], drops = 0;
	for (let x in read_list_entries(res, 'auto_auth.txt')) {
		let c = classify_entry(x);
		if (c && c.kind === 'domain')
			push(doms, c.value);
		else
			drops++;
	}
	write_ruleset_file(res + '/auto_auth.json', {
		version: 1,
		rules: length(doms) ? [ { domain_suffix: doms } ] : []
	});
	return { domains: length(doms), dropped: drops };
};

/* RU-geo rule-sets for the "RU never via proxy" guard:
 *   ru_geoip.json   = ip_cidr from resources/ru_geoip.txt   (all RU networks, v4+v6)
 *   ru_geosite.json = domain entries from resources/ru_geosite.txt
 * The .txt sources are downloaded by ru_geo_update.sh (RPC / daemon auto-update).
 * JSON files are (re)written ONLY when missing or stale (source newer) — they are
 * hundreds of KB and live on flash; regenerating on every call would wear it. */
export function sync_ru_geo_rulesets(res_dir) {
	let res = res_dir || (HP_DIR + '/resources');
	system('mkdir -p ' + shellQuote(res));
	let gdrops = 0;
	let stale = (src, dst) => {
		if (!access(dst)) return true;
		let a = stat(src), b = stat(dst);
		if (a && b && a.mtime && b.mtime && a.mtime > b.mtime) return true;
		return false;
	};

	/* geoip: plain CIDR lines (v4/v6 mixed), classified by classify_entry()
	 * (Ф4.1) — prefix length validated (a /33 from a broken upstream mirror
	 * never reaches the core as a dead/malformed entry), bare IPs normalized
	 * to /32|/128. An empty rule-set is emitted when the source has not been
	 * downloaded yet — the config always references these files
	 * (hot reload needs a stable path), so they must always exist. */
	if (!access(res + '/ru_geoip.json') ||
	    (access(res + '/ru_geoip.txt') && stale(res + '/ru_geoip.txt', res + '/ru_geoip.json'))) {
		let cids = [];
		for (let x in read_list_entries(res, 'ru_geoip.txt')) {
			let c = classify_entry(x);
			if (!c || c.kind === 'domain') {
				gdrops++;
				continue;
			}
			push(cids, c.value);
		}
		write_ruleset_file(res + '/ru_geoip.json', {
			version: 1,
			rules: length(cids) ? [ { ip_cidr: cids } ] : []
		});
	}

	/* geosite: prefixed lines (v2ray geosite source format):
	 *   domain:x → domain_suffix, full:x → domain, keyword:x → domain_keyword.
	 * regexp/attribute lines are skipped (not representable without PCRE).
	 * NOT classified strictly (Ф4.1): the upstream format carries TLD-level
	 * suffixes like 'domain:.ru' that a strict hostname check would DROP —
	 * that would silently punch a hole in the RU-protection. The format is
	 * structured upstream data, not user-authored entries.
	 * Empty rule-set emitted when the source is not downloaded yet (see geoip). */
	if (!access(res + '/ru_geosite.json') ||
	    (access(res + '/ru_geosite.txt') && stale(res + '/ru_geosite.txt', res + '/ru_geosite.json'))) {
		let suf = [], full = [], kw = [];
		let raw = access(res + '/ru_geosite.txt') ? readfile(res + '/ru_geosite.txt') : '';
		if (raw)
			for (let i, x in filter(split(trim(raw), /[\r\n]/), (y) => {
				y = trim(y);
				return length(y) && !match(y, /^\s*#/);
			})) {
				let m = match(x, /^(domain|full|keyword):(.+)$/);
				if (m) {
					let v = lc(trim(m[2]));
					if (!length(v)) continue;
					if (m[1] === 'domain') push(suf, v);
					else if (m[1] === 'full') push(full, v);
					else push(kw, v);
				} else if (!match(x, ':')) {
					/* bare domain line (our own older exports) → suffix */
					push(suf, lc(x));
				}
			}
		let rules = [];
		if (length(suf)) push(rules, { domain_suffix: suf });
		if (length(full)) push(rules, { domain: full });
		if (length(kw)) push(rules, { domain_keyword: kw });
		write_ruleset_file(res + '/ru_geosite.json', {
			version: 1,
			rules: rules
		});
	}
	return { geoip: access(res + '/ru_geoip.json'), geosite: access(res + '/ru_geosite.json'), dropped: gdrops };
};

/* Utilities end */

/* String helper start */
export function isEmpty(res) {
	return !res || res === 'nil' || (type(res) in ['array', 'object'] && length(res) === 0);
};

export function strToBool(str) {
	return (str === '1') || null;
};

export function strToInt(str) {
	return !isEmpty(str) ? (int(str) || null) : null;
};

export function strToTime(str) {
	if (isEmpty(str))
		return null;
	str = '' + str;
	/* A subscription may already deliver a unit-bearing duration (e.g. sing-box
	 * "10s", "1m30s"); only append 's' to a bare number so we never emit "10ss". */
	return match(str, /[a-zA-Z]$/) ? str : (str + 's');
};

export function removeBlankAttrs(res) {
	let content;

	if (type(res) === 'object') {
		content = {};
		map(keys(res), (k) => {
			if (type(res[k]) in ['array', 'object'])
				content[k] = removeBlankAttrs(res[k]);
			else if (res[k] !== null && res[k] !== '')
				content[k] = res[k];
		});
	} else if (type(res) === 'array') {
		content = [];
		map(res, (k, i) => {
			if (type(k) in ['array', 'object'])
				push(content, removeBlankAttrs(k));
			else if (k !== null && k !== '')
				push(content, k);
		});
	} else
		return res;

	return content;
};

export function validateHostname(hostname) {
	return (match(hostname, /^[a-zA-Z0-9_]+$/) != null ||
		(match(hostname, /^[a-zA-Z0-9_][a-zA-Z0-9_%-.]*[a-zA-Z0-9]$/) &&
			match(hostname, /[^0-9.]/)));
};

export function validation(datatype, data) {
	if (!datatype || !data)
		return null;

	const ret = system(`/sbin/validate_data ${shellQuote(datatype)} ${shellQuote(data)} 2>/dev/null`);
	return (ret === 0);
};

/* ── Ф5.3 (аудит 51): ЕДИНЫЙ валидатор узлов для всех импортёров ─────────────
 * Подписки (update_subscriptions), share-link (import_link), .conf-импорт
 * (import_conf.uc) и браузерный parseWireGuardConf пропускают узел через
 * ЭТУ функцию ДО записи в UCI: адрес/порт/ключи проверяются по одним правилам,
 * битый узел отбрасывается С ПРИЧИНОЙ, а не молча попадает в генерируемый
 * конфиг (где ядро падает на валидации, а LKG откатывает старт целиком).
 * Возвращает null (узел валиден) либо МАССИВ строк с причинами (русские —
 * строки идут в лог/UI/TG без _()). Экспортируется для вызова из скриптов. */
function hp_key_b64(s) {
	/* WireGuard/Amnezia ключ = 44 символа base64 (43 + '='). Допускаем
	 * url-safe алфавит ('-'/'_'), как decodeBase64Str. */
	if (type(s) !== 'string' || length(s) !== 44)
		return false;
	return match(replace(replace(s, '-', '+'), '_', '/'), /^[A-Za-z0-9+/]{43}=$/) != null;
}

function hp_uuid_ok(s) {
	return (type(s) === 'string' &&
		match(s, /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/) != null);
}

function hp_addr_ok(s) {
	if (type(s) !== 'string' || !length(trim(s)))
		return false;
	const a = trim(s);
	if (validateHostname(a))
		return true;
	/* IPv4/IPv6 — тем же разбором, что classify_entry (без CIDR-суффикса). */
	if (ipv4_parts_ok(a))
		return true;
	const hx = ipv6_hextets(a);
	return (hx != null);
}

function hp_port_ok(s, lo) {
	if (type(s) !== 'string' || !match(s, /^\d+$/))
		return false;
	const p = int(s);
	const min = (lo == null) ? 1 : lo;   /* 🔴 не «lo || 1»: 0 валиден для keepalive */
	return (p >= min && p <= 65535);
};

export function validate_node_config(cfg) {
	if (type(cfg) !== 'object')
		return [ 'узел: конфиг не объект' ];

	const t = cfg.type;
	const TYPES = ['vless', 'vmess', 'trojan', 'shadowsocks', 'naive', 'tuic',
		'hysteria', 'hysteria2', 'wireguard', 'amneziawg', 'ssh', 'mieru',
		'anytls', 'trusttunnel', 'socks', 'http'];
	if (type(t) !== 'string' || !(t in TYPES))
		return [ 'неизвестный тип узла: ' + ((t == null) ? '—' : '' + t) ];

	let errs = [];

	if (!hp_addr_ok(cfg.address))
		push(errs, 'адрес отсутствует или невалиден');
	if (t === 'mieru') {
		/* Генератор силой ставит server_port=0 — порт идёт ТОЛЬКО через
		 * mieru_port_range "min:max". */
		if (cfg.port !== '0')
			push(errs, 'mieru: порт должен быть 0 (диапазон — в mieru_port_range)');
		const pr = cfg.mieru_port_range;
		if (type(pr) !== 'string' || !match(pr, /^\d+:\d+$/))
			push(errs, 'mieru: отсутствует диапазон портов min:max');
		else {
			const pp = split(pr, ':');
			const lo = int(pp[0]), hi = int(pp[1]);
			if (lo < 1 || hi > 65535 || lo > hi)
				push(errs, 'mieru: диапазон портов ' + pr + ' вне 1–65535 или перепутан');
		}
	} else if (!hp_port_ok(cfg.port, 1)) {
		push(errs, 'порт отсутствует или вне диапазона 1–65535');
	}

	if ((t === 'vless' || t === 'vmess' || t === 'tuic') && !hp_uuid_ok(cfg.uuid))
		push(errs, t + ': UUID отсутствует или невалиден');
	if ((t === 'trojan' || t === 'anytls') && (type(cfg.password) !== 'string' || !length(cfg.password)))
		push(errs, t + ': пароль отсутствует');
	if (t === 'shadowsocks') {
		if (type(cfg.shadowsocks_encrypt_method) !== 'string' || !length(cfg.shadowsocks_encrypt_method))
			push(errs, 'shadowsocks: метод шифрования отсутствует');
		if (type(cfg.password) !== 'string' || !length(cfg.password))
			push(errs, 'shadowsocks: пароль отсутствует');
	}
	if (t === 'ssh' && (type(cfg.ssh_priv_key) !== 'string' || !length(cfg.ssh_priv_key)))
		push(errs, 'ssh: приватный ключ отсутствует');

	if (t === 'wireguard' || t === 'amneziawg') {
		if (!hp_key_b64(cfg.wireguard_private_key))
			push(errs, 'wireguard: private_key не base64-ключ (44 символа)');
		if (!hp_key_b64(cfg.wireguard_peer_public_key ?? cfg.wireguard_public_key))
			push(errs, 'wireguard: public_key пира не base64-ключ (44 символа)');
		if (cfg.wireguard_pre_shared_key && !hp_key_b64(cfg.wireguard_pre_shared_key))
			push(errs, 'wireguard: pre_shared_key не base64-ключ (44 символа)');
		const ka = cfg.wireguard_local_address;
		if (type(ka) === 'array') {
			for (let i, a in ka) {
				const c = classify_entry(a);
				if (!c || c.kind === 'domain')
					push(errs, 'wireguard: локальный адрес «' + a + '» не IP/подсеть');
			}
			if (!length(ka))
				push(errs, 'wireguard: локальный адрес пуст');
		} else if (ka != null && length('' + ka)) {
			push(errs, 'wireguard: локальный адрес должен быть списком IP/подсетей');
		}
		/* Аудит 51: PersistentKeepalive не теряется и остаётся числом. */
		const pk = cfg.wireguard_persistent_keepalive_interval;
		if (pk != null && ('' + pk) !== '' && !hp_port_ok('' + pk, 0))
			push(errs, 'wireguard: persistent_keepalive «' + pk + '» не число 0–65535');
	}

	if (t === 'hysteria2' && cfg.hysteria_hopping_port != null &&
	    type(cfg.hysteria_hopping_port) === 'array') {
		for (let i, r in cfg.hysteria_hopping_port) {
			if (type(r) !== 'string' || !match(r, /^\d+:\d+$/) ||
			    int(split(r, ':')[0]) < 1 || int(split(r, ':')[1]) > 65535 ||
			    int(split(r, ':')[0]) > int(split(r, ':')[1]))
				push(errs, 'hysteria2: диапазон port-hopping «' + r + '» невалиден');
		}
	}

	if (cfg.tls_sni && !hp_addr_ok(cfg.tls_sni))
		push(errs, 'tls_sni невалиден');

	return length(errs) ? errs : null;
};
/* String parser start */
export function decodeBase64Str(str) {
	if (isEmpty(str))
		return null;

	str = trim(str);
	str = replace(str, '_', '/');
	str = replace(str, '-', '+');

	const padding = length(str) % 4;
	if (padding)
		str = str + substr('====', padding);

	return b64dec(str);
};

export function parseURL(url) {
	if (type(url) !== 'string')
		return null;

	const services = {
		http: '80',
		https: '443'
	};

	const objurl = {};

	objurl.href = url;

	url = replace(url, /#(.+)$/, (_, val) => {
		objurl.hash = val;
		return '';
	});

	url = replace(url, /^(\w[A-Za-z0-9\+\-\.]+):/, (_, val) => {
		objurl.protocol = val;
		return '';
	});

	url = replace(url, /\?(.+)/, (_, val) => {
		objurl.search = val;
		objurl.searchParams = urldecode_params(val);
		return '';
	});

	url = replace(url, /^\/\/([^\/]+)/, (_, val) => {
		val = replace(val, /^([^@]+)@/, (_, val) => {
			objurl.userinfo = val;
			return '';
		});

		val = replace(val, /:(\d+)$/, (_, val) => {
			objurl.port = val;
			return '';
		});

		if (validation('ip4addr', val) ||
		    validation('ip6addr', replace(val, /\[|\]/g, '')) ||
		    validation('hostname', val))
			objurl.hostname = val;

		return '';
	});

	objurl.pathname = url || '/';

	if (!objurl.protocol || !objurl.hostname)
		return null;

	if (objurl.userinfo) {
		objurl.userinfo = replace(objurl.userinfo, /:(.+)$/, (_, val) => {
			objurl.password = val;
			return '';
		});

		if (match(objurl.userinfo, /^[A-Za-z0-9\+\-\_\.]+$/)) {
			objurl.username = objurl.userinfo;
			delete objurl.userinfo;
		} else {
			delete objurl.userinfo;
			delete objurl.password;
		}
	};

	if (!objurl.port)
		objurl.port = services[objurl.protocol];

	objurl.host = objurl.hostname + (objurl.port ? `:${objurl.port}` : '');
	objurl.origin = `${objurl.protocol}://${objurl.host}`;

	return objurl;
};
/* String parser end */

/* ── Ф4.1 selftest (B6.10) — обязательные микротесты классификации ──────────
 * Чистая логика (classify_entry / ipv6_hextets) + файл-уровень в ИЗОЛИРОВАННОМ
 * каталоге /tmp/hp-selftest-<ts> (параметр res_dir у sync-семьи — живые
 * /etc/ravnex/resources самотест НЕ трогает). Сценарии B6.10: IPv4/32,
 * ручные IP → ip_cidr (не domain_suffix), битый CIDR (не проходит молча),
 * повреждённый список не ломает ruleset (JSON остаётся валидным), статический
 * keyword-список сохраняет семантику с извлечением IP-строк.
 * Прогон: ucode -e 'import {selftest} from "…/homeproxy.uc"; printf("%.J\n", selftest());' */
export function selftest() {
	let pass = 0, fail = 0, details = [];
	let ok = (name, cond) => {
		if (cond) { pass++; return; }
		fail++;
		push(details, name);
	};
	let cls = (s) => { let c = classify_entry(s); return c ? (c.kind + '|' + c.value) : 'null'; };

	const CASES = [
		['93.184.216.34', 'ipv4|93.184.216.34/32'],
		['93.184.216.34/32', 'cidr4|93.184.216.34/32'],
		['93.184.216.0/24', 'cidr4|93.184.216.0/24'],
		[' 93.184.216.34 ', 'ipv4|93.184.216.34/32'],
		['1.2.3.4/33', 'null'],
		['1.2.3.4/99', 'null'],
		['1.2.3.4/0', 'null'],
		['1.2.3.4/abc', 'null'],
		['999.1.1.1', 'null'],
		['1.2.3', 'null'],
		['1.2.3.4.5', 'null'],
		['01.2.3.4', 'null'],
		['256.1.1.1', 'null'],
		['2001:db8::1', 'ipv6|2001:db8::1/128'],
		['2001:db8::/32', 'cidr6|2001:db8::/32'],
		['::1', 'ipv6|::1/128'],
		['::', 'ipv6|::/128'],
		['::ffff:1.2.3.4', 'ipv6|::ffff:1.2.3.4/128'],
		['a::b::c', 'null'],
		[':::', 'null'],
		['1.2.3.4::b', 'null'],
		['12345::', 'null'],
		['1:2:3:4:5:6:7:8', 'ipv6|1:2:3:4:5:6:7:8/128'],
		['1:2:3:4:5:6:1.2.3.4', 'ipv6|1:2:3:4:5:6:1.2.3.4/128'],
		['1:2:3:4:5:6:7:1.2.3.4', 'null'],
		['2001:db8::1/129', 'null'],
		['example.com', 'domain|example.com'],
		['.Example.COM.', 'domain|example.com'],
		['EXAMPLE.com', 'domain|example.com'],
		['xn--b1agh1fop.com', 'domain|xn--b1agh1fop.com'],
		['localhost', 'null'],
		['a..b', 'null'],
		['example.com/path', 'null'],
		['example.com:443', 'null'],
		['-bad-', 'null'],
		['user@Example.com', 'null'],
		['example.com/24', 'null'],
		['', 'null'],
		['   ', 'null']
	];
	for (let i, t in CASES)
		ok('classify [' + t[0] + '] → ' + t[1], cls(t[0]) === t[1]);

	let hx = (s) => { let a = ipv6_hextets(s); return a ? join(',', a) : 'null'; };
	ok('hextets ::ffff:1.2.3.4', hx('::ffff:1.2.3.4') === '0,0,0,0,0,65535,258,772');
	ok('hextets 2001:db8::1', hx('2001:db8::1') === '8193,3512,0,0,0,0,0,1');
	ok('hextets :: ', hx('::') === '0,0,0,0,0,0,0,0');
	ok('hextets full form', hx('2001:0db8:0000:0000:0000:0000:0000:0001') === hx('2001:db8::1'));

	/* Ф5.3 (аудит 51): единый валидатор узлов импортёров */
	let vld = (c) => { let e = validate_node_config(c); return e ? join('|', e) : 'ok'; };
	ok('vld vless good', vld({ type: 'vless', address: 'a.example.com', port: '443',
		uuid: '8f2c5e6a-1b2c-3d4e-5f60-7a8b9c0d1e2f' }) === 'ok');
	ok('vld bad uuid', index(vld({ type: 'vless', address: 'a.example.com', port: '443',
		uuid: 'xyz' }), 'UUID') >= 0);
	ok('vld bad port', index(vld({ type: 'trojan', address: '1.2.3.4', port: '70000',
		password: 'x' }), 'порт') >= 0);
	ok('vld no address', index(vld({ type: 'trojan', address: null, port: '443',
		password: 'x' }), 'адрес') >= 0);
	ok('vld ipv6 address ok', vld({ type: 'socks', address: '2001:db8::1', port: '1080' }) === 'ok');
	ok('vld ss good', vld({ type: 'shadowsocks', address: 'a.b.c', port: '8388',
		shadowsocks_encrypt_method: 'aes-128-gcm', password: 'pw' }) === 'ok');
	ok('vld ss no method', index(vld({ type: 'shadowsocks', address: 'a.b.c', port: '8388',
		password: 'pw' }), 'метод') >= 0);
	ok('vld unknown type', index(vld({ type: 'juju', address: 'a.b.c', port: '1' }),
		'неизвестный тип') >= 0);
	ok('vld null config', type(validate_node_config(null)) === 'array');
	ok('vld mieru good', vld({ type: 'mieru', address: 'a.b.c', port: '0',
		mieru_port_range: '10000:20000' }) === 'ok');
	ok('vld mieru bad range', index(vld({ type: 'mieru', address: 'a.b.c', port: '0',
		mieru_port_range: '20000:10000' }), 'диапазон') >= 0);
	ok('vld mieru nonzero port', index(vld({ type: 'mieru', address: 'a.b.c', port: '8080',
		mieru_port_range: '10000:20000' }), 'mieru') >= 0);
	ok('vld hy2 hopping good', vld({ type: 'hysteria2', address: 'a.b.c', port: '443',
		hysteria_hopping_port: [ '40000:50000' ] }) === 'ok');
	ok('vld hy2 hopping bad', index(vld({ type: 'hysteria2', address: 'a.b.c', port: '443',
		hysteria_hopping_port: [ '50000:40000' ] }), 'port-hopping') >= 0);
	ok('vld tls_sni bad', index(vld({ type: 'vless', address: 'a.b.c', port: '443',
		uuid: '8f2c5e6a-1b2c-3d4e-5f60-7a8b9c0d1e2f', tls_sni: 'bad sni' }), 'tls_sni') >= 0);

	/* файл-уровень в изоляции */
	let dir = '/tmp/hp-selftest-' + sprintf('%d', time());
	system('rm -rf ' + shellQuote(dir));
	system('mkdir -p ' + shellQuote(dir));
	try {
		let rj = (name) => { let raw = readfile(dir + '/' + name); let j = null; try { j = json(raw); } catch (e) { j = null; } return j; };

		/* B6.1: голый IPv4 выученного списка → /32 маршрутизируется; битый
		 * префикс и мусор отброшены И посчитаны (не молча). v6-семпл —
		 * глобально-маршрутизируемый: 2001:db8::/32 = IANA documentation,
		 * его честно ловит is_special_ip (s190). */
		writefile(dir + '/auto_proxy_ip.txt', '93.184.216.34\n2606:4700:4700::1111\n1.2.3.4/33\nnot-an-ip\n# comment\n\n');
		let r1 = sync_learned_rulesets(dir);
		let j1 = rj('auto_ip.json');
		ok('B6.1 counts', r1.auto_ips === 2 && r1.dropped === 2);
		ok('B6.1 json cidr /32+/128', j1 && j1.rules[0] &&
			index(j1.rules[0].ip_cidr, '93.184.216.34/32') >= 0 &&
			index(j1.rules[0].ip_cidr, '2606:4700:4700::1111/128') >= 0);

		/* B6.3: ручные IP (proxy_list + manual_proxy) → manual_ip.json,
		 * выученные → auto_ip.json — два отдельных набора */
		writefile(dir + '/proxy_list.txt', 'youtube\n93.184.216.34\n');
		writefile(dir + '/manual_proxy.txt', '8.8.8.8\nexample.com\n');
		writefile(dir + '/auto_proxy_ip.txt', '1.1.1.1\n');
		let r10 = sync_learned_rulesets(dir);
		let jm = rj('manual_ip.json');
		let ja = rj('auto_ip.json');
		ok('B6.3 split counts', r10.manual_ips === 2 && r10.auto_ips === 1);
		ok('B6.3 manual json', jm && jm.rules[0] &&
			index(jm.rules[0].ip_cidr, '93.184.216.34/32') >= 0 &&
			index(jm.rules[0].ip_cidr, '8.8.8.8/32') >= 0);
		ok('B6.3 auto json isolated', ja && ja.rules[0] &&
			length(ja.rules[0].ip_cidr) === 1 && ja.rules[0].ip_cidr[0] === '1.1.1.1/32');

		/* B6.2: ручной IP → ip_cidr (НИКОГДА domain_suffix) и — B6.3 — в
		 * MANUAL набор (manual_ip.json), а не в выученный (auto_ip.json);
		 * домен → suffix, мусор отброшен с счётчиком */
		writefile(dir + '/proxy_list.txt', '');
		writefile(dir + '/auto_proxy_list.txt', '');
		writefile(dir + '/auto_proxy_ip.txt', '');
		writefile(dir + '/manual_proxy.txt', 'example.com\n1.2.3.4\nbad..entry\n');
		let r2 = sync_learned_rulesets(dir);
		let j2 = rj('proxy_domain.json');
		let j3 = rj('manual_ip.json');
		let j3a = rj('auto_ip.json');
		ok('B6.2 manual split', r2.domains === 1 && r2.manual_ips === 1 && r2.dropped === 1);
		ok('B6.2 suffix only domain', j2 && j2.rules[0] && j2.rules[0].domain_suffix &&
			length(j2.rules[0].domain_suffix) === 1 && j2.rules[0].domain_suffix[0] === 'example.com');
		ok('B6.2 ip in manual cidr', j3 && j3.rules[0] && index(j3.rules[0].ip_cidr, '1.2.3.4/32') >= 0);
		ok('B6.3 auto set untouched', j3a && type(j3a.rules) === 'array' && length(j3a.rules) === 0);

		/* «Напрямую»-пины: тот же расклад для manual_direct */
		writefile(dir + '/manual_direct.txt', '4.3.2.1\nexample.org\ngarbage@@\n');
		let r4 = sync_manual_direct_ruleset(dir);
		let j4 = rj('auto_direct.json');
		ok('direct split', r4.domains === 1 && r4.ips === 1 && r4.dropped === 1);
		ok('direct cidr+suffix', j4 && length(j4.rules) === 2 &&
			j4.rules[0].domain_suffix[0] === 'example.org' &&
			index(j4.rules[1].ip_cidr, '4.3.2.1/32') >= 0);
		/* B6.5: domain-only twin для DNS-правила (ip_cidr в DNS-правиле —
		 * FATAL валидации sing-box 1.14+) */
		let j4b = rj('auto_direct_domain.json');
		ok('direct domain-only twin', j4b && length(j4b.rules) === 1 &&
			j4b.rules[0].domain_suffix[0] === 'example.org');

		/* статический keyword-список: семантика сохранена, IP-строки извлечены
		 * В РУЧНОЙ набор (manual_ip.json — B6.3) */
		writefile(dir + '/proxy_list.txt', 'youtube\n93.184.216.34\nt.co\n');
		writefile(dir + '/manual_proxy.txt', '');
		writefile(dir + '/auto_proxy_list.txt', '');
		writefile(dir + '/auto_proxy_ip.txt', '');
		let r5 = sync_learned_rulesets(dir);
		let j5 = rj('proxy_domain.json');
		let j6 = rj('manual_ip.json');
		ok('static keywords kept', j5 && j5.rules[0] && j5.rules[0].domain_keyword &&
			length(j5.rules[0].domain_keyword) === 2 &&
			j5.rules[0].domain_keyword[0] === 'youtube' && j5.rules[0].domain_keyword[1] === 't.co');
		ok('static ip extracted', j6 && j6.rules[0] && index(j6.rules[0].ip_cidr, '93.184.216.34/32') >= 0);

		/* B6.8: конвейер нормализации — keyword-список лоуэркастится и
		 * дедуплицируется на построении ruleset (исходник не переписывается),
		 * выученный домен пишется нормализованным (c.value) */
		writefile(dir + '/proxy_list.txt', 'YouTube\nYOUTUBE\nExample.COM\n');
		writefile(dir + '/auto_proxy_list.txt', 'WWW.LinkedIn.com\n');
		writefile(dir + '/manual_proxy.txt', '');
		writefile(dir + '/auto_proxy_ip.txt', '');
		let r14 = sync_learned_rulesets(dir);
		let j14 = rj('proxy_domain.json');
		ok('B6.8 keyword lc+dedup', j14 && j14.rules[0] && j14.rules[0].domain_keyword &&
			length(j14.rules[0].domain_keyword) === 2 &&
			j14.rules[0].domain_keyword[0] === 'youtube' &&
			j14.rules[0].domain_keyword[1] === 'example.com');
		ok('B6.8 learned normalized', j14 && j14.rules[1] && j14.rules[1].domain_suffix &&
			length(j14.rules[1].domain_suffix) === 2 &&
			j14.rules[1].domain_suffix[0] === 'www.linkedin.com' &&
			j14.rules[1].domain_suffix[1] === 'linkedin.com');

		/* повреждённый список: sync выживает, JSON остаётся ВАЛИДНЫМ (ядро не
		 * получает битый rule-set), валидные соседи-строки выживают */
		writefile(dir + '/manual_direct.txt', sprintf('%c%cbroken', 1, 2) + '@@\n4.3.2.1\n');
		let r7 = sync_manual_direct_ruleset(dir);
		let j7 = rj('auto_direct.json');
		ok('damaged list survives', r7.dropped === 1 && j7 && j7.rules[0] &&
			index(j7.rules[0].ip_cidr, '4.3.2.1/32') >= 0);

		/* Ф4.2 user list: домены → domain_suffix, дедуп, мусор отброшен и
		 * посчитан; IP-тип → ip_cidr; домен в IP-списке отброшен; битый id и
		 * битый ctype отвергнуты БЕЗ записи файлов */
		system('mkdir -p ' + shellQuote(dir + '/lists'));
		writefile(dir + '/lists/ul_t1.txt', 'Example.COM.\nwww.example.com\nbad..entry\n1.2.3.4\n# note\nExample.com\n');
		let r11 = sync_user_list(dir, 'ul_t1', 'domains');
		let j11 = rj('lists/ul_t1.json');
		ok('user list domains', r11.accepted === 2 && r11.dropped === 2);
		ok('user list json', j11 && j11.rules[0] && j11.rules[0].domain_suffix &&
			length(j11.rules[0].domain_suffix) === 2 &&
			j11.rules[0].domain_suffix[0] === 'example.com' &&
			j11.rules[0].domain_suffix[1] === 'www.example.com');
		writefile(dir + '/lists/ul_t2.txt', '10.0.0.0/8\n2001:db8::/32\nexample.org\n10.0.0.0/8\n');
		let r12 = sync_user_list(dir, 'ul_t2', 'ips');
		let j12 = rj('lists/ul_t2.json');
		ok('user list ips', r12.accepted === 2 && r12.dropped === 1);
		ok('user list ip json', j12 && j12.rules[0] &&
			index(j12.rules[0].ip_cidr, '10.0.0.0/8') >= 0 &&
			index(j12.rules[0].ip_cidr, '2001:db8::/32') >= 0);
		ok('user list bad id', sync_user_list(dir, 'evil/../../x', 'domains').error === 'bad list id' &&
			!access(dir + '/lists/evil'));
		ok('user list bad ctype', sync_user_list(dir, 'ul_t1', 'mixed').error === 'bad list type');
		writefile(dir + '/lists/ul_t3.txt', 'garbage@@\n');
		let r13 = sync_user_list(dir, 'ul_t3', 'domains');
		let j13 = rj('lists/ul_t3.json');
		ok('user list empty json valid', r13.accepted === 0 && r13.dropped === 1 &&
			j13 && type(j13.rules) === 'array' && length(j13.rules) === 0);

		/* oauth: только домены; IP/мусор отброшены */
		writefile(dir + '/oauth_stable.txt', 'clerk.com\n1.2.3.4\n# c\n');
		let r8 = sync_oauth_ruleset(dir);
		ok('oauth domains only', r8.domains === 1 && r8.dropped === 1);

		/* wireguard-ключи и PersistentKeepalive (аудит 51: поле не теряется) */
		const K43A = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
		const K43B = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
		ok('vld wg good', vld({ type: 'wireguard', address: '1.2.3.4', port: '51820',
			wireguard_private_key: K43A, wireguard_peer_public_key: K43B,
			wireguard_local_address: [ '10.0.0.2/32' ],
			wireguard_persistent_keepalive_interval: '25' }) === 'ok');
		ok('vld wg short key', index(vld({ type: 'wireguard', address: '1.2.3.4', port: '51820',
			wireguard_private_key: 'short', wireguard_peer_public_key: K43B }), 'base64') >= 0);
		ok('vld wg keepalive junk', index(vld({ type: 'wireguard', address: '1.2.3.4', port: '51820',
			wireguard_private_key: K43A, wireguard_peer_public_key: K43B,
			wireguard_persistent_keepalive_interval: 'foo' }), 'persistent_keepalive') >= 0);
		ok('vld wg keepalive zero ok', vld({ type: 'wireguard', address: '1.2.3.4', port: '51820',
			wireguard_private_key: K43A, wireguard_peer_public_key: K43B,
			wireguard_persistent_keepalive_interval: '0' }) === 'ok');
		ok('vld wg bad local addr', index(vld({ type: 'wireguard', address: '1.2.3.4', port: '51820',
			wireguard_private_key: K43A, wireguard_peer_public_key: K43B,
			wireguard_local_address: [ 'example.com' ] }), 'локальный адрес') >= 0);

		/* ru_geoip: валидация CIDR апстрима */
		writefile(dir + '/ru_geoip.txt', '5.61.0.0/16\n2001:db8::/32\n1.2.3.4/33\n');
		let r9 = sync_ru_geo_rulesets(dir);
		let j9 = rj('ru_geoip.json');
		ok('geoip validated', r9.dropped === 1 && j9 && j9.rules[0] && length(j9.rules[0].ip_cidr) === 2);
	} catch (e) {
		ok('file-level no exception: ' + sprintf('%s', e), false);
	}
	system('rm -rf ' + shellQuote(dir));

	return { ok: fail === 0, pass: pass, fail: fail, details: details };
};
