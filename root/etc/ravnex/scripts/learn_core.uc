// SPDX-License-Identifier: GPL-2.0-only
//
// Ravnex — IP-learning core helpers (Ф6.6, план 20 §Ф6; аудит B5).
//
// Чистые вычисления жизненного цикла выученных записей, вынесенные из
// automation.uc в МОДУЛЬ (проверяемый IMPORT'ом + selftest на роутере):
//   validate_learned_ip() — единая валидация выученного IP с ПРИЧИНОЙ
//     отказа (аудит B5.17: одна и та же защита в load/learn/sync);
//   uuid_collapse() — схлопывание UUID-меток ТОЛЬКО для известных
//     tracker/CDN-суффиксов (B5.6: <uuid>.tenant-platform.example
//     больше не превращает всю платформу в одну запись);
//   psl_parent() — зарегистрированный родитель домена по Public
//     Suffix List (B5.5: com.es без записи больше не расширяет всю зону);
//   src_diversity() — разнообразие НЕЗАВИСИМЫХ свидетельств для
//     pain-порога (B5.12, урок 254: DNS-шум одного источника — не боль).
//
// Правила ucode учтены: export → `};` (245), нет `undefined` (246),
// push/sort/keys — глобальные (249), match() — только regex-литерал (26).

'use strict';

/* ── B5.6: UUID-схлопывание только для известных суффиксов ──
 * Пер-пользовательские UUID-метки реально живут на трекер/CDN-хостах;
 * схлопывание там безопасно (вся зона и так один источник). Для прочих
 * доменов (<uuid>.tenant-platform.example) схлопывание съедало бы
 * тенанта целиком — теперь host возвращается БЕЗ изменений. */
export const UUID_TRACKER_SUFFIXES = [
	'fbcdn.net', 'cdninstagram.com', 'tiktokcdn.com', 'tiktokcdn-us.com',
	'tiktokv.com', 'tiktokw.us', 'twimg.com', 'googlevideo.com',
	'ytimg.com', 'gvt1.com', 'cloudfront.net', 'akamaized.net',
	'azureedge.net', 'edgekey.net', 'edgesuite.net'
];

function has_suffix(host, suffix) {
	return (host === suffix) || (substr(host, -length(suffix) - 1) === '.' + suffix);
};

export function uuid_collapse(host, suffixes) {
	const h = lc(trim('' + host));
	const parts = split(h, '.');
	if (length(parts) < 3)
		return null;                       /* нечего схлопывать */
	if (!match(parts[0], /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i))
		return null;                       /* первая метка не UUID-форма */
	let collapsed;
	if (length(parts[0]) === 36)
		collapsed = join('.', slice(parts, 1));       /* чистый UUID */
	else if (substr(parts[0], 36, 1) === '-')
		collapsed = (length(substr(parts[0], 37)) ? substr(parts[0], 37) + '.' : '') +
			join('.', slice(parts, 1));               /* сплавленный */
	else
		return null;
	const list = (type(suffixes) === 'array' && length(suffixes)) ? suffixes : UUID_TRACKER_SUFFIXES;
	for (let s in list) {
		if (has_suffix(collapsed, '' + s))
			return collapsed;              /* известный трекер/CDN — схлопываем */
	}
	return null;                           /* чужой домен — НЕ трогаем (B5.6) */
};

/* ── B5.5: зарегистрированный родитель по PSL ──
 * rules — массив суффиксов Public Suffix List (только многометковые правила
 * суть; однометковые TLD обрабатываются как раньше). Поддержка wildcard
 * (`*.ck`) и исключений (`!www.ck`). Возвращает ОДНУ метку над суффиксом
 * (registered domain) или null, если хост сам является публичным суффиксом. */
export function psl_parent(host, rules) {
	const h = lc(trim('' + host));
	const parts = split(h, '.');
	const n = length(parts);
	if (n < 2)
		return null;
	const excl = (type(rules) === 'object' && type(rules.excl) === 'object') ? rules.excl : null;
	const wild = (type(rules) === 'object' && type(rules.wild) === 'object') ? rules.wild : null;
	const set = (type(rules) === 'object' && type(rules.set) === 'object') ? rules.set : null;
	if (set == null)
		return null;
	/* Длиннейшее совпадение: точное правило, исключение или wildcard
	 * `*.y` (звезда покрывает ОДНУ метку: суффикс хоста a.b.y = b.y). */
	let best = 0;                          /* число меток в совпавшем суффиксе */
	for (let i = 0; i < n; i++) {
		const cand = join('.', slice(parts, i));
		const len = n - i;
		if (excl != null && excl[cand]) {
			/* Исключение `!cand` — cand САМ публичный суффикс. */
			best = len;
			break;
		}
		if (set[cand]) {
			if (len > best)
				best = len;
			continue;
		}
		if (wild != null && len === 2) {
			const la = split(cand, '.');
			if (wild[la[1]] && len > best)
				best = len;
		}
	}
	if (best <= 0)
		best = 1;                          /* однометковый TLD по умолчанию */
	const reg_start = n - best - 1;        /* метка registered-домена */
	if (reg_start < 0)
		return null;                       /* хост = сам публичный суффикс */
	return join('.', slice(parts, reg_start));
};

/* ── B5.12: разнообразие независимых свидетельств ──
 * st — запись состояния (src_dns/src_sni/src_clash — времена последних
 * упоминаний источниками; sight — накопленные появления по проходам;
 * sight_t — время последнего).-diversity: 0..3. Две СВЕЖИЕ (в окне 10 мин)
 * разные источники ИЛИ появления в ≥2 разных проходах — независимые
 * свидетельства; один DNS-шторм (AAAA/prefetch) внутри одного прохода — нет. */
export function src_diversity(st, now) {
	if (type(st) !== 'object')
		return 0;
	const fresh = (t) => (int(t || 0) > 0 && (int(now) - int(t)) < 600);
	let div = 0;
	if (fresh(st.src_dns)) div++;
	if (fresh(st.src_sni)) div++;
	if (fresh(st.src_clash)) div++;
	if (div >= 2)
		return div;
	/* Повторные пробы: появления в ≥2 разных проходах (sight копится ПО
	 * ПРОХОДАМ — урок 254: несколько устройств/AAAA в одном проходе дают
	 * host_score, но не sight≥2). */
	if (div >= 1 && int(st.sight || 0) >= 2)
		return div + 1;
	return div;
};

/* ── B5.17: единая валидация выученного IP ──
 * env — инъекция зависимостей (модуль не импортирует discovery/geo):
 *   special(ip) — IANA Special-Purpose (discovery.is_special_ip);
 *   shared_cdn(ip), infra(ip), resolver(ip), local(ip), ru_ip(ip).
 * Возвращает null (валиден) или ПРИЧИНУ для UI:
 *   invalid / private_range / shared_cdn / resolver_infrastructure /
 *   local / ru_network. */
export function validate_learned_ip(ip, env) {
	const s = trim('' + (ip == null ? '' : ip));
	if (!length(s))
		return 'invalid';
	const m = match(s, /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (m == null)
		return 'invalid';
	for (let i = 1; i <= 4; i++)
		if (int(m[i]) > 255)
			return 'invalid';
	const e = (type(env) === 'object') ? env : null;
	if (e == null)
		return null;
	if (type(e.local) === 'function' && e.local(s))
		return 'local';
	if (type(e.resolver) === 'function' && e.resolver(s))
		return 'resolver_infrastructure';
	if (type(e.infra) === 'function' && e.infra(s))
		return 'resolver_infrastructure';
	if (type(e.special) === 'function' && e.special(s))
		return 'private_range';
	if (type(e.shared_cdn) === 'function' && e.shared_cdn(s))
		return 'shared_cdn';
	if (type(e.ru_ip) === 'function' && e.ru_ip(s))
		return 'ru_network';
	return null;
};

/* ── Selftest ──
 * Тот же контракт, что service_optimizer/service_profiles:
 * возвращает { pass, fail, details }. */
export function selftest() {
	const pass = [], fail = [];
	const t = (name, cond) => (cond) ? push(pass, name) : push(fail, name);

	/* validate_learned_ip */
	const env = {
		special: (ip) => (ip === '100.64.1.1' || ip === '198.18.0.1' || ip === '192.168.5.5' || ip === '10.0.0.1'),
		shared_cdn: (ip) => (ip === '104.16.1.1'),
		infra: (ip) => (ip === '8.8.8.8'),
		resolver: (ip) => (ip === '1.1.1.1'),
		local: (ip) => (ip === '192.168.1.1'),
		ru_ip: (ip) => (ip === '95.161.1.1')
	};
	t('vld public ok', validate_learned_ip('93.184.216.34', env) == null);
	t('vld octet overflow', validate_learned_ip('1.2.3.999', env) === 'invalid');
	t('vld non-ip', validate_learned_ip('not-an-ip', env) === 'invalid');
	t('vld empty', validate_learned_ip('', env) === 'invalid');
	t('vld local', validate_learned_ip('192.168.1.1', env) === 'local');
	t('vld resolver', validate_learned_ip('1.1.1.1', env) === 'resolver_infrastructure');
	t('vld infra', validate_learned_ip('8.8.8.8', env) === 'resolver_infrastructure');
	t('vld cgnat', validate_learned_ip('100.64.1.1', env) === 'private_range');
	t('vld shared cdn', validate_learned_ip('104.16.1.1', env) === 'shared_cdn');
	t('vld ru', validate_learned_ip('95.161.1.1', env) === 'ru_network');
	t('vld no-env passes', validate_learned_ip('93.184.216.34', null) == null);

	/* uuid_collapse (B5.6) */
	t('uuid pure fbcdn', uuid_collapse('12345678-abcd-4bcd-8def-123456789abc.xz.fbcdn.net') === 'xz.fbcdn.net');
	t('uuid fused fbcdn', uuid_collapse('12345678-abcd-4bcd-8def-123456789abc-netseer.xz.fbcdn.net') === 'netseer.xz.fbcdn.net');
	t('uuid foreign NOT collapsed (B5.6)', uuid_collapse('12345678-abcd-4bcd-8def-123456789abc.tenant-platform.example') == null);
	t('uuid non-uuid label untouched', uuid_collapse('web.fbcdn.net') == null);
	t('uuid too-short host', uuid_collapse('short.name') == null);

	/* psl_parent (B5.5) */
	const rules = {
		set: { 'com.au': true, 'co.uk': true, 'com.es': true, 'com.tr': true, 'co.jp': true, 'blogspot.com': true, 'github.io': true },
		wild: { 'ck': true },
		excl: { 'www.ck': true }
	};
	t('psl plain 2-label', psl_parent('accounts.google.com', rules) === 'google.com');
	t('psl co.uk', psl_parent('x.y.co.uk', rules) === 'y.co.uk');
	t('psl com.es registered parent (B5.5 fix)', psl_parent('profile.x.com.es', rules) === 'x.com.es');
	t('psl host IS the suffix', psl_parent('blogspot.com', rules) == null);
	t('psl private entry = own blog', psl_parent('profile.blogspot.com', rules) === 'profile.blogspot.com');
	t('psl github.io private', psl_parent('docs.github.io', rules) === 'docs.github.io');
	t('psl wildcard *.ck', psl_parent('site.foo.ck', rules) === 'site.foo.ck');
	t('psl exception !www.ck = suffix itself', psl_parent('www.ck', rules) == null);
	t('psl default TLD fallback', psl_parent('example.com', rules) === 'example.com');

	/* src_diversity (B5.12) */
	const now = 1000000;
	t('div single dns only', src_diversity({ src_dns: now - 10, sight: 1 }, now) === 1);
	t('div dns+sni', src_diversity({ src_dns: now - 10, src_sni: now - 20, sight: 1 }, now) === 2);
	t('div dns + multi-pass sight', src_diversity({ src_dns: now - 10, sight: 3, sight_t: now - 5 }, now) === 2);
	t('div stale window', src_diversity({ src_dns: now - 10000 }, now) === 0);
	t('div no record', src_diversity(null, now) === 0);
	t('div three sources', src_diversity({ src_clash: now - 5, src_sni: now - 5, src_dns: now - 5 }, now) === 3);

	return { pass: length(pass), fail: length(fail), details: fail };
};
