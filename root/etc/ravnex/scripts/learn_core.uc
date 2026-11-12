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

/* ── s190: pragmatic IPv6 sanity for validate_learned_ip (ERE-safe).
 * charset hex/colon only, no ':::', no lone edge colons, '::' at most once,
 * every group 1-4 hex chars. Not a full RFC 4291 parser — it rejects junk,
 * which is the only job of a LEARNED-entry validator. */
function ipv6_groups_ok(s) {
	const g = split(s, ':');
	if (length(g) < 1 || length(g) > 8)
		return 0;
	for (let x in g) {
		if (!length(x) || length(x) > 4)
			return 0;
		if (!match(x, /^[0-9a-fA-F]{1,4}$/))
			return 0;
	}
	return 1;
}

function ipv6_sane(s) {
	if (!match(s, /^[0-9a-fA-F:]{2,45}$/))
		return 0;
	if (match(s, /:::/))
		return 0;
	const L = length(s);
	if (substr(s, 0, 1) === ':' && substr(s, 1, 1) !== ':')
		return 0;
	if (substr(s, L - 1, 1) === ':' && substr(s, L - 2, 1) !== ':')
		return 0;
	const parts = split(s, '::');
	if (length(parts) > 2)
		return 0;
	if (length(parts) === 2) {
		if (parts[0] !== '' && !ipv6_groups_ok(parts[0]))
			return 0;
		if (parts[1] !== '' && !ipv6_groups_ok(parts[1]))
			return 0;
		return 1;
	}
	return ipv6_groups_ok(s);
}

/* ── s190: resolver / time-sync infrastructure NEVER learned as blocked
 * domains. A DNS/NTP endpoint does not serve HTTP on :443 — the probe reads
 * direct 000/403/404 against a live proxy answer, which looks exactly like
 * an instant block; once learned, the user's own DNS/NTP bootstrapping is
 * dragged through the tunnel (live fact 2026-11-12: cloudflare-dns.com,
 * dns.google, *.pool.ntp.org sat in auto_proxy_list.txt). Dot-boundary
 * suffix match (exact or ".suffix"). */
const NEVER_LEARN_SUFFIXES = [
	'pool.ntp.org', 'ntp.org', 'time.nist.gov',
	'time.apple.com', 'time.windows.com', 'time.google.com',
	'time.facebook.com', 'time.cloudflare.com',
	'cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'chrome.cloudflare-dns.com',
	'security.cloudflare-dns.com', 'family.cloudflare-dns.com', 'wireguard.cloudflare-dns.com',
	'dns.google', 'dns.google.com',
	'dns.quad9.net', 'dns9.quad9.net', 'dns10.quad9.net', 'dns11.quad9.net',
	'dns.adguard.com', 'dns.adguard-dns.com',
	'doh.opendns.com', 'use-application-dns.net'
];

function never_learn_suffix_hit(h, s) {
	const n = length(s);
	if (length(h) < n)
		return 0;
	if (substr(h, length(h) - n, n) !== s)
		return 0;
	return (length(h) === n) ? 1 : (substr(h, length(h) - n - 1, 1) === '.' ? 1 : 0);
}

export function is_never_learn_domain(d) {
	const h = lc(trim('' + (d == null ? '' : d)));
	if (!length(h))
		return 0;
	for (let s in NEVER_LEARN_SUFFIXES)
		if (never_learn_suffix_hit(h, s))
			return 1;
	return 0;
};

/* ── B5.17: единая валидация выученного IP ──
 * env — инъекция зависимостей (модуль не импортирует discovery/geo):
 *   special(ip) — IANA Special-Purpose (discovery.is_special_ip);
 *   shared_cdn(ip), infra(ip), resolver(ip), local(ip), ru_ip(ip).
 * Возвращает null (валиден) или ПРИЧИНУ для UI:
 *   invalid / private_range / shared_cdn / resolver_infrastructure /
 *   local / ru_network. */
export function validate_learned_ip(ip, env) {
	const s0 = trim('' + (ip == null ? '' : ip));
	if (!length(s0))
		return 'invalid';
	/* s190: callers pass EITHER a bare host (load/learn in automation.uc)
	 * OR the classifier-normalized CIDR value (sync_learned_rulesets feeds
	 * c.value, e.g. '93.184.216.34/32'). The dotted-quad regex alone rejected
	 * every normalized value, so the generator dropped ALL learned IPs as
	 * 'invalid' and auto_ip.json never routed ("0 ips" on every hot apply —
	 * IP-shaped resources, hardcoded-IP apps, never covered). Strip one
	 * optional /plen (family-bounded) and run the gates on the bare host.
	 * ERE note: no \S — use [^/]+ (lesson: ucode ERE has no \d/\S). */
	const ipv6 = (index(s0, ':') >= 0);
	const plen_hi = ipv6 ? 128 : 32;
	let s = s0;
	const pm = match(s0, /^([^/]+)\/(\d{1,3})$/);
	if (pm != null) {
		const plen = int(pm[2]);
		if (plen == null || plen < 0 || plen > plen_hi)
			return 'invalid';
		s = pm[1];
	}
	if (ipv6) {
		if (!ipv6_sane(s))
			return 'invalid';
	} else {
		const m = match(s, /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
		if (m == null)
			return 'invalid';
		for (let i = 1; i <= 4; i++)
			if (int(m[i]) > 255)
				return 'invalid';
	}
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

/* ── сеанс 187 G2: транспортные подп-kind'ы для неклассифицированных
 * отказов ──
 * Выводится ТОЛЬКО из полей, которые Go-щуп (probe_pool) УЖЕ возвращает:
 * code (curl RC или HTTP-код), phase (последняя достигнутая фаза:
 * dns|tcp|tls|http), tls_note (classifyTLSFailure: reset|spoof|alert|
 * mitm|timeout|tcp). НИКАКИХ новых проб; вызывается ПОСЛЕ существующей
 * kind-цепочки (tls_dpi/stub/… разбирают свои формы первыми).
 *
 * Таблица (main.go: executeTCPProbe/classifyTLSFailure + шелл-RC):
 *   code '7'                → tcp_refused  (dial refused/no-route/unreachable)
 *   code '28', phase 'tcp'  → connect_timeout (чистый dial-таймаут)
 *   code '28', phase ''     → connect_timeout (TCP-сторона без фазы: dial и есть фаза)
 *   code '28', phase 'tls', note 'timeout' → tls_timeout (тихий дроп после ClientHello)
 *   code '000', phase 'tls'/'tcp', note 'tcp' → tcp_refused ( refusal на стадии
 *                                TLS-набора — соединение не установилось)
 *   code '000', phase 'tls', note 'mitm' → tls_mitm («спящая» ветка: текущая
 *                                сборка щупа ходит с InsecureSkipVerify=true,
 *                                заметка mitm недостижима; ветку держим для
 *                                будущего Go-гейта верификации сертификата)
 *   всё прочее (dns-фаза, alert, HTTP-side 28/000 без фазы, живые коды) → ''
 *   — честное «не различимо этими полями», не фейк-ноль. */
export function transport_kind(code, phase, tls_note) {
	const c = trim('' + (code == null ? '' : code));
	const p = trim('' + (phase == null ? '' : phase));
	const tn = trim('' + (tls_note == null ? '' : tls_note));
	if (p === 'dns')
		return '';
	if (c === '7')
		return 'tcp_refused';
	if (c === '28') {
		if (p === 'tcp' || p === '')
			return 'connect_timeout';
		if (p === 'tls' && tn === 'timeout')
			return 'tls_timeout';
		return '';
	}
	if (c === '000') {
		if ((p === 'tls' || p === 'tcp') && tn === 'tcp')
			return 'tcp_refused';
		if (p === 'tls' && tn === 'mitm')
			return 'tls_mitm';
		return '';
	}
	return '';
};

/* ── сеанс 187 G1-readside: корроборация по реестровым спискам ──
 * Хост, который движок выучил как заблокированный, может УЖЕ стоять в
 * реестровых/комьюнити-списках, доставленных конвейером (локальное зеркало
 * хаба). Совпадение — это ПОДСКАЗКА класса причины («Blocked (RKN-listed?)»,
 * знак вопроса обязателен: перекрытие списка ≠ доказательство причины), она
 * НИКАК не влияет на learn/heal. sets — массив {cat, entries}; entries —
 * ОБЪЕКТ-набор нижнекореженных суффиксов БЕЗ ведущих точек (нормализация —
 * забота загрузчика). Матч: точное имя или любой родительский суффикс.
 * Возвращает cat первого совпавшего набора или null («не измерено»). */
export function rkn_corroborate(host, sets) {
	const h = lc(trim('' + (host == null ? '' : host)));
	if (!length(h) || sets == null || type(sets) !== 'array')
		return null;
	for (let s in sets) {
		if (type(s) !== 'object' || type(s.entries) !== 'object')
			continue;
		if (s.entries[h])
			return '' + (s.cat || '');
		const parts = split(h, '.');
		for (let i = 1; i < length(parts); i++) {
			const anc = join('.', slice(parts, i));
			if (s.entries[anc])
				return '' + (s.cat || '');
		}
	}
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
	/* s190: generator passes the NORMALIZED CIDR value (c.value) — the old
	 * strict regex dropped every learned IP as 'invalid' ("0 ips" bug). */
	t('vld cidr normalized ok', validate_learned_ip('93.184.216.34/32', env) == null);
	t('vld plen overflow v4', validate_learned_ip('93.184.216.34/33', env) === 'invalid');
	t('vld cidr no-env ok', validate_learned_ip('93.184.216.34/32', null) == null);
	t('vld gate sees bare host', validate_learned_ip('100.64.1.1/32', env) === 'private_range');
	t('vld v6 bare ok', validate_learned_ip('2606:4700:4700::1111', env) == null);
	t('vld v6 cidr ok', validate_learned_ip('2001:db8::1/128', env) == null);
	t('vld v6 plen overflow', validate_learned_ip('2001:db8::1/129', env) === 'invalid');
	t('vld v6 triple-colon junk', validate_learned_ip('2001:db8:::1/64', env) === 'invalid');
	t('vld v6 bad group junk', validate_learned_ip('2001:db8::zz11', env) === 'invalid');
	t('vld cidr text junk', validate_learned_ip('10.0.0.1/hello', env) === 'invalid');

	/* s190: never-learn guard (resolver/NTP/DoH infrastructure) */
	t('nl ntp sub', is_never_learn_domain('0.pool.ntp.org') === 1);
	t('nl ntp datadog sub', is_never_learn_domain('0.datadog.pool.ntp.org') === 1);
	t('nl ntp openwrt sub', is_never_learn_domain('2.openwrt.pool.ntp.org') === 1);
	t('nl doh cf', is_never_learn_domain('cloudflare-dns.com') === 1);
	t('nl doh cf mozilla', is_never_learn_domain('mozilla.cloudflare-dns.com') === 1);
	t('nl doh google', is_never_learn_domain('dns.google') === 1);
	t('nl doh google com', is_never_learn_domain('dns.google.com') === 1);
	t('nl not fooled apex', is_never_learn_domain('mail.google.com') === 0);
	t('nl not fooled embed', is_never_learn_domain('ntpro.net') === 0);
	t('nl not fooled sub', is_never_learn_domain('blog.cloudflare-dns.com.evil.example') === 0);
	t('nl case-insensitive', is_never_learn_domain('0.POOL.NTP.ORG') === 1);
	t('nl empty', is_never_learn_domain('') === 0);

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

	/* сеанс 187 G2: transport_kind — таблица из полей Go-щупа */
	t('tk 7 → tcp_refused', transport_kind('7', '', '') === 'tcp_refused');
	t('tk 7 tls-note tolerated', transport_kind('7', 'tls', 'reset') === 'tcp_refused');
	t('tk 28 tcp → connect_timeout', transport_kind('28', 'tcp', '') === 'connect_timeout');
	t('tk 28 no-phase (TCP row) → connect_timeout', transport_kind('28', '', '') === 'connect_timeout');
	t('tk 28 tls+timeout → tls_timeout', transport_kind('28', 'tls', 'timeout') === 'tls_timeout');
	t('tk 28 tls+reset → "" (tls_dpi owns it)', transport_kind('28', 'tls', 'reset') === '');
	t('tk 28 http-phase honest ""', transport_kind('28', 'http', 'timeout') === '');
	t('tk 000 tls tcp → tcp_refused', transport_kind('000', 'tls', 'tcp') === 'tcp_refused');
	t('tk 000 tcp tcp → tcp_refused', transport_kind('000', 'tcp', 'tcp') === 'tcp_refused');
	t('tk 000 tls mitm → tls_mitm (sleeping)', transport_kind('000', 'tls', 'mitm') === 'tls_mitm');
	t('tk 000 tls reset → "" (tls_dpi owns it)', transport_kind('000', 'tls', 'reset') === '');
	t('tk 000 tls alert → "" (kopilka)', transport_kind('000', 'tls', 'alert') === '');
	t('tk dns-phase never kinds', transport_kind('28', 'dns', 'timeout') === '');
	t('tk ok-code honest ""', transport_kind('200', 'http', '') === '');
	t('tk numeric code tolerated', transport_kind(7, null, null) === 'tcp_refused');
	t('tk null inputs safe', transport_kind(null, null, null) === '');

	/* сеанс 187 G1: rkn_corroborate — точный и родительский суффикс */
	const sets = [
		{ cat: 'antifilter', entries: { 'rutracker.org': true, 'example.com': true, 'zapret.example.ru': true } },
		{ cat: 'watchlist', entries: { 'cdnnetwork.example': true } }
	];
	t('rkn exact match', rkn_corroborate('rutracker.org', sets) === 'antifilter');
	t('rkn subdomain match', rkn_corroborate('www2.rutracker.org', sets) === 'antifilter');
	t('rkn second set', rkn_corroborate('a.cdnnetwork.example', sets) === 'watchlist');
	t('rkn no match', rkn_corroborate('wikipedia.org', sets) == null);
	t('rkn empty sets', rkn_corroborate('rutracker.org', []) == null);
	t('rkn garbage host', rkn_corroborate('   ', sets) == null);
	t('rkn case folded', rkn_corroborate('RuTracker.ORG', sets) === 'antifilter');
	t('rkn leaf-first (deep ancestor)', rkn_corroborate('deep.sub.zapret.example.ru', sets) === 'antifilter');
	t('rkn null sets', rkn_corroborate('rutracker.org', null) == null);

	return { pass: length(pass), fail: length(fail), details: fail };
};
