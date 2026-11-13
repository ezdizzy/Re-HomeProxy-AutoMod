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

/* ── сеанс 195 G4: «контур как объект» — ПАМЯТЬ владельца контура ──
 * Реконструкция REPORT_s188_g4_design.md: контракт (генератор объявляет) и
 * hotswap_state (движок владеет) уже существуют, третьей проекции — ПАМЯТИ —
 * нет. Память живёт в персистентном /etc/ravnex/provider_profile.json
 * (конверт State Store); первичный объект — КОНТУР, владелец = owner.
 * Писатели: generate_client (декларации kind/uci_key/gen_sig), hotswap
 * (смены владельца), luci.ravnex hp_profile_touch (измеренные факты).
 * ЗДЕСЬ только ЧИСТАЯ логика: нормализация владельца (exit_stamp) и
 * diff-слияние (profile_apply); I/O — у писателей. Дисциплина:
 * только измеренные/объявленные факты; «не измерено» = поле отсутствует;
 * никаких credentials (address_host с @/портом/путём отбрасывается);
 * полевые `provider`-омонимы исключены (в hp_exit_lookup provider — имя
 * lookup-сервиса, здесь поле называется owner, а провайдер = owner класса
 * 'isp'). НЕ влияет на решения learn/heal — только доказуемость (G1). */

const PP_OWNER_CLASS = { node: true, engine: true, isp: true };
const PP_LABEL_CAP = 96;
const PP_ORG_CAP = 96;
const PP_ASN_CAP = 24;
const PP_HOST_CAP = 128;
const PP_SRC_CAP = 32;
const PP_SID_CAP = 64;

function pp_txt(v, cap) {
	if (v == null)
		return null;
	const s = trim('' + v);
	return length(s) ? substr(s, 0, cap) : null;
};

function pp_owner_identity(o) {
	if (o == null || type(o) !== 'object')
		return null;
	const cls = '' + (o.class || '-');
	/* ISP на коробке ОДИН (прямой контур = WAN): владелец класса 'isp'
	 * идентифицируется классом, факты (ASN/org) — обогащение того же лица,
	 * а не «смена владельца». Узловые/движковые — по sid. */
	let key = o.sid;
	if (cls !== 'node' && cls !== 'engine')
		key = '';
	return cls + '|' + (key || '');
};

function pp_owner_disp(o) {
	if (o == null || type(o) !== 'object')
		return '—';
	if (o.label && length(o.label))
		return o.label;
	if (o.org && length(o.org))
		return o.org;
	if (o.asn && length(o.asn))
		return o.asn;
	return (o.class === 'isp') ? 'ISP' : '—';
};

/* Нормализация владельца: обрезки, lc кода страны, мусор → null, капы длин,
 * address_host без credential-подобных форм (@ / порт / путь / схема).
 * Возвращает чистый объект (пустые поля отсутствуют) или null, если нечего
 * заявлять. */
export function exit_stamp(patch) {
	if (patch == null || type(patch) !== 'object')
		return null;
	const o = {};
	const cls = (type(patch.class) === 'string' && PP_OWNER_CLASS[patch.class]) ? patch.class : null;
	if (cls)
		o.class = cls;
	o.sid = pp_txt(patch.sid, PP_SID_CAP);
	o.label = pp_txt(patch.label, PP_LABEL_CAP);
	o.src = (pp_txt(patch.src, PP_SRC_CAP) != null) ? lc(pp_txt(patch.src, PP_SRC_CAP)) : null;
	o.address_host = pp_txt(patch.address_host, PP_HOST_CAP);
	if (o.address_host != null) {
		let h = lc(o.address_host);
		const sm = match(h, /^[a-z][a-z0-9+.-]*:\/\//);
		if (sm)
			h = substr(h, length(sm[0]));
		/* '@' (userinfo), ':' (порт), '/' (путь) = credential-подобная форма —
		 * честный отказ: в профиль попадает только голый сервер-хост (без
		 * схемы/порта/пути, обязательно доменная форма с точкой). */
		o.address_host = match(h, /^[a-z0-9._-]+\.[a-z0-9._-]+$/) ? h : null;
	}
	o.country = null;
	const cc = pp_txt(patch.country_code, PP_ASN_CAP);
	if (cc != null && match(cc, /^[a-zA-Z]{2}$/))
		o.country = lc(cc);
	o.asn = pp_txt(patch.asn, PP_ASN_CAP);
	if (o.asn != null) {
		/* ERE этой сборки НЕ имеет \d (урок) — только [0-9]. */
		if (match(o.asn, /^AS[0-9]+$/i)) {
			let a = '' + o.asn;
			if (lc(substr(a, 0, 2)) === 'as')
				a = substr(a, 2);
			o.asn = 'AS' + a;
		} else if (match(o.asn, /^[0-9]+$/))
			o.asn = 'AS' + o.asn;
		else
			o.asn = null;
	}
	o.org = pp_txt(patch.org, PP_ORG_CAP);
	for (let k in keys(o))
		if (o[k] == null)
			delete o[k];
	return length(keys(o)) ? o : null;
};

/* Diff-слияние факта по контуру: патч (kind/uci_key/gen_sig/owner) применяется
 * к doc.contours[tag]; битый doc разворачивается в каркас; мусорный патч —
 * честный отказ (changed=false, ничего не тронуто). Смена ВЛАДЕЛЬЦА (identity
 * class+sid/ASN) = history-ring + since_ts; обогащение тем же лицом (touch
 * страну/ASN поверх узла) = история НЕ растёт, since_ts НЕ сбрасывается;
 * флип-флап A→B→A в пределах flap_win → дедуп (ring не растёт). owner.ts
 * ставится здесь; writer-src остаётся у установившего владельца (churn
 * gen↔hotswap не дёргает записи). owner класса 'isp' зеркалится в
 * doc.provider (алиас ISP-проекции: asn/name/country/src/ts). */
export function profile_apply(doc, tag, patch, now, hist_cap) {
	const now_i = (int(now) > 0) ? int(now) : time();
	if (doc == null || type(doc) !== 'object')
		doc = {};
	if (doc.engine_version == null)
		doc.engine_version = 1;
	if (type(doc.contours) !== 'object')
		doc.contours = {};
	if (type(doc.history) !== 'array')
		doc.history = [];
	if (type(doc.provider) !== 'object')
		doc.provider = {};
	if (type(tag) !== 'string' || !length(trim(tag)) || patch == null || type(patch) !== 'object')
		return { doc: doc, changed: false };
	tag = trim(tag);
	const cap = (int(hist_cap) > 0) ? int(hist_cap) : 16;
	let ct = doc.contours[tag];
	if (type(ct) !== 'object')
		ct = { kind: null, uci_key: null, gen_sig: null, owner: null, since_ts: 0 };
	let changed = false;

	const nrm = (v) => ((v == null || !length(trim('' + v))) ? null : trim('' + v));
	/* ОТСУТСТВУЮЩИЙ ключ патча = «не трогать» (укод не различает absent и null —
	 * различаем по ключам патча); явная очистка = несуществующее поле, писатели
	 * её не шлют. */
	const pkeys = {};
	for (let k in keys(patch))
		pkeys[k] = true;
	for (let f in [ 'kind', 'uci_key', 'gen_sig' ]) {
		if (!pkeys[f])
			continue;
		const nv = nrm(patch[f]);
		const ev = (ct[f] === '') ? null : ct[f];
		if (nv !== ev) {
			ct[f] = nv;
			changed = true;
		}
	}

	const no = (type(patch.owner) === 'object') ? patch.owner : null;
	const nid = (no != null) ? pp_owner_identity(no) : null;
	const cur = ct.owner;
	const cid = (cur != null && type(cur) === 'object') ? pp_owner_identity(cur) : null;

	if (no != null && nid != null && nid !== cid) {
		/* Смена владельца (включая первую фиксацию с уже существующим
		 * другим владельцем): history + since_ts; флип-флап — дедуп. */
		const last = (length(doc.history) > 0) ? doc.history[length(doc.history) - 1] : null;
		if (cur != null && last != null &&
		    int(last.ts) > 0 && (now_i - int(last.ts)) <= 60 &&
		    last.from_id === nid && last.to_id === cid) {
			/* A→B→A в пределах 60 с: снимаем сам переход (ring не растёт). */
			pop(doc.history);
		} else if (cur != null) {
			push(doc.history, {
				ts: now_i,
				contour: tag,
				from: pp_owner_disp(cur),
				to: pp_owner_disp(no),
				from_id: cid,
				to_id: nid,
				reason: nrm(patch.reason),
				src: nrm(no.src) || nrm(cur.src) || null
			});
			if (length(doc.history) > cap)
				doc.history = slice(doc.history, length(doc.history) - cap);
		}
		ct.owner = {};
		for (let k in keys(no))
			if (no[k] != null)
				ct.owner[k] = no[k];
		ct.owner.ts = now_i;
		ct.since_ts = now_i;
		changed = true;
	} else if (no != null && nid != null && cur != null && type(cur) === 'object') {
		/* Обогащение тем же лицом: фактические поля + label (переименование —
		 * НЕ смена владельца), без src (src = кто УСТАНОВИЛ владельца). */
		let touched = false;
		for (let f in [ 'label', 'address_host', 'country', 'asn', 'org' ]) {
			const nv = no[f];
			if (nv != null && nv !== cur[f]) {
				ct.owner[f] = nv;
				touched = true;
			}
		}
		if (touched) {
			ct.owner.ts = now_i;
			changed = true;
		}
	}

	if (changed && type(ct.owner) === 'object' && ct.owner.class === 'isp') {
		/* Алиас ISP-проекции: name = org. Не трогаем чужие ключи (dpi и т.п.).
		 * NULL-факты не затираем: «не измерено» = поле отсутствует, а не ложь. */
		let pdirty = false;
		for (let f in [ 'asn', 'country' ]) {
			const nv = ct.owner[f];
			if (nv != null && doc.provider[f] !== nv) {
				doc.provider[f] = nv;
				pdirty = true;
			}
		}
		if (ct.owner.org != null && doc.provider.name !== ct.owner.org) {
			doc.provider.name = ct.owner.org;
			pdirty = true;
		}
		if (pdirty || (int(ct.owner.ts) || 0) !== (int(doc.provider.ts) || 0)) {
			doc.provider.src = ct.owner.src || doc.provider.src || null;
			doc.provider.ts = ct.owner.ts;
			pdirty = true;
		}
		changed = changed || pdirty;
	}

	doc.contours[tag] = ct;
	return { doc: doc, changed: changed };
};

function pv_like_usable(ip) {
	/* Зеркало pv_ip_usable демона: 0.0.0.0/127.* = DNS-блокер, не «живой»
	 * ответ — для вердикта «домен умер» такой ответ не считается. */
	return ip !== '0.0.0.0' && substr(ip, 0, 4) !== '127.';
};

function dns_out_answers(raw) {
	if (raw == null || !length('' + raw))
		return 0;
	const s = '' + raw;
	let n = 0;
	for (let l in split(s, '\n')) {
		const m = match(trim(l), /^Address(\s+[0-9]+)?:\s*(\S+)/);
		if (m && pv_like_usable(m[2]))
			n++;
	}
	return n;
};

export function dns_nxdomain_verdict(plain_out, public_out) {
	const p = dns_out_answers(plain_out);
	const q = dns_out_answers(public_out);
	if (p > 0 && q > 0)
		return 'answered';
	if (p === 0 && q === 0)
		return 'dead_nxdomain';
	return null;
};

/* ── сеанс 195 s-волна: DNS-здоровье выученных записей ──
 * Два чистых инструмента для движка (I/O у демона):
 *   ipv4_in_net(ip, cidr)      — принадлежность IPv4 сети вида a.b.c.d/p;
 *   dns_nxdomain_verdict(p, q) — вердикт по ДВУМ сырым выводам nslookup:
 *     оба «нет адреса» → 'dead_nxdomain' (домен умер ВСЕГДА — класс
 *     «мёртвый VPN-хост» выучивать нельзя, а выученное снимается честно),
 *     оба ответили → 'answered', расходятся → null (эпизод, ждать). */

export function ipv4_in_net(ip, cidr) {
	const i0 = trim('' + (ip == null ? '' : ip));
	const c0 = trim('' + (cidr == null ? '' : cidr));
	const im = match(i0, /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	const cm = match(c0, /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/);
	if (im == null || cm == null)
		return false;
	let mask = 32;
	if (cm[5] != null) {
		mask = int(cm[6]);
		if (mask == null || mask < 0 || mask > 32)
			return false;
	}
	for (let k = 1; k <= 4; k++) {
		const io = int(im[k]), co = int(cm[k]);
		if (io > 255 || co > 255)
			return false;
		if (mask <= 0)
			return true;
		const bits = (mask >= 8) ? 8 : mask;
		const sh = 8 - bits;
		/* Старшие биты байта сравниваются СДВИГОМ: маска ~bits в 64-битной
		 * семантике ucode затирала бы не те биты (поймано selftest'ом). */
		if ((io >> sh) !== (co >> sh))
			return false;
		mask -= bits;
	}
	return true;
};

/* ── сеанс 198 G3: QUIC-контраст (вторая лейна правды движка) ──
 * Все существующие пробы — TCP; судьба UDP/443 не измерялась вовсе
 * (automation.uc:28 «UDP NOT detectable»). probe_pool -quic-check (v1.7.0)
 * даёт UDP/443 Version-Negotiation-щуп с вердиктами vn/icmp/silence —
 * ЗДЕСЬ только чистая нормализация и таблица контраста (I/O у демона).
 * Дисциплина G1 соблюдена по построению: результат — ТОЛЬКО лейблы
 * контраста, никаких learn/heal-решений. Честность: silence ≠ блок
 * (сервер может игнорировать VN) — нота «вероятно»; ctrl='spoofed'
 * (VN-подмена провайдера на контрольной цели) перекрывает доверие к alive.
 * Влияние на порог — осознанное юзер-решение фазы 2, не этой волны. */

export function quic_norm(raw) {
	if (raw == null)
		return null;
	const s = lc(trim('' + raw));
	/* Идемпотентно: принимает И сырой вердикт щупа (vn/silence/icmp), И уже
	 * нормализованный (alive/cut/reject) — писатели передают разное. */
	if (s === 'vn' || s === 'alive')
		return 'alive';
	if (s === 'silence' || s === 'cut')
		return 'cut';
	if (s === 'icmp' || s === 'reject')
		return 'reject';
	return null;
};

/* tcp_ok: true = прямая TCP-проба прошла, false = срезан, null = не измерено.
 * quic_v: сырой вердикт щупа ('vn'/'silence'/'icmp') или null.
 * ctrl_v: вердикт контроль-пробы ISP-уровня ('vn'/'silence'/'icmp'/'spoofed').
 * Возвращает { kind, note }: kind '' = норма (поле не пишем), null = QUIC не
 * измерен (поле отсутствует — никогда не фейк-ноль). */
export function quic_contrast(tcp_ok, quic_v, ctrl_v) {
	if (tcp_ok == null || quic_v == null)
		return null;
	const q = quic_norm(quic_v);
	if (q == null)
		return null;
	const spoofed = (lc(trim('' + (ctrl_v == null ? '' : ctrl_v))) === 'spoofed');
	if (tcp_ok === true) {
		if (q === 'alive')
			return { kind: '', note: spoofed ? 'spoofed' : null };
		/* QUIC срезан/отвергнут при живом TCP: per-origin reject ничего
		 * не добавляет — QUIC-лейна уже мертва на уровне провайдера. */
		return { kind: 'quic_dead', note: null };
	}
	if (tcp_ok === false) {
		if (q === 'alive')
			return { kind: 'tcp_only_block',
				note: spoofed ? 'unverified' : 'browser_h3' };
		if (q === 'cut')
			return { kind: 'blocked_both', note: 'likely' };
		return { kind: 'blocked_both', note: 'rejected' };
	}
	return null;
};

/* ── сеанс 198 G5: флап-окна — устойчивость вердиктов ВО ВРЕМЕНИ ──
 * Окна меняют только МОМЕНТ и ЧАСТОТУ смены состояния, не критерии:
 * L1 = существующие лестницы (не трогаются), L2 = условный тормоз
 * «2 подтверждения в 10 мин» ТОЛЬКО после недавнего противоположного
 * коммита (первый learn любого хоста остаётся мгновенным/лестничным
 * как сегодня), L3 = флап-супервизор «≥3 коммит-флипа в 6 ч → честный
 * бейдж Flapping + подавление per-host событий со счётчиком». Здесь
 * ТОЛЬКО чистое ядро (I/O и события — у демона). Состояние живёт в
 * записи automation_state.json: st.flips (кольцо ≤FLIP_RING_CAP:
 * {t, dir: 'fwd'|'rev', src}), st.flapping ({since, suppressed}),
 * st.pending (кандидат-вердикт {v, n, since, last}). Emergency-путь
 * (прецедент sev='crit' бота): crit-коммиты всегда проходят — реальная
 * смерть ресурса не может зависнуть в старом вердикте; reverse всегда
 * коммитит (серия 3× — сильнейшее доказательство, зона вызывающего). */

export const FLAP_WINDOW = 21600;   /* скользящее окно подсчёта флипов (6 ч) */
export const FLAP_FLIPS = 3;        /* порог «нестабилен» */
export const FLAP_RELEASE = 86400;  /* тишина до снятия flapping (24 ч) */
export const HOLD_WINDOW = 600;     /* окно условного тормоза L2 (10 мин) */
export const HOLD_CONFIRM = 2;      /* подтверждений в окне тормоза */
export const PENDING_MAX = 900;     /* кандидат живёт ≤15 мин без свежих замеров */
export const FLIP_RING_CAP = 6;     /* кап кольца флипов */
export const DEAD_DNS_GAP = 900;    /* второй dead-замер через 15 мин (U3) */

/* Регистрация коммит-флипа: кольцо с капом; мусорные входы — честный
 * отказ (false), не краш. */
export function flip_ring(rec, dir, now, src) {
	if (rec == null || type(rec) !== 'object')
		return false;
	const d = (dir === 'fwd' || dir === 'rev') ? dir : null;
	if (d == null || !(int(now) > 0))
		return false;
	if (type(rec.flips) !== 'array')
		rec.flips = [];
	push(rec.flips, { t: int(now), dir: d,
		src: (src == null || !length(trim('' + src))) ? null : trim('' + src) });
	while (length(rec.flips) > FLIP_RING_CAP)
		shift(rec.flips);
	return true;
};

/* Флап-вердикт записи: активный эпизод держится до FLAP_RELEASE от входа
 * (старые флипы выходят из окна — кольцо капнуто — но эпизод честен, пока
 * не истекла тишина; явное снятие завершённой серией — у вызывающего) или
 * открывается по ≥FLAP_FLIPS флипов в окне. Возвращает
 * { flapping, since, n, opened?, released? }. */
export function flap_verdict(rec, now) {
	const now_i = (int(now) > 0) ? int(now) : time();
	if (rec == null || type(rec) !== 'object')
		return { flapping: false, since: 0, n: 0 };
	const flips = (type(rec.flips) === 'array') ? rec.flips : [];
	let n = 0;
	for (let f in flips)
		if (type(f) === 'object' && int(f.t) > 0 && (now_i - int(f.t)) <= FLAP_WINDOW)
			n++;
	const cur = (type(rec.flapping) === 'object' && int(rec.flapping.since || 0) > 0) ? rec.flapping : null;
	if (cur != null) {
		if ((now_i - int(cur.since)) >= FLAP_RELEASE)
			return { flapping: false, since: int(cur.since), n: n, released: true };
		return { flapping: true, since: int(cur.since), n: n };
	}
	if (n >= FLAP_FLIPS)
		return { flapping: true, since: now_i, n: n, opened: true };
	return { flapping: false, since: 0, n: n };
};

/* L2-гейт коммита: 'commit' (быстрая дорожка цела / тормоз пройден),
 * 'hold' (forward после недавнего reverse — нужны HOLD_CONFIRM замера в
 * окне, кандидат ведёт вызывающий через pending_*), 'commit_crit'
 * (emergency: INSTANT-виды и pain-override проходят всегда). Reverse —
 * всегда 'commit': решает завершённая серия вызывающего. */
export function commit_gate(rec, dir, now, crit) {
	if (dir === 'rev')
		return 'commit';
	if (crit)
		return 'commit_crit';
	if (rec == null || type(rec) !== 'object')
		return 'commit';
	const now_i = int(now);
	const flips = (type(rec.flips) === 'array') ? rec.flips : [];
	let last_rev = 0;
	for (let f in flips)
		if (type(f) === 'object' && f.dir === 'rev' && int(f.t) > last_rev)
			last_rev = int(f.t);
	if (!last_rev || (now_i - last_rev) > HOLD_WINDOW)
		return 'commit';
	const p = (type(rec.pending) === 'object' && rec.pending.v === 'blocked') ? rec.pending : null;
	if (p != null && int(p.n || 0) >= HOLD_CONFIRM)
		return 'commit';
	return 'hold';
};

/* Кандидат-вердикт: слияние замера ОДНОГО направления; противоположный
 * кандидат сбрасывает счёт; остывший (>PENDING_MAX) начинает заново.
 * Возвращает накопленное n. */
export function pending_merge(rec, v, now) {
	if (rec == null || type(rec) !== 'object' || (v !== 'blocked' && v !== 'direct'))
		return 0;
	const now_i = int(now);
	let p = (type(rec.pending) === 'object') ? rec.pending : null;
	if (p == null || p.v !== v || (now_i - int(p.last || 0)) > PENDING_MAX)
		p = { v: v, n: 0, since: now_i, last: now_i };
	p.n = int(p.n || 0) + 1;
	p.last = now_i;
	rec.pending = p;
	return int(p.n);
};

export function pending_ready(rec, need) {
	if (rec == null || type(rec) !== 'object')
		return false;
	const p = rec.pending;
	return (type(p) === 'object' && int(p.n || 0) >= ((int(need) > 0) ? int(need) : 1));
};

export function pending_clear(rec) {
	if (rec != null && type(rec) === 'object')
		delete rec.pending;
};

/* U3 (единственное место §4.7, где критерий «почти меняется»: число
 * измерений, не форма): dead-domain unlearn по ВТОРОМУ независимому
 * замеру. Первый dead → 'hold' (окно DEAD_DNS_GAP); второй по прошествии
 * окна → 'commit'. Расхождение сторон (verdict null) — 'wait' без записи
 * окна; если юзер сочтёт задержку честного unlearn ~15 мин слишком высокой,
 * пункт вырезается отдельно, остальная волна не зависит. */
export function dead_dns_gate(first_ts, now) {
	const now_i = (int(now) > 0) ? int(now) : time();
	const f = int(first_ts || 0);
	if (f <= 0)
		return 'hold';
	return ((now_i - f) >= DEAD_DNS_GAP) ? 'commit' : 'hold';
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

	/* ── сеанс 195 G4: exit_stamp — нормализация владельца контура ── */
	t('ex junk scalar', exit_stamp('x') == null && exit_stamp(42) == null);
	t('ex empty object', exit_stamp({}) == null);
	t('ex class kept', exit_stamp({ class: 'node', label: 'A' }).class === 'node');
	t('ex junk class dropped', exit_stamp({ class: 'ghost', label: 'A' }).class == null);
	t('ex cc lowercased', exit_stamp({ country_code: 'NL' }).country === 'nl');
	t('ex junk cc honest null', exit_stamp({ country_code: 'NotACode!' }) == null);
	t('ex asn bare number', exit_stamp({ asn: '123' }).asn === 'AS123');
	t('ex asn as-prefixed case', exit_stamp({ asn: 'as999' }).asn === 'AS999');
	t('ex asn junk null', exit_stamp({ asn: 'garbage' }) == null);
	t('ex host strips scheme', exit_stamp({ address_host: 'https://Srv.Example.com' }).address_host === 'srv.example.com');
	t('ex host drops scheme+port', exit_stamp({ address_host: 'https://Srv.Example.com:8443' }) == null);
	t('ex host drops credential shape', exit_stamp({ address_host: 'user@srv.example.com' }) == null);
	t('ex host drops bare port form', exit_stamp({ address_host: 'srv.example.com:8443' }) == null);
	let ex_big = '';
	for (let i = 0; i < 300; i++)
		ex_big += 'x';
	t('ex cap label', length(exit_stamp({ label: ex_big }).label) === 96);
	t('ex null fields absent', exit_stamp({ label: 'A' }).sid == null);

	/* ── сеанс 195 G4: profile_apply — diff-слияние контура ── */
	const r1 = profile_apply(null, 'main-out', { kind: 'node', uci_key: 'abc123', owner: exit_stamp({ class: 'node', sid: 'abc123', label: 'Node A', src: 'gen' }) }, 1000, null);
	t('pa scaffold + first owner', r1.changed === true && r1.doc.contours['main-out'].kind === 'node' &&
		r1.doc.engine_version === 1 && r1.doc.contours['main-out'].since_ts === 1000 &&
		r1.doc.contours['main-out'].owner.label === 'Node A');
	t('pa first owner writes no history', length(r1.doc.history) === 0);
	const r2 = profile_apply(r1.doc, 'main-out', { owner: exit_stamp({ class: 'node', sid: 'abc123', label: 'Node A', src: 'gen' }) }, 1010, null);
	t('pa same owner no write', r2.changed === false && length(r2.doc.history) === 0);
	const r3 = profile_apply(r1.doc, 'main-out', { owner: exit_stamp({ class: 'node', sid: 'abc123', label: 'Node A', src: 'gen' }), gen_sig: 'e2:manual' }, 1020, null);
	t('pa gen_sig change only', r3.changed === true && length(r3.doc.history) === 0 && r3.doc.contours['main-out'].gen_sig === 'e2:manual');
	const r4 = profile_apply(r1.doc, 'main-out', { owner: exit_stamp({ class: 'node', sid: 'zzz9', label: 'Node B', src: 'hotswap' }) }, 1100, null);
	t('pa owner change → history+since', r4.changed === true && length(r4.doc.history) === 1 &&
		r4.doc.contours['main-out'].since_ts === 1100 && r4.doc.history[0].from === 'Node A' && r4.doc.history[0].to === 'Node B');
	const r5a = profile_apply(null, 'c1', { owner: exit_stamp({ class: 'node', sid: 's1', label: 'Old', src: 'gen' }) }, 100, null);
	const r5b = profile_apply(r5a.doc, 'c1', { owner: exit_stamp({ class: 'node', sid: 's1', label: 'New' }) }, 110, null);
	t('pa label rename is enrichment, not ownership', r5b.changed === true && length(r5b.doc.history) === 0 &&
		r5b.doc.contours['c1'].owner.label === 'New' && r5b.doc.contours['c1'].owner.src === 'gen' &&
		r5b.doc.contours['c1'].since_ts === 100);
	const r6a = profile_apply(null, 'c2', { owner: exit_stamp({ class: 'node', sid: 's2', label: 'N', src: 'gen' }) }, 100, null);
	const r6b = profile_apply(r6a.doc, 'c2', { owner: exit_stamp({ class: 'node', sid: 's2', label: 'N', country_code: 'NL', asn: '60404' }) }, 110, null);
	t('pa enrichment keeps since_ts and adds facts', r6b.changed === true && r6b.doc.contours['c2'].owner.country === 'nl' &&
		r6b.doc.contours['c2'].owner.asn === 'AS60404' && r6b.doc.contours['c2'].since_ts === 100 &&
		length(r6b.doc.history) === 0);
	const r7a = profile_apply(null, 'c3', { owner: exit_stamp({ class: 'node', sid: 'sa', label: 'A' }) }, 1000, null);
	const r7b = profile_apply(r7a.doc, 'c3', { owner: exit_stamp({ class: 'node', sid: 'sb', label: 'B' }) }, 1030, null);
	const r7c = profile_apply(r7b.doc, 'c3', { owner: exit_stamp({ class: 'node', sid: 'sa', label: 'A' }) }, 1055, null);
	t('pa flip-flap dedup 60 s', r7c.changed === true && length(r7c.doc.history) === 0 &&
		r7c.doc.contours['c3'].owner.label === 'A');
	const r8a = profile_apply(null, 'c4', { owner: exit_stamp({ class: 'node', sid: 'sa', label: 'A' }) }, 1000, null);
	const r8b = profile_apply(r8a.doc, 'c4', { owner: exit_stamp({ class: 'node', sid: 'sb', label: 'B' }) }, 1030, null);
	const r8c = profile_apply(r8b.doc, 'c4', { owner: exit_stamp({ class: 'node', sid: 'sa', label: 'A' }) }, 1120, null);
	t('pa non-flap beyond 60 s keeps ring', length(r8c.doc.history) === 2);
	let r10d = null;
	for (let i = 0; i < 8; i++)
		r10d = profile_apply(r10d, 'c5', { owner: exit_stamp({ class: 'node', sid: 'n' + (i % 2), label: (i % 2) ? 'B' : 'A' }) }, 1000 + i * 100, 3).doc;
	t('pa ring cap', length(r10d.history) === 3);
	t('pa junk patch honest refusal', profile_apply(null, 'c6', 'garbage', 10, null).changed === false &&
		profile_apply(null, '', { kind: 'node' }, 10, null).changed === false);
	const r9 = profile_apply(profile_apply(null, 'main-out', { kind: 'urltest' }, 10, null).doc, 'main-udp-out', { kind: 'urltest' }, 20, null);
	t('pa foreign tag creates branch', r9.changed === true && r9.doc.contours['main-udp-out'].kind === 'urltest' &&
		r9.doc.contours['main-out'].kind === 'urltest');
	const r11 = profile_apply(null, 'direct-out', { owner: exit_stamp({ class: 'isp', asn: 'AS12389', org: 'Rostelecom', country_code: 'RU', src: 'geo_diag' }) }, 100, null);
	t('pa provider mirror from isp owner', r11.changed === true && r11.doc.provider.asn === 'AS12389' &&
		r11.doc.provider.name === 'Rostelecom' && r11.doc.provider.country === 'ru');

	/* ── сеанс 195 s-волна: DNS-здоровье (ipv4_in_net, nxdomain-вердикт) ── */
	t('net /23 covers both halves', ipv4_in_net('188.114.97.1', '188.114.96.0/23') === true);
	t('net /23 outside', ipv4_in_net('188.115.0.1', '188.114.96.0/23') === false);
	t('net /24 boundary', ipv4_in_net('188.114.96.255', '188.114.96.0/24') === true &&
		ipv4_in_net('188.114.97.1', '188.114.96.0/24') === false);
	t('net /32 exact', ipv4_in_net('80.244.44.132', '80.244.44.132/32') === true);
	t('net /32 mismatch', ipv4_in_net('80.244.44.133', '80.244.44.132/32') === false);
	t('net /0 open', ipv4_in_net('1.2.3.4', '0.0.0.0/0') === true);
	t('net junk inputs', ipv4_in_net('junk', '188.114.96.0/23') === false && ipv4_in_net('188.114.96.1', 'junk') === false);
	t('net plen junk', ipv4_in_net('188.114.96.1', '188.114.96.0/40') === false);
	t('dns both empty = dead', dns_nxdomain_verdict("** server can't find de4.hotway.linkpc.net: NXDOMAIN\n", '** server can\'t find de4.hotway.linkpc.net: NXDOMAIN\n') === 'dead_nxdomain');
	t('dns both answers = answered', dns_nxdomain_verdict('Address: 104.21.83.169\n', 'Address: 172.67.179.59\n') === 'answered');
	t('dns disagreement inconclusive', dns_nxdomain_verdict("** server can't find x: NXDOMAIN\n", 'Address: 1.2.3.4\n') == null);
	t('dns blocker-style not an answer', dns_nxdomain_verdict('Address: 0.0.0.0\n', '** server can\'t find x: NXDOMAIN\n') === 'dead_nxdomain');
	t('dns empty inputs dead', dns_nxdomain_verdict('', null) === 'dead_nxdomain');

	/* ── сеанс 198 G3: QUIC-контраст ── */
	t('qn vn alive', quic_norm('vn') === 'alive');
	t('qn silence cut', quic_norm('silence') === 'cut');
	t('qn icmp reject', quic_norm('icmp') === 'reject');
	t('qn case fold', quic_norm('VN') === 'alive');
	t('qn junk null', quic_norm('garbage') == null && quic_norm(42) == null && quic_norm(null) == null);
	t('qn idempotent alive', quic_norm('alive') === 'alive');
	t('qn idempotent cut', quic_norm('cut') === 'cut');
	t('qn idempotent reject', quic_norm('reject') === 'reject');
	t('qc ok alive norm empty', quic_contrast(true, 'vn', null).kind === '');
	t('qc ok cut dead', quic_contrast(true, 'silence', null).kind === 'quic_dead');
	t('qc ok reject dead', quic_contrast(true, 'icmp', null).kind === 'quic_dead');
	t('qc fail alive tcp_only', quic_contrast(false, 'vn', null).kind === 'tcp_only_block' &&
		quic_contrast(false, 'vn', null).note === 'browser_h3');
	t('qc fail cut blocked_both likely', quic_contrast(false, 'silence', null).kind === 'blocked_both' &&
		quic_contrast(false, 'silence', null).note === 'likely');
	t('qc fail reject blocked_both', quic_contrast(false, 'icmp', null).kind === 'blocked_both' &&
		quic_contrast(false, 'icmp', null).note === 'rejected');
	t('qc spoofed overrides alive (fail)', quic_contrast(false, 'vn', 'spoofed').kind === 'tcp_only_block' &&
		quic_contrast(false, 'vn', 'spoofed').note === 'unverified');
	t('qc spoofed ok alive noted', quic_contrast(true, 'vn', 'spoofed').kind === '' &&
		quic_contrast(true, 'vn', 'spoofed').note === 'spoofed');
	t('qc quic null honest', quic_contrast(false, null, null) == null);
	t('qc tcp null honest', quic_contrast(null, 'vn', null) == null);
	t('qc junk quic honest', quic_contrast(false, 'garbage', null) == null);

	/* ── сеанс 198 G5: флап-окна ── */
	t('fr first flip', flip_ring({}, 'fwd', 1000, 'learn') === true);
	t('fr junk dir refused', flip_ring({}, 'sideways', 1000, 'x') === false);
	t('fr junk rec refused', flip_ring(null, 'fwd', 1000, 'x') === false && flip_ring('x', 'fwd', 1000, 'x') === false);
	let fr_rec = {};
	for (let i = 0; i < 8; i++)
		flip_ring(fr_rec, (i % 2) ? 'rev' : 'fwd', 1000 + i, 's');
	t('fr ring cap 6', length(fr_rec.flips) === FLIP_RING_CAP && fr_rec.flips[0].t === 1002);
	t('fv two flips not flapping', flap_verdict({ flips: [ { t: 100, dir: 'fwd' }, { t: 200, dir: 'rev' } ] }, 300).flapping === false);
	const fv3 = flap_verdict({ flips: [ { t: 100, dir: 'fwd' }, { t: 150, dir: 'rev' }, { t: 200, dir: 'fwd' } ] }, 300);
	t('fv three flips open', fv3.flapping === true && fv3.since === 300 && fv3.opened === true && fv3.n === 3);
	const fv4 = flap_verdict({ flapping: { since: 300 }, flips: [ { t: 100, dir: 'fwd' } ] }, 22000);
	t('fv active persists below window', fv4.flapping === true && fv4.n === 0);
	const fv5 = flap_verdict({ flapping: { since: 100 }, flips: [] }, 100 + FLAP_RELEASE);
	t('fv release after 24h silence', fv5.flapping === false && fv5.released === true);
	t('fv garbage rec safe', flap_verdict(null, 1).flapping === false && flap_verdict('x', 1).flapping === false);
	t('fv flips outside window ignored', flap_verdict({ flips: [ { t: 10, dir: 'fwd' }, { t: 20, dir: 'rev' }, { t: 30, dir: 'fwd' } ] }, 100 + FLAP_WINDOW).flapping === false);
	t('cg no history commits fast', commit_gate({}, 'fwd', 1000, false) === 'commit');
	t('cg rev always commits', commit_gate({ flips: [ { t: 990, dir: 'rev' } ] }, 'rev', 1000, false) === 'commit');
	t('cg recent rev holds fwd', commit_gate({ flips: [ { t: 990, dir: 'rev' } ] }, 'fwd', 1000, false) === 'hold');
	const cg2 = { flips: [ { t: 990, dir: 'rev' } ], pending: { v: 'blocked', n: 2, since: 995, last: 999 } };
	t('cg hold satisfied by pending', commit_gate(cg2, 'fwd', 1000, false) === 'commit');
	t('cg crit bypasses hold', commit_gate({ flips: [ { t: 990, dir: 'rev' } ] }, 'fwd', 1000, true) === 'commit_crit');
	t('cg old rev outside window', commit_gate({ flips: [ { t: 300, dir: 'rev' } ] }, 'fwd', 1000, false) === 'commit');
	t('cg junk rec commits', commit_gate(null, 'fwd', 1000, false) === 'commit' && commit_gate('x', 'fwd', 1000, false) === 'commit');
	let pm_rec = {};
	t('pm merge counts', pending_merge(pm_rec, 'blocked', 1000) === 1 && pending_merge(pm_rec, 'blocked', 1010) === 2);
	t('pm opposite resets', pending_merge(pm_rec, 'direct', 1020) === 1 && pm_rec.pending.v === 'direct');
	t('pm stale restarts', pending_merge(pm_rec, 'direct', 1020 + PENDING_MAX + 5) === 1 && pm_rec.pending.since === 1020 + PENDING_MAX + 5);
	t('pr ready need=1 immediate', pending_ready({ pending: { v: 'blocked', n: 1 } }, 1) === true && pending_ready({}, 1) === false);
	t('pr need=2 gate', pending_ready({ pending: { v: 'blocked', n: 2 } }, 2) === true && pending_ready({ pending: { v: 'blocked', n: 1 } }, 2) === false);
	pending_clear(pm_rec);
	t('pc clears', pm_rec.pending == null && pending_ready(pm_rec, 1) === false);
	t('dd first hold', dead_dns_gate(0, 1000) === 'hold');
	t('dd second before gap hold', dead_dns_gate(950, 1000) === 'hold');
	t('dd second after gap commit', dead_dns_gate(100, 100 + DEAD_DNS_GAP) === 'commit');

	return { pass: length(pass), fail: length(fail), details: fail };
};
