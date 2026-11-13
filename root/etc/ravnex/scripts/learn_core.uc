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

/* ── s201: family_derive — чистая ре-деривация СЕМЕЙНОЙ НОГИ ──
 * Философия юзера (сеанс 201): сайт должен работать ЦЕЛИКОМ, как в Global;
 * жёсткие правила — только RU-зона. Члены семьи (сиблинги-домены, голые
 * CDN-IP) БЕЗ собственного вердикта следуют ноге якоря. Семья = ЧИСТАЯ
 * функция от (якоря, свежие совместные наблюдения, гварды): нет якоря /
 * нет наблюдений → нет члена. Reversible по конструкции.
 *
 * anchors — кандидаты в якоря: { host: { pain: true|false } }
 *   (якорь жив: наблюдение в ledger свежее anchor_ttl ИЛИ pain-фаза);
 * ledger — наблюдения: { host: { t_last, seen_win, clients: { ip|'': t } } };
 * cur — текущие члены: { host: { a, k, t, ls, cl, s } } (из state[h].fam);
 * quic_edges — { ip: anchor_host }: свежие QUIC-края якорей (прямое
 *   свидетельство «край обслуживает якорь», кейс flowmusic 8.47.69.0);
 * env — инъекция зависимостей (все необязательны, отсутствие = гвард пропущен):
 *   ru_dom(h), ru_ip(ip), ru_ptr(ip), never_learn(h), cdn_ip(ip),
 *   special(ip), local(ip), resolver(ip), in_lists(h), status_of(h);
 * opts — { now, anchor_ttl, sight_win, fresh_dom, fresh_ip,
 *          max_members, max_per_anchor, max_ip_per_anchor }.
 *
 * Возвращает { next, added, removed, changed, anchors_alive }:
 *   next — { host: { a: якорь, k: 'd'|'ip', t: допуск, ls: со-наблюдение,
 *                    cl: совместный клиент, s: совместных наблюдений } }. */
export function family_derive(anchors, ledger, cur, quic_edges, env, opts) {
	const o = (type(opts) === 'object') ? opts : {};
	const now = int(o.now || 0) || time();
	const anchor_ttl = int(o.anchor_ttl || 900);
	const sight_win = int(o.sight_win || 300);
	const fresh_dom = int(o.fresh_dom || 86400);
	const fresh_ip = int(o.fresh_ip || 21600);
	const cap_members = int(o.max_members || 256);
	const cap_per_anchor = int(o.max_per_anchor || 64);
	const cap_ip_per_anchor = int(o.max_ip_per_anchor || 48);
	const e = (type(env) === 'object') ? env : {};
	const fn = (k) => ((type(e[k]) === 'function') ? e[k] : null);

	const next = {};
	const added = [];
	const removed = [];
	const guard = (host) => {
		const f = fn('in_lists');
		if (f && f(host)) return false;
		const st = fn('status_of');
		if (st) {
			const s = st(host);
			if (s === 'blocked' || s === 'geo_blocked' || s === 'blocked_no_proxy')
				return false;
		}
		const rd = fn('ru_dom');
		if (rd && rd(host)) return false;
		const nl = fn('never_learn');
		if (nl && nl(host)) return false;
		/* s201: RU plain-view гвард — RU-сервис на иностранном TLD (класс
		 * sberbank-tele.com), которого нет в geo-DB, не следует в туннель:
		 * его plain A-ответ в RU-сетях = RU-зона, всегда direct (философия
		 * юзера: жёстко — только RU; последний и самый дешёвый гвард). */
		const rpl = fn('ru_plain');
		if (rpl && rpl(host)) return false;
		return true;
	};
	const guard_ip = (ip) => {
		const ru = fn('ru_ip');
		if (ru && ru(ip)) return false;
		const rp = fn('ru_ptr');
		if (rp && rp(ip)) return false;      /* s201: вторая линия RU-защиты */
		const ci = fn('cdn_ip');
		if (!ci || !ci(ip)) return false;    /* только класс CDN — дверь семьи */
		const sp = fn('special');
		if (sp && sp(ip)) return false;
		const lo = fn('local');
		if (lo && lo(ip)) return false;
		const rs = fn('resolver');
		if (rs && rs(ip)) return false;
		return true;
	};

	/* 1. Живые якоря: свежее наблюдение в окне anchor_ttl или боль. */
	const anchors_alive = {};
	const led = (type(ledger) === 'object') ? ledger : {};
	const anc = (type(anchors) === 'object') ? anchors : {};
	for (let a in anc) {
		const rd = fn('ru_dom');
		if (rd && rd(a)) continue;           /* RU никогда не якорь */
		const nl = fn('never_learn');
		if (nl && nl(a)) continue;
		const le = led[a];
		const seen_fresh = (type(le) === 'object') && ((now - int(le.t_last || 0)) <= anchor_ttl);
		const pain = (type(anc[a]) === 'object' && anc[a].pain === true);
		if (seen_fresh || pain)
			anchors_alive[a] = (type(le) === 'object') ? le : { clients: {} };
	}
	if (!length(keys(anchors_alive))) {
		const gone = [], c0 = (type(cur) === 'object') ? cur : {};
		for (let host in c0)
			if (type(c0[host]) === 'object')
				push(gone, { host: host, why: 'family died (anchor/freshness)' });
		return { next: {}, added: [], removed: gone, changed: length(gone) > 0, anchors_alive: 0 };
	}

	/* 2. Кандидаты из свежих наблюдений ledger. */
	for (let host in led) {
		const ent = led[host];
		if (type(ent) !== 'object') continue;
		if ((now - int(ent.t_last || 0)) > sight_win) continue;
		if (anchors_alive[host]) continue;           /* якорь сам себе не член */
		if (!guard(host)) continue;
		const is_ip = (match('' + host, /^\d{1,3}(\.\d{1,3}){3}$/) != null);
		if (is_ip) {
			if (!guard_ip(host)) continue;
		}
		/* Совместное наблюдение: пересечение клиентов с живым якорем.
		 * Выбираем якоря с самой свежей совместностью. */
		let best = null, best_t = -1, joint_n = 0;
		const cl = (type(ent.clients) === 'object') ? ent.clients : {};
		for (let a in anchors_alive) {
			const ac = (type(anchors_alive[a].clients) === 'object') ? anchors_alive[a].clients : {};
			let shared = null;
			for (let c in cl)
				if (ac[c] != null && c !== '') { shared = c; break; }
			if (shared != null) {
				joint_n++;
				const at = int(anchors_alive[a].t_last || 0);
				if (at > best_t) { best_t = at; best = { a: a, cl: shared }; }
			}
		}
		/* Слабый свидетель: только SNI без клиента, ≥2 наблюдений в окне. */
		let weak_only = false;
		if (best == null) {
			let only_anon = true, n = 0;
			for (let c in cl) {
				if (c !== '') only_anon = false;
				n += int(cl[c] || 0) > 0 ? 1 : 0;
			}
			weak_only = only_anon && (int(ent.seen_win || 0) >= 2 || n >= 2);
			if (weak_only) {
				/* самый свежий якорь */
				let bt = -1;
				for (let a in anchors_alive) {
					const at = int(anchors_alive[a].t_last || 0);
					if (at > bt) { bt = at; best = { a: a, cl: '' }; }
				}
			}
		}
		if (best == null) continue;
		const kind = is_ip ? 'ip' : 'd';
		next[host] = {
			a: best.a, k: kind, t: int(ent.t_last || 0), ls: int(ent.t_last || 0),
			cl: best.cl, s: (joint_n > 0) ? joint_n : int(ent.seen_win || 1)
		};
	}
	/* QUIC-края якорей — IP-члены с seen=1 (адресная проба якоря). */
	const qe = (type(quic_edges) === 'object') ? quic_edges : {};
	for (let ip in qe) {
		const a = qe[ip];
		if (!anchors_alive[a] || type(next[ip]) === 'object') continue;
		if (!guard(ip) || !guard_ip(ip)) continue;
		next[ip] = { a: a, k: 'ip', t: now, ls: now, cl: '', s: 1 };
	}

	/* 3. Свежесть существующих членов: держим, пока якорь жив и ls не истёк;
	 *    свежее совместное наблюдение продлевает (sliding). */
	const c = (type(cur) === 'object') ? cur : {};
	for (let host in c) {
		const f = c[host];
		if (type(f) !== 'object') continue;
		const fresh = (f.k === 'ip') ? fresh_ip : fresh_dom;
		const anchor_ok = (anchors_alive[f.a] == null) ? false
			: ((now - int(f.ls || 0)) <= fresh);
		if (anchor_ok) {
			if (type(next[host]) === 'object') {
				next[host].t = f.t;             /* допуск не старше исходного */
			} else {
				next[host] = { a: f.a, k: f.k, t: f.t, ls: f.ls, cl: f.cl, s: f.s };
			}
		} else if (type(next[host]) === 'object') {
			/* со-наблюдение есть, но якорь сменился — допуск обновляется сам */
		} else {
			push(removed, { host: host, why: 'family died (anchor/freshness)' });
		}
	}

	/* 4. Diff + капы. */
	for (let host in next)
		if (type(c[host]) !== 'object')
			push(added, host);
	for (let host in c) {
		if (type(c[host]) !== 'object') continue;
		if (type(next[host]) !== 'object') {
			let dup = false;
			for (let r in removed)
				if (r.host === host) { dup = true; break; }
			if (!dup)
				push(removed, { host: host, why: 'family died (anchor/freshness)' });
		}
	}
	/* Пер-якорь и IP-капы: eviction по свежести ls (старейшие уходят). */
	const per_anchor = {}, per_anchor_ip = {};
	for (let host in next) {
		const m = next[host];
		per_anchor[m.a] = (int(per_anchor[m.a] || 0) + 1);
		if (m.k === 'ip')
			per_anchor_ip[m.a] = (int(per_anchor_ip[m.a] || 0) + 1);
	}
	const evict = [];
	for (let a in per_anchor) {
		while (int(per_anchor[a]) > cap_per_anchor) {
			let oldest = null, ot = 0;
			for (let host in next) {
				if (next[host].a !== a) continue;
				if (oldest == null || int(next[host].ls) < ot) { ot = int(next[host].ls); oldest = host; }
			}
			if (oldest == null) break;
			if (type(c[oldest]) === 'object')
				push(removed, { host: oldest, why: 'family cap (per anchor)' });
			delete next[oldest];
			per_anchor[a] = int(per_anchor[a]) - 1;
			push(evict, oldest);
		}
	}
	for (let a in per_anchor_ip) {
		while (int(per_anchor_ip[a]) > cap_ip_per_anchor) {
			let oldest = null, ot = 0;
			for (let host in next) {
				if (next[host].a !== a || next[host].k !== 'ip') continue;
				if (oldest == null || int(next[host].ls) < ot) { ot = int(next[host].ls); oldest = host; }
			}
			if (oldest == null) break;
			if (type(c[oldest]) === 'object')
				push(removed, { host: oldest, why: 'family cap (ip/anchor)' });
			delete next[oldest];
			per_anchor_ip[a] = int(per_anchor_ip[a]) - 1;
		}
	}
	while (length(keys(next)) > cap_members) {
		let oldest = null, ot = 0;
		for (let host in next) {
			if (oldest == null || int(next[host].ls) < ot) { ot = int(next[host].ls); oldest = host; }
		}
		if (oldest == null) break;
		if (type(c[oldest]) === 'object')
			push(removed, { host: oldest, why: 'family cap (total)' });
		delete next[oldest];
	}
	/* Эвиктированные новые кандидаты — не «added». */
	const added2 = [];
	for (let i = 0; i < length(added); i++)
		if (type(next[added[i]]) === 'object')
			push(added2, added[i]);
	for (let i = 0; i < length(evict); i++) {
		for (let j = 0; j < length(added2); j++) {
			if (added2[j] === evict[i]) { added2[j] = ''; break; }
		}
	}
	const added3 = filter(added2, (x) => length(x));
	const changed = (length(added3) > 0) || (length(removed) > 0);
	return { next: next, added: added3, removed: removed, changed: changed, anchors_alive: length(keys(anchors_alive)) };
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

	/* ── s201: family_derive — семейная нога ── */
	const fenv = {
		ru_dom: (h) => (h === 'sberbank.example' || match(h, /\.(ru|su)$/)),
		ru_ip: (ip) => (ip === '95.161.1.1'),
		ru_ptr: (ip) => (ip === '89.250.12.19'),
		never_learn: (h) => (h === 'cloudflare-dns.com' || h === '0.pool.ntp.org'),
		cdn_ip: (ip) => (match(ip, /^3\./) != null || ip === '8.47.69.0'),
		special: (ip) => (ip === '100.64.1.1'),
		local: (ip) => (ip === '192.168.1.1'),
		resolver: (ip) => (ip === '8.8.8.8'),
		in_lists: (h) => (h === 'listed.example' || h === 'excluded.example'),
		status_of: (h) => (h === 'blockedhost.example' ? 'blocked' :
			(h === 'bnphost.example' ? 'blocked_no_proxy' :
			(h === 'directhost.example' ? 'direct' : null)))
	};
	const fopts = { now: 1000000, anchor_ttl: 900, sight_win: 300, fresh_dom: 86400, fresh_ip: 21600,
		max_members: 256, max_per_anchor: 64, max_ip_per_anchor: 48 };
	const anchor_live = { 'site.example': { pain: false } };
	const led_live = {
		'site.example':        { t_last: 999990, seen_win: 3, clients: { '192.168.1.50': 999990 } },
		'sib.myspacecdn.example': { t_last: 999980, seen_win: 2, clients: { '192.168.1.50': 999980 } },
		'other.example':       { t_last: 999970, seen_win: 1, clients: { '192.168.1.77': 999970 } },
		'anon-sniff.example':  { t_last: 999960, seen_win: 1, clients: { '': 999960 } },
		'anon-sniff2.example': { t_last: 999955, seen_win: 2, clients: { '': 999955 } },
		'ru-sib.example.ru':   { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'cloudflare-dns.com':  { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'listed.example':      { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'blockedhost.example': { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'bnphost.example':     { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'directhost.example':  { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'3.33.252.61':         { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'93.184.216.34':       { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'95.161.1.1':          { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'89.250.12.19':        { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'8.8.8.8':             { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } }
	};
	const fr1 = family_derive(anchor_live, led_live, {}, {}, fenv, fopts);
	t('fam sibling same client joins', type(fr1.next['sib.myspacecdn.example']) === 'object' &&
		fr1.next['sib.myspacecdn.example'].a === 'site.example' && fr1.next['sib.myspacecdn.example'].k === 'd');
	t('fam foreign client no join', fr1.next['other.example'] == null);
	t('fam weak 1 sighting no join', fr1.next['anon-sniff.example'] == null);
	t('fam weak 2 sightings joins', fr1.next['anon-sniff2.example'] != null);
	t('fam ru sibling never joins', fr1.next['ru-sib.example.ru'] == null);
	t('fam never-learn no join', fr1.next['cloudflare-dns.com'] == null);
	t('fam listed/excluded no join', fr1.next['listed.example'] == null);
	t('fam blocked-verdict no join', fr1.next['blockedhost.example'] == null && fr1.next['bnphost.example'] == null);
	t('fam direct-verdict CAN join', type(fr1.next['directhost.example']) === 'object');
	t('fam cdn ip joins as ip', type(fr1.next['3.33.252.61']) === 'object' && fr1.next['3.33.252.61'].k === 'ip');
	t('fam non-cdn ip no join', fr1.next['93.184.216.34'] == null);
	t('fam ru ip no join', fr1.next['95.161.1.1'] == null);
	t('fam ru-ptr ip no join', fr1.next['89.250.12.19'] == null);
	t('fam resolver ip no join', fr1.next['8.8.8.8'] == null);
	/* s201: RU plain-view гвард — RU-сервис на чужом TLD (geo-DB gap) не член */
	const fenv_rp = { ru_dom: fenv.ru_dom, ru_ip: fenv.ru_ip, never_learn: fenv.never_learn,
		cdn_ip: fenv.cdn_ip, in_lists: fenv.in_lists, status_of: fenv.status_of,
		ru_plain: (h) => (h === 'sbt.example') };
	const led_rp = {
		'site.example': { t_last: 999990, seen_win: 2, clients: { '192.168.1.50': 999990 } },
		'sbt.example':  { t_last: 999985, seen_win: 2, clients: { '192.168.1.50': 999985 } }
	};
	const fr10 = family_derive(anchor_live, led_rp, {}, {}, fenv_rp, fopts);
	t('fam ru-plain service never joins', fr10.next['sbt.example'] == null);
	t('fam anchor not its own member', fr1.next['site.example'] == null);
	t('fam anchors_alive counted', fr1.anchors_alive === 1);
	/* QUIC-край якоря — IP-член с seen=1 (кейс flowmusic 8.47.69.0) */
	const fr2 = family_derive(anchor_live, led_live, {}, { '8.47.69.0': 'site.example' }, fenv, fopts);
	t('fam quic edge joins seen=1', type(fr2.next['8.47.69.0']) === 'object' &&
		fr2.next['8.47.69.0'].s === 1 && fr2.next['8.47.69.0'].k === 'ip');
	/* Смерть якоря гасит семью */
	const cur1 = { 'sib.myspacecdn.example': { a: 'site.example', k: 'd', t: 999980, ls: 999980, cl: '192.168.1.50', s: 1 } };
	const fr3 = family_derive({}, led_live, cur1, {}, fenv, fopts);
	t('fam anchor death clears', fr3.next == null || length(keys(fr3.next)) === 0);
	t('fam anchor death reports removal', fr3.changed === true && length(fr3.removed) === 1 &&
		fr3.removed[0].host === 'sib.myspacecdn.example');
	/* Свежесть: sliding продлевает, истечение удаляет */
	const cur_old = { 'sib.myspacecdn.example': { a: 'site.example', k: 'd', t: 990000, ls: 990000, cl: '192.168.1.50', s: 1 } };
	const fr4 = family_derive(anchor_live, led_live, cur_old, {}, fenv, fopts);
	t('fam sliding refresh keeps member', type(fr4.next['sib.myspacecdn.example']) === 'object' &&
		int(fr4.next['sib.myspacecdn.example'].ls) === 999980);
	const cur_stale = { 'sib.myspacecdn.example': { a: 'site.example', k: 'd', t: 900000, ls: 900000, cl: '192.168.1.50', s: 1 } };
	const fopts_cold = { now: 1000000, anchor_ttl: 900, sight_win: 300, fresh_dom: 86400, fresh_ip: 21600,
		max_members: 256, max_per_anchor: 64, max_ip_per_anchor: 48 };
	const led_cold = { 'site.example': { t_last: 999990, seen_win: 1, clients: { '192.168.1.50': 999990 } } };
	const fr5 = family_derive(anchor_live, led_cold, cur_stale, {}, fenv, fopts_cold);
	t('fam stale member dropped (no co-observation)', fr5.next['sib.myspacecdn.example'] == null &&
		length(fr5.removed) === 1);
	/* Идемпотентность: повторный прогон с cur=next не меняет */
	const cur2 = {};
	for (let h in fr1.next)
		cur2[h] = { a: fr1.next[h].a, k: fr1.next[h].k, t: fr1.next[h].t, ls: fr1.next[h].ls, cl: fr1.next[h].cl, s: fr1.next[h].s };
	const fr6 = family_derive(anchor_live, led_live, cur2, {}, fenv, fopts);
	t('fam idempotent rerun', fr6.changed === false && length(fr6.added) === 0 && length(fr6.removed) === 0);
	/* Пер-якорь кап: старейший вылетает */
	const fopts_cap = { now: 1000000, anchor_ttl: 900, sight_win: 300, fresh_dom: 86400, fresh_ip: 21600,
		max_members: 256, max_per_anchor: 2, max_ip_per_anchor: 48 };
	const led_cap = {
		'site.example': { t_last: 999990, seen_win: 1, clients: { '192.168.1.50': 999990 } },
		'cap1.example': { t_last: 999900, seen_win: 2, clients: { '192.168.1.50': 999900 } },
		'cap2.example': { t_last: 999950, seen_win: 2, clients: { '192.168.1.50': 999950 } },
		'cap3.example': { t_last: 999980, seen_win: 2, clients: { '192.168.1.50': 999980 } }
	};
	const fr7 = family_derive(anchor_live, led_cap, {}, {}, fenv, fopts_cap);
	t('fam per-anchor cap evicts oldest', fr7.next['cap1.example'] == null &&
		type(fr7.next['cap2.example']) === 'object' && type(fr7.next['cap3.example']) === 'object');
	/* RU-якорь невозможен */
	const fr8 = family_derive({ 'ru-site.example.ru': { pain: true } }, led_live, {}, {}, fenv, fopts);
	t('fam ru anchor never alive', fr8.anchors_alive === 0 && length(fr8.removed) === 0 && fr8.changed === false);
	/* pain-якорь без ledger-наблюдений жив */
	const fr9 = family_derive({ 'pain.example': { pain: true } }, {}, {}, {}, fenv, fopts);
	t('fam pain anchor alive', fr9.anchors_alive === 1);

	return { pass: length(pass), fail: length(fail), details: fail };
};
