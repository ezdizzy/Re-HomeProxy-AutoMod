#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023-2025 ImmortalWrt.org
 */

'use strict';

import { access, popen, readfile, writefile } from 'fs';
import { isnan } from 'math';
import { connect } from 'ubus';
import { cursor } from 'uci';

import {
	isEmpty, parseURL, strToBool, strToInt, strToTime,
	removeBlankAttrs, validation, HP_DIR, RUN_DIR,
	sync_learned_rulesets, sync_manual_direct_ruleset, sync_ru_geo_rulesets,
	sync_oauth_ruleset, sync_auto_auth_ruleset, sync_family_rulesets, sync_user_list, classify_entry
} from 'homeproxy';

/* Process Manager (Ф1.4b): ownership-grade mosdns liveness — a bare pidof
 * accepted a FOREIGN mosdns as "running" and pointed every resolver at a
 * listener that was never ours (audit 11). */
import {
	find_daemons as pm_find, reg_get as pm_reg_get, entry_alive as pm_entry_alive
} from '/etc/ravnex/scripts/pmgr.uc';
/* сеанс 187: деривация негативного стиринга (steer_pools + суффикс текущего
 * стрима) — тот же модуль, что и у фидера, с селфтест-гейтом; 188: +
 * pool_keyword_from_suffix (слияние выученных зомби-пулов). */
import {
	steer_pools, current_suffix_from_host, pool_keyword_from_suffix
} from '/etc/ravnex/scripts/yt_steer.uc';

/* State Store (Ф1.7, аудит 10): state-файлы генератора — через канонический
 * атомарный механизм + версионированный конверт (schema_version/config_revision). */
import { write_state as ss_write_state, read_state as ss_read_state } from '/etc/ravnex/scripts/statestore.uc';
/* G4 (REPORT_s188_g4_design.md): декларации контуров в память владельца —
 * learn_core листовой (без импортов), циклов нет. I/O профиля — здесь. */
import { exit_stamp, profile_apply } from '/etc/ravnex/scripts/learn_core.uc';

/* Lists conveyor (seance 178): the source catalog is the ONE authority for
 * rule-set URLs — the generator reads catalog accessors and never hardcodes
 * an upstream URL. The accessors return the hub-primary (ezdizzy/ravnex-lists)
 * when the hub delivers the category; upstream URLs stay in the catalog as
 * the conveyor's fallback ladder. */
import {
	catalog_url as ls_catalog_url, catalog_ip_url as ls_catalog_ip_url,
	catalog_pair as ls_catalog_pair, catalog_find as ls_catalog_find
} from '/etc/ravnex/scripts/rulesets_catalog.uc';

const ubus = connect();

/* Lesson 355: a REMOTE service rule-set can silently die when the upstream
 * release asset goes stale (google_ai.srs shipped with ZERO gemini domains —
 * verified live 2026-11-07: 375 bytes, no gemini/aistudio strings; the rule
 * matched nothing, Gemini rode the direct path with the real IP, and the
 * service check stayed green because it probed the main exit only). Sources
 * with a SHIPPED local list (resources/rule_<src>.txt) become an INLINE
 * domain_suffix rule — no rule-set binary needed, identical on every core
 * dialect, and the route trace can prove the match locally. Missing/empty
 * list -> null: the remote .srs path stays the honest fallback.
 * 🔴 Top-level (lesson 93/126: no hoisting — the DNS and route scopes are
 * different blocks, a nested declaration is invisible to the route loop). */
function hp_service_inline_domains(src) {
	const f = HP_DIR + '/resources/rule_' + src + '.txt';
	let raw = null;
	if (access(f)) {
		try { raw = readfile(f); } catch (e) { raw = null; }
	}
	if (raw == null || type(raw) !== 'string')
		return null;
	const out = [];
	for (let l in split('' + raw, /[\r\n]/)) {
		l = trim(l);
		if (length(l) && substr(l, 0, 1) !== '#')
			push(out, lc(l));
	}
	return length(out) ? out : null;
}

/* Сеанс 184: категория может ПРЕДПОЧИТАТЬ обновляемый remote-рулесет хаба,
 * даже когда shipped-список жив (флаг inline_pref:false в каталоге).
 * Хаб-CI валидирует каждый ассет (непустота, SRS-магия, sha256 в манифесте) —
 * класс отказа lesson 355 («мёртвый апстрим прислал пустой .srs») для
 * хаб-пути закрыт. Shipped-список остаётся честным откатом: вернуть
 * inline_pref true — инлайн-рендер вернётся без прочих правок. */
function hp_remote_preferred(src) {
	const ce = ls_catalog_find(src);
	return (ce != null && ce.inline_pref === false);
}

/* const features = ubus.call('luci.ravnex', 'singbox_get_features') || {}; */

/* UCI config start */
const uci = cursor();

const uciconfig = 'ravnex';
uci.load(uciconfig);

const uciinfra = 'infra',
      ucimain = 'config',
      ucicontrol = 'control';

const uciroutingnode = 'routing_node',
      uciroutingrule = 'routing_rule';

const ucinode = 'node';
const uciruleset = 'ruleset';
const uciserver = 'server';
const ucirurule = 'proxy_ru_rule';

/* Ф3.1 (D14/D23): THREE routing modes —
 *   proxy_banned_ru  «Обход блокировок» — the WORKING mode: bypass engines + routing
 *                    rules; the itdoginfo/refilter lists are its built-in preset;
 *   direct           «Напрямую» — ALL bypass mechanisms are OFF (the service runs the
 *                    app plane only); the core is not started, generation is skipped;
 *   global           «Всё через узел» — ALL traffic goes through the selected main node.
 * Custom routing / Custom JSON are RETIRED (D23): a legacy value still present in an
 * old UCI is read honestly as the working mode (with a warn); the migrator
 * migrate_routing_mode.uc rewrites it with a snapshot at the next service start
 * (Ф3.4). */
const routing_mode_raw = uci.get(uciconfig, ucimain, 'routing_mode');
let routing_mode = (routing_mode_raw == null || routing_mode_raw === '')
	? 'proxy_banned_ru' : '' + routing_mode_raw;
if (routing_mode === 'custom' || routing_mode === 'custom_json') {
	warn('homeproxy: routing mode "' + routing_mode + '" is retired (D23) - generating the working-mode config; the migrator rewrites it at the next service start.\n');
	routing_mode = 'proxy_banned_ru';
}
if (routing_mode === 'direct') {
	warn('homeproxy: direct mode («Напрямую») - all bypass mechanisms are OFF; the core is not started and config generation is skipped.\n');
	exit(0);
}

/* Selective routing is ONE engine; the region is data.
 *   forward (blocklist): default direct, lists -> proxy.            proxy_banned_ru (RU)
 *   reverse (bypass):    default proxy, region -> direct, overrides. bypass_cn / bypass_ir
 * Adding a country = one REGION row + a routing_mode value + a client.js entry. */
const REGION = {
	cn: {
		geosite:     'https://fastly.jsdelivr.net/gh/1715173329/sing-geosite@rule-set-unstable/geosite-geolocation-cn.srs',
		geoip:       'https://fastly.jsdelivr.net/gh/1715173329/IPCIDR-CHINA@rule-set/cn.srs',
		geosite_non: 'https://fastly.jsdelivr.net/gh/1715173329/sing-geosite@rule-set-unstable/geosite-geolocation-!cn.srs',
		local_dns:   { type: 'udp', server: '223.5.5.5' },	/* AliDNS */
		guard:       true					/* geoip fallback + !cn guard (China list is non-exhaustive) */
	},
	ir: {
		geosite:     'https://fastly.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs',
		geoip:       'https://fastly.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geoip-ir.srs',
		geosite_non: null,
		local_dns:   { type: 'udp', server: '178.22.122.100' },	/* Shecan (default; overridable via iran_dns_server) — stable public IPs, not ISP-delegated */
		guard:       false					/* Iran configs use the simple scheme, no geoip fallback */
	}
};
const MODE_REGION = { bypass_cn: 'cn', bypass_ir: 'ir' };
function is_bypass_mode(m) { return m in ['bypass_cn', 'bypass_ir']; }
function is_selective_mode(m) { return m === 'proxy_banned_ru' || is_bypass_mode(m); }
function region_of(m) { return MODE_REGION[m]; }

let wan_dns = ubus.call('network.interface', 'status', {'interface': 'wan'})?.['dns-server']?.[0];
if (!wan_dns)
	wan_dns = '8.8.8.8';	/* ultimate fallback for the remote/bootstrap resolver; region-local DNS comes from REGION */

const dns_port = uci.get(uciconfig, uciinfra, 'dns_port') || '5333';

const ntp_server = uci.get(uciconfig, uciinfra, 'ntp_server') || 'time.apple.com';

/* Detect active core. Must match the core init.d actually runs, or the generated dialect
 * won't fit it. Mirror init.d's precedence: honor preferred_core when that core is
 * installed, otherwise auto-pick (hiddify-core first, then sing-box).
 * Falls back to a UCI custom path when neither standard binary is present. */
const preferred_core = uci.get(uciconfig, ucimain, 'preferred_core') || 'auto';
const have_hiddify = !!access('/usr/bin/hiddify-core');
const have_singbox = !!access('/usr/bin/sing-box');

let is_hiddify = false, is_singbox = false;
if (preferred_core === 'hiddify' && have_hiddify)
	is_hiddify = true;
else if (preferred_core === 'singbox' && have_singbox)
	is_singbox = true;
else if (have_hiddify)
	is_hiddify = true;
else if (have_singbox)
	is_singbox = true;
else {
	const custom_path = uci.get(uciconfig, ucimain, 'custom_core_path');
	const custom_type = uci.get(uciconfig, ucimain, 'custom_core_type');
	if (custom_path && access(custom_path)) {
		is_hiddify = custom_type === 'hiddify';
		is_singbox = !is_hiddify;
	}
}

/* sing-box-family cores (sing-box-extended) speak the sing-box config dialect
 * (snake_case fields); hiddify-core speaks the HiddifyCli dialect. Dialect-
 * sensitive emission below keys off the flags above. */

const ipv6_support = uci.get(uciconfig, ucimain, 'ipv6_support') || '0';

/* ── Per-core outbound capability (Preferred core support) ─────────────────
 * The two supported cores are different BUILDS: a node type the selected core
 * does not compile is a hard FATAL at config load ("naive outbound is not
 * included in this build") that crash-loops the whole service — picking
 * sing-box-extended with a NaïveProxy node in the pool used to leave the
 * service dead ("core does not start"). Generation is therefore
 * capability-aware:
 *   1. a static map type → required build tag, resolved from the selected
 *      binary's own `version` output (both cores print a Tags line);
 *   2. a runtime check-heal: for sing-box (has `check`; hiddify-core has no
 *      such subcommand) the generated config is validated right after the
 *      write — if the core still rejects an outbound/endpoint type, that type
 *      is recorded in $RUN_DIR/core_extra_skip_<core>.json (keyed by the core
 *      version, so a core update re-tests it) and generation re-runs without
 *      it, bounded by the number of distinct types.
 * Skipped nodes degrade gracefully: they drop out of pools/geo/routing, a
 * skipped main node falls back to the URLTest pool (or direct), and the skip
 * list is exposed to the UI via $RUN_DIR/core_skipped.json.
 * Verified empirically (device, 2026-09-17) on hiddify-core 4.1.0
 * (hiddify sing-box dialect 1.13.1) and sing-box-extended 1.14.0-extended-2.7.1:
 * the extended build ships WITHOUT with_naive_outbound (NaïveProxy dropped);
 * everything else this app can configure — vless / vmess / trojan /
 * shadowsocks / shadowtls / socks / http / ssh / hysteria(2) / tuic / anytls /
 * mieru / wireguard / amneziawg (nested `amnezia` options) — is present on
 * both. */
function hp_shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function hp_core_info() {
	/* {path, version, tags:{}} for the core this config targets. */
	let path = null;
	if (is_hiddify)
		path = '/usr/bin/hiddify-core';
	else if (is_singbox)
		path = '/usr/bin/sing-box';
	else {
		path = uci.get(uciconfig, ucimain, 'custom_core_path');
		if (!(path && access(path)))
			return null;
	}
	/* The lite COMPRESSED sing-box build (sing-box-extended-lite, issue #4)
	 * puts a tiny sh wrapper (<10 KB) at /usr/bin/sing-box that answers
	 * `version` from a first-line cache — no Tags line — and execs the real
	 * binary for everything else. Probe /usr/libexec/sing-box-core for the
	 * REAL tags, else the tag map would come back empty and every tagged
	 * node type (quic/wireguard/…) would be skipped although the core runs
	 * them. `path` stays the wrapper: `sing-box check` works through it. */
	let probe = path;
	if (path === '/usr/bin/sing-box') {
		/* 2>/dev/null first: a missing binary must fail silently. */
		const szf = popen('wc -c 2>/dev/null < /usr/bin/sing-box');
		const sz = szf ? int(trim(szf.read('all'))) : 0;
		if (szf) szf.close();
		if (sz > 0 && sz < 10000 && access('/usr/libexec/sing-box-core'))
			probe = '/usr/libexec/sing-box-core';
	}
	const fd = popen(hp_shellquote(probe) + ' version 2>/dev/null');
	if (!fd)
		return { path: path, version: null, tags: {} };
	const out = fd.read('all'); fd.close();
	const vm = match(out, / version v?([0-9][0-9a-zA-Z._-]*)/);
	const tm = match(out, /\nTags: ([^\n]+)/);
	let tags = {};
	if (tm)
		for (let t in split(tm[1], ','))
			tags[trim(t)] = true;
	return { path: path, version: vm ? vm[1] : null, tags: tags };
}

const hp_core = hp_core_info();

/* ч.129 (ан-146): upstream hiddify-core ≥5 (sing-box 1.15) отвергает legacy
 * поле `download_detour` у rule_set — «legacy download_detour is deprecated,
 * FATAL to continuing using this feature» (проверено на устройстве, v5.1.0).
 * Новый диалект — переопределение `http_client.detour` на самом rule_set.
 * Гейт по мажорной версии целевого ядра: hiddify ≥5 → http_client; всё
 * остальное (старые сборки семейства hiddify / sing-box-extended 1.14 /
 * custom) →
 * download_detour. Отдельная глобальная секция http_client не нужна:
 * частичный объект с одним detour валиден сам по себе (остальные поля —
 * дефолты). */
const hp_ver_major = (hp_core.version && type(hp_core.version) == 'string')
	? int(split(hp_core.version, '.')[0]) : 0;
const hp_rule_http_client = is_hiddify && hp_ver_major >= 5;
const hp_rs_dl = (detour) => hp_rule_http_client
	? { http_client: { detour: detour } }
	: { download_detour: detour };

/* A node type may only be emitted when the running build provides its tag. */
const HP_TYPE_REQ_TAG = {
	naive: 'with_naive_outbound',
	hysteria: 'with_quic',
	hysteria2: 'with_quic',
	tuic: 'with_quic',
	wireguard: 'with_wireguard',
	amneziawg: 'with_wireguard',
	trusttunnel: 'with_trusttunnel'
};

/* WireGuard/AmneziaWG network stack (GitHub issue #3): the userspace gVisor
 * stack is only available when the selected binary actually carries the
 * with_gvisor tag — lite sing-box builds omit it and the endpoint dies with
 * "gVisor is not included" even though the kernel module works. When the
 * binary cannot be probed at all (custom core, no version output) the
 * historical always-gvisor behavior is kept. */
const hp_wg_gvisor = !hp_core || ('with_gvisor' in hp_core.tags);

/* Runtime-learned rejections (check-heal), keyed per core version so a core
 * update re-tests types rejected by an older build. */
const hp_core_id = is_hiddify ? 'hiddify' : is_singbox ? 'singbox' : 'custom';
const hp_extra_skip_file = RUN_DIR + '/core_extra_skip_' + hp_core_id + '.json';
let hp_extra_skip = {};
let hp_extra_skip_stale = false;
try {
	const raw = readfile(hp_extra_skip_file);
	if (raw) {
		const st = json(raw);
		if (type(st) === 'object' && type(st.types) === 'array' &&
		    st.version != null && st.version === (hp_core ? hp_core.version : null))
			for (let t in st.types)
				hp_extra_skip[t] = true;
		else
			hp_extra_skip_stale = true;
	}
} catch (e) { hp_extra_skip = {}; }

function hp_core_supports_type(t) {
	if (!hp_core)
		return true;
	const req = HP_TYPE_REQ_TAG[t];
	if (req && !(req in hp_core.tags))
		return false;
	if (t in hp_extra_skip)
		return false;
	return true;
}

/* Nodes the selected core cannot load — collected for the UI state file. */
const hp_skipped_nodes = {};
function hp_node_usable(sid) {
	const t = uci.get(uciconfig, sid, 'type');
	if (t == null)
		return false;    /* dangling reference — existing guards handle it */
	if (hp_core_supports_type(t))
		return true;
	if (!(sid in hp_skipped_nodes))
		hp_skipped_nodes[sid] = { sid: sid, type: t, label: uci.get(uciconfig, sid, 'label') || sid };
	return false;
}

/* foreach over proxy node sections the SELECTED CORE can actually load. */
function foreach_node(cb) {
	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (hp_node_usable(cfg['.name']))
			cb(cfg);
	});
}

/* Filter a sid list to existing AND core-supported nodes. */
function usable_nodes(list) {
	return filter(list || [], (k) => (uci.get_all(uciconfig, k) != null) && hp_node_usable(k));
}

const byedpi_enabled = uci.get(uciconfig, ucimain, 'byedpi_enabled');
/* zapret: a `direct` outbound stamped with routing_mark; nft catches the mark and
 * sends the handshake to NFQUEUE where nfqws desyncs it. Separate from byedpi. */
const zapret_enabled = uci.get(uciconfig, ucimain, 'zapret_enabled');
const zapret_mark = uci.get(uciconfig, ucimain, 'zapret_mark') || '110';
/* Opt-in: route call/voice UDP ports (50000-65530) to zapret-out instead of the proxy.
 * Only honored when zapret_enabled === '1' (zapret-out exists). */
const zapret_voice = uci.get(uciconfig, ucimain, 'zapret_voice') || '0';
/* Automation (auto blocked-site detection): when enabled we expose two loopback test
 * inbounds (forced direct / forced main) and merge the learned list into proxy_domain_list. */
const automation_enabled = uci.get(uciconfig, 'automation', 'enabled');

/* Exit Engine (Ф9.16, D35a): ОДИН движок владеет выходом — три режима (auto/prefer/
 * manual) поверх main_node + сквозной резерв-список. См. LOCAL_DOCS/REFACTOR/
 * 21-EXIT_ENGINE_DESIGN.md. Легаси-опции (hotswap_*, main_urltest_mode/nodes/preferred)
 * читаются как фолбэк — неконфигурация без миграции ведёт себя как раньше; миграцию
 * делает migrate_config.uc. Демон (scripts/hotswap.uc) владеет селектором; генератор
 * строит пулы + пишет контракт exit_engine.json (и легаси-зеркало hotswap.json). */
const exit_mode_raw = uci.get(uciconfig, ucimain, 'exit_mode');
const legacy_ut_mode = uci.get(uciconfig, ucimain, 'main_urltest_mode') || 'manual';
const exit_mode_opt = (exit_mode_raw in ['auto', 'prefer', 'manual']) ? exit_mode_raw : legacy_ut_mode;
const exit_preferred_raw = uci.get(uciconfig, ucimain, 'exit_preferred');
const exit_preferred_opt = !isEmpty(exit_preferred_raw) ? exit_preferred_raw : uci.get(uciconfig, ucimain, 'main_urltest_preferred');
const exit_probe_interval_opt = int(uci.get(uciconfig, ucimain, 'exit_probe_interval') || uci.get(uciconfig, ucimain, 'hotswap_interval') || '10') || 10;
const exit_tolerance_raw = uci.get(uciconfig, ucimain, 'exit_tolerance');
const exit_tolerance_opt = !isEmpty(exit_tolerance_raw) ? exit_tolerance_raw : uci.get(uciconfig, ucimain, 'main_urltest_tolerance');
const exit_failback_opt = (uci.get(uciconfig, ucimain, 'exit_failback') || uci.get(uciconfig, ucimain, 'hotswap_failback') || '1') !== '0';
const exit_upgrade_opt = (uci.get(uciconfig, ucimain, 'exit_upgrade') === '1');
const exit_dead_after_opt = int(uci.get(uciconfig, ucimain, 'exit_dead_after') || '2') || 2;
const exit_recovery_oks_opt = int(uci.get(uciconfig, ucimain, 'exit_recovery_oks') || '3') || 3;
const exit_recovery_window_opt = int(uci.get(uciconfig, ucimain, 'exit_recovery_window') || '30') || 30;
const exit_hysteresis_opt = int(uci.get(uciconfig, ucimain, 'exit_hysteresis') || '3') || 3;
const exit_udp_preferred_raw = uci.get(uciconfig, ucimain, 'exit_udp_preferred');
const exit_udp_preferred_opt = !isEmpty(exit_udp_preferred_raw) ? exit_udp_preferred_raw : exit_preferred_opt;
/* Резерв-список: hotswap_nodes (приоритет пользователя) + main_urltest_nodes только
 * в легаси-manual (там это был пул ручного режима — данные не терять, D35a). */
let exit_reserves = [];
for (let hs_sid in (uci.get(uciconfig, ucimain, 'hotswap_nodes') || []))
	if (index(exit_reserves, hs_sid) < 0)
		push(exit_reserves, hs_sid);
if (legacy_ut_mode === 'manual')
	for (let hs_sid in (uci.get(uciconfig, ucimain, 'main_urltest_nodes') || []))
		if (index(exit_reserves, hs_sid) < 0)
			push(exit_reserves, hs_sid);
/* Kernel-композиция групп (единая для main/UDP): prefer — только с живым
 * preferred (структура [preferred, alt] держит preferred на уровне ядра);
 * manual — пул юзера (резервы: «фейловер строго по списку», дизайн §3.2 +
 * GitHub issue #18 — 170-узловая подписка на слабом боксе = fd-взрыв от
 * URL-проб всех узлов; пустой список → весь пул, fallback build_urltest);
 * иначе auto (все узлы — kernel-страховка, политика у движка). */
const exit_pref_usable = !isEmpty(exit_preferred_opt) &&
	uci.get_all(uciconfig, exit_preferred_opt) != null && hp_node_usable(exit_preferred_opt);
const exit_kernel_mode = (exit_mode_opt === 'prefer' && exit_pref_usable) ? 'prefer'
	: ((exit_mode_opt === 'manual') ? 'manual' : 'auto');

/* OAuth stability (ч.59): auth-provider hosts ride the SAME exit as the services that
 * use them (main-out) instead of the RU-geo "always direct" split, QUIC/SVCB escapes
 * are closed, and resolution goes through the encrypted pool. See LOCAL_DOCS/08. */
const oauth_stability_opt = (uci.get(uciconfig, ucimain, 'oauth_stability') !== '0');

/* Reload on WAN up (ч.59): the heritage trigger reloaded the WHOLE service on every
 * WAN interface up event — every PPPoE redial tore down every connection (direct
 * included) and the DNS hijack for seconds. The core survives WAN changes on its own
 * (auto_detect_interface re-binds; firewall marks are fwmark-based and interface
 * independent), so the trigger is opt-in now. */
const reload_on_wan_opt = (uci.get(uciconfig, ucimain, 'reload_on_wan') === '1');

let main_node, main_udp_node, dedicated_udp_node,
    domain_strategy, dns_server, china_dns_server, iran_dns_server, russia_dns_server,
    secure_dns_server, proxy_calls, no_proxy_torrents, show_advanced_rules, dns_default_strategy,
    direct_domain_list, direct_ips, proxy_domain_list,
    multidns_enabled, mdns_use_plain, mdns_use_secure, mdns_secure_via_proxy,
    mdns_ok, mdns_plain_port, mdns_secure_port, mdns_proxy_in, mdns_proxy_port,
    secure_detour;

/* App-managed config: every remaining mode (working / «Всё через узел» / legacy
 * region presets) reads the SAME UCI knobs — the custom-section branch was
 * retired with D23. */
{
	main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';
	if (main_node === 'nil' || isEmpty(main_node)) {
		/* Legacy 'nil' used to abort generation entirely, leaving the service
		 * dead (or silently running a stale config). That is never what a user
		 * picking "Disable" wants: treat it as an explicit no-proxy setup —
		 * main-out becomes a plain direct outbound so the whole rule engine
		 * stays valid and traffic egresses directly. */
		warn('homeproxy: main_node not configured - generating a NO-PROXY config (main-out = direct).\n');
		main_node = 'direct-out';
	}
	/* Preferred-core capability: emitting a main node the selected core cannot
	 * load would FATAL the whole service. Degrade to the URLTest pool of the
	 * remaining (supported) nodes; if that pool is empty too, its builder
	 * already falls back to direct. */
	/* Dangling main_node: the UCI section is gone (deleted node, restore,
	 * installer) while still selected. The classic path would deref null in
	 * push_outbound (get_all → {} → generate_outbound → null) and FATAL the
	 * whole generation — degrade to the URLTest pool like an unsupported
	 * node. */
	if (!(main_node in ['direct-out', 'byedpi-out', 'zapret-out', 'urltest']) &&
	    uci.get_all(uciconfig, main_node) == null) {
		warn('homeproxy: main node references a missing section (dangling) - falling back to URLTest pool.\n');
		main_node = 'urltest';
	}
	if (!(main_node in ['direct-out', 'byedpi-out', 'zapret-out']) &&
	    uci.get_all(uciconfig, main_node) != null && !hp_node_usable(main_node)) {
		warn('homeproxy: main node is not supported by the selected core - falling back to URLTest pool.\n');
		main_node = 'urltest';
	}
	main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
	/* Same capability guard for the dedicated UDP node: an unsupported node
	 * degrades to 'same' (rides the main path) instead of FATALing the core. */
	if (!(main_udp_node in ['nil', 'urltest', 'same', 'byedpi-out', 'zapret-out']) &&
	    uci.get_all(uciconfig, main_udp_node) != null && !hp_node_usable(main_udp_node)) {
		warn('homeproxy: UDP node is not supported by the selected core - it follows the main path.\n');
		main_udp_node = 'same';
	}
	dedicated_udp_node = !isEmpty(main_udp_node) && !(main_udp_node in ['same', main_node]);

	dns_server = uci.get(uciconfig, ucimain, 'dns_server');
	if (isEmpty(dns_server) || dns_server === 'wan')
		dns_server = wan_dns;

	/* Region local resolver: optional UCI override, else the stable default from REGION
	 * (AliDNS for CN, Shecan for IR). 'wan'/empty falls back to that default. */
	if (routing_mode === 'bypass_cn') {
		china_dns_server = uci.get(uciconfig, ucimain, 'china_dns_server');
		if (isEmpty(china_dns_server) || type(china_dns_server) !== 'string' || china_dns_server === 'wan')
			china_dns_server = REGION.cn.local_dns.server;
	}
	if (routing_mode === 'bypass_ir') {
		iran_dns_server = uci.get(uciconfig, ucimain, 'iran_dns_server');
		if (isEmpty(iran_dns_server) || type(iran_dns_server) !== 'string' || iran_dns_server === 'wan')
			iran_dns_server = REGION.ir.local_dns.server;
	}

	/* Shared selective knobs (forward RU + reverse CN/IR): remote DoH + exceptions.
	 * Reverse modes ride the same engine, so they get secure-dns/overrides for free. */
	/* DNS fields can be a single value or a DynamicList (array); use the first entry. */
	let first_of = (v) => (type(v) === 'array') ? (length(v) ? v[0] : '') : v;

	/* MultiDNS: a dedicated mosdns instance races several servers of each pool
	 * (plain "Russia" pool + encrypted "secure" pool) at query time and returns the
	 * fastest valid answer. When enabled per pool, the sing-box resolvers below are
	 * repointed to the local mosdns listener instead of hitting a single upstream
	 * directly. The daemon (scripts/multidns.uc) builds the mosdns config from these
	 * same UCI lists and continuously scores/ranks servers by latency + HTTP "site
	 * opens" verification + trends, pruning consistently-bad ones. */
	multidns_enabled = uci.get(uciconfig, 'multidns', 'enabled') || '0';
	mdns_use_plain = (uci.get(uciconfig, 'multidns', 'use_plain') || '1') !== '0';
	mdns_use_secure = (uci.get(uciconfig, 'multidns', 'use_secure') || '1') !== '0';
	mdns_secure_via_proxy = (uci.get(uciconfig, 'multidns', 'secure_via_proxy') || '1') !== '0';
	mdns_plain_port = uci.get(uciconfig, 'multidns', 'plain_port') || '5453';
	mdns_secure_port = uci.get(uciconfig, 'multidns', 'secure_port') || '5454';

	/* Safety: only repoint resolvers to the local racing listener when MultiDNS is
	 * enabled AND mosdns is actually running. The daemon (init.d bootstraps it
	 * before this script runs) owns the mosdns process; if it ever fails to
	 * start (bad config, port clash, missing binary) we MUST fall back to the
	 * standard single upstreams — otherwise every query hits a dead listener and
	 * the whole network loses DNS/internet. This guard is the hard safety net. */
	let mdns_running = false;
	const mreg = pm_reg_get('mosdns');
	if (mreg != null && pm_entry_alive(mreg))
		mdns_running = true;
	if (!mdns_running)
		mdns_running = length(pm_find({ exe: '/usr/bin/mosdns', arg: [
			RUN_DIR + '/multidns/mosdns.yaml',
			RUN_DIR + '/multidns/mosdns.candidate.yaml'
		] })) > 0;
	mdns_ok = (multidns_enabled === '1') && access('/usr/bin/mosdns') && mdns_running;

	/* Dedicated loopback inbound the secure pool's DoH/DoT rides when
	 * secure_via_proxy is set, so the encrypted query goes through main-out and the
	 * ISP cannot even see that a DoH server is being contacted. (The plain pool
	 * resolves directly and needs no tunnel.) Port is configurable
	 * (homeproxy.multidns.proxy_port, default 5338) and MUST match the socks5
	 * target the multidns daemon puts into the mosdns config. */
	mdns_proxy_in = mdns_ok && mdns_use_secure && mdns_secure_via_proxy;
	mdns_proxy_port = int(uci.get(uciconfig, 'multidns', 'proxy_port') || '5338') || 5338;

	/* Ф1.6 (аудит 13): honest secure-DNS egress. A real VPN node as main →
	 * DoH/DoT rides main-out, so the UI's "resolves via proxy" promise is
	 * FACTUAL (the ISP no longer sees a plain DoH connection). ByeDPI/Zapret
	 * main → direct-out ON PURPOSE: their desync corrupts tunneled DoH/DoT
	 * sessions (ByeDPI carries traffic; DNS resolves directly), and with a
	 * Direct main node there is no proxy to ride. MultiDNS secure is exempt —
	 * the resolver points at the local loopback listener (the query never
	 * leaves the box) and mosdns itself egresses its secure pool through
	 * mdns-proxy-in → main-out, one layer down. multidns_status reads the
	 * FACTUAL detour from the generated config and renders it on the DNS
	 * page, so this expression and the RPC's intended-transport fallback must
	 * stay in lockstep. 🔴 Declared in the top-level let list ABOVE and only
	 * assigned here: a const INSIDE this block is block-scoped in ucode, and
	 * the DNS emission below (outside the block) died with "access to
	 * undeclared variable" — the exact ч.192 fatal class. A manual run with
	 * MultiDNS secure ON hid it (the ternary never evaluated the else branch)
	 * — only a full-stderr run of the mdns_sec=false path proves it. */
	secure_detour = (main_node in ['direct-out', 'byedpi-out', 'zapret-out'])
		? 'direct-out' : 'main-out';

	if (is_selective_mode(routing_mode)) {
		secure_dns_server = first_of(uci.get(uciconfig, ucimain, 'secure_dns_server')) || 'https://cloudflare-dns.com/dns-query';
		domain_strategy = uci.get(uciconfig, ucimain, 'domain_strategy');
		proxy_calls = uci.get(uciconfig, ucimain, 'proxy_calls');
		no_proxy_torrents = uci.get(uciconfig, ucimain, 'no_proxy_torrents');
		show_advanced_rules = uci.get(uciconfig, ucimain, 'show_advanced_rules');
	}
	if (routing_mode === 'proxy_banned_ru')
		russia_dns_server = first_of(uci.get(uciconfig, ucimain, 'russia_dns_server')) || '77.88.8.8';

	dns_default_strategy = (ipv6_support !== '1') ? 'ipv4_only' : null;

	direct_ips = [];
	direct_domain_list = trim(readfile(HP_DIR + '/resources/direct_list.txt'));
	if (direct_domain_list) {
		/* Ф4.1: static list keeps its KEYWORD semantics for domain-shaped lines
		 * (curated by the user), but IP-shaped lines are classified out into a
		 * paired inline ip_cidr rule-set ('direct-ip'): as a keyword an IP can
		 * never match a hostname — a dead entry; as ip_cidr it routes exactly
		 * the pinned address (normalized: bare IPv4 → /32). */
		let kw = [];
		for (let i, d in split(direct_domain_list, /[\r\n]/)) {
			d = trim(d);
			if (!length(d))
				continue;
			let c = classify_entry(d);
			if (c && c.kind !== 'domain')
				push(direct_ips, c.value);
			else
				push(kw, d);
		}
		direct_domain_list = length(kw) ? kw : null;
	}

	proxy_domain_list = trim(readfile(HP_DIR + '/resources/proxy_list.txt'));
	if (proxy_domain_list)
		proxy_domain_list = split(proxy_domain_list, /[\r\n]/);

	/* ч.129 (ан-146): inbound-уровневые sniff/sniff_override_destination удалены
	 * из диалекта — поле удалили в vanilla 1.13/1.14 и upstream v5 (decode
	 * «removed in 1.13.0»); UCI-ключи остаются нетронутыми для совместимости
	 * (миграция старых установок — в migrate_config.uc). */
}

const proxy_mode = uci.get(uciconfig, ucimain, 'proxy_mode') || 'redirect_tproxy',
      default_interface = uci.get(uciconfig, ucicontrol, 'bind_interface');

const mixed_port = uci.get(uciconfig, uciinfra, 'mixed_port') || '5330';

let self_mark, redirect_port, tproxy_port, tun_name,
    tun_addr4, tun_addr6, tun_mtu, tcpip_stack,
    udp_timeout;

udp_timeout = uci.get(uciconfig, 'infra', 'udp_timeout');

/* self_mark is needed in EVERY mode, not just redirect: firewall_post.ut return-
 * rules expect route.default_mark as the loop guard for the core's own egress.
 * Reading it only under redirect left tproxy/tun configs unstamped — the mangle
 * output chain then re-captured the core's own traffic (DNS included) into tproxy. */
self_mark = uci.get(uciconfig, 'infra', 'self_mark') || '100';
if (match(proxy_mode, /redirect/)) {
	redirect_port = uci.get(uciconfig, 'infra', 'redirect_port') || '5331';
}
if (match(proxy_mode, /tproxy/))
	tproxy_port = uci.get(uciconfig, 'infra', 'tproxy_port') || '5332';
if (match(proxy_mode, /tun/)) {
	tun_name = uci.get(uciconfig, uciinfra, 'tun_name') || 'singtun0';
	tun_addr4 = uci.get(uciconfig, uciinfra, 'tun_addr4') || '172.19.0.1/30';
	tun_addr6 = uci.get(uciconfig, uciinfra, 'tun_addr6') || 'fdfe:dcba:9876::1/126';
	tun_mtu = uci.get(uciconfig, uciinfra, 'tun_mtu') || '9000';
	tcpip_stack = 'system';
}

const log_level = uci.get(uciconfig, ucimain, 'log_level') || 'warn';
/* UCI config end */

/* Config helper start */
function parse_port(strport) {
	if (type(strport) !== 'array' || isEmpty(strport))
		return null;

	let ports = [];
	for (let i in strport)
		push(ports, int(i));

	return ports;

}

function parse_dnsserver(server_addr, default_protocol) {
	if (isEmpty(server_addr))
		return null;

	if (!match(server_addr, /:\/\//))
		server_addr = (default_protocol || 'udp') + '://' + (validation('ip6addr', server_addr) ? `[${server_addr}]` : server_addr);
	server_addr = parseURL(server_addr);

	return {
		type: server_addr.protocol,
		server: server_addr.hostname,
		server_port: strToInt(server_addr.port),
		path: (server_addr.pathname !== '/') ? server_addr.pathname : null,
	}
}

/* Ф1.6-д (mdns-off secure-DNS, 2026-11-03): well-known encrypted-DNS providers
 * with anycast IPs whose TLS certificates carry the IP literal in SAN, so a
 * hostname URL for them is rewritten to the IP literal AT GENERATION and the
 * core never bootstraps the name. Why: with MultiDNS off the bootstrap of the
 * DoH hostname rode the direct plain pool (secure-dns domain_resolver =
 * russia-dns) — a poisoned/broken pool SERVFAILs the bootstrap while the
 * tunnel itself is perfectly healthy (the live window: every secure-dns answer
 * dead at 0.36 s round-trip), and proxied domains lose DNS — "the whole
 * internet is very slow". An IP-literal URL has nothing to bootstrap. */
const SECURE_DNS_IP_MAP = [
	{ host: 'cloudflare-dns.com', ip: '1.1.1.1' },
	{ host: 'one.one.one.one', ip: '1.1.1.1' },
	{ host: 'dns.google', ip: '8.8.8.8' },
	{ host: 'dns.quad9.net', ip: '9.9.9.9' },
	{ host: 'dns.adguard-dns.com', ip: '94.140.14.140' },
	{ host: 'doh.dns.sb', ip: '185.222.222.222' },
];

function secure_ip_literal(server_addr) {
	if (isEmpty(server_addr) || type(server_addr) !== 'string' || !match(server_addr, /:\/\//))
		return server_addr;
	const u = parseURL(server_addr);
	if (u == null || isEmpty(u.hostname))
		return server_addr;
	const host = lc(u.hostname);
	if (validation('ip4addr', host) || validation('ip6addr', host))
		return server_addr;
	for (let m in SECURE_DNS_IP_MAP) {
		if (host === m.host) {
			const ip = validation('ip6addr', m.ip) ? ('[' + m.ip + ']') : m.ip;
			let out = u.protocol + '://' + ip;
			if (!isEmpty(u.port))
				out += ':' + u.port;
			if (u.pathname && u.pathname !== '/')
				out += u.pathname;
			return out;
		}
	}
	return server_addr;
}

/* Bootstrap hardening for a secure resolver that is STILL a hostname after the
 * rewrite (custom DoH/DoT): an IP-literal UDP upstream (8.8.8.8 needs no
 * bootstrap of its own) riding the SAME egress as the encrypted resolver, so
 * the direct plain pool is never in the loop. Returns null for IP-literal
 * servers (nothing to resolve — callers drop it and leave domain_resolver
 * empty). */
function secure_bootstrap_tag(server, detour) {
	if (server == null || validation('ip4addr', '' + server) || validation('ip6addr', '' + server))
		return null;
	return {
		tag: 'secure-bootstrap',
		type: 'udp',
		server: '8.8.8.8',
		detour: detour
	};
}

function parse_dnsquery(strquery) {
	if (type(strquery) !== 'array' || isEmpty(strquery))
		return null;

	let querys = [];
	for (let i in strquery)
		isnan(int(i)) ? push(querys, i) : push(querys, int(i));

	return querys;

}

function generate_endpoint(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const is_wg = node.type in ['wireguard', 'amneziawg'];

	/* GitHub issue #3: wireguard_backend = auto | system | gvisor (per node,
	 * default auto). auto uses gVisor only when the core ships it, otherwise
	 * the kernel (system) stack (needs the wireguard/amneziawg kmod). The
	 * kernel stack creates a REAL TUN device whose default name is shared by
	 * every endpoint — with two or more WG/AWG endpoints the second one dies
	 * with "TUNSETIFF: device or resource busy" — so a per-node name is
	 * emitted whenever system is in play (capped at IFNAMSIZ 15: 'wg-' + 12
	 * chars of the UCI section name; section names are [A-Za-z0-9_], valid
	 * for an interface name). One section may be emitted MORE THAN ONCE
	 * (dedicated UDP exit + rule reference) — the final pass below de-dupes
	 * the kernel names with numeric suffixes. */
	const wg_backend = (node.wireguard_backend === 'system' || node.wireguard_backend === 'gvisor')
		? node.wireguard_backend : 'auto';
	const wg_system = (wg_backend === 'system') ? true
		: (wg_backend === 'gvisor') ? false : !hp_wg_gvisor;

	const addPrefix = (addr) => {
		if (!addr || match(addr, /\//)) return addr;
		return match(addr, /:/) ? addr + '/128' : addr + '/32';
	};
	const raw_addr = node.wireguard_local_address;

	const endpoint = {
		type: is_wg ? 'wireguard' : node.type,
		tag: 'cfg-' + node['.name'] + '-out',
		address: type(raw_addr) === 'array' ? map(raw_addr, addPrefix) : addPrefix(raw_addr),
		mtu: strToInt(node.wireguard_mtu),
		private_key: node.wireguard_private_key,
		peers: is_wg ? [
			{
				address: node.address,
				port: strToInt(node.port),
				allowed_ips: [
					'0.0.0.0/0',
					'::/0'
				],
				persistent_keepalive_interval: strToInt(node.wireguard_persistent_keepalive_interval),
				public_key: node.wireguard_peer_public_key,
				pre_shared_key: node.wireguard_pre_shared_key,
				reserved: parse_port(node.wireguard_reserved),
			}
		] : null,
		system: is_wg ? wg_system : null,
		name: (is_wg && wg_system) ? 'wg-' + substr(node['.name'], 0, 12) : null,
		amnezia: (node.type === 'amneziawg') ? {
			jc: strToInt(node.amnezia_jc),
			jmin: strToInt(node.amnezia_jmin),
			jmax: strToInt(node.amnezia_jmax),
			s1: strToInt(node.amnezia_s1),
			s2: strToInt(node.amnezia_s2),
			s3: strToInt(node.amnezia_s3),
			s4: strToInt(node.amnezia_s4),
			h1: node.amnezia_h1 || null,
			h2: node.amnezia_h2 || null,
			h3: node.amnezia_h3 || null,
			h4: node.amnezia_h4 || null,
			i1: node.amnezia_i1 || null,
			i2: node.amnezia_i2 || null,
			i3: node.amnezia_i3 || null,
			i4: node.amnezia_i4 || null,
			i5: node.amnezia_i5 || null,
			j1: node.amnezia_j1 || null,
			j2: node.amnezia_j2 || null,
			j3: node.amnezia_j3 || null,
			itime: strToInt(node.amnezia_itime),
		} : null,
		tcp_fast_open: strToBool(node.tcp_fast_open),
		tcp_multi_path: strToBool(node.tcp_multi_path),
		udp_fragment: strToBool(node.udp_fragment)
	};

	return endpoint;
}

/* The transport "host" JSON type differs by transport: sing-box's HTTP/2 (`http`)
 * transport takes an ARRAY of strings, while xhttp and httpupgrade take a single
 * STRING. The UI's DynamicList (and some share-link parsers) store http_host as a
 * UCI list, which would emit a JSON array and crash hiddify-core on an xhttp node
 * ("json: cannot unmarshal array into Go value of type string"). Coerce to the
 * correct shape per transport here, so every input path (UI edit, share-link,
 * subscription) produces valid config. */
function transport_host(node) {
	let h = node.http_host;
	if (node.transport === 'http')
		return (type(h) === 'array') ? (length(h) ? h : null) : (isEmpty(h) ? null : [ h ]);
	if (type(h) === 'array')
		h = h[0];
	return h || node.httpupgrade_host;
}

/* xhttp "split download" (the "dl=h2"/"dl=h3" feature): the download direction can use
 * a different host, path, server/port and TLS (commonly a different server_name + ALPN
 * such as h2/h3) than the upload. sing-box-extended names this nested transport
 * `download`; hiddify-core uses the xray-style `downloadSettings`. The inner shape is
 * the same sing-box transport + TLS for both, so build it once and let the caller pick
 * the key per core. Returns null when the node has no split download configured. An
 * unset server/port is omitted (removeBlankAttrs strips it) = "reuse the main
 * connection" — this matches the hiddify reference configs (and works on hiddify-core);
 * sing-box users should set an explicit download server. */
function xhttp_download(node) {
	if (node.transport !== 'xhttp')
		return null;
	if (isEmpty(node.xhttp_download_host) && isEmpty(node.xhttp_download_sni) && isEmpty(node.xhttp_download_path))
		return null;

	const sec = node.xhttp_download_security;
	const want_tls = (sec === 'tls' || sec === 'reality' || !isEmpty(node.xhttp_download_sni) || !isEmpty(node.xhttp_download_alpn));
	const tls = want_tls ? {
		enabled: true,
		server_name: node.xhttp_download_sni,
		insecure: strToBool(node.xhttp_download_insecure),
		alpn: node.xhttp_download_alpn ? (type(node.xhttp_download_alpn) === 'array' ? node.xhttp_download_alpn : split(node.xhttp_download_alpn, ',')) : null,
		/* Reality requires uTLS in sing-box (see the main-TLS block) — default the
		 * fingerprint to 'edge' when reality is on but the node carries none. */
		utls: (!isEmpty(node.xhttp_download_fp) || sec === 'reality') ? {
			enabled: true,
			fingerprint: !isEmpty(node.xhttp_download_fp) ? node.xhttp_download_fp : 'edge'
		} : null,
		reality: (sec === 'reality') ? {
			enabled: true,
			public_key: node.xhttp_download_pbk,
			short_id: node.xhttp_download_sid
		} : null
	} : null;

	return {
		host: node.xhttp_download_host || transport_host(node),
		path: node.xhttp_download_path || node.http_path,
		server: node.xhttp_download_server || null,
		server_port: strToInt(node.xhttp_download_port) || null,
		tls: tls
	};
}

/* sing-box-extended FATALs with "x_padding_bytes cannot be disabled" whenever xhttp
 * padding resolves to empty: an explicit "0"/"0-0" disables it, AND an absent field
 * decodes to "" in Go which counts as disabled too. So the field must always be present
 * and non-empty on every xhttp transport — including the nested `download` block, which
 * is itself a full transport. Coerce any disabling/empty value to the default range. */
function xhttp_padding(v) {
	return (isEmpty(v) || v === '0' || v === '0-0') ? '100-1000' : v;
}

function generate_outbound(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const outbound = {
		type: node.type,
		tag: 'cfg-' + node['.name'] + '-out',

		server: (node.type === 'shadowsocks' && node.shadowtls_enabled === '1') ? null : node.address,
		server_port: (node.type === 'mieru') ? 0 : ((node.type === 'shadowsocks' && node.shadowtls_enabled === '1') ? null : strToInt(node.port)),
		/* Hysteria(2) / Mieru (sing-box-extended) */
		server_ports: (!is_hiddify && node.type === 'mieru' && node.mieru_port_range) ? [node.mieru_port_range] : node.hysteria_hopping_port,

		username: (node.type !== 'ssh') ? node.username : null,
		user: (node.type === 'ssh') ? node.username : null,
		password: node.password,

		/* Direct */
		override_address: node.override_address,
		override_port: strToInt(node.override_port),
		proxy_protocol: strToInt(node.proxy_protocol),
		/* AnyTLS */
		idle_session_check_interval: strToTime(node.anytls_idle_session_check_interval),
		idle_session_timeout: strToTime(node.anytls_idle_session_timeout),
		min_idle_session: strToInt(node.anytls_min_idle_session),
		/* Hysteria (2) */
		hop_interval: strToTime(node.hysteria_hop_interval),
		up_mbps: strToInt(node.hysteria_up_mbps),
		down_mbps: strToInt(node.hysteria_down_mbps),
		obfs: node.hysteria_obfs_type ? {
			type: node.hysteria_obfs_type,
			password: node.hysteria_obfs_password
		} : node.hysteria_obfs_password,
		auth: (node.hysteria_auth_type === 'base64') ? node.hysteria_auth_payload : null,
		auth_str: (node.hysteria_auth_type === 'string') ? node.hysteria_auth_payload : null,
		recv_window_conn: strToInt(node.hysteria_recv_window_conn),
		recv_window: strToInt(node.hysteria_revc_window),
		disable_mtu_discovery: strToBool(node.hysteria_disable_mtu_discovery),
		/* Shadowsocks */
		method: node.shadowsocks_encrypt_method,
		plugin: node.shadowsocks_plugin,
		plugin_opts: node.shadowsocks_plugin_opts,
		/* ShadowTLS / Socks */
		version: (node.type === 'shadowtls') ? strToInt(node.shadowtls_version) : ((node.type === 'socks') ? node.socks_version : null),
		/* Mieru */
		portBindings: (is_hiddify && node.type === 'mieru' && node.mieru_protocol && node.mieru_port_range) ? [
			{ protocol: node.mieru_protocol, portRange: replace(node.mieru_port_range, /:/g, '-') }
		] : null,
		multiplexing: (node.type === 'mieru') ? node.mieru_multiplexing : null,
		handshake_mode: (is_hiddify && node.type === 'mieru') ? node.mieru_handshake_mode : null,
		/* SSH */
		client_version: node.ssh_client_version,
		host_key: node.ssh_host_key,
		host_key_algorithms: node.ssh_host_key_algo,
		private_key: node.ssh_priv_key,
		private_key_passphrase: node.ssh_priv_key_pp,
		/* Tuic */
		uuid: node.uuid,
		congestion_control: node.tuic_congestion_control,
		udp_relay_mode: node.tuic_udp_relay_mode,
		udp_over_stream: strToBool(node.tuic_udp_over_stream),
		zero_rtt_handshake: strToBool(node.tuic_enable_zero_rtt),
		heartbeat: strToTime(node.tuic_heartbeat),
		/* VLESS / VMess */
		flow: node.vless_flow,
		alter_id: strToInt(node.vmess_alterid),
		security: node.vmess_encrypt,
		global_padding: strToBool(node.vmess_global_padding),
		authenticated_length: strToBool(node.vmess_authenticated_length),
		packet_encoding: node.packet_encoding,

		multiplex: (node.multiplex === '1') ? {
			enabled: true,
			protocol: node.multiplex_protocol,
			max_connections: strToInt(node.multiplex_max_connections),
			min_streams: strToInt(node.multiplex_min_streams),
			max_streams: strToInt(node.multiplex_max_streams),
			padding: strToBool(node.multiplex_padding),
			brutal: (node.multiplex_brutal === '1') ? {
				enabled: true,
				up_mbps: strToInt(node.multiplex_brutal_up),
				down_mbps: strToInt(node.multiplex_brutal_down)
			} : null
		} : null,
		tls_fragment: (node.tls_fragment === '1') ? {
			enabled: true,
			size: node.tls_fragment_size,
			sleep: node.tls_fragment_sleep
		} : null,
		/* Shadowsocks has no top-level tls field in ANY sing-box-based core — for a
		 * ShadowTLS-wrapped Shadowsocks the TLS lives on the separate shadowtls transport
		 * outbound (detour). Both sing-box-extended AND hiddify-core 4.1.0 (HiddifyCli)
		 * strict-reject a stray tls here ("unknown field tls" → FATAL), so suppress it for
		 * shadowsocks unconditionally (the earlier is_singbox-only gate was wrong — hiddify
		 * is not lenient). */
		tls: (node.tls === '1' && node.type !== 'shadowsocks') ? {
			enabled: true,
			server_name: node.tls_sni,
			insecure: strToBool(node.tls_insecure),
			alpn: node.tls_alpn ? (type(node.tls_alpn) === 'array' ? node.tls_alpn : [node.tls_alpn]) : null,
			min_version: node.tls_min_version,
			max_version: node.tls_max_version,
			cipher_suites: node.tls_cipher_suites,
			certificate_path: node.tls_cert_path,
			ech: (node.tls_ech === '1') ? {
				enabled: true,
				config: node.tls_ech_config,
				config_path: node.tls_ech_config_path
			} : null,
			/* Reality REQUIRES uTLS in sing-box ("uTLS is required by reality client"
			 * is a FATAL that crash-loops the whole service; hiddify-core defaults it
			 * silently). So when reality is on we always emit utls, defaulting the
			 * fingerprint to 'edge' if the node (e.g. a sub-imported reality node)
			 * didn't carry one. */
			utls: (!isEmpty(node.tls_utls) || node.tls_reality === '1') ? {
				enabled: true,
				fingerprint: !isEmpty(node.tls_utls) ? node.tls_utls : 'edge'
			} : null,
			reality: (node.tls_reality === '1') ? {
				enabled: true,
				public_key: node.tls_reality_public_key,
				short_id: node.tls_reality_short_id
			} : null
		} : null,
		transport: (!is_hiddify && node.type === 'mieru') ? node.mieru_protocol : !isEmpty(node.transport) ? {
			type: node.transport,
			host: transport_host(node),
			path: node.http_path || node.ws_path,
			mode: (node.transport === 'xhttp') ? (node.xhttp_mode || 'auto') : null,
			/* xhttp transport options differ by core DIALECT: hiddify-core (HiddifyCli, the
			 * format the Hiddify app exports) uses camelCase — xPaddingBytes /
			 * scMaxEachPostBytes / scMinPostsIntervalMs — while sing-box-extended uses
			 * snake_case. Emit both spellings; the wrong-core one is null and removeBlankAttrs
			 * strips it before write. sing-box keeps a forced 100-1000 padding default to
			 * preserve prior behaviour; hiddify only emits what the node actually carries. */
			x_padding_bytes: (is_singbox && node.transport === 'xhttp') ? xhttp_padding(node.xhttp_padding_bytes) : null,
			xPaddingBytes: (is_hiddify && node.transport === 'xhttp' && !isEmpty(node.xhttp_padding_bytes)) ? xhttp_padding(node.xhttp_padding_bytes) : null,
			sc_max_each_post_bytes: (is_singbox && node.transport === 'xhttp') ? (node.xhttp_sc_max_each_post_bytes || null) : null,
			scMaxEachPostBytes: (is_hiddify && node.transport === 'xhttp') ? (node.xhttp_sc_max_each_post_bytes || null) : null,
			sc_min_posts_interval_ms: (is_singbox && node.transport === 'xhttp') ? (node.xhttp_sc_min_posts_interval_ms || null) : null,
			scMinPostsIntervalMs: (is_hiddify && node.transport === 'xhttp') ? (node.xhttp_sc_min_posts_interval_ms || null) : null,
			headers: node.xhttp_headers ? json(node.xhttp_headers) : (node.ws_host ? { Host: node.ws_host } : null),
			method: node.http_method,
			max_early_data: strToInt(node.websocket_early_data),
			early_data_header_name: node.websocket_early_data_header,
			service_name: node.grpc_servicename,
			idle_timeout: (node.http_idle_timeout),
			ping_timeout: (node.http_ping_timeout),
			permit_without_stream: strToBool(node.grpc_permit_without_stream)
		} : null,
		/* NaiveProxy */
		quic: (node.type === 'naive') ? strToBool(node.naive_quic) :
		      (node.type === 'trusttunnel') ? strToBool(node.trusttunnel_quic) : null,
		extra_headers: (node.type === 'naive') ? (node.naive_extra_headers ? json(node.naive_extra_headers) : null) : null,
		/* TrustTunnel (sing-box-extended only; its congestion key differs from tuic's) */
		network: (node.type === 'trusttunnel') ? ((type(node.trusttunnel_network) === 'array') ?
			(length(node.trusttunnel_network) ? node.trusttunnel_network : null) :
			(isEmpty(node.trusttunnel_network) ? null : [ node.trusttunnel_network ])) : null,
		congestion_controller: (node.type === 'trusttunnel') ? (node.trusttunnel_congestion_controller || null) : null,
		cwnd: (node.type === 'trusttunnel') ? strToInt(node.trusttunnel_cwnd) : null,
		health_check: (node.type === 'trusttunnel') ? strToBool(node.trusttunnel_health_check) : null,
		/* sing-box-extended's ssh outbound has NO udp_over_tcp field → emitting it FATALs
		 * with "unknown field udp_over_tcp" (verified on sing-box check). hiddify-core's
		 * ssh works with it as-is (tested), so keep the ssh branch for hiddify only.
		 * naive/shadowsocks keep udp_over_tcp on both cores. */
		udp_over_tcp: (node.type === 'naive') ? strToBool(node.naive_udp_over_tcp) :
		              (is_hiddify && node.type === 'ssh') ? (node.ssh_udp_over_tcp !== '0' ? true : null) :
		              ((is_hiddify && node.udp_over_tcp === '1') ? {
			enabled: true,
			version: strToInt(node.udp_over_tcp_version)
		} : null),
		tcp_fast_open: strToBool(node.tcp_fast_open),
		tcp_multi_path: strToBool(node.tcp_multi_path),
		udp_fragment: strToBool(node.udp_fragment),
		bind_interface: node.bind_interface || null,
		detour: (node.type === 'shadowsocks' && node.shadowtls_enabled === '1') ? ('cfg-' + node['.name'] + '-shadowtls-out') : null
	};

	/* xhttp split download: attach under the per-core key (`download` for
	 * sing-box-extended, `downloadSettings` for hiddify-core). The download block is a
	 * full xhttp transport, so sing-box requires it to carry x_padding_bytes too — an
	 * absent field decodes to "" and FATALs ("cannot be disabled"). Mirror the main
	 * transport's per-core padding spelling (sing-box always forces a default; hiddify
	 * only emits what the node carries). */
	if (type(outbound.transport) === 'object') {
		const dl = xhttp_download(node);
		if (dl) {
			if (is_singbox && node.transport === 'xhttp')
				dl.x_padding_bytes = xhttp_padding(node.xhttp_padding_bytes);
			else if (is_hiddify && node.transport === 'xhttp' && !isEmpty(node.xhttp_padding_bytes))
				dl.xPaddingBytes = xhttp_padding(node.xhttp_padding_bytes);
			outbound.transport[is_hiddify ? 'downloadSettings' : 'download'] = dl;
		}
	}

	/* TrustTunnel (sing-box-extended) multiplex: same JSON key as the generic
	 * mux above but a different option shape (no protocol/padding/brutal) —
	 * replace it wholesale; removeBlankAttrs strips the null. */
	if (node.type === 'trusttunnel') {
		outbound.multiplex = (node.trusttunnel_multiplex === '1') ? {
			enabled: true,
			max_connections: strToInt(node.trusttunnel_mp_max_connections),
			min_streams: strToInt(node.trusttunnel_mp_min_streams),
			max_streams: strToInt(node.trusttunnel_mp_max_streams)
		} : null;
	}

	return outbound;
}

/* Push outbound(s) for a node. For ShadowTLS-wrapped Shadowsocks, first pushes the
 * hidden ShadowTLS transport outbound, then the Shadowsocks outbound with detour set. */
function push_outbound(list, node) {
	if (node.type === 'shadowsocks' && node.shadowtls_enabled === '1') {
		push(list, {
			type: 'shadowtls',
			tag: 'cfg-' + node['.name'] + '-shadowtls-out',
			server: node.address,
			server_port: strToInt(node.port),
			version: strToInt(node.shadowtls_version) || 3,
			password: node.shadowtls_password || null,
			tls: {
				enabled: true,
				server_name: node.tls_sni || null,
				insecure: strToBool(node.tls_insecure),
				utls: !isEmpty(node.tls_utls) ? { enabled: true, fingerprint: node.tls_utls } : null
			}
		});
	}
	push(list, generate_outbound(node));
}

/* ч.118: `config` + `has_outbound` hoisted ABOVE get_outbound — in this
 * ucode dialect a name declared LATER is invisible to a function defined
 * earlier (no hoisting at all; lesson 126), and get_outbound's reroute
 * branches call has_outbound() — for every user WITHOUT the tg-ws
 * bridge those branches threw "left-hand side is not a function" and the
 * whole generation died (dormant since the helpers sat at the file tail;
 * this router has the bridge, so the branch never ran here). The block
 * references nothing but itself — the hoist is behavior-neutral.
 * ч.200 (D34b): tg-ws removed entirely — a legacy 'tgws-out' rule node
 * rides the main path (same fallback the off-branch used). */
const config = {};

const has_outbound = (tag) => {
	for (let ob in config.outbounds)
		if (ob?.tag === tag) return true;
	for (let ep in (config.endpoints || []))
		if (ep?.tag === tag) return true;
	return false;
};

function get_outbound(cfg) {
	if (isEmpty(cfg))
		return null;

	if (type(cfg) === 'array') {
		if ('any-out' in cfg)
			return 'any';

		let outbounds = [];
		for (let i in cfg)
			push(outbounds, get_outbound(i));
		return outbounds;
	} else {
		switch (cfg) {
		case 'block-out':
		case 'direct-out':
		case 'main-out':
			return cfg;
		case 'byedpi-out':
			/* Fall back to direct if ByeDPI is disabled so the config stays valid */
			return (byedpi_enabled === '1') ? 'byedpi-out' : 'direct-out';
		case 'zapret-out':
			/* Fall back to plain direct if zapret is disabled so the config stays valid */
			return (zapret_enabled === '1') ? 'zapret-out' : 'direct-out';
		case 'tgws-out':
			/* D34b: the tg-ws bridge is gone; a legacy rule node rides the main path. */
			return has_outbound('main-out') ? 'main-out' : 'direct-out';
		default:
			const node = uci.get(uciconfig, cfg, 'node');
			if (isEmpty(node)) {
				/* A dangling reference (rule/node pointing at a deleted proxy node)
				 * must not kill the whole generation — the service would keep running
				 * on a stale config with no hint why. Skip with a warning instead;
				 * downstream has_outbound()/null checks drop the dead reference. */
				warn(sprintf('homeproxy: %s references a missing node - skipping.\n', cfg));
				return null;
			}
			else if (node === 'urltest')
				return 'cfg-' + cfg + '-out';
			else if (!hp_node_usable(node)) {
				/* Capability guard: referencing a node the selected core cannot
				 * load is a fatal "non-existent outbound". Reroute to the main
				 * path (direct when there is no main outbound). */
				warn(sprintf('homeproxy: %s targets a node not supported by the selected core - rerouted to the main path.\n', cfg));
				return has_outbound('main-out') ? 'main-out' : 'direct-out';
			}
			else
				return 'cfg-' + node + '-out';
		}
	}
}

function get_resolver(cfg) {
	if (isEmpty(cfg))
		return null;

	switch (cfg) {
	case 'default-dns':
	case 'system-dns':
	/* Built-in selective-mode resolvers — emitted with these literal tags (forward RU:
	 * russia-dns/secure-dns; reverse CN/IR: region-dns/secure-dns; global: main-dns),
	 * so a custom DNS rule may target them directly (don't prefix as a cfg-*-dns). */
	case 'russia-dns':
	case 'secure-dns':
	case 'region-dns':
	case 'main-dns':
		return cfg;
	default:
		return 'cfg-' + cfg + '-dns';
	}
}

function get_ruleset(cfg) {
	if (isEmpty(cfg))
		return null;

	let rules = [];
	for (let i in cfg)
		push(rules, isEmpty(i) ? null : 'cfg-' + i + '-rule');
	return rules;
}
/* Config helper end */

/* Log */
config.log = {
	disabled: false,
	level: log_level,
	output: RUN_DIR + '/hiddify-c.log',
	timestamp: true
};

/* NTP */
if (!isEmpty(ntp_server))
	config.ntp = {
		enabled: true,
		server: ntp_server,
		detour: 'direct-out',
		domain_resolver: 'default-dns',
	};

/* B6.5 (Ф4.5): the per-service (Master) rule list is collected ONCE, in the
 * canonical priority order (specific services → russia-inside → refilter as
 * the largest list last), and drives BOTH the route rules and the DNS rules —
 * the DNS policy mirrors the route policy: the same sources, the same order,
 * and a per-source DNS server consistent with the source's effective outbound
 * (proxy-family → secure-dns; direct egress → the plain direct pool, i.e. no
 * DNS rule — the final resolver is already the direct one). The audit found
 * DNS and route orders drifting apart (a direct-routed host resolving through
 * the proxy pool and vice versa); one list for both eliminates the drift. */
const ru_source_priority = (s) => s === 'refilter' ? 2 : s === 'russia-inside' ? 1 : 0;
let ru_rules = [];
/* ч.274 audit: UCI-first enabled node per source — parity with the sentinel
 * core_rule_map contract (first ENABLED rule per source in UCI file order,
 * sentinel.uc uci_rule_nodes): the classic hp-ru-<src>-out tag belongs to it. */
let ru_uci_first = {};
uci.foreach(uciconfig, ucirurule, (cfg) => { if (cfg.enabled === '1') {
	if (ru_uci_first['' + cfg.source] == null)
		ru_uci_first['' + cfg.source] = '' + cfg.node;
	push(ru_rules, cfg); } });
ru_rules = sort(ru_rules, (a, b) => ru_source_priority(a.source) - ru_source_priority(b.source));

/* DNS start */
/* Default settings */
config.dns = {
	servers: [
		{
			tag: 'default-dns',
			type: 'udp',
			server: wan_dns,
			detour: 'direct-out'
		},
		{
			tag: 'system-dns',
			type: 'local',
			detour: 'direct-out'
		}
	],
	rules: [],
	strategy: dns_default_strategy
};

if (!isEmpty(main_node)) {
	if (routing_mode === 'proxy_banned_ru') {
		/* Russia mode: direct-default routing, russia-dns for all, secure-dns for proxy lists.
		 *
		 * MultiDNS accelerates both pools: when it is enabled the resolvers are pointed at the
		 * dedicated mosdns racing listeners (127.0.0.1:5453 plain / :5454 secure). mosdns
		 * races several servers in each pool on every query and returns the fastest valid
		 * answer, and drops poisoned/dead-IP answers. The plain pool resolves DIRECTLY (no
		 * proxy) — that is the documented behaviour and avoids a hard proxy dependency; the
		 * secure pool uses DoH/DoT (encrypted, hijack-proof). When MultiDNS is off we fall
		 * back to sing-box's own resolver so DNS never breaks. */
		const ru_dns_target = (mdns_ok && mdns_use_plain)
			? { type: 'udp', server: '127.0.0.1', server_port: int(mdns_plain_port) }
			: parse_dnsserver(russia_dns_server);
		push(config.dns.servers, {
			tag: 'russia-dns',
			detour: 'direct-out',
			...ru_dns_target
		});
		/* Secure pool: race via the local mosdns listener when MultiDNS is on (DoH/DoT
		 * bypasses the hijack); otherwise sing-box's own DoH/DoT resolver with the
		 * honest egress (secure_detour — audit 13). Ф1.6-д: the DoH/DoT host is
		 * rewritten to an IP literal when possible (nothing to bootstrap) and any
		 * remaining hostname bootstraps through secure-bootstrap (IP-literal 8.8.8.8
		 * on the same egress) — never through the direct plain pool, which dies when
		 * poisoned and starved every proxied domain of DNS (mdns-off outage). */
		const mdns_sec = (mdns_ok && mdns_use_secure);
		const secure_target = mdns_sec
			? { type: 'udp', server: '127.0.0.1', server_port: int(mdns_secure_port) }
			: parse_dnsserver(secure_ip_literal(secure_dns_server), 'tcp');
		const secure_bs = (!mdns_sec && secure_target != null)
			? secure_bootstrap_tag(secure_target.server, secure_detour) : null;
		if (secure_bs != null)
			push(config.dns.servers, secure_bs);
		push(config.dns.servers, {
			tag: 'secure-dns',
			domain_resolver: mdns_sec
				? { server: 'russia-dns', strategy: (ipv6_support !== '1') ? 'ipv4_only' : null }
				: (secure_bs != null)
					? { server: 'secure-bootstrap', strategy: (ipv6_support !== '1') ? 'ipv4_only' : null }
					: null,
			detour: mdns_sec ? 'direct-out' : secure_detour,
			...secure_target
		});
		config.dns.final = 'russia-dns';

		/* andrevi.ch always via secure-dns (hardcoded diagnostic anchor) */
		push(config.dns.rules, {
			domain: ['andrevi.ch'],
			action: 'route',
			server: 'secure-dns'
		});

		/* B6.5: the DNS rules below MIRROR the route rules in the SAME order —
		 * first match wins in BOTH lists, so a source pair routes and resolves
		 * together. The audit's split (direct-routed traffic resolving through
		 * the proxy pool / proxy-routed traffic resolving through the plain
		 * pool) is gone: per-source DNS follows the source's effective
		 * outbound class. Manual exclusions go FIRST, exactly where the
		 * auto-direct rule sits in the route list: a hand-pinned host rides
		 * direct-out, so it resolves through the PLAIN direct pool
		 * (russia-dns) even when the same host is also listed in proxy lists
		 * further down. The dedicated DOMAIN-ONLY ruleset ('auto-direct-
		 * domain', written by sync_manual_direct_ruleset) is the DNS ruleset
		 * for manual exclusions — a DNS rule may not reference a ruleset
		 * carrying ip_cidr entries (sing-box 1.14+ FATAL "Legacy Address
		 * Filter Fields in DNS rules"). */
		push(config.dns.rules, {
			rule_set: 'auto-direct-domain',
			action: 'route',
			server: 'russia-dns'
		});

		/* Per-service sources in the canonical order (ru_rules, collected
		 * above — the SAME list the route rules iterate). A source whose
		 * effective outbound is proxy-family (main-out, a URLTest pool or
		 * a real node) resolves through the encrypted pool
		 * (secure-dns); a source that falls back to direct egress (ByeDPI/
		 * Zapret disabled) gets NO rule — the final resolver is already the
		 * plain direct pool, matching the direct route. Engines that DIAL
		 * the resolved IP themselves (ByeDPI/Zapret enabled) need
		 * poison-proof answers and keep secure-dns. */
		/* Lesson 355 — the helper lives at module top level (see the header):
		 * the DNS and route scopes are different blocks (lesson 93/126). */
		const ru_dns_target_of = (cfg) => {
			const n = cfg.node || 'main-out';
			if (n === 'byedpi-out')
				return (byedpi_enabled === '1') ? 'secure-dns' : null;
			if (n === 'zapret-out')
				return (zapret_enabled === '1') ? 'secure-dns' : null;
			return 'secure-dns';
		};
		/* сеанс 187: НЕГАТИВНЫЙ СТИРИНГ YouTube — мёртвые пулы (dead_whole
		 * из каталога свипов /var/run/ravnex/zapret_pools.json, свежесть ≤48 ч,
		 * деривация = yt_steer.uc steer_pools, СЕЛФТЕСТ-гейт модуля) отвергаются
		 * НА СЛОЕ DNS ЯДРА: клиент получает мгновенный отказ и ротит на живой
		 * край, вместо 5-10 с таймаута. Пивот ×2: (1) с mosdns на ядро —
		 * qname-матчер этой сборки mosdns не срабатывает на файловом domain_set
		 * (доказано живьём: 5453 отвечал реальными IP при заполненном наборе);
		 * (2) чтение ЗАПИСИ фидера заменено прямым деривом из каталога — гонка
		 * «RPC-регенерация vs тик фидера» (файл пустеет при OFF и восстанавливается
		 * тиком) давала пустой набор на регене. Форма правила = проверенный
		 * шаблон rejects (oauth-domain): ЛОКАЛЬНЫЙ rule_set + action:'reject';
		 * инлайн domain_suffix-массив в reject-правиле не сработал на этом ядре.
		 * Свежесть = момент регенерации (автопилот применяет после свипов). */
		if ((uci.get(uciconfig, 'config', 'yt_steer_dead') || '0') === '1') {
			const steer_cat = access('/var/run/ravnex/zapret_pools.json') ?
				(json(readfile('/var/run/ravnex/zapret_pools.json') || '') || null) : null;
			const steer_stream = access('/var/run/ravnex/yt_stream.json') ?
				(json(readfile('/var/run/ravnex/yt_stream.json') || '') || null) : null;
			const steer_cur = (steer_stream != null && type(steer_stream) === 'object') ?
				current_suffix_from_host('' + (steer_stream.host || '')) : '';
			let steer_rows = (steer_cat != null && type(steer_cat.pools) === 'object') ?
				steer_pools(steer_cat.pools, time(), steer_cur) : [];
			/* сеанс 188 (решение юзера): ВЫУЧЕННЫЕ зомби-пулы (автообучение
			 * automation-тика из живых соединений, yt_steer_learned.json) —
			 * в тот же поток: регенерация и DNS-слой несут их наравне со
			 * свип-каталогом. Гварды те же: hits>=3, свежесть 48 ч, пул
			 * текущего стрима исключается префиксом. */
			try {
				/* 188: learned-файл = tmpfs (флеш-износ /etc недопустим при
				 * поминутных сканах); потеря при ребуте = переучивание. */
				const steer_lf = '/var/run/ravnex/yt_steer_learned.json';
				if (access(steer_lf)) {
					const lf = json(readfile(steer_lf) || '');
					const lp = (lf != null && type(lf) === 'object' && lf.pools) ? lf.pools : {};
					const lks = keys(lp);
					sort(lks, (a, b) => (a < b ? -1 : (a > b ? 1 : 0)));
					const now_ts = time();
					for (let pool in lks) {
						const lr = lp[pool];
						if (lr == null || type(lr) !== 'object')
							continue;
						if (int(lr.hits || 0) < 3)
							continue;
						const ts = int(lr.last_ts || 0);
						if (ts <= 0 || (now_ts - ts) > 172800)
							continue;
						const kw = pool_keyword_from_suffix(pool);
						if (!length(kw))
							continue;
						if (length(steer_cur) && index(steer_cur, kw) === 0)
							continue;
						push(steer_rows, kw);
					}
					/* dedupe + sort (свип-строки уже отсортированы; merge — нет) */
					let sseen = {};
					let smerged = [];
					for (let kw in steer_rows) {
						if (sseen[kw]) continue;
						sseen[kw] = true;
						push(smerged, kw);
					}
					sort(smerged, (a, b) => (a < b ? -1 : (a > b ? 1 : 0)));
					steer_rows = smerged;
				}
			} catch (e) { /* learned-файл бит/недоступен — свип-строки остаются */ }
			if (length(steer_rows)) {
				/* 188-урок (живьём, clash-api): matcher ядра (sing-box
				 * 1.15-alpha) строит label-trie — googlevideo-кластер в хосте
				 * это ОДИН лейбл (rr9---sn-oj5hn5-5a), подстрочный суффикс
				 * каталога (sn-oj5hn5-5a...) лейбл-границей не является:
				 * domain_suffix НЕ матчится (тот же корень, что у мёртвого
				 * mosdns qname и dns.rules reject). Рабочая форма —
				 * domain_keyword (подстрока): route-reject доказан живьём
				 * (reset @ 4.7 мс против 404 @ 21 мс на контроле). */
				const steer_rs = HP_DIR + '/resources/yt_steer_dead.json';
				const rs_body = { version: 1, rules: [ { domain_keyword: steer_rows } ] };
				writefile(steer_rs + '.tmp', sprintf('%.J\n', rs_body));
				system(`mv -f '${steer_rs}.tmp' '${steer_rs}'`);
				/* Дедуп-гвард = ТОЛЬКО в route-секции ниже: has_ruleset объявлен
				 * ТЕКСТУАЛЬНО ПОЗЖЕ этого места (урок 405) — вызов здесь валил
				 * генератор (ReferenceError) и уводил apply в LKG. */
				push(config.dns.rules, {
					rule_set: 'yt-steer-dead',
					action: 'reject'
				});
			}
		}
		for (let cfg in ru_rules) {
			const dnst = ru_dns_target_of(cfg);
			if (!dnst)
				continue;
			const inline_dns = hp_remote_preferred(cfg.source) ? null : hp_service_inline_domains(cfg.source);
			if (inline_dns)
				push(config.dns.rules, {
					domain_suffix: inline_dns,
					action: 'route',
					server: dnst
				});
			else
				push(config.dns.rules, {
					rule_set: (cfg.source === 'refilter') ? 'hp-ru-refilter-domain' : ('hp-ru-' + cfg.source),
					action: 'route',
					server: dnst
				});
		}

		/* OAuth stability (ч.59): auth providers resolve through the encrypted
		 * pool (consistent, poison-proof) and HTTPS/SVCB records are filtered so
		 * browsers cannot discover an h3 endpoint and escape into QUIC. Referenced
		 * rule-set is emitted with the route rules below (proxy_banned_ru).
		 * B6.5: placed AFTER the per-service rules — the same position OAuth
		 * holds in the route list. */
		if (oauth_stability_opt) {
			push(config.dns.rules, {
				rule_set: 'oauth-domain',
				query_type: [64, 65],
				action: 'reject'
			});
			push(config.dns.rules, {
				rule_set: 'oauth-domain',
				action: 'route',
				server: 'secure-dns'
			});
			/* ч.61: auth FAMILIES (learned auth-like hosts → parent domain)
			 * get the same deterministic encrypted resolution. */
			push(config.dns.rules, {
				rule_set: 'auto-auth-domain',
				query_type: [64, 65],
				action: 'reject'
			});
			push(config.dns.rules, {
				rule_set: 'auto-auth-domain',
				action: 'route',
				server: 'secure-dns'
			});
		}

		/* The proxy-domain DNS pair (SVCB reject + secure-dns route) and the
		 * user-list / RU-protect DNS rules are emitted NEXT TO their route
		 * rules in the routing section below (B6.5 mirror) — the user-list
		 * rule-set declarations exist only after user_list_prepare() runs
		 * there, and the adjacency keeps the two policies reviewable as one. */
	} else if (is_bypass_mode(routing_mode)) {
		/* Reverse (bypass) mode: default route is PROXY; region traffic carved out to direct.
		 * DNS mirrors it -- proxied (default) resolves via DoH-through-tunnel (anti-pollution +
		 * hides queries from the ISP/operator); region domains resolve via the local resolver
		 * (correct domestic CDN, fast, shutdown-resilient). One engine, region is data. */
		const r = region_of(routing_mode);
		const region = REGION[r];

		/* Region-local resolver (direct egress): user-chosen server (china_dns_server /
		 * iran_dns_server), defaulting to the REGION baseline (AliDNS CN / Shecan IR). */
		const region_dns_server = (r === 'cn') ? china_dns_server : iran_dns_server;
		push(config.dns.servers, {
			tag: 'region-dns',
			detour: 'direct-out',
			...parse_dnsserver(region_dns_server)
		});
		/* Remote/default resolver: DoH through the tunnel. Ф1.6-д: the DoH/DoT host
		 * is rewritten to an IP literal when possible (nothing to bootstrap) and
		 * any remaining hostname bootstraps through secure-bootstrap (IP-literal
		 * 8.8.8.8 on the same egress as the encrypted resolver) — never through the
		 * region resolver, which can be poisoned by the ISP (the old NOTE (Iran
		 * validation) workaround "set secure_dns_server to an IP-literal DoH" is
		 * now automatic for known providers). */
		/* Secure pool: race via the local mosdns listener when MultiDNS+secure is on;
		 * otherwise the honest egress (secure_detour — audit 13, same rule as RU). */
		const secure_target_br = (		mdns_ok && mdns_use_secure)
			? { type: 'udp', server: '127.0.0.1', server_port: int(mdns_secure_port) }
			: parse_dnsserver(secure_ip_literal(secure_dns_server), 'tcp');
		const secure_bs_br = (!(mdns_ok && mdns_use_secure) && secure_target_br != null)
			? secure_bootstrap_tag(secure_target_br.server, secure_detour) : null;
		if (secure_bs_br != null)
			push(config.dns.servers, secure_bs_br);
		push(config.dns.servers, {
			tag: 'secure-dns',
			domain_resolver: (mdns_ok && mdns_use_secure)
				? { server: 'region-dns', strategy: (ipv6_support !== '1') ? 'ipv4_only' : null }
				: (secure_bs_br != null)
					? { server: 'secure-bootstrap', strategy: (ipv6_support !== '1') ? 'ipv4_only' : null }
					: null,
			detour: (mdns_ok && mdns_use_secure) ? 'direct-out' : secure_detour,
			...secure_target_br
		});
		config.dns.final = 'secure-dns';

		/* B6.5 mirror (same as the RU branch): manual exclusions FIRST —
		 * auto-direct pins ride direct-out, so they resolve through the
		 * region-local resolver, never through the tunnel resolver.
		 * DOMAIN-ONLY ruleset: ip_cidr entries are rejected inside DNS
		 * rules (sing-box 1.14+). */
		push(config.dns.rules, {
			rule_set: 'auto-direct-domain',
			action: 'route',
			server: 'region-dns'
		});

		/* Custom direct list -> region-dns */
		if (length(direct_domain_list))
			push(config.dns.rules, {
				rule_set: 'direct-domain',
				action: 'route',
				server: 'region-dns'
			});

		/* Region domains -> region-dns (local) */
		push(config.dns.rules, {
			rule_set: 'geosite-' + r,
			action: 'route',
			server: 'region-dns',
			strategy: 'prefer_ipv6'
		});

		/* Optional geoip fallback + non-region guard. CN: list non-exhaustive, catch unlisted
		 * domestic by IP. IR: off -- Iran configs use the simple scheme. */
		if (region.guard)
			push(config.dns.rules, {
				type: 'logical',
				mode: 'and',
				rules: [
					{ rule_set: 'geosite-non' + r, invert: true },
					{ rule_set: 'geoip-' + r }
				],
				action: 'route',
				server: 'region-dns',
				strategy: 'prefer_ipv6'
			});
	} else {
		/* Global (proxy everything): plain remote DNS through the tunnel. No region carve-out. */
		push(config.dns.servers, {
			tag: 'main-dns',
			domain_resolver: {
				server: 'default-dns',
				strategy: (ipv6_support !== '1') ? 'ipv4_only' : null
			},
			detour: 'main-out',
			...parse_dnsserver(dns_server, 'tcp')
		});
		config.dns.final = 'main-dns';

		if (length(direct_domain_list))
			push(config.dns.rules, {
				rule_set: 'direct-domain',
				action: 'route',
				server: 'default-dns'
			});

		/* Filter out SVCB/HTTPS queries for proxied custom domains */
		push(config.dns.rules, {
			rule_set: 'proxy-domain',
			query_type: [64, 65],
			action: 'reject'
		});
	}
}
/* DNS end */

/* Inbound start */
config.inbounds = [];

push(config.inbounds, {
	type: 'direct',
	tag: 'dns-in',
	listen: '::',
	listen_port: int(dns_port)
});

push(config.inbounds, {
	type: 'mixed',
	tag: 'mixed-in',
	listen: '::',
	listen_port: int(mixed_port),
	udp_timeout: strToTime(udp_timeout),
});

/* MultiDNS: the plain (Russia) pool resolves DIRECTLY via mosdns upstreams (no proxy —
 * documented behaviour, and avoids a hard proxy dependency). The secure pool's DoH/DoT is
 * encrypted so it is hijack-proof on its own; when secure_via_proxy is set it additionally
 * rides a dedicated loopback inbound mdns-proxy-in (127.0.0.1:5338) pinned to main-out via a
 * route rule below, so the ISP can't even see the encrypted query. The plain pool needs no
 * tunnel. (The previous smartdns design's dedicated 5338 inbound never bound because only
 * the inbound — never its route rule — was emitted; both are now emitted together.) */

if (match(proxy_mode, /redirect/))
	push(config.inbounds, {
		type: 'redirect',
		tag: 'redirect-in',

		listen: '::',
		listen_port: int(redirect_port),
	});
if (match(proxy_mode, /tproxy/))
	push(config.inbounds, {
		type: 'tproxy',
		tag: 'tproxy-in',

		listen: '::',
		listen_port: int(tproxy_port),
		network: 'udp',
		udp_timeout: strToTime(udp_timeout),
		/* ч.264 (копилка аудита): NAT-лимит UDP ЯВНО — ядро держит запись
		 * NAT до udp_timeout, но без явного потолка буря новых UDP-флоу
		 * упирается только в недокументированный дефолт ядра. Потолок
		 * фиксируем на 65536 записей (≥ nf_conntrack_max любого класса
		 * боксов — запись никогда не станет узким местом, при этом рост
		 * ограничен конструктивно; ~13 МБ worst-case на таблицу). */
		udp_nat_max: 65536,
	});
if (match(proxy_mode, /tun/))
	push(config.inbounds, {
		type: 'tun',
		tag: 'tun-in',

		interface_name: tun_name,
		address: (ipv6_support === '1') ? [tun_addr4, tun_addr6] : [tun_addr4],
		mtu: strToInt(tun_mtu),
		auto_route: false,
		udp_timeout: strToTime(udp_timeout),
		udp_nat_max: 65536,   /* ч.264: см. комментарий tproxy-in */
		stack: tcpip_stack,
	});

/* Diagnostic test inbounds: loopback-only mixed inbounds used by the auto-detection
 * daemon AND the routing Wizard (Ф2) to probe a site BOTH direct and through the main
 * path, so it can tell a blocked domain from a merely-slow one. They are bound to
 * 127.0.0.1 only (never exposed). The matching route rules (below) pin each inbound
 * to a fixed outbound. Emitted whenever the core config is generated by THIS
 * generator (main-out exists in every app-managed mode). */
if (!isEmpty(main_node))
	push(config.inbounds, {
		type: 'mixed',
		tag: 'auto-direct-in',
		listen: '127.0.0.1',
		listen_port: 5336,
	}, {
		type: 'mixed',
		tag: 'auto-proxy-in',
		listen: '127.0.0.1',
		listen_port: 5337,
	});

/* MultiDNS secure-via-proxy inbound: a loopback-only mixed (SOCKS5/HTTP) inbound the
 * mosdns secure pool's DoH/DoT rides when secure_via_proxy is set. Pinned to main-out by
 * a route rule below, so the encrypted DNS query actually egresses through the proxy
 * (fixing the old latent bug where DoH went direct despite the toggle). Bound to
 * 127.0.0.1 only (never exposed). Port 5338 is free (5330/5333/5335-5337/5453/5454 are used). */
if (mdns_proxy_in)
	push(config.inbounds, {
		type: 'mixed',
		tag: 'mdns-proxy-in',
		listen: '127.0.0.1',
		listen_port: mdns_proxy_port,
	});

/* Server inbounds. Master switch (the 'server' NamedSection, type 'ravnex') is the
 * UI promise "whether Ravnex accepts incoming connections at all" — firewall_pre.uc
 * honors it for the port accepts, so the generator must honor it the same way: a
 * shell-side audit (Ф9.6/D31) caught enabled server inbounds being generated (and
 * LISTENING) while the master switch was OFF. */
if (uci.get(uciconfig, uciserver, 'enabled') === '1')
uci.foreach(uciconfig, uciserver, (cfg) => {
	if (cfg.enabled !== '1')
		return;

	push(config.inbounds, {
		type: cfg.type,
		tag: 'cfg-' + cfg['.name'] + '-in',

		listen: cfg.address || '::',
		listen_port: strToInt(cfg.port),
		bind_interface: cfg.bind_interface,
		reuse_addr: strToBool(cfg.reuse_addr),
		tcp_fast_open: strToBool(cfg.tcp_fast_open),
		tcp_multi_path: strToBool(cfg.tcp_multi_path),
		udp_fragment: strToBool(cfg.udp_fragment),
		udp_timeout: strToTime(cfg.udp_timeout),
		network: cfg.network,

		/* AnyTLS */
		padding_scheme: cfg.anytls_padding_scheme,

		/* Hysteria */
		up_mbps: strToInt(cfg.hysteria_up_mbps),
		down_mbps: strToInt(cfg.hysteria_down_mbps),
		/* Ф9.6/D31 live audit: hiddify-core v5.1.0 rejects an OBJECT here for the
		 * Hysteria(1) inbound ("cannot unmarshal object ... HysteriaInboundOptions.obfs
		 * of type string") — hysteria1 obfs is a plain password STRING (salamander is
		 * the only scheme). The object form {type,password} is only valid for the
		 * Hysteria2 inbound (the UI offers obfs_type there). The old code sent the
		 * object whenever obfs_type was set (crash-loop + LKG rollback) and a raw
		 * password string otherwise (which the core decodes fine). */
		obfs: (cfg.type === 'hysteria') ? (cfg.hysteria_obfs_password || null) :
			((cfg.type === 'hysteria2' && cfg.hysteria_obfs_type) ? {
				type: cfg.hysteria_obfs_type,
				password: cfg.hysteria_obfs_password
			} : null),
		recv_window_conn: strToInt(cfg.hysteria_recv_window_conn),
		recv_window_client: strToInt(cfg.hysteria_recv_window_client),
		max_conn_client: strToInt(cfg.hysteria_max_conn_client),
		disable_mtu_discovery: strToBool(cfg.hysteria_disable_mtu_discovery),
		ignore_client_bandwidth: strToBool(cfg.hysteria_ignore_client_bandwidth),
		masquerade: cfg.hysteria_masquerade,

		/* Shadowsocks */
		method: (cfg.type === 'shadowsocks') ? cfg.shadowsocks_encrypt_method : null,
		password: (cfg.type in ['shadowsocks', 'shadowtls']) ? cfg.password : null,

		/* Tuic */
		congestion_control: cfg.tuic_congestion_control,
		auth_timeout: strToTime(cfg.tuic_auth_timeout),
		zero_rtt_handshake: strToBool(cfg.tuic_enable_zero_rtt),
		heartbeat: strToTime(cfg.tuic_heartbeat),

		/* MTProxy */
		concurrency: (cfg.type === 'mtproxy') ? strToInt(cfg.mtproxy_concurrency) : null,
		idle_timeout: (cfg.type === 'mtproxy') ? (cfg.mtproxy_idle_timeout || null) : null,
		handshake_timeout: (cfg.type === 'mtproxy') ? (cfg.mtproxy_handshake_timeout || null) : null,
		domain_fronting_port: (cfg.type === 'mtproxy') ? strToInt(cfg.domain_fronting_port) : null,
		domain_fronting_host: (cfg.type === 'mtproxy') ? (cfg.domain_fronting_host || null) : null,

		/* AnyTLS / HTTP / Hysteria (2) / Mixed / MTProxy / Socks / Trojan / Tuic / VLESS / VMess */
		users: (cfg.type === 'mtproxy') ?
			map(cfg.mtproxy_secrets || [], (s, i) => ({ name: 'user' + (i + 1), secret: s })) :
			(cfg.type !== 'shadowsocks') ? [
			{
				name: !(cfg.type in ['http', 'mixed', 'naive', 'socks']) ? 'cfg-' + cfg['.name'] + '-server' : null,
				username: cfg.username,
				password: cfg.password,

				/* Hysteria */
				auth: (cfg.hysteria_auth_type === 'base64') ? cfg.hysteria_auth_payload : null,
				auth_str: (cfg.hysteria_auth_type === 'string') ? cfg.hysteria_auth_payload : null,

				/* Tuic */
				uuid: cfg.uuid,

				/* VLESS / VMess */
				flow: cfg.vless_flow,
				alterId: strToInt(cfg.vmess_alterid)
			}
		] : null,

		multiplex: (cfg.multiplex === '1') ? {
			enabled: true,
			padding: strToBool(cfg.multiplex_padding),
			brutal: (cfg.multiplex_brutal === '1') ? {
				enabled: true,
				up_mbps: strToInt(cfg.multiplex_brutal_up),
				down_mbps: strToInt(cfg.multiplex_brutal_down)
			} : null
		} : null,

		tls: (cfg.tls === '1') ? {
			enabled: true,
			server_name: cfg.tls_sni,
			alpn: cfg.tls_alpn,
			min_version: cfg.tls_min_version,
			max_version: cfg.tls_max_version,
			cipher_suites: cfg.tls_cipher_suites,
			certificate_path: cfg.tls_cert_path,
			key_path: cfg.tls_key_path,
			acme: (cfg.tls_acme === '1') ? {
				domain: cfg.tls_acme_domain,
				data_directory: HP_DIR + '/certs',
				default_server_name: cfg.tls_acme_dsn,
				email: cfg.tls_acme_email,
				provider: cfg.tls_acme_provider,
				disable_http_challenge: strToBool(cfg.tls_acme_dhc),
				disable_tls_alpn_challenge: (cfg.tls_acme_dtac),
				alternative_http_port: strToInt(cfg.tls_acme_ahp),
				alternative_tls_port: strToInt(cfg.tls_acme_atp),
				external_account: (cfg.tls_acme_external_account === '1') ? {
					key_id: cfg.tls_acme_ea_keyid,
					mac_key: cfg.tls_acme_ea_mackey
				} : null,
				dns01_challenge: (cfg.tls_dns01_challenge === '1') ? {
					provider: cfg.tls_dns01_provider,
					access_key_id: cfg.tls_dns01_ali_akid,
					access_key_secret: cfg.tls_dns01_ali_aksec,
					region_id: cfg.tls_dns01_ali_rid,
					api_token: cfg.tls_dns01_cf_api_token
				} : null
			} : null,
			ech: (cfg.tls_ech_key) ? {
				enabled: true,
				key: split(cfg.tls_ech_key, '\n')
			} : null,
			reality: (cfg.tls_reality === '1') ? {
				enabled: true,
				private_key: cfg.tls_reality_private_key,
				short_id: cfg.tls_reality_short_id,
				max_time_difference: strToTime(cfg.tls_reality_max_time_difference),
				handshake: {
					server: cfg.tls_reality_server_addr,
					server_port: strToInt(cfg.tls_reality_server_port)
				}
			} : null
		} : null,

		transport: !isEmpty(cfg.transport) ? {
			type: cfg.transport,
			host: transport_host(cfg),
			path: cfg.http_path || cfg.ws_path,
			mode: (cfg.transport === 'xhttp') ? (cfg.xhttp_mode || 'auto') : null,
			x_padding_bytes: (is_singbox && cfg.transport === 'xhttp') ? xhttp_padding(cfg.xhttp_padding_bytes) : null,
			headers: cfg.ws_host ? {
				Host: cfg.ws_host
			} : null,
			method: cfg.http_method,
			max_early_data: strToInt(cfg.websocket_early_data),
			early_data_header_name: cfg.websocket_early_data_header,
			service_name: cfg.grpc_servicename,
			idle_timeout: strToTime(cfg.http_idle_timeout),
			ping_timeout: strToTime(cfg.http_ping_timeout)
		} : null
	});
});
/* Inbound end */

/* Outbound start */
config.endpoints = [];

/* Default outbounds */
config.outbounds = [
	{
		type: 'direct',
		tag: 'direct-out',
		/* ч.129 (ан-146): routing_mark делает direct-out «непустым» outbound —
		 * sing-box ≥1.12 (и upstream hiddify-core v5) FATAL'ит на detour к
		 * пустому direct outbound («detour to an empty direct outbound makes
		 * no sense» — DNS/NTP-серверы детурят в direct-out). Значение ТО ЖЕ,
		 * что раньше давал route.default_mark на этом dialer'е: проводного
		 * изменения нет, но detour теперь легален во всех версиях ядер. */
		routing_mark: strToInt(self_mark)
	},
	{
		type: 'block',
		tag: 'block-out'
	}
];

/* Build a URLTest outbound from one of three pool modes:
 *   auto   — every imported node participates (no list to maintain);
 *   prefer — the preferred node first, the rest behind a nested urltest
 *            (main-out-alt). The top-level group runs with a huge tolerance
 *            (PREFER_HOLD_TOLERANCE): the core only replaces a member whose
 *            history entry is MISSING (failed probe = treated as dead), so the
 *            preferred node is kept while it answers, regardless of latency.
 *            Without this the group drifted to the fastest node and — the worst
 *            part — never returned to the preferred one (a slower preferred
 *            node can never beat the pool's best by the tolerance again).
 *   manual — only the explicitly selected nodes (legacy behavior).
 *
 * STICKY SELECTION: the core keeps urltest state in RAM only (clash cache_file
 * does NOT persist urltest picks), so every regen+restart (UCI save, WAN up
 * trigger, subscription update) re-picked "first member with history" from a
 * fresh measurement — the node changed while the tolerance said otherwise.
 * init.d snapshots the running picks into $RUN_DIR/urltest_sticky before the
 * core stops; here each pool puts that node FIRST (the core's startup rule is
 * "first member with history wins unless another is faster by > tolerance"),
 * which makes the tolerance effectively apply across restarts too.
 *
 * Returns { outbound, extra } where extra is the flat list of node sections
 * used (for endpoint/outbound emission) and outbound may be null when the pool
 * ends up empty (caller falls back to a plain direct outbound so the config
 * stays valid and DNS/internet keep working). */

/* A preferred node must never lose its place to a merely-faster node. The core
 * compares uint16 ms delays: switch iff current > other + tolerance (mod
 * 65536). 30000 exceeds any real measured delay (probe timeout caps at ~15s)
 * without overflowing uint16, so "beaten by > tolerance" becomes impossible
 * while the preferred node still answers. Do NOT raise this to 65535: the
 * uint16 addition wraps and inverts the comparison for slow nodes. */
const PREFER_HOLD_TOLERANCE = 30000;

/* Sticky pick per group tag ("main-out=cfg-<sid>-out" lines written by init.d
 * from the live Clash API while the old core was still running). */
let urltest_sticky = {};
const sticky_raw = readfile(RUN_DIR + '/urltest_sticky');
if (sticky_raw)
	for (let sticky_line in split(trim(sticky_raw), '\n')) {
		const sm = match(sticky_line, /^([^=\s]+)=(\S+)$/);
		if (sm)
			urltest_sticky[sm[1]] = sm[2];
	}

/* Node tags the exit engine (hotswap.uc, Ф9.16) marked dead by its own
 * probes ($RUN_DIR/urltest_dead, outbound tags like cfg-<sid>-out). A sticky pick
 * pointing at such a node must NOT be fronted on the next (re)start, and the
 * node itself sinks to the END of every pool so a fresh core never starts on
 * it. Marks fade when the node measures alive again (the engine removes them). */
let urltest_dead = {};
const dead_raw = readfile(RUN_DIR + '/urltest_dead');
if (dead_raw)
	for (let dead_line in split(trim(dead_raw), '\n')) {
		const dt = trim(dead_line);
		if (length(dt))
			urltest_dead[dt] = true;
	}

/* Sink dead-marked nodes to the end of the pool. Returns null when nothing
 * needs reordering (also used as a "no marks" fast path). */
function dead_last(tags) {
	if (isEmpty(urltest_dead))
		return null;
	let alive = [], dead = [];
	for (let t in tags)
		push((urltest_dead[t] != null) ? dead : alive, t);
	if (!length(dead))
		return null;
	return [...alive, ...dead];
}

/* Hot Swap state contract for scripts/hotswap.uc (written next to
 * core_skipped.json at the end of generation; null = feature off/inapplicable). */
let hotswap_state = null;

/* Front the previously-running member of a pool (snapshot written by init.d
 * into $RUN_DIR/urltest_sticky before the old core stopped). The core's
 * startup selection is "first member with history wins unless another member
 * is faster by > tolerance", so fronting the old pick keeps the group on the
 * same node across regen+restarts — the configured tolerance then also applies
 * across restarts instead of re-picking whatever measured fastest that instant.
 * Returns the reordered tag list, or null when there is nothing to move. */
function sticky_first(tag_key, tags) {
	const raw_tag = urltest_sticky[tag_key];
	if (isEmpty(raw_tag))
		return null;
	/* A dead-marked node must never be fronted by the sticky snapshot. */
	if (urltest_dead[raw_tag] != null)
		return null;
	const i = index(tags, raw_tag);
	if (i <= 0)
		return null; /* absent from the (new) pool or already first */
	let nt = [raw_tag];
	for (let k, v in tags)
		if (k != i)
			push(nt, v);
	return nt;
}

function build_urltest(tag, mode, preferred, manual_nodes, interval, tolerance) {
	let outbounds = [],
	    extra = [],
	    rest = [],
	    pref = null;

	/* Fast failover defaults: an empty UCI value used to mean the core's own
	 * 3-minute default interval, so a dead node held the group for minutes.
	 * 30s / 150ms keeps switching responsive without measurable overhead. */
	interval = isEmpty(interval) ? '30' : interval;
	tolerance = isEmpty(tolerance) ? '150' : tolerance;

	if (mode === 'auto') {
		foreach_node((cfg) => {
			push(outbounds, `cfg-${cfg['.name']}-out`);
			push(extra, cfg['.name']);
		});
		const re = sticky_first(tag, outbounds);
		if (re)
			outbounds = re;
	} else if (mode === 'prefer') {
		if (!isEmpty(preferred) && uci.get_all(uciconfig, preferred) != null &&
		    hp_node_usable(preferred)) {
			pref = preferred;
			push(outbounds, `cfg-${pref}-out`);
			push(extra, pref);
		}
		foreach_node((cfg) => {
			if (cfg['.name'] === pref)
				return;
			push(rest, `cfg-${cfg['.name']}-out`);
			push(extra, cfg['.name']);
		});
		if (length(rest)) {
			/* Front the last failover pick inside the fallback pool only: the
			 * top-level order stays [preferred, alt] so a restart always hands
			 * traffic back to the preferred node while it answers. */
			const re = sticky_first(tag + '-alt', rest);
			if (re)
				rest = re;
			const de = dead_last(rest);
			if (de)
				rest = de;
			push(config.outbounds, {
				type: 'urltest',
				tag: tag + '-alt',
				outbounds: rest,
				interval: strToTime(interval),
				tolerance: strToInt(tolerance),
				/* Do NOT kill existing connections when the group re-ranks: an
				 * OAuth chain (Autodesk/Google social sign-in) is pinned to the
				 * client exit IP — a re-rank mid-flow (or a mere tolerance
				 * flap between close-latency nodes) switched the exit and
				 * looped socialSignInFailed forever. A dead node still tears
				 * down its own connections via tunnel error, so real failover
				 * latency is not lost. */
				interrupt_exist_connections: false
			});
			push(outbounds, tag + '-alt');
		}
	} else {
		for (let k in (manual_nodes || [])) {
			if (uci.get_all(uciconfig, k) == null)
				continue;
			if (!hp_node_usable(k))
				continue;
			push(outbounds, `cfg-${k}-out`);
			push(extra, k);
		}
		const re = sticky_first(tag, outbounds);
		if (re)
			outbounds = re;
	}

	if (!length(outbounds)) {
		/* Empty resolved pool (stale manual list, deleted preferred node, zero
		 * nodes in a non-auto mode): degrade to ALL existing nodes instead of a
		 * bare direct outbound — the latter silently killed the tunnel while the
		 * user still had perfectly working nodes configured. Only when there are
		 * truly no nodes at all does main-out fall back to direct. */
		let any = [], any_extra = [];
		foreach_node((cfg) => {
			push(any, `cfg-${cfg['.name']}-out`);
			push(any_extra, cfg['.name']);
		});
		if (!length(any))
			return { outbound: null, extra: extra };
		warn(sprintf('homeproxy: %s pool empty - falling back to all %d nodes.\n', tag, length(any)));
		/* extra MUST list the same sids as the urltest references: the caller emits
		 * one outbound per extra entry — an empty extra here left the group pointing
		 * at outbounds that were never emitted (fatal "non-existent outbound"). */
		const re = sticky_first(tag, any);
		if (re)
			any = re;
		const de = dead_last(any);
		if (de)
			any = de;
		return { outbound: {
			type: 'urltest',
			tag: tag,
			outbounds: any,
			interval: strToTime(interval),
			tolerance: strToInt(tolerance),
			/* See the alt-group comment above: re-rank must not tear sessions. */
			interrupt_exist_connections: false
		}, extra: any_extra };
	}

	/* Watchdog dead marks: sink dead-marked nodes to the END of the final pool
	 * (auto/manual pools and the prefer top-level [preferred, alt]). A fresh
	 * core picks "first member with history" after its first probe round, so a
	 * dead node at the tail never wins the startup race against living ones. */
	const dl = dead_last(outbounds);
	if (dl)
		outbounds = dl;

	return { outbound: {
		type: 'urltest',
		tag: tag,
		outbounds: outbounds,
		interval: strToTime(interval),
		/* prefer: hold the preferred node while it answers (see header comment);
		 * the user tolerance still governs the fallback pool and manual/auto. */
		tolerance: (mode === 'prefer') ? PREFER_HOLD_TOLERANCE : strToInt(tolerance),
		idle_timeout: (strToInt(interval) > 1800) ? `${interval * 2}s` : null,
		/* Re-rank must NOT tear existing connections: with 150 ms tolerance and
		 * close-latency nodes a re-rank fired constantly and every OAuth flow
		 * (Autodesk social sign-in) lost its pinned exit IP mid-chain — the
		 * service answered socialSignInFailed=True and the page looped. A
		 * genuinely dead node still kills its own sessions via tunnel error,
		 * so real failover speed is unaffected. */
		interrupt_exist_connections: false
	}, extra: extra };
}

/* manual-пул для kernel-группы (GitHub issue #18): резервы юзера + ТЕКУЩИЙ пик
 * контура из стейта движка. Design §3.2: manual держит ВЫБОР юзера — пик из
 * дашборда может лежать вне списка резервов; без него селектор после регена
 * не предложит его и sticky-resume потеряет пик. Пустой итог → весь пул
 * (fallback build_urltest). Хелпер объявлен ВЫШЕ обоих вызовов (lesson 405). */
function exit_manual_pool(contour) {
	const out = [...exit_reserves];
	try {
		const ms = ss_read_state(RUN_DIR + '/hotswap_state.json').data;
		let held = null;
		if (ms && type(ms.contours) === 'object' && type(ms.contours[contour]) === 'object' &&
		    type(ms.contours[contour].held) === 'string')
			held = ms.contours[contour].held;
		else if (contour === 'main-out' && ms && type(ms.active) === 'string')
			held = ms.active;   /* legacy mirror */
		const m = (held != null) ? match(held, /^cfg-([A-Za-z0-9]+)-out$/) : null;
		if (m && index(out, m[1]) < 0)
			push(out, m[1]);
	} catch (e) {}
	return out;
}

/* Main outbounds */
if (!isEmpty(main_node)) {
	let urltest_nodes = [];

	if (main_node === 'urltest') {
		/* Exit Engine (Ф9.16, D35a): kernel-группа main-out-auto + селектор main-out
		 * ВСЕГДА (когда пул ≥2) — движок владеет селектором без легаси-флага hotswap.
		 * Состав kernel-группы по exit_mode: prefer → [preferred, alt(rest)]
		 * (PREFER_HOLD_TOLERANCE держит preferred на уровне ядра — страховка при
		 * мёртвом движке), manual → резервы юзера (строгий список — дизайн §3.2 +
		 * GitHub issue #18; пустой список → весь пул через fallback build_urltest),
		 * auto → все узлы (kernel = страховка, политика — у движка). Легаси
		 * main_urltest_nodes в состав пула отдельно не входит — он мигрировал в
		 * резервы движка (exit_reserves). */
		const main_urltest_interval = uci.get(uciconfig, ucimain, 'main_urltest_interval');
		const main_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_urltest_tolerance');
		const hs_group = 'main-out-auto';
		const ut = build_urltest(hs_group, exit_kernel_mode, exit_preferred_opt,
			(exit_kernel_mode === 'manual') ? exit_manual_pool('main-out') : exit_reserves,
			main_urltest_interval, main_urltest_tolerance);
		if (ut.outbound) {
			push(config.outbounds, ut.outbound);
			urltest_nodes = ut.extra;
			if (length(ut.extra)) {
				/* Selector failover targets: the group + every node of its pool
				 * (prefer mode nests the alt subgroup too — deduped below). */
				let hs_members = [hs_group];
				for (let hs_sid in ut.extra) {
					const hs_tag = 'cfg-' + hs_sid + '-out';
					if (index(hs_members, hs_tag) < 0)
						push(hs_members, hs_tag);
				}
				for (let hs_tag in ut.outbound.outbounds)
					if (index(hs_members, hs_tag) < 0)
						push(hs_members, hs_tag);
				const hsd = dead_last(hs_members);
				if (hsd)
					hs_members = hsd;
				/* Резервы (exit_reserves): порядок пользователя, отфильтрованный
				 * по пулу; пусто → движок сканирует весь пул в порядке пула. */
				let hs_reserve_tags = [];
				for (let hs_sid in exit_reserves) {
					const hs_tag = 'cfg-' + hs_sid + '-out';
					if (index(ut.extra, hs_sid) >= 0 && index(hs_reserve_tags, hs_tag) < 0)
						push(hs_reserve_tags, hs_tag);
				}
				/* Sticky: resume on the engine's last active pick after a restart
				 * (it may be a direct node the engine failed over to); a dead-
				 * marked pick is never fronted. "prefer" is EXEMPT: the exit must
				 * return to the GROUP on every regen+restart — the group fronts
				 * the preferred node (top-level [preferred, alt] + urltest_sticky
				 * + PREFER_HOLD_TOLERANCE), and resuming the engine's last
				 * concrete pick here re-pinned a stale node forever. Otherwise
				 * the group. */
				let hs_default = null;
				if (exit_mode_opt !== 'prefer') {
					try {
						const hs_prev = ss_read_state(RUN_DIR + '/hotswap_state.json').data;
						if (hs_prev && type(hs_prev.active) === 'string' &&
						    index(hs_members, hs_prev.active) >= 0 &&
						    urltest_dead[hs_prev.active] == null)
							hs_default = hs_prev.active;
					} catch (e) { hs_default = null; }
				}
				if (isEmpty(hs_default))
					hs_default = hs_group;
				push(config.outbounds, {
					type: 'selector',
					tag: 'main-out',
					outbounds: hs_members,
					default: hs_default,
					/* Selector switches are pure API ops; never tear sessions. */
					interrupt_exist_connections: false
				});
				/* ч.67: human-readable names for the engine's last_reason — the
				 * daemon is UCI-blind by contract design, so the generator
				 * ships a tag→label map (missing label falls back to the sid). */
				let hs_labels = {};
				hs_labels[hs_group] = 'URLTest';
				for (let hs_tag in hs_members) {
					const hm = match(hs_tag, /^cfg-([A-Za-z0-9]+)-out$/);
					if (hm) {
						const hlbl = uci.get(uciconfig, hm[1], 'label');
						hs_labels[hs_tag] = (hlbl && length(hlbl)) ? '' + hlbl : hm[1];
					}
				}
				hotswap_state = {
					engine_version: 2,
					enabled: true,
					mode: exit_mode_opt,
					failback: exit_failback_opt,
					upgrade: exit_upgrade_opt,
					probe: {
						interval: (exit_probe_interval_opt < 5) ? 5 : ((exit_probe_interval_opt > 120) ? 120 : exit_probe_interval_opt),
						timeout: 6000
					},
					thresholds: {
						dead_after: exit_dead_after_opt,
						recovery_oks: exit_recovery_oks_opt,
						recovery_window: exit_recovery_window_opt,
						hysteresis_rounds: exit_hysteresis_opt,
						tolerance: strToInt(isEmpty(exit_tolerance_opt) ? '150' : exit_tolerance_opt) || 150
					},
					labels: hs_labels,
					contours: {
						'main-out': {
							selector: 'main-out',
							group: hs_group,
							preferred: (exit_kernel_mode === 'prefer') ? ('cfg-' + exit_preferred_opt + '-out') : null,
							manual_pick: null,
							reserves: hs_reserve_tags
						}
					}
				};
				warn(sprintf('homeproxy: Exit Engine on - URLTest group %s under main-out selector with %d members, mode %s (reserves %d).\n',
					hs_group, length(hs_members), exit_mode_opt, length(hs_reserve_tags)));
			}
		}
		else {
			/* Empty pool (no nodes yet): keep the config valid — direct egress means
			 * DNS + internet keep working, the user just has no proxying. */
			warn('homeproxy: URLTest pool is empty, main-out falls back to direct.\n');
			push(config.outbounds, { type: 'direct', tag: 'main-out' });
		}
	} else if (main_node === 'byedpi-out') {
		/* ByeDPI as main node: route through the local ByeDPI socks proxy.
		 * byedpi-out is a synthetic tag, not a real node section, so build the
		 * socks outbound here. Fall back to direct if ByeDPI is disabled. */
		if (byedpi_enabled === '1')
			push(config.outbounds, {
				type: 'socks',
				tag: 'main-out',
				server: '127.0.0.1',
				server_port: 5335,
				udp_over_tcp: (uci.get(uciconfig, ucimain, 'byedpi_udp_over_tcp') !== '0') || null
			});
		else
			push(config.outbounds, { type: 'direct', tag: 'main-out' });
	} else if (main_node === 'zapret-out') {
		/* Zapret as main node: egress direct but stamped with the Zapret routing_mark, so
		 * nft feeds the handshake to nfqws2 (desync everything, no proxy — the Zapret
		 * equivalent of standalone ByeDPI). Synthetic tag; fall back to plain direct if
		 * Zapret is disabled so the config stays valid. */
		if (zapret_enabled === '1')
			push(config.outbounds, {
				type: 'direct',
				tag: 'main-out',
				routing_mark: strToInt(zapret_mark)
			});
		else
			push(config.outbounds, { type: 'direct', tag: 'main-out' });
	} else if (main_node === 'direct-out') {
		/* Explicit "no proxy" fallback: used when the user has no subscription or
		 * node configured yet. Everything routes direct and the internet keeps
		 * working (DNS hijack → core → direct resolution). */
		push(config.outbounds, { type: 'direct', tag: 'main-out' });
	} else {
		const main_node_cfg = uci.get_all(uciconfig, main_node) || {};
		/* ── Hot Swap (ч.59) ──────────────────────────────────────────────────
		 * With Hot Swap enabled the specific main node is emitted under its own
		 * tag and `main-out` becomes a SELECTOR: [primary, backups…, cold spares].
		 * The hotswap daemon (scripts/hotswap.uc) probes the active node and the
		 * backups through the core's Clash API and re-pins the selector to a
		 * proven-alive member when the primary dies — a pure API switch, NO core
		 * restart, so direct traffic/DNS/other connections never notice. A fixed
		 * main node otherwise has NO failover at all (and the URLTest watchdog
		 * cannot pin URLTest groups — Clash API PUT is Selector-only), which is
		 * exactly the "proxy died, internet died with it" complaint.
		 * Needs the primary PLUS at least one other usable node; otherwise the
		 * classic shape ("the node IS main-out") is kept. */
		let hs_cands = [];
		if (!isEmpty(main_node_cfg)) {
			/* Exit Engine (Ф9.16): движок активен для узла-main ВСЕГДА, когда есть
			 * хоть один другой живой кандидат (раньше это был флаг hotswap=1).
			 * Резервы (exit_reserves) задают порядок, остальные usable-узлы идут
			 * как холодный запас в конце селектора. Invalid/dangling picks и сам
			 * primary пропускаются. */
			for (let hs_sid in exit_reserves) {
				if (hs_sid === main_node || index(hs_cands, hs_sid) >= 0)
					continue;
				if (uci.get_all(uciconfig, hs_sid) == null || !hp_node_usable(hs_sid))
					continue;
				if (has_outbound('cfg-' + hs_sid + '-out'))
					continue;
				push(hs_cands, hs_sid);
			}
			foreach_node((cfg) => {
				if (cfg['.name'] === main_node)
					return;
				if (index(hs_cands, cfg['.name']) >= 0)
					return;
				if (has_outbound('cfg-' + cfg['.name'] + '-out'))
					return;
				push(hs_cands, cfg['.name']);
			});
		}
		if (!isEmpty(main_node_cfg) && length(hs_cands)) {
			let hs_reserve_tags = [];
			const primary_tag = 'cfg-' + main_node + '-out';
			if (main_node_cfg.type in ['wireguard', 'amneziawg']) {
				push(config.endpoints, generate_endpoint(main_node_cfg));
				config.endpoints[length(config.endpoints)-1].tag = primary_tag;
			} else {
				push_outbound(config.outbounds, main_node_cfg);
				config.outbounds[length(config.outbounds)-1].tag = primary_tag;
			}
			/* Резервы движения: список пользователя задаёт ПОРЯДОК фейловера и
			 * горячих проб; узел-main при смерти уходит на первый живой резерв. */
			for (let hs_sid in hs_cands) {
				const gt = 'cfg-' + hs_sid + '-out';
				const bnc = uci.get_all(uciconfig, hs_sid) || {};
				if (bnc.type in ['wireguard', 'amneziawg']) {
					push(config.endpoints, generate_endpoint(bnc));
					config.endpoints[length(config.endpoints)-1].tag = gt;
				} else {
					push_outbound(config.outbounds, bnc);
					config.outbounds[length(config.outbounds)-1].tag = gt;
				}
				if (index(exit_reserves, hs_sid) >= 0)
					push(hs_reserve_tags, gt);
			}
			/* The selector is [primary, reserves…, cold spares]: the engine probes
			 * reserves first (hot dials); cold spares keep the group usable even
			 * if every reserve dies. */
			let hs_members = ['cfg-' + main_node + '-out'];
			for (let hs_sid in hs_cands)
				push(hs_members, 'cfg-' + hs_sid + '-out');
			const hs_dead = dead_last(hs_members);
			if (hs_dead)
				hs_members = hs_dead;
			/* Sticky: after a restart, resume on the engine's LAST ACTIVE pick
			 * (hotswap_state.json survives on tmpfs) instead of the urltest
			 * sticky snapshot — the snapshot may point at any pool member and
			 * would defeat the primary/failback model. Fallback: the primary.
			 * A dead-marked pick is never fronted. */
			let hs_default = null;
			try {
				const hs_prev = ss_read_state(RUN_DIR + '/hotswap_state.json').data;
				if (hs_prev && type(hs_prev.active) === 'string')
					hs_default = hs_prev.active;
			} catch (e) { hs_default = null; }
			if (isEmpty(hs_default) || index(hs_members, hs_default) < 0 ||
			    urltest_dead[hs_default] != null)
				hs_default = primary_tag;
			push(config.outbounds, {
				type: 'selector',
				tag: 'main-out',
				outbounds: hs_members,
				default: hs_default,
				/* Do NOT kill existing connections on switch: sessions riding a
				 * still-healthy node (failback, rotation) must survive; the dead
				 * primary's connections are torn down by its own tunnel error,
				 * and clients reconnect instantly onto the new pick. */
				interrupt_exist_connections: false
			});
			/* ч.67: tag→label map for the engine's last_reason (see the
			 * urltest branch — the daemon itself stays UCI-blind). */
			let hs_labels = {};
			for (let hs_tag in hs_members) {
				const hm = match(hs_tag, /^cfg-([A-Za-z0-9]+)-out$/);
				if (hm) {
					const hlbl = uci.get(uciconfig, hm[1], 'label');
					hs_labels[hs_tag] = (hlbl && length(hlbl)) ? '' + hlbl : hm[1];
				}
			}
			hotswap_state = {
				engine_version: 2,
				enabled: true,
				mode: 'manual',
				failback: exit_failback_opt,
				upgrade: false,
				probe: {
					interval: (exit_probe_interval_opt < 5) ? 5 : ((exit_probe_interval_opt > 120) ? 120 : exit_probe_interval_opt),
					timeout: 6000
				},
				thresholds: {
					dead_after: exit_dead_after_opt,
					recovery_oks: exit_recovery_oks_opt,
					recovery_window: exit_recovery_window_opt,
					hysteresis_rounds: exit_hysteresis_opt,
					tolerance: strToInt(isEmpty(exit_tolerance_opt) ? '150' : exit_tolerance_opt) || 150
				},
				labels: hs_labels,
				contours: {
					'main-out': {
						selector: 'main-out',
						group: null,
						preferred: null,
						manual_pick: primary_tag,
						reserves: hs_reserve_tags
					}
				}
			};
			warn(sprintf('homeproxy: Exit Engine on - main-out selector with %d members, mode manual (reserves %d, primary %s).\n',
				length(hs_members), length(hs_reserve_tags), primary_tag));
		} else {
			if (main_node_cfg.type in ['wireguard', 'amneziawg']) {
				push(config.endpoints, generate_endpoint(main_node_cfg));
				config.endpoints[length(config.endpoints)-1].tag = 'main-out';
			} else {
				push_outbound(config.outbounds, main_node_cfg);
				config.outbounds[length(config.outbounds)-1].tag = 'main-out';
			}
		}
	}

	if (main_udp_node === 'urltest') {
		const main_udp_urltest_interval = uci.get(uciconfig, ucimain, 'main_udp_urltest_interval');
		const main_udp_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_udp_urltest_tolerance');
		/* Exit Engine (Ф9.16, второй контур): kernel-группа main-udp-auto под
		 * селектором main-udp-out (тег правил сохранён). Режим/пороги общие с main
		 * (manual → строгий список + пик контура, как у main — issue #18);
		 * preferred у UDP свой (exit_udp_preferred, иначе наследует main). Резервы
		 * общие, применяются к пулу UDP. Правила ссылаются на main-udp-out — тег
		 * селектора, поэтому правила не меняются. */
		const udp_pref_sid = (!isEmpty(exit_udp_preferred_opt) &&
			uci.get_all(uciconfig, exit_udp_preferred_opt) != null &&
			hp_node_usable(exit_udp_preferred_opt)) ? exit_udp_preferred_opt : null;
		const udp_kernel_mode = (exit_kernel_mode === 'prefer' && udp_pref_sid != null) ? 'prefer'
			: ((exit_kernel_mode === 'manual') ? 'manual' : 'auto');
		const ut = build_urltest('main-udp-auto', udp_kernel_mode, udp_pref_sid,
			(udp_kernel_mode === 'manual') ? exit_manual_pool('main-udp-out') : exit_reserves,
			main_udp_urltest_interval, main_udp_urltest_tolerance);
		if (ut.outbound && length(ut.extra) >= 2) {
			push(config.outbounds, ut.outbound);
			let udp_members = ['main-udp-auto'];
			for (let hs_sid in ut.extra) {
				const hs_tag = 'cfg-' + hs_sid + '-out';
				if (index(udp_members, hs_tag) < 0)
					push(udp_members, hs_tag);
			}
			for (let hs_tag in ut.outbound.outbounds)
				if (index(udp_members, hs_tag) < 0)
					push(udp_members, hs_tag);
			const udd = dead_last(udp_members);
			if (udd)
				udp_members = udd;
			push(config.outbounds, {
				type: 'selector',
				tag: 'main-udp-out',
				outbounds: udp_members,
				default: 'main-udp-auto',
				interrupt_exist_connections: false
			});
			let udp_reserve_tags = [];
			for (let hs_sid in exit_reserves) {
				const hs_tag = 'cfg-' + hs_sid + '-out';
				if (index(ut.extra, hs_sid) >= 0 && index(udp_reserve_tags, hs_tag) < 0)
					push(udp_reserve_tags, hs_tag);
			}
			let udp_labels = {};
			udp_labels['main-udp-auto'] = 'URLTest (UDP)';
			for (let hs_tag in udp_members) {
				const hm = match(hs_tag, /^cfg-([A-Za-z0-9]+)-out$/);
				if (hm) {
					const hlbl = uci.get(uciconfig, hm[1], 'label');
					udp_labels[hs_tag] = (hlbl && length(hlbl)) ? '' + hlbl : hm[1];
				}
			}
			/* Контур UDP в контракт (hotswap_state может быть null, когда main —
			 * синтетика: тогда контракт создаётся здесь, только с UDP-контором). */
			if (hotswap_state == null)
				hotswap_state = {
					engine_version: 2,
					enabled: true,
					mode: exit_mode_opt,
					failback: exit_failback_opt,
					upgrade: exit_upgrade_opt,
					probe: {
						interval: (exit_probe_interval_opt < 5) ? 5 : ((exit_probe_interval_opt > 120) ? 120 : exit_probe_interval_opt),
						timeout: 6000
					},
					thresholds: {
						dead_after: exit_dead_after_opt,
						recovery_oks: exit_recovery_oks_opt,
						recovery_window: exit_recovery_window_opt,
						hysteresis_rounds: exit_hysteresis_opt,
						tolerance: strToInt(isEmpty(exit_tolerance_opt) ? '150' : exit_tolerance_opt) || 150
					},
					labels: {},
					contours: {}
				};
			for (let ulk, ulv in udp_labels)
				hotswap_state.labels[ulk] = ulv;
			hotswap_state.contours['main-udp-out'] = {
				selector: 'main-udp-out',
				group: 'main-udp-auto',
				preferred: (udp_kernel_mode === 'prefer') ? ('cfg-' + udp_pref_sid + '-out') : null,
				manual_pick: null,
				reserves: udp_reserve_tags
			};
			warn(sprintf('homeproxy: Exit Engine on - UDP group main-udp-auto under main-udp-out selector with %d members (reserves %d).\n',
				length(udp_members), length(udp_reserve_tags)));
			urltest_nodes = [...urltest_nodes, ...filter(ut.extra, (l) => !~index(urltest_nodes, l))];
		} else {
			/* Мало узлов для UDP-контура (0/1): прежняя форма — голая группа под
			 * ТЕГОМ ПРАВИЛ main-udp-out или direct; движок UDP не владеет. */
			if (ut.outbound) {
				ut.outbound.tag = 'main-udp-out';
				push(config.outbounds, ut.outbound);
				urltest_nodes = [...urltest_nodes, ...filter(ut.extra, (l) => !~index(urltest_nodes, l))];
			} else {
				warn('homeproxy: UDP URLTest pool is empty, main-udp-out falls back to direct.\n');
				push(config.outbounds, { type: 'direct', tag: 'main-udp-out' });
			}
		}
	} else if (dedicated_udp_node && main_udp_node === 'byedpi-out') {
		/* ByeDPI as dedicated UDP node — same synthetic-tag handling as above */
		if (byedpi_enabled === '1')
			push(config.outbounds, {
				type: 'socks',
				tag: 'main-udp-out',
				server: '127.0.0.1',
				server_port: 5335,
				udp_over_tcp: (uci.get(uciconfig, ucimain, 'byedpi_udp_over_tcp') !== '0') || null
			});
		else
			push(config.outbounds, { type: 'direct', tag: 'main-udp-out' });
	} else if (dedicated_udp_node && main_udp_node === 'zapret-out') {
		/* Zapret as dedicated UDP node — direct egress + Zapret mark; nfqws2 desyncs
		 * UDP/QUIC too (unlike ByeDPI). Synthetic tag, fall back to plain direct. */
		if (zapret_enabled === '1')
			push(config.outbounds, {
				type: 'direct',
				tag: 'main-udp-out',
				routing_mark: strToInt(zapret_mark)
			});
		else
			push(config.outbounds, { type: 'direct', tag: 'main-udp-out' });
	} else if (dedicated_udp_node) {
		const main_udp_node_cfg = uci.get_all(uciconfig, main_udp_node) || {};
		if (main_udp_node_cfg.type in ['wireguard', 'amneziawg']) {
			push(config.endpoints, generate_endpoint(main_udp_node_cfg));
			config.endpoints[length(config.endpoints)-1].tag = 'main-udp-out';
		} else {
			push_outbound(config.outbounds, main_udp_node_cfg);
			config.outbounds[length(config.outbounds)-1].tag = 'main-udp-out';
		}
	}

	for (let i in urltest_nodes) {
		const urltest_node = uci.get_all(uciconfig, i);
		if (!urltest_node) continue;
		/* Duplicate-tag guard (Hot Swap): with Hot Swap on, the selector pool
		 * already emitted these nodes under cfg-<sid>-out; a second emission is
		 * a fatal "duplicate outbound tag" for the core. (The other emission
		 * loops — advanced rules — carry the same guard.) */
		if (has_outbound('cfg-' + i + '-out')) continue;
		if (urltest_node.type in ['wireguard', 'amneziawg']) {
			push(config.endpoints, generate_endpoint(urltest_node));
			config.endpoints[length(config.endpoints)-1].tag = 'cfg-' + i + '-out';
		} else {
			push_outbound(config.outbounds, urltest_node);
			config.outbounds[length(config.outbounds)-1].tag = 'cfg-' + i + '-out';
		}
	}

	/* The dedicated geo-out selector (ч.53-ч.66) is REMOVED (ч.69): geo-sensitive
	 * hosts ride the regular main-out path and a refused exit is surfaced by the
	 * engine's exit-health check instead of an auto-rotation machinery. */

	/* D35b: routing_node outbounds are emitted by EXISTENCE of enabled=1
	 * sections — NO show_advanced_rules gate, NO mode gate. The old flag
	 * silently dropped user-created chains from the generated config while
	 * the sections kept existing (a silent behavior change; the editors now
	 * live on the Service rules page and the flag gates ONLY the raw
	 * routing_rule emission below). */
	{
		let adv_urltest_nodes = [],
		    adv_routing_nodes = [];

		uci.foreach(uciconfig, uciroutingnode, (cfg) => {
			if (cfg.enabled !== '1') return;

			if (cfg.node === 'urltest') {
				const existing_urltest_nodes = usable_nodes(cfg.urltest_nodes);
				push(config.outbounds, {
					type: 'urltest',
					tag: 'cfg-' + cfg['.name'] + '-out',
					outbounds: map(existing_urltest_nodes, (k) => `cfg-${k}-out`),
					url: cfg.urltest_url,
					interval: strToTime(cfg.urltest_interval),
					tolerance: strToInt(cfg.urltest_tolerance),
					idle_timeout: strToTime(cfg.urltest_idle_timeout),
					interrupt_exist_connections: strToBool(cfg.urltest_interrupt_exist_connections)
				});
				adv_urltest_nodes = [...adv_urltest_nodes, ...filter(existing_urltest_nodes, (l) => !~index(adv_urltest_nodes, l))];
			} else {
				const outbound = uci.get_all(uciconfig, cfg.node) || {};
				/* Skip a routing node whose target proxy node is empty or dangling —
				 * otherwise push_outbound() appends a null outbound and the next line
				 * dereferences it, crashing config generation (no file is written). */
				if (isEmpty(outbound)) return;
				/* Skip a target the selected core cannot load — emitting it would
				 * FATAL the core; get_outbound() reroutes references to main-out. */
				if (!hp_node_usable(cfg.node)) return;
				/* Duplicate tag guard: two routing nodes (or a routing node + the main
				 * URLTest pool) may reference the SAME proxy node — a second emission
				 * of 'cfg-X-out' is a fatal "duplicate tag" for the core. */
				if (has_outbound('cfg-' + cfg.node + '-out'))
					return;
				if (outbound.type in ['wireguard', 'amneziawg']) {
					push(config.endpoints, generate_endpoint(outbound));
					config.endpoints[length(config.endpoints)-1].bind_interface = cfg.bind_interface;
					config.endpoints[length(config.endpoints)-1].detour = get_outbound(cfg.outbound);
				} else {
					push_outbound(config.outbounds, outbound);
					config.outbounds[length(config.outbounds)-1].bind_interface = cfg.bind_interface;
					const adv_chain_detour = get_outbound(cfg.outbound);
					if (adv_chain_detour)
						config.outbounds[length(config.outbounds)-1].detour = adv_chain_detour;
				}
				push(adv_routing_nodes, cfg.node);
			}
		});

		for (let i in filter(adv_urltest_nodes, (l) => !~index(adv_routing_nodes, l))) {
			if (has_outbound('cfg-' + i + '-out')) continue;
			const urltest_node = uci.get_all(uciconfig, i);
			if (!urltest_node) continue;
			if (urltest_node.type in ['wireguard', 'amneziawg'])
				push(config.endpoints, generate_endpoint(urltest_node));
			else
				push_outbound(config.outbounds, urltest_node);
		}
	}
}

if (isEmpty(config.endpoints))
	config.endpoints = null;
/* Outbound end */

/* Routing rules start */
/* Default settings */
config.route = {
	rules: [
		{
			inbound: 'dns-in',
			action: 'hijack-dns'
		},
		{
			/* Explicit sniff action — emit for BOTH cores. hiddify-core's legacy inbound
			 * `sniff: true` does NOT sniff QUIC (TLS works, QUIC doesn't), so without this
			 * route action QUIC carries no SNI and can't be domain-routed (e.g. YouTube
			 * video → zapret-out fell through to direct). Device-confirmed on hiddify-core
			 * 1.13.1; both cores support the action. */
			action: 'sniff'
		}
	],
	rule_set: [],
	auto_detect_interface: isEmpty(default_interface) ? true : null,
	default_interface: default_interface,
	default_mark: strToInt(self_mark)
};

/* сеанс 187/188: негативный стиринг на СЛОЕ МАРШРУТА — дополнение к DNS-отказу
 * (dns.rules REJECT этого ядра не срабатывает ни в одной форме — mosdns-матчер
 * и инлайн, и SVCB-oauth тоже молчат; ЖИВОЙ ФАКТ). Route-reject работает по
 * имени ПОСЛЕ сниффа SNI: соединение к мёртвому пулу получает мгновенный отказ
 * и плеер ротит — тот же UX, что мгновенный DNS-отказ. 188: блок поднял на
 * позиции 3/4 — сразу после hijack-dns/sniff и ВЫШЕ диагностических inbound-пинов
	 * и авто-direct/пер-сорсных правил: в позиции 8/9 (сеанс 187) пер-сорсные правила
	 * матчили первыми и уводили живой трафик мимо отказа. 188-доказательство: только
	 * domain_keyword матчится (label-trie — подстрочный суффикс каталога не
	 * лейбл-граница), route-reject = reset @ 4.7 мс при живом контроле 404 @ 21 мс.
	 * rule_set-путь в route.rules выпрошен инертным — decl остаётся для dns-правила. */
	if ((uci.get(uciconfig, 'config', 'yt_steer_dead') || '0') === '1' &&
		access(HP_DIR + '/resources/yt_steer_dead.json')) {
		let steer_inline = [];
		let steer_file = json(readfile(HP_DIR + '/resources/yt_steer_dead.json'));
		for (let sr in (steer_file.rules || []))
			for (let sd in (sr.domain_keyword || sr.domain_suffix || []))
				push(steer_inline, sd);
		if (length(steer_inline)) {
			push(config.route.rules, {
				domain_keyword: steer_inline,
				network: 'udp',
				port: [443],
				action: 'reject'
			});
			push(config.route.rules, {
				domain_keyword: steer_inline,
				network: 'tcp',
				port: [443],
				action: 'reject'
			});
		}
		/* 188-эксперимент: rule_set-путь на route-слое с keyword-файлом —
		 * dns2 (rule_set) с keyword-формой ЗАЖЁГСЯ живьём (REFUSED :5333),
		 * route-вариант проверяется тем же дискриминатором; файл rule_set
		 * горячо перегружается ядром (см. learned hot-reload) — тогда
		 * выученные пулы применяются БЕЗ рестартов. */
		push(config.route.rules, {
			rule_set: 'yt-steer-dead',
			network: 'udp',
			port: [443],
			action: 'reject'
		});
		push(config.route.rules, {
			rule_set: 'yt-steer-dead',
			network: 'tcp',
			port: [443],
			action: 'reject'
		});
	}

/* Diagnostic test inbounds: pin each to a fixed outbound so the auto-detection daemon
 * and the routing Wizard can probe a site direct vs through the main path. These must sit
 * ABOVE the resolve/sniff and region rules so the probes are not themselves re-routed by
 * the normal rules. The proxy side forces `main-out` — which already IS byedpi-out /
 * zapret-out when those are the configured main node — so detection stays faithful to the
 * user's chosen anti-DPI path. Same gate as the inbounds: main-out must exist
 * (a dangling outbound reference would FATAL the core — ч.65-class trap). */
if (!isEmpty(main_node)) {
	push(config.route.rules, {
		inbound: 'auto-direct-in',
		action: 'route',
		outbound: 'direct-out'
	});
	push(config.route.rules, {
		inbound: 'auto-proxy-in',
		action: 'route',
		outbound: 'main-out'
	});
}

/* MultiDNS secure-via-proxy: pin the dedicated mdns-proxy-in inbound to main-out so the
 * mosdns secure pool's DoH/DoT really egresses through the proxy. Also emitted with the
 * inbound itself (above), so the pair is never split — the split was the historical
 * "5338 never bound" trap. Placed ABOVE resolve/region rules like the automation pair. */
if (mdns_proxy_in) {
	push(config.route.rules, {
		inbound: 'mdns-proxy-in',
		action: 'route',
		outbound: 'main-out'
	});
}

/* Routing rules */
/* Ф4.2 (U7): user-defined lists — enabled sections of type 'user_list'.
 * kind 'direct' rules sit right after the per-service rules (explicit user
 * intent, engines allowed — same tier as the service rules); kind 'proxy'
 * rules sit AFTER the RU-protect guard, so the "RU never via proxy" invariant
 * stays ironclad for proxy lists (a RU domain in a proxy list routes direct).
 * Only sections named ul_<id> are ours; foreign sections never break
 * generation. */
let user_lists = [];
uci.foreach(uciconfig, 'user_list', (s) => {
	const sid = '' + s['.name'];
	if (!match(sid, /^ul_[A-Za-z0-9_]{1,64}$/))
		return;
	push(user_lists, {
		sid,
		on: (s.enabled === '1'),
		kind: (s.kind === 'direct') ? 'direct' : 'proxy',
		ctype: (s.ctype === 'ips') ? 'ips' : 'domains',
		node: '' + (s.node || ''),
		urltest_nodes: (type(s.urltest_nodes) === 'array') ? s.urltest_nodes : []
	});
});

/* Ф4.2: the effective outbound of a user list. Engine availability mirrors the
 * per-service rules exactly (a disabled engine falls back like a rule does):
 * direct lists fall back to direct-out, proxy lists to main-out. A real node
 * must be a node section; anything else rides the default exit of the kind. */
const user_list_outbound = (l) => {
	if (l.kind === 'direct') {
		if (l.node === 'zapret-out')
			return (zapret_enabled === '1') ? 'zapret-out' : 'direct-out';
		if (l.node === 'byedpi-out')
			return (byedpi_enabled === '1') ? 'byedpi-out' : 'direct-out';
		return 'direct-out';
	}
	if (l.node === 'byedpi-out')
		return (byedpi_enabled === '1') ? 'byedpi-out' : 'main-out';
	if (l.node === 'zapret-out')
		return (zapret_enabled === '1') ? 'zapret-out' : 'main-out';
	if (l.node === 'urltest')
		return 'user-' + l.sid + '-out';
	const nc = uci.get_all(uciconfig, l.node);
	return (nc && nc['.type'] === 'node') ? 'cfg-' + l.node + '-out' : 'main-out';
};

/* Ф4.2: prepare ONE user list — build the outbound (reusing existing tags),
 * declare the watched local rule-set file, and return the outbound tag
 * (null = the list must not emit, e.g. an empty urltest pool). */
const user_list_rs_seen = {};
const user_list_prepare = (l) => {
	let ob = user_list_outbound(l);
	if (l.kind === 'proxy' && l.node === 'urltest') {
		const tag = 'user-' + l.sid + '-out';
		const ut_nodes = usable_nodes(l.urltest_nodes);
		if (!length(ut_nodes))
			return null;
		if (!has_outbound(tag)) {
			push(config.outbounds, {
				type: 'urltest',
				tag,
				outbounds: map(ut_nodes, (k) => `cfg-${k}-out`),
				interval: strToTime(uci.get(uciconfig, l.sid, 'urltest_interval') || '180'),
				tolerance: strToInt(uci.get(uciconfig, l.sid, 'urltest_tolerance') || '150'),
				idle_timeout: '1800s'
			});
			for (let n in ut_nodes) {
				if (has_outbound('cfg-' + n + '-out')) continue;
				const nc = uci.get_all(uciconfig, n);
				if (!nc) continue;
				if (nc.type in ['wireguard', 'amneziawg']) {
					push(config.endpoints, generate_endpoint(nc));
					config.endpoints[length(config.endpoints)-1].tag = 'cfg-' + n + '-out';
				} else {
					push_outbound(config.outbounds, nc);
					config.outbounds[length(config.outbounds)-1].tag = 'cfg-' + n + '-out';
				}
			}
		}
		ob = tag;
	} else if (l.kind === 'proxy' && match(ob, /^cfg-/)) {
		/* The outbound tag carries the node section — make sure it exists. */
		if (!has_outbound(ob)) {
			const nc = uci.get_all(uciconfig, l.node);
			if (!nc) {
				return 'main-out';
			} else if (nc.type in ['wireguard', 'amneziawg']) {
				push(config.endpoints, generate_endpoint(nc));
				config.endpoints[length(config.endpoints)-1].tag = ob;
			} else {
				push_outbound(config.outbounds, nc);
				config.outbounds[length(config.outbounds)-1].tag = ob;
			}
		}
	}
	if (!user_list_rs_seen['user-' + l.sid]) {
		user_list_rs_seen['user-' + l.sid] = true;
		push(config.route.rule_set, {
			type: 'local',
			tag: 'user-' + l.sid,
			format: 'source',
			path: HP_DIR + '/resources/lists/' + l.sid + '.json'
		});
	}
	return ob;
};

if (!isEmpty(main_node)) {
	/* Avoid DNS loop */
	/* sing-box-extended supports action object; hiddify-core (standard sing-box 1.12) expects a string tag. */
	const default_resolver_server = is_bypass_mode(routing_mode) ? 'region-dns' :
	                                (routing_mode === 'proxy_banned_ru') ? 'russia-dns' : 'default-dns';
	config.route.default_domain_resolver = is_singbox ? {
		action: 'route',
		server: default_resolver_server,
		strategy: (ipv6_support !== '1') ? 'prefer_ipv4' : null
	} : default_resolver_server;

	/* Direct list (not needed in proxy_banned_ru — direct is the default).
	 * Ф4.1: IP-shaped entries of direct_list ride the paired inline 'direct-ip'
	 * rule-set in the SAME rule (a single rule_set array — one match attempt,
	 * domain keywords and ip_cidr together). */
	if ((length(direct_domain_list) || length(direct_ips)) && routing_mode !== 'proxy_banned_ru') {
		let direct_rs = [];
		if (length(direct_domain_list))
			push(direct_rs, 'direct-domain');
		if (length(direct_ips))
			push(direct_rs, 'direct-ip');
		push(config.route.rules, {
			rule_set: direct_rs,
			action: 'route',
			outbound: 'direct-out'
		});
	}

	/* Main UDP out — only in `global` here (everything proxied, no carve-outs, order moot).
	 * In selective modes (RU/reverse) the UDP-node rule is emitted LAST, after the region
	 * baseline + per-service overrides, so domestic/override UDP isn't swept into it. */
	if (dedicated_udp_node && routing_mode === 'global')
		push(config.route.rules, {
			network: 'udp',
			action: 'route',
			outbound: 'main-udp-out'
		});

	config.route.final = (routing_mode === 'proxy_banned_ru') ? 'direct-out' : 'main-out';

	/* Local rule-set fallback (issue #12). The core initializes remote
	 * rule-sets SYNCHRONOUSLY at start; on a cold boot (fresh flash or a
	 * wiped /var/run — no cache.db yet) the first failing download is FATAL
	 * and the proxy never comes up ("FATAL start service: initialize
	 * rule-set"). `initial_path` gives the core a local first-load source:
	 * when the file exists it is used for the initial load and the network
	 * fetch runs in the background per update_interval; a MISSING file only
	 * logs a warn and falls back to the normal fetch (verified against
	 * sing-box 1.14 route/rule/rule_set_remote.go). {tag} is substituted by
	 * the core itself. Emitted for the sing-box family only — hiddify-core
	 * (1.13 dialect) does not know the option and would reject the config.
	 * Gated on the dir EXISTING so users who never use the feature get
	 * byte-identical configs (and no per-rule-set warn noise).
	 * UI: Client Settings → Routing «Local rule-set fallback»; the files are
	 * pre-seeded by app_rulesets_local_seed (rulesets_seed.uc). */
	const ruleset_local_dir = (uci.get(uciconfig, ucimain, 'ruleset_local') !== '0')
		? ('' + (uci.get(uciconfig, ucimain, 'ruleset_local_path') || '/etc/ravnex/rulesets'))
		: '';
	const ruleset_initial_path = (is_singbox && length(ruleset_local_dir) &&
		substr(ruleset_local_dir, 0, 1) === '/' && index(ruleset_local_dir, '..') < 0 &&
		access(ruleset_local_dir))
		? (ruleset_local_dir + '/{tag}.srs')
		: null;

	/* Rule set */
	/* Direct list (domain keywords) + paired IP twin ('direct-ip', Ф4.1) —
	 * both inline: the direct_list apply path is a full generate+reload
	 * (acllist_write → op_spawn('reload')), so inline is hot enough and the
	 * entries never sit in the config as dead keyword strings. */
	if (length(direct_domain_list) && routing_mode !== 'proxy_banned_ru')
		push(config.route.rule_set, {
			type: 'inline',
			tag: 'direct-domain',
			rules: [
				{
					domain_keyword: direct_domain_list,
				}
			]
		});
	if (length(direct_ips) && routing_mode !== 'proxy_banned_ru')
		push(config.route.rule_set, {
			type: 'inline',
			tag: 'direct-ip',
			rules: [
				{
					ip_cidr: direct_ips,
				}
			]
		});

	/* Proxy list — also used in proxy_banned_ru for proxy-domain → main-out.
	 * Backed by a WATCHED local rule-set file (resources/proxy_domain.json, written by
	 * sync_learned_rulesets() from proxy_list.txt + the learned auto_proxy_list.txt). The
	 * core hot-reloads it on file change, so Automation can apply learned sites with no
	 * service restart. Always emitted (the file always exists, possibly empty) so hot
	 * reloads work even when the list starts empty. */
	push(config.route.rule_set, {
		type: 'local',
		tag: 'proxy-domain',
		format: 'source',
		path: HP_DIR + '/resources/proxy_domain.json'
	});

	/* Learned IP list (Automation, B): IP-only destinations (games/apps without SNI)
	 * that fail direct but work via the proxy. WATCHED local rule-set file
	 * (resources/auto_ip.json) so it hot-reloads without a restart. */
	if (automation_enabled === '1' && !isEmpty(main_node))
		push(config.route.rule_set, {
			type: 'local',
			tag: 'auto-ip',
			format: 'source',
			path: HP_DIR + '/resources/auto_ip.json'
		});

	/* s201 СЕМЕЙНАЯ НОГА: члены семьи (сиблинги-домены + голые CDN-IP, со-
	 * наблюдённые с живым якорем) следуют ноге якоря БЕЗ собственного
	 * вердикта — философия юзера «сайт целиком, как в Global»; жёстко —
	 * только RU (RU-члены невозможны по гвардам демона, порядок правил ниже —
	 * вторая линия). ДВА watched-файла от демона (sync_families):
	 *   family-route.json — СМЕШАННЫЙ: на него смотрят ОБА route-правила
	 *     ниже (UDP/443-reject = QUIC-drop вслед + route → main-out);
	 *   family-domain.json — domains-only близнец для DNS-зеркала
	 *     (B6.5: DNS-правило с ip_cidr = FATAL sing-box 1.14+).
	 * Гейт как у auto-ip; always-emitted НЕ нужен: без включённой автоматизации
	 * семьи не существует (демон выключен — файлы не пишутся). */
	if (automation_enabled === '1' && !isEmpty(main_node)) {
		push(config.route.rule_set, {
			type: 'local',
			tag: 'family-route',
			format: 'source',
			path: HP_DIR + '/resources/family_route.json'
		});
		push(config.route.rule_set, {
			type: 'local',
			tag: 'family-domain',
			format: 'source',
			path: HP_DIR + '/resources/family_domain.json'
		});
	}

	/* B6.3: MANUAL IP entries (static proxy_list + manual "always proxy" pins)
	 * in their OWN watched rule-set file, emitted UNCONDITIONALLY (empty is a
	 * no-op) — a hand-pinned IP must route with Automation off too. The
	 * matching rule is emitted after the proxy-domain rule below. */
	push(config.route.rule_set, {
		type: 'local',
		tag: 'manual-ip',
		format: 'source',
		path: HP_DIR + '/resources/manual_ip.json'
	});

	/* s200 QUIC-drop: транспорт обхода. Хост обходной ноги едет прокси ПО TCP —
	 * браузерный QUIC (UDP/443) сквозь socks-ногу не едет никогда, он идёт сырым
	 * direct'ом, где h3-потоки режутся посреди стрима (живой класс myspace
	 * 2026-11-13: VN-щуп «alive», браузер ловит ERR_QUIC). Reject-правило ниже
	 * (рядом с per-origin googlevideo) роняет UDP/443 к этим доменам → браузер
	 * мгновенно падает на TCP, который едет по обходной ноге. WATCHED-файл пишет
	 * sync_learned_rulesets() (+ state-флаги st.quic_drop сливает демон) —
	 * hot-reload вместе с learned-набором. Always emitted (пустой = no-op,
	 * пустой rules[] валиден — прецедент manual-ip). */
	push(config.route.rule_set, {
		type: 'local',
		tag: 'auto-quic-drop',
		format: 'source',
		path: HP_DIR + '/resources/auto_quic_drop.json'
	});

	/* Ф4.2 (U7): user list rule-set files (watched, one per list) — declared
	 * in user_list_prepare() at rule emission time below. */

	/* RU-geo databases (RU-protect): watched local rule-set files refreshed by
	 * ru_geo_update.sh. Always emitted (possibly empty) so the geo_update path
	 * hot-reloads the files without a service restart. */
	push(config.route.rule_set, {
		type: 'local',
		tag: 'ru-geoip',
		format: 'source',
		path: HP_DIR + '/resources/ru_geoip.json'
	});
	push(config.route.rule_set, {
		type: 'local',
		tag: 'ru-geosite',
		format: 'source',
		path: HP_DIR + '/resources/ru_geosite.json'
	});

	if (is_selective_mode(routing_mode)) {
		/* Resolve domains before routing — prevents the proxy server from doing its own DNS
		 * resolution, and (reverse) lets the geoip baseline match by IP. */
		push(config.route.rules, {
			action: 'resolve',
			strategy: (ipv6_support !== '1') ? 'ipv4_only' : null
		});

		/* Manual "always direct" pins from the Automation table (watched local
		 * rule-set resources/auto_direct.json → hot reload). Placed FIRST among
		 * the routing rules: it is the user's most specific, most recent intent
		 * (a single host forced to direct outranks every list-based rule). */
		push(config.route.rule_set, {
			type: 'local',
			tag: 'auto-direct',
			format: 'source',
			path: HP_DIR + '/resources/auto_direct.json'
		});
		/* B6.5: the DOMAIN-ONLY twin of auto-direct for the DNS rules (a DNS
		 * rule may not reference a ruleset carrying ip_cidr entries —
		 * sing-box 1.14+ "Legacy Address Filter Fields" FATAL). Written by
		 * sync_manual_direct_ruleset next to auto_direct.json; watched. */
		push(config.route.rule_set, {
			type: 'local',
			tag: 'auto-direct-domain',
			format: 'source',
			path: HP_DIR + '/resources/auto_direct_domain.json'
		});
		push(config.route.rules, {
			rule_set: 'auto-direct',
			action: 'route',
			outbound: 'direct-out'
		});

		/* Advanced custom routing rules (highest priority) */
		if (show_advanced_rules === '1') {
			uci.foreach(uciconfig, uciroutingrule, (cfg) => {
				if (cfg.enabled !== '1') return;

				push(config.route.rules, {
					inbound: cfg.inbound,
					ip_version: strToInt(cfg.ip_version),
					protocol: cfg.protocol,
					network: cfg.network,
					domain: cfg.domain,
					domain_suffix: cfg.domain_suffix,
					domain_keyword: cfg.domain_keyword,
					domain_regex: cfg.domain_regex,
					source_ip_cidr: cfg.source_ip_cidr,
					source_ip_is_private: strToBool(cfg.source_ip_is_private),
					ip_cidr: cfg.ip_cidr,
					ip_is_private: strToBool(cfg.ip_is_private),
					source_port: parse_port(cfg.source_port),
					source_port_range: cfg.source_port_range,
					port: parse_port(cfg.port),
					port_range: cfg.port_range,
					process_name: cfg.process_name,
					process_path: cfg.process_path,
					process_path_regex: cfg.process_path_regex,
					user: cfg.user,
					rule_set: get_ruleset(cfg.rule_set),
					rule_set_ip_cidr_match_source: strToBool(cfg.rule_set_ip_cidr_match_source),
					rule_set_ip_cidr_accept_empty: strToBool(cfg.rule_set_ip_cidr_accept_empty),
					invert: strToBool(cfg.invert),
					action: cfg.action,
					outbound: get_outbound(cfg.outbound),
					override_address: cfg.override_address,
					override_port: strToInt(cfg.override_port)
				});
			});
		}

		/* сеанс 187 (решение юзера): per-origin QUIC reject — UDP/443 к
		 * googlevideo роняется в ЯДРЕ (sing-box route-reject, домен-адресуемо),
		 * браузер мгновенно падает на TCP (экономия 2–4 с на стартах видео).
		 * Глобальный prerouting-drop (byedpi_block_quic) остаётся ЖЁСТКИМ
		 * опциональным режимом: он бьёт по ВСЕМУ LAN UDP/443 (DoH/h3-DNS на
		 * устройствах, туннели/узлы на UDP/443) — блок «QUIC» на странице
		 * «Подключение» описывает это честно. */
		push(config.route.rules, {
			domain_suffix: ['googlevideo.com'],
			network: 'udp',
			port: [443],
			action: 'reject'
		});
		/* s200 QUIC-drop для обходной ноги — см. комментарий у декларации
		 * 'auto-quic-drop' выше. Пользовательские advanced-правила ВЫШЕ остаются
		 * старше (своё UDP-правило юзера побеждает reject — first-match-wins). */
		push(config.route.rules, {
			rule_set: 'auto-quic-drop',
			network: 'udp',
			port: [443],
			action: 'reject'
		});
		/* Call proxying rules: UDP media ports + XMPP/SIP ports for VoIP apps */
		/* Torrent bypass first — takes priority over proxy_calls port ranges (51413 overlaps 50000:65530) */
		if (no_proxy_torrents === '1') {
			push(config.route.rules, {
				protocol: ['bittorrent'],
				action: 'route',
				outbound: 'direct-out'
			});
			push(config.route.rules, {
				port_range: ['6881:6889', '51413:51413'],
				action: 'route',
				outbound: 'direct-out'
			});
		}

		/* Zapret Discord voice (opt-in): send Discord's voice-server UDP ranges
		 * (19294-19344, 50000-50100 — from flowseal/zapret-discord-youtube) to zapret-out
		 * BEFORE proxy_calls, so Discord voice is desynced via Zapret instead of proxied.
		 * Emitted ONLY when Zapret is on (so zapret-out exists) — when Zapret is off this
		 * rule disappears and proxy_calls handles these ports as before. Works on either core. */
		if (zapret_enabled === '1' && zapret_voice === '1')
			push(config.route.rules, {
				network: 'udp',
				port_range: ['19294:19344', '50000:50100'],
				action: 'route',
				outbound: 'zapret-out'
			});

		if (proxy_calls === '1') {
			push(config.route.rules, {
				network: 'udp',
				port: [1400, 8443],
				port_range: ['50000:65530', '596:599', '3478:3497', '16384:16387', '16393:16402'],
				action: 'route',
				outbound: 'main-out'
			});
			push(config.route.rules, {
				port: [4244, 7985, 5222, 5223, 5242, 5243],
				action: 'route',
				outbound: 'main-out'
			});
		}

		/* andrevi.ch always via proxy (hardcoded diagnostic anchor) */
		push(config.route.rules, {
			domain: ['andrevi.ch'],
			action: 'route',
			outbound: 'main-out'
		});

		/* Custom proxy list + learned sites and auto-ip rules are emitted BELOW the
		 * user's per-service rules (see ru_rules loop): first-match-wins routing
		 * means an earlier learned rule HIJACKED service rules — learned YouTube
		 * shards outranked YouTube→Zapret and the site silently rode the main proxy. */
		/* Per-rule outbounds and rule sets. ru_rules was collected once ABOVE
		 * the DNS section in the canonical priority order and already drives
		 * the mirrored DNS rules (B6.5) — do not re-sort here. */

		/* Use direct-out for rule set downloads when the main path isn't startup-safe:
		 * WireGuard/AmneziaWG endpoints aren't ready yet, and ByeDPI resolves hostnames
		 * through sing-box's own DNS inbound — which isn't serving during rule-set init, so
		 * downloading github through it deadlocks (socks5 code 4 "host unreachable") and
		 * FATALs the whole service. Direct download lets sing-box resolve via russia-dns. */
		const main_node_type = uci.get(uciconfig, main_node, 'type') || '';
		let main_has_wg = (main_node_type in ['wireguard', 'amneziawg']);
		if (!main_has_wg && main_node === 'urltest') {
			/* Exit Engine: kernel pool = все узлы в auto/manual (prefer = preferred +
			 * rest) — WG-скан всегда по всем узлам. */
			const scan_wg = (n) => ((uci.get(uciconfig, n, 'type') || '') in ['wireguard', 'amneziawg']);
			foreach_node((c) => {
				if (!main_has_wg && scan_wg(c['.name']))
					main_has_wg = true;
			});
		}
		const ruleset_detour = (main_has_wg || main_node === 'byedpi-out') ? 'direct-out' : 'main-out';

		/* Rule-set declaration dedup — MUST live across the WHOLE rule loop.
		 * ⚠ ч.65: seen_rulesets used to be re-created inside the loop body, so two
		 * enabled rules with the same source but different targets (YouTube → main-out
		 * AND YouTube → Zapret is a legitimate, UI-supported combination) each declared
		 * `hp-ru-<source>` again → the core died with FATAL "duplicate rule-set tag" —
		 * in proxy_banned_ru only (global emits no hp-ru rule-sets), i.e. exactly
		 * "switch back from Global = internet down, core crash-looping". ч.63's
		 * filter() ban still applies: plain object lookups only. */
		let seen_rulesets = {};
		const has_ruleset = (tag) => !!seen_rulesets[tag];
		const remember_ruleset = (tag) => { seen_rulesets[tag] = true; };
		/* ч.274 audit (КРИТ «второй выход»): owner map for the per-source
		 * outbound tags. The CLASSIC tag hp-ru-<src>-out belongs to the UCI-FIRST
		 * enabled rule of the source (sentinel parity above); a second+ rule of
		 * the SAME source with a DIFFERENT exit claims its own tag
		 * hp-ru-<src>-<node>-out instead of silently riding the first rule's
		 * clone. Same exit (node id, and for urltest pools the same node list)
		 * still shares the tag it claimed. */
		let hp_tag_owner = {};
		const hp_claim_tag = (base, owner) => {
			if (hp_tag_owner[base] == null || hp_tag_owner[base] === owner) {
				hp_tag_owner[base] = owner;
				return base;
			}
			for (let i = 2; ; i++) {
				const alt = base + '-' + i;
				if (hp_tag_owner[alt] == null || hp_tag_owner[alt] === owner) {
					hp_tag_owner[alt] = owner;
					return alt;
				}
			}
		};

		for (let cfg in ru_rules) {

			/* 'main-out' routes through the main proxy; 'byedpi-out' through the shared ByeDPI
			 * socks outbound (already created when ByeDPI is enabled). Both reuse an existing
			 * outbound, so no per-source outbound is generated. */
			let effective_outbound;
			if (cfg.node === 'main-out' || isEmpty(cfg.node))
				effective_outbound = 'main-out';
			else if (cfg.node === 'byedpi-out') {
				/* ч.274 audit: a disabled engine previously swallowed the rule into
				 * direct-out SILENTLY — the warn makes the skip visible in the
				 * apply log (the UI-side disable confirmation is the other half). */
				if (byedpi_enabled === '1')
					effective_outbound = 'byedpi-out';
				else {
					warn('homeproxy: RU rule "' + cfg.name + '" points at ByeDPI but the engine is DISABLED - the rule rides direct-out.\n');
					effective_outbound = 'direct-out';
				}
			} else if (cfg.node === 'zapret-out') {
				if (zapret_enabled === '1')
					effective_outbound = 'zapret-out';
				else {
					warn('homeproxy: RU rule "' + cfg.name + '" points at Zapret but the engine is DISABLED - the rule rides direct-out.\n');
					effective_outbound = 'direct-out';
				}
			} else if (cfg.node === 'tgws-out')
				/* D34b: tg-ws removed — a legacy rule node rides the main path. */
				effective_outbound = has_outbound('main-out') ? 'main-out' : 'direct-out';
			else {
				/* ч.274 audit: classic tag = the UCI-first enabled rule of the
				 * source; other exits claim their own tags instead of riding
				 * the first rule's clone. For urltest rules the owner identity
				 * includes the pool's usable node list, so two DIFFERENT pools
				 * never share an outbound. */
				const classic = 'hp-ru-' + cfg.source + '-out';
				let owner = '' + cfg.node;
				if (cfg.node === 'urltest')
					owner += ':' + join(',', usable_nodes(cfg.urltest_nodes) || []);
				let base = classic;
				if (hp_tag_owner[classic] != null && ru_uci_first['' + cfg.source] !== '' + cfg.node)
					base = 'hp-ru-' + cfg.source + '-' + cfg.node + '-out';
				effective_outbound = hp_claim_tag(base, owner);
			}

			if (cfg.node === 'main-out' || isEmpty(cfg.node) || cfg.node === 'byedpi-out' || cfg.node === 'zapret-out' || cfg.node === 'tgws-out') {
				/* no new outbound needed — main-out / byedpi-out / zapret-out already exist */
			} else if (!has_outbound(effective_outbound)) {
				if (cfg.node === 'urltest') {
					const ut_nodes = usable_nodes(cfg.urltest_nodes);
					/* ч.274 audit: an EMPTY pool (nodes removed or unsupported by
					 * the core) would emit urltest outbounds:[] — the kernel
					 * FATALS on it. Honest fallback: the rule rides main-out
					 * (whose own empty-pool fallback keeps the net alive) — the
					 * same shape as the unsupported-node branch below. */
					if (!length(ut_nodes)) {
						warn('homeproxy: RU rule "' + cfg.name + '" carries an EMPTY URLTest pool - the rule rides main-out instead of a fatal empty urltest outbound.\n');
						effective_outbound = has_outbound('main-out') ? 'main-out' : 'direct-out';
					} else {
						push(config.outbounds, {
							type: 'urltest',
							tag: effective_outbound,
							outbounds: map(ut_nodes, (k) => `cfg-${k}-out`),
							interval: strToTime(cfg.urltest_interval || '180'),
							tolerance: strToInt(cfg.urltest_tolerance || '150'),
							idle_timeout: '1800s'
						});
						/* Generate underlying node outbounds, skipping already-generated tags */
						for (let n in ut_nodes) {
							if (has_outbound('cfg-' + n + '-out')) continue;
							const nc = uci.get_all(uciconfig, n);
							if (!nc) continue;
							if (nc.type in ['wireguard', 'amneziawg']) {
								push(config.endpoints, generate_endpoint(nc));
								config.endpoints[length(config.endpoints)-1].tag = 'cfg-' + n + '-out';
							} else {
								push_outbound(config.outbounds, nc);
								config.outbounds[length(config.outbounds)-1].tag = 'cfg-' + n + '-out';
							}
						}
					}
				} else if (!isEmpty(cfg.node)) {
					if (!hp_node_usable(cfg.node)) {
						/* Unsupported by the selected core: no outbound is emitted,
						 * so the rule below must not reference the dead tag — ride
						 * the main path instead. */
						warn('homeproxy: RU rule node not supported by the selected core - rerouted to main-out.\n');
						effective_outbound = 'main-out';
					} else {
						const nc = uci.get_all(uciconfig, cfg.node) || {};
						if (nc.type in ['wireguard', 'amneziawg']) {
							push(config.endpoints, generate_endpoint(nc));
							config.endpoints[length(config.endpoints)-1].tag = effective_outbound;
						} else {
							push_outbound(config.outbounds, nc);
							config.outbounds[length(config.outbounds)-1].tag = effective_outbound;
						}
					}
				}
			}

			/* W4 IP companions: Telegram MTProto DCs, Roblox and Twitch stream
			 * edges are IP-based, so a domain-only rule lets that traffic
			 * fall to the mass refilter_ip list. The IP twins (tag
			 * '<tag>-ip') live in the lists catalog (rulesets_catalog.uc) —
			 * the routing rule below pairs them with the domain rule-set. */

			/* Routing rules. Sources with a shipped local list ride an INLINE
			 * domain_suffix rule (lesson 355 — the remote asset can silently
			 * go stale and the rule dies without a trace). */
			const inline_dom = hp_remote_preferred(cfg.source) ? null : hp_service_inline_domains(cfg.source);
			if (inline_dom) {
				push(config.route.rules, {
					domain_suffix: inline_dom,
					action: 'route',
					outbound: effective_outbound,
					network: null
				});
			} else {
				let rule_sets;
				if (cfg.source === 'refilter')
					rule_sets = ls_catalog_pair('refilter');
				else if (ls_catalog_ip_url(cfg.source))
					rule_sets = ['hp-ru-' + cfg.source, 'hp-ru-' + cfg.source + '-ip'];
				else
					rule_sets = ['hp-ru-' + cfg.source];
				push(config.route.rules, {
					rule_set: rule_sets,
					action: 'route',
					outbound: effective_outbound,
					network: null
				});
			}

			/* Rule sets (remote — core handles download and 1d refresh).
			 * ⚠ ч.63: NO filter() with an inner arrow here — this ucode build does
			 * not bind the outer callable's parameter inside a nested arrow
			 * (verified live: has('hp-ru-youtube') stayed false with the tag
			 * present), so the old filter-based dedup pushed every declaration
			 * twice for repeated sources and the core died with "duplicate
			 * rule-set tag". The seen_rulesets state lives ABOVE the loop (ч.65)
			 * so declarations dedup across ALL rules, not within one. */
			if (cfg.source === 'refilter') {
				const refilter_pair = ls_catalog_pair('refilter');
				if (!has_ruleset(refilter_pair[0])) {
					remember_ruleset(refilter_pair[0]);
					push(config.route.rule_set, {
						type: 'remote',
						tag: refilter_pair[0],
						format: 'binary',
						url: ls_catalog_url('refilter-domain'),
						initial_path: ruleset_initial_path,
						...hp_rs_dl(ruleset_detour),
						update_interval: '1d'
					});
				}
				if (!has_ruleset(refilter_pair[1])) {
					remember_ruleset(refilter_pair[1]);
					push(config.route.rule_set, {
						type: 'remote',
						tag: refilter_pair[1],
						format: 'binary',
						url: ls_catalog_url('refilter-ip'),
						initial_path: ruleset_initial_path,
						...hp_rs_dl(ruleset_detour),
						update_interval: '1d'
					});
				}
			} else {
				/* URL selection = the catalog (hub primary, upstream reserves).
				 * The itdog expression survives only as the last-resort default
				 * for a source id that is missing from the catalog. */
				const ce = ls_catalog_find(cfg.source);
				if (ce && ce.consumption === 'local-json') {
					/* Lists-conveyor converted categories (raw feeds turned
					 * into sing-box source rule-sets): a LOCAL rule-set when
					 * the conveyor has placed the file, else the hub's already
					 * converted JSON as a normal remote rule-set. */
					const lpath = ruleset_local_dir + '/' + ce.tag + '.json';
					if (access(lpath)) {
						if (!has_ruleset(ce.tag)) {
							remember_ruleset(ce.tag);
							push(config.route.rule_set, {
								type: 'local',
								tag: ce.tag,
								format: 'source',
								path: lpath
							});
						}
					} else if (!has_ruleset(ce.tag) && length('' + (ls_catalog_url(cfg.source) || ''))) {
						remember_ruleset(ce.tag);
						push(config.route.rule_set, {
							type: 'remote',
							tag: ce.tag,
							format: 'source',
							url: ls_catalog_url(cfg.source),
							initial_path: ruleset_initial_path
								? (ruleset_local_dir + '/{tag}.json') : null,
							...hp_rs_dl(ruleset_detour),
							update_interval: '1d'
						});
					}
				} else if (!hp_remote_preferred(cfg.source) && hp_service_inline_domains(cfg.source)) {
					/* Shipped inline list (lesson 355) — no rule-set to
					 * declare: the route/DNS rules above carry the
					 * domain_suffix array directly. Сеанс 184: категория с
					 * inline_pref:false (google_ai → hub) минует ветку и
					 * объявляет remote-рулесет ниже. */
				} else if (!has_ruleset('hp-ru-' + cfg.source)) {
					remember_ruleset('hp-ru-' + cfg.source);
					push(config.route.rule_set, {
						type: 'remote',
						tag: 'hp-ru-' + cfg.source,
						format: 'binary',
						url: ls_catalog_url(cfg.source) ||
						     ('https://github.com/itdoginfo/allow-domains/releases/latest/download/' + replace(cfg.source, '-', '_') + '.srs'),
						initial_path: ruleset_initial_path,
						...hp_rs_dl(ruleset_detour),
						update_interval: '1d'
					});
				}
				if (ls_catalog_ip_url(cfg.source) && !has_ruleset('hp-ru-' + cfg.source + '-ip')) {
					remember_ruleset('hp-ru-' + cfg.source + '-ip');
					push(config.route.rule_set, {
						type: 'remote',
						tag: 'hp-ru-' + cfg.source + '-ip',
						format: 'binary',
						url: ls_catalog_ip_url(cfg.source),
						initial_path: ruleset_initial_path,
						...hp_rs_dl(ruleset_detour),
						update_interval: '1d'
					});
				}
			}
		}

		/* OAuth stability (ч.59/ч.61/ч.62): auth-provider hosts (accounts.google.com,
		 * login.microsoftonline.com, …) AND the whole DOMAIN FAMILY of every
		 * learned auth-like host (accounts.autodesk.com learned → autodesk.com
		 * family: profile./cdn./iam. siblings ride along) route to `main-out` —
		 * the SAME LIVE EXIT the service that opened the flow uses.
		 * ч.62 removed ч.61's dedicated pinned `oauth-out` urltest: a pinned
		 * group holds its first-alive node forever while the main exit moves
		 * (re-rank, Hot Swap) — the identity legs then ride a DIFFERENT exit
		 * than the service pages and the provider's risk engine rejects the
		 * session (Autodesk socialSignInFailed again). The login-chain
		 * infrastructure is IP-bound the same way and used to fall through to
		 * the final (direct) rule or be half-learned — the live connections
		 * showed *.w.hcaptcha.com challenge websockets on `final` (direct RU IP)
		 * while the LogOn page rode the proxy, and cdn/charon.protect.clerk.com
		 * on `final` while clerk.openrouter.ai rode main-out (OpenRouter sign-up
		 * dead). resources/oauth_stable.txt now also lists clerk.com,
		 * hcaptcha.com/.net, recaptcha.net and challenges.cloudflare.com so page
		 * + identity + captcha + bot checks share one exit. Order: user rules
		 * and auto-direct pins stay ABOVE (a manual pin wins), this block sits
		 * above RU-protect and the learned/static proxy lists. QUIC (UDP/443) is
		 * rejected for both rule-sets so every client takes the deterministic
		 * TCP path. */
		if (oauth_stability_opt) {
			push(config.route.rule_set, {
				type: 'local',
				tag: 'oauth-domain',
				format: 'source',
				path: HP_DIR + '/resources/oauth_domain.json'
			});
			/* сеанс 187: декларация rule_set негативного стиринга (файл пишет
			 * DNS-секция при деривации; здесь только объявление — config.route
			 * в DNS-секции ещё не существует, урок этого сеанса). */
			if ((uci.get(uciconfig, 'config', 'yt_steer_dead') || '0') === '1' &&
				access(HP_DIR + '/resources/yt_steer_dead.json')) {
				push(config.route.rule_set, {
					type: 'local',
					tag: 'yt-steer-dead',
					format: 'source',
					path: HP_DIR + '/resources/yt_steer_dead.json'
				});
			}
			push(config.route.rule_set, {
				type: 'local',
				tag: 'auto-auth-domain',
				format: 'source',
				path: HP_DIR + '/resources/auto_auth.json'
			});
			push(config.route.rules, {
				rule_set: 'oauth-domain',
				network: 'udp',
				port: [443],
				action: 'reject'
			});
			push(config.route.rules, {
				rule_set: 'auto-auth-domain',
				network: 'udp',
				port: [443],
				action: 'reject'
			});
			push(config.route.rules, {
				rule_set: 'oauth-domain',
				action: 'route',
				outbound: 'main-out'
			});
			push(config.route.rules, {
				rule_set: 'auto-auth-domain',
				action: 'route',
				outbound: 'main-out'
			});
			warn('homeproxy: OAuth stability - providers + auth families + login infra ride the main exit with the service.\n');
		}

		/* Ф4.2 (U7): user DIRECT lists — right after the per-service rules,
		 * BEFORE the RU-protect guard. A direct list is the user's explicit
		 * "not through the node" intent (pure direct-out or through an
		 * engine), the same tier as the service rules above. The watched
		 * rule-set files were declared in user_list_prepare. */
		const direct_dns_pool = (routing_mode === 'proxy_banned_ru') ? 'russia-dns' : 'region-dns';
		for (let l in user_lists) {
			if (l.kind !== 'direct' || !l.on)
				continue;
			const ob = user_list_prepare(l);
			if (ob === null)
				continue;
			push(config.route.rules, {
				rule_set: 'user-' + l.sid,
				action: 'route',
				outbound: ob
			});
			/* B6.5 mirror: direct-routed traffic resolves through the DIRECT
			 * pool (russia-dns / region-dns) — never through the secure
			 * tunnel pool, and ahead-of-position rules like proxy-domain's
			 * secure-dns route must not capture a user-excluded host's DNS. */
			if (l.ctype === 'domains')
				push(config.dns.rules, {
					rule_set: 'user-' + l.sid,
					action: 'route',
					server: direct_dns_pool
				});
		}

		/* RU-protect ("Russian internet never via proxy"): the downloaded RU-geo
		 * databases (watched local rule-sets resources/ru_geoip.json + ru_geosite.json,
		 * refreshed by ru_geo_update.sh) are matched BEFORE the proxy lists, so a
		 * stale/learned/static-list hit on RU infrastructure can never tunnel RU
		 * traffic — RU services' anti-fraud flags VPN exits. Placed AFTER the
		 * per-service rules (user rules keep priority) and BEFORE the proxy-domain /
		 * auto-ip learned rules. Toggled by homeproxy.automation.geo_protect (default on). */
		if ((uci.get(uciconfig, 'automation', 'geo_protect') || '1') !== '0') {
			push(config.route.rules, {
				rule_set: [ 'ru-geoip', 'ru-geosite' ],
				action: 'route',
				outbound: 'direct-out'
			});
			/* B6.5 mirror: RU-protect routes direct → resolve through the
			 * direct pool. Without this rule a RU domain that is ALSO in the
			 * proxy lists resolved through the secure tunnel pool while its
			 * traffic rode direct — the audit's split. Emitted BEFORE the
			 * user-proxy/proxy-domain DNS rules, exactly where the guard
			 * sits in the route list. DOMAIN entries only ('ru-geosite';
			 * 'ru-geoip' carries ip_cidr and is rejected inside DNS rules,
			 * sing-box 1.14+ — and an IP has no DNS query anyway). */
			push(config.dns.rules, {
				rule_set: 'ru-geosite',
				action: 'route',
				server: direct_dns_pool
			});
		}

		/* Ф4.2 (U7): user PROXY lists — AFTER the RU-protect guard (the
		 * "RU never via proxy" invariant stays ironclad for proxy lists: a RU
		 * domain put into a proxy list routes direct, exactly like the mass
		 * lists and learned records), BEFORE the proxy-domain rule. */
		for (let l in user_lists) {
			if (l.kind !== 'proxy')
				continue;
			const ob = user_list_prepare(l);
			if (ob === null)
				continue;
			push(config.route.rules, {
				rule_set: 'user-' + l.sid,
				action: 'route',
				outbound: ob
			});
			/* B6.5 mirror: a proxied list resolves through the encrypted pool
			 * (RU mode: the final resolver is the PLAIN pool — without this
			 * rule a proxied list resolved plain while riding the tunnel;
			 * reverse modes: secure-dns is already the final — the explicit
			 * rule is emitted in RU mode only, no redundant duplicate). */
			if (l.ctype === 'domains' && routing_mode === 'proxy_banned_ru')
				push(config.dns.rules, {
					rule_set: 'user-' + l.sid,
					action: 'route',
					server: 'secure-dns'
				});
		}

		/* Custom proxy list → main-out. The learned sites share this rule-set via the
		 * watched local file, so they hot-reload without a restart. Always emitted
		 * (empty rule-set is a no-op) so hot reloads work even from an empty list.
		 * Placed AFTER the per-service rules above: automation-learned entries must
		 * never outrank an explicit user rule (see comment at their old position). */
		/* B6.5 mirror (moved from the DNS section): the SVCB/HTTPS reject wins
		 * BEFORE the proxied route rule, then proxied domains resolve through
		 * the encrypted pool. Browsers use HTTPS records to discover alternate
		 * endpoints and HTTP/3; letting them resolve via plain DNS leaks
		 * interest in blocked domains and lets clients bypass domain routing
		 * via QUIC. In RU mode this pair sits AFTER the user-direct/RU-protect
		 * mirrors, so an excluded/RU host resolves direct even when it is also
		 * listed in the proxy lists (the audit's split — fixed). */
		push(config.dns.rules, {
			rule_set: 'proxy-domain',
			query_type: [64, 65],
			action: 'reject'
		});
		push(config.dns.rules, {
			rule_set: 'proxy-domain',
			action: 'route',
			server: 'secure-dns'
		});
		/* s201 СЕМЕЙНАЯ НОГА, DNS-зеркало (domains-only близнец): члены семьи
		 * резолвятся через зашифрованный пул + SVCB/HTTPS-reject (анти-лик:
		 * интерес к домену семьи не виден TSPU в plain-резолве; паритет с
		 * learned-доменами). IP-члены DNS не имеют (прецедент ru-geoip). */
		if (automation_enabled === '1' && !isEmpty(main_node)) {
			push(config.dns.rules, {
				rule_set: 'family-domain',
				query_type: [64, 65],
				action: 'reject'
			});
			push(config.dns.rules, {
				rule_set: 'family-domain',
				action: 'route',
				server: 'secure-dns'
			});
		}
		push(config.route.rules, {
			rule_set: 'proxy-domain',
			action: 'route',
			outbound: 'main-out'
		});

		/* B6.3: MANUAL IP entries (static proxy_list + manual "always proxy"
		 * pins) → main-out. The 'manual-ip' rule is emitted UNCONDITIONALLY
		 * (empty rule-set is a no-op): a hand-pinned IP must route regardless
		 * of the Automation toggle — it used to be swallowed by the same
		 * ruleset/rule as the learned IPs, which only existed when
		 * automation_enabled='1'. The watched file (manual_ip.json) hot-reloads. */
		push(config.route.rules, {
			rule_set: 'manual-ip',
			action: 'route',
			outbound: 'main-out'
		});

		/* Learned IP list (Automation, B) → main-out. References the watched local
		 * rule-set file (auto-ip); hot-reloaded, so newly learned IPs apply immediately. */
		if (automation_enabled === '1' && !isEmpty(main_node))
			push(config.route.rules, {
				rule_set: 'auto-ip',
				action: 'route',
				outbound: 'main-out'
			});

		/* s201 СЕМЕЙНАЯ НОГА: QUIC-drop вслед + маршрут вслед (позиция — сразу
		 * после auto-ip, ДО region-baseline/final=direct-out и НИЖЕ user-слоёв
		 * RU-protect/auto-direct/per-service: first-match-wins — вторая линия
		 * RU-защиты). QUIC-drop: браузерный h3 к члену роняется → мгновенный
		 * фолбэк на TCP, который едет main-out (QUIC сквозь socks мёртв, сырой
		 * h3 напрямую TSPU режет посреди потока — сеанс 200). Trade: общий
		 * CDN-край теряет h3 и для чужих сайтов на том же крае — они честно
		 * фолбэкаются на TCP (не ломаются); откат = убрать reject-правило. */
		if (automation_enabled === '1' && !isEmpty(main_node)) {
			push(config.route.rules, {
				rule_set: 'family-route',
				network: 'udp',
				port: [443],
				action: 'reject'
			});
			push(config.route.rules, {
				rule_set: 'family-route',
				action: 'route',
				outbound: 'main-out'
			});
		}
		/* Reverse: region baseline -> direct (lowest priority, AFTER per-service overrides).
		 * MUST include geoip (IP) so non-sniffable UDP / no-SNI gets the direct decision. */
		if (is_bypass_mode(routing_mode)) {
			push(config.route.rules, {
				rule_set: [ 'geosite-' + region_of(routing_mode), 'geoip-' + region_of(routing_mode) ],
				action: 'route',
				outbound: 'direct-out'
			});
			/* Proxied-UDP default node, after baseline+overrides so domestic/override UDP isn't swept in. */
			if (dedicated_udp_node)
				push(config.route.rules, {
					network: 'udp',
					action: 'route',
					outbound: 'main-udp-out'
				});
		}
	}

	if (is_bypass_mode(routing_mode)) {
		/* Region rule-sets (.srs). Direct-bootstrap: download direct so a not-yet-up proxy
		 * can't deadlock rule-set init at startup. geosite_non only when guard is on (CN). */
		const r = region_of(routing_mode);
		const region = REGION[r];
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geoip-' + r,
			format: 'binary',
			url: region.geoip,
			initial_path: ruleset_initial_path,
			...hp_rs_dl('direct-out'),
			update_interval: '1d'
		});
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-' + r,
			format: 'binary',
			url: region.geosite,
			initial_path: ruleset_initial_path,
			...hp_rs_dl('direct-out'),
			update_interval: '1d'
		});
		if (region.guard)
			push(config.route.rule_set, {
				type: 'remote',
				tag: 'geosite-non' + r,
				format: 'binary',
				url: region.geosite_non,
				initial_path: ruleset_initial_path,
				...hp_rs_dl('direct-out'),
				update_interval: '1d'
			});
	}

	if (isEmpty(config.route.rule_set))
		config.route.rule_set = null;
}
/* Routing rules end */

/* ByeDPI outbound */
if (byedpi_enabled === '1') {
	const byedpi_uot = uci.get(uciconfig, ucimain, 'byedpi_udp_over_tcp') !== '0';
	push(config.outbounds, {
		type: 'socks',
		tag: 'byedpi-out',
		server: '127.0.0.1',
		server_port: 5335,
		udp_over_tcp: byedpi_uot || null
	});
}
/* ByeDPI outbound end */

/* zapret outbound: a plain direct dialer stamped with routing_mark. sing-box egresses
 * the selected (e.g. YouTube) flows directly but tagged with zapret_mark; nft catches
 * that mark and feeds the handshake to NFQUEUE where nfqws (running separately) desyncs
 * the DPI. routing_mark OVERRIDES the global default_mark, so firewall_post.ut adds a
 * matching loop-avoidance return for zapret_mark. */
if (zapret_enabled === '1') {
	push(config.outbounds, {
		type: 'direct',
		tag: 'zapret-out',
		routing_mark: strToInt(zapret_mark)
	});
}
/* zapret outbound end */

/* Experimental start */
config.experimental = {
	clash_api: {
		external_controller: '127.0.0.1:9090'
	}
};
if (is_selective_mode(routing_mode)) {
	config.experimental.cache_file = {
		enabled: true,
		path: RUN_DIR + '/cache.db'
	};
}
/* Experimental end */

system('mkdir -p ' + RUN_DIR);

/* Write the watched learned-list rule-set files (proxy_domain.json / auto_ip.json) so they
 * exist before the core starts. Automation rewrites them on every learn → hot reload.
 * Also the manual "always direct" pins (auto_direct.json), the RU-geo rule-set files
 * (ru_geoip.json / ru_geosite.json — stale-only rewrite, see sync_ru_geo_rulesets),
 * the OAuth stability list (oauth_domain.json, ч.59), and the Ф4.2 user list
 * files (resources/lists/<sid>.json — one watched rule-set per user list).
 * Ф4.1: invalid list entries are dropped AND counted by the classifier — never silent. */
{
	let cls_dropped = 0;
	let 	rr = sync_learned_rulesets();        cls_dropped += rr.dropped || 0;
	rr = sync_manual_direct_ruleset();       cls_dropped += rr.dropped || 0;
	rr = sync_ru_geo_rulesets();             cls_dropped += rr.dropped || 0;
	rr = sync_oauth_ruleset();               cls_dropped += rr.dropped || 0;
	rr = sync_auto_auth_ruleset();           cls_dropped += rr.dropped || 0;
	/* s201: семейная нога — файлы должны существовать до старта ядра
	 * (пустой набор = no-op). Содержимое пишет демон (sync_families);
	 * СУЩЕСТВУЮЩИЕ файлы НЕ затираем: реген конфига не должен пустить
	 * семью впустую до следующего прохода демона (члены уже в state). */
	if (!access(HP_DIR + '/resources/family_route.json') ||
	    !access(HP_DIR + '/resources/family_domain.json')) {
		rr = sync_family_rulesets(null, [], []);
		cls_dropped += rr.dropped || 0;
	}
	/* Ф4.2: every user list (incl. DISABLED ones — the file must exist, the
	 * core's hot-reload watch may already reference it from a previous start). */
	for (let ul in user_lists) {
		rr = sync_user_list(HP_DIR + '/resources', ul.sid, ul.ctype);
		cls_dropped += rr.dropped || 0;
	}
	if (cls_dropped > 0)
		warn('homeproxy: classify_entry dropped ' + cls_dropped + ' invalid list entries (Ф4.1 validation — see /etc/ravnex/resources/*.txt)\n');
}

/* ч.65 last line of defense: a duplicate tag among dns servers / outbounds /
 * endpoints / rule-sets is a hard core FATAL ("duplicate rule-set tag ...") →
 * crash-loop → the whole internet down. A fatal config must never displace the
 * RUNNING one: exit WITHOUT writing the file — init.d then rolls back to
 * hiddify-c.json.lastgood and the service keeps running the previous config. */
/* GitHub issue #3, part 2: the kernel (system) WG/AWG stack creates a real
 * TUN device per emitted endpoint object — and the SAME node can be emitted
 * more than once (a dedicated UDP exit AND a rule reference both push their
 * own endpoint with a different tag). Two device creations with one name die
 * with "TUNSETIFF: device or resource busy", so every re-used kernel name
 * gets a numeric suffix ('-N', IFNAMSIZ-bounded: 12 + dash + digits <= 15).
 * gVisor endpoints create no kernel device and stay nameless. */
if (config.endpoints) {
	const wg_names = {};
	for (let ep in config.endpoints)
		if (ep.type === 'wireguard' && ep.system && ep.name) {
			if (ep.name in wg_names) {
				const base = substr(ep.name, 0, 12);
				let n = 2;
				while (length(base) + 1 + length('' + n) <= 15 && (base + '-' + n) in wg_names)
					n++;
				if (length(base) + 1 + length('' + n) <= 15)
					ep.name = base + '-' + n;
			}
			wg_names[ep.name] = true;
		}
}

let dup_tags = {};
const scan_dup_tags = (arr, kind) => {
	if (type(arr) !== 'array')
		return;
	for (let item in arr) {
		const t = item?.tag;
		if (!t)
			continue;
		if (dup_tags[t]) {
			warn(sprintf('homeproxy: refusing to write a fatal config - duplicate tag "%s" (%s).\n', t, kind));
			exit(1);
		}
		dup_tags[t] = kind;
	}
};
scan_dup_tags(config.dns.servers, 'dns-server');
scan_dup_tags(config.outbounds, 'outbound');
scan_dup_tags(config.endpoints, 'endpoint');
scan_dup_tags(config.route.rule_set, 'rule-set');

/* Atomic (temp + mv): a kill/power-cut mid-writefile would leave a truncated
 * file — the core would die at start with no config at all. Ф1.2 (аудит 27):
 * the target of the write is now the CANDIDATE; the running hiddify-c.json is
 * replaced atomically ONLY after the core check passed, so a fatal config
 * never displaces the RUNNING one. */
const candidate = RUN_DIR + '/hiddify-c.json.candidate';
const cfg_tmp = candidate + '.tmp';
writefile(cfg_tmp, sprintf('%.J\n', removeBlankAttrs(config)));
system('mv -f ' + hp_shellquote(cfg_tmp) + ' ' + hp_shellquote(candidate));

/* Exit Engine contract (Ф9.16): движок читает exit_engine.json (v2-контракт);
 * hotswap.json = легаси-зеркало в старом формате (откат на прежний движок читает
 * его же формат). Оба — атомарный write_state State Store с конвертом (Ф1.7).
 * Отсутствие/протухание → движок в idle (или легаси-режим до регенерации). */
if (hotswap_state) {
	ss_write_state(RUN_DIR + '/exit_engine.json', hotswap_state);
	const mspec = hotswap_state.contours['main-out'];
	if (mspec) {
		ss_write_state(RUN_DIR + '/hotswap.json', {
			enabled: true,
			mode: mspec.group ? 'urltest' : 'node',
			group: 'main-out',
			primary: mspec.group ? mspec.group : mspec.manual_pick,
			hot: [...(mspec.group ? [mspec.group] : []), ...mspec.reserves],
			count: (mspec.group ? 1 : 0) + length(mspec.reserves),
			interval: hotswap_state.probe.interval,
			failback: hotswap_state.failback,
			antiflap: true,
			pool_mode: hotswap_state.mode,
			tolerance: hotswap_state.thresholds.tolerance,
			labels: hotswap_state.labels
		});
	} else {
		system('rm -f ' + hp_shellquote(RUN_DIR + '/hotswap.json') + ' 2>/dev/null');
	}
} else {
	system('rm -f ' + hp_shellquote(RUN_DIR + '/exit_engine.json') + ' 2>/dev/null');
	system('rm -f ' + hp_shellquote(RUN_DIR + '/hotswap.json') + ' 2>/dev/null');
}

/* ── G4: ДЕКЛАРАЦИИ контуров в профиль владельца (память, не состояние) ──
 * /etc/ravnex/provider_profile.json — персистентный (переживает ребут).
 * «Генератор объявляет → движок владеет → профиль помнит»: здесь только
 * kind/uci_key/gen_sig этой генерации и владельцы узловых контуров (label +
 * сервер-хост БЕЗ credentials); факты ISP (страна/ASN) допишет luci.ravnex
 * (hp_profile_touch), смены held — hotswap. Прямой/движковый контур
 * объявляется владельцем class 'isp' (выход = WAN). Warn-only: ошибка слияния
 * НЕ ломает генерацию — конфиг уже выписан в candidate. Запись — ТОЛЬКО при
 * изменении (profile_apply diff), чтобы overlay-flash не дёргался. */
try {
	const pp = { doc: null, changed: false };
	try { pp.doc = ss_read_state('/etc/ravnex/provider_profile.json').data; } catch (e2) { pp.doc = null; }
	const pp_gen = (spec) => {
		const r = profile_apply(pp.doc, spec.tag, {
			kind: spec.kind,
			uci_key: spec.ukey,
			gen_sig: spec.sig,
			owner: (spec.owner != null) ? exit_stamp(spec.owner) : null
		}, time(), 16);
		pp.doc = r.doc;
		pp.changed = pp.changed || r.changed;
	};
	let pp_sig = 'e2:synth';
	if (hotswap_state)
		pp_sig = sprintf('e2:%s fb%d up%d i%d da%d ro%d rw%d hy%d to%d',
			hotswap_state.mode, hotswap_state.failback ? 1 : 0, hotswap_state.upgrade ? 1 : 0,
			hotswap_state.probe.interval, hotswap_state.thresholds.dead_after,
			hotswap_state.thresholds.recovery_oks, hotswap_state.thresholds.recovery_window,
			hotswap_state.thresholds.hysteresis_rounds, hotswap_state.thresholds.tolerance);
	if (hotswap_state) {
		for (let tag, spec in hotswap_state.contours) {
			let kind = 'urltest', ukey = null, owner = null;
			if (spec.group == null && spec.manual_pick != null) {
				kind = 'node';
				const km = match(spec.manual_pick, /^cfg-(.+)-out$/);
				ukey = km ? km[1] : spec.manual_pick;
				const ncfg = uci.get_all(uciconfig, ukey);
				const nlabel = hotswap_state.labels[spec.manual_pick];
				owner = {
					class: 'node',
					sid: ukey,
					label: (nlabel && length(nlabel)) ? '' + nlabel : ukey,
					address_host: (ncfg && ncfg.address && length('' + ncfg.address)) ? ('' + ncfg.address) : null,
					src: 'gen'
				};
			}
			pp_gen({ tag: tag, kind: kind, ukey: ukey, sig: pp_sig, owner: owner });
		}
	} else if (main_node != null && main_node !== 'nil') {
		/* Без движка: urltest = пустой пул → main-out = direct; синтетика
		 * (byedpi/zapret/direct) — владелец WAN; одиночный узел — владелец узел. */
		let kind = 'node', ukey = null, owner = null;
		if (main_node === 'urltest') {
			kind = 'direct';
			owner = { class: 'isp', src: 'gen' };
		} else if (main_node === 'byedpi-out') {
			kind = (byedpi_enabled === '1') ? 'byedpi' : 'direct';
			owner = { class: 'isp', src: 'gen' };
		} else if (main_node === 'zapret-out') {
			kind = (zapret_enabled === '1') ? 'zapret' : 'direct';
			owner = { class: 'isp', src: 'gen' };
		} else if (main_node === 'direct-out') {
			kind = 'direct';
			owner = { class: 'isp', src: 'gen' };
		} else {
			const ncfg = uci.get_all(uciconfig, main_node);
			if (ncfg == null) {
				kind = 'direct';
				owner = { class: 'isp', src: 'gen' };
			} else {
				ukey = main_node;
				const nlabel = uci.get(uciconfig, main_node, 'label');
				owner = {
					class: 'node',
					sid: main_node,
					label: (nlabel && length(nlabel)) ? '' + nlabel : main_node,
					address_host: (ncfg.address && length('' + ncfg.address)) ? ('' + ncfg.address) : null,
					src: 'gen'
				};
			}
		}
		pp_gen({ tag: 'main-out', kind: kind, ukey: ukey, sig: 'e2:synth', owner: owner });
	}
	/* UDP-контур вне движка: dedicated-синтетика/одиночный узел; urltest-ветка
	 * уже покрыта hotswap_state (или пул слишком мал — отдельного контура нет). */
	if (main_udp_node != null && main_udp_node !== 'nil' &&
	    !(hotswap_state && hotswap_state.contours['main-udp-out']) &&
	    main_udp_node !== 'same' && main_udp_node !== main_node) {
		let ukind = 'node', uukey = null, uowner = null;
		if (main_udp_node === 'urltest') {
			/* Вне движка пул urltest мал: 0 узлов → direct-фолбэк, 1 узел →
			 * голая kernel-группа под тегом main-udp-out. */
			const uusable = [];
			foreach_node((ucfg2) => {
				if (hp_node_usable(ucfg2['.name']))
					push(uusable, ucfg2['.name']);
			});
			if (length(uusable) === 0) {
				ukind = 'direct';
				uowner = { class: 'isp', src: 'gen' };
			} else
				ukind = 'urltest';
		} else if (main_udp_node === 'byedpi-out') {
			ukind = (byedpi_enabled === '1') ? 'byedpi' : 'direct';
			uowner = { class: 'isp', src: 'gen' };
		} else if (main_udp_node === 'zapret-out') {
			ukind = (zapret_enabled === '1') ? 'zapret' : 'direct';
			uowner = { class: 'isp', src: 'gen' };
		} else {
			const ucfg = uci.get_all(uciconfig, main_udp_node);
			if (ucfg == null) {
				ukind = 'direct';
				uowner = { class: 'isp', src: 'gen' };
			} else {
				uukey = main_udp_node;
				const ulabel = uci.get(uciconfig, main_udp_node, 'label');
				uowner = {
					class: 'node',
					sid: main_udp_node,
					label: (ulabel && length(ulabel)) ? '' + ulabel : main_udp_node,
					address_host: (ucfg.address && length('' + ucfg.address)) ? ('' + ucfg.address) : null,
					src: 'gen'
				};
			}
		}
		pp_gen({ tag: 'main-udp-out', kind: ukind, ukey: uukey, sig: 'e2:synth', owner: uowner });
	}
	if (pp.changed && pp.doc != null)
		ss_write_state('/etc/ravnex/provider_profile.json', pp.doc);
} catch (e) {
	warn('homeproxy: provider profile merge failed: ' + e + '\n');
}

/* ── Capability bookkeeping + runtime check-heal ──────────────────────────
 * Expose which nodes the selected core cannot load ($RUN_DIR/core_skipped.json
 * — rendered by the UI), then — for sing-box dialects only, since hiddify-core
 * has no `check` subcommand — ask the core itself to validate the freshly
 * written config. When the core rejects an outbound/endpoint type the static
 * tag map did not know about, record it (per core version) and regenerate
 * without it; the re-exec terminates because each pass adds one new type. */
if (hp_core) {
	const skipped_list = [];
	for (let k, v in hp_skipped_nodes)
		push(skipped_list, v);
	ss_write_state(RUN_DIR + '/core_skipped.json', {
		core: hp_core_id,
		version: hp_core.version,
		skipped: skipped_list
	});

	if (is_singbox) {
		/* Ф1.2 (аудит 27): check runs against the CANDIDATE, and its exit code
		 * is authoritative. rc==0 → the candidate is promoted. A non-type
		 * fatal (rc!=0, unknown pattern) leaves the running config untouched
		 * and exits 1 — init.d keeps/rolls back the previous config. */
		const chk_out = '/tmp/hp_check.out';
		const chk_rc = system(hp_shellquote(hp_core.path) + ' check -c ' +
		                      hp_shellquote(candidate) + ' >' + hp_shellquote(chk_out) + ' 2>&1');
		let out = (chk_rc != 0 && access(chk_out)) ? readfile(chk_out) : '';
		system('rm -f ' + hp_shellquote(chk_out));
		let bad = null;
		if (chk_rc != 0) {
			/* Pattern 1 captures the TYPE in m[1] and the word
			 * "outbound/endpoint" in m[2] — the other two patterns are the
			 * other way round. The old `m[2] || m[1]` extracted the literal
			 * word for pattern 1: an inert skip-entry that never matched the
			 * real type → check failed forever → infinite regen loop. */
			let m = match(out || '', /\[[0-9]+\]: ([a-z0-9_]+) (outbound|endpoint) is not included/);
			if (m)
				bad = m[1];
			if (!bad) {
				m = match(out || '', /unknown (outbound|endpoint) type: ([a-z0-9_]+)/);
				if (m)
					bad = m[2];
			}
			if (!bad) {
				m = match(out || '', /outbound type "([a-z0-9_]+)" not implemented/);   /* core dialect phrasing */
				if (m)
					bad = m[1];
			}
		}
		if (bad) {
			hp_extra_skip[bad] = true;
			writefile(hp_extra_skip_file, sprintf('%.J\n', {
				version: hp_core.version,
				types: keys(hp_extra_skip)
			}));
			warn(sprintf('homeproxy: the core rejects outbound type "%s" - regenerating without it.\n', bad));
			system('/usr/bin/ucode ' + hp_shellquote(HP_DIR + '/scripts/generate_client.uc') + ' >/dev/null 2>&1');
			exit(0);
		}
		if (chk_rc != 0) {
			/* A non-type fatal: the candidate stays on disk (the running config
			 * is NOT displaced); init.d keeps the previous config / rolls back
			 * to .lastgood — a dead core never gets a half-broken config. */
			warn('homeproxy: core config check FAILED - keeping the previous config ('
				+ trim(out || 'no output') + ')\n');
			exit(1);
		}
		if (out) {
			/* rc==0 with output: warnings only — log them, promote the config. */
			warn('homeproxy: core config check: ' + trim(out) + '\n');
		} else if (hp_extra_skip_stale) {
			/* The file held rejections from another core version and the current
			 * config validates — persist the (now empty) current-version state. */
			writefile(hp_extra_skip_file, sprintf('%.J\n', {
				version: hp_core.version,
				types: keys(hp_extra_skip)
			}));
		}
	}
}

/* Ф1.2: check passed (or the core has no check) — the candidate becomes the
 * running config, atomically. MUST run even when hp_core is null. */
system('mv -f ' + hp_shellquote(candidate) + ' ' + hp_shellquote(RUN_DIR + '/hiddify-c.json'));

/* Marker: the running config now references the learned local rule-sets, so Automation can
 * hot-reload (rewrite the files) instead of restarting the service. Absent → do_reload falls
 * back to a full restart once to inject the rule-sets, then writes this marker. */
writefile(RUN_DIR + '/.learned_hotreload', '1');
