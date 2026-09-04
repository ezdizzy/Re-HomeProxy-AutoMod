#!/usr/bin/ucode
/* config_heal.uc — проверка и самовосстановление критических конфигов приложения.
 *
 * Приложение редактирует /etc/config/firewall только при установке пакета
 * (uci-defaults). Если этот файл повредился (обрезан, откатился из бэкапа,
 * перезаписан другим пакетом), includes homeproxy_* исчезают и перехват
 * трафика молча перестаёт работать. Этот скрипт проверяет целостность
 * критических настроек и умеет их восстанавливать.
 *
 * Вызов:
 *   ucode config_heal.uc          — только проверка (dry-run), JSON-отчёт
 *   ucode config_heal.uc repair   — проверка + восстановление, JSON-отчёт
 */

'use strict';

import { readfile, writefile } from 'fs';
import { cursor } from 'uci';

const _mode = ARGV[0] || 'check';
const REPAIR = (_mode == 'repair' || _mode == 'repair-noreload' || _mode == 'repair-rules');
const FW_RELOAD = (_mode == 'repair' || _mode == 'repair-rules');
/* repair-rules: применять правила БЕЗУСЛОВНО (вызывается init.d, когда после
 * fw4 reload правил перехвата в живом nft всё равно нет — например, сборку
 * fw4 валит чужой битый include). */
const RULES_FORCE = (_mode == 'repair-rules');

let repaired = [];
let issues = [];
let warnings = [];
let checked = [];

function ok(name) { push(checked, name); }
function issue(msg) { push(issues, msg); }
function warn_msg(msg) { push(warnings, msg); }
function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

/* ---------------------------------------------------------------- firewall */
/* Эталонные includes из uci-defaults/luci-homeproxy: идемпотентно recreate.
 * ВАЖНО: '=include' — тип СЕКЦИИ (в batch), а ОПЦИЯ type обязана быть
 * 'nftables' — запись 'include' в опцию валит fw4 целиком (все правила
 * перехвата исчезают), поэтому значение зашито здесь константой. */
const FW_INCLUDES = {
	homeproxy_forward: {
		path: '/var/run/homeproxy/fw4_forward.nft',
		position: 'chain-pre', chain: 'forward'
	},
	homeproxy_input: {
		path: '/var/run/homeproxy/fw4_input.nft',
		position: 'chain-pre', chain: 'input'
	},
	homeproxy_post: {
		path: '/var/run/homeproxy/fw4_post.nft',
		position: 'table-post', chain: null
	}
};

function check_firewall() {
	/* get_all вернёт null и для отсутствующей секции, и для отсутствующего
	 * файла — оба случая считаем «сломанным firewall» и чиним одинаково. */
	const uci = cursor();
	uci.load('firewall');
	let need = false;
	let broken_names = [];

	for (let name, spec in FW_INCLUDES) {
		const vals = uci.get_all('firewall', name);
		let good = (vals && vals['.type'] === 'include' && vals.type === 'nftables' && vals.path === spec.path);
		if (good && spec.chain !== null)
			good = (vals.chain === spec.chain);
		if (good && spec.position)
			good = (vals.position === spec.position);
		if (!good) {
			push(broken_names, name);
			need = true;
		}
	}

	if (!need) {
		ok('firewall: includes homeproxy_* корректны');
		return true;
	}
	issue('firewall: сломаны/отсутствуют includes: ' + join(', ', broken_names));

	if (!REPAIR)
		return false;

	const lines = [
		'delete firewall.homeproxy_forward',
		'delete firewall.homeproxy_input',
		'delete firewall.homeproxy_post'
	];
	for (let name, spec in FW_INCLUDES) {
		push(lines, `set firewall.${name}=include`);
		/* ОПЦИЯ type — только 'nftables' ('include' в опции валит fw4 целиком). */
		push(lines, `set firewall.${name}.type=nftables`);
		push(lines, `set firewall.${name}.path=${shellquote(spec.path)}`);
		if (spec.position)
			push(lines, `set firewall.${name}.position=${spec.position}`);
		if (spec.chain !== null)
			push(lines, `set firewall.${name}.chain=${spec.chain}`);
	}
	push(lines, 'commit firewall');

	/* Через uci batch (как в uci-defaults): cursor.set не создаёт именованную
	 * секцию с типом, если она отсутствует. */
	writefile('/tmp/hp_fw_heal.batch', join('\n', lines) + '\n');
	if (system('uci -q batch < /tmp/hp_fw_heal.batch') === 0)
		push(repaired, 'firewall: includes homeproxy_* восстановлены');
	else
		issue('firewall: uci batch завершился ошибкой — includes НЕ восстановлены');
	system('rm -f /tmp/hp_fw_heal.batch');
	return false;
}

/* ----------------------------------------------------------------- uci-dhcp */
/* dnsmasq redirect делается в рантайме через /tmp — восстанавливать нечего,
 * но проверяем, что dnsmasq вообще сконфигурирован. */
function check_dnsmasq() {
	/* '@dnsmasq[0]' — синтаксис uci-CLI; через cursor libuci его не дают. */
	if (system('uci -q get dhcp.@dnsmasq[0] >/dev/null') !== 0) {
		issue('dhcp: секция dnsmasq не найдена');
		return false;
	}
	ok('dhcp: секция dnsmasq на месте');
	return true;
}

/* ------------------------------------------------------- /etc/config/homeproxy */
/* Если файл конфигурации приложения потерян — восстанавливаем поставочные
 * дефолты (пользовательские подписки/узлы при этом, к сожалению, не вернуть:
 * их просто не из чего). */
const HP_DEFAULT = `
config homeproxy 'infra'
	option __warning 'DO NOT EDIT THIS SECTION, OR YOU ARE ON YOUR OWN!'
	option common_port '22,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418'
	option mixed_port '5330'
	option redirect_port '5331'
	option tproxy_port '5332'
	option dns_port '5333'
	option dns_redirect '1'
	option ntp_server 'nil'
	option sniff_override '1'
	option udp_timeout ''
	option tun_name 'singtun0'
	option tun_addr4 '172.19.0.1/30'
	option tun_addr6 'fdfe:dcba:9876::1/126'
	option tun_mtu '9000'
	option table_mark '100'
	option self_mark '100'
	option tproxy_mark '101'
	option tun_mark '102'
	option tun_table '104'

config homeproxy 'migration'
	option crontab '1'

config homeproxy 'config'
	option main_node 'nil'
	option main_udp_node 'same'
	option dns_server '8.8.8.8'
	option china_dns_server '223.5.5.5'
	option routing_mode 'proxy_banned_ru'
	option proxy_mode 'redirect_tproxy'
	option ipv6_support '0'
	option proxy_calls '1'
	option no_proxy_torrents '1'
	option github_token ''
	option log_level 'warn'
	list alt_dns_servers ''
	list russia_dns_server '77.88.8.8'
	list russia_dns_server '8.8.8.8'
	list russia_dns_server 'https://cloudflare-dns.com/dns-query'
	list secure_dns_server 'https://dns.google/dns-query'
	list secure_dns_server 'https://cloudflare-dns.com/dns-query'
	list secure_dns_server 'https://dns.quad9.net/dns-query'
	option dns_failover '0'
	option dns_failover_plain '0'
	option dns_failover_secure '0'
	option russia_dns_use_wan '1'
	option russia_dns_auto_doh '0'

config homeproxy 'control'
	option lan_proxy_mode 'disabled'

config homeproxy 'routing'
	option sniff_override '1'
	option default_outbound 'direct-out'
	option default_outbound_dns 'default-dns'

config homeproxy 'dns'
	option dns_strategy 'prefer_ipv4'
	option default_server 'local-dns'
	option disable_cache '0'
	option disable_cache_expire '0'

config homeproxy 'multidns'
	option enabled '0'
	option use_plain '1'
	option use_secure '1'
	option secure_via_proxy '1'
	option bench_interval '120'
	option alpha '0.4'
	option min_live_ratio '0.5'
	option min_score '20'
	option plain_port '5453'
	option secure_port '5454'
	option proxy_port '5338'

config homeproxy 'subscription'
	option auto_update '0'
	option allow_insecure '0'
	option packet_encoding 'xudp'
	option update_via_proxy '0'
	option filter_nodes 'blacklist'

config homeproxy 'server'
	option enabled '0'
	option log_level 'warn'

config homeproxy 'automation'
	option enabled '0'
	option mode 'balanced'
	option test_method 'http'
	option timeout '6'
	option max_entries '2000'
	option min_confirm '1'
	option discover 'all'
	option reeval_interval '3600'
	option reload_interval '300'
	option exclude 'localhost,local,lan,in-addr.arpa,ip6.arpa'
	option proxy_path 'main'
	option flush_min_entries '5'
	option ip_learn '0'
`;

function check_homeproxy_cfg() {
	const path = '/etc/config/homeproxy';
	const content = readfile(path);
	if (content !== null && length(content) > 0) {
		ok('homeproxy: /etc/config/homeproxy на месте');
		return true;
	}
	issue('homeproxy: /etc/config/homeproxy отсутствует/пуст — восстановлю дефолты');
	if (!REPAIR)
		return false;
	writefile(path, HP_DEFAULT);
	push(repaired, 'homeproxy: восстановлены поставочные дефолты /etc/config/homeproxy');
	return false;
}

/* -------------------------------------------------------------- файлы пакета */
const REQUIRED_FILES = [
	'/etc/init.d/homeproxy',
	'/etc/homeproxy/scripts/generate_client.uc',
	'/etc/homeproxy/scripts/multidns.uc',
	'/etc/homeproxy/scripts/automation.uc',
	'/usr/share/rpcd/ucode/luci.homeproxy'
];

function check_files() {
	let missing = [];
	for (let f in REQUIRED_FILES)
		if (!readfile(f))
			push(missing, f);
	if (length(missing)) {
		issue('пакет: отсутствуют файлы: ' + join(', ', missing) + ' — требуется переустановка пакета');
		return false;
	}
	ok('пакет: все ключевые файлы на месте');
	return true;
}

/* --------------------------------------------------------------- применение */
function capture(cmd) {
	const tmp = '/tmp/hp_heal_cap.tmp';
	system(cmd + ' > ' + shellquote(tmp) + ' 2>&1');
	const c = readfile(tmp);
	system('rm -f ' + shellquote(tmp));
	return c || '';
}

/* Живой nft: даже корректные UCI-includes бесполезны, если fw4 не собирает
 * ruleset (наблюдено вживую: ЧУЖОЙ битый include валит сборку целиком —
 * 'In file included from ...' — и весь перехват homeproxy молча исчезает). */
function nft_homeproxy_lines() {
	const out = capture('nft list table inet fw4 2>/dev/null');
	return length(filter(split(out, '\n'), (l) => match(l, /homeproxy/)));
}

function service_active() {
	if (system('pidof hiddify-core >/dev/null 2>&1') === 0)
		return true;
	if (system('pidof sing-box >/dev/null 2>&1') === 0)
		return true;
	return false;
}

function check_nft_live() {
	/* Служба не запущена — правил перехвата в nft и не должно быть. */
	if (!service_active()) {
		ok('nft: служба не запущена — live-проверка пропущена');
		return true;
	}
	if (nft_homeproxy_lines() > 0) {
		ok('nft: правила перехвата применены в живом fw4');
		return true;
	}
	issue('nft: правил перехвата homeproxy НЕТ в живой таблице fw4 — сборка fw4 падает (битый include?) или firewall не запущен');
	return false;
}

/* Отключить ЧУЖИЕ includes, из-за которых nft отказывается собирать ruleset.
 * Виновников ищем рендером ruleset (fw4 print) + nft -c -f (проверка синтаксиса,
 * ничего не применяет): fw4 start без state-файла не собирает ruleset и не
 * показывает виновника. nft -c пишет «In file included from <файл>» на каждую
 * ошибку — сопоставляем файл с секциями firewall include. Свои секции
 * (homeproxy_*) не трогаем — их чинит основной путь. */
function disable_broken_foreign_includes() {
	const rtmp = '/tmp/hp_heal_ruleset.nft';
	system('fw4 print > ' + shellquote(rtmp) + ' 2>/dev/null');
	const err = capture('nft -c -f ' + shellquote(rtmp));
	system('rm -f ' + shellquote(rtmp));
	const bad_files = [];
	for (let line in split(err, '\n')) {
		const m = match(line, /In file included from [^:]+:.*$/);
		const f = m ? replace(replace(m[0], 'In file included from ', ''), /:[0-9-]+.*$/, '') : null;
		if (f && !match(f, /homeproxy/) && index(bad_files, f) === -1)
			push(bad_files, f);
	}
	if (length(bad_files) === 0)
		return false;

	const uci = cursor();
	uci.load('firewall');
	let disabled = false;
	uci.foreach('firewall', 'include', (s) => {
		if (s.path && index(bad_files, s.path) !== -1 && s['.name'] && !match(s['.name'], /^homeproxy/)) {
			uci.set('firewall', s['.name'], 'enabled', '0');
			disabled = true;
			push(repaired, 'firewall: чужой битый include отключён (enabled=0): ' + s['.name'] + ' → ' + s.path);
		}
	});
	if (!disabled)
		return false;
	uci.commit('firewall');
	return true;
}

function apply_rules() {
	if (!FW_RELOAD)
		return;
	if (system('fw4 reload >/dev/null 2>&1') === 0) {
		push(repaired, 'firewall: fw4 reload применён');
		return;
	}
	/* fw4 reload отказывает, когда у fw4 нет state-файла («does not appear to
	 * be loaded») — наблюдено вживую. Полный рестарт службы firewall
	 * пересоздаёт state и всю таблицу (включая наши includes). */
	if (system('/etc/init.d/firewall restart >/dev/null 2>&1') === 0) {
		push(repaired, 'firewall: правила применены через рестарт службы firewall');
		return;
	}
	/* Firewall всё ещё не собирается — ищем чужие битые include и отключаем. */
	if (disable_broken_foreign_includes()) {
		if (system('/etc/init.d/firewall restart >/dev/null 2>&1') === 0)
			push(repaired, 'firewall: после отключения чужого include правила применены');
		else
			warn_msg('firewall: чужой include отключён, но правила не применились — попробуйте рестарт службы/роутера');
		return;
	}
	warn_msg('firewall: fw4 reload и рестарт firewall не сработали — правила применятся при рестарте службы или роутера');
}

check_files();
check_homeproxy_cfg();
const fw_ok = check_firewall();
check_dnsmasq();
const nft_ok = check_nft_live();

/* Чиним, если сломан UCI-слой, правила не применены в живом nft,
 * или это принудительный repair-rules. */
if (REPAIR && (!fw_ok || !nft_ok || RULES_FORCE))
	apply_rules();

printf('%s\n', sprintf('%J', {
	mode: _mode,
	ok: (length(issues) == 0),
	checked: checked,
	repaired: repaired,
	warnings: warnings,
	issues: issues
}));
