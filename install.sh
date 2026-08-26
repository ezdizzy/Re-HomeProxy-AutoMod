#!/bin/sh
# Установщик и интерактивный конфигуратор Re:HomeProxy AutoMod для OpenWrt (apk / opkg / 23.05 legacy)
# https://github.com/ezdizzy/re-homeproxy
#
# Вручную ставится только LuCI-приложение + ключ подписи, а ядро, ByeDPI и Zapret
# устанавливаются через собственный бэкенд приложения (core_mgmt.uc + rpcd-объект
# luci.homeproxy) — поэтому определение архитектуры, компактные сборки под малую
# флеш-память, проверка подписи и резерв через зеркало GitHub работают той же
# проверенной логикой, что и графический интерфейс.
#
# Установка (одной строкой — ввод читается из /dev/tty, пайп остаётся интерактивным):
#   wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | sh
# Для ЭТОГО форка HP_REPO по умолчанию = ezdizzy/re-homeproxy, поэтому приложение и
# русская локаль ставятся именно из вашего репозитория; ядра/ByeDPI/Zapret — из апстрима.
# Либо в два шага (надёжнее, если нужно переопределить репозиторий):
#   wget -O /tmp/install.sh https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh
#   HP_REPO=otheruser/re-homeproxy sh /tmp/install.sh
#
# При заблокированном/замедленном GitHub можно указать зеркало:
#   GH_MIRROR=https://my.mirror sh install.sh
# (зеркало также пишется в uci, чтобы делегированные загрузки тоже его использовали).
# Внимание: `sh <(wget -O- ...)` на OpenWrt НЕ работает — в busybox ash нет
# process substitution; используйте форму с пайпом выше.
#
# ПОВТОРНЫЙ ЗАПУСК = режим настройки: скрипт обнаруживает уже установленное приложение,
# показывает состояние всех модулей и предлагает интерактивное меню (добавить подписку /
# строку подключения, выбрать основной узел, включить MultiDNS/Автоматизацию, подобрать
# стратегию Zapret и т.д.). Ничего уже настроенного не ломается.
#
# Главное правило: после установки/настройки пользователь НИКОГДА не остаётся без
# интернета — при отсутствии подписки включается прямой режим (direct) и автоматически
# создаётся правило «YouTube → Zapret» (если Zapret установлен; иначе правило деградирует
# в прямой доступ и просто ничего не блокирует).
HP_REPO="${HP_REPO:-ezdizzy/re-homeproxy}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; N='\033[0m'
ok()   { echo -e "${G}$1${N}"; }
info() { echo -e "${C}$1${N}"; }
warn() { echo -e "${Y}$1${N}"; }
die()  { echo -e "${R}$1${N}"; exit 1; }
ask()  { printf "${C}%s${N} " "$1"; REPLY=""; [ -c /dev/tty ] && read -r REPLY 2>/dev/null </dev/tty || REPLY=""; }
is_yes() { case "$1" in y|Y|yes|YES|да|Да|д|Д) return 0;; *) return 1;; esac; }
is_no()  { case "$1" in n|N|no|NO|нет|Нет|н|Н) return 0;; *) return 1;; esac; }

# --- Разбор JSON (на устройстве нет jq): достать строковое поле / проверить result:true
jget()  { printf '%s\n' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }
jtrue() { printf '%s'   "$1" | grep -qE "\"result\"[[:space:]]*:[[:space:]]*true"; }
jerr()  { printf '%s\n' "$1" | grep -qE "\"error\""; }
jfalse(){ printf '%s'   "$1" | grep -qE "\"$2\"[[:space:]]*:[[:space:]]*false"; }

# --- Загрузка «сначала GitHub, при сбое — зеркало» для первого хопа (app + ключ),
#     пока ещё нет собственного gh_fetch приложения. dl <url> <файл>
dl() {
	wget -qO "$2" --timeout=20 "$1" 2>/dev/null && [ -s "$2" ] && return 0
	if [ -n "$GH_MIRROR" ]; then
		m=$(echo "$1" | sed "s#https://github.com#${GH_MIRROR}#")
		wget -qO "$2" --timeout=20 "$m" 2>/dev/null && [ -s "$2" ] && return 0
	fi
	return 1
}
api() { wget -qO- --timeout=20 "$1" 2>/dev/null; }   # GitHub API (без зеркала)

CM=/usr/share/homeproxy/scripts/core_mgmt.uc
HAS_UCB=0
have_ubus() { command -v ubus >/dev/null 2>&1; }

# ------------------------------------------------------------------ helpers

count_nodes() {
	uci show homeproxy 2>/dev/null | grep -cE "^homeproxy\.[^.]+=node$"
}

# Домен/адрес узла -> IPv4 (пусто, если не резолвится)
resolve4() {
	nslookup -type=A "$1" 2>/dev/null | grep -v ':53' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1
}

# Гео по IP в формате диагностики: "<ip> (<CC>, <ORG>)". Без пинга — он одномоментный.
# Результат кэшируется на время одного вызова list_nodes (файл $1).
geo_cached() {
	local IP="$1" CACHE="$2" R CC ORG C
	C=$(grep -F "$IP|" "$CACHE" 2>/dev/null | head -n1 | cut -d'|' -f2-)
	if [ -z "$C" ]; then
		R=$(wget -qO- --timeout=5 "http://ip-api.com/json/$IP?fields=countryCode,org&lang=ru" 2>/dev/null)
		CC=$(printf '%s' "$R" | sed -n 's/.*"countryCode":"\([^"]*\)".*/\1/p')
		ORG=$(printf '%s' "$R" | sed -n 's/.*"org":"\([^"]*\)".*/\1/p')
		C="$IP"
		[ -n "$CC" ] && C="$C ($CC"
		[ -n "$ORG" ] && C="$C, $ORG"
		[ -n "$CC" ] && C="$C)"
		printf '%s|%s\n' "$IP" "$C" >> "$CACHE"
	fi
	printf '%s' "$C"
}

list_nodes() {
	# Человекочитаемый список как в Диагностике: «Метка → IP (CC, организация)»,
	# имя секции — в конце строки (его просят ввести в меню выбора узла).
	local GEO=/tmp/hp_geo.$$
	: > "$GEO"
	uci show homeproxy 2>/dev/null | sed -n 's/^homeproxy\.\([^.]*\)=node$/\1/p' | while read -r sec; do
		LBL=$(uci -q get "homeproxy.$sec.label" 2>/dev/null)
		[ -z "$LBL" ] && LBL=$sec
		ADDR=$(uci -q get "homeproxy.$sec.address" 2>/dev/null)
		INFO=""
		if [ -n "$ADDR" ]; then
			IP=$(resolve4 "$ADDR")
			[ -n "$IP" ] && INFO=" → $(geo_cached "$IP" "$GEO")"
		fi
		printf "    %s%s  [%s]\n" "$LBL" "$INFO" "$sec"
	done
	rm -f "$GEO"
}

# Добавить правило прокси, если правила с таким источником ещё нет. add_rule <source> <node>
add_rule() {
	# uci show prints auto-generated section ids (homeproxy.cfgXXXX.source='…'),
	# NOT the section type — matching on "proxy_ru_rule" never matched, so every
	# re-run appended another duplicate rule.
	if uci show homeproxy 2>/dev/null | grep -q "\.source='$1'"; then
		return 0
	fi
	SEC=$(uci add homeproxy proxy_ru_rule 2>/dev/null)
	[ -n "$SEC" ] || { warn "  не удалось добавить правило $1 → $2."; return 1; }
	uci -q set "homeproxy.$SEC.source=$1"
	uci -q set "homeproxy.$SEC.node=$2"
	uci -q set "homeproxy.$SEC.enabled=1"
	uci -q commit homeproxy
	ok "  добавлено правило: Источник $1 → Узел $2"
	return 0
}

# Гарантия интернета: если основной узел не задан (нет подписки/узлов) — прямой режим
# и правило YouTube → Zapret. Ничего уже настроенного не трогает.
ensure_baseline() {
	apply_gh_mirror
	[ -z "$(uci -q get homeproxy.config.routing_mode)" ] && uci -q set homeproxy.config.routing_mode=proxy_banned_ru
	[ -z "$(uci -q get homeproxy.config.main_udp_node)" ] && uci -q set homeproxy.config.main_udp_node=same
	MN=$(uci -q get homeproxy.config.main_node)
	if [ -z "$MN" ] || [ "$MN" = nil ]; then
		if [ "$(count_nodes)" -gt 0 ]; then
			uci -q set homeproxy.config.main_node=urltest
			uci -q set homeproxy.config.main_urltest_mode=auto
			ok "  узлы найдены — включён URLTest (авто, все узлы)."
			[ "$(uci -q get homeproxy.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
		elif [ "$(uci -q get homeproxy.config.zapret_enabled)" = 1 ]; then
			# Zapret is an engine, not a main node: direct main keeps the internet up.
			# NO unconditional YouTube→Zapret rule here: per policy that rule is added
			# ONLY after a strategy passed its live test (install_zapret does exactly
			# that); re-running the installer must not route YouTube into an untested
			# engine.
			uci -q set homeproxy.config.main_node=direct-out
			info "  нет подписки: интернет напрямую."
			info "  YouTube через Zapret добавится после успешного теста стратегии (пункт меню Zapret)."
		else
			uci -q set homeproxy.config.main_node=direct-out
			info "  нет подписки: интернет работает как обычно (напрямую)."
			info "  Заблокированные сайты станут доступны после добавления подписки/узла."
		fi
		uci -q commit homeproxy
	fi
}

# Дефолтные DNS-пулы MultiDNS/резолверов: 3 обычных + 3 защищённых (только если не заданы)
set_dns_defaults() {
	CUR=$(uci -q get homeproxy.config.russia_dns_server)
	if [ -z "$CUR" ]; then
		uci -q delete homeproxy.config.russia_dns_server 2>/dev/null
		uci -q add_list homeproxy.config.russia_dns_server=77.88.8.8
		uci -q add_list homeproxy.config.russia_dns_server=8.8.8.8
		uci -q add_list homeproxy.config.russia_dns_server=https://cloudflare-dns.com/dns-query
		ok "  обычный DNS-пул: Яндекс 77.88.8.8, Google 8.8.8.8, Cloudflare DoH (прямой)"
	fi
	CUR=$(uci -q get homeproxy.config.secure_dns_server)
	if [ -z "$CUR" ]; then
		uci -q delete homeproxy.config.secure_dns_server 2>/dev/null
		uci -q add_list homeproxy.config.secure_dns_server=https://dns.google/dns-query
		uci -q add_list homeproxy.config.secure_dns_server=https://cloudflare-dns.com/dns-query
		uci -q add_list homeproxy.config.secure_dns_server=https://dns.quad9.net/dns-query
		ok "  защищённый DNS-пул: Google, Cloudflare, Quad9 (DoH)"
	fi
	CUR=$(uci -q get homeproxy.config.russia_dns_use_wan)
	if [ -z "$CUR" ]; then
		uci -q set homeproxy.config.russia_dns_use_wan='1'
		ok "  DNS провайдера (WAN) добавлен в обычный пул по умолчанию"
	fi
	uci -q commit homeproxy
}

wait_core() {
	i=0
	while [ $i -lt 40 ]; do
		pidof hiddify-core >/dev/null 2>&1 && return 0
		pidof sing-box >/dev/null 2>&1 && return 0
		sleep 2; i=$((i+2))
	done
	warn "  ядро не запустилось за 40с — проверьте Диагностику в LuCI."
	return 1
}

internet_check() {
	if command -v curl >/dev/null 2>&1; then
		CODE=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 8 --max-time 12 https://www.google.com 2>/dev/null)
		case "$CODE" in
			2??|3??) ok "  интернет работает (google.com → HTTP $CODE)."; return 0;;
			*) warn "  google.com не ответил (HTTP ${CODE:-—})."; return 1;;
		esac
	fi
	if wget --spider -qT8 https://www.google.com 2>/dev/null; then
		ok "  интернет работает (google.com отвечает)."; return 0
	fi
	warn "  google.com не отвечает — откройте LuCI → Диагностика."
	return 1
}

# Проверка, что прокси-путь реально работает (если есть узлы)
validate_proxy() {
	if [ "$(count_nodes)" -eq 0 ]; then return 0; fi
	MIX=$(uci -q get homeproxy.infra.mixed_port)
	[ -z "$MIX" ] && MIX=5330
	if command -v curl >/dev/null 2>&1; then
		CODE=$(curl -sx "socks5://127.0.0.1:$MIX" -o /dev/null -w '%{http_code}' \
			--connect-timeout 10 --max-time 20 https://www.youtube.com 2>/dev/null)
		case "$CODE" in
			2??|3??) ok "  прокси работает (YouTube через основной узел — HTTP $CODE)."; return 0;;
			*) warn "  прокси пока не отвечает (HTTP ${CODE:-—}) — проверьте узел в LuCI → Диагностика."; return 1;;
		esac
	fi
	RES=$(ubus call luci.homeproxy connection_check '{"site":"youtube"}' 2>/dev/null)
	if printf '%s' "$RES" | grep -q '"result"[[:space:]]*:[[:space:]]*true'; then
		ok "  прокси работает (YouTube отвечает)."; return 0
	fi
	warn "  прокси пока не отвечает — проверьте узел в LuCI → Диагностика."
	return 1
}

apply_and_check() {
	info "  применяю настройки (перезапуск службы)..."
	/etc/init.d/homeproxy enable >/dev/null 2>&1
	/etc/init.d/homeproxy restart >/dev/null 2>&1
	wait_core
	sleep 3
	validate_proxy
	internet_check
}

status_line() {
	CORE="нет"; [ -x /usr/bin/hiddify-core ] && CORE=hiddify-core; [ -x /usr/bin/sing-box ] && CORE="$CORE + sing-box"
	MOS="нет"; [ -x /usr/bin/mosdns ] && MOS="да"
	ZAP="нет"; [ -x /opt/zapret2/nfq2/nfqws2 ] && ZAP="да"
	BYE="нет"; [ -x /usr/bin/ciadpi ] && BYE="да"
	CURL="нет"; command -v curl >/dev/null 2>&1 && CURL="да"
	MN=$(uci -q get homeproxy.config.main_node); [ -z "$MN" ] && MN="(не задан)"
	MD="выкл"; [ "$(uci -q get homeproxy.multidns.enabled)" = 1 ] && MD="вкл"
	AU="выкл"; [ "$(uci -q get homeproxy.automation.enabled)" = 1 ] && AU="вкл"
	ZN="выкл"; [ "$(uci -q get homeproxy.config.zapret_enabled)" = 1 ] && ZN="вкл"
	echo "  Ядро: $CORE | mosdns: $MOS | Zapret: $ZAP ($ZN) | ByeDPI: $BYE | curl: $CURL"
	echo "  Узлов: $(count_nodes) | Основной узел: $MN | MultiDNS: $MD | Автоматизация: $AU"
}

# ---------------------------------------------------------------- 0. окружение
echo
ok "===== Re:HomeProxy AutoMod — установка и настройка ====="

[ "$(id -u)" = 0 ] || die "Запустите от root."
[ -r /etc/openwrt_release ] || die "Это не OpenWrt (нет /etc/openwrt_release)."
. /etc/openwrt_release 2>/dev/null
ARCH="$DISTRIB_ARCH"; VER="$DISTRIB_RELEASE"
[ -n "$ARCH" ] || die "Не удалось определить архитектуру пакетов (DISTRIB_ARCH)."
if   command -v apk  >/dev/null 2>&1; then PM=apk;  EXT=apk
elif command -v opkg >/dev/null 2>&1; then PM=opkg; EXT=ipk
else die "Не найден поддерживаемый менеджер пакетов (apk/opkg)."; fi
case "$VER" in
	23.05*)              LEGACY=1 ;;
	24.10*|25.*|*SNAPSHOT*) LEGACY=0 ;;
	22.*|21.*|19.*)      die "OpenWrt $VER слишком старая — нужна 23.05 или новее." ;;
	*)                   LEGACY=0; warn "Непроверенная версия OpenWrt $VER — продолжаю." ;;
esac
SUFFIX="_all"; [ "$LEGACY" = 1 ] && SUFFIX="_all-legacy"
info "Версия: OpenWrt $VER  |  Архитектура: $ARCH  |  Менеджер пакетов: $PM  |  legacy=$LEGACY"

# Прописываем зеркало в бэкенд, чтобы делегированные загрузки тоже его использовали
# Зеркало GitHub для бэкенда приложения пишем в UCI ПОСЛЕ установки пакета:
# ранняя запись при отсутствии /etc/config/homeproxy создавала пустой конфиг,
# который (как conffile) блокировал поставку shipped-дефолтов из пакета.
apply_gh_mirror() {
	if [ -n "$GH_MIRROR" ] && [ -f /etc/config/homeproxy ]; then
		uci set homeproxy.config.github_mirror="$GH_MIRROR"
		uci commit homeproxy 2>/dev/null
	fi
}

# Приложение уже установлено?
APP_INSTALLED=0
if [ -f /etc/config/homeproxy ] && [ -f /usr/share/rpcd/ucode/luci.homeproxy ] && command -v ucode >/dev/null 2>&1; then
	APP_INSTALLED=1
fi

# ------------------------------------------------- Проверка версии и пакеты приложения
# Сравнить две версии X.Y.Z: 0, если $1 < $2 (нужно обновление), иначе 1.
ver_lt() {
	awk -v a="$1" -v b="$2" 'BEGIN {
		na = split(a, A, "[.]"); nb = split(b, B, "[.]");
		n = (na > nb) ? na : nb;
		for (i = 1; i <= n; i++) {
			xa = (i <= na) ? (A[i] + 0) : 0;
			xb = (i <= nb) ? (B[i] + 0) : 0;
			if (xa < xb) { exit 0 }
			if (xa > xb) { exit 1 }
		}
		exit 1
	}'
}

# Установленная версия пакета приложения (пусто, если не определена).
app_installed_version() {
	if [ "$PM" = apk ]; then
		apk info luci-app-re-homeproxy 2>/dev/null | head -1 \
			| sed -n 's/.*luci-app-re-homeproxy-\([0-9][0-9.]*\).*/\1/p'
	else
		opkg status luci-app-re-homeproxy 2>/dev/null \
			| sed -n 's/^Version: \([0-9][0-9.]*\).*/\1/p'
	fi
}

# Последняя версия из GitHub-релиза (пусто, если GitHub недоступен).
app_latest_version() {
	api "https://api.github.com/repos/${HP_REPO}/releases/latest" \
		| sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v*\([0-9][0-9.]*\)".*/\1/p' | head -1
}

# Ключ подписи apk (идемпотентно; best-effort).
ensure_key() {
	[ "$PM" = apk ] || return 0
	[ -f /etc/apk/keys/homeproxy-hiddify.pub ] && return 0
	dl "https://github.com/${HP_REPO}/releases/latest/download/homeproxy-hiddify.pub" /tmp/hp.pub \
		&& cp /tmp/hp.pub /etc/apk/keys/ && rm -f /tmp/hp.pub \
		&& ok "  ключ подписи добавлен в доверенные" \
		|| warn "  не удалось скачать ключ подписи — поставлю без проверки подписи"
}

# Скачать и установить приложение + русскую локаль из последнего релиза (без вопросов).
# Возвращает 0 при успешной установке приложения.
app_install_pkgs() {
	APPURL=$(api "https://api.github.com/repos/${HP_REPO}/releases" \
		| grep -o "https://github\.com/[^\"]*luci-app-re-homeproxy[^\"]*${SUFFIX}\.${EXT}" | head -1)
	if [ -z "$APPURL" ]; then warn "  не нашёл пакет luci-app-re-homeproxy${SUFFIX}.${EXT} (GitHub заблокирован?)."; return 1; fi
	dl "$APPURL" /tmp/app.$EXT || { warn "  не удалось скачать приложение."; return 1; }
	if [ "$PM" = apk ]; then
		apk add /tmp/app.$EXT 2>/dev/null || apk add --allow-untrusted /tmp/app.$EXT || { rm -f /tmp/app.$EXT; warn "  apk add завершился ошибкой."; return 1; }
	else
		opkg update >/dev/null 2>&1; opkg install /tmp/app.$EXT || { rm -f /tmp/app.$EXT; warn "  opkg install завершился ошибкой."; return 1; }
	fi
	rm -f /tmp/app.$EXT

	LURL=$(api "https://api.github.com/repos/${HP_REPO}/releases" \
		| grep -o "https://github\.com/[^\"]*luci-i18n-homeproxy-ru[^\"]*\.${EXT}" | head -1)
	if [ -n "$LURL" ] && dl "$LURL" /tmp/i18n.$EXT; then
		if [ "$PM" = apk ]; then apk add /tmp/i18n.$EXT 2>/dev/null || apk add --allow-untrusted /tmp/i18n.$EXT; \
		else opkg install /tmp/i18n.$EXT; fi
		rm -f /tmp/i18n.$EXT
	fi
	return 0
}

# Обновить приложение и перевод, если установлена старая версия (best-effort:
# при недоступном GitHub настройка продолжается со старой версией).
app_update_if_needed() {
	INST=$(app_installed_version)
	if [ -z "$INST" ]; then
		warn "  не удалось определить установленную версию — пропускаю проверку обновления."
		return 0
	fi
	LATEST=$(app_latest_version)
	if [ -z "$LATEST" ]; then
		warn "  не удалось проверить свежую версию (GitHub недоступен?) — продолжаю с установленной $INST."
		return 0
	fi
	if ver_lt "$INST" "$LATEST"; then
		info "  установлена $INST, свежая $LATEST — обновляю приложение и перевод..."
		ensure_key
		if app_install_pkgs; then
			ok "  приложение обновлено до $LATEST."
		else
			warn "  обновление не удалось — продолжаю со старой версией (часть функций может работать некорректно)."
		fi
	else
		ok "  приложение актуально ($INST)."
	fi
}

# ------------------------------------------------- 1. LuCI-приложение + ключ
install_app() {
	ok "[1/7] Устанавливаю LuCI-приложение Re:HomeProxy AutoMod..."
	ensure_key
	app_install_pkgs || die "Установка приложения завершилась ошибкой."
	ok "  приложение установлено."

	# Русский язык интерфейса (по умолчанию — да)
	ask "  Установить пакет русского языка? [Д/н] (по умолчанию да):"
	if ! is_no "$REPLY"; then
		info "  ставлю русский язык LuCI..."
		if [ "$PM" = apk ]; then apk add luci-i18n-base-ru >/dev/null 2>&1; else opkg install luci-i18n-base-ru >/dev/null 2>&1; fi
		uci set luci.main.lang=ru; uci commit luci
		ok "  русский язык установлен" 
	fi

	# rpcd нужно перезапустить, чтобы появились ubus-методы приложения
	/etc/init.d/rpcd restart >/dev/null 2>&1; sleep 2
	[ -f "$CM" ] || die "core_mgmt.uc не найден после установки — прерываю."
}

# ------------------------------------------------------- 2. ядро прокси
install_core() {
	ok "[2/7] Ядро прокси (обязательно — выберите одно)"
	warn "  ⚠  Без действующей подписки/конфигурации прокси-часть работать не будет:"
	warn "     Telegram, WhatsApp, Instagram и другие заблокированные сервисы останутся недоступны."
	warn "     Интернет при этом останется полностью рабочим (напрямую)."
	echo "    1) hiddify-core       (по умолчанию; на малой флеш-памяти выберет компактную сборку)"
	echo "    2) sing-box-extended  (AmneziaWG / WARP, самый широкий набор протоколов)"
	ask "  Выбор [1/2] (по умолчанию 1):"
	case "$REPLY" in 2) CORE=singbox ;; *) CORE=hiddify ;; esac

	PREP=$(ucode "$CM" prepare_install "$CORE" 2>/dev/null)
	jerr "$PREP" && die "  подготовка ядра не удалась: $(jget "$PREP" error)"
	DLURL=$(jget "$PREP" dl_url); TMP=$(jget "$PREP" tmp_path); PMG=$(jget "$PREP" pkg_manager)
	[ -n "$DLURL" ] && [ -n "$TMP" ] && [ -n "$PMG" ] || die "  подготовка ядра не вернула данные для загрузки."
	info "  скачиваю $CORE..."
	jtrue "$(ucode "$CM" download_pkg "$DLURL" "$TMP" 2>/dev/null)" || die "  не удалось скачать ядро (попробуйте GH_MIRROR=...)."
	jtrue "$(ucode "$CM" install_pkg "$CORE" "$TMP" "$PMG" 2>/dev/null)" || die "  установка ядра не удалась."
	jtrue "$(ucode "$CM" install_kmods "$PMG" 2>/dev/null)" || warn "  не удалось поставить kmod — без kmod-nft-tproxy/kmod-tun прокси не будет маршрутизировать."
	ok "  $CORE установлен."
}

# ------------------------------------------------------ 2.5 mosdns (MultiDNS)
install_mosdns() {
	if [ -x /usr/bin/mosdns ]; then ok "  mosdns уже установлен."; return 0; fi
	info "  ставлю mosdns (движок гонки DNS для MultiDNS)..."
	case "$ARCH" in
		aarch64_*) MARCH=arm64 ;;
		arm_cortex-a7*|arm_cortex-a9*|arm_cortex-a15*|arm_cortex-a8*|arm_mpcore*) MARCH=arm-7 ;;
		arm_cortex-a5*|arm926ej-s|arm_fa526) MARCH=arm-6 ;;
		x86_64) MARCH=amd64 ;;
		mipsel_24kc|mipsel_74kc) MARCH=mipsle-softfloat ;;
		*) MARCH="" ;;
	esac
	if [ -z "$MARCH" ]; then
		warn "  mosdns: нет готового бинарника для архитектуры $ARCH — пропускаю (MultiDNS будет недоступен)."
		return 1
	fi
	if ! command -v unzip >/dev/null 2>&1; then
		if [ "$PM" = apk ]; then apk add unzip >/dev/null 2>&1; else opkg install unzip >/dev/null 2>&1; fi
	fi
	if command -v unzip >/dev/null 2>&1 && \
	   dl "https://github.com/IrineSistiana/mosdns/releases/latest/download/mosdns-linux-${MARCH}.zip" /tmp/mosdns.zip; then
		unzip -o /tmp/mosdns.zip -d /tmp/mosdns >/dev/null 2>&1
		MBIN=$(find /tmp/mosdns -type f -name 'mosdns' | head -1)
		if [ -n "$MBIN" ]; then
			# busybox `install` applet отсутствует на части образов — cp + chmod эквивалентны
			cp "$MBIN" /usr/bin/mosdns && chmod 0755 /usr/bin/mosdns && ok "  mosdns установлен ($MARCH)."
		else
			warn "  mosdns: бинарник не найден в архиве — пропускаю."
		fi
		rm -rf /tmp/mosdns /tmp/mosdns.zip
	else
		warn "  mosdns: не удалось скачать (GitHub заблокирован? попробуйте GH_MIRROR=...) — MultiDNS будет недоступен."
		return 1
	fi
	return 0
}

# ------------------------------------------------- 3. подписка / конфигурация
subscription_add() {
	ask "  Вставьте URL подписки (например https://ваш-провайдер/sub):"
	URL=$(echo "$REPLY" | tr -d ' ')
	if [ -z "$URL" ]; then warn "  URL пуст — пропускаю."; return 1; fi
	uci -q add_list homeproxy.subscription.subscription_url="$URL"
	uci -q commit homeproxy
	info "  загружаю узлы из подписки (может занять минуту)..."
	ucode /etc/homeproxy/scripts/update_subscriptions.uc >/dev/null 2>&1
	if [ "$(count_nodes)" -gt 0 ]; then
		ok "  подписка добавлена: узлов $(count_nodes)."
		MN=$(uci -q get homeproxy.config.main_node)
		if [ -z "$MN" ] || [ "$MN" = nil ]; then
			uci -q set homeproxy.config.main_node=urltest
			uci -q set homeproxy.config.main_urltest_mode=auto
			ok "  включён URLTest (авто) по всем узлам — выбирается самый быстрый."
		fi
		[ "$(uci -q get homeproxy.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
		uci -q commit homeproxy
		return 0
	fi
	warn "  подписка не дала узлов — проверьте URL и доступность сайта подписки."
	warn "  Узлы можно добавить позже повторным запуском скрипта."
	return 1
}

share_link_add() {
	ask "  Вставьте строку подключения (vless://, vmess://, trojan://, ss://, hysteria2:// …):"
	LINK=$(echo "$REPLY" | tr -d ' ')
	if [ -z "$LINK" ]; then warn "  строка пуста — пропускаю."; return 1; fi
	RES=$(ucode /etc/homeproxy/scripts/import_link.uc "$LINK" 2>/dev/null)
	if printf '%s' "$RES" | grep -q '"result"[[:space:]]*:[[:space:]]*true'; then
		ok "  узел импортирован ($(printf '%s' "$RES" | sed -n 's/.*"imported":\[{"section":"\([^"]*\)".*/\1/p'))."
		MN=$(uci -q get homeproxy.config.main_node)
		if [ -z "$MN" ] || [ "$MN" = nil ]; then
			uci -q set homeproxy.config.main_node=urltest
			uci -q set homeproxy.config.main_urltest_mode=auto
			ok "  включён URLTest (авто)."
		fi
		[ "$(uci -q get homeproxy.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
		uci -q commit homeproxy
		return 0
	fi
	warn "  импорт не удался: $(printf '%s' "$RES" | head -1)"
	return 1
}

# ------------------------------------------------ выбор основного узла (меню)
choose_main_node() {
	if [ "$(count_nodes)" -eq 0 ]; then
		warn "  Нет узлов — сначала добавьте подписку (п.1) или строку подключения (п.2)."
		return 1
	fi
	echo "  1) Авто — URLTest по всем узлам (рекомендуется: сам выбирает самый быстрый живой)"
	echo "  2) Авто с приоритетным узлом (выбранный узел используется первым)"
	echo "  3) Конкретный узел (фиксированный)"
	ask "  Выбор [1/2/3]:"
	case "$REPLY" in
		2)
			list_nodes
			ask "  Приоритетный узел (имя секции из списка):"
			if [ -n "$(uci -q get "homeproxy.$REPLY" 2>/dev/null)" ]; then
				uci -q set homeproxy.config.main_node=urltest
				uci -q set homeproxy.config.main_urltest_mode=prefer
				uci -q set homeproxy.config.main_urltest_preferred="$REPLY"
				ok "  URLTest: приоритетный узел $REPLY + авто-пул остальных."
			else
				warn "  секция не найдена — отменено."; return 1
			fi ;;
		3)
			list_nodes
			ask "  Узел (имя секции из списка):"
			if [ -n "$(uci -q get "homeproxy.$REPLY" 2>/dev/null)" ]; then
				uci -q set homeproxy.config.main_node="$REPLY"
				ok "  основной узел: $REPLY."
			else
				warn "  секция не найдена — отменено."; return 1
			fi ;;
		*)
			uci -q set homeproxy.config.main_node=urltest
			uci -q set homeproxy.config.main_urltest_mode=auto
			ok "  URLTest: авто (все узлы)." ;;
	esac
	uci -q set homeproxy.config.main_udp_node=same
	[ "$(uci -q get homeproxy.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
	uci -q commit homeproxy
	return 0
}

# ------------------------------------------------------- 4. MultiDNS
ask_multidns() {
	echo; ok "[4/7] MultiDNS — ускоритель DNS"
	info "  Гоняет ВСЕ DNS-серверы пула параллельно и отдаёт самый быстрый живой ответ;"
	info "  демон качества проверяет, что ответы реально открывают сайты, и отсекает мёртвые."
	info "  Работает и без подписки (обычный пул — напрямую)."
	ask "  Включить сейчас? [Д/н]:"
	if is_no "$REPLY"; then info "  Включить позже: Client Settings → MultiDNS."; return 0; fi
	install_mosdns || return 1
	if [ -x /usr/bin/mosdns ]; then
		uci -q set homeproxy.multidns.enabled=1
		uci -q set homeproxy.multidns.bench_interval=120
		uci -q commit homeproxy
		ok "  MultiDNS включён (проверка качества каждые 120 секунд)."
	fi
	return 0
}

# ------------------------------------------------------- 5. Автоматизация
ask_automation() {
	echo; ok "[5/7] Автоматизация — автообнаружение заблокированных сайтов"
	info "  Сама находит сайты, которые не открываются напрямую, и добавляет их в прокси-список."
	info "  БЕЗ подписки обнаружение работает, но маршрутизировать сайты через прокси нечем —"
	info "  они добавятся в список и заработают после добавления подписки/узла."
	ask "  Включить сейчас? [Д/н]:"
	if is_no "$REPLY"; then info "  Включить позже: Automation."; return 0; fi
	# tcpdump нужен источнику SNI (ловит DoH-клиентов и приложения с hardcoded IP);
	# без него SNI молча неактивен, остальные источники работают.
	command -v tcpdump >/dev/null 2>&1 || { info "  ставлю tcpdump (источник SNI)..."; if [ "$PM" = apk ]; then apk add tcpdump >/dev/null 2>&1; else opkg install tcpdump >/dev/null 2>&1; fi; }
	uci -q set homeproxy.automation.enabled=1
	# Источники кандидатов: канонический СПИСОК (dns/clash/sni) под новый MultiValue-UI.
	# Старое значение 'all' демон понимает, но виджет его не показывает как выбранные пункты.
	uci -q delete homeproxy.automation.discover 2>/dev/null
	uci -q add_list homeproxy.automation.discover=dns
	uci -q add_list homeproxy.automation.discover=clash
	uci -q add_list homeproxy.automation.discover=sni
	# IP-обучение включено по умолчанию: conntrack-кандидаты фильтруются (повторы >=2 раз,
	# shared-CDN исключены, кап 8/цикл, min_confirm>=2) — безопасно и ловит Telegram DC/игры.
	uci -q set homeproxy.automation.ip_learn=1
	uci -q commit homeproxy
	ok "  Автоматизация включена (источники: DNS-лог + Clash + SNI; IP-изучение: вкл)."
	return 0
}

# ------------------------------------------------------- 6. Zapret 2
# Тест стратегии Zapret на YouTube через встроенный тестер (RPC zapret_strategy_test).
# Возвращает 1, если YouTube-рука прошла (tag=yt ok=1), иначе пусто/0.
zapret_test() {
	RES=$(ubus call luci.homeproxy zapret_strategy_test "{\"cmd_opts\":\"$1\"}" 2>/dev/null)
	# The RPC embeds the tester JSON as an escaped string: \"tag\":\"yt\" ...
	printf '%s' "$RES" | sed -n 's/.*\\"tag\\":\\"yt\\"[^{}]*\\"ok\\":\([01]\).*/\1/p'
}

# Поставить Hostfakesplit по умолчанию, проверить YouTube; если не работает —
# перебрать встроенные стратегии до первой прошедшей.
zapret_pick_strategy() {
	[ -f /etc/homeproxy/zapret_candidates.json ] || { warn "  нет списка стратегий — оставляю значение по умолчанию."; return 1; }
	command -v curl >/dev/null 2>&1 || { info "  ставлю curl (нужен тестеру)..."; [ "$PM" = apk ] && apk add curl >/dev/null 2>&1 || opkg install curl >/dev/null 2>&1; }

	HOSTFAKE=$(ucode -e 'import { readfile } from "fs"; let j = json(readfile("/etc/homeproxy/zapret_candidates.json") || "{}"); for (let c in (j.candidates || [])) { if (c.name == "Hostfakesplit") { printf("%s", c.args); break; } }')
	[ -n "$HOSTFAKE" ] && uci -q set homeproxy.config.zapret_cmd_opts="$HOSTFAKE"

	# Гарантия чистого прямого пути: на время тестов останавливаем сервис, чтобы
	# YouTube-проверка измеряла ТОЛЬКО стратегию Zapret, а не работающий прокси
	# (иначе при активной подписке тест всегда «проходит» через прокси).
	HP_WAS_RUNNING=0
	pidof hiddify-core >/dev/null 2>&1 && HP_WAS_RUNNING=1
	pidof sing-box >/dev/null 2>&1 && HP_WAS_RUNNING=1
	[ "$HP_WAS_RUNNING" = 1 ] && /etc/init.d/homeproxy stop >/dev/null 2>&1

	RC=1
	info "  тестирую стратегию по умолчанию (Hostfakesplit) на YouTube (прямой путь)..."
	if [ "$(zapret_test "$HOSTFAKE")" = 1 ]; then
		uci -q commit homeproxy
		ok "  Hostfakesplit работает — YouTube открывается."
		RC=0
	else
		info "  YouTube не открылся — перебираю встроенные стратегии (Recommended → остальные)..."
		ucode -e 'import { readfile } from "fs"; let j = json(readfile("/etc/homeproxy/zapret_candidates.json") || "{}"); for (let c in (j.candidates || [])) { if (c.name != "Hostfakesplit") printf("%s\t%s\t%s\n", c.name, c.args, (c.group || "auto")); }' > /tmp/zcand.txt
		TRIED=0
		FOUND=0
		while IFS="$(printf '\t')" read -r NAME ARGS GROUP; do
			[ -n "$ARGS" ] || continue
			TRIED=$((TRIED+1))
			[ "$TRIED" -gt 12 ] && { info "  лимит перебора (12) — останавливаюсь."; break; }
			printf '    %2d) %s: ' "$TRIED" "$NAME"
			if [ "$(zapret_test "$ARGS")" = 1 ]; then
				echo "YouTube OK"
				uci -q set homeproxy.config.zapret_cmd_opts="$ARGS"
				FOUND=1
				break
			fi
			echo "нет"
		done < /tmp/zcand.txt
		rm -f /tmp/zcand.txt
		uci -q commit homeproxy
		if [ "$FOUND" = 1 ]; then
			ok "  выбрана стратегия: $NAME"
			RC=0
		else
			warn "  ни одна стратегия не прошла YouTube-тест — оставлена Hostfakesplit."
			warn "  Подберите позже: Node Settings → Zapret → Full strategy test."
		fi
	fi

	# Возвращаем сервис (финальный рестарт в конце всё равно перечитает конфиг)
	[ "$HP_WAS_RUNNING" = 1 ] && { /etc/init.d/homeproxy start >/dev/null 2>&1; sleep 3; }
	return $RC
}

install_zapret() {
	echo; ok "[6/7] Zapret 2 — обход DPI на уровне пакетов (подписка НЕ нужна)"
	info "  Бесплатно разблокирует YouTube и другие сервисы без VPN-подписки."
	info "  Встроенные профили + тестер: поставлю Hostfakesplit и проверю YouTube;"
	info "  если не заработает — сам переберу другие стратегии."
	ask "  Установить Zapret 2? [Д/н]:"
	if is_no "$REPLY"; then info "  пропускаю (можно поставить позже повторным запуском)."; return 0; fi
	info "  ставлю модуль ядра NFQUEUE..."
	if [ "$PM" = apk ]; then apk add kmod-nft-queue >/dev/null 2>&1; else opkg install kmod-nft-queue >/dev/null 2>&1; fi
	ZP=$(ubus call luci.homeproxy zapret_prepare_install 2>/dev/null)
	if [ -z "$ZP" ] || jerr "$ZP"; then warn "  не удалось подготовить Zapret — пропускаю. ($(jget "$ZP" error))"
	else
		ZURL=$(jget "$ZP" dl_url); ZTMP=$(jget "$ZP" tmp_path); ZPMG=$(jget "$ZP" pkg_manager)
		if [ -n "$ZURL" ] && dl "$ZURL" "$ZTMP"; then
			RES=$(ubus call luci.homeproxy zapret_install_pkg "{\"tmp_path\":\"$ZTMP\",\"pkg_manager\":\"$ZPMG\"}" 2>/dev/null)
			if jtrue "$RES"; then
				ok "  Zapret установлен."
				ZST=$(ubus call luci.homeproxy zapret_status 2>/dev/null)
				if jfalse "$ZST" kmod_ok; then
					warn "  модуль NFQUEUE не загружен — Zapret не включаю (иначе сломается firewall)."
					warn "  Включите вручную после kmod-nft-queue (Node Settings → Zapret)."
				else
					uci -q set homeproxy.config.zapret_enabled=1
					uci -q commit homeproxy
					ok "  Zapret включён."
					if zapret_pick_strategy; then
						# Стратегия подтверждена на прямом пути — YouTube идёт через
						# Zapret всегда (и с подпиской, и без): это снимает нагрузку
						# с прокси и работает даже без подписки.
						add_rule youtube zapret-out
					else
						warn "  правило YouTube → Zapret НЕ добавлено (нет рабочей стратегии — иначе YouTube бы не открывался)."
						warn "  После подбора стратегии добавьте правило вручную: Proxy Rules → YouTube → Zapret."
					fi
				fi
			else warn "  установка Zapret не удалась."; fi
		else warn "  не удалось скачать Zapret — пропускаю."; fi
	fi
	return 0
}

# ------------------------------------------------------- 7. ByeDPI
install_byedpi() {
	echo; ok "[7/7] ByeDPI — обход DPI через локальный SOCKS (на ваше усмотрение)"
	info "  Альтернатива Zapret; стратегии подбираются в UI (тестер встроен)."
	ask "  Установить ByeDPI? [y/N]:"
	if ! is_yes "$REPLY"; then info "  пропускаю."; return 0; fi
	info "  ставлю curl (его использует тестер стратегий ByeDPI)..."
	if [ "$PM" = apk ]; then apk add curl >/dev/null 2>&1; else opkg install curl >/dev/null 2>&1; fi
	BP=$(ubus call luci.homeproxy byedpi_prepare_install 2>/dev/null)
	if [ -z "$BP" ] || jerr "$BP"; then warn "  не удалось подготовить ByeDPI — пропускаю. ($(jget "$BP" error))"
	else
		BURL=$(jget "$BP" dl_url); BTMP=$(jget "$BP" tmp_path); BPMG=$(jget "$BP" pkg_manager)
		if [ -n "$BURL" ] && dl "$BURL" "$BTMP"; then
			RES=$(ubus call luci.homeproxy byedpi_install_pkg "{\"tmp_path\":\"$BTMP\",\"pkg_manager\":\"$BPMG\"}" 2>/dev/null)
			if jtrue "$RES"; then
				ok "  ByeDPI установлен."
				uci set homeproxy.config.byedpi_enabled=1; uci commit homeproxy; ok "  ByeDPI включён."
			else warn "  установка ByeDPI не удалась."; fi
		else warn "  не удалось скачать ByeDPI — пропускаю."; fi
	fi
	return 0
}

# ------------------------------------------------------------- меню (повторный запуск)
menu() {
	while true; do
		echo
		info "===== Настройка Re:HomeProxy AutoMod ====="
		status_line
		echo "  1) Добавить подписку (URL)"
		echo "  2) Добавить узел (строка подключения)"
		echo "  3) Выбрать основной узел / режим URLTest"
		echo "  4) MultiDNS (вкл/выкл)"
		echo "  5) Автоматизация (вкл/выкл)"
		echo "  6) Zapret 2 (установить / подобрать стратегию)"
		echo "  7) ByeDPI (установить/обновить)"
		echo "  8) Ядро прокси (установить/обновить)"
		echo "  9) Обновить узлы из подписок"
		echo "  0) Выход"
		ask "  Выбор [0-9]:"
		case "$REPLY" in
			1) subscription_add && apply_and_check ;;
			2) share_link_add && apply_and_check ;;
			3) choose_main_node && apply_and_check ;;
			4)
				if [ "$(uci -q get homeproxy.multidns.enabled)" = 1 ]; then
					ask "  MultiDNS включён. Выключить? [y/N]:"
					if is_yes "$REPLY"; then
						uci -q set homeproxy.multidns.enabled=0; uci -q commit homeproxy
						/etc/init.d/homeproxy restart >/dev/null 2>&1
						ok "  MultiDNS выключен."
					fi
				else
					install_mosdns && ask "  Включить MultiDNS? [Д/н]:" && \
						if ! is_no "$REPLY"; then
							uci -q set homeproxy.multidns.enabled=1
							uci -q set homeproxy.multidns.bench_interval=120
							uci -q commit homeproxy
							/etc/init.d/homeproxy restart >/dev/null 2>&1
							ok "  MultiDNS включён."
						fi
				fi ;;
			5)
				if [ "$(uci -q get homeproxy.automation.enabled)" = 1 ]; then
					ask "  Автоматизация включена. Выключить? [y/N]:"
					if is_yes "$REPLY"; then
						uci -q set homeproxy.automation.enabled=0; uci -q commit homeproxy
						/etc/init.d/homeproxy restart >/dev/null 2>&1
						ok "  Автоматизация выключена."
					fi
				else
					ask "  Включить Автоматизацию? [Д/н]:"
					if ! is_no "$REPLY"; then
						uci -q set homeproxy.automation.enabled=1; uci -q commit homeproxy
						/etc/init.d/homeproxy restart >/dev/null 2>&1
						ok "  Автоматизация включена."
					fi
				fi ;;
			6)
				if [ ! -x /opt/zapret2/nfq2/nfqws2 ]; then
					install_zapret
				else
					ask "  Zapret установлен. Подобрать стратегию заново? [Д/н]:"
					if ! is_no "$REPLY"; then
						zapret_pick_strategy && add_rule youtube zapret-out
					elif [ "$(uci -q get homeproxy.config.zapret_enabled)" = 1 ] && [ -n "$(uci -q get homeproxy.config.zapret_cmd_opts)" ]; then
						info "  стратегия уже задана — проверяю правило YouTube → Zapret..."
						add_rule youtube zapret-out
					fi
				fi
				apply_and_check ;;
			7) install_byedpi; apply_and_check ;;
			8) install_core; apply_and_check ;;
			9)
				if [ -z "$(uci -q get homeproxy.subscription.subscription_url)" ]; then
					warn "  подписок не настроено — добавьте через п.1."
				else
					info "  обновляю узлы из подписок..."
					ucode /etc/homeproxy/scripts/update_subscriptions.uc >/dev/null 2>&1
					ok "  готово: узлов $(count_nodes)."
					apply_and_check
				fi ;;
			0|"") info "  Готово. Откройте LuCI → Services → Re:HomeProxy AutoMod."; break ;;
			*) warn "  неизвестный пункт." ;;
		esac
	done
}

# ------------------------------------------------------------------ финал
summary() {
	LANIP=$(uci -q get network.lan.ipaddr | cut -d/ -f1)
	[ -n "$LANIP" ] || LANIP=$(ip -4 addr show br-lan 2>/dev/null | sed -n 's#.*inet \([0-9.]*\).*#\1#p' | head -1)
	[ -n "$LANIP" ] || LANIP="192.168.1.1"
	echo
	ok "===== Готово ====="
	status_line
	info "Откройте Re:HomeProxy AutoMod в браузере:"
	URL="http://$LANIP/cgi-bin/luci/admin/services/homeproxy"
	printf '\033[0;36m  \033]8;;%s\033\\%s\033]8;;\033\\\033[0m\n' "$URL" "$URL"
	info "Проверка прокси и выбор стратегий: Диагностика / Node Settings → Zapret."
}

# ======================================================== ГЛАВНЫЙ ПОТОК

if [ "$APP_INSTALLED" = 1 ]; then
	ok "Приложение уже установлено — проверяю обновления и перехожу в режим настройки."
	app_update_if_needed
	/etc/init.d/rpcd restart >/dev/null 2>&1; sleep 1
	ensure_baseline
	apply_and_check
	menu
	exit 0
fi

install_app

set_dns_defaults

install_core

echo; ok "[3/7] Подписка или конфигурация (можно добавить позже)"
info "  Без подписки заблокированные сервисы (Telegram, WhatsApp, Instagram…) недоступны,"
info "  но интернет будет работать полностью (напрямую)."
ask "  Добавить подписку (URL) сейчас? [y/N]:"
if is_yes "$REPLY"; then
	subscription_add
else
	ask "  Добавить узел строкой подключения (vless://… и т.п.)? [y/N]:"
	is_yes "$REPLY" && share_link_add
fi

ask_multidns
ask_automation
install_zapret
install_byedpi

ensure_baseline

echo; ok "[финал] Применяю настройки"
/etc/init.d/homeproxy enable >/dev/null 2>&1
/etc/init.d/homeproxy restart >/dev/null 2>&1
wait_core
sleep 4
validate_proxy
internet_check
summary
