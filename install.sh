#!/bin/sh
# Установщик и интерактивный конфигуратор Ravnex для OpenWrt (apk / opkg)
# https://github.com/ezdizzy/re-homeproxy
#
# Вручную ставится только LuCI-приложение + ключ подписи, а ядро, ByeDPI и Zapret
# устанавливаются через собственный бэкенд приложения (core_mgmt.uc + rpcd-объект
# luci.ravnex) — поэтому определение архитектуры, компактные сборки под малую
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
# Оффлайн-установка из каталога с файлами пакетов (Ф11.4 — у 80% роутеров нет
# памяти под большой архив, поэтому ОДИНОЧНЫЕ файлы, не архив):
#   sh install.sh --local /path/to/files
#   (в каталоге: пакеты приложения и русской локали, ядро/движки, mosdns,
#   помощники — имена как в релизах/фиде; сценарии «Android-телефон с
#   терминалом» и «ПК + scp» — в Wiki).
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
SUFFIX="_all"   # суффикс имени пакета приложения в релизах

# --local /path — оффлайн-режим: все загрузки заменяются файлами из каталога.
LOCAL_DIR=""
if [ "$1" = "--local" ]; then
	LOCAL_DIR="$2"
	[ -n "$LOCAL_DIR" ] && [ -d "$LOCAL_DIR" ] || { echo "install.sh --local: укажите каталог с файлами пакетов"; exit 1; }
	shift 2
fi

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
# В режиме --local загрузка = файл из каталога (по точному имени или по префиксу).
dl() {
	if [ -n "$LOCAL_DIR" ]; then
		local lf=$(local_of "$1")
		[ -n "$lf" ] && cp "$lf" "$2" && return 0
		return 1
	fi
	wget -qO "$2" --timeout=20 "$1" 2>/dev/null && [ -s "$2" ] && return 0
	if [ -n "$GH_MIRROR" ]; then
		m=$(echo "$1" | sed "s#https://github.com#${GH_MIRROR}#")
		wget -qO "$2" --timeout=20 "$m" 2>/dev/null && [ -s "$2" ] && return 0
	fi
	return 1
}
# local_of <url> — файл в каталоге --local: точное имя, затем префикс до первого
# разделителя (hiddify-core_..., luci-app-re-homeproxy-..., probe_pool-linux-...).
local_of() {
	local base
	base=$(basename "$1")
	[ -f "$LOCAL_DIR/$base" ] && { printf '%s' "$LOCAL_DIR/$base"; return 0; }
	local pref
	pref=$(printf '%s' "$base" | sed -E 's/[-_].*//')
	local f
	f=$(ls "$LOCAL_DIR/${pref}"* 2>/dev/null | head -n1)
	[ -n "$f" ] && { printf '%s' "$f"; return 0; }
	return 1
}
api() { [ -n "$LOCAL_DIR" ] && return 0; wget -qO- --timeout=20 "$1" 2>/dev/null; }   # GitHub API (без зеркала); --local — обновления не проверяются

CM=/usr/share/homeproxy/scripts/core_mgmt.uc
HAS_UCB=0
have_ubus() { command -v ubus >/dev/null 2>&1; }

# -------------------------------------------------- источник обновлений (Ф11 V2)
# Клиент НЕ пишет repositories.d вовсе: ключ подписи в /etc/apk/keys/ + manifest.json
# (контракт клиента: pkg → version → apk/ipk файл + sha256). Установка = скачать
# ЯВНЫЙ файл по манифесту → sha256-гейт → apk add ./x.apk (подпись проверит apk по
# нашему ключу) | opkg install ./x.ipk (opkg подписи не проверяет — sha256 и есть
# проверка). Лестница источников (Ф11.4): raw.githubusercontent → jsDelivr → GH_MIRROR.
FEED_MAN=""
feed_manifest() {
	[ -n "$FEED_MAN" ] && return 0
	[ -n "$LOCAL_DIR" ] && return 1
	local series rel u
	series=$(printf '%s' "$VER" | cut -d. -f1,2)
	rel="releases/$series/$ARCH/manifest.json"
	for u in \
		"https://raw.githubusercontent.com/${HP_REPO}/refs/heads/feed/$rel" \
		"https://cdn.jsdelivr.net/gh/${HP_REPO}@feed/$rel"; do
		if wget -qO /tmp/feed_manifest.json --timeout=15 "$u" 2>/dev/null && [ -s /tmp/feed_manifest.json ]; then
			FEED_MAN=/tmp/feed_manifest.json; return 0
		fi
	done
	if [ -n "$GH_MIRROR" ]; then
		u="${GH_MIRROR}/${HP_REPO}/raw/refs/heads/feed/$rel"
		if wget -qO /tmp/feed_manifest.json --timeout=15 "$u" 2>/dev/null && [ -s /tmp/feed_manifest.json ]; then
			FEED_MAN=/tmp/feed_manifest.json; return 0
		fi
	fi
	return 1
}
feed_init() {
	[ -n "$LOCAL_DIR" ] && return 1
	if [ "$PM" = apk ] && [ ! -f /etc/apk/keys/ravnex-feed.pub ]; then
		if dl "https://github.com/${HP_REPO}/raw/refs/heads/feed/ravnex-feed.pub" /tmp/ravnex-feed.pub; then
			head -c 27 /tmp/ravnex-feed.pub | grep -q 'BEGIN PUBLIC KEY' && {
				mkdir -p /etc/apk/keys /lib/upgrade/keep.d
				cp /tmp/ravnex-feed.pub /etc/apk/keys/ravnex-feed.pub
				chmod 644 /etc/apk/keys/ravnex-feed.pub
				printf '%s\n' /etc/apk/keys/ravnex-feed.pub > /lib/upgrade/keep.d/ravnex-feed
				ok "  ключ источника обновлений установлен (подпись пакетов проверяется apk)"
			}
		fi
		rm -f /tmp/ravnex-feed.pub
	fi
	feed_manifest && return 0
	return 1
}
feed_field() { # <pkg> <поле> — значение из манифеста (пусто = нет)
	[ -n "$FEED_MAN" ] || return 0
	ucode -e "import { readfile } from 'fs'; let m = json(readfile('$FEED_MAN') || ''); let e = (m && m.pkgs) ? m.pkgs['$1'] : null; print((e && e['$2']) ? e['$2'] : '');" 2>/dev/null
}
feed_install() { # <pkg> — явный файл из манифеста + sha256-гейт + установка; 0 = успех
	[ "$PM" = apk ] && [ ! -f /etc/apk/keys/ravnex-feed.pub ] && return 1
	local f sha got tmp
	f=$(feed_field "$1" "$PM"); sha=$(feed_field "$1" "${PM}_sha256")
	[ -n "$f" ] && [ -n "$sha" ] || return 1
	tmp="/tmp/feed_$1.$PM"
	local rel="releases/$(printf '%s' "$VER" | cut -d. -f1,2)/$ARCH/$f"
	local done_=""
	for u in \
		"https://raw.githubusercontent.com/${HP_REPO}/refs/heads/feed/$rel" \
		"https://cdn.jsdelivr.net/gh/${HP_REPO}@feed/$rel"; do
		wget -qO "$tmp" --timeout=15 "$u" 2>/dev/null && [ -s "$tmp" ] && { done_=1; break; }
	done
	if [ -z "$done_" ] && [ -n "$GH_MIRROR" ]; then
		u="${GH_MIRROR}/${HP_REPO}/raw/refs/heads/feed/$rel"
		wget -qO "$tmp" --timeout=15 "$u" 2>/dev/null && [ -s "$tmp" ] && done_=1
	fi
	[ -n "$done_" ] || return 1
	got=$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')
	if [ "$got" != "$sha" ]; then
		rm -f "$tmp"
		warn "  sha256 файла $f не совпал с манифестом — установка отменена (источник повреждён?)"
		return 1
	fi
	if [ "$PM" = apk ]; then
		if apk info -e "$1" >/dev/null 2>&1; then
			apk upgrade "$tmp" >/dev/null 2>&1 || apk add "$tmp" >/dev/null 2>&1
		else
			apk add "$tmp" >/dev/null 2>&1
		fi
	else
		opkg install --force-reinstall "$tmp" >/dev/null 2>&1
	fi
	local rc=$?
	rm -f "$tmp"
	return $rc
}

# ------------------------------------------------------------------ helpers

count_nodes() {
	uci show ravnex 2>/dev/null | grep -cE "^ravnex\.[^.]+=node$"
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
	uci show ravnex 2>/dev/null | sed -n 's/^ravnex\.\([^.]*\)=node$/\1/p' | while read -r sec; do
		LBL=$(uci -q get "ravnex.$sec.label" 2>/dev/null)
		[ -z "$LBL" ] && LBL=$sec
		ADDR=$(uci -q get "ravnex.$sec.address" 2>/dev/null)
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
	# uci show prints auto-generated section ids (ravnex.cfgXXXX.source='…'),
	# NOT the section type — matching on "proxy_ru_rule" never matched, so every
	# re-run appended another duplicate rule.
	if uci show ravnex 2>/dev/null | grep -q "\.source='$1'"; then
		return 0
	fi
	SEC=$(uci add ravnex proxy_ru_rule 2>/dev/null)
	[ -n "$SEC" ] || { warn "  не удалось добавить правило $1 → $2."; return 1; }
	uci -q set "ravnex.$SEC.source=$1"
	uci -q set "ravnex.$SEC.node=$2"
	uci -q set "ravnex.$SEC.enabled=1"
	uci -q commit ravnex
	ok "  добавлено правило: Источник $1 → Узел $2"
	return 0
}

# Гарантия интернета: если основной узел не задан (нет подписки/узлов) — прямой режим
# и правило YouTube → Zapret. Ничего уже настроенного не трогает.
ensure_baseline() {
	apply_gh_mirror
	[ -z "$(uci -q get ravnex.config.routing_mode)" ] && uci -q set ravnex.config.routing_mode=proxy_banned_ru
	[ -z "$(uci -q get ravnex.config.main_udp_node)" ] && uci -q set ravnex.config.main_udp_node=same
	MN=$(uci -q get ravnex.config.main_node)
	if [ -z "$MN" ] || [ "$MN" = nil ]; then
		if [ "$(count_nodes)" -gt 0 ]; then
			uci -q set ravnex.config.main_node=urltest
			uci -q set ravnex.config.main_urltest_mode=auto
			ok "  узлы найдены — включён URLTest (авто, все узлы)."
			[ "$(uci -q get ravnex.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
		elif [ "$(uci -q get ravnex.config.zapret_enabled)" = 1 ]; then
			# Zapret is an engine, not a main node: direct main keeps the internet up.
			# NO unconditional YouTube→Zapret rule here: per policy that rule is added
			# ONLY after a strategy passed its live test (install_zapret does exactly
			# that); re-running the installer must not route YouTube into an untested
			# engine.
			uci -q set ravnex.config.main_node=direct-out
			info "  нет подписки: интернет напрямую."
			info "  YouTube через Zapret добавится после успешного теста стратегии (пункт меню Zapret)."
		else
			uci -q set ravnex.config.main_node=direct-out
			info "  нет подписки: интернет работает как обычно (напрямую)."
			info "  Заблокированные сайты станут доступны после добавления подписки/узла."
		fi
		uci -q commit ravnex
	fi
}

# Дефолтные DNS-пулы MultiDNS/резолверов: 3 обычных + 3 защищённых (только если не заданы)
set_dns_defaults() {
	CUR=$(uci -q get ravnex.config.russia_dns_server)
	if [ -z "$CUR" ]; then
		uci -q delete ravnex.config.russia_dns_server 2>/dev/null
		uci -q add_list ravnex.config.russia_dns_server=77.88.8.8
		uci -q add_list ravnex.config.russia_dns_server=8.8.8.8
		uci -q add_list ravnex.config.russia_dns_server=https://cloudflare-dns.com/dns-query
		ok "  обычный DNS-пул: Яндекс 77.88.8.8, Google 8.8.8.8, Cloudflare DoH (прямой)"
	fi
	CUR=$(uci -q get ravnex.config.secure_dns_server)
	if [ -z "$CUR" ]; then
		uci -q delete ravnex.config.secure_dns_server 2>/dev/null
		uci -q add_list ravnex.config.secure_dns_server=https://dns.google/dns-query
		uci -q add_list ravnex.config.secure_dns_server=https://cloudflare-dns.com/dns-query
		uci -q add_list ravnex.config.secure_dns_server=https://dns.quad9.net/dns-query
		ok "  защищённый DNS-пул: Google, Cloudflare, Quad9 (DoH)"
	fi
	CUR=$(uci -q get ravnex.config.russia_dns_use_wan)
	if [ -z "$CUR" ]; then
		uci -q set ravnex.config.russia_dns_use_wan='1'
		ok "  DNS провайдера (WAN) добавлен в обычный пул по умолчанию"
	fi
	uci -q commit ravnex
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
	MIX=$(uci -q get ravnex.infra.mixed_port)
	[ -z "$MIX" ] && MIX=5330
	if command -v curl >/dev/null 2>&1; then
		CODE=$(curl -sx "socks5://127.0.0.1:$MIX" -o /dev/null -w '%{http_code}' \
			--connect-timeout 10 --max-time 20 https://www.youtube.com 2>/dev/null)
		case "$CODE" in
			2??|3??) ok "  прокси работает (YouTube через основной узел — HTTP $CODE)."; return 0;;
			*) warn "  прокси пока не отвечает (HTTP ${CODE:-—}) — проверьте узел в LuCI → Диагностика."; return 1;;
		esac
	fi
	RES=$(ubus call luci.ravnex connection_check '{"site":"youtube"}' 2>/dev/null)
	if printf '%s' "$RES" | grep -q '"result"[[:space:]]*:[[:space:]]*true'; then
		ok "  прокси работает (YouTube отвечает)."; return 0
	fi
	warn "  прокси пока не отвечает — проверьте узел в LuCI → Диагностика."
	return 1
}

apply_and_check() {
	info "  применяю настройки (перезапуск службы)..."
	/etc/init.d/ravnex enable >/dev/null 2>&1
	/etc/init.d/ravnex restart >/dev/null 2>&1
	wait_core
	sleep 3
	validate_proxy
	internet_check
}

	status_line() {
	CORE="нет"; [ -x /usr/bin/hiddify-core ] && CORE=hiddify-core; [ -x /usr/bin/sing-box ] && CORE="$CORE + sing-box"
	# lite-сборка sing-box (экономит место на флеше): на месте ELF — крошечный sh-враппер (~10 КБ), который exec'ает реальный бинарь из /usr/libexec.
	if [ -x /usr/bin/sing-box ]; then
		SZ=$(wc -c < /usr/bin/sing-box 2>/dev/null)
		case "$SZ" in ''|*[!0-9]*) SZ=999999 ;; esac
		[ "$SZ" -lt 10000 ] && CORE="$CORE (lite·upx)"
	fi
	MOS="нет"; [ -x /usr/bin/mosdns ] && MOS="да"
	ZAP="нет"; [ -x /opt/zapret2/nfq2/nfqws2 ] && ZAP="да"
	BYE="нет"; [ -x /usr/bin/ciadpi ] && BYE="да"
	CURL="нет"; command -v curl >/dev/null 2>&1 && CURL="да"
	MN=$(uci -q get ravnex.config.main_node); [ -z "$MN" ] && MN="(не задан)"
	MD="выкл"; [ "$(uci -q get ravnex.multidns.enabled)" = 1 ] && MD="вкл"
	AU="выкл"; [ "$(uci -q get ravnex.automation.enabled)" = 1 ] && AU="вкл"
	ZN="выкл"; [ "$(uci -q get ravnex.config.zapret_enabled)" = 1 ] && ZN="вкл"
	TG="выкл"; [ "$(uci -q get ravnex.telegram.enabled)" = 1 ] && TG="вкл"
	KC="выкл"; [ "$(uci -q get ravcontrol.main.enabled)" = 1 ] && KC="вкл"
	AP="выкл"; [ "$(uci -q get ravnex.autopilot.enabled)" = 1 ] && AP="вкл"
	echo "  Ядро: $CORE | mosdns: $MOS | Zapret: $ZAP ($ZN) | ByeDPI: $BYE | curl: $CURL"
	echo "  Узлов: $(count_nodes) | Основной узел: $MN | MultiDNS: $MD | Автоматизация: $AU"
	echo "  Автопилот: $AP | Telegram-бот: $TG | Контроль: $KC"
}

# ---------------------------------------------------------------- 0. окружение
echo
ok "===== Ravnex — установка и настройка ====="

[ "$(id -u)" = 0 ] || die "Запустите от root."
[ -r /etc/openwrt_release ] || die "Это не OpenWrt (нет /etc/openwrt_release)."
. /etc/openwrt_release 2>/dev/null
ARCH="$DISTRIB_ARCH"; VER="$DISTRIB_RELEASE"
[ -n "$ARCH" ] || die "Не удалось определить архитектуру пакетов (DISTRIB_ARCH)."
if   command -v apk  >/dev/null 2>&1; then PM=apk;  EXT=apk
elif command -v opkg >/dev/null 2>&1; then PM=opkg; EXT=ipk
else die "Не найден поддерживаемый менеджер пакетов (apk/opkg)."; fi
case "$VER" in
	# 23.05 — EOL, поддержка снята (ucode-mod-digest больше не зависит от пакета,
	# но старый ucode/23.05 не тестировался). Явный отказ вместо сломанной установки.
	23.05*)              die "OpenWrt $VER достигла конца поддержки (EOL) и больше не поддерживается. Обновитесь до 24.10 или новее." ;;
	24.10*|25.*|*SNAPSHOT*) : ;;
	22.*|21.*|19.*)      die "OpenWrt $VER слишком старая — нужна 24.10 или новее." ;;
	*)                   warn "Непроверенная версия OpenWrt $VER — продолжаю." ;;
esac
info "Версия: OpenWrt $VER  |  Архитектура: $ARCH  |  Менеджер пакетов: $PM"
# Железо в баннер: слабым роутерам (1–2 ядра, мало RAM) модули ресурсной адаптации
# (MultiDNS, автоматизация, автопилот) сами выбирают щадящие интервалы.
CORES=$(nproc 2>/dev/null); [ -z "$CORES" ] && CORES=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
case "$CORES" in ''|*[!0-9]*) CORES='' ;; esac   # нечисловое → нет данных
RAMKB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)
OVRKB=$(df -k /overlay 2>/dev/null | awk 'NR==2 {print $2}')
HWLINE="  Железо: ${CORES:-?} ядер | RAM: $([ -n "$RAMKB" ] && echo $((RAMKB/1024)) || echo '?') МБ"
[ -n "$OVRKB" ] && HWLINE="$HWLINE | Flash (overlay): $((OVRKB/1024)) МБ"
info "$HWLINE"
if [ -n "$CORES" ] && [ "$CORES" -le 2 ]; then
	info "  Слабый роутер: демоны качества работают в ресурсосберегающих интервалах автоматически"
	info "  (MultiDNS — проверка раз в 600 с, автоматизация подстраивает цикл под load, автопилот — quick-режим)."
fi

# Прописываем зеркало в бэкенд, чтобы делегированные загрузки тоже его использовали
# Зеркало GitHub для бэкенда приложения пишем в UCI ПОСЛЕ установки пакета:
# ранняя запись при отсутствии /etc/config/ravnex создавала пустой конфиг,
# который (как conffile) блокировал поставку shipped-дефолтов из пакета.
apply_gh_mirror() {
	if [ -n "$GH_MIRROR" ] && [ -f /etc/config/ravnex ]; then
		uci set ravnex.config.github_mirror="$GH_MIRROR"
		uci commit ravnex 2>/dev/null
	fi
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

# Наш пакет/файлы установлены? (пакет — надёжный источник; файл — на случай
# установки без менеджера пакетов).
# ВНИМАНИЕ: определения обязаны стоять ВЫШЕ первого вызова (POSIX sh не умеет
# hoisting — вызов до определения давал «sh: own_pkg_installed: not found»).
own_pkg_installed() {
	[ -n "$(app_installed_version)" ] && return 0
	[ -f /usr/share/luci/menu.d/luci-app-re-homeproxy.json ] && return 0
	return 1
}

# Чужая (оригинальная) homeproxy-версия: другой пакет с теми же файлами.
# Его наличие нельзя молча игнорировать — файлы (/etc/config/ravnex,
# rpcd-объект) конфликтуют, и «установка поверх» не происходит на самом деле.
foreign_homeproxy_pkg() {
	for _p in luci-app-homeproxy luci-app-homeproxy-hiddify; do
		if [ "$PM" = apk ]; then
			apk info -e "$_p" >/dev/null 2>&1 && { echo "$_p"; return 0; }
		else
			opkg status "$_p" 2>/dev/null | grep -q "^Status: install" && { echo "$_p"; return 0; }
		fi
	done
	return 1
}

# Приложение уже установлено? (раньше детект был по файлам rpcd/конфига — они есть
# и у оригинальной homeproxy, из-за чего «установка поверх» чужой версии молча
# превращалась в «режим настройки»). Теперь — только наш пакет/наши файлы.
APP_INSTALLED=0
own_pkg_installed && APP_INSTALLED=1

# Чужая homeproxy-версия: конфликтует файлами, установщик не должен «становиться
# поверх». При предлагаемом удалении конфиг чужого пакета сохраняется в бэкап.
FOREIGN_PKG=$(foreign_homeproxy_pkg)
FOREIGN_REMOVED=0
if [ "$APP_INSTALLED" = 0 ] && [ -n "$FOREIGN_PKG" ]; then
	warn "════════════════════════════════════════════════════════════"
	warn "  Обнаружена ЧУЖАЯ (оригинальная) версия homeproxy: пакет"
	warn "  '$FOREIGN_PKG' установлен. Она конфликтует с Ravnex"
	warn "  (те же конфиги и rpcd-объекты) — поверх ставить нельзя."
	ask "$FOREIGN_PKG будет удалён, Ravnex установлен. Продолжить? [Д/н]:"
	if ! is_yes "$REPLY"; then
		die "Установка отменена. Сначала удалите '$FOREIGN_PKG': $( [ "$PM" = apk ] && echo "apk del $FOREIGN_PKG" || echo "opkg remove $FOREIGN_PKG" )."
	fi
	info "  останавливаю службу и удаляю '$FOREIGN_PKG'..."
	/etc/init.d/ravnex stop >/dev/null 2>&1
	if [ "$PM" = apk ]; then apk del "$FOREIGN_PKG" >/dev/null 2>&1; else opkg remove "$FOREIGN_PKG" >/dev/null 2>&1; fi
	# Чужой пакет часто остаётся в списке (conffiles не даёт удалить) — жёстко добиваем.
	if [ -n "$(foreign_homeproxy_pkg)" ]; then
		if [ "$PM" = apk ]; then apk del --force "$FOREIGN_PKG" >/dev/null 2>&1; else opkg remove --force-removal-of-dependent-packages "$FOREIGN_PKG" >/dev/null 2>&1; fi
	fi
	if [ -f /etc/config/ravnex ]; then
		ask "  Сохранить текущий конфиг /etc/config/ravnex как homeproxy.foreign.bak? [Д/н]: (рекомендуется — чтобы поставились наши дефолты)"
		if ! is_no "$REPLY"; then
			mv /etc/config/ravnex /etc/config/ravnex.foreign.bak
			ok "  конфиг сохранён как /etc/config/ravnex.foreign.bak"
		fi
	fi
	# Убедимся, что чужой пакет ушёл
	[ -z "$(foreign_homeproxy_pkg)" ] || die "Не удалось удалить '$FOREIGN_PKG' — установите его удаление вручную и повторите."
fi
if [ "$APP_INSTALLED" = 1 ] && [ -n "$FOREIGN_PKG" ]; then
	warn "  ⚠ ВАЖНО: одновременно установлены и Ravnex, и '$FOREIGN_PKG'."
	warn "    Они конфликтуют (общие файлы: конфиг, rpcd-объект, скрипты)."
	# GL.iNet-прошивки (4.8+) несут свой 'luci-app-homeproxy-hiddify' из каталога
	# плагинов — на таком роутере предупреждение появляется даже у того, кто ставил
	# только наш пакет: чужой был в прошивке. Поэтому не только предупреждаем, но и
	# предлагаем удалить сразу (конфиг НЕ трогаем — он общий и наш).
	ask "  Удалить '$FOREIGN_PKG' сейчас и переустановить Ravnex? [Д/н]:"
	if is_yes "$REPLY"; then
		info "  останавливаю службу и удаляю '$FOREIGN_PKG'..."
		/etc/init.d/ravnex stop >/dev/null 2>&1
		if [ "$PM" = apk ]; then apk del "$FOREIGN_PKG" >/dev/null 2>&1; else opkg remove "$FOREIGN_PKG" >/dev/null 2>&1; fi
		# apk/opkg могут упереться в «общие» файлы — жёсткий второй заход.
		if [ -n "$(foreign_homeproxy_pkg)" ]; then
			if [ "$PM" = apk ]; then apk del --force "$FOREIGN_PKG" >/dev/null 2>&1; else opkg remove --force-removal-of-dependent-packages "$FOREIGN_PKG" >/dev/null 2>&1; fi
		fi
		if [ -z "$(foreign_homeproxy_pkg)" ]; then
			ok "  чужой пакет удалён."
			FOREIGN_REMOVED=1   # главный поток ниже переустановит наш пакет поверх
		else
			warn "  не удалось удалить '$FOREIGN_PKG' — удалите вручную ($( [ "$PM" = apk ] && echo "apk del --force $FOREIGN_PKG" || echo "opkg remove --force-removal-of-dependent-packages $FOREIGN_PKG" )) и запустите п.10 в меню."
		fi
	else
		warn "  оставлено как есть. Рекомендуется удалить позже:"
		warn "    $( [ "$PM" = apk ] && echo "apk del $FOREIGN_PKG" || echo "opkg remove $FOREIGN_PKG" ) и переустановка (п.10 в меню)."
	fi
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
		opkg update >/dev/null 2>&1; opkg install --force-reinstall /tmp/app.$EXT || { rm -f /tmp/app.$EXT; warn "  opkg install завершился ошибкой."; return 1; }
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

# Переустановить приложение заново из последнего релиза (той же/новой версии).
app_reinstall() {
	info "  переустанавливаю приложение из последнего релиза..."
	ensure_key
	if app_install_pkgs; then
		ok "  приложение переустановлено."
		/etc/init.d/rpcd restart >/dev/null 2>&1; sleep 2
		/etc/init.d/uhttpd restart >/dev/null 2>&1
		# Помощники НЕ входят в пакет (он arch-independent) — после переустановки
		# гарантируем их наличие (ставятся только отсутствующие).
		install_native_helpers
		heal_configs
		apply_and_check
	else
		warn "  переустановка не удалась — прежняя версия оставлена на месте."
	fi
}

# Проверить и восстановить критические конфиги (firewall includes и др.).
heal_configs() {
	info "  проверяю критические конфиги (firewall includes и др.)..."
	RES=$(ucode /etc/ravnex/scripts/config_heal.uc repair 2>/dev/null)
	if printf '%s' "$RES" | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
		ok "  конфигурация в порядке."
	elif [ -n "$RES" ]; then
		if printf '%s' "$RES" | grep -q '"repaired":[[:space:]]*\[[^]]'; then
			ok "  критические конфиги восстановлены."
			info "  применяю правила (рестарт службы)..."
			/etc/init.d/ravnex restart >/dev/null 2>&1
		else
			warn "  часть проблем не удалось исправить автоматически:"
			echo "$RES"
			return 1
		fi
	else
		warn "  config_heal.uc недоступен — переустановите приложение."
		return 1
	fi
	return 0
}

# ------------------------------------------------- 1. LuCI-приложение + ключ
install_app() {
	ok "[1/10] Устанавливаю LuCI-приложение Ravnex..."
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
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	[ -f "$CM" ] || die "core_mgmt.uc не найден после установки — прерываю."
}

# ------------------------------------------------------- 2. ядро прокси
install_core() {
	ok "[2/10] Ядро прокси (обязательно — выберите одно)"
	warn "  ⚠  Без действующей подписки/конфигурации прокси-часть работать не будет:"
	warn "     Telegram, WhatsApp, Instagram и другие заблокированные сервисы останутся недоступны."
	warn "     Интернет при этом останется полностью рабочим (напрямую)."
	echo "    1) hiddify-core            (по умолчанию; оригинальные сборки hiddify/hiddify-core, форк — резерв; NaïveProxy на musl-сборках; на малой флеш-памяти выберет компактную сборку форка)"
	echo "    2) sing-box-extended       (более новая база sing-box 1.14: WARP/MASQUE/TrustTunnel в ядре; без NaïveProxy — такие узлы будут пропускаться)"
	echo "    3) sing-box-extended-lite  (лёгкая сборка sing-box 1.14 для роутеров с малой флеш-памятью: VLESS Reality, Trojan, Shadowsocks,"
	echo "                               Hysteria2, TUIC, WireGuard/AmneziaWG (стек ядра) и Clash API; БЕЗ NaïveProxy/WARP/MASQUE/Tailscale/gVisor —"
	echo "                               такие узлы будут пропускаться; обычная сборка ~46 МБ на флеше, компактная UPX ~10 МБ + ~96 МБ свободной ОЗУ)"
	ask "  Выбор [1/2/3] (по умолчанию 1):"
	VARIANT=""
	case "$REPLY" in
		2) CORE=singbox ;;
		3)
			CORE=singbox-lite
			echo "  Сборка lite:"
			echo "    1) обычная     (~46 МБ на флеше, ОЗУ не грузит — нужно ~50 МБ свободного места)"
			echo "    2) компактная  (UPX, ~10 МБ на флеше, распаковывается в ОЗУ при каждом запуске — нужно ~16 МБ места и ~96 МБ ОЗУ)"
			ask "  Выбор [1/2] (пусто = авто — установщик подберёт по ресурсам роутера):"
			case "$REPLY" in
				1) VARIANT=normal ;;
				2) VARIANT=compressed ;;
				*) VARIANT=""; info "  сборку выберет установщик по ресурсам роутера." ;;
			esac ;;
		*) CORE=hiddify ;;
	esac

	PREP=$(ucode "$CM" prepare_install "$CORE" "$VARIANT" 2>/dev/null)
	jerr "$PREP" && die "  подготовка ядра не удалась: $(jget "$PREP" error)"
	# Ф11 V2 feed-first: prepare вернул источник обновлений — явный файл из
	# манифеста (sha256 + подпись), никакого tar-бола/asset-пути.
	if [ "$(jget "$PREP" source)" = "feed" ] && [ -n "$(jget "$PREP" feed_pkg)" ]; then
		FEEDPKG=$(jget "$PREP" feed_pkg)
		info "  $CORE: ставлю из источника обновлений ($FEEDPKG $(jget "$PREP" version))..."
		if jtrue "$(ucode "$CM" install_feed_pkg "$FEEDPKG" 2>/dev/null)"; then
			jtrue "$(ucode "$CM" install_kmods "$(jget "$PREP" pkg_manager)" 2>/dev/null)" || warn "  не удалось поставить kmod — без kmod-nft-tproxy/kmod-tun прокси не будет маршрутизировать."
			ok "  $CORE установлен (источник обновлений)."
			return 0
		fi
		warn "  установка из источника обновлений не удалась — возврат к обычным путям."
		PREP=$(ucode "$CM" prepare_install "$CORE" "$VARIANT" 2>/dev/null)
		jerr "$PREP" && die "  подготовка ядра не удалась: $(jget "$PREP" error)"
	fi
	DLURL=$(jget "$PREP" dl_url)
	# lite-ядро ставится собственным install.sh проекта (dl_url нет — есть installer_url)
	[ -z "$DLURL" ] && DLURL=$(jget "$PREP" installer_url)
	TMP=$(jget "$PREP" tmp_path); PMG=$(jget "$PREP" pkg_manager)
	[ -n "$DLURL" ] && [ -n "$TMP" ] && [ -n "$PMG" ] || die "  подготовка ядра не вернула данные для загрузки."
	info "  скачиваю $CORE..."
	if [ -n "$LOCAL_DIR" ]; then
		lf=$(local_of "$DLURL")
		[ -n "$lf" ] && cp "$lf" "$TMP" || die "  в каталоге --local нет файла для $DLURL."
	else
		jtrue "$(ucode "$CM" download_pkg "$DLURL" "$TMP" 2>/dev/null)" || die "  не удалось скачать ядро (попробуйте GH_MIRROR=...)."
	fi
	jtrue "$(ucode "$CM" install_pkg "$CORE" "$TMP" "$PMG" 2>/dev/null)" || die "  установка ядра не удалась."
	jtrue "$(ucode "$CM" install_kmods "$PMG" 2>/dev/null)" || warn "  не удалось поставить kmod — без kmod-nft-tproxy/kmod-tun прокси не будет маршрутизировать."
	ok "  $CORE установлен."
}

# ------------------------------------------------------ 2.5 mosdns (MultiDNS)
install_mosdns() {
	if [ -x /usr/bin/mosdns ]; then ok "  mosdns уже установлен."; return 0; fi
	info "  ставлю mosdns (движок гонки DNS для MultiDNS)..."
	# Ф11 V2 feed-first: явный пакет из манифеста (sha256-гейт), фолбэк — zip.
	if ! [ -n "$LOCAL_DIR" ] && feed_install mosdns && [ -x /usr/bin/mosdns ]; then
		ok "  mosdns установлен (источник обновлений)."
		return 0
	fi
	# --local: готовый zip из каталога ставится обычным zip-путём ниже.
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

# ------------------------------------------------- 2.6-2.7 native helpers (probe_pool, sni_sniffer, utls_probe)
# Все опциональны: без них автоматизация работает штатно (shell-воркеры +
# tcpdump), а лаборатория — curl-пробами. Бинарники arch-специфичны и НЕ входят
# в пакет (пакет arch-independent) — скачиваются с релизов по архитектуре роутера.
go_arch_mapping() {
	case "$ARCH" in
		aarch64_*) GOASSET=arm64 ;;
		arm_cortex-a7*|arm_cortex-a9*|arm_cortex-a15*|arm_cortex-a8*|arm_mpcore*) GOASSET=armv7 ;;
		arm_cortex-a5*|arm926ej-s|arm_fa526) GOASSET=armv6 ;;
		x86_64) GOASSET=amd64 ;;
		mipsel_24kc|mipsel_74kc) GOASSET=mipsle-softfloat ;;
		mips_24kc|mips_74kc|mips_mips32*) GOASSET=mips-softfloat ;;
		riscv64*) GOASSET=riscv64 ;;
		*) GOASSET="" ;;
	esac
}

install_go_tool() {
	TOOL="$1"
	# $2 = "force": download again even if the binary is already present (update).
	if [ -x "/usr/bin/$TOOL" ] && [ "$2" != "force" ]; then ok "  $TOOL уже установлен."; return 0; fi
	info "  ставлю $TOOL (нативный помощник автоматизации)..."
	# Ф11 V2 feed-first: probe_pool/sni_sniffer живут в фиде явными пакетами.
	# utls_probe в фиде НЕ собирается — всегда релизный zip (честно).
	if [ "$TOOL" = "probe_pool" ] || [ "$TOOL" = "sni_sniffer" ]; then
		if [ -n "$LOCAL_DIR" ]; then
			lf=$(local_of "https://github.com/${HP_REPO}/releases/latest/download/${TOOL}-linux-x.zip")
			if [ -n "$lf" ]; then
				if ! command -v unzip >/dev/null 2>&1; then
					[ "$PM" = apk ] && apk add unzip >/dev/null 2>&1 || opkg install unzip >/dev/null 2>&1
				fi
				if command -v unzip >/dev/null 2>&1 && unzip -o "$lf" -d "/tmp/${TOOL}" >/dev/null 2>&1; then
					TBIN=$(find "/tmp/${TOOL}" -type f \( -name "$TOOL" -o -name "${TOOL}-*" \) 2>/dev/null | head -1)
					[ -n "$TBIN" ] && cp "$TBIN" "/usr/bin/$TOOL" && chmod 0755 "/usr/bin/$TOOL" && ok "  $TOOL установлен (--local)." && return 0
					rm -rf "/tmp/${TOOL}"
				fi
			fi
		elif feed_install "$TOOL" && [ -x "/usr/bin/$TOOL" ]; then
			ok "  $TOOL установлен (источник обновлений)."
			return 0
		fi
	fi
	go_arch_mapping
	if [ -z "$GOASSET" ]; then
		warn "  $TOOL: нет готового бинарника для архитектуры $ARCH — пропускаю (автоматизация обойдётся без него)."
		return 1
	fi
	if ! command -v unzip >/dev/null 2>&1; then
		if [ "$PM" = apk ]; then apk add unzip >/dev/null 2>&1; else opkg install unzip >/dev/null 2>&1; fi
	fi
	if command -v unzip >/dev/null 2>&1 && \
	   dl "https://github.com/${HP_REPO}/releases/latest/download/${TOOL}-linux-${GOASSET}.zip" "/tmp/${TOOL}.zip"; then
		unzip -o "/tmp/${TOOL}.zip" -d "/tmp/${TOOL}" >/dev/null 2>&1
		# В zip релиза бинарник лежит под полным именем ассета (probe_pool-linux-arm64),
		# допускаем и голое имя (probe_pool) — на случай смены формата архива.
		TBIN=$(find "/tmp/${TOOL}" -type f \( -name "$TOOL" -o -name "${TOOL}-*" \) 2>/dev/null | head -1)
		if [ -n "$TBIN" ]; then
			cp "$TBIN" "/usr/bin/$TOOL" && chmod 0755 "/usr/bin/$TOOL" && ok "  $TOOL установлен ($GOASSET)."
		else
			warn "  $TOOL: бинарник не найден в архиве — пропускаю (архив повреждён или пуст?)."
		fi
		rm -rf "/tmp/${TOOL}" "/tmp/${TOOL}.zip"
	else
		if ! command -v unzip >/dev/null 2>&1; then
			warn "  $TOOL: не установился unzip — некем распаковать архив — пропускаю."
		else
			warn "  $TOOL: не удалось скачать (GitHub заблокирован? попробуйте GH_MIRROR=...) — автоматизация обойдётся без него."
		fi
		return 1
	fi
	return 0
}

# Установить/обновить ВСЕХ нативных помощников одним пунктом. С force — даже
# если уже стоят (обновление из свежего релиза); без force — только отсутствующие.
install_native_helpers() {
	FORCE="$1"
	info "  нативные помощники (probe_pool, sni_sniffer, utls_probe)..."
	install_go_tool probe_pool $FORCE || true  # не фатально — фолбэк на shell-воркеры
	install_go_tool sni_sniffer $FORCE || true  # не фатально — фолбэк на tcpdump
	# ч.232: браузерная ClientHello-проба лаборатории (TSPU видит отпечаток
	# клиента; curl не воспроизводит). Нет бинарника — Passed честно меряет
	# только curl (как раньше), прогон не падает.
	install_go_tool utls_probe $FORCE || true
}

# ------------------------------------------------- 3. подписка / конфигурация
subscription_add() {
	ask "  Вставьте URL подписки (например https://ваш-провайдер/sub):"
	URL=$(echo "$REPLY" | tr -d ' ')
	if [ -z "$URL" ]; then warn "  URL пуст — пропускаю."; return 1; fi
	uci -q add_list ravnex.subscription.subscription_url="$URL"
	uci -q commit ravnex
	info "  загружаю узлы из подписки (может занять минуту)..."
	ucode /etc/ravnex/scripts/update_subscriptions.uc >/dev/null 2>&1
	if [ "$(count_nodes)" -gt 0 ]; then
		ok "  подписка добавлена: узлов $(count_nodes)."
		MN=$(uci -q get ravnex.config.main_node)
		if [ -z "$MN" ] || [ "$MN" = nil ]; then
			uci -q set ravnex.config.main_node=urltest
			uci -q set ravnex.config.main_urltest_mode=auto
			ok "  включён URLTest (авто) по всем узлам — выбирается самый быстрый."
		fi
		[ "$(uci -q get ravnex.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
		uci -q commit ravnex
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
	RES=$(ucode /etc/ravnex/scripts/import_link.uc "$LINK" 2>/dev/null)
	if printf '%s' "$RES" | grep -q '"result"[[:space:]]*:[[:space:]]*true'; then
		ok "  узел импортирован ($(printf '%s' "$RES" | sed -n 's/.*"imported":\[{"section":"\([^"]*\)".*/\1/p'))."
		MN=$(uci -q get ravnex.config.main_node)
		if [ -z "$MN" ] || [ "$MN" = nil ]; then
			uci -q set ravnex.config.main_node=urltest
			uci -q set ravnex.config.main_urltest_mode=auto
			ok "  включён URLTest (авто)."
		fi
		[ "$(uci -q get ravnex.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
		uci -q commit ravnex
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
			if [ -n "$(uci -q get "ravnex.$REPLY" 2>/dev/null)" ]; then
				uci -q set ravnex.config.main_node=urltest
				uci -q set ravnex.config.main_urltest_mode=prefer
				uci -q set ravnex.config.main_urltest_preferred="$REPLY"
				ok "  URLTest: приоритетный узел $REPLY + авто-пул остальных."
			else
				warn "  секция не найдена — отменено."; return 1
			fi ;;
		3)
			list_nodes
			ask "  Узел (имя секции из списка):"
			if [ -n "$(uci -q get "ravnex.$REPLY" 2>/dev/null)" ]; then
				uci -q set ravnex.config.main_node="$REPLY"
				ok "  основной узел: $REPLY."
			else
				warn "  секция не найдена — отменено."; return 1
			fi ;;
		*)
			uci -q set ravnex.config.main_node=urltest
			uci -q set ravnex.config.main_urltest_mode=auto
			ok "  URLTest: авто (все узлы)." ;;
	esac
	uci -q set ravnex.config.main_udp_node=same
	[ "$(uci -q get ravnex.config.routing_mode)" = proxy_banned_ru ] && add_rule refilter main-out
	uci -q commit ravnex
	return 0
}

# ------------------------------------------------------- 4. Hot Swap (горячий резерв)
ask_hotswap() {
	echo; ok "[4/10] Hot Swap — горячий резерв основного узла"
	info "  Держит наготове «горячие» запасные подключения: если активный узел умрёт,"
	info "  трафик за секунды переедет на живой резерв — БЕЗ рестарта ядра, без разрыва"
	info "  интернета и без сброса DNS. При восстановлении основной узел вернётся сам."
	info "  Работает и с конкретным основным узлом, и в режиме URLTest (спасает группу,"
	info "  залипшую на мёртвом узле). Имеет смысл, когда узлов два и больше."
	ask "  Включить сейчас? [Д/н]:"
	if is_no "$REPLY"; then
		info "  Включить позже: Client Settings → Routing → Hot Swap."
		return 0
	fi
	uci -q set ravnex.config.hotswap=1
	uci -q set ravnex.config.hotswap_count=3
	uci -q set ravnex.config.hotswap_failback=1
	uci -q commit ravnex
	ok "  Hot Swap включён (3 горячих соединения, автоматический возврат на основной)."
	return 0
}

# ------------------------------------------------------- 5. MultiDNS
ask_multidns() {
	echo; ok "[5/10] MultiDNS — ускоритель DNS"
	info "  Гоняет ВСЕ DNS-серверы пула параллельно и отдаёт самый быстрый живой ответ;"
	info "  демон качества проверяет, что ответы реально открывают сайты, и отсекает мёртвые."
	info "  Работает и без подписки (обычный пул — напрямую)."
	ask "  Включить сейчас? [Д/н]:"
	if is_no "$REPLY"; then info "  Включить позже: Client Settings → MultiDNS."; return 0; fi
	install_mosdns || return 1
	if [ -x /usr/bin/mosdns ]; then
		uci -q set ravnex.multidns.enabled=1
		uci -q set ravnex.multidns.bench_interval=600
		uci -q commit ravnex
		ok "  MultiDNS включён (проверка качества каждые 600 секунд)."
	fi
	return 0
}

# ------------------------------------------------------- 6. Автоматизация
ask_automation() {
	echo; ok "[6/10] Автоматизация — автообнаружение заблокированных сайтов"
	info "  Сама находит сайты, которые не открываются напрямую, и добавляет их в прокси-список."
	info "  БЕЗ подписки обнаружение работает, но маршрутизировать сайты через прокси нечем —"
	info "  они добавятся в список и заработают после добавления подписки/узла."
	ask "  Включить сейчас? [Д/н]:"
if is_no "$REPLY"; then info "  Включить позже: Automation."; return 0; fi
	# tcpdump нужен источнику SNI (ловит DoH-клиентов и приложения с hardcoded IP);
	# без него SNI молча неактивен, остальные источники работают.
	# probe_pool — нативный батч-пробировщик (HTTP/2, один процесс на волну вместо кучи shell-воркеров)
	install_native_helpers
	uci -q set ravnex.automation.enabled=1
	# Источники кандидатов: канонический СПИСОК (dns/clash/sni) под новый MultiValue-UI.
	# Старое значение 'all' демон понимает, но виджет его не показывает как выбранные пункты.
	uci -q delete ravnex.automation.discover 2>/dev/null
	uci -q add_list ravnex.automation.discover=dns
	uci -q add_list ravnex.automation.discover=clash
	uci -q add_list ravnex.automation.discover=sni
	# IP-обучение включено по умолчанию: conntrack-кандидаты фильтруются (повторы >=2 раз,
	# shared-CDN исключены, кап 8/цикл, min_confirm>=2) — безопасно и ловит Telegram DC/игры.
	uci -q set ravnex.automation.ip_learn=1
	uci -q commit ravnex
	ok "  Автоматизация включена (источники: DNS-лог + Clash + SNI; IP-изучение: вкл)."
	return 0
}

# ------------------------------------------------------- 7. Zapret 2
# Тест стратегии Zapret на YouTube через встроенный тестер (RPC zapret_strategy_test).
# Возвращает 1, если YouTube-рука прошла (tag=yt ok=1), иначе пусто/0.
zapret_test() {
	RES=$(ubus call luci.ravnex zapret_strategy_test "{\"cmd_opts\":\"$1\"}" 2>/dev/null)
	# The RPC embeds the tester JSON as an escaped string: \"tag\":\"yt\" ...
	printf '%s' "$RES" | sed -n 's/.*\\"tag\\":\\"yt\\"[^{}]*\\"ok\\":\([01]\).*/\1/p'
}

# Поставить Hostfakesplit по умолчанию, проверить YouTube; если не работает —
# перебрать встроенные стратегии до первой прошедшей.
zapret_pick_strategy() {
	[ -f /etc/ravnex/zapret_candidates.json ] || { warn "  нет списка стратегий — оставляю значение по умолчанию."; return 1; }
	command -v curl >/dev/null 2>&1 || { info "  ставлю curl (нужен тестеру)..."; [ "$PM" = apk ] && apk add curl >/dev/null 2>&1 || opkg install curl >/dev/null 2>&1; }

	HOSTFAKE=$(ucode -e 'import { readfile } from "fs"; let j = json(readfile("/etc/ravnex/zapret_candidates.json") || "{}"); for (let c in (j.candidates || [])) { if (c.name == "Hostfakesplit") { printf("%s", c.args); break; } }')
	[ -n "$HOSTFAKE" ] && uci -q set ravnex.config.zapret_cmd_opts="$HOSTFAKE"

	# Гарантия чистого прямого пути: на время тестов останавливаем сервис, чтобы
	# YouTube-проверка измеряла ТОЛЬКО стратегию Zapret, а не работающий прокси
	# (иначе при активной подписке тест всегда «проходит» через прокси).
	HP_WAS_RUNNING=0
	pidof hiddify-core >/dev/null 2>&1 && HP_WAS_RUNNING=1
	pidof sing-box >/dev/null 2>&1 && HP_WAS_RUNNING=1
	[ "$HP_WAS_RUNNING" = 1 ] && /etc/init.d/ravnex stop >/dev/null 2>&1

	RC=1
	info "  тестирую стратегию по умолчанию (Hostfakesplit) на YouTube (прямой путь)..."
	if [ "$(zapret_test "$HOSTFAKE")" = 1 ]; then
		uci -q commit ravnex
		ok "  Hostfakesplit работает — YouTube открывается."
		RC=0
	else
		info "  YouTube не открылся — перебираю встроенные стратегии (Recommended → остальные)..."
		ucode -e 'import { readfile } from "fs"; let j = json(readfile("/etc/ravnex/zapret_candidates.json") || "{}"); for (let c in (j.candidates || [])) { if (c.name != "Hostfakesplit") printf("%s\t%s\t%s\n", c.name, c.args, (c.group || "auto")); }' > /tmp/zcand.txt
		TRIED=0
		FOUND=0
		while IFS="$(printf '\t')" read -r NAME ARGS GROUP; do
			[ -n "$ARGS" ] || continue
			TRIED=$((TRIED+1))
			[ "$TRIED" -gt 12 ] && { info "  лимит перебора (12) — останавливаюсь."; break; }
			printf '    %2d) %s: ' "$TRIED" "$NAME"
			if [ "$(zapret_test "$ARGS")" = 1 ]; then
				echo "YouTube OK"
				uci -q set ravnex.config.zapret_cmd_opts="$ARGS"
				FOUND=1
				break
			fi
			echo "нет"
		done < /tmp/zcand.txt
		rm -f /tmp/zcand.txt
		uci -q commit ravnex
		if [ "$FOUND" = 1 ]; then
			ok "  выбрана стратегия: $NAME"
			RC=0
		else
			warn "  ни одна стратегия не прошла YouTube-тест — оставлена Hostfakesplit."
			warn "  Подберите позже: Мастер → Обход DPI (Strategy Lab)."
		fi
	fi

	# Возвращаем сервис (финальный рестарт в конце всё равно перечитает конфиг)
	[ "$HP_WAS_RUNNING" = 1 ] && { /etc/init.d/ravnex start >/dev/null 2>&1; sleep 3; }
	return $RC
}

install_zapret() {
	echo; ok "[7/10] Zapret 2 — обход DPI на уровне пакетов (подписка НЕ нужна)"
	info "  Бесплатно разблокирует YouTube и другие сервисы без VPN-подписки."
	info "  Встроенные профили + тестер: поставлю Hostfakesplit и проверю YouTube;"
	info "  если не заработает — сам переберу другие стратегии."
	ask "  Установить Zapret 2? [Д/н]:"
	if is_no "$REPLY"; then info "  пропускаю (можно поставить позже повторным запуском)."; return 0; fi
	info "  ставлю модуль ядра NFQUEUE..."
	if [ "$PM" = apk ]; then apk add kmod-nft-queue >/dev/null 2>&1; else opkg install kmod-nft-queue >/dev/null 2>&1; fi
	ZP=$(ubus call luci.ravnex zapret_prepare_install 2>/dev/null)
	if [ -z "$ZP" ] || jerr "$ZP"; then warn "  не удалось подготовить Zapret — пропускаю. ($(jget "$ZP" error))"
	else
		# Ф11 V2 feed-first: prepare вернул источник обновлений — явный файл.
		if [ "$(jget "$ZP" source)" = "feed" ] && [ -n "$(jget "$ZP" feed_pkg)" ]; then
			ZFPKG=$(jget "$ZP" feed_pkg)
			info "  Zapret: ставлю из источника обновлений ($ZFPKG $(jget "$ZP" version))..."
			if jtrue "$(ubus call luci.ravnex install_feed_pkg "{\"pkg\":\"$ZFPKG\"}" 2>/dev/null)"; then
				ok "  Zapret установлен (источник обновлений)."
				ZST=$(ubus call luci.ravnex zapret_status 2>/dev/null)
				if jfalse "$ZST" kmod_ok; then
					warn "  модуль NFQUEUE не загружен — Zapret не включаю (иначе сломается firewall)."
					warn "  Включите вручную после kmod-nft-queue (Client Settings → Routing → Enable Zapret)."
				else
					uci -q set ravnex.config.zapret_enabled=1
					uci -q commit ravnex
					ok "  Zapret включён."
					if zapret_pick_strategy; then
						add_rule youtube zapret-out
					else
						warn "  правило YouTube → Zapret НЕ добавлено (нет рабочей стратегии — иначе YouTube бы не открывался)."
						warn "  После подбора стратегии добавьте правило вручную: Proxy Rules → YouTube → Zapret."
					fi
				fi
				return 0
			fi
			warn "  установка из источника обновлений не удалась — возврат к обычным путям."
			ZP=$(ubus call luci.ravnex zapret_prepare_install 2>/dev/null)
			[ -n "$ZP" ] && ! jerr "$ZP" || return 0
		fi
		ZURL=$(jget "$ZP" dl_url); ZTMP=$(jget "$ZP" tmp_path); ZPMG=$(jget "$ZP" pkg_manager)
		if [ -n "$ZURL" ] && dl "$ZURL" "$ZTMP"; then
			RES=$(ubus call luci.ravnex zapret_install_pkg "{\"tmp_path\":\"$ZTMP\",\"pkg_manager\":\"$ZPMG\"}" 2>/dev/null)
			if jtrue "$RES"; then
				ok "  Zapret установлен."
				ZST=$(ubus call luci.ravnex zapret_status 2>/dev/null)
				if jfalse "$ZST" kmod_ok; then
					warn "  модуль NFQUEUE не загружен — Zapret не включаю (иначе сломается firewall)."
					warn "  Включите вручную после kmod-nft-queue (Client Settings → Routing → Enable Zapret)."
				else
					uci -q set ravnex.config.zapret_enabled=1
					uci -q commit ravnex
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

# ------------------------------------------------------- 7б. Автопилот стратегий
# Автопилот сам поддерживает обход в рабочем состоянии: по расписанию переразмечает
# корпус стратегий и применяет лучшую для YouTube/Discord/Telegram, ставит правила
# → Zapret, а при поломке стратегии подбирает новую не дожидаясь цикла.
ask_autopilot() {
	echo; ok "[8/10] Автопилот стратегий — обход поддерживается сам"
	info "  По расписанию (по умолчанию каждые 6 ч) гоняет фаззинг корпуса Zapret,"
	info "  применяет лучшую стратегию для каждого ресурса и держит правила"
	info "  YouTube/Discord/Telegram на Zapret; если стратегия перестала работать —"
	info "  новая подбирается сразу (проверки каждые 15 мин), не дожидаясь цикла."
	info "  Каждое применение делает снапшот — Restore в интерфейсе всё откатывает."
	ask "  Включить автоподбор стратегий? [Д/н]:"
	if is_no "$REPLY"; then
		info "  Включить позже: Мастер → Обход DPI → Автопилот (по расписанию)."
		return 0
	fi
	uci -q set ravnex.autopilot=ravnex
	uci -q set ravnex.autopilot.enabled=1
	uci -q set "ravnex.autopilot.resources=youtube discord telegram"
	uci -q set ravnex.autopilot.set_rules=1
	uci -q set ravnex.autopilot.interval_h=6
	uci -q set ravnex.autopilot.check_min=15
	uci -q set ravnex.autopilot.fail_strikes=2
	uci -q set ravnex.autopilot.fuzz_mode=quick
	uci -q commit ravnex
	ok "  Автопилот включён (цикл 6 ч, проверки каждые 15 мин)."
	info "  Настроить тонко: Мастер → Обход DPI → Автопилот (ресурсы, интервалы, окно)."
	return 0
}

# ------------------------------------------------------- 8. ByeDPI
install_byedpi() {
	echo; ok "[9/10] ByeDPI — обход DPI через локальный SOCKS (на ваше усмотрение)"
	info "  Альтернатива Zapret; стратегии подбираются в Мастере → Обход DPI (тестер встроен)."
	ask "  Установить ByeDPI? [y/N]:"
	if ! is_yes "$REPLY"; then info "  пропускаю."; return 0; fi
	info "  ставлю curl (его использует тестер стратегий ByeDPI)..."
	if [ "$PM" = apk ]; then apk add curl >/dev/null 2>&1; else opkg install curl >/dev/null 2>&1; fi
	BP=$(ubus call luci.ravnex byedpi_prepare_install 2>/dev/null)
	if [ -z "$BP" ] || jerr "$BP"; then warn "  не удалось подготовить ByeDPI — пропускаю. ($(jget "$BP" error))"
	else
		# Ф11 V2 feed-first: prepare вернул источник обновлений — явный файл.
		if [ "$(jget "$BP" source)" = "feed" ] && [ -n "$(jget "$BP" feed_pkg)" ]; then
			BFPKG=$(jget "$BP" feed_pkg)
			info "  ByeDPI: ставлю из источника обновлений ($BFPKG $(jget "$BP" version))..."
			if jtrue "$(ubus call luci.ravnex install_feed_pkg "{\"pkg\":\"$BFPKG\"}" 2>/dev/null)"; then
				ok "  ByeDPI установлен (источник обновлений)."
				uci set ravnex.config.byedpi_enabled=1; uci commit ravnex; ok "  ByeDPI включён."
				return 0
			fi
			warn "  установка из источника обновлений не удалась — возврат к обычным путям."
			BP=$(ubus call luci.ravnex byedpi_prepare_install 2>/dev/null)
			[ -n "$BP" ] && ! jerr "$BP" || return 0
		fi
		BURL=$(jget "$BP" dl_url); BTMP=$(jget "$BP" tmp_path); BPMG=$(jget "$BP" pkg_manager)
		if [ -n "$BURL" ] && dl "$BURL" "$BTMP"; then
			RES=$(ubus call luci.ravnex byedpi_install_pkg "{\"tmp_path\":\"$BTMP\",\"pkg_manager\":\"$BPMG\"}" 2>/dev/null)
			if jtrue "$RES"; then
				ok "  ByeDPI установлен."
				uci set ravnex.config.byedpi_enabled=1; uci commit ravnex; ok "  ByeDPI включён."
			else warn "  установка ByeDPI не удалась."; fi
		else warn "  не удалось скачать ByeDPI — пропускаю."; fi
	fi
	return 0
}

# ------------------------------------------------------- 10. Telegram-бот и «Контроль»
# Токен проверяется форматом и живым getMe (api.telegram.org может быть недоступен
# напрямую — тогда токен всё равно сохраняется, бот переподключится сам).
# chat_id оставляем пустым: бот привязывает ПЕРВЫЙ чат, который напишет боту.
telegram_setup() {
	# Боту нужен curl (tg_call ходит в Bot API через curl); если нет — ставим.
	command -v curl >/dev/null 2>&1 || { [ "$PM" = apk ] && apk add curl >/dev/null 2>&1 || opkg install curl >/dev/null 2>&1; }
	uci -q get ravnex.telegram >/dev/null 2>&1 || uci -q set ravnex.telegram=ravnex
	ask "  Вставьте токен бота от @BotFather (123456:ABC-DEF…), пусто — пропустить:"
	TOK=$(echo "$REPLY" | tr -d ' \t')
	if [ -z "$TOK" ]; then
		warn "  токен не задан — бот остаётся выключенным (токен позже: LuCI → Telegram-бот или повторный запуск)."
		return 0
	fi
	if ! printf '%s' "$TOK" | grep -qE '^[0-9]+:[A-Za-z0-9_-]+$'; then
		warn "  токен не похож на формат Telegram (ожидается цифры:символы) — отмена."
		return 1
	fi
	RES=$(curl -s --max-time 10 "https://api.telegram.org/bot${TOK}/getMe" 2>/dev/null)
	BOTNAME=$(jget "$RES" username)
	if printf '%s' "$RES" | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
		ok "  токен принят (бот: @${BOTNAME:-?})."
	else
		warn "  api.telegram.org не ответил (заблокирован провайдером/нет сети) — токен сохраняю, бот подключится сам."
	fi
	uci -q set ravnex.telegram.token="$TOK"
	uci -q set ravnex.telegram.enabled=1
	uci -q commit ravnex
	ok "  Telegram-бот включён."
	info "  Привяжите чат: отправьте боту /start — первый написавший привязывается автоматически."
	info "  Держите токен в секрете: кто первый напишет боту, тот и получит управление."
	return 0
}

telegram_toggle() {
	if [ "$(uci -q get ravnex.telegram.enabled)" = 1 ]; then
		ask "  Бот включён. Выключить? [y/N]:"
		if is_yes "$REPLY"; then
			uci -q set ravnex.telegram.enabled=0; uci -q commit ravnex
			ok "  Telegram-бот выключен (демон остаётся в спящем цикле, токен сохранён)."
		fi
	else
		telegram_setup || true
		if [ "$(uci -q get ravnex.telegram.enabled)" = 1 ]; then
			info "  применяю (рестарт службы)..."
			/etc/init.d/ravnex restart >/dev/null 2>&1
		fi
	fi
	return 0
}

control_setup() {
	uci -q get ravcontrol.main >/dev/null 2>&1 || uci -q set ravcontrol.main=main
	uci -q set ravcontrol.main.enabled=1
	uci -q set ravcontrol.main.paused=0
	uci -q set ravcontrol.main.log_enabled=1
	uci -q set ravcontrol.main.log_max=500
	uci -q commit ravcontrol
	ok "  «Контроль» включён (без правил пока ничего не блокирует)."
	info "  Устройства / правила / расписания / Wi-Fi: LuCI → Контроль или прямо из бота"
	info "  (/devices, /blocksite, /wifi). Движок применения правил запускается службой сам."
	return 0
}

control_toggle() {
	if [ "$(uci -q get ravcontrol.main.enabled)" = 1 ]; then
		ask "  «Контроль» включён. Выключить? [y/N]:"
		if is_yes "$REPLY"; then
			uci -q set ravcontrol.main.enabled=0; uci -q commit ravcontrol
			ok "  «Контроль» выключен (все правила сняты при следующем проходе движка)."
		fi
	else
		control_setup
	fi
	return 0
}

ask_telegram_control() {
	echo; ok "[10/10] Telegram-бот и родительский контроль («Контроль»)"
	info "  Бот: /status, /nodes, /switch, /devices, /blocksite, /wifi, /snapshot и пуш-уведомления"
	info "  о событиях (Hot Swap, Zapret/ByeDPI, обучение, контроль) — управление роутером из чата."
	info "  «Контроль»: блок сайтов/устройств по расписанию, временные разрешения, Wi-Fi."
	ask "  Настроить Telegram-бота сейчас (нужен токен от @BotFather)? [y/N]:"
	if is_yes "$REPLY"; then telegram_setup; fi
	ask "  Включить «Контроль» (каркас; правила настраиваются потом)? [y/N]:"
	if is_yes "$REPLY"; then control_setup; fi
	return 0
}

# ------------------------------------------------------------- меню (повторный запуск)
menu() {
	while true; do
		echo
		info "===== Настройка Ravnex ====="
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
		echo "  10) Переустановить приложение (скачать и поставить заново)"
		echo "  11) Восстановить критические конфиги (firewall includes и др.)"
		echo "  12) Нативные помощники автоматизации (установить/обновить)"
		echo "  13) Telegram-бот (вкл/выкл, токен)"
		echo "  14) «Контроль» — родительский контроль (вкл/выкл)"
		echo "  0) Выход"
		ask "  Выбор [0-14]:"
		case "$REPLY" in
			1) subscription_add && apply_and_check ;;
			2) share_link_add && apply_and_check ;;
			3) choose_main_node && apply_and_check ;;
			4)
				if [ "$(uci -q get ravnex.multidns.enabled)" = 1 ]; then
					ask "  MultiDNS включён. Выключить? [y/N]:"
					if is_yes "$REPLY"; then
						uci -q set ravnex.multidns.enabled=0; uci -q commit ravnex
						/etc/init.d/ravnex restart >/dev/null 2>&1
						ok "  MultiDNS выключен."
					fi
				else
					install_mosdns && ask "  Включить MultiDNS? [Д/н]:" && \
						if ! is_no "$REPLY"; then
							uci -q set ravnex.multidns.enabled=1
							uci -q set ravnex.multidns.bench_interval=600
							uci -q commit ravnex
							/etc/init.d/ravnex restart >/dev/null 2>&1
							ok "  MultiDNS включён."
						fi
				fi ;;
			5)
				if [ "$(uci -q get ravnex.automation.enabled)" = 1 ]; then
					ask "  Автоматизация включена. Выключить? [y/N]:"
					if is_yes "$REPLY"; then
						uci -q set ravnex.automation.enabled=0; uci -q commit ravnex
						/etc/init.d/ravnex restart >/dev/null 2>&1
						ok "  Автоматизация выключена."
					fi
				else
					ask "  Включить Автоматизацию? [Д/н]:"
					if ! is_no "$REPLY"; then
						install_native_helpers
						uci -q set ravnex.automation.enabled=1; uci -q commit ravnex
						/etc/init.d/ravnex restart >/dev/null 2>&1
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
					elif [ "$(uci -q get ravnex.config.zapret_enabled)" = 1 ] && [ -n "$(uci -q get ravnex.config.zapret_cmd_opts)" ]; then
						info "  стратегия уже задана — проверяю правило YouTube → Zapret..."
						add_rule youtube zapret-out
					fi
					ask "  Включить автоподбор стратегий (автопилот)? [Д/н]:"
					if ! is_no "$REPLY"; then
						uci -q set ravnex.autopilot=ravnex
						uci -q set ravnex.autopilot.enabled=1
						uci -q set "ravnex.autopilot.resources=youtube discord telegram"
						uci -q set ravnex.autopilot.set_rules=1
						uci -q set ravnex.autopilot.interval_h=6
						uci -q set ravnex.autopilot.check_min=15
						uci -q set ravnex.autopilot.fail_strikes=2
						uci -q set ravnex.autopilot.fuzz_mode=quick
						uci -q commit ravnex
						ok "  Автопилот включён (цикл 6 ч, проверки каждые 15 мин)."
					fi
				fi
				apply_and_check ;;
			7) install_byedpi; apply_and_check ;;
			8) install_core; apply_and_check ;;
			9)
				if [ -z "$(uci -q get ravnex.subscription.subscription_url)" ]; then
					warn "  подписок не настроено — добавьте через п.1."
				else
					info "  обновляю узлы из подписок..."
					ucode /etc/ravnex/scripts/update_subscriptions.uc >/dev/null 2>&1
					ok "  готово: узлов $(count_nodes)."
					apply_and_check
				fi ;;
			0|"") info "  Готово. Откройте LuCI → Services → Ravnex."; break ;;
			10) app_reinstall ;;
			11) heal_configs ;;
			12)
				install_native_helpers force
				# Новые бинарники подхватит следующий проход демона; рестарт ускоряет.
				if [ "$(uci -q get ravnex.automation.enabled)" = 1 ]; then
					info "  перезапускаю службу, чтобы помощники подхватились сразу..."
					/etc/init.d/ravnex restart >/dev/null 2>&1
				fi ;;
			13) telegram_toggle; apply_and_check ;;
			14)
				control_toggle
				# Движок контроля гейтится сам на каждом тике — рестарт не нужен,
				# но разовый apply ускоряет первое применение.
				if [ "$(uci -q get ravcontrol.main.enabled)" = 1 ]; then
					info "  применяю состояние контроля..."
					( /usr/bin/ucode -L /etc/ravnex/scripts /etc/ravnex/scripts/control_apply.uc >/dev/null 2>&1 & )
				fi ;;
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
	info "Откройте Ravnex в браузере:"
	URL="http://$LANIP/cgi-bin/luci/admin/services/ravnex"
	printf '\033[0;36m  \033]8;;%s\033\\%s\033]8;;\033\\\033[0m\n' "$URL" "$URL"
	info "Проверка прокси и выбор стратегий: Диагностика / Мастер → Обход DPI (Strategy Lab)."
}

# ======================================================== ГЛАВНЫЙ ПОТОК

if [ "$APP_INSTALLED" = 1 ]; then
	ok "Приложение уже установлено — проверяю обновления и перехожу в режим настройки."
	app_update_if_needed
	# Чужой конфликтующий пакет только что удалили — гарантированно ставим наш
	# пакет заново поверх (файлы могли остаться записанными от чужого пакета).
	[ "$FOREIGN_REMOVED" = 1 ] && app_reinstall
	/etc/init.d/rpcd restart >/dev/null 2>&1; sleep 1
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	feed_init || true   # источник обновлений: ключ + манифест (best-effort, фолбэк — обычные пути)
	ensure_baseline
	apply_and_check
	menu
	exit 0
fi

install_app

set_dns_defaults

feed_init || true   # источник обновлений: ключ + манифест (best-effort, фолбэк — обычные пути)

install_core

echo; ok "[3/10] Подписка или конфигурация (можно добавить позже)"
info "  Без подписки заблокированные сервисы (Telegram, WhatsApp, Instagram…) недоступны,"
info "  но интернет будет работать полностью (напрямую)."
ask "  Добавить подписку (URL) сейчас? [y/N]:"
if is_yes "$REPLY"; then
	subscription_add
else
	ask "  Добавить узел строкой подключения (vless://… и т.п.)? [y/N]:"
	is_yes "$REPLY" && share_link_add
fi

ask_hotswap
ask_multidns
ask_automation
install_zapret
ask_autopilot
install_byedpi
ask_telegram_control

ensure_baseline

echo; ok "[финал] Применяю настройки"
/etc/init.d/ravnex enable >/dev/null 2>&1
/etc/init.d/ravnex restart >/dev/null 2>&1
wait_core
sleep 4
validate_proxy
internet_check
summary
