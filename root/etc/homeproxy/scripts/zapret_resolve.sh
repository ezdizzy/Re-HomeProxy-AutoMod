#!/bin/sh
# Resolve the Strategy Lab tester's fixed test hosts — ONCE, up front, so the
# full-test sweep doesn't re-hit DNS for every one of its candidates.
#
# Ф6.4 (план 20 §Ф6; аудит 85): each tag resolves TWO distinct IPv4 (the
# finalists' second pass measures a DIFFERENT edge — one IP per sweep made the
# whole ranking a single-CDN measurement). A tag with fewer A-records carries
# an empty second/third IP and the finalists pass honestly skips them.
#
# Ф6.4 (аудит 58/59/83): the probe path must repeat the DEVICE's DNS path and
# the sweep must compare DNS SETS, not single answers. Four honest views:
#   device  — the router's normal resolver: the SAME secure-DNS/direct path
#             production uses for these blocked domains (what a LAN client
#             is served);
#   plain   — direct UDP/53 to 8.8.8.8 (may be transparently hijacked —
#             that is exactly what the comparison exposes);
#   plain2  — direct UDP/53 to 1.1.1.1;
#   doh     — independent DoH (Cloudflare JSON API over the router's normal
#             egress — NOT the ISP's UDP/53 path).
# SETS (unique IPv4, sorted) are compared as SETS:
#   consistent   — the device set intersects the independent views;
#   divergence   — device disagrees with BOTH plain views while those agree
#                  (geo-balancing/anycast/CDN policy) — explicitly NOT
#                  "poison" (audit 58: dns_divergence ≠ dns_poison without
#                  the differential probe);
#   device_fail  — device empty while the independent views answer (direct
#                  probes would measure nothing — honest flag);
#   device_only  — the device path answers but no independent view does
#                  (filtered/hijacked UDP or v6-only answers upstream);
#                  the device set is taken as is, honestly noted.
#
# Each lookup is time-bounded (busybox has no `timeout`: bg + watchdog kill)
# so a wedged resolver can't hang the rpcd call. The device view keeps one
# retry (applying Zapret restarts the DNS resolver and it is briefly
# unavailable right after).
#
# Output: one JSON line —
#   {"ok":1,"ips":{"yt":"1.2.3.4",…},"ips2":{"yt":"5.6.7.8"|"",…},
#    "dns":{"yt":{"device":[…],"plain":[…],"plain2":[…],"doh":[…],
#                 "verdict":"…","note":"…"},…}}
#   {"ok":0,"error":"…"}

# ч.235 (решение пользователя): tg УБРАН из набора проб свипа — telegram нет
# в autopilot.resources («youtube discord»), вердикт для tg после ч.234 всё
# равно «не применим» (via_node), а пробы тратили минуты и добавляли
# DNS-таймауты-шум (ч.233). resource_verdict на пустом наборе честно даёт
# no_candidate → оптимизатор показывает via_node, как и раньше. Ручной тестер
# (zapret_test.sh без аргументов) сохраняет tg — точечная диагностика жива.
HOSTS="yt|redirector.googlevideo.com dc|discord.com st|www.speedtest.net"

TMP=/tmp/zapret_resolve.$$
mkdir -p "$TMP" 2>/dev/null
trap 'rm -rf "$TMP" 2>/dev/null' EXIT INT TERM

# SET extraction: server lines on this busybox carry a ":53" port suffix and
# IPv6 answers contain ':digits' — both are dropped, leaving bare IPv4
# answers only (verified live: "Address: 1.2.3.4", server "Address:
# 127.0.0.1:53"). The SET keeps EVERY answer incl. bogus/private ones — the
# comparison is the evidence (a poisoned 127.0.0.1 in the device set vs real
# IPs elsewhere is exactly what divergence must show); private/bogon answers
# are excluded only when picking the PROBE IP below.
set_from() {  # $1 = nslookup output file → sorted unique IPv4 to stdout
	grep -E '^[[:space:]]*Address' "$1" 2>/dev/null \
		| grep -vE ':[0-9]+' \
		| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
		| sort -u
}

lookup_bg() {  # $1=host  $2=resolverspec(empty=device)  $3=outfile
	nslookup "$1" $2 > "$3" 2>&1 &
	np=$!
	( sleep 2; kill "$np" 2>/dev/null ) >/dev/null 2>&1 & sw=$!
	wait "$np" 2>/dev/null
	kill "$sw" 2>/dev/null
}

doh_query() {  # $1=host → Cloudflare JSON API over the router's normal egress
	curl -s --connect-timeout 4 --max-time 8 \
		-H 'accept: application/dns-json' \
		"https://1.1.1.1/dns-query?name=$1&type=A" 2>/dev/null
}

resolve_tag() {  # $1=tag  $2=host
	lookup_bg "$2" "" "$TMP/raw_dev_$1"
	if ! grep -qE '([0-9]{1,3}\.){3}' "$TMP/raw_dev_$1" 2>/dev/null; then
		sleep 1
		lookup_bg "$2" "" "$TMP/raw_dev_$1"
	fi
	lookup_bg "$2" "8.8.8.8" "$TMP/raw_pl_$1"
	lookup_bg "$2" "1.1.1.1" "$TMP/raw_pl2_$1"
	doh_query "$2" > "$TMP/raw_doh_$1" 2>/dev/null
	set_from "$TMP/raw_dev_$1" > "$TMP/dev_$1"
	set_from "$TMP/raw_pl_$1" > "$TMP/pl_$1"
	set_from "$TMP/raw_pl2_$1" > "$TMP/pl2_$1"
	grep -oE '"data":"([0-9]{1,3}\.){3}[0-9]{1,3}"' "$TMP/raw_doh_$1" 2>/dev/null \
		| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$TMP/doh_$1"
	# second/third distinct PUBLIC A for the finalists (audit 85)
	grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|198\.(1[89])\.|2[4-9][0-9]\.|0\.)' "$TMP/dev_$1" 2>/dev/null > "$TMP/pub_$1"
}

# SET intersection via grep -Fx -f (busybox has no comm — verified live).
inter_count() {  # $1=set file A  $2=set file B → count of lines of B ∩ A
	grep -Fx -f "$1" "$2" 2>/dev/null | wc -l
}

json_array() {  # $1=set file → "a","b" (no brackets)
	awk '{printf "%s\"%s\"", (n++ ? "," : ""), $1}' "$1" 2>/dev/null
}

# Set comparison (audit 58): SETS, honest confidence, no "poison". The
# independent reference = the UNION of the three independent views (plain,
# plain2, doh) — direct UDP/53 to public resolvers is commonly dropped by the
# ISP (live fact: those views time out empty), the DoH view then carries the
# independent evidence alone. Device ∩ union ≠ ∅ → consistent; empty →
# divergence (geo/anycast/CDN policy — NOT poison without the differential
# probe).
verdict_for() {  # $1=tag → "verdict<TAB>note"
	local nd no inter
	nd=$(wc -l < "$TMP/dev_$1" 2>/dev/null)
	cat "$TMP/pl_$1" "$TMP/pl2_$1" "$TMP/doh_$1" 2>/dev/null | sort -u > "$TMP/oth_$1"
	no=$(wc -l < "$TMP/oth_$1" 2>/dev/null)
	if [ "$nd" -eq 0 ] && [ "$no" -gt 0 ]; then
		printf 'device_fail\tпуть устройства НЕ ответил на запрос — прямые пробы этого домена ничего не измеряют, помечены честно'
		return
	fi
	if [ "$nd" -gt 0 ] && [ "$no" -eq 0 ]; then
		printf 'device_only\tнезависимые резолверы не ответили (UDP-фильтрация у провайдера или v6-only ответы) — сравнение наборов невозможно, набор устройства взят как есть'
		return
	fi
	if [ "$nd" -eq 0 ] && [ "$no" -eq 0 ]; then
		printf 'device_fail\tDNS не ответил ни на одном пути — проверка DNS недоступна'
		return
	fi
	inter=$(inter_count "$TMP/dev_$1" "$TMP/oth_$1")
	if [ "$inter" -eq 0 ]; then
		printf 'divergence\tнабор адресов пути устройства не пересекается с независимыми резолверами (гео-балансировка/anycast/CDN-политика) — расхождение DNS, НЕ доказательство подмены'
	else
		printf 'consistent\t'
	fi
}

J_IPS=""; J_IPS2=""; J_DNS=""; ANY=0
for pass in 1 2; do
	J_IPS=""; J_IPS2=""; J_DNS=""; ANY=0
	for h in $HOSTS; do
		tag=${h%%|*}; host=${h##*|}
		resolve_tag "$tag" "$host"
		ip1=$(head -n 1 "$TMP/pub_$tag" 2>/dev/null)
		ip2=$(sed -n '2p' "$TMP/pub_$tag" 2>/dev/null)
		[ -n "$ip1" ] && ANY=1
		[ -n "$J_IPS" ] && J_IPS="$J_IPS,"
		J_IPS="$J_IPS\"$tag\":\"$ip1\""
		[ -n "$J_IPS2" ] && J_IPS2="$J_IPS2,"
		J_IPS2="$J_IPS2\"$tag\":\"$ip2\""
		v=$(verdict_for "$tag")
		vv=$(printf '%s' "$v" | cut -f1)
		vn=$(printf '%s' "$v" | cut -f2)
		[ -n "$J_DNS" ] && J_DNS="$J_DNS,"
		J_DNS="$J_DNS\"$tag\":{\"device\":[$(json_array "$TMP/dev_$tag")],\"plain\":[$(json_array "$TMP/pl_$tag")],\"plain2\":[$(json_array "$TMP/pl2_$tag")],\"doh\":[$(json_array "$TMP/doh_$tag")],\"verdict\":\"$vv\",\"note\":\"$vn\"}"
	done
	[ "$ANY" = 1 ] && break
	[ "$pass" = 2 ] || sleep 1
done

if [ "$ANY" = 1 ]; then
	echo "{\"ok\":1,\"ips\":{$J_IPS},\"ips2\":{$J_IPS2},\"dns\":{$J_DNS}}"
else
	echo '{"ok":0,"error":"could not resolve any test host (DNS not ready? wait a few seconds after Apply, then retry)"}'
fi
