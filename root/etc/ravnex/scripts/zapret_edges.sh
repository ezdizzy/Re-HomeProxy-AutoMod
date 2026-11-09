#!/bin/sh
# zapret_edges.sh — the CDN pool edge matrix, measured through the LIVE path
# (the currently applied strategy/engine), ONCE per fuzz sweep.
#
# WHY (сеанс 181, живой диагноз 2026-11-09): "одна выдача YouTube — одни видео
# грузятся, другие нет" — один googlevideo-пул (sn-XXXX) обслуживается
# несколькими rrN-хостами = несколькими РАЗНЫМИ IP, и отдельный IP пула может
# быть отрезан по пути ЦЕЛИКОМ (живой факт: 185.221.46.48 = rr5---sn-nx5pm-3ggl
# — TCP/TLS молча drop, соседи .45-.47 живы; никакая стратегия это не чинит).
# Свип обязан ЗНАТЬ такую карту до перебора стратегий: мёртвый край не должен
# наказывать стратегию, а живые края = кандидаты для per-edge глубокой батареи.
#
# Pure observation: NO nft manipulation, NO temp queue — every probe rides the
# production path exactly like a LAN client (that IS the quantity of interest).
#
# Input:  $1 = a videoplayback URL (or any googlevideo URL) — its host defines
#         the pool suffix; empty → the yt_stream.json cache host.
# Output: one JSON line {"ok":N,"suffix":"sn-…","engine":"live",
#         "edges":[{"host","ip","tls_ok","tls_ms","get_code","get_bytes",
#                   "get_spd","quic","primary":0|1},…],"note":""}
#
# Per edge: utls_probe (chrome ClientHello, 6 s) + a root-path HTTP fetch
# (server liveness; the primary edge additionally gets a ranged 2 MB pull of
# the REAL videoplayback URL = throughput) + probe_pool QUIC check (5 s).

URL="${1:-${YTV_URL}}"
CACHE=/var/run/ravnex/yt_stream.json

emit_fail() { echo "{\"ok\":0,\"error\":\"$1\"}"; exit 0; }

[ -z "$URL" ] && [ -s "$CACHE" ] && URL=$(grep -oE '"url": *"https://[^"]+' "$CACHE" 2>/dev/null | head -1 | cut -d'"' -f4)
[ -n "$URL" ] || emit_fail "no videoplayback URL (set $1 or have a fresh yt_stream.json)"

HOST=$(printf '%s' "$URL" | sed -E 's#^https://([^/]+).*#\1#')
case "$HOST" in
	*.googlevideo.com) : ;;
	*) emit_fail "URL host is not googlevideo: $HOST" ;;
esac
SUFFIX=$(printf '%s' "$HOST" | sed -E 's/^rr[0-9]*---//')

# enumerate pool members rr1..rr6 of the same suffix, distinct public IPs
POOL=""
for k in 1 2 3 4 5 6; do
	PH="rr$k---$SUFFIX"
	PIP=$(nslookup "$PH" 2>/dev/null \
		| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
		| grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|198\.(1[89])\.|2[4-9][0-9]\.|0\.)' \
		| head -1)
	[ -n "$PIP" ] || continue
	case "$POOL" in *"[$PIP]"*) continue ;; esac
	POOL="$POOL[$PIP]$PH
"
done

[ -n "$(printf '%s' "$POOL" | tr -d '[:space:]')" ] || emit_fail "pool enumeration returned nothing for $SUFFIX"

EJSON=""
printf '%s' "$POOL" | { SEP=""
while IFS= read -r line; do
	[ -n "$line" ] || continue
	PIP=${line%%]*}
	PIP=${PIP#[}
	PH=${line#*]}
	PRIMARY=0
	[ "$PH" = "$HOST" ] && PRIMARY=1
	# TLS ClientHello (browser fingerprint)
	TLS_OK=0; TLS_MS=0
	UOUT=$(/usr/bin/utls_probe -host "$PH" -ip "$PIP" -fp chrome -timeout 6 2>/dev/null | head -1)
	case "$UOUT" in
		*'ok":1'*|*'ok": true'*)
			TLS_OK=1
			TLS_MS=$(printf '%s' "$UOUT" | grep -oE '"tls_ms":[0-9]+' | head -1 | cut -d: -f2)
			;;
	esac
	# HTTP liveness (root path; a live googlevideo edge answers 404 quickly)
	GCODE=0; GBYTES=0; GSPD=0
	COUT=$(curl -s --resolve "$PH:443:$PIP" -o /dev/null \
		-w '%{http_code}|%{size_download}|%{speed_download}' \
		--connect-timeout 4 --max-time 8 "https://$PH/" 2>/dev/null)
	GCODE=$(printf '%s' "$COUT" | cut -d'|' -f1)
	GBYTES=$(printf '%s' "$COUT" | cut -d'|' -f2)
	GSPD=$(printf '%s' "$COUT" | cut -d'|' -f3)
	case "$GCODE" in ''|*[!0-9]*) GCODE=0 ;; esac
	case "$GBYTES" in ''|*[!0-9]*) GBYTES=0 ;; esac
	case "$GSPD" in ''|*[!0-9]*|*.*) GSPD=0 ;; esac
	# real throughput on the primary edge only (ranged 2 MB of the actual URL)
	if [ "$PRIMARY" = "1" ]; then
		C2=$(curl -s --resolve "$PH:443:$PIP" -r 0-2097151 -o /dev/null \
			-w '%{http_code}|%{size_download}|%{speed_download}' \
			--connect-timeout 4 --max-time 10 "$URL" 2>/dev/null)
		P_CODE=$(printf '%s' "$C2" | cut -d'|' -f1)
		P_SPD=$(printf '%s' "$C2" | cut -d'|' -f3)
		case "$P_CODE" in 200|206)
			GCODE=$P_CODE
			GBYTES=$(printf '%s' "$C2" | cut -d'|' -f2)
			case "$P_SPD" in ''|*[!0-9]*|*.*) P_SPD=0 ;; esac
			GSPD=$P_SPD
			;;
		esac
	fi
	# QUIC contour (probe_pool VN-level)
	QV="-"
	if [ -x /usr/bin/probe_pool ]; then
		QV=$(/usr/bin/probe_pool -quic-check "$PIP" -quic-host "$PH" 2>/dev/null \
			| grep -oE '"quic":"[a-z]+"' | head -1 | cut -d'"' -f4)
		[ -n "$QV" ] || QV="-"
	fi
	case "$GSPD" in ''|*[!0-9]*) GSPD=0 ;; esac
	case "$TLS_MS" in ''|*[!0-9]*) TLS_MS=0 ;; esac
	printf '%s{"host":"%s","ip":"%s","tls_ok":%d,"tls_ms":%d,"get_code":%s,"get_bytes":%s,"get_spd":%s,"quic":"%s","primary":%d}' \
		"$SEP" "$PH" "$PIP" "$TLS_OK" "$TLS_MS" "$GCODE" "$GBYTES" "$GSPD" "$QV" "$PRIMARY"
	SEP=","
done
} > /tmp/zapret_edges_rows.$$

# assemble (the pipe runs the loop in a subshell; the rows file carries data out)
ROWS=/tmp/zapret_edges_rows.$$
# count OCCURRENCES, not lines: the rows print on ONE line (live fact of the
# first acceptance sweep: grep -c counted 1 for a 6-edge matrix)
NEDGE=$(grep -o '"host"' "$ROWS" 2>/dev/null | wc -l)
[ -n "$NEDGE" ] || NEDGE=0
echo "{\"ok\":1,\"suffix\":\"$SUFFIX\",\"engine\":\"live\",\"edge_count\":$NEDGE,\"edges\":[$(cat "$ROWS")]}"
rm -f "$ROWS" 2>/dev/null
