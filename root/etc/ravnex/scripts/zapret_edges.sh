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
#         OR $1 = --pools, $2 = suffix list (CSV/space): measure EVERY pool
#         independently (сeанс 183: whole /29 blackouts per pool in ONE moment —
#         nx5pm alive while 5goeen7y/aj5goc were dead entirely) and emit ONE
#         combined JSON {"ok":1,"engine":"live","pools":[{suffix,edges},…]}.
#         Multipool has no per-pool videoplayback URL → no ranged 2MB pull,
#         primary=0 for every edge; the probes themselves are identical.
# Output: one JSON line {"ok":N,"suffix":"sn-…","engine":"live",
#         "edges":[{"host","ip","tls_ok","tls_ms","get_code","get_bytes",
#                   "get_score"→"get_spd","quic","primary":0|1},…],"note":""}
#         (multipool mode: {"ok":1,"engine":"live","pools":[…]}; a pool whose
#         enumeration returns nothing is recorded as a fail entry, not a crash)
#
# Per edge: utls_probe (chrome ClientHello, 6 s) + a root-path HTTP fetch
# (server liveness; the primary edge additionally gets a ranged 2 MB pull of
# the REAL videoplayback URL = throughput) + probe_pool QUIC check (5 s).

URL="${1:-${YTV_URL}}"
CACHE=/var/run/ravnex/yt_stream.json

emit_fail() { echo "{\"ok\":0,\"error\":\"$1\"}"; exit 0; }

# ONE probe implementation for BOTH modes (double-copy lesson: a forked
# probe body always drifted) — prints the edge row JSON on stdout.
# Args: host ip primary(0|1). Uses $URL for the primary ranged pull.
measure_row() {
	_PH="$1"; _PIP="$2"; _PRIMARY="$3"; _DOQ="${4:-1}"
	# TLS ClientHello (browser fingerprint)
	TLS_OK=0; TLS_MS=0
	UOUT=$(/usr/bin/utls_probe -host "$_PH" -ip "$_PIP" -fp chrome -timeout 6 2>/dev/null | head -1)
	case "$UOUT" in
		*'ok":1'*|*'ok": true'*)
			TLS_OK=1
			TLS_MS=$(printf '%s' "$UOUT" | grep -oE '"tls_ms":[0-9]+' | head -1 | cut -d: -f2)
			;;
	esac
	# HTTP liveness (root path; a live googlevideo edge answers 404 quickly)
	GCODE=0; GBYTES=0; GSPD=0
	COUT=$(curl -s --resolve "$_PH:443:$_PIP" -o /dev/null \
		-w '%{http_code}|%{size_download}|%{speed_download}' \
		--connect-timeout 4 --max-time 8 "https://$_PH/" 2>/dev/null)
	GCODE=$(printf '%s' "$COUT" | cut -d'|' -f1)
	GBYTES=$(printf '%s' "$COUT" | cut -d'|' -f2)
	GSPD=$(printf '%s' "$COUT" | cut -d'|' -f3)
	case "$GCODE" in ''|*[!0-9]*) GCODE=0 ;; esac
	case "$GBYTES" in ''|*[!0-9]*) GBYTES=0 ;; esac
	case "$GSPD" in ''|*[!0-9]*|*.*) GSPD=0 ;; esac
	# real throughput on the primary edge only (ranged 2 MB of the actual URL)
	if [ "$_PRIMARY" = "1" ]; then
		C2=$(curl -s --resolve "$_PH:443:$_PIP" -r 0-2097151 -o /dev/null \
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
	# QUIC contour (probe_pool VN-level). Only where the edge ANSWERED
	# something (TLS or root-HTTP): a black edge answers nothing anywhere,
	# the probe is a fixed ~5 s tax per dead edge and a fully black /29
	# would pay it 5-6 times per pool. On a dead edge "-" is as honest.
	# Field name rides BOTH probe_pool generations: the 3.1.0 helpers emit
	# "verdict", the older ones "quic" (live fact 2026-11-10: every edge
	# showed quic:"-" because the parser greped a field the binary no
	# longer prints).
	QV="-"
	if [ "${_DOQ:-1}" = "1" ] && { [ "$TLS_OK" = "1" ] || [ "$GCODE" != "0" ]; } \
		&& [ -x /usr/bin/probe_pool ]; then
		QV=$(/usr/bin/probe_pool -quic-check "$_PIP" -quic-host "$_PH" 2>/dev/null \
			| grep -oE '"(verdict|quic)":"[a-z]+"' | head -1 | cut -d'"' -f4)
		[ -n "$QV" ] || QV="-"
	fi
	case "$GSPD" in ''|*[!0-9]*) GSPD=0 ;; esac
	case "$TLS_MS" in ''|*[!0-9]*) TLS_MS=0 ;; esac
	printf '%s' "{\"host\":\"$_PH\",\"ip\":\"$_PIP\",\"tls_ok\":$TLS_OK,\"tls_ms\":$TLS_MS,\"get_code\":$GCODE,\"get_bytes\":$GBYTES,\"get_spd\":$GSPD,\"quic\":\"$QV\",\"primary\":$_PRIMARY}"
}

# Enumerate rr1..rr6 of one suffix into "ip host" lines (fresh nslookup,
# distinct public IPs; private/reserved ranges excluded). Arg: suffix.
enumerate_pool() {
	_POOL=""
	for k in 1 2 3 4 5 6; do
		PH="rr$k---$1"
		PIP=$(nslookup "$PH" 2>/dev/null \
			| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
			| grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|198\.(1[89])\.|2[4-9][0-9]\.|0\.)' \
			| head -1)
		[ -n "$PIP" ] || continue
		case "$_POOL" in *"[$PIP]"*) continue ;; esac
		_POOL="$_POOL[$PIP]"
		printf '%s %s\n' "$PIP" "$PH"
	done
}

# ── Multipool mode (сеанс 183) ────────────────────────────────────────────────
if [ "$1" = "--pools" ]; then
	URL=""
	LIST=$(printf '%s' "${2:-}" | tr ',;' ' ')
	OUT=""
	SEP=""
	NPOOLS=0
	DEDUP=""
	for raw in $LIST; do
		[ -n "$raw" ] || continue
		SFX=$(printf '%s' "$raw" | sed -E 's#^https?://##; s/^rr[0-9]+---//' | cut -d'/' -f1)
		# normalize: bare sn-… gets the googlevideo.com tail; junk is skipped
		case "$SFX" in
			*[!.a-z0-9-]*|"") continue ;;
		esac
		case "$SFX" in
			*.googlevideo.com) : ;;
			sn-*) SFX="$SFX.googlevideo.com" ;;
			*) continue ;;
		esac
		# dedup AFTER normalization: the catalog feeds bare and full forms
		# from different sources (live conns vs persisted history) — without
		# this the cap-10 slot budget paid for duplicate measurements
		# (live fact: aj5goc-5x and 5goeen7y measured twice, 5go7yner and
		# q4flrnsk never reached)
		case "$DEDUP" in *"[$SFX]"*) continue ;; esac
		DEDUP="$DEDUP[$SFX]"
		[ "$NPOOLS" -lt 10 ] || break
		NPOOLS=$((NPOOLS + 1))
		POOL=$(enumerate_pool "$SFX")
		if [ -z "$(printf '%s' "$POOL" | tr -d '[:space:]')" ]; then
			OUT="$OUT$SEP{\"ok\":0,\"suffix\":\"$SFX\",\"error\":\"pool enumeration returned nothing\"}"
			SEP=","
			continue
		fi
		ROWS=/tmp/zapret_edges_mp.$$
		: > "$ROWS"
		printf '%s' "$POOL" | {
			RSEP=""
			while read -r PIP PH; do
				[ -n "$PIP" ] && [ -n "$PH" ] || continue
				# QUIC check only where the edge answered something (a black
				# /29 answers nothing anywhere — the probe is a fixed ~5 s tax)
				OUT_ROW=$(measure_row "$PH" "$PIP" 0)
				printf '%s%s' "$RSEP" "$OUT_ROW" >> "$ROWS"
				RSEP=","
			done
		}
		EROWS=$(cat "$ROWS" 2>/dev/null)
		NEDGE=$(grep -o '"host"' "$ROWS" 2>/dev/null | wc -l)
		[ -n "$NEDGE" ] || NEDGE=0
		rm -f "$ROWS" 2>/dev/null
		OUT="$OUT$SEP{\"ok\":1,\"suffix\":\"$SFX\",\"engine\":\"live\",\"edge_count\":$NEDGE,\"edges\":[$EROWS]}"
		SEP=","
	done
	echo "{\"ok\":1,\"engine\":\"live\",\"pools\":[$OUT]}"
	exit 0
fi

[ -z "$URL" ] && [ -s "$CACHE" ] && URL=$(grep -oE '"url": *"https://[^"]+' "$CACHE" 2>/dev/null | head -1 | cut -d'"' -f4)
[ -n "$URL" ] || emit_fail "no videoplayback URL (set $1 or have a fresh yt_stream.json)"

HOST=$(printf '%s' "$URL" | sed -E 's#^https://([^/]+).*#\1#')
case "$HOST" in
	*.googlevideo.com) : ;;
	*) emit_fail "URL host is not googlevideo: $HOST" ;;
esac
SUFFIX=$(printf '%s' "$HOST" | sed -E 's/^rr[0-9]*---//')

# enumerate pool members rr1..rr6 of the same suffix, distinct public IPs
POOL=$(enumerate_pool "$SUFFIX")

[ -n "$(printf '%s' "$POOL" | tr -d '[:space:]')" ] || emit_fail "pool enumeration returned nothing for $SUFFIX"

ROWS=/tmp/zapret_edges_rows.$$
: > "$ROWS"
printf '%s' "$POOL" | {
	while read -r PIP PH; do
		[ -n "$PIP" ] && [ -n "$PH" ] || continue
		PRIMARY=0
		[ "$PH" = "$HOST" ] && PRIMARY=1
		printf '%s%s' "$SEP" "$(measure_row "$PH" "$PIP" $PRIMARY)" >> "$ROWS"
		SEP=","
	done
}

# assemble (the pipe runs the loop in a subshell; the rows file carries data out)
# count OCCURRENCES, not lines: the rows print on ONE line (live fact of the
# first acceptance sweep: grep -c counted 1 for a 6-edge matrix)
NEDGE=$(grep -o '"host"' "$ROWS" 2>/dev/null | wc -l)
[ -n "$NEDGE" ] || NEDGE=0
echo "{\"ok\":1,\"suffix\":\"$SUFFIX\",\"engine\":\"live\",\"edge_count\":$NEDGE,\"edges\":[$(cat "$ROWS")]}"
rm -f "$ROWS" 2>/dev/null
