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

# ── Direct-contour mode (сеанс 187, REPORT_s187_yt_ab_design.md §3) ─────────
# --contour temp|"temp-bare" "suffix list" — the SAME pool catalog measured
# through the TEMP contour = honest RU-direct (bypass-return in
# homeproxy_output_redir + OWN nfqueue + nfqws2 carrying the APPLIED
# ravnex.config.zapret_cmd_opts): «что увидит юзер, если youtube идёт мимо
# узла под текущим движком». temp-bare = no strategy listener (bare direct
# reference; the bypassed packets pass the empty queue unchanged). Rows carry
# "contour":"direct"; the QUIC sub-check is skipped (its UDP path cannot ride
# the TCP-only rig — reporting it as "-" keeps the field honest). No lab_lock
# here: the parent fuzz already owns it; the resmgr queue IS the guard.
if [ "$1" = "--contour" ]; then
	CONTOUR="$2"
	shift 2
	case "$CONTOUR" in
		temp|temp-bare) : ;;
		*) emit_fail "unknown contour: $CONTOUR" ;;
	esac
	command -v nft >/dev/null 2>&1 || emit_fail "nft missing"
	nft list chain inet fw4 homeproxy_output_redir >/dev/null 2>&1 || emit_fail "output_redir chain missing"
	QNUM=""
	NFQ_PID=""
	cleanup_contour() {
		for hnd in $(nft -a list chain inet fw4 homeproxy_output_redir 2>/dev/null | grep "edgec$$" | grep -oE 'handle [0-9]+' | grep -oE '[0-9]+'); do
			nft delete rule inet fw4 homeproxy_output_redir handle "$hnd" 2>/dev/null
		done
		nft delete table inet edge_ctest 2>/dev/null
		if [ -n "$NFQ_PID" ]; then
			ucode /etc/ravnex/scripts/pmgr_cli.uc kill_args "$NFQWS2BIN" "--qnum=$QNUM" >/dev/null 2>&1
			kill "$NFQ_PID" 2>/dev/null
		fi
		if [ -n "$QNUM" ]; then
			ucode -e "import {release} from '/etc/ravnex/scripts/test_resmgr.uc'; release($QNUM, 'edges_temp');" >/dev/null 2>&1
		fi
	}
	trap cleanup_contour EXIT INT TERM

	QOUT=$(ucode -e 'import {acquire} from "/etc/ravnex/scripts/test_resmgr.uc"; print(sprintf("%.J", acquire("edges_temp")));' 2>/dev/null)
	QNUM=$(printf '%s' "$QOUT" | sed -n 's/.*"qnum":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
	case "$QNUM" in ''|*[!0-9]*) emit_fail "no free test queue (209-212)" ;; esac

	nft add table inet edge_ctest 2>/dev/null
	nft add chain inet edge_ctest out '{ type filter hook output priority -150; policy accept; }' 2>/dev/null

	STRAT_CONT=0
	NFQWS2BIN=/opt/zapret2/nfq2/nfqws2
	if [ "$CONTOUR" = "temp" ]; then
		STRAT=$(uci -q get ravnex.config.zapret_cmd_opts 2>/dev/null)
		[ -n "$(printf '%s' "$STRAT" | tr -d '[:space:]')" ] || emit_fail "zapret_cmd_opts empty - nothing to mirror"
		[ -x "$NFQWS2BIN" ] || emit_fail "nfqws2 not installed"
		"$NFQWS2BIN" --qnum="$QNUM" --user=daemon --fwmark=0x40000000 --lua-init=@/opt/zapret2/lua/zapret-lib.lua --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua --lua-init=@/opt/zapret2/lua/zapret-auto.lua $STRAT >/dev/null 2>&1 &
		NFQ_PID=$!
		sleep 2
		[ -n "$(ps w 2>/dev/null | grep -- "--qnum=$QNUM" | grep -v grep)" ] || emit_fail "nfqws candidate died with applied args"
		STRAT_CONT=1
	fi

	PUID=$(id -u daemon 2>/dev/null)
	case "$PUID" in ''|*[!0-9]*) PUID="" ;; esac
	ct_stage() { # $1=IPS
		if [ -n "$PUID" ]; then
			nft add rule inet edge_ctest out "meta skuid $PUID meta mark and 0x40000000 == 0 ip daddr { $1 } tcp dport 443 ct original packets 1-12 counter queue num $QNUM bypass" 2>/dev/null
		fi
		nft add rule inet edge_ctest out "meta skuid 0 meta mark and 0x40000000 == 0 ip daddr { $1 } tcp dport 443 ct original packets 1-12 counter queue num $QNUM bypass" 2>/dev/null
		nft add rule inet edge_ctest out "meta mark and 0x40000000 != 0 notrack" 2>/dev/null
		nft insert rule inet fw4 homeproxy_output_redir ip daddr "{ $1 }" tcp dport 443 counter return comment "\"edgec$$\"" 2>/dev/null
	}
	ct_unstage() {
		for hnd in $(nft -a list chain inet fw4 homeproxy_output_redir 2>/dev/null | grep "edgec$$" | grep -oE 'handle [0-9]+' | grep -oE '[0-9]+'); do
			nft delete rule inet fw4 homeproxy_output_redir handle "$hnd" 2>/dev/null
		done
		nft flush chain inet edge_ctest out 2>/dev/null
	}

	COUT=""
	CSEP=""
	CN=0
	CDEDUP=""
	LIST=$(printf '%s' "${1:-}" | tr ',;' ' ')
	for craw in $LIST; do
		[ -n "$craw" ] || continue
		CSFX=$(printf '%s' "$craw" | sed -E 's#^https?://##; s/^rr[0-9]+---//' | cut -d'/' -f1)
		case "$CSFX" in
			*[!.a-z0-9-]*|"") continue ;;
		esac
		case "$CSFX" in
			*.googlevideo.com) : ;;
			sn-*) CSFX="$CSFX.googlevideo.com" ;;
			*) continue ;;
		esac
		case "$CDEDUP" in *"[$CSFX]"*) continue ;; esac
		CDEDUP="$CDEDUP[$CSFX]"
		[ "$CN" -lt 10 ] || break
		CN=$((CN + 1))
		CPOOL=$(enumerate_pool "$CSFX")
		if [ -z "$(printf '%s' "$CPOOL" | tr -d '[:space:]')" ]; then
			COUT="$COUT$CSEP{\"ok\":0,\"suffix\":\"$CSFX\",\"error\":\"pool enumeration returned nothing\",\"contour\":\"direct\"}"
			CSEP=","
			continue
		fi
		CROWS=/tmp/zapret_edges_ct.$$
		: > "$CROWS"
		printf '%s' "$CPOOL" | {
			_CRSEP=""
			while read -r CPIP CPH; do
				[ -n "$CPIP" ] && [ -n "$CPH" ] || continue
				CROW=$(measure_row "$CPH" "$CPIP" 0 0)
				CROW=${CROW%\}}
				printf '%s%s,\"contour\":\"direct\"}' "$_CRSEP" "$CROW" >> "$CROWS"
				_CRSEP=","
			done
		}
		_EROWS=$(cat "$CROWS" 2>/dev/null)
		_EN=$(grep -o '"host"' "$CROWS" 2>/dev/null | wc -l)
		[ -n "$_EN" ] || _EN=0
		rm -f "$CROWS" 2>/dev/null
		COUT="$COUT$CSEP{\"ok\":1,\"suffix\":\"$CSFX\",\"edge_count\":$_EN,\"contour\":\"direct\",\"edges\":[$_EROWS]}"
		CSEP=","
	done
	echo "{\"ok\":1,\"engine\":\"temp\",\"contour\":\"direct\",\"strategy\":$STRAT_CONT,\"pools\":[$COUT]}"
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
