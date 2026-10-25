#!/bin/sh
# Isolated nfqws2 strategy tester.
#
# nfqws2 is a packet mangler (NFQUEUE), not a SOCKS proxy: queue ONLY the
# tester's own probe handshakes to a TEMP NFQUEUE running the candidate
# strategy, probe the TLS handshake with curl, and tear everything down via
# a trap — without disturbing the live homeproxy queue (qnum 200) or ANY
# other traffic.
#
# Probe isolation (user report: the auto-pick sweep killed live connections):
# the historical temp table hooked postrouting on the test IPs, which also
# caught the CORE's own flows to those IPs — unmarked direct-out dials AND
# zapret-mark (110) dials. Those handshakes were then mangled TWICE (test
# strategy + live strategy) or by a random test strategy alone, so live
# YouTube/Telegram/Discord/Speedtest connections kept breaking during every
# sweep pass. Now the probes run as a NON-ROOT user (daemon) and the temp
# queue matches `meta skuid` in the OUTPUT hook: locally generated packets
# only, and sing-box (root) never matches. When su is unavailable the
# fallback keeps the postrouting hook but matches EXACT-unmarked packets,
# which still protects the zapret-marked flows (the worst breakage).
#
# Usage:  zapret_test.sh [--baseline] [--deep] "<strategy opts>" [tag=ip tag=ip …]
# Output: a single JSON line:  {"ok":N,"total":M,"results":[{tag,label,host,ip,tls,ok,reason},…]}
#         with --deep each result also carries code/bytes/deep_ok (a content
#         fetch through the same temp queue) — «сайт открывается» is not the
#         verdict, the resource must load its media hosts too (user report:
#         a strategy can pass the TLS handshake and still stall the video).
#
# Pass signal = curl time_appconnect > 0 (the TLS handshake completed = the desync
# got the ClientHello past the DPI). HTTP status is irrelevant.
#
# --baseline (ч.70): run the SAME probes WITHOUT any desync (no nfqws2 on the
# temp queue — NFQUEUE bypass passes packets unchanged when nothing listens).
# Hosts that pass without a strategy are not DPI-blocked and cannot credit one.
#
# ч.86: probe results are collected by POLLING the r_<tag> files instead of
# `wait` — the wait-builtin wakeup is unreliable in some spawn contexts (ucode
# system(cmd, timeout) leaves the child's background-job SIGCHLD handling
# broken, so wait blocks until the watchdog fires, the trap then deleted the
# temp dir and the caller got garbage JSON: ip:""/reason:"fail"). Polling is
# signal-immune. The trap also no longer deletes $TMP — probe results must
# survive a watchdog teardown so the caller still gets REAL data.

BASELINE=0
DEEP=0
if [ "$1" = "--baseline" ]; then
	BASELINE=1
	shift
fi
if [ "$1" = "--deep" ]; then
	DEEP=1
	shift
fi

STRAT="$1"
IPS_ARG="$2"                   # optional pre-resolved "tag=ip tag=ip …"
QNUM=209                       # temp queue, distinct from the live 200
DMARK=0x40000000               # nfqws2 DESYNC_MARK (its reinjected fakes)
NFQWS=/opt/zapret2/nfq2/nfqws2
LUA="--lua-init=@/opt/zapret2/lua/zapret-lib.lua --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua --lua-init=@/opt/zapret2/lua/zapret-auto.lua"
TABLE=zapret_test
CMT=zapret_test                # comment tag on our output_redir bypass rules
TMP=/tmp/zapret_test.$$

# tag|label|host  — far/near spread (mirrors the ByeDPI tester)
HOSTS="yt|YouTube|redirector.googlevideo.com tg|Telegram|telegram.org dc|Discord|discord.com st|Speedtest|www.speedtest.net"

# --deep content probes (ч.109): a handshake passing ≠ the resource working.
# Each resource gets real fetches through the SAME temp queue — YouTube is
# checked on the page (a ~1MB content fetch), the thumbnail CDN (generate_204)
# and the video-stream edge (ANY HTTP answer proves the DPI let the host
# through; its root path legitimately answers 404). Telegram/Discord/Speedtest
# on their main pages.
# ч.116: the SUSTAINED-FLOW throughput probe (ytv) — the user's complaint is
# exactly what a handshake cannot see: TSPU lets the ClientHello through and
# then THROTTLES the flow («превью и видео грузятся вечность»). ytv fetches
# 24 real thumbnails of stable public videos over ONE keep-alive TLS flow to
# i.ytimg.com (the google-CDN class the complaint is about) and measures
# Σbytes/Σtime — a throttled flow fails the bar honestly. yts = the REAL
# video-stream download (a ranged 4 MB of a live videoplayback URL from
# yt_stream_probe.uc) when the upstream hands one out (often bot-gated —
# then the probe is honestly absent).
# id|url  (the yt edge reuses the yt handshake host/IP; id ytr = edge probe;
# id ytv = sustained-flow throughput; id yts = real video stream)
DEEP_PROBES=""
YTV_URLS=""
if [ "$DEEP" = "1" ]; then
	DEEP_PROBES="ytp|https://www.youtube.com/ yti|https://i.ytimg.com/generate_204 ytr|https://redirector.googlevideo.com/ ytv|BATCH tgp|https://web.telegram.org/ dcp|https://discord.com/ stp|https://www.speedtest.net/"
	if [ -f /etc/homeproxy/resources/yt_probe_ids.txt ]; then
		for vid in $(grep -vE '^\s*(#|$)' /etc/homeproxy/resources/yt_probe_ids.txt); do
			YTV_URLS="$YTV_URLS https://i.ytimg.com/vi/$vid/mqdefault.jpg https://i.ytimg.com/vi/$vid/hq720.jpg"
		done
	fi
	if [ -n "$YTV_URL" ]; then
		DEEP_PROBES="$DEEP_PROBES yts|$YTV_URL"
	fi
fi

NFQ_PID=""
WATCH_PID=""

cleanup() {
	# nfqws2 daemonizes (so $! is stale) and busybox has no pkill. Match nfqws2 by
	# process NAME (never the shell/grep itself), then kill only the one on our temp
	# qnum (sparing the live qnum=200 instance).
	for p in $(pgrep nfqws2 2>/dev/null); do
		tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "qnum=$QNUM" && kill "$p" 2>/dev/null
	done
	[ -n "$NFQ_PID" ] && kill "$NFQ_PID" 2>/dev/null
	nft delete table inet "$TABLE" 2>/dev/null
	# remove our surgical bypass rules from the LIVE output_redir chain (by comment)
	for hnd in $(nft -a list chain inet fw4 homeproxy_output_redir 2>/dev/null | grep "$CMT" | grep -oE 'handle [0-9]+' | grep -oE '[0-9]+'); do
		nft delete rule inet fw4 homeproxy_output_redir handle "$hnd" 2>/dev/null
	done
	[ -n "$WATCH_PID" ] && kill "$WATCH_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

fail() { echo "{\"ok\":0,\"total\":0,\"error\":\"$1\"}"; exit 0; }

[ -x "$NFQWS" ] || fail "zapret2 not installed"
command -v curl >/dev/null 2>&1 || fail "curl missing"
mkdir -p "$TMP" 2>/dev/null

# Watchdog: guarantee teardown within 50s even if curl/nslookup wedges, so the
# live firewall is never left modified (busybox has no `timeout` applet).
# 50 s (ч.116): the deep battery grew a 9 s stream download on top of the
# 25 s handshake poll — 35 s could tear down mid-deep and drop results.
# Redirect its fds to /dev/null: otherwise the backgrounded `sleep` keeps the
# caller's stdout pipe open and rpcd/popen blocks on read() for the full span.
( sleep 50; kill -TERM $$ 2>/dev/null ) >/dev/null 2>&1 &
WATCH_PID=$!

# 1. Test-host IPs — BEFORE touching the firewall, so a slow resolver never runs
#    while the redirect is modified. Prefer IPs passed in via "$2" (the fuzzer's
#    full sweep resolves ONCE up front via zapret_resolve.sh); fall back to
#    resolving here for a standalone call.
IPSET=""
if [ -n "$IPS_ARG" ]; then
	for kv in $IPS_ARG; do
		tag=${kv%%=*}; ip=${kv#*=}
		[ -n "$tag" ] && echo "$ip" > "$TMP/ip_$tag"
		[ -n "$ip" ] && IPSET="$IPSET$ip,"
	done
else
	for h in $HOSTS; do
		tag=${h%%|*}; rest=${h#*|}; label=${rest%%|*}; host=${rest#*|}
		ip=$(nslookup "$host" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '^127\.' | tail -1)
		echo "$ip" > "$TMP/ip_$tag"
		[ -n "$ip" ] && IPSET="$IPSET$ip,"
	done
fi
IPSET=$(echo "$IPSET" | sed 's/[[:space:]]//g; s/,$//')
[ -z "$IPSET" ] && fail "could not resolve any test host"

# Deep-mode resolution: every deep URL host must be pinned to a resolved IP AND
# its IP must join the temp-queue IPSET BEFORE the nft rules render — otherwise
# the deep fetch would ride the LIVE path and measure the wrong thing.
if [ "$DEEP" = "1" ]; then
	for dp in $DEEP_PROBES; do
		did=${dp%%|*}; durl=${dp#*|}
		dhost=$(printf '%s' "$durl" | sed -E 's#^https?://([^/]+).*#\1#')
		if [ "$did" = "ytr" ]; then
			cp "$TMP/ip_yt" "$TMP/dip_$did" 2>/dev/null
		elif [ "$did" = "ytv" ]; then
			# the sustained-flow batch rides the SAME host+IP as the yti probe
			cp "$TMP/dip_yti" "$TMP/dip_$did" 2>/dev/null
			echo "i.ytimg.com" > "$TMP/dhost_$did"
		else
			dip=$(nslookup "$dhost" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '^127\.' | tail -1)
			echo "$dip" > "$TMP/dip_$did"
			echo "$dhost" > "$TMP/dhost_$did"
		fi
		dep=$(cat "$TMP/dip_$did" 2>/dev/null)
		[ -n "$dep" ] && case ",$IPSET," in *",$dep,"*) ;; *) IPSET="$IPSET,$dep";; esac
	done
fi

# Probe identity: run the curls as the non-root `daemon` user (uid resolved
# live) and queue by meta skuid — sing-box (root) can never match. Fallback
# when su is unusable: keep root probes, but match EXACT-unmarked packets so
# the zapret-mark (110) flows are still protected from the test instance.
PROBE_UID=""
if command -v su >/dev/null 2>&1; then
	PROBE_UID=$(id -u daemon 2>/dev/null)
	case "$PROBE_UID" in ''|*[!0-9]*) PROBE_UID="" ;; esac
	[ -n "$PROBE_UID" ] && ! su -s /bin/sh daemon -c true >/dev/null 2>&1 && PROBE_UID=""
fi

# 2. Surgically send ONLY the test IPs' TCP/443 direct (return from output_redir,
#    so router-origin curl egresses direct where our temp queue can catch it).
#    Tagged with a comment for clean teardown.
if nft list chain inet fw4 homeproxy_output_redir >/dev/null 2>&1; then
	nft insert rule inet fw4 homeproxy_output_redir ip daddr "{ $IPSET }" tcp dport 443 counter return comment "\"$CMT\"" 2>/dev/null
fi

# 3. Temp table: queue ONLY the probe handshakes to QNUM (exclude nfqws's own
#    reinjected DMARK fakes so they aren't re-queued, and notrack those fakes).
nft add table inet "$TABLE" 2>/dev/null
if [ -n "$PROBE_UID" ]; then
	nft add chain inet "$TABLE" out "{ type filter hook output priority -150; policy accept; }" 2>/dev/null
	nft add rule  inet "$TABLE" out "meta skuid $PROBE_UID meta mark and $DMARK == 0 ip daddr { $IPSET } tcp dport 443 ct original packets 1-12 counter queue num $QNUM bypass" 2>/dev/null
	nft add rule  inet "$TABLE" out "meta mark and $DMARK != 0 notrack" 2>/dev/null
else
	nft add chain inet "$TABLE" pre "{ type filter hook postrouting priority mangle; policy accept; }" 2>/dev/null
	nft add rule  inet "$TABLE" pre "meta mark 0 ip daddr { $IPSET } tcp dport 443 ct original packets 1-12 counter queue num $QNUM bypass" 2>/dev/null
	nft add chain inet "$TABLE" out "{ type filter hook output priority -150; policy accept; }" 2>/dev/null
	nft add rule  inet "$TABLE" out "meta mark and $DMARK != 0 notrack" 2>/dev/null
fi

# 4. Start the candidate nfqws2 on the temp queue (skipped in --baseline mode:
#    no queue listener = packets pass unchanged = pure baseline).
if [ "$BASELINE" != "1" ]; then
	$NFQWS --qnum=$QNUM --user=daemon --fwmark=$DMARK $LUA $STRAT >/dev/null 2>&1 &
	NFQ_PID=$!
	sleep 1
	pgrep -f "qnum=$QNUM" >/dev/null 2>&1 || fail "nfqws2 did not start - check strategy"
fi

# 5. Probe every host in parallel: curl forced to the resolved IP, write
#    "time_appconnect curl_exit". Collect by POLLING the r_<tag> files
#    (signal-immune; each curl is capped by --max-time 10, so 25s is a ceiling).
#    In skuid mode each probe runs as `daemon` (the queue rule matches that
#    uid only); the temp dir must then accept the daemon's result files.
[ -n "$PROBE_UID" ] && chmod 777 "$TMP" 2>/dev/null
for h in $HOSTS; do
	tag=${h%%|*}; rest=${h#*|}; label=${rest%%|*}; host=${rest#*|}
	ip=$(cat "$TMP/ip_$tag" 2>/dev/null)
	if [ -z "$ip" ]; then echo "0 6" > "$TMP/r_$tag"; continue; fi
	if [ -n "$PROBE_UID" ]; then
		# tag/host/ip are tester-owned constants (fixed labels, resolved
		# numeric IPs, /tmp path with PID) — safe to inline in the body.
		su -s /bin/sh daemon -c "out=\$(curl -s --resolve '${host}:443:${ip}' -o /dev/null -w '%{time_appconnect}' --connect-timeout 4 --max-time 10 'https://${host}' 2>/dev/null); echo \"\$out \$?\" > '${TMP}/r_${tag}'" >/dev/null 2>&1 &
	else
		( out=$(curl -s --resolve "${host}:443:${ip}" -o /dev/null -w '%{time_appconnect}' --connect-timeout 4 --max-time 10 "https://${host}" 2>/dev/null); echo "$out $?" > "$TMP/r_$tag" ) >/dev/null 2>&1 &
	fi
done
n=0
while [ "$n" -lt 25 ]; do
	all=1
	for h in $HOSTS; do
		tag=${h%%|*}
		[ -s "$TMP/r_$tag" ] || all=0
	done
	[ "$all" = 1 ] && break
	sleep 1
	n=$((n + 1))
done

# 5b. Deep content fetches (--deep): run through the SAME temp queue (the
# fetch IPs joined the IPSET above, each URL host pinned with --resolve).
# Pass = an HTTP answer within the window (2xx–399) AND a body except 204 —
# a DPI-stalled media host fails here even when its TLS handshake passed.
DJSON_ALL=""
if [ "$DEEP" = "1" ]; then
	[ -n "$PROBE_UID" ] && chmod 777 "$TMP" 2>/dev/null
	for dp in $DEEP_PROBES; do
		did=${dp%%|*}; durl=${dp#*|}
		dhost=$(cat "$TMP/dhost_$did" 2>/dev/null)
		[ -z "$dhost" ] && dhost=$(printf '%s' "$durl" | sed -E 's#^https?://([^/]+).*#\1#')
		dip=$(cat "$TMP/dip_$did" 2>/dev/null)
		if [ -z "$dip" ]; then echo "000 0 0 0 6" > "$TMP/d_$did"; continue; fi
		# ч.116: the stream probe downloads a ranged 4 MB of the REAL video —
		# the speed_download field is the honest verdict metric.
		DRANGE=""
		[ "$did" = "yts" ] && DRANGE="-r 0-4194303"
		if [ "$did" = "ytv" ]; then
			# SUSTAINED-FLOW throughput: 24 real thumbnails over ONE keep-alive
			# flow (--max-time caps the WHOLE run; curl exits 28 on a throttled
			# link — the completed transfers still report). Σbytes/Σtime = the
			# honest per-flow bytes/s; ≥8 successful transfers = code 200.
			# One -o per URL: with a single -o curl discards only the FIRST
			# body and dumps the rest to stdout (caught live ч.116).
			CURL_ARGS=""
			for yu in $YTV_URLS; do
				CURL_ARGS="$CURL_ARGS -o /dev/null $yu"
			done
			if [ -n "$PROBE_UID" ]; then
				su -s /bin/sh daemon -c "out=\$(curl -sL --max-redirs 2 --resolve '${dhost}:443:${dip}' -w '%{http_code} %{time_total} %{size_download}\n' --connect-timeout 4 --max-time 9 -k ${CURL_ARGS} 2>/dev/null | awk '{s+=\$3; t+=\$2; o++; if (\$1==200 || \$1==206) n++;} END {if (t<0.1) t=0.1; code=0; if (n>=8) code=200; print code, t, s, int(s/t), o}'); echo \"\$out\" > '${TMP}/d_${did}'" >/dev/null 2>&1 &
			else
				( out=$(curl -sL --max-redirs 2 --resolve "${dhost}:443:${dip}" -w '%{http_code} %{time_total} %{size_download}\n' --connect-timeout 4 --max-time 9 -k ${CURL_ARGS} 2>/dev/null | awk '{s+=$3; t+=$2; o++; if ($1==200 || $1==206) n++;} END {if (t<0.1) t=0.1; code=0; if (n>=8) code=200; print code, t, s, int(s/t), o}'); echo "$out" > "$TMP/d_ytv" ) >/dev/null 2>&1 &
			fi
			continue
		fi
		if [ -n "$PROBE_UID" ]; then
			su -s /bin/sh daemon -c "out=\$(curl -sL $DRANGE --max-redirs 3 --resolve '${dhost}:443:${dip}' -o /dev/null -w '%{http_code} %{time_total} %{size_download} %{speed_download}' --connect-timeout 4 --max-time 9 -k '${durl}' 2>/dev/null); echo \"\$out \$?\" > '${TMP}/d_${did}'" >/dev/null 2>&1 &
		else
			( out=$(curl -sL $DRANGE --max-redirs 3 --resolve "${dhost}:443:${dip}" -o /dev/null -w '%{http_code} %{time_total} %{size_download} %{speed_download}' --connect-timeout 4 --max-time 9 -k "$durl" 2>/dev/null); echo "$out $?" > "$TMP/d_$did" ) >/dev/null 2>&1 &
		fi
	done
	dn=0
	while [ "$dn" -lt 14 ]; do
		all=1
		for dp in $DEEP_PROBES; do
			did=${dp%%|*}
			[ -s "$TMP/d_$did" ] || all=0
		done
		[ "$all" = 1 ] && break
		sleep 1
		dn=$((dn + 1))
	done
	# attach the deep results to the owning main tag: yt ← ytp,yti,ytr,ytv,yts; tg ← tgp; dc ← dcp; st ← stp
	for h in $HOSTS; do
		tag=${h%%|*}
		case "$tag" in
			yt) OWNER="ytp yti ytr ytv yts" ;;
			tg) OWNER="tgp" ;;
			dc) OWNER="dcp" ;;
			st) OWNER="stp" ;;
		esac
		DJSON=""
		DOK=0; DTOT=0
		for did in $OWNER; do
			raw=$(cat "$TMP/d_$did" 2>/dev/null)
			# An ABSENT probe (e.g. no real-stream URL this sweep) is not a
			# failure — emitting empty fields produced INVALID JSON (caught
			# live ч.116: "bytes":, broke the fuzzer's json() parse) and the
			# whole deep verdict was lost. Absent = skipped entirely.
			[ -n "$raw" ] || continue
			dcode=$(printf '%s' "$raw" | awk '{print $1}')
			dsec=$(printf '%s' "$raw" | awk '{print $2}')
			dbytes=$(printf '%s' "$raw" | awk '{print $3}')
			dspeed=$(printf '%s' "$raw" | awk '{print $4}')
			# curl prints speed_download as a double ("9563726.000") — busybox
			# test needs an integer: truncate at the decimal point.
			dspeed=${dspeed%%.*}
			drc=$(printf '%s' "$raw" | awk '{print $5}')
			DTOT=$((DTOT+1))
			case "$dcode" in ''|000|0) dok=0;; *)
			dok=1
			case "$dcode" in 2*|3*) : ;; *) dok=0 ;; esac
			# edge probe: ANY HTTP answer proves the DPI let the host through
			case "$did" in ytr) [ "$dcode" != "000" ] && dok=1 ;; esac
			# ч.116 ytv (sustained-flow batch): ≥8 real thumbnails fetched AND
			# ≥128 KB/s over ONE keep-alive flow AND ≥0.4 MB total — the
			# «превью грузятся вечность» case fails here honestly.
			case "$did" in ytv)
				case "$dcode" in 200) : ;; *) dok=0 ;; esac
				[ "$dspeed" -ge 131072 ] 2>/dev/null || dok=0
				[ "$dbytes" -ge 409600 ] 2>/dev/null || dok=0
			;; esac
			# ч.116 yts (real video stream): 2xx AND ≥128 KB/s AND ≥0.5 MB.
			case "$did" in yts)
				case "$dcode" in 200|206) : ;; *) dok=0 ;; esac
				[ "$dspeed" -ge 131072 ] 2>/dev/null || dok=0
				[ "$dbytes" -ge 524288 ] 2>/dev/null || dok=0
			;; esac
			[ "$dcode" = "204" ] || [ "$dbytes" -gt 0 ] 2>/dev/null || dok=0
			;; esac
			[ "$dok" = 1 ] && DOK=$((DOK+1))
			[ -n "$DJSON" ] && DJSON="$DJSON,"
			DJSON="$DJSON{\"id\":\"$did\",\"code\":\"$dcode\",\"sec\":\"$dsec\",\"bytes\":$dbytes,\"speed\":$dspeed,\"ok\":$dok}"
		done
		eval "D_${tag}_OK=$DOK"
		eval "D_${tag}_TOT=$DTOT"
		eval "D_${tag}_JSON='$DJSON'"
		DJSON_ALL="$DJSON_ALL $tag:$DOK/$DTOT"
	done
fi

# 6. Build JSON (the temp dir survives watchdog teardowns now).
JSON=""; OKC=0; TOT=0; ALLOK=0; ALLTOT=0
for h in $HOSTS; do
	tag=${h%%|*}; rest=${h#*|}; label=${rest%%|*}; host=${rest#*|}
	ip=$(cat "$TMP/ip_$tag" 2>/dev/null)
	raw=$(cat "$TMP/r_$tag" 2>/dev/null); tls=${raw%% *}; rc=${raw##* }
	TOT=$((TOT+1))
	ok=0; case "$tls" in 0|0.000000|"") ok=0;; *) ok=1;; esac
	[ "$ok" = 1 ] && OKC=$((OKC+1))
	reason=""
	if [ "$ok" = 0 ]; then
		case "$rc" in 6) reason=dns;; 7) reason=refused;; 28) reason=timeout;; 35|51|53|56|58|59|60) reason=tls;; *) reason=fail;; esac
	fi
	DEEPJSON=""
	if [ "$DEEP" = "1" ]; then
		eval "dok=\$D_${tag}_OK"; eval "dtot=\$D_${tag}_TOT"; eval "dj=\$D_${tag}_JSON"
		ALLOK=$((ALLOK+dok)); ALLTOT=$((ALLTOT+dtot))
		DEEPJSON=",\"deep_ok\":$dok,\"deep_total\":$dtot,\"deep\":[$dj]"
	fi
	[ -n "$JSON" ] && JSON="$JSON,"
	JSON="$JSON{\"tag\":\"$tag\",\"label\":\"$label\",\"host\":\"$host\",\"ip\":\"$ip\",\"tls\":\"$tls\",\"ok\":$ok,\"reason\":\"$reason\"$DEEPJSON}"
done

if [ "$DEEP" = "1" ]; then
	echo "{\"ok\":$OKC,\"total\":$TOT,\"deep_ok\":$ALLOK,\"deep_total\":$ALLTOT,\"results\":[$JSON]}"
else
	echo "{\"ok\":$OKC,\"total\":$TOT,\"results\":[$JSON]}"
fi
rm -rf "$TMP" 2>/dev/null
