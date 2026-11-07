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
# fallback keeps the OUTPUT hook but matches root-owned unmarked packets
# (meta skuid 0) — the probes are root curls there, so they still match,
# while FORWARDED LAN traffic never traverses the OUTPUT hook at all: the
# user's devices can no longer be mangled by a test strategy (the historical
# fallback queued the postrouting path — every unmarked LAN flow to the test
# IPs got the random candidate applied). Router-origin root dials to the few
# test IPs remain the only exposed class, for the ~20 s of one pass.
#
# --validate: ARGUMENT-ONLY check (audit of the "zapret dead after apply"
# class): spawn the candidate nfqws2 on its OWN resmgr queue for ~2 s — no
# firewall, no probes, no live traffic — and report whether the binary
# survives the args. The apply paths run this BEFORE writing UCI: an invalid
# strategy used to crashloop nfqws2 through the procd retry budget
# (respawn 3600 1 5) and leave the engine dead.
#
# Usage:  zapret_test.sh [--baseline] [--deep] [--validate] "<strategy opts>" [tag=ip tag=ip …]
#         zapret_test.sh --quic "<strategy opts>" "tag=ip …"   (UDP/443 contour)
# Output: a single JSON line:  {"ok":N,"total":M,"results":[{tag,label,host,ip,code,tls,redirect,rc,ok,reason},…]}
#         with --deep each result also carries deep_ok/deep items with the
#         UNIFIED probe record (audit 82): {id,code,sec,bytes,speed,rc,ttfb,
#         ok,app_state,kind,geo_refused,waf} — app_state/kind/geo/waf come
#         from diag_core.classify_path on the SAVED body (one classification
#         implementation for the whole project, Ф6.1); a bare curl and a
#         browser-like fingerprint profile (audit 90) are measured separately
#         (ids with the "f" suffix: ytpf/tgpf/dcpf/stpf — a DIFFERENT verdict
#         between the two profiles is client filtering / WAF, not DPI).
#         --quic runs the UDP/443 contour: the candidate strategy (its UDP
#         profile) on the temp queue + a REAL QUIC probe (probe_pool
#         -quic-check) as the daemon user → {"ok":1,"quic":"vn|icmp|silence"}.
#         A real HTTP/3 handshake is NOT possible on this hardware (§2.5:
#         quic-go does not build on mipsle) — VN-level A/B is the honest
#         ceiling, everything above stays unprobed.
#
# Pass signal (audit 82, hardened): TLS handshake completed (time_appconnect
# > 0) AND curl exit 0 — «handshake прошёл, поток порван посередине»
# (rc != 0 при tls > 0) больше НЕ считается успехом, это отдельная причина
# flow_reset; HTTP-код и redirect_url сохраняются в каждой пробе.
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
QUIC=0
VALIDATE=0
# Ф6.4: order-insensitive flag parsing — the old two `if`s made
# "--deep --baseline" silently treat "--baseline" as the STRATEGY args.
while [ $# -gt 0 ]; do
	case "$1" in
		--baseline) BASELINE=1 ;;
		--deep) DEEP=1 ;;
		--quic) QUIC=1 ;;
		--validate) VALIDATE=1 ;;
		*) break ;;
	esac
	shift
done

STRAT="$1"
IPS_ARG="$2"                   # optional pre-resolved "tag=ip tag=ip …"
# Ф6.4 Test Resource Manager (audit 80): the queue belongs to ONE task —
# callers acquire a qnum from the pool (test_resmgr.uc) and hand it over in
# TEST_QNUM; a bare call defaults to 209. The production queue is refused:
# a tester on the live queue would mangle REAL traffic.
QNUM="${TEST_QNUM:-209}"
case "$QNUM" in ''|*[!0-9]*) QNUM=209 ;; esac
PROD_QNUM=$(uci -q get homeproxy.config.zapret_qnum 2>/dev/null)
[ -n "$PROD_QNUM" ] || PROD_QNUM=200
if [ "$QNUM" = "$PROD_QNUM" ]; then
	echo '{"ok":0,"total":0,"error":"TEST_QNUM equals the production queue - refused"}'
	exit 0
fi
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
# id ytv = sustained-flow throughput; id yts = real video stream;
# ids with the "f" suffix = the SAME page probe under a browser-like
# fingerprint profile (audit 90) — bare-curl vs browser verdicts differing
# is client filtering / WAF, not DPI; bodies are saved for diag_core)
DEEP_PROBES=""
YTV_URLS=""
if [ "$DEEP" = "1" ]; then
	DEEP_PROBES="ytp|https://www.youtube.com/ yti|https://i.ytimg.com/generate_204 ytr|https://redirector.googlevideo.com/ ytv|BATCH tgp|https://web.telegram.org/ dcp|https://discord.com/ stp|https://www.speedtest.net/ ytpf|https://www.youtube.com/ tgpf|https://web.telegram.org/ dcpf|https://discord.com/ stpf|https://www.speedtest.net/"
	if [ -f /etc/homeproxy/resources/yt_probe_ids.txt ]; then
		# Ф6.4: cap the batch at 12 URLs (6 videos × 2 thumbs) — the ≥8-pass
		# bar stays reachable while the WORST-CASE window (every fetch timing
		# out at the connect cap) stays bounded instead of 24 × connect-timeout.
		for vid in $(grep -vE '^\s*(#|$)' /etc/homeproxy/resources/yt_probe_ids.txt | head -n 6); do
			YTV_URLS="$YTV_URLS https://i.ytimg.com/vi/$vid/mqdefault.jpg https://i.ytimg.com/vi/$vid/hq720.jpg"
		done
	fi
	if [ -n "$YTV_URL" ]; then
		DEEP_PROBES="$DEEP_PROBES yts|$YTV_URL"
		# Ф6.4 (audit 85 + the user's live report 2026-11-04): videos live on
		# DIFFERENT googlevideo edges — the real stream is measured on the
		# SECOND resolved edge too (yts2); one edge lied before.
		DEEP_PROBES="$DEEP_PROBES yts2|$YTV_URL"
	fi
	# Browser-like fingerprint probe (audit 90): the stock curl fingerprint is
	# NOT a browser's — a strategy/WAF can pass the bare probe and challenge
	# the browser-shaped one (or vice versa). One shared script, su-safe.
	# (mkdir first: this block runs BEFORE the shared mkdir below.)
	mkdir -p "$TMP" 2>/dev/null
	cat > "$TMP/fp_flow.sh" <<'FPFLOW'
#!/bin/sh
# browser-like fingerprint profile probe → "code secs bytes speed ttfb rc"
# (Ф6.4: the 6th unified field — ttfb rides along like the content probes)
pin="$1"; url="$2"; body="$3"
curl -sL --max-redirs 3 --resolve "$pin" \
	-A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' \
	-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
	-H 'Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7' \
	-H 'Upgrade-Insecure-Requests: 1' \
	--compressed -o "$body" \
	-w '%{http_code} %{time_total} %{size_download} %{speed_download} %{time_starttransfer}' \
	--connect-timeout 4 --max-time 9 -k "$url" 2>/dev/null
echo " $?"
FPFLOW
	chmod 755 "$TMP/fp_flow.sh" 2>/dev/null
fi

NFQ_PID=""
WATCH_PID=""
# --validate owns a resmgr queue of its own; the EXIT trap releases it.
VREL_TASK=""
VREL_QNUM=""

cleanup() {
	# nfqws2 daemonizes (so $! is stale) and busybox has no pkill. Ф1.4b: kill
	# through the Process Manager CLI — the exact binary whose --qnum element
	# equals OUR temp queue, (pid, starttime) verified per signal (the old
	# pgrep+grep loop matched substrings and could signal a reused PID; the
	# live qnum=200 instance is never touched).
	ucode /etc/homeproxy/scripts/pmgr_cli.uc kill_args "$NFQWS" "--qnum=$QNUM" >/dev/null 2>&1
	[ -n "$NFQ_PID" ] && kill "$NFQ_PID" 2>/dev/null
	nft delete table inet "$TABLE" 2>/dev/null
	# remove our surgical bypass rules from the LIVE output_redir chain (by comment)
	for hnd in $(nft -a list chain inet fw4 homeproxy_output_redir 2>/dev/null | grep "$CMT" | grep -oE 'handle [0-9]+' | grep -oE '[0-9]+'); do
		nft delete rule inet fw4 homeproxy_output_redir handle "$hnd" 2>/dev/null
	done
	[ -n "$WATCH_PID" ] && kill "$WATCH_PID" 2>/dev/null
	# --validate acquired its queue INSIDE the script — release it here, so
	# even a mid-run teardown never leaks it until the TTL.
	if [ -n "$VREL_TASK" ]; then
		ucode -e "import {release} from '/etc/homeproxy/scripts/test_resmgr.uc'; release($VREL_QNUM, '$VREL_TASK');" >/dev/null 2>&1
	fi
}
trap cleanup EXIT INT TERM

fail() { echo "{\"ok\":0,\"total\":0,\"error\":\"$1\"}"; exit 0; }

[ -x "$NFQWS" ] || fail "zapret2 not installed"
command -v curl >/dev/null 2>&1 || fail "curl missing"
mkdir -p "$TMP" 2>/dev/null

# ── --validate: argument-only spawn check (no firewall, no probes) ───────
# The candidate nfqws2 gets its OWN resmgr queue and must survive 2 s with
# the given args. Anything invalid (unknown --lua-desync method/arg, garbage
# flags) dies here — honestly reported — instead of crashlooping the live
# engine through the procd retry budget after an apply.
if [ "$VALIDATE" = "1" ]; then
	[ -n "$(printf '%s' "$STRAT" | tr -d '[:space:]')" ] || fail "validate needs a strategy"
	VQ=$(ucode -e 'import {acquire} from "/etc/homeproxy/scripts/test_resmgr.uc"; print(sprintf("%.J", acquire("validate")));' 2>/dev/null | sed -n 's/.*"qnum":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
	case "$VQ" in ''|*[!0-9]*)
		fail "no free test queue (209-212) - another lab task is running" ;;
	esac
	VREL_TASK="validate"
	VREL_QNUM="$VQ"
	# The EXIT-trap cleanup kills by --qnum=$QNUM — point it at the owned queue.
	QNUM="$VQ"
	$NFQWS --qnum="$VQ" --user=daemon --fwmark=$DMARK $LUA $STRAT >/dev/null 2>&1 &
	NFQ_PID=$!
	sleep 2
	# Ф1.4b identity liveness (exact exe + the --qnum element), not a substring.
	if ucode /etc/homeproxy/scripts/pmgr_cli.uc find "$NFQWS" "--qnum=$VQ" >/dev/null 2>&1; then
		echo '{"ok":1,"validate":"alive"}'
	else
		echo '{"ok":0,"validate":"dead","error":"nfqws2 rejected the strategy (did not survive the spawn)"}'
	fi
	exit 0
fi

# Watchdog: guarantee teardown within 100s even if curl/nslookup wedges, so the
# live firewall is never left modified (busybox has no `timeout` applet).
# 100 s (ч.129): the deep battery's ytv probe now runs THREE windows + the
# fresh-connection START phase (~38 s worst case) on top of the 25 s handshake
# poll and the 45 s deep collection — 70 s could tear down mid-deep and drop
# results (the live ч.129 fact: deep_count 4 of 7 selected). Redirect its fds
# to /dev/null: otherwise the backgrounded `sleep` keeps the caller's stdout
# pipe open and rpcd/popen blocks on read().
( sleep 100; kill -TERM $$ 2>/dev/null ) >/dev/null 2>&1 &
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
	elif [ "$did" = "yts2" ]; then
		# Ф6.4: the SECOND real-stream edge — a DIFFERENT public A of the same
		# host (the user's live report: videos live on different edges; one
		# edge lied). Falls back to the yts IP when the resolver has one A.
		nslookup "redirector.googlevideo.com" 2>/dev/null \
			| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
			| grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|0\.)' \
			| sort -u > "$TMP/yt2_ips"
		nyts=$(wc -l < "$TMP/yt2_ips" 2>/dev/null)
		if [ "$nyts" -ge 2 ]; then
			sed -n '2p' "$TMP/yt2_ips" > "$TMP/dip_$did"
		else
			cp "$TMP/dip_yts" "$TMP/dip_$did" 2>/dev/null
		fi
		echo "redirector.googlevideo.com" > "$TMP/dhost_$did"
	elif [ "${did%f}" != "$did" ]; then
		# Ф6.4 fingerprint variant: the SAME page under the browser-like
		# profile — the base id's resolution is REUSED (no second DNS hit).
		base=${did%f}
		cp "$TMP/dip_$base" "$TMP/dip_$did" 2>/dev/null
		dh=$(cat "$TMP/dhost_$base" 2>/dev/null)
		[ -n "$dh" ] && echo "$dh" > "$TMP/dhost_$did"
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
# when su is unusable: keep root probes, but the queue rule stays in the
# OUTPUT hook and matches ROOT-owned unmarked packets (meta skuid 0) — the
# probes are root curls there, so they still match, while FORWARDED LAN
# traffic never traverses OUTPUT: user devices can no longer be mangled by
# the test strategy (the historical postrouting fallback queued every
# unmarked LAN flow to the test IPs). The probe mode is reported honestly
# in the "probe" field of the result JSON (the fuzzer surfaces it in the UI).
PROBE_UID=""
PROBE_MODE="skuid"
if command -v su >/dev/null 2>&1; then
	PROBE_UID=$(id -u daemon 2>/dev/null)
	case "$PROBE_UID" in ''|*[!0-9]*) PROBE_UID="" ;; esac
	[ -n "$PROBE_UID" ] && ! su -s /bin/sh daemon -c true >/dev/null 2>&1 && PROBE_UID=""
fi
[ -n "$PROBE_UID" ] || PROBE_MODE="fallback"

# ── Ф6.4: UDP/QUIC contour (audit 61) ────────────────────────────────────
# --quic: the candidate strategy's UDP profile (or none = baseline) on the
# temp queue + a REAL QUIC probe (probe_pool -quic-check) as the daemon user
# → {"ok":1,"quic":"vn|icmp|silence|absent","strategy":0|1}. A real HTTP/3
# handshake is NOT possible on this hardware (§2.5: quic-go does not build on
# mipsle) — the Version-Negotiation A/B is the honest ceiling here; STUN/Voice
# UDP has no probe tool on this router (no nc -u, no socat) and stays honestly
# unprobed (audit 60/91 — service_profiles.uc carries that component).
if [ "$QUIC" = "1" ]; then
	QIP=""
	for kv in $IPS_ARG; do
		case "$kv" in yt=*) QIP=${kv#yt=} ;; esac
	done
	[ -z "$QIP" ] && fail "quic contour needs the yt=ip argument"
	[ -x /usr/bin/probe_pool ] || { echo '{"ok":0,"error":"probe_pool not installed"}'; exit 0; }
	QSTRAT="false"
	[ "$BASELINE" != "1" ] && [ -n "$(printf '%s' "$STRAT" | tr -d '[:space:]')" ] && QSTRAT="true"
	if nft list chain inet fw4 homeproxy_output_redir >/dev/null 2>&1; then
		nft insert rule inet fw4 homeproxy_output_redir ip daddr "{ $QIP }" udp dport 443 counter return comment "\"$CMT\"" 2>/dev/null
	fi
	nft add table inet "$TABLE" 2>/dev/null
	if [ -n "$PROBE_UID" ]; then
		nft add chain inet "$TABLE" out "{ type filter hook output priority -150; policy accept; }" 2>/dev/null
		nft add rule  inet "$TABLE" out "meta skuid $PROBE_UID meta mark and $DMARK == 0 ip daddr { $QIP } udp dport 443 ct original packets 1-3 counter queue num $QNUM bypass" 2>/dev/null
		nft add rule  inet "$TABLE" out "meta mark and $DMARK != 0 notrack" 2>/dev/null
	else
		nft add chain inet "$TABLE" out "{ type filter hook output priority -150; policy accept; }" 2>/dev/null
		nft add rule  inet "$TABLE" out "meta skuid 0 meta mark and $DMARK == 0 ip daddr { $QIP } udp dport 443 ct original packets 1-3 counter queue num $QNUM bypass" 2>/dev/null
		nft add rule  inet "$TABLE" out "meta mark and $DMARK != 0 notrack" 2>/dev/null
	fi
	if [ "$QSTRAT" = "true" ]; then
		$NFQWS --qnum=$QNUM --user=daemon --fwmark=$DMARK $LUA $STRAT >/dev/null 2>&1 &
		NFQ_PID=$!
		sleep 1
		ucode /etc/homeproxy/scripts/pmgr_cli.uc find "$NFQWS" "--qnum=$QNUM" >/dev/null 2>&1 || fail "nfqws2 did not start - check strategy"
		# ч.229: same queue-bind readiness gate as the TCP contour — the QUIC
		# A/B measured inside the settling window would compare the baseline
		# against an engine that was not listening yet.
		QWAIT=0
		QBOUND=0
		while [ "$QWAIT" -lt 50 ]; do
			if awk -v q="$QNUM" '$1 == q { f = 1; exit } END { exit (f ? 0 : 1) }' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; then
				QBOUND=1
				break
			fi
			sleep 0.2
			QWAIT=$((QWAIT + 1))
		done
		if [ "$QBOUND" != "1" ]; then
			ucode /etc/homeproxy/scripts/pmgr_cli.uc find "$NFQWS" "--qnum=$QNUM" >/dev/null 2>&1 || fail "nfqws2 died before queue bind"
			echo "queue $QNUM bind wait timeout - quic probe may pass un-mangled" >&2
		fi
	fi
	QOUT="$TMP/quic_out.json"
	if [ -n "$PROBE_UID" ]; then
		su -s /bin/sh daemon -c "/usr/bin/probe_pool -quic-check '$QIP' -quic-host redirector.googlevideo.com > '$QOUT' 2>/dev/null" >/dev/null 2>&1
	else
		/usr/bin/probe_pool -quic-check "$QIP" -quic-host redirector.googlevideo.com > "$QOUT" 2>/dev/null
	fi
	QV=$(grep -oE '"verdict":"[a-z]+"' "$QOUT" 2>/dev/null | head -n 1 | cut -d'"' -f4)
	# Ф6.4 defensive (live fact): a stray token the ucode json() parser turns
	# into a bare NaN must never reach the result — only the three honest
	# verdicts pass; anything else reads as "unknown" (honest unmeasured).
	case "$QV" in vn|icmp|silence) : ;; *) QV="unknown" ;; esac
	[ -n "$QV" ] || QV="unknown"
	echo "{\"ok\":1,\"quic\":\"$QV\",\"strategy\":$QSTRAT,\"probe\":\"$PROBE_MODE\"}"
	exit 0
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
		nft add chain inet "$TABLE" out "{ type filter hook output priority -150; policy accept; }" 2>/dev/null
		nft add rule  inet "$TABLE" out "meta skuid 0 meta mark and $DMARK == 0 ip daddr { $IPSET } tcp dport 443 ct original packets 1-12 counter queue num $QNUM bypass" 2>/dev/null
		nft add rule  inet "$TABLE" out "meta mark and $DMARK != 0 notrack" 2>/dev/null
	fi

# 4. Start the candidate nfqws2 on the temp queue (skipped in --baseline mode:
#    no queue listener = packets pass unchanged = pure baseline).
if [ "$BASELINE" != "1" ]; then
	$NFQWS --qnum=$QNUM --user=daemon --fwmark=$DMARK $LUA $STRAT >/dev/null 2>&1 &
	NFQ_PID=$!
	sleep 1
	# Ф1.4b: identity liveness (exact exe + the --qnum element), not a
	# substring pgrep that matched any process mentioning the number.
	ucode /etc/homeproxy/scripts/pmgr_cli.uc find "$NFQWS" "--qnum=$QNUM" >/dev/null 2>&1 || fail "nfqws2 did not start - check strategy"
	# ч.229: the identity check passes while the queue is NOT yet bound —
	# nfqws2 binds only after its lua init. Probes fired inside that window
	# return 000 at exactly the connect-timeout while the SAME probes pass
	# seconds later (the settling window proven live in ч.228 on the wizard
	# verify; the wizard got wait_probe_ready — the fuzz contour did not,
	# and a lost round 1 kills a candidate by majority). /proc/net/netfilter/
	# nfnetlink_queue lists bound queues as a padded "<qnum> <pid> ..." line;
	# poll for OUR qnum in column 1 (0.2s x 50 = 10s cap).
	QWAIT=0
	QBOUND=0
	while [ "$QWAIT" -lt 50 ]; do
		if awk -v q="$QNUM" '$1 == q { f = 1; exit } END { exit (f ? 0 : 1) }' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; then
			QBOUND=1
			break
		fi
		sleep 0.2
		QWAIT=$((QWAIT + 1))
	done
	if [ "$QBOUND" != "1" ]; then
		ucode /etc/homeproxy/scripts/pmgr_cli.uc find "$NFQWS" "--qnum=$QNUM" >/dev/null 2>&1 || fail "nfqws2 died before queue bind"
		echo "queue $QNUM bind wait timeout - probes may pass un-mangled" >&2
	fi
fi

# 5. Probe every host in parallel: curl forced to the resolved IP, write
#    "http_code time_appconnect redirect_url curl_exit" — the UNIFIED record
#    (audit 82): the exit code and the HTTP answer are now part of the
#    verdict, «handshake прошёл, поток порван» больше не выглядит успехом.
#    Collect by POLLING the r_<tag> files (signal-immune; each curl is capped
#    by --max-time 10, so 25s is a ceiling). In skuid mode each probe runs as
#    `daemon` (the queue rule matches that uid only); the temp dir must then
#    accept the daemon's result files.
[ -n "$PROBE_UID" ] && chmod 777 "$TMP" 2>/dev/null
for h in $HOSTS; do
	tag=${h%%|*}; rest=${h#*|}; label=${rest%%|*}; host=${rest#*|}
	ip=$(cat "$TMP/ip_$tag" 2>/dev/null)
	if [ -z "$ip" ]; then echo "000 0 - 6" > "$TMP/r_$tag"; continue; fi
	if [ -n "$PROBE_UID" ]; then
		# tag/host/ip are tester-owned constants (fixed labels, resolved
		# numeric IPs, /tmp path with PID) — safe to inline in the body.
		su -s /bin/sh daemon -c "out=\$(curl -s --resolve '${host}:443:${ip}' -o /dev/null -w '%{http_code} %{time_appconnect} %{redirect_url}' --connect-timeout 4 --max-time 10 'https://${host}' 2>/dev/null); echo \"\$out \$?\" > '${TMP}/r_${tag}'" >/dev/null 2>&1 &
	else
		( out=$(curl -s --resolve "${host}:443:${ip}" -o /dev/null -w '%{http_code} %{time_appconnect} %{redirect_url}' --connect-timeout 4 --max-time 10 "https://${host}" 2>/dev/null); echo "$out $?" > "$TMP/r_$tag" ) >/dev/null 2>&1 &
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
		if [ -z "$dip" ]; then echo "000 0 0 0 0 6" > "$TMP/d_$did"; continue; fi
		# ч.116: the stream probe downloads a ranged 4 MB of the REAL video —
		# the speed_download field is the honest verdict metric.
		# Ф6.4: flow-THROUGHPUT probes measure the path THROUGH a strategy —
		# in --baseline (no desync) they are meaningless by construction and
		# would only hang the pass on DPI-blocked connects: honest absence.
		if [ "$BASELINE" = "1" ]; then
			case "$did" in ytv|yts|yts2) continue ;; esac
		fi
		DRANGE=""
		case "$did" in yts|yts2) DRANGE="-r 0-4194303" ;; esac
		if [ "$did" = "ytv" ]; then
			# SUSTAINED-FLOW throughput: real thumbnails over keep-alive
			# flows (--max-time caps EACH window; curl exits 28 on a
			# throttled link — the completed transfers still report).
			# One -o per URL: with a single -o curl discards only the FIRST
			# body and dumps the rest to stdout (caught live ч.116).
			# ч.123: TWO windows, one keep-alive flow each — the mean no
			# longer hinges on one lucky or one unlucky window.
			# ч.129: THREE windows, and the verdict metric is the MEDIAN of
			# the per-window speeds (Σbytes/Σtime of each window) — the live
			# A/B run showed a ~2x swing of the pooled single-pair number
			# (the same strategy measured 525 KB/s in one sweep and 242 KB/s
			# minutes later); a median of three windows tames the burst.
			# A window that stalls entirely is dropped; a majority of OK
			# windows (≥2 of 3) is the 200 verdict, both stalled = honest
			# fail. Plus the ч.127 START phase, hardened: THREE DEDICATED
			# fresh single-fetch connections (parallel, one small thumbnail
			# each) join each window's first-transfer time_starttransfer —
			# the verdict START is the lower-median of up to 6 fresh-
			# connection samples (the hover-preview latency must not hinge
			# on one bursty sample).
			CURL_ARGS=""
			for yu in $YTV_URLS; do
				CURL_ARGS="$CURL_ARGS -o /dev/null $yu"
			done
			cat > "$TMP/ytv_flow.sh" <<'YTVFLOW'
#!/bin/sh
# three sustained-flow windows + a fresh-connection START phase →
# "code secs bytes speed fetched start"
pin="$1"; shift
w() {
	curl -sL --max-redirs 2 --resolve "$pin" -w '%{http_code} %{time_total} %{size_download} %{time_starttransfer}\n' --connect-timeout 4 --max-time 9 -k "$@" 2>/dev/null | awk '{s+=$3; t+=$2; o++; if ($1==200 || $1==206) n++; if (NR==1) tf=$4} END {if (t<0.1) t=0.1; print ((n>=8)?200:0), t, s+0, o+0, (s/t)+0, tf+0}'
}
W1=$(w "$@")
sleep 1
W2=$(w "$@")
sleep 1
W3=$(w "$@")
# START phase: three parallel fresh connections, one small fetch each
u="$1"
d=$(dirname "$0")
fr() {
	curl -sL --max-redirs 2 --resolve "$pin" -o /dev/null -w '%{http_code} %{time_starttransfer}\n' --connect-timeout 4 --max-time 9 -k "$u" 2>/dev/null
}
fr > "$d/f1.$$" & fr > "$d/f2.$$" & fr > "$d/f3.$$" &
wait
{
	printf '%s\n' "$W1" "$W2" "$W3"
	cat "$d/f1.$$" "$d/f2.$$" "$d/f3.$$" 2>/dev/null
} | awk '
NF >= 6 { nw++; c[nw]=$1; t[nw]=$2; s[nw]=$3; o[nw]=$4; sp[nw]=$5; tfw[nw]=$6; next }
NF >= 2 && ($1 == 200 || $1 == 206) { nf++; tff[nf]=$2+0; next }
END {
	if (nw < 1) { print 0, 0.1, 0, 0, 0, 0; exit }
	okw = 0; tt = 0; ss = 0; oo = 0
	for (i = 1; i <= nw; i++) { if (c[i] == 200) okw++; tt += t[i]; ss += s[i]; oo += o[i] }
	code = (okw >= 2) ? 200 : 0
	if (tt < 0.1) tt = 0.1
	# median of the per-window speeds (lower-median)
	sn = 0
	for (i = 1; i <= nw; i++) if (sp[i] > 0) { sn++; v[sn] = sp[i] }
	for (i = 1; i <= sn; i++) for (j = i + 1; j <= sn; j++) if (v[j] < v[i]) { tmpv = v[i]; v[i] = v[j]; v[j] = tmpv }
	spd = (sn > 0) ? v[int((sn + 1) / 2)] : 0
	# lower-median of the fresh-connection START samples (windows firsts + fresh probes)
	tn = 0
	for (i = 1; i <= nw; i++) if (tfw[i] > 0) { tn++; q[tn] = tfw[i] }
	for (i = 1; i <= nf; i++) if (tff[i] > 0) { tn++; q[tn] = tff[i] }
	for (i = 1; i <= tn; i++) for (j = i + 1; j <= tn; j++) if (q[j] < q[i]) { tmpq = q[i]; q[i] = q[j]; q[j] = tmpq }
	st = (tn > 0) ? q[int((tn + 1) / 2)] : 0
	print code, tt, ss, int(spd), oo, st
}'
	rm -f "$d/f1.$$" "$d/f2.$$" "$d/f3.$$" 2>/dev/null
YTVFLOW
			chmod 755 "$TMP/ytv_flow.sh"
			if [ -n "$PROBE_UID" ]; then
				su -s /bin/sh daemon -c "sh '${TMP}/ytv_flow.sh' '${dhost}:443:${dip}' ${CURL_ARGS} > '${TMP}/d_${did}'" >/dev/null 2>&1 &
			else
				sh "$TMP/ytv_flow.sh" "${dhost}:443:${dip}" $CURL_ARGS > "$TMP/d_$did" 2>/dev/null &
			fi
			continue
		fi
		# Ф6.4 (audit 82): content probes SAVE the body for diag_core
		# classification (yts keeps /dev/null — its verdict is speed-based);
		# fingerprint variants (ids with "f") run the browser-like profile.
		DBODY="$TMP/b_$did"
		case "$did" in yts|yts2) DBODY="/dev/null" ;; esac
		if [ "${did%f}" != "$did" ]; then
			if [ -n "$PROBE_UID" ]; then
				su -s /bin/sh daemon -c "sh '${TMP}/fp_flow.sh' '${dhost}:443:${dip}' '${durl}' '${TMP}/b_${did}' > '${TMP}/d_${did}'" >/dev/null 2>&1 &
			else
				sh "$TMP/fp_flow.sh" "${dhost}:443:${dip}" "$durl" "$TMP/b_$did" > "$TMP/d_$did" 2>/dev/null &
			fi
			continue
		fi
		if [ -n "$PROBE_UID" ]; then
			su -s /bin/sh daemon -c "out=\$(curl -sL $DRANGE --max-redirs 3 --resolve '${dhost}:443:${dip}' -o '${DBODY}' -w '%{http_code} %{time_total} %{size_download} %{speed_download} %{time_starttransfer}' --connect-timeout 4 --max-time 9 -k '${durl}' 2>/dev/null); echo \"\$out \$?\" > '${TMP}/d_${did}'" >/dev/null 2>&1 &
		else
			( out=$(curl -sL $DRANGE --max-redirs 3 --resolve "${dhost}:443:${dip}" -o "$DBODY" -w '%{http_code} %{time_total} %{size_download} %{speed_download} %{time_starttransfer}' --connect-timeout 4 --max-time 9 -k "$durl" 2>/dev/null); echo "$out $?" > "$TMP/d_$did" ) >/dev/null 2>&1 &
		fi
	done
	dn=0
	while [ "$dn" -lt 45 ]; do
		all=1
		for dp in $DEEP_PROBES; do
			did=${dp%%|*}
			[ -s "$TMP/d_$did" ] || all=0
		done
	[ "$all" = 1 ] && break
	sleep 1
	dn=$((dn + 1))
done
fi

# 5c. Ф6.4: classification + unified result build (audit 82) — ONE ucode pass:
# diag_core.classify_path over the saved bodies + the honest speed gates
# (ytv/yts) + the full result JSON. The manifest rides stdin (lesson 8: ARGV
# unreliable on this build); the builder prints the final line.
	if [ "$DEEP" = "1" ]; then
	{
		printf '{"tmp":"%s","probe":"%s","deep":true,"hosts":[' "$TMP" "$PROBE_MODE"
		firsth=1
		for h in $HOSTS; do
			tag=${h%%|*}; rest=${h#*|}; label=${rest%%|*}; host=${rest#*|}
			[ "$firsth" = 1 ] || printf ','
			firsth=0
			printf '["%s","%s","%s"]' "$tag" "$label" "$host"
		done
		printf '],"owners":{"yt":["ytp","ytpf","yti","ytr","ytv","yts","yts2"],"tg":["tgp","tgpf"],"dc":["dcp","dcpf"],"st":["stp","stpf"]}}\n'
	} > "$TMP/manifest.json"
	ucode /etc/homeproxy/scripts/zapret_deep_build.uc < "$TMP/manifest.json"
else
	# plain build: the same unified record (code/tls/redirect/rc), no deep.
	JSON=""; OKC=0; TOT=0
	for h in $HOSTS; do
		tag=${h%%|*}; rest=${h#*|}; label=${rest%%|*}; host=${rest#*|}
		ip=$(cat "$TMP/ip_$tag" 2>/dev/null)
		raw=$(cat "$TMP/r_$tag" 2>/dev/null)
		set -- $raw
		dcode=${1:-000}; tls=${2:-0}; rc=${3:-1}; redir="-"
		case "$tls" in ''|*[!0-9.]*) tls=0 ;; esac
		if [ "$#" -ge 4 ]; then
			redir="$3"
			case "$redir" in http*) : ;; *) redir="-" ;; esac
			rc=$4
		fi
		case "$rc" in ''|*[!0-9]*) rc=1 ;; esac
		TOT=$((TOT+1))
		tlsok=0; case "$tls" in 0|0.000000|"") tlsok=0;; *) tlsok=1;; esac
		ok=0; [ "$tlsok" = 1 ] && [ "$rc" = 0 ] && ok=1
		[ "$ok" = 1 ] && OKC=$((OKC+1))
		reason=""
		if [ "$ok" = 0 ]; then
			if [ "$tlsok" = 1 ]; then
				reason=flow_reset
			else
				case "$rc" in 6) reason=dns;; 7) reason=refused;; 28) reason=timeout;; 35|51|53|56|58|59|60) reason=tls;; *) reason=fail;; esac
			fi
		fi
		[ -n "$JSON" ] && JSON="$JSON,"
		JSON="$JSON{\"tag\":\"$tag\",\"label\":\"$label\",\"host\":\"$host\",\"ip\":\"$ip\",\"code\":\"$dcode\",\"tls\":\"$tls\",\"redirect\":\"$redir\",\"rc\":$rc,\"ok\":$ok,\"reason\":\"$reason\",\"probe\":\"$PROBE_MODE\"}"
	done
	echo "{\"ok\":$OKC,\"total\":$TOT,\"probe\":\"$PROBE_MODE\",\"results\":[$JSON]}"
fi
rm -rf "$TMP" 2>/dev/null
