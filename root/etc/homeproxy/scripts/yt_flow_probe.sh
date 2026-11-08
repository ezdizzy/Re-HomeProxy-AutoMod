#!/bin/sh
# Re:HomeProxy AutoMod — sustained-flow throughput probe, LIVE path (ч.116).
#
# The user's complaint («страница открывается, а превью/видео грузятся
# вечность») is invisible to a TLS handshake and to tiny fetches: TSPU lets
# the ClientHello through and THROTTLES the flow. This probe fetches 24 real
# thumbnails of stable public videos over ONE keep-alive TLS flow to
# i.ytimg.com (the same google-CDN class the complaint is about) through the
# CONFIGURED path — exactly the way LAN clients are served — and reports
# Σbytes/Σtime. A throttled flow fails the ≥128 KB/s bar honestly; the
# router CPU is never the bottleneck at these sizes.
#
# ч.127: the answer also reports START — the time_starttransfer of EACH
# window's FIRST transfer (each window opens a FRESH connection, so the
# first transfer carries the full TCP+TLS+request+server path to the first
# byte). That is the hover-preview latency the user described: «навожу на
# карточку — превью не стартует или стартует с задержкой». The two windows
# are averaged; a window that never answered contributes nothing.
#
# Output (one JSON line):
#   {"ok":0|1,"code":"200|0","speed":<int B/s>,"bytes":<int>,"secs":<float>,
#    "fetched":<n>,"start_ms":<int>}
# ok = code 200 (≥8 transfers succeeded) AND speed ≥ 131072 AND bytes ≥ 409600.
# A 28 (curl whole-run timeout on a throttled link) is a HONEST result: the
# completed transfers still report, the speed bar decides.

IDS=/etc/homeproxy/resources/yt_probe_ids.txt
[ -f "$IDS" ] || { echo '{"ok":0,"code":"0","speed":0,"bytes":0,"secs":0,"fetched":0,"start_ms":0}'; exit 0; }
URLS=""
for vid in $(grep -vE '^[[:space:]]*(#|$)' "$IDS"); do
	URLS="$URLS https://i.ytimg.com/vi/$vid/mqdefault.jpg https://i.ytimg.com/vi/$vid/hq720.jpg"
done
[ -n "$URLS" ] || { echo '{"ok":0,"code":"0","speed":0,"bytes":0,"secs":0,"fetched":0,"start_ms":0}'; exit 0; }
# one -o per URL: with a single -o curl discards only the FIRST body and
# dumps the rest to stdout (caught live — the awk then ate JPEG garbage).
CURL_ARGS=""
for u in $URLS; do
	CURL_ARGS="$CURL_ARGS -o /dev/null $u"
done

window() {
	curl -sL --max-redirs 2 -w '%{http_code} %{time_total} %{size_download} %{time_starttransfer}\n' \
		--connect-timeout 4 --max-time 9 $CURL_ARGS 2>/dev/null | \
		awk '{s+=$3; t+=$2; o++; if ($1==200 || $1==206) n++; if (NR==1) tf=$4} END {if (t<0.1) t=0.1; code=0; if (n>=8) code=200; print code, t, s+0, o+0, tf+0}'
}
# ч.123: TWO windows ~1 s apart — TSPU throttling is bursty; the mean
# (Σbytes/Σtime of both windows) stops the verdict from hinging on one lucky
# or one unlucky window. A window that stalls entirely is dropped; if both
# stall, the honest fail stands.
W1=$(window)
sleep 1
W2=$(window)
out=$(printf '%s\n%s\n' "$W1" "$W2" | awk '
{ c[NR]=$1; t[NR]=$2; s[NR]=$3; o[NR]=$4; tf[NR]=$5 }
END {
	if (NR == 1) { tt=t[1]; if (tt<0.1) tt=0.1; print c[1], tt, s[1]+0, int((s[1]+0)/tt), o[1]+0, tf[1]+0; exit }
	code=0; if (c[1]==200 && c[2]==200) code=200
	tt=t[1]+t[2]; ss=s[1]+s[2]; if (tt<0.1) tt=0.1
	ns=0; ts=0
	for (i=1; i<=NR; i++) if (tf[i] > 0) { ts += tf[i]; ns++ }
	st = (ns > 0) ? ts/ns : 0
	print code, tt, ss, int(ss/tt), o[1]+o[2], st
}')
# out = "code secs bytes speed fetched start"
set -- $(printf '%s' "$out")
CODE=$1; SECS=$2; BYTES=$3; SPEED=$4; FETCHED=$5; START=$6
[ -n "$CODE" ] || { echo '{"ok":0,"code":"0","speed":0,"bytes":0,"secs":0,"fetched":0,"start_ms":0}'; exit 0; }
OK=1
[ "$CODE" = "200" ] || OK=0
[ "$SPEED" -ge 131072 ] 2>/dev/null || OK=0
[ "$BYTES" -ge 409600 ] 2>/dev/null || OK=0
START_MS=$(awk -v t="$START" 'BEGIN{printf "%d", (t+0)*1000}')
printf '{"ok":%s,"code":"%s","speed":%s,"bytes":%s,"secs":%s,"fetched":%s,"start_ms":%s}\n' \
	"$OK" "$CODE" "$SPEED" "$BYTES" "$SECS" "$FETCHED" "$START_MS"
