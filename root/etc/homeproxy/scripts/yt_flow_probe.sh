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
# Output (one JSON line):
#   {"ok":0|1,"code":"200|0","speed":<int B/s>,"bytes":<int>,"secs":<float>,"fetched":<n>}
# ok = code 200 (≥8 transfers succeeded) AND speed ≥ 131072 AND bytes ≥ 409600.
# A 28 (curl whole-run timeout on a throttled link) is a HONEST result: the
# completed transfers still report, the speed bar decides.

IDS=/etc/homeproxy/resources/yt_probe_ids.txt
[ -f "$IDS" ] || { echo '{"ok":0,"code":"0","speed":0,"bytes":0,"secs":0,"fetched":0,"note":"no ids file"}'; exit 0; }
URLS=""
for vid in $(grep -vE '^[[:space:]]*(#|$)' "$IDS"); do
	URLS="$URLS https://i.ytimg.com/vi/$vid/mqdefault.jpg https://i.ytimg.com/vi/$vid/hq720.jpg"
done
[ -n "$URLS" ] || { echo '{"ok":0,"code":"0","speed":0,"bytes":0,"secs":0,"fetched":0,"note":"no ids"}'; exit 0; }
# one -o per URL: with a single -o curl discards only the FIRST body and
# dumps the rest to stdout (caught live — the awk then ate JPEG garbage).
CURL_ARGS=""
for u in $URLS; do
	CURL_ARGS="$CURL_ARGS -o /dev/null $u"
done

out=$(curl -sL --max-redirs 2 -w '%{http_code} %{time_total} %{size_download}\n' \
	--connect-timeout 4 --max-time 9 $CURL_ARGS 2>/dev/null | \
	awk '{s+=$3; t+=$2; o++; if ($1==200 || $1==206) n++;} END {if (t<0.1) t=0.1; code=0; if (n>=8) code=200; print code, t, s+0, int((s+0)/t), o+0}')
# out = "code secs bytes speed fetched"
set -- $(printf '%s' "$out")
CODE=$1; SECS=$2; BYTES=$3; SPEED=$4; FETCHED=$5
[ -n "$CODE" ] || { echo '{"ok":0,"code":"0","speed":0,"bytes":0,"secs":0,"fetched":0}'; exit 0; }
OK=1
[ "$CODE" = "200" ] || OK=0
[ "$SPEED" -ge 131072 ] 2>/dev/null || OK=0
[ "$BYTES" -ge 409600 ] 2>/dev/null || OK=0
printf '{"ok":%s,"code":"%s","speed":%s,"bytes":%s,"secs":%s,"fetched":%s}\n' \
	"$OK" "$CODE" "$SPEED" "$BYTES" "$SECS" "$FETCHED"
