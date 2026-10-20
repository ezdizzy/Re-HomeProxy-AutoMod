#!/bin/sh
echo "=== CLASH API: rule providers status ==="
curl -s --max-time 5 http://127.0.0.1:9090/providers/rules | tr ',' '\n' | grep -A0 'valve' | head -5
echo ""
echo "=== route_explain store.steampowered.com ==="
ubus call luci.homeproxy route_explain '{"host":"store.steampowered.com"}'
echo ""
echo "=== route_explain steamcommunity.com ==="
ubus call luci.homeproxy route_explain '{"host":"steamcommunity.com"}'
