#!/bin/sh
( curl -s -o /dev/null -m 20 https://store.steampowered.com/ ) &
sleep 2
echo "=== steam conn detail ==="
curl -s -m 5 'http://127.0.0.1:9090/connections' | grep -oE '\{[^{}]*steam[^{}]*\}' | head -3
echo ""
echo "=== all rulePayload values ==="
curl -s -m 5 'http://127.0.0.1:9090/connections' | grep -o '"rulePayload":"[^"]*"' | sort | uniq -c | head -10
echo ""
echo "=== valve log ==="
logread | grep -iE 'valve|srs' | tail -6
wait
echo "=== done ==="
