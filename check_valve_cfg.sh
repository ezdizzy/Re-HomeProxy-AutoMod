#!/bin/sh
echo "=== CONTEXT AROUND 'valve' (lines) ==="
grep -n -B3 -A6 'valve' /tmp/run/homeproxy/hiddify-c.json | head -60
echo ""
echo "=== OUTBOUND/SERVER lines (rules section) ==="
grep -n '"outbound"' /tmp/run/homeproxy/hiddify-c.json | head -25
