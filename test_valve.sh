#!/bin/sh
echo "=== APPLY VALVE PRESET ==="
ubus call luci.homeproxy wizard_preset_apply '{"source":"valve","node":"main-out"}'
echo ""
echo "=== UCI CHECK (valve rule) ==="
uci show homeproxy | grep -i 'valve' | head -20
echo ""
echo "=== SERVICE STATUS ==="
/etc/init.d/homeproxy status 2>/dev/null || ubus call service list '{"name":"homeproxy"}' | head -50
