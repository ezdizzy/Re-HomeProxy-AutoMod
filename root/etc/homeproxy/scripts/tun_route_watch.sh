#!/bin/sh
# TUN policy-route watcher (ч.72): installs the fwmark -> table -> tun-device
# policy route as soon as the core brings up the tun device, and re-installs
# it whenever the rule/route disappears (core respawn re-creates the device).
#
# Why: a tun-mode core may initialize remote rule-sets BEFORE inbounds/TUN —
# on a slow start the device appears well past 40 s, which the old one-shot
# blocking wait in init.d missed ("tun device not ready") — the policy route
# was then never installed, every marked packet fell through to the main table
# and egressed DIRECTLY, so every site that should go through the proxy was
# dead while the core itself looked healthy.
#
# procd instance arguments: <tun_name> <tun_mark> <tun_table> <ipv6 0|1>
# Runs for the whole service lifetime; stopped by procd on service stop.

RUN_DIR="/var/run/homeproxy"
LOG="$RUN_DIR/homeproxy.log"
TUN_NAME="$1"
TUN_MARK="$2"
TUN_TABLE="$3"
IPV6="$4"

logline() {
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DAEMON] $1" >> "$LOG" 2>/dev/null
}

while :; do
	if ip link show "$TUN_NAME" >/dev/null 2>&1; then
		MARK_HEX=$(printf '%x' "$TUN_MARK" 2>/dev/null)
		if ! ip rule show 2>/dev/null | grep -q "fwmark 0x$MARK_HEX"; then
			if ip rule add fwmark "$TUN_MARK" table "$TUN_TABLE" 2>/dev/null; then
				logline "TUN policy rule installed (fwmark $TUN_MARK -> table $TUN_TABLE)."
			fi
		fi
		if ! ip route show table "$TUN_TABLE" 2>/dev/null | grep -q "dev $TUN_NAME"; then
			if ip route add 0.0.0.0/0 dev "$TUN_NAME" table "$TUN_TABLE" 2>/dev/null; then
				logline "TUN policy route installed (table $TUN_TABLE -> $TUN_NAME)."
			fi
		fi
		if [ "$IPV6" = "1" ]; then
			if ! ip -6 rule show 2>/dev/null | grep -q "fwmark 0x$MARK_HEX"; then
				ip -6 rule add fwmark "$TUN_MARK" table "$TUN_TABLE" 2>/dev/null
			fi
			if ! ip -6 route show table "$TUN_TABLE" 2>/dev/null | grep -q "dev $TUN_NAME"; then
				ip -6 route add ::/0 dev "$TUN_NAME" table "$TUN_TABLE" 2>/dev/null
			fi
		fi
	fi
	sleep 3
done
