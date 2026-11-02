#!/bin/sh
# TUN policy-route watcher (ч.72) + fail-closed floor (Ф1.3, audit 22).
#
# Installs the fwmark -> table -> tun-device policy route as soon as the core
# brings up the tun device, and re-installs it whenever the rule/route
# disappears (core respawn re-creates the device).
#
# Why: a tun-mode core may initialize remote rule-sets BEFORE inbounds/TUN —
# on a slow start the device appears well past 40 s, which the old one-shot
# blocking wait in init.d missed ("tun device not ready") — the policy route
# was then never installed, every marked packet fell through to the main table
# and egressed DIRECTLY, so every site that should go through the proxy was
# dead while the core itself looked healthy.
#
# Ф1.3 fail-closed (audit 22): while the working route is absent — device not
# up yet, core crash respawn, watcher between ticks — the kernel falls through
# the EMPTY policy table to the main table and egresses DIRECTLY (fail-open:
# traffic that must be proxied leaks to WAN). A permanent `unreachable default`
# in the policy table closes that window: marked packets get ENETUNREACH
# (fail-closed) instead of leaking, and the working route (metric 0) always
# wins over the floor (metric 42780) while the device is up. init.d removes
# the floor together with the rule on service stop.
#
# State: $RUN_DIR/tun_state.json (atomic tmp+mv; written only on status CHANGE)
# — {"status":"ok|degraded|down",...} for the Health Monitor / acceptance.
#
# procd instance arguments: <tun_name> <tun_mark> <tun_table> <ipv6 0|1>
# Runs for the whole service lifetime; stopped by procd on service stop.

RUN_DIR="/var/run/homeproxy"
LOG="$RUN_DIR/homeproxy.log"
TUN_NAME="$1"
TUN_MARK="$2"
TUN_TABLE="$3"
IPV6="$4"
STATE="$RUN_DIR/tun_state.json"
FLOOR_METRIC="42780"

logline() {
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DAEMON] $1" >> "$LOG" 2>/dev/null
}

cur_status=""
write_state() {
	# $1 = status (ok|degraded|down), $2 = detail. Written on change only —
	# a 3 s tick must not churn the state file (RAM-writes are cheap, but the
	# Health Monitor wants a change signal, not a heartbeat).
	if [ "$cur_status" != "$1" ] || [ ! -f "$STATE" ]; then
		printf '{"status":"%s","device":"%s","detail":"%s","ts":%s}\n' \
			"$1" "$TUN_NAME" "$2" "$(date +%s)" > "$STATE.tmp" 2>/dev/null &&
			mv -f "$STATE.tmp" "$STATE" 2>/dev/null
		cur_status="$1"
		logline "TUN state: $1 ($2)."
	fi
}

# Fail-closed floor FIRST and ALWAYS — even before the device ever appears
# (the start window is exactly the leak window audit 22 describes).
if ! ip route show table "$TUN_TABLE" 2>/dev/null | grep -q "unreachable default"; then
	if ip route add unreachable default metric "$FLOOR_METRIC" table "$TUN_TABLE" 2>/dev/null; then
		logline "TUN fail-closed floor installed (unreachable default, table $TUN_TABLE)."
	else
		logline "TUN fail-closed floor FAILED to install — leak window stays open (check ip route support)."
	fi
fi
if [ "$IPV6" = "1" ] && ! ip -6 route show table "$TUN_TABLE" 2>/dev/null | grep -q "unreachable default"; then
	ip -6 route add unreachable default metric "$FLOOR_METRIC" table "$TUN_TABLE" 2>/dev/null ||
		logline "TUN fail-closed floor (IPv6) FAILED to install."
fi

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
		if ip route show table "$TUN_TABLE" 2>/dev/null | grep -q "dev $TUN_NAME"; then
			write_state ok "policy route present"
		else
			write_state degraded "device up but route install failed"
		fi
	else
		write_state down "device absent — unreachable floor active (fail-closed)"
	fi
	sleep 3
done
