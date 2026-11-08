#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# F10.2 OOM victim ordering + Go soft-heap cap.
# Spawned by procd/shell INSTEAD of the target binary:
#   oom_adj.sh <adj> <gomemlimit_mb|0> <cmd> [args...]
#
# adj — oom_score_adj written BEFORE exec (exec keeps the pid, the kernel
#       keeps the value): expendable/respawnable processes (proxy core,
#       DPI engines, resident helpers) become the deterministic OOM victims
#       so the killer stops shooting the UI/DNS/WiFi plane (dnsmasq,
#       hostapd, uhttpd, rpcd stay at 0) — the WR3000H lockup class.
# gomemlimit — GOMEMLIMIT (Go soft heap limit, MB) applied on EVERY box:
#       the Go processes must keep their heap inside the box budget instead
#       of growing into a global OOM (lesson 197: the core was OOM-killed
#       at 727 MB anon on 1 GB boxes). The effective cap is
#       min(gomemlimit, MemTotal/2) so a large requested value can never
#       exceed half of the physical RAM. 0 = off.

ADJ="$1"
GML="$2"
shift 2

case "$ADJ" in ''|*[!0-9]*) ADJ=0;; esac
echo "$ADJ" > /proc/self/oom_score_adj 2>/dev/null

case "$GML" in ''|*[!0-9]*) GML=0;; esac
if [ "$GML" -gt 0 ]; then
	MT=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)
	case "$MT" in ''|*[!0-9]*) MT=0;; esac
	if [ "$MT" -gt 0 ]; then
		# Effective cap = min(requested, half of physical RAM), applied on
		# every box (was lite-only): 1 GB box + 384 requested -> 384MiB;
		# 256 MB box + 384 requested -> 128MiB; tiny boxes shrink likewise.
		CAP=$((MT / 2048))
		[ "$CAP" -lt "$GML" ] && GML=$CAP
		# Go requires the byte-unit suffix: "384M"/"384MB" are FATAL
		# ("malformed GOMEMLIMIT", caught live ch.257), only MiB is valid.
		GOMEMLIMIT="${GML}MiB"
		export GOMEMLIMIT
	fi
fi

exec "$@"
