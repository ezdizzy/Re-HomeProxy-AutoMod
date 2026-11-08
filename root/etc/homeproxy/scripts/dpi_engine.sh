#!/bin/sh
# DPI engine launcher (light strategy-apply path).
#
# procd registers THIS script as the instance command (init.d: instances
# "byedpi"/"zapret"). On every spawn it re-reads the CURRENT UCI strategy,
# so engine_restart() (init.d) can apply a new strategy with a single kill:
# procd respawns the wrapper and the engine comes back with the fresh args —
# no service reload, no core restart, no DNS outage, no tunnel teardown.
# The full reload path stays reserved for changes the core actually
# consumes (nodes/rules/DNS — generate_client output).
#
# `exec` keeps the PID: procd keeps watching the same process it spawned.
# Quote-aware split (eval) so an argument value containing spaces survives
# intact — same rationale as the init.d registration (admin-owned root UCI
# value: argument parsing, not a trust boundary).

CONF=homeproxy
MODE="$1"

# F10.2 OOM victim ordering: the engines are respawnable (procd respawns
# this wrapper) — under memory pressure they die BEFORE the DNS/UI plane.
echo 300 > /proc/self/oom_score_adj 2>/dev/null

case "$MODE" in
zapret)
	[ "$(uci -q get $CONF.config.zapret_enabled)" = "1" ] || exit 0
	[ -x /opt/zapret2/nfq2/nfqws2 ] || exit 0
	QNUM="$(uci -q get $CONF.config.zapret_qnum)"
	[ -n "$QNUM" ] || QNUM=200
	# Default strategy = zapret2's shipped recipe minus hostlists, TCP
	# http+tls only (must match init.d's zapret_default_opts).
	OPTS="$(uci -q get $CONF.config.zapret_cmd_opts)"
	[ -n "$OPTS" ] || OPTS="--filter-tcp=80 --filter-l7=http --payload=http_req --lua-desync=fake:blob=fake_default_http:tcp_md5 --lua-desync=multisplit:pos=method+2 --new --filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000 --lua-desync=multidisorder:pos=1,midsld"
	# The engine's own words on tmpfs: procd discards instance output, so a
	# lua/queue failure died SILENTLY (the exit-code-0 crash-loop class — the
	# "nfqws2 fell again during the fuzz" report 2026-11-07). A dated spawn
	# header timestamps every (re)start; the 64 KB cap keeps tmpfs clean.
	NFQ_LOG=/var/run/homeproxy/nfqws2.log
	NFQ_SZ=$(wc -c < "$NFQ_LOG" 2>/dev/null)
	case "$NFQ_SZ" in ''|*[!0-9]*) NFQ_SZ=0 ;; esac
	[ "$NFQ_SZ" -gt 65536 ] && mv -f "$NFQ_LOG" "$NFQ_LOG.1" 2>/dev/null
	echo "$(date '+%F %T') dpi_engine: spawn nfqws2 qnum=$QNUM" >> "$NFQ_LOG" 2>/dev/null
	eval "set -- $OPTS"
	exec /opt/zapret2/nfq2/nfqws2 \
		--qnum="$QNUM" \
		--user=daemon \
		--fwmark=0x40000000 \
		--lua-init=@/opt/zapret2/lua/zapret-lib.lua \
		--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua \
		--lua-init=@/opt/zapret2/lua/zapret-auto.lua "$@" >> "$NFQ_LOG" 2>&1
	;;
byedpi)
	[ "$(uci -q get $CONF.config.byedpi_enabled)" = "1" ] || exit 0
	[ -x /usr/bin/ciadpi ] || exit 0
	OPTS="$(uci -q get $CONF.config.byedpi_cmd_opts)"
	[ -n "$OPTS" ] || OPTS="--disorder 1"
	eval "set -- $OPTS"
	exec /usr/bin/ciadpi -i 127.0.0.1 -p 5335 "$@"
	;;
*)
	exit 1
	;;
esac
