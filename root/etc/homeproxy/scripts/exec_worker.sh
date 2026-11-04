#!/bin/sh
# Ф8.3/D15 exec worker: runs ONE owner command with a hard timeout, caps the
# output, kills the WHOLE process tree on timeout/overflow (session sweep —
# lesson 112: a plain kill only reaches the direct child), and writes the
# result atomically (the done marker lands LAST). Args: <id> <timeout_sec>
ID="$1"
T="$2"
D="/tmp/hp-exec/$ID"
[ -n "$ID" ] || exit 1
case "$ID" in *[!0-9-]*) exit 1 ;; esac
[ -d "$D" ] || exit 1
case "$T" in ''|*[!0-9]*) T=20 ;; esac
[ "$T" -ge 5 ] || T=5
[ "$T" -le 120 ] || T=120

# Housekeeping: exec dirs older than 2 h (best effort; never our own).
find /tmp/hp-exec -maxdepth 1 -type d -mmin +120 2>/dev/null |
while read -r old; do
	[ "$old" != "/tmp/hp-exec" ] && rm -rf "$old"
done

OUT="$D/out"
: > "$OUT"
START=$(date +%s)
# Own session via setsid: sid == CPID, so the sweep below reaches the WHOLE
# tree, including grandchildren the plain kill would orphan (lesson 112).
setsid sh "$D/cmd.sh" > "$OUT" 2>&1 < /dev/null &
CPID=$!

alive() {
	[ -d "/proc/$1" ] || return 1
	ST=$(sed -n 's/^[0-9]* (.*) //p' "/proc/$1/stat" 2>/dev/null | awk '{print $1}')
	[ "$ST" != "Z" ]
}

# Kill every process of the child's session; two rounds with a pause catch
# secondarily spawned children (lesson 112). Never matches the worker
# itself: our own sid is our own pid, not CPID.
sweep() {
	n=1
	while [ "$n" -le 2 ]; do
		for p in /proc/[0-9]*; do
			P=${p#/proc/}
			[ "$P" = "$CPID" ] && continue
			S=$(sed -n 's/^[0-9]* (.*) //p' "$p/stat" 2>/dev/null | awk '{print $4}')
			[ "$S" = "$CPID" ] && kill -9 "$P" 2>/dev/null
		done
		kill -9 "$CPID" 2>/dev/null
		[ "$n" = 1 ] && sleep 1
		n=$((n+1))
	done
}

RC='done'
i=0
while [ "$i" -lt "$T" ]; do
	sleep 1
	alive "$CPID" || break
	SZ=$(wc -c < "$OUT" 2>/dev/null)
	case "$SZ" in ''|*[!0-9]*) SZ=0 ;; esac
	if [ "$SZ" -gt 262144 ]; then
		RC='overflow'
		break
	fi
	i=$((i+1))
done
# Budget exhausted with the child still alive = timeout (caught live T9:
# without this the worker sat in wait() for the full child runtime and
# reported the child's own exit code instead of the timeout).
if [ "$RC" = 'done' ] && alive "$CPID"; then
	RC='timeout'
fi
[ "$RC" = 'done' ] || sweep
wait "$CPID" 2>/dev/null
WRC=$?
case "$WRC" in ''|*[!0-9]*) WRC='?' ;; esac
END=$(date +%s)
DUR=$((END - START))
if [ "$RC" = 'done' ]; then
	echo "$WRC" > "$D/rc.tmp"
else
	echo "$RC" > "$D/rc.tmp"
fi
echo "$DUR" > "$D/dur.tmp"
# Atomic result publication: rc/dur first, the done marker LAST, so a
# reader never sees done without a complete result (automation atomic-write
# discipline).
mv -f "$D/rc.tmp" "$D/rc"
mv -f "$D/dur.tmp" "$D/dur"
: > "$D/done.tmp"
mv -f "$D/done.tmp" "$D/done"
