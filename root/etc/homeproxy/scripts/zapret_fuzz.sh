#!/bin/sh
# DPI Strategy Fuzzer v3 (ч.70): batch-test nfqws2 strategies and rank them.
#
# Corpus = the shipped /etc/homeproxy/zapret_candidates.json (same pool the
# node.js tester uses): group 'recommended' for a quick fuzz, ALL groups for
# the full one. Each candidate runs ROUNDS isolated passes through
# zapret_test.sh (temp NFQUEUE 209, live firewall untouched, pre-resolved IPs);
# a host PASSES only with a strict majority of rounds (1/1, 2/2, 2/3) so one
# lucky handshake can no longer promote a flaky strategy. One extra BASELINE
# pass (--baseline, no desync) marks hosts that are not DPI-blocked for this
# ISP — such hosts cannot measure a strategy and weigh 10x less in the score.
#
# Writes:
#   /var/run/homeproxy/zapret_fuzz.json        live status {running,done,total,current,rounds}
#   /var/run/homeproxy/zapret_fuzz_result.json final ranking (per-host details, baseline note)
#   /var/run/homeproxy/zapret_fuzz_history.json last 5 runs {ts,mode,rounds,best}
#
# Usage: zapret_fuzz.sh <quick|full> [rounds 1..3, default 2]

MODE="${1:-quick}"
ROUNDS="${2:-2}"
case "$ROUNDS" in 1|2|3) ;; *) ROUNDS=2 ;; esac
MAJ=$(( ROUNDS / 2 + 1 ))
RUN=/var/run/homeproxy
STATUS="$RUN/zapret_fuzz.json"
RESULT="$RUN/zapret_fuzz_result.json"
HISTORY="$RUN/zapret_fuzz_history.json"
CAND=/etc/homeproxy/zapret_candidates.json
TMP=/tmp/zapret_fuzz.$$

[ -f "$CAND" ] || { echo '{"running":false,"done":0,"total":0,"error":"no candidates file"}' > "$STATUS"; exit 0; }
command -v ucode >/dev/null 2>&1 || { echo '{"running":false,"error":"ucode missing"}' > "$STATUS"; exit 0; }

# One ucode pass → "name<TAB>args" lines (TAB cannot occur inside either field).
if [ "$MODE" = "full" ]; then
	PAIRS=$(ucode -e 'import {readfile} from "fs"; let j=json(readfile("'$CAND'")); for (let c in (j.candidates||[])) if (type(c)=="object") print((c.name||"?") + "\t" + c.args + "\n");' 2>/dev/null)
else
	PAIRS=$(ucode -e 'import {readfile} from "fs"; let j=json(readfile("'$CAND'")); for (let c in (j.candidates||[])) if (type(c)=="object" && c.group=="recommended") print((c.name||"?") + "\t" + c.args + "\n");' 2>/dev/null)
fi
TOTAL=$(printf '%s\n' "$PAIRS" | grep -c '[^[:space:]]')
[ "$TOTAL" -lt 1 ] && { echo '{"running":false,"done":0,"total":0,"error":"empty corpus"}' > "$STATUS"; exit 0; }

echo '{"running":true,"done":0,"total":'$TOTAL',"rounds":'$ROUNDS',"current":"resolving test hosts…"}' > "$STATUS"

# zapret_resolve.sh prints {"ok":1,"ips":{"yt":"…",…}} — flatten to "tag=ip …".
RJSON=$(sh /etc/homeproxy/scripts/zapret_resolve.sh 2>/dev/null)
IPS=$(printf '%s' "$RJSON" | ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("/dev/stdin") || ""); } catch (e) { j = null; }
if (!j || j.ok != 1) exit(1);
let parts = [];
for (let k in keys(j.ips || {}))
	if (j.ips[k]) push(parts, k + "=" + j.ips[k]);
print(join(" ", parts));
' 2>/dev/null)
if [ -z "$IPS" ]; then
	echo '{"running":false,"done":0,"total":'$TOTAL',"error":"could not resolve test hosts (DNS not ready?)"}' > "$STATUS"
	exit 0
fi

mkdir -p "$TMP"
printf '%s\n' "$PAIRS" > "$TMP/pairs.tsv"

# One BASELINE pass (no desync): hosts that pass without a strategy are not
# DPI-blocked and cannot credit any strategy. "" = no strategy needed there.
sh /etc/homeproxy/scripts/zapret_test.sh --baseline "" "$IPS" 2>/dev/null > "$TMP/baseline.json"

DONE=0
IDX=0
while IFS='	' read -r NAME STRAT; do
	[ -z "$(printf '%s' "$STRAT" | tr -d '[:space:]')" ] && continue
	IDX=$((IDX + 1))
	for R in $(seq 1 "$ROUNDS"); do
		echo "{\"running\":true,\"done\":$DONE,\"total\":$TOTAL,\"rounds\":$ROUNDS,\"current\":\"$NAME (round $R/$ROUNDS)\"}" > "$STATUS"
		sh /etc/homeproxy/scripts/zapret_test.sh "$STRAT" "$IPS" 2>/dev/null > "$TMP/c${IDX}_${R}.json"
	done
	DONE=$((DONE + 1))
done < "$TMP/pairs.tsv"

# Aggregate + rank — ucode does everything nontrivial (shell cannot escape
# strategy strings safely, and the ч.69 greedy-sed parse of "ok" was WRONG:
# it matched the last per-host flag instead of the top-level count).
ucode -e '
import {readfile, writefile, access} from "fs";
const TMP = "'$TMP'", ROUNDS = int('$ROUNDS'), MAJ = int('$MAJ'), TOTAL = int('$TOTAL');
const RESULT = "'$RESULT'", HISTORY = "'$HISTORY'";
const now = time();

/* corpus order: name \t args per line */
const pairs = [];
const praw = readfile(TMP + "/pairs.tsv") || "";
for (let l in split(praw, "\n")) {
	const p = split(l, "\t");
	if (length(p) >= 2 && length(trim(p[0])))
		push(pairs, { name: p[0], args: p[1] });
}

const parse = (path) => {
	if (!access(path)) return null;
	try { return json(readfile(path) || ""); } catch (e) { return null; }
};

/* baseline: tag → { ok, tls } (hosts passing WITHOUT desync = non-distinguishing) */
const bres = {};
const bj = parse(TMP + "/baseline.json");
if (bj && type(bj.results) == "array")
	for (let r in bj.results)
		if (type(r) == "object" && r.tag)
			bres[r.tag] = { ok: (r.ok == 1), tls: r.tls };

const strategies = [];
for (let n = 0; n < length(pairs); n++) {
	const idx = n + 1;
	/* collect per-host across rounds (results keep the fixed HOSTS order) */
	let per = null;          /* tag → {label, host, ip, votes, tls_min, last_reason} */
	let order = [];
	let total = 0;
	for (let rd = 1; rd <= ROUNDS; rd++) {
		const j = parse(TMP + "/c" + idx + "_" + rd + ".json");
		if (!j || type(j.results) != "array") continue;
		if (!total) total = int(j.total) || 0;
		if (int(j.total) > total) total = int(j.total);
		if (!per) {
			per = {};
			for (let r in j.results)
				if (type(r) == "object" && r.tag) {
					push(order, r.tag);
					per[r.tag] = { label: r.label || r.tag, host: r.host || "", ip: r.ip || "",
					               votes: 0, tls_min: 0, last_reason: "" };
				}
		}
		for (let r in j.results) {
			if (type(r) != "object" || !r.tag || !per[r.tag]) continue;
			const tls = ("" + r.tls) * 1.0;
			if (r.ok == 1) {
				per[r.tag].votes++;
				const ms = int(tls * 1000);
				if (ms > 0 && (per[r.tag].tls_min == 0 || ms < per[r.tag].tls_min))
					per[r.tag].tls_min = ms;
			} else {
				per[r.tag].last_reason = r.reason || "fail";
			}
		}
	}
	if (!total) { total = length(order); }
	let hosts = [], ok = 0, dist_ok = 0, dist_total = 0, tls_sum = 0, tls_n = 0;
	for (let t in order) {
		const p = per[t];
		const host_ok = (p.votes >= MAJ);
		const dist = (bres[t] == null || !bres[t].ok);
		if (host_ok) {
			ok++;
			tls_sum += p.tls_min; tls_n++;
			if (dist) dist_ok++;
		}
		if (dist) dist_total++;
		push(hosts, { tag: t, label: p.label, host: p.host, ok: host_ok,
		              votes: p.votes, rounds: ROUNDS, tls_ms: p.tls_min,
		              reason: host_ok ? "" : (p.last_reason || "fail"), dist: dist });
	}
	/* score: distinguishing successes weigh 1000, already-free hosts 100,
	 * minus the average SUCCESSFUL handshake time (fast winning strategies
	 * rank first among equally-passing ones). */
	const avg = (tls_n > 0) ? int((tls_sum * 1.0) / tls_n) : 0;
	const score = dist_ok * 1000 + (ok - dist_ok) * 100 - int(avg / 10);
	push(strategies, { name: pairs[n].name, args: pairs[n].args, ok: ok, total: total,
	                   dist_ok: dist_ok, dist_total: dist_total,
	                   avg_tls_ms: avg, score: score, hosts: hosts });
}
sort(strategies, (a, b) => b.score - a.score);

const bnote = [];
if (bj && type(bj.results) == "array")
	for (let r in bj.results)
		if (type(r) == "object")
			push(bnote, { tag: r.tag, label: r.label || r.tag, host: r.host || "", ok: (r.ok == 1) });

writefile(RESULT, sprintf("%.J\n", {
	running: false, done: length(strategies), total: length(strategies),
	rounds: ROUNDS, majority: MAJ, ts: now, baseline: bnote, strategies: strategies
}));

/* history: keep the last 5 runs (tmpfs — survives until reboot) */
let hist = [];
if (access(HISTORY)) {
	const hj = parse(HISTORY);
	if (hj && type(hj.runs) == "array") hist = hj.runs;
}
const best = (length(strategies)) ? strategies[0] : null;
push(hist, { ts: now, mode: "'$MODE'", rounds: ROUNDS,
             best: best ? { name: best.name, ok: best.ok, total: best.total,
                            dist_ok: best.dist_ok, dist_total: best.dist_total } : null });
while (length(hist) > 5) shift(hist);
writefile(HISTORY, sprintf("%.J\n", { runs: hist }));
' 2>/dev/null
rm -rf "$TMP"
echo '{"running":false,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS'}' > "$STATUS"
