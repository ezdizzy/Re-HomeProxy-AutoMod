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
# ч.123: the currently applied strategy joins the deep battery (measured
# verdict for what actually serves the user right now).
CURRENT_OPTS=$(uci -q get homeproxy.config.zapret_cmd_opts 2>/dev/null)
RUN=/var/run/homeproxy
STATUS="$RUN/zapret_fuzz.json"
RESULT="$RUN/zapret_fuzz_result.json"
HISTORY="$RUN/zapret_fuzz_history.json"
CAND=/etc/homeproxy/zapret_candidates.json
TMP=/tmp/zapret_fuzz.$$

[ -f "$CAND" ] || { echo '{"running":false,"done":0,"total":0,"error":"no candidates file"}' > "$STATUS"; exit 0; }
command -v ucode >/dev/null 2>&1 || { echo '{"running":false,"error":"ucode missing"}' > "$STATUS"; exit 0; }

# Ф6.4 Test Resource Manager (audit 80): the sweep OWNS its temp queue for the
# whole run — an import/generate started in parallel can no longer kill this
# nfqws2 instance (each task gets its own qnum from the pool, kills are
# ownership-checked). Release runs on EVERY exit path via the trap.
RQNUM=$(ucode -e 'import {acquire} from "/etc/homeproxy/scripts/test_resmgr.uc"; print(sprintf("%.J", acquire("fuzz")));' 2>/dev/null | sed -n 's/.*"qnum":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
case "$RQNUM" in ''|*[!0-9]*)
	# the acquire SUCCEEDED-then-mis-parsed case would leak the queue —
	# release by task name regardless (idempotent for the owner only).
	ucode -e 'import {status, release} from "/etc/homeproxy/scripts/test_resmgr.uc"; let st = status(); for (let q in keys(st.queues)) if (st.queues[q] != null && st.queues[q].task === "fuzz") release(q, "fuzz");' >/dev/null 2>&1
	echo '{"running":false,"done":0,"total":0,"error":"no free test queue (209-212) - another lab task is running"}' > "$STATUS"
	exit 0 ;;
esac
release_resmgr() {
	[ -n "$RQNUM" ] && ucode -e "import {release} from '/etc/homeproxy/scripts/test_resmgr.uc'; release($RQNUM, 'fuzz');" >/dev/null 2>&1
	return 0
}
trap release_resmgr EXIT INT TERM
# Audit (2026-11-07): the acquired queue rode along as a MUTEX only — every
# zapret_test.sh call still defaulted to qnum 209, so a manual test holding
# 209 collided with the sweep (two nfqws2 on one queue, one cleanup killed
# the other's probes). The acquired queue is now the ACTUAL test queue.
TEST_QNUM="$RQNUM"
export TEST_QNUM

# One ucode pass → "name<TAB>group<TAB>args" lines (TAB cannot occur inside
# any field). ч.129: the GROUP rides along — the deep battery selection must
# measure the best IMPORTED and GENERATED strategies too, not only the top
# of the (tie-prone) handshake score.
if [ "$MODE" = "full" ]; then
	PAIRS=$(ucode -e 'import {readfile} from "fs"; let j=json(readfile("'$CAND'")); for (let c in (j.candidates||[])) if (type(c)=="object") print((c.name||"?") + "\t" + (c.group||"") + "\t" + c.args + "\n");' 2>/dev/null)
else
	PAIRS=$(ucode -e 'import {readfile} from "fs"; let j=json(readfile("'$CAND'")); for (let c in (j.candidates||[])) if (type(c)=="object" && c.group=="recommended") print((c.name||"?") + "\t" + (c.group||"") + "\t" + c.args + "\n");' 2>/dev/null)
fi
TOTAL=$(printf '%s\n' "$PAIRS" | grep -c '[^[:space:]]')
[ "$TOTAL" -lt 1 ] && { echo '{"running":false,"done":0,"total":0,"error":"empty corpus"}' > "$STATUS"; exit 0; }

echo '{"running":true,"done":0,"total":'$TOTAL',"rounds":'$ROUNDS',"current":"resolving test hosts…"}' > "$STATUS"

# zapret_resolve.sh prints {"ok":1,"ips":{…},"ips2":{…},"dns":{…}} —
# flatten the primary IPs to "tag=ip …"; the SECOND IPs (audit 85: finalists
# on a different edge) and the DNS-SETS comparison (audit 58) ride into the
# merge THROUGH FILES (never shell-injected — the JSON carries quotes).
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
printf '%s' "$RJSON" > "$TMP/resolve.json" 2>/dev/null || { mkdir -p "$TMP"; printf '%s' "$RJSON" > "$TMP/resolve.json"; }
IPS2=$(ucode -e '
import {readfile} from "fs";
let j = json(readfile("'$TMP'/resolve.json") || "");
if (j == null || type(j.ips2) != "object") exit(0);
let parts = [];
for (let k in keys(j.ips2 || {}))
	if (j.ips2[k]) push(parts, k + "=" + j.ips2[k]);
print(join(" ", parts));
' 2>/dev/null)
# Ф6.4 QUIC baseline (audit 61): the sweep-level UDP/443 verdict measured
# BEFORE any candidate runs on our queue — the per-strategy A/B below is
# compared against THIS, not against a guess.
YIP=$(printf '%s\n' "$IPS" | tr ' ' '\n' | sed -n 's/^yt=//p' | head -n 1)
if [ -n "$YIP" ] && [ -x /usr/bin/probe_pool ]; then
	sh /etc/homeproxy/scripts/zapret_test.sh --quic "" "yt=$YIP" 2>/dev/null > "$TMP/quic_base.json"
	grep -q '^{"ok"' "$TMP/quic_base.json" 2>/dev/null || rm -f "$TMP/quic_base.json"
fi

mkdir -p "$TMP"
printf '%s\n' "$PAIRS" > "$TMP/pairs.tsv"
# ч.123: the CURRENT strategy crosses to the rank pass THROUGH A FILE — a
# shell-injected string (the old `"'$CURRENT_OPTS'"` form) breaks the ucode
# quoting the moment a strategy carries a `"`/`'`/`$` (the sweep would die
# with an obscure ucode error instead of ranking). The UCI value is stored
# in SHELL-QUOTED form (`'arg1' 'arg2' ...` — init.d eval-splits it), so the
# literal quotes are stripped HERE (tr), before any ucode comparison/regex
# (`^--[a-z]` never matches a string starting with a quote).
printf '%s' "$CURRENT_OPTS" | tr -d "'" > "$TMP/current_opts.txt"

# One BASELINE pass (no desync): hosts that pass without a strategy are not
# DPI-blocked and cannot credit any strategy. "" = no strategy needed there.
sh /etc/homeproxy/scripts/zapret_test.sh --baseline "" "$IPS" 2>/dev/null > "$TMP/baseline.json"

# Honest probe mode (skuid|fallback) — the tester reports it in every result
# JSON; the fallback (no isolated uid) touches only router-origin root dials
# since the OUTPUT-hook fix, but the ranking noise and the residual router-
# side class must be visible in the UI.
PMODE=$(sed -n 's/.*"probe":[[:space:]]*"\([a-z]*\)".*/\1/p' "$TMP/baseline.json" 2>/dev/null | head -n 1)
case "$PMODE" in skuid|fallback) ;; *) PMODE="skuid" ;; esac
if [ "$PMODE" = "fallback" ]; then
	echo '{"running":true,"done":0,"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"fallback","current":"resolving test hosts… (fallback probe mode)"}' > "$STATUS"
fi

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
# ч.109: TWO passes — pass 1 ranks by handshakes and writes the top-5 list;
# the shell then runs the DEEP content battery on those five (a handshake
# passing is not «ресурс работает» — the page, the thumbnail CDN and the
# video edge must load); pass 2 merges the deep verdicts and finalizes the
# ranking (deep-verified first). The corpus keeps the RANKING DEPTH: the
# resource auto-pick prefers deep-verified winners.
echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"rank","current":"ranking…"}' > "$STATUS"
ucode -e '
import {readfile, writefile, access} from "fs";
import { samples_stats } from "/etc/homeproxy/scripts/strategy_lab.uc";
const TMP = "'$TMP'", ROUNDS = int('$ROUNDS'), MAJ = int('$MAJ'), TOTAL = int('$TOTAL');
/* ч.123: the CURRENT strategy comes from the file the shell wrote — with
 * the shell-quoting already stripped there (see the tr above). */
const CURRENT_OPTS = trim(readfile(TMP + "/current_opts.txt") || "");
const now = time();

/* corpus order: name \t group \t args per line (ч.129: the group rides
 * along for the deep battery selection) */
const pairs = [];
const praw = readfile(TMP + "/pairs.tsv") || "";
for (let l in split(praw, "\n")) {
	const p = split(l, "\t");
	if (length(p) >= 3 && length(trim(p[0])))
		push(pairs, { name: p[0], group: p[1], args: p[2] });
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
	/* collect per-host across rounds (results keep the fixed HOSTS order).
	 * Ф6.4 (аудит 66): the rating uses the SERIES (median/P90/success rate/
	 * jitter) instead of the best single measurement — the round samples are
	 * kept per tag and reduced by strategy_lab.samples_stats (ONE stats
	 * implementation for the whole project). */
	let per = null;          /* tag → {label, host, ip, votes, tls_min, last_reason, times, oks} */
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
					               votes: 0, tls_min: 0, last_reason: "", times: [], oks: [] };
				}
		}
		for (let r in j.results) {
			if (type(r) != "object" || !r.tag || !per[r.tag]) continue;
			const tls = ("" + r.tls) * 1.0;
			const oksv = (r.ok == 1) ? 1 : 0;
			push(per[r.tag].times, tls * 1000.0);
			push(per[r.tag].oks, oksv);
			if (oksv == 1) {
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
		/* Ф6.4 (аудит 66): the series stats per host — ONE implementation
		 * (strategy_lab.samples_stats); tls_ms keeps the historical min for
		 * the compatibility readers, median_ms is the honest rating value.
		 * The RAW round samples ride along for dims_of in the merge. */
		const sst = samples_stats(p.times, p.oks);
		const rr = [];
		for (let ri = 0; ri < length(p.times); ri++)
			push(rr, { ok: p.oks[ri], tls_ms: p.times[ri] });
		if (host_ok) {
			ok++;
			tls_sum += p.tls_min; tls_n++;
			if (dist) dist_ok++;
		}
		if (dist) dist_total++;
		push(hosts, { tag: t, label: p.label, host: p.host, ok: host_ok,
		              votes: p.votes, rounds: ROUNDS, tls_ms: p.tls_min,
		              median_ms: int(sst.median), p90_ms: int(sst.p90),
		              jitter_ms: int(sst.jitter), ok_rate: sst.ok_rate,
		              samples: rr,
		              reason: host_ok ? "" : (p.last_reason || "fail"), dist: dist });
	}
	/* score: distinguishing successes weigh 1000, already-free hosts 100,
	 * minus the average SUCCESSFUL handshake time (fast winning strategies
	 * rank first among equally-passing ones). */
	const avg = (tls_n > 0) ? int((tls_sum * 1.0) / tls_n) : 0;
	const score = dist_ok * 1000 + (ok - dist_ok) * 100 - int(avg / 10);
	push(strategies, { name: pairs[n].name, group: pairs[n].group, args: pairs[n].args,
	                   ok: ok, total: total,
	                   dist_ok: dist_ok, dist_total: dist_total,
	                   avg_tls_ms: avg, score: score, hosts: hosts });
}
sort(strategies, (a, b) => b.score - a.score);
/* ч.123: the deep battery is NOT just the handshake top-5 anymore — a
 * fast handshake does not predict a fast flow (the ч.116 live fact), so
 * the strategies worth MEASURING are chosen beyond the handshake order.
 * ч.129 rework (the live full-sweep fact: score 2984 shared by ~32
 * strategies — the old "top-5" was four multisplit-family strategies
 * picked by avg-TLS noise, so the whole deep battery measured one
 * technique family while the felt-fast strategies of OTHER families
 * were never measured and could never win):
 *   1. up to 5 best-ranked strategies, one per DISTINCT technique family;
 *   2. the remaining slots of that five filled by rank order;
 *   3. the first strategy of every OTHER family (all 8 families get a
 *      measured verdict);
 *   4. the best-ranked IMPORTED and GENERATED strategy — the catalogs
 *      the user brought in must be measured too;
 *   5. the CURRENTLY APPLIED strategy (single-block only) if not already
 *      listed — the user must always see its measured verdict.
 * Every pick requires at least one passing handshake host (ok > 0).
 * The list keeps the INDEX into rank.json strategies: the pass-2 merge
 * maps d<i>.json back through it. */
/* ч.129 FIX #2: the patterns are method-anchored (desync=METHOD) — the
 * method follows "=" in --lua-desync=METHOD:…, so the old /--method/
 * patterns matched NOTHING and the whole family selection was a silent
 * no-op since ч.123 (the deep battery stayed the bare handshake top-5).
 * hostfakesplit/fakesplit stay AHEAD of fake: "desync=fake" must not
 * swallow them (it does not — "host…" breaks the prefix — but the order
 * keeps the intent explicit). */
const FAM = [
	[ "syndata", /desync=syndata/ ],
	[ "multisplit", /desync=multisplit/ ],
	[ "hostfakesplit", /desync=hostfakesplit/ ],
	[ "fakesplit", /desync=fakesplit/ ],
	[ "disorder", /desync=multidisorder/ ],
	[ "seg2split", /desync=seg2split/ ],
	/* fakedsplit BEFORE fake: /desync=fake/ is a PREFIX of "desync=fakedsplit"
	 * (the community fake+fakedsplit candidate would silently join the fake
	 * family and never get its own measured slot). */
	[ "fakedsplit", /desync=fakedsplit/ ],
	[ "fake", /desync=fake/ ],
	[ "oob", /desync=oob/ ]
];
/* ч.129 FIX: family detection reads ONLY the TLS/UDP desync profiles —
 * every corpus strategy carries the HTTP profile --filter-tcp=80 …
 * --lua-desync=multisplit:pos=method+2, so matching the raw args made
 * EVERY strategy "multisplit" and the family diversity selection
 * degenerated into the rank order (the old ч.123 selection measured
 * four multisplit strategies and called them four families). */
const fam_of = (args) => {
	let s = "";
	for (let seg in split("" + args, /--new/))
		if (index(seg, "--filter-tcp=80") < 0)
			s += " " + seg;
	for (let f in FAM)
		if (match(s, f[1]))
			return f[0];
	return null;
};
const fams_seen = {};
let covered = [];
/* 1. family-diverse leaders */
for (let i = 0; i < length(strategies) && length(covered) < 5; i++) {
	if (int(strategies[i].ok) <= 0) continue;
	const f = fam_of(strategies[i].args || "");
	if (f != null) {
		if (fams_seen[f]) continue;
		fams_seen[f] = true;
	}
	push(covered, i + 1);
}
/* 2. fill the five by rank order */
for (let i = 0; i < length(strategies) && length(covered) < 5; i++) {
	if (int(strategies[i].ok) <= 0 || index(covered, i + 1) >= 0) continue;
	push(covered, i + 1);
}
/* 3. the remaining families */
for (let i = 0; i < length(strategies) && length(keys(fams_seen)) < 9; i++) {
	if (int(strategies[i].ok) <= 0 || index(covered, i + 1) >= 0) continue;
	const f = fam_of(strategies[i].args || "");
	if (f == null || fams_seen[f]) continue;
	fams_seen[f] = true;
	push(covered, i + 1);
}
/* 4. the best imported and generated strategy (the user catalogs) */
for (let gi in ["imported", "generated"]) {
	for (let i = 0; i < length(strategies); i++) {
		if (strategies[i].group != gi || int(strategies[i].ok) <= 0) continue;
		if (index(covered, i + 1) < 0)
			push(covered, i + 1);
		break;
	}
}
const cur_args = trim(CURRENT_OPTS);
if (length(cur_args) > 3 && index(cur_args, "--new") < 0 &&
	match(cur_args, /^--[a-z]/)) {
	let dup = false;
	for (let i = 0; i < length(strategies); i++)
		if (strategies[i].args === cur_args) {
			if (index(covered, i + 1) < 0)
				push(covered, i + 1);
			dup = true;
			break;
		}
	if (!dup) {
		/* the live strategy is not in this corpus — measure it as an extra
		 * run beyond the ranked list (idx 0 = "not a rank.json entry") */
		push(strategies, { name: "current (applied)", group: "", args: cur_args,
			ok: 0, total: 0, dist_ok: 0, dist_total: 0, avg_tls_ms: 0,
			score: 0, hosts: [] });
		push(covered, length(strategies));
	}
}
/* ч.129 FIX: rank.json is written AFTER the current-strategy append —
 * the merge maps d<i>.json through deep_list.json indexes into THIS
 * array, and the old order (write first, append after) made the merge
 * silently drop the measured verdict of the current strategy forever. */
writefile(TMP + "/rank.json", sprintf("%.J\n", { strategies: strategies, ts: now }));
/* ч.129 FIX (🔴 lesson 20/31 hit the ч.123 code): for-in over an ARRAY
 * yields ELEMENTS — the old `for (let i in covered) { idx: covered[i] … }`
 * read covered[element] (an off-by-one NEIGHBOUR as the deep-verdict owner,
 * and broken entries for the last items — the silent "?" cases). Count by
 * index explicitly. */
const deep_list = [];
for (let n = 0; n < length(covered); n++)
	push(deep_list, { idx: covered[n], args: strategies[covered[n] - 1].args });
writefile(TMP + "/deep_list.json", sprintf("%.J\n", { list: deep_list }));
/* top-5 for the deep content battery — kept for compatibility readers */
let top5 = [];
for (let i = 0; i < length(strategies) && i < 5; i++)
	push(top5, { idx: i + 1, args: strategies[i].args });
writefile(TMP + "/top5.json", sprintf("%.J\n", { list: top5 }));
' 2>/dev/null

if [ ! -s "$TMP/rank.json" ]; then
	rm -rf "$TMP"
	echo '{"running":false,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"error":"ranking failed"}' > "$STATUS"
	exit 0
fi

# Deep content battery (TWO full passes — the deciding metrics are single-
# pass medians otherwise, and a ~2x TSPU regime swing between runs flips the
# >25% START verdict; two passes a battery-length apart average that out —
# the audit of the "probe says Default, reality says Hostfakesplit" report).
# ч.123: the battery list is deep_list.json — the handshake top-5 PLUS up to
# 2 representatives of distinct technique families PLUS the currently applied
# strategy (see the rank pass above). d<i>.json / d<i>b.json map back through
# the list; the merge averages what both passes measured.
TOPN=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); print(length((j && j.list) || 0));' 2>/dev/null)
YTV_URL=$(ucode /etc/homeproxy/scripts/yt_stream_probe.uc get 2>/dev/null | ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("/dev/stdin") || ""); } catch (e) { j = null; }
if (j && j.ok && j.url) print(j.url);
' 2>/dev/null)
if [ -z "$YTV_URL" ]; then
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","note":"deep battery: page/CDN/edge + the sustained-flow throughput probe (the real-stream URL is unavailable)"}' > "$STATUS"
else
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","note":"deep battery includes the real video-stream probe"}' > "$STATUS"
fi
# deep_pass <suffix> <pass#> — one full battery pass; results land in d<i><suf>.json.
deep_pass() {
	i=0
	while [ "$i" -lt "$TOPN" ]; do
		i=$((i + 1))
		ARGS=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); let e = (j && j.list) ? j.list['"$((i-1))"'] : null; print(e ? e.args : "");' 2>/dev/null)
		[ -z "$(printf '%s' "$ARGS" | tr -d '[:space:]')" ] && continue
		echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","done2":'$i',"total2":'$TOPN',"current":"deep check '"$i"'/'"$TOPN"' (pass '"$2"')"}' > "$STATUS"
		YTV_URL="$YTV_URL" sh /etc/homeproxy/scripts/zapret_test.sh --deep "$ARGS" "$IPS" 2>/dev/null > "$TMP/d$i$1.json"
	done
}
# deep_retry <suffix> <pass#> — one retry per failed/empty run (ч.129: a deep
# run can die mid-sweep; the merge counts what still failed honestly).
deep_retry() {
	i=0
	while [ "$i" -lt "$TOPN" ]; do
		i=$((i + 1))
		NEED=$(ucode -e 'import {readfile, access} from "fs";
let ok = 0;
const p = "'$TMP'/d'"$i$1"'.json";
if (access(p)) {
	let j = null;
	try { j = json(readfile(p) || ""); } catch (e) { j = null; }
	if (j && type(j.results) == "array" && length(j.results) > 0) {
		let items = 0, alive = 0;
		for (let r in j.results) {
			if (type(r) != "object") continue;
			for (let it in (r.deep || [])) {
				if (type(it) != "object" || it.id == null) continue;
				items++;
				const cc = "" + (it.code || "");
				if (length(cc) && cc != "0" && cc != "000") alive++;
			}
		}
		if (items > 0 && alive > 0) ok = 1;
	}
}
print(ok ? "0" : "1");' 2>/dev/null)
		[ "$NEED" = "1" ] || continue
		ARGS=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); let e = (j && j.list) ? j.list['"$((i-1))"'] : null; print(e ? e.args : "");' 2>/dev/null)
		[ -z "$(printf '%s' "$ARGS" | tr -d '[:space:]')" ] && continue
		echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","done2":'$i',"total2":'$TOPN',"current":"deep retry '"$i"'/'"$TOPN"' (pass '"$2"')"}' > "$STATUS"
		YTV_URL="$YTV_URL" sh /etc/homeproxy/scripts/zapret_test.sh --deep "$ARGS" "$IPS" 2>/dev/null > "$TMP/d$i$1.json"
	done
}
deep_pass "" 1
deep_retry "" 1
deep_pass "b" 2
deep_retry "b" 2

# Ф6.4 (audit 84): CONTROL baseline — the baseline is a SERIES, not a single
# measurement: a host passing baseline #1 but failing the control (or vice
# versa) is DRIFT, and the free-pass credit requires BOTH passes (the merge
# recomputes dist conservatively and reports the drift honestly).
echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"control","current":"контрольный baseline…"}' > "$STATUS"
sh /etc/homeproxy/scripts/zapret_test.sh --baseline "" "$IPS" 2>/dev/null > "$TMP/control.json"

# Ф6.4 (audit 85): the finalists on the SECOND edge/IP — one IP per sweep
# made the whole ranking a single-CDN measurement. Plain handshake pass per
# deep-tested strategy on the alternative addresses.
if [ -n "$IPS2" ]; then
	i=0
	while [ "$i" -lt "$TOPN" ]; do
		i=$((i + 1))
		ARGS=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); let e = (j && j.list) ? j.list['"$((i-1))"'] : null; print(e ? e.args : "");' 2>/dev/null)
		[ -z "$(printf '%s' "$ARGS" | tr -d '[:space:]')" ] && continue
		echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"alt-ip","done2":'$i',"total2":'$TOPN',"current":"второй IP '"$i"'/'"$TOPN"'"}' > "$STATUS"
		sh /etc/homeproxy/scripts/zapret_test.sh "$ARGS" "$IPS2" 2>/dev/null > "$TMP/a$i.json"
	done
fi

# Ф6.4 (audit 61): QUIC A/B per finalist carrying a UDP profile — the
# strategy's own mangling on the temp queue vs the sweep baseline verdict
# (quic_base.json, measured before any candidate ran). A strategy WITHOUT a
# UDP profile honestly skips the A/B (it does not touch QUIC at all).
if [ -n "$YIP" ]; then
	i=0
	while [ "$i" -lt "$TOPN" ]; do
		i=$((i + 1))
		ARGS=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); let e = (j && j.list) ? j.list['"$((i-1))"'] : null; print(e ? e.args : "");' 2>/dev/null)
		[ -z "$(printf '%s' "$ARGS" | tr -d '[:space:]')" ] && continue
		case "$ARGS" in *--filter-udp=443*) ;; *) continue ;; esac
		echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"quic","done2":'$i',"total2":'$TOPN',"current":"QUIC A/B '"$i"'/'"$TOPN"'"}' > "$STATUS"
		sh /etc/homeproxy/scripts/zapret_test.sh --quic "$ARGS" "yt=$YIP" 2>/dev/null > "$TMP/q$i.json"
	done
fi

ucode -e '
import {readfile, writefile, access} from "fs";
import { samples_stats, dims_of, resource_verdict, strategy_verdict, engine_can } from "/etc/homeproxy/scripts/strategy_lab.uc";
const TMP = "'$TMP'", RESULT = "'$RESULT'", HISTORY = "'$HISTORY'";
const ROUNDS = int('$ROUNDS'), MAJ = int('$MAJ');
const now = time();
const parse = (path) => {
	if (!access(path)) return null;
	try { return json(readfile(path) || ""); } catch (e) { return null; }
};

/* Pass 2 — merge the deep content verdicts into the handshake ranking.
 * d<i>.json corresponds to rank.json strategies[i-1] (the top5 order).
 * ч.116: probes are compared ACROSS the deep-tested strategies FIRST —
 * a probe every strategy passed (or none passed) is NOT differential and
 * must not rank strategies (ч.110 live fact: the ~1 MB YouTube page fetch
 * failed for ALL top-5 on the live ISP, which dragged every deep verdict
 * equally and let the raw TLS tie-break promote a strategy that throttles
 * the actual video stream). The merge keeps the RAW items for the tooltip
 * and ranks by the differential-only deep ratio. */
const rank = parse(TMP + "/rank.json") || { strategies: [] };
const strategies = rank.strategies || [];
/* ч.123: d<i>.json maps through deep_list.json (idx into rank.json), NOT
 * positionally — the battery now covers the top-5 + family reps + the
 * current strategy. */
const dlist = parse(TMP + "/deep_list.json");
const dlist_items = (dlist && type(dlist.list) === "array") ? dlist.list : [];
let deepN = 0;
const drawn = [];
const deep_failed = [];
for (let i = 1; i <= length(dlist_items); i++) {
	const d = parse(TMP + "/d" + i + ".json");
	const ent = dlist_items[i - 1];
	const ent_s = (ent && ent.idx > 0) ? strategies[ent.idx - 1] : null;
	if (!d || type(d.results) != "array" || !ent || !ent_s) {
		push(deep_failed, (ent_s != null) ? ("" + (ent_s.name || "custom args")) : "?");
		continue;
	}
	/* The SECOND battery pass (d<i>b.json) — averaged into the deciding
	 * metrics; a missing/failed second pass degrades to the first one. */
	let d2res = null;
	const d2 = parse(TMP + "/d" + i + "b.json");
	if (d2 && type(d2.results) == "array" && length(d2.results) > 0)
		d2res = d2.results;
	push(drawn, { s: ent_s, results: d.results, results2: d2res, passes: (d2res != null) ? 2 : 1 });
	deepN++;
}
/* Ф6.4: the sweep-level QUIC baseline verdict — measured BEFORE any
 * candidate ran on our queue (zapret_test.sh --quic with no strategy),
 * read from the FILE the shell wrote (never shell-injected). Shape kept
 * compatible for the readers: {verdict: 'vn'|'icmp'|'silence'|''}. */
let quic = null;
if (access(TMP + "/quic_base.json")) {
	const qb = parse(TMP + "/quic_base.json");
	if (qb != null && type(qb) === "object" && qb.quic != null) {
		const qvs = '' + qb.quic;
		/* Ф6.4 defensive (live fact): ucode json() accepts a bare NaN token —
		 * only the three honest verdicts pass; anything else = unmeasured. */
		if (qvs === "vn" || qvs === "icmp" || qvs === "silence")
			quic = { verdict: qvs };
	}
}
const probe_cnt = {};
for (let r in drawn)
	for (let res in r.results) {
		if (type(res) != "object" || res.tag == null) continue;
		for (let it in (res.deep || [])) {
			if (type(it) != "object" || it.id == null) continue;
			const pc = probe_cnt[it.id] || { have: 0, ok: 0 };
			pc.have++;
			if (it.ok == 1) pc.ok++;
			probe_cnt[it.id] = pc;
		}
	}
const diff_ids = {};
for (let id in keys(probe_cnt))
	if (probe_cnt[id].ok > 0 && probe_cnt[id].ok < probe_cnt[id].have)
		diff_ids[id] = true;
const skipped_ids = [];
for (let id in keys(probe_cnt))
	if (!diff_ids[id])
		push(skipped_ids, id);
for (let r in drawn) {
	const s = r.s;
	let dok = 0, dtot = 0, hosts = [];
	/* One result entry → the metric set the merge ranks by (the per-item
	 * collection from the pre-two-pass code, extracted verbatim). */
	const collect = (res) => {
		let hdok = 0, dtot_h = 0, stream = 0, start_ms = 0, stream2 = 0, vstart = 0;
		for (let it in (res.deep || [])) {
			if (type(it) != "object" || it.id == null) continue;
			if ((it.id == "ytv" || it.id == "yts") && int(it.speed || 0) > stream)
				stream = int(it.speed || 0);
			if (it.id == "ytv" && int(it.ttfb || 0) > start_ms)
				start_ms = int(it.ttfb || 0);
			if ((it.id == "yts" || it.id == "yts2") && int(it.ttfb || 0) > vstart)
				vstart = int(it.ttfb || 0);
			if (it.id == "yts2" && int(it.speed || 0) > stream2)
				stream2 = int(it.speed || 0);
			if (!diff_ids[it.id]) continue;
			dtot_h++;
			if (it.ok == 1) hdok++;
		}
		return { hdok: hdok, dtot_h: dtot_h, stream: stream, start_ms: start_ms,
			stream2: stream2, vstart: vstart };
	};
	for (let res in r.results) {
		if (type(res) != "object" || res.tag == null) continue;
		const m1 = collect(res);
		/* The matching entry of the SECOND pass — metrics AVERAGE over both
		 * (int mean), the deep verdict counts SUM (2 passes = 2x items). */
		let m2 = null;
		if (r.results2 != null)
			for (let res2 in r.results2)
				if (type(res2) == "object" && res2.tag == res.tag) { m2 = collect(res2); break; }
		let stream = m1.stream, start_ms = m1.start_ms, stream2 = m1.stream2, vstart = m1.vstart;
		let hok = m1.hdok, htot = m1.dtot_h;
		if (m2 != null) {
			if (int(m2.stream) > 0) stream = (stream > 0) ? int((stream + m2.stream) / 2) : m2.stream;
			if (int(m2.start_ms) > 0) start_ms = (start_ms > 0) ? int((start_ms + m2.start_ms) / 2) : m2.start_ms;
			if (int(m2.stream2) > 0) stream2 = (stream2 > 0) ? int((stream2 + m2.stream2) / 2) : m2.stream2;
			if (int(m2.vstart) > 0) vstart = (vstart > 0) ? int((vstart + m2.vstart) / 2) : m2.vstart;
			hok += m2.hdok;
			htot += m2.dtot_h;
			dok += m2.hdok;
			dtot += m2.dtot_h;
		}
		dok += m1.hdok;
		dtot += m1.dtot_h;
		push(hosts, { tag: res.tag, label: res.label || res.tag,
			deep_ok: (htot > 0 && hok == htot),
			deep_pass: hok, deep_total: htot,
			deep_total_raw: int(res.deep_total) || 0,
			stream: stream, start_ms: start_ms,
			stream2: stream2, stream_start_ms: vstart, items: res.deep || [] });
		if (res.tag == "yt") {
			s.stream = stream;
			s.start_ms = start_ms;
			if (stream2 > 0) s.stream2 = stream2;
			if (vstart > 0) s.stream_start_ms = vstart;
		}
	}
	s.deep = { ok: dok, total: dtot, hosts: hosts, passes: r.passes };
}
/* ── Ф6.4 v3: измерения, второй IP, QUIC A/B, вердикты ─────────────────── */

/* (аудит 84) baseline-СЕРИЯ: контрольный проход после прогона; хост,
 * расходящийся между двумя baseline, — ДРЕЙФ и теряет бесплатный зачёт
 * (консервативно: dist = хост НЕ прошёл ХОТЯ БЫ один из двух baseline;
 * free-pass требует ОБОИХ). */
const base1 = parse(TMP + "/baseline.json");
const ctrl = parse(TMP + "/control.json");
const b1map = {}, c2map = {};
if (base1 && type(base1.results) == "array")
	for (let r in base1.results)
		if (type(r) == "object" && r.tag) b1map[r.tag] = (r.ok == 1);
const drift = [];
if (ctrl && type(ctrl.results) == "array")
	for (let r in ctrl.results)
		if (type(r) == "object" && r.tag) {
			c2map[r.tag] = (r.ok == 1);
			if (b1map[r.tag] != null && b1map[r.tag] !== c2map[r.tag])
				push(drift, { tag: r.tag, first: (b1map[r.tag] == true), control: (c2map[r.tag] == true) });
		}
for (let s in strategies)
	for (let h in s.hosts) {
		const b1 = (b1map[h.tag] != null) ? b1map[h.tag] : false;
		const b2 = (c2map[h.tag] != null) ? c2map[h.tag] : false;
		h.dist = !(b1 && b2);
	}

/* (аудит 85) второй IP финалистов: ручной проход по альтернативным адресам
 * подливается в host-записи (ip2/alt-статистика) — рейтинг больше не
 * измерение одного-единственного CDN-края. */
for (let i = 1; i <= length(dlist_items); i++) {
	const ent = dlist_items[i - 1];
	const s = (ent && ent.idx > 0) ? strategies[ent.idx - 1] : null;
	if (s == null) continue;
	const aj = parse(TMP + "/a" + i + ".json");
	if (aj && type(aj.results) == "array")
		for (let r in aj.results) {
			if (type(r) != "object" || r.tag == null) continue;
			for (let h in s.hosts)
				if (h.tag == r.tag) {
					h.ip2 = r.ip || "";
					h.alt_ok = (r.ok == 1);
					h.alt_tls_ms = int((("" + r.tls) * 1.0) * 1000);
					h.alt_reason = (r.ok == 1) ? "" : (r.reason || "fail");
				}
		}
	/* (аудит 61) QUIC A/B: стратегия с UDP-профилем на очереди против
	 * sweep-baseline; стратегии без UDP-профиля честно не участвуют. */
	if (match(s.args || "", /--filter-udp=443/)) {
		const qj = parse(TMP + "/q" + i + ".json");
		if (qj != null && type(qj) === "object" && qj.quic != null)
			s.quic_ab = { strategy: '' + qj.quic,
				baseline: (quic != null && quic.verdict != null) ? quic.verdict : "" };
	}
}

/* ЧЕТЫРЕ ИЗМЕРЕНИЯ (аудит 66/71) на каждую стратегию и ресурс — одним
 * кодом (strategy_lab.dims_of; сырые раунды уже в rank.json-хостах). */
for (let s in strategies) {
	s.dims = {};
	for (let h in s.hosts) {
		let deep_h = null;
		if (s.deep && type(s.deep.hosts) === "array")
			for (let dh in s.deep.hosts)
				if (dh.tag === h.tag) deep_h = dh;
		s.dims[h.tag] = dims_of(h.samples || [], deep_h, "zapret");
	}
}

/* Final order: deep-tested strategies first (deep ratio, then handshake
 * score), the rest keep their handshake rank order. */
const tested = [], rest = [];
for (let s in strategies)
	(s.deep) ? push(tested, s) : push(rest, s);
sort(tested, (a, b) => {
	const ra = a.deep.total ? (a.deep.ok * 1.0 / a.deep.total) : 0;
	const rb = b.deep.total ? (b.deep.ok * 1.0 / b.deep.total) : 0;
	if (ra != rb)
		return rb - ra;
	/* ч.116: equal deep verdicts → a MEASURED verdict decides (the TLS
	 * handshake time does not predict the throttled flow).
	 * ч.129: the fresh-connection START latency is what the user FEELS
	 * first («навожу на карточку — превью не стартует») — a >25% better
	 * START wins outright; a smaller gap is bursty TSPU noise (tie). The
	 * sustained flow decides next at a >10% gap, then the handshake.
	 * The old order (flow first, START only inside a 10% flow tie) kept a
	 * strategy with a fast keep-alive bulk but a slow every-fresh-
	 * connection start on top — exactly the reported complaint. */
	const ta = int(a.start_ms || 0), tb = int(b.start_ms || 0);
	if (ta > 0 && tb > 0 && ta != tb) {
		const hi = (ta > tb) ? ta : tb, lo = (ta > tb) ? tb : ta;
		if (hi - lo > int(hi / 4))
			return ta - tb;
	}
	/* Ф6.4 (замер пользователя 2026-11-04): the VIDEO-edge START (yts/yts2
	 * ttfb) decides next at the same >25% margin — the preview START does
	 * not cover the videoplayback edges (the user: «на Hostfakesplit видео
	 * открывается быстро, на победителе — долго»). */
	const va = int(a.stream_start_ms || 0), vb = int(b.stream_start_ms || 0);
	if (va > 0 && vb > 0 && va != vb) {
		const hi = (va > vb) ? va : vb, lo = (va > vb) ? vb : va;
		if (hi - lo > int(hi / 4))
			return va - vb;
	}
	const sa = int(a.stream || 0), sb = int(b.stream || 0);
	if (sa != sb) {
		if (sa > 0 && sb > 0) {
			const hi = (sa > sb) ? sa : sb, lo = (sa > sb) ? sb : sa;
			if (hi - lo > int(hi / 10))
				return sb - sa;
		} else if (sa > 0 || sb > 0)
			return sb - sa;
	}
	return (int(a.avg_tls_ms || 0) - int(b.avg_tls_ms || 0)) || (b.score - a.score);
});
const final = [];
for (let s in tested) push(final, s);
for (let s in rest) push(final, s);
/* Финалисты получают ВЕРДИКТ по каждому ресурсу (аудит 92):
 * best_verified / best_available / no_candidate. */
const RES_TAGS = { youtube: "yt", discord: "dc", telegram: "tg", general: null };
const udp_any = (function () {
	for (let s in strategies)
		if (match(s.args || "", /--filter-udp=443/)) return true;
	return false;
})();
const qv = (quic != null && quic.verdict != null) ? quic.verdict : "";
/* Verdicts walk the FINAL order (deep-tested first, the visible table
 * head) — chosen must match what the user sees on top, not the raw
 * handshake rank. */
const verdicts = {};
const rn_keys = keys(RES_TAGS);
for (let ri = 0; ri < length(rn_keys); ri++) {
	const resname = rn_keys[ri];
	const tag = RES_TAGS[resname];
	const entries = [];
	for (let s in final) {
		let reach_ok = false;
		let deep_items = null;
		if (tag == null) {
			for (let h in s.hosts)
				if (h.ok && h.dist) reach_ok = true;
			/* general has no service battery: the MANDATORY check IS the
			 * distinguishing handshake — expressed as a synthetic deep
			 * item so best_verified stays reachable (аудит 92 без лжи:
			 * «проверено» = рукопожатие различающих хостов). */
			deep_items = [ { id: 'reach', ok: reach_ok ? 1 : 0 } ];
		} else {
			for (let h in s.hosts)
				if (h.tag == tag) reach_ok = (h.ok && h.dist);
			if (s.deep && type(s.deep.hosts) === "array")
				for (let dh in s.deep.hosts)
					if (dh.tag == tag) deep_items = dh.items || [];
		}
		push(entries, { name: s.name, args: s.args, reach_ok: reach_ok, deep_items: deep_items });
	}
	verdicts[resname] = resource_verdict(entries, (qv != "") ? qv : null, udp_any);
}

const bnote = [];
const bj = parse(TMP + "/baseline.json");
if (bj && type(bj.results) == "array")
	for (let r in bj.results)
		if (type(r) == "object")
			push(bnote, { tag: r.tag, label: r.label || r.tag, host: r.host || "", ok: (r.ok == 1) });
const cnote = [];
if (ctrl && type(ctrl.results) == "array")
	for (let r in ctrl.results)
		if (type(r) == "object")
			push(cnote, { tag: r.tag, label: r.label || r.tag, host: r.host || "", ok: (r.ok == 1) });
/* Ф6.4 (аудит 58/83): наборы DNS четырёх взглядов — из resolver-файла. */
const rj = parse(TMP + "/resolve.json");
const dns_sets = (rj != null && type(rj) === "object" && type(rj.dns) === "object") ? rj.dns : null;

writefile(RESULT, sprintf("%.J\n", {
	running: false, done: length(final), total: length(final),
	rounds: ROUNDS, majority: MAJ, ts: now, baseline: bnote, strategies: final,
	deep_count: deepN, deep_selected: length(dlist_items),
	deep_failed: deep_failed, deep_skipped: skipped_ids, quic: quic,
	probe_mode: "'$PMODE'",
	lab: "v3",
	baseline_series: { first: bnote, control: cnote, drift: drift },
	dns_sets: dns_sets,
	verdicts: verdicts,
	deep_note: "top " + deepN + " of " + length(dlist_items) + " selected deep-checked: family-diverse leaders + imported/generated bests + the current strategy; failed: " + ((length(deep_failed)) ? join(", ", deep_failed) : "none") + "; probes identical across all deep-tested strategies (" + join(", ", skipped_ids) + ") do not rank"
}));

/* history: keep the last 5 runs (tmpfs — survives until reboot) */
let hist = [];
if (access(HISTORY)) {
	const hj = parse(HISTORY);
	if (hj && type(hj.runs) == "array") hist = hj.runs;
}
const best = (length(final)) ? final[0] : null;
push(hist, { ts: now, mode: "'$MODE'", rounds: ROUNDS,
             best: best ? { name: best.name, ok: best.ok, total: best.total,
                            dist_ok: best.dist_ok, dist_total: best.dist_total } : null });
while (length(hist) > 5) shift(hist);
writefile(HISTORY, sprintf("%.J\n", { runs: hist }));
' 2>/dev/null
rm -rf "$TMP"
echo '{"running":false,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'"}' > "$STATUS"
