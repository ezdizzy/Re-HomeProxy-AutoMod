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
echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"stage":"rank","current":"ranking…"}' > "$STATUS"
ucode -e '
import {readfile, writefile, access} from "fs";
const TMP = "'$TMP'", ROUNDS = int('$ROUNDS'), MAJ = int('$MAJ'), TOTAL = int('$TOTAL');
/* ч.123: the CURRENT strategy comes from the file the shell wrote — with
 * the shell-quoting already stripped there (see the tr above). */
const CURRENT_OPTS = trim(readfile(TMP + "/current_opts.txt") || "");
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
writefile(TMP + "/rank.json", sprintf("%.J\n", { strategies: strategies, ts: now }));
/* ч.123: the deep battery is NOT just the handshake top-5 anymore — a
 * fast handshake does not predict a fast flow (the ч.116 live fact), so
 * the strategies worth MEASURING are chosen beyond the handshake order:
 *   1. the top-5 by score (as before);
 *   2. up to 2 more representatives of DISTINCT technique families
 *      (syndata/multisplit/hostfakesplit/fakesplit/disorder/seg2split/
 *      fake/oob — the first unrepresented strategy per family in rank
 *      order), so a flow-fast/slow-handshake strategy is measured too;
 *   3. the CURRENTLY APPLIED strategy (single-block only) if not already
 *      listed — the user must always see its measured verdict.
 * The list keeps the INDEX into rank.json strategies: the pass-2 merge
 * maps d<i>.json back through it. */
let covered = [];
for (let i = 0; i < length(strategies) && i < 5; i++)
	push(covered, i + 1);
const FAM = [
	[ "syndata", /--syndata/ ],
	[ "multisplit", /--multisplit/ ],
	[ "hostfakesplit", /--hostfakesplit/ ],
	[ "fakesplit", /--fakesplit/ ],
	[ "disorder", /--disorder/ ],
	[ "seg2split", /--seg2split/ ],
	[ "fake", /--fake/ ],
	[ "oob", /--oob/ ]
];
const fam_of = (args) => {
	for (let f in FAM)
		if (match(args, f[1]))
			return f[0];
	return null;
};
const fams_seen = {};
let extra_fam = 0;
for (let i = 0; i < length(strategies) && extra_fam < 2; i++) {
	const idx = i + 1;
	if (index(covered, idx) >= 0) {
		const f0 = fam_of(strategies[i].args || "");
		if (f0 != null) fams_seen[f0] = true;
		continue;
	}
	const f = fam_of(strategies[i].args || "");
	if (f == null || fams_seen[f])
		continue;
	fams_seen[f] = true;
	push(covered, idx);
	extra_fam++;
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
		push(strategies, { name: "current (applied)", args: cur_args,
			ok: 0, total: 0, dist_ok: 0, dist_total: 0, avg_tls_ms: 0,
			score: 0, hosts: [] });
		push(covered, length(strategies));
	}
}
const deep_list = [];
for (let i in covered)
	push(deep_list, { idx: covered[i], args: strategies[covered[i] - 1].args });
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

# Deep content battery (one pass each, same isolated queue). ч.123: the
# battery list is deep_list.json — the handshake top-5 PLUS up to 2
# representatives of distinct technique families PLUS the currently applied
# strategy (see the rank pass above). d<i>.json maps back through the list.
TOPN=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); print(length((j && j.list) || 0));' 2>/dev/null)
YTV_URL=$(ucode /etc/homeproxy/scripts/yt_stream_probe.uc get 2>/dev/null | ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("/dev/stdin") || ""); } catch (e) { j = null; }
if (j && j.ok && j.url) print(j.url);
' 2>/dev/null)
if [ -z "$YTV_URL" ]; then
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"stage":"deep","note":"deep battery: page/CDN/edge + the sustained-flow throughput probe (the real-stream URL is unavailable)"}' > "$STATUS"
else
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"stage":"deep","note":"deep battery includes the real video-stream probe"}' > "$STATUS"
fi
i=0
while [ "$i" -lt "$TOPN" ]; do
	i=$((i + 1))
	ARGS=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); let e = (j && j.list) ? j.list['"$((i-1))"'] : null; print(e ? e.args : "");' 2>/dev/null)
	[ -z "$(printf '%s' "$ARGS" | tr -d '[:space:]')" ] && continue
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"stage":"deep","done2":'$i',"total2":'$TOPN',"current":"deep check '"$i"'/'"$TOPN"'"}' > "$STATUS"
	YTV_URL="$YTV_URL" sh /etc/homeproxy/scripts/zapret_test.sh --deep "$ARGS" "$IPS" 2>/dev/null > "$TMP/d$i.json"
done

# ч.123: the sweep-level QUIC (UDP/443) verdict — a Version-Negotiation
# probe through the same path (probe_pool ≥ 1.6.0). Strategy-independent
# (it is stored ONCE for the sweep, not per strategy): vn = the UDP path
# carries 443 end-to-end (a real QUIC server answered), icmp = an on-path
# rejection, silence = no answer (typically a silent TSPU cut). The UI uses
# it to explain QUIC-vs-TCP YouTube behavior honestly.
QIP=$(printf '%s\n' "$IPS" | tr ' ' '\n' | sed -n 's/^yt=//p' | head -n 1)
if [ -n "$QIP" ] && [ -x /usr/bin/probe_pool ]; then
	# ч.123: the probe answer crosses to the merge pass THROUGH A FILE (the
	# JSON carries double quotes — a shell-injected string would break the
	# ucode quoting of the merge pass).
	/usr/bin/probe_pool -quic-check "$QIP" -quic-host redirector.googlevideo.com 2>/dev/null | head -n 1 > "$TMP/quic_probe.json"
	grep -q '^{"ok"' "$TMP/quic_probe.json" 2>/dev/null || rm -f "$TMP/quic_probe.json"
fi

ucode -e '
import {readfile, writefile, access} from "fs";
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
for (let i = 1; i <= length(dlist_items); i++) {
	const d = parse(TMP + "/d" + i + ".json");
	const ent = dlist_items[i - 1];
	if (!d || type(d.results) != "array" || !ent)
		continue;
	const s = (ent.idx > 0) ? strategies[ent.idx - 1] : null;
	if (!s) continue;
	push(drawn, { s: s, results: d.results });
	deepN++;
}
/* ч.123: the sweep-level QUIC verdict (probe_pool -quic-check, yt edge),
 * read from the FILE the shell wrote (never shell-injected — the JSON
 * carries double quotes). */
let quic = null;
if (access(TMP + "/quic_probe.json")) {
	try { quic = json(readfile(TMP + "/quic_probe.json") || ""); } catch (e) { quic = null; }
	if (quic != null && (type(quic) !== "object" || quic.verdict == null))
		quic = null;
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
	for (let res in r.results) {
		if (type(res) != "object" || res.tag == null) continue;
		let hdok = 0, dtot_h = 0, stream = 0;
		for (let it in (res.deep || [])) {
			if (type(it) != "object" || it.id == null) continue;
			/* the sustained-flow speed (ytv batch / yts real stream) — the
			 * honest quality metric WITHIN a passing deep verdict: both
			 * strategies can pass the ≥128 KB/s bar while one crawls at
			 * 350 KB/s and the other flies at 540 KB/s (the live ч.116
			 * comparison the user reported). */
			if ((it.id == "ytv" || it.id == "yts") && int(it.speed || 0) > stream)
				stream = int(it.speed || 0);
			if (!diff_ids[it.id]) continue;
			dtot_h++;
			if (it.ok == 1) hdok++;
		}
		dok += hdok;
		dtot += dtot_h;
		push(hosts, { tag: res.tag, label: res.label || res.tag,
			deep_ok: (dtot_h > 0 && hdok == dtot_h),
			deep_pass: hdok, deep_total: dtot_h,
			deep_total_raw: int(res.deep_total) || 0,
			stream: stream, items: res.deep || [] });
		if (res.tag == "yt")
			s.stream = stream;
	}
	s.deep = { ok: dok, total: dtot, hosts: hosts };
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
	/* ч.116: equal deep verdicts → the faster sustained video flow wins
	 * (the TLS handshake time does not predict the throttled flow). */
	const sa = int(a.stream || 0), sb = int(b.stream || 0);
	if (sa > 0 && sb > 0 && sa != sb)
		return sb - sa;
	return b.score - a.score;
});
const final = [];
for (let s in tested) push(final, s);
for (let s in rest) push(final, s);

const bnote = [];
const bj = parse(TMP + "/baseline.json");
if (bj && type(bj.results) == "array")
	for (let r in bj.results)
		if (type(r) == "object")
			push(bnote, { tag: r.tag, label: r.label || r.tag, host: r.host || "", ok: (r.ok == 1) });

writefile(RESULT, sprintf("%.J\n", {
	running: false, done: length(final), total: length(final),
	rounds: ROUNDS, majority: MAJ, ts: now, baseline: bnote, strategies: final,
	deep_count: deepN, deep_skipped: skipped_ids, quic: quic,
	deep_note: "top " + deepN + " deep-checked: page/CDN/media-edge fetches + the real video-stream throughput probe (ytv); probes identical across all deep-tested strategies (" + join(", ", skipped_ids) + ") do not rank"
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
echo '{"running":false,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS'}' > "$STATUS"
