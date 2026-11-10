#!/bin/sh
# DPI Strategy Fuzzer v3 (ч.70): batch-test nfqws2 strategies and rank them.
#
# Corpus = the shipped /etc/ravnex/zapret_candidates.json (same pool the
# node.js tester uses): group 'recommended' for a quick fuzz, ALL groups for
# the full one. Each candidate runs ROUNDS isolated passes through
# zapret_test.sh (temp NFQUEUE 209, live firewall untouched, pre-resolved IPs);
# a host PASSES only with a strict majority of rounds (1/1, 2/2, 2/3) so one
# lucky handshake can no longer promote a flaky strategy. One extra BASELINE
# pass (--baseline, no desync) marks hosts that are not DPI-blocked for this
# ISP — such hosts cannot measure a strategy and weigh 10x less in the score.
#
# Writes:
#   /var/run/ravnex/zapret_fuzz.json        live status {running,done,total,current,rounds}
#   /var/run/ravnex/zapret_fuzz_result.json final ranking (per-host details, baseline note)
#   /var/run/ravnex/zapret_fuzz_history.json last 5 runs {ts,mode,rounds,best}
#
# Usage: zapret_fuzz.sh <quick|full> [rounds 1..3, default 2]

MODE="${1:-quick}"
ROUNDS="${2:-2}"
case "$ROUNDS" in 1|2|3) ;; *) ROUNDS=2 ;; esac
MAJ=$(( ROUNDS / 2 + 1 ))
# ч.123: the currently applied strategy joins the deep battery (measured
# verdict for what actually serves the user right now).
CURRENT_OPTS=$(uci -q get ravnex.config.zapret_cmd_opts 2>/dev/null)
RUN=/var/run/ravnex
STATUS="$RUN/zapret_fuzz.json"
RESULT="$RUN/zapret_fuzz_result.json"
HISTORY="$RUN/zapret_fuzz_history.json"
CAND=/etc/ravnex/zapret_candidates.json
TMP=/tmp/zapret_fuzz.$$
# ч.235 (решение пользователя): load average в статус и результат —
# ретроспективно отличает «хост умер» от «роутер задыхался» (прод-nfqws2 +
# кандидат + пробы одновременно). Каждый значимый этап пишет сэмпл 1-min LA
# в $TMP/load.tsv; финальный merge кладёт карту в result.loads.
loadmark() { mkdir -p "$TMP" 2>/dev/null; printf '%s %s\n' "$1" "$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)" >> "$TMP/load.tsv" 2>/dev/null; return 0; }

[ -f "$CAND" ] || { echo '{"running":false,"done":0,"total":0,"error":"no candidates file"}' > "$STATUS"; exit 0; }
command -v ucode >/dev/null 2>&1 || { echo '{"running":false,"error":"ucode missing"}' > "$STATUS"; exit 0; }

# Ф6.4 Test Resource Manager (audit 80): the sweep OWNS its temp queue for the
# whole run — an import/generate started in parallel can no longer kill this
# nfqws2 instance (each task gets its own qnum from the pool, kills are
# ownership-checked). Release runs on EVERY exit path via the trap.
RQNUM=$(ucode -e 'import {acquire} from "/etc/ravnex/scripts/test_resmgr.uc"; print(sprintf("%.J", acquire("fuzz")));' 2>/dev/null | sed -n 's/.*"qnum":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
case "$RQNUM" in ''|*[!0-9]*)
	# the acquire SUCCEEDED-then-mis-parsed case would leak the queue —
	# release by task name regardless (idempotent for the owner only).
	ucode -e 'import {status, release} from "/etc/ravnex/scripts/test_resmgr.uc"; let st = status(); for (let q in keys(st.queues)) if (st.queues[q] != null && st.queues[q].task === "fuzz") release(q, "fuzz");' >/dev/null 2>&1
	echo '{"running":false,"done":0,"total":0,"error":"no free test queue (209-212) - another lab task is running"}' > "$STATUS"
	exit 0 ;;
esac
release_resmgr() {
	[ -n "$RQNUM" ] && ucode -e "import {release} from '/etc/ravnex/scripts/test_resmgr.uc'; release($RQNUM, 'fuzz');" >/dev/null 2>&1
	return 0
}
trap release_resmgr EXIT INT TERM
# Audit (2026-11-07): the acquired queue rode along as a MUTEX only — every
# zapret_test.sh call still defaulted to qnum 209, so a manual test holding
# 209 collided with the sweep (two nfqws2 on one queue, one cleanup killed
# the other's probes). The acquired queue is now the ACTUAL test queue.
TEST_QNUM="$RQNUM"
export TEST_QNUM
# ч.235: ОДИН свип за раз — настоящий мьютекс через resmgr, а не статус-файл.
# Живой факт 00:19-00:42: два свипа шли параллельно и затирали result/history
# (статус-гвард RPC читает файл, который мог протухнуть или быть сброшен
# вручную). Пул даёт каждому запуску СВОЮ очередь (209-212), поэтому второй
# свип легально получил бы 210 при занятой 209 — эта проверка закрывает лаз.
# Строгая hold старше 5400 с = мёртвый свип (зависший после kill -9) —
# освобождается на месте, живая — честный отказ.
_conflict=$(ucode -e '
import {status, release} from "/etc/ravnex/scripts/test_resmgr.uc";
let st = status();
let found = "";
for (let q in keys(st.queues)) {
	if (st.queues[q] == null || st.queues[q].task !== "fuzz") continue;
	if (q == "'$RQNUM'") continue;
	const age = time() - int(st.queues[q].ts || 0);
	if (age > 5400) { release(q, "fuzz"); continue; }
	found = "queue " + q + ", hold age " + age + "s";
}
print(found);
' 2>/dev/null)
if [ -n "$_conflict" ]; then
	ucode -e "import {release} from '/etc/ravnex/scripts/test_resmgr.uc'; release($RQNUM, 'fuzz');" >/dev/null 2>&1
	echo '{"running":false,"done":0,"total":0,"error":"another fuzz sweep is already running ('$_conflict') - one sweep at a time"}' > "$STATUS"
	exit 0
fi

# One ucode pass → "name<TAB>group<TAB>args" lines (TAB cannot occur inside
# any field). ч.129: the GROUP rides along — the deep battery selection must
# measure the best IMPORTED and GENERATED strategies too, not only the top
# of the (tie-prone) handshake score.
if [ "$MODE" = "full" ]; then
	PAIRS=$(ucode -e 'import {readfile} from "fs"; let j=json(readfile("'$CAND'")); for (let c in (j.candidates||[])) if (type(c)=="object") print((c.name||"?") + "\t" + (c.group||"") + "\t" + c.args + "\n");' 2>/dev/null)
else
	# ч.183: quick measures recommended in full PLUS a SMALL DETERMINISTIC
	# ROTATION over the other groups (the corpus grew 2.6x with Tachyon —
	# a quick that never touches 68 strategies is blind on the axis the
	# user cares about). Rotation seed = sweep history length: successive
	# sweeps visit DIFFERENT members, coverage converges over runs.
	PAIRS=$(ucode -e '
import {readfile} from "fs";
let j = json(readfile("'$CAND'"));
let hist = 0;
try { let h = json(readfile("/var/run/ravnex/zapret_fuzz_history.json")); if (h != null && type(h.runs) == "array") hist = length(h.runs); } catch (e) { hist = 0; }
const QUOTA = { tachyon: 3, community: 1, auto: 1, imported: 1, generated: 1 };
const out = [];
for (let c in (j.candidates || []))
	if (type(c) == "object" && (c.group || "") == "recommended")
		push(out, (c.name || "?") + "\t" + (c.group || "") + "\t" + c.args + "\n");
for (let grp in keys(QUOTA)) {
	const pool = [];
	for (let c in (j.candidates || []))
		if (type(c) == "object" && (c.group || "") == grp)
			push(pool, c);
	if (length(pool) == 0) continue;
	const cap = QUOTA[grp];
	if (cap >= length(pool)) {
		for (let c in pool)
			push(out, (c.name || "?") + "\t" + (c.group || "") + "\t" + c.args + "\n");
		continue;
	}
	const off = hist % length(pool);
	for (let n = 0; n < cap; n++) {
		const c = pool[(off + n) % length(pool)];
		push(out, (c.name || "?") + "\t" + (c.group || "") + "\t" + c.args + "\n");
	}
}
print(join("", out));
' 2>/dev/null)
fi
TOTAL=$(printf '%s\n' "$PAIRS" | grep -c '[^[:space:]]')
[ "$TOTAL" -lt 1 ] && { echo '{"running":false,"done":0,"total":0,"error":"empty corpus"}' > "$STATUS"; exit 0; }

echo '{"running":true,"done":0,"total":'$TOTAL',"rounds":'$ROUNDS',"current":"resolving test hosts…"}' > "$STATUS"

# zapret_resolve.sh prints {"ok":1,"ips":{…},"ips2":{…},"dns":{…}} —
# flatten the primary IPs to "tag=ip …"; the SECOND IPs (audit 85: finalists
# on a different edge) and the DNS-SETS comparison (audit 58) ride into the
# merge THROUGH FILES (never shell-injected — the JSON carries quotes).
RJSON=$(sh /etc/ravnex/scripts/zapret_resolve.sh 2>/dev/null)
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
# ч.269: DONE must exist before the edge-matrix status echo below (the old
# init sat after the baseline pass — the edges stage printed an empty "done")
DONE=0
IDX=0
if [ -n "$YIP" ] && [ -x /usr/bin/probe_pool ]; then
	sh /etc/ravnex/scripts/zapret_test.sh --quic "" "yt=$YIP" 2>/dev/null > "$TMP/quic_base.json"
	grep -q '^{"ok"' "$TMP/quic_base.json" 2>/dev/null || rm -f "$TMP/quic_base.json"
	loadmark quic_base
fi

# ч.269 (сеанс 181, приёмка свипа): STUN-бейслайн Discord-голоса БЕЗ
# стратегии — provider-state для вердикта discord (решение юзера
# «baseline + provider-note»). Живой факт приёмки: baseline-проход гоняется
# БЕЗ --deep ⇒ dcv в нём НЕ измеряется, stun_baseline оставался null и провал
# dcv честно (но слепо) демотил discord. Здесь выделенный дешёвый baseline:
# только dc-глубина (dcp/dcpf/dcv; потоковые пробы в baseline честно
# отсутствуют) ⇒ «STUN молчит и без стратегии» = измеримый факт.
DIPB=$(printf '%s\n' "$IPS" | tr ' ' '\n' | sed -n 's/^dc=//p' | head -n 1)
if [ -n "$DIPB" ]; then
	sh /etc/ravnex/scripts/zapret_test.sh --baseline --deep "" "dc=$DIPB" 2>/dev/null > "$TMP/stun_base.json"
	# ч.269 observability (live fact of sweeps 2-3: the file was absent at
	# merge time while the standalone replica always produces it — the next
	# sweep self-diagnoses via fuzz_stderr.log)
echo "stun_base bytes=$(wc -c < "$TMP/stun_base.json" 2>/dev/null) head=$(head -c 60 "$TMP/stun_base.json" 2>/dev/null | tr -d '\n')" >> /var/run/ravnex/fuzz_stderr.log 2>/dev/null
# ч.270 ROOT CAUSE of the ch.269 STUN anomaly (the diagnostic line caught it
# live): the builder prints PRETTY multi-line JSON ({ + newline first), and
# the anchored guard `grep -q '^{"ok"'` only matches a single-line blob —
# every sweep DELETED a perfectly valid baseline file → stun_items=0 → dcv
# demoted silently. Guard = the write is COMPLETE (closing brace at EOF). The
# merge parse (json) handles multi-line fine; ok:0 in the content is EXPECTED
# (blocked-resource handshakes fail without desync — dcv is the only item
# whose baseline verdict matters here).
tail -c 2 "$TMP/stun_base.json" 2>/dev/null | grep -q '}' || rm -f "$TMP/stun_base.json"
	loadmark stun_base
fi

# ч.269 (сеанс 181): КАРТА КРАЁВ CDN-ПУЛА через ЖИВОЙ путь — прямой ответ на
# феномен юзера «одна выдача — одни видео грузятся, другие нет» (живой диагноз:
# rr2..rr5 пула sn-nx5pm-3ggl = 4 IP, 185.221.46.48 отрезан по пути ЦЕЛИКОМ,
# соседи живы; мёртвый край НЕ зависит от стратегии). Матрица снимается ДО
# кандидатов: (1) результат едет в итог JSON (диагностика для юзера), (2)
# глубокая батарея получает EDGE_HINTS «живые впереди» (мёртвый край не
# должен отжигать 4-МБ таймауты на каждой стратегии), (3) инфраструктурно
# мёртвые края попадают в вердикт-заметки, а не в штраф стратегий.
# Чистое наблюдение: zapret_edges.sh НЕ трогает nft — пробы идут по
# продуктовому пути с применённой стратегией, как у LAN-клиента.
YTURL_EARLY=$(ucode /etc/ravnex/scripts/yt_stream_probe.uc get 2>/dev/null | ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("/dev/stdin") || ""); } catch (e) { j = null; }
if (j && j.ok && j.url) print(j.url);
' 2>/dev/null)
if [ -n "$YTURL_EARLY" ]; then
	L1E=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null); [ -n "$L1E" ] || L1E=0
	echo "{\"running\":true,\"done\":$DONE,\"total\":$TOTAL,\"rounds\":$ROUNDS,\"load\":$L1E,\"stage\":\"edges\",\"current\":\"карта пулов CDN (live, мультипул)…\"}" > "$STATUS"
	# ч.183 МУЛЬТИПУЛ: одна матрица одного пула ничего не знает про ЦЕЛЫЕ
	# /29-блэкауты в ДРУГИХ пулах (живой факт сеанса 183: 6/9 пулов черны
	# целиком в один момент при живых q4fl*/nx5pm; «видео не открывается» =
	# watch-страница выдала чёрный пул). Каталог пулов:
	#  (1) суффикс текущего стрима (всегда первый),
	#  (2) mn= фолбек-цепочка самого URL (Google сам перечисляет пулы, куда
	#      может прыгнуть отдача),
	#  (3) ЖИВЫЕ конны ядра (/connections — rr-хосты прямо сейчас),
	#  (4) персист-история zapret_pools.json (≤48 ч, свежие сверху),
	#  (5) EXTRA_POOLS (ручная дверь re-shoot).
	PSUF=$(printf '%s' "$YTURL_EARLY" | sed -E 's#https://rr[0-9]*---##; s#\.googlevideo\.com.*##')
	MNLIST=$(printf '%s' "$YTURL_EARLY" | sed -n 's/.*[?&]mn=//p' | cut -d'&' -f1 | sed 's/%2[cC]/ /g')
	CNLIST=$(curl -s --max-time 3 http://127.0.0.1:9090/connections 2>/dev/null \
		| grep -oE 'rr[0-9]+---sn-[a-z0-9]+[a-z0-9.-]*\.googlevideo\.com' \
		| sed -E 's/^rr[0-9]+---//; s/\.googlevideo\.com//' \
		| sort -u | tr '\n' ' ')
	HISTPOOLS=$(ucode -e '
import {readfile, access} from "fs";
let j = null;
try { j = json(readfile("/var/run/ravnex/zapret_pools.json") || ""); } catch (e) { j = null; }
if (j != null && type(j.pools) == "object") {
	let rows = [];
	for (let s in keys(j.pools)) {
		const p = j.pools[s];
		if (type(p) != "object") continue;
		if (time() - int(p.last_ts || 0) > 172800) continue;
		let ss = "" + s;
		/* emit the BARE suffix: the other catalog sources are bare and the
		 * consumer dedups on the normalized form */
		const gtail = ".googlevideo.com";
		if (substr(ss, length(ss) - length(gtail)) == gtail)
			ss = substr(ss, 0, length(ss) - length(gtail));
		push(rows, { s: ss, ts: int(p.last_ts || 0) });
	}
	sort(rows, (a, b) => b.ts - a.ts);
	let out = [];
	for (let r in rows) push(out, r.s);
	print(join(" ", out));
}' 2>/dev/null)
	POOL_LIST=$(printf '%s' "$PSUF $MNLIST $CNLIST $EXTRA_POOLS $HISTPOOLS" \
		| tr ' ' '\n' | sed '/^$/d' | awk '!seen[$0]++' | head -10 | tr '\n' ' ')
	sh /etc/ravnex/scripts/zapret_edges.sh --pools "$POOL_LIST" 2>/dev/null > "$TMP/pool_matrix.json"
	grep -q '"ok":1' "$TMP/pool_matrix.json" 2>/dev/null || rm -f "$TMP/pool_matrix.json"
	# Primary-pool matrix rides OUT as edge_matrix.json — every existing
	# consumer (EH/DEAD hint builders, the merge infra-dead union, the result
	# field, verdict dead_edges) keeps its exact contract; other pools travel
	# in pool_matrix.json (+ pool_map in the merge).
	if [ -s "$TMP/pool_matrix.json" ]; then
		ucode -e '
import {readfile, writefile} from "fs";
let j = null;
try { j = json(readfile("'$TMP'/pool_matrix.json") || ""); } catch (e) { j = null; }
const psuf = "'$PSUF'";
if (j != null && type(j.pools) == "array")
	for (let p in j.pools)
		if (type(p) == "object" && p.suffix == psuf + ".googlevideo.com") {
			writefile("'$TMP'/edge_matrix.json", sprintf("%.J\n", p));
			break;
		}
' 2>/dev/null
	fi
	loadmark edges_multipool
	# ── сеанс 187: DIRECT-слой (RU-правда) — тот же каталог через TEMP-контур ──
	# Live-строки меряют «вид из настроенного пути» (правило youtube может
	# вести на узел = вид из этого узла, дискриминант ч.273); direct-строки =
	# честный RU-direct + ПРИМЕНЁННАЯ стратегия (то, что увидит юзер в
	# архитектуре «всё youtube на движке»). Всё аддитивно:
	# alive_dir/dead_dir/dead_whole_dir + поле pool_matrix_direct; провал
	# прохода (нет очереди/нет движка) честно убирает файл — свип живёт.
	if [ -s "$TMP/pool_matrix.json" ]; then
		sh /etc/ravnex/scripts/zapret_edges.sh --contour temp "$POOL_LIST" 2>/dev/null > "$TMP/pool_matrix_direct.json"
		grep -q '"ok":1' "$TMP/pool_matrix_direct.json" 2>/dev/null || rm -f "$TMP/pool_matrix_direct.json"
	fi
	loadmark edges_direct
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

# ч.235 (решение пользователя «Резолв+retry»): свежие края против чёрных дыр
# TSPU. Эксперимент (w24_matrix, живой роутер) доказал: свип долбит ОДИН
# закреплённый на старте IP (209.85.233.198) — TSPU глотает ВСЁ на нём (все
# 16 стратегий + оба контроля таймаутятся), а устройства живут на свежих
# краях DNS (та же составная на 142.251.20.100 проходит за 207 мс curl +
# 211 мс utls-chrome). Отсюда: (1) резолв перед каждой фазой, (2) retry
# прохода со свежим краем, если ЛЮБОЙ тег вернул таймаут (сигнатура
# мёртвого края).
reresolve() {
	_R2=$(sh /etc/ravnex/scripts/zapret_resolve.sh 2>/dev/null)
	[ -n "$_R2" ] || return 0
	printf '%s' "$_R2" > "$TMP/resolve.json" 2>/dev/null
	_RIPS=$(printf '%s' "$_R2" | ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("/dev/stdin") || ""); } catch (e) { j = null; }
if (!j || j.ok != 1) exit(1);
let parts = [];
for (let k in keys(j.ips || {}))
	if (j.ips[k]) push(parts, k + "=" + j.ips[k]);
print(join(" ", parts));
' 2>/dev/null)
	[ -n "$_RIPS" ] && IPS="$_RIPS"
	return 0
}
# retry_probe <resultfile> <tester args...>: если в результате есть тег с
# таймаутом — свежий резолв + ОДИН повтор; повторный результат заменяет
# исходный (мажорность раундов дальше всё равно работает по фактам).
retry_probe() {
	local OUT="$1"; shift
	local NEED=$(ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("'$1'") || ""); } catch (e) { j = null; }
let to = false;
if (j != null && type(j.results) == "array")
	for (let r in j.results)
		if (type(r) == "object" && r.ok != 1 && ("" + r.reason) == "timeout") { to = true; break; }
print(to ? "RETRY" : "");
' 2>/dev/null)
	[ "$NEED" = "RETRY" ] || return 0
	reresolve
	sh /etc/ravnex/scripts/zapret_test.sh "$@" 2>/dev/null > "$OUT"
	return 0
}

# One BASELINE pass (no desync): hosts that pass without a strategy are not
# DPI-blocked and cannot credit any strategy. "" = no strategy needed there.
sh /etc/ravnex/scripts/zapret_test.sh --baseline "" "$IPS" 2>/dev/null > "$TMP/baseline.json"
retry_probe "$TMP/baseline.json" --baseline "" "$IPS"
loadmark baseline

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
		L1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null); [ -n "$L1" ] || L1=0
		echo "{\"running\":true,\"done\":$DONE,\"total\":$TOTAL,\"rounds\":$ROUNDS,\"load\":$L1,\"current\":\"$NAME (round $R/$ROUNDS)\"}" > "$STATUS"
		sh /etc/ravnex/scripts/zapret_test.sh "$STRAT" "$IPS" 2>/dev/null > "$TMP/c${IDX}_${R}.json"
		retry_probe "$TMP/c${IDX}_${R}.json" "$STRAT" "$IPS"
		loadmark "c${IDX}_${R}"
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
import { samples_stats } from "/etc/ravnex/scripts/strategy_lab.uc";
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

/* baseline: tag → { ok, uok, tls } (hosts passing WITHOUT desync = non-
 * distinguishing; uok = the browser-Hello class verdict, false when the
 * probe class was not measured — conservative NOT free). */
const bres = {};
const bj = parse(TMP + "/baseline.json");
if (bj && type(bj.results) == "array")
	for (let r in bj.results)
		if (type(r) == "object" && r.tag)
			bres[r.tag] = { ok: (r.ok == 1), uok: (r.uok == 1), tls: r.tls };

const strategies = [];
/* ч.232: the sweep carries the BROWSER ClientHello probe class (utls_probe)
 * when the binary is installed — detected from the round JSONs. The ranking
 * policy lives HERE (one place): a host "passes" only when BOTH classes pass
 * (curl AND browser Hello), because TSPU decides by the client fingerprint
 * and the curl Hello is not a browser Hello (live fact 2026-11-07: Default passed
 * every router probe and failed on the phone). No binary → curl-only sweep,
 * the honest status quo. */
let u_meas = false;
for (let n = 0; n < length(pairs); n++) {
	const idx = n + 1;
	/* collect per-host across rounds (results keep the fixed HOSTS order).
	 * Ф6.4 (аудит 66): the rating uses the SERIES (median/P90/success rate/
	 * jitter) instead of the best single measurement — the round samples are
	 * kept per tag and reduced by strategy_lab.samples_stats (ONE stats
	 * implementation for the whole project). */
	let per = null;          /* tag → {label, host, ip, votes, tls_min, last_reason, times, oks, uoks, utls_min} */
	let order = [];
	let total = 0;
	for (let rd = 1; rd <= ROUNDS; rd++) {
		const j = parse(TMP + "/c" + idx + "_" + rd + ".json");
		if (!j || type(j.results) != "array") continue;
		if (j.utls_probe == true)
			u_meas = true;
		if (!total) total = int(j.total) || 0;
		if (int(j.total) > total) total = int(j.total);
		if (!per) {
			per = {};
			for (let r in j.results)
				if (type(r) == "object" && r.tag) {
					push(order, r.tag);
					per[r.tag] = { label: r.label || r.tag, host: r.host || "", ip: r.ip || "",
					               votes: 0, tls_min: 0, last_reason: "", times: [], oks: [],
					               uoks: [], utls_min: 0, last_u_reason: "" };
				}
		}
		for (let r in j.results) {
			if (type(r) != "object" || !r.tag || !per[r.tag]) continue;
			const tls = ("" + r.tls) * 1.0;
			const oksv = (r.ok == 1) ? 1 : 0;
			/* uok: null = the probe class was not measured (no binary) —
			 * treated as a pass so the curl-only behavior stays intact. */
			const uokv = (r.uok == null) ? 1 : ((r.uok == 1) ? 1 : 0);
			push(per[r.tag].times, tls * 1000.0);
			push(per[r.tag].oks, oksv);
			push(per[r.tag].uoks, uokv);
			if (oksv == 1) {
				per[r.tag].votes++;
				const ms = int(tls * 1000);
				if (ms > 0 && (per[r.tag].tls_min == 0 || ms < per[r.tag].tls_min))
					per[r.tag].tls_min = ms;
			} else {
				per[r.tag].last_reason = r.reason || "fail";
			}
			if (uokv == 1) {
				const ums = int(r.utls_ms || 0);
				if (ums > 0 && (per[r.tag].utls_min == 0 || ums < per[r.tag].utls_min))
					per[r.tag].utls_min = ums;
			} else {
				per[r.tag].last_u_reason = (r.u_err != null) ? ("" + r.u_err) : "u_fail";
			}
		}
	}
	if (!total) { total = length(order); }
	let hosts = [], ok = 0, dist_ok = 0, dist_total = 0, tls_sum = 0, tls_n = 0;
	for (let t in order) {
		const p = per[t];
		let uvotes = 0;
		for (let u in p.uoks)
			uvotes += u;
		/* combined pass: curl majority AND (when measured) browser-Hello
		 * majority; without the binary — curl-only, as before. */
		const host_ok = (p.votes >= MAJ) && (!u_meas || uvotes >= MAJ);
		/* free-pass: the RAW pass of EITHER class cannot credit a strategy.
		 * The browser baseline verdict (uok) is known only when the probe
		 * class was measured; unknown → conservative NOT free. */
		const free_curl = (bres[t] != null && bres[t].ok == true);
		const free_browser = (bres[t] != null && bres[t].uok == true);
		const dist = !free_curl && !free_browser;
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
		              uok: u_meas ? (uvotes >= MAJ) : null,
		              utls_ms: (u_meas && uvotes >= MAJ) ? p.utls_min : 0,
		              u_reason: (!u_meas || uvotes >= MAJ) ? "" : p.last_u_reason,
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
 *   5. the CURRENTLY APPLIED strategy if not already listed — the user
 *      must always see its measured verdict. ч.229: multi-block composites
 *      (--new) measure like any corpus candidate — the corpus itself carries
 *      --new chains and nfqws2 is profile-native (first matching profile
 *      wins); the old single-block-only guard left the REAL composite
 *      unmeasured while deep_note claimed otherwise.
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
/* 4. the best imported and generated strategy (the user catalogs); ч.183:
 * the tachyon/community groups join the quota — an import of 68 strategies
 * deserves its best measured rep in the deep battery, not invisibility. */
for (let gi in ["imported", "generated", "tachyon", "community"]) {
	for (let i = 0; i < length(strategies); i++) {
		if (strategies[i].group != gi || int(strategies[i].ok) <= 0) continue;
		if (index(covered, i + 1) < 0)
			push(covered, i + 1);
		break;
	}
}
const cur_args = trim(CURRENT_OPTS);
let cur_measured = false;
if (length(cur_args) > 3 && match(cur_args, /^--[a-z]/)) {
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
	cur_measured = true;
}
/* ч.129 FIX: rank.json is written AFTER the current-strategy append —
 * the merge maps d<i>.json through deep_list.json indexes into THIS
 * array, and the old order (write first, append after) made the merge
 * silently drop the measured verdict of the current strategy forever. */
writefile(TMP + "/rank.json", sprintf("%.J\n", { strategies: strategies, ts: now,
	cur_measured: cur_measured, utls_probe: u_meas, utls_fp: u_meas ? "chrome" : "" }));
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
# ч.269: the stream URL was fetched EARLY (the edge-matrix phase) — reuse it;
# a fresh fetch here would re-hammer innertube for the same answer.
YTV_URL="$YTURL_EARLY"
if [ -z "$YTV_URL" ]; then
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","note":"deep battery: page/CDN/edge + the sustained-flow throughput probe (the real-stream URL is unavailable)"}' > "$STATUS"
else
	echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","note":"deep battery includes the real video-stream probe"}' > "$STATUS"
fi
# ч.269: EDGE_HINTS для глубокой батареи — «host ip» строк живых краёв из
# карты (мёртвые исключены: стратегия не обязана чинить инфраструктуру).
# Ротация по проходам (аудит 2): проход 1 идёт в порядке карты, проход 2 —
# в обратном, чтобы первичность края не была привязана к проходу.
EH_FWD=""
EH_REV=""
if [ -s "$TMP/edge_matrix.json" ]; then
	EH_FWD=$(ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("'$TMP'/edge_matrix.json") || ""); } catch (e) { j = null; }
if (j != null && type(j.edges) == "array") {
	let parts = [];
	for (let e in j.edges) {
		if (type(e) != "object" || !e.host || !e.ip) continue;
		if (e.tls_ok == 0 && ("" + (e.get_code || "0")) == "0") continue;
		push(parts, e.host + " " + e.ip);
	}
	print(join("\n", parts));
}' 2>/dev/null)
	EH_REV=$(printf '%s\n' "$EH_FWD" | tac 2>/dev/null)
	[ -n "$EH_REV" ] || EH_REV="$EH_FWD"
fi
# ч.270: DEAD_HINTS — «host ip» строки МЁРТВЫХ краёв карты (зеркало
# EDGE_HINTS, которое их исключало). Глубокая батарея пере-пробует их ПОД
# КАЖДОЙ стратегией (1 MB range): стратегия, ОЖИВЛЯЮЩАЯ мёртвый край, несёт
# первосортный дифференцирующий признак — живое доказательство сеанса 182:
# .48 оживает под Hostfakesplit и был мёртв под fakedsplit catch-all, значит
# «мёртвость края» НЕ инфраструктура, а свойство формы потока стратегии.
DEAD_HINTS=""
if [ -s "$TMP/edge_matrix.json" ]; then
	DEAD_HINTS=$(ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("'$TMP'/edge_matrix.json") || ""); } catch (e) { j = null; }
if (j != null && type(j.edges) == "array") {
	let parts = [];
	for (let e in j.edges) {
		if (type(e) != "object" || !e.host || !e.ip) continue;
		if (e.tls_ok != 0) continue;
		push(parts, e.host + " " + e.ip);
	}
	print(join("\n", parts));
}' 2>/dev/null)
fi
# ч.183: CROSSPOOL_HINTS — ЖИВЫЕ края ДРУГИХ пулов (pool_matrix, не основной
# суффикс). Глубокая батарея получает yts5: межпуловый тянутый пункт — «стрим
# под этой стратегией играет из ЧУЖОГО пула или нет» (внутрипуловая ротация
# yts2..yts4 не видит пуловую чёрноту). Один пункт на стратегию, дёшево.
CROSSPOOL_HINTS=""
if [ -s "$TMP/pool_matrix.json" ]; then
	CROSSPOOL_HINTS=$(ucode -e '
import {readfile} from "fs";
let j = null;
try { j = json(readfile("'$TMP'/pool_matrix.json") || ""); } catch (e) { j = null; }
const psuf = "'$PSUF'.googlevideo.com";
if (j != null && type(j.pools) == "array") {
	let parts = [];
	for (let p in j.pools) {
		if (type(p) != "object" || p.ok != 1) continue;
		if ("" + p.suffix == psuf) continue;
		if (type(p.edges) != "array") continue;
		for (let e in p.edges) {
			if (type(e) != "object" || !e.host || !e.ip) continue;
			if (e.tls_ok == 0 && ("" + (e.get_code || "0")) == "0") continue;
			push(parts, e.host + " " + e.ip);
		}
	}
	/* cap: one item per strategy — 4 rows are plenty for the rotation */
	while (length(parts) > 4) shift(parts);
	print(join("\n", parts));
}' 2>/dev/null)
fi
# deep_pass <suffix> <pass#> — one full battery pass; results land in d<i><suf>.json.
deep_pass() {
	i=0
	_EH="$EH_FWD"
	[ "$2" = "2" ] && [ -n "$EH_REV" ] && _EH="$EH_REV"
	while [ "$i" -lt "$TOPN" ]; do
		i=$((i + 1))
		ARGS=$(ucode -e 'import {readfile} from "fs"; let j = json(readfile("'$TMP'/deep_list.json")); let e = (j && j.list) ? j.list['"$((i-1))"'] : null; print(e ? e.args : "");' 2>/dev/null)
		[ -z "$(printf '%s' "$ARGS" | tr -d '[:space:]')" ] && continue
		DL1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null); [ -n "$DL1" ] || DL1=0
		echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"deep","load":'$DL1',"done2":'$i',"total2":'$TOPN',"current":"deep check '"$i"'/'"$TOPN"' (pass '"$2"')"}' > "$STATUS"
		YTV_URL="$YTV_URL" EDGE_HINTS="$_EH" DEAD_HINTS="$DEAD_HINTS" CROSSPOOL_HINTS="$CROSSPOOL_HINTS" sh /etc/ravnex/scripts/zapret_test.sh --deep "$ARGS" "$IPS" 2>/dev/null > "$TMP/d$i$1.json"
		loadmark "deep${i}_p$2"
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
		YTV_URL="$YTV_URL" EDGE_HINTS="$EH_FWD" DEAD_HINTS="$DEAD_HINTS" CROSSPOOL_HINTS="$CROSSPOOL_HINTS" sh /etc/ravnex/scripts/zapret_test.sh --deep "$ARGS" "$IPS" 2>/dev/null > "$TMP/d$i$1.json"
	done
}
# ч.235: fresh edges before the deep battery — the battery is the EXPENSIVE
# phase (~10 min); a dead pinned edge here poisons every deep verdict.
reresolve
deep_pass "" 1
deep_retry "" 1
deep_pass "b" 2
deep_retry "b" 2

# Ф6.4 (audit 84): CONTROL baseline — the baseline is a SERIES, not a single
# measurement: a host passing baseline #1 but failing the control (or vice
# versa) is DRIFT, and the free-pass credit requires BOTH passes (the merge
# recomputes dist conservatively and reports the drift honestly).
echo '{"running":true,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'","stage":"control","current":"контрольный baseline…"}' > "$STATUS"
reresolve
sh /etc/ravnex/scripts/zapret_test.sh --baseline "" "$IPS" 2>/dev/null > "$TMP/control.json"
retry_probe "$TMP/control.json" --baseline "" "$IPS"

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
		sh /etc/ravnex/scripts/zapret_test.sh "$ARGS" "$IPS2" 2>/dev/null > "$TMP/a$i.json"
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
		sh /etc/ravnex/scripts/zapret_test.sh --quic "$ARGS" "yt=$YIP" 2>/dev/null > "$TMP/q$i.json"
	done
fi

# ч.235: the 1-min load at merge time — result.load_now. 🔴 ONE field only:
# the triple from /proc/loadavg carries SPACES and "'$LNOW'" inside the
# single-quoted ucode -e program word-splits on them — the -e argument was
# truncated at `load_now: "1.25` (unterminated string, proven live 00:16 via
# fuzz_stderr.log) and the whole merge died silently (2>/dev/null era).
LNOW=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null); [ -n "$LNOW" ] || LNOW="0"

ucode -e '
import {readfile, writefile, access} from "fs";
import { samples_stats, dims_of, resource_verdict, strategy_verdict, engine_can } from "/etc/ravnex/scripts/strategy_lab.uc";
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
/* ч.232: the browser-Hello probe class verdict (rank pass detected it) —
 * the free-credit and the result flag below honor it. */
const u_meas2 = (rank.utls_probe == true);
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
 * compatible for the readers: {verdict: vn|icmp|silence|empty}. */
let quic = null;
if (access(TMP + "/quic_base.json")) {
	const qb = parse(TMP + "/quic_base.json");
	if (qb != null && type(qb) === "object" && qb.quic != null) {
		const qvs = "" + qb.quic;
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
			if ((it.id == "ytv" || it.id == "yts" || it.id == "yts2" || it.id == "yts3" || it.id == "yts4" || it.id == "yts5") && int(it.speed || 0) > stream)
				stream = int(it.speed || 0);
			if (it.id == "ytv" && int(it.ttfb || 0) > start_ms)
				start_ms = int(it.ttfb || 0);
			if ((it.id == "yts" || it.id == "yts2" || it.id == "yts3" || it.id == "yts4" || it.id == "yts5") && int(it.ttfb || 0) > vstart)
				vstart = int(it.ttfb || 0);
			if ((it.id == "yts2" || it.id == "yts3" || it.id == "yts4") && int(it.speed || 0) > stream2)
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
		let res2hit = null;
		if (r.results2 != null)
			for (let res2 in r.results2)
				if (type(res2) == "object" && res2.tag == res.tag) { m2 = collect(res2); res2hit = res2; break; }
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
			/* ч.269: per-edge stream map — every pool edge carries host+ip
			 * and BOTH pass verdicts; the merge turns a consistently dead
			 * edge into an infra note (never a strategy penalty), and a
			 * FLIPPING edge into an instability flag (entropy). */
			const byid = (arr) => {
				const m = {};
				if (type(arr) !== "array") return m;
				for (let it in arr) {
					if (type(it) !== "object" || it.id == null) continue;
					m["" + it.id] = it;
				}
				return m;
			};
			const pa = byid(res.deep);
			const pb = (res2hit != null) ? byid(res2hit.deep) : {};
			const em = [];
			for (let eid in ["yts", "yts2", "yts3", "yts4", "yts5"]) {
				const a = pa[eid], b = pb[eid];
				if (a == null && b == null) continue;
				push(em, { id: eid,
					host: (a != null && a.host != null) ? ("" + a.host) : ((b != null && b.host != null) ? ("" + b.host) : null),
					ip: (a != null && a.ip != null) ? ("" + a.ip) : ((b != null && b.ip != null) ? ("" + b.ip) : null),
					ok1: (a != null) ? ((a.ok == 1) ? 1 : 0) : null,
					ok2: (b != null) ? ((b.ok == 1) ? 1 : 0) : null,
					spd1: (a != null) ? int(a.speed || 0) : null,
					spd2: (b != null) ? int(b.speed || 0) : null });
			}
			s.edge_map = em;
			let flips = 0, deadc = 0;
			for (let e in em) {
				if (e.ok1 != null && e.ok2 != null && e.ok1 != e.ok2) flips++;
				if (e.ok1 == 0 && e.ok2 == 0) deadc++;
			}
			s.unstable_edges = flips;
			s.dead_edges_consistent = deadc;
			/* ч.270: dead-edge REVIVE per strategy — the dedg items carry the
			 * matrix-dead edges re-probed UNDER THIS STRATEGY; ok==1 = revived
			 * (first-class differential signal, weight above band). */
			let revd = [];
			for (let it in (res.deep || [])) {
				if (type(it) != "object" || it.id == null) continue;
				if (index(("" + it.id), "dedg") !== 0) continue;
				if (it.ok == 1)
					push(revd, { ip: (it.ip != null) ? ("" + it.ip) : null,
						host: (it.host != null) ? ("" + it.host) : null });
			}
			s.dead_edge_revive = length(revd);
			if (length(revd) > 0) s.revived_edges = revd;
		}
	}
	s.deep = { ok: dok, total: dtot, hosts: hosts, passes: r.passes };
}

/* ч.270: the DEAD-EDGE REVIVE registry — edges that AT LEAST ONE deep
 * strategy revived (dedg ok) are NOT infrastructure-dead: their death is a
 * property of the flow shape the strategy builds (live proof of session 182:
 * .48 revived under Hostfakesplit, dead under the fakedsplit catch-all).
 * This redefines infra_dead (the ч.269 model «matrix says dead = forever»
 * is retired; a revived edge re-enters the pool for the next sweeps). */
const revived_ips = {};
for (let r in drawn)
	for (let res in r.results) {
		if (type(res) != "object" || res.tag == null) continue;
		for (let it in (res.deep || [])) {
			if (type(it) != "object" || it.id == null) continue;
			if (index(("" + it.id), "dedg") !== 0) continue;
			if (it.ok == 1 && it.ip != null)
				revived_ips["" + it.ip] = { host: ("" + (it.host || "")) };
		}
	}
const revived_edges = [];
for (let rip in keys(revived_ips))
	push(revived_edges, { ip: rip, host: revived_ips[rip].host });

/* ч.269: INFRA-DEAD edges — an edge EVERY measured strategy failed on both
 * passes (and, when present, the live edge matrix agrees) is the PATH
 * property, not a strategy property: surfaced as notes, never as a penalty. */
const emx = parse(TMP + "/edge_matrix.json");
const infra_dead_edges = [];
{
	const per_ip = {};
	for (let r in drawn) {
		const s = r.s;
		if (s.edge_map == null) continue;
		for (let e in s.edge_map) {
			if (e.ip == null) continue;
			const rec = per_ip[e.ip] || { host: e.host, have: 0, dead: 0 };
			if (e.ok1 != null && e.ok2 != null) {
				rec.have++;
				if (e.ok1 == 0 && e.ok2 == 0) rec.dead++;
			}
			per_ip[e.ip] = rec;
		}
	}
	for (let ip in keys(per_ip)) {
		const rec = per_ip[ip];
		if (rec.have >= 2 && rec.dead == rec.have)
			push(infra_dead_edges, { ip: ip, host: rec.host });
	}
}
/* ч.269 (приёмка свипа): the LIVE edge matrix is the primary source of
 * infra-dead edges — the deep battery never measures the dead ones (they
 * are excluded via EDGE_HINTS), so without this union the verdict notes
 * stayed silent about exactly the edges that explain the user phenomenon
 * (live fact: matrix says rr5=.48/rr6=.49 tls=0 get=000, deep battery has
 * nothing on them). Union, dedup by ip.
 * ч.270: REVISED — a matrix-dead edge that at least one strategy REVIVED
 * (dedg ok) is excluded: its death was strategy-shaped, not infra. */
if (emx != null && type(emx.edges) == "array")
	for (let me in emx.edges) {
		if (type(me) != "object" || me.ip == null) continue;
		if (me.tls_ok != 0 || ("" + (me.get_code || "0")) != "0") continue;
		if (revived_ips["" + me.ip] != null) continue;
		let dup = false;
		for (let d2 in infra_dead_edges)
			if (d2.ip == me.ip) { dup = true; break; }
		if (!dup)
			push(infra_dead_edges, { ip: me.ip, host: me.host });
	}
/* ── ч.183 МУЛЬТИПУЛОВАЯ ПРАВДА ────────────────────────────────────────── */
/* per-pool карта из pool_matrix.json: вердикт честности «пул мёртв ЦЕЛИКОМ =
 * выдача не играется НИ ПРИ КАКОЙ стратегии — перегенерируйте страницу».
 * Персист /var/run/ravnex/zapret_pools.json несёт межсвиповое ВРЕМЯ: ротация
 * /29-блэкаутов измеряется МЕЖДУ прогонами (re-shoot), а не внутри одного. */
const pmx = parse(TMP + "/pool_matrix.json");
const pool_map = {};
const pool_extra = [];
/* сеанс 187: DIRECT-слой (RU-правда) — второй столбец карты краёв из
 * zapret_edges.sh --contour temp (честный RU-direct + ПРИМЕНЁННАЯ стратегия).
 * Аддитивные ключи alive_dir/dead_dir/dead_whole_dir рядом с live-значениями;
 * их ОТСУТСТВИЕ = прямой проход не измерен (нет очереди/движка) — не
 * фейк-ноль (прецедент dedgu «не измерено»). */
const pmxd = parse(TMP + "/pool_matrix_direct.json");
const dir_map = {};
if (pmxd != null && type(pmxd.pools) == "array")
	for (let dp in pmxd.pools) {
		if (type(dp) != "object" || dp.suffix == null) continue;
		let dalive = 0, ddead = 0;
		if (type(dp.edges) == "array")
			for (let de in dp.edges) {
				if (type(de) != "object") continue;
				if (de.tls_ok == 0 && ("" + (de.get_code || "0")) == "0") ddead++;
				else dalive++;
			}
		dir_map["" + dp.suffix] = { alive: dalive, dead: ddead,
			dead_whole: (dp.ok != 1 || (ddead > 0 && dalive == 0)) ? 1 : 0 };
	}
if (pmx != null && type(pmx.pools) == "array")
	for (let p in pmx.pools) {
		if (type(p) != "object" || p.suffix == null) continue;
		let alive = 0, dead = 0;
		if (type(p.edges) == "array")
			for (let e in p.edges) {
				if (type(e) != "object") continue;
				if (e.tls_ok == 0 && ("" + (e.get_code || "0")) == "0") dead++;
				else alive++;
			}
		const whole = (p.ok != 1 || (dead > 0 && alive == 0));
		let ss = "" + p.suffix;
		const gtail = ".googlevideo.com";
		if (substr(ss, length(ss) - length(gtail)) == gtail)
			ss = substr(ss, 0, length(ss) - length(gtail));
		pool_map["" + p.suffix] = { alive: alive, dead: dead, dead_whole: whole ? 1 : 0 };
		const dm = dir_map["" + p.suffix];
		if (dm != null) {
			pool_map["" + p.suffix].alive_dir = dm.alive;
			pool_map["" + p.suffix].dead_dir = dm.dead;
			pool_map["" + p.suffix].dead_whole_dir = dm.dead_whole;
			push(pool_extra, { suffix: ss, alive: alive, dead: dead, dead_whole: whole ? 1 : 0,
				alive_dir: dm.alive, dead_dir: dm.dead, dead_whole_dir: dm.dead_whole });
		} else {
			push(pool_extra, { suffix: ss, alive: alive, dead: dead, dead_whole: whole ? 1 : 0 });
		}
	}
let pstate = {};
const POOLSF = "/var/run/ravnex/zapret_pools.json";
if (access(POOLSF)) {
	const pj = parse(POOLSF);
	if (pj != null && type(pj.pools) == "object") pstate = pj.pools;
}
for (let s in keys(pool_map)) {
	/* сеанс 187: dir-ключи едут в персист — свежие из dir_map, иначе
	 * предыдущие (нет измерения = нет записи, не фейк-ноль). */
	const prev_p = (type(pstate[s]) == "object") ? pstate[s] : null;
	const dm2 = dir_map[s];
	const row2 = { last_ts: now, alive: pool_map[s].alive, dead: pool_map[s].dead,
		dead_whole: pool_map[s].dead_whole };
	if (dm2 != null) {
		row2.alive_dir = dm2.alive;
		row2.dead_dir = dm2.dead;
		row2.dead_whole_dir = dm2.dead_whole;
	} else if (prev_p != null && prev_p.alive_dir != null) {
		row2.alive_dir = prev_p.alive_dir;
		row2.dead_dir = prev_p.dead_dir;
		row2.dead_whole_dir = prev_p.dead_whole_dir;
	}
	pstate[s] = row2;
}
/* touch the primary even when the whole edges stage failed (the catalog
 * itself is a fact: the stream pool was referenced today) */
const PSUF_FULL = "'$PSUF'.googlevideo.com";
if (pstate[PSUF_FULL] == null)
	pstate[PSUF_FULL] = { last_ts: now, alive: -1, dead: -1, dead_whole: -1 };
else
	pstate[PSUF_FULL].last_ts = now;
/* prune >30d, cap 40 by freshness (LRU) */
let prow = [];
for (let s in keys(pstate))
	if (type(pstate[s]) == "object" && now - int(pstate[s].last_ts || 0) <= 2592000)
		push(prow, { s: s, ts: int(pstate[s].last_ts || 0) });
sort(prow, (a, b) => b.ts - a.ts);
let pnew = {};
for (let r in prow) {
	if (length(keys(pnew)) >= 40) break;
	pnew[r.s] = pstate[r.s];
}
/* сеанс 187: атомарная запись персиста (урок automation.atomic_write:
 * writefile = truncate+write — читатель посреди записи видит ОБРЕЗАННЫЙ
 * JSON; живой случай пойнан: фидер стиринга читал pools.json и получал
 * «unexpected end of data» → честный пустой набор, но данными впустую).
 * tmp + mv -f — контракт проекта. ⚠ heredoc однократно-кавыченный:
 * ВНУТРИ него нельзя строк с одинарными кавычками (урок 187: они рвут
 * shell-литерал и молча калечат программу ucode — пойман живьём: mv не
 * выполнился, персист остался .tmp) — mv с ДВОЙНЫМИ кавычками. */
writefile(POOLSF + ".tmp", sprintf("%.J\n", { ts: now, pools: pnew }));
system(`mv -f "${POOLSF}.tmp" "${POOLSF}"`);

/* ── Ф6.4 v3: измерения, второй IP, QUIC A/B, вердикты ─────────────────── */

/* (аудит 84) baseline-СЕРИЯ: контрольный проход после прогона; хост,
 * расходящийся между двумя baseline, — ДРЕЙФ и теряет бесплатный зачёт
 * (консервативно: dist = хост НЕ прошёл ХОТЯ БЫ один из двух baseline;
 * free-pass требует ОБОИХ). */
const base1 = parse(TMP + "/baseline.json");
const ctrl = parse(TMP + "/control.json");
const b1map = {}, c2map = {};
/* ч.232: the browser-class baseline verdicts of both series (free credit
 * requires BOTH passes of BOTH classes; unknown class → conservative NOT free). */
const b1u = {}, c2u = {};
if (base1 && type(base1.results) == "array")
	for (let r in base1.results)
		if (type(r) == "object" && r.tag) { b1map[r.tag] = (r.ok == 1); b1u[r.tag] = (r.uok == 1); }
const drift = [];
if (ctrl && type(ctrl.results) == "array")
	for (let r in ctrl.results)
		if (type(r) == "object" && r.tag) {
			c2map[r.tag] = (r.ok == 1);
			c2u[r.tag] = (r.uok == 1);
			if (b1map[r.tag] != null && b1map[r.tag] !== c2map[r.tag])
				push(drift, { tag: r.tag, first: (b1map[r.tag] == true), control: (c2map[r.tag] == true) });
		}
for (let s in strategies)
	for (let h in s.hosts) {
		const b1 = (b1map[h.tag] != null) ? b1map[h.tag] : false;
		const b2 = (c2map[h.tag] != null) ? c2map[h.tag] : false;
		const fu1 = (u_meas2) ? ((b1u[h.tag] != null) ? b1u[h.tag] : false) : false;
		const fu2 = (u_meas2) ? ((c2u[h.tag] != null) ? c2u[h.tag] : false) : false;
		h.dist = !(b1 && b2) && !(fu1 && fu2);
	}

/* ч.231 (honest Passed column): a handshake host that failed for EVERY
 * strategy AND both baseline series is dead on this network/sweep — it
 * measures the NETWORK, not the strategy, and painted every row red
 * (live fact 2026-11-07: the telegram.org pinned-IP timed out for all 16
 * strategies → every row showed a misleading "3/4"). Exclude such hosts
 * from the per-strategy ok/total display counts; the per-host detail stays
 * in hosts[] (tooltip) and the sweep-level list goes to the result as
 * dead_hosts. Distinguishing (dist) counts, score and verdicts are
 * untouched — a dead host never passed, so it never contributed. */
const tag_seen = {};
for (let s in strategies)
	for (let h in s.hosts)
		if (type(h) === "object" && h.tag != null && tag_seen[h.tag] == null)
			tag_seen[h.tag] = h;
const dead_map = {};
const dead_hosts = [];
for (let tag in keys(tag_seen)) {
	const h0 = tag_seen[tag];
	const b1 = (b1map[tag] != null) ? b1map[tag] : false;
	const b2 = (c2map[tag] != null) ? c2map[tag] : false;
	let any_ok = false;
	for (let s in strategies)
		for (let h in s.hosts)
			if (type(h) === "object" && h.tag === tag && h.ok == true) { any_ok = true; break; }
	if (!any_ok && !b1 && !b2) {
		dead_map[tag] = true;
		push(dead_hosts, { tag: tag, label: (type(h0) === "object") ? (h0.label || tag) : tag,
			host: (type(h0) === "object") ? (h0.host || "") : "" });
	}
}
if (length(dead_hosts))
	for (let s in strategies) {
		let ok2 = 0, tot2 = 0;
		for (let h in s.hosts) {
			if (type(h) !== "object" || dead_map[h.tag]) continue;
			tot2++;
			if (h.ok == true) ok2++;
		}
		s.ok = ok2;
		s.total = tot2;
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
			s.quic_ab = { strategy: "" + qj.quic,
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
/* ч.229 FIX (ranking cycle): the old pairwise comparator (deep ratio →
 * START >25% → vSTART >25% → flow >10% → avg_tls → score) is NOT a total
 * order — the thresholds create cycles. Live proof, run ts 1794065143:
 * Fake+fakedsplit beat Default pairwise on flow (522563 vs 464903 B/s,
 * 12.4% > 10%), Multisplit beat fakedsplit on avg_tls (174 < 179), and
 * Default tied Multisplit on every metric — M > F > D ≈ M — so the stable
 * sort crowned the corpus-first Default with the WORST measured flow.
 * Rank classes are now computed against the BEST measured value in the
 * deep set (the same noise margins, applied globally): a strategy worse
 * than the threshold drops to class 1, others stay 0. Total order:
 * deep ratio desc → classes → avg_tls → score → corpus rank. */
let b_start = 0, b_vstart = 0, b_flow = 0;
for (let s in tested) {
	const st = int(s.start_ms || 0);
	if (st > 0 && (b_start == 0 || st < b_start)) b_start = st;
	const vs = int(s.stream_start_ms || 0);
	if (vs > 0 && (b_vstart == 0 || vs < b_vstart)) b_vstart = vs;
	const fl = int(s.stream || 0);
	if (fl > b_flow) b_flow = fl;
}
for (let s in tested) {
	const st = int(s.start_ms || 0);
	s.rk_start = (b_start > 0 && st > 0 && st > b_start + int(b_start / 4)) ? 1 : 0;
	const vs = int(s.stream_start_ms || 0);
	s.rk_vstart = (b_vstart > 0 && vs > 0 && vs > b_vstart + int(b_vstart / 4)) ? 1 : 0;
	const fl = int(s.stream || 0);
	/* a measured flow beats an unmeasured (0) one outright — the old
	 * pairwise rule carried that; the class keeps it */
	s.rk_flow = (b_flow > 0 && (fl <= 0 || fl < b_flow - int(b_flow / 10))) ? 1 : 0;
}
for (let n = 0; n < length(tested); n++)
	tested[n].rk_i = n;
sort(tested, (a, b) => {
	const ra = a.deep.total ? (a.deep.ok * 1.0 / a.deep.total) : 0;
	const rb = b.deep.total ? (b.deep.ok * 1.0 / b.deep.total) : 0;
	if (ra != rb)
		return rb - ra;
	if (a.rk_start != b.rk_start)
		return a.rk_start - b.rk_start;
	if (a.rk_vstart != b.rk_vstart)
		return a.rk_vstart - b.rk_vstart;
	if (a.rk_flow != b.rk_flow)
		return a.rk_flow - b.rk_flow;
	return (int(a.avg_tls_ms || 0) - int(b.avg_tls_ms || 0)) ||
		(b.score - a.score) || (a.rk_i - b.rk_i);
});
const final = [];
for (let s in tested) push(final, s);
for (let s in rest) push(final, s);
/* ── ч.232: метки С УСТРОЙСТВА — наивысший вес ранжирования ──────────────
 * Проба-модель лаборатории не видит ClientHello браузера/телефона, QUIC-
 * фоллбек и паттерн соединений (живой факт 2026-11-07: Default best_verified
 * опровергнут телефоном). Метки пользователя хранит
 * /etc/ravnex/device_verdicts.json: works — выбор подтверждён устройством
 * (первый приоритет resource_verdict и верх таблицы), broken — опровергнута
 * (не выбирается при наличии альтернатив, низ таблицы). */
const DEVP = "/etc/ravnex/device_verdicts.json";
let devres = {};
if (access(DEVP)) {
	const dj = parse(DEVP);
	if (dj != null && type(dj.resources) === "object")
		devres = dj.resources;
}
const dev_of = (resname) => (type(devres["" + resname]) === "object") ? devres["" + resname] : null;
const dev_cls = (s) => {
	let w = false, b = false;
	for (let rn in devres) {
		const dm = devres[rn];
		if (type(dm) !== "object")
			continue;
		const mv = dm[s.args];
		const v = (mv != null && type(mv) === "object") ? ("" + (mv.verdict || "")) : "";
		if (v === "works") w = true;
		if (v === "broken") b = true;
	}
	return w ? 0 : (b ? 2 : 1);
};
for (let n = 0; n < length(final); n++)
	final[n].dev_i = n;
sort(final, (a, b) => {
	const ca = dev_cls(a), cb = dev_cls(b);
	if (ca != cb)
		return ca - cb;
	return a.dev_i - b.dev_i;
});
/* Финалисты получают ВЕРДИКТ по каждому ресурсу (аудит 92):
 * best_verified / best_available / no_candidate.
 * ч.235 (завершение В3): telegram УБРАН из RES_TAGS — свип не пробует tg,
 * пустой entries дал бы красный no_candidate («ни одна не прошла») вместо
 * честного отсутствия вердикта; оптимизатор при отсутствующем ключе даёт
 * via_node (lab_verdict=null), автопилот tg не управляет (ч.233). */
const RES_TAGS = { youtube: "yt", discord: "dc", general: null };
const udp_any = (function () {
	for (let s in strategies)
		if (match(s.args || "", /--filter-udp=443/)) return true;
	return false;
})();
const qv = (quic != null && quic.verdict != null) ? quic.verdict : "";
/* ч.269: контекст вердиктов — DNS-наборы тега, инфраструктурно мёртвые края,
 * STUN-baseline (Discord голос: провайдер режет UDP/3478?) и провайдер-скан. */
const rj = parse(TMP + "/resolve.json");
const dns_sets = (rj != null && type(rj) === "object" && type(rj.dns) === "object") ? rj.dns : null;
const stun_sb = parse(TMP + "/stun_base.json");
const stun_baseline = (function () {
	/* ч.269: the DEDICATED no-strategy STUN baseline (cheap dc-only
	 * baseline+deep run) — the honest provider-state source; the old
	 * fallback (baseline.json deep dcv) never existed: the baseline pass
	 * runs WITHOUT --deep, so dcv was never measured there. */
	if (stun_sb != null && type(stun_sb.results) == "array")
		for (let r in stun_sb.results) {
			if (type(r) != "object" || r.tag != "dc") continue;
			for (let it in (r.deep || [])) {
				if (type(it) == "object" && it.id == "dcv") return (it.ok == 1);
			}
		}
	return null;
})();
/* ч.269 observability: how many dc deep items the baseline+deep probe
 * actually carried (0 ⇒ the probe degenerated — the merge must say so
 * instead of silently judging dcv without a baseline). */
const stun_items = (function () {
	let n = 0;
	if (stun_sb != null && type(stun_sb.results) == "array")
		for (let r in stun_sb.results) {
			if (type(r) != "object" || r.tag != "dc") continue;
			n += length(r.deep || []);
		}
	return n;
})();
const scanj = parse("/var/run/ravnex/wizard_scan_result.json");
let scan_note = null;
if (scanj != null && type(scanj) === "object") {
	for (let sk in ["isp_name", "isp", "provider", "asn_name"]) {
		const sv = scanj[sk];
		if (sv != null && type(sv) === "string" && length(sv)) {
			scan_note = "провайдер (скан): " + sv;
			break;
		}
	}
}
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
			deep_items = [ { id: "reach", ok: reach_ok ? 1 : 0 } ];
		} else {
			for (let h in s.hosts)
				if (h.tag == tag) reach_ok = (h.ok && h.dist);
			if (s.deep && type(s.deep.hosts) === "array")
				for (let dh in s.deep.hosts)
					if (dh.tag == tag) deep_items = dh.items || [];
		}
		push(entries, { name: s.name, args: s.args, reach_ok: reach_ok, deep_items: deep_items,
			unstable_edges: int(s.unstable_edges || 0) });
	}
	/* ч.234: dead-тег (никто не прошёл хост + оба контрольных прохода
	 * провалены, dead_map выше) — вход честного «измерение невозможно»;
	 * general (tag=null) имеет только синтетический reach-пункт — false. */
	const dead_tag = (tag == null) ? false : (dead_map[tag] == true);
	const extra = {
		dns: (tag != null && dns_sets != null && type(dns_sets[tag]) === "object")
			? { verdict: "" + (dns_sets[tag].verdict || ""), note: "" + (dns_sets[tag].note || "") }
			: null,
		dead_edges: (resname === "youtube") ? infra_dead_edges : null,
		revived: (resname === "youtube") ? revived_edges : null,
		pools: (resname === "youtube") ? pool_extra : null,
		stun_baseline: (resname === "discord") ? stun_baseline : null,
		scan_note: scan_note
	};
	verdicts[resname] = resource_verdict(entries, (qv != "") ? qv : null,
		udp_any, dev_of(resname), dead_tag, extra);
}

const bnote = [];
const bj = parse(TMP + "/baseline.json");
if (bj && type(bj.results) == "array")
	for (let r in bj.results)
		if (type(r) == "object")
			push(bnote, { tag: r.tag, label: r.label || r.tag, host: r.host || "", ok: (r.ok == 1),
				uok: (u_meas2) ? (r.uok == 1) : null });
const cnote = [];
if (ctrl && type(ctrl.results) == "array")
	for (let r in ctrl.results)
		if (type(r) == "object")
			push(cnote, { tag: r.tag, label: r.label || r.tag, host: r.host || "", ok: (r.ok == 1),
				uok: (u_meas2) ? (r.uok == 1) : null });

/* ч.229: the note may claim "the current strategy" ONLY when it was
 * actually measured (rank.cur_measured — set at the append site in the
 * rank pass; the old hardcoded note claimed it even for runs where the
 * --new composite was excluded and never measured). */
const cur_measured = (rank.cur_measured == true);
/* ч.235: load samples (1-min LA per stage) — retrospectively distinguishes
 * «the host died» from «the router was choking» (prod nfqws2 + candidate +
 * probes at once). Last sample per stage wins. */
const loads = {};
if (access(TMP + "/load.tsv")) {
	const llines = split(trim(readfile(TMP + "/load.tsv") || ""), "\n");
	for (let li = 0; li < length(llines); li++) {
		const lparts = split(trim(llines[li]), " ");
		if (length(lparts) == 2 && length(lparts[0]) > 0 && length(lparts[1]) > 0)
			loads[lparts[0]] = "" + lparts[1];
	}
}
writefile(RESULT, sprintf("%.J\n", {
	running: false, done: length(final), total: length(final),
	rounds: ROUNDS, majority: MAJ, ts: now, baseline: bnote, strategies: final,
	deep_count: deepN, deep_selected: length(dlist_items),
	deep_failed: deep_failed, deep_skipped: skipped_ids, quic: quic,
	probe_mode: "'$PMODE'",
	load_now: "'$LNOW'",
	loads: loads,
	/* ч.232: the browser-ClientHello probe class verdict — false = the
	 * utls_probe binary is not installed, Passed honestly measures only
	 * the curl class (status quo). */
	utls_probe: u_meas2, utls_fp: u_meas2 ? "chrome" : "",
	lab: "v3",
	dead_hosts: dead_hosts,
	baseline_series: { first: bnote, control: cnote, drift: drift },
	dns_sets: dns_sets,
	edge_matrix: emx,
	pool_matrix: pmx,
	pool_matrix_direct: pmxd,
	pools_state: pnew,
	infra_dead_edges: infra_dead_edges,
	revived_edges: revived_edges,
	stun_baseline: stun_baseline,
	stun_items: stun_items,
	verdicts: verdicts,
	deep_note: "top " + deepN + " of " + length(dlist_items) + " selected deep-checked: family-diverse leaders + imported/generated/tachyon/community bests" + (cur_measured ? " + the current strategy" : "") + "; failed: " + ((length(deep_failed)) ? join(", ", deep_failed) : "none") + "; probes identical across all deep-tested strategies (" + join(", ", skipped_ids) + ") do not rank" + (u_meas2 ? "; Passed = curl AND browser ClientHello (utls_probe chrome)" : "; browser ClientHello probe NOT installed — Passed measures only the curl class")
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
' 2>>/var/run/ravnex/fuzz_stderr.log
rm -rf "$TMP"
echo '{"running":false,"done":'$DONE',"total":'$TOTAL',"rounds":'$ROUNDS',"probe_mode":"'$PMODE'"}' > "$STATUS"
