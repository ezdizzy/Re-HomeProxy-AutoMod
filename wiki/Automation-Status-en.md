🇬🇧 [English](Automation-Status-en) | 🇷🇺 [Русский](Automation-Status-ru)

# Auto-bypass

The **Auto-bypass** page is the home of the self-learning engine and the scheduled autopilot.
This is a user handbook: what the system does on its own, how to read its verdicts, and where
its boundaries are.

---

## The self-learning engine

Automatically discovers sites unreachable directly: traffic that **fails directly but works through the
proxy** is added to the routing rule lists.

- **Candidate sources**: DNS queries (captured before the connection is established), Clash
  lists, SNI capture by the built-in sniffer.
- **Each candidate is probed twice**: directly and through the main path. Only entries that
  fail directly but work via proxy make it into the list.
- **Instant application (INSTANT)**: what is learned is applied with a hot reload — **no
  connection drops**, no core restart.
- **Compatibility**: fully compatible with ByeDPI and Zapret — learned sites simply ride your
  main path.

### Block types (per-resource verdict)

The engine distinguishes **how** a resource is blocked and shows it in the table:

| Badge | Meaning |
|---|---|
| `tls_dpi` | DPI filtering on TLS metadata |
| `dns_poison` | DNS response poisoning |
| `stub` | Provider stub |
| `sigpage` | Refusal page (signature block) |
| `hardcode` | Hardcoded address |
| `upstream_blocked` | Blocked at the upstream |

### QUIC context

- **QUIC contrast**: the engine measures UDP/443 (Version Negotiation) on the learned hosts — the
  `tcp_only_block` / `blocked_both` / `quic_dead` classes are visible in the verdicts and the «Why»
  column; a control probe from the router's own WAN every 6 h catches an ISP swapping VN responses
  (in that case the QUIC measurements are flagged unreliable).
- **QUIC drop**: UDP/443 to hosts sent through the proxy is dropped in the kernel (route-reject) —
  QUIC cannot ride a SOCKS proxy anyway, and raw direct h3 gets cut mid-stream by the ISP; the
  browser instantly falls back to TCP. A host learned «by pain» while QUIC was alive keeps the
  QUIC drop even after being taken off the bypass — the «removed → QUIC pain → put back» cycle
  does not repeat.

### Verdict stability

- **Flap windows**: ≥3 verdict changes within 6 h make an honest «Unstable» (Flapping) episode with
  per-host event suppression and a counter. A direct learn shortly after a reverse one requires
  2 confirmations within 10 minutes (the first learn of any host is instant, critical tracks have
  no brake); a dead domain is removed only after a second independent NXDOMAIN measurement
  15 minutes later.
- **Pain-aware heal**: the take-off-the-bypass series does not finish while the user is actively
  using the resource (the pain is fresh) — but not forever: after two deferred series the heal
  finishes honestly («the deferral budget is exhausted, the direct path kept confirming»). Events
  are worded «taken off the bypass».

### The resource table

- The **Resource** column holds a domain or an IP address; the **Type** column shows the entry
  kind and the probe verdict.
- Entries are written atomically — status cards never show «half a file».

### RU-internet protection

Domains under **`.ru`, `.рф`, `.su` are never probed** and never enter the proxy lists: at
startup the engine removes previously learned `.ru` domains from the list. Russian resources
always go direct.

### When the engine is paused

- in **«Everything via node»** — everything is tunneled, there is nothing to learn;
- when the Main node is **Direct** — there is no proxy side to probe against;
- in the **Direct** mode — all mechanisms are off.

The pause is shown honestly on the page with its reason — switch to «Blocking bypass» to
continue.

---

## The DPI autopilot

A permanent strategy watchdog (as opposed to the one-shot **auto-pick** on
[Strategy master](Routing-Master-en)):

- on schedule it re-ranks the verified strategies and applies the best one per resource;
- when a resource stops answering it immediately applies the next alternative;
- **verdicts**: alive / degraded / dead — every change is backed by a measurement;
- every application takes a **server-side snapshot** (the rollback is always available) and
  verifies the resource live;
- settings: enable, resources, re-ranking interval, nightly auto-pick.

---

## Native helpers (Go)

- **probe_pool** — batch probing of candidates;
- **sni_sniffer** — SNI capture as a candidate source;
- **utls_probe** — a browser-style ClientHello probe; installed from the release zip, deliberately
  absent from the feed.

Helper version parity with the app version is controlled — any drift is visible in the
«Application» card on Maintenance.

---

## See also

- [Routing Master](Routing-Master-en) — the Strategy Lab and the one-click pick
- [Hot Swap and reliability](Hot-Swap-and-Reliability-en) — what the system does on failures
