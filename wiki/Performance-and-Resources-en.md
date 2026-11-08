🇬🇧 [English](Performance-and-Resources-en) | 🇷🇺 [Русский](Performance-and-Resources-ru)

# Resources & performance

Ravnex is built for modest hardware and needs no manual tuning. This page explains where CPU
and RAM go, which safeguards are built in, and what can be tuned deliberately. The figures
below were measured live on a real box: 4 cores, 1 GB RAM, OpenWrt 25.12 — in steady state the
app occupies ~213 MB of RAM (742 MB available) and ~5% of the total CPU capacity.

---

## Where CPU goes

| Consumer | Steady state | Notes |
|---|---|---|
| Proxy core (Go) | a few % of one core | grows with traffic by design (userspace TLS/QUIC, tproxy/redirect) — the price of the feature, not waste |
| nfqws2 / ciadpi | ~0 when idle | nfqws2 only sees the **first 12 packets of each flow** from NFQUEUE — userspace processing is throttled at the firewall level by design |
| Automation engine | a few % of one core | a probe cycle every ~40 s; the tick rate adapts to load/RAM and scales with the resource profile |
| rpcd (web RPC) | depends on the tab | an open tab polls the state; a **background one stays silent** (see «Sleeping tab») |

Bottom line: at idle the system is nearly free; under active traffic the CPU goes to
interception and encryption — inherent to any userspace bypass.

## Memory: three safeguards

### 1. The OOM victim hierarchy

Every respawnable process carries an `oom_score_adj` mark — under peak memory pressure the
kernel recycles renewable processes, not the vital plane:

| Process | adj | Why |
|---|---|---|
| UI/DNS plane (dnsmasq, hostapd, uhttpd, rpcd) | **0** | never a victim |
| Automation engine | **200** | respawnable, state on tmpfs |
| Proxy core, DPI engines | **300** | the first legitimate victims, raised by watchdogs |
| probe_pool, sni_sniffer | **400** | helpers, die first |

This is the cure for the «OOM-killer shot my Wi-Fi» class on weak boxes.

### 2. Memory budgets and the Sentinel

Every daemon has its own RSS and fd norms; the Sentinel watches them independently of the
main monitoring:

| Daemon | warn | crit | Action on crit |
|---|---|---|---|
| proxy core | 384 MB | 512 MB | **automatic core restart** before the OOM-killer fires |
| automation, mosdns | 96 MB | 160 MB | an honest «degraded» verdict |
| probe_pool, sni_sniffer | 48 MB | 96 MB | an honest «degraded» verdict |
| other daemons | 64 MB | 128 MB | an honest «degraded» verdict |

An automatic core restart means ~20 seconds of dropped connections instead of the whole
system collapsing — a deliberate lesser evil, and it rarely triggers (see the next safeguard).

### 3. GOMEMLIMIT — a soft Go heap cap on every box

Go processes (proxy core, mosdns) get a soft-heap limit **on all boxes, not only tiny ones**:

- proxy core — **384 MB**, mosdns — **32 MB**;
- the effective cap = `min(requested, half of the physical RAM)`, so a large request can never
  exceed half of the box's memory;
- the cap is soft: near it Go just collects garbage more often, traffic is never cut.

Historical background: before this safeguard the core's heap on 1 GB boxes was unlimited and
under a load peak could grow to 727–750 MB with an OOM kill and collateral damage. Such a
peak is now impossible by construction.

## The sleeping tab

The web UI polls the router on a schedule (the home screen every 4 s; other pages between
4 and 60 s). Since 3.1.0 the polls honor tab visibility:

- a minimized/background tab **stops talking to the router entirely** (zero RPCs);
- when you switch back, polling resumes instantly, without a manual reload;
- long-operation pages (snapshot generation, reports) stay ungated — they are short-lived,
  and watching their progress is the whole point.

This removes the background rpcd load (a few percent of a core for a permanently open tab),
along with its heat and power cost.

## Resource profiles

The **Maintenance → Resource profile** page: Auto (by cores/RAM) or manual.

| Profile | UI poll rate | Daemons | For |
|---|---|---|---|
| Eco | ×3 slower | reduced samples, state_cap 5000 | boxes ≤256 MB RAM |
| Balanced | ×2 | middle ground | the 512 MB class |
| Performance | ×1 (reference) | full history depth and samples | 1 GB and up |
| Auto | — | picked by hardware | the default |

A profile changes the **frequency and breadth** of observation, not functionality.

## zram / swap — deliberately not used

Swap is neither used nor offered: on flash-constrained boxes zram has little to give, and
boxes with 1 GB of RAM or more do not need the headroom. The peak scenarios are covered by
GOMEMLIMIT + the OOM victim hierarchy.

## Updating from 3.0.x to 3.1.0+

Release 3.1.0 renames the package (`luci-app-re-homeproxy` → `luci-app-ravnex`). On a 3.0.x
box the **Update** button will honestly report the pinned old-package-name conflict in the
apk world (the router is not harmed). The correct path is installing the new version with
the script:

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/ravnex/master/install.sh | sh
```

The installer clears the old world pins and migrates the app to the new name together with
its configuration, rules and history.

## See also

- [Monitoring & connections](Monitoring-and-Connections-en) — live charts and per-daemon resources
- [Hot Swap & reliability](Hot-Swap-and-Reliability-en) — failure behavior
- [Core management](Core-Management-en) — picking a core build for your free space
