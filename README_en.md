[**Русский 🇷🇺**](README.md) / [**English 🇬🇧**](README_en.md)

![Ravnex](docs/img/logo_hero.png)

# Ravnex

**Own the Route.**

A multi-core proxy platform for OpenWrt: VPN subscriptions, VPN-free DPI bypass, automation,
monitoring and diagnostics — all from the LuCI web interface, all local on the router.

[![Release](https://img.shields.io/github/v/release/ezdizzy/re-homeproxy?style=for-the-badge&color=22C55E)](../../releases/latest)
[![Stars](https://img.shields.io/github/stars/ezdizzy/re-homeproxy?style=for-the-badge&color=22C55E)](../../stargazers)
[![License](https://img.shields.io/github/license/ezdizzy/re-homeproxy?style=for-the-badge&color=22C55E)](LICENSE)
[![OpenWrt](docs/img/badge_openwrt.svg)](https://openwrt.org/)

## About

**Ravnex** is a network-traffic control system for OpenWrt/ImmortalWrt routers that combines:

- **two selectable proxy cores** — [hiddify-core](https://github.com/hiddify/hiddify-core) (a sing-box fork, default)
  and [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) / compact
  [sing-box-extended-lite](https://github.com/MANCrimSon/sing-box-extended-lite) for low-flash devices;
- **two VPN-free DPI bypass engines** — [Zapret 2](https://github.com/bol-van/zapret2) (nfqws2) and
  [ByeDPI](https://github.com/hufrea/byedpi) (ciadpi) with a strategy catalog, a picking lab and an autopilot;
- a **self-learning automation engine** that discovers blocked resources and routes them on its own;
- **hot-standby node failover** (Hot Swap), **DNS server racing** (MultiDNS),
  **parental control**, a **Telegram control bot** and **in-app self-update**.

All logic runs on **ucode** — OpenWrt's native interpreter — so the app is frugal with RAM and needs
no external services: the web UI loads nothing from CDNs, every chart is drawn locally, and update
checks happen only on your request.

## Why Ravnex

- **Blocked-site access with no subscription.** Zapret 2 and ByeDPI run on the router itself:
  YouTube, Discord and thousands of sites open over ordinary traffic with DPI desynchronization.
  A proxy node is needed only for private routes and resources that cannot be unblocked otherwise.
- **Never leaves you offline.** A failed core, engines or firewall chains mean traffic flows
  straight through, not a dead network; with a working WAN you always keep at least the Russian
  internet — an invariant verified live by a cascade of failures. The emergency «Restore internet»
  button returns direct connectivity in one click.
- **A failure is not downtime.** Hot Swap keeps continuously probed backups of the main node and
  switches within seconds without restarting the core; watchdogs repair a broken strategy on
  their own, and the scheduled autopilot watches quality.
- **Honest diagnostics.** Verdicts are built from real measurements; a host unreachable by any
  strategy is excluded from scoring instead of painting the whole table red; differences within
  the noise margin are marked as such.
- **Frugal.** The control logic is ucode with no external runtimes; for weak devices there is a
  compact UPX core build, lite daemon modes, and Auto/Lite/Balanced/Performance profiles.

## How traffic flows

Connections are classified by **nftables** tables and sent down their lanes — no unnecessary
transit through user space:

| Lane | Mechanism | What rides it |
|---|---|---|
| **Direct** | routing around the intercept, zero overhead | trusted resources: RU services, banks, government, local networks |
| **Zapret 2** | [`nfqws2`](https://github.com/bol-van/zapret2) — packet-level desynchronization in NFQUEUE | YouTube, Discord and more open **with no VPN and no subscription**, fast, with the Russian region preserved |
| **ByeDPI** | [`ciadpi`](https://github.com/hufrea/byedpi) — local SOCKS desynchronizer | 47 ready presets and a strategy tester |
| **Proxy core** | hiddify-core / sing-box-extended | blocked and private routes via your node/subscription: VLESS (Reality/XHTTP), Hysteria2, VMess, Trojan, Shadowsocks, WireGuard/**AmneziaWG**, SSH, NaiveProxy, Mieru and more |
| **Smart DNS** | [mosdns](https://github.com/IrineSistiana/mosdns) — every query races the whole pool | separate plain/secure pools, quality control, automatic pruning of dead servers |

## How it works

- **Everything runs on the router.** Background daemons are written in **ucode** — OpenWrt's
  native interpreter — and consume single-digit megabytes of RAM; Go is used sparingly, for
  native helpers (batch probing, SNI capture). The web UI talks to the daemon through `rpcd`
  (ubus) with read/write ACL separation.
- **Config in UCI, live state in tmpfs.** Settings live in `/etc/config`; daemon runtime state
  lives in `/var/run`, so flash wear stays minimal.
- **Hot reload instead of restarts.** Learned rules, resource lists and routing changes are
  applied by re-reading configs — without dropping established connections.
- **Last-known-good for critical configs.** Core, mosdns, rule-sets, RU-geo: a candidate is
  generated and verified beside the working one, swaps the file atomically and only becomes the
  new `.lastgood` after a live service verification; rollback is automatic.
- **Fail-safe interception.** Until TUN is up, the «nowhere» route is pre-closed — there is no
  leak window past the intercept; dead DPI engines or wiped firewall chains mean packets flow
  straight, not a dead network; a snapshot of the provider's DNS servers is kept as dnsmasq's
  last resolver so names still resolve while the proxy DNS chain is down.
- **Watchdogs and self-recovery.** Health keeps live verdicts for every service (ok / degraded /
  down) with cause and confidence; Sentinel is an independent watchdog over the monitoring and
  configs themselves, with a loop guard; Recovery is a coordinator with hysteresis, exponential
  retries and an auto-repair budget.
- **Signed feed with integrity checks.** Cores, DPI engines and helpers come from our mirror of
  the upstreams' official releases, signed with our key; feed files are verified against the
  sha256 in the manifest before installation.

## Features

### Routing & reliability
- **Routing Wizard** — an interactive hub: provider diagnostics (what is blocked and how — directly
  or via your rules), «Services → exits» (a per-service exit with live verification), DPI bypass,
  strategy catalog imports.
- **Hot Swap** — hot standby for the main node: several continuously probed connections and a
  switch to a live backup within seconds **without restarting the core**; anti-flap guard.
- **URLTest with three modes** — Auto / Preferred node + auto / Manual list; dead-node watchdog.
- **RU rules** — RU Proxy Rules (Russia Inside, Re:Filter) in one click; the entire Russian
  internet is excluded from the proxy.
- **Direct-connection resilience** — a node failure no longer breaks SSH/DNS/sessions; OAuth
  logins (Google/Microsoft/Apple) ride a pinned secure exit.

### DPI bypass
- **Strategy Lab** — fuzzing of the whole strategy corpus on an isolated NFQUEUE with a baseline
  run, per-round ranking, and «preview start» + «stream speed» metrics.
- **One-click pick & autopilot** — pick the best strategy for YouTube/Discord with one button; the
  scheduled autopilot watches quality (alive/degraded/dead verdicts) and repairs a broken strategy.
- **Composition** — different strategies for different resources at the same time (a YouTube profile
  + a Discord profile + a general fallback), with a server-side snapshot and a rollback button.
- **nfqws2 multi-strategies** — one process with several profiles and separate hostlists; a custom
  strategy generator and an editable TSPU list (dpi-detect).

### Automation & control
- **Self-learning engine** — discovers blocked sites (DNS/Clash/SNI sources), classifies the block
  type (DPI / DNS poisoning / stub / refusal page), self-heals and applies what it learned with a
  hot reload that never drops connections; native (Go) helpers for batch probing and SNI capture.
- **Control** — parental control: devices from the live network, site rules, schedules, Wi-Fi,
  journal — and the same through the Telegram bot.
- **Telegram bot v2** — status, nodes, restart-free switching, snapshots, push notifications
  (node changes, failures, learning) with dedup and rate-limiting.

### Network & diagnostics
- **MultiDNS (mosdns)** — every DNS query races the whole pool; the fastest live answer wins; a
  quality daemon verifies that returned IPs actually open sites and prunes dead/poisoned ones.
- **Node monitoring** — a latency/status dashboard and a live connection list with search and filters.
- **Overview** — cards for every subsystem, local SVG charts (CPU/RAM/temperature/connections/
  latency), per-exit traffic, quick actions.
- **Health center** — a system-wide verdict banner, a services table with causes and repair
  buttons, and the full event feed.
- **Diagnostics** — core, DNS, nftables intercept, connectivity checks + a support report.
- **Snapshots & recovery** — one-click config backup and an emergency «restore internet (direct)».

### Server mode
- **The router as an entry point** — inbound listeners: VLESS, Trojan, Hysteria2, Shadowsocks,
  VMess, SOCKS/HTTP (mixed), AnyTLS, MTProxy and more; independent of the client mode — use both
  or neither.
- **Per-inbound firewall switch** — the port stays LAN-only by default; opening it to the internet
  is a separate toggle.
- **TLS out of the box** — your own certificate, one-click self-signed generation, or automatic
  Let's Encrypt / ZeroSSL issuance via ACME (HTTP-01/DNS-01, on ACME-capable builds).

### Install & update
- **Interactive installer** — sets up the app, core, subscription, Hot Swap, MultiDNS, automation
  and Zapret step by step and **never leaves you offline** (with no subscription it enables direct
  mode and creates a «YouTube → Zapret» rule).
- **Self-update** — check and install a new version right from the web UI, no SSH needed.
- **Smart core installer** — picks a build for your free space (including a compact UPX one) and
  architecture; asynchronous installs with live progress.

## Installation

Requirements: OpenWrt/ImmortalWrt **24.10+** (opkg) or **25.12+** (apk). ~40 MB of free space is
recommended.

### Quick install (one command)

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | sh
```

The interactive installer walks you through: app + Russian locale → core → subscription/node →
Hot Swap → MultiDNS → Automation → Zapret 2 with an auto-test → autopilot → ByeDPI.
Re-running the script opens the settings menu. If GitHub is blocked, point at a mirror
(the variable goes before `sh`):

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | GH_MIRROR=https://your.mirror sh
```

### Manual packages

APK (OpenWrt 25.12+):

```sh
wget -O /tmp/homeproxy-hiddify.pub https://github.com/ezdizzy/re-homeproxy/releases/latest/download/homeproxy-hiddify.pub
cp /tmp/homeproxy-hiddify.pub /etc/apk/keys/
wget -O /tmp/app.apk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-app-re-homeproxy[^"]*\.apk' | head -1)"
apk add /tmp/app.apk
```

opkg (OpenWrt 24.10):

```sh
wget -O /tmp/app.ipk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-app-re-homeproxy[^"]*\.ipk' | head -1)"
opkg install /tmp/app.ipk
```

The core, ByeDPI, Zapret 2 and mosdns are installed from the **Maintenance → Core management**
page — the installer detects the architecture and picks a fitting build. Detailed manual steps
live in the [wiki](../../wiki/Getting-Started-en).

### Updating

**Maintenance → Core management → Application → Check update**. Versions are compared against
the latest GitHub release; the update applies in place and rpcd restarts automatically. Updates
from previous versions (Re:HomeProxy AutoMod 2.x) need no manual steps — the app is called Ravnex
once the new version is installed.

## Documentation

Full guides live in the **[wiki](../../wiki/Home)**:

- [Getting started](../../wiki/Getting-Started-en) — from a fresh install to a working connection
- [Installation & updates](../../wiki/Installation-and-Updates-en) — installer, mirrors, self-update, the feed
- [Overview](../../wiki/Overview-en) — the home screen: cards, charts, quick actions
- [Core management](../../wiki/Core-Management-en) — hiddify-core or sing-box-extended, builds, memory
- [Supported protocols](../../wiki/Supported-Protocols-en) — every protocol and its build tags
- [Subscriptions & node import](../../wiki/Subscriptions-en) — share links, .conf, Amnezia `vpn://`, base64
- [Routing Master](../../wiki/Routing-Master-en) — DPI bypass, the Lab, service rules
- [Routing & access control](../../wiki/Routing-and-Access-Control-en) — modes, the exit engine
- [Hot Swap & reliability](../../wiki/Hot-Swap-and-Reliability-en) — node standby, the RU-internet invariant
- [Monitoring & connections](../../wiki/Monitoring-and-Connections-en) — dashboard, Health center
- [Access control](../../wiki/Access-Control-en) · [Phone control](../../wiki/Telegram-en)
- [Auto-bypass](../../wiki/Automation-Status-en) — the self-learning engine and the autopilot
- [DNS settings](../../wiki/DNS-Settings-en) — pools, reserve DNS and MultiDNS
- [ByeDPI](../../wiki/ByeDPI-en) · [Zapret](../../wiki/Zapret-en) — presets, testers, strategies
- [Advanced rules](../../wiki/Custom-Routing-en) · [Server mode](../../wiki/Server-Settings-en)
- [Troubleshooting](../../wiki/Troubleshooting-en)

## Security & privacy

- **LAN only** — the app opens no WAN ports; local service listeners bind to loopback only.
- **Everything local** — the UI loads no external CDN assets/fonts; charts are built client-side.
- **Own signed repository** — every component (cores, DPI engines, helpers) is delivered from our
  feed, a mirror of the upstreams' official releases signed with our key; the app itself is built
  by GitHub CI from this repository.

## Credits

The project builds on the work of the open-source community:

- [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy) — the original LuCI app
- [hiddify-core](https://github.com/hiddify/hiddify-core) · [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) · [sing-box](https://sing-box.sagernet.org) — proxy cores
- [zapret2 (bol-van)](https://github.com/bol-van/zapret2) and [ByeDPI (hufrea)](https://github.com/hufrea/byedpi) — DPI bypass
- [Re:Filter](https://github.com/1andrevich/re-filter), [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) — routing lists
- [StressOzz/Zapret-Manager](https://github.com/StressOzz/Zapret-Manager) — strategy catalog
- [1andrevich/homeproxy-hiddify](https://github.com/1andrevich/homeproxy-hiddify) — the direct base of the Re:HomeProxy line

All trademarks belong to their owners and are mentioned nominatively.

## License

[GPL-2.0-only](LICENSE) — same as the original LuCI app. Cores and DPI engines ship under their
own licenses and are downloaded at install time from their own releases.
