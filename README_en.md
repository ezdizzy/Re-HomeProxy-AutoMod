[**Русский 🇷🇺**](README.md) / [**English 🇬🇧**](README_en.md)

![Ravnex](docs/img/logo_hero.png)

# Ravnex

**Own the Route.**

A multi-core proxy platform for OpenWrt: VPN subscriptions, VPN-free DPI bypass, automation,
monitoring and diagnostics — all from the LuCI web interface, all local on the router.

> The project was previously known as **Re:HomeProxy AutoMod** (a fork of
> [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy)). From the 3.0 branch on it
> develops under the **Ravnex** name. The package and service keep the technical `homeproxy` name —
> updates from previous releases apply in place, with no manual steps.

[![Release](https://img.shields.io/github/v/release/ezdizzy/re-homeproxy?style=for-the-badge&color=22C55E)](../../releases/latest)
[![Stars](https://img.shields.io/github/stars/ezdizzy/re-homeproxy?style=for-the-badge&color=22C55E)](../../stargazers)
[![License](https://img.shields.io/github/license/ezdizzy/re-homeproxy?style=for-the-badge&color=22C55E)](LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-24.10%20%7C%2025.12%2B%20%7C%20SNAPSHOT-for-the-badge?style=for-the-badge&logo=openwrt&color=00B5E2)](https://openwrt.org/)

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

## How traffic flows

1. **Trusted resources** (RU services, banks, government) — straight out, zero overhead.
2. **Zapret 2 (`nfqws2`)** — packet-level desynchronization via NFQUEUE: YouTube, Discord and more open
   **with no VPN and no subscription**, fast, with the Russian region preserved.
3. **ByeDPI (`ciadpi`)** — SOCKS-level desynchronizer: 47 ready presets and a strategy tester.
4. **Proxy core** — blocked and private routes through your node/subscription: VLESS (Reality/XHTTP),
   Hysteria2, VMess, Trojan, Shadowsocks, WireGuard/**AmneziaWG**, SSH, NaiveProxy, Mieru and more.
5. **Smart DNS** — separate plain/secure pools, every query raced across the whole pool
   (the [mosdns](https://github.com/IrineSistiana/mosdns) engine) with quality control and
   automatic pruning of dead servers.

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
- **Diagnostics** — core, DNS, nftables intercept, connectivity checks + a support report.
- **Snapshots & recovery** — one-click config backup and an emergency «restore internet (direct)».

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

The core, ByeDPI, Zapret 2 and mosdns are installed from the **Core & Tools** tab — the installer
detects the architecture and picks a fitting build. Detailed manual steps live in the
[wiki](../../wiki/Getting-Started-en).

### Updating

**Core & Tools → Application → Check update**. Versions are compared against the latest GitHub
release; the update applies in place and rpcd restarts automatically. Updates from previous
versions (Re:HomeProxy AutoMod 2.x) need no manual steps — the app is called Ravnex once the new
version is installed.

## 3.0 roadmap

The 3.0 branch (the Ravnex rebrand) develops in four directions:

- **Design v3** — a unified design system in the spirit of the logo, an icon set, an Overview
  brand block.
- **Support Bundle** — collect full diagnostics (configs/logs/daemon states) into one archive with
  automatic secret redaction: «Build report» → attach to an issue or send to the bot.
- **YouTube probes v4** — long stream windows, bitrate control, QUIC and googlevideo-region
  awareness + calibration from your «works well/poorly» feedback (ranking threshold backtests).
- **Pre-release audit** — leaks, performance, hangs: static checks + a 24-hour stress run of all
  daemons.

## Documentation

Full guides live in the **[wiki](../../wiki/Home)**:

- [Getting started](../../wiki/Getting-Started-en) — from a fresh install to a working connection
- [Core management](../../wiki/Core-Management-en) — hiddify-core or sing-box-extended, builds, memory
- [Supported protocols](../../wiki/Supported-Protocols-en) — every protocol and its build tags
- [Subscriptions & node import](../../wiki/Subscriptions-en) — share links, .conf, Amnezia `vpn://`, base64
- [Routing & access control](../../wiki/Routing-and-Access-Control-en)
- [DNS settings](../../wiki/DNS-Settings-en) — pools, reserve DNS and MultiDNS
- [ByeDPI](../../wiki/ByeDPI-en) · [Zapret](../../wiki/Zapret-en) — presets, testers, strategies
- [Custom routing](../../wiki/Custom-Routing-en) · [Custom JSON config](../../wiki/Custom-JSON-Config-en)
- [Automation](../../wiki/Automation-Status-en) · [Troubleshooting](../../wiki/Troubleshooting-en)

## Security & privacy

- **LAN only** — the app opens no WAN ports; local service listeners bind to loopback only.
- **Everything local** — the UI loads no external CDN assets/fonts; charts are built client-side.
- **Upstream-signed binaries** — cores and DPI engines are downloaded from their official releases
  (signed apk keys); the app itself is built by GitHub CI from this repository.

## Credits

The project builds on the work of the open-source community:

- [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy) — the original LuCI app
- [hiddify-core](https://github.com/hiddify/hiddify-core) · [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) · [sing-box](https://sing-box.sagernet.org) — proxy cores
- [zapret2 (bol-van)](https://github.com/bol-van/zapret2) and [ByeDPI (hufrea)](https://github.com/hufrea/byedpi) — DPI bypass; OpenWrt packages by [1andrevich](https://github.com/1andrevich)
- [Re:Filter](https://github.com/1andrevich/re-filter), [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) — routing lists
- [StressOzz/Zapret-Manager](https://github.com/StressOzz/Zapret-Manager) — strategy catalog
- [1andrevich/homeproxy-hiddify](https://github.com/1andrevich/homeproxy-hiddify) — the direct base of the Re:HomeProxy line

All trademarks belong to their owners and are mentioned nominatively.

## License

[GPL-2.0-only](LICENSE) — same as the original LuCI app. Cores and DPI engines ship under their
own licenses and are downloaded at install time from their own releases.
