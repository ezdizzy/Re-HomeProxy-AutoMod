[**Русский 🇷🇺**](README.md) / [**English 🇬🇧**](README_en.md)


# Re:HomeProxy AutoMod
Orginal project - https://github.com/1andrevich/homeproxy-hiddify

A modern multi-core proxy platform powered by [hiddify-core](https://github.com/hiddify/hiddify-core) and [sing-box-extended](https://github.com/shtorm-7/sing-box-extended).
A fork of [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy).

> **Re:HomeProxy AutoMod** is a mod of Re-HomeProxy by **@ezdizzy**. It builds on the original
> Re-HomeProxy app and adds AutoMod-specific changes (see *AutoMod modifications* below) — most importantly the **Automation**
> tab and **in-app self-update**. The proxy cores, ByeDPI and Zapret engines are fetched from their own upstream releases;
> only the LuCI app and its Russian translation are built here (repo `ezdizzy/re-homeproxy`).

## Overview

Re-HomeProxy is a feature-rich proxy management system, a fresh take on ImmortalWrt's HomeProxy. It runs on a choice of
cores ([hiddify-core](https://github.com/hiddify/hiddify-core) or [sing-box-extended](https://github.com/shtorm-7/sing-box-extended)),
adds a built-in DPI-bypass based on [Zapret2](https://github.com/bol-van/zapret2) and [ByeDPI](https://github.com/hufrea/byedpi)
for un-throttling sites without a VPN, ready-made Russia routing rules, and a one-click core installer — all from the LuCI
web interface.

## What's new in 2.0

Version 2.0 is a major UX rework of the whole interface (still everything local on the router — no external resources):

- **New Overview (home) page** — status cards for every subsystem (core, active node, routing mode, Zapret/ByeDPI with the
  live strategy name and NFQUEUE counters, MultiDNS pools, Automation, Telegram), inline-SVG performance charts
  (CPU / RAM / temperature / connections / node delay / learned-records growth) with auto-scaled axes, a **traffic by
  exit** panel (cumulative bytes and live speeds for VPN / Direct / Zapret / ByeDPI / tg-ws — LAN-client traffic through
  the core only), system parameters and quick actions (restart service, snapshot, emergency "restore internet (direct)").
  Everything is served locally — the page never queries external resources on its own; update availability is checked
  on demand.
- **Routing Wizard (center of the app)** — an interactive hub in four tabs:
  - *Provider diagnostics* — probes YouTube, Discord, Telegram, Google AI, OpenAI, X, Instagram and more through your
    **real paths**: directly, via the main node, and via your **configured routing** (rules, learned lists, Zapret/ByeDPI
    desync) — the way LAN clients are actually served. A redirect chain reset mid-way is not a success; verdicts are
    rc-aware and geo-aware (Gemini "something went wrong" is caught). Per-resource verdicts, DNS comparison and a
    "Configured" column resolve which rule already covers each resource.
  - *Services → exits* — pick an exit for each service (Main node / a specific node / URLTest / Zapret / ByeDPI /
    Direct); the Wizard maintains one routing rule per service (the same records as the manual editor), applies and
    verifies live in one place. Your own domain lists live here too (advanced).
  - *DPI bypass* — engine status, strategy picker with the catalog, **Strategy Lab** (quick/full fuzzing of the whole
    strategy corpus on an isolated NFQUEUE with baseline and majority-of-rounds ranking), **Composition Builder**
    (per-resource profiles of Zapret AND ByeDPI strategies, built/tested server-side, apply with a server snapshot and
    a Restore button that survives page reloads), one-click **Auto-pick** (fuzz → best strategy for the resource →
    apply → live check), the scheduled **Auto-pilot** (periodic re-ranks + health checks that immediately re-pick a
    broken strategy and keep the managed rules on Zapret), catalog import (StressOzz/Zapret-Manager), a **strategy
    generator** that derives new mutations from the best fuzz results, and the editable **TSPU watchlist** (dpi-detect).
    ByeDPI strategy presets, the tester and the engine option flags live here too — the strategy tabs were moved out of
    Node Settings into this card.
  - *Advanced* — the Telegram bot panel (see below) and the **Telegram without a proxy** cards (TG WS Proxy, below).
- **Automation engine overview** — the Automation tab shows how the learning engine actually works: cycle/probe counters,
  engine RAM, learned-records sparkline, verdict breakdown (DPI / DNS-poisoned / stub / refusal / block-page), sources
  of the last cycle and a live event feed.
- **Telegram bot v2** — HTML messages with inline keyboards: /status, /nodes, /switch N (switches the exit without a
  restart), /service, /snapshot, /status_engine, /mute, plus push notifications about Hot Swap node changes, dead URLTest
  nodes, automation learning and service faults (dedup + rate-limit, every toggle configurable in the UI). The bot
  daemon runs always-on and hot-reloads its settings — saving never restarts the service.
- **Telegram without a proxy (TG WS Proxy)** — Telegram messaging that works **transparently for the whole LAN, without
  a VPN and without per-app proxy settings**. Two complementary cards in the Wizard:
  - **Transparent bridge** — the Wizard can install the third-party bridge ([tg-ws-proxy-go](https://github.com/d0mhate/tg-ws-proxy-go), MIT)
    with one button: it runs locally (loopback SOCKS5, auto-restarted by procd) and carries Telegram messaging over a
    WebSocket path DPI does not block; a dedicated routing rule sends Telegram domains and DC IPs through it with an
    automatic fallback to the main node if the bridge dies (voice calls stay UDP and ride the VPN as before). Telegram
    will show the relay's exit country instead of your home IP — that is expected.
  - **TG WS Proxy (rs) detection** — if you already run [tg-ws-proxy-rs](https://github.com/valnesfjord/tg-ws-proxy-rs)
    yourself, the Wizard detects it read-only, shows its status and builds the `tg://` per-client connect link; nothing
    is repacked into this app's packages.
- **Devices & interfaces page** — per-device proxy policy for the LAN, upstream IP policy for the WAN and interface
  binding, separated from the client settings; domain lists moved into the Wizard, empty tabs are gated by mode.
- **nfqws2 multi-strategies** — a single nfqws2 process can run several profiles, each with its own `--hostlist`
  (e.g. a dedicated YouTube profile plus a general fallback); two such composite strategies ship in the corpus.
- **Snapshots & recovery, Hot Swap, MultiDNS** — carried over and verified (a snapshot copies the app configuration and
  the routing lists; Hot Swap keeps hot standbys verified with real probes and switches without a core restart; MultiDNS
  races every query across the pool and prunes dead servers).

## Screenshots

![Overview](docs/img/overview.png)
*Overview: subsystem cards, local SVG charts, system parameters, quick actions.*

![Wizard — DPI bypass & Strategy Lab](docs/img/wizard_dpi.png)
*Routing Wizard — DPI bypass: engine status, strategy catalog, fuzzing on an isolated queue.*

![Wizard — Telegram bot & TG WS Proxy](docs/img/wizard_advanced.png)
*Routing Wizard — Advanced: Telegram bot v2 panel and the Telegram-without-a-proxy card.*

![Automation — engine overview](docs/img/automation_engine.png)
*Automation: learning-engine overview with sparklines and a live event feed.*

## Safety & privacy

- **LAN-only by design** — the app does not open any port to the WAN. The optional tg-ws-proxy-rs component does not
  open WAN ports either (per its own README); nothing in this app exposes your router to the internet.
- **Only upstream-signed binaries** — cores and DPI engines are fetched from their own official releases (signed apk
  keys for hiddify-core/ByeDPI and zapret2). The app itself is built by GitHub CI from this repository.
- **Third-party components stay third-party** — tg-ws-proxy-rs (if you install it) keeps its own LuCI page and its own
  configuration; the Wizard only detects it, shows its status and builds the `tg://` link. Nothing is repacked into this
  app's packages.
- Port ranges used by the app (diagnostic inbounds 5336/5337, MultiDNS listeners, metrics) are checked for collisions
  with third-party components before any integration card reports a working state.

## AutoMod modifications

This mod adds the following on top of the original Re-HomeProxy app:

- **Hot Swap (hot standby)** — keeps several connections alive at once (configurable count): the main node plus hot
  standbys that are continuously verified with real probes. When the main node dies, traffic switches to a working
  standby within seconds **without restarting the core** — direct connections, SSH and DNS never notice. Configured on
  the Client Settings tab (Hot Swap section for a specific main node), status shown on the Node Monitoring page.
- **Direct-connection resilience** — the service no longer restarts "just in case": a dead node no longer triggers a
  restart (Hot Swap switches the selector via the API; in URLTest mode the watchdog first forces the core to re-pick
  with an API-initiated probe), the reload-on-WAN-up trigger is off by default, and LAN DNS gets a fallback resolver
  for the core-restart window.
- **OAuth sign-in stability** — authentication providers (accounts.google.com, login.microsoftonline.com,
  appleid.apple.com, …) ride the same exit as the services that open them, resolve via encrypted DNS and use TCP only
  (QUIC/HTTPS records filtered). Fixes "Sign in with Google" loops on proxied services (endless socialSignInFailed),
  and the automation engine no longer learns auth hosts from indirect evidence.
- **Automation tab** — automatic detection of blocked sites. A background monitor probes hosts both directly and through
  the proxy; a host that fails directly but works via the proxy is remembered and routed through the proxy / ByeDPI / Zapret.
  Raw IP destinations are covered too (games, Telegram data centers, apps without SNI): recurring conntrack addresses are
  verified with a TCP probe through both paths, shared CDN ranges are excluded, and learned entries self-heal — an
  unblocked site returns to the direct path on its own. The learned list is applied with a hot reload — no restart, no
  dropped connections. The engine is adaptive: probe timeouts and confirmation thresholds follow per-host behavior,
  candidates are prioritized by a weighted score across sources (DNS / Clash / SNI), cycle pacing respects CPU load and
  free memory, and plain-view DNS resolves through the local mosdns plain listener when MultiDNS is active. Two optional
  native helpers (Go binaries downloaded per-architecture from releases) speed things up further: **probe_pool** batches
  a whole probe wave into one HTTP/2-capable process instead of many shell workers, and **sni_sniffer** captures TLS
  ClientHello names continuously with a kernel packet filter instead of tcpdump. Without them everything falls back to
  the classic methods automatically.
- **Per-service exits (Services → exits in the Wizard)** — Google AI / Gemini, YouTube, Discord, Telegram and other
  services are routed by explicit routing rules you configure in the Wizard: pick an exit per service (a specific node,
  URLTest, Zapret/ByeDPI or direct), apply and verify live with the AI-exit region check (the Wizard warns when an
  exit's country/IP will be refused by Google AI). No hidden hardcoded lists — the same `proxy_ru_rule` records as the
  manual editor, so both views always agree.
- **DNS Settings page** — every DNS setting in one menu: server pools (plain "Russia" 🔓 + encrypted "Secure" 🔒),
  reserve DNS for setups without MultiDNS, and the **MultiDNS** engine with a live quality monitor.
- **MultiDNS (mosdns engine)** — a DNS accelerator: every query is raced in parallel across all servers of the pool,
  returning the fastest live answer. A quality daemon verifies over HTTPS that the returned IPs actually open sites and
  auto-prunes dead/polluted servers and IPs. Configure it on the dedicated **DNS Settings** page; install/update mosdns
  from its card on **Core & Tools**.
- **URLTest with three modes** — **Auto** (all imported nodes), **Preferred node + auto** (your chosen node first, the
  fastest of the rest when it dies or slows down) and **Manual node list** (classic explicit selection). Test interval and
  tolerance are configurable (30 s / 150 ms by default); existing connections are interrupted on switch. The mieru
  emission for hiddify-core is fixed (port-range format) — such a node used to become "Invalid" and stall URLTest
  failover; the monitor flags nodes the core cannot build.
- **Node Monitoring tab** — a Podkop/Forkop-style dashboard: status cards (core, active node with latency, Zapret, ByeDPI,
  alive-node counter), a per-node latency/status/pool table and **connection monitoring** — a live list of active
  connections with hosts, chains, rules and traffic (plus a "Close all connections" button).
- **Tun TCP/UDP fix** — corrected Tun mode delivery of `tun_mark` flows into the tun device with a loop guard, so Tun
  routing works correctly.
- **In-app self-update** — on the **Core & Tools** tab you can check for a new version and update the LuCI app (and the
  Russian translation) in place, without touching the SSH console. See *Updating the app* below.
- **Fork default** — `install.sh` installs the LuCI app and Russian locale from `ezdizzy/re-homeproxy` by default
  (cores / ByeDPI / Zapret still come from upstream `1andrevich/*`).
- **Interactive installer** — `install.sh` walks you through everything (subscription, Hot Swap, MultiDNS, Automation, Zapret with
  automatic strategy testing, the strategy **auto-pilot** opt-in and ByeDPI) and **never leaves you without internet**:
  with no subscription it switches to direct mode and adds a "YouTube → Zapret" rule. Re-running the script opens a
  configuration menu.
- Complete Russian (ru) translation of every tab, including Automation and DNS-failover strings.

> ⚠️ This is an experimental mod. By installing it you acknowledge that some features may not work as expected —
> use it at your own risk.

## Key Features

- **Multi-core engine** — run on **hiddify-core** or **sing-box-extended**, your choice per device. The built-in
  **Core & Tools** page installs and updates the core for you and automatically picks the right build for your available
  storage (with a compact build for tight-storage devices). Both cores run every protocol the app can configure;
  **Preferred core** switching is capability-aware — nodes a core can't load are skipped automatically (and shown in the UI).
- **Wide protocol support** — Naive (hiddify-core), Mieru, Hysteria, SOCKS, Shadowsocks, ShadowTLS, Trojan,
  VLESS (XHTTP), VMess, WireGuard, **AmneziaWG** (both cores), SSH and more. WireGuard/AmneziaWG nodes pick their
  network stack — userspace (gVisor) or the kernel module (the `wireguard_backend` node option: auto/system/gvisor):
  sing-box builds without gVisor switch to the kernel stack automatically, TUN interfaces get unique names, and
  several WG/AWG endpoints can run at once.
- **Two built-in DPI-bypass engines** — un-throttle and unblock sites (e.g. YouTube, Discord) **without any VPN subscription**:
  - **ByeDPI** ([hufrea/byedpi](https://github.com/hufrea/byedpi)) — a SOCKS-level desync proxy, with 47 ready-made
    strategy presets and a multi-site **strategy tester** that shows which setting actually works on your ISP.
  - **Zapret 2** ([bol-van/zapret2](https://github.com/bol-van/zapret2), nfqws2) — a packet-level NFQUEUE desync that
    mangles the handshake in-place. Selected per routing rule (e.g. send only YouTube/Discord through it), with curated
    presets, optional Discord-voice desync, and its own scoped tester.
- **URLTest auto-selection** — three modes: **Auto** (all nodes), **Preferred node + auto**, **Manual node list**.
  Automatically routes through the fastest reachable node and fails over when one goes down.
- **MultiDNS** — races every DNS server of the pool on each query (mosdns engine) plus a quality daemon with HTTP
  "site opens" verification and automatic pruning of dead servers/IPs.
- **Russia routing rules** — one-click RU Proxy Rules (Russia Inside, Re:Filter) with curated domain/IP lists, so only
  blocked destinations go through the proxy.
- **Subscription support** — import nodes from subscription links (sing-box JSON / Hiddify, base64 / plain share-links,
  and Xray/V2Ray JSON configs) and update them on demand.
- **Diagnostics** — a built-in page to check core/system health, inspect ports, and generate a shareable report.
- **Node Monitoring** — a visual dashboard: which nodes are alive, their latency, Zapret/ByeDPI usage and active
  connections (the **Node Monitoring** tab).
- **Automation** — auto-detect blocked sites and route them through the proxy/ByeDPI/Zapret (see *AutoMod modifications*).
- **In-app self-update** — update the LuCI app from the **Core & Tools** tab.
- **Modern web interface** — clean, responsive LuCI UI with node management, ACL traffic routing, and NFT rule control.

## Prerequisites

- OpenWRT / ImmortalWrt 24.10 or higher (opkg)
- OpenWRT / ImmortalWrt 25.12 or higher (apk)

Optionally legacy build for 23.05 is available in Releases.

## Installation

*~40 MB of free space recommended. Tight on storage? Install the LuCI app first, then use its **Core & Tools** tab
(Services → Re:HomeProxy AutoMod → Core & Tools) to install a core — it auto-picks a build that fits, including a
compact build for small memory devices.*

### Quick install (one-liner)

Interactive installer: it installs the LuCI app (+ Russian language), then walks you through the rest step by step — the
proxy core (with a warning that Telegram/WhatsApp/Instagram and other blocked services won't work without a subscription),
adding a subscription or a share-link, enabling **Hot Swap** (hot-standby failover, on by default), **MultiDNS** and
**Automation**, installing **Zapret 2** with automatic
strategy testing (starts with Hostfakesplit and checks YouTube), the strategy **auto-pilot** opt-in and **ByeDPI** (up to you).

Key point: **you are never left without internet** — with no subscription the script switches to direct mode and
immediately creates a "Source YouTube → Node Zapret" rule. Re-running the script opens a **configuration menu**: add a
subscription/node, pick the main node, toggle MultiDNS/Automation, retest Zapret strategies, update the core, etc. Works
on APK (25.12+), opkg (24.10) and 23.05 legacy. Run over SSH on the router:

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | sh
```

The script detects an existing installation and opens the configuration menu instead of reinstalling.

Behind a blocked/throttled GitHub, pass a mirror (note: the env var goes on `sh`, not `wget`):

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | GH_MIRROR=https://your.mirror sh
```

Prefer to do it by hand? Follow the per-version steps below.

### OpenWRT 25.12+ (APK)

#### 1. Install *luci-app-re-homeproxy* package

```sh
wget -O /tmp/homeproxy-hiddify.pub https://github.com/ezdizzy/re-homeproxy/releases/latest/download/homeproxy-hiddify.pub
cp /tmp/homeproxy-hiddify.pub /etc/apk/keys/
wget -O /tmp/luci-app-re-homeproxy.apk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-app-re-homeproxy[^"]*\.apk' | head -1)"
apk add /tmp/luci-app-re-homeproxy.apk
```

Once the key is in `/etc/apk/keys/` it is trusted permanently — no flag needed for future updates.

#### 2. Install components from the **Core & Tools** tab

Open **Services → Re:HomeProxy AutoMod → Core & Tools** and install what you need — the installer auto-picks a build
that fits your storage:

- **Proxy core** *(required, pick one)* — [hiddify-core](https://github.com/hiddify/hiddify-core) (default; includes
  NaïveProxy) or [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) (newer sing-box 1.14 base with
  WARP / MASQUE / TrustTunnel in the core; no NaïveProxy — such nodes are skipped automatically).
- **ByeDPI** *(optional)* — SOCKS-level DPI bypass that un-throttles sites without a VPN, with 47 presets and a built-in
  strategy tester.
- **Zapret 2** *(optional)* — packet-level (nfqws2) DPI bypass selected per routing rule, with curated presets and
  optional Discord-voice desync.
- **Re:HomeProxy AutoMod** *(the app itself)* — see *Updating the app*; update in place from this tab.

#### 3. Install the Russian language pack (optional)

```sh
wget -O /tmp/luci-i18n-homeproxy-ru.apk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-i18n-homeproxy-ru[^"]*\.apk' | head -1)"
apk add /tmp/luci-i18n-homeproxy-ru.apk
```

### OpenWRT 24.10 (opkg)

#### 1. Install *luci-app-re-homeproxy* package

```sh
wget -O /tmp/luci-app-re-homeproxy.ipk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-app-re-homeproxy[^"]*\.ipk' | head -1)"
opkg install /tmp/luci-app-re-homeproxy.ipk
```

#### 2. Install components from the **Core & Tools** tab

Open **Services → Re:HomeProxy AutoMod → Core & Tools** and install what you need — the installer auto-picks a build
that fits your storage (same options as the APK section above).

### Manual install over SSH (alternative to the Core & Tools tab)

The **Core & Tools** tab is recommended — it auto-detects your hardware and picks a build that fits. To install the same
components by hand over SSH, first detect your architecture and package format:

```sh
. /etc/openwrt_release; ARCH="$DISTRIB_ARCH"
command -v apk >/dev/null && EXT=apk || EXT=ipk
echo "$ARCH / $EXT"
```

The hiddify-core and ByeDPI packages are signed with the `homeproxy-hiddify.pub` key trusted during the app install
above; if you skipped that, add `--allow-untrusted` to `apk add`.

**Proxy core — pick one** (plus its required kernel modules):

```sh
if [ "$EXT" = apk ]; then apk add kmod-nft-tproxy kmod-tun; else opkg install kmod-nft-tproxy kmod-tun; fi

# hiddify-core (default; for a compact build replace 'latest/download' with 'download/upx')
wget -O /tmp/hiddify-core.$EXT "https://github.com/1andrevich/hiddify-core/releases/latest/download/hiddify-core_${ARCH}.${EXT}"
if [ "$EXT" = apk ]; then apk add /tmp/hiddify-core.apk; else opkg install --force-reinstall /tmp/hiddify-core.ipk; fi

# ...OR sing-box-extended (AmneziaWG / WARP, widest protocol set; unsigned)
URL=$(wget -qO- 'https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest' | grep -o "https://github\.com/[^\"]*${ARCH}[^\"]*\.${EXT}" | head -1)
wget -O /tmp/sing-box-extended.$EXT "$URL"
if [ "$EXT" = apk ]; then apk add --allow-untrusted /tmp/sing-box-extended.apk; else opkg install /tmp/sing-box-extended.ipk; fi
```

**ByeDPI** *(optional)* — needs `curl` (its built-in strategy tester uses it):

```sh
if [ "$EXT" = apk ]; then apk add curl; else opkg install curl; fi
URL=$(wget -qO- 'https://api.github.com/repos/1andrevich/ByeDPI-OpenWrt/releases/latest' | grep -o "https://github\.com/[^\"]*byedpi_[^\"]*${ARCH}\.${EXT}" | head -1)
wget -O /tmp/byedpi.$EXT "$URL"
if [ "$EXT" = apk ]; then apk add /tmp/byedpi.apk; else opkg install /tmp/byedpi.ipk; fi
```

**Zapret 2** *(optional)* — needs the NFQUEUE kernel module:

```sh
if [ "$EXT" = apk ]; then apk add kmod-nft-queue; else opkg install kmod-nft-queue; fi
[ "$EXT" = apk ] && wget -O /etc/apk/keys/zapret2-1andrevich.pub "https://github.com/1andrevich/zapret2-openwrt/releases/latest/download/zapret2-1andrevich.pub"
wget -O /tmp/zapret2.$EXT "https://github.com/1andrevich/zapret2-openwrt/releases/latest/download/zapret2_${ARCH}.${EXT}"
if [ "$EXT" = apk ]; then apk add /tmp/zapret2.apk; else opkg install /tmp/zapret2.ipk; fi
```

### 4. Start the service

```sh
/etc/init.d/homeproxy start
```

The service will auto-start on boot. Monitor logs at **Services → Re:HomeProxy AutoMod → Core & Tools**.

## Updating the app (AutoMod self-update)

You do **not** need the SSH console to update Re:HomeProxy AutoMod:

1. Open **Services → Re:HomeProxy AutoMod → Core & Tools**.
2. In the **Application** card, click **Check update**. It compares your installed version (shown as
   `Re:HomeProxy AutoMod vX.Y.Z`) with the latest GitHub release of `ezdizzy/re-homeproxy`.
3. If an update is available, click **Update**. The app downloads the new `luci-app-re-homeproxy` package (and the
   Russian translation) and installs it in place; rpcd restarts automatically and the page reloads.

> The app pulls its own builds from `ezdizzy/re-homeproxy`. Cores / ByeDPI / Zapret are still updated via their own
> cards on the same tab (those come from upstream). A GitHub token (set in **Core & Tools → GitHub token**) raises the
> GitHub API rate limit used by the update check.

## Versioning & Releases

- **Version scheme:** semantic `X.Y.Z` (e.g. `2.0.0`). The GitHub release tag is `vX.Y.Z` and matches the app's
  `PKG_VERSION`; the in-app self-update compares your installed version against the latest release tag.
- **Current release: [2.0.0](../../releases/tag/v2.0.0)** — the v2 interface rework (Overview, Routing Wizard,
  Automation engine overview, Telegram bot v2, TG WS Proxy card, Devices & interfaces, nfqws2 multi-strategies,
  provider-scan v2 with the LIVE configured-path probe). Requires OpenWrt / ImmortalWrt 25.12+ (apk).

## Documentation

Full guides live in the **[Wiki](../../wiki/Home)**:

- **[Getting Started](../../wiki/Getting-Started-en)** — from a fresh install to a working connection, step by step
- **[Core Management](../../wiki/Core-Management-en)** — hiddify-core vs sing-box-extended, the smart installer, storage and the compact build
- **[Supported Protocols](../../wiki/Supported-Protocols-en)** — every protocol, transport, and the build tags each needs
- **[Subscriptions & Node Import](../../wiki/Subscriptions-en)** — share links, .conf, Amnezia `vpn://` (AmneziaWG/Xray), subscriptions, base64
- **[Routing & Access Control](../../wiki/Routing-and-Access-Control-en)** — routing modes, RU Proxy Rules, per-device access control
- **[Server Settings](../../wiki/Server-Settings-en)** — run the router as a proxy server (inbounds, types, TLS/ACME)
- **[DNS & Diagnostics](../../wiki/DNS-and-Diagnostics-en)** — clean vs secure DNS, IPv6 leaks, and the Diagnostics page
- **[DNS Settings](../../wiki/DNS-Settings-en)** — the dedicated DNS page: server pools, reserve DNS and MultiDNS with a live quality monitor
- **[ByeDPI](../../wiki/ByeDPI-en)** — SOCKS-level DPI bypass, strategy presets and the tester
- **[Zapret](../../wiki/Zapret-en)** — packet-level (nfqws2) DPI bypass, presets, Discord-voice and the tester
- **[Custom Routing](../../wiki/Custom-Routing-en)** — UI routing nodes + rules (match by domain/IP/port/protocol/process)
- **[Custom JSON Config](../../wiki/Custom-JSON-Config-en)** — raw hiddify-core config routing mode
- **[Automation](../../wiki/Automation-Status-en)** — the AutoMod Automation tab (A–D states, risks, TODO)
- **[Troubleshooting](../../wiki/Troubleshooting-en)** — common errors and fixes

## Credits & Acknowledgements

Re-HomeProxy stands on the work of many upstream projects. The LuCI app is GPL-licensed; the cores and bypass engines are
fetched at install time from their own releases and remain under their own licenses.

**Base & cores**
- [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy) — the original LuCI app this is a fork of
- [hiddify-core](https://github.com/hiddify/hiddify-core) — default proxy core (a sing-box fork by the Hiddify team)
- [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) — alternative core with extra build tags (AmneziaWG/WARP, widest protocol set)
- [sing-box](https://sing-box.sagernet.org) — the upstream engine both cores derive from

**DPI-bypass engines**
- [hufrea/byedpi](https://github.com/hufrea/byedpi) — the ByeDPI (`ciadpi`) desync engine; OpenWrt packages by [1andrevich/ByeDPI-OpenWrt](https://github.com/1andrevich/ByeDPI-OpenWrt)
- [bol-van/zapret2](https://github.com/bol-van/zapret2) — the Zapret / nfqws2 / blockcheck2 packet desync engine; OpenWrt packages by [1andrevich/zapret2-openwrt](https://github.com/1andrevich/zapret2-openwrt); some strategy presets adapted from [flowseal/zapret-discord-youtube](https://github.com/flowseal/zapret-discord-youtube) (MIT)
- [StressOzz/Zapret-Manager](https://github.com/StressOzz/Zapret-Manager) — the strategy catalog imported by the Wizard's DPI section (converted to nfqws2 args and re-tested on the router)

**Optional third-party components (Telegram without a proxy)**
- [d0mhate/tg-ws-proxy-go](https://github.com/d0mhate/tg-ws-proxy-go) (MIT) — the transparent Telegram bridge the Wizard installs by button (loopback SOCKS5, procd-managed)
- [valnesfjord/tg-ws-proxy-rs](https://github.com/valnesfjord/tg-ws-proxy-rs) (MIT) — the MTProto-over-WebSocket component detected read-only if you run it yourself; installed only by the user's explicit action with the component's own official installer, never packed into this app

**Protocols** — implemented by the cores above (see [Supported Protocols](../../wiki/Supported-Protocols-en)):

Naive, Mieru, Hysteria/Hysteria2, TUIC, SOCKS, Shadowsocks/Shadowsocks 2022, ShadowTLS, AnyTLS, Trojan, VLESS (Reality, XHTTP), VMess, WireGuard, AmneziaWG/WARP, SSH.

**Routing lists**
- [Re:Filter](https://github.com/1andrevich/re-filter) — RKN-registry domain + IP blocklist
- [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) — "Russia Inside" and the per-service routing lists (YouTube, Telegram, Discord, Meta, etc.)
- [itdoginfo](https://github.com/itdoginfo) — HODCA and other curated lists by itdoginfo

All trademarks and service names are the property of their respective owners and are referenced nominatively to identify the traffic each rule or list affects.
