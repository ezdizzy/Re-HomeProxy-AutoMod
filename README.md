[**Русский 🇷🇺**](README_ru.md) / [**English**](README.md)


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

## AutoMod modifications

This mod adds the following on top of the original Re-HomeProxy app:

- **Automation tab** — automatic detection of blocked sites. A background monitor probes hosts both directly and through
  the proxy; a host that fails directly but works via the proxy is remembered (base domain + learned IPs) and routed
  through the proxy / ByeDPI / Zapret. Fully compatible with ByeDPI and Zapret — learned sites follow the same path the
  user selected.
- **MultiDNS (mosdns engine)** — a DNS accelerator: every query is raced in parallel across all servers of the pool
  (plain "Russia" + encrypted "Secure"), returning the fastest live answer. A quality daemon verifies over HTTPS that the
  returned IPs actually open sites and auto-prunes dead/polluted servers and IPs. Configure on the **MultiDNS** tab of
  Client Settings; install/update mosdns from its card on **Core & Tools**.
- **URLTest with three modes** — **Auto** (all imported nodes), **Preferred node + auto** (your chosen node first, the
  fastest of the rest when it dies or slows down) and **Manual node list** (classic explicit selection).
- **Tun TCP/UDP fix** — corrected Tun mode delivery of `tun_mark` flows into the tun device with a loop guard, so Tun
  routing works correctly.
- **In-app self-update** — on the **Core & Tools** tab you can check for a new version and update the LuCI app (and the
  Russian translation) in place, without touching the SSH console. See *Updating the app* below.
- **Fork default** — `install.sh` installs the LuCI app and Russian locale from `ezdizzy/re-homeproxy` by default
  (cores / ByeDPI / Zapret still come from upstream `1andrevich/*`).
- **Interactive installer** — `install.sh` walks you through everything (subscription, MultiDNS, Automation, Zapret with
  automatic strategy testing) and **never leaves you without internet**: with no subscription it switches to direct mode
  and adds a "YouTube → Zapret" rule. Re-running the script opens a configuration menu.
- Complete Russian (ru) translation of every tab, including Automation and DNS-failover strings.

> ⚠️ This is an experimental mod. By installing it you acknowledge that some features may not work as expected —
> use it at your own risk.

## Key Features

- **Multi-core engine** — run on **hiddify-core** or **sing-box-extended**, your choice per device. The built-in
  **Core & Tools** page installs and updates the core for you and automatically picks the right build for your available
  storage (with a compact build for tight-storage devices).
- **Wide protocol support** — Naive, Mieru, Hysteria, SOCKS, Shadowsocks, ShadowTLS, Trojan, VLESS (XHTTP), VMess,
  WireGuard, **AmneziaWG / WARP** (sing-box-extended), SSH and more.
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
adding a subscription or a share-link, enabling **MultiDNS** and **Automation**, installing **Zapret 2** with automatic
strategy testing (starts with Hostfakesplit and checks YouTube) and **ByeDPI** (up to you).

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

- **Proxy core** *(required, pick one)* — [hiddify-core](https://github.com/hiddify/hiddify-core) (default) or
  [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) (adds AmneziaWG / WARP and the widest protocol set).
- **ByeDPI** *(optional)* — SOCKS-level DPI bypass that un-throttles sites without a VPN, with 47 presets and a built-in
  strategy tester.
- **Zapret 2** *(optional)* — packet-level (nfqws2) DPI bypass selected per routing rule, with curated presets and
  optional Discord-voice desync.
- **Re:HomeProxy AutoMod** *(the app itself)* — see *Updating the app*; update in place from this tab.

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

- **Version scheme:** semantic `X.Y.Z` (e.g. `1.0.0`).

## Documentation

Full guides live in the **[Wiki](../../wiki/Home)**:

- **[Getting Started](../../wiki/Getting-Started-en)** — from a fresh install to a working connection, step by step
- **[Core Management](../../wiki/Core-Management-en)** — hiddify-core vs sing-box-extended, the smart installer, storage and the compact build
- **[Supported Protocols](../../wiki/Supported-Protocols-en)** — every protocol, transport, and the build tags each needs
- **[Subscriptions & Node Import](../../wiki/Subscriptions-en)** — share links, .conf, Amnezia `vpn://` (AmneziaWG/Xray), subscriptions, base64
- **[Routing & Access Control](../../wiki/Routing-and-Access-Control-en)** — routing modes, RU Proxy Rules, per-device access control
- **[Server Settings](../../wiki/Server-Settings-en)** — run the router as a proxy server (inbounds, types, TLS/ACME)
- **[DNS & Diagnostics](../../wiki/DNS-and-Diagnostics-en)** — clean vs secure DNS, IPv6 leaks, and the Diagnostics page
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

**Protocols** — implemented by the cores above (see [Supported Protocols](../../wiki/Supported-Protocols-en)):

Naive, Mieru, Hysteria/Hysteria2, TUIC, SOCKS, Shadowsocks/Shadowsocks 2022, ShadowTLS, AnyTLS, Trojan, VLESS (Reality, XHTTP), VMess, WireGuard, AmneziaWG/WARP, SSH.

**Routing lists**
- [Re:Filter](https://github.com/1andrevich/re-filter) — RKN-registry domain + IP blocklist
- [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) — "Russia Inside" and the per-service routing lists (YouTube, Telegram, Discord, Meta, etc.)
- [itdoginfo](https://github.com/itdoginfo) — HODCA and other curated lists by itdoginfo

All trademarks and service names are the property of their respective owners and are referenced nominatively to identify the traffic each rule or list affects.
