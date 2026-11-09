🇬🇧 [English](Installation-and-Updates-en) | 🇷🇺 [Русский](Installation-and-Updates-ru)

# Installation & updates

Requirements: OpenWrt/ImmortalWrt **24.10+** (opkg) or **25.12+** (apk). ~40 MB of free space
is recommended.

---

## Quick install (one command)

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/ravnex/master/install.sh | sh
```

The interactive installer walks you through: app + Russian locale → core → subscription/node →
Hot Swap → MultiDNS → Automation → Zapret 2 with an auto-test → autopilot → ByeDPI.
The installer **never leaves you offline**: with no subscription it enables direct mode and
creates a «YouTube → Zapret» rule.

Re-running the script opens the settings menu.

### If GitHub is unreachable

Point at a mirror (the variable goes before `sh`):

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/ravnex/master/install.sh | GH_MIRROR=https://your.mirror sh
```

There is also a local `--local` mode — installing from files on the device (for example,
downloaded on an Android phone with a terminal and pushed to the router).

---

## Manual packages

APK (OpenWrt 25.12+):

```sh
wget -O /tmp/homeproxy-hiddify.pub https://github.com/ezdizzy/ravnex/releases/latest/download/homeproxy-hiddify.pub
cp /tmp/homeproxy-hiddify.pub /etc/apk/keys/
wget -O /tmp/app.apk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/ravnex/releases' | grep -o 'https://github\.com/[^"]*luci-app-ravnex[^"]*\.apk' | head -1)"
apk add /tmp/app.apk
```

opkg (OpenWrt 24.10):

```sh
wget -O /tmp/app.ipk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/ravnex/releases' | grep -o 'https://github\.com/[^"]*luci-app-ravnex[^"]*\.ipk' | head -1)"
opkg install /tmp/app.ipk
```

The core, ByeDPI, Zapret 2 and mosdns are installed from **Maintenance → Core management** —
the installer detects the architecture and picks a build for your free space (UPX builds of
sing-box-extended/lite for small routers). The cores are installed only from the **original
developer repositories**, every download SHA256-verified. Installs are asynchronous with live
progress. Detailed manual steps live in [Getting started](Getting-Started-en).

---

## App self-update

**Maintenance → Application → Check update**. Versions are compared against the latest GitHub
release; the **Update** button installs the new app (and the Russian translation) in place and
rpcd restarts automatically — no SSH needed.

Updates from previous versions (Re:HomeProxy AutoMod 2.x) need no manual steps — the app is
called Ravnex once the new version is installed.

---

## Own signed package source (the feed)

**OUR components** — the app, mosdns, the automation helpers — and **our own apk/ipk packaging
of the DPI engines** (byedpi ← hufrea static tarballs, zapret2 ← the bol-van openwrt-embedded
release) are delivered from **our signed feed**: the packages are built by this repository's CI
and signed with our key.

The proxy cores (hiddify-core, sing-box-extended, lite) are **NOT delivered through the feed** —
they install straight from the original releases with the SHA256 gate (see
[Core Management](Core-Management-en)).

- **manifest.json is the client contract**: which packages, versions, files and sha256 hashes
  the feed carries.
- The download ladder: raw.githubusercontent → jsDelivr → the mirror from UCI (`github_mirror`).
- The client never registers foreign repositories with the package manager (no `repositories.d`
  line at all) — a foreign feed cannot out-version our components.

The source status is visible on **Maintenance → the «Update source» card**: key presence,
manifest reachability and freshness, an «installed → offered» table per component, and the
**Connect / Disconnect** buttons.

---

## See also

- [Core management](Core-Management-en) — builds, memory, rule-sets
- [Getting started](Getting-Started-en) — what to do right after installation
