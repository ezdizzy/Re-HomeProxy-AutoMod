🇬🇧 [English](Installation-and-Updates-en) | 🇷🇺 [Русский](Installation-and-Updates-ru)

# Installation & updates

Requirements: OpenWrt/ImmortalWrt **24.10+** (opkg) or **25.12+** (apk). ~40 MB of free space
is recommended.

---

## Quick install (one command)

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | sh
```

The interactive installer walks you through: app + Russian locale → core → subscription/node →
Hot Swap → MultiDNS → Automation → Zapret 2 with an auto-test → autopilot → ByeDPI.
The installer **never leaves you offline**: with no subscription it enables direct mode and
creates a «YouTube → Zapret» rule.

Re-running the script opens the settings menu.

### If GitHub is blocked

Point at a mirror (the variable goes before `sh`):

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | GH_MIRROR=https://your.mirror sh
```

There is also a local `--local` mode — installing from files on the device (for example,
downloaded on an Android phone with a terminal and pushed to the router).

---

## Manual packages

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

The core, ByeDPI, Zapret 2 and mosdns are installed from **Maintenance → Core management** —
the installer detects the architecture and picks a build for your free space (including a
compact UPX build for small routers). Installs are asynchronous with live progress. Detailed
manual steps live in [Getting started](Getting-Started-en).

---

## App self-update

**Maintenance → Application → Check update**. Versions are compared against the latest GitHub
release; the **Update** button installs the new app (and the Russian translation) in place and
rpcd restarts automatically — no SSH needed.

Updates from previous versions (Re:HomeProxy AutoMod 2.x) need no manual steps — the app is
called Ravnex once the new version is installed.

---

## Own signed repository (the feed)

Every component — cores, DPI engines, helpers — is delivered from **our feed**: mirrors of the
upstreams' official releases, rebuilt under our signature by this repository's CI.

- **manifest.json is the client contract**: which packages, versions, files and sha256 hashes
  the feed carries.
- The download ladder: raw.githubusercontent → jsDelivr → the mirror from UCI (`github_mirror`).
- The client never registers foreign repositories with the package manager (no `repositories.d`
  line at all) — a foreign feed cannot out-version our components.
- For byedpi / zapret2 there is an honest fallback: without the feed the package is downloaded
  from the upstream asset path.

The feed status is visible on **Maintenance → the «Update source» card**: key presence, manifest
reachability and freshness, an «installed → in feed» table per component, and the
**Connect / Disconnect** buttons.

---

## See also

- [Core management](Core-Management-en) — builds, memory, rule-sets
- [Getting started](Getting-Started-en) — what to do right after installation
