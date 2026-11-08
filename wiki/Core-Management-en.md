🇬🇧 [English](Core-Management-en) | 🇷🇺 [Русский](Core-Management-ru)

# Core Management

Ravnex is **multi-core**: the LuCI app is the interface, and a separate **core** binary does the
actual proxying. You install, update, and switch cores from **Maintenance → Core management** —
no SSH required.

---

## Choosing a core

| | **hiddify-core** (default) | **sing-box-extended** |
|---|---|---|
| Engine | hiddify-core v5.x (a sing-box 1.15 base) | Extended sing-box base (shtorm-7) |
| Size | Lighter; a **compact build** exists for weak devices | Larger (~26 MB installed) |
| App protocols | Every protocol the app can configure | Every protocol the app can configure |
| **NaïveProxy** | ✅ **Supported** | ❌ **No** (such nodes are **skipped automatically**) |
| **AmneziaWG** | ✅ Supported | ✅ Supported |
| **WARP / MASQUE / TrustTunnel** | ❌ Not used by the app | ✅ Present in the core |

**The rule:** both cores run every protocol the app can configure — the practical difference is
**NaïveProxy** (hiddify-core only). If your subscription has NaïveProxy nodes, stay on
hiddify-core. When you switch to sing-box-extended, unsupported nodes are automatically excluded
from all pools (the app tells you which). There is also a **lite core**
(sing-box-extended-lite) for devices with very little flash.

Which protocols appear in the node editor depends on the installed core; see
[Supported protocols](Supported-Protocols-en).

---

## Installation — the smart installer

Build selector: **Auto / Full / UPX**. In «Auto» the installer checks the device and picks a
build that actually fits:

1. It reads the free space on `/overlay` (persistent flash) and free RAM.
2. If the full build fits → the **standard** build is installed. If space is tight but RAM
   suffices → the **compact (UPX)** build is installed, with a note.
3. If nothing fits → it stops with a clear message instead of installing something that cannot
   work.

**Why this guard exists:** a core binary larger than the free overlay gets **truncated** when
written and then dies with a **«bus error» (SIGBUS)** at start — the installer never offers a
build that cannot fit.

**The compact build (UPX)** takes much less flash but **unpacks into RAM on every start**. On
most routers this is unnoticeable in daily use.

Installs are **asynchronous with live status** — the page stays responsive (a large download no
longer freezes the tab).

---

## Memory — briefly

| Free on `/overlay` | What gets installed |
|---|---|
| ~40 MB+ | hiddify-core or sing-box-extended (full build) |
| ~25–40 MB | hiddify-core (compact build, if RAM suffices) |
| < ~25 MB | Not enough — free up space or bake the core into your own firmware image |

> On a compressing overlay (jffs2/ubifs) the full build needs less free space than the raw
> number. The installer accounts for this automatically — trust its check, not the table.

---

## Switching cores and updating

- **Updating:** press **Install** again — the latest release is downloaded and reinstalled.
- **Switching cores:** install the other core; when both are present, the **Preferred core**
  setting (the Connection page) decides. The config generator and the service honor the same
  setting.
- **Version / status:** the section shows the installed core and version.

The core, ByeDPI, Zapret 2 and mosdns come from **our signed feed** — details and the «Update
source» card: [Installation & updates](Installation-and-Updates-en).

---

## Rule-sets — the cold-start safety net

The **Rule-sets** card downloads local `.srs` copies for every rule-set (file name = tag). While
the local folder exists, every remote rule-set also gets a local first-load copy: a cold start
without working internet (fresh firmware, DPI-blocked GitHub) no longer kills the core with
«FATAL initialize rule-set». The lists still refresh from the network daily in the background.

---

## Resources and kernel modules

- The RU routing lists and geo databases **update themselves** on a schedule; subscriptions
  update separately — see [Subscriptions & node import](Subscriptions-en).
- Transparent routing needs `kmod-nft-tproxy` and `kmod-tun` — the installer pulls them in.

See also: [ByeDPI](ByeDPI-en) · [Zapret](Zapret-en) · [Supported protocols](Supported-Protocols-en) ·
[Troubleshooting](Troubleshooting-en)
