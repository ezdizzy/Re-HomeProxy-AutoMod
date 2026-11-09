🇬🇧 [English](Core-Management-en) | 🇷🇺 [Русский](Core-Management-ru)

# Core Management

Ravnex is **multi-core**: the LuCI app is the interface, while the actual proxying is done by
a separate **core** binary. Install, update and switch cores on **Maintenance → Core
management** — no SSH required.

---

## Sources — originals only

Every core is installed **directly from the ORIGINAL repositories** of its developers:

- **hiddify-core** → [hiddify/hiddify-core](https://github.com/hiddify/hiddify-core) releases
  (original OpenWrt apk/ipk packages; the tarball is the fallback path);
- **sing-box-extended** → [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended)
  releases (apk/ipk; an original UPX-compressed tarball for small flash);
- **sing-box-extended-lite** → [MANCrimSon/sing-box-extended-lite](https://github.com/MANCrimSon/sing-box-extended-lite)
  releases (Pure/UPX tarballs; their own installer stays as a fallback path).

Every download is verified against **SHA256** (the asset digest from the GitHub API) before
installation. Silent downgrades are forbidden: an older version can only be installed
explicitly — via the **Rollback** button on the core card.

---

## Choosing a core

| | **hiddify-core** (default) | **sing-box-extended** |
|---|---|---|
| Engine | hiddify-core v5.x (sing-box 1.15 base) | Extended sing-box base (shtorm-7) |
| Size | Large (~101 MB binary) | Larger (~26 MB installed); a UPX build exists |
| App protocols | Every protocol the app can configure | Every protocol the app can configure |
| **NaïveProxy** | ✅ **Supported** | ❌ **No** (such nodes are **skipped automatically**) |
| **AmneziaWG** | ✅ Supported | ✅ Supported |
| **WARP / MASQUE / TrustTunnel** | ❌ Not used by the app | ✅ In the core |

**Rule:** both cores work with every protocol the app can configure — the practical
difference is **NaïveProxy** (hiddify-core only). If your subscription has NaïveProxy nodes,
stay on hiddify-core. When you switch to sing-box-extended, unsupported nodes are
automatically excluded from all pools (the app shows which). There is also a **lite core**
(sing-box-extended-lite) for devices with very little flash.

Which protocols appear in the node editor depends on the installed core; see
[Supported Protocols](Supported-Protocols-en).

---

## Installation — the smart installer

The build selector (for the cores that have one): **Auto / Full / UPX**. In «Auto» the
installer checks the device and picks a build that will actually fit:

1. Reads the free space on `/overlay` (persistent flash) and free RAM.
2. If the full build fits → the **standard** build is installed. If space is tight but RAM
   suffices (and the core HAS a UPX build) → the **compact (UPX)** build is installed, with a
   note.
3. If neither fits → it stops with a clear message instead of installing something that
   cannot work.

**hiddify-core** has no compact UPX build (the original publishes none) — only the full build
is offered. UPX variants exist for **sing-box-extended** and **lite**; on soft-float MIPS UPX
is unreliable, so «Auto» never picks it there — only an explicit choice does.

**The compact build (UPX)** takes much less flash but **unpacks into RAM on every start**. On
most routers this is unnoticeable in everyday use.

Installation is **asynchronous with a live status** — the page stays responsive (a large
download does not freeze the tab). After the install the backend probes the new core and
restarts the service itself.

---

## Memory — briefly

| Free on `/overlay` | What gets installed |
|---|---|
| ~110 MB+ | hiddify-core (full original build) |
| ~40 MB+ | sing-box-extended (full) or its UPX build (if RAM suffices) |
| < ~25 MB | Not enough — free up space or bake the core into your own firmware image |

> On a compressing overlay (jffs2/ubifs) the full build needs less free space than the raw
> number. The installer accounts for this automatically — trust its check, not the table.

---

## Switching cores and updating

- **Update:** press **Install** again — the latest original release is downloaded and
  reinstalled.
- **Rollback:** the **Rollback** button on the core card lists the recent releases of the
  original repository; the chosen release is downloaded fresh, verified by SHA256 and
  installed as an EXPLICIT downgrade (only this confirmation bypasses the no-silent-downgrade
  gate). Nothing is cached on the router — the archive is deleted right after the install.
- **Switching cores:** install another core; when both are present the **Preferred core**
  setting (Connection page) decides. The config generator and the service honour the same
  setting.
- **Version / status:** the section shows the installed core and its version.

The app itself, mosdns, the helpers and our own apk/ipk packaging of the engines come from
**our signed package source**; the cores themselves come only from the originals: details and
the «Update source» card: [Installation and Updates](Installation-and-Updates-en).

---

## Rule-sets — cold-start insurance

The **«Rule-sets»** card downloads local `.srs` copies for every rule-set (name = tag). When
the local copies folder exists, each remote rule-set gets a local copy for the first load: a
cold start without a working internet connection (fresh firmware, GitHub blocked by DPI) no
longer kills the core with «FATAL initialize rule-set». The lists still refresh from the
network daily in the background.

---

## Resources and kernel modules

- RU routing lists and geo databases **update themselves** on a schedule; subscriptions update
  separately — see [Subscriptions and node import](Subscriptions-en).
- Transparent routing needs `kmod-nft-tproxy` and `kmod-tun` — the installer pulls them in.

See also: [ByeDPI](ByeDPI-en) · [Zapret](Zapret-en) · [Supported Protocols](Supported-Protocols-en) ·
[Troubleshooting](Troubleshooting-en)
