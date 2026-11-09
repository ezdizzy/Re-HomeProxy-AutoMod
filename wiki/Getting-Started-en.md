🇬🇧 [English](Getting-Started-en) | 🇷🇺 [Русский](Getting-Started-ru)

# Getting started

This page walks you from a fresh install to a working connection. It assumes Ravnex is already
installed (see [Installation & updates](Installation-and-Updates-en) for packages).

> Everything below happens in the LuCI web interface: **Services → Ravnex**.

---

## Step 1 — Install a core

The LuCI app is only the interface; the actual proxying is done by a separate **core** binary.
Open **Maintenance → Core management** and install one of:

- **hiddify-core** (default) — the only core with **NaïveProxy**; installed from the original
  hiddify package/tarball;
- **sing-box-extended** — a newer sing-box base (WARP / MASQUE / TrustTunnel in the core), a
  UPX build exists for small flash;
- **sing-box-extended-lite** — a lightweight build for devices with very little flash;
  no NaïveProxy/WARP/MASQUE — such nodes are skipped automatically.

The installer picks the build for your storage. Details: **[Core management](Core-Management-en)**.

---

## Step 2 — Add at least one node

Open the **Servers** page. A «node» is the proxy server you connect through. You can add:

- **Share-link import** — paste `vless://`, `vmess://`, `ss://`, `trojan://`, `vpn://` (Amnezia),
  Hysteria, etc.;
- **.conf import** — a WireGuard / AmneziaWG config file;
- **A subscription link** — the router downloads and keeps updating the node list;
- **Manually** — fill the fields yourself.

All methods and formats: **[Subscriptions & node import](Subscriptions-en)**.

---

## Step 3 — Pick the main node

On the **Connection** page set **Main node** = your added node — or choose **URLTest**, so
Ravnex picks the fastest reachable node and switches on failures. URLTest has three modes
(Auto / Preferred node + auto / Manual list) — see
**[Hot Swap and reliability](Hot-Swap-and-Reliability-en)**.

---

## Step 4 — Pick the routing mode

On the **Connection** page choose the **Routing mode**. The default for RU installs is
**Blocking bypass (rule lists)**:

- **Blocking bypass (rule lists)** — the everyday working mode: everything goes direct, while
  traffic matched by the Routing rules (YouTube, Russia Inside, Re:Filter…) rides the Main
  node — the listed resources open without tunneling the whole connection. This is where the
  transport-layer engines (Zapret / ByeDPI) and the automation engine live.
- **Everything via node** — all traffic through the Main node; per-service rules are not used.
- **Direct** — the repair/diagnostics mode: interception, engines, the DNS scheme and the core
  itself are off; the router hands out exactly what the provider gives.

For «Blocking bypass» enable the lists you need (Russia Inside, Re:Filter, YouTube, Discord…)
— rules and presets are described in **[Routing & access control](Routing-and-Access-Control-en)**,
and the transport layer (DPI) in the **[Routing Master](Routing-Master-en)**.

---

## Step 5 — Save, apply, start

Press **Save & apply**. Then start the service (it also starts at boot):

```sh
/etc/init.d/ravnex start
```

Logs live on the **Maintenance** page.

---

## Step 6 — Verify it works

Open the **Health center** and run the checks:

- **Connection check** — test-site reachability; on hiddify-core it shows your **provider IP**
  vs the **proxy IP** (while proxying they must differ);
- **Core & system** — the core is installed and running;
- **Configuration** — the generated config is valid.

Service states and the event journal live in the same
**[Health center](Monitoring-and-Connections-en#health-center)**. If something is off — see
**[Troubleshooting](Troubleshooting-en)**.

---

## Optional — removing throttling without a VPN

If a site (YouTube, Discord) is *throttled* rather than IP-blocked, hand it to the built-in
transport layer (DPI) instead of spending subscription traffic:

- **[Zapret](Zapret-en)** — packet-level desynchronization (nfqws2);
- **[ByeDPI](ByeDPI-en)** — SOCKS-level desynchronization.

Both can be selected per rule (for example, YouTube via Zapret, the rest via VPN). Sites unreachable
directly can also be learned automatically — see **[Auto-bypass](Automation-Status-en)**.

See also: [Overview](Overview-en) · [Core management](Core-Management-en) ·
[Troubleshooting](Troubleshooting-en)
