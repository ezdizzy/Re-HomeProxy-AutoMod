🇬🇧 [English](Routing-and-Access-Control-en) | 🇷🇺 [Русский](Routing-and-Access-Control-ru)

# Routing & access control

The **Connection** page decides **where** traffic goes: the main node, the routing mode, and
what keeps the link alive when a server dies (the exit engine, URLTest, Hot Swap). New servers
are added on the [Servers](Subscriptions-en) page.

---

## Routing modes

Three modes — simple and non-overlapping:

| Mode | What it does |
|---|---|
| **Blocking bypass (rule lists)** | The everyday **working** mode: everything goes direct, while traffic matched by the [Service rules](Routing-Master-en) rides its assigned exit. This is where the transport-layer engines (Zapret / ByeDPI) and the automation engine live. |
| **Everything via node** | All traffic through the Main node; per-service rules are not used. |
| **Direct (all mechanisms off)** | The repair/diagnostics mode: interception, engines, the DNS scheme and the core itself are off — the router hands out exactly what the provider gives. |

When you switch the mode the page re-arranges itself and only the mode-relevant settings
remain. Legacy values from old versions migrate into the working mode automatically at service
start (with an honest warning).

**Routing ports** — limit which destination ports get proxied (for example, *common ports
only* keeps P2P direct).

**Proxy mode** — how traffic is intercepted: `Redirect TCP`, `Redirect TCP + TProxy UDP`
(default), TUN modes (require `kmod-tun`).

---

## The exit engine (Main node)

One engine owns the exit for **every** mode. Three operating modes:

| Mode | Behavior |
|---|---|
| **Auto** — best node | Holds the best node and moves only when another stays faster by more than the tolerance for several probe rounds in a row |
| **Preferred node** | Holds your chosen node while it responds; leaves only when it really dies; returns after recovery |
| **Manual** | Holds the node you picked |

Key settings:

- **Reserve nodes** — the failover priority order; reserves are probed live (their tunnels stay
  warm). This is **Hot Swap** — see [Hot Swap and reliability](Hot-Swap-and-Reliability-en);
- **Test / probe interval** — how often nodes and the active pick are verified;
- **Switch tolerance** — the minimum latency gap required to move (anti-flap);
- **Return after recovery** (failback) and **Upgrade on a better node**;
- advanced thresholds: dead threshold, recovery probes/window, auto hysteresis.

The engine state is visible on the page: the active node, the mode, the switch count,
«failback on / anti-flap on».

### A separate UDP exit

By default UDP follows TCP. The **Main UDP node** field sends UDP/QUIC (games, calls) through a
different exit — down to ByeDPI/Zapret. «Same as main node» restores a single route.

---

## Access control — which devices it touches

The per-device policy moved to a dedicated **[Access control](Access-Control-en)** page: the
proxy mode on the device card (Auto/Direct/Via proxy/Gaming/Global), honest badges, site rules,
Wi-Fi and schedules.

**WAN IP Policy** (force-proxy or force-direct specific destination IPs) and **Interface
Control** — a collapsed section at the bottom of the Connection page.

---

## OAuth resilience

Google/Microsoft/Apple logins ride a **pinned secure exit** — logins do not «fall off» on IP or
node changes. More: [Hot Swap and reliability](Hot-Swap-and-Reliability-en).

---

## Tips

- In the working mode start with **Russia Inside + Re:Filter** on the Service rules page; add
  service lists only if a specific site still misbehaves.
- If a site is *throttled* rather than *blocked*, hand it to [ByeDPI](ByeDPI-en) or
  [Zapret](Zapret-en) instead of the VPN.
- The real route of any site is verified by the «Check route» button on the Service rules page.

See also: [Getting started](Getting-Started-en) · [Routing Master](Routing-Master-en) ·
[Access control](Access-Control-en) · [DNS settings](DNS-Settings-en)
