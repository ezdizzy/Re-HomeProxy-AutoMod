🇬🇧 [English](DNS-and-Diagnostics-en) | 🇷🇺 [Русский](DNS-and-Diagnostics-ru)

# DNS & Diagnostics

Two related topics: how Ravnex resolves names (and why that matters for leaks), and how to verify
everything works.

---

## DNS

The DNS pools, Reserve DNS and MultiDNS are configured on the dedicated
**[DNS Settings](DNS-Settings-en)** page. The Connection page keeps only the single DNS server
of the «Everything via node» mode. Which fields are visible depends on the routing mode.

### The working mode — two resolvers

«Blocking bypass» splits DNS into a **plain** and a **secure** resolver so queries go where they
should:

| Field | Purpose | Default |
|---|---|---|
| **Russia DNS server 🔓** | Resolves **Russian** domains **directly**, without the proxy. Plain UDP DNS. | Yandex `77.88.8.8` (also SkyDNS, Comss.one, Cloudflare, Google) |
| **Secure DNS server 🔒** | Resolves **restricted** domains **through the proxy** over encrypted DNS (DoH/DoT), so these queries stay invisible to the provider. | Cloudflare DoH (also Quad9, AdGuard, Google; DoT variants) |

This split matters: resolving a direct-unreachable domain over the provider's plain DNS either fails or
leaks the query, so such domains ride encrypted DNS through the proxy while plain Russian
domains resolve fast and direct.

> **About ByeDPI:** when the node is ByeDPI, the secure DNS is automatically detoured **direct**
> (not through ByeDPI), because desync corrupts DoH/DoT. This is handled for you — see
> [ByeDPI](ByeDPI-en).

### IPv6 and leaks

In the working mode **IPv6 support is disabled by default on purpose**: the RU routing lists
**contain no IPv6 subnets**, so any IPv6 traffic would bypass *both* the proxy and the rules —
a silent leak. If your WAN has IPv6 and you want everything controlled, it is safer to **leave
IPv6 off**.

---

## Diagnostics

The live checks live on the **[Health center](Monitoring-and-Connections-en#health-center)** page.
Every card has its own **Check** button.

| Card | What it shows |
|---|---|
| **Connection check** | Test-site reachability. On **hiddify-core** it also shows your **provider IP** vs the **proxy IP** (while really proxying they must differ); on **sing-box-extended** it shows the **Active node** instead. |
| **Core & system** | Whether the core and the engines are installed, the active binary, version, running state (with PIDs) and listening ports. Has a **Restart service** button. |
| **Configuration** | Whether the generated core config is valid, its size and the inbound / outbound / rule counters. |
| **DNS test** | Verifies resolution through the configured resolvers; in the working mode the **RU pool** is honestly checked too (not silently skipped). |
| **MultiDNS monitor** | Live scores of the racing servers — on the **[DNS Settings](DNS-Settings-en)** page: open-ratio, latency, pruning. |
| **Traffic interception** | The nft/firewall interception state and, with Zapret enabled, the **NFQUEUE counters**, so you can see packets actually reaching nfqws2. |
| **Support report** | **Generate** a text report combining the checks above. Building runs **in the background** (the status shows on the button), the result is **Download .txt**; attach it when asking for help. |

### How to read the results

- **Provider IP == proxy IP** (hiddify-core) → traffic is not proxied (check the main node /
  routing mode). On sing-box-extended make sure the **Active node** row shows your node.
- **Core is not running** → press **Restart service**; detailed verdicts live in the
  [Health center](Monitoring-and-Connections-en#health-center).
- **Invalid config** → a node or a rule is malformed; the report names the error.
- **Zapret counters do not grow** → the strategy/queue is not catching traffic — see
  [Zapret](Zapret-en).

See also: [Getting started](Getting-Started-en) · [DNS settings](DNS-Settings-en) ·
[Monitoring and connections](Monitoring-and-Connections-en) · [Troubleshooting](Troubleshooting-en)
