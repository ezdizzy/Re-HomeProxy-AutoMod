🇬🇧 [English](Hot-Swap-and-Reliability-en) | 🇷🇺 [Русский](Hot-Swap-and-Reliability-ru)

# Hot Swap and reliability

What Ravnex does when nodes die, configs corrupt, and the provider throttles traffic.

---

## Hot Swap — hot standby for the main node

The main node is the single point of failure of a usual proxy scheme. Hot Swap removes that:

- several **continuously probed** backup connections stay warm next to the main one;
- when the main node dies, the switch to a live backup happens **within seconds and without
  restarting the core** — established sessions survive;
- the **anti-flap guard** stops the system from oscillating between nodes at marginal quality;
- after the main node recovers, a **failback** to it is possible.

Settings live on the **Connection** page (the Hot Swap section): the backup list
(`hotswap_nodes`) and the switcher behavior. Every switch lands in the event journal with a
**human-readable node name** and arrives as a Telegram push.

---

## URLTest — three modes

When the main node = **URLTest**, the node group picks the best member itself:

| Mode | Behavior |
|---|---|
| **Auto** | Best node of the group by measurements; switches on degradation |
| **Preferred node + auto** | Always try the named node first; on its death — the best of the group |
| **Manual list** | You define the order and the members |

A dead-node watchdog watches the group and writes events (node dead / recovered / config
reloaded) to the journal.

---

## Invariant: the Russian internet is always alive

With a working WAN you **always have at least the Russian internet** — even if any mechanism
breaks. The failure cascade is verified live:

- the proxy path dies → RU sites keep working directly, proxied traffic fails fast;
- the core is killed → a 4–8 second window, then a service restart;
- the engines are killed → interception passes packets straight through (NFQUEUE bypass);
- the firewall chains are wiped → everything goes direct;
- mosdns dies → DNS lives on the dnsmasq ladder, the MultiDNS daemon rebuilds the config itself.

The «Direct» mode is part of reliability too: all bypass machinery switches off and the router
hands out exactly what the provider gives. The mode for repairs and diagnostics.

---

## Last-known-good for every config

Every important config (core, mosdns, rule-sets, RU geo) goes through a pipeline:

1. a candidate is generated next to the live file and **checked**;
2. a passing candidate replaces the old file atomically;
3. the service starts — the verifier confirms it is actually alive;
4. only then does the candidate become the new `.lastgood`.

A broken config never reaches production, and if something breaks after the start — an
automatic rollback to `.lastgood` and a restart.

---

## Fail-safe interception

- **TUN fail-closed** — while TUN is not up, an «unreachable» route is pre-installed: there is
  no window for traffic to leak past the interception.
- **WAN-DNS freeze** — a snapshot of the provider resolvers is kept as the last dnsmasq server:
  when the proxied DNS chain dies, domains still resolve directly.

Direct-connection resilience: a node failure no longer breaks SSH/DNS/long-lived sessions;
**OAuth logins** (Google/Microsoft/Apple) ride a pinned secure exit — logins do not «fall off»
on IP changes.

---

## Watchdogs and the health center

- **Health** — live verdicts for every service (ok / degraded / down / off) with a reason and
  confidence.
- **Sentinel** — an independent watchdog for the monitoring itself and the configs, with a
  loop-guard against repair loops.
- **Recovery** — the recovery coordinator: hysteresis, exponential retries, auto-repair limits,
  priority for manual action.

All of it is visible in the **[Health center](Monitoring-and-Connections-en#health-center)**: a
verdict banner, a service table with repair buttons, and the full event feed.

---

## Snapshots and emergency recovery

On the **Maintenance** page: a one-click config snapshot and the **Restore internet** button —
an emergency switch to the direct connection.

---

## See also

- [Routing & access control](Routing-and-Access-Control-en) — modes and device control
- [Routing Master](Routing-Master-en) — strategies and composition rollbacks
