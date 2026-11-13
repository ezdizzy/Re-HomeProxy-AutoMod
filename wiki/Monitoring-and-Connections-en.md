🇬🇧 [English](Monitoring-and-Connections-en) | 🇷🇺 [Русский](Monitoring-and-Connections-ru)

# Monitoring and connections

The **Monitoring** page is the live picture of nodes and connections; the **Health center**
is the state of every app service.

---

## Node dashboard

- The **node table** with latencies and statuses — who is alive, degraded, or dead.
- The dashboard updates locally (SVG charts on the Home page: latency, connections, per-exit
  traffic).

---

## Live connections

- The list of active connections with **search and filters** (by device, node, resource).
- The **Close all** button — drop every connection (for example, after an exit change, so apps
  immediately re-dial through the new route).
- Selective close: per-row checkboxes + **«Close selected»**.

---

## Daemon resources

The «Daemon resources» card shows the consumption of Ravnex's own daemons (RSS memory and open
file descriptors) against defined budgets:

- findings are honestly labeled `res:<name>` and surface in the Health center;
- observation intervals are adaptive: on overuse the pass frequency grows;
- on weak devices the **resource profile** (Lite / Balanced / Performance) applies — see
  «Maintenance → Resource profile».

---

## Health center

A dedicated page (Sidebar → System → «Health center»):

- a **verdict banner** — the aggregated system state + counters;
- the **service table by groups** with honest explanations (why this status, what the system
  already did, what happens next) and **Repair / Unblock** buttons;
- «System attention» — Sentinel findings that do not write into Health;
- the **repair history** and the full **event feed** (apply operations journal, Health, Recovery,
  Hot Swap, the automation engine, etc.);
- **Service restart** — through the safe apply door with an operations journal.

Every automatic decision is explainable: the reason, the confidence, the next check — no black
box.

---

## See also

- [Hot Swap and reliability](Hot-Swap-and-Reliability-en) — the watchdogs and the RU-internet
  invariant
- [Overview](Overview-en) — charts and subsystem cards
