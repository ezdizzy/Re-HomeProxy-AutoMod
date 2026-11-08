🇬🇧 [English](Overview-en) | 🇷🇺 [Русский](Overview-ru)

# Overview (Home)

The first page of the app is the Ravnex «home screen». It answers three questions in seconds:
what is happening in the network right now, is everything alive, and what to do next.

Open it via **Services → Ravnex → Home**.

---

## What is here

### Subsystem cards

Every key subsystem gets its own card with an honest live status:

- **Main node** — the active proxy connection (node, latency);
- **Routing mode** — «Blocking bypass» / «Everything via node» / «Direct»;
- **Bypass engines** — Zapret 2 / ByeDPI and their current state;
- **DNS** — pool health and MultiDNS;
- **Automation** — the self-learning engine (running / paused with a reason);
- **Health center** — an aggregated verdict across all services and problem counters.

The cards are «smart»: in «Direct» mode the page re-arranges itself and shows an honest banner
instead of failing checks.

### Charts

Every chart is drawn **locally in your browser** (SVG, no CDNs):

- CPU and RAM load;
- temperature;
- connection count;
- main-node latency;
- **traffic per exit** — how much went through the main node, the engines, and directly.

### Quick actions

From the home page you can switch the mode, restart the service or jump to the dedicated pages:
**[Routing Master](Routing-Master-en)**, **[Service rules](Routing-Master-en)**,
**[Health center](Monitoring-and-Connections-en#health-center)** and more.

---

## Resource profile

The bottom of the page shows your hardware profile badge: **Auto / Lite / Balanced /
Performance**. The profile scales how often pages and watcher daemons refresh to match your
hardware (on weaker routers «Lite» cuts polling ×3). Details: **Maintenance → Resource profile**.

---

## See also

- [Hot Swap and reliability](Hot-Swap-and-Reliability-en) — what keeps the link alive
- [Monitoring and connections](Monitoring-and-Connections-en) — node dashboard and live connections
- [Routing Master](Routing-Master-en) — the transport layer (DPI) and rules
