🇬🇧 [English](Routing-Master-en) | 🇷🇺 [Русский](Routing-Master-ru)

# Routing Master

The routing control center: two pages that together decide «which resource rides which exit» —
**Strategy master** (transport-layer engines and strategies) and **Service rules** (which service rides
which exit).

> Both work in the **«Blocking bypass»** mode. In «Everything via node» all traffic is tunneled
> into the main node; in «Direct» every mechanism is off — see
> [Routing & access control](Routing-and-Access-Control-en).

---

## Transport-layer engines (DPI)

Ravnex ships two VPN-free engines — use one or both:

- **Zapret 2 (`nfqws2`)** — packet-level connection processing via NFQUEUE: YouTube, Discord and other resources
  ride ordinary traffic with no VPN and no subscription, fast, with the Russian region preserved.
- **ByeDPI (`ciadpi`)** — SOCKS level: 47 ready presets and a strategy tester.

Engines are enabled on the **Connection** page (the package installs automatically on first
enable); strategies are configured here. Routing rules can hand a specific resource to Zapret
or ByeDPI instead of the proxy — that saves subscription traffic.

---

## The «Strategy master» page

### Provider diagnostics

Shows which resources are unreachable and how: directly or through your rules. The starting point
before picking strategies.

### Strategies and catalog

- Ready presets and the **strategy catalog** (Zapret-Manager) — one-click import.
- A **custom strategy generator** and an editable **TSPU list** (dpi-detect).
- **nfqws2 multi-strategies** — one process with several profiles and separate hostlists.

### Strategy Lab (strategy testing)

Fuzzing of the whole strategy corpus on an **isolated NFQUEUE** with a baseline run:

- per-round ranking with «preview start» and «stream speed» metrics;
- the currently applied strategy is measured too (the «current» row, deep battery);
- hosts no candidate passed are honestly excluded from the counts (`dead hosts`);
- a verdict is a measurement **on this router**: differences up to ~25% count as noise.

### One-click pick

Picks the best strategy for a single resource (YouTube / Discord / …): ranks strategies, applies
the winner, takes a **server-side snapshot** and verifies live — the rollback button is always
there.

### Composition

Different strategies for different resources at the same time: a YouTube profile + a Discord
profile + a general fallback. Also with a server snapshot and a rollback button.

### Scheduled autopilot

The permanent watchdog (schedule, re-ranking, auto-repair of a broken strategy with
alive / degraded / dead verdicts) lives on the **[Auto-bypass](Automation-Status-en)** page.

---

## The «Service rules» page

### Routing order map

Shows how the route is decided: host pins → service rules → routing rules → «everything else
goes direct».

### Service → exit

Every service gets its own exit in a table row: main node, another node, Zapret / ByeDPI, or
direct. The **Check** button in the row performs a live exit verification.

**The check is honest by design**: a site shell (~850 KB SPA) cannot be judged by a body probe —
the verdict is `refused`/`unknown` where appropriate, and nodes additionally get an egress probe.

### Rule exit options

| Option | Behavior |
|---|---|
| **Same as main node** | Your main proxy (in the «Direct» mode such rules are honestly disabled — resources assigned to the node must not fall back to direct) |
| **URLTest pool** | Auto-pick among a chosen node set, with its own test interval and tolerance |
| **A specific node** | The named server |
| **ByeDPI / Zapret** | Hand the list to a transport-layer engine instead of the VPN — saves subscription traffic |
| **No rule** | The domain is NOT added to the proxy lists and follows the general rules — this is **not** «straight into the Russian internet» |

### Preset lists

Every rule = a **source list** + an **exit**. The lists are community-maintained and
**auto-update** on the router; you only choose which ones to enable:

- **Russia**: Russia Inside (1000+ domains, itdoginfo) — the mandatory set; Re:Filter (60000+
  domains + 25000+ IPs) — the RKN block base; Block (the core of RKN-blocked resources);
  Russia Outside (RU-only services — for use abroad);
- **Services**: YouTube, Discord, Telegram, OpenAI, Claude, WhatsApp, Twitch, Meta, Twitter/X,
  TikTok, Roblox, Google Play, Google Meet, Google AI;
- **CDNs and hosting**: Cloudflare, CloudFront, DigitalOcean, Hetzner, OVH, HODCA;
- **Gaming**: Valve/Steam, Epic, Riot, PlayStation, EA, Ubisoft, Blizzard, Nintendo, Wargaming,
  Xbox;
- **Other**: international news, anime, HDRezka, adult, geo-blocked services.

Re-adding the same source is marked — only the first rule takes effect. A custom-list rule can
be deleted row by row — the button in the row; the list pipeline is checked automatically by
the CI hub with a sha256 gate.

### Pins

**«Always direct»** for a specific host — a pin from the automation table ranks **above every
list**: one host forced to direct wins over any rule.

### The Google AI rule

A dedicated row with a full check: the page opens → the model replies → the **Check other
nodes** button finds a node with a «clean» region when the model rejects the current one.

### Host pinning

«Always via proxy» / «Always direct» for a specific host:

- a pin covers **exactly this host and its subdomains** — CDN, API and other service domains
  follow their own rules;
- «always via proxy» rides the main node **below** the service rules (an enabled service rule
  wins); «always direct» goes direct **above** all rules;
- the real route of any site can be checked with the **Check route** button.

### Advanced rules (expert)

A collapsed group for raw rules — for those who know exactly what they are doing.

---

## See also

- [Zapret](Zapret-en) — nfqws2 in detail · [ByeDPI](ByeDPI-en) — ciadpi in detail
- [Auto-bypass](Automation-Status-en) — the autopilot and the self-learning engine
- [Hot Swap and reliability](Hot-Swap-and-Reliability-en) — what happens when a node dies
