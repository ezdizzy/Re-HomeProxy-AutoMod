🇬🇧 [English](Telegram-en) | 🇷🇺 [Русский](Telegram-ru)

# Phone control

The Telegram bot is a full Ravnex remote: status, nodes, house control, subscriptions,
snapshots and push notifications. The settings page is **Phone control**.

---

## Connecting the bot

1. Create a bot with **@BotFather** and paste the token on the Phone control page.
2. Send the bot its first message — your chat is bound as the owner chat.

The bot daemon is always running and **re-reads the settings itself** — saving does not restart
the service. The bot controls the router only through the app's internal API (no direct
UCI/shell edits).

---

## Commands

**Router:**

| Command | What it does |
|---|---|
| `/status` | System state |
| `/nodes` | Node list |
| `/switch N` | Switch the exit **without a core restart** |
| `/service` | Service control |
| `/snapshot` | Config snapshot |
| `/status_engine` | Bypass engine state |
| `/connections` | Live connections |
| `/close` | Close connections |

**Access control:**

| Command | What it does |
|---|---|
| `/menu` | Everything in buttons |
| `/devices` | Block / timed block / timed allow / Wi-Fi block |
| `/blocksite` | Block a site |
| `/pause` · `/resume` | Pause and resume rules |
| `/wifi` | Wi-Fi control |

**Subscriptions:** `/subs` — list and status, `/subadd` — add a subscription by URL; device
mode changes and subscription deletions require an explicit confirmation.

---

## Arbitrary commands

The owner can run an arbitrary command on the router — with a **preview and confirmation**, a
timeout and hang-protection, and a full audit trail in the journal.

---

## Push notifications

- node switches (Hot Swap) — with a **human-readable node name**;
- service failures and recoveries;
- self-learning engine events (a new blocked site learned, etc.).

Pushes are **deduplicated**: a repeated alarm from one subsystem does not spam (cooldown), and
«recovered» arrives only in response to an actually delivered alarm; critical notifications are
never gated. Notification categories are configurable — unnecessary noise can be turned off.

The bot stays connected even when the **proxy chain has died** — channel resilience is built in.

---

## See also

- [Access control](Access-Control-en) — devices, site rules, Wi-Fi
- [Hot Swap and reliability](Hot-Swap-and-Reliability-en) — node switches
