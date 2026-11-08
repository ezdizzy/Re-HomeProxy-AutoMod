🇬🇧 [English](Access-Control-en) | 🇷🇺 [Русский](Access-Control-ru)

# Access Control

Parental control and per-device policy: who is in the house, what they ride, and when. One page
— **Access Control** — and the same from the Telegram bot.

---

## Devices

- The device list comes from the **live network** (not a static file — what is actually
  connected).
- **The proxy mode sits right on the device card**: Auto / Direct / Via proxy / Gaming /
  Global. «Auto» means «like everyone else» — the house-wide policy; an explicit mode overrides
  it for this device.
- **The honest badge**: a device's final mode is resolved with the same semantics as the
  firewall — you see what is actually applied.
- Expert **chip lists** (exceptions) — batch editing, no bulky forms.

---

## Site rules and Wi-Fi

- **Site blocking** — rules for individual resources (by domain).
- **Schedules and presets** — when and what is allowed.
- **Wi-Fi blocking** — entirely or per device.
- The **journal** — the access-control history.

An honest boundary: the restriction works through the DNS filter — **IPv4** clients and a
foreign-DoH bypass can get around it; that is a deliberate boundary, not a hidden bug.

---

## WAN IP policy and interface control

The advanced settings (WAN IP Policy, Interface Control) live on the
**[Connection](Routing-and-Access-Control-en)** page in a collapsed section.

---

## The same — from Telegram

The bot does all of this with commands and buttons: `/menu` (all in buttons), `/devices`
(block / timed block / timed allow / Wi-Fi block), `/blocksite`, `/pause`, `/resume`, `/wifi`.
Details: **[Phone control](Telegram-en)**.

---

## See also

- [Routing & access control](Routing-and-Access-Control-en) — routing modes
- [Phone control](Telegram-en) — the bot
