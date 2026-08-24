🇬🇧 [English](DNS-Settings-en) | 🇷🇺 [Русский](DNS-Settings-ru)

# DNS Settings

A dedicated menu page (**Services → Re:HomeProxy AutoMod → DNS Settings**) that gathers every DNS setting in one place. Three tabs:

## DNS servers

The two pools behind the Russia-mode split routing:

| List | Purpose |
|---|---|
| **Russia DNS server 🔓** | Resolves **Russian** domains **directly**, without the proxy |
| **Secure DNS server 🔒** | Resolves **blocked** domains **through the proxy** over an encrypted channel (DoH/DoT) |

Each list accepts multiple entries. Without MultiDNS the first entry is used; with MultiDNS all entries are raced.

## Reserve DNS

For setups **without MultiDNS**: a daemon watches the **first server of each list above**; when it stops answering, a healthy server from the same list is moved to the front (all entries are kept). Two sub-switches enable the check for the plain and the secure pool separately; only plain UDP/Do53 servers are health-checked, DoH/DoT are assumed always up.

> ⚠️ Ignored while MultiDNS is enabled — MultiDNS already races every server of each pool on every query. Use one or the other.

## MultiDNS

The DNS racing engine ([mosdns](https://github.com/mosdns/mosdns)): every query is sent to all servers of the pool in parallel, the fastest valid answer wins. A separate quality daemon:

- verifies over HTTPS that returned IPs actually open the site;
- keeps a rolling per-server score (open-ratio + latency + success);
- prunes consistently bad servers from the live pool and automatically restores them once they recover;
- maintains a "dead IP" blacklist with automatic expiry.

Options: race the plain pool, race the secure pool, tunnel secure-pool queries through the proxy, quality check interval. Below — a live monitor showing each server's score, latency and open-ratio, plus Rebuild pools / Reset trends / Disable & restore DNS buttons.

To install/update the mosdns engine use the **MultiDNS / mosdns** card on the [Core & Tools](Core-Management-en) page.

## Related pages

- [Getting Started](Getting-Started-en)
- [Routing & Access Control](Routing-and-Access-Control-en)
- [DNS & Diagnostics](DNS-and-Diagnostics-en)
