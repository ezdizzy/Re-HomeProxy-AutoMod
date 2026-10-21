# Project status: automatic blocked-site detection (Automation)

> The purpose of this document is to record what is already done for the A–D list, what is NOT
> yet tested on the device and what remains to be done, so work can continue in another session.

Engine: `root/etc/homeproxy/scripts/automation.uc` (runs as a separate procd instance from
`root/etc/init.d/homeproxy` when `automation.enabled=1`). Controlled from the Lua UI:
`htdocs/luci-static/resources/view/homeproxy/automation.js`; RPC methods in
`root/usr/share/rpcd/ucode/luci.homeproxy` (`automation_status`, `automation_list_read/write`,
`automation_clear`, `automation_test_now`, `diag_service_restart`). Kernel config generation:
`root/etc/homeproxy/scripts/generate_client.uc`.

General classification principle (unchanged): each candidate is probed TWICE — directly
(`auto-direct-in` → `direct-out`) and through the main path (`auto-proxy-in` → `main-out`, which
is already `byedpi-out`/`zapret-out`). Only things that do NOT work directly but DO work through
the proxy end up in `auto_proxy_list.txt`/`auto_proxy_ip.txt`. This is ByeDPI/Zapret-compatible.

---

## A. "DNS race" mode (detect at the resolution stage) + picking a working DNS

**Done:**
- New detection mode `dns`: the daemon enables the dnsmasq log (`logqueries=1` +
  `logfacility=/var/log/dnsmasq-q.log`, `enable_dns_log()`), then reads the file and extracts
  the domain with the regex `query\[[Aq]+\]\s+<domain>\s+from`. The domain is captured BEFORE
  the connection is established — the "site will be fixed on the second visit" window shrinks
  to a single attempt.
- The log offset is tracked (`dns_log_offset` in `automation_state.json`) so it does not
  rescan from the beginning after a restart; on log rotation the offset resets.
- UI (`automation.js`): modes `dns`, `both` (Clash+DNS), `all` (Clash+DNS+conntrack).
- Working DNS picker (`client.js`): the `dns_preset` selector (Cloudflare/Google/AdGuard/Quad9/
  OpenDNS). When picked, it sets the main `dns_server` and "seeds" a backup into
  `alt_dns_servers` (see C). Below the selector there is a real `DynamicList alt_dns_servers`
  on the Client ▸ DNS tab.

**Not finished / risks (must be verified on hardware):**
- The regex must match the exact dnsmasq build installed on the router (the line format
  `query[A] ... from` may differ). Check and adjust if it does not match.
- The dnsmasq log is global and grows; there is no rotation/trimming of `/var/log/dnsmasq-q.log`.
  Add a size limit or logrotate.
- "Works on the first visit" is achieved by the combination of A (early capture) + D (preloading
  popular sites). For a brand-new site the first visit may still fail when direct fails — it is
  fixed on the second one. That is expected behavior.

---

## B. IP:port learning through conntrack (games/apps without SNI)

**Done:**
- Mode `conntrack`: `discover_conntrack()` takes `dst=` from `conntrack -L` (ESTABLISHED),
  probes each IP directly/through the proxy, and on `direct=fail & proxy=ok` writes it to
  `resources/auto_proxy_ip.txt` (the base domain is not applied — these are IPs).
- Controlled by the `automation.ip_learn` flag (default **0/off**, so that extra IP traffic is
  not routed without an explicit need).
- `generate_client.uc`: `auto_proxy_ip.txt` → inline ruleset `auto-ip` (ip_cidr) → `main-out`
  (lines ~1557–1574 and the rule at ~1682–1695), for both routed and tun modes.
  ByeDPI/Zapret-compatible.
- `automation_clear` now also removes `auto_proxy_ip.txt`.

**Risks:**
- `conntrack` yields many CDN IPs — possible over-routing through the proxy. Needs dedup/cap
  and, maybe, ignoring popular ASNs.
- Probing an IP via `https://<ip>` with `-k` is unreliable (no SNI/Host) — some sites reject
  IP-based requests even when they work by domain. May produce false positives. Requires field
  testing and, possibly, different probe logic for IPs.
- The UI monitor shows only domains; learned IPs are not visible in the monitor (only in the file).

---

## C. DNS server failover when unavailable

**Done:**
- `config.dns_failover` (flag, UI in automation.js) + `config.alt_dns_servers`
  (`DynamicList`, UI on the Client ▸ DNS tab; the `dns_preset` selector seeds it too).
- `dns_failover_check()` (once a minute): if the main `dns_server` is unavailable — switches
  `dns_server` to the first healthy one from `alt_dns_servers`, runs `generate_client.uc` + reload.
- `dns_reachable()` probes only plain UDP/Do53 (DoH/DoT are considered always available):
  `curl https://<srv>/dns-query` OR `dig +short @srv`, otherwise `nc -u -z`.

**Risks:**
- `dig` may be missing on the target system — then plain-server health is checked only via
  `curl` to the DoH endpoint, which is inaccurate for pure UDP servers. Replace with a real
  UDP query (e.g. via `nslookup`/`drill` or an in-process core resolver).
- Switching `dns_server` rewrites UCI and regenerates — make sure this does not conflict with
  other places reading `dns_server`.

---

## D. Backup / restore of YOUR list (two buttons)

**Done:**
- The Automation tab has two buttons (no URLs/settings):
  - **"Download list" (backup)** — via the `automation_backup` RPC it returns the contents of
    `auto_proxy_list.txt` straight to the browser as a `homeproxy_learned_list.txt` file.
  - **"Restore list" (from file)** — via the `automation_restore` RPC it accepts a user-uploaded
    file (one domain per line) and **adds only the missing** sites (existing ones stay as they
    are), seeds them as learned into `auto_proxy_list.txt`, sets pending_reload and reloads
    the config.
- Purpose: avoid re-learning from scratch after a router reset — restore the previously learned
  list from a computer.
- This is NOT a curated external blocklist and not URL synchronization — a local file only.

**Risks:**
- Restore adds only missing lines (no base_domain dedup); exact duplicates are ignored.
- The uploaded file must be plain text, one domain per line.

---

## What is still NOT verified (critical before release)

1. Build and install: `.\\build-run.sh` → `dist/` → zip into `release/`; `install.sh` installs
   onto the router. Not run on a real device in this session.
2. Availability of tools on the target: `curl`, `dig`/`nc`, `conntrack`, `wget`, and the `ucode`
   version (uses `fd.seek`/`fd.tell`, `stat().size`, `json()`, `index()`, `type()` — verify on
   the target ucode).
3. The dnsmasq log line format (see A) — the main risk for the `dns` mode.
4. Behavior of `formvalue(section_id, name, value)` (the setter) in LuCI when writing
   `alt_dns_servers` from `dns_preset.write` — it is assumed that DynamicList saves the array.
   Verify in the UI.

## Open TODOs (continuation)

> **Update (August 2026, Automation v2):** implemented — dedup/cap/CDN filter for
> conntrack IPs (repeat threshold ≥2, shared CDNs excluded, cap 8/cycle, min_confirm≥2);
> learned IPs shown in the monitor; TCP/TLS-fallback probing for non-HTTP endpoints
> (Telegram DCs, games); self-healing of learned entries in both modes; hot-reload of the list;
> batched state writing with hygiene (prune + hard cap). UI: sources — multi-select
> dns/clash/sni, a separate "Learn IP destinations" toggle.

- Rotation/limit of `/var/log/dnsmasq-q.log`.
- More precise DNS health checks (a UDP query instead of `curl`-to-DoH).
- Field tests of A/B/C/D on the router and regex/logic fixes based on the results.

## Quick build/test checklist

```
.\\build-run.sh            # build dist/ and release/
# install.sh installs the opkg package onto the router
# Enable in the UI: Automation ▸ Enable + sources (multi-select dns/clash/sni) + Learn IP destinations
# Optional: the "DNS Settings" page ▸ preset/reserve (for Global mode) or MultiDNS
# Daemon log: /var/run/homeproxy/automation.log ; state: /var/run/homeproxy/automation_state.json
# Learned data: /etc/homeproxy/resources/auto_proxy_list.txt and auto_proxy_ip.txt
```


---

## Update 2026-09-11: engine rework (adaptivity + native helpers)

The engine received the "Phase 1" rework (see LOCAL_DOCS/07-AUTOMATION_ENGINE_OVERHAUL) and two
optional native helpers. Everything below is optional and degrades gracefully:

**In the `automation.uc` core:**
- **Plain-view DNS through mosdns** — the direct probe resolves hosts via the local mosdns plain
  listener (127.0.0.1:5453) when MultiDNS is active (flag + binary + `pidof` are checked);
  otherwise — the previous nslookup cascade of 8.8.8.8/1.1.1.1/77.88.8.8. The answer is the same
  RU-facing view the browser sees.
- **Adaptive timeout** (`adaptive_timeout`, on by default) — an EWMA of response time per host
  (state fields `ewma_rtt_direct/proxy`) sets the per-host probe timeout `clamp(ewma×3+1s, 2s, 2×base)`:
  fast hosts are checked faster, slow ones get headroom. Applies in all wave paths (native batch
  and shell workers); the serial self-heal stays on the base timeout.
- **Adaptive confirmation threshold** (`adaptive_confirm`, on) — hard blocks (4xx/5xx and 200
  with a block page) are learned with the normal `min_confirm`; "000/timeout" — with +1.
- **Weighted cross-correlation of sources** — candidate priority = Σ(weight × occurrences):
  `discover_weight_dns` (1.0) / `discover_weight_clash` (1.5) / `discover_weight_sni` (1.2).
- **Resource-aware scheduling** (`resource_aware`, on) — cycle pause of 5/10/30 s based on loadavg
  and MemAvailable; a mode change is logged once, without spam.
- **HTTP/2 probes** (`http2_probe`, on) — `--http2` only if `curl --version` really supports
  HTTP2 (otherwise the flag is silently disabled — on curl without h2 it would break ALL probes).
- **CDN range exclusions** (`asn_enabled`, on) — `resources/cdn_ip4.txt` (built by `ru_geo_build.uc`
  from the free IPtoASN database over a list of CDN/cloud ASNs) is checked with binary search;
  IPs from these ranges are never learned. No runtime whois and no external queries.

**Native helpers (Go, installed by `install.sh` from releases per architecture — arm64 / amd64 /
mipsle-softfloat / armv7 / armv6; unsupported architecture → skipped with a warning):**
- **`probe_pool`** — one probe wave = one process: a batch of hosts is fed as a JSON file
  (`-in/-out`), inside are parallel probes through the same pinned inbounds (socks5 :5336 /
  socks5h :5337), pinned plain-view IP for the direct side (batch resolution — parallel, window
  8/16 concurrent requests), HTTP/2, keep-alive. Verdicts
  (ok/block) are computed by THE SAME ucode logic — the binary only measures. Any failure →
  fallback to shell workers until the daemon restarts. Enabled by `probe_pool_enabled` (on).
  Used in all profiles: perf — chunks of 16, eco — 8 (without the helper eco stays serial).
- **`sni_sniffer`** — continuous TLS ClientHello (SNI) capture on br-lan: kernel BPF filter
  (tcp/443 + PSH), ClientHello parsing, 10 min dedup, JSONL events into
  `/var/run/homeproxy/sni_events.jsonl` (~512 KB rotation). The daemon is started lazily by the
  automation daemon (pidof-guard + 10 min cooldown); if there are no events for 15 minutes —
  restart + one tcpdump wave. Without the binary — classic tcpdump. Enabled by
  `sni_sniffer_enabled` (on), interface — `sni_sniffer_interface` (br-lan).

**Rejected during the audit** (was in a draft implementation, removed as harmful/non-working):
a SQLite state backend (state_db) — the RPC and the UI table read `automation_state.json`
directly, SQLite would break them and carry 10-15 MB binaries with zero benefit (the state lives
on tmpfs); RU-geo delta updates (`.includes()` does not exist in ucode — fatal); the db-ip ASN
database with a hardcoded 2024-01 URL and RU detection by a substring in the ASN name; whois
queries for every IP candidate; HTTP/3 (quic-go does not build on 32-bit MIPS); a Prometheus
endpoint.

## Update 2026-09-12: pre-release speedups + helper visibility

- **Native batch in all profiles** — `probe_pool` is no longer disabled in eco: average 2-core
  routers with the helper installed (e.g. Cudy WR3000H: MT7981B, aarch64,
  128-256 MB RAM — supported, installed by the installer) get batches of 8 concurrent probes
  instead of serial ones; perf keeps 16. Without the helper eco remains classically serial.
- **Parallel plain-view batch resolution** — before the native batch, hosts are resolved
  concurrently (mosdns-5453 → public, window 8/16, 12 s deadline) rather than one by one:
  16-64 hosts no longer wait in a serial nslookup queue before the batch is sent.
- **Adaptive timeout is actually applied** (see the update above) — previously the EWMA was
  only recorded.
- **Visibility on the Automation ▸ Overview tab**: the active engine profile (eco/perf) and the
  status of native helpers — probe_pool installed/not installed, sni_sniffer installed+running/
  stopped/not installed (data from `automation_status`).
