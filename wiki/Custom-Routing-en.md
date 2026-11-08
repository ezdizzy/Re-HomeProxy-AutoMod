🇬🇧 [English](Custom-Routing-en) | 🇷🇺 [Русский](Custom-Routing-ru)

# Advanced rules (expert)

A collapsed expert group on the **[Service rules](Routing-Master-en)** page — for those who know
exactly what they are doing. Two tools live here:

1. **Routing Nodes** — named outbounds that rules can point to;
2. **Raw custom rules** — raw sing-box rules with the highest priority.

> The old «Custom routing» mode of v2 is gone in v3 — its capabilities moved here.

---

## Routing nodes

A **routing node** is a named outbound rules can point to. The editor is always visible (inside
the expert group) and the generator honors these nodes:

- a specific **node** or **URLTest** (auto-pick of the fastest in a pool);
- its own **Domain resolver** (including the Russia 🔓 / Secure 🔒 servers);
- a **Domain strategy** (IPv4 only, prefer IPv6, etc.).

This enables things like «this rule → node A, but resolve its domains over secure DNS».

---

## Raw rules

The **«Raw custom rules (expert)» 👨‍💻** flag enables the raw sing-box rule editor. These rules
are emitted with the **HIGHEST priority** — above every preset row and user list. They are for
shapes the preset rows and routing nodes cannot build; write them only if you know the sing-box
rule schema. The flag takes effect on Save & Apply.

### Matching fields (raw rules)

| Group | Match by |
|---|---|
| Other fields | **Protocol** (via sniffing — BitTorrent, DNS, QUIC, TLS, HTTP, STUN, SSH, RDP, DTLS…), IP version, network, rule-sets |
| Host/IP | `domain` / `domain_suffix` / `domain_keyword` / `domain_regex`, destination and source IP CIDR |
| Ports | destination / source port and port ranges |
| Process | process name / path (for traffic originating on the router itself) |

Matching logic — OR within a category, AND across categories; rules are evaluated top-down, the
first match wins. The fields map one-to-one to a sing-box route rule:

- [Route](https://sing-box.sagernet.org/configuration/route/) — how routing is structured
- [Route Rule](https://sing-box.sagernet.org/configuration/route/rule/) — every matching field
- [Sniff](https://sing-box.sagernet.org/configuration/route/sniff/) — protocol matching requires
  sniffing (enabled by default)

---

## Route check

The **Check route** button on the Service rules page answers, for a given site: which rule won
in the **live** config, the exit chain, and the protection verdict. Remote rule-sets are matched
by the core itself, so their exact membership is honestly reported as «probable».

See also: [Routing & access control](Routing-and-Access-Control-en) ·
[Routing Master](Routing-Master-en) · [Supported protocols](Supported-Protocols-en)
