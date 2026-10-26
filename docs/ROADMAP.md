# Roadmap against the PRD/TRD

| Area | v0.1.0 | Next |
|---|---|---|
| Authorised reconnaissance (Nmap) | Done: scoped, rate-limited, confirmed, audited | Exclusions, IPv6, per-target budgets |
| Live monitoring | Done: interface counters and charts (not packet capture) | Per-protocol breakdown, configurable refresh |
| Topology | Done: evidence-aware graph, filters, provenance, partial-view notice | Inferred edges, layouts |
| Packet analysis | Done offline: TShark PCAP/PCAPNG, filters, Wireshark launch | Live capture with a least-privilege helper |
| Defensive monitoring | Done: Suricata EVE and Zeek conn.log import, alert triage | Zeek DNS/TLS logs, anomaly rules |
| Assets and investigations | Done: provenance, uncertainty, notes, PDF reports | Correlation suggestions, search across sources |
| Integration framework | Detected tools, import adapters | Formal adapter contract and plugin permissions |
| Greenbone, SpiderFoot, Amass | Not implemented | Structured imports |
| Job management | Per-page background tasks, scan guard | Central job queue with persisted states |
| Privilege model | App must be elevated for ARP/MAC | Separate elevated helper process |
| Packaging | Windows script provided | Signed builds, Linux packages |
