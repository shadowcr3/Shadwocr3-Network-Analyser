# Roadmap against the PRD/TRD

| Area | v0.1.0 | Next |
|---|---|---|
| Authorised reconnaissance (Nmap) | Done: scoped discovery and service scans | Exclusions, IPv6, per-target budgets |
| Safety gates, audit, rate limits | Done for scans | Generalise into a shared policy engine for every integration |
| Data, history, export | Done: SQLite, provenance, JSON/CSV | Retention settings, redaction options, reports |
| Job management | Single scan guard, cancellation | Job manager: IDs, states, queue, progress |
| Integration framework | Nmap adapter only | Adapter contract (capabilities, limits, cancellation), plugin permissions |
| Packet analysis | Not started | TShark PCAP/PCAPNG import, filters, offline replay |
| Defensive monitoring | Not started | Offline Zeek and Suricata (EVE) ingestion |
| Live monitoring | Not started | psutil interface metrics, pyqtgraph charts |
| Topology | Not started | QGraphicsView and NetworkX with provenance per edge |
| Investigations, correlation | Not started | Linked evidence, notes, uncertainty-aware correlation |
| Vulnerability and OSINT imports | Not started | Greenbone import, then SpiderFoot/Amass |
| Privilege model | App must be elevated for ARP/MAC | Separate elevated helper process |
| Packaging | Windows script provided | Signed builds, Linux packages |

Order of work: platform core -> offline imports -> live monitoring -> topology -> investigations
-> external-intelligence imports. Offline before live and adapters before UI keeps privileged and
active features for last.
