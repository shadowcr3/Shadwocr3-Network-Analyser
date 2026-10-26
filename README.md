# Shadowcr3 Network Analyzer

A local-first desktop workstation for network visibility and authorised assessment: scoped Nmap
scans, offline packet analysis, Suricata and Zeek imports, asset inventory, topology, alert
triage and evidence-backed investigations with branded PDF reports. Python, PySide6, SQLite.

> **Use only on networks you own or have written permission to test.** The tool enforces a
> conservative scope and records your authorisation, but it cannot verify it. See
> [docs/SAFETY.md](docs/SAFETY.md).

## Workspaces

| Workspace | What it does |
|---|---|
| Dashboard | Live interface throughput and packet-rate charts (OS counters), inventory tiles |
| Topology | Interactive graph of assets and observed conversations, with provenance per edge |
| Assets | Inventory from scans and imports; conflicting identities flagged as uncertain |
| Packets | Offline PCAP/PCAPNG inspection through TShark; open in Wireshark; add conversations to topology |
| Alerts | Import Suricata EVE JSON; triage (acknowledge, resolve, false positive), notes |
| Reconnaissance | Scoped, rate-limited Nmap scans with impact confirmation, history and PDF/CSV export |
| Investigations | Link evidence, write notes, export a branded PDF report |
| Integrations | Detected tools, imported evidence with hashes, policies, audit log |

## Status: v0.1.0

Implemented and tested: everything above, plus an append-only audit log, versioned database
migrations, cancellation and timeouts, partial-result labelling, redacted rotating logs, light and
dark themes, keyboard navigation (Ctrl+1 to Ctrl+8).

Not implemented (listed honestly in Integrations): live packet capture, Greenbone and
SpiderFoot/Amass imports, plugins, scan-to-scan comparison. See [docs/ROADMAP.md](docs/ROADMAP.md).
Tested on Windows 11 and Linux; macOS is untested.

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download) 7.80+ for scanning (Windows installer includes Npcap)
- [Wireshark/TShark](https://www.wireshark.org/download.html) for packet inspection (optional)

## Install and run

```
python -m venv .venv
.venv\Scripts\activate            # Linux: source .venv/bin/activate
pip install -e ".[gui]"
shadowcr3-na doctor               # verifies tools, privileges and storage
shadowcr3-na-gui                  # the workstation
```

## CLI

```
shadowcr3-na scan 192.168.1.0/24 --i-am-authorised --confirm-high-impact --save --pdf report.pdf
shadowcr3-na history list
shadowcr3-na history export 3 report.pdf
shadowcr3-na audit
```

Reports are PDF (human-readable) or CSV (spreadsheets). Exit codes: 0 ok, 2 invalid input or
missing authorisation, 3 out of scope, 4 tool missing, 5 timeout, 6 failure, 7 high-impact not
confirmed, 8 rate limited, 9 storage or audit unavailable, 130 interrupted.

## Your data

Per user: `%LOCALAPPDATA%\shadowcr3-na\` (Windows) or `~/.local/share/shadowcr3-na/` (Linux);
override with `SHADOWCR3_NA_HOME`. Nothing is uploaded. Deletion is always explicit.

## Develop

```
pip install -e ".[gui,dev]"
python -m ruff check src tests
python -m mypy src
python -m pytest
```

## Known limitations

- Scans: IPv4 only, one target per scan; the one-scan guard is per process
- Elevated features (ARP/MAC) need the whole app run as Administrator/root
- PDFs use standard fonts, so non-ASCII text in reports is replaced with `?`
- The audit log blocks accidental edits but is not tamper-proof against a privileged local user
- The Windows package script is provided but its output must be smoke-tested before release
