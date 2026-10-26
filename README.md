# Shadowcr3 Network Analyzer

Discover hosts and open services on networks **you own or are explicitly authorised to assess**.
Python, Nmap, SQLite and PySide6. Local-first: nothing leaves your machine.

> **Use only on networks you own or have written permission to test.** The tool enforces a
> conservative scope and records your authorisation confirmation, but it cannot verify it.
> That responsibility is yours. See [docs/SAFETY.md](docs/SAFETY.md).

## Status: v0.1.0

Verified in this release (automated tests, plus manual checks on the maintainer's machines):

- Scoped host discovery and port/service scans through Nmap (GUI and CLI)
- Safety gates: private-range-only scope, size cap, authorisation confirmation, impact
  confirmation for large scans, one scan at a time, cooldown, Nmap rate and retry caps
- Append-only audit log, scan history with provenance (exact command, tool version, exit
  status, completeness, SHA-256 of the original output), JSON/CSV reports
- Cancellation, hard timeouts, partial-result labelling, interrupted-scan detection

Planned, **not** in this release: live traffic monitoring, topology graph, packet/PCAP
analysis, Suricata/Zeek/Greenbone/OSINT integrations, plugins, investigations, scan comparison.
See [docs/ROADMAP.md](docs/ROADMAP.md). Tested platforms: Windows 11 and Linux. macOS is untested.

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download) 7.80+ on `PATH` (the Windows installer bundles Npcap)

## Install

```
python -m venv .venv
.venv\Scripts\activate            # Linux: source .venv/bin/activate
pip install -e ".[gui]"
shadowcr3-na doctor               # verifies Nmap, privileges and storage
```

## Use

GUI: `shadowcr3-na-gui`. Enter a target such as `192.168.1.0/24`, tick the authorisation box,
choose a profile and press Scan.

CLI:

```
shadowcr3-na scan 192.168.1.0/24 --i-am-authorised --confirm-high-impact --save
shadowcr3-na scan 192.168.1.20 -p services --i-am-authorised --json report.json
shadowcr3-na history list
shadowcr3-na history show 3 --raw
shadowcr3-na audit
```

| Profile | What it does |
|---|---|
| `discovery` | Host discovery only, no port scan |
| `quick-ports` | Top 100 TCP ports |
| `services` | Top 100 TCP ports plus light service/version detection |

Scans above 64 addresses, or `services` above 16, are **high impact** and need explicit
confirmation (a dialog in the GUI, `--confirm-high-impact` in the CLI).

| Exit code | Meaning |
|---|---|
| 0 | Success (zero hosts is still a valid result) |
| 2 | Invalid input or missing authorisation |
| 3 | Target outside the allowed scope |
| 4 | Nmap missing or unsupported |
| 5 | Scan timed out |
| 6 | Scan failed or output could not be parsed |
| 7 | High-impact scan not confirmed |
| 8 | Refused by rate limiting (busy or cooldown) |
| 9 | Storage or audit log unavailable |
| 130 | Interrupted (Ctrl+C) |

## Privileges

ARP discovery and MAC addresses need Administrator/root. Without them Nmap falls back to TCP
probes, MAC addresses are unavailable and quiet hosts can be missed; results say whether the
scan was privileged. Running the whole app elevated is a known v0.1 limitation (a separate
elevated helper is planned).

## Your data

Stored per user: `%LOCALAPPDATA%\shadowcr3-na\` on Windows, `~/.local/share/shadowcr3-na/` on
Linux (override with `SHADOWCR3_NA_HOME`). It holds the history database (scans, hosts, ports,
original Nmap output, audit log) and rotated logs. Nothing is uploaded. Deletion and pruning are
always explicit. Reports contain IPs, MACs, hostnames and open services: store them securely.

## Develop

```
pip install -e ".[gui,dev]"
python -m ruff check src tests
python -m mypy src
python -m pytest
```

Tests use a fake Nmap and fixtures; they never touch a network.

## Known limitations (v0.1)

- IPv4 only, one target per scan, no hostnames
- The one-scan-at-a-time guard is per process (CLI and GUI are not coordinated)
- The audit log blocks accidental edits but is not tamper-proof against a privileged local user
- Nmap's reverse DNS lookups go to your configured resolver
- Windows packaging script is provided but its output must be smoke-tested before release
