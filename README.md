# Shadowcr3 Network Analyzer

Network discovery and port/service analysis for networks you own or are
explicitly authorised to assess. Python, Nmap, SQLite, PySide6.

> **Use only on networks you own or have written permission to test.**
> The tool enforces a conservative scope (private, loopback and link-local
> IPv4 ranges, at most 256 addresses) and records your authorisation
> confirmation with every saved scan. It cannot verify that confirmation;
> that responsibility is yours.

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download) on `PATH` (the Windows installer bundles Npcap)
- Windows 11 and Linux (Arch) are the tested targets; macOS is best-effort

## Install (from source)

```
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage (CLI)

```
python src/cli.py 192.168.1.0/24 --i-am-authorised
python src/cli.py 192.168.1.20 -p services --i-am-authorised
```

| Profile | What it does |
|---|---|
| `discovery` | Host discovery only, no port scan |
| `quick-ports` | Top 100 TCP ports |
| `services` | Top 100 TCP ports plus light service/version detection |

| Exit code | Meaning |
|---|---|
| 0 | Scan completed (zero hosts found is still a valid result) |
| 2 | Invalid input or missing authorisation flag |
| 3 | Target outside the allowed scope |
| 4 | Nmap not found |
| 5 | Scan timed out |
| 6 | Scan failed or output could not be parsed |

## Privileges

Raw-socket features (ARP discovery, MAC addresses, SYN scans) need
Administrator/root. Without them Nmap falls back to TCP connect probes and
MAC addresses are unavailable. Results show whether the scan was privileged.

## Reports and history

Scans are stored in a local SQLite database (per-user data directory).
Reports export to JSON or CSV. CSV cells that begin with `=`, `+`, `-` or `@`
are prefixed with `'` so spreadsheet apps do not execute scanned data as formulas.

## Development

```
python -m ruff check src
python -m mypy src
python -m pytest
```

Tests use a fake Nmap executable and saved XML fixtures; they never touch a network.

## Known limitations (v0.2)

- IPv4 only, single target per scan, no hostnames
- No scan-to-scan comparison yet
