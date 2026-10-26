# Changelog

## 0.1.0

First release.

- Scoped Nmap discovery and service scans from a PySide6 GUI and a CLI
- Safety gates: private-range scope, size cap, authorisation, impact confirmation, one scan at a
  time, cooldown, Nmap rate and retry caps, audit-first operation
- Append-only audit log, interrupted-scan detection, scan history with provenance and verified raw output
- JSON and CSV reports with SHA-256, CSV formula-injection protection
- Cancellation, hard timeouts, partial-result labelling, structured redacted logs, versioned migrations
