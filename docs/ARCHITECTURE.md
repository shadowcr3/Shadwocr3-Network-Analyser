# Architecture

```
src/shadowcr3_na/
  core/        no Qt, no SQLite: scope, policy, runner (Nmap adapter), parser, scanner, export (CSV),
               importers/ (Suricata EVE, Zeek, TShark), netmon, topology, integrations
  storage/     SQLite: db (migrations), repository (scans), inventory (assets, connections, alerts,
               imports), investigations, audit (append-only log)
  reports/     branded PDF reports (ReportLab): scan assessment and investigation
  gui/         PySide6: workstation shell, pages/ (dashboard, topology, assets, packets, alerts,
               investigations, integrations), main_window (reconnaissance), tasks, charts, theme
  cli.py       argparse front end over the same core and storage
  paths.py, logging_setup.py
```

Flow of one scan: front end validates scope, assesses impact (confirmation), writes
`scan_requested`/`scan_started`, then `core.scanner.scan()` runs: validate -> impact check ->
guard slot -> locate and version-check Nmap -> `run_nmap` (argument list, deadline, cancel, tree kill)
-> `parse_nmap_xml` -> `ScanResult` with provenance. The front end then saves the result and
writes exactly one terminal audit event.

Rules that keep it safe and testable:

- The worker thread only runs Nmap. Widgets and the SQLite connection stay on the main thread.
- `core` raises typed errors, each with a `category` used by the audit log and exit codes.
- The core enforces policy itself (`ConfirmationRequired`, `ScanBusy`, `CooldownActive`), so a
  front end cannot skip it.
- Schema changes are versioned migrations run inside one transaction with an automatic backup.

Mapping to the PRD layers: presentation = `gui/`; services = `core/scanner`, `core/policy`;
integration adapter = `core/runner` + `core/parser` (Nmap); storage = `storage/`.
