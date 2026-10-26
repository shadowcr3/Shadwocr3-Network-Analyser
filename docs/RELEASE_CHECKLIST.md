# Release checklist (v0.1.0)

Before tagging, on the Windows 11 machine, using only your own network:

- [ ] `python -m ruff check src tests`, `python -m mypy src`, `python -m pytest` are all green
- [ ] `shadowcr3-na doctor` reports Nmap and the correct privilege state
- [ ] GUI: scan `127.0.0.1` (`quick-ports`) shows the host
- [ ] GUI: scan your LAN IP with `services` shows open ports
- [ ] GUI: `/24` `discovery` asks for confirmation; declining starts nothing
- [ ] Same `/24` from a normal and an Administrator terminal; compare hosts and MACs
- [ ] Cancel a running `/24` scan: status says cancelled, no `nmap.exe` left in Task Manager
- [ ] Press Scan twice quickly: second attempt is refused (cooldown), no crash
- [ ] Export a PDF and a CSV; open the PDF (branding, page numbers, tables) and the CSV in Excel
- [ ] Import a Suricata EVE file and a Zeek conn.log; open a PCAP in Packets; check the topology
- [ ] Create an investigation, link evidence, export its PDF report
- [ ] Close and reopen: history persists; incomplete scans are marked; Audit log opens
- [ ] Rename the history database temporarily: the app starts cleanly with a new one
- [ ] `packaging\build_windows.ps1`, then run the built exe on a machine without Python
- [ ] Record the SHA-256 of the release zip in the release notes
- [ ] Add a LICENSE file (your choice) and confirm README claims match reality
- [ ] `git tag v0.1.0` and publish the GitHub release with CHANGELOG.md notes
