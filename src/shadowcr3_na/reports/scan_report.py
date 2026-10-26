"""Branded PDF for one Nmap scan: summary, hosts, services, limitations and provenance."""
from __future__ import annotations

import os

from reportlab.platypus import Flowable, KeepTogether, Spacer

from shadowcr3_na.core.export import ReportInfo
from shadowcr3_na.core.models import ScanResult

from . import brand
from .pdf import (
    Badge,
    build_pdf,
    code_box,
    data_table,
    facts,
    para,
    section,
    title_block,
    utc_now_text,
    write_pdf_atomic,
)

_COMPLETE = {True: ("Complete", brand.OK), False: ("Incomplete", brand.BAD),
             None: ("Unknown", brand.MUTED)}


def _ports_text(host_ports: tuple) -> str:
    return "  ".join(f"{p.number}/{p.service or '?'}" for p in host_ports) or "-"


def _story(r: ScanResult) -> list[Flowable]:
    hosts_up = [h for h in r.hosts if h.state == "up"]
    open_total = sum(len(h.open_ports) for h in r.hosts)
    label, color = _COMPLETE[r.complete]
    story: list[Flowable] = title_block(
        "Network Assessment Report", f"{r.target}   |   profile: {r.profile}",
        f"Scan started {r.started_at:%Y-%m-%d %H:%M} UTC   |   report generated {utc_now_text()}")
    story.append(facts([
        ("Target", r.target), ("Profile", r.profile),
        ("Scan result", Badge(label, color)),
        ("Hosts found", str(len(hosts_up))), ("Open ports", str(open_total)),
        ("Duration", f"{r.duration_s:.1f} s"),
        ("Tool", f"Nmap {r.nmap_version or '?'}"),
        ("Privileges", "Administrator/root" if r.privileged else "Standard user"),
        ("Exit status", "-" if r.exit_status is None else str(r.exit_status)),
    ]))
    story.append(Spacer(1, 3 * 2.83))
    story.append(para("Prepared with Shadowcr3 Network Analyzer for a network the operator owns "
                      "or is authorised to assess.", "small"))

    limits: list[str] = []
    if r.complete is False:
        limits.append("Results may be INCOMPLETE. " + (" ".join(r.warnings) or
                                                        "Nmap did not report a clean finish."))
    elif r.complete is None:
        limits.append("Completeness is unknown: this record predates completeness tracking.")
    if not r.privileged:
        limits.append("Scanned without Administrator/root privileges: MAC addresses and ARP "
                      "discovery may be unavailable and quiet hosts can be missed.")
    if not r.hosts:
        limits.append("No hosts responded. This does not prove the network is empty: devices can "
                      "ignore probes, and scans without privileges see less.")
    if limits:
        story += [Spacer(1, 6 * 2.83), *section("Result quality and limitations")]
        story += [para("- " + item, "body") for item in limits]

    if r.hosts:
        story += [Spacer(1, 6 * 2.83), *section("Hosts")]
        rows = [[h.ip, h.hostname or "-",
                 (h.mac or "-") + (f" ({h.vendor})" if h.vendor else ""), h.state,
                 _ports_text(h.open_ports)] for h in r.hosts]
        story.append(data_table(("IP address", "Hostname", "MAC (vendor)", "State", "Open ports"),
                                rows, (26, 36, 58, 12, 42)))
    detail = [(h, p) for h in r.hosts for p in h.open_ports]
    if detail:
        story += [Spacer(1, 6 * 2.83), *section("Open services")]
        rows = [[h.ip, f"{p.number}/{p.protocol}", p.service or "-",
                 " ".join(x for x in (p.product, p.version) if x) or "-"] for h, p in detail]
        story.append(data_table(("Host", "Port", "Service", "Product and version"), rows,
                                (32, 24, 40, 78)))

    prov: list[Flowable] = [*section("Provenance"),
                            para("Command executed (arguments passed as a list, never through a "
                                 "shell):", "small"), Spacer(1, 2 * 2.83),
                            code_box(" ".join(r.command) or "not recorded"), Spacer(1, 3 * 2.83),
                            para("SHA-256 of the original Nmap output:", "small"),
                            Spacer(1, 2 * 2.83), code_box(r.raw_sha256 or "not recorded")]
    story += [Spacer(1, 6 * 2.83), KeepTogether(prov)]
    return story


def build_scan_pdf(result: ScanResult, path: str | os.PathLike[str]) -> ReportInfo:
    def build(tmp: os.PathLike[str]) -> None:
        from pathlib import Path

        build_pdf(Path(tmp), _story(result), kind="Assessment report",
                  short_title=f"Assessment report | {result.target}",
                  title=f"Network Assessment Report {result.target}",
                  subject=f"Nmap {result.profile} scan of {result.target}")

    return write_pdf_atomic(path, build)
