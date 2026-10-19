from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from core.models import Host, Port, ScanResult


@dataclass(frozen=True, slots=True)
class ScanSummary:
    id: int
    target: str
    profile: str
    started_at: datetime
    duration_s: float
    host_count: int


def save_scan(conn: sqlite3.Connection, result: ScanResult, *, attested: bool) -> int:
    with conn:  # one transaction: a failure part-way leaves nothing behind
        cur = conn.execute(
            "INSERT INTO scans (target, profile, nmap_version, privileged, attested,"
            " started_at, duration_s) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                result.target,
                result.profile,
                result.nmap_version,
                int(result.privileged),
                int(attested),
                result.started_at.isoformat(),
                result.duration_s,
            ),
        )
        scan_id = cur.lastrowid
        assert scan_id is not None
        for h in result.hosts:
            hcur = conn.execute(
                "INSERT INTO hosts (scan_id, ip, state, mac, vendor, hostname)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, h.ip, h.state, h.mac, h.vendor, h.hostname),
            )
            conn.executemany(
                "INSERT INTO ports (host_id, number, protocol, state, service,"
                " product, version) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (hcur.lastrowid, p.number, p.protocol, p.state,
                     p.service, p.product, p.version)
                    for p in h.ports
                ],
            )
    return scan_id


def list_scans(conn: sqlite3.Connection, limit: int = 100) -> list[ScanSummary]:
    rows = conn.execute(
        "SELECT s.id, s.target, s.profile, s.started_at, s.duration_s,"
        " COUNT(h.id) AS host_count"
        " FROM scans s LEFT JOIN hosts h ON h.scan_id = s.id"
        " GROUP BY s.id ORDER BY s.started_at DESC, s.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        ScanSummary(
            r["id"], r["target"], r["profile"],
            datetime.fromisoformat(r["started_at"]), r["duration_s"], r["host_count"],
        )
        for r in rows
    ]


def get_scan(conn: sqlite3.Connection, scan_id: int) -> ScanResult | None:
    s = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if s is None:
        return None
    host_rows = conn.execute(
        "SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)
    ).fetchall()
    ports_by_host: dict[int, list[Port]] = defaultdict(list)
    for p in conn.execute(
        "SELECT p.* FROM ports p JOIN hosts h ON h.id = p.host_id"
        " WHERE h.scan_id = ? ORDER BY p.id",
        (scan_id,),
    ):
        ports_by_host[p["host_id"]].append(
            Port(p["number"], p["protocol"], p["state"],
                 p["service"], p["product"], p["version"])
        )
    hosts = tuple(
        Host(h["ip"], h["state"], h["mac"], h["vendor"], h["hostname"],
             tuple(ports_by_host[h["id"]]))
        for h in host_rows
    )
    return ScanResult(
        target=s["target"],
        profile=s["profile"],
        nmap_version=s["nmap_version"],
        privileged=bool(s["privileged"]),
        started_at=datetime.fromisoformat(s["started_at"]),
        duration_s=s["duration_s"],
        hosts=hosts,
    )


def delete_scan(conn: sqlite3.Connection, scan_id: int) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cur.rowcount > 0
