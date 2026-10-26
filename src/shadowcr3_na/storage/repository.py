from __future__ import annotations

import hashlib
import json
import sqlite3
import zlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from shadowcr3_na.core.errors import StorageError
from shadowcr3_na.core.models import Host, Port, ScanResult


@dataclass(frozen=True, slots=True)
class ScanSummary:
    id: int
    target: str
    profile: str
    started_at: datetime
    duration_s: float
    host_count: int
    complete: bool | None


def save_scan(conn: sqlite3.Connection, result: ScanResult, *, attested: bool) -> int:
    with conn:  # one transaction: a failure part-way leaves nothing behind
        cur = conn.execute(
            "INSERT INTO scans (target, profile, nmap_version, privileged, attested,"
            " started_at, duration_s, command, exit_status, complete, warnings, raw_sha256)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.target,
                result.profile,
                result.nmap_version,
                int(result.privileged),
                int(attested),
                result.started_at.isoformat(),
                result.duration_s,
                json.dumps(list(result.command)),
                result.exit_status,
                None if result.complete is None else int(result.complete),
                json.dumps(list(result.warnings)),
                result.raw_sha256,
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
        if result.raw_xml:
            raw = result.raw_xml.encode("utf-8")
            conn.execute(
                "INSERT INTO raw_output (scan_id, sha256, size, data) VALUES (?, ?, ?, ?)",
                (scan_id, hashlib.sha256(raw).hexdigest(), len(raw), zlib.compress(raw)),
            )
    return scan_id


def list_scans(conn: sqlite3.Connection, limit: int = 500) -> list[ScanSummary]:
    rows = conn.execute(
        "SELECT s.id, s.target, s.profile, s.started_at, s.duration_s, s.complete,"
        " COUNT(h.id) AS host_count"
        " FROM scans s LEFT JOIN hosts h ON h.scan_id = s.id"
        " GROUP BY s.id ORDER BY s.started_at DESC, s.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        ScanSummary(
            r["id"], r["target"], r["profile"],
            datetime.fromisoformat(r["started_at"]), r["duration_s"], r["host_count"],
            None if r["complete"] is None else bool(r["complete"]),
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
        command=tuple(json.loads(s["command"])) if s["command"] else (),
        exit_status=s["exit_status"],
        complete=None if s["complete"] is None else bool(s["complete"]),
        warnings=tuple(json.loads(s["warnings"])) if s["warnings"] else (),
        raw_sha256=s["raw_sha256"],
    )


def get_raw_xml(conn: sqlite3.Connection, scan_id: int) -> str | None:
    """Return the original tool output, verifying it against the stored hash."""
    row = conn.execute(
        "SELECT sha256, data FROM raw_output WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if row is None:
        return None
    try:
        raw = zlib.decompress(row["data"])
    except zlib.error as exc:
        raise StorageError(f"Stored output for scan {scan_id} is corrupted: {exc}") from None
    if hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise StorageError(f"Stored output for scan {scan_id} failed its integrity check.")
    return raw.decode("utf-8")


def delete_scan(conn: sqlite3.Connection, scan_id: int) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cur.rowcount > 0


def prune_history(conn: sqlite3.Connection, keep_last: int) -> list[int]:
    """Delete everything but the newest `keep_last` scans. Explicit, never automatic."""
    if keep_last < 0:
        raise ValueError("keep_last must be >= 0")
    ids = [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM scans ORDER BY started_at DESC, id DESC LIMIT -1 OFFSET ?",
            (keep_last,),
        )
    ]
    with conn:
        conn.executemany("DELETE FROM scans WHERE id = ?", [(i,) for i in ids])
    return ids
