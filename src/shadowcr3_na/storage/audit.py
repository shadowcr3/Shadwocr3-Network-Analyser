"""Append-only audit trail (enforced by triggers against accidental modification).

A local audit log cannot be tamper-proof against a sufficiently privileged local
user who edits the database file directly; it records what the application did.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

TERMINAL_EVENTS = (
    "scan_completed",
    "scan_failed",
    "scan_cancelled",
    "scan_timed_out",
    "scan_interrupted",
)
_MAX_DETAILS = 4000


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: int
    ts: datetime
    event: str
    job_id: str | None
    scan_id: int | None
    details: dict[str, Any]


def new_job_id() -> str:
    return uuid.uuid4().hex


def record(
    conn: sqlite3.Connection,
    event: str,
    *,
    job_id: str | None = None,
    scan_id: int | None = None,
    **details: Any,
) -> int:
    payload = json.dumps(details, default=str, sort_keys=True)
    if len(payload) > _MAX_DETAILS:
        payload = json.dumps({"truncated": True, "preview": payload[: _MAX_DETAILS - 100]})
    with conn:
        cur = conn.execute(
            "INSERT INTO audit_log (ts_utc, event, job_id, scan_id, details)"
            " VALUES (?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), event, job_id, scan_id, payload),
        )
    assert cur.lastrowid is not None
    return cur.lastrowid


def list_events(conn: sqlite3.Connection, limit: int = 200) -> list[AuditEvent]:
    rows = conn.execute(
        "SELECT id, ts_utc, event, job_id, scan_id, details FROM audit_log"
        " ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    events = []
    for r in rows:
        try:
            details = json.loads(r["details"])
        except ValueError:
            details = {"unreadable": True}
        events.append(
            AuditEvent(
                r["id"], datetime.fromisoformat(r["ts_utc"]), r["event"],
                r["job_id"], r["scan_id"], details,
            )
        )
    return events


def interrupted_jobs(conn: sqlite3.Connection, older_than_s: float = 3900) -> list[str]:
    """Jobs that started, never finished, and are old enough to be certainly dead.

    The default exceeds the longest allowed scan (3600 s) plus a margin, so a scan
    that is still legitimately running in another process is never misreported.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=older_than_s)).isoformat()
    placeholders = ",".join("?" for _ in TERMINAL_EVENTS)
    rows = conn.execute(
        "SELECT DISTINCT job_id FROM audit_log WHERE event = 'scan_started'"
        " AND job_id IS NOT NULL AND ts_utc < ? AND job_id NOT IN"
        f" (SELECT job_id FROM audit_log WHERE job_id IS NOT NULL AND event IN ({placeholders}))",
        (cutoff, *TERMINAL_EVENTS),
    ).fetchall()
    return [r["job_id"] for r in rows]


def mark_interrupted(conn: sqlite3.Connection, older_than_s: float = 3900) -> list[str]:
    """Record jobs that started but never finished (crash, power loss, kill).

    Interrupted scans are never restarted automatically.
    """
    jobs = interrupted_jobs(conn, older_than_s)
    for job_id in jobs:
        record(
            conn, "scan_interrupted", job_id=job_id,
            note="The application ended before this scan finished. It was not restarted.",
        )
    return jobs
