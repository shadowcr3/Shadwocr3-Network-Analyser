"""Investigations: analyst-curated links to evidence, with notes and an evidence-backed report."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from shadowcr3_na.core.textutil import clean_text

from . import inventory
from .repository import get_scan

KINDS = ("scan", "asset", "alert", "connection")
STATUSES = ("open", "closed")
_MAX_NOTES = 20000
_GONE = "(evidence no longer available)"

DISCLAIMER = (
    "Automated findings (such as IDS alerts) are indicators that require interpretation, not "
    "proof of compromise. Public or imported intelligence is not a live observation of this "
    "network. Absence of a result is not proof of absence."
)


@dataclass(frozen=True, slots=True)
class Investigation:
    id: int
    title: str
    status: str
    created_at: datetime
    updated_at: datetime
    notes: str


@dataclass(frozen=True, slots=True)
class Item:
    id: int
    investigation_id: int
    kind: str
    ref_id: int
    note: str
    added_at: datetime


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _inv(r: sqlite3.Row) -> Investigation:
    return Investigation(r["id"], r["title"], r["status"], datetime.fromisoformat(r["created_at"]),
                         datetime.fromisoformat(r["updated_at"]), r["notes"])


def create_investigation(conn: sqlite3.Connection, title: str) -> int:
    title = clean_text(title.strip(), 200)
    if not title:
        raise ValueError("An investigation needs a title.")
    with conn:
        cur = conn.execute(
            "INSERT INTO investigations (title, created_at, updated_at) VALUES (?, ?, ?)",
            (title, _now(), _now()))
    assert cur.lastrowid is not None
    return cur.lastrowid


def list_investigations(conn: sqlite3.Connection) -> list[Investigation]:
    return [_inv(r) for r in conn.execute("SELECT * FROM investigations ORDER BY updated_at DESC")]


def get_investigation(conn: sqlite3.Connection, inv_id: int) -> Investigation | None:
    r = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    return _inv(r) if r else None


def find_by_title(conn: sqlite3.Connection, title: str) -> int | None:
    r = conn.execute("SELECT id FROM investigations WHERE title = ?", (title.strip(),)).fetchone()
    return int(r["id"]) if r else None


def update_investigation(conn: sqlite3.Connection, inv_id: int, *, status: str | None = None,
                         notes: str | None = None) -> bool:
    if status is not None and status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    sets, args = ["updated_at = ?"], [_now()]  # type: list[str], list[object]
    if status is not None:
        sets.append("status = ?")
        args.append(status)
    if notes is not None:
        sets.append("notes = ?")
        args.append(notes[:_MAX_NOTES])
    with conn:
        cur = conn.execute(f"UPDATE investigations SET {', '.join(sets)} WHERE id = ?",
                           (*args, inv_id))
    return cur.rowcount > 0


def delete_investigation(conn: sqlite3.Connection, inv_id: int) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
    return cur.rowcount > 0


def add_item(conn: sqlite3.Connection, inv_id: int, kind: str, ref_id: int, note: str = "") -> int:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    if get_investigation(conn, inv_id) is None:
        raise ValueError("No such investigation.")
    dup = conn.execute(
        "SELECT id FROM investigation_items WHERE investigation_id = ? AND kind = ? AND ref_id = ?",
        (inv_id, kind, ref_id)).fetchone()
    if dup:
        return int(dup["id"])  # already linked: never duplicate evidence
    with conn:
        cur = conn.execute(
            "INSERT INTO investigation_items (investigation_id, kind, ref_id, note, added_at)"
            " VALUES (?, ?, ?, ?, ?)", (inv_id, kind, ref_id, note[:2000], _now()))
        conn.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (_now(), inv_id))
    assert cur.lastrowid is not None
    return cur.lastrowid


def list_items(conn: sqlite3.Connection, inv_id: int) -> list[Item]:
    rows = conn.execute(
        "SELECT * FROM investigation_items WHERE investigation_id = ? ORDER BY added_at, id",
        (inv_id,))
    return [Item(r["id"], r["investigation_id"], r["kind"], r["ref_id"], r["note"],
                 datetime.fromisoformat(r["added_at"])) for r in rows]


def remove_item(conn: sqlite3.Connection, item_id: int) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM investigation_items WHERE id = ?", (item_id,))
    return cur.rowcount > 0


def item_summary(conn: sqlite3.Connection, item: Item) -> str:
    """One plain-text line describing a linked item (or saying its evidence is gone)."""
    if item.kind == "scan":
        scan = get_scan(conn, item.ref_id)
        return f"Nmap scan {scan.target} ({len(scan.hosts)} hosts)" if scan else _GONE
    if item.kind == "asset":
        a = inventory.get_asset(conn, item.ref_id)
        return f"Asset {a.ip} {a.hostname or ''}".strip() if a else _GONE
    if item.kind == "alert":
        al = inventory.get_alert(conn, item.ref_id)
        return f"Alert: {al.signature} ({al.src or '?'} -> {al.dst or '?'})" if al else _GONE
    c = inventory.get_connection(conn, item.ref_id)
    return f"Conversation {c.src} -> {c.dst} {c.protocol}/{c.dst_port}" if c else _GONE


# ---- report data (rendered to PDF by shadowcr3_na.reports) ---------------------------


@dataclass(frozen=True, slots=True)
class ReportItem:
    kind: str
    ref_id: int
    ts: datetime | None
    lines: tuple[str, ...]
    flags: tuple[str, ...]
    note: str
    available: bool


@dataclass(frozen=True, slots=True)
class ReportData:
    investigation: Investigation
    items: tuple[ReportItem, ...]
    generated_at: datetime


def _t(value: object, limit: int = 400) -> str:
    return clean_text(str(value), limit).replace("\n", " ")


def _describe(conn: sqlite3.Connection, item: Item) -> ReportItem:
    note = _t(item.note, 2000)

    def make(ts: datetime | None, lines: list[str], flags: tuple[str, ...] = ()) -> ReportItem:
        return ReportItem(item.kind, item.ref_id, ts, tuple(lines), flags, note, True)

    gone = ReportItem(item.kind, item.ref_id, None, (), (), note, False)
    if item.kind == "scan":
        scan = get_scan(conn, item.ref_id)
        if scan is None:
            return gone
        done = {True: "complete", False: "INCOMPLETE", None: "unknown"}[scan.complete]
        flags = ("Results may be incomplete.",) if scan.complete is False else ()
        return make(scan.started_at, [
            (f"Nmap scan of {_t(scan.target)}, profile {_t(scan.profile)}, {len(scan.hosts)} "
            f"host(s), completeness: {done}"),
            (f"Tool: nmap {_t(scan.nmap_version or '?')}; privileged: "
            f"{'yes' if scan.privileged else 'no'}"),
            f"Command: {_t(' '.join(scan.command) or 'not recorded', 600)}",
            f"Original output SHA-256: {_t(scan.raw_sha256 or 'not recorded')}"], flags)
    if item.kind == "asset":
        a = inventory.get_asset(conn, item.ref_id)
        if a is None:
            return gone
        flags = (f"Uncertain identity: {_t(a.note or 'sources disagree')}",) if a.uncertain else ()
        return make(a.last_seen, [
            f"Asset {_t(a.ip)}, MAC {_t(a.mac or 'unknown')}, hostname {_t(a.hostname or 'unknown')}",
            (f"First seen {a.first_seen:%Y-%m-%d %H:%M} UTC, last seen {a.last_seen:%Y-%m-%d %H:%M}"
            f" UTC; sources: {_t(', '.join(a.sources))}")], flags)
    if item.kind == "alert":
        al = inventory.get_alert(conn, item.ref_id)
        if al is None:
            return gone
        imp = inventory.get_import(conn, al.import_id) if al.import_id else None
        lines = [f"{_t(al.source)} alert, severity {al.severity} (1 = high): {_t(al.signature)}",
                 (f"{_t(al.src or '?')} to {_t(al.dst or '?')} {_t(al.proto or '')} port "
                 f"{al.dst_port if al.dst_port is not None else '?'}; status: {al.status}")]
        if al.note:
            lines.append(f"Analyst note on the alert: {_t(al.note)}")
        if imp:
            lines.append(f"Source file {_t(imp.path)}; SHA-256 {_t(imp.sha256)}")
        return make(al.ts, lines)
    c = inventory.get_connection(conn, item.ref_id)
    if c is None:
        return gone
    imp = inventory.get_import(conn, c.import_id) if c.import_id else None
    lines = [(f"{c.kind.capitalize()} conversation {_t(c.src)} to {_t(c.dst)} {_t(c.protocol)} port "
             f"{c.dst_port if c.dst_port is not None else '?'}; {c.flows} flow(s), "
             f"{c.packets if c.packets is not None else '?'} packets, "
             f"{c.bytes if c.bytes is not None else '?'} bytes"),
             f"{c.first_seen:%Y-%m-%d %H:%M:%S} to {c.last_seen:%Y-%m-%d %H:%M:%S} UTC"]
    if imp:
        lines.append(f"Source {_t(imp.kind)} file {_t(imp.path)}; SHA-256 {_t(imp.sha256)}")
    return make(c.last_seen, lines)


def collect_report(conn: sqlite3.Connection, inv_id: int) -> ReportData:
    inv = get_investigation(conn, inv_id)
    if inv is None:
        raise ValueError("No such investigation.")
    items = tuple(_describe(conn, i) for i in list_items(conn, inv_id))
    return ReportData(inv, items, datetime.now(timezone.utc))
