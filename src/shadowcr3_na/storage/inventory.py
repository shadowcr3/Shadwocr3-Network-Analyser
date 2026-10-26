"""Assets, observed connections, alerts and import records.

Every row keeps its provenance (source tags, import id). Ambiguous identity (an IP seen
with a different MAC) is flagged `uncertain` rather than silently merged or overwritten.
"""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import datetime
from typing import Any

from shadowcr3_na.core.models import ScanResult
from shadowcr3_na.core.records import (
    AlertRecord,
    AlertRow,
    AssetRow,
    ConnectionRecord,
    ConnectionRow,
    ImportResult,
    ImportRow,
)
from shadowcr3_na.core.scope import DEFAULT_ALLOWED

ALERT_STATUSES = ("new", "acknowledged", "resolved", "false_positive")
_MAX_SOURCES = 20
_MAX_NOTE = 2000
_V6_LOCAL = ipaddress.ip_network("fc00::/7")


def is_local_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in DEFAULT_ALLOWED)
    return addr.is_loopback or addr.is_link_local or addr in _V6_LOCAL


def _ts(value: datetime) -> str:
    return value.isoformat()


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


# ---- assets ---------------------------------------------------------------


def upsert_asset(
    conn: sqlite3.Connection,
    ip: str,
    *,
    source: str,
    first_seen: datetime,
    last_seen: datetime | None = None,
    mac: str | None = None,
    vendor: str | None = None,
    hostname: str | None = None,
) -> int:
    last_seen = last_seen or first_seen
    row = conn.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
    if row is None:
        cur = conn.execute(
            "INSERT INTO assets (ip, mac, vendor, hostname, first_seen, last_seen, sources)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ip, mac, vendor, hostname, _ts(first_seen), _ts(last_seen), json.dumps([source])),
        )
        assert cur.lastrowid is not None
        return cur.lastrowid
    sources = json.loads(row["sources"])
    if source not in sources and len(sources) < _MAX_SOURCES:
        sources.append(source)
    uncertain, note = bool(row["uncertain"]), row["note"] or ""
    new_mac = row["mac"]
    if mac:
        if row["mac"] and row["mac"].lower() != mac.lower():
            uncertain = True
            note = (
                note + f" MAC differs between sources: {row['mac']} vs {mac} ({source}).").strip()
        elif not row["mac"]:
            new_mac = mac
    conn.execute(
        "UPDATE assets SET mac = ?, vendor = COALESCE(vendor, ?), hostname = COALESCE(hostname, ?),"
        " first_seen = ?, last_seen = ?, sources = ?, uncertain = ?, note = ? WHERE id = ?",
        (new_mac, vendor, hostname, min(_dt(row["first_seen"]), first_seen).isoformat(),
         max(_dt(row["last_seen"]), last_seen).isoformat(), json.dumps(sources),
         int(uncertain), note[:_MAX_NOTE] or None, row["id"]),
    )
    return int(row["id"])


def upsert_assets_from_scan(conn: sqlite3.Connection, scan_id: int, result: ScanResult) -> int:
    count = 0
    with conn:
        for host in result.hosts:
            if host.state != "up":
                continue
            upsert_asset(conn, host.ip, source=f"nmap-scan:{scan_id}",
                         first_seen=result.started_at, mac=host.mac, vendor=host.vendor,
                         hostname=host.hostname)
            count += 1
    return count


def _row_to_asset(r: sqlite3.Row) -> AssetRow:
    return AssetRow(r["id"], r["ip"], r["mac"], r["vendor"], r["hostname"], _dt(r["first_seen"]),
                    _dt(r["last_seen"]), tuple(json.loads(r["sources"])), bool(r["uncertain"]),
                    r["note"])


def list_assets(conn: sqlite3.Connection, limit: int = 5000) -> list[AssetRow]:
    rows = conn.execute("SELECT * FROM assets ORDER BY last_seen DESC, id DESC LIMIT ?", (limit,))
    return [_row_to_asset(r) for r in rows]


def get_asset(conn: sqlite3.Connection, asset_id: int) -> AssetRow | None:
    r = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return _row_to_asset(r) if r else None


# ---- imports ---------------------------------------------------------------


def save_import(conn: sqlite3.Connection, kind: str, path: str, result_sha: str, size: int,
                records: int, rejected: int, truncated: bool) -> int:
    from datetime import timezone

    cur = conn.execute(
        "INSERT INTO imports (kind, path, sha256, size, imported_at, records, rejected, truncated)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (kind, path, result_sha, size, datetime.now(timezone.utc).isoformat(), records,
         rejected, int(truncated)),
    )
    assert cur.lastrowid is not None
    return cur.lastrowid


def _row_to_import(r: sqlite3.Row) -> ImportRow:
    return ImportRow(r["id"], r["kind"], r["path"], r["sha256"], r["size"], _dt(r["imported_at"]),
                     r["records"], r["rejected"], bool(r["truncated"]))


def list_imports(conn: sqlite3.Connection, limit: int = 200) -> list[ImportRow]:
    rows = conn.execute("SELECT * FROM imports ORDER BY id DESC LIMIT ?", (limit,))
    return [_row_to_import(r) for r in rows]


def get_import(conn: sqlite3.Connection, import_id: int) -> ImportRow | None:
    r = conn.execute("SELECT * FROM imports WHERE id = ?", (import_id,)).fetchone()
    return _row_to_import(r) if r else None


def delete_import(conn: sqlite3.Connection, import_id: int) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM imports WHERE id = ?", (import_id,))
    return cur.rowcount > 0


def _upsert_endpoints(conn: sqlite3.Connection, seen: dict[str, tuple[datetime, datetime]],
                      source: str) -> None:
    for ip, (first, last) in seen.items():
        if is_local_address(ip):
            upsert_asset(conn, ip, source=source, first_seen=first, last_seen=last)


def save_connection_import(
    conn: sqlite3.Connection, kind: str, path: str, result: ImportResult
) -> int:
    """Persist an imported capture/log as one import plus its conversations and assets."""
    conns: tuple[ConnectionRecord, ...] = result.records
    with conn:
        import_id = save_import(conn, kind, path, result.sha256, result.size, len(conns),
                                result.rejected, result.truncated)
        conn.executemany(
            "INSERT INTO connections (src, dst, protocol, dst_port, first_seen, last_seen,"
            " packets, bytes, flows, kind, import_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed', ?)",
            [(c.src, c.dst, c.protocol, c.dst_port, _ts(c.first_seen), _ts(c.last_seen),
              c.packets, c.bytes, c.flows, import_id) for c in conns],
        )
        seen: dict[str, tuple[datetime, datetime]] = {}
        for c in conns:
            for ip in (c.src, c.dst):
                old = seen.get(ip)
                seen[ip] = (min(old[0], c.first_seen), max(old[1], c.last_seen)) if old else (
                    c.first_seen, c.last_seen)
        _upsert_endpoints(conn, seen, f"{kind}:{import_id}")
    return import_id


def save_alert_import(conn: sqlite3.Connection, path: str, result: ImportResult) -> int:
    alerts: tuple[AlertRecord, ...] = result.records
    with conn:
        import_id = save_import(conn, result.kind, path, result.sha256, result.size, len(alerts),
                                result.rejected, result.truncated)
        conn.executemany(
            "INSERT INTO alerts (ts, source, signature, signature_id, severity, category, src,"
            " dst, proto, dst_port, raw, import_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(_ts(a.ts), a.source, a.signature, a.signature_id, a.severity, a.category, a.src,
              a.dst, a.proto, a.dst_port, a.raw, import_id) for a in alerts],
        )
        seen: dict[str, tuple[datetime, datetime]] = {}
        for a in alerts:
            for ip in (a.src, a.dst):
                if ip:
                    old = seen.get(ip)
                    seen[ip] = (min(old[0], a.ts), max(old[1], a.ts)) if old else (a.ts, a.ts)
        _upsert_endpoints(conn, seen, f"{result.kind}:{import_id}")
    return import_id


# ---- connections ------------------------------------------------------------


def _row_to_conn(r: sqlite3.Row) -> ConnectionRow:
    return ConnectionRow(r["id"], r["src"], r["dst"], r["protocol"], r["dst_port"],
                         _dt(r["first_seen"]), _dt(r["last_seen"]), r["packets"], r["bytes"],
                         r["flows"], r["kind"], r["import_id"])


def list_connections(conn: sqlite3.Connection, limit: int = 20000) -> list[ConnectionRow]:
    rows = conn.execute("SELECT * FROM connections ORDER BY last_seen DESC, id DESC LIMIT ?",
                        (limit,))
    return [_row_to_conn(r) for r in rows]


def get_connection(conn: sqlite3.Connection, conn_id: int) -> ConnectionRow | None:
    r = conn.execute("SELECT * FROM connections WHERE id = ?", (conn_id,)).fetchone()
    return _row_to_conn(r) if r else None


# ---- alerts -----------------------------------------------------------------


def _row_to_alert(r: sqlite3.Row) -> AlertRow:
    return AlertRow(r["id"], _dt(r["ts"]), r["source"], r["signature"], r["signature_id"],
                    r["severity"], r["category"], r["src"], r["dst"], r["proto"], r["dst_port"],
                    r["status"], r["note"], r["raw"], r["import_id"])


def list_alerts(conn: sqlite3.Connection, status: str | None = None,
                limit: int = 5000) -> list[AlertRow]:
    if status:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY severity ASC, ts DESC LIMIT ?",
            (status, limit))
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY severity ASC, ts DESC LIMIT ?", (limit,))
    return [_row_to_alert(r) for r in rows]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> AlertRow | None:
    r = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_alert(r) if r else None


def update_alert(conn: sqlite3.Connection, alert_id: int, *, status: str | None = None,
                 note: str | None = None) -> bool:
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {ALERT_STATUSES}")
    sets, args = [], []  # type: list[str], list[Any]
    if status is not None:
        sets.append("status = ?")
        args.append(status)
    if note is not None:
        sets.append("note = ?")
        args.append(note[:_MAX_NOTE])
    if not sets:
        return False
    with conn:
        cur = conn.execute(f"UPDATE alerts SET {', '.join(sets)} WHERE id = ?", (*args, alert_id))
    return cur.rowcount > 0


def counts(conn: sqlite3.Connection) -> dict[str, Any]:
    def one(sql: str) -> int:
        return int(conn.execute(sql).fetchone()[0])

    last = conn.execute("SELECT MAX(started_at) FROM scans").fetchone()[0]
    return {
        "assets": one("SELECT COUNT(*) FROM assets"),
        "connections": one("SELECT COUNT(*) FROM connections"),
        "alerts_total": one("SELECT COUNT(*) FROM alerts"),
        "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE status IN ('new','acknowledged')"),
        "scans": one("SELECT COUNT(*) FROM scans"),
        "last_scan": _dt(last) if last else None,
        "imports": one("SELECT COUNT(*) FROM imports"),
    }


def asset_id_for_ip(conn: sqlite3.Connection, ip: str) -> int | None:
    r = conn.execute("SELECT id FROM assets WHERE ip = ?", (ip,)).fetchone()
    return int(r["id"]) if r else None


def connection_ids_between(
    conn: sqlite3.Connection, src: str, dst: str, limit: int = 50
) -> list[int]:
    rows = conn.execute("SELECT id FROM connections WHERE src = ? AND dst = ? ORDER BY id LIMIT ?",
                        (src, dst, limit))
    return [int(r["id"]) for r in rows]


def alerts_for_ip(conn: sqlite3.Connection, ip: str, limit: int = 50) -> list[AlertRow]:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE src = ? OR dst = ? ORDER BY severity ASC, ts DESC LIMIT ?",
        (ip, ip, limit))
    return [_row_to_alert(r) for r in rows]
