from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from core.errors import StorageError

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE scans (
    id           INTEGER PRIMARY KEY,
    target       TEXT NOT NULL,
    profile      TEXT NOT NULL,
    nmap_version TEXT,
    privileged   INTEGER NOT NULL,
    attested     INTEGER NOT NULL,
    started_at   TEXT NOT NULL,
    duration_s   REAL NOT NULL
);
CREATE TABLE hosts (
    id       INTEGER PRIMARY KEY,
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip       TEXT NOT NULL,
    state    TEXT NOT NULL,
    mac      TEXT,
    vendor   TEXT,
    hostname TEXT
);
CREATE TABLE ports (
    id       INTEGER PRIMARY KEY,
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    number   INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state    TEXT NOT NULL,
    service  TEXT,
    product  TEXT,
    version  TEXT
);
CREATE INDEX idx_hosts_scan ON hosts(scan_id);
CREATE INDEX idx_ports_host ON ports(host_id);
"""


def default_db_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "shadowcr3-na" / "history.sqlite3"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = str(path) if path is not None else str(default_db_path())
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise StorageError(
            f"History database is version {version}; this app only understands "
            f"up to {SCHEMA_VERSION}. Update the app."
        )
    if version == 0:
        # One script, one transaction: the schema and the version stamp
        # land together or not at all.
        conn.executescript(
            f"BEGIN;\n{SCHEMA}\nPRAGMA user_version = {SCHEMA_VERSION};\nCOMMIT;"
        )
