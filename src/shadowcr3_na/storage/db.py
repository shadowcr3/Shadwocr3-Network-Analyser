"""SQLite connection and versioned, transactional migrations.

Each entry in MIGRATIONS brings the schema from version i to i+1 inside one
transaction together with the PRAGMA user_version stamp. A failing migration is
rolled back and never leaves a half-migrated database. Existing databases are
backed up (SQLite online backup) before the first pending migration runs.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from shadowcr3_na.core.errors import StorageError
from shadowcr3_na.paths import default_db_path, make_private_dir, restrict_file

_V1 = """
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

_V2 = """
ALTER TABLE scans ADD COLUMN command    TEXT;     -- JSON list; NULL for legacy rows
ALTER TABLE scans ADD COLUMN exit_status INTEGER;
ALTER TABLE scans ADD COLUMN complete   INTEGER;  -- NULL = unknown
ALTER TABLE scans ADD COLUMN warnings   TEXT;     -- JSON list
ALTER TABLE scans ADD COLUMN raw_sha256 TEXT;

CREATE TABLE raw_output (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    sha256  TEXT NOT NULL,
    size    INTEGER NOT NULL,
    data    BLOB NOT NULL
);

CREATE TABLE audit_log (
    id      INTEGER PRIMARY KEY,
    ts_utc  TEXT NOT NULL,
    event   TEXT NOT NULL,
    job_id  TEXT,
    scan_id INTEGER,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_job ON audit_log(job_id);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

MIGRATIONS: tuple[str, ...] = (_V1, _V2)
SCHEMA_VERSION = len(MIGRATIONS)


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = str(path) if path is not None else str(default_db_path())
    on_disk = target != ":memory:"
    if on_disk:
        make_private_dir(Path(target).parent)
    try:
        conn = sqlite3.connect(target)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        if on_disk:
            conn.execute("PRAGMA journal_mode = WAL")
            if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                conn.close()
                raise StorageError(
                    f"The history database {target} failed its integrity check. "
                    "Move it aside (or restore a .bak-v* backup) and restart."
                )
        migrate(conn, target if on_disk else None)
    except sqlite3.Error as exc:
        raise StorageError(f"Could not open the history database: {exc}") from exc
    if on_disk:
        restrict_file(Path(target))
    return conn


def migrate(conn: sqlite3.Connection, backup_base: str | None = None) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise StorageError(
            f"History database is version {version}; this app only understands up to "
            f"{SCHEMA_VERSION}. Update the app."
        )
    if version == SCHEMA_VERSION:
        return
    if version > 0 and backup_base:
        backup = Path(f"{backup_base}.bak-v{version}")
        if not backup.exists():
            dest = sqlite3.connect(str(backup))
            try:
                conn.backup(dest)
            finally:
                dest.close()
            restrict_file(backup)
    for new_version in range(version + 1, SCHEMA_VERSION + 1):
        script = MIGRATIONS[new_version - 1]
        try:
            conn.executescript(
                f"BEGIN;\n{script}\nPRAGMA user_version = {new_version};\nCOMMIT;"
            )
        except sqlite3.Error as exc:
            if conn.in_transaction:
                conn.rollback()
            raise StorageError(
                f"Database migration to version {new_version} failed: {exc}"
            ) from exc
