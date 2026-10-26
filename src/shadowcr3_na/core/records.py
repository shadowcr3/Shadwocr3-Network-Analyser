"""Plain data records shared by importers, storage, topology and the GUI.

Unknown values stay None; nothing is filled with an invented default.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class AlertRecord:
    ts: datetime
    source: str
    signature: str
    signature_id: int | None
    severity: int  # 1 = high ... 3 = low (Suricata convention)
    category: str | None
    src: str | None
    dst: str | None
    proto: str | None
    dst_port: int | None
    raw: str


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    src: str
    dst: str
    protocol: str
    dst_port: int | None
    first_seen: datetime
    last_seen: datetime
    packets: int | None = None
    bytes: int | None = None
    flows: int = 1


@dataclass(frozen=True, slots=True)
class PacketRecord:
    number: int
    ts: datetime | None
    src: str | None
    dst: str | None
    protocol: str
    length: int | None
    info: str
    dst_port: int | None = None


@dataclass(frozen=True, slots=True)
class ImportResult:
    kind: str
    records: tuple[Any, ...]
    read: int  # valid source records before aggregation
    rejected: int  # malformed records that were skipped
    ignored: int  # well-formed records of an irrelevant type
    truncated: bool  # stopped early because of a safety limit
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class AssetRow:
    id: int
    ip: str
    mac: str | None
    vendor: str | None
    hostname: str | None
    first_seen: datetime
    last_seen: datetime
    sources: tuple[str, ...]
    uncertain: bool
    note: str | None


@dataclass(frozen=True, slots=True)
class ConnectionRow:
    id: int
    src: str
    dst: str
    protocol: str
    dst_port: int | None
    first_seen: datetime
    last_seen: datetime
    packets: int | None
    bytes: int | None
    flows: int
    kind: str  # observed | inferred
    import_id: int | None


@dataclass(frozen=True, slots=True)
class AlertRow:
    id: int
    ts: datetime
    source: str
    signature: str
    signature_id: int | None
    severity: int
    category: str | None
    src: str | None
    dst: str | None
    proto: str | None
    dst_port: int | None
    status: str
    note: str | None
    raw: str
    import_id: int | None


@dataclass(frozen=True, slots=True)
class ImportRow:
    id: int
    kind: str
    path: str
    sha256: str
    size: int
    imported_at: datetime
    records: int
    rejected: int
    truncated: bool
