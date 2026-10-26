from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class Port:
    number: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class Host:
    ip: str
    state: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    ports: tuple[Port, ...] = ()

    @property
    def open_ports(self) -> tuple[Port, ...]:
        return tuple(p for p in self.ports if p.state == "open")


@dataclass(frozen=True, slots=True)
class ScanResult:
    """One scan, with the provenance needed to trace it back to the tool run.

    `complete` is tri-state: True/False when known, None for records that
    predate completeness tracking. Unknown stays unknown.
    """

    target: str
    profile: str
    nmap_version: str | None
    privileged: bool
    started_at: datetime
    duration_s: float
    hosts: tuple[Host, ...]
    command: tuple[str, ...] = ()
    exit_status: int | None = None
    complete: bool | None = None
    warnings: tuple[str, ...] = ()
    raw_sha256: str | None = None
    raw_xml: str = field(default="", repr=False, compare=False)
