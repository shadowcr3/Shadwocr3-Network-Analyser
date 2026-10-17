from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True, slots=True)
class Port:
    number: int
    protocol: str
    state: str
    service: str | None=None
    product: str | None=None
    version: str | None=None

@dataclass(frozen=True, slots=True)
class Host:
    ip: str
    state: str
    mac: str | None=None
    vendor: str | None=None
    hostname: str | None=None
    ports: tuple[Port, ...] = ()

    @property
    def open_ports(self) -> tuple[Port, ...]:
        return tuple(p for p in self.ports if p.state == "open")

@dataclass(frozen=True, slots=True)
class ScanResult:
    target: str
    profile: str
    nmap_version: str | None
    privileged: bool
    started_at: datetime
    duration_s: float
    hosts: tuple[Host, ...]
