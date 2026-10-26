"""Named scan profiles. Users pick a name; they never supply raw Nmap flags."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    args: tuple[str, ...]
    probes_per_host: int  # rough, for impact estimates only


PROFILES: dict[str, Profile] = {
    p.name: p
    for p in (
        Profile("discovery", "Host discovery only, no port scan", ("-sn",), 4),
        Profile("quick-ports", "Top 100 TCP ports", ("-F",), 100),
        Profile(
            "services",
            "Top 100 TCP ports with light service/version detection",
            ("-F", "-sV", "--version-light"),
            120,
        ),
    )
}
