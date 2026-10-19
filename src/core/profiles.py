from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    args: tuple[str, ...]


PROFILES: dict[str, Profile] = {
    p.name: p
    for p in (
        Profile("discovery", "Gost discovery only, no port scan", ("-sn",)),
        Profile("quick-ports", "Top 100 TCP ports", ("-F",)),
        Profile(
            "services",
            "Top 100 TCP ports with light service/version detection",
            ("-F", "-sV", "--version-light"),
        ),
    )
}
