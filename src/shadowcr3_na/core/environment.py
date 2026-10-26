"""Dependency and privilege verification (used by `doctor` and the GUI banner)."""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass

from .errors import NmapNotFound
from .runner import find_nmap, is_privileged, nmap_version

MIN_NMAP = (7, 80)


def parse_version(text: str | None) -> tuple[int, int] | None:
    m = re.match(r"(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


@dataclass(frozen=True)
class Environment:
    nmap_path: str | None
    nmap_version: str | None
    nmap_supported: bool
    privileged: bool
    platform: str
    problems: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return self.nmap_path is not None and self.nmap_supported


def check_environment(nmap_path: str | None = None) -> Environment:
    problems: list[str] = []
    path: str | None = None
    version: str | None = None
    supported = False
    try:
        path = find_nmap(nmap_path)
    except NmapNotFound as exc:
        problems.append(str(exc))
    if path:
        version = nmap_version(path)
        parsed = parse_version(version)
        if parsed is None:
            supported = True  # unknown is allowed, but visible
            problems.append("Could not determine the Nmap version.")
        elif parsed < MIN_NMAP:
            problems.append(
                f"Nmap {version} is older than the supported minimum "
                f"{MIN_NMAP[0]}.{MIN_NMAP[1]}."
            )
        else:
            supported = True
    return Environment(path, version, supported, is_privileged(), sys.platform, tuple(problems))
