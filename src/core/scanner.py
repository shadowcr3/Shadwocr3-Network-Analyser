from __future__ import annotations

import time
from datetime import datetime, timezone

from .models import ScanResult
from .parser import parse_nmap_xml
from .profiles import PROFILES
from .runner import find_nmap, is_privileged, nmap_version, run_nmap
from .scope import ScopePolicy, validate_target


def scan(
    target: str,
    profile: str = "discovery",
    *,
    timeout_s: int = 120,
    policy: ScopePolicy = ScopePolicy(),
    nmap_path: str | None = None,
) -> ScanResult:
    if not 1 <= timeout_s <= 3600:
        raise ValueError("timeout_s must be between 1 and 3600")
    net = validate_target(target, policy)  # first, before any OS interaction
    prof = PROFILES[profile]
    nmap = find_nmap(nmap_path)
    version = nmap_version(nmap)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    xml = run_nmap(nmap, prof, net, timeout_s)
    parsed = parse_nmap_xml(xml)
    return ScanResult(
        target=str(net),
        profile=prof.name,
        nmap_version=parsed.nmap_version or version,
        privileged=is_privileged(),
        started_at=started,
        duration_s=parsed.elapsed_s if parsed.elapsed_s is not None else time.monotonic() - t0,
        hosts=parsed.hosts,
    )
