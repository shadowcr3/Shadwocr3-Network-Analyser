"""Orchestration: validate -> policy -> locate Nmap -> run -> parse -> ScanResult."""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import datetime, timezone

from .environment import MIN_NMAP, parse_version
from .errors import ConfirmationRequired, UnsupportedNmap
from .models import ScanResult
from .parser import parse_nmap_xml
from .policy import DEFAULT_GUARD, DEFAULT_LIMITS, ScanGuard, ScanLimits, assess_impact
from .profiles import PROFILES
from .runner import clean_text, find_nmap, is_privileged, nmap_version, run_nmap
from .scope import ScopePolicy, validate_target

log = logging.getLogger(__name__)

_WARNING_HINTS = ("warning", "skipping host", "host timeout", "giving up")
_PARTIAL_HINTS = ("host timeout", "skipping host")


def extract_warnings(stderr: str, limit: int = 10) -> tuple[str, ...]:
    found: list[str] = []
    for line in clean_text(stderr, 4000).splitlines():
        if any(h in line.lower() for h in _WARNING_HINTS):
            found.append(line.strip()[:200])
            if len(found) >= limit:
                break
    return tuple(found)


def scan(
    target: str,
    profile: str = "discovery",
    *,
    timeout_s: int = 120,
    policy: ScopePolicy = ScopePolicy(),
    limits: ScanLimits = DEFAULT_LIMITS,
    guard: ScanGuard | None = None,
    nmap_path: str | None = None,
    cancel: threading.Event | None = None,
    confirmed_high_impact: bool = False,
) -> ScanResult:
    if not 1 <= timeout_s <= 3600:
        raise ValueError("timeout_s must be between 1 and 3600")
    net = validate_target(target, policy)  # first, before any OS interaction
    prof = PROFILES[profile]
    impact = assess_impact(net, prof, limits)
    if impact.high and not confirmed_high_impact:
        raise ConfirmationRequired(impact.summary() + " Explicit confirmation is required.")
    with (guard or DEFAULT_GUARD).slot(limits.cooldown_s):
        nmap = find_nmap(nmap_path)
        version = nmap_version(nmap)
        parsed_version = parse_version(version)
        if parsed_version is not None and parsed_version < MIN_NMAP:
            raise UnsupportedNmap(
                f"Nmap {version} is older than the supported minimum "
                f"{MIN_NMAP[0]}.{MIN_NMAP[1]}."
            )
        started = datetime.now(timezone.utc)
        t0 = time.monotonic()
        log.info("scan starting", extra={"event": "scan_starting"})
        run = run_nmap(nmap, prof, net, timeout_s, cancel, limits)
        parsed = parse_nmap_xml(run.stdout)
    warnings = extract_warnings(run.stderr)
    partial = any(h in w.lower() for w in warnings for h in _PARTIAL_HINTS)
    complete = bool(parsed.finished_ok) and not partial
    elapsed = parsed.elapsed_s if parsed.elapsed_s is not None else time.monotonic() - t0
    return ScanResult(
        target=str(net),
        profile=prof.name,
        nmap_version=parsed.nmap_version or version,
        privileged=is_privileged(),
        started_at=started,
        duration_s=elapsed,
        hosts=parsed.hosts,
        command=run.command,
        exit_status=run.returncode,
        complete=complete,
        warnings=warnings,
        raw_sha256=hashlib.sha256(run.stdout.encode("utf-8")).hexdigest(),
        raw_xml=run.stdout,
    )
