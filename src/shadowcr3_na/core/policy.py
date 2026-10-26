"""Resource governance: limits, impact assessment and the one-scan-at-a-time guard."""
from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .errors import CooldownActive, ScanBusy
from .profiles import Profile


@dataclass(frozen=True)
class ScanLimits:
    max_rate_pps: int = 250  # passed to Nmap as --max-rate
    max_retries: int = 2  # passed to Nmap as --max-retries (bounded retransmission)
    cooldown_s: float = 2.0  # minimum gap between scans
    high_impact_addresses: int = 64
    high_impact_service_addresses: int = 16


DEFAULT_LIMITS = ScanLimits()


@dataclass(frozen=True)
class Impact:
    addresses: int
    profile: str
    estimated_probes: int
    min_duration_s: int
    max_rate_pps: int
    high: bool
    reasons: tuple[str, ...]

    def summary(self) -> str:
        text = (
            f"{self.addresses} address(es), profile '{self.profile}', roughly "
            f"{self.estimated_probes} probes, at least ~{self.min_duration_s}s at the "
            f"{self.max_rate_pps} packets/s cap."
        )
        if self.reasons:
            text += " High impact: " + "; ".join(self.reasons) + "."
        return text


def assess_impact(
    net: ipaddress.IPv4Network, profile: Profile, limits: ScanLimits = DEFAULT_LIMITS
) -> Impact:
    addresses = net.num_addresses
    probes = addresses * profile.probes_per_host
    reasons = []
    if addresses > limits.high_impact_addresses:
        reasons.append(f"more than {limits.high_impact_addresses} addresses")
    if profile.name == "services" and addresses > limits.high_impact_service_addresses:
        reasons.append(
            f"service detection probes every open port on more than "
            f"{limits.high_impact_service_addresses} addresses"
        )
    return Impact(
        addresses=addresses,
        profile=profile.name,
        estimated_probes=probes,
        min_duration_s=math.ceil(probes / limits.max_rate_pps),
        max_rate_pps=limits.max_rate_pps,
        high=bool(reasons),
        reasons=tuple(reasons),
    )


class ScanGuard:
    """At most one active scan per process, with a cooldown after each scan.

    Not a cross-process lock: two separate processes (for example the CLI and
    the GUI) are not coordinated. Documented limitation.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_end: float | None = None

    @contextmanager
    def slot(self, cooldown_s: float) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise ScanBusy("Another scan is already running. Wait for it to finish or cancel it.")
        ran = False
        try:
            if self._last_end is not None:
                remaining = cooldown_s - (self._clock() - self._last_end)
                if remaining > 0:
                    raise CooldownActive(
                        f"Please wait {math.ceil(remaining)}s before starting another scan."
                    )
            ran = True
            yield
        finally:
            if ran:
                self._last_end = self._clock()
            self._lock.release()


DEFAULT_GUARD = ScanGuard()
