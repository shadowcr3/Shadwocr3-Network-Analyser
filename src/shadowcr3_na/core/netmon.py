"""Live interface metrics from OS counters (psutil).

These are interface counters, NOT packet captures: they are labelled as such and never
presented as interchangeable with capture-derived measurements.
"""
from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import MetricsUnavailable

SOURCE = "interface counters (psutil)"


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    name: str
    is_up: bool
    speed_mbps: int | None
    mtu: int | None


@dataclass(frozen=True, slots=True)
class Sample:
    ts: datetime
    interface: str
    interval_s: float
    rx_bps: float | None
    tx_bps: float | None
    rx_pps: float | None
    tx_pps: float | None
    source: str = SOURCE
    note: str | None = None


@dataclass(frozen=True, slots=True)
class _Counters:
    bytes_recv: int
    bytes_sent: int
    packets_recv: int
    packets_sent: int


def _default_counters() -> dict[str, Any]:
    try:
        import psutil
    except ImportError:
        raise MetricsUnavailable("The 'psutil' package is not installed.") from None
    try:
        return dict(psutil.net_io_counters(pernic=True))
    except OSError as exc:
        raise MetricsUnavailable(
            f"The operating system refused to report counters: {exc}"
        ) from None


def list_interfaces() -> list[InterfaceInfo]:
    try:
        import psutil

        stats = psutil.net_if_stats()
    except ImportError:
        raise MetricsUnavailable("The 'psutil' package is not installed.") from None
    except OSError as exc:
        raise MetricsUnavailable(f"Could not list interfaces: {exc}") from None
    return [InterfaceInfo(n, s.isup, s.speed or None, s.mtu or None)
            for n, s in sorted(stats.items())]


class InterfaceSampler:
    """Turns successive counter readings into rates, with a bounded history per interface."""

    def __init__(
        self,
        counters_fn: Callable[[], dict[str, Any]] = _default_counters,
        clock: Callable[[], float] = time.monotonic,
        history: int = 600,
    ) -> None:
        self._counters_fn = counters_fn
        self._clock = clock
        self._history_len = history
        self._prev: dict[str, tuple[float, _Counters]] = {}
        self._history: dict[str, deque[Sample]] = {}

    def sample(self, interface: str) -> Sample | None:
        """Return a new Sample, or None without a baseline or for an unknown interface."""
        readings = self._counters_fn()
        raw = readings.get(interface)
        if raw is None:
            return None
        now = self._clock()
        cur = _Counters(raw.bytes_recv, raw.bytes_sent, raw.packets_recv, raw.packets_sent)
        prev = self._prev.get(interface)
        self._prev[interface] = (now, cur)
        if prev is None:
            return None
        dt = now - prev[0]
        if dt <= 0:
            return None
        d = (cur.bytes_recv - prev[1].bytes_recv, cur.bytes_sent - prev[1].bytes_sent,
             cur.packets_recv - prev[1].packets_recv, cur.packets_sent - prev[1].packets_sent)
        ts = datetime.now(timezone.utc)
        if min(d) < 0:  # counter reset or wrap: do not invent a rate
            s = Sample(ts, interface, dt, None, None, None, None, note="counter reset")
        else:
            s = Sample(ts, interface, dt, d[0] * 8 / dt, d[1] * 8 / dt, d[2] / dt, d[3] / dt)
        self._history.setdefault(interface, deque(maxlen=self._history_len)).append(s)
        return s

    def history(self, interface: str) -> list[Sample]:
        return list(self._history.get(interface, ()))

    def clear(self) -> None:
        self._prev.clear()
        self._history.clear()


def format_rate(bits_per_s: float | None, unit: str = "bit/s") -> str:
    if bits_per_s is None:
        return "n/a"
    value = float(bits_per_s)
    for prefix in ("", "K", "M", "G"):
        if abs(value) < 1000 or prefix == "G":
            return f"{value:.1f} {prefix}{unit}" if prefix else f"{value:.0f} {unit}"
        value /= 1000
    return f"{value:.1f} G{unit}"
