from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QObject, QThread, Signal

from shadowcr3_na.core.errors import ScanCancelled, Shadowcr3Error
from shadowcr3_na.core.policy import DEFAULT_LIMITS, ScanGuard, ScanLimits
from shadowcr3_na.core.scanner import scan

log = logging.getLogger(__name__)


class ScanThread(QThread):
    """Runs one scan off the UI thread.

    The thread only runs Nmap. It never touches widgets or the SQLite connection:
    results travel back as queued signals and the window does the saving.
    """

    succeeded = Signal(object)  # ScanResult
    failed = Signal(str, str)  # error category, user-presentable message
    cancelled = Signal()

    def __init__(
        self,
        target: str,
        profile: str,
        timeout_s: int,
        *,
        nmap_path: str | None = None,
        guard: ScanGuard | None = None,
        limits: ScanLimits = DEFAULT_LIMITS,
        confirmed_high_impact: bool = False,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._target = target
        self._profile = profile
        self._timeout_s = timeout_s
        self._nmap_path = nmap_path
        self._guard = guard
        self._limits = limits
        self._confirmed = confirmed_high_impact
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            result = scan(
                self._target,
                self._profile,
                timeout_s=self._timeout_s,
                limits=self._limits,
                guard=self._guard,
                nmap_path=self._nmap_path,
                cancel=self._cancel,
                confirmed_high_impact=self._confirmed,
            )
        except ScanCancelled:
            self.cancelled.emit()
        except Shadowcr3Error as exc:
            self.failed.emit(exc.category, str(exc))
        except Exception as exc:  # a bug, not an expected failure
            log.exception("scan thread crashed")
            self.failed.emit("internal", f"Unexpected error: {exc}")
        else:
            self.succeeded.emit(result)
