from __future__ import annotations

import logging
import threading

from PySide6.QtCore import QObject, QThread, Signal

from core.errors import ScanCancelled, Shadowcr3Error
from core.scanner import scan

log = logging.getLogger(__name__)


class ScanThread(QThread):
    succeeded = Signal(object)  # ScanResult
    failed = Signal(str)  # user-presentable message
    cancelled = Signal()

    def __init__(
        self,
        target: str,
        profile: str,
        timeout_s: int,
        nmap_path: str | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._target = target
        self._profile = profile
        self._timeout_s = timeout_s
        self._nmap_path = nmap_path
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            result = scan(
                self._target,
                self._profile,
                timeout_s=self._timeout_s,
                nmap_path=self._nmap_path,
                cancel=self._cancel,
            )
        except ScanCancelled:
            self.cancelled.emit()
        except Shadowcr3Error as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # a bug, not an expected failure
            log.exception("scan thread crashed")
            self.failed.emit(f"Unexpected error: {exc}")
        else:
            self.succeeded.emit(result)