"""One background task at a time per page. Workers never touch widgets or the database."""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

from shadowcr3_na.core.errors import ScanCancelled, Shadowcr3Error

log = logging.getLogger(__name__)


class TaskThread(QThread):
    succeeded = Signal(object)
    failed = Signal(str, str)  # category, user-presentable message
    cancelled = Signal()

    def __init__(self, fn: Callable[[threading.Event], Any], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._fn = fn
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            result = self._fn(self._cancel)
        except ScanCancelled:
            self.cancelled.emit()
        except Shadowcr3Error as exc:
            self.failed.emit(exc.category, str(exc))
        except Exception as exc:  # a bug, not an expected failure
            log.exception("background task crashed")
            self.failed.emit("internal", f"Unexpected error: {exc}")
        else:
            self.succeeded.emit(result)


class TaskRunner(QObject):
    busy_changed = Signal(bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: TaskThread | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def start(
        self,
        fn: Callable[[threading.Event], Any],
        on_success: Callable[[Any], None],
        on_failure: Callable[[str, str], None],
        on_cancel: Callable[[], None] | None = None,
    ) -> bool:
        if self._thread is not None:
            return False
        thread = TaskThread(fn, self)
        thread.succeeded.connect(on_success)
        thread.failed.connect(on_failure)
        if on_cancel is not None:
            thread.cancelled.connect(on_cancel)
        thread.finished.connect(self._on_finished)
        self._thread = thread
        thread.start()
        self.busy_changed.emit(True)
        return True

    def cancel(self) -> None:
        if self._thread is not None:
            self._thread.cancel()

    def shutdown(self, wait_ms: int = 10000) -> None:
        if self._thread is not None:
            self._thread.cancel()
            self._thread.wait(wait_ms)

    def _on_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.deleteLater()
        self.busy_changed.emit(False)
