import time

from PySide6.QtCore import QCoreApplication


def wait_for(condition, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False
