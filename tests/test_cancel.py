import threading
import time

import pytest

from core.errors import ScanCancelled
from core.scanner import scan


def test_cancel_stops_the_scan(fake_nmap, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(ScanCancelled):
        scan("192.168.1.5", nmap_path=fake_nmap, cancel=cancel)
    assert time.monotonic() - start < 10
