import logging
import os
import sys
from pathlib import Path

import pytest

from shadowcr3_na.core.policy import ScanGuard

FIXTURES = Path(__file__).parent / "fixtures"

# A stand-in for nmap, driven by environment variables so every failure path
# can be exercised without a network or a real Nmap.
FAKE_NMAP = '''\
import os
import sys
import time
from pathlib import Path

marker = os.environ.get("FAKE_NMAP_MARKER")
if marker:
    Path(marker).touch()
if sys.argv[1:] == ["--version"]:
    print("Nmap version " + os.environ.get("FAKE_NMAP_VERSION", "7.95") + " ( https://nmap.org )")
    sys.exit(0)
args = os.environ.get("FAKE_NMAP_ARGS")
if args:
    Path(args).write_text(" ".join(sys.argv[1:]))
pidfile = os.environ.get("FAKE_NMAP_PIDFILE")
if pidfile:
    Path(pidfile).write_text(str(os.getpid()))
time.sleep(float(os.environ.get("FAKE_NMAP_SLEEP", "0")))
stderr = os.environ.get("FAKE_NMAP_STDERR")
if stderr:
    print(stderr, file=sys.stderr)
code = os.environ.get("FAKE_NMAP_EXIT")
if code:
    if not stderr:
        print("boom", file=sys.stderr)
    sys.exit(int(code))
sys.stdout.write(Path(os.environ["FAKE_NMAP_XML"]).read_text(encoding="utf-8"))
'''


FAKE_TSHARK = '''\
import os
import sys
import time
from pathlib import Path

if sys.argv[1:] == ["--version"]:
    print("TShark (Wireshark) " + os.environ.get("FAKE_TSHARK_VERSION", "4.2.2"))
    sys.exit(0)
pidfile = os.environ.get("FAKE_TSHARK_PIDFILE")
if pidfile:
    Path(pidfile).write_text(str(os.getpid()))
time.sleep(float(os.environ.get("FAKE_TSHARK_SLEEP", "0")))
code = os.environ.get("FAKE_TSHARK_EXIT")
if code:
    print("tshark: boom", file=sys.stderr)
    sys.exit(int(code))
src = os.environ.get("FAKE_TSHARK_OUTPUT")
if src:
    sys.stdout.write(Path(src).read_text(encoding="utf-8"))
'''


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the real per-user data directory."""
    monkeypatch.setenv("SHADOWCR3_NA_HOME", str(tmp_path / "home"))
    yield
    logger = logging.getLogger("shadowcr3_na")
    for handler in list(logger.handlers):
        if getattr(handler, "_shadowcr3", False):
            logger.removeHandler(handler)
            handler.close()


@pytest.fixture
def guard():
    return ScanGuard()  # fresh guard: no cooldown carried over between tests


@pytest.fixture
def fake_nmap(tmp_path, monkeypatch):
    script = tmp_path / "fake_nmap.py"
    script.write_text(FAKE_NMAP, encoding="utf-8")
    if os.name == "nt":
        launcher = tmp_path / "nmap.cmd"
        launcher.write_text(f'@echo off\n"{sys.executable}" "{script}" %*\n')
    else:
        launcher = tmp_path / "nmap"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        launcher.chmod(0o755)
    monkeypatch.setenv("FAKE_NMAP_XML", str(FIXTURES / "discovery.xml"))
    return str(launcher)


@pytest.fixture(scope="session")
def qapp():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import gc

    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app
    # Destroy leftover widgets while the QApplication is still alive; otherwise Python tears
    # them down in arbitrary order at interpreter exit and Qt can crash.
    for widget in app.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    app.processEvents()
    gc.collect()


@pytest.fixture
def fake_tshark(tmp_path):
    script = tmp_path / "fake_tshark.py"
    script.write_text(FAKE_TSHARK, encoding="utf-8")
    if os.name == "nt":
        launcher = tmp_path / "tshark.cmd"
        launcher.write_text(f'@echo off\n"{sys.executable}" "{script}" %*\n')
    else:
        launcher = tmp_path / "tshark"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        launcher.chmod(0o755)
    return str(launcher)
