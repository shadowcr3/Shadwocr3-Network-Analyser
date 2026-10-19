import os  
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

FAKE_NMAP = '''\
import os
import sys
import time
from pathlib import Path

marker = os.environ.get("FAKE_NMAP_MARKER")
if marker:
    Path(marker).touch()
if sys.argv[1:] == ["--version"]:
    print("Nmap version 7.95 ( https://nmap.org )")
    sys.exit(0)
time.sleep(float(os.environ.get("FAKE_NMAP_SLEEP", "0")))
code = os.environ.get("FAKE_NMAP_EXIT")
if code:
    print("boom", file=sys.stderr)
    sys.exit(int(code))
sys.stdout.write(Path(os.environ["FAKE_NMAP_XML"]).read_text(encoding="utf-8"))
'''

@pytest.fixture
def fake_nmap(tmp_path, monkeypatch):
    script = tmp_path/ "fake_nmap.py"
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
