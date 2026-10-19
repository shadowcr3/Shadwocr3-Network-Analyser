import time

import pytest

from cli import main
from core import runner
from core.errors import NmapNotFound, ScanFailed, ScanTimeout, ScopeViolation
from core.profiles import PROFILES
from core.scanner import scan
from core.scope import validate_target

def test_command_shape():
    net = validate_target("192.168.1.0/24")
    cmd = runner.build_command("nmap", PROFILES["services"], net, 10)
    assert cmd[0] == "nmap"
    assert "-sV" in cmd and "-oX" in cmd
    assert cmd[-2:] == ["--", "192.168.1.0/24"]
    single = runner.build_command("nmap", PROFILES["discovery"], validate_target("192.168.1.5"), 10)
    assert single[-1] == "192.168.1.5"

def test_nmap_not_found_explicit(tmp_path):
    with pytest.raises(NmapNotFound):
        runner.find_nmap(str(tmp_path / "nope"))

def test_nmap_not_found_on_path(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    with pytest.raises(NmapNotFound):
        runner.find_nmap()

def test_end_to_end(fake_nmap):
    result = scan("192.168.1.0/24", nmap_path=fake_nmap)
    assert result.profile == "discovery"
    assert result.nmap_version == "7.95"
    assert result.duration_s == 2.31
    assert [h.ip for h in result.hosts] == ["192.168.1.1", "192.168.1.20"]

def test_scope_violation_never_spawns_a_process(fake_nmap, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))
    with pytest.raises(ScopeViolation):
        scan("8.8.8.8", nmap_path=fake_nmap)
    assert not marker.exists()

def test_timeout_stops_the_process(fake_nmap, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    start = time.monotonic()
    with pytest.raises(ScanTimeout):
        scan("192.168.1.5", nmap_path=fake_nmap, timeout_s=1)
    assert time.monotonic() - start < 10

def test_nonzero_exit(fake_nmap, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_EXIT", "3")
    with pytest.raises(ScanFailed, match="boom"):
        scan("192.168.1.5", nmap_path=fake_nmap)

def test_bad_timeout_value(fake_nmap):
    with pytest.raises(ValueError):
        scan("192.168.1.5", nmap_path=fake_nmap, timeout_s=0)

def test_cli_requires_attention():
    assert main(["192.168.1.5"]) == 2

def test_cli_exit_codes_and_output(fake_nmap, capsys):
    base = ["--i-am-authorised", "--nmap-path", fake_nmap]
    assert main(["8.8.8.8", *base]) == 3
    assert main(["192.168.1.0/24", *base]) == 0
    out = capsys.readouterr().out
    assert "router.lan" in out
    assert "192.168.1.20" in out