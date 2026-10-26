import os
import threading
import time

import pytest

from shadowcr3_na.core import runner
from shadowcr3_na.core.errors import (
    ConfirmationRequired,
    CooldownActive,
    NmapNotFound,
    OutputTooLarge,
    PrivilegeRequired,
    ScanBusy,
    ScanCancelled,
    ScanFailed,
    ScanTimeout,
    ScopeViolation,
    UnsupportedNmap,
)
from shadowcr3_na.core.policy import ScanLimits
from shadowcr3_na.core.profiles import PROFILES
from shadowcr3_na.core.scanner import scan
from shadowcr3_na.core.scope import validate_target


def test_command_shape_includes_rate_limits_and_separator():
    net = validate_target("192.168.1.0/24")
    cmd = runner.build_command("nmap", PROFILES["services"], net, 10, ScanLimits(300, 1))
    assert cmd[0] == "nmap" and "-sV" in cmd and "-oX" in cmd
    assert cmd[cmd.index("--max-rate") + 1] == "300"
    assert cmd[cmd.index("--max-retries") + 1] == "1"
    assert cmd[-2:] == ["--", "192.168.1.0/24"]
    single = runner.build_command("nmap", PROFILES["discovery"], validate_target("192.168.1.5"), 10)
    assert single[-1] == "192.168.1.5"


def test_nmap_not_found(tmp_path, monkeypatch):
    with pytest.raises(NmapNotFound):
        runner.find_nmap(str(tmp_path / "nope"))
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    with pytest.raises(NmapNotFound):
        runner.find_nmap()


def test_result_carries_provenance(fake_nmap, guard, tmp_path, monkeypatch):
    argsfile = tmp_path / "args.txt"
    monkeypatch.setenv("FAKE_NMAP_ARGS", str(argsfile))
    result = scan("192.168.1.5", "discovery", nmap_path=fake_nmap, guard=guard)
    assert result.profile == "discovery" and result.nmap_version == "7.95"
    assert result.duration_s == 2.31 and result.complete is True and result.exit_status == 0
    assert [h.ip for h in result.hosts] == ["192.168.1.1", "192.168.1.20"]
    assert result.command[-2:] == ("--", "192.168.1.5") and "--max-rate" in result.command
    assert result.raw_xml.startswith("<?xml") and len(result.raw_sha256 or "") == 64
    assert "--max-rate 250 --max-retries 2" in argsfile.read_text()


def test_scope_violation_never_spawns_a_process(fake_nmap, guard, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))
    with pytest.raises(ScopeViolation):
        scan("8.8.8.8", nmap_path=fake_nmap, guard=guard)
    assert not marker.exists()


def test_high_impact_requires_explicit_confirmation(fake_nmap, guard, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))
    with pytest.raises(ConfirmationRequired):
        scan("192.168.1.0/24", nmap_path=fake_nmap, guard=guard)
    assert not marker.exists()
    assert scan("192.168.1.0/24", nmap_path=fake_nmap, guard=guard, confirmed_high_impact=True)


def test_timeout_stops_the_process(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    start = time.monotonic()
    with pytest.raises(ScanTimeout):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard, timeout_s=1)
    assert time.monotonic() - start < 10


def test_cancel_stops_the_scan(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(ScanCancelled):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard, cancel=cancel)
    assert time.monotonic() - start < 10


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX-only")
def test_ctrl_c_style_interrupt_kills_the_child(fake_nmap, guard, tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    monkeypatch.setenv("FAKE_NMAP_PIDFILE", str(pidfile))

    class Interrupt:
        def is_set(self):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard, cancel=Interrupt())  # type: ignore[arg-type]
    pid = int(pidfile.read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_nonzero_exit_surfaces_stderr(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_EXIT", "3")
    with pytest.raises(ScanFailed, match="boom"):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)


def test_privilege_problems_are_classified(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_EXIT", "1")
    monkeypatch.setenv("FAKE_NMAP_STDERR", "dnet: Failed to open device eth0")
    with pytest.raises(PrivilegeRequired) as info:
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)
    assert info.value.category == "permission_denied"


def test_host_timeout_warning_marks_results_incomplete(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_STDERR", "Warning: Skipping host 192.168.1.9 due to host timeout")
    result = scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)
    assert result.complete is False and "host timeout" in result.warnings[0]


def test_unsupported_nmap_version_is_refused(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_VERSION", "7.40")
    with pytest.raises(UnsupportedNmap):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)


def test_oversized_output_is_rejected(fake_nmap, guard, monkeypatch):
    monkeypatch.setattr(runner, "MAX_OUTPUT_BYTES", 100)
    with pytest.raises(OutputTooLarge):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)


def test_second_scan_while_one_runs_is_refused(fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "3")
    errors = []
    cancel = threading.Event()
    t = threading.Thread(
        target=lambda: _quiet(lambda: scan("192.168.1.5", nmap_path=fake_nmap, guard=guard, cancel=cancel))
    )
    t.start()
    time.sleep(1.0)
    try:
        with pytest.raises(ScanBusy):
            scan("192.168.1.6", nmap_path=fake_nmap, guard=guard)
    finally:
        cancel.set()
        t.join(10)
    assert errors == []


def _quiet(fn):
    try:
        fn()
    except ScanCancelled:
        pass


def test_cooldown_applies_between_scans(fake_nmap, guard):
    scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)
    with pytest.raises(CooldownActive):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard)
    scan("192.168.1.5", nmap_path=fake_nmap, guard=guard, limits=ScanLimits(cooldown_s=0))


def test_bad_timeout_value(fake_nmap, guard):
    with pytest.raises(ValueError):
        scan("192.168.1.5", nmap_path=fake_nmap, guard=guard, timeout_s=0)
