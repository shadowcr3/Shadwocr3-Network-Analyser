import ipaddress
import threading

import pytest

from shadowcr3_na.core.errors import CooldownActive, ScanBusy
from shadowcr3_na.core.policy import ScanGuard, ScanLimits, assess_impact
from shadowcr3_na.core.profiles import PROFILES


def net(text):
    return ipaddress.IPv4Network(text)


def test_small_scans_are_normal_impact():
    impact = assess_impact(net("192.168.1.5/32"), PROFILES["services"])
    assert not impact.high and impact.addresses == 1
    assert not assess_impact(net("192.168.1.0/26"), PROFILES["discovery"]).high  # 64 addresses


def test_large_scan_is_high_impact():
    impact = assess_impact(net("192.168.1.0/24"), PROFILES["discovery"])
    assert impact.high and "more than 64" in impact.reasons[0]


def test_service_detection_threshold_is_lower():
    assert assess_impact(net("192.168.1.0/27"), PROFILES["services"]).high  # 32 addresses
    assert not assess_impact(net("192.168.1.0/27"), PROFILES["quick-ports"]).high


def test_estimates_use_the_rate_cap():
    impact = assess_impact(net("192.168.1.0/24"), PROFILES["quick-ports"], ScanLimits(max_rate_pps=100))
    assert impact.estimated_probes == 25600 and impact.min_duration_s == 256
    assert "256 address(es)" in impact.summary()


def test_guard_allows_one_scan_at_a_time():
    guard = ScanGuard()
    with guard.slot(0):
        with pytest.raises(ScanBusy), guard.slot(0):
            pass
    with guard.slot(0):  # released afterwards
        pass


def test_guard_enforces_cooldown_with_a_fake_clock():
    now = [100.0]
    guard = ScanGuard(clock=lambda: now[0])
    with guard.slot(5):
        pass
    now[0] = 102.0
    with pytest.raises(CooldownActive, match="3s"), guard.slot(5):
        pass
    now[0] = 106.0
    with guard.slot(5):
        pass


def test_refused_attempts_do_not_extend_the_cooldown():
    now = [0.0]
    guard = ScanGuard(clock=lambda: now[0])
    with guard.slot(5):
        pass
    now[0] = 4.0
    with pytest.raises(CooldownActive), guard.slot(5):
        pass
    now[0] = 5.1  # measured from the end of the real scan, not the refused attempt
    with guard.slot(5):
        pass


def test_guard_is_thread_safe_under_contention():
    guard = ScanGuard()
    entered, results = threading.Event(), []

    def worker():
        try:
            with guard.slot(0):
                entered.set()
                threading.Event().wait(0.3)
        except ScanBusy:
            results.append("busy")

    t = threading.Thread(target=worker)
    t.start()
    entered.wait(2)
    worker()
    t.join()
    assert results == ["busy"]
