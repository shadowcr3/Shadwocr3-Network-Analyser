import pytest

from core.errors import InvalidTarget, ScopeViolation
from core.scope import ScopePolicy, validate_target

@pytest.mark.parametrize("target", [
    "192.168.1.5",
    "192.168.1.0/24",
    "10.0.0.0/24",
    "172.16.5.0/25",
    "127.0.0.1",
    "169.254.1.1",
])
def test_alloed(target):
    validate_target(target)

@pytest.mark.parametrize("target", [
    "",
    "  ",
    "-sS",
    "--script=x",
    "example.com",
    "192.168.1.5/24",
    "192.168.001.1",
    "0x7f.0.0.1",
    "192.168.1.1 192.168.1.2",
    "192.168.1.1, 192.168.1.2",
    "192.168.1.1-20",
    "::1",
    "192.168.1.0/33",
    "192.168.1.1\n-sS",
])
def test_invalid(target):
    with pytest.raises(InvalidTarget):
        validate_target(target)
@pytest.mark.parametrize("target", [
    "8.8.8.8",
    "1.1.1.0/24",
    "0.0.0.0/0",
    "255.255.255.255",
    "224.0.0.1",
    "100.64.0.1",
    "172.168.0.0/23",
    "10.0.0.0/8",
])  
def test_out_of_scope(target):
    with pytest.raises(InvalidTarget):
        validate_target(None)

def test_non_string_input():
    with pytest.raises(InvalidTarget):
        validate_target(None)

def test_custom_policy_limit():
    tiny = ScopePolicy(max_addresses=4)
    validate_target("192.168.1.0/30", tiny)
    with pytest.raises(ScopeViolation):
        validate_target("192.168.1.0/29", tiny)