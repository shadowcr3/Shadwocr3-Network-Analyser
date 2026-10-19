from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from .errors import InvalidTarget, ScopeViolation

DEFAULT_ALLOWED = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/16",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)


@dataclass(frozen=True)
class ScopePolicy:
    allowed_networks: tuple[ipaddress.IPv4Network, ...] = DEFAULT_ALLOWED
    max_addresses: int = 256


def validate_target(raw: str, policy: ScopePolicy = ScopePolicy()) -> ipaddress.IPv4Network:
    if not isinstance(raw, str):
        raise InvalidTarget("Target Must be Text.")
    text = raw.strip()
    if not text:
        raise InvalidTarget("Target is empty.")
    if text.startswith("-"):
        raise InvalidTarget("Target Must not start with '-'.")
    if any(c.isspace() or c == "," for c in text):
        raise InvalidTarget("Provide Exactly one IPv4 Address or CIDR range")
    try:
        net = ipaddress.IPv4Network(text, strict=True)
    except ValueError as exc:
        raise InvalidTarget(
            f"'{text}' is not a valid IPv4 Address or CIDR."
            f"(hostnames and IPv4 are not supported yet): {exc}"
        ) from None
    if net.num_addresses > policy.max_addresses:
        raise ScopeViolation(
            f"{net} has {net.num_addresses} addresses; the limit is {policy.max_addresses}."
        )
    if not any(net.subnet_of(allowed) for allowed in policy.allowed_networks):
        raise ScopeViolation(
            f"{net} is outside the allowed scan scope "
            "(private, loopback and link-local ranges only)."
        )
    return net
