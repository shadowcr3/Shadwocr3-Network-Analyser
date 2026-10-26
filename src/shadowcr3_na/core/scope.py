"""Target validation and scope policy.

Runs before anything touches the OS. The app cannot verify authorisation; it
can refuse by default, bound the blast radius, and record the user's
attestation (the caller's job).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .errors import InvalidTarget, ScopeViolation

DEFAULT_ALLOWED = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
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
    """Return the validated network or raise InvalidTarget / ScopeViolation.

    IPv4 only. No hostnames (DNS could resolve into public space). Host bits
    must be zero: "192.168.1.5/24" is rejected, never silently widened.
    """
    if not isinstance(raw, str):
        raise InvalidTarget("Target must be text.")
    text = raw.strip()
    if not text:
        raise InvalidTarget("Target is empty.")
    if text.startswith("-"):
        raise InvalidTarget("Target must not start with '-'.")
    if any(c.isspace() or c == "," for c in text):
        raise InvalidTarget("Provide exactly one IPv4 address or CIDR range.")
    try:
        net = ipaddress.IPv4Network(text, strict=True)
    except ValueError as exc:
        raise InvalidTarget(
            f"'{text}' is not a valid IPv4 address or CIDR "
            f"(hostnames and IPv6 are not supported yet): {exc}"
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
