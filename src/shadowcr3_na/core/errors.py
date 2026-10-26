"""Exception hierarchy.

Messages are written to be shown to the user as-is. Every error carries a
`category` so front ends and the audit log can classify failures without
parsing message text.
"""


class Shadowcr3Error(Exception):
    category = "internal"


class TargetError(Shadowcr3Error):
    category = "invalid_input"


class InvalidTarget(TargetError):
    """Not a well-formed single IPv4 address or CIDR."""


class ScopeViolation(TargetError):
    """Well-formed, but outside the allowed scan scope."""

    category = "out_of_scope"


class PolicyError(Shadowcr3Error):
    category = "rate_limited"


class ScanBusy(PolicyError):
    """Another scan is already running in this process."""


class CooldownActive(PolicyError):
    """Too soon after the previous scan."""


class ConfirmationRequired(PolicyError):
    """A high-impact scan was requested without explicit confirmation."""

    category = "confirmation_required"


class NmapNotFound(Shadowcr3Error):
    category = "missing_dependency"


class UnsupportedNmap(Shadowcr3Error):
    category = "unsupported_version"


class ScanTimeout(Shadowcr3Error):
    category = "timeout"


class ScanCancelled(Shadowcr3Error):
    category = "cancelled"


class ScanFailed(Shadowcr3Error):
    category = "tool_failure"


class PrivilegeRequired(ScanFailed):
    category = "permission_denied"


class OutputTooLarge(ScanFailed):
    category = "resource_limit"


class ParseError(Shadowcr3Error):
    category = "malformed_output"


class StorageError(Shadowcr3Error):
    category = "storage"
