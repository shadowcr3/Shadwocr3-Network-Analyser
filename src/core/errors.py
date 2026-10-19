class Shadowcr3Error(Exception):
    """Base class. Messages are written to be shown to the user as-is."""


class TargetError(Shadowcr3Error):
    pass


class InvalidTarget(TargetError):
    """not a well-formed single IPv4 address or CIDR."""


class ScopeViolation(TargetError):
    """Well-Formed, but outside the allowed scan scope."""


class NmapNotFound(Shadowcr3Error):
    pass


class ScanTimeout(Shadowcr3Error):
    pass


class ScanFailed(Shadowcr3Error):
    pass


class ParseError(Shadowcr3Error):
    pass


class ScanCancelled(Shadowcr3Error):
    pass
