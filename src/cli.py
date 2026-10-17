from __future__ import annotations

import argparse
import sys

from core import errors as E
from core.models import ScanResult
from core.profiles import PROFILES
from core.scanner import scan

EXIT_CODES = (
    (E.InvalidTarget, 2),
    (E.ScopeViolation, 3),
    (E.NmapNotFound, 4),
    (E.ScanTimeout, 5),
    (E.Shadowcr3Error, 6),
)

def render(r: ScanResult) -> str:
    lines = [
      (
          f"Scan {r.target}  profile={r.profile}  nmap={r.nmap_version or '?'}  "
          f"privileged={'yes' if r.privileged else 'no'}  {r.duration_s:.1f}s"
      ),
    ]
    if not r.privileged:
        lines.append(
            "Note: unprivileged scan - MAC addresses and ARP discovery may be unavailable."
        )
    lines.append("")
    if not r.hosts:
        lines.append("No hosts responded. (That is a valid result, not an error.)")
        return "\n".join(lines)
    lines.append(f"{'IP':<16}{'MAC':<19}{'Hostname':<28}Open ports")
    for h in r.hosts:
        ports = ",".join(f"{p.number}/{p.service or '?'}" for p in h.open_ports) or "-"
        lines.append(f"{h.ip:<16}{h.mac or '-':<19}{h.hostname or '-':<28}{ports}")
        return "\n".join(lines)

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="Shadowcr3-net",
        description="Scan networks you own or are authorised to assess.",
    )
    ap.add_argument("target", help="IPv4 address or CIDR (private/loopback/link-local only)")
    ap.add_argument("-p", "--profile", choices=sorted(PROFILES), default="discovery")
    ap.add_argument("-t", "--timeout", type=int, default=120, help="hard timeout in seconds (1-3600)")
    ap.add_argument("--nmap-path", help="explicit path to the nmap binary")
    ap.add_argument(
        "--i-am-authorised", "-i-am-authorized",
        action="store_true",
        help="confirm you own or have permission to scan this target",
    )
    args = ap.parse_args(argv)

    if not args.i_am_authorised:
        print("Refusing to scan: confirm authorisation with --i-am-authorised.", file=sys.stderr)
        return 2
    try:
        result = scan(args.target, args.profile, timeout_s=args.timeout, nmap_path=args.nmap_path)
    except E.Shadowcr3Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return next(code for cls, code in EXIT_CODES if isinstance(exc, cls))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(result))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())