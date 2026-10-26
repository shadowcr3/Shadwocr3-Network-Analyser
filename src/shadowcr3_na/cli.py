"""Command-line front end. Safe by default: no scan runs without an attestation, a
valid in-scope target, a writable audit log, and (for large scans) confirmation."""
from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from shadowcr3_na import __version__
from shadowcr3_na.core import errors as E
from shadowcr3_na.core.environment import check_environment
from shadowcr3_na.core.models import ScanResult
from shadowcr3_na.core.policy import DEFAULT_LIMITS, ScanGuard, assess_impact
from shadowcr3_na.core.profiles import PROFILES
from shadowcr3_na.core.scanner import scan
from shadowcr3_na.core.scope import validate_target
from shadowcr3_na.logging_setup import configure_logging
from shadowcr3_na.paths import default_db_path, log_dir
from shadowcr3_na.reports import write_scan_report
from shadowcr3_na.storage import audit
from shadowcr3_na.storage.db import connect
from shadowcr3_na.storage.repository import (
    delete_scan,
    get_raw_xml,
    get_scan,
    list_scans,
    prune_history,
    save_scan,
)

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_SCOPE = 3
EXIT_NO_NMAP = 4
EXIT_TIMEOUT = 5
EXIT_FAILED = 6
EXIT_CONFIRM = 7
EXIT_RATE_LIMITED = 8
EXIT_STORAGE = 9
EXIT_INTERRUPTED = 130

# First isinstance match wins: subclasses before their base classes.
_EXIT_BY_ERROR: tuple[tuple[type[Exception], int], ...] = (
    (E.InvalidTarget, EXIT_USAGE),
    (E.ScopeViolation, EXIT_SCOPE),
    (E.ConfirmationRequired, EXIT_CONFIRM),
    (E.PolicyError, EXIT_RATE_LIMITED),
    (E.NmapNotFound, EXIT_NO_NMAP),
    (E.UnsupportedNmap, EXIT_NO_NMAP),
    (E.ScanTimeout, EXIT_TIMEOUT),
    (E.StorageError, EXIT_STORAGE),
    (E.Shadowcr3Error, EXIT_FAILED),
)


def exit_code_for(exc: Exception) -> int:
    return next(code for cls, code in _EXIT_BY_ERROR if isinstance(exc, cls))


def render_result(r: ScanResult) -> str:
    header = (
        f"Scan {r.target}  profile={r.profile}  nmap={r.nmap_version or '?'}  "
        f"privileged={'yes' if r.privileged else 'no'}  {r.duration_s:.1f}s  "
        f"started {r.started_at.astimezone():%Y-%m-%d %H:%M:%S}"
    )
    lines = [header]
    if r.complete is False:
        detail = " ".join(r.warnings) or "Nmap did not report a clean finish."
        lines.append(f"WARNING: results may be INCOMPLETE. {detail}")
    elif r.complete is None:
        lines.append("Note: completeness unknown (record predates completeness tracking).")
    if not r.privileged:
        lines.append(
            "Note: not running as Administrator/root: MAC addresses and ARP discovery "
            "may be unavailable and quiet hosts can be missed."
        )
    lines.append("")
    if not r.hosts:
        lines.append(
            "No hosts responded. This does not prove the network is empty: devices can "
            "ignore probes, and scans without privileges see less."
        )
        return "\n".join(lines)
    lines.append(f"{'IP':<16}{'MAC':<19}{'Hostname':<28}Open ports")
    for h in r.hosts:
        ports = ", ".join(f"{p.number}/{p.service or '?'}" for p in h.open_ports) or "-"
        lines.append(f"{h.ip:<16}{h.mac or '-':<19}{h.hostname or '-':<28}{ports}")
    return "\n".join(lines)


def _safe_audit(
    conn: sqlite3.Connection, event: str, job_id: str | None, **details: Any
) -> None:
    try:
        audit.record(conn, event, job_id=job_id, **details)
    except sqlite3.Error:
        log.exception("could not write audit event %s", event)


def _fail(message: str, code: int) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def _cmd_scan(args: argparse.Namespace, conn: sqlite3.Connection, guard: ScanGuard | None) -> int:
    job_id = audit.new_job_id()
    try:
        if not args.i_am_authorised:
            audit.record(conn, "scan_refused", job_id=job_id,
                         category="no_attestation", target=args.target)
            return _fail("refusing to scan: confirm authorisation with --i-am-authorised.",
                         EXIT_USAGE)
        try:
            net = validate_target(args.target)
        except E.TargetError as exc:
            audit.record(conn, "scan_refused", job_id=job_id, category=exc.category,
                         target=args.target, message=str(exc)[:300])
            return _fail(str(exc), exit_code_for(exc))
        impact = assess_impact(net, PROFILES[args.profile], DEFAULT_LIMITS)
        if impact.high and not args.confirm_high_impact:
            audit.record(conn, "scan_refused", job_id=job_id,
                         category="confirmation_required", target=str(net),
                         profile=args.profile, impact=impact.summary())
            return _fail(
                f"high-impact scan: {impact.summary()} Re-run with --confirm-high-impact "
                "to proceed.", EXIT_CONFIRM,
            )
        audit.record(
            conn, "scan_requested", job_id=job_id, target=str(net), profile=args.profile,
            timeout_s=args.timeout, attested=True, high_impact=impact.high,
            estimated_probes=impact.estimated_probes, front_end="cli",
        )
        audit.record(conn, "scan_started", job_id=job_id, target=str(net))
    except sqlite3.Error:
        log.exception("audit log unavailable")
        return _fail("refusing to scan: the audit log is unavailable.", EXIT_STORAGE)

    cancel = threading.Event()
    try:
        result = scan(
            str(net), args.profile, timeout_s=args.timeout, nmap_path=args.nmap_path,
            cancel=cancel, confirmed_high_impact=args.confirm_high_impact, guard=guard,
        )
    except KeyboardInterrupt:
        cancel.set()
        _safe_audit(conn, "scan_cancelled", job_id, reason="keyboard_interrupt")
        print("\nScan cancelled.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (E.Shadowcr3Error, ValueError) as exc:
        category = getattr(exc, "category", "invalid_input")
        if isinstance(exc, E.ScanTimeout):
            event = "scan_timed_out"
        elif isinstance(exc, E.ScanCancelled):
            event = "scan_cancelled"
        else:
            event = "scan_failed"
        _safe_audit(conn, event, job_id, category=category, message=str(exc)[:500])
        log.warning("scan failed: %s", exc, extra={"job_id": job_id, "category": category})
        return _fail(str(exc), exit_code_for(exc) if isinstance(exc, E.Shadowcr3Error)
                     else EXIT_USAGE)

    status = EXIT_OK
    scan_id = None
    if args.save:
        try:
            scan_id = save_scan(conn, result, attested=True)
        except sqlite3.Error as exc:
            log.exception("could not save scan")
            print(f"warning: the scan finished but could not be saved: {exc}", file=sys.stderr)
            status = EXIT_STORAGE
    _safe_audit(
        conn, "scan_completed", job_id, scan_id=scan_id, hosts=len(result.hosts),
        complete=result.complete, duration_s=result.duration_s, saved=scan_id is not None,
    )
    print(render_result(result))
    for flag, suffix in ((args.pdf, ".pdf"), (args.csv, ".csv")):
        if flag:
            status = _export(conn, result, Path(flag), suffix, scan_id, job_id) or status
    return status


def _export(
    conn: sqlite3.Connection, result: ScanResult, path: Path, suffix: str,
    scan_id: int | None, job_id: str | None,
) -> int:
    if suffix not in (".pdf", ".csv") or path.suffix.lower() != suffix:
        return _fail("export path must end in .pdf (report) or .csv (data)", EXIT_USAGE)
    try:
        info = write_scan_report(result, path)
    except (OSError, ValueError) as exc:
        return _fail(f"export failed: {exc}", EXIT_FAILED)
    _safe_audit(conn, "report_exported", job_id, scan_id=scan_id, path=str(info.path),
                sha256=info.sha256, size=info.size)
    print(f"Report written: {info.path}  (sha256 {info.sha256[:16]}...)")
    return EXIT_OK


def _cmd_history(args: argparse.Namespace, conn: sqlite3.Connection, _g: ScanGuard | None) -> int:
    action = args.history_cmd
    if action == "list":
        rows = list_scans(conn, args.limit)
        if not rows:
            print("No saved scans.")
        for s in rows:
            done = {True: "complete", False: "INCOMPLETE", None: "unknown"}[s.complete]
            print(f"{s.id:>5}  {s.started_at.astimezone():%Y-%m-%d %H:%M}  {s.target:<18} "
                  f"{s.profile:<12} {s.host_count:>3} hosts  {done}")
        return EXIT_OK
    if action == "prune":
        if not args.yes:
            return _fail("pruning deletes saved scans; re-run with --yes to confirm.", EXIT_USAGE)
        removed = prune_history(conn, args.keep)
        _safe_audit(conn, "history_pruned", None, keep=args.keep, removed=len(removed))
        print(f"Deleted {len(removed)} scan(s); kept the newest {args.keep}.")
        return EXIT_OK
    result = get_scan(conn, args.id)
    if result is None:
        return _fail(f"no saved scan with id {args.id}.", EXIT_USAGE)
    if action == "show":
        if args.raw:
            raw = get_raw_xml(conn, args.id)
            print(raw if raw is not None else "No raw output stored for this scan.")
        else:
            print(render_result(result))
        return EXIT_OK
    if action == "export":
        path = Path(args.path)
        return _export(conn, result, path, path.suffix.lower(), args.id, None)
    if action == "delete":
        if not args.yes:
            return _fail("deleting a scan is permanent; re-run with --yes to confirm.", EXIT_USAGE)
        delete_scan(conn, args.id)
        _safe_audit(conn, "scan_deleted", None, scan_id=args.id)
        print(f"Deleted scan {args.id}.")
        return EXIT_OK
    return EXIT_USAGE


def _cmd_audit(args: argparse.Namespace, conn: sqlite3.Connection, _g: ScanGuard | None) -> int:
    events = audit.list_events(conn, args.limit)
    if not events:
        print("The audit log is empty.")
    for e in events:
        print(f"{e.ts.astimezone():%Y-%m-%d %H:%M:%S}  {e.event:<16} job={e.job_id or '-':<32} "
              f"scan={e.scan_id or '-'}  {e.details}")
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    env = check_environment(args.nmap_path)
    print(f"Platform:        {env.platform}")
    print(f"Nmap:            {env.nmap_path or 'NOT FOUND'}  (version {env.nmap_version or '?'})")
    print(f"Privileged:      {'yes' if env.privileged else 'no (MAC/ARP discovery limited)'}")
    print(f"History DB:      {args.db or default_db_path()}")
    print(f"Log directory:   {log_dir()}")
    for problem in env.problems:
        print(f"PROBLEM: {problem}")
    return EXIT_OK if env.ready else EXIT_NO_NMAP


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="shadowcr3-na",
        description="Discover and assess hosts on networks you own or are authorised to assess.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--db", help="path to the history database (default: per-user data dir)")
    sub = ap.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="run a scan")
    sc.add_argument("target", help="IPv4 address or CIDR (private/loopback/link-local only)")
    sc.add_argument("-p", "--profile", choices=sorted(PROFILES), default="discovery")
    sc.add_argument("-t", "--timeout", type=int, default=120, help="hard timeout, seconds")
    sc.add_argument("--nmap-path", help="explicit path to the nmap binary")
    sc.add_argument("--i-am-authorised", "--i-am-authorized", action="store_true",
                    help="confirm you own or have permission to scan this target")
    sc.add_argument("--confirm-high-impact", action="store_true",
                    help="acknowledge a large or intrusive scan")
    sc.add_argument("--save", action="store_true", help="save the result to history")
    sc.add_argument("--pdf", metavar="PATH", help="also write a branded PDF report")
    sc.add_argument("--csv", metavar="PATH", help="also write a CSV data export")
    sc.set_defaults(func=_cmd_scan)

    hi = sub.add_parser("history", help="saved scans")
    hsub = hi.add_subparsers(dest="history_cmd", required=True)
    hl = hsub.add_parser("list")
    hl.add_argument("--limit", type=int, default=50)
    hs = hsub.add_parser("show")
    hs.add_argument("id", type=int)
    hs.add_argument("--raw", action="store_true", help="print the original Nmap XML")
    he = hsub.add_parser("export")
    he.add_argument("id", type=int)
    he.add_argument("path")
    hd = hsub.add_parser("delete")
    hd.add_argument("id", type=int)
    hd.add_argument("--yes", action="store_true")
    hp = hsub.add_parser("prune", help="keep only the newest N scans")
    hp.add_argument("--keep", type=int, required=True)
    hp.add_argument("--yes", action="store_true")
    hi.set_defaults(func=_cmd_history)

    au = sub.add_parser("audit", help="show the audit log")
    au.add_argument("--limit", type=int, default=50)
    au.set_defaults(func=_cmd_audit)

    dr = sub.add_parser("doctor", help="verify Nmap, privileges and storage")
    dr.add_argument("--nmap-path")
    return ap


def main(argv: Sequence[str] | None = None, *, guard: ScanGuard | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        configure_logging()
    except OSError:
        pass  # logging must never block a safe operation
    if args.command == "doctor":
        return _cmd_doctor(args)
    try:
        conn = connect(args.db)
    except E.StorageError as exc:
        return _fail(str(exc), EXIT_STORAGE)
    try:
        stale = audit.mark_interrupted(conn)
        if stale:
            print(f"note: {len(stale)} earlier scan(s) were interrupted and not restarted "
                  "(see 'audit').", file=sys.stderr)
        return args.func(args, conn, guard)
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
