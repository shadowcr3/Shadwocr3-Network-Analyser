"""Process control around Nmap: argument lists only, hard timeout, tree kill,
cancellation, bounded output."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from .errors import (
    NmapNotFound,
    OutputTooLarge,
    PrivilegeRequired,
    ScanCancelled,
    ScanFailed,
    ScanTimeout,
)
from .policy import DEFAULT_LIMITS, ScanLimits
from .profiles import Profile
from .textutil import clean_text

MAX_OUTPUT_BYTES = 20 * 1024 * 1024
_PRIVILEGE_HINTS = re.compile(
    r"requires root|administrator|operation not permitted|permission denied|npcap|"
    r"failed to open device|dnet:",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class RunOutput:
    stdout: str
    stderr: str
    returncode: int
    command: tuple[str, ...]


def find_nmap(explicit: str | None = None) -> str:
    path = explicit or shutil.which("nmap")
    if not path or not os.path.isfile(path):
        raise NmapNotFound(
            "Nmap was not found. Install it (https://nmap.org/download) and make sure "
            "it is on PATH. On Windows, Nmap's installer also provides Npcap."
        )
    return path


def nmap_version(nmap_path: str) -> str | None:
    try:
        out = subprocess.run(
            [nmap_path, "--version"],
            capture_output=True, text=True, timeout=10, **_popen_kwargs(),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Nmap version (\S+)", out)
    return m.group(1) if m else None


def is_privileged() -> bool:
    """Best-effort: root / Administrator. Does not detect Linux file capabilities
    (CAP_NET_RAW), so it can under-report."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def build_command(
    nmap_path: str,
    profile: Profile,
    target: ipaddress.IPv4Network,
    host_timeout_s: int,
    limits: ScanLimits = DEFAULT_LIMITS,
) -> list[str]:
    target_arg = str(target.network_address) if target.prefixlen == 32 else str(target)
    return [
        nmap_path,
        *profile.args,
        "--max-rate", str(limits.max_rate_pps),
        "--max-retries", str(limits.max_retries),
        "-oX", "-",
        "--host-timeout", f"{host_timeout_s}s",
        "--",  # nothing after this can be parsed as an option
        target_arg,
    ]


def run_nmap(
    nmap_path: str,
    profile: Profile,
    target: ipaddress.IPv4Network,
    timeout_s: int,
    cancel: threading.Event | None = None,
    limits: ScanLimits = DEFAULT_LIMITS,
) -> RunOutput:
    cmd = build_command(nmap_path, profile, target, max(1, int(timeout_s * 0.8)), limits)
    deadline = time.monotonic() + timeout_s
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        **_popen_kwargs(),
    ) as proc:
        try:
            while True:
                wait = min(0.25, max(0.01, deadline - time.monotonic()))
                try:
                    out, err = proc.communicate(timeout=wait)
                    break
                except subprocess.TimeoutExpired:
                    if cancel is not None and cancel.is_set():
                        _kill_tree(proc)
                        proc.communicate()
                        raise ScanCancelled("Scan cancelled.") from None
                    if time.monotonic() >= deadline:
                        _kill_tree(proc)
                        proc.communicate()
                        raise ScanTimeout(
                            f"Scan exceeded {timeout_s}s and was stopped."
                        ) from None
        except BaseException:
            # Any exit path (including Ctrl+C) must not leave Nmap running.
            if proc.poll() is None:
                _kill_tree(proc)
            raise
    if proc.returncode != 0:
        detail = clean_text(err.strip())
        if _PRIVILEGE_HINTS.search(err):
            raise PrivilegeRequired(
                "Nmap needs additional privileges or Npcap for this scan. Run the app as "
                f"Administrator/root, or choose a profile that works unprivileged. ({detail})"
            )
        raise ScanFailed(f"Nmap exited with code {proc.returncode}: {detail}")
    if len(out) > MAX_OUTPUT_BYTES:
        raise OutputTooLarge("Nmap produced more output than the safety limit allows.")
    return RunOutput(out, err, proc.returncode, tuple(cmd))


def _popen_kwargs() -> dict:
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}  # own process group so we can kill children too


def _kill_tree(proc: subprocess.Popen) -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
