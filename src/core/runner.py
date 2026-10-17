from __future__ import annotations

import ipaddress
import os
import re 
import shutil
import signal
import subprocess

from .errors import NmapNotFound, ScanFailed, ScanTimeout
from .profiles import Profile

def find_nmap(explicit: str | None=None) -> str:
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
            [nmap_path, "--version"],\
            capture_output=True, text=True, timeout=10, **_popen_kwargs(),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Nmap Version(\S*)", out)
    return m.group(1) if m else None

def is_privileged() -> bool:
    """Best-effort: root / Administrator. Does not detec Linux file capabilities
    (CAP_NET_RAW), so it can under-report."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception :
            return False
    return os.geteuid() == 0

def build_command(
        nmap_path: str, profile: Profile, target: ipaddress.IPv4Network, host_timeout_s: int
) -> list[str]:
    target_arg = str(target.network_address) if target.prefixlen == 32 else str (target)
    return [
        nmap_path,
        *profile.args,
        "-oX", "-",
        "--host-timeout", f"{host_timeout_s}s",
        "--",
        target_arg,
    ] 
def run_nmap(
        nmap_path: str, profile: Profile, target: ipaddress.IPv4Network, timeout_s: int
) -> str:
    cmd = build_command(nmap_path, profile, target, max(1, int(timeout_s * 0.8)))
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        **_popen_kwargs(),
    ) as proc:
        try:
            out, err = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.communicate()
            raise ScanTimeout(f"Scan exceeded {timeout_s}s and was stopped.") from None
        if proc.returncode != 0:
            raise  ScanFailed(f"Nmap exited with code {proc.returncode}: {err.strip()[:500]}")
        return out

def _popen_kwargs() -> dict:
    if os.name == "nt":
            return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}

def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass