from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR_NAME = "shadowcr3-na"


def data_root() -> Path:
    override = os.environ.get("SHADOWCR3_NA_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / APP_DIR_NAME


def default_db_path() -> Path:
    return data_root() / "history.sqlite3"


def log_dir() -> Path:
    return data_root() / "logs"


def make_private_dir(path: Path) -> None:
    """Create the directory; if we created it, restrict it to the current user (POSIX).

    Windows per-user directories under %LOCALAPPDATA% are already user-private by ACL.
    """
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if created and sys.platform != "win32":
        path.chmod(0o700)


def restrict_file(path: Path) -> None:
    if sys.platform != "win32" and path.exists():
        path.chmod(0o600)
