from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .paths import log_dir, make_private_dir, restrict_file

LOGGER_NAME = "shadowcr3_na"
_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b(\s*[=:]\s*)\S+"
)
_CONTEXT_KEYS = ("job_id", "event", "category")


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _SECRET.sub(r"\1\2[REDACTED]", record.getMessage())
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "msg": record.getMessage(),
        }
        for key in _CONTEXT_KEYS:
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = _SECRET.sub(
                r"\1\2[REDACTED]", self.formatException(record.exc_info)
            )
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(level: int = logging.INFO, directory: Path | None = None) -> Path:
    """Idempotent. Returns the log file path."""
    target_dir = directory or log_dir()
    make_private_dir(target_dir)
    path = target_dir / "shadowcr3-na.log"
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        if getattr(handler, "_shadowcr3", False):
            logger.removeHandler(handler)
            handler.close()
    handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler._shadowcr3 = True  # type: ignore[attr-defined]
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    restrict_file(path)






