import json
import logging
import os

from shadowcr3_na.logging_setup import LOGGER_NAME, configure_logging


def test_logs_are_structured_and_redacted(tmp_path):
    path = configure_logging(directory=tmp_path / "logs")
    log = logging.getLogger("shadowcr3_na.test")
    log.info("scan done password=hunter2 token: abc123", extra={"job_id": "j1", "event": "e"})
    for h in logging.getLogger(LOGGER_NAME).handlers:
        h.flush()
    entry = json.loads(path.read_text().splitlines()[-1])
    assert entry["level"] == "INFO" and entry["job_id"] == "j1" and entry["event"] == "e"
    assert "hunter2" not in entry["msg"] and "abc123" not in entry["msg"]
    assert entry["msg"].count("[REDACTED]") == 2


def test_configuration_is_idempotent_and_rotating(tmp_path):
    configure_logging(directory=tmp_path / "logs")
    configure_logging(directory=tmp_path / "logs")
    handlers = [h for h in logging.getLogger(LOGGER_NAME).handlers if getattr(h, "_shadowcr3", False)]
    assert len(handlers) == 1
    assert handlers[0].maxBytes == 1_000_000 and handlers[0].backupCount == 3


def test_log_directory_and_file_are_private(tmp_path):
    path = configure_logging(directory=tmp_path / "logs")
    if os.name != "nt":
        assert (path.parent.stat().st_mode & 0o777) == 0o700
        assert (path.stat().st_mode & 0o777) == 0o600


def test_exceptions_are_logged_with_redaction(tmp_path):
    path = configure_logging(directory=tmp_path / "logs")
    try:
        raise RuntimeError("boom api_key=SECRET123")
    except RuntimeError:
        logging.getLogger("shadowcr3_na.test").exception("failed")
    for h in logging.getLogger(LOGGER_NAME).handlers:
        h.flush()
    assert "SECRET123" not in path.read_text()
