"""Structured logs avoid dumping records, credentials, or response bodies."""

import json
import logging
import traceback
from datetime import UTC, datetime
from pathlib import Path


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
            "logger": record.name,
        }
        for key in ("assessment_id", "domain", "check_module", "error_type"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            exception_type, _, tb = record.exc_info
            payload["error_type"] = exception_type.__name__ if exception_type else "Unknown"
            payload["stack"] = [
                {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                for frame in traceback.extract_tb(tb)
            ]
        return json.dumps(payload)


def configure_logging() -> None:
    logger = logging.getLogger("cybercheck")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
