"""Local SQLite persistence with short-lived connections and parameterized SQL."""

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cybercheck.models import Assessment

SCHEMA_VERSION = 1


class StorageDataError(ValueError):
    """A stored payload is malformed or unsupported; preserve it for recovery."""


def load_payload(payload: str) -> Assessment:
    try:
        return Assessment.from_dict(json.loads(payload))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise StorageDataError("Stored assessment data is invalid or has an unsupported schema") from exc


class Repository:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create privately before SQLite opens the file; do not follow a final
        # symlink. Parent directories remain trusted local configuration.
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("Database path must be a regular file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        with self.connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, SCHEMA_VERSION}:
                raise ValueError(f"Unsupported database schema version: {version}")
            connection.execute("""CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY, domain TEXT NOT NULL, started_at TEXT NOT NULL,
                completed_at TEXT, payload TEXT NOT NULL)""")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_domain_time ON assessments(domain, started_at)"
            )
            if version == 0:
                connection.execute("PRAGMA user_version=1")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, assessment: Assessment) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO assessments VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, completed_at=excluded.completed_at""",
                (
                    assessment.id,
                    assessment.domain,
                    assessment.started_at,
                    assessment.completed_at,
                    json.dumps(assessment.to_dict(), ensure_ascii=False),
                ),
            )

    def list(self, domain: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        query = "SELECT id, domain, started_at, completed_at FROM assessments"
        params: list = []
        if domain:
            query += " WHERE domain = ?"
            params.append(domain)
        query += " ORDER BY started_at DESC, rowid DESC LIMIT ? OFFSET ?"
        params.extend((limit, offset))
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(query, params)]

    def get(self, assessment_id: str) -> Assessment | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        return load_payload(row["payload"]) if row else None

    def previous(self, assessment: Assessment) -> Assessment | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT payload FROM assessments
                WHERE domain=? AND (started_at<? OR (started_at=? AND
                    rowid < COALESCE((SELECT rowid FROM assessments WHERE id=?), 9223372036854775807)))
                ORDER BY started_at DESC, rowid DESC LIMIT 1""",
                (assessment.domain, assessment.started_at, assessment.started_at, assessment.id),
            ).fetchone()
        return load_payload(row["payload"]) if row else None


def stable_evidence(value: object, key: str = "") -> object:
    """Ignore countdowns and serialization/order noise, never changed policy data."""
    if isinstance(value, dict):
        return {k: stable_evidence(v, k) for k, v in value.items() if k != "days_until_expiration"}
    if isinstance(value, (list, tuple)):
        items = [stable_evidence(v) for v in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True)) if key == "records" else items
    return value


def compare(previous: Assessment, current: Assessment) -> list[dict]:
    """Compare stable check IDs; changed evidence alone is not a risk regression."""
    if previous.domain != current.domain:
        raise ValueError("Only assessments of the same domain can be compared")
    before = {f.check_id: f for f in previous.findings}
    after = {f.check_id: f for f in current.findings}
    changes = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        if (
            old is None
            or new is None
            or (old.status, old.severity, stable_evidence(old.evidence))
            != (new.status, new.severity, stable_evidence(new.evidence))
        ):
            changes.append(
                {
                    "check_id": key,
                    "previous_status": old.status.value if old else None,
                    "current_status": new.status.value if new else None,
                    "previous_severity": old.severity.value if old else None,
                    "current_severity": new.severity.value if new else None,
                    "evidence_changed": bool(
                        old and new and stable_evidence(old.evidence) != stable_evidence(new.evidence)
                    ),
                }
            )
    return changes
