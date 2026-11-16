"""Local SQLite persistence with short-lived connections and parameterized SQL."""

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cybercheck.core.comparison import compare_assessments, stable_evidence  # noqa: F401
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


def compare(previous: Assessment, current: Assessment) -> list[dict]:
    """Compatibility adapter: retain the changed-row list and familiar field names.

    New callers should use compare_assessments for full comparability and unchanged
    or persistent findings. Source storage is never mutated.
    """
    comparison = compare_assessments(previous, current)
    return [
        item
        for item in comparison.findings
        if item["earlier"] is None
        or item["later"] is None
        or item["differences"]
        or any(
            item["dimensions"][name]
            for name in (
                "status_changed",
                "severity_changed",
                "applicability_changed",
                "scoring_eligibility_changed",
            )
        )
    ]
