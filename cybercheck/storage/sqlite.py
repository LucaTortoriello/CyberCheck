"""Local SQLite persistence with short-lived connections and parameterized SQL."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from cybercheck.models import Assessment


class Repository:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY, domain TEXT NOT NULL, started_at TEXT NOT NULL,
                completed_at TEXT, payload TEXT NOT NULL)""")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_domain_time ON assessments(domain, started_at)"
            )
            connection.execute("PRAGMA user_version=1")
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
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
        query += " ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?"
        params.extend((limit, offset))
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(query, params)]

    def get(self, assessment_id: str) -> Assessment | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        return Assessment.from_dict(json.loads(row["payload"])) if row else None

    def previous(self, assessment: Assessment) -> Assessment | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT payload FROM assessments
                WHERE domain=? AND started_at<? ORDER BY started_at DESC, id DESC LIMIT 1""",
                (assessment.domain, assessment.started_at),
            ).fetchone()
        return Assessment.from_dict(json.loads(row["payload"])) if row else None


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
            or (old.status, old.severity, old.evidence) != (new.status, new.severity, new.evidence)
        ):
            changes.append(
                {
                    "check_id": key,
                    "previous_status": old.status.value if old else None,
                    "current_status": new.status.value if new else None,
                    "previous_severity": old.severity.value if old else None,
                    "current_severity": new.severity.value if new else None,
                    "evidence_changed": bool(old and new and old.evidence != new.evidence),
                }
            )
    return changes
