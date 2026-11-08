"""Serializable domain model. Findings retain both supported languages."""

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


def now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Text:
    en: str
    it: str

    def get(self, language: str = "it") -> str:
        return self.en if language == "en" else self.it


class Status(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    UNKNOWN = "unknown"
    ERROR = "error"
    NA = "not_applicable"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class Finding:
    check_id: str
    check_name: Text
    category: str
    status: Status
    severity: Severity
    explanation: Text
    business_impact: Text
    remediation: Text
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    scoreable: bool = False
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=now)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        values = dict(data)
        for key in ("check_name", "explanation", "business_impact", "remediation"):
            values[key] = Text(**values[key])
        values["status"] = Status(values["status"])
        values["severity"] = Severity(values["severity"])
        return cls(**values)


@dataclass
class Assessment:
    domain: str
    selectors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=now)
    completed_at: str | None = None
    authorization_confirmed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Assessment":
        values = dict(data)
        values["findings"] = [Finding.from_dict(f) for f in values.get("findings", [])]
        return cls(**values)

    @property
    def counts(self) -> dict[str, int]:
        counts = Counter(f.status.value for f in self.findings)
        return {s.value: counts[s.value] for s in Status}

    @property
    def health(self) -> dict[str, int | float | None]:
        eligible = [f for f in self.findings if f.scoreable and f.status in (Status.PASSED, Status.FAILED)]
        passed = sum(f.status == Status.PASSED for f in eligible)
        return {
            "score": round(100 * passed / len(eligible), 1) if eligible else None,
            "passed": passed,
            "evaluated": len(eligible),
            "excluded": len(self.findings) - len(eligible),
        }
