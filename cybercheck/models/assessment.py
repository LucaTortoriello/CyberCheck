"""Serializable domain model. Findings retain both supported languages."""

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from cybercheck.models.validation import MAX_FINDINGS, DataValidationError, validate_data_size


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

    @property
    def applicability(self) -> str:
        details = self.evidence.get("applicability")
        state = details.get("state") if isinstance(details, dict) else None
        return state if state in ("applicable", "not_applicable", "unknown") else "unknown"

    @property
    def applicability_reason(self) -> Text:
        details = self.evidence.get("applicability")
        reason = details.get("reason") if isinstance(details, dict) else None
        return (
            Text(reason["en"], reason["it"])
            if isinstance(reason, dict) and all(isinstance(reason.get(key), str) for key in ("en", "it"))
            else Text(
                "Applicability was not recorded; service context remains unknown.",
                "Applicabilità non registrata; il contesto del servizio resta sconosciuto.",
            )
        )

    @property
    def needs_attention(self) -> bool:
        return (
            self.status in {Status.FAILED, Status.WARNING}
            and self.severity != Severity.INFO
            and self.applicability != "not_applicable"
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        values = dict(data)
        # Missing provenance stays missing; never invent historical UUIDs/times.
        values.setdefault("id", "")
        values.setdefault("timestamp", "")
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
        validate_data_size(data)
        if not isinstance(data, dict) or not isinstance(data.get("findings", []), list):
            raise DataValidationError("Historical assessment must contain a finding list")
        if len(data.get("findings", [])) > MAX_FINDINGS:
            raise DataValidationError("Historical assessment exceeds the finding limit")
        values = dict(data)
        if type(values.get("schema_version", 1)) is not int or values.get("schema_version", 1) != 1:
            raise ValueError("Unsupported assessment schema version")
        values.setdefault("id", "")
        values.setdefault("started_at", "")
        for derived in ("configuration_health", "score_formula", "methodology", "disclaimer", "summary"):
            values.pop(derived, None)
        values["findings"] = [Finding.from_dict(f) for f in values.get("findings", [])]
        assessment = cls(**values)
        validate_assessment(assessment)
        return assessment

    @property
    def counts(self) -> dict[str, int]:
        counts = Counter(f.status.value for f in self.findings)
        return {s.value: counts[s.value] for s in Status}

    @property
    def health(self) -> dict[str, int | float | None]:
        eligible = [
            f
            for f in self.findings
            if f.scoreable
            and f.status in (Status.PASSED, Status.FAILED)
            and (
                self.metadata.get("scoring_profile") != "context-v1"
                or (f.applicability == "applicable" and f.category != "headers")
            )
        ]
        passed = sum(f.status == Status.PASSED for f in eligible)
        return {
            "score": round(100 * passed / len(eligible), 1) if eligible else None,
            "passed": passed,
            "evaluated": len(eligible),
            "excluded": len(self.findings) - len(eligible),
        }


def validate_assessment(assessment: Assessment, *, strict_evidence: bool = True) -> None:
    """Validate the model contract without reinterpreting or modifying findings."""
    if not isinstance(assessment, Assessment):
        raise DataValidationError("Expected an assessment")
    for name in ("domain", "id", "started_at"):
        if not isinstance(getattr(assessment, name), str):
            raise DataValidationError("Invalid assessment identity or timestamp type")
    if not assessment.domain or not assessment.id or not isinstance(assessment.metadata, dict):
        raise DataValidationError("Invalid assessment domain or metadata")
    if type(assessment.schema_version) is not int or assessment.schema_version != 1:
        raise DataValidationError("Unsupported assessment schema")
    if type(assessment.authorization_confirmed) is not bool:
        raise DataValidationError("Invalid historical authorization declaration")
    if assessment.completed_at is not None and not isinstance(assessment.completed_at, str):
        raise DataValidationError("Invalid assessment completion timestamp type")
    if not isinstance(assessment.selectors, list) or not all(
        isinstance(s, str) for s in assessment.selectors
    ):
        raise DataValidationError("Invalid historical selectors")
    if not isinstance(assessment.findings, list) or len(assessment.findings) > MAX_FINDINGS:
        raise DataValidationError("Invalid or oversized finding list")
    for f in assessment.findings:
        if not isinstance(f, Finding):
            raise DataValidationError("Invalid historical finding")
        if not all(isinstance(getattr(f, name), str) for name in ("check_id", "category", "id", "timestamp")):
            raise DataValidationError("Invalid finding identity or category")
        if not f.check_id or not f.id or not f.category:
            raise DataValidationError("Missing finding identity or category")
        if (
            not isinstance(f.status, Status)
            or not isinstance(f.severity, Severity)
            or type(f.scoreable) is not bool
        ):
            raise DataValidationError("Invalid finding evaluation fields")
        for name in ("check_name", "explanation", "business_impact", "remediation"):
            text = getattr(f, name)
            if not isinstance(text, Text) or not isinstance(text.en, str) or not isinstance(text.it, str):
                raise DataValidationError("Invalid bilingual finding text")
        if strict_evidence and not isinstance(f.evidence, dict):
            raise DataValidationError("Invalid historical evidence type")
        if not isinstance(f.references, list) or not all(isinstance(r, str) for r in f.references):
            raise DataValidationError("Invalid historical references")
    validate_data_size(assessment)
