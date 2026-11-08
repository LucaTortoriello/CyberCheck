import json

import pytest

from cybercheck.locales.findings import finding
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.sqlite import Repository, compare


def test_score_excludes_unknown_inapplicable_errors_and_warnings():
    a = Assessment(
        "example.com",
        findings=[
            finding("tls.chain", status, Severity.INFO, "en", "it", scoreable=True) for status in Status
        ],
    )
    assert a.health == {"score": 50.0, "passed": 1, "evaluated": 2, "excluded": 4}
    assert Assessment("example.com").health["score"] is None


def test_storage_round_trip_and_previous(tmp_path):
    repo = Repository(tmp_path / "history.sqlite3")
    before = Assessment(
        "example.com",
        started_at="2026-01-01T00:00:00+00:00",
        findings=[finding("email.spf", Status.WARNING, Severity.LOW, "Before", "Prima")],
    )
    current = Assessment(
        "example.com",
        started_at="2026-01-02T00:00:00+00:00",
        findings=[finding("email.spf", Status.PASSED, Severity.INFO, "After", "Dopo")],
    )
    repo.save(before)
    repo.save(current)
    repo.save(current)
    assert len(repo.list()) == 2
    assert repo.get(current.id).to_dict() == current.to_dict()
    assert repo.previous(current).id == before.id
    assert repo.list("example.com' OR 1=1 --") == []
    assert repo.get("missing") is None
    changes = compare(before, current)
    assert changes[0]["current_status"] == "passed"
    assert compare(current, current) == []
    with pytest.raises(ValueError):
        compare(current, Assessment("other.com"))


def test_report_escapes_untrusted_evidence_and_preserves_data():
    payload = '<script>alert("xss")</script>'
    a = Assessment(
        "example.com",
        findings=[finding("email.spf", Status.WARNING, Severity.LOW, payload, payload, {"record": payload})],
    )
    html = render_html(a, "en", include_score=True)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "Executive summary" in html
    assert "Metodologia" in render_html(a, "it")
    exported = json.loads(render_json(a))
    assert exported["findings"][0]["evidence"]["record"] == payload
    assert "configuration_health" in exported
    assert "Content-Security-Policy" in html


def test_model_roundtrip_retains_both_languages():
    a = Assessment(
        "example.com", findings=[finding("tls.hostname", Status.PASSED, Severity.INFO, "English", "Italiano")]
    )
    restored = Assessment.from_dict(a.to_dict())
    assert restored.findings[0].explanation.get("it") == "Italiano"
    assert restored.findings[0].status == Status.PASSED
