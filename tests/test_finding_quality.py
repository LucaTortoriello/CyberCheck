"""v0.3 context, classification, report and scoring regressions. Offline only."""

import json
import socket
import ssl
from contextlib import closing
from copy import deepcopy
from datetime import UTC, datetime
from html import unescape
from unittest.mock import MagicMock, patch

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from cybercheck.checks.email import check_dmarc, check_spf
from cybercheck.checks.headers import check_headers
from cybercheck.cli import main
from cybercheck.core.context import AssessmentContext, apply_context
from cybercheck.core.dns import DNSResult
from cybercheck.core.engine import run_assessment
from cybercheck.core.network import WebClient, WebResponse
from cybercheck.locales.findings import DEFINITIONS, REMEDIATIONS, finding
from cybercheck.locales.ui import tr
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.sqlite import Repository, compare


def mocked_run(fake_dns, context=None, *, domain="web.example.com", records=None):
    dns = fake_dns({(domain, "A"): ["8.8.8.8"]} | (records or {}))
    with (
        closing(
            WebClient(
                dns,
                dns.budget,
                httpx.MockTransport(
                    lambda request: httpx.Response(200, headers={"content-type": "text/html"})
                ),
            )
        ) as web,
        patch("cybercheck.checks.tls.socket.create_connection", side_effect=TimeoutError()),
    ):
        return run_assessment(domain, authorized=True, dns=dns, web=web, context=context), dns


def indexed(a):
    return {f.check_id: f for f in a.findings}


def raw_evidence(a):
    return {f.check_id: {k: v for k, v in f.evidence.items() if k != "applicability"} for f in a.findings}


def test_web_only_missing_mx_spf_dmarc_are_observations_not_operational_failures(fake_dns):
    a, dns = mocked_run(fake_dns, AssessmentContext(sends_email=False, receives_email=False))
    findings = indexed(a)
    for key in ("dns.mx", "email.spf", "email.dmarc"):
        f = findings[key]
        assert (f.status, f.severity, f.applicability) == (
            Status.WARNING,
            Severity.INFO,
            "not_applicable",
        )
        assert f.evidence["records"] == []
        assert not f.needs_attention
    assert findings["email.dkim"].status == Status.UNKNOWN
    assert findings["email.dkim"].applicability == "not_applicable"
    assert not any("_domainkey" in name for name, _ in dns.queries)
    assert "implicit" in findings["dns.mx"].explanation.en
    assert "no-senders" in findings["email.spf"].remediation.en
    assert "anti-impersonation" in findings["email.spf"].applicability_reason.en
    assert a.health["score"] is None


def test_unknown_applicability_and_dns_control_are_never_inferred(fake_dns):
    a, _ = mocked_run(fake_dns)
    f = indexed(a)
    for key in (
        "dns.mx",
        "dns.caa",
        "email.spf",
        "email.dmarc",
        "email.dkim",
        "headers.permissions",
        "headers.framing",
    ):
        assert f[key].applicability == "unknown"
    assert a.metadata["context"] == {
        "sends_email": None,
        "receives_email": None,
        "controls_dns": None,
        "source": "user_declared",
        "independently_verified": False,
    }
    assert f["email.spf"].severity == f["email.dmarc"].severity == Severity.INFO
    assert "DNS control is unknown" in f["dns.mx"].remediation.en


@pytest.mark.parametrize("domain", ["tenant.onrender.com", "tenant.unrecognized-platform.example.com"])
def test_shared_hosting_without_provider_ownership_heuristics(fake_dns, domain):
    a, _ = mocked_run(fake_dns, domain=domain)
    assert a.metadata["context"]["controls_dns"] is None
    assert indexed(a)["email.spf"].applicability == "unknown"
    assert "provider" not in a.metadata
    controlled, _ = mocked_run(fake_dns, AssessmentContext(controls_dns=False), domain=domain)
    assert "declared absent" in indexed(controlled)["dns.caa"].remediation.en
    assert "gestore della piattaforma" in indexed(controlled)["dns.caa"].remediation.it


@pytest.mark.parametrize("sends,receives", [(True, False), (False, True), (True, True), (None, None)])
def test_optional_email_roles_are_separate_and_unverified(fake_dns, sends, receives):
    a, _ = mocked_run(
        fake_dns, AssessmentContext(sends_email=sends, receives_email=receives, controls_dns=True)
    )
    f = indexed(a)
    states = {True: "applicable", False: "not_applicable", None: "unknown"}
    assert f["dns.mx"].applicability == states[receives]
    for key in ("email.spf", "email.dmarc", "email.dkim"):
        assert f[key].applicability == states[sends]
        assert f[key].evidence["applicability"]["basis"] == ("unknown" if sends is None else "user_declared")
    assert f["email.spf"].severity == (Severity.LOW if sends is True else Severity.INFO)
    assert f["email.dmarc"].severity == (Severity.LOW if sends is True else Severity.INFO)
    assert not a.metadata["context"]["independently_verified"]
    assert "not independently verified" in f["dns.mx"].remediation.en


def test_context_never_changes_dns_requests_or_raw_evidence(fake_dns):
    a, first_dns = mocked_run(fake_dns)
    b, second_dns = mocked_run(fake_dns, AssessmentContext(False, False, False))
    assert first_dns.queries == second_dns.queries
    assert raw_evidence(a) == raw_evidence(b)
    assert [(f.check_id, f.status) for f in a.findings] == [(f.check_id, f.status) for f in b.findings]


def test_caa_ns_and_aaaa_absence_do_not_prove_missing_effective_policy(fake_dns):
    a, dns = mocked_run(fake_dns)
    f = indexed(a)
    assert f["dns.records"].status == Status.PASSED
    assert f["dns.records"].evidence["NS"]["records"] == []
    assert f["dns.records"].evidence["AAAA"]["records"] == []
    assert f["dns.caa"].severity == Severity.INFO
    assert "Parent/CNAME" in f["dns.caa"].explanation.en
    assert "optional" in f["dns.caa"].explanation.en
    assert "facoltativo" in f["dns.caa"].explanation.it
    assert ("example.com", "CAA") not in dns.queries


def test_dmarc_absence_retains_both_queries_and_no_claimed_inheritance(fake_dns):
    f = check_dmarc("web.example.com", fake_dns())[0]
    assert [d["name"] for d in f.evidence["discovery"]] == ["_dmarc.web.example.com", "_dmarc.example.com"]
    assert not f.evidence["inherited"]
    assert f.evidence["dmarc_records"] == []
    assert "RFC 9989" in f.explanation.en and "RFC 9989" in f.explanation.it


def test_inherited_dmarc_is_preserved_and_child_record_is_not_required(fake_dns):
    records = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=none"]}
    a, _ = mocked_run(fake_dns, AssessmentContext(sends_email=True), records=records)
    f = indexed(a)["email.dmarc"]
    assert f.evidence["inherited"]
    assert f.evidence["effective_policy"] == "none"
    assert f.status == Status.WARNING and f.severity == Severity.LOW
    assert "inherited policy first" in f.remediation.en
    assert len(f.evidence["discovery"]) == 2


def test_dmarc_parent_lookup_error_preserves_exact_name_evidence(fake_dns):
    dns = fake_dns({("_dmarc.example.com", "TXT"): DNSResult("_dmarc.example.com", "TXT", "error")})
    f = check_dmarc("web.example.com", dns)[0]
    assert f.status == Status.UNKNOWN
    assert len(f.evidence["discovery"]) == 2


@pytest.mark.parametrize("tag", ["t=y", "np=reject", "psd=y"])
def test_modern_dmarc_markers_do_not_fail_legacy_percentage_checks(fake_dns, tag):
    dns = fake_dns({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=999; " + tag]})
    f = check_dmarc("example.com", dns)[0]
    assert f.status == Status.UNKNOWN and not f.scoreable
    assert f.evidence["syntax_errors"] == ["Invalid pct"]


def test_permissive_spf_is_warning_not_syntax_failure(fake_dns):
    f = check_spf("example.com", fake_dns({("example.com", "TXT"): ["v=spf1 +all"]}))[0]
    assert f.status == Status.WARNING and f.severity == Severity.MEDIUM
    assert f.evidence["syntax_errors"] == []
    assert not f.scoreable


@pytest.mark.parametrize("enabled", [False, True])
def test_head_501_still_requires_separate_get_authorization_with_context(fake_dns, enabled):
    from cybercheck.core.config import Budget, Settings

    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
    dns.budget = Budget(Settings(allow_get_fallback=enabled))
    methods = []

    def handler(request):
        methods.append((request.method, request.url.scheme))
        return httpx.Response(200 if request.method == "GET" else 501, headers={"content-type": "text/html"})

    with (
        closing(WebClient(dns, dns.budget, httpx.MockTransport(handler))) as web,
        patch("cybercheck.checks.tls.socket.create_connection", side_effect=TimeoutError()),
    ):
        a = run_assessment(
            "example.com", authorized=True, dns=dns, web=web, context=AssessmentContext(False, False, True)
        )
    f = indexed(a)
    assert methods == (
        [("HEAD", "https"), ("GET", "https"), ("HEAD", "http")]
        if enabled
        else [("HEAD", "https"), ("HEAD", "http")]
    )
    assert f["http.https"].status == Status.PASSED
    assert f["http.application"].status == (Status.PASSED if enabled else Status.UNKNOWN)
    assert f["headers.csp"].status == (Status.WARNING if enabled else Status.UNKNOWN)
    assert not any(item.status == Status.FAILED for item in a.findings)


def test_optional_headers_are_not_scored_even_when_present():
    headers = {
        "content-type": "text/html",
        "strict-transport-security": "max-age=100",
        "x-content-type-options": "nosniff",
    }
    a = Assessment(
        "example.com", findings=check_headers(WebResponse("https://example.com/", 200, headers, "8.8.8.8"))
    )
    apply_context(a, AssessmentContext())
    assert not any(f.scoreable for f in a.findings)
    assert a.health["evaluated"] == 0
    assert indexed(a)["headers.hsts"].applicability == "applicable"
    assert indexed(a)["headers.permissions"].applicability == "unknown"
    b = Assessment(
        "example.com",
        findings=check_headers(
            WebResponse("https://example.com/", 200, {"content-type": "text/html"}, "8.8.8.8")
        ),
    )
    apply_context(b, AssessmentContext())
    assert a.health == b.health
    assert all(f.status == Status.WARNING for f in b.findings)


def test_framing_wildcard_host_is_not_asserted_to_be_restrictive():
    r = WebResponse(
        "https://example.com/",
        200,
        {"content-type": "text/html", "content-security-policy": "frame-ancestors https://*"},
        "8.8.8.8",
    )
    f = next(f for f in check_headers(r) if f.check_id == "headers.framing")
    assert f.status == Status.WARNING


def test_nonhtml_and_unknown_content_types_have_explicit_applicability():
    for content_type, expected in [("application/json", "not_applicable"), ("", "unknown")]:
        a = Assessment(
            "example.com",
            findings=check_headers(
                WebResponse("https://example.com/", 200, {"content-type": content_type}, "8.8.8.8")
            ),
        )
        apply_context(a, AssessmentContext())
        assert indexed(a)["headers.csp"].applicability == expected
        assert indexed(a)["headers.permissions"].applicability == expected


def test_tls_success_does_not_enumerate_protocol_support(fake_dns, monkeypatch):
    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
    raw, context = MagicMock(), MagicMock()
    monkeypatch.setattr(socket, "create_connection", MagicMock(return_value=raw))
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    secured = context.wrap_socket.return_value.__enter__.return_value
    secured.getpeercert.return_value = {
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Jan 01 00:00:00 2027 GMT",
    }
    secured.version.return_value = "TLSv1.3"
    secured.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    with patch("cybercheck.checks.tls.datetime", wraps=datetime) as clock:
        clock.now.return_value = datetime(2026, 11, 16, tzinfo=UTC)
        with closing(
            WebClient(dns, dns.budget, httpx.MockTransport(lambda request: httpx.Response(200)))
        ) as web:
            a = run_assessment("example.com", authorized=True, dns=dns, web=web)
    f = indexed(a)["tls.protocol"]
    assert f.status == Status.PASSED and f.evidence["protocol"] == "TLSv1.3"
    assert f.evidence["protocol_support_enumerated"] is False
    assert "not probed" in f.explanation.en
    socket.create_connection.assert_called_once()
    assert a.health["evaluated"] == 4


@pytest.mark.parametrize("language", ["en", "it"])
def test_json_html_applicability_context_and_recommendation_parity(fake_dns, language):
    a, _ = mocked_run(fake_dns, AssessmentContext(False, False, False))
    before = deepcopy(a.to_dict())
    report = json.loads(render_json(a))
    html = unescape(render_html(a, language, include_score=True))
    assert "context-v1" in report["score_formula"] and "context-v1" in html
    assert tr("report_context_note", language) in html
    for f, serialized in zip(a.findings, report["findings"], strict=True):
        assert serialized["evidence"]["applicability"]["state"] == f.applicability
        assert f.applicability_reason.get(language) in html
        assert f.remediation.get(language) in html
    assert a.to_dict() == before
    assert Assessment.from_dict(report).to_dict() == a.to_dict()
    assert all(indexed(a)["dns.mx"].id != value for value in report["summary"]["priority_finding_ids"])


def test_all_finding_names_and_specific_recommendations_are_bilingual():
    for key, (_, en, it, _) in DEFINITIONS.items():
        assert en.strip() and it.strip(), key
    for key, text in REMEDIATIONS.items():
        assert text.en.strip() and text.it.strip() and text.en != text.it, key
    # Important qualifications must survive translation, beyond catalog completeness.
    for key, en, it in [
        ("email.spf", "If this hostname sends", "Se questo host invia"),
        ("email.dmarc", "inherited policy first", "prima la policy ereditata"),
        ("dns.mx", "missing MX alone", "MX assenti non provano da soli"),
        ("dns.caa", "optional", "facoltativo"),
        ("headers.permissions", "not universally required", "non è sempre richiesta"),
        ("tls.protocol", "was not tested", "non è stato testato"),
    ]:
        assert en in REMEDIATIONS[key].en and it in REMEDIATIONS[key].it


@pytest.mark.parametrize("declared,expected", [(None, None), (False, None), (True, 0.0)])
def test_score_policy_failure_requires_applicability_and_context(fake_dns, declared, expected):
    records = {("web.example.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]}
    a, _ = mocked_run(fake_dns, AssessmentContext(sends_email=declared), records=records)
    assert indexed(a)["email.spf"].status == Status.FAILED
    assert a.health["score"] == expected
    assert a.health["evaluated"] == (1 if declared is True else 0)
    # Older schema-v1 consumers that use just status/scoreable get the same result.
    eligible = [f for f in a.findings if f.scoreable and f.status in {Status.PASSED, Status.FAILED}]
    assert len(eligible) == a.health["evaluated"]


def test_score_never_penalizes_unknown_error_warning_or_optional_headers():
    a = Assessment(
        "example.com",
        findings=[
            finding("tls.chain", status, Severity.HIGH, "en", "it", scoreable=True) for status in Status
        ],
    )
    apply_context(a, AssessmentContext())
    assert a.health == {"score": 50.0, "passed": 1, "evaluated": 2, "excluded": 4}
    optional = finding(
        "headers.hsts",
        Status.PASSED,
        Severity.INFO,
        "en",
        "it",
        {"content_type": "text/html"},
        scoreable=True,
    )
    a.findings.append(optional)
    apply_context(a, AssessmentContext())
    assert a.health["score"] == 50.0 and a.health["evaluated"] == 2


def test_historical_json_sqlite_scores_and_source_are_not_rewritten(tmp_path):
    legacy = Assessment(
        "example.com",
        findings=[
            finding(
                "tls.chain", Status.FAILED, Severity.HIGH, "Old failure", "Errore storico", scoreable=True
            ),
            finding(
                "headers.hsts", Status.PASSED, Severity.INFO, "Old pass", "Superato storico", scoreable=True
            ),
        ],
    )
    original = json.dumps(legacy.to_dict())
    repo = Repository(tmp_path / "history.sqlite3")
    repo.save(legacy)
    with repo.connect() as db:
        before = db.execute("SELECT payload FROM assessments").fetchone()[0]
    loaded = repo.get(legacy.id)
    assert loaded.health["score"] == 50.0
    assert indexed(loaded)["tls.chain"].applicability == "unknown"
    exported = json.loads(render_json(loaded))
    assert exported["configuration_health"]["score"] == 50.0
    assert exported["score_formula"] == tr("score_formula", "en")
    assert "context-v1" not in render_html(loaded, include_score=True)
    assert "evidence" in exported["findings"][0]
    assert "applicability" not in exported["findings"][0]["evidence"]
    assert json.dumps(Assessment.from_dict(exported).to_dict()) == original
    assert compare(legacy, loaded) == []
    with repo.connect() as db:
        assert db.execute("SELECT payload FROM assessments").fetchone()[0] == before
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_cli_passes_optional_context_without_authorizing_get(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "history.sqlite3"))
    monkeypatch.setattr(
        "sys.argv",
        [
            "cybercheck",
            "example.com",
            "--authorized",
            "--sends-email",
            "yes",
            "--receives-email",
            "no",
            "--controls-dns",
            "no",
            "--output",
            str(tmp_path / "exports"),
        ],
    )
    with patch("cybercheck.cli.run_assessment", return_value=Assessment("example.com")) as run:
        assert main() == 0
    assert run.call_args.kwargs["context"] == AssessmentContext(True, False, False)
    assert not run.call_args.kwargs["settings"].allow_get_fallback


def test_dashboard_context_defaults_and_explicit_declarations(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "history.sqlite3"))
    app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
    app.radio(key="navigation").set_value("new").run()
    for name in ("sends_email", "receives_email", "controls_dns"):
        assert app.selectbox(key="context_" + name).value == "unknown"
    app.selectbox(key="context_sends_email").set_value("yes")
    app.selectbox(key="context_receives_email").set_value("no")
    app.selectbox(key="context_controls_dns").set_value("no")
    app.text_input[0].set_value("example.com")
    app.checkbox[0].check()
    with patch("cybercheck.app.dashboard.run_assessment", return_value=Assessment("example.com")) as run:
        app.button[0].click().run()
    assert not app.exception
    assert run.call_args.kwargs["context"] == AssessmentContext(True, False, False)
    assert not run.call_args.kwargs["settings"].allow_get_fallback


@pytest.mark.parametrize("value", ["yes", 1, 0, [], {}])
def test_context_rejects_ambiguous_non_boolean_values(value):
    with pytest.raises(ValueError):
        AssessmentContext(sends_email=value)


def test_invalid_context_rejected_before_network(fake_dns):
    dns = fake_dns()
    with pytest.raises(ValueError, match="AssessmentContext"):
        run_assessment("example.com", authorized=True, dns=dns, context={"sends_email": True})
    assert dns.queries == []


@pytest.mark.parametrize(
    "details", [None, "legacy free-form note", {"state": "unsupported"}, {"reason": {"en": "incomplete"}}]
)
def test_optional_evidence_keys_do_not_break_legacy_free_form_payloads(details):
    f = finding("dns.mx", Status.WARNING, Severity.INFO, "en", "it", {"applicability": details})
    a = Assessment("example.com", findings=[f])
    original = deepcopy(a.to_dict())
    assert f.applicability == "unknown"
    assert f.applicability_reason.en
    assert "Applicability" in render_html(a, "en")
    assert a.to_dict() == original
