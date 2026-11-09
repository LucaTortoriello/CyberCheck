"""Deterministic regressions for parsing, persistence and comparison defects."""

import json
import sqlite3

import pytest

from cybercheck.checks.email import check_dmarc, check_dns, check_spf
from cybercheck.checks.headers import check_headers
from cybercheck.core.dns import DNSResult
from cybercheck.core.network import WebResponse
from cybercheck.locales.findings import finding
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_json
from cybercheck.storage.sqlite import Repository, compare


@pytest.mark.parametrize("record", ["v=spf1 future=x future=y ~all", "v=spf1 future= ~all"])
def test_spf_ignores_unknown_modifiers_even_when_repeated_or_empty(fake_dns, record):
    assert check_spf("example.com", fake_dns({("example.com", "TXT"): [record]}))[0].status == Status.PASSED


def test_spf_equals_delimiter_inside_macro_is_not_a_modifier(fake_dns):
    results = check_spf(
        "example.com", fake_dns({("example.com", "TXT"): ["v=spf1 exists:%{l1r=}.example.com -all"]})
    )
    assert results[0].status == Status.UNKNOWN
    assert results[1].status == Status.UNKNOWN


def test_spf_underscore_dependency_is_a_dns_name_not_a_web_hostname(fake_dns):
    dns = fake_dns(
        {
            ("example.com", "TXT"): ["v=spf1 include:_spf.example.com ~all"],
            ("_spf.example.com", "TXT"): ["v=spf1 -all"],
        }
    )
    result = check_spf("example.com", dns)[1]
    assert result.status == Status.PASSED
    assert ("_spf.example.com", "TXT") in dns.queries


@pytest.mark.parametrize(
    "mechanism", ["a/33", "mx//129", "mx:example.com/100", "ptr/24", "ip4:1.2.3.4/255.255.255.0"]
)
def test_spf_rejects_definite_supported_mechanism_grammar_errors(fake_dns, mechanism):
    record = f"v=spf1 {mechanism} ~all"
    assert check_spf("example.com", fake_dns({("example.com", "TXT"): [record]}))[0].status == Status.FAILED


def test_dmarc_version_whitespace_does_not_select_inherited_policy(fake_dns):
    dns = fake_dns(
        {
            ("_dmarc.shop.example.com", "TXT"): ["v = DMARC1; p=none"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        }
    )
    result = check_dmarc("shop.example.com", dns)[0]
    assert result.status == Status.WARNING
    assert result.evidence["policy_domain"] == "shop.example.com"


@pytest.mark.parametrize(
    "header", ['max-age="31536000', 'max-age=31536000"', "max-age=100; includeSubDomains; includeSubDomains"]
)
def test_malformed_hsts_is_not_reported_as_active(header):
    r = WebResponse("https://example.com/", 200, {"strict-transport-security": header}, "8.8.8.8")
    assert next(f for f in check_headers(r) if f.check_id == "headers.hsts").status == Status.WARNING


def test_long_hsts_integer_cannot_crash_header_checks():
    r = WebResponse(
        "https://example.com/", 200, {"strict-transport-security": "max-age=" + "9" * 5000}, "8.8.8.8"
    )
    assert len(check_headers(r)) == 6


def test_multiple_csp_policies_enforce_their_intersection():
    r = WebResponse(
        "https://example.com/",
        200,
        {"content-type": "text/html", "content-security-policy": "frame-ancestors *, frame-ancestors 'none'"},
        "8.8.8.8",
    )
    assert next(f for f in check_headers(r) if f.check_id == "headers.framing").status == Status.PASSED


def test_nxdomain_inventory_is_inconclusive_not_passed(fake_dns):
    dns = fake_dns(
        {
            ("example.com", kind): DNSResult("example.com", kind, "nxdomain")
            for kind in ("A", "AAAA", "NS", "MX", "CAA")
        }
    )
    assert all(f.status == Status.UNKNOWN for f in check_dns("example.com", dns))
    dns = fake_dns({("example.com", "TXT"): DNSResult("example.com", "TXT", "nxdomain")})
    assert check_spf("example.com", dns)[0].status == Status.UNKNOWN


def test_future_database_schema_is_never_downgraded(tmp_path):
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="schema"):
        Repository(path)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99


def test_equal_assessment_timestamps_still_have_a_previous_run(tmp_path):
    repo = Repository(tmp_path / "db.sqlite3")
    first = Assessment("example.com", started_at="2026-01-01T00:00:00+00:00")
    second = Assessment("example.com", started_at=first.started_at)
    repo.save(first)
    repo.save(second)
    assert repo.previous(second).id == first.id
    assert repo.previous(first) is None
    assert repo.list()[0]["id"] == second.id


def test_expiry_countdown_and_dns_record_order_are_not_configuration_changes():
    a = Assessment(
        "example.com",
        findings=[
            finding(
                "tls.validity",
                Status.PASSED,
                Severity.INFO,
                "en",
                "it",
                {"days_until_expiration": 50, "not_after": "same", "cipher": ("cipher", "TLSv1.3", 256)},
            ),
            finding(
                "dns.records",
                Status.PASSED,
                Severity.INFO,
                "en",
                "it",
                {"A": {"records": ["8.8.8.8", "8.8.4.4"]}},
            ),
        ],
    )
    b = Assessment.from_dict(json.loads(json.dumps(a.to_dict())))
    b.findings[0].evidence["days_until_expiration"] = 49
    b.findings[1].evidence["A"]["records"].reverse()
    assert compare(a, b) == []


def test_exported_json_can_be_loaded_without_trusting_derived_score():
    exported = json.loads(render_json(Assessment("example.com")))
    exported["configuration_health"]["score"] = 100
    restored = Assessment.from_dict(exported)
    assert restored.health["score"] is None
