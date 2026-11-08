from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from cybercheck.checks.email import check_dkim, check_dmarc, check_dns, check_spf
from cybercheck.core.config import Budget, Settings
from cybercheck.core.dns import DNSClient, DNSResult
from cybercheck.models import Severity, Status


@pytest.mark.parametrize(
    ("exc", "state"),
    [
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoAnswer(), "absent"),
        (dns.exception.Timeout(), "error"),
        (dns.resolver.NoNameservers(), "error"),
    ],
)
def test_dns_errors_and_absence_are_distinct(resolver, exc, state):
    resolver.resolve.side_effect = exc
    client = DNSClient(Budget(Settings()), resolver)
    assert client.query("example.com", "TXT").state == state
    assert client.query("example.com", "TXT").state == state
    resolver.resolve.assert_called_once()


def test_txt_chunks_joined_with_absolute_query(resolver):
    resolver.resolve.return_value = [Mock(strings=(b"v=spf1 ", b"~all"))]
    client = DNSClient(Budget(Settings()), resolver)
    assert client.query("example.com", "TXT").records == ["v=spf1 ~all"]
    assert resolver.resolve.call_args.args[0] == "example.com."
    assert resolver.resolve.call_args.kwargs["search"] is False


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([], Status.WARNING),
        (["v=spf1 ~all"], Status.PASSED),
        (["v=spf1 -all"], Status.PASSED),
        (["v=spf1 +all"], Status.FAILED),
        (["v=spf1 ?all"], Status.WARNING),
        (["v=spf1 ~all", "v=spf1 -all"], Status.FAILED),
        (["v=spf1 ip4:banana -all"], Status.FAILED),
        (["v=spf1 madeup -all"], Status.FAILED),
        (["v=spf11 -all"], Status.WARNING),
        (["v=spf1 include: -all"], Status.FAILED),
    ],
)
def test_spf_cases(fake_dns, records, expected):
    dns = fake_dns({("example.com", "TXT"): records})
    assert check_spf("example.com", dns)[0].status == expected


def test_spf_lookup_complexity_is_warning_not_runtime_failure(fake_dns):
    records = ["v=spf1 " + " ".join(f"include:a{i}.example.com" for i in range(11)) + " ~all"]
    mapping = {("example.com", "TXT"): records}
    mapping.update({(f"a{i}.example.com", "TXT"): ["v=spf1 -all"] for i in range(11)})
    result = check_spf("example.com", fake_dns(mapping))[1]
    assert result.status == Status.WARNING
    assert result.evidence["potential_dns_terms"] == 11


def test_spf_include_cycle_and_terminal_all(fake_dns):
    dns = fake_dns({("example.com", "TXT"): ["v=spf1 include:example.com ~all"]})
    assert check_spf("example.com", dns)[1].status == Status.UNKNOWN
    dns = fake_dns({("example.com", "TXT"): ["v=spf1 -all include:unused.example.com"]})
    check_spf("example.com", dns)
    assert ("unused.example.com", "TXT") not in dns.queries


def test_spf_dns_error_is_unknown(fake_dns):
    dns = fake_dns({("example.com", "TXT"): DNSResult("example.com", "TXT", "error", error="timeout")})
    assert check_spf("example.com", dns)[0].status == Status.UNKNOWN


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("v=DMARC1; p=none; rua=mailto:reports@example.com", Status.WARNING),
        ("v=DMARC1; p=reject; pct=25", Status.WARNING),
        ("v=DMARC1; p=quarantine", Status.PASSED),
        ("v=DMARC1; p=reject; pct=0", Status.WARNING),
        ("v=DMARC1; p=reject; pct=101", Status.FAILED),
        ("v=DMARC1; p=reject; p=none", Status.FAILED),
        ("v=DMARC1; p=invalid", Status.FAILED),
        ("v=DMARC1; rua=mailto:a@example.com; p=reject", Status.FAILED),
    ],
)
def test_dmarc_policies(fake_dns, policy, expected):
    dns = fake_dns({("_dmarc.example.com", "TXT"): [policy]})
    result = check_dmarc("example.com", dns)[0]
    assert result.status == expected
    assert result.severity != Severity.CRITICAL


def test_dmarc_org_inheritance_and_reporting(fake_dns):
    dns = fake_dns(
        {("_dmarc.example.co.uk", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:reports@example.co.uk"]}
    )
    results = check_dmarc("shop.example.co.uk", dns)
    assert results[0].evidence["policy_domain"] == "example.co.uk"
    assert results[0].evidence["effective_policy"] == "none"
    assert results[0].status == Status.WARNING
    assert results[1].status == Status.PASSED
    assert all(record_type == "TXT" for _, record_type in dns.queries)


def test_dkim_never_guesses_selectors(fake_dns):
    dns = fake_dns()
    result = check_dkim("example.com", [], dns)[0]
    assert result.status == Status.UNKNOWN
    assert dns.queries == []
    result = check_dkim("example.com", ["explicit"], dns)[0]
    assert result.status == Status.UNKNOWN
    assert dns.queries == [("explicit._domainkey.example.com", "TXT")]


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("v=DKIM1; p=", Status.WARNING),
        ("v=DKIM1; p=%%%", Status.FAILED),
        ("v=DKIM1; p=YWJj", Status.PASSED),
        ("v=DKIM1; k=ed25519; p=YWJj", Status.FAILED),
    ],
)
def test_dkim_key_states(fake_dns, policy, expected):
    dns = fake_dns({("s1._domainkey.example.com", "TXT"): [policy]})
    result = check_dkim("example.com", ["s1"], dns)[0]
    assert result.status == expected
    assert result.scoreable is False


def test_null_mx_conflict_and_caa_scope(fake_dns):
    dns = fake_dns({("example.com", "MX"): ["0 .", "10 mail.example.com."]})
    results = check_dns("example.com", dns)
    assert results[1].status == Status.FAILED
    assert "Parent/CNAME" in results[2].explanation.en
