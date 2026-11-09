"""Regressions for confirmed v0.2 security findings. No live targets."""

import json
from unittest.mock import Mock, patch

import httpx
import pytest

from cybercheck.cli import main
from cybercheck.core.network import WebClient
from cybercheck.core.validation import UnsafeTarget, public_ip
from cybercheck.models import Assessment
from cybercheck.reports.render import render_html, render_json


def test_http_upgrade_can_never_downgrade_later(fake_dns):
    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
    requests = []

    def respond(request):
        requests.append(request)
        destination = "https://example.com/secure" if len(requests) == 1 else "http://example.com/plain"
        return httpx.Response(302, headers={"location": destination})

    with_client = WebClient(dns, dns.budget, httpx.MockTransport(respond))
    try:
        with pytest.raises(UnsafeTarget):
            with_client.fetch("http://example.com/", "example.com")
        assert len(requests) == 2
    finally:
        with_client.close()


@pytest.mark.parametrize("address", ["4000::1", "2001:4860::8888%lo0", "192.88.99.1", "3fff::1"])
def test_reserved_scoped_and_special_purpose_addresses_are_blocked(address):
    with pytest.raises(UnsafeTarget):
        public_ip(address)


def test_cookie_and_redirect_token_do_not_enter_reports(fake_dns):
    from cybercheck.checks.web import check_web

    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})

    def respond(request):
        if request.url.path == "/":
            return httpx.Response(
                302,
                headers={
                    "location": "/landing?token=secret-url-sentinel",
                    "set-cookie": "session=secret-cookie-sentinel",
                },
            )
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "set-cookie": "session=secret-cookie-sentinel",
                "x-custom-token": "secret-custom-sentinel",
            },
        )

    web = WebClient(dns, dns.budget, httpx.MockTransport(respond))
    try:
        findings = check_web("example.com", web)
    finally:
        web.close()
    a = Assessment("example.com", findings=findings)
    serialized = json.dumps(a.to_dict()) + render_json(a) + render_html(a)
    for secret in ("secret-url-sentinel", "secret-cookie-sentinel", "secret-custom-sentinel"):
        assert secret not in serialized
    assert "content-type" in serialized


def test_cli_will_not_follow_existing_report_symlink(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "db.sqlite3"))
    output = tmp_path / "exports"
    output.mkdir()
    a = Assessment("example.com", authorization_confirmed=True)
    victim = tmp_path / "unrelated.txt"
    victim.write_text("preserve me")
    report = output / f"cybercheck-{a.domain}-{a.id[:8]}.html"
    report.symlink_to(victim)
    monkeypatch.setattr("sys.argv", ["cybercheck", "example.com", "--authorized", "--output", str(output)])
    with patch("cybercheck.cli.run_assessment", return_value=a):
        with pytest.raises(SystemExit):
            main()
    assert victim.read_text() == "preserve me"


def test_log_formatter_does_not_leak_exception_message():
    import logging
    import sys

    from cybercheck.core.logging import JSONFormatter

    try:
        raise RuntimeError("secret-exception-sentinel")
    except RuntimeError:
        record = logging.LogRecord(
            "cybercheck", logging.ERROR, __file__, 1, "module_error", (), sys.exc_info()
        )
    output = JSONFormatter().format(record)
    assert "RuntimeError" in output
    assert "secret-exception-sentinel" not in output


def test_network_exception_message_not_persisted(fake_dns):
    from cybercheck.checks.web import check_web

    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
    handler = Mock(side_effect=httpx.ConnectError("secret-network-sentinel"))
    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    try:
        observations = check_web("example.com", web)
    finally:
        web.close()
    assert "secret-network-sentinel" not in json.dumps([f.evidence for f in observations])


def test_database_path_cannot_follow_a_final_symlink(tmp_path):
    from cybercheck.storage.sqlite import Repository

    victim = tmp_path / "unrelated.txt"
    victim.write_text("preserve me")
    link = tmp_path / "history.sqlite3"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        Repository(link)
    assert victim.read_text() == "preserve me"


def test_legacy_web_history_is_redacted_on_export_without_rewriting_source():
    from cybercheck.locales.findings import finding
    from cybercheck.models import Severity, Status

    a = Assessment(
        "example.com",
        findings=[
            finding(
                "http.https",
                Status.PASSED,
                Severity.INFO,
                "en",
                "it",
                {
                    "url": "https://user:secret-legacy-credentials@example.com/path?token=secret-legacy-query#secret-legacy-fragment",
                    "headers": {"set-cookie": "secret-legacy-cookie", "content-type": "text/html"},
                },
            )
        ],
    )
    output = render_json(a) + render_html(a)
    assert "secret-legacy" not in output
    assert a.findings[0].evidence["headers"]["set-cookie"] == "secret-legacy-cookie"
