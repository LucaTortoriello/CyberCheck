"""HEAD fallback regression coverage; synthetic DNS and response streams only."""

import json
from html import unescape
from unittest.mock import patch

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from cybercheck.checks.headers import HEADER_KEYS
from cybercheck.checks.web import check_web
from cybercheck.cli import main
from cybercheck.core.config import Budget, Settings
from cybercheck.core.engine import run_assessment
from cybercheck.core.network import WebClient
from cybercheck.models import Assessment, Status
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.sqlite import Repository

HEADERS = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=100",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
}


@pytest.fixture
def web_factory(fake_dns):
    clients = []

    def create(handler, *, enabled=True, **limits):
        dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
        dns.budget = Budget(Settings(allow_get_fallback=enabled, **limits))
        requests = []

        def record(request):
            requests.append(request)
            if request.url.scheme == "http":
                return httpx.Response(503)
            return handler(request, dns)

        web = WebClient(dns, dns.budget, httpx.MockTransport(record))
        clients.append(web)
        return web, requests

    yield create
    for client in clients:
        client.close()


def assess(web):
    return {f.check_id: f for f in check_web("example.com", web)}


def observation(findings):
    return findings["http.application"].evidence["http_observation"]


def assert_inconclusive(findings):
    assert findings["http.https"].status == Status.PASSED
    assert findings["http.application"].status == Status.UNKNOWN
    assert all(findings[key].status == Status.UNKNOWN for key in HEADER_KEYS)
    assert not any(f.status == Status.FAILED for f in findings.values())


@pytest.mark.parametrize("enabled", [False, True])
def test_head_200_never_uses_get(web_factory, enabled):
    web, requests = web_factory(lambda r, d: httpx.Response(200, headers=HEADERS), enabled=enabled)
    findings = assess(web)
    assert all(r.method == "HEAD" for r in requests)
    assert findings["http.application"].status == Status.PASSED
    assert observation(findings)["get_fallback"]["state"] == "not_needed"
    assert all(findings[key].evidence["method"] == "HEAD" for key in HEADER_KEYS)


@pytest.mark.parametrize("head_status", [405, 501])
@pytest.mark.parametrize("enabled", [False, True])
def test_unsupported_head_requires_opt_in_and_uses_get_headers(web_factory, head_status, enabled):
    web, requests = web_factory(
        lambda r, d: (
            httpx.Response(head_status) if r.method == "HEAD" else httpx.Response(200, headers=HEADERS)
        ),
        enabled=enabled,
    )
    findings = assess(web)
    assert [r.method for r in requests] == (["HEAD", "GET", "HEAD"] if enabled else ["HEAD", "HEAD"])
    assert observation(findings)["head_status_code"] == head_status
    assert observation(findings)["head_unsupported"]
    assert findings["http.https"].evidence["status_code"] == head_status
    if enabled:
        assert observation(findings)["get_fallback"]["state"] == "succeeded"
        assert findings["http.application"].status == Status.PASSED
        assert all(findings[key].status == Status.PASSED for key in HEADER_KEYS)
        assert all(findings[key].evidence["method"] == "GET" for key in HEADER_KEYS)
        get = requests[1]
        assert get.url.host == "8.8.8.8"
        assert get.headers["host"] == "example.com"
        assert get.extensions["sni_hostname"] == "example.com"
    else:
        assert_inconclusive(findings)
        assert observation(findings)["get_fallback"]["state"] == "disabled"


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_other_head_errors_are_not_vulnerabilities_and_do_not_trigger_get(web_factory, status):
    web, requests = web_factory(lambda r, d: httpx.Response(status, headers=HEADERS))
    findings = assess(web)
    assert_inconclusive(findings)
    assert all(r.method == "HEAD" for r in requests)
    assert not observation(findings)["head_unsupported"]


@pytest.mark.parametrize("outcome", [405, 501, 503, "timeout", "verification"])
def test_unsuccessful_get_remains_inconclusive_without_retry(web_factory, outcome):
    def handler(request, dns):
        if request.method == "HEAD":
            return httpx.Response(501, headers=HEADERS)
        if outcome == "timeout":
            raise httpx.ReadTimeout("synthetic timeout")
        if outcome == "verification":
            raise httpx.ConnectError("synthetic TLS verification failure")
        return httpx.Response(outcome, headers=HEADERS)

    web, requests = web_factory(handler)
    findings = assess(web)
    assert_inconclusive(findings)
    assert sum(r.method == "GET" for r in requests) == 1
    assert observation(findings)["get_fallback"]["state"] in {"non_success", "unsuccessful"}


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.com/",
        "http://example.com/",
        "https://127.0.0.1/",
        "https://example.com:8443/",
        "https://user:secret@example.com/",
        "https://internal.example.com/",
    ],
)
def test_get_redirect_policy_is_enforced_before_connection(web_factory, target):
    def handler(request, dns):
        dns.mapping[("internal.example.com", "A")] = ["10.0.0.1"]
        return (
            httpx.Response(501)
            if request.method == "HEAD"
            else httpx.Response(302, headers={"location": target})
        )

    web, requests = web_factory(handler)
    findings = assess(web)
    assert_inconclusive(findings)
    assert observation(findings)["get_fallback"]["state"] == "blocked"
    assert sum(r.method == "GET" for r in requests) == 1
    assert all(r.url.host == "8.8.8.8" for r in requests)


@pytest.mark.parametrize(("family", "address"), [("A", "169.254.169.254"), ("AAAA", "::1")])
def test_rebinding_before_fallback_is_blocked(web_factory, family, address):
    def handler(request, dns):
        dns.mapping[("example.com", family)] = [address]
        return httpx.Response(501)

    web, requests = web_factory(handler)
    findings = assess(web)
    assert_inconclusive(findings)
    assert observation(findings)["get_fallback"]["state"] == "blocked"
    assert [r.method for r in requests] == ["HEAD"]


def test_get_redirect_rebinding_is_blocked(web_factory):
    def handler(request, dns):
        if request.method == "GET":
            dns.mapping[("example.com", "A")] = ["10.0.0.1"]
            return httpx.Response(302, headers={"location": "/next"})
        return httpx.Response(501)

    web, requests = web_factory(handler)
    findings = assess(web)
    assert_inconclusive(findings)
    assert observation(findings)["get_fallback"]["state"] == "blocked"
    assert [r.method for r in requests] == ["HEAD", "GET"]


def test_get_cannot_redirect_between_render_tenants(fake_dns):
    dns = fake_dns({("alice.onrender.com", "A"): ["8.8.8.8"], ("bob.onrender.com", "A"): ["8.8.4.4"]})
    dns.budget = Budget(Settings(allow_get_fallback=True))
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "HEAD":
            return httpx.Response(501)
        return httpx.Response(302, headers={"location": "https://bob.onrender.com/"})

    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    try:
        findings = {f.check_id: f for f in check_web("alice.onrender.com", web)}
        assert_inconclusive(findings)
        assert observation(findings)["get_fallback"]["state"] == "blocked"
        assert sum(r.method == "GET" for r in requests) == 1
        assert all(r.url.host == "8.8.8.8" for r in requests)
    finally:
        web.close()


def test_valid_get_redirect_evaluates_final_response_without_cookies(web_factory):
    def handler(request, dns):
        assert not any(
            name in request.headers for name in ("cookie", "authorization", "proxy-authorization", "range")
        )
        if request.method == "HEAD":
            return httpx.Response(501, headers={"set-cookie": "session=secret; Secure"})
        if request.url.path == "/":
            return httpx.Response(
                302, headers={"location": "/final?q=secret", "set-cookie": "session=secret; Secure"}
            )
        return httpx.Response(200, headers=HEADERS)

    web, requests = web_factory(handler)
    findings = assess(web)
    assert findings["headers.hsts"].status == Status.PASSED
    assert findings["headers.hsts"].evidence["url"] == "https://example.com/final?redacted"
    assert [r.method for r in requests] == ["HEAD", "GET", "GET", "HEAD"]
    assert "secret" not in render_json(Assessment("example.com", findings=list(findings.values())))


@pytest.mark.parametrize("head_redirects", [0, 1])
def test_head_and_get_share_redirect_limit(web_factory, head_redirects):
    def handler(request, dns):
        if request.method == "HEAD" and (not head_redirects or request.url.path == "/canonical"):
            return httpx.Response(501)
        return httpx.Response(302, headers={"location": "/canonical"})

    web, requests = web_factory(handler, max_redirects=head_redirects)
    findings = assess(web)
    assert_inconclusive(findings)
    fallback = observation(findings)["get_fallback"]
    assert fallback["reason"] == "request_or_time_limit"
    assert sum(r.method == "GET" for r in requests) == 1


def test_get_consumes_existing_http_budget(web_factory):
    web, requests = web_factory(
        lambda r, d: httpx.Response(501) if r.method == "HEAD" else httpx.Response(200, headers=HEADERS),
        max_http=2,
    )
    findings = assess(web)
    assert findings["headers.hsts"].status == Status.PASSED
    assert web.budget.http == 2
    assert [r.method for r in requests] == ["HEAD", "GET"]
    assert findings["http.redirect"].status == Status.UNKNOWN


@pytest.mark.parametrize("exhaust", ["http", "dns", "time"])
def test_exhausted_budget_prevents_get(web_factory, exhaust):
    def handler(request, dns):
        if exhaust == "time":
            dns.budget.started -= 100
        else:
            setattr(dns.budget, exhaust, getattr(dns.budget.settings, f"max_{exhaust}"))
        return httpx.Response(501)

    web, requests = web_factory(handler)
    findings = assess(web)
    assert_inconclusive(findings)
    assert observation(findings)["get_fallback"]["reason"] == "request_or_time_limit"
    assert [r.method for r in requests] == ["HEAD"]


def test_get_uses_remaining_time_without_resetting_deadline(web_factory, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("cybercheck.core.config.monotonic", lambda: clock[0])

    def handler(request, dns):
        if request.method == "HEAD":
            clock[0] = 8.5
            return httpx.Response(501)
        return httpx.Response(200, headers=HEADERS)

    web, requests = web_factory(handler, max_seconds=10)
    assess(web)
    assert requests[0].extensions["timeout"]["read"] == 5
    assert requests[1].extensions["timeout"]["read"] == 1.5


class UnreadBody(httpx.SyncByteStream):
    closed = False

    def __iter__(self):
        raise AssertionError("Response body must not be read")

    def close(self):
        self.closed = True


def test_stream_body_is_closed_unread_and_not_persisted(web_factory, tmp_path):
    body = UnreadBody()
    web, requests = web_factory(
        lambda r, d: (
            httpx.Response(501) if r.method == "HEAD" else httpx.Response(200, headers=HEADERS, stream=body)
        ),
    )
    assessment = Assessment("example.com", findings=list(assess(web).values()))
    assert body.closed
    repo = Repository(tmp_path / "history.sqlite3")
    repo.save(assessment)
    loaded = repo.get(assessment.id)
    assert loaded.to_dict() == assessment.to_dict()
    assert "body" not in render_json(loaded)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("language", ["it", "en"])
def test_reports_explain_transport_application_and_fallback(web_factory, enabled, language):
    web, _ = web_factory(
        lambda r, d: httpx.Response(501) if r.method == "HEAD" else httpx.Response(200, headers=HEADERS),
        enabled=enabled,
    )
    a = Assessment("example.com", findings=list(assess(web).values()))
    html = unescape(render_html(a, language))
    assert ("HTTPS connection established" if language == "en" else "Connessione HTTPS stabilita") in html
    assert ("HTTP application response" if language == "en" else "Risposta HTTP applicativa") in html
    assert ("HEAD may be unsupported" if language == "en" else "HEAD potrebbe non essere supportato") in html
    if enabled:
        assert ("GET fallback attempted" if language == "en" else "Fallback GET tentato") in html
        assert (
            "Security headers evaluated" if language == "en" else "Intestazioni di sicurezza valutate"
        ) in html
    else:
        assert ("GET fallback skipped" if language == "en" else "Fallback GET saltato") in html
        assert (
            "Security headers are inconclusive"
            if language == "en"
            else "Intestazioni di sicurezza inconcludenti"
        ) in html
    report = json.loads(render_json(a))
    assert report["schema_version"] == 1
    assert Assessment.from_dict(report).to_dict() == a.to_dict()
    app = next(f for f in report["findings"] if f["check_id"] == "http.application")
    assert app["evidence"]["http_observation"]["get_fallback"]["state"] == (
        "succeeded" if enabled else "disabled"
    )
    assert "501" in app["explanation"]["en"] and "501" in app["explanation"]["it"]
    assert not report["summary"]["confirmed_finding_ids"]


def test_default_settings_do_not_authorize_get(web_factory):
    assert not Settings.from_env().allow_get_fallback
    web, requests = web_factory(lambda r, d: httpx.Response(200), enabled=False)
    with pytest.raises(ValueError):
        web.fetch("https://example.com/", "example.com", method="GET")
    assert not requests


@pytest.mark.parametrize("enabled", [False, True])
def test_cli_explicit_get_consent_reaches_engine(monkeypatch, tmp_path, enabled):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "db.sqlite3"))
    args = ["cybercheck", "example.com", "--authorized", "--output", str(tmp_path / "exports")]
    monkeypatch.setattr("sys.argv", args + (["--allow-get-fallback"] if enabled else []))
    with patch("cybercheck.cli.run_assessment", return_value=Assessment("example.com")) as run:
        assert main() == 0
    assert run.call_args.kwargs["settings"].allow_get_fallback is enabled


def test_ui_get_requires_separate_consent(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "ui.sqlite3"))
    with patch("cybercheck.app.dashboard.run_assessment", return_value=Assessment("example.com")) as run:
        app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
        app.radio(key="navigation").set_value("new").run()
        app.text_input[0].set_value("example.com")
        assert not app.checkbox[1].value
        app.checkbox[0].check()
        app.checkbox[1].check()
        app.button[0].click().run()
        assert not app.exception
    assert run.call_args.kwargs["settings"].allow_get_fallback


def test_engine_records_get_authorization_and_requests(web_factory):
    web, _ = web_factory(
        lambda r, d: httpx.Response(501) if r.method == "HEAD" else httpx.Response(200, headers=HEADERS),
    )
    with patch("cybercheck.checks.tls.socket.create_connection", side_effect=TimeoutError()):
        a = run_assessment("example.com", authorized=True, dns=web.dns, web=web)
    assert a.metadata["get_fallback_enabled"]
    assert a.metadata["http_requests"] == 3
    assert next(f for f in a.findings if f.check_id == "headers.hsts").evidence["method"] == "GET"
