import socket
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest

from cybercheck.checks.headers import check_headers
from cybercheck.checks.tls import check_tls
from cybercheck.checks.web import check_web
from cybercheck.core.network import WebClient, WebResponse
from cybercheck.models import Status


def response(headers=None, status=200):
    return WebResponse("https://example.com/", status, headers or {}, "8.8.8.8")


def by_key(findings):
    return {f.check_id: f for f in findings}


def test_headers_present_and_frame_ancestors_alternative():
    findings = by_key(
        check_headers(
            response(
                {
                    "content-type": "text/html; charset=utf-8",
                    "strict-transport-security": "max-age=31536000",
                    "x-content-type-options": "nosniff",
                    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                    "referrer-policy": "strict-origin-when-cross-origin",
                    "permissions-policy": "camera=(), microphone=()",
                }
            )
        )
    )
    assert all(f.status == Status.PASSED for f in findings.values())


def test_missing_headers_never_critical_or_confirmed_vulnerability():
    findings = check_headers(response({"content-type": "text/html"}))
    assert all(f.status == Status.WARNING for f in findings)
    assert all(f.severity.value not in {"critical", "high"} for f in findings)


def test_nonhtml_and_blocked_responses_are_not_failed():
    findings = by_key(check_headers(response({"content-type": "application/json"})))
    assert findings["headers.csp"].status == Status.NA
    assert all(f.status == Status.UNKNOWN for f in check_headers(response(status=403)))
    assert all(f.status == Status.UNKNOWN for f in check_headers(None, "timeout"))


@pytest.mark.parametrize(
    "csp", ["frame-ancestors *", "frame-ancestors garbage", "frame-ancestors *; frame-ancestors 'none'"]
)
def test_unrestricted_or_invalid_csp_overrides_xfo_conservatively(csp):
    findings = by_key(
        check_headers(
            response({"content-type": "text/html", "content-security-policy": csp, "x-frame-options": "DENY"})
        )
    )
    assert findings["headers.framing"].status == Status.WARNING


def tls_setup(fake_dns, monkeypatch):
    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
    raw = MagicMock()
    monkeypatch.setattr(socket, "create_connection", MagicMock(return_value=raw))
    context = MagicMock()
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    return dns, context


def test_verified_tls_collects_real_certificate_fields(fake_dns, monkeypatch):
    dns, context = tls_setup(fake_dns, monkeypatch)
    secured = context.wrap_socket.return_value.__enter__.return_value
    expiry = datetime.now(UTC) + timedelta(days=45)
    start = datetime.now(UTC) - timedelta(days=45)
    secured.getpeercert.return_value = {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore": start.strftime("%b %d %H:%M:%S %Y GMT"),
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.com"),),
    }
    secured.version.return_value = "TLSv1.3"
    secured.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    findings = by_key(check_tls("example.com", dns, dns.budget))
    assert all(f.status == Status.PASSED for f in findings.values())
    assert findings["tls.validity"].evidence["days_until_expiration"] in {44, 45}
    socket.create_connection.assert_called_once_with(("8.8.8.8", 443), timeout=pytest.approx(5, abs=0.01))
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"


@pytest.mark.parametrize(("code", "key"), [(10, "tls.validity"), (62, "tls.hostname"), (20, "tls.chain")])
def test_specific_certificate_failures_only_fail_proven_dimension(fake_dns, monkeypatch, code, key):
    dns, context = tls_setup(fake_dns, monkeypatch)
    exc = ssl.SSLCertVerificationError(1, "failed")
    exc.verify_code, exc.verify_message = code, "mock certificate failure"
    context.wrap_socket.side_effect = exc
    findings = by_key(check_tls("example.com", dns, dns.budget))
    assert findings[key].status == Status.FAILED
    assert sum(f.status == Status.FAILED for f in findings.values()) == 1
    assert all(f.status == Status.UNKNOWN for name, f in findings.items() if name != key)


def test_connection_timeout_does_not_prove_tls_insecurity(fake_dns, monkeypatch):
    dns, _ = tls_setup(fake_dns, monkeypatch)
    socket.create_connection.side_effect = TimeoutError("timed out")
    assert all(f.status == Status.UNKNOWN for f in check_tls("example.com", dns, dns.budget))


def test_http_upgrade_and_headers_offline(fake_dns):
    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})

    def handler(request):
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"})
        return httpx.Response(200, headers={"content-type": "text/html", "x-frame-options": "SAMEORIGIN"})

    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    findings = by_key(check_web("example.com", web))
    assert findings["http.redirect"].status == Status.PASSED
    assert findings["headers.framing"].status == Status.PASSED
    web.close()


def test_http_connection_errors_keep_headers_and_redirect_unknown(fake_dns):
    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})

    def fail(request):
        raise httpx.ConnectError("synthetic refusal", request=request)

    web = WebClient(dns, dns.budget, httpx.MockTransport(fail))
    findings = check_web("example.com", web)
    assert len(findings) == 8
    assert all(f.status == Status.UNKNOWN for f in findings)
    web.close()
