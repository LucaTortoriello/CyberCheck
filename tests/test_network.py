from unittest.mock import Mock

import httpcore
import httpx
import pytest

from cybercheck.core.config import Budget, LimitReached, Settings
from cybercheck.core.dns import DNSResult
from cybercheck.core.network import WebClient
from cybercheck.core.transport import DeadlineStream, PinnedTransport
from cybercheck.core.validation import UnsafeTarget


def dns_for(fake_dns, extra=None):
    return fake_dns({("example.com", "A"): ["8.8.8.8"]} | (extra or {}))


def test_requests_pin_ip_and_keep_host_and_sni(fake_dns):
    dns = dns_for(fake_dns)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/html"})

    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    response = web.fetch("https://example.com/path?q=1", "example.com")
    assert requests[0].url.host == "8.8.8.8"
    assert requests[0].headers["host"] == "example.com"
    assert requests[0].extensions["sni_hostname"] == "example.com"
    assert requests[0].method == "HEAD"
    assert response.url == "https://example.com/path?q=1"
    web.close()


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1",
        "https://evil.com/",
        "https://example.com:8443",
        "http://example.com/",
        "https://internal.example.com/",
    ],
)
def test_redirect_attacks_blocked_before_second_request(fake_dns, target):
    dns = dns_for(fake_dns, {("internal.example.com", "A"): ["10.0.0.1"]})
    handler = Mock(return_value=httpx.Response(302, headers={"location": target}))
    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    with pytest.raises(UnsafeTarget):
        web.fetch("https://example.com/", "example.com")
    assert handler.call_count == 1
    web.close()


def test_mixed_public_private_answer_fails_closed(fake_dns):
    dns = dns_for(fake_dns, {("example.com", "AAAA"): ["::1"]})
    handler = Mock()
    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    with pytest.raises(UnsafeTarget):
        web.fetch("https://example.com/", "example.com")
    handler.assert_not_called()
    web.close()


def test_unresolved_family_fails_closed(fake_dns):
    dns = dns_for(
        fake_dns, {("example.com", "AAAA"): DNSResult("example.com", "AAAA", "error", error="SERVFAIL")}
    )
    with pytest.raises(OSError):
        dns.public_addresses("example.com")


def test_rebinding_between_hops_revalidated(fake_dns):
    dns = dns_for(fake_dns)
    handler = Mock()

    def rebind(request):
        dns.mapping[("example.com", "A")] = ["169.254.169.254"]
        return httpx.Response(302, headers={"location": "/next"})

    handler.side_effect = rebind
    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    with pytest.raises(UnsafeTarget):
        web.fetch("https://example.com/", "example.com")
    assert handler.call_count == 1
    web.close()


def test_redirect_budget(fake_dns):
    dns = dns_for(fake_dns)
    handler = Mock(return_value=httpx.Response(302, headers={"location": "/loop"}))
    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    with pytest.raises(LimitReached):
        web.fetch("https://example.com/", "example.com")
    assert handler.call_count == dns.budget.settings.max_redirects + 1
    web.close()


def test_core_transport_offline_protocol_path():
    budget = Budget(Settings())
    backend = httpcore.MockBackend(
        [b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 999\r\n\r\n"]
    )
    transport = PinnedTransport(budget, backend)
    with httpx.Client(transport=transport) as client:
        response = client.head("https://8.8.8.8/", extensions={"sni_hostname": "example.com"})
        assert response.status_code == 200
        assert response.content == b""


def test_header_cap_and_global_deadline(monkeypatch):
    budget = Budget(Settings())
    underlying = Mock()
    underlying.read.side_effect = lambda max_bytes, timeout: b"x" * max_bytes
    stream = DeadlineStream(underlying, budget)
    assert len(stream.read(100000)) == 65536
    with pytest.raises(httpcore.RemoteProtocolError):
        stream.read(1)
    fresh = DeadlineStream(Mock(), budget)
    budget.started -= 100
    with pytest.raises(LimitReached):
        fresh.read(1)


def test_dns_and_http_budgets():
    budget = Budget(Settings(max_dns=8, max_http=2))
    for _ in range(8):
        budget.consume("dns")
    with pytest.raises(LimitReached):
        budget.consume("dns")
    for _ in range(2):
        budget.consume("http")
    with pytest.raises(LimitReached):
        budget.consume("http")


def test_shared_hosting_tenants_are_different_redirect_scopes(fake_dns):
    dns = fake_dns({("alice.github.io", "A"): ["8.8.8.8"], ("bob.github.io", "A"): ["8.8.4.4"]})
    handler = Mock(return_value=httpx.Response(302, headers={"location": "https://bob.github.io/"}))
    web = WebClient(dns, dns.budget, httpx.MockTransport(handler))
    with pytest.raises(UnsafeTarget):
        web.fetch("https://alice.github.io/", "alice.github.io")
    assert handler.call_count == 1
    web.close()


def test_transport_maps_network_errors():
    backend = Mock()
    backend.connect_tcp.side_effect = httpcore.ConnectTimeout("synthetic timeout")
    with httpx.Client(transport=PinnedTransport(Budget(Settings()), backend)) as client:
        with pytest.raises(httpx.TimeoutException):
            client.head("https://8.8.8.8/")
    backend.connect_tcp.side_effect = httpcore.ConnectError("synthetic refusal")
    with httpx.Client(transport=PinnedTransport(Budget(Settings()), backend)) as client:
        with pytest.raises(httpx.TransportError):
            client.head("https://8.8.8.8/")
