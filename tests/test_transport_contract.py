"""Exercise the real HTTPX/httpcore adapter through public backend interfaces."""

import ssl
from collections import deque

import httpcore
import httpx
import pytest

from cybercheck.core.config import Budget, LimitReached, Settings
from cybercheck.core.transport import DeadlineBackend, DeadlineStream, PinnedTransport


class MemoryStream(httpcore.NetworkStream):
    def __init__(self, chunks, on_read=lambda: None):
        self.chunks = deque(chunks)
        self.on_read = on_read
        self.closed = False
        self.written = []
        self.tls = None
        self.timeouts = []

    def read(self, max_bytes, timeout=None):
        self.on_read()
        self.timeouts.append(timeout)
        if not self.chunks:
            return b""
        chunk = self.chunks.popleft()
        if len(chunk) > max_bytes:
            self.chunks.appendleft(chunk[max_bytes:])
        return chunk[:max_bytes]

    def write(self, buffer, timeout=None):
        self.timeouts.append(timeout)
        self.written.append(buffer)

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.tls = (ssl_context, server_hostname, timeout)
        return self

    def get_extra_info(self, info):
        return False if info == "is_readable" else None

    def close(self):
        self.closed = True


class MemoryBackend(httpcore.NetworkBackend):
    def __init__(self, stream):
        self.stream = stream
        self.connections = []

    def connect_tcp(self, host, port, **kwargs):
        self.connections.append((host, port, kwargs))
        return self.stream


def transport_for(budget, stream):
    backend = DeadlineBackend(budget)
    memory = MemoryBackend(stream)
    backend.backend = memory
    return PinnedTransport(budget, backend), memory


def test_original_hostname_and_verification_reach_actual_core_backend():
    budget = Budget(Settings())
    stream = MemoryStream([b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", b"never"])
    transport, backend = transport_for(budget, stream)
    with httpx.Client(transport=transport, trust_env=False) as client:
        response = client.head(
            "https://8.8.8.8/", headers={"Host": "example.com"}, extensions={"sni_hostname": "example.com"}
        )
        assert response.status_code == 200
    assert backend.connections[0][:2] == ("8.8.8.8", 443)
    context, hostname, timeout = stream.tls
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert hostname == "example.com"
    assert 0 < timeout <= budget.settings.timeout
    assert b"Host: example.com" in b"".join(stream.written)
    assert stream.chunks == deque([b"never"])  # HEAD body is never consumed.
    assert stream.closed


def test_slow_fragmented_headers_stop_at_shared_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("cybercheck.core.config.monotonic", lambda: clock[0])
    budget = Budget(Settings(max_seconds=10))

    def tick():
        clock[0] += 1.0

    stream = MemoryStream([b"HTTP/1.1 200 OK\r\n"] + [b"X" for _ in range(30)], tick)
    transport, _ = transport_for(budget, stream)
    with httpx.Client(transport=transport) as client:
        with pytest.raises(LimitReached):
            client.head("http://8.8.8.8/")
    assert clock[0] == 10
    assert stream.closed


def test_oversized_headers_are_stopped_and_socket_is_closed():
    stream = MemoryStream([b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 70000])
    transport, _ = transport_for(Budget(Settings()), stream)
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.TransportError):
            client.head("http://8.8.8.8/")
    assert stream.closed


def test_expired_deadline_before_tls_upgrade_closes_connected_socket():
    budget = Budget(Settings())
    stream = MemoryStream([])
    wrapped = DeadlineStream(stream, budget)
    budget.started -= 100
    with pytest.raises(LimitReached):
        wrapped.start_tls(ssl.create_default_context(), server_hostname="example.com")
    assert stream.closed


def test_backend_respects_a_shorter_caller_timeout():
    budget = Budget(Settings())
    stream = MemoryStream([b"x"])
    wrapped = DeadlineStream(stream, budget)
    wrapped.read(1, timeout=0.25)
    wrapped.write(b"HEAD /", timeout=0.5)
    assert stream.timeouts == [0.25, 0.5]
