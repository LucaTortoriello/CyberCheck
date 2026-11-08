"""All tests are offline. Unexpected DNS or outbound sockets fail the test."""

import socket
from unittest.mock import Mock

import dns.resolver
import pytest

from cybercheck.core.config import Budget, Settings
from cybercheck.core.dns import DNSClient, DNSResult


class FakeDNS(DNSClient):
    def __init__(self, mapping=None):
        self.budget = Budget(Settings())
        self.mapping = mapping or {}
        self.queries = []

    def query(self, name, record_type):
        self.queries.append((name, record_type))
        self.budget.consume("dns")
        value = self.mapping.get((name, record_type), [])
        if isinstance(value, DNSResult):
            return value
        return DNSResult(name, record_type, "ok" if value else "absent", value)


@pytest.fixture(autouse=True)
def no_live_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Live network calls are forbidden in the test suite")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", blocked)


@pytest.fixture
def fake_dns():
    return FakeDNS


@pytest.fixture
def resolver():
    return Mock()
