"""Public-target-only input and destination validation."""

import ipaddress
import re
from urllib.parse import urlsplit

import idna


class UnsafeTarget(ValueError):
    pass


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253 or any(c in value for c in "/:@?#\\%"):
        raise UnsafeTarget("Enter a domain only, without URL, credentials, path, or port")
    try:
        domain = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError) as exc:
        raise UnsafeTarget("Invalid internationalized domain") from exc
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise UnsafeTarget("IP addresses are not accepted")
    labels = domain.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise UnsafeTarget("A valid fully qualified domain is required")
    if labels[-1].isdigit() or labels[-1] in {
        "localhost",
        "local",
        "internal",
        "lan",
        "home",
        "invalid",
        "test",
        "onion",
    }:
        raise UnsafeTarget("Local, reserved, and non-public domain suffixes are blocked")
    return domain


def normalize_selectors(value: str | list[str]) -> list[str]:
    parts = re.split(r"[,\s]+", value.strip()) if isinstance(value, str) else value
    result: list[str] = []
    for selector in filter(None, parts):
        if len(selector) > 128 or not all(
            re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?", label)
            for label in selector.split(".")
        ):
            raise UnsafeTarget("Invalid DKIM selector")
        selector = selector.lower()
        if selector not in result:
            result.append(selector)
    if len(result) > 5:
        raise UnsafeTarget("At most five explicit DKIM selectors are allowed")
    return result


def public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsafeTarget("Invalid destination address") from exc
    # Reject transition mechanisms and mapped IPv4 to avoid alternate private routes.
    if (
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or getattr(address, "ipv4_mapped", None)
        or getattr(address, "sixtofour", None)
        or getattr(address, "teredo", None)
        or address in ipaddress.ip_network("64:ff9b::/96")
    ):
        raise UnsafeTarget("Non-public or transition destination blocked")
    return str(address)


def validate_url(url: str) -> tuple[str, str, str]:
    if len(url) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
        raise UnsafeTarget("Invalid redirect URL")
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or parts.username is not None or parts.password is not None:
            raise UnsafeTarget("Only HTTP(S), without credentials, is allowed")
        expected = 443 if parts.scheme == "https" else 80
        if parts.port not in (None, expected):
            raise UnsafeTarget("Nonstandard ports are blocked")
        host = normalize_domain(parts.hostname or "")
    except ValueError as exc:
        raise UnsafeTarget(str(exc)) from exc
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, host, path
