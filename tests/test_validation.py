import pytest

from cybercheck.core.validation import (
    UnsafeTarget,
    normalize_domain,
    normalize_selectors,
    public_ip,
    validate_url,
)


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "x.local",
        "127.0.0.1",
        "2130706433",
        "[::1]",
        "https://example.com",
        "example.com:443",
        "user@example.com",
        "example.com/x",
        "example.com\n.evil",
        "-x.example",
        "example.123",
        "a..com",
        "foo.test",
        "example.com%00",
    ],
)
def test_reject_unsafe_domains(value):
    with pytest.raises(UnsafeTarget):
        normalize_domain(value)


def test_domain_and_selector_normalization():
    assert normalize_domain(" BÜCHER.DE. ") == "xn--bcher-kva.de"
    assert normalize_selectors("S1, s2 S1") == ["s1", "s2"]
    assert normalize_selectors("a.b, foo_bar") == ["a.b", "foo_bar"]


@pytest.mark.parametrize("value", ["x;ls", "a/../../", ".bad", "a" * 64, "a,b,c,d,e,f"])
def test_bad_selectors(value):
    with pytest.raises(UnsafeTarget):
        normalize_selectors(value)


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2002:0808:0808::1",
        "ff02::1",
    ],
)
def test_nonpublic_addresses_rejected(value):
    with pytest.raises(UnsafeTarget):
        public_ip(value)


def test_public_addresses():
    assert public_ip("8.8.8.8") == "8.8.8.8"
    assert public_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:22/",
        "https://example.com:80/",
        "file:///etc/passwd",
        "http://127.0.0.1/",
        "https://user:pass@example.com",
        "https://example.com\\@evil.com",
        "https://example.com/\r\nHost:evil",
    ],
)
def test_redirect_validation(url):
    with pytest.raises(UnsafeTarget):
        validate_url(url)


def test_standard_ports_and_paths():
    assert validate_url("https://example.com:443/a?q=b#c") == ("https", "example.com", "/a?q=b")
