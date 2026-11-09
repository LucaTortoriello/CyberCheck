"""Pinned HTTP transport. Validate every hop, then connect to a literal IP.

HTTPX's documented sni_hostname extension preserves TLS hostname verification.
No proxy environment, cookies, authentication, retries, or response-body reads.
"""

from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin

import httpx
import tldextract

from cybercheck import __version__
from cybercheck.core.config import Budget, LimitReached
from cybercheck.core.dns import DNSClient
from cybercheck.core.evidence import EVIDENCE_HEADERS, redact_url, safe_headers
from cybercheck.core.transport import PinnedTransport
from cybercheck.core.validation import UnsafeTarget, validate_url

_suffixes = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)


def organizational_domain(domain: str) -> str:
    result = _suffixes(domain)
    return result.top_domain_under_public_suffix or domain


@dataclass
class WebResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    address: str
    hops: list[dict] = field(default_factory=list)
    method: str = "HEAD"
    header_values: dict[str, list[str]] = field(default_factory=dict)

    def values(self, name: str) -> list[str]:
        return self.header_values.get(
            name.lower(), [self.headers[name.lower()]] if name.lower() in self.headers else []
        )

    def evidence(self) -> dict:
        values = asdict(self)
        values["url"] = redact_url(self.url)
        values["headers"] = safe_headers(self.headers)
        values["header_values"] = {
            name.lower(): [safe_headers({name: value})[name.lower()] for value in entries]
            for name, entries in self.header_values.items()
            if name.lower() in EVIDENCE_HEADERS
        }
        values["hops"] = [dict(hop, url=redact_url(hop["url"])) for hop in self.hops]
        return values


class WebClient:
    def __init__(self, dns: DNSClient, budget: Budget, transport: httpx.BaseTransport | None = None):
        self.dns = dns
        self.budget = budget
        self.last_hops: list[dict] = []
        self.client = httpx.Client(
            transport=transport or PinnedTransport(budget),
            trust_env=False,
            follow_redirects=False,
            headers={"User-Agent": f"CyberCheck/{__version__} (authorized configuration assessment)"},
        )

    def close(self) -> None:
        self.client.close()

    def fetch(self, url: str, scope: str) -> WebResponse:
        hops: list[dict] = []
        self.last_hops = hops
        seen_https = False
        for _ in range(self.budget.settings.max_redirects + 1):
            scheme, hostname, path = validate_url(url)
            if organizational_domain(hostname) != organizational_domain(scope):
                raise UnsafeTarget("Redirect outside the authorized organizational domain blocked")
            if seen_https and scheme != "https":
                raise UnsafeTarget("HTTPS downgrade redirect blocked")
            seen_https |= scheme == "https"
            # Reject the entire DNS answer if any address is non-public.
            address = self.dns.public_addresses(hostname)[0]
            literal = f"[{address}]" if ":" in address else address
            pinned_url = f"{scheme}://{literal}{path}"
            timeout = self.budget.consume("http")
            self.client.cookies.clear()
            # HEAD is deliberately used throughout; no fallback GET or body download.
            with self.client.stream(
                "HEAD",
                pinned_url,
                headers={"Host": hostname},
                extensions={"sni_hostname": hostname},
                timeout=timeout,
            ) as response:
                headers = dict(response.headers)
                header_values = {
                    name: response.headers.get_list(name)
                    for name in EVIDENCE_HEADERS
                    if name in response.headers
                }
                status = response.status_code
            hops.append({"url": redact_url(url), "address": address, "status_code": status})
            if status not in {301, 302, 303, 307, 308}:
                safe_values = {
                    name: [safe_headers({name: value})[name] for value in entries]
                    for name, entries in header_values.items()
                }
                return WebResponse(
                    url, status, safe_headers(headers), address, hops, header_values=safe_values
                )
            location = headers.get("location")
            if not location:
                raise OSError("Redirect response has no Location header")
            url = urljoin(url, location)
        raise LimitReached("Redirect limit reached")
