"""Pinned HTTP transport. Validate every hop, then connect to a literal IP.

HTTPX's documented sni_hostname extension preserves TLS hostname verification.
No proxy environment, cookies, authentication, retries, or response-body reads.
"""

from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin

import httpx
import tldextract

from cybercheck.core.config import Budget, LimitReached
from cybercheck.core.dns import DNSClient
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

    def evidence(self) -> dict:
        return asdict(self)


class WebClient:
    def __init__(self, dns: DNSClient, budget: Budget, transport: httpx.BaseTransport | None = None):
        self.dns = dns
        self.budget = budget
        self.client = httpx.Client(
            transport=transport or PinnedTransport(budget),
            trust_env=False,
            follow_redirects=False,
            headers={"User-Agent": "CyberCheck/0.1 (authorized configuration assessment)"},
        )

    def close(self) -> None:
        self.client.close()

    def fetch(self, url: str, scope: str) -> WebResponse:
        hops: list[dict] = []
        initial_scheme, _, _ = validate_url(url)
        for _ in range(self.budget.settings.max_redirects + 1):
            scheme, hostname, path = validate_url(url)
            if organizational_domain(hostname) != organizational_domain(scope):
                raise UnsafeTarget("Redirect outside the authorized organizational domain blocked")
            if initial_scheme == "https" and scheme != "https":
                raise UnsafeTarget("HTTPS downgrade redirect blocked")
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
                status = response.status_code
            hops.append({"url": url, "address": address, "status_code": status})
            if status not in {301, 302, 303, 307, 308}:
                return WebResponse(url, status, headers, address, hops)
            location = headers.get("location")
            if not location:
                raise OSError("Redirect response has no Location header")
            url = urljoin(url, location)
        raise LimitReached("Redirect limit reached")
