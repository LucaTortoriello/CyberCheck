"""Bounded DNS observations; absence and lookup errors remain distinct."""

from dataclasses import asdict, dataclass, field

import dns.exception
import dns.resolver

from cybercheck.core.config import Budget, LimitReached
from cybercheck.core.validation import UnsafeTarget, normalize_domain, public_ip


@dataclass
class DNSResult:
    name: str
    record_type: str
    state: str  # ok, absent, nxdomain, error
    records: list[str] = field(default_factory=list)
    error: str | None = None

    def evidence(self) -> dict:
        return asdict(self)


class DNSClient:
    def __init__(self, budget: Budget, resolver: dns.resolver.Resolver | None = None):
        self.budget = budget
        self.resolver = resolver or dns.resolver.Resolver()
        self.cache: dict[tuple[str, str], DNSResult] = {}

    def query(self, name: str, record_type: str) -> DNSResult:
        key = (name.lower().rstrip("."), record_type.upper())
        if key in self.cache:
            return self.cache[key]
        try:
            timeout = self.budget.consume("dns")
            answers = self.resolver.resolve(key[0] + ".", key[1], lifetime=timeout, search=False)
            records = []
            for answer in answers:
                if key[1] == "TXT":
                    records.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
                else:
                    records.append(answer.to_text())
            result = DNSResult(*key, "ok", records)
        except dns.resolver.NXDOMAIN:
            result = DNSResult(*key, "nxdomain")
        except dns.resolver.NoAnswer:
            result = DNSResult(*key, "absent")
        except (dns.exception.DNSException, OSError, LimitReached) as exc:
            result = DNSResult(*key, "error", error=f"{type(exc).__name__}: {exc}")
        self.cache[key] = result
        return result

    def public_addresses(self, hostname: str) -> list[str]:
        hostname = normalize_domain(hostname)
        answers = [self.query(hostname, kind) for kind in ("A", "AAAA")]
        # Fail closed even if only one family is unresolved.
        if any(a.state == "error" for a in answers):
            raise OSError("Destination DNS resolution incomplete")
        addresses = [public_ip(ip) for answer in answers for ip in answer.records]
        if not addresses:
            raise OSError("No public address records found")
        if any(a.state == "nxdomain" for a in answers):
            raise UnsafeTarget("Inconsistent destination DNS response")
        return list(dict.fromkeys(addresses))
