"""Sequential, bounded assessment orchestration. No UI or storage dependencies."""

import logging
from collections.abc import Callable

from cybercheck import __version__
from cybercheck.checks.email import check_dkim, check_dmarc, check_dns, check_spf
from cybercheck.checks.tls import check_tls
from cybercheck.checks.web import check_web
from cybercheck.core.config import Budget, Settings
from cybercheck.core.dns import DNSClient
from cybercheck.core.network import WebClient
from cybercheck.core.validation import normalize_domain, normalize_selectors
from cybercheck.locales.findings import finding
from cybercheck.models import Assessment, Severity, Status
from cybercheck.models.assessment import now

logger = logging.getLogger("cybercheck.engine")


def run_assessment(
    domain: str,
    selectors: str | list[str] = "",
    *,
    authorized: bool = False,
    settings: Settings | None = None,
    progress: Callable[[int, int, str], None] | None = None,
    dns: DNSClient | None = None,
    web: WebClient | None = None,
) -> Assessment:
    if not authorized:
        raise PermissionError("Confirm ownership or explicit authorization before assessing this domain")
    domain = normalize_domain(domain)
    selectors = normalize_selectors(selectors)
    # Validate the longest selector query before performing any network operations.
    if any(len(f"{selector}._domainkey.{domain}") > 253 for selector in selectors):
        raise ValueError("DKIM query name exceeds DNS length limit")
    settings = settings or (dns.budget.settings if dns else Settings.from_env())
    budget = dns.budget if dns else Budget(settings)
    dns = dns or DNSClient(budget)
    own_web = web is None
    web = web or WebClient(dns, budget)
    assessment = Assessment(
        domain=domain,
        selectors=selectors,
        authorization_confirmed=True,
        metadata={"engine_version": __version__, "mode": "public-target-only", "http_method": "HEAD"},
    )
    tasks = [
        ("dns", lambda: check_dns(domain, dns)),
        ("spf", lambda: check_spf(domain, dns)),
        ("dmarc", lambda: check_dmarc(domain, dns)),
        ("dkim", lambda: check_dkim(domain, selectors, dns)),
        ("tls", lambda: check_tls(domain, dns, budget)),
        ("http", lambda: check_web(domain, web)),
    ]
    logger.info("assessment_started", extra={"domain": domain, "assessment_id": assessment.id})
    try:
        for index, (name, task) in enumerate(tasks):
            if progress:
                progress(index, len(tasks), name)
            try:
                assessment.findings.extend(task())
            except Exception as exc:
                # Isolate unexpected module failures; preserve already collected evidence.
                logger.exception("module_error", extra={"check_module": name, "assessment_id": assessment.id})
                assessment.findings.append(
                    finding(
                        "engine.error",
                        Status.ERROR,
                        Severity.INFO,
                        "This module encountered an unexpected local execution error; no security conclusion is available.",
                        "Questo modulo ha incontrato un errore locale inatteso; nessuna conclusione di sicurezza disponibile.",
                        {"module": name, "error_type": type(exc).__name__},
                        suffix=f":{name}",
                    )
                )
        assessment.completed_at = now()
        assessment.metadata |= {
            "dns_queries": budget.dns,
            "http_requests": budget.http,
            "limits": {
                "dns": settings.max_dns,
                "http": settings.max_http,
                "redirects": settings.max_redirects,
                "seconds": settings.max_seconds,
            },
        }
        if progress:
            progress(len(tasks), len(tasks), "done")
    finally:
        if own_web:
            web.close()
    logger.info("assessment_completed", extra={"domain": domain, "assessment_id": assessment.id})
    return assessment
