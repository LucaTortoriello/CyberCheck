"""HTTPS reachability and bounded HTTP-to-HTTPS behavior."""

from urllib.parse import urlsplit

import httpx

from cybercheck.checks.headers import check_headers
from cybercheck.core.config import LimitReached
from cybercheck.core.evidence import network_error
from cybercheck.core.network import WebClient
from cybercheck.core.validation import UnsafeTarget
from cybercheck.locales.findings import finding
from cybercheck.models import Finding
from cybercheck.models import Severity as S
from cybercheck.models import Status as T


def check_web(domain: str, web: WebClient) -> list[Finding]:
    findings: list[Finding] = []
    response = None
    error = None
    try:
        response = web.fetch(f"https://{domain}/", domain)
        findings.append(
            finding(
                "http.https",
                T.PASSED,
                S.INFO,
                "An HTTPS HEAD response was received. HTTP status is evidence of application behavior, not a security rating.",
                "Ricevuta una risposta HEAD HTTPS. Lo stato HTTP descrive il comportamento applicativo, non un giudizio di sicurezza.",
                response.evidence(),
            )
        )
    except (httpx.HTTPError, OSError, UnsafeTarget, LimitReached) as exc:
        error = network_error(exc)
        findings.append(
            finding(
                "http.https",
                T.UNKNOWN,
                S.INFO,
                "HTTPS request could not be completed; HTTPS is not proven absent or insecure.",
                "Richiesta HTTPS non completata; non prova che HTTPS sia assente o insicuro.",
                error | {"hops": list(web.last_hops)},
            )
        )
    findings.extend(check_headers(response, error))
    try:
        redirected = web.fetch(f"http://{domain}/", domain)
        upgraded = urlsplit(redirected.url).scheme == "https"
        ambiguous = not upgraded and not 200 <= redirected.status_code < 300
        status = T.PASSED if upgraded else T.UNKNOWN if ambiguous else T.WARNING
        findings.append(
            finding(
                "http.redirect",
                status,
                S.INFO if upgraded or ambiguous else S.LOW,
                "HTTP redirected to verified HTTPS within the permitted scope."
                if upgraded
                else "HTTP returned a non-success response without a verified HTTPS upgrade; redirect behavior is inconclusive."
                if ambiguous
                else "HTTP returned successful content without an HTTPS upgrade. First-visit plaintext exposure may remain.",
                "HTTP ha reindirizzato a HTTPS verificato nell'ambito consentito."
                if upgraded
                else "HTTP ha risposto senza successo e senza passaggio HTTPS verificato; comportamento inconcludente."
                if ambiguous
                else "HTTP ha restituito contenuto con successo senza passare a HTTPS. Può restare esposta la prima visita in chiaro.",
                redirected.evidence(),
            )
        )
    except (httpx.HTTPError, OSError, UnsafeTarget, LimitReached) as exc:
        findings.append(
            finding(
                "http.redirect",
                T.UNKNOWN,
                S.INFO,
                "HTTP redirect behavior could not be established. Closed port 80 can be intentional.",
                "Comportamento del redirect HTTP non accertato. La porta 80 chiusa può essere intenzionale.",
                network_error(exc) | {"hops": list(web.last_hops)},
            )
        )
    return findings
