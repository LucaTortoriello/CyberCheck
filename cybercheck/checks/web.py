"""HTTPS reachability and bounded HTTP-to-HTTPS behavior."""

from urllib.parse import urlsplit

import httpx

from cybercheck.checks.headers import check_headers
from cybercheck.core.config import LimitReached
from cybercheck.core.evidence import network_error
from cybercheck.core.network import WebClient
from cybercheck.core.validation import UnsafeTarget
from cybercheck.locales.findings import finding
from cybercheck.models import Finding, Text
from cybercheck.models import Severity as S
from cybercheck.models import Status as T


def check_web(domain: str, web: WebClient) -> list[Finding]:
    findings: list[Finding] = []
    response = None
    error = None
    try:
        response = web.fetch(f"https://{domain}/", domain)
    except (httpx.HTTPError, OSError, UnsafeTarget, LimitReached) as exc:
        error = network_error(exc) | {"method": "HEAD", "hops": list(web.last_hops)}

    selected = response
    unsupported = response is not None and response.status_code in {405, 501}
    fallback = {"state": "not_needed" if response else "skipped_no_response"}
    en = (
        f"HEAD returned HTTP {response.status_code}. "
        if response
        else "HEAD request could not be completed. "
    )
    it = (
        f"HEAD ha restituito HTTP {response.status_code}. " if response else "Richiesta HEAD non completata. "
    )
    if unsupported:
        en += "HEAD may be unsupported. "
        it += "HEAD potrebbe non essere supportato. "
        if not web.budget.settings.allow_get_fallback:
            fallback = {"state": "disabled"}
            en += "GET fallback skipped: explicit authorization was not enabled. "
            it += "Fallback GET saltato: autorizzazione esplicita non abilitata. "
        else:
            # One fallback chain only. HEAD and GET share the redirect allowance,
            # DNS/HTTP counters and deadline; start at the validated final HEAD URL.
            selected = None
            try:
                selected = web.fetch(
                    response.url,
                    domain,
                    method="GET",
                    max_redirects=web.budget.settings.max_redirects - (len(response.hops) - 1),
                )
                fallback = {
                    "state": "succeeded" if 200 <= selected.status_code < 300 else "non_success",
                    "status_code": selected.status_code,
                    "hops": selected.hops,
                }
                en += f"GET fallback attempted after HEAD {response.status_code}; returned HTTP {selected.status_code}. "
                it += f"Fallback GET tentato dopo HEAD {response.status_code}; restituito HTTP {selected.status_code}. "
            except (httpx.HTTPError, OSError, UnsafeTarget, LimitReached) as exc:
                error = network_error(exc) | {"method": "GET", "hops": list(web.last_hops)}
                fallback = {"state": "blocked" if isinstance(exc, UnsafeTarget) else "unsuccessful"} | error
                en += "GET fallback attempted but blocked or unsuccessful; no eligible response obtained. "
                it += "Fallback GET tentato ma bloccato o non riuscito; nessuna risposta idonea ottenuta. "
    else:
        en += "GET fallback skipped: " + (
            "HEAD did not return 405/501. " if response else "no HEAD response. "
        )
        it += "Fallback GET saltato: " + (
            "HEAD non ha restituito 405/501. " if response else "nessuna risposta HEAD. "
        )

    eligible = selected is not None and 200 <= selected.status_code < 300
    observation = {
        "head_status_code": response.status_code if response else None,
        "head_unsupported": unsupported,
        "get_fallback": fallback,
        "security_headers": "evaluated_where_applicable" if eligible else "inconclusive",
    }
    evidence = (selected.evidence() if selected else error or {}) | {"http_observation": observation}
    findings.append(
        finding(
            "http.https",
            T.PASSED if response else T.UNKNOWN,
            S.INFO,
            (
                "HTTPS connection established and an HTTP response received; this alone does not establish application availability. "
                if response
                else "HTTPS connectivity is inconclusive, not proven absent or insecure. "
            )
            + en,
            (
                "Connessione HTTPS stabilita e risposta HTTP ricevuta; questo da solo non dimostra la disponibilità applicativa. "
                if response
                else "Connettività HTTPS inconcludente, non dimostrata assente o insicura. "
            )
            + it,
            (response.evidence() if response else error or {}) | {"http_observation": observation},
        )
    )
    findings.append(
        finding(
            "http.application",
            T.PASSED if eligible else T.UNKNOWN,
            S.INFO,
            en
            + (
                "A successful application response was observed for this method and URL; full application functionality was not tested. "
                if eligible
                else "Application availability is inconclusive; HTTP errors alone do not establish a security vulnerability. "
            )
            + (
                "Security headers evaluated where applicable."
                if eligible
                else "Security headers are inconclusive."
            ),
            it
            + (
                "Osservata una risposta applicativa riuscita per questo metodo e URL; il funzionamento completo non è stato verificato. "
                if eligible
                else "Disponibilità applicativa inconcludente; gli errori HTTP da soli non dimostrano una vulnerabilità. "
            )
            + (
                "Intestazioni di sicurezza valutate dove applicabili."
                if eligible
                else "Intestazioni di sicurezza inconcludenti."
            ),
            evidence,
        )
    )
    for header in check_headers(selected, error):
        header.explanation = Text(en + header.explanation.en, it + header.explanation.it)
        header.evidence |= {"http_observation": observation}
        findings.append(header)
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
