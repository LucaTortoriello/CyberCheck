"""Optional, unverified service context. No network activity or provider inference."""

from dataclasses import asdict, dataclass

from cybercheck.models import Assessment, Finding, Text
from cybercheck.models import Severity as S
from cybercheck.models import Status as T

SCORING_PROFILE = "context-v1"


@dataclass(frozen=True)
class AssessmentContext:
    sends_email: bool | None = None
    receives_email: bool | None = None
    controls_dns: bool | None = None

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if value is not None and type(value) is not bool:
                raise ValueError(f"{name} must be True, False or None (unknown)")

    def evidence(self) -> dict:
        return asdict(self) | {"source": "user_declared", "independently_verified": False}


def applicability(f: Finding, context: AssessmentContext) -> dict:
    """Relevance of the limited criterion/action, independent of result status."""
    state, basis = "unknown", "unknown"
    reason = Text(
        "Service requirements are unknown; relevance is conditional. No vulnerability is established by absence alone.",
        "I requisiti del servizio sono sconosciuti; la rilevanza è condizionale. La sola assenza non dimostra una vulnerabilità.",
    )
    if f.category == "email" or f.check_id == "dns.mx":
        receiving = f.check_id == "dns.mx"
        declared = context.receives_email if receiving else context.sends_email
        if declared is not None:
            state, basis = "applicable" if declared else "not_applicable", "user_declared"
            reason = Text(
                "Relevance to receiving email follows the user's unverified declaration. This does not establish sending behavior."
                if receiving
                else "Relevance to sending email follows the user's unverified declaration. Non-senders may still benefit from anti-impersonation policies; this result does not establish spoofing resistance.",
                "La rilevanza per la ricezione email segue la dichiarazione non verificata dell'utente. Questo non accerta il comportamento di invio."
                if receiving
                else "La rilevanza per l'invio email segue la dichiarazione non verificata dell'utente. Anche i non mittenti possono beneficiare di policy contro le impersonificazioni; questo risultato non accerta la resistenza allo spoofing.",
            )
    elif f.category == "tls" or f.check_id in {"dns.records", "http.https", "http.application"}:
        state, basis = "applicable", "observed_scope"
        reason = Text(
            "Applicable to the explicitly tested criterion and endpoint only; a passed result does not cover untested behavior.",
            "Applicabile solo al criterio e all'endpoint verificati; un risultato superato non copre comportamenti non testati.",
        )
    elif f.check_id == "http.redirect" and f.status in {T.PASSED, T.WARNING}:
        state, basis = "applicable", "observed_response"
        reason = Text(
            "An HTTP response established the observed upgrade/plaintext behavior for this URL only.",
            "Una risposta HTTP ha accertato il comportamento di passaggio a HTTPS o in chiaro solo per questo URL.",
        )
    elif f.category == "headers":
        if f.status == T.NA:
            state, basis = "not_applicable", "observed_content_type"
            reason = Text(
                "This document-level criterion does not apply to the observed non-HTML response.",
                "Questo criterio a livello di documento non si applica alla risposta non HTML osservata.",
            )
        elif f.status != T.UNKNOWN and f.check_id in {"headers.hsts", "headers.nosniff", "headers.csp"}:
            if f.evidence.get("content_type") in {"text/html", "application/xhtml+xml"}:
                state, basis = "applicable", "observed_content_type"
                reason = Text(
                    "Optional browser hardening for the observed HTML response; absence is not proof of exploitation.",
                    "Misura facoltativa di difesa browser per la risposta HTML osservata; l'assenza non prova uno sfruttamento.",
                )
    if f.check_id == "dns.caa":
        reason = Text(
            "CAA is optional. Exact-name presence or absence does not establish the effective inherited issuance policy.",
            "CAA è facoltativo. La presenza o assenza al nome esatto non accerta la policy di emissione effettiva ereditata.",
        )
    return {"state": state, "basis": basis, "reason": asdict(reason)}


def apply_context(assessment: Assessment, context: AssessmentContext) -> None:
    """Annotate a new run only; never called when loading or exporting history."""
    assessment.metadata |= {"context": context.evidence(), "scoring_profile": SCORING_PROFILE}
    for f in assessment.findings:
        f.evidence["applicability"] = applicability(f, context)
        # Persist eligibility so schema-v1 readers also exclude conditional criteria.
        if f.applicability != "applicable" or f.category == "headers":
            f.scoreable = False
        if f.check_id in {"email.spf", "email.dmarc"} and f.status == T.WARNING:
            # Absence has no established operational importance without sending context.
            absent = (
                not f.evidence.get("spf_records")
                if f.check_id == "email.spf"
                else not f.evidence.get("dmarc_records")
            )
            if absent:
                f.severity = S.LOW if context.sends_email is True else S.INFO
        if f.category in {"dns", "email"}:
            control_note = Text(
                "DNS control was declared absent; ask the responsible DNS administrator or platform operator to review any proposed change."
                if context.controls_dns is False
                else "DNS control was declared by the user but was not independently verified; confirm permissions before changes."
                if context.controls_dns is True
                else "DNS control is unknown; identify the responsible administrator or platform operator before changes.",
                "Il controllo DNS è dichiarato assente; chiedi all'amministratore DNS o al gestore della piattaforma di valutare ogni modifica proposta."
                if context.controls_dns is False
                else "Il controllo DNS è dichiarato dall'utente ma non verificato indipendentemente; conferma i permessi prima delle modifiche."
                if context.controls_dns is True
                else "Il controllo DNS è sconosciuto; identifica l'amministratore o il gestore della piattaforma responsabile prima delle modifiche.",
            )
            f.remediation = Text(
                f.remediation.en + " " + control_note.en, f.remediation.it + " " + control_note.it
            )
