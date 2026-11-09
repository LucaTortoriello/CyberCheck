"""HEAD-response browser policy observations, with explicit applicability."""

import re

from cybercheck.core.evidence import redact_url
from cybercheck.core.network import WebResponse
from cybercheck.locales.findings import finding
from cybercheck.models import Finding
from cybercheck.models import Severity as S
from cybercheck.models import Status as T

HEADER_KEYS = (
    "headers.hsts",
    "headers.csp",
    "headers.nosniff",
    "headers.referrer",
    "headers.permissions",
    "headers.framing",
)


def active_hsts_policy(value: str | None) -> bool:
    directives: dict[str, str | None] = {}
    parts: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for character in value or "":
        if character == ";" and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
        if escaped:
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
    if quoted or escaped:
        return False
    parts.append("".join(current))
    for part in parts:
        if not part.strip():
            continue
        match = re.fullmatch(
            r'([!#$%&\'*+.^_`|~0-9a-z-]+)(?:\s*=\s*([!#$%&\'*+.^_`|~0-9a-z-]+|"(?:\\.|[^"\\])*"))?',
            part.strip(),
            re.I,
        )
        if not match:
            return False
        name, argument = match.groups()
        name = name.lower()
        if name in directives:
            return False
        directives[name] = argument
    age = directives.get("max-age")
    if age is None or not re.fullmatch(r'(?:[0-9]+|"[0-9]+")', age):
        return False
    if "includesubdomains" in directives and directives["includesubdomains"] is not None:
        return False
    # A positive decimal needs no unbounded int conversion.
    return bool(age.strip('"').lstrip("0"))


def check_headers(response: WebResponse | None, error: dict | str | None = None) -> list[Finding]:
    if response is None or not 200 <= response.status_code < 300:
        evidence = response.evidence() if response else {"error": error}
        return [
            finding(
                key,
                T.UNKNOWN,
                S.INFO,
                "No successful HTTPS HEAD response available; application header configuration is unknown.",
                "Nessuna risposta HEAD HTTPS riuscita; configurazione delle intestazioni applicative sconosciuta.",
                evidence,
            )
            for key in HEADER_KEYS
        ]
    h = {key.lower(): value for key, value in response.headers.items()}
    content_type = h.get("content-type", "").split(";", 1)[0].strip().lower()
    html = content_type in {"text/html", "application/xhtml+xml"}
    findings: list[Finding] = []

    def add(
        key: str, status: T, severity: S, en: str, it: str, value: str | None, scoreable: bool = False
    ) -> None:
        findings.append(
            finding(
                key,
                status,
                severity,
                en,
                it,
                {
                    "url": redact_url(response.url),
                    "method": "HEAD",
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "header_value": value,
                },
                scoreable=scoreable,
            )
        )

    hsts_values = response.values("strict-transport-security")
    hsts = hsts_values[0] if hsts_values else None  # RFC 6797: only the first field is processed.
    active_hsts = active_hsts_policy(hsts)
    add(
        "headers.hsts",
        T.PASSED if active_hsts else T.WARNING,
        S.INFO if active_hsts else S.LOW,
        "HSTS requests future HTTPS-only browser access. Subdomains/preload require separate rollout decisions."
        if active_hsts
        else "HSTS is missing, disabled, or malformed. This hardening gap matters for browser HTTPS enforcement; assess rollout before enabling subdomains/preload.",
        "HSTS richiede accessi browser futuri solo HTTPS. Sottodomini/preload richiedono valutazioni separate."
        if active_hsts
        else "HSTS assente, disabilitato o malformato. Questa misura serve all'uso browser di HTTPS; valuta l'impatto prima di sottodomini/preload.",
        hsts,
        True,
    )
    nosniff = h.get("x-content-type-options")
    add(
        "headers.nosniff",
        T.PASSED if nosniff and nosniff.lower() == "nosniff" else T.WARNING,
        S.INFO if nosniff and nosniff.lower() == "nosniff" else S.LOW,
        "nosniff prevents some browser MIME type guessing."
        if nosniff and nosniff.lower() == "nosniff"
        else "A valid nosniff header was not found; correct MIME types also remain necessary.",
        "nosniff impedisce alcune interpretazioni automatiche del tipo MIME."
        if nosniff and nosniff.lower() == "nosniff"
        else "Intestazione nosniff valida non trovata; restano necessari tipi MIME corretti.",
        nosniff,
        True,
    )
    referrer = h.get("referrer-policy")
    recognized = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
    policies = [
        part.strip().lower() for part in (referrer or "").split(",") if part.strip().lower() in recognized
    ]
    restrictive = bool(policies) and policies[-1] not in {"unsafe-url", "no-referrer-when-downgrade"}
    add(
        "headers.referrer",
        T.PASSED if restrictive else T.WARNING,
        S.INFO if restrictive else S.LOW,
        "Recognized referrer policy limits some cross-site URL disclosure."
        if restrictive
        else "Referrer policy is absent, unrecognized, or permissive. Modern browser defaults may already limit disclosure.",
        "La policy referrer riconosciuta limita alcune divulgazioni di URL verso altri siti."
        if restrictive
        else "Policy referrer assente, non riconosciuta o permissiva. I browser moderni possono già limitare la divulgazione per impostazione predefinita.",
        referrer,
    )
    if not html:
        status = T.NA if content_type else T.UNKNOWN
        for key, name in (
            ("headers.csp", "content-security-policy"),
            ("headers.permissions", "permissions-policy"),
            ("headers.framing", "x-frame-options"),
        ):
            add(
                key,
                status,
                S.INFO,
                "Document-level browser policy was not evaluated for a non-HTML or unknown content type.",
                "Policy browser a livello di documento non valutata per contenuto non HTML o di tipo sconosciuto.",
                h.get(name),
            )
        return findings
    csp = h.get("content-security-policy")
    add(
        "headers.csp",
        T.PASSED if csp else T.WARNING,
        S.INFO if csp else S.LOW,
        "Enforcing CSP header present. Full directive effectiveness, nonces and resource compatibility were not evaluated."
        if csp
        else "No enforcing CSP header found. CSP reduces content injection impact; report-only and HTML meta policies are not equivalent to this header check.",
        "Intestazione CSP applicata presente. Efficacia completa, nonce e compatibilità delle risorse non valutati."
        if csp
        else "Nessuna intestazione CSP applicata. CSP riduce l'impatto di contenuti iniettati; report-only e policy meta HTML non equivalgono a questa verifica.",
        csp,
    )
    permissions = h.get("permissions-policy")
    add(
        "headers.permissions",
        T.PASSED if permissions else T.WARNING,
        S.INFO,
        "Permissions-Policy header present; feature restrictions were not semantically validated."
        if permissions
        else "Permissions-Policy is absent. Restrict sensitive browser features only where relevant; defaults vary by feature.",
        "Permissions-Policy presente; restrizioni delle funzionalità non validate semanticamente."
        if permissions
        else "Permissions-Policy assente. Limita le funzionalità browser sensibili dove necessario; i valori predefiniti variano.",
        permissions,
    )
    xfo = h.get("x-frame-options", "")
    frame_policies: list[list[str]] = []
    for policy in (csp or "").split(","):
        for directive in policy.split(";"):
            tokens = directive.strip().split()
            if tokens and tokens[0].lower() == "frame-ancestors":
                frame_policies.append(tokens[1:])
                break  # First duplicate directive wins within each policy.
    valid_frames = any(
        bool(tokens)
        and "*" not in tokens
        and all(token in {"'self'", "'none'"} or re.fullmatch(r"https?://[^\s;]+", token) for token in tokens)
        and ("'none'" not in tokens or len(tokens) == 1)
        for tokens in frame_policies
    )
    valid_xfo = xfo.upper() in {"DENY", "SAMEORIGIN"}
    # An effective frame-ancestors directive takes precedence over XFO.
    protected = valid_frames if frame_policies else valid_xfo
    add(
        "headers.framing",
        T.PASSED if protected else T.WARNING,
        S.INFO if protected else S.LOW,
        "A restrictive frame-ancestors or valid X-Frame-Options policy was found. Review allowed origins against business needs."
        if protected
        else "No recognized restrictive framing policy found. Clickjacking relevance depends on interactive HTML content and intended embedding.",
        "Trovata una policy frame-ancestors restrittiva o X-Frame-Options valida. Verifica le origini consentite rispetto alle esigenze applicative."
        if protected
        else "Nessuna policy di framing restrittiva riconosciuta. La rilevanza del clickjacking dipende dai contenuti interattivi e dall'incorporamento previsto.",
        f"frame-ancestors={frame_policies}; X-Frame-Options={xfo}",
    )
    return findings
