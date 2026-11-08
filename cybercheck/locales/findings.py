"""Bilingual finding vocabulary, independent of Streamlit."""

from cybercheck.models import Finding, Severity, Status, Text

# Category, English/Italian title, reference.
DEFINITIONS = {
    "dns.records": (
        "dns",
        "DNS record inventory",
        "Inventario record DNS",
        "https://www.rfc-editor.org/rfc/rfc1035",
    ),
    "dns.mx": (
        "dns",
        "Mail routing (MX)",
        "Instradamento email (MX)",
        "https://www.rfc-editor.org/rfc/rfc7505",
    ),
    "dns.caa": (
        "dns",
        "Certificate authorities (CAA)",
        "Autorità di certificazione (CAA)",
        "https://www.rfc-editor.org/rfc/rfc8659",
    ),
    "email.spf": (
        "email",
        "SPF configuration",
        "Configurazione SPF",
        "https://www.rfc-editor.org/rfc/rfc7208",
    ),
    "email.spf_lookups": (
        "email",
        "SPF lookup complexity",
        "Complessità lookup SPF",
        "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4",
    ),
    "email.dmarc": ("email", "DMARC policy", "Policy DMARC", "https://www.rfc-editor.org/rfc/rfc7489"),
    "email.dmarc_reporting": (
        "email",
        "DMARC aggregate reporting",
        "Report aggregati DMARC",
        "https://www.rfc-editor.org/rfc/rfc7489#section-7",
    ),
    "email.dkim": ("email", "DKIM selector", "Selettore DKIM", "https://www.rfc-editor.org/rfc/rfc6376"),
    "tls.connection": (
        "tls",
        "Verified HTTPS handshake",
        "Handshake HTTPS verificato",
        "https://docs.python.org/3/library/ssl.html",
    ),
    "tls.chain": (
        "tls",
        "Certificate chain",
        "Catena del certificato",
        "https://docs.python.org/3/library/ssl.html",
    ),
    "tls.hostname": (
        "tls",
        "Certificate hostname",
        "Nome host del certificato",
        "https://www.rfc-editor.org/rfc/rfc9525",
    ),
    "tls.validity": (
        "tls",
        "Certificate validity and expiry",
        "Validità e scadenza del certificato",
        "https://www.rfc-editor.org/rfc/rfc5280",
    ),
    "tls.protocol": (
        "tls",
        "Negotiated TLS protocol",
        "Protocollo TLS negoziato",
        "https://www.rfc-editor.org/rfc/rfc8446",
    ),
    "http.https": ("http", "HTTPS endpoint", "Endpoint HTTPS", "https://www.rfc-editor.org/rfc/rfc9110"),
    "http.redirect": (
        "http",
        "HTTP to HTTPS redirect",
        "Redirect da HTTP a HTTPS",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    ),
    "headers.hsts": (
        "headers",
        "HTTP Strict Transport Security",
        "HTTP Strict Transport Security",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    "headers.csp": (
        "headers",
        "Content Security Policy",
        "Content Security Policy",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
    "headers.nosniff": (
        "headers",
        "MIME type protection",
        "Protezione del tipo MIME",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    "headers.referrer": (
        "headers",
        "Referrer policy",
        "Policy del referrer",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    "headers.permissions": (
        "headers",
        "Browser permissions policy",
        "Policy dei permessi browser",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    "headers.framing": (
        "headers",
        "Framing protection",
        "Protezione dall'incorporamento",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
    ),
    "engine.error": ("system", "Check execution", "Esecuzione verifica", ""),
}

CONTEXT = {
    "dns": (
        Text(
            "DNS records control service discovery and routing; absence alone need not be insecure.",
            "I record DNS controllano instradamento e scoperta dei servizi; un'assenza non indica da sola insicurezza.",
        ),
        Text(
            "Review the evidence with the DNS administrator and change only records relevant to your services.",
            "Esamina le evidenze con l'amministratore DNS e modifica solo i record pertinenti ai tuoi servizi.",
        ),
    ),
    "email": (
        Text(
            "Email authentication configuration can affect impersonation resistance and message delivery. DNS alone does not prove successful authentication.",
            "L'autenticazione email può influire sulla resistenza alle impersonificazioni e sulla consegna. Il solo DNS non prova l'autenticazione dei messaggi.",
        ),
        Text(
            "Inventory legitimate senders with your mail provider, then validate changes using real message headers and reports.",
            "Censisci i mittenti legittimi con il provider email, quindi verifica le modifiche usando intestazioni di messaggi reali e report.",
        ),
    ),
    "tls": (
        Text(
            "Browsers rely on trusted certificates and encrypted transport. Results represent one endpoint and the local trust store at this time.",
            "I browser si affidano a certificati attendibili e trasporto cifrato. Il risultato riguarda un endpoint e il trust store locale in questo momento.",
        ),
        Text(
            "Review the certificate, DNS name, full intermediate chain, and automatic renewal with the hosting provider.",
            "Verifica con l'hosting certificato, nome DNS, catena intermedia completa e rinnovo automatico.",
        ),
    ),
    "http": (
        Text(
            "Transport behavior affects browser access and exposure of an initial unencrypted request.",
            "Il comportamento del trasporto influisce sull'accesso browser e sull'esposizione della prima richiesta non cifrata.",
        ),
        Text(
            "Serve the site over valid HTTPS and redirect port 80 to its HTTPS canonical URL.",
            "Servi il sito con HTTPS valido e reindirizza la porta 80 al suo URL canonico HTTPS.",
        ),
    ),
    "headers": (
        Text(
            "Browser defense headers reduce specific client-side risks. Relevance depends on content, application behavior, and browser support.",
            "Le intestazioni di difesa browser riducono rischi specifici lato client. La rilevanza dipende da contenuti, applicazione e supporto browser.",
        ),
        Text(
            "Configure this header for the application after testing compatibility. Presence alone does not establish an effective policy.",
            "Configura questa intestazione per l'applicazione dopo i test di compatibilità. La sola presenza non garantisce una policy efficace.",
        ),
    ),
    "system": (
        Text(
            "An incomplete check provides no reliable security conclusion.",
            "Una verifica incompleta non permette conclusioni affidabili sulla sicurezza.",
        ),
        Text(
            "Review local logs and retry after resolving the execution issue.",
            "Controlla i log locali e riprova dopo aver risolto il problema.",
        ),
    ),
}

REMEDIATIONS = {
    "email.spf": Text(
        "Keep exactly one v=spf1 TXT record. Inventory every legitimate sender, correct invalid mechanisms, and choose a fail/softfail policy appropriate to your rollout; never use +all.",
        "Mantieni un solo record TXT v=spf1. Censisci tutti i mittenti legittimi, correggi i meccanismi non validi e scegli fail/softfail in base al rilascio; non usare +all.",
    ),
    "email.spf_lookups": Text(
        "Ask the mail administrator to evaluate representative sender paths against the ten-lookup limit. Remove obsolete includes; avoid blindly flattening provider-managed records.",
        "Chiedi all'amministratore email di valutare percorsi rappresentativi rispetto al limite di dieci lookup. Rimuovi include obsoleti; evita di appiattire alla cieca record gestiti dai provider.",
    ),
    "email.dmarc": Text(
        "Publish one valid DMARC record. Use aggregate reports to confirm legitimate sender alignment before progressively requesting quarantine/reject enforcement; review pct and inherited sp.",
        "Pubblica un record DMARC valido. Usa i report aggregati per confermare l'allineamento dei mittenti legittimi prima di richiedere progressivamente quarantine/reject; verifica pct e sp ereditato.",
    ),
    "email.dkim": Text(
        "Confirm the exact selector with the mail provider and publish its supplied key. Check DKIM-Signature and Authentication-Results on an authorized test message; rotate revoked or invalid keys.",
        "Conferma il selettore esatto con il provider e pubblica la chiave fornita. Controlla DKIM-Signature e Authentication-Results di un messaggio di prova autorizzato; ruota chiavi revocate o non valide.",
    ),
    "dns.mx": Text(
        "If mail is received, configure the provider's MX records. If no inbound mail is intended, use a single null MX (0 .) without other MX records. Do not change mail routing without confirming service requirements.",
        "Se ricevi email, configura gli MX del provider. Se non ricevi email, usa un solo null MX (0 .) senza altri MX. Conferma i requisiti del servizio prima di cambiare l'instradamento.",
    ),
    "dns.caa": Text(
        "Review effective parent/CNAME CAA and your certificate issuers before restricting issuance. CAA is optional; avoid blocking automatic certificate renewal.",
        "Verifica CAA ereditato da padre/CNAME e le autorità usate prima di limitare l'emissione. CAA è facoltativo; evita di bloccare il rinnovo automatico.",
    ),
    "tls.hostname": Text(
        "Deploy a certificate whose subject alternative names cover the assessed hostname and verify the correct virtual host/SNI configuration.",
        "Installa un certificato con subject alternative names che coprano il nome host analizzato e verifica virtual host e SNI.",
    ),
    "tls.chain": Text(
        "Install the correct leaf certificate and full intermediate chain. Check the local machine clock and trust store; never disable verification to hide the error.",
        "Installa il certificato corretto e la catena intermedia completa. Verifica orologio e trust store locali; non disabilitare la verifica per nascondere l'errore.",
    ),
    "tls.validity": Text(
        "Renew certificates before expiry, automate renewal and monitor failures. Check the machine clock if the validity period appears incorrect.",
        "Rinnova i certificati prima della scadenza, automatizza il rinnovo e monitora gli errori. Controlla l'orologio se il periodo di validità appare errato.",
    ),
    "headers.hsts": Text(
        "After HTTPS works consistently, deploy Strict-Transport-Security with a tested positive max-age. Start with a short duration; add includeSubDomains or preload only after reviewing every affected service.",
        "Quando HTTPS funziona stabilmente, configura Strict-Transport-Security con max-age positivo e testato. Parti con una durata breve; aggiungi includeSubDomains o preload solo dopo aver verificato tutti i servizi coinvolti.",
    ),
    "headers.nosniff": Text(
        "Serve correct Content-Type values and set X-Content-Type-Options: nosniff at the application or reverse proxy. Verify script and stylesheet loading.",
        "Servi Content-Type corretti e imposta X-Content-Type-Options: nosniff nell'applicazione o nel proxy. Verifica il caricamento di script e fogli di stile.",
    ),
    "headers.csp": Text(
        "Inventory scripts, styles and external resources. Trial a restrictive CSP in report-only mode, then enforce a tested policy using nonces or hashes where appropriate.",
        "Censisci script, stili e risorse esterne. Prova una CSP restrittiva in modalità report-only, quindi applica una policy testata con nonce o hash dove appropriato.",
    ),
    "headers.referrer": Text(
        "Consider Referrer-Policy: strict-origin-when-cross-origin or a stricter tested policy, and avoid placing sensitive data in URLs.",
        "Valuta Referrer-Policy: strict-origin-when-cross-origin o una policy testata più restrittiva, ed evita dati sensibili negli URL.",
    ),
    "headers.permissions": Text(
        "Identify required browser features and restrict unused sensitive features, for example camera=(), microphone=(), geolocation=(), after compatibility testing.",
        "Identifica le funzionalità browser necessarie e limita quelle sensibili inutilizzate, ad esempio camera=(), microphone=(), geolocation=(), dopo test di compatibilità.",
    ),
    "headers.framing": Text(
        "For interactive HTML, configure CSP frame-ancestors with the intended embedding origins. Use 'none' only when embedding is unnecessary; X-Frame-Options DENY/SAMEORIGIN can support older clients.",
        "Per HTML interattivo, configura CSP frame-ancestors con le origini di incorporamento previste. Usa 'none' solo se l'incorporamento non serve; X-Frame-Options DENY/SAMEORIGIN può supportare client meno recenti.",
    ),
}


def finding(
    key: str,
    status: Status,
    severity: Severity,
    en: str,
    it: str,
    evidence: dict | None = None,
    *,
    scoreable: bool = False,
    remediation: Text | None = None,
    suffix: str = "",
) -> Finding:
    category, title_en, title_it, reference = DEFINITIONS[key]
    impact, default_remediation = CONTEXT[category]
    return Finding(
        check_id=key + suffix,
        check_name=Text(title_en + suffix, title_it + suffix),
        category=category,
        status=status,
        severity=severity,
        explanation=Text(en, it),
        business_impact=impact,
        remediation=remediation or REMEDIATIONS.get(key, default_remediation),
        evidence=evidence or {},
        references=[reference] if reference else [],
        scoreable=scoreable,
    )
