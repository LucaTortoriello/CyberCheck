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
    "http.https": (
        "http",
        "HTTPS connectivity",
        "Connettività HTTPS",
        "https://www.rfc-editor.org/rfc/rfc9110",
    ),
    "http.application": (
        "http",
        "HTTP application response",
        "Risposta HTTP applicativa",
        "https://www.rfc-editor.org/rfc/rfc9110",
    ),
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
        "If this hostname sends email, verify authorized sending infrastructure with the mail administrator and review one appropriate SPF policy, correcting observed syntax errors. If it does not send email, assess whether an explicit no-senders policy is appropriate and within your DNS control. SPF does not inherit from parent names; receiving email alone does not establish a sending requirement. Confirm intent before changing a permissive +all policy.",
        "Se questo host invia email, verifica con l'amministratore l'infrastruttura di invio autorizzata e valuta una policy SPF appropriata, correggendo gli errori di sintassi osservati. Se non invia email, valuta se una policy esplicita senza mittenti sia opportuna e sotto il tuo controllo DNS. SPF non si eredita dai nomi padre; la sola ricezione non implica un requisito di invio. Conferma l'intento prima di cambiare una policy permissiva +all.",
    ),
    "email.spf_lookups": Text(
        "Ask the mail administrator to evaluate representative sender paths against the ten-lookup limit. Remove obsolete includes; avoid blindly flattening provider-managed records.",
        "Chiedi all'amministratore email di valutare percorsi rappresentativi rispetto al limite di dieci lookup. Rimuovi include obsoleti; evita di appiattire alla cieca record gestiti dai provider.",
    ),
    "email.dmarc": Text(
        "If this hostname is used as an email author domain, review the applicable DMARC policy and sender alignment with the mail/DNS administrator before changing enforcement. Check inherited policy first; avoid unnecessary duplicate records. For non-senders, consider anti-impersonation policy only after confirming requirements and DNS control. This legacy RFC 7489 check does not establish effective RFC 9989 policy; validate current-standard behavior separately and do not change modern tags or pct solely to satisfy this result.",
        "Se questo host è usato come dominio autore delle email, verifica con l'amministratore email/DNS la policy DMARC applicabile e l'allineamento dei mittenti prima di cambiare l'applicazione. Controlla prima la policy ereditata; evita duplicati inutili. Per i non mittenti, valuta una policy contro le impersonificazioni solo dopo aver confermato requisiti e controllo DNS. Questa verifica legacy RFC 7489 non accerta la policy effettiva RFC 9989; valida separatamente il comportamento attuale e non modificare tag moderni o pct solo per soddisfare questo risultato.",
    ),
    "email.dkim": Text(
        "If this hostname signs outgoing email, confirm the exact active selector with the mail provider and compare its supplied key. Use an authorized message's DKIM-Signature and Authentication-Results to verify signing and alignment. A revoked selector may be intentionally retired; replace it only if still intended for signing. Do not modify keys without the responsible operator's approval.",
        "Se questo host firma email in uscita, conferma con il provider il selettore attivo esatto e confronta la chiave fornita. Usa DKIM-Signature e Authentication-Results di un messaggio autorizzato per verificare firma e allineamento. Un selettore revocato può essere intenzionalmente ritirato; sostituiscilo solo se ancora destinato alla firma. Non modificare chiavi senza l'approvazione del gestore responsabile.",
    ),
    "dns.mx": Text(
        "If this hostname is intended to receive email, verify explicit or implicit mail routing with the mail administrator; missing MX alone does not prove broken delivery. If inbound mail is not intended, consider a single null MX (0 .), without other MX, only after confirming requirements and DNS control. Receiving and sending are separate roles; do not change shared-platform routing without appropriate control.",
        "Se questo host deve ricevere email, verifica con l'amministratore l'instradamento esplicito o implicito; gli MX assenti non provano da soli una consegna non funzionante. Se la ricezione non è prevista, valuta un solo null MX (0 .), senza altri MX, solo dopo aver confermato requisiti e controllo DNS. Ricezione e invio sono ruoli distinti; non modificare l'instradamento di piattaforme condivise senza il controllo appropriato.",
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
        "For browser-facing services, consider HSTS with the application/hosting operator after HTTPS works consistently. Test a short positive max-age before longer durations; includeSubDomains or preload require review of every affected service. Missing HSTS alone does not establish an exploitable vulnerability.",
        "Per servizi destinati ai browser, valuta HSTS con il gestore applicativo/hosting quando HTTPS funziona stabilmente. Prova un max-age positivo breve prima di durate maggiori; includeSubDomains o preload richiedono la verifica di tutti i servizi coinvolti. HSTS assente non accerta da solo una vulnerabilità sfruttabile.",
    ),
    "headers.nosniff": Text(
        "For browser-consumed responses, review correct Content-Type values and consider X-Content-Type-Options: nosniff with the application/proxy operator. Test script and stylesheet loading; header absence alone does not demonstrate MIME-based exploitation.",
        "Per risposte usate dai browser, verifica Content-Type corretti e valuta X-Content-Type-Options: nosniff con il gestore applicativo/proxy. Prova il caricamento di script e fogli di stile; l'assenza dell'intestazione non dimostra da sola uno sfruttamento basato sul MIME.",
    ),
    "headers.csp": Text(
        "For HTML applications, review injection defenses and resource requirements with the application operator. If CSP is appropriate, trial it in report-only mode before enforcing a tested policy, using nonces or hashes where suitable. This header check neither detects injection nor evaluates HTML meta policies or full CSP effectiveness.",
        "Per applicazioni HTML, verifica con il gestore le difese dalle iniezioni e i requisiti delle risorse. Se CSP è appropriata, provala in modalità report-only prima di applicare una policy testata, con nonce o hash dove adatti. Questa verifica non rileva iniezioni e non valuta policy meta HTML o l'efficacia completa della CSP.",
    ),
    "headers.referrer": Text(
        "Consider Referrer-Policy: strict-origin-when-cross-origin or a stricter tested policy, and avoid placing sensitive data in URLs.",
        "Valuta Referrer-Policy: strict-origin-when-cross-origin o una policy testata più restrittiva, ed evita dati sensibili negli URL.",
    ),
    "headers.permissions": Text(
        "If the HTML application uses sensitive browser features, review feature defaults and requirements with the application operator. Consider restricting unused features, for example camera=(), microphone=(), geolocation=(), after compatibility testing. This optional header is not universally required; its presence does not prove effective restrictions.",
        "Se l'applicazione HTML usa funzionalità browser sensibili, verifica valori predefiniti e requisiti con il gestore applicativo. Valuta restrizioni alle funzionalità inutilizzate, ad esempio camera=(), microphone=(), geolocation=(), dopo test di compatibilità. Questa intestazione facoltativa non è sempre richiesta; la presenza non prova restrizioni efficaci.",
    ),
    "headers.framing": Text(
        "For interactive HTML, configure CSP frame-ancestors with the intended embedding origins. Use 'none' only when embedding is unnecessary; X-Frame-Options DENY/SAMEORIGIN can support older clients.",
        "Per HTML interattivo, configura CSP frame-ancestors con le origini di incorporamento previste. Usa 'none' solo se l'incorporamento non serve; X-Frame-Options DENY/SAMEORIGIN può supportare client meno recenti.",
    ),
    "tls.connection": Text(
        "Review the observed handshake with the HTTPS operator if it was inconclusive. One successful verified handshake does not establish application availability or comprehensive TLS security.",
        "Verifica l'handshake osservato con il gestore HTTPS se inconcludente. Un handshake verificato riuscito non accerta la disponibilità applicativa o la sicurezza TLS completa.",
    ),
    "tls.protocol": Text(
        "Review the negotiated protocol only as evidence for this connection. If broader TLS support needs assessment, arrange a separately authorized protocol review with the operator; older-version support was not tested here.",
        "Considera il protocollo negoziato come evidenza solo per questa connessione. Se occorre valutare il supporto TLS completo, concorda con il gestore una verifica dei protocolli autorizzata separatamente; qui il supporto delle versioni precedenti non è stato testato.",
    ),
    "http.https": Text(
        "Review the recorded method, status and connection error with the web operator if needed. Any verified HTTPS response establishes limited connectivity; an HTTP error does not by itself prove the application is unavailable or insecure.",
        "Verifica se necessario metodo, stato ed errore di connessione registrati con il gestore web. Una risposta HTTPS verificata accerta connettività limitata; un errore HTTP non prova da solo un'applicazione indisponibile o insicura.",
    ),
    "http.application": Text(
        "Check application behavior with the operator using the recorded method and URL. After HEAD 405/501, enable GET fallback only with explicit authorization for GET and its redirects. A 2xx response does not verify login or business functions; response bodies were not inspected.",
        "Verifica con il gestore il comportamento applicativo usando metodo e URL registrati. Dopo HEAD 405/501, abilita il fallback GET solo con autorizzazione esplicita per GET e relativi redirect. Una risposta 2xx non verifica login o funzioni operative; i corpi delle risposte non sono stati ispezionati.",
    ),
    "http.redirect": Text(
        "If HTTP serves this browser-facing site, review a canonical HTTPS redirect with the web operator. Do not open port 80 merely to clear an inconclusive check; closure can be intentional. Confirm intended routing before changes.",
        "Se HTTP serve questo sito destinato ai browser, valuta con il gestore un redirect HTTPS canonico. Non aprire la porta 80 solo per eliminare una verifica inconcludente; la chiusura può essere intenzionale. Conferma l'instradamento previsto prima delle modifiche.",
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
