"""Presentation strings shared by the app and report renderer."""

STRINGS = {
    "synthetic_notice": (
        "SYNTHETIC TEST FIXTURE — This is not a live assessment.",
        "DATI SINTETICI DI TEST — Questo non è un assessment live.",
    ),
    "config_error": (
        "Startup configuration is invalid. Check the numeric environment variables and documented ranges, then restart the app.",
        "Configurazione di avvio non valida. Controlla le variabili d'ambiente numeriche e gli intervalli documentati, quindi riavvia l'app.",
    ),
    "storage_error": (
        "The local database could not be opened or uses an unsupported schema. Check its path and permissions; preserve it and restore a backup or choose a separate database path.",
        "Impossibile aprire il database locale, oppure schema non supportato. Controlla percorso e permessi; conservalo e ripristina un backup o scegli un percorso separato.",
    ),
    "stored_invalid": (
        "This stored assessment cannot be read. Its data has been preserved. Select another assessment or recover a database backup.",
        "Questo assessment salvato non è leggibile. I dati sono stati conservati. Seleziona un altro assessment o recupera un backup del database.",
    ),
    "checks_done": (
        "Checks completed; saving results locally…",
        "Verifiche completate; salvataggio locale in corso…",
    ),
    "checks_not_saved": (
        "Checks completed; local saving needs attention.",
        "Verifiche completate; salvataggio locale da verificare.",
    ),
    "unsaved": (
        "An assessment is available only in this session. Save it again or download it from Reports before closing the app.",
        "Un assessment è disponibile solo in questa sessione. Riprova il salvataggio o scaricalo da Report prima di chiudere l'app.",
    ),
    "retry_save": ("Retry saving results", "Riprova il salvataggio"),
    "incomplete_notice": (
        "{count} checks could not establish a result. Review Unknown/Error findings before drawing conclusions; these are not confirmed vulnerabilities.",
        "{count} verifiche non hanno prodotto un risultato accertabile. Esamina gli esiti Sconosciuto/Errore prima di trarre conclusioni; non sono vulnerabilità confermate.",
    ),
    "attention_count": (
        "Showing {displayed} of {total} items by priority. Open Findings to view and filter all results.",
        "Mostrati {displayed} di {total} elementi in ordine di priorità. Apri Risultati per visualizzarli e filtrarli tutti.",
    ),
    "previous_severity": ("Previous severity", "Gravità precedente"),
    "current_severity": ("Current severity", "Gravità attuale"),
    "report_scope": ("Assessment scope", "Ambito dell'assessment"),
    "report_scope_body": (
        "DNS and email configuration for the stated domain; one certificate endpoint and bounded root-page HTTP HEAD requests on ports 80/443. An explicitly authorized HTTPS GET fallback may follow HEAD 405/501. Related redirects are limited to the same organizational domain. Only explicitly supplied DKIM selectors are queried.",
        "Configurazione DNS ed email del dominio indicato; un endpoint del certificato e richieste HTTP HEAD limitate alla pagina iniziale sulle porte 80/443. Dopo HEAD 405/501 è possibile un fallback GET HTTPS esplicitamente autorizzato. I redirect correlati sono limitati allo stesso dominio organizzativo. Vengono interrogati solo i selettori DKIM esplicitamente forniti.",
    ),
    "allow_get_fallback": (
        "Authorize GET fallback after HEAD 405/501 (optional)",
        "Autorizza il fallback GET dopo HEAD 405/501 (facoltativo)",
    ),
    "get_fallback_help": (
        "Disabled by default. Authorize GET for this assessment and permitted redirects only if allowed by the asset owner. Only headers are retained; a poorly designed application may still perform actions on GET.",
        "Disattivato per impostazione predefinita. Autorizza GET per questo assessment e i redirect consentiti solo se permesso dal proprietario. Si conservano solo le intestazioni; un'applicazione progettata male potrebbe comunque eseguire azioni con GET.",
    ),
    "report_confirmed": ("Confirmed configuration issues", "Problemi di configurazione confermati"),
    "report_inconclusive": ("Unknown and incomplete checks", "Verifiche sconosciute e incomplete"),
    "no_confirmed": (
        "No confirmed configuration issue was recorded within the evaluated scope.",
        "Nessun problema di configurazione confermato registrato nell'ambito valutato.",
    ),
    "no_inconclusive": (
        "No unknown or execution-error result was recorded.",
        "Nessun risultato sconosciuto o errore di esecuzione registrato.",
    ),
    "overview": ("Overview", "Panoramica"),
    "new": ("New Assessment", "Nuovo assessment"),
    "history": ("Assessment History", "Cronologia assessment"),
    "findings": ("Findings", "Risultati"),
    "reports": ("Reports", "Report"),
    "settings": ("Settings", "Impostazioni"),
    "tagline": (
        "Understand your domain's security configuration.",
        "Comprendi la configurazione di sicurezza del tuo dominio.",
    ),
    "local": ("COMMUNITY · LOCAL WORKSPACE", "COMMUNITY · AMBIENTE LOCALE"),
    "empty": ("Your first assessment starts here", "Il tuo primo assessment inizia qui"),
    "empty_body": (
        "Assess a domain you own or are authorized to review. Findings and evidence will appear here after the assessment.",
        "Analizza un dominio di tua proprietà o per cui hai un'autorizzazione. Risultati ed evidenze appariranno qui al termine.",
    ),
    "selected": ("Selected assessment", "Assessment selezionato"),
    "passed": ("Passed", "Superato"),
    "failed": ("Failed", "Non superato"),
    "warning": ("Warning", "Avviso"),
    "unknown": ("Unknown", "Sconosciuto"),
    "error": ("Error", "Errore"),
    "not_applicable": ("Not applicable", "Non applicabile"),
    "critical": ("Critical", "Critica"),
    "high": ("High", "Alta"),
    "medium": ("Medium", "Media"),
    "low": ("Low", "Bassa"),
    "informational": ("Informational", "Informativa"),
    "dns": ("DNS infrastructure", "Infrastruttura DNS"),
    "email": ("Email authentication", "Autenticazione email"),
    "tls": ("HTTPS & TLS", "HTTPS e TLS"),
    "http": ("Web transport", "Trasporto web"),
    "headers": ("Browser security headers", "Intestazioni di sicurezza browser"),
    "system": ("Execution", "Esecuzione"),
    "domain": ("Domain", "Dominio"),
    "date": ("Assessment date (UTC)", "Data assessment (UTC)"),
    "checks_passed": ("Checks passed", "Verifiche superate"),
    "warnings": ("Warnings", "Avvisi"),
    "confirmed": ("Confirmed findings", "Problemi confermati"),
    "incomplete": ("Unknown / errors", "Sconosciuti / errori"),
    "category": ("Category", "Categoria"),
    "status": ("Status", "Stato"),
    "severity": ("Severity", "Gravità"),
    "summary": ("Configuration overview", "Panoramica configurazione"),
    "attention": ("Items to review", "Elementi da esaminare"),
    "no_attention": (
        "No confirmed findings or warnings in the completed checks. This is not a security guarantee.",
        "Nessun problema confermato o avviso nelle verifiche completate. Non è una garanzia di sicurezza.",
    ),
    "scope_note": (
        "Point-in-time, low-impact configuration checks. Unknown results are not failures. This is not a penetration test or certification.",
        "Verifiche di configurazione a basso impatto in un dato momento. I risultati sconosciuti non sono fallimenti. Non è un penetration test o una certificazione.",
    ),
    "new_intro": (
        "One domain. Real observations. Clear next steps.",
        "Un dominio. Osservazioni reali. Prossimi passi chiari.",
    ),
    "domain_help": (
        "Domain name only, without https://, path or port. Only public destinations are supported.",
        "Solo il nome di dominio, senza https://, percorso o porta. Sono supportate solo destinazioni pubbliche.",
    ),
    "selectors": ("DKIM selectors (optional)", "Selettori DKIM (facoltativi)"),
    "selector_help": (
        "Up to five selectors separated by commas. Obtain them from your mail provider; no automatic discovery is performed.",
        "Fino a cinque selettori separati da virgole. Richiedili al provider email; nessuna ricerca automatica.",
    ),
    "authorization": (
        "I own this domain or have explicit authorization to assess it, including related redirects within its organizational domain.",
        "Sono proprietario del dominio o ho un'autorizzazione esplicita ad analizzarlo, inclusi i redirect correlati nel suo dominio organizzativo.",
    ),
    "authorization_error": (
        "Confirm ownership or authorization before starting.",
        "Conferma la proprietà o l'autorizzazione prima di iniziare.",
    ),
    "start": ("Start Assessment", "Avvia assessment"),
    "running": ("Assessment in progress", "Assessment in corso"),
    "done": ("Assessment completed and saved locally.", "Assessment completato e salvato localmente."),
    "save_error": (
        "Assessment completed, but local saving failed. Results remain in this session; download a report now.",
        "Assessment completato, ma salvataggio locale non riuscito. I risultati restano nella sessione; scarica subito un report.",
    ),
    "validation_error": (
        "Invalid domain or selector. Use a public fully qualified domain, no URL or port, and up to five valid selectors.",
        "Dominio o selettore non valido. Usa un dominio pubblico completo, senza URL o porta, e fino a cinque selettori validi.",
    ),
    "execution_error": (
        "Local execution failed. Review the terminal logs for details.",
        "Esecuzione locale non riuscita. Controlla i log del terminale per i dettagli.",
    ),
    "search": ("Search findings and evidence", "Cerca nei risultati e nelle evidenze"),
    "all": ("All", "Tutti"),
    "no_results": ("No findings match these filters.", "Nessun risultato corrisponde ai filtri."),
    "technical": ("Technical explanation", "Spiegazione tecnica"),
    "impact": ("Business impact", "Impatto aziendale"),
    "remediation": ("Recommended remediation", "Intervento consigliato"),
    "evidence": ("Evidence", "Evidenze"),
    "verified": ("Observed at (UTC)", "Osservato il (UTC)"),
    "references": ("Reference", "Riferimento"),
    "history_intro": (
        "Assessments stay in your local SQLite database. Compare consecutive observations for the same domain.",
        "Gli assessment restano nel database SQLite locale. Confronta osservazioni consecutive per lo stesso dominio.",
    ),
    "history_domain": ("Filter by exact domain (optional)", "Filtra per dominio esatto (facoltativo)"),
    "page": ("History page", "Pagina cronologia"),
    "open_assessment": ("Open assessment", "Apri assessment"),
    "compare": ("Changes since the previous assessment", "Cambiamenti dall'assessment precedente"),
    "previous_status": ("Previous status", "Stato precedente"),
    "current_status": ("Current status", "Stato attuale"),
    "evidence_changed": ("Evidence changed", "Evidenze cambiate"),
    "check": ("Check", "Verifica"),
    "yes": ("Yes", "Sì"),
    "no": ("No", "No"),
    "no_previous": (
        "There is no earlier assessment for this domain.",
        "Non esiste un assessment precedente per questo dominio.",
    ),
    "no_changes": (
        "No status, severity or evidence changes detected.",
        "Nessun cambiamento di stato, gravità o evidenze rilevato.",
    ),
    "compare_note": (
        "Evidence changes are observations, not automatic risk increases. Different selectors and incomplete checks can change coverage.",
        "Le modifiche alle evidenze sono osservazioni, non aumenti automatici del rischio. Selettori diversi e verifiche incomplete possono modificare la copertura.",
    ),
    "reports_intro": (
        "Export the selected assessment with evidence, recommended actions and methodology. Open HTML in your browser to print or save as PDF.",
        "Esporta l'assessment selezionato con evidenze, azioni consigliate e metodologia. Apri l'HTML nel browser per stampare o salvare in PDF.",
    ),
    "download_html": ("Download printable HTML", "Scarica HTML stampabile"),
    "download_json": ("Download JSON", "Scarica JSON"),
    "report_title": ("Security Assessment Report", "Report di assessment di sicurezza"),
    "executive": ("Executive summary", "Sintesi esecutiva"),
    "report_executive": (
        "This report records observable domain, email and web configurations. Prioritize confirmed issues and contextual warnings; incomplete checks require further verification.",
        "Questo report registra configurazioni osservabili di dominio, email e web. Dai priorità ai problemi confermati e agli avvisi contestuali; le verifiche incomplete richiedono approfondimenti.",
    ),
    "methodology": ("Methodology and limitations", "Metodologia e limiti"),
    "methodology_body": (
        "DNS uses the configured recursive resolver, bounded queries and only supplied DKIM selectors. DMARC uses explicitly labeled legacy RFC 7489 PSL/pct interpretation; current RFC 9989 tree-walk/testing semantics are not implemented. Records with np/psd/t remain inconclusive. Sender alignment and reporting delivery are not tested. SPF checks common syntax and potential lookup paths, not full sender-dependent evaluation. CAA is inspected only at the exact name. One TLS handshake verifies the requested hostname and chain using the local trust store; obsolete protocol support, revocation and CT are not probed. HTTP uses HEAD on ports 80/443 and, only with explicit opt-in after HTTPS HEAD 405/501, a GET fallback. HTTPS connectivity does not establish application availability; security headers require a final HTTPS 2xx response. Both methods use validated public IPs and bounded same-organizational-domain redirects. GET can cause application side effects even when only headers are read. Bodies and HTML meta policies are not inspected. Headers reflect the final successful response, possibly a CDN. Only one selected IP is sampled. Saved web evidence uses a header allowlist and redacts URL queries, credentials and fragments; paths and DNS records can still be sensitive. Failures and blocked requests are unknown, not confirmed vulnerabilities. Ownership is a user declaration, not independently verified.",
        "Il DNS usa il resolver ricorsivo configurato, query limitate e solo i selettori DKIM forniti. DMARC usa l'interpretazione legacy RFC 7489 PSL/pct esplicitamente indicata; ricerca nell'albero DNS e modalità di test RFC 9989 non sono implementate. Record con np/psd/t restano inconcludenti. Allineamento e consegna dei report non sono verificati. SPF verifica sintassi comune e percorsi potenziali, senza valutazione completa per mittente. CAA è esaminato solo al nome esatto. Un handshake TLS verifica nome host e catena con il trust store locale; supporto di protocolli obsoleti, revoca e CT non sono sondati. HTTP usa HEAD sulle porte 80/443 e, solo con consenso esplicito dopo HEAD HTTPS 405/501, un fallback GET. La connettività HTTPS non dimostra la disponibilità applicativa; le intestazioni richiedono una risposta HTTPS finale 2xx. Entrambi i metodi usano IP pubblici validati e redirect limitati allo stesso dominio organizzativo. GET può causare effetti applicativi anche leggendo solo le intestazioni. Corpi e policy meta HTML non sono ispezionati. Le intestazioni riflettono la risposta finale riuscita, eventualmente di un CDN. È campionato un solo IP. Le evidenze web salvate usano un elenco di intestazioni consentite e oscurano query URL, credenziali e frammenti; percorsi e record DNS possono restare sensibili. Errori e blocchi sono sconosciuti, non vulnerabilità confermate. La proprietà è dichiarata dall'utente, non verificata indipendentemente.",
    ),
    "disclaimer": (
        "This assessment is not a penetration test, audit certification, compliance attestation, or guarantee of security. It cannot establish the security of an organization or the probability of compromise. Assess only assets you own or are explicitly authorized to review.",
        "Questo assessment non è un penetration test, una certificazione, un'attestazione di conformità o una garanzia di sicurezza. Non stabilisce la sicurezza di un'organizzazione né la probabilità di compromissione. Analizza solo asset di tua proprietà o con autorizzazione esplicita.",
    ),
    "health": ("Configuration Health", "Stato della configurazione"),
    "show_score": (
        "Show optional configuration-health score",
        "Mostra il punteggio facoltativo di configurazione",
    ),
    "score_formula": (
        "100 × passed / (passed + failed), using only explicitly scoreable checks. Warnings, unknown, errors and inapplicable checks are excluded. Missing policies may remain warnings, so read coverage and findings alongside the score. This is not a probability of compromise or a security guarantee.",
        "100 × superati / (superati + non superati), solo per verifiche esplicitamente valutabili. Avvisi, sconosciuti, errori e non applicabili sono esclusi. Policy mancanti possono restare avvisi: leggi copertura e risultati insieme al punteggio. Non è una probabilità di compromissione o una garanzia di sicurezza.",
    ),
    "coverage": (
        "Score coverage: {evaluated} evaluated, {excluded} excluded.",
        "Copertura punteggio: {evaluated} valutate, {excluded} escluse.",
    ),
    "settings_intro": (
        "Local-first configuration. Network and storage limits are configured through environment variables at launch.",
        "Configurazione locale. I limiti di rete e archiviazione si impostano con variabili d'ambiente all'avvio.",
    ),
    "limits": ("Active limits", "Limiti attivi"),
    "storage": ("Local database", "Database locale"),
    "settings_note": (
        "Public-target mode is always enabled. Proxy environment variables are ignored. Keep this app on localhost; remote hosting requires authentication and additional isolation.",
        "La modalità per destinazioni pubbliche è sempre attiva. Le variabili proxy sono ignorate. Mantieni l'app su localhost; l'hosting remoto richiede autenticazione e ulteriore isolamento.",
    ),
    "not_assessed": ("Not assessed yet", "Non ancora analizzato"),
}


def tr(key: str, language: str = "it", **values) -> str:
    pair = STRINGS.get(key, (key, key))
    return pair[0 if language == "en" else 1].format(**values)
