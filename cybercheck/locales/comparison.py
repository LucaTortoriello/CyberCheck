"""Bilingual comparison labels and explicit rule explanations."""

from dataclasses import asdict

from cybercheck.models import Text

STRINGS = {
    "same_criterion_different_result": (
        "Measurements for this criterion are equivalent although other TLS facts differ. The result change is an evaluation change, not a new or resolved configuration concern.",
        "Le misure relative a questo criterio sono equivalenti anche se altri dati TLS differiscono. Il cambio di esito è una variazione di valutazione, non un nuovo problema di configurazione o una risoluzione.",
    ),
    "title": ("Assessment comparison", "Confronto tra assessment"),
    "intro": (
        "Choose two saved runs for the same target. Categories describe evidence, not proven exploitation.",
        "Scegli due esecuzioni salvate dello stesso target. Le categorie descrivono evidenze, non sfruttamenti dimostrati.",
    ),
    "earlier": ("Earlier assessment", "Assessment precedente"),
    "later": ("Later assessment", "Assessment successivo"),
    "page": ("Comparison history page", "Pagina cronologia per il confronto"),
    "baseline_page": ("Earlier assessment history page", "Pagina cronologia dell'assessment precedente"),
    "compare": ("Compare selected assessments", "Confronta gli assessment selezionati"),
    "choose_distinct": (
        "Choose two distinct assessments, in chronological order.",
        "Scegli due assessment distinti, in ordine cronologico.",
    ),
    "compatibility": ("Comparability", "Confrontabilità"),
    "comparable": ("Comparable", "Confrontabile"),
    "partially_comparable": ("Partially comparable", "Parzialmente confrontabile"),
    "not_comparable": ("Not comparable", "Non confrontabile"),
    "new_issue": ("New concern", "Nuovo elemento da esaminare"),
    "resolved_issue": ("Resolved concern", "Elemento risolto"),
    "persistent_issue": ("Persistent concern", "Elemento persistente"),
    "unchanged": ("Unchanged", "Invariato"),
    "changed_observation": ("Changed observation", "Osservazione cambiata"),
    "evaluation_changed": ("Evaluation changed", "Valutazione cambiata"),
    "inconclusive": ("Inconclusive", "Inconcludente"),
    "equivalent": ("Equivalent observations", "Osservazioni equivalenti"),
    "changed": ("Different observations", "Osservazioni diverse"),
    "details": (
        "Finding comparisons and supporting evidence",
        "Confronti dei finding ed evidenze di supporto",
    ),
    "dimensions": ("Separate comparison dimensions", "Dimensioni separate del confronto"),
    "score": ("Score comparison", "Confronto dei punteggi"),
    "score_valid": (
        "Profiles, context and evaluated criteria match. The delta is a limited diagnostic, not a security rating.",
        "Profili, contesto e criteri valutati coincidono. La differenza è un dato diagnostico limitato, non un giudizio di sicurezza.",
    ),
    "score_invalid": (
        "No numerical delta: profiles, context, methodology, coverage or supporting observations are incompatible or unknown. Historical scores are preserved.",
        "Nessuna differenza numerica: profili, contesto, metodologia, copertura o osservazioni di supporto sono incompatibili o sconosciuti. I punteggi storici sono conservati.",
    ),
    "overlap": (
        "Counts are per finding and categories can overlap. A changed observation does not establish a configuration-wide improvement or regression.",
        "I conteggi riguardano i finding e le categorie possono sovrapporsi. Un'osservazione cambiata non dimostra un miglioramento o peggioramento complessivo della configurazione.",
    ),
    "methodology": (
        "comparison-v1 compares allowlisted measured fields by exact check ID; missing evidence, method/context changes and unrecognized rules reduce comparability. It never reruns checks or rewrites saved assessments.",
        "comparison-v1 confronta campi misurati consentiti tramite check ID esatti; evidenze mancanti, metodi/contesto diversi e regole non riconosciute riducono la confrontabilità. Non riesegue controlli e non riscrive assessment salvati.",
    ),
    "evidence": (
        "Compared technical evidence (limited projection)",
        "Evidenze tecniche confrontate (proiezione limitata)",
    ),
    "download_json": ("Download comparison JSON", "Scarica confronto JSON"),
    "download_html": ("Download comparison HTML", "Scarica confronto HTML"),
    "methodology_changed": (
        "Check methodologies differ; a result transition cannot be attributed solely to the target.",
        "Le metodologie dei controlli differiscono; una variazione di esito non può essere attribuita solo al target.",
    ),
    "methodology_unknown": (
        "A check methodology is missing or unrecognized; equivalent rules cannot be established.",
        "Una metodologia dei controlli è assente o non riconosciuta; non si possono accertare regole equivalenti.",
    ),
    "context_changed": (
        "User-declared service context differs; it is not independently verified and can change evaluation without DNS changes.",
        "Il contesto del servizio dichiarato dall'utente differisce; non è verificato indipendentemente e può cambiare la valutazione senza modifiche DNS.",
    ),
    "context_missing": (
        "Relevant historical service context was not recorded; missing declarations are not equated to explicit unknown values.",
        "Il contesto storico rilevante non è registrato; dichiarazioni mancanti non sono equiparate a valori esplicitamente sconosciuti.",
    ),
    "applicability_changed": (
        "Applicability state, recorded basis or its availability differs; a result transition may depend on relevance rather than configuration alone.",
        "Stato di applicabilità, base registrata o relativa disponibilità differiscono; una transizione può dipendere dalla rilevanza, non solo dalla configurazione.",
    ),
    "profile_changed": (
        "Scoring profiles differ; numerical scores are not directly comparable.",
        "I profili di punteggio differiscono; i valori numerici non sono direttamente confrontabili.",
    ),
    "profile_unknown": (
        "A scoring profile cannot be established from the saved metadata.",
        "Un profilo di punteggio non è determinabile dai metadati salvati.",
    ),
    "selectors_changed": (
        "DKIM selector sets differ. Added or removed selector checks do not establish new or resolved signing problems.",
        "I selettori DKIM differiscono. Controlli aggiunti o rimossi non accertano nuovi problemi di firma o risoluzioni.",
    ),
    "get_scope_changed": (
        "GET authorization or initial HTTP method differs or is missing; request coverage may differ.",
        "Autorizzazione GET o metodo HTTP iniziale differiscono o sono assenti; la copertura delle richieste può differire.",
    ),
    "method_changed": (
        "Observed HTTP methods differ or a method was not recorded; HEAD and GET responses need not be equivalent.",
        "I metodi HTTP osservati differiscono o un metodo non è registrato; risposte HEAD e GET possono non essere equivalenti.",
    ),
    "client_version_changed": (
        "HTTP client versions differ. The versioned User-Agent can change responses even when check rules and methods match.",
        "Le versioni del client HTTP differiscono. Lo User-Agent con versione può cambiare le risposte anche con regole e metodi uguali.",
    ),
    "endpoint_changed": (
        "The measured endpoint, DNS policy name or selected IP differs; results describe the recorded endpoints only.",
        "Endpoint misurato, nome della policy DNS o IP selezionato differiscono; i risultati riguardano solo gli endpoint registrati.",
    ),
    "redacted_scope": (
        "URL query values were redacted. Equal visible URLs do not establish equivalent hidden request parameters.",
        "I valori delle query URL sono oscurati. URL visibili uguali non accertano parametri nascosti equivalenti.",
    ),
    "response_scope_changed": (
        "HTTP status or content type differs; header/application criteria may refer to different response contexts.",
        "Stato HTTP o tipo di contenuto differiscono; i criteri delle intestazioni/applicativi possono riguardare contesti di risposta diversi.",
    ),
    "missing_earlier": (
        "No unique earlier check exists. This may be a newly introduced check or different coverage, not a new issue.",
        "Non esiste un controllo precedente univoco. Può essere un nuovo controllo o una copertura diversa, non un nuovo problema.",
    ),
    "missing_later": (
        "No unique later check exists. A missing or skipped finding does not prove resolution.",
        "Non esiste un controllo successivo univoco. Un finding assente o saltato non prova la risoluzione.",
    ),
    "duplicate_id": (
        "Duplicate check IDs make matching ambiguous; no arbitrary finding was selected.",
        "Check ID duplicati rendono ambiguo l'abbinamento; nessun finding è stato scelto arbitrariamente.",
    ),
    "incomplete_evidence": (
        "Required measured evidence is missing, malformed, failed or unsupported. Missing fields are not treated as empty observations.",
        "Evidenze misurate necessarie sono mancanti, malformate, fallite o non supportate. I campi mancanti non sono trattati come osservazioni vuote.",
    ),
    "field_coverage_changed": (
        "The sets of recorded measured fields differ; only common fields can be compared directly.",
        "I campi misurati registrati differiscono; solo i campi comuni possono essere confrontati direttamente.",
    ),
    "unmeasured_result": (
        "Unknown, Error or Not applicable on either side prevents a supported concern lifecycle transition.",
        "Uno stato Sconosciuto, Errore o Non applicabile impedisce una transizione attendibile del ciclo del finding.",
    ),
    "same_observation_different_result": (
        "Equivalent recorded observations received different interpretations. This is an evaluation change, not proof of a target improvement or regression; time-dependent expiry rules can also change results.",
        "Osservazioni registrate equivalenti hanno ricevuto interpretazioni diverse. È un cambiamento di valutazione, non prova di miglioramento o peggioramento del target; anche le soglie di scadenza dipendenti dal tempo possono cambiare gli esiti.",
    ),
    "new_supported": (
        "A previously Passed criterion now has a supported concern and different measured evidence under comparable conditions.",
        "Un criterio prima Superato presenta ora un elemento da esaminare supportato da evidenze misurate diverse in condizioni confrontabili.",
    ),
    "resolved_supported": (
        "A previously supported concern now meets the Passed criterion with different measured evidence under comparable conditions.",
        "Un elemento precedentemente supportato soddisfa ora il criterio Superato con evidenze misurate diverse in condizioni confrontabili.",
    ),
    "persistent_supported": (
        "The same criterion remains a supported concern in both runs. This does not establish exploitation or identical underlying causes.",
        "Lo stesso criterio resta un elemento da esaminare supportato in entrambe le esecuzioni. Non dimostra sfruttamento o cause sottostanti identiche.",
    ),
    "observation_changed": (
        "Recorded technical observations differ. Review the field differences and comparability limits before attributing a configuration change.",
        "Le osservazioni tecniche registrate differiscono. Esamina i campi variati e i limiti di confrontabilità prima di attribuire una modifica di configurazione.",
    ),
    "observation_equivalent": (
        "The supported measured fields and interpretation are equivalent within this limited comparison.",
        "I campi misurati supportati e l'interpretazione sono equivalenti entro questo confronto limitato.",
    ),
    "score_criteria_changed": (
        "Scored criterion IDs, applicability or eligibility differ; matching totals alone do not make scores comparable.",
        "ID dei criteri conteggiati, applicabilità o ammissibilità differiscono; totali uguali non rendono confrontabili i punteggi.",
    ),
    "no_scored_criteria": (
        "No nonempty set of evaluated score criteria is available; a numerical score comparison is not meaningful.",
        "Non è disponibile un insieme non vuoto di criteri valutati per il punteggio; un confronto numerico non è significativo.",
    ),
    "invalid_time": (
        "An assessment timestamp is missing or malformed; chronological comparability cannot be established.",
        "Una data di assessment è assente o malformata; la confrontabilità cronologica non è accertabile.",
    ),
    "empty_comparison": (
        "No matched, supported observations are available for this pair.",
        "Non sono disponibili osservazioni abbinate e supportate per questa coppia.",
    ),
}


def ct(key: str, language: str = "it") -> str:
    return STRINGS[key][0 if language == "en" else 1]


def reason(code: str) -> dict:
    return {"code": code, "explanation": asdict(Text(*STRINGS[code]))}
