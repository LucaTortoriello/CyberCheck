"""Conservative DNS/email configuration checks, without sending email."""

import base64
import binascii
import ipaddress
import re

from cybercheck.core.dns import DNSClient, DNSResult
from cybercheck.core.network import organizational_domain
from cybercheck.core.validation import UnsafeTarget, normalize_dns_name
from cybercheck.locales.findings import finding
from cybercheck.models import Finding, Text
from cybercheck.models import Severity as S
from cybercheck.models import Status as T


def unavailable(key: str, result: DNSResult, *, suffix: str = "") -> Finding:
    return finding(
        key,
        T.UNKNOWN,
        S.INFO,
        "DNS name does not exist; this configuration cannot be established."
        if result.state == "nxdomain"
        else "DNS lookup could not be completed; configuration is unknown.",
        "Il nome DNS non esiste; questa configurazione non è accertabile."
        if result.state == "nxdomain"
        else "La query DNS non è stata completata; la configurazione è sconosciuta.",
        result.evidence(),
        suffix=suffix,
    )


def tags(record: str) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    errors: list[str] = []
    for part in record.split(";"):
        if not part.strip():
            continue
        key, sep, value = part.strip().partition("=")
        key = key.strip()
        if not sep or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", key):
            errors.append(f"Malformed tag: {part}")
            continue
        if key in values:
            errors.append(f"Duplicate tag: {key}")
        values[key] = value.strip()
    return values, errors


def check_dns(domain: str, dns: DNSClient) -> list[Finding]:
    records = {kind: dns.query(domain, kind) for kind in ("A", "AAAA", "NS", "MX", "CAA")}
    inventory = finding(
        "dns.records",
        T.UNKNOWN if any(v.state in {"error", "nxdomain"} for v in records.values()) else T.PASSED,
        S.INFO,
        "Exact-name DNS inventory; NS records can legitimately exist only at the zone apex.",
        "Inventario DNS del nome esatto; i record NS possono legittimamente esistere solo all'apice della zona.",
        {kind: result.evidence() for kind, result in records.items()},
    )
    mx, caa = records["MX"], records["CAA"]
    findings = [inventory]
    if mx.state in {"error", "nxdomain"}:
        findings.append(unavailable("dns.mx", mx))
    else:
        null = any(re.fullmatch(r"0\s+\.", value) for value in mx.records)
        contradictory = null and len(mx.records) > 1
        findings.append(
            finding(
                "dns.mx",
                T.FAILED if contradictory else T.PASSED if mx.records else T.WARNING,
                S.MEDIUM if contradictory else S.INFO,
                "Null MX conflicts with other MX records."
                if contradictory
                else "Null MX explicitly declares no inbound email."
                if null
                else "MX records found; mail server reachability was not tested."
                if mx.records
                else "No explicit MX found; implicit A/AAAA mail routing may apply. This is not a vulnerability by itself.",
                "Il Null MX è in conflitto con altri record MX."
                if contradictory
                else "Il Null MX dichiara esplicitamente che il dominio non riceve email."
                if null
                else "Record MX presenti; la raggiungibilità dei server email non è stata verificata."
                if mx.records
                else "Nessun MX esplicito; può valere l'instradamento implicito A/AAAA. Non è da solo una vulnerabilità.",
                mx.evidence(),
                scoreable=contradictory,
            )
        )
    if caa.state in {"error", "nxdomain"}:
        findings.append(unavailable("dns.caa", caa))
    else:
        findings.append(
            finding(
                "dns.caa",
                T.PASSED if caa.records else T.WARNING,
                S.INFO,
                "CAA records published at this exact name; issuer authorization semantics were not evaluated."
                if caa.records
                else "No CAA at this exact name. Parent/CNAME policies may apply; effective CAA was not evaluated.",
                "Record CAA pubblicati a questo nome esatto; la semantica di autorizzazione non è stata valutata."
                if caa.records
                else "Nessun CAA al nome esatto. Possono valere policy del padre/CNAME; il CAA effettivo non è stato valutato.",
                caa.evidence(),
            )
        )
    return findings


def spf_records(result: DNSResult) -> list[str]:
    return [r for r in result.records if re.match(r"^v=spf1(?:\s|$)", r, re.I)]


def check_spf(domain: str, dns: DNSClient) -> list[Finding]:
    result = dns.query(domain, "TXT")
    if result.state in {"error", "nxdomain"}:
        return [unavailable("email.spf", result)]
    records = spf_records(result)
    evidence = result.evidence() | {"spf_records": records}
    if not records:
        return [
            finding(
                "email.spf",
                T.WARNING,
                S.MEDIUM,
                "No SPF policy found at this name. Confirm whether the domain sends email before choosing a policy.",
                "Nessuna policy SPF a questo nome. Verifica se il dominio invia email prima di scegliere una policy.",
                evidence,
            )
        ]
    if len(records) > 1:
        return [
            finding(
                "email.spf",
                T.FAILED,
                S.MEDIUM,
                "Multiple SPF records cause SPF permerror.",
                "Più record SPF causano un permerror SPF.",
                evidence,
                scoreable=True,
            )
        ]
    terms = records[0].split()[1:]
    errors: list[str] = []
    modifiers: dict[str, str] = {}
    all_qualifier: str | None = None
    macros = False
    for term in terms:
        modifier = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)", term)
        if modifier:
            name, value = modifier.groups()
            name = name.lower()
            if name in {"redirect", "exp"} and (not value or name in modifiers):
                errors.append(f"Malformed or duplicate defined modifier: {term}")
            if name in {"redirect", "exp"}:
                macros |= "%" in value
            modifiers[name] = value
            continue
        macros |= "%" in term
        qualifier = term[0] if term and term[0] in "+-~?" else "+"
        mechanism = term[1:] if term and term[0] in "+-~?" else term
        name = re.split(r"[:/]", mechanism, maxsplit=1)[0].lower()
        if name not in {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}:
            errors.append(f"Unknown mechanism: {term}")
        if name == "all":
            if mechanism.lower() != "all":
                errors.append(f"Invalid all mechanism: {term}")
            if all_qualifier is None:
                all_qualifier = qualifier
        if name in {"include", "exists"} and (":" not in mechanism or not mechanism.partition(":")[2]):
            errors.append(f"Missing domain: {term}")
        if name in {"a", "mx"} and "%" not in mechanism:
            match = re.fullmatch(
                r"(?:a|mx)(?::[^/]+)?(?:/(0|[1-9][0-9]?))?(?://(0|[1-9][0-9]{0,2}))?", mechanism, re.I
            )
            if (
                not match
                or (match[1] is not None and int(match[1]) > 32)
                or (match[2] is not None and int(match[2]) > 128)
            ):
                errors.append(f"Invalid A/MX CIDR syntax: {term}")
        if name == "ptr" and "%" not in mechanism and not re.fullmatch(r"ptr(?::[^/]+)?", mechanism, re.I):
            errors.append(f"Invalid PTR syntax: {term}")
        if name in {"ip4", "ip6"}:
            try:
                address = mechanism.partition(":")[2]
                if "%" in address or (
                    "/" in address and not re.fullmatch(r"[^/]+/(0|[1-9][0-9]{0,2})", address)
                ):
                    raise ValueError("Invalid SPF prefix")
                network = ipaddress.ip_network(address, strict=False)
                if network.version != (4 if name == "ip4" else 6):
                    raise ValueError("Address family mismatch")
            except ValueError:
                errors.append(f"Invalid IP network: {term}")
    evidence |= {
        "terminal_all_qualifier": all_qualifier,
        "modifiers": modifiers,
        "syntax_errors": errors,
        "scope": "Common syntax checks only; no sender-dependent SPF evaluation",
    }
    if errors:
        status, severity = T.FAILED, S.MEDIUM
        en, it = (
            "Definite SPF syntax problems detected: " + "; ".join(errors),
            "Problemi certi di sintassi SPF: " + "; ".join(errors),
        )
    elif all_qualifier == "+":
        status, severity = T.FAILED, S.HIGH
        en, it = (
            "The first all mechanism uses +all and authorizes every sender not already matched by an earlier mechanism.",
            "Il primo meccanismo all usa +all e autorizza ogni mittente non già intercettato da un meccanismo precedente.",
        )
    elif all_qualifier == "?" or (all_qualifier is None and "redirect" not in modifiers):
        status, severity = T.WARNING, S.LOW
        en, it = (
            "SPF has a neutral or implicit neutral fallback. Review against the legitimate sending inventory.",
            "SPF ha un esito finale neutro o neutro implicito. Verifica rispetto ai mittenti legittimi.",
        )
    elif macros:
        status, severity = T.UNKNOWN, S.INFO
        en, it = (
            "SPF macros require sender context; complete policy validity was not determined.",
            "Le macro SPF richiedono il contesto del mittente; la validità completa non è determinata.",
        )
    else:
        status, severity = T.PASSED, S.INFO
        en, it = (
            "Common SPF checks passed. Softfail and fail policies serve different rollout needs; -all is not universally required.",
            "Le verifiche SPF comuni sono superate. Softfail e fail rispondono a esigenze diverse; -all non è sempre richiesto.",
        )
    findings = [finding("email.spf", status, severity, en, it, evidence, scoreable=False)]
    count, notes, visited = 0, [], []

    def walk(name: str, policy: str, ancestors: set[str]) -> None:
        nonlocal count
        if name in ancestors or len(ancestors) >= 10:
            notes.append("Cycle or depth limit encountered; sender-dependent evaluation deferred")
            return
        visited.append(name)
        local_all = False
        redirect = None
        for term in policy.split()[1:]:
            modifier = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)", term)
            if modifier and modifier[1].lower() not in {"redirect", "exp"}:
                continue
            if "%" in term:
                notes.append("Sender-dependent macro; lookup path cannot be fully evaluated")
            term = term.lstrip("+-~?")
            if term.lower() == "all":
                local_all = True
                break
            if term.lower().startswith("redirect="):
                redirect = term.split("=", 1)[1]
                continue
            name_part = re.split(r"[:/]", term, maxsplit=1)[0].lower()
            if name_part in {"include", "a", "mx", "ptr", "exists"}:
                count += 1
            if name_part == "include":
                nested(term.partition(":")[2], ancestors | {name})
            if count > 10:
                return
        if redirect and not local_all:
            count += 1
            nested(redirect, ancestors | {name})

    def nested(name: str, ancestors: set[str]) -> None:
        if count > 10:
            return
        try:
            target = normalize_dns_name(name)
        except UnsafeTarget:
            notes.append("Macro, unsupported, or invalid include/redirect target")
            return
        response = dns.query(target, "TXT")
        policies = spf_records(response)
        if response.state == "error" or len(policies) != 1:
            notes.append(f"Dependent SPF not uniquely available: {target}")
        else:
            walk(target, policies[0], ancestors)

    walk(domain, records[0], set())
    findings.append(
        finding(
            "email.spf_lookups",
            T.WARNING if count > 10 else T.UNKNOWN if notes else T.PASSED,
            S.LOW if count > 10 else S.INFO,
            "Static lookup-path estimate only. More than ten potential DNS terms can exceed RFC limits on some sender paths; this is not a confirmed runtime permerror. MX/PTR fan-out, void lookups and macros are not fully evaluated.",
            "Solo stima statica dei percorsi. Oltre dieci termini DNS potenziali possono superare i limiti RFC su alcuni percorsi; non è un permerror runtime confermato. Fan-out MX/PTR, lookup vuoti e macro non sono valutati completamente.",
            {"potential_dns_terms": count, "notes": notes, "visited_policies": visited},
        )
    )
    return findings


def dmarc_records(result: DNSResult) -> list[str]:
    return [r for r in result.records if re.match(r"^v[ \t]*=[ \t]*DMARC1(?:[ \t]*;|[ \t]*$)", r)]


def check_dmarc(domain: str, dns: DNSClient) -> list[Finding]:
    policy_domain = domain
    result = dns.query(f"_dmarc.{domain}", "TXT")
    if result.state == "error":
        return [unavailable("email.dmarc", result)]
    records = dmarc_records(result)
    org = organizational_domain(domain)
    if not records and org != domain:
        policy_domain = org
        result = dns.query(f"_dmarc.{org}", "TXT")
        if result.state == "error":
            return [unavailable("email.dmarc", result)]
        records = dmarc_records(result)
    evidence = result.evidence() | {"policy_domain": policy_domain, "inherited": policy_domain != domain}
    if not records:
        return [
            finding(
                "email.dmarc",
                T.WARNING,
                S.MEDIUM,
                "No DMARC policy found at this name or its organizational domain using the bundled public suffix list.",
                "Nessuna policy DMARC al nome o al dominio organizzativo secondo la lista dei suffissi pubblici inclusa.",
                evidence,
            )
        ]
    parsed, errors = tags(records[0])
    if len(records) != 1:
        errors.append("Multiple DMARC records")
    if parsed.get("v") != "DMARC1" or parsed.get("p") not in {"none", "quarantine", "reject"}:
        errors.append("Invalid or missing v/p")
    if list(parsed)[:2] != ["v", "p"]:
        errors.append("v and p must be the first two tags")
    if "sp" in parsed and parsed["sp"] not in {"none", "quarantine", "reject"}:
        errors.append("Invalid sp")
    for alignment in ("adkim", "aspf"):
        if parsed.get(alignment, "r") not in {"r", "s"}:
            errors.append(f"Invalid {alignment}")
    pct_text = parsed.get("pct", "100")
    pct = int(pct_text) if re.fullmatch(r"[0-9]{1,3}", pct_text) else -1
    if not 0 <= pct <= 100:
        errors.append("Invalid pct")
    policy = parsed.get("sp", parsed.get("p")) if policy_domain != domain else parsed.get("p")
    evidence |= {
        "tags": parsed,
        "effective_policy": policy,
        "pct": pct,
        "syntax_errors": errors,
        "policy_model": "RFC 7489 legacy discovery and percentage semantics",
        "limitations": "RFC 9989 DNS tree walk, np, psd and t semantics are not implemented",
    }
    if errors:
        return [
            finding(
                "email.dmarc",
                T.FAILED,
                S.MEDIUM,
                "DMARC record has configuration errors: " + "; ".join(errors),
                "Il record DMARC contiene errori: " + "; ".join(errors),
                evidence,
                scoreable=True,
            )
        ]
    unsupported = bool({"np", "psd", "t"} & parsed.keys())
    monitoring = policy == "none" or pct == 0
    partial = not monitoring and pct < 100
    findings = [
        finding(
            "email.dmarc",
            T.UNKNOWN if unsupported else T.WARNING if monitoring or partial else T.PASSED,
            S.INFO if unsupported else S.LOW if monitoring or partial else S.INFO,
            f"Legacy RFC 7489 policy {policy}, pct={pct}. "
            + (
                "Current-standard tags were observed; effective RFC 9989 receiver policy was not determined."
                if unsupported
                else "Monitoring without requested enforcement; appropriate during a managed rollout."
                if monitoring
                else "Partial enforcement requested; receiver behavior can differ."
                if partial
                else "Enforcement requested; this does not verify message alignment or receiver compliance."
            ),
            f"Policy legacy RFC 7489 {policy}, pct={pct}. "
            + (
                "Osservati tag del nuovo standard; la policy effettiva RFC 9989 non è determinata."
                if unsupported
                else "Monitoraggio senza applicazione richiesta; può essere appropriato durante un rilascio controllato."
                if monitoring
                else "Applicazione parziale richiesta; il comportamento dei destinatari può variare."
                if partial
                else "Applicazione richiesta; non verifica l'allineamento dei messaggi o il comportamento dei destinatari."
            ),
            evidence,
        )
    ]
    rua = parsed.get("rua", "")
    destinations = [s.strip() for s in rua.split(",") if s.strip()]
    valid = bool(destinations) and all(
        re.fullmatch(r"mailto:[^\s@,]+@[^\s@,]+(?:![0-9]+[kmgt]?)?", value, re.I) for value in destinations
    )
    findings.append(
        finding(
            "email.dmarc_reporting",
            T.PASSED if valid else T.WARNING,
            S.INFO,
            "Aggregate reporting destinations are configured. Delivery, external-destination authorization and mailbox ownership are not verified."
            if valid
            else "Aggregate reporting is absent or has an unsupported/malformed destination; this is an operational observation, not proof of an authentication failure.",
            "Destinazioni dei report aggregati configurate. Consegna, autorizzazione esterna e proprietà delle caselle non sono verificate."
            if valid
            else "Report aggregati assenti o con destinazione non supportata/malformata; è un'osservazione operativa, non prova di mancata autenticazione.",
            {"rua": rua, "ruf": parsed.get("ruf"), "policy_domain": policy_domain},
            remediation=Text(
                "Use a monitored aggregate-report mailbox or reporting service. Consider privacy before enabling forensic reports (ruf).",
                "Usa una casella monitorata per report aggregati o un servizio di analisi. Valuta la privacy prima dei report forensi (ruf).",
            ),
        )
    )
    return findings


def check_dkim(domain: str, selectors: list[str], dns: DNSClient) -> list[Finding]:
    if not selectors:
        return [
            finding(
                "email.dkim",
                T.UNKNOWN,
                S.INFO,
                "DKIM cannot be reliably determined from a domain alone. No selector was supplied; no selector discovery was attempted. Unknown does not mean disabled.",
                "DKIM non è determinabile in modo affidabile dal solo dominio. Nessun selettore fornito; non è stata tentata una ricerca. Sconosciuto non significa disabilitato.",
                remediation=Text(
                    "Get selectors from your mail provider or the s= tag of a DKIM-Signature header.",
                    "Ottieni i selettori dal provider email o dal tag s= dell'intestazione DKIM-Signature.",
                ),
            )
        ]
    findings = []
    for selector in selectors:
        result = dns.query(f"{selector}._domainkey.{domain}", "TXT")
        suffix = f":{selector}"
        if result.state == "error":
            findings.append(unavailable("email.dkim", result, suffix=suffix))
            continue
        if not result.records:
            findings.append(
                finding(
                    "email.dkim",
                    T.UNKNOWN,
                    S.INFO,
                    "No key found at this supplied selector; other selectors may be active. DKIM is not proven disabled.",
                    "Nessuna chiave a questo selettore; altri selettori possono essere attivi. DKIM non risulta disabilitato.",
                    result.evidence(),
                    suffix=suffix,
                )
            )
            continue
        parsed, errors = tags(result.records[0])
        if len(result.records) != 1:
            errors.append("Multiple key records")
        if parsed.get("v", "DKIM1") != "DKIM1" or ("v" in parsed and next(iter(parsed)) != "v"):
            errors.append("Invalid key version or version position")
        if "p" not in parsed:
            errors.append("Missing public key tag")
        revoked = "p" in parsed and not parsed["p"]
        key_bytes = b""
        try:
            key_bytes = base64.b64decode(re.sub(r"\s", "", parsed.get("p", "")), validate=True)
        except (ValueError, binascii.Error):
            errors.append("Public key is not valid base64")
        if parsed.get("k", "rsa") == "ed25519" and not revoked and len(key_bytes) != 32:
            errors.append("Ed25519 public key must have 32 bytes")
        status = T.FAILED if errors else T.WARNING if revoked else T.PASSED
        findings.append(
            finding(
                "email.dkim",
                status,
                S.MEDIUM if errors or revoked else S.INFO,
                "Published selector has malformed key tags: " + "; ".join(errors)
                if errors
                else "This selector's public key is explicitly revoked (empty p=); other selectors may remain active."
                if revoked
                else "A base64-encoded public key is published. Key cryptographic validity, signing and alignment were not verified.",
                "Il selettore pubblicato contiene tag malformati: " + "; ".join(errors)
                if errors
                else "La chiave di questo selettore è revocata (p= vuoto); altri selettori possono essere attivi."
                if revoked
                else "Chiave pubblica codificata base64 pubblicata. Validità crittografica, firma e allineamento non sono verificati.",
                result.evidence() | {"tags": parsed, "errors": errors},
                suffix=suffix,
            )
        )
    return findings
