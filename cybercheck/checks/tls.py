"""One verified TLS handshake, without version/cipher enumeration."""

import socket
import ssl
from datetime import UTC, datetime

from cybercheck.core.config import Budget, LimitReached
from cybercheck.core.dns import DNSClient
from cybercheck.core.validation import UnsafeTarget
from cybercheck.locales.findings import finding
from cybercheck.models import Finding
from cybercheck.models import Severity as S
from cybercheck.models import Status as T

KEYS = ("tls.connection", "tls.chain", "tls.hostname", "tls.validity", "tls.protocol")


def check_tls(domain: str, dns: DNSClient, budget: Budget) -> list[Finding]:
    evidence: dict = {"hostname": domain, "port": 443, "verification": "local system trust store"}
    try:
        address = dns.public_addresses(domain)[0]
        evidence["address"] = address
        timeout = budget.remaining()
        context = ssl.create_default_context()
        # No insecure retry to retrieve otherwise untrusted certificate data.
        with socket.create_connection((address, 443), timeout=timeout) as raw:
            raw.settimeout(budget.remaining())
            with context.wrap_socket(raw, server_hostname=domain) as secured:
                certificate = secured.getpeercert()
                protocol = secured.version()
                cipher = secured.cipher()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), UTC)
        starts = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notBefore"]), UTC)
        seconds = (expires - datetime.now(UTC)).total_seconds()
        days = int(seconds // 86400)
        issuer = {name: value for component in certificate.get("issuer", ()) for name, value in component}
        evidence |= {
            "issuer": issuer,
            "not_before": starts.isoformat(),
            "not_after": expires.isoformat(),
            "days_until_expiration": days,
            "protocol": protocol,
            "cipher": cipher,
            "subject_alt_names": certificate.get("subjectAltName", ()),
        }
        return [
            finding(
                "tls.connection",
                T.PASSED,
                S.INFO,
                "Verified HTTPS handshake succeeded for this hostname.",
                "Handshake HTTPS verificato riuscito per questo nome host.",
                evidence,
            ),
            finding(
                "tls.chain",
                T.PASSED,
                S.INFO,
                "Certificate chain accepted by the local trust store. Revocation/CT were not checked.",
                "Catena accettata dal trust store locale. Revoca e Certificate Transparency non verificate.",
                evidence,
                scoreable=True,
            ),
            finding(
                "tls.hostname",
                T.PASSED,
                S.INFO,
                "The TLS library verified the requested hostname against the certificate.",
                "La libreria TLS ha verificato il nome host richiesto rispetto al certificato.",
                evidence,
                scoreable=True,
            ),
            finding(
                "tls.validity",
                T.WARNING if seconds < 30 * 86400 else T.PASSED,
                S.LOW if seconds < 30 * 86400 else S.INFO,
                f"Certificate is currently valid and expires on {expires.date().isoformat()} UTC ({days} complete days remaining).",
                f"Certificato attualmente valido, in scadenza il {expires.date().isoformat()} UTC ({days} giorni interi rimanenti).",
                evidence,
                scoreable=True,
            ),
            finding(
                "tls.protocol",
                T.PASSED if protocol in {"TLSv1.2", "TLSv1.3"} else T.UNKNOWN,
                S.INFO,
                f"Negotiated {protocol}. Other supported or obsolete versions were not probed.",
                f"Negoziato {protocol}. Le altre versioni supportate o obsolete non sono state sondate.",
                evidence,
                scoreable=True,
            ),
        ]
    except ssl.SSLCertVerificationError as exc:
        evidence |= {"verify_code": exc.verify_code, "verify_message": exc.verify_message}
        # A specific verification failure is evidence only for that dimension.
        failed_key = (
            "tls.hostname"
            if exc.verify_code in {62, 64}
            else "tls.validity"
            if exc.verify_code in {9, 10}
            else "tls.chain"
        )
        return [
            finding(
                key,
                T.FAILED if key == failed_key else T.UNKNOWN,
                S.HIGH if key == failed_key else S.INFO,
                "Certificate verification failed: " + str(exc.verify_message)
                if key == failed_key
                else "Handshake stopped on certificate verification; this dimension was not independently established.",
                "Verifica del certificato fallita: " + str(exc.verify_message)
                if key == failed_key
                else "Handshake interrotto dalla verifica del certificato; questa dimensione non è accertata indipendentemente.",
                evidence,
                scoreable=key == failed_key,
            )
            for key in KEYS
        ]
    except (OSError, ssl.SSLError, UnsafeTarget, LimitReached) as exc:
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        return [
            finding(
                key,
                T.UNKNOWN,
                S.INFO,
                "TLS check could not complete. A connection failure is not proof of an insecure certificate or absent HTTPS.",
                "Verifica TLS non completata. Un errore di connessione non prova un certificato insicuro o l'assenza di HTTPS.",
                evidence,
            )
            for key in KEYS
        ]
