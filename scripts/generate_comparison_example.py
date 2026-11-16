"""Generate labeled, fictional comparison reports offline; never scans a target."""

from copy import deepcopy
from pathlib import Path

from cybercheck.core.comparison import compare_assessments
from cybercheck.locales.findings import finding
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_comparison_html, render_comparison_json


def dns(records: list[str], name: str = "example.com") -> dict:
    return {"name": name, "record_type": "TXT", "state": "ok", "records": records}


def header(value: str | None) -> dict:
    return {
        "url": "https://example.com/",
        "method": "HEAD",
        "status_code": 200,
        "content_type": "text/html",
        "header_value": value,
    }


def main() -> None:
    metadata = {
        "engine_version": "0.4.0",
        "scoring_profile": "context-v1",
        "context": {
            "sends_email": True,
            "receives_email": False,
            "controls_dns": False,
            "source": "user_declared",
            "independently_verified": False,
        },
        "http_method": "HEAD",
        "get_fallback_enabled": False,
        "synthetic_fixture": True,
    }
    earlier = Assessment(
        "example.com",
        id="synthetic-earlier",
        started_at="2026-10-01T00:00:00+00:00",
        metadata=deepcopy(metadata),
    )
    later = Assessment(
        "example.com",
        id="synthetic-later",
        started_at="2026-11-16T00:00:00+00:00",
        metadata=deepcopy(metadata),
    )
    later.metadata |= {"engine_version": "0.4.0", "methodology_version": "checks-v0.3"}
    cert = {
        "hostname": "example.com",
        "port": 443,
        "address": "8.8.8.8",
        "issuer": {"organizationName": "Fictional test CA"},
        "not_before": "2026-09-01T00:00:00+00:00",
        "not_after": "2026-12-01T00:00:00+00:00",
        "protocol": "TLSv1.2",
    }
    renewed = cert | {
        "not_before": "2026-11-16T00:00:00+00:00",
        "not_after": "2027-02-14T00:00:00+00:00",
        "protocol": "TLSv1.3",
    }
    rows = [
        ("email.spf", Status.WARNING, Status.PASSED, dns(["v=spf1 +all"]), dns(["v=spf1 -all"])),
        (
            "email.dmarc",
            Status.WARNING,
            Status.PASSED,
            dns(["v=DMARC1; p=none"], "_dmarc.example.com"),
            dns(["v=DMARC1; p=reject"], "_dmarc.example.com"),
        ),
        ("headers.csp", Status.WARNING, Status.PASSED, header(None), header("default-src 'self'")),
        ("tls.validity", Status.PASSED, Status.PASSED, cert, renewed),
        ("tls.protocol", Status.PASSED, Status.PASSED, cert, renewed),
        (
            "headers.framing",
            Status.WARNING,
            Status.PASSED,
            header("frame-ancestors=[]; X-Frame-Options="),
            header("frame-ancestors=[]; X-Frame-Options=DENY")
            | {"observed_headers": {"content-security-policy": [], "x-frame-options": ["DENY"]}},
        ),
        ("headers.referrer", Status.WARNING, Status.WARNING, header(None), header(None)),
    ]
    for key, old_status, new_status, old_evidence, new_evidence in rows:
        for a, status, evidence in ((earlier, old_status, old_evidence), (later, new_status, new_evidence)):
            evidence = deepcopy(evidence) | {
                "applicability": {
                    "state": "applicable",
                    "basis": "user_declared",
                    "reason": {
                        "en": "Fictional service requirements",
                        "it": "Requisiti fittizi del servizio",
                    },
                }
            }
            f = finding(
                key,
                status,
                Severity.INFO if status == Status.PASSED else Severity.LOW,
                "Fictional educational observation; not a live result.",
                "Osservazione didattica fittizia; non è un risultato live.",
                evidence,
                scoreable=key.startswith("tls."),
            )
            f.id = f"{a.id}-{key}"
            f.timestamp = a.started_at
            a.findings.append(f)
    comparison = compare_assessments(earlier, later)
    destination = Path(__file__).resolve().parents[1] / "docs" / "examples"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "comparison.json").write_text(render_comparison_json(comparison), encoding="utf-8")
    for language in ("en", "it"):
        (destination / f"comparison.{language}.html").write_text(
            render_comparison_html(comparison, language), encoding="utf-8"
        )
    print(f"Wrote fictional, offline comparison reports to {destination}")


if __name__ == "__main__":
    main()
