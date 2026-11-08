"""Generate explicitly synthetic examples offline. Never contacts a target."""

from pathlib import Path
from unittest.mock import Mock, patch

import dns.resolver
import dns.rrset
import httpx

from cybercheck.core.config import Budget, Settings
from cybercheck.core.dns import DNSClient
from cybercheck.core.engine import run_assessment
from cybercheck.core.network import WebClient
from cybercheck.reports.render import render_html, render_json


def main() -> None:
    records = {
        ("example.com.", "A"): ["8.8.8.8"],  # Mocked destination only; never connected.
        ("example.com.", "NS"): ["ns.example.com."],
        ("example.com.", "MX"): ["10 mail.example.com."],
        ("example.com.", "TXT"): ['"v=spf1 ~all"'],
        ("_dmarc.example.com.", "TXT"): ['"v=DMARC1; p=none; rua=mailto:reports@example.com"'],
    }

    def resolve(name, kind, **kwargs):
        if (name, kind) not in records:
            raise dns.resolver.NoAnswer()
        return dns.rrset.from_text(name, 300, "IN", kind, *records[(name, kind)])

    settings = Settings()
    budget = Budget(settings)
    client = DNSClient(budget, Mock(resolve=resolve))

    def respond(request):
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"})
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
        )

    web = WebClient(client, budget, httpx.MockTransport(respond))
    try:
        with patch(
            "cybercheck.checks.tls.socket.create_connection",
            side_effect=TimeoutError("Synthetic fixture: no TLS connection attempted"),
        ):
            assessment = run_assessment(
                "example.com", authorized=True, settings=settings, dns=client, web=web
            )
    finally:
        web.close()
    assessment.metadata |= {
        "synthetic_fixture": True,
        "notice": "SYNTHETIC TEST FIXTURE. Not live evidence; no network assessment occurred.",
    }
    destination = Path(__file__).resolve().parents[1] / "docs" / "examples"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "assessment.html").write_text(render_html(assessment, "en"), encoding="utf-8")
    (destination / "assessment.json").write_text(render_json(assessment), encoding="utf-8")
    print(f"Wrote explicitly synthetic, offline report fixtures to {destination}")


if __name__ == "__main__":
    main()
