"""Scriptable local assessments with an explicit authorization declaration."""

import argparse
import logging
import sqlite3
from pathlib import Path

from cybercheck.core.config import Settings
from cybercheck.core.engine import run_assessment
from cybercheck.core.logging import configure_logging
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.files import write_private_text
from cybercheck.storage.sqlite import Repository


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberCheck: authorized public-domain configuration checks")
    parser.add_argument("domain", help="Domain name only, without URL or port")
    parser.add_argument("--selectors", default="", help="Comma-separated explicit DKIM selectors (maximum 5)")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm ownership or explicit authorization for this domain and related redirects",
    )
    parser.add_argument("--output", type=Path, default=Path("exports"))
    parser.add_argument("--language", choices=["en", "it"], default="it")
    parser.add_argument("--include-score", action="store_true")
    args = parser.parse_args()
    if not args.authorized:
        parser.error(
            "--authorized is required; assess only assets you own or are explicitly authorized to review"
        )
    configure_logging()
    try:
        settings = Settings.from_env()
        assessment = run_assessment(args.domain, args.selectors, authorized=True, settings=settings)
        args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        stem = f"cybercheck-{assessment.domain}-{assessment.id[:8]}"
        # Export before database save so a persistence error does not lose the observations.
        for extension, content in (
            ("html", render_html(assessment, args.language, include_score=args.include_score)),
            ("json", render_json(assessment)),
        ):
            path = args.output / f"{stem}.{extension}"
            write_private_text(path, content)
        Repository(settings.db_path).save(assessment)
    except (ValueError, PermissionError, OSError, sqlite3.Error) as exc:
        logging.getLogger("cybercheck.cli").error("cli_error", extra={"error_type": type(exc).__name__})
        parser.exit(1, f"CyberCheck could not complete: {exc}\n")
    print(f"Assessment {assessment.id}: {assessment.domain}")
    print(f"Results: {assessment.counts}")
    print(f"Reports: {args.output / stem}.html / .json")
    return 0
