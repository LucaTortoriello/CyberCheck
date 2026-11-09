"""Optional browser/print smoke check against an isolated localhost preview.

Requires Playwright in a separate developer environment and installed Chrome.
Never starts an assessment. Use a database containing labeled synthetic data.
"""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


def main() -> None:
    from playwright.sync_api import expect, sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8502)
    parser.add_argument("--output", type=Path, default=Path("/tmp/cybercheck-v02-browser"))
    parser.add_argument("--report", type=Path, default=Path("docs/examples/assessment.html"))
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a local development port between 1024 and 65535")
    args.output.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    result: dict = {"synthetic_only": True, "live_assessment_started": False, "viewports": []}

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(viewport={"width": 1365, "height": 900})

        def local_only(route) -> None:
            url = urlsplit(route.request.url)
            if url.scheme in {"file", "data", "blob"} or (
                url.hostname == "127.0.0.1" and url.port == args.port
            ):
                route.continue_()
            else:
                route.abort()

        context.route("**/*", local_only)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(f"http://127.0.0.1:{args.port}/")
        expect(
            page.get_by_text("DATI SINTETICI DI TEST — Questo non è un assessment live.", exact=True)
        ).to_be_visible()
        page.screenshot(path=str(args.output / "overview-it-desktop.png"), full_page=True)
        page.get_by_role("combobox").first.click()
        page.get_by_role("option", name="English", exact=True).click()
        expect(
            page.get_by_text("SYNTHETIC TEST FIXTURE — This is not a live assessment.", exact=True)
        ).to_be_visible()

        for view in ("Overview", "New Assessment", "Assessment History", "Findings", "Reports", "Settings"):
            page.get_by_role("radiogroup").get_by_text(view, exact=True).click()
            expect(
                page.get_by_role("heading", name="example.com" if view == "Overview" else view, exact=True)
            ).to_be_visible()
            expect(page.locator('[data-testid="stException"]')).to_have_count(0)
        page.get_by_role("radiogroup").get_by_text("New Assessment", exact=True).click()
        expect(page.get_by_role("button", name="Start Assessment", exact=True)).to_be_visible()
        page.screenshot(path=str(args.output / "new-assessment-en-desktop.png"), full_page=True)
        for width, height in ((1365, 900), (390, 844)):
            page.set_viewport_size({"width": width, "height": height})
            page.get_by_role("radiogroup").get_by_text("Overview", exact=True).click()
            expect(
                page.get_by_text("SYNTHETIC TEST FIXTURE — This is not a live assessment.", exact=True)
            ).to_be_visible()
            page.wait_for_timeout(250)  # Allow responsive layout measurement to settle.
            dimensions = page.evaluate("({width: innerWidth, scroll: document.documentElement.scrollWidth})")
            assert dimensions["scroll"] <= width + 2, dimensions
            result["viewports"].append({"width": width, "height": height, "horizontal_overflow": False})
            page.screenshot(path=str(args.output / f"overview-en-{width}.png"), full_page=True)
        report = context.new_page()
        report.set_viewport_size({"width": 1100, "height": 1000})
        report.goto(args.report.resolve().as_uri())
        expect(report.get_by_role("heading", name="Security Assessment Report", exact=True)).to_be_visible()
        expect(
            report.get_by_text("SYNTHETIC TEST FIXTURE — NOT A LIVE ASSESSMENT", exact=True)
        ).to_be_visible()
        report.emulate_media(media="print")
        report.screenshot(path=str(args.output / "report-print-preview.png"))
        pdf = report.pdf(path=str(args.output / "synthetic-report.pdf"), format="A4", print_background=True)
        assert pdf.startswith(b"%PDF") and len(pdf) > 5000
        result["pdf_bytes"] = len(pdf)
        result["pdf_pages"] = len(re.findall(rb"/Type\s*/Page\b", pdf))
        result["browser"] = browser.version
        result["page_errors"] = errors
        assert not errors, errors
        context.close()
        browser.close()
    (args.output / "browser-validation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
