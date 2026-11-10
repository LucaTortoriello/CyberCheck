"""User-facing reliability and report coverage, using synthetic data only."""

import json
import sqlite3
from html import unescape
from unittest.mock import patch

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from cybercheck.checks.email import check_dmarc, check_spf
from cybercheck.checks.headers import active_hsts_policy, check_headers
from cybercheck.cli import main
from cybercheck.core.network import WebClient
from cybercheck.locales.findings import finding
from cybercheck.locales.ui import STRINGS, tr
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.sqlite import Repository, StorageDataError


def sample():
    return Assessment(
        "example.com",
        findings=[
            finding("tls.chain", Status.FAILED, Severity.HIGH, "Confirmed", "Confermato", scoreable=True),
            finding("email.dkim", Status.UNKNOWN, Severity.INFO, "Not verified", "Non verificato"),
            finding("engine.error", Status.ERROR, Severity.INFO, "Incomplete", "Incompleto"),
            finding("headers.csp", Status.NA, Severity.INFO, "Not applicable", "Non applicabile"),
        ],
        metadata={"synthetic_fixture": True},
        authorization_confirmed=True,
    )


def test_json_summary_never_classifies_unknown_error_or_na_as_confirmed():
    a = sample()
    report = json.loads(render_json(a))
    assert report["summary"]["confirmed_finding_ids"] == [a.findings[0].id]
    assert report["summary"]["inconclusive_finding_ids"] == [a.findings[1].id, a.findings[2].id]
    assert Assessment.from_dict(report).to_dict() == a.to_dict()


@pytest.mark.parametrize("language", ["en", "it"])
def test_html_scope_inconclusive_sections_and_print_styling(language):
    a = sample()
    report = render_html(a, language)
    for key in ("report_scope", "report_confirmed", "report_inconclusive", "methodology", "disclaimer"):
        assert tr(key, language) in unescape(report)
    assert "@page{size:A4" in report
    assert "display:table-header-group" in report
    assert f'id="finding-{a.findings[1].id}"' in report
    assert "SYNTHETIC TEST FIXTURE" in report


def test_translation_catalog_pairs_are_nonempty_and_format_compatibly():
    from string import Formatter

    formatter = Formatter()
    for key, pair in STRINGS.items():
        assert len(pair) == 2 and all(pair), key
        en_fields = {name for _, name, _, _ in formatter.parse(pair[0]) if name}
        it_fields = {name for _, name, _, _ in formatter.parse(pair[1]) if name}
        assert en_fields == it_fields, key


@pytest.mark.parametrize("suffix", ["t=y", "np=reject", "psd=y"])
def test_current_dmarc_markers_remain_inconclusive(fake_dns, suffix):
    dns = fake_dns({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; " + suffix]})
    f = check_dmarc("example.com", dns)[0]
    assert f.status == Status.UNKNOWN and f.severity == Severity.INFO
    assert not f.scoreable
    assert "RFC 7489" in f.explanation.en
    assert "RFC 9989" in f.explanation.en


def test_ignored_spf_extension_macros_do_not_create_unknown_status(fake_dns):
    dns = fake_dns({("example.com", "TXT"): ["v=spf1 future=%{l} ~all"]})
    assert all(f.status == Status.PASSED for f in check_spf("example.com", dns))


def test_hsts_extension_quoted_semicolon_is_not_a_directive_separator():
    assert active_hsts_policy('max-age=100; custom="a;b"')


@pytest.mark.parametrize(
    ("values", "expected"),
    [(["max-age=100", "max-age=0"], Status.PASSED), (["max-age=0", "max-age=100"], Status.WARNING)],
)
def test_first_hsts_field_is_used_through_httpx(fake_dns, values, expected):
    dns = fake_dns({("example.com", "A"): ["8.8.8.8"]})
    web = WebClient(
        dns,
        dns.budget,
        httpx.MockTransport(
            lambda r: httpx.Response(200, headers=[("strict-transport-security", v) for v in values])
        ),
    )
    try:
        response = web.fetch("https://example.com/", "example.com")
        assert response.values("strict-transport-security") == values
        assert next(f for f in check_headers(response) if f.check_id == "headers.hsts").status == expected
    finally:
        web.close()


def test_ui_retry_saves_existing_results_without_running_assessment_again(monkeypatch, tmp_path):
    path = tmp_path / "history.sqlite3"
    monkeypatch.setenv("CYBERCHECK_DB", str(path))
    a = sample()
    with patch("cybercheck.app.dashboard.run_assessment", return_value=a) as run:
        app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
        app.radio(key="navigation").set_value("new").run()
        app.text_input[0].set_value("example.com")
        app.checkbox[0].check()
        with patch.object(Repository, "save", side_effect=sqlite3.OperationalError("locked")):
            app.button[0].click().run()
        assert not app.exception
        assert not app.success
        assert app.get("progress")[0].proto.text == tr("checks_not_saved")
        app.radio(key="navigation").set_value("reports").run()
        assert len(app.get("download_button")) == 2
        app.button(key="retry_save").click().run()
        assert not app.exception
        assert run.call_count == 1
        assert Repository(path).get(a.id) is not None


def test_ui_configuration_error_is_actionable_and_bilingual(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "unused.sqlite3"))
    monkeypatch.setenv("CYBERCHECK_TIMEOUT", "invalid")
    app = AppTest.from_file("../streamlit_app.py").run()
    assert not app.exception
    assert app.error[0].value == tr("config_error", "it")
    app.selectbox(key="language").set_value("en").run()
    assert app.error[0].value == tr("config_error", "en")


def test_corrupt_saved_assessment_is_preserved_and_ui_does_not_crash(monkeypatch, tmp_path):
    path = tmp_path / "db.sqlite3"
    monkeypatch.setenv("CYBERCHECK_DB", str(path))
    repo = Repository(path)
    a = sample()
    repo.save(a)
    with repo.connect() as db:
        db.execute("UPDATE assessments SET payload=? WHERE id=?", ("{corrupt", a.id))
    with pytest.raises(StorageDataError):
        repo.get(a.id)
    app = AppTest.from_file("../streamlit_app.py").run()
    assert not app.exception
    assert any(e.value == tr("stored_invalid") for e in app.error)
    assert repo.list()[0]["id"] == a.id


def test_cli_reports_survive_database_failure_with_clear_exit(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "db.sqlite3"))
    monkeypatch.setattr(
        "sys.argv", ["cybercheck", "example.com", "--authorized", "--output", str(tmp_path / "exports")]
    )
    with (
        patch("cybercheck.cli.run_assessment", return_value=sample()),
        patch.object(Repository, "save", side_effect=sqlite3.OperationalError("locked")),
    ):
        with pytest.raises(SystemExit) as error:
            main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert "reports saved" in output.err
    assert "Reports:" in output.out
    assert len(list((tmp_path / "exports").glob("*.json"))) == 1
