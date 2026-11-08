from unittest.mock import patch

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from cybercheck.core.engine import run_assessment
from cybercheck.core.network import WebClient
from cybercheck.models import Status
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.sqlite import Repository


def test_authorization_and_validation_before_network(fake_dns):
    dns = fake_dns()
    with pytest.raises(PermissionError):
        run_assessment("example.com", dns=dns)
    with pytest.raises(ValueError):
        run_assessment("localhost", authorized=True, dns=dns)
    assert not dns.queries


def fixture_assessment(fake_dns):
    dns = fake_dns(
        {
            ("example.com", "A"): ["8.8.8.8"],
            ("example.com", "TXT"): ["v=spf1 ~all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:reports@example.com"],
        }
    )
    web = WebClient(
        dns,
        dns.budget,
        httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "text/html"})),
    )
    # TLS failure path is also exercised through the orchestrator, without an actual socket.
    with patch(
        "cybercheck.checks.tls.socket.create_connection", side_effect=TimeoutError("synthetic timeout")
    ):
        assessment = run_assessment("example.com", authorized=True, dns=dns, web=web)
    web.close()
    assessment.metadata["synthetic_fixture"] = True
    return assessment


def test_complete_mocked_workflow(fake_dns, tmp_path):
    a = fixture_assessment(fake_dns)
    assert a.completed_at and a.authorization_confirmed
    assert len(a.findings) == 21
    assert all(f.status != Status.ERROR for f in a.findings)
    repo = Repository(tmp_path / "db.sqlite3")
    repo.save(a)
    loaded = repo.get(a.id)
    assert loaded.domain == "example.com"
    assert "SYNTHETIC TEST FIXTURE" in render_html(loaded)
    assert '"domain": "example.com"' in render_json(loaded)


def test_module_exception_preserves_other_observations(fake_dns):
    with patch("cybercheck.core.engine.check_spf", side_effect=RuntimeError("unexpected")):
        a = fixture_assessment(fake_dns)
    assert any(f.status == Status.ERROR and f.evidence["module"] == "spf" for f in a.findings)
    assert any(f.check_id == "email.dmarc" for f in a.findings)


def test_app_navigation_both_languages_and_authorization(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "app.sqlite3"))
    app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
    assert not app.exception
    assert "Comprendi" in app.title[0].value
    app.radio(key="navigation").set_value("new").run()
    assert not app.exception
    app.text_input[0].set_value("example.com")
    app.button[0].click().run()
    assert app.error and "autorizzazione" in app.error[0].value
    app.selectbox(key="language").set_value("en").run()
    assert app.title[0].value == "New Assessment"
    for page in ("history", "findings", "reports", "settings", "overview"):
        app.radio(key="navigation").set_value(page).run()
        assert not app.exception


def test_app_can_assess_save_filter_and_export(fake_dns, monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "app.sqlite3"))
    assessment = fixture_assessment(fake_dns)
    with patch("cybercheck.app.dashboard.run_assessment", return_value=assessment) as run:
        app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
        app.radio(key="navigation").set_value("new").run()
        app.text_input[0].set_value("example.com")
        app.checkbox[0].check()
        app.button[0].click().run()
        assert not app.exception
        run.assert_called_once()
        assert app.success
        assert len(Repository(tmp_path / "app.sqlite3").list()) == 1
    for page in ("overview", "findings", "reports", "history", "settings"):
        app.radio(key="navigation").set_value(page).run()
        assert not app.exception
    app.radio(key="navigation").set_value("findings").run()
    app.text_input[0].set_value("SPF").run()
    assert not app.exception
    assert len(app.expander) == 2
    app.radio(key="navigation").set_value("reports").run()
    assert not app.exception
    assert len(app.get("download_button")) == 2


def test_history_picker_and_score_persist(fake_dns, monkeypatch, tmp_path):
    path = tmp_path / "app.sqlite3"
    monkeypatch.setenv("CYBERCHECK_DB", str(path))
    repo = Repository(path)
    first = fixture_assessment(fake_dns)
    first.started_at = "2026-01-01T00:00:00+00:00"
    second = fixture_assessment(fake_dns)
    second.started_at = "2026-01-02T00:00:00+00:00"
    repo.save(first)
    repo.save(second)
    app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
    assert app.selectbox(key="assessment_picker").value == second.id
    app.selectbox(key="assessment_picker").set_value(first.id).run()
    assert app.session_state["active_id"] == first.id
    app.radio(key="navigation").set_value("history").run()
    app.selectbox(key="history_selected").set_value(second.id)
    app.button[0].click().run()
    assert not app.exception
    assert app.session_state["active_id"] == second.id
    # Switch back to a previously rendered picker and confirm history stays selected.
    app.selectbox(key="history_selected").set_value(first.id)
    app.button[0].click().run()
    assert app.session_state["active_id"] == first.id
    app.radio(key="navigation").set_value("settings").run()
    app.checkbox(key="_show_score").check().run()
    app.radio(key="navigation").set_value("overview").run()
    assert not app.exception
    assert len(app.metric) == 5
    app.run()
    assert len(app.metric) == 5
