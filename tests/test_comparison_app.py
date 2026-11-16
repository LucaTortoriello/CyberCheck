"""History comparison integration with real SQLite and offline Streamlit AppTest."""

from dataclasses import replace

import pytest
from streamlit.testing.v1 import AppTest
from test_comparison import pair, tls_evidence

from cybercheck.locales.comparison import ct
from cybercheck.models import Status
from cybercheck.storage.sqlite import Repository


def seed(monkeypatch, tmp_path):
    path = tmp_path / "history.sqlite3"
    monkeypatch.setenv("CYBERCHECK_DB", str(path))
    repo = Repository(path)
    a, b = pair()
    c = replace(b, id="third-assessment", started_at="2026-03-01T00:00:00+00:00")
    other = replace(a, id="other-target", domain="other.example.com")
    for run in (a, b, c, other):
        repo.save(run)
    return repo, a, b, c


def open_history(active_id):
    app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
    app.selectbox(key="assessment_picker").set_value(active_id).run()
    app.radio(key="navigation").set_value("history").run()
    assert not app.exception
    return app


def test_two_nonconsecutive_saved_assessments_can_be_compared_and_exported(monkeypatch, tmp_path):
    repo, a, b, c = seed(monkeypatch, tmp_path)
    app = open_history(c.id)
    key = f"comparison_{c.id}"
    assert app.selectbox(key=key + "_earlier").value == b.id
    assert app.selectbox(key=key + "_later").value == c.id
    assert not any("other-ta" in option for option in app.selectbox(key=key + "_earlier").options)
    app.selectbox(key=key + "_earlier").set_value(a.id).run()
    assert not app.exception
    assert any(ct("resolved_issue", "it") in expander.label for expander in app.expander)
    assert len(app.get("download_button")) == 2
    app.selectbox(key="language").set_value("en").run()
    assert not app.exception
    assert any(ct("resolved_issue", "en") in expander.label for expander in app.expander)
    assert repo.get(a.id).to_dict() == a.to_dict()


def test_comparison_history_pagination_can_reach_older_runs(monkeypatch, tmp_path):
    repo, a, b, c = seed(monkeypatch, tmp_path)
    for day in range(2, 32):
        repo.save(replace(a, id=f"run-{day}", started_at=f"2026-01-{day:02d}T00:00:00+00:00"))
    app = open_history(c.id)
    key = f"comparison_{c.id}"
    app.number_input(key=key + "_earlier_page").set_value(2).run()
    app.selectbox(key=key + "_earlier").set_value(a.id).run()
    assert not app.exception
    assert app.selectbox(key=key + "_later").value == c.id
    assert len(app.get("download_button")) == 2


def test_same_or_reversed_selection_never_shows_misleading_export(monkeypatch, tmp_path):
    _, a, _, c = seed(monkeypatch, tmp_path)
    app = open_history(c.id)
    key = f"comparison_{c.id}"
    app.selectbox(key=key + "_earlier").set_value(c.id).run()
    assert not app.exception
    assert any(ct("choose_distinct", "it") in item.value for item in app.info)
    assert len(app.get("download_button")) == 0
    app.selectbox(key=key + "_later").set_value(a.id).run()
    assert not app.exception
    assert len(app.get("download_button")) == 0


def test_corrupt_predecessor_does_not_block_other_valid_pairs(monkeypatch, tmp_path):
    repo, a, b, c = seed(monkeypatch, tmp_path)
    with repo.connect() as db:
        db.execute("UPDATE assessments SET payload=? WHERE id=?", ("{", b.id))
    app = open_history(c.id)
    key = f"comparison_{c.id}"
    assert app.warning
    app.selectbox(key=key + "_earlier").set_value(a.id).run()
    assert not app.exception
    assert len(app.get("download_button")) == 2
    with repo.connect() as db:
        assert db.execute("SELECT payload FROM assessments WHERE id=?", (b.id,)).fetchone()[0] == "{"


@pytest.mark.parametrize("different_profile", [False, True])
def test_ui_only_displays_score_delta_for_a_valid_comparison(monkeypatch, tmp_path, different_profile):
    repo, _, _, _ = seed(monkeypatch, tmp_path)
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    if different_profile:
        a.metadata.pop("scoring_profile")
        a.metadata["engine_version"] = "0.2.0"
    repo.save(a)
    repo.save(b)
    app = open_history(b.id)
    assert not app.exception
    assert any("Δ" in item.value for item in app.caption) is not different_profile
