from unittest.mock import patch

import pytest

from cybercheck.cli import main
from cybercheck.models import Assessment


def test_cli_refuses_missing_authorization(monkeypatch):
    monkeypatch.setattr("sys.argv", ["cybercheck", "example.com"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2


def test_cli_persists_and_exports_without_network(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERCHECK_DB", str(tmp_path / "db.sqlite3"))
    monkeypatch.setattr(
        "sys.argv",
        [
            "cybercheck",
            "example.com",
            "--authorized",
            "--language",
            "en",
            "--output",
            str(tmp_path / "exports"),
        ],
    )
    assessment = Assessment("example.com", authorization_confirmed=True)
    with patch("cybercheck.cli.run_assessment", return_value=assessment):
        assert main() == 0
    assert len(list((tmp_path / "exports").glob("*.html"))) == 1
    assert len(list((tmp_path / "exports").glob("*.json"))) == 1
    assert (tmp_path / "db.sqlite3").exists()
