"""Adversarial pre-merge reproductions, independent of the v0.4 fixtures."""

import json
import sqlite3
from copy import deepcopy

import pytest

from cybercheck.core.comparison import compare_assessments
from cybercheck.locales.findings import finding
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_comparison_html, render_comparison_json
from cybercheck.storage.sqlite import Repository, StorageDataError, load_payload


def assessment_pair(key, before, after, old=Status.WARNING, new=Status.PASSED):
    metadata = {
        "engine_version": "0.4.0",
        "methodology_version": "checks-v0.3",
        "scoring_profile": "context-v1",
        "context": {"sends_email": True, "receives_email": True, "controls_dns": True},
        "http_method": "HEAD",
        "get_fallback_enabled": False,
    }
    runs = []
    for index, (evidence, status, date) in enumerate(
        ((before, old, "2026-01-01T00:00:00+00:00"), (after, new, "2026-02-10T00:00:00+00:00"))
    ):
        record = deepcopy(evidence) | {"applicability": {"state": "applicable", "basis": "observed_scope"}}
        f = finding(
            key,
            status,
            Severity.INFO if status == Status.PASSED else Severity.LOW,
            "Synthetic evidence",
            "Evidenze sintetiche",
            record,
            scoreable=key.startswith("tls."),
        )
        runs.append(
            Assessment(
                "example.com",
                id=f"review-{index}",
                started_at=date,
                findings=[f],
                metadata=deepcopy(metadata),
            )
        )
    return runs


def certificate():
    return {
        "hostname": "example.com",
        "port": 443,
        "address": "8.8.8.8",
        "not_before": "2025-12-01T00:00:00+00:00",
        "not_after": "2026-03-01T00:00:00+00:00",
        "issuer": {"organizationName": "Synthetic CA"},
        "subject_alt_names": [["DNS", "example.com"]],
        "protocol": "TLSv1.2",
        "cipher": ["SYNTHETIC_CIPHER", "TLSv1.2", 256],
    }


def dns_record(records, state="ok"):
    return {"name": "example.com", "record_type": "TXT", "state": state, "records": records}


def header(value=None):
    return {
        "url": "https://example.com/",
        "method": "HEAD",
        "status_code": 200,
        "content_type": "text/html",
        "header_value": value,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("protocol", "TLSv1.3"),
        ("cipher", ["OTHER_CIPHER", "TLSv1.2", 128]),
        ("issuer", {"organizationName": "Other CA"}),
        ("subject_alt_names", [["DNS", "example.com"], ["DNS", "www.example.com"]]),
    ],
)
def test_review_same_expiry_crosses_time_threshold_while_other_tls_fields_change(field, value):
    before = certificate()
    a, b = assessment_pair("tls.validity", before, before | {field: value}, Status.PASSED, Status.WARNING)
    item = compare_assessments(a, b).findings[0]
    assert "new_issue" not in item["categories"]
    assert "evaluation_changed" in item["categories"]
    assert item["observation_change"] == "changed"  # Preserve the separate measurement delta.


@pytest.mark.parametrize(
    "key,records,state",
    [
        ("email.spf", ["v=spf1 +all"], "absent"),
        ("email.spf", [], "ok"),
        ("dns.mx", ["0 .", "10 mail.example.com."], "absent"),
    ],
)
def test_review_contradictory_dns_result_cannot_establish_resolution(key, records, state):
    before = dns_record(records, state)
    after = dns_record(["v=spf1 -all"])
    if key == "dns.mx":
        before["record_type"] = after["record_type"] = "MX"
        after["records"] = ["0 ."]
    a, b = assessment_pair(key, before, after)
    item = compare_assessments(a, b).findings[0]
    assert item["concern_change"] == "inconclusive"
    assert item["comparability"] != "comparable"


@pytest.mark.parametrize("key", ["headers.csp", "headers.permissions", "headers.framing"])
def test_review_document_headers_on_nonhtml_cannot_establish_resolution(key):
    before, after = header(), header("default-src 'self'")
    before["content_type"] = after["content_type"] = "application/json"
    if key == "headers.framing":
        before["observed_headers"] = {"content-security-policy": [], "x-frame-options": []}
        after["observed_headers"] = {"content-security-policy": [], "x-frame-options": ["DENY"]}
    a, b = assessment_pair(key, before, after)
    assert compare_assessments(a, b).findings[0]["concern_change"] == "inconclusive"


def test_review_contradictory_scalar_and_raw_header_are_not_trusted():
    before = header("default-src 'self'")
    before["observed_headers"] = {"content-security-policy": []}
    a, b = assessment_pair("headers.csp", before, header("default-src 'none'"))
    assert compare_assessments(a, b).findings[0]["concern_change"] == "inconclusive"


@pytest.mark.parametrize("field", ["engine_version", "http_method", "get_fallback_enabled"])
def test_review_export_never_copies_nested_metadata_body_or_credentials(field):
    a, b = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    for run in (a, b):
        run.metadata[field] = {"body": "SYNTHETIC_PRIVATE_BODY", "authorization": "SYNTHETIC_PRIVATE_TOKEN"}
    result = compare_assessments(a, b)
    for exported in (
        render_comparison_json(result),
        render_comparison_html(result, "it"),
        render_comparison_html(result, "en"),
    ):
        assert "SYNTHETIC_PRIVATE_BODY" not in exported
        assert "SYNTHETIC_PRIVATE_TOKEN" not in exported


@pytest.mark.parametrize("mutation", ["selectors", "metadata", "check_id", "scoreable", "text", "category"])
def test_review_structurally_corrupt_json_is_rejected_at_storage_boundary(mutation):
    a, _ = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    payload = a.to_dict()
    if mutation == "selectors":
        payload["selectors"] = None
    elif mutation == "metadata":
        payload["metadata"] = []
    elif mutation == "check_id":
        payload["findings"][0]["check_id"] = ["unhashable"]
    elif mutation == "scoreable":
        payload["findings"][0]["scoreable"] = "yes"
    elif mutation == "text":
        payload["findings"][0]["check_name"]["en"] = {"body": "not a title"}
    else:
        payload["findings"][0]["category"] = []
    with pytest.raises(StorageDataError):
        load_payload(json.dumps(payload))


def test_review_missing_source_timestamp_is_not_replaced_with_load_time():
    a, _ = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    payload = a.to_dict()
    payload.pop("started_at")
    restored = load_payload(json.dumps(payload))
    assert restored.started_at in (None, "")


def test_review_index_identity_mismatch_is_preserved_and_rejected(tmp_path):
    a, _ = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    repo = Repository(tmp_path / "history.sqlite3")
    repo.save(a)
    payload = a.to_dict() | {"domain": "other.example.com"}
    raw = json.dumps(payload)
    with repo.connect() as db:
        db.execute("UPDATE assessments SET payload=? WHERE id=?", (raw, a.id))
    with pytest.raises(StorageDataError):
        repo.get(a.id)
    with repo.connect() as db:
        assert db.execute("SELECT payload FROM assessments WHERE id=?", (a.id,)).fetchone()[0] == raw


def test_review_oversized_payload_is_rejected_before_json_decode(monkeypatch):
    raw = '{"metadata":{"extra":"' + "x" * (17 * 1024 * 1024) + '"}}'

    def forbidden(*args, **kwargs):
        raise AssertionError("Oversized history reached JSON decoding")

    monkeypatch.setattr("cybercheck.storage.sqlite.json.loads", forbidden)
    with pytest.raises(StorageDataError):
        load_payload(raw)


def test_review_deep_payload_is_rejected_without_recursing_into_export():
    a, _ = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    value = {}
    for _ in range(80):
        value = {"nested": value}
    a.metadata["extra"] = value
    with pytest.raises(ValueError):
        load_payload(json.dumps(a.to_dict()))
    with pytest.raises(ValueError):
        compare_assessments(a, a)


@pytest.mark.parametrize("key", ["tls.chain", "tls.hostname"])
def test_review_partial_certificate_cannot_make_score_comparison_valid(key):
    partial = {
        "hostname": "example.com",
        "port": 443,
        "address": "8.8.8.8",
        "not_after": "2026-03-01T00:00:00+00:00",
    }
    a, b = assessment_pair(key, partial, partial, Status.PASSED, Status.PASSED)
    result = compare_assessments(a, b)
    assert result.findings[0]["comparability"] != "comparable"
    assert not result.scoring["valid"] and result.scoring["delta"] is None
    assert result.scoring["earlier"]["score"] == result.scoring["later"]["score"] == 100


@pytest.mark.parametrize("fault", ["reversed_validity", "rejected_with_certificate"])
def test_review_contradictory_tls_evidence_is_inconclusive(fault):
    before = certificate()
    if fault == "reversed_validity":
        before["not_before"] = "2027-01-01T00:00:00+00:00"
    else:
        before["verify_code"] = 20
    a, b = assessment_pair("tls.validity", before, certificate())
    assert compare_assessments(a, b).findings[0]["concern_change"] == "inconclusive"


@pytest.mark.parametrize("fault", ["case_collision", "raw_and_combined_disagree", "null_combined_headers"])
def test_review_conflicting_legacy_header_representations_do_not_prove_resolution(fault):
    before = header()
    if fault == "case_collision":
        before.pop("header_value")
        before["headers"] = {"Content-Security-Policy": "default-src 'self'", "content-security-policy": ""}
    elif fault == "raw_and_combined_disagree":
        before["header_value"] = "default-src 'self'"
        before["observed_headers"] = {"content-security-policy": ["default-src 'self'"]}
        before["headers"] = {"content-security-policy": ""}
    else:
        before["headers"] = None
    a, b = assessment_pair("headers.csp", before, header("default-src 'none'"))
    assert compare_assessments(a, b).findings[0]["concern_change"] == "inconclusive"


@pytest.mark.parametrize("fault", ["missing_hop_scope", "wrong_final_response", "wrong_method"])
def test_review_inconsistent_redirect_chain_is_not_a_supported_resolution(fault):
    before = {
        "url": "http://example.com/",
        "method": "HEAD",
        "status_code": 200,
        "address": "8.8.8.8",
        "hops": [{"url": "http://example.com/", "method": "HEAD", "status_code": 200, "address": "8.8.8.8"}],
    }
    after = deepcopy(before)
    after["url"] = "https://example.com/"
    after["hops"] = [
        {"url": "http://example.com/", "method": "HEAD", "status_code": 301, "address": "8.8.8.8"},
        {"url": "https://example.com/", "method": "HEAD", "status_code": 200, "address": "8.8.8.8"},
    ]
    if fault == "missing_hop_scope":
        for source in (before, after):
            source["hops"][0].pop("method")
            source["hops"][0].pop("address")
    elif fault == "wrong_final_response":
        after["hops"][-1]["status_code"] = 403
    else:
        after["hops"][-1]["method"] = "GET"
    a, b = assessment_pair("http.redirect", before, after)
    assert compare_assessments(a, b).findings[0]["concern_change"] == "inconclusive"


def test_review_explicit_unknown_methodology_is_not_inferred_from_version():
    a, b = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    a.metadata["methodology_version"] = None
    result = compare_assessments(a, b)
    assert result.earlier["methodology_version"] is None
    assert result.findings[0]["concern_change"] == "inconclusive"


def test_review_explicit_unknown_legacy_score_profile_prevents_delta():
    a, b = assessment_pair("tls.protocol", certificate(), certificate(), Status.PASSED, Status.PASSED)
    for source in (a, b):
        source.metadata |= {
            "engine_version": "0.2.0",
            "scoring_profile": None,
            "methodology_version": "checks-v0.2",
        }
    result = compare_assessments(a, b)
    assert not result.scoring["valid"] and result.scoring["delta"] is None


@pytest.mark.parametrize("operation", ["get", "previous"])
def test_review_sql_size_guard_does_not_fetch_oversized_json_for_decoding(monkeypatch, tmp_path, operation):
    a, b = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    a.metadata["padding"] = "x" * 70_000
    repo = Repository(tmp_path / "history.sqlite3")
    repo.save(a)
    repo.save(b)
    monkeypatch.setattr("cybercheck.storage.sqlite.MAX_PAYLOAD_BYTES", 65_536)

    def forbidden(*args, **kwargs):
        raise AssertionError("Oversized SQLite row reached JSON decoding")

    monkeypatch.setattr("cybercheck.storage.sqlite.json.loads", forbidden)
    with pytest.raises(StorageDataError):
        repo.get(a.id) if operation == "get" else repo.previous(b)
    with repo.connect() as db:
        assert "padding" in db.execute("SELECT payload FROM assessments WHERE id=?", (a.id,)).fetchone()[0]


def test_review_decoder_recursion_is_reported_as_preserved_invalid_history(monkeypatch):
    def recurse(*args, **kwargs):
        raise RecursionError("Synthetic decoder recursion")

    monkeypatch.setattr("cybercheck.storage.sqlite.json.loads", recurse)
    with pytest.raises(StorageDataError):
        load_payload("{}")


def test_review_invalid_unicode_is_rejected_but_valid_unicode_round_trips():
    a, b = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    a.findings[0].check_name = type(a.findings[0].check_name)("Caffè — Ω 🔐", "Caffè — Ω 🔐")
    raw = json.dumps(a.to_dict(), ensure_ascii=False)
    assert load_payload(raw).findings[0].check_name.en == "Caffè — Ω 🔐"
    a.metadata["bad_unicode"] = "\ud800"
    with pytest.raises(StorageDataError):
        load_payload(json.dumps(a.to_dict()))
    with pytest.raises(ValueError):
        compare_assessments(a, b)


def test_review_unexpected_issuer_properties_are_not_exported():
    before = certificate()
    before["issuer"]["body"] = "SYNTHETIC_PRIVATE_BODY"
    before["issuer"]["authorization"] = "SYNTHETIC_PRIVATE_TOKEN"
    a, b = assessment_pair("tls.chain", before, certificate(), Status.PASSED, Status.PASSED)
    exported = render_comparison_json(compare_assessments(a, b))
    assert "SYNTHETIC_PRIVATE_BODY" not in exported and "SYNTHETIC_PRIVATE_TOKEN" not in exported
    assert compare_assessments(a, b).findings[0]["observation_change"] == "equivalent"


@pytest.mark.parametrize("fault", ["selectors", "metadata", "evidence", "identity"])
def test_review_corrupt_structured_record_isolated_in_streamlit(monkeypatch, tmp_path, fault):
    from dataclasses import replace

    from streamlit.testing.v1 import AppTest

    from cybercheck.locales.ui import tr

    path = tmp_path / "history.sqlite3"
    monkeypatch.setenv("CYBERCHECK_DB", str(path))
    a, b = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    c = replace(b, id="review-later", started_at="2026-03-01T00:00:00+00:00")
    repo = Repository(path)
    for run in (a, b, c):
        repo.save(run)
    payload = b.to_dict()
    if fault == "selectors":
        payload["selectors"] = None
    elif fault == "metadata":
        payload["metadata"] = []
    elif fault == "evidence":
        payload["findings"][0]["evidence"] = None
    else:
        payload["domain"] = "other.example.com"
    raw = json.dumps(payload)
    with repo.connect() as db:
        db.execute("UPDATE assessments SET payload=? WHERE id=?", (raw, b.id))
    app = AppTest.from_file("../streamlit_app.py", default_timeout=20).run()
    app.radio(key="navigation").set_value("history").run()
    assert not app.exception
    assert any(tr("stored_invalid", "it") in message.value for message in app.warning)
    app.selectbox(key=f"comparison_{c.id}_earlier").set_value(a.id).run()
    assert not app.exception
    assert len(app.get("download_button")) == 2
    app.selectbox(key=f"comparison_{c.id}_earlier").set_value(b.id).run()
    assert not app.exception
    assert app.error and len(app.get("download_button")) == 0
    with repo.connect() as db:
        assert db.execute("SELECT payload FROM assessments WHERE id=?", (b.id,)).fetchone()[0] == raw


def test_review_input_node_and_finding_limits_precede_expensive_export():
    a, _ = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    a.metadata["wide"] = [None] * 210_000
    with pytest.raises(ValueError):
        compare_assessments(a, a)
    a.metadata.pop("wide")
    a.findings = a.findings * 513
    with pytest.raises(ValueError):
        compare_assessments(a, a)


@pytest.mark.parametrize("operation", ["get", "previous"])
def test_review_sqlite_native_length_error_is_a_recoverable_read_error(monkeypatch, tmp_path, operation):
    a, b = assessment_pair("email.spf", dns_record(["v=spf1 +all"]), dns_record(["v=spf1 -all"]))
    a.metadata["padding"] = "x" * 300_000
    repo = Repository(tmp_path / "history.sqlite3")
    repo.save(a)
    repo.save(b)
    monkeypatch.setattr("cybercheck.storage.sqlite.MAX_PAYLOAD_BYTES", 65_536)
    with pytest.raises(StorageDataError) as caught:
        repo.get(a.id) if operation == "get" else repo.previous(b)
    assert isinstance(caught.value.__cause__, sqlite3.DataError)
    with repo.connect() as db:
        raw = db.execute("SELECT payload FROM assessments WHERE id=?", (a.id,)).fetchone()[0]
    assert json.loads(raw)["metadata"]["padding"] == "x" * 300_000
