"""Deterministic comparison regressions; no live targets or history mutation."""

import json
from copy import deepcopy
from dataclasses import replace
from html import unescape

import pytest

from cybercheck.checks.headers import HEADER_NAMES as CHECK_HEADER_NAMES
from cybercheck.core.comparison import HEADER_NAMES, compare_assessments, observe
from cybercheck.locales.comparison import STRINGS, ct
from cybercheck.locales.findings import finding
from cybercheck.models import Assessment, Severity, Status
from cybercheck.reports.render import render_comparison_html, render_comparison_json, render_json
from cybercheck.storage.sqlite import Repository, compare


def metadata():
    return {
        "engine_version": "0.4.0",
        "methodology_version": "checks-v0.3",
        "scoring_profile": "context-v1",
        "context": {"sends_email": True, "receives_email": True, "controls_dns": True},
        "http_method": "HEAD",
        "get_fallback_enabled": False,
    }


def dns_evidence(records, record_type="TXT", name="example.com"):
    return {
        "name": name,
        "record_type": record_type,
        "state": "ok" if records else "absent",
        "records": records,
    }


def tls_evidence():
    return {
        "hostname": "example.com",
        "port": 443,
        "address": "8.8.8.8",
        "issuer": {"organizationName": "Test CA"},
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00",
        "protocol": "TLSv1.3",
        "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256],
        "subject_alt_names": [["DNS", "example.com"], ["DNS", "www.example.com"]],
        "days_until_expiration": 60,
    }


def header_evidence(value):
    return {
        "url": "https://example.com/",
        "method": "HEAD",
        "status_code": 200,
        "content_type": "text/html",
        "header_value": value,
    }


def make_finding(key, status, evidence, *, severity=None, scoreable=False):
    severity = severity or (Severity.INFO if status == Status.PASSED else Severity.MEDIUM)
    evidence = deepcopy(evidence)
    if isinstance(evidence, dict):
        evidence.setdefault(
            "applicability",
            {
                "state": "applicable",
                "basis": "user_declared",
                "reason": {"en": "Declared context", "it": "Contesto dichiarato"},
            },
        )
    f = finding(
        key.split(":")[0],
        status,
        severity,
        "Synthetic finding",
        "Finding sintetico",
        scoreable=scoreable,
        suffix=(":" + key.split(":", 1)[1]) if ":" in key else "",
    )
    f.evidence = evidence
    return f


def pair(key="email.spf", old=Status.WARNING, new=Status.PASSED, before=None, after=None, *, scoreable=False):
    before = dns_evidence(["v=spf1 +all"]) if before is None else before
    after = dns_evidence(["v=spf1 -all"]) if after is None else after
    return (
        Assessment(
            "example.com",
            id="earlier-assessment",
            started_at="2026-01-01T00:00:00+00:00",
            metadata=metadata(),
            findings=[make_finding(key, old, before, scoreable=scoreable)],
        ),
        Assessment(
            "example.com",
            id="later-assessment",
            started_at="2026-02-01T00:00:00+00:00",
            metadata=metadata(),
            findings=[make_finding(key, new, after, scoreable=scoreable)],
        ),
    )


def change(a, b):
    return compare_assessments(a, b).findings[0]


def codes(value):
    return {r["code"] for r in value}


@pytest.mark.parametrize(
    "key,record_type,old_record,new_record",
    [
        ("email.spf", "TXT", "v=spf1 +all", "v=spf1 -all"),
        ("email.dmarc", "TXT", "v=DMARC1; p=none", "v=DMARC1; p=reject"),
        ("dns.mx", "MX", "10 old.example.com.", "10 new.example.com."),
        ("dns.caa", "CAA", '0 issue "old.example"', '0 issue "new.example"'),
    ],
)
def test_measured_dns_policy_and_record_changes(key, record_type, old_record, new_record):
    a, b = pair(
        key, before=dns_evidence([old_record], record_type), after=dns_evidence([new_record], record_type)
    )
    item = change(a, b)
    assert item["observation_change"] == "changed"
    assert item["concern_change"] == "resolved_issue"
    assert item["comparability"] == "comparable"
    assert "records" in {d["field"] for d in item["differences"]}


def test_dns_inventory_record_order_and_duplicates_are_not_changes():
    evidence = {kind: dns_evidence(["8.8.8.8", "8.8.4.4"], kind) for kind in ("A", "AAAA", "NS", "MX", "CAA")}
    a, b = pair("dns.records", Status.PASSED, Status.PASSED, evidence, deepcopy(evidence))
    for result in b.findings[0].evidence.values():
        if isinstance(result, dict) and "records" in result:
            result["records"] = list(reversed(result["records"])) + result["records"][:1]
    item = change(a, b)
    assert item["observation_change"] == "equivalent" and item["categories"] == ["unchanged"]
    assert compare(a, b) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("not_after", "2028-01-01T00:00:00+00:00"),
        ("protocol", "TLSv1.2"),
        ("issuer", {"organizationName": "Different CA"}),
        ("subject_alt_names", [["DNS", "example.com"]]),
    ],
)
def test_tls_observations_change_without_automatic_improvement(field, value):
    a, b = pair(
        "tls.protocol" if field == "protocol" else "tls.validity",
        Status.PASSED,
        Status.PASSED,
        tls_evidence(),
        tls_evidence(),
    )
    b.findings[0].evidence[field] = value
    item = change(a, b)
    assert item["categories"] == ["changed_observation"]
    assert item["concern_change"] == "unchanged"
    assert not {"resolved_issue", "new_issue"} & set(item["categories"])


def test_tls_countdown_and_san_order_are_not_changes():
    a, b = pair("tls.validity", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence())
    b.findings[0].evidence["days_until_expiration"] = 30
    b.findings[0].evidence["subject_alt_names"].reverse()
    assert change(a, b)["categories"] == ["unchanged"]


@pytest.mark.parametrize(
    "old,new,before,after,expected",
    [
        (Status.WARNING, Status.PASSED, None, "default-src 'self'", "resolved_issue"),
        (Status.PASSED, Status.WARNING, "default-src 'self'", None, "new_issue"),
    ],
)
def test_header_added_or_removed_with_comparable_response(old, new, before, after, expected):
    a, b = pair("headers.csp", old, new, header_evidence(before), header_evidence(after))
    item = change(a, b)
    assert item["comparability"] == "comparable"
    assert expected in item["categories"] and "changed_observation" in item["categories"]


@pytest.mark.parametrize(
    "old,new,expected",
    [
        (Status.WARNING, Status.PASSED, "resolved_issue"),
        (Status.FAILED, Status.PASSED, "resolved_issue"),
        (Status.PASSED, Status.WARNING, "new_issue"),
        (Status.WARNING, Status.WARNING, "persistent_issue"),
    ],
)
def test_supported_lifecycle_transitions(old, new, expected):
    a, b = pair(old=old, new=new)
    assert change(a, b)["concern_change"] == expected


def test_equivalent_evidence_with_result_change_is_evaluation_change():
    a, b = pair(before=dns_evidence(["v=spf1 -all"]), after=dns_evidence(["v=spf1 -all"]))
    item = change(a, b)
    assert item["observation_change"] == "equivalent"
    assert item["categories"] == ["inconclusive", "evaluation_changed"]
    assert "same_observation_different_result" in codes(item["reasons"])


@pytest.mark.parametrize(
    "old,new",
    [
        (Status.UNKNOWN, Status.FAILED),
        (Status.ERROR, Status.PASSED),
        (Status.WARNING, Status.UNKNOWN),
        (Status.NA, Status.PASSED),
    ],
)
def test_unmeasured_results_cannot_prove_new_or_resolved_issues(old, new):
    a, b = pair(old=old, new=new)
    item = change(a, b)
    assert item["concern_change"] == "inconclusive"
    assert "unmeasured_result" in codes(item["reasons"])


@pytest.mark.parametrize("missing", ["earlier", "later"])
def test_newly_introduced_or_missing_check_does_not_prove_lifecycle(missing):
    a, b = pair(new=Status.FAILED)
    (a if missing == "earlier" else b).findings.clear()
    item = change(a, b)
    assert item["concern_change"] == "inconclusive" and item["comparability"] == "not_comparable"
    assert "missing_" + missing in codes(item["reasons"])


def test_different_dkim_selectors_never_match_by_title():
    a, b = pair(
        "email.dkim:s1", before=dns_evidence(["v=DKIM1; p=YWJj"]), after=dns_evidence(["v=DKIM1; p=YWJj"])
    )
    a.selectors, b.selectors = ["s1"], ["s2"]
    b.findings[0].check_id = "email.dkim:s2"
    result = compare_assessments(a, b)
    assert len(result.findings) == 2
    assert result.summary["new_issue"] == result.summary["resolved_issue"] == 0
    assert "selectors_changed" in codes(result.limitations)


def test_context_change_without_dns_change_is_separate_evaluation_change():
    a, b = pair(new=Status.WARNING, after=dns_evidence(["v=spf1 +all"]))
    b.metadata["context"]["sends_email"] = False
    b.findings[0].evidence["applicability"]["state"] = "not_applicable"
    item = change(a, b)
    assert item["observation_change"] == "equivalent"
    assert item["dimensions"]["context_changed"] and item["dimensions"]["applicability_changed"]
    assert "evaluation_changed" in item["categories"]
    assert item["concern_change"] == "inconclusive"


def test_context_and_score_changes_can_coexist_with_observation_change():
    a, b = pair(scoreable=True)
    b.metadata["context"]["sends_email"] = False
    b.findings[0].scoreable = False
    item = change(a, b)
    assert {"changed_observation", "evaluation_changed", "inconclusive"} <= set(item["categories"])
    assert item["dimensions"]["scoring_eligibility_changed"]


def test_different_scoring_profiles_invalidate_delta():
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    a.metadata["engine_version"] = "0.2.0"
    a.metadata["methodology_version"] = "checks-v0.2"
    del a.metadata["scoring_profile"]
    result = compare_assessments(a, b)
    assert not result.scoring["valid"] and result.scoring["delta"] is None
    assert "profile_changed" in codes(result.scoring["reasons"])


def test_v02_to_v03_identical_spf_is_evaluation_change_not_target_change():
    a, b = pair(old=Status.FAILED, new=Status.WARNING, after=dns_evidence(["v=spf1 +all"]))
    a.metadata = {"engine_version": "0.2.0", "http_method": "HEAD"}
    b.metadata["engine_version"] = "0.3.0"
    del b.metadata["methodology_version"]
    a.findings[0].severity = Severity.HIGH
    a.findings[0].evidence.pop("applicability")
    result = compare_assessments(a, b)
    item = result.findings[0]
    assert item["observation_change"] == "equivalent"
    assert "evaluation_changed" in item["categories"]
    assert result.summary["resolved_issue"] == result.summary["new_issue"] == 0
    assert result.comparability == "partially_comparable"
    assert not result.scoring["valid"]


def test_v03_to_v04_known_unchanged_check_methodology_is_comparable():
    a, b = pair(
        "email.spf",
        Status.PASSED,
        Status.PASSED,
        dns_evidence(["v=spf1 -all"]),
        dns_evidence(["v=spf1 -all"]),
    )
    a.metadata["engine_version"] = "0.3.0"
    del a.metadata["methodology_version"]
    item = change(a, b)
    assert item["comparability"] == "comparable"
    assert item["dimensions"]["engine_version_changed"]
    assert not item["dimensions"]["methodology_changed"]


def test_timestamps_ids_counters_and_parser_prose_are_not_observation_changes():
    a, b = pair(
        old=Status.PASSED,
        new=Status.PASSED,
        before=dns_evidence(["v=spf1 -all"]),
        after=dns_evidence(["v=spf1 -all"]),
    )
    a.findings[0].id, b.findings[0].id = "random-one", "random-two"
    a.findings[0].timestamp, b.findings[0].timestamp = "old-time", "new-time"
    a.findings[0].evidence["syntax_errors"] = ["old parser wording"]
    b.findings[0].evidence["syntax_errors"] = ["new parser wording"]
    b.metadata |= {"dns_queries": 999, "http_requests": 1, "duration": 20, "generated_at": "today"}
    assert change(a, b)["categories"] == ["unchanged"]
    assert compare(a, b) == []


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        "legacy string",
        {},
        {"records": None},
        {"records": "v=spf1 -all"},
        {"records": [123]},
        {"records": [], "state": {"bad": True}},
        {"records": [], "state": "error"},
    ],
)
def test_malformed_or_incomplete_historical_evidence_is_inconclusive(bad):
    a, b = pair(before=dns_evidence([]))
    a.findings[0].evidence = bad
    result = compare_assessments(a, b)
    assert result.findings[0]["concern_change"] == "inconclusive"
    assert "incomplete_evidence" in codes(result.findings[0]["reasons"])
    assert not result.scoring["valid"]
    render_comparison_json(result)
    render_comparison_html(result)


def test_missing_records_are_not_equated_to_observed_empty_records():
    a, b = pair(old=Status.WARNING, new=Status.WARNING, before={"state": "absent"}, after=dns_evidence([]))
    item = change(a, b)
    assert item["observation_change"] == "inconclusive"
    diff = next(d for d in item["differences"] if d["field"] == "records")
    assert not diff["earlier_present"] and diff["later_present"] and diff["later"] == []


@pytest.mark.parametrize("method", ["GET", None])
def test_head_vs_get_or_unrecorded_method_reduces_comparability(method):
    a, b = pair("headers.csp", before=header_evidence(None), after=header_evidence("default-src 'self'"))
    b.metadata["get_fallback_enabled"] = True
    if method is None:
        b.findings[0].evidence.pop("method")
    else:
        b.findings[0].evidence["method"] = method
    item = change(a, b)
    assert item["comparability"] == "partially_comparable"
    assert item["concern_change"] == "inconclusive"
    assert "method_changed" in codes(item["reasons"])


@pytest.mark.parametrize(
    "field,value",
    [("url", "https://www.example.com/"), ("content_type", "application/json"), ("status_code", 403)],
)
def test_different_http_endpoint_or_response_scope_is_qualified(field, value):
    a, b = pair("headers.csp", before=header_evidence(None), after=header_evidence("default-src 'self'"))
    b.findings[0].evidence[field] = value
    assert change(a, b)["comparability"] == "partially_comparable"


def test_duplicate_stable_ids_are_ambiguous_not_arbitrary_matches():
    a, b = pair()
    a.findings.append(deepcopy(a.findings[0]))
    item = change(a, b)
    assert item["comparability"] == "not_comparable"
    assert "duplicate_id" in codes(item["reasons"])


def test_same_domain_and_chronological_order_are_enforced():
    a, b = pair()
    with pytest.raises(ValueError, match="same domain"):
        compare_assessments(a, replace(b, domain="different.example.com"))
    with pytest.raises(ValueError, match="Earlier"):
        compare_assessments(b, a)


def test_malformed_timestamp_reduces_comparability_instead_of_guessing_order():
    a, b = pair()
    a.started_at = "unknown"
    result = compare_assessments(a, b)
    assert result.comparability == "partially_comparable"
    assert "invalid_time" in codes(result.limitations)


@pytest.mark.parametrize("version", ["unrecognized", None, ["invalid-version"]])
def test_unknown_methodology_does_not_fabricate_equivalent_rules(version):
    a, b = pair()
    a.metadata["engine_version"] = version
    a.metadata.pop("methodology_version")
    assert "methodology_unknown" in codes(compare_assessments(a, b).limitations)


def test_absent_context_is_not_equal_to_explicit_unknown_context():
    a, b = pair()
    a.metadata.pop("context")
    b.metadata["context"] = {"sends_email": None, "receives_email": None, "controls_dns": None}
    assert "context_missing" in codes(compare_assessments(a, b).limitations)


def test_valid_score_delta_requires_same_criteria_and_supporting_observations():
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    result = compare_assessments(a, b)
    assert result.scoring["valid"] and result.scoring["delta"] == 0.0
    assert result.scoring["evaluated_check_ids"] == ["tls.protocol"]
    b.findings[0].scoreable = False
    assert not compare_assessments(a, b).scoring["valid"]


def test_equal_score_totals_with_different_criterion_ids_are_not_comparable():
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    b.findings[0].check_id = "tls.chain"
    result = compare_assessments(a, b)
    assert result.scoring["earlier"]["score"] == result.scoring["later"]["score"] == 100
    assert not result.scoring["valid"] and result.scoring["delta"] is None


@pytest.mark.parametrize("language", ["en", "it"])
def test_html_json_comparison_report_consistency_and_escaping(language):
    a, b = pair()
    a.domain = b.domain = '<script>alert("xss")</script>'
    result = compare_assessments(a, b)
    report = json.loads(render_comparison_json(result))
    html = render_comparison_html(result, language)
    assert report["report_type"] == "assessment_comparison" and report["schema_version"] == 1
    assert report["summary"] == result.summary
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert report["earlier"]["id"] in html and report["later"]["id"] in html
    for item in result.findings:
        for message in item["reasons"]:
            assert message["explanation"][language] in unescape(html)
    assert ct(result.comparability, language) in html
    assert "Content-Security-Policy" in html


def test_comparison_exports_minimize_legacy_web_data_and_never_include_bodies():
    raw = {
        "url": "https://example.com/?token=secret-query#secret-fragment",
        "method": "HEAD",
        "status_code": 200,
        "headers": {
            "content-type": "text/html",
            "set-cookie": "secret-cookie",
            "authorization": "secret-auth",
        },
        "body": "secret-body",
        "response_body": "other-secret-body",
        "arbitrary": "secret-extra",
    }
    a, b = pair("http.application", Status.PASSED, Status.PASSED, raw, raw)
    exported = render_comparison_json(compare_assessments(a, b))
    for secret in (
        "secret-query",
        "secret-fragment",
        "secret-cookie",
        "secret-auth",
        "secret-body",
        "secret-extra",
    ):
        assert secret not in exported
    assert "redacted" in exported


def test_storage_payloads_and_historical_scores_remain_byte_for_byte_unchanged(tmp_path):
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    a.metadata = {"engine_version": "0.2.0"}
    a.findings[0].evidence.pop("applicability")
    repo = Repository(tmp_path / "history.sqlite3")
    repo.save(a)
    repo.save(b)
    with repo.connect() as db:
        before = [tuple(row) for row in db.execute("SELECT * FROM assessments ORDER BY id")]
    old, new = repo.get(a.id), repo.get(b.id)
    old_json, new_json = deepcopy(old.to_dict()), deepcopy(new.to_dict())
    result = compare_assessments(old, new)
    render_comparison_json(result)
    render_comparison_html(result, "it")
    render_comparison_html(result, "en")
    assert old.to_dict() == old_json and new.to_dict() == new_json
    assert old.health["score"] == 100
    assert Assessment.from_dict(json.loads(render_json(old))).to_dict() == old_json
    with repo.connect() as db:
        assert [tuple(row) for row in db.execute("SELECT * FROM assessments ORDER BY id")] == before
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1


def test_bilingual_catalog_and_header_field_mapping_are_consistent():
    assert HEADER_NAMES == CHECK_HEADER_NAMES
    for code, pair_text in STRINGS.items():
        assert len(pair_text) == 2 and all(pair_text) and pair_text[0] != pair_text[1], code


def test_legacy_framing_parser_output_is_not_fabricated_as_raw_header():
    a, b = pair(
        "headers.framing",
        before=header_evidence("frame-ancestors=[]; X-Frame-Options="),
        after=header_evidence("frame-ancestors=[]; X-Frame-Options=DENY"),
    )
    assert not observe(a.findings[0]).complete
    assert change(a, b)["concern_change"] == "inconclusive"
    b.findings[0].evidence["observed_headers"] = {"content-security-policy": [], "x-frame-options": ["DENY"]}
    assert observe(b.findings[0]).complete


def test_comparison_is_deterministic_for_the_same_saved_inputs():
    a, b = pair()
    assert render_comparison_json(compare_assessments(a, b)) == render_comparison_json(
        compare_assessments(a, b)
    )


def test_empty_assessment_pair_is_not_comparable():
    a, b = pair()
    a.findings.clear()
    b.findings.clear()
    assert compare_assessments(a, b).comparability == "not_comparable"


def test_failed_dns_query_is_not_measured_absence_or_configuration_change():
    a, b = pair(
        old=Status.UNKNOWN,
        new=Status.WARNING,
        before={"name": "example.com", "record_type": "TXT", "state": "error", "records": []},
        after=dns_evidence([]),
    )
    item = change(a, b)
    assert "records" not in item["earlier"]["evidence"]
    assert item["observation_change"] == "inconclusive"
    assert "new_issue" not in item["categories"] and "changed_observation" not in item["categories"]


def test_unrelated_txt_publication_does_not_change_observed_spf_absence():
    a, b = pair(
        old=Status.WARNING,
        new=Status.WARNING,
        before=dns_evidence([]),
        after=dns_evidence(["unrelated=verification-token"]),
    )
    item = change(a, b)
    assert item["observation_change"] == "equivalent"
    assert "verification-token" not in render_comparison_json(compare_assessments(a, b))


def test_incomplete_scored_legacy_evidence_does_not_crash_score_comparison():
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    a.findings[0].evidence = None
    result = compare_assessments(a, b)
    assert not result.scoring["valid"] and result.scoring["delta"] is None


def test_unknown_future_check_is_not_assumed_to_share_known_normalization():
    a, b = pair("tls.protocol", before=tls_evidence(), after=tls_evidence())
    a.findings[0].check_id = b.findings[0].check_id = "tls.future_check"
    assert change(a, b)["comparability"] == "not_comparable"


def test_malformed_new_header_evidence_is_not_replaced_by_legacy_fallback():
    a, b = pair("headers.csp", before=header_evidence(None), after=header_evidence("default-src 'self'"))
    b.findings[0].evidence["observed_headers"] = {"content-security-policy": "malformed"}
    assert not observe(b.findings[0]).complete
    assert change(a, b)["concern_change"] == "inconclusive"


def test_new_raw_framing_values_and_duplicate_hsts_fields_are_compared():
    from cybercheck.checks.headers import check_headers
    from cybercheck.core.network import WebResponse

    raw = WebResponse(
        "https://example.com/",
        200,
        {"content-type": "text/html", "strict-transport-security": "max-age=100", "x-frame-options": "DENY"},
        "8.8.8.8",
        header_values={"strict-transport-security": ["max-age=100", "max-age=0"]},
    )
    collected = {f.check_id: f for f in check_headers(raw)}
    assert collected["headers.hsts"].evidence["observed_headers"]["strict-transport-security"] == [
        "max-age=100",
        "max-age=0",
    ]
    assert observe(collected["headers.framing"]).complete
    assert observe(collected["headers.hsts"]).fields["header_fields"]["strict-transport-security"] == [
        "max-age=100",
        "max-age=0",
    ]


def test_http_redirect_to_verified_https_can_resolve_same_initial_http_criterion():
    before = {
        "url": "http://example.com/",
        "method": "HEAD",
        "status_code": 200,
        "address": "8.8.8.8",
        "headers": {"content-type": "text/html"},
        "hops": [{"url": "http://example.com/", "method": "HEAD", "status_code": 200, "address": "8.8.8.8"}],
    }
    after = deepcopy(before)
    after |= {
        "url": "https://www.example.com/",
        "address": "8.8.4.4",
        "hops": [
            {"url": "http://example.com/", "method": "HEAD", "status_code": 301, "address": "8.8.8.8"},
            {"url": "https://www.example.com/", "method": "HEAD", "status_code": 200, "address": "8.8.4.4"},
        ],
    }
    a, b = pair("http.redirect", before=before, after=after)
    assert change(a, b)["concern_change"] == "resolved_issue"
    assert change(a, b)["observation_change"] == "changed"


def test_redacted_queries_do_not_prove_equivalent_endpoint_parameters():
    a, b = pair("headers.csp", before=header_evidence(None), after=header_evidence("default-src 'self'"))
    a.findings[0].evidence["url"] = "https://example.com/?token=secret-one"
    b.findings[0].evidence["url"] = "https://example.com/?token=secret-two"
    item = change(a, b)
    assert item["concern_change"] == "inconclusive"
    assert "redacted_scope" in codes(item["reasons"])


def test_applicability_basis_changes_are_evaluation_changes_even_with_same_state():
    a, b = pair(
        old=Status.PASSED,
        new=Status.PASSED,
        before=dns_evidence(["v=spf1 -all"]),
        after=dns_evidence(["v=spf1 -all"]),
    )
    b.findings[0].evidence["applicability"]["basis"] = "observed_scope"
    item = change(a, b)
    assert item["dimensions"]["applicability_changed"]
    assert "applicability_changed" in codes(item["reasons"])
    assert "evaluation_changed" in item["categories"]


def test_different_http_client_versions_qualify_even_known_equivalent_rules():
    a, b = pair("headers.csp", before=header_evidence(None), after=header_evidence("default-src 'self'"))
    a.metadata["engine_version"] = "0.3.0"
    item = change(a, b)
    assert not item["dimensions"]["methodology_changed"]
    assert item["concern_change"] == "inconclusive"
    assert "client_version_changed" in codes(item["reasons"])


def test_partially_failed_inventory_still_reports_supported_common_record_change():
    inventory = {kind: dns_evidence(["8.8.8.8"], kind) for kind in ("A", "AAAA", "NS", "MX", "CAA")}
    a, b = pair("dns.records", Status.PASSED, Status.UNKNOWN, inventory, inventory)
    b.findings[0].evidence["A"]["records"] = ["8.8.4.4"]
    b.findings[0].evidence["AAAA"] = {
        "name": "example.com",
        "record_type": "AAAA",
        "state": "error",
        "records": [],
    }
    item = change(a, b)
    assert item["comparability"] == "partially_comparable"
    assert {"changed_observation", "inconclusive"} <= set(item["categories"])
    assert "AAAA.records" not in item["later"]["evidence"]


def test_irrelevant_email_context_does_not_reclassify_tls_observations():
    a, b = pair("tls.protocol", Status.PASSED, Status.PASSED, tls_evidence(), tls_evidence(), scoreable=True)
    b.metadata["context"]["sends_email"] = False
    result = compare_assessments(a, b)
    item = result.findings[0]
    assert item["categories"] == ["unchanged"]
    assert not item["dimensions"]["context_changed"]
    assert item["dimensions"]["assessment_context_changed"]
    assert result.comparability == "partially_comparable"
    assert not result.scoring["valid"]
