"""Pure, conservative comparison of saved assessments. No checks or writes."""

import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from cybercheck import CHECK_METHODOLOGY
from cybercheck.core.evidence import EVIDENCE_HEADERS, redact_url
from cybercheck.locales.comparison import ct, reason
from cybercheck.models import Assessment, Finding, Severity, Status, Text
from cybercheck.models.assessment import validate_assessment

COMPARISON_VERSION = "comparison-v1"
KNOWN_METHODOLOGIES = {"0.2.0": "checks-v0.2", "0.3.0": CHECK_METHODOLOGY, "0.4.0": CHECK_METHODOLOGY}
CATEGORIES = (
    "new_issue",
    "resolved_issue",
    "persistent_issue",
    "unchanged",
    "changed_observation",
    "evaluation_changed",
    "inconclusive",
)
HEADER_NAMES = {
    "headers.hsts": ("strict-transport-security",),
    "headers.csp": ("content-security-policy",),
    "headers.nosniff": ("x-content-type-options",),
    "headers.referrer": ("referrer-policy",),
    "headers.permissions": ("permissions-policy",),
    "headers.framing": ("content-security-policy", "x-frame-options"),
}
ISSUER_FIELDS = frozenset(
    {
        "commonName",
        "countryName",
        "localityName",
        "stateOrProvinceName",
        "organizationName",
        "organizationalUnitName",
        "emailAddress",
        "serialNumber",
        "domainComponent",
    }
)


def stable_evidence(value: object, key: str = "") -> object:
    """Existing normalization: exclude countdown, normalize sequence encoding/order."""
    if isinstance(value, dict):
        return {k: stable_evidence(v, k) for k, v in value.items() if k != "days_until_expiration"}
    if isinstance(value, (list, tuple)):
        items = [stable_evidence(v) for v in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True)) if key == "records" else items
    return value


@dataclass(frozen=True)
class Observation:
    fields: dict
    complete: bool


@dataclass(frozen=True)
class Comparison:
    domain: str
    earlier: dict
    later: dict
    comparability: str
    limitations: list[dict]
    findings: list[dict]
    summary: dict[str, int]
    scoring: dict
    methodology: Text
    comparison_version: str = COMPARISON_VERSION
    schema_version: int = 1
    report_type: str = "assessment_comparison"

    def to_dict(self) -> dict:
        return asdict(self)


def _metadata(a: Assessment) -> dict:
    return a.metadata if isinstance(a.metadata, dict) else {}


def _known_difference(left: Any, right: Any) -> bool | None:
    return left != right if left is not None and right is not None else None


def methodology(a: Assessment) -> str | None:
    metadata = _metadata(a)
    explicit = metadata.get("methodology_version")
    if "methodology_version" in metadata:
        return (
            explicit if isinstance(explicit, str) and explicit in {"checks-v0.2", CHECK_METHODOLOGY} else None
        )
    version = metadata.get("engine_version")
    return KNOWN_METHODOLOGIES.get(version) if isinstance(version, str) else None


def _profile(a: Assessment) -> str | None:
    metadata = _metadata(a)
    profile = metadata.get("scoring_profile")
    if "scoring_profile" in metadata:
        return profile if profile == "context-v1" else None
    return "legacy-v1" if metadata.get("engine_version") == "0.2.0" else None


def _context(a: Assessment) -> dict | None:
    value = _metadata(a).get("context")
    if not isinstance(value, dict):
        return None
    fields = ("sends_email", "receives_email", "controls_dns")
    if not all(key in value and (value[key] is None or type(value[key]) is bool) for key in fields):
        return None
    # Copy selected fields; do not trust arbitrary metadata or declarations as proof.
    return {key: value[key] for key in fields}


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except (TypeError, ValueError, OverflowError):
        return None


def _snapshot(a: Assessment) -> dict:
    def text(name: str) -> str | None:
        value = _metadata(a).get(name)
        return value if isinstance(value, str) and len(value) <= 128 else None

    enabled = _metadata(a).get("get_fallback_enabled")
    return {
        "id": a.id,
        "domain": a.domain,
        "started_at": a.started_at,
        "completed_at": a.completed_at,
        "engine_version": text("engine_version"),
        "methodology_version": methodology(a),
        "scoring_profile": _profile(a),
        "context": _context(a),
        "context_source": "user_declared_unverified" if _context(a) is not None else "not_recorded",
        "selectors": sorted(a.selectors),
        "http_method": text("http_method"),
        "get_fallback_enabled": enabled if type(enabled) is bool else None,
        "synthetic_fixture": _metadata(a).get("synthetic_fixture") is True,
    }


def _records(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return sorted(set(value))


def _scalar_fields(data: dict, names: tuple[str, ...]) -> dict:
    return {key: data[key] for key in names if key in data and isinstance(data[key], str)}


def _dns_observation(data: dict, key: str) -> Observation:
    fields = _scalar_fields(data, ("name", "record_type", "state"))
    records = _records(data.get("records"))
    if records is not None:
        if key == "email.spf":
            records = [item for item in records if re.match(r"^v=spf1(?:\s|$)", item, re.I)]
        elif key == "email.dmarc":
            records = [
                item for item in records if re.match(r"^v[ \t]*=[ \t]*DMARC1(?:[ \t]*;|[ \t]*$)", item)
            ]
        if data.get("state") in ("ok", "absent"):
            fields["records"] = records
    expected = {"dns.mx": "MX", "dns.caa": "CAA", "email.spf": "TXT", "email.dmarc": "TXT"}.get(
        key,
        "TXT" if key.startswith("email.dkim:") else key if key in {"A", "AAAA", "NS", "MX", "CAA"} else None,
    )
    complete = (
        records is not None
        and data.get("state") in ("ok", "absent")
        and isinstance(data.get("name"), str)
        and data.get("record_type") == expected
        and bool(data.get("name"))
        and (bool(data["records"]) if data.get("state") == "ok" else not data["records"])
    )
    return Observation(fields, complete)


def _legacy_header_fields(headers: object, names: tuple[str, ...]) -> dict | None:
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ):
        return None
    lowered = {}
    for key, value in headers.items():
        name = key.lower()
        if name in names:
            if name in lowered:
                return None  # Case-folding must not silently select a duplicate field.
            lowered[name] = value
    return {name: [lowered[name]] if name in lowered else [] for name in names}


def _header_fields(data: dict, names: tuple[str, ...]) -> dict | None:
    legacy = _legacy_header_fields(data.get("headers"), names) if "headers" in data else None
    if "headers" in data and legacy is None:
        return None
    observed = data.get("observed_headers")
    if isinstance(observed, dict) and all(
        name in observed
        and isinstance(observed[name], list)
        and all(isinstance(v, str) for v in observed[name])
        for name in names
    ):
        if legacy is not None and any(
            (", ".join(observed[name]) if observed[name] else None)
            != (legacy[name][0] if legacy[name] else None)
            for name in names
        ):
            return None
        if len(names) == 1 and "header_value" in data:
            values = observed[names[0]]
            expected = (
                (values[0] if names[0] == "strict-transport-security" else ", ".join(values))
                if values
                else None
            )
            if data["header_value"] != expected:
                return None
        return {name: list(observed[name]) for name in names}
    if "observed_headers" in data:
        return None
    if legacy is not None:
        if (
            len(names) == 1
            and "header_value" in data
            and data["header_value"] != (legacy[names[0]][0] if legacy[names[0]] else None)
        ):
            return None
        return legacy
    if (
        len(names) == 1
        and "header_value" in data
        and (data["header_value"] is None or isinstance(data["header_value"], str))
    ):
        return {names[0]: [] if data["header_value"] is None else [data["header_value"]]}
    return None  # Historical framing values are parser-generated, not raw fields.


def _coherent_hops(data: dict) -> bool:
    hops = data.get("hops")
    if not isinstance(hops, list) or not hops:
        return False
    for hop in hops:
        if not isinstance(hop, dict) or not isinstance(hop.get("url"), str):
            return False
        if hop.get("method") != data.get("method") or not isinstance(hop.get("address"), str):
            return False
        code = hop.get("status_code")
        if type(code) is not int or not 100 <= code <= 599:
            return False
        try:
            uri = urlsplit(hop["url"])
            if uri.scheme not in {"http", "https"} or not uri.hostname:
                return False
        except ValueError:
            return False
    last = hops[-1]
    return (
        redact_url(last["url"]) == redact_url(data.get("url", ""))
        and last["status_code"] == data.get("status_code")
        and ("address" not in data or last["address"] == data["address"])
    )


def observe(f: Finding | None) -> Observation:
    if f is None or not isinstance(f.evidence, dict):
        return Observation({}, False)
    data = f.evidence
    key = f.check_id
    if (
        key.partition(".")[0] in {"dns", "email", "tls", "http", "headers"}
        and f.category != key.partition(".")[0]
    ):
        return Observation({}, False)
    if key == "dns.records":
        parts = {
            kind: _dns_observation(data.get(kind, {}) if isinstance(data.get(kind), dict) else {}, kind)
            for kind in ("A", "AAAA", "NS", "MX", "CAA")
        }
        return Observation(
            {f"{kind}.{k}": v for kind, part in parts.items() for k, v in part.fields.items()},
            all(p.complete for p in parts.values()),
        )
    if key in {"dns.mx", "dns.caa", "email.spf", "email.dmarc"} or key.startswith("email.dkim:"):
        return _dns_observation(data, key)
    if key in {"tls.connection", "tls.chain", "tls.hostname", "tls.validity", "tls.protocol"}:
        fields = _scalar_fields(data, ("hostname", "address", "not_before", "not_after", "protocol"))
        if type(data.get("port")) is int:
            fields["port"] = data["port"]
        if type(data.get("verify_code")) is int:
            fields["verify_code"] = data["verify_code"]
        issuer = data.get("issuer")
        if isinstance(issuer, dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in issuer.items()
        ):
            fields["issuer"] = {k: v for k, v in issuer.items() if k in ISSUER_FIELDS}
        sans = data.get("subject_alt_names")
        if isinstance(sans, (list, tuple)) and all(
            isinstance(item, (list, tuple)) and len(item) == 2 and all(isinstance(v, str) for v in item)
            for item in sans
        ):
            fields["subject_alt_names"] = sorted({tuple(item) for item in sans})
        cipher = data.get("cipher")
        if (
            isinstance(cipher, (list, tuple))
            and len(cipher) == 3
            and isinstance(cipher[0], str)
            and isinstance(cipher[1], str)
            and type(cipher[2]) is int
        ):
            fields["cipher"] = list(cipher)
        measured = (
            isinstance(fields.get("protocol"), str)
            if key == "tls.protocol"
            else _time(fields.get("not_after")) is not None
        )
        complete = measured and all(name in fields for name in ("hostname", "address", "port"))
        if key == "tls.validity":
            complete = complete and _time(fields.get("not_before")) is not None
            if complete:
                complete = _time(fields["not_before"]) <= _time(fields["not_after"])
        elif key == "tls.chain":
            complete = complete and bool(fields.get("issuer"))
        elif key == "tls.hostname":
            complete = complete and bool(fields.get("subject_alt_names"))
        if "verify_code" in fields:
            complete = False  # Known capture format stops verification before collecting a certificate.
        return Observation(stable_evidence(fields), complete)
    if key in HEADER_NAMES or key in {"http.https", "http.application", "http.redirect"}:
        fields = _scalar_fields(data, ("method", "content_type", "address"))
        if isinstance(data.get("url"), str):
            fields["url"] = redact_url(data["url"])
        code = data.get("status_code")
        if type(code) is int and 100 <= code <= 599:
            fields["status_code"] = code
        if f.category == "headers":
            headers = _header_fields(data, HEADER_NAMES.get(key, ()))
            if headers is not None and key in HEADER_NAMES:
                fields["header_fields"] = headers
            complete = (
                headers is not None
                and key in HEADER_NAMES
                and all(name in fields for name in ("url", "method", "content_type", "status_code"))
                and 200 <= fields["status_code"] < 300
            )
            if key in {"headers.csp", "headers.permissions", "headers.framing"}:
                complete = complete and fields.get("content_type") in {"text/html", "application/xhtml+xml"}
        else:
            headers = data.get("headers")
            if isinstance(headers, dict):
                fields["headers"] = {
                    k.lower(): redact_url(v) if k.lower() == "location" else v
                    for k, v in headers.items()
                    if isinstance(k, str) and k.lower() in EVIDENCE_HEADERS and isinstance(v, str)
                }
                if "content-type" in fields["headers"]:
                    fields["content_type"] = (
                        fields["headers"]["content-type"].split(";", 1)[0].strip().lower()
                    )
            hops = data.get("hops")
            if isinstance(hops, list) and all(
                isinstance(hop, dict)
                and isinstance(hop.get("url"), str)
                and type(hop.get("status_code")) is int
                for hop in hops
            ):
                fields["hop_count"] = len(hops)
                for index, hop in enumerate(hops):
                    fields |= {
                        f"hops.{index}.{k}": v
                        for k, v in {
                            "url": redact_url(hop["url"]),
                            "status_code": hop["status_code"],
                            **_scalar_fields(hop, ("method", "address")),
                        }.items()
                    }
            complete = all(name in fields for name in ("url", "method", "status_code"))
            if key == "http.redirect" or data.get("hops"):
                complete = complete and _coherent_hops(data)
        try:
            parsed = urlsplit(fields.get("url", ""))
            complete = (
                complete
                and parsed.scheme in ("http", "https")
                and bool(parsed.hostname)
                and fields.get("method") in ("HEAD", "GET")
            )
            if f.category == "headers":
                complete = complete and parsed.scheme == "https"
        except ValueError:
            complete = False
        return Observation(fields, complete)
    return Observation({}, False)


def _global_reasons(earlier: Assessment, later: Assessment) -> list[str]:
    codes = []
    methods = methodology(earlier), methodology(later)
    if None in methods:
        codes.append("methodology_unknown")
    elif methods[0] != methods[1]:
        codes.append("methodology_changed")
    profiles = _profile(earlier), _profile(later)
    if None in profiles:
        codes.append("profile_unknown")
    elif profiles[0] != profiles[1]:
        codes.append("profile_changed")
    if _context(earlier) != _context(later):
        codes.append(
            "context_changed"
            if _context(earlier) is not None and _context(later) is not None
            else "context_missing"
        )
    if set(earlier.selectors) != set(later.selectors):
        codes.append("selectors_changed")
    for field in ("http_method", "get_fallback_enabled"):
        old, new = _metadata(earlier), _metadata(later)
        valid = (
            (old.get(field) == "HEAD" and new.get(field) == "HEAD")
            if field == "http_method"
            else (type(old.get(field)) is bool and type(new.get(field)) is bool)
        )
        if not valid or old[field] != new[field]:
            codes.append("get_scope_changed")
            break
    if _time(earlier.started_at) is None or _time(later.started_at) is None:
        codes.append("invalid_time")
    return codes


def _finding_snapshot(f: Finding | None, observation: Observation) -> dict | None:
    if f is None:
        return None
    return {
        "id": f.id,
        "status": f.status.value,
        "severity": f.severity.value,
        "applicability": f.applicability if isinstance(f.evidence, dict) else "unknown",
        "applicability_basis": _applicability(f)[1],
        "applicability_recorded": _applicability(f)[2],
        "scoreable": f.scoreable,
        "evidence": observation.fields,
        "evidence_complete": observation.complete,
    }


def _applicability(f: Finding) -> tuple:
    details = f.evidence.get("applicability") if isinstance(f.evidence, dict) else None
    recorded = isinstance(details, dict) and details.get("state") in (
        "applicable",
        "not_applicable",
        "unknown",
    )
    basis = (
        details.get("basis") if isinstance(details, dict) and isinstance(details.get("basis"), str) else None
    )
    return (f.applicability if isinstance(f.evidence, dict) else "unknown", basis, recorded)


def _concern(f: Finding) -> bool:
    return (
        f.status in {Status.WARNING, Status.FAILED}
        and f.severity != Severity.INFO
        and (not isinstance(f.evidence, dict) or f.applicability != "not_applicable")
    )


def _criterion_change(key: str, differences: list[dict], observation: str) -> str:
    """Other TLS facts can change without changing this particular criterion."""
    relevant = {
        "tls.validity": {"not_before", "not_after"},
        "tls.protocol": {"protocol"},
        "tls.hostname": {"hostname", "subject_alt_names", "verify_code"},
        "tls.chain": {"issuer", "verify_code"},
    }.get(key)
    if relevant is None:
        return observation
    selected = [item for item in differences if item["field"] in relevant]
    if any(item["earlier_present"] and item["later_present"] for item in selected):
        return "changed"
    if selected or observation == "inconclusive":
        return "inconclusive"
    return "equivalent"


def _compare_finding(
    key: str,
    old: Finding | None,
    new: Finding | None,
    earlier: Assessment,
    later: Assessment,
    global_codes: list[str],
    duplicate: bool,
) -> dict:
    left, right = observe(old), observe(new)
    codes = [
        code
        for code in global_codes
        if code
        in {
            "methodology_unknown",
            "methodology_changed",
            "profile_unknown",
            "profile_changed",
            "invalid_time",
        }
    ]
    if (old or new) and (old or new).category in {"email", "dns"}:
        codes.extend(code for code in global_codes if code in {"context_changed", "context_missing"})
        if key.startswith("email.") or key == "dns.mx":
            if _context(earlier) is None or _context(later) is None:
                codes.append("context_missing")
    if (old or new) and (old or new).category in {"http", "headers"}:
        if _metadata(earlier).get("engine_version") != _metadata(later).get("engine_version"):
            codes.append("client_version_changed")
        if key != "http.redirect":
            codes.extend(code for code in global_codes if code == "get_scope_changed")
        if (
            "method" not in left.fields
            or "method" not in right.fields
            or left.fields.get("method") != right.fields.get("method")
        ):
            codes.append("method_changed")
        if any(
            left.fields.get(field) != right.fields.get(field) for field in ("content_type", "status_code")
        ):
            codes.append("response_scope_changed")
        if any(
            "?" in value
            for fields in (left.fields, right.fields)
            for name, value in fields.items()
            if (name == "url" or name.endswith(".url")) and isinstance(value, str)
        ):
            codes.append("redacted_scope")
    if duplicate:
        codes.append("duplicate_id")
    if old is None:
        codes.append("missing_earlier")
    if new is None:
        codes.append("missing_later")
    if not left.complete or not right.complete:
        codes.append("incomplete_evidence")

    def additional_hop(field: str, fields: dict) -> bool:
        match = re.fullmatch(r"hops\.([0-9]+)\..+", field)
        return bool(match and "hop_count" in fields and int(match[1]) >= fields["hop_count"])

    coverage_changes = [
        field
        for field in left.fields.keys() ^ right.fields.keys()
        if not additional_hop(field, right.fields if field in left.fields else left.fields)
    ]
    if coverage_changes:
        codes.append("field_coverage_changed")
    scope_fields = {
        field
        for field in left.fields.keys() & right.fields.keys()
        if field in {"url", "hostname", "address", "name", "port"} or field.endswith(".name")
    }
    if key == "http.redirect" and "hops.0.url" in left.fields and "hops.0.url" in right.fields:
        # The redirect criterion tests the same initial HTTP request. Changing the
        # final destination is an observation, not itself a change of input scope.
        scope_fields -= {"url", "address"}
        scope_fields |= {"hops.0.url", "hops.0.address"} & left.fields.keys() & right.fields.keys()
    if any(left.fields[field] != right.fields[field] for field in scope_fields):
        codes.append("endpoint_changed")
    differences = [
        {
            "field": field,
            "earlier_present": field in left.fields,
            "later_present": field in right.fields,
            "earlier": left.fields.get(field),
            "later": right.fields.get(field),
        }
        for field in sorted(left.fields.keys() | right.fields.keys())
        if field not in left.fields or field not in right.fields or left.fields[field] != right.fields[field]
    ]
    measured_differences = [
        item for item in differences if item["field"] != "state" and not item["field"].endswith(".state")
    ]
    shared_differences = any(
        item["earlier_present"] and item["later_present"] for item in measured_differences
    )
    observation = (
        "changed"
        if shared_differences
        else "equivalent"
        if left.complete and right.complete and not measured_differences
        else "inconclusive"
    )
    criterion_observation = _criterion_change(key, differences, observation)
    matched = old is not None and new is not None

    def changed(attribute: str) -> bool | None:
        return getattr(old, attribute) != getattr(new, attribute) if matched else None

    dimensions = {
        "status_changed": changed("status"),
        "severity_changed": changed("severity"),
        "applicability_changed": _applicability(old) != _applicability(new) if matched else None,
        "context_changed": _context(earlier) != _context(later)
        and bool((old or new) and (old or new).category in {"email", "dns"}),
        "assessment_context_changed": _context(earlier) != _context(later),
        "scoring_eligibility_changed": changed("scoreable"),
        "scoring_profile_changed": _known_difference(_profile(earlier), _profile(later)),
        "methodology_changed": _known_difference(methodology(earlier), methodology(later)),
        "engine_version_changed": _metadata(earlier).get("engine_version")
        != _metadata(later).get("engine_version"),
    }
    interpretation = any(
        dimensions[name]
        for name in (
            "status_changed",
            "severity_changed",
            "applicability_changed",
            "scoring_eligibility_changed",
        )
    )
    if dimensions["applicability_changed"]:
        codes.append("applicability_changed")
    if matched and (
        old.status in {Status.UNKNOWN, Status.ERROR, Status.NA}
        or new.status in {Status.UNKNOWN, Status.ERROR, Status.NA}
    ):
        codes.append("unmeasured_result")
    if criterion_observation == "equivalent" and interpretation:
        codes.append(
            "same_observation_different_result"
            if observation == "equivalent"
            else "same_criterion_different_result"
        )
    compatibility = (
        "not_comparable"
        if not matched or duplicate or not left.fields or not right.fields
        else "partially_comparable"
        if codes
        else "comparable"
    )
    lifecycle = "inconclusive"
    explanations = []
    if compatibility == "comparable" and matched:
        if _concern(old) and _concern(new):
            lifecycle = "persistent_issue"
            explanations.append("persistent_supported")
        elif criterion_observation == "changed" and old.status == Status.PASSED and _concern(new):
            lifecycle = "new_issue"
            explanations.append("new_supported")
        elif criterion_observation == "changed" and _concern(old) and new.status == Status.PASSED:
            lifecycle = "resolved_issue"
            explanations.append("resolved_supported")
        else:
            lifecycle = "unchanged"
    categories = [lifecycle] if lifecycle != "unchanged" or observation == "equivalent" else []
    if observation == "changed":
        categories.append("changed_observation")
        explanations.append("observation_changed")
    elif observation == "equivalent" and not interpretation:
        explanations.append("observation_equivalent")
    if (criterion_observation == "equivalent" and interpretation) or any(
        dimensions[name]
        for name in (
            "context_changed",
            "scoring_profile_changed",
            "methodology_changed",
            "applicability_changed",
            "scoring_eligibility_changed",
        )
    ):
        categories.append("evaluation_changed")
    title = (new or old).check_name if matched or old or new else Text(key, key)
    return {
        "check_id": key,
        "check_name": asdict(title),
        "categories": list(dict.fromkeys(categories)),
        "concern_change": lifecycle,
        "observation_change": observation,
        "criterion_observation_change": criterion_observation,
        "comparability": compatibility,
        "dimensions": dimensions,
        "differences": differences,
        "reasons": [reason(code) for code in dict.fromkeys(codes + explanations)],
        "earlier": _finding_snapshot(old, left),
        "later": _finding_snapshot(new, right),
        # Preserve familiar fields for existing comparison callers.
        "previous_status": old.status.value if old else None,
        "current_status": new.status.value if new else None,
        "previous_severity": old.severity.value if old else None,
        "current_severity": new.severity.value if new else None,
        "evidence_changed": observation == "changed",
    }


def _score_comparison(
    earlier: Assessment, later: Assessment, changes: list[dict], global_codes: list[str]
) -> dict:
    def criteria(a: Assessment) -> list[tuple]:
        return sorted(
            (f.check_id, f.scoreable, f.applicability if isinstance(f.evidence, dict) else "unknown")
            for f in a.findings
            if f.scoreable
            and f.status in {Status.PASSED, Status.FAILED}
            and (
                _profile(a) != "context-v1"
                or (
                    isinstance(f.evidence, dict)
                    and f.category != "headers"
                    and f.applicability == "applicable"
                )
            )
        )

    left, right = criteria(earlier), criteria(later)
    codes = [code for code in global_codes if code != "get_scope_changed"]
    if _context(earlier) is None or _context(later) is None:
        codes.append("context_missing")
    ids = {entry[0] for entry in left}
    if left != right:
        codes.append("score_criteria_changed")
    elif not ids:
        codes.append("no_scored_criteria")
    if any(c["comparability"] != "comparable" for c in changes if c["check_id"] in ids):
        codes.append("incomplete_evidence")

    def health(a: Assessment) -> dict:
        try:
            return a.health
        except (TypeError, AttributeError, ValueError):
            codes.append("incomplete_evidence")
            return {"score": None, "passed": None, "evaluated": None, "excluded": None}

    old_health, new_health = health(earlier), health(later)
    valid = not codes and old_health["score"] is not None and new_health["score"] is not None
    return {
        "valid": valid,
        "earlier": old_health,
        "later": new_health,
        "delta": round(new_health["score"] - old_health["score"], 1) if valid else None,
        "evaluated_check_ids": sorted(ids) if valid else None,
        "explanation": asdict(Text(ct("score_valid", "en"), ct("score_valid", "it")))
        if valid
        else asdict(Text(ct("score_invalid", "en"), ct("score_invalid", "it"))),
        "reasons": [reason(code) for code in dict.fromkeys(codes)],
    }


def compare_assessments(earlier: Assessment, later: Assessment) -> Comparison:
    validate_assessment(earlier, strict_evidence=False)
    validate_assessment(later, strict_evidence=False)
    if earlier.domain != later.domain:
        raise ValueError("Only assessments of the same domain can be compared")
    left_time, right_time = _time(earlier.started_at), _time(later.started_at)
    if left_time is not None and right_time is not None and left_time > right_time:
        raise ValueError("Earlier assessment must not be newer than later assessment")
    before, after = defaultdict(list), defaultdict(list)
    for f in earlier.findings:
        before[f.check_id].append(f)
    for f in later.findings:
        after[f.check_id].append(f)
    codes = _global_reasons(earlier, later)
    changes = [
        _compare_finding(
            key,
            before[key][0] if len(before[key]) == 1 else None,
            after[key][0] if len(after[key]) == 1 else None,
            earlier,
            later,
            codes,
            len(before[key]) > 1 or len(after[key]) > 1,
        )
        for key in sorted(before.keys() | after.keys())
    ]
    if not changes or all(item["comparability"] == "not_comparable" for item in changes):
        compatibility = "not_comparable"
        codes.append("empty_comparison")
    elif codes or any(item["comparability"] != "comparable" for item in changes):
        compatibility = "partially_comparable"
    else:
        compatibility = "comparable"
    # Include concrete per-finding limitations in the overall explanation too.
    limits = codes + [
        r["code"]
        for item in changes
        for r in item["reasons"]
        if item["comparability"] != "comparable"
        and r["code"] not in {"observation_changed", "observation_equivalent"}
    ]
    counts = Counter(category for item in changes for category in item["categories"])
    return Comparison(
        earlier.domain,
        _snapshot(earlier),
        _snapshot(later),
        compatibility,
        [reason(code) for code in dict.fromkeys(limits)],
        changes,
        {category: counts[category] for category in CATEGORIES},
        _score_comparison(earlier, later, changes, codes),
        Text(ct("methodology", "en"), ct("methodology", "it")),
    )
