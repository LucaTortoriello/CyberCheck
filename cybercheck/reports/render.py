"""Self-contained, escaped and printable HTML; evidence-preserving JSON."""

import json
from copy import deepcopy
from importlib.resources import files

from jinja2 import Environment, select_autoescape

from cybercheck.core.evidence import safe_web_evidence
from cybercheck.locales.ui import tr
from cybercheck.models import Assessment


def report_view(assessment: Assessment) -> Assessment:
    result = deepcopy(assessment)
    for finding in result.findings:
        if finding.category in {"http", "headers"}:
            finding.evidence = safe_web_evidence(finding.evidence)
    return result


def render_json(assessment: Assessment) -> str:
    assessment = report_view(assessment)
    return json.dumps(
        assessment.to_dict()
        | {
            "configuration_health": assessment.health,
            "summary": {
                "counts": assessment.counts,
                "confirmed_finding_ids": [f.id for f in assessment.findings if f.status == "failed"],
                "inconclusive_finding_ids": [
                    f.id for f in assessment.findings if f.status in {"unknown", "error"}
                ],
            },
            "score_formula": tr("score_formula", "en"),
            "methodology": tr("methodology_body", "en"),
            "disclaimer": tr("disclaimer", "en"),
        },
        indent=2,
        ensure_ascii=False,
    )


def render_html(assessment: Assessment, language: str = "it", *, include_score: bool = False) -> str:
    assessment = report_view(assessment)
    language = "en" if language == "en" else "it"
    environment = Environment(autoescape=select_autoescape(default=True))
    template = environment.from_string(
        files("cybercheck.reports").joinpath("template.html").read_text("utf-8")
    )
    grouped = {
        category: [f for f in assessment.findings if f.category == category]
        for category in dict.fromkeys(f.category for f in assessment.findings)
    }
    return template.render(
        a=assessment,
        language=language,
        t=lambda key, **values: tr(key, language, **values),
        groups=grouped,
        include_score=include_score,
    )
