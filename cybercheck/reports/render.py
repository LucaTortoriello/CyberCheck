"""Self-contained, escaped and printable HTML; evidence-preserving JSON."""

import json
from importlib.resources import files

from jinja2 import Environment, select_autoescape

from cybercheck.locales.ui import tr
from cybercheck.models import Assessment


def render_json(assessment: Assessment) -> str:
    return json.dumps(
        assessment.to_dict()
        | {
            "configuration_health": assessment.health,
            "score_formula": tr("score_formula", "en"),
            "methodology": tr("methodology_body", "en"),
            "disclaimer": tr("disclaimer", "en"),
        },
        indent=2,
        ensure_ascii=False,
    )


def render_html(assessment: Assessment, language: str = "it", *, include_score: bool = False) -> str:
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
