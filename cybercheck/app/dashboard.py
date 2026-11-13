"""Local Streamlit UI. All checks and storage remain usable without Streamlit."""

import json
import logging
import sqlite3
from dataclasses import replace
from html import escape

import streamlit as st

from cybercheck import __version__
from cybercheck.core.config import Settings
from cybercheck.core.engine import run_assessment
from cybercheck.core.evidence import safe_web_evidence
from cybercheck.core.logging import configure_logging
from cybercheck.locales.ui import tr
from cybercheck.models import Assessment, Finding, Severity, Status
from cybercheck.reports.render import render_html, render_json
from cybercheck.storage.sqlite import Repository, StorageDataError, compare

CSS = """
<style>
.block-container{max-width:1380px;padding-top:2.4rem;padding-bottom:3rem}
[data-testid="stHeader"]{background:transparent}
.cc-brand{display:flex;align-items:center;gap:12px;font-size:26px;font-weight:750;letter-spacing:-1px}
.cc-mark{font-size:20px;background:#153c38;color:#78e2bd;padding:5px 11px;border:1px solid #27584f;border-radius:10px}
.cc-muted{color:#91a1b9;font-size:13px;letter-spacing:.06em}
.cc-hero{padding:26px 30px;border:1px solid #27354a;border-radius:14px;background:linear-gradient(120deg,#15273b,#111d2f);margin:16px 0 24px}
.cc-hero h1{font-size:38px;letter-spacing:-1px;line-height:1.2;margin:5px 0 12px;color:#f1f6ff}
.cc-hero p{margin:0;color:#9aacc4}
[data-testid="stMetric"]{border:1px solid #28364b;border-radius:12px;padding:20px;background:#121e31}
[data-testid="stMetricValue"]{font-size:34px;font-weight:650}
[data-testid="stExpander"]{border-color:#28364b;border-radius:10px}
div[role="radiogroup"]{gap:1rem;flex-wrap:wrap}
button[kind="primary"]{font-weight:650}
@media(max-width:700px){.block-container{padding:1rem}.cc-hero{padding:20px}.cc-hero h1{font-size:28px}}
</style>
"""


def show_finding(f: Finding, language: str, *, expanded: bool = False) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    with st.expander(f"{t(f.status)} · {t(f.severity)} · {f.check_name.get(language)}", expanded=expanded):
        st.caption(f"{t(f.category)} · {f.check_id}")
        st.markdown(f"**{t('technical')}**")
        st.text(f.explanation.get(language))
        st.markdown(f"**{t('impact')}**")
        st.text(f.business_impact.get(language))
        st.markdown(f"**{t('remediation')}**")
        st.text(f.remediation.get(language))
        st.markdown(f"**{t('evidence')}**")
        st.json(
            safe_web_evidence(f.evidence) if f.category in {"http", "headers"} else f.evidence, expanded=False
        )
        st.caption(f"{t('verified')}: {f.timestamp}")
        for reference in f.references:
            st.link_button(t("references"), reference)


def empty_state(language: str) -> None:
    st.subheader(tr("empty", language))
    st.write(tr("empty_body", language))


def overview(a: Assessment | None, language: str) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    if not a:
        empty_state(language)
        return
    if a.metadata.get("synthetic_fixture"):
        st.warning(t("synthetic_notice"))
    st.markdown(
        f'<div class="cc-hero"><div class="cc-muted">{escape(t("overview").upper())}</div>'
        f"<h1>{escape(a.domain)}</h1><p>{escape(t('date'))}: {escape(a.completed_at or a.started_at)}</p></div>",
        unsafe_allow_html=True,
    )
    counts = a.counts
    for column, key, value in zip(
        st.columns(4),
        ("checks_passed", "warnings", "confirmed", "incomplete"),
        (counts["passed"], counts["warning"], counts["failed"], counts["unknown"] + counts["error"]),
        strict=True,
    ):
        column.metric(t(key), value)
    st.caption(t("scope_note"))
    if counts["unknown"] + counts["error"]:
        st.info(tr("incomplete_notice", language, count=counts["unknown"] + counts["error"]))
    if st.session_state.get("show_score", False):
        health = a.health
        st.metric(t("health"), "—" if health["score"] is None else f"{health['score']}/100")
        st.caption(tr("coverage", language, **health))
        st.info(t("score_formula"))
    st.subheader(t("summary"))
    categories = list(dict.fromkeys(f.category for f in a.findings))
    rows = []
    for category in categories:
        category_findings = [f for f in a.findings if f.category == category]
        rows.append(
            {t("category"): t(category)}
            | {t(status.value): sum(f.status == status for f in category_findings) for status in Status}
        )
    st.dataframe(rows, hide_index=True, width="stretch")
    st.subheader(t("attention"))
    items = [f for f in a.findings if f.status in {Status.FAILED, Status.WARNING}]
    order = {s: i for i, s in enumerate(Severity)}
    for f in sorted(items, key=lambda f: (f.status != Status.FAILED, order[f.severity]))[:6]:
        show_finding(f, language)
    if items:
        st.caption(tr("attention_count", language, displayed=min(6, len(items)), total=len(items)))
    if not items:
        st.info(t("no_attention"))


def new_assessment(repository: Repository, settings: Settings, language: str) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    st.title(t("new"))
    st.write(t("new_intro"))
    st.info(t("scope_note"))
    with st.form("new_assessment"):
        domain = st.text_input(t("domain"), placeholder="azienda.it", help=t("domain_help"), max_chars=253)
        selectors = st.text_input(
            t("selectors"), placeholder="selector1, selector2", help=t("selector_help"), max_chars=650
        )
        authorized = st.checkbox(t("authorization"))
        allow_get_fallback = st.checkbox(t("allow_get_fallback"), value=False)
        st.caption(t("get_fallback_help"))
        submitted = st.form_submit_button(t("start"), type="primary")
    if not submitted:
        return
    if not authorized:
        st.error(t("authorization_error"))
        return
    progress_bar = st.progress(0, text=t("running"))

    def progress(current: int, total: int, module: str) -> None:
        labels = {
            "spf": "SPF",
            "dmarc": "DMARC",
            "dkim": "DKIM",
            "dns": "DNS",
            "tls": "TLS",
            "http": "HTTP",
            "done": t("checks_done"),
        }
        progress_bar.progress(current / total, text=f"{current}/{total} — {labels[module]}")

    try:
        assessment = run_assessment(
            domain,
            selectors,
            authorized=True,
            settings=replace(settings, allow_get_fallback=allow_get_fallback),
            progress=progress,
        )
    except ValueError:
        progress_bar.empty()
        st.error(t("validation_error"))
        return
    except Exception:
        progress_bar.empty()
        logging.getLogger("cybercheck.app").exception("assessment_ui_error")
        st.error(t("execution_error"))
        return
    st.session_state["unsaved_assessment"] = assessment
    try:
        repository.save(assessment)
    except (OSError, sqlite3.Error):
        logging.getLogger("cybercheck.app").exception("assessment_save_error")
        st.warning(t("save_error"))
        progress_bar.progress(1.0, text=t("checks_not_saved"))
    else:
        st.session_state.pop("unsaved_assessment", None)
        st.session_state["active_id"] = assessment.id
        st.success(t("done"))
        progress_bar.progress(1.0, text=t("done"))
    st.session_state["last_assessment"] = assessment
    st.download_button(
        t("download_html"),
        render_html(assessment, language, include_score=st.session_state.get("show_score", False)),
        file_name=f"cybercheck-{assessment.domain}-{assessment.id[:8]}.html",
        mime="text/html",
    )
    overview(assessment, language)


def findings_view(a: Assessment | None, language: str) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    st.title(t("findings"))
    if not a:
        empty_state(language)
        return
    search = st.text_input(t("search")).casefold()
    cols = st.columns(3)
    categories = cols[0].multiselect(t("category"), sorted({f.category for f in a.findings}), format_func=t)
    severities = cols[1].multiselect(t("severity"), list(Severity), format_func=t)
    statuses = cols[2].multiselect(t("status"), list(Status), format_func=t)
    matches = [
        f
        for f in a.findings
        if (not categories or f.category in categories)
        and (not severities or f.severity in severities)
        and (not statuses or f.status in statuses)
        and (
            not search
            or search
            in (
                f.check_name.get(language) + " " + f.explanation.get(language) + " " + json.dumps(f.evidence)
            ).casefold()
        )
    ]
    st.caption(f"{len(matches)} / {len(a.findings)}")
    for f in matches:
        show_finding(f, language)
    if not matches:
        st.info(t("no_results"))


def history_view(repository: Repository, a: Assessment | None, language: str) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    st.title(t("history"))
    st.write(t("history_intro"))
    domain_filter = st.text_input(t("history_domain")).strip().lower()
    page = st.number_input(t("page"), min_value=1, step=1, value=1)
    records = repository.list(domain_filter or None, limit=25, offset=(page - 1) * 25)
    if records:
        st.dataframe(
            [{t("domain"): r["domain"], t("date"): r["started_at"], "ID": r["id"]} for r in records],
            hide_index=True,
            width="stretch",
        )
        labels = {r["id"]: f"{r['domain']} · {r['started_at'][:19]} · {r['id'][:8]}" for r in records}
        selected = st.selectbox(t("selected"), list(labels), format_func=labels.get, key="history_selected")
        if st.button(t("open_assessment")):
            st.session_state["active_id"] = selected
            st.rerun()
    else:
        st.info(t("not_assessed"))
    if a:
        st.subheader(t("compare"))
        st.caption(a.domain + " · " + (a.completed_at or a.started_at))
        try:
            previous = repository.previous(a)
        except StorageDataError:
            st.error(t("stored_invalid"))
            return
        if not previous:
            st.info(t("no_previous"))
        else:
            changes = compare(previous, a)
            if changes:
                st.dataframe(
                    [
                        {
                            t("check"): c["check_id"],
                            t("previous_status"): t(c["previous_status"] or "not_assessed"),
                            t("current_status"): t(c["current_status"] or "not_assessed"),
                            t("previous_severity"): t(c["previous_severity"] or "not_assessed"),
                            t("current_severity"): t(c["current_severity"] or "not_assessed"),
                            t("evidence_changed"): t("yes" if c["evidence_changed"] else "no"),
                        }
                        for c in changes
                    ],
                    hide_index=True,
                    width="stretch",
                )
            else:
                st.info(t("no_changes"))
            st.caption(t("compare_note"))


def reports_view(a: Assessment | None, language: str) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    st.title(t("reports"))
    if not a:
        empty_state(language)
        return
    st.write(t("reports_intro"))
    st.subheader(a.domain)
    st.caption((a.completed_at or a.started_at) + " · " + a.id)
    left, right = st.columns(2)
    filename = f"cybercheck-{a.domain}-{a.id[:8]}"
    left.download_button(
        t("download_html"),
        render_html(a, language, include_score=st.session_state.get("show_score", False)),
        file_name=filename + ".html",
        mime="text/html",
        type="primary",
    )
    right.download_button(
        t("download_json"), render_json(a), file_name=filename + ".json", mime="application/json"
    )
    st.info(t("disclaimer"))
    with st.expander(t("methodology")):
        st.write(t("methodology_body"))


def settings_view(settings: Settings, language: str) -> None:
    t = lambda key: tr(key, language)  # noqa: E731
    st.title(t("settings"))
    st.write(t("settings_intro"))
    # Widget state is cleaned up when leaving this page; persist preferences in
    # a separate session key so the choice survives further navigation/reruns.
    st.session_state["_show_score"] = st.session_state.get("show_score", False)

    def persist_score() -> None:
        st.session_state["show_score"] = st.session_state["_show_score"]

    st.checkbox(t("show_score"), key="_show_score", on_change=persist_score)
    st.caption(t("score_formula"))
    st.subheader(t("limits"))
    st.json(
        {
            "timeout_seconds": settings.timeout,
            "max_dns_queries": settings.max_dns,
            "max_http_requests": settings.max_http,
            "max_redirects": settings.max_redirects,
            "max_assessment_seconds": settings.max_seconds,
            "public_targets_only": True,
        }
    )
    st.subheader(t("storage"))
    st.code(str(settings.db_path.resolve()), language=None)
    st.info(t("settings_note"))


def main() -> None:
    st.set_page_config(
        page_title="CyberCheck", page_icon="◈", layout="wide", initial_sidebar_state="collapsed"
    )
    configure_logging()
    st.markdown(CSS, unsafe_allow_html=True)
    brand, language_column = st.columns([5, 1])
    with brand:
        st.markdown(
            '<div class="cc-brand"><span class="cc-mark">C</span>CyberCheck</div>', unsafe_allow_html=True
        )
    language = language_column.selectbox(
        "Lingua / Language",
        ["it", "en"],
        format_func=lambda lang: "Italiano" if lang == "it" else "English",
        key="language",
    )
    t = lambda key: tr(key, language)  # noqa: E731
    st.caption(t("local") + f" · v{__version__}")
    try:
        settings = Settings.from_env()
    except ValueError:
        logging.getLogger("cybercheck.app").exception("configuration_error")
        st.error(t("config_error"))
        st.stop()
    try:
        repository = Repository(settings.db_path)
        records = repository.list()
    except (ValueError, OSError, sqlite3.Error):
        logging.getLogger("cybercheck.app").exception("startup_error")
        st.error(t("storage_error"))
        st.stop()
    pages = ["overview", "new", "history", "findings", "reports", "settings"]
    page = st.radio(
        "Navigation", pages, format_func=t, horizontal=True, label_visibility="collapsed", key="navigation"
    )
    st.divider()
    assessment = st.session_state.get("unsaved_assessment")
    if assessment is not None:
        st.warning(t("unsaved"))
        if st.button(t("retry_save"), key="retry_save"):
            try:
                repository.save(assessment)
            except (OSError, sqlite3.Error):
                logging.getLogger("cybercheck.app").exception("assessment_retry_save_error")
                st.error(t("save_error"))
            else:
                st.session_state.pop("unsaved_assessment", None)
                st.session_state["active_id"] = assessment.id
                st.rerun()
    if records and assessment is None:
        labels = {r["id"]: f"{r['domain']} · {r['started_at'][:19]} · {r['id'][:8]}" for r in records}
        active_id = st.session_state.get("active_id")
        if active_id and active_id not in labels:
            try:
                older = repository.get(active_id)
            except StorageDataError:
                older = None
            if older:
                labels[active_id] = f"{older.domain} · {older.started_at[:19]} · {older.id[:8]}"
        ids = list(labels)
        index = ids.index(active_id) if active_id in ids else 0
        # Synchronize explicit selection changes from creation/history before the
        # widget is instantiated; retain ordinary picker interaction otherwise.
        if active_id in labels and active_id != st.session_state.get("_picker_active_id"):
            st.session_state["assessment_picker"] = active_id
        elif st.session_state.get("assessment_picker") not in ids:
            st.session_state["assessment_picker"] = ids[index]
        selected_id = st.selectbox(
            t("selected"),
            ids,
            index=index,
            format_func=labels.get,
            key="assessment_picker",
        )
        st.session_state["active_id"] = selected_id
        st.session_state["_picker_active_id"] = selected_id
        try:
            assessment = repository.get(selected_id)
        except StorageDataError:
            st.error(t("stored_invalid"))
    if page == "overview":
        if not assessment:
            st.title(t("tagline"))
        overview(assessment, language)
    elif page == "new":
        new_assessment(repository, settings, language)
    elif page == "history":
        history_view(repository, assessment, language)
    elif page == "findings":
        findings_view(assessment, language)
    elif page == "reports":
        reports_view(assessment, language)
    else:
        settings_view(settings, language)
    st.divider()
    st.caption("CyberCheck Community · " + t("scope_note"))
