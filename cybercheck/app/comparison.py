"""Read-only, paginated pair selection and comparison presentation."""

import streamlit as st

from cybercheck.core.comparison import compare_assessments
from cybercheck.locales.comparison import ct
from cybercheck.locales.ui import tr
from cybercheck.models import Assessment
from cybercheck.reports.render import render_comparison_html, render_comparison_json
from cybercheck.storage.sqlite import Repository, StorageDataError


def comparison_view(repository: Repository, active: Assessment, language: str) -> None:
    t = lambda key: ct(key, language)  # noqa: E731
    st.subheader(t("title"))
    st.write(t("intro"))
    columns = st.columns(2)
    key = f"comparison_{active.id}"
    earlier_page = columns[0].number_input(
        t("baseline_page"), min_value=1, max_value=1_000_000, value=1, step=1, key=key + "_earlier_page"
    )
    later_page = columns[1].number_input(
        t("page"), min_value=1, max_value=1_000_000, value=1, step=1, key=key + "_later_page"
    )
    earlier_rows = repository.list(active.domain, limit=25, offset=(earlier_page - 1) * 25)
    later_rows = repository.list(active.domain, limit=25, offset=(later_page - 1) * 25)
    try:
        previous = repository.previous(active)
    except StorageDataError:
        st.warning(tr("stored_invalid", language))
        previous = None

    def options(rows: list[dict], default: Assessment) -> dict:
        values = {row["id"]: f"{row['started_at']} · {row['id'][:8]}" for row in rows}
        # Pin the active/predecessor so defaults also work outside the loaded page.
        values.setdefault(default.id, f"{default.started_at} · {default.id[:8]}")
        return values

    earlier_options, later_options = options(earlier_rows, previous or active), options(later_rows, active)
    selected_earlier = columns[0].selectbox(
        t("earlier"),
        list(earlier_options),
        index=list(earlier_options).index((previous or active).id),
        format_func=earlier_options.get,
        key=key + "_earlier",
    )
    selected_later = columns[1].selectbox(
        t("later"),
        list(later_options),
        index=list(later_options).index(active.id),
        format_func=later_options.get,
        key=key + "_later",
    )
    if selected_earlier == selected_later:
        st.info(t("choose_distinct"))
        return
    try:
        earlier, later = repository.get(selected_earlier), repository.get(selected_later)
        if (
            earlier is None
            or later is None
            or earlier.domain != active.domain
            or later.domain != active.domain
        ):
            st.error(tr("stored_invalid", language))
            return
        comparison = compare_assessments(earlier, later)
    except StorageDataError:
        st.error(tr("stored_invalid", language))
        return
    except ValueError:
        st.info(t("choose_distinct"))
        return
    for column, label, snapshot in zip(
        columns, ("earlier", "later"), (comparison.earlier, comparison.later), strict=True
    ):
        column.caption(
            f"{t(label)}: {snapshot['started_at']} · CyberCheck {snapshot['engine_version'] or tr('unknown', language)}"
        )
    if comparison.earlier["synthetic_fixture"] or comparison.later["synthetic_fixture"]:
        st.warning(tr("synthetic_notice", language))
    st.markdown(f"**{t('compatibility')}: {t(comparison.comparability)}**")
    for item in comparison.limitations:
        st.caption(item["explanation"][language])
    st.caption(t("overlap"))
    st.dataframe(
        [
            {tr("category", language): t(category), tr("summary", language): count}
            for category, count in comparison.summary.items()
        ],
        hide_index=True,
        width="stretch",
    )
    st.subheader(t("score"))
    st.write(comparison.scoring["explanation"][language])
    if comparison.scoring["valid"]:
        st.caption(
            f"{comparison.scoring['earlier']['score']} → {comparison.scoring['later']['score']} · Δ {comparison.scoring['delta']}"
        )
    for item in comparison.scoring["reasons"]:
        st.caption(item["explanation"][language])
    exports = st.columns(2)
    stem = f"cybercheck-comparison-{active.domain}-{earlier.id[:8]}-{later.id[:8]}"
    exports[0].download_button(
        t("download_html"),
        render_comparison_html(comparison, language),
        file_name=stem + ".html",
        mime="text/html",
        key=key + "_html",
    )
    exports[1].download_button(
        t("download_json"),
        render_comparison_json(comparison),
        file_name=stem + ".json",
        mime="application/json",
        key=key + "_json",
    )
    st.subheader(t("details"))
    for item in comparison.findings:
        with st.expander(
            f"{item['check_name'][language]} · " + ", ".join(t(category) for category in item["categories"])
        ):
            st.caption(item["check_id"] + " · " + t(item["comparability"]))
            st.text(
                f"{tr(item['previous_status'] or 'not_assessed', language)} → {tr(item['current_status'] or 'not_assessed', language)} · "
                f"{tr('severity', language)}: {tr(item['previous_severity'] or 'not_assessed', language)} → {tr(item['current_severity'] or 'not_assessed', language)}"
            )
            for label in ("earlier", "later"):
                snapshot = item[label]
                if snapshot is not None:
                    st.caption(t(label) + " · " + tr("applicability_" + snapshot["applicability"], language))
            for explanation in item["reasons"]:
                st.text(explanation["explanation"][language])
            st.caption(t("dimensions"))
            st.json(item["dimensions"], expanded=False)
            st.caption(t("evidence"))
            st.json(
                {"earlier": item["earlier"], "later": item["later"], "differences": item["differences"]},
                expanded=False,
            )
