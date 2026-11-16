# v0.4 comparison audit and design

Inspected main `5500bb0` (merged v0.3), before implementation. Baseline tests:
265 offline cases. No live assessment is required for this work.

## Existing behavior and limitations

SQLite already stores complete schema-v1 assessments, lists paginated history,
loads an assessment by ID and finds its immediate predecessor. `compare()` matches
stable check IDs, returns status/severity and an evidence-changed flag, ignores
certificate countdown and sorts DNS records. The dashboard displays this flat
table for the active run and its predecessor. Existing JSON/HTML assessment
exports, evidence minimization, bilingual text and optional scores can be reused.

Limitations identified:

- Applicability explanations, parser diagnostics and technical observations share
  the evidence dictionary; generic dictionary differences conflate them.
- Missing checks and changed selectors appear in the table without distinguishing
  missing coverage from new/resolved concerns. Duplicate IDs are silently lost.
- Context, engine/methodology versions, scoring profiles, method/GET authorization,
  endpoint changes and incomplete evidence do not qualify the comparison.
- Scores have no comparison validity check. v0.2 and context-v1 eligibility differ.
- There is no concern lifecycle, arbitrary saved-pair selector, detailed comparison
  evidence view, or comparison export. Only the immediately preceding run is used.

## Small implementation plan

Keep SQLite schema and source payloads unchanged. Introduce one pure comparison
module, using stable IDs and existing order/countdown normalization. Return
separate axes: observation, status/severity, applicability/context, eligibility/
profile and methodology. Provide seven nonexclusive summary categories: new,
resolved, persistent, unchanged, changed observation, evaluation changed and
inconclusive. Counts are per finding, so categories can overlap.

Concern labels mean a supported Warning/Failed criterion of noninformational
severity, not a proven vulnerability. New/resolved labels require comparable,
measurable evidence, a measured observation change and a Passed result on the
other side. An Unknown/Error/NA or missing baseline cannot establish a new issue;
a missing later check cannot prove resolution. Equivalent observations with a
changed result are evaluation changes, never automatic posture transitions.

Comparability is explicit (comparable/partially comparable/not comparable), with
bilingual rule-based reasons and no numerical confidence. Missing metadata is
not fabricated. Historical versions with known rules can map to a documented
methodology; unknown versions stay unknown. v0.4 adds a methodology identifier
for future runs because the checking rules themselves remain the v0.3 rules.

Normalize only allowlisted measured evidence, not explanatory prose, derived
parser decisions, applicability reasons, UUIDs, counters or times. Explicit nulls
and empty record sets remain distinguishable from absent fields. Incomplete or
malformed evidence reduces comparability; additional future/unrecognized fields
cannot establish equivalence. Export this projection only, using existing URL/
header minimization; never export arbitrary legacy response bodies/cookies.

Scores retain each assessment's historical calculation. Only expose a numerical
delta when known profiles, methodology, context, evaluated IDs and per-criterion
applicability/eligibility are compatible and supporting evidence is comparable.
Otherwise explain why the comparison is invalid; do not rewrite historical data.

History will retain its existing paginated list/open controls and add two same-
target selectors, using that target's existing history pagination. Default to
the active run and its predecessor. Reuse Jinja and translation infrastructure
for standalone JSON/HTML comparison exports without altering assessment formats.

## Validation plan

Cover all 24 requested scenarios with synthetic fixtures: policy/record/header
changes, DNS order, TLS renewal/protocol, lifecycle transitions, missing checks,
selectors, context/profile/methodology changes, legacy payloads, temporal noise,
malformed evidence, domain/order boundaries and bilingual report parity. Verify
SQLite payload bytes before/after comparison/export and no new network requests.
Run the complete suite, coverage, Ruff, dependency compatibility and advisory
checks. Preserve all existing transport/authorization/fallback regression suites.
