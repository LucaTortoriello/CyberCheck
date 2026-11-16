# CyberCheck v0.4 — independent pre-merge review

Date: 2026-11-16. PR: [#7](https://github.com/LucaTortoriello/CyberCheck/pull/7).
Branch: `improvement/cybercheck-v0.4-comparison`; fetched base `origin/main`
`5500bb0c95c2c8080a3abefc01030f7798745b7b`. Reviewed incoming head:
`8525ce455bb25d349b82f7b149eed8de6f90d9aa`. The local `main` reference was
older; the review uses the fetched remote base, not that stale local reference.

## A. Executive verdict

**READY TO MERGE WITH MINOR RESERVATIONS**, after the corrections described here
and successful CI on the updated branch. The incoming head required changes:
passing implementation tests did not cover several misleading comparisons,
structured-data export leaks and corrupt-history handling failures.

Five confirmed issue groups were corrected: four Medium, one Low. No Critical
or High issue was confirmed. Severity reflects the demonstrated local historical
data/export scenarios; no remote exploit, credential theft or memory exhaustion
was demonstrated. All 345 incoming tests still pass, alongside 48 independent
review cases. Remaining limitations concern supported projections, provenance,
resource limits and validation scope; they are not unresolved merge blockers.

This is a second-pass adversarial review, not an external human attestation.
Code, tests, templates, storage integration and documentation were inspected;
earlier claims of success were checked against executable reproductions.

## B. Confirmed findings by severity

Locations labeled **incoming** refer to `8525ce4`; **fixed** locations refer to
the files in this review revision. Regression names below are in
[`tests/test_review_v04.py`](../tests/test_review_v04.py). Run them with
`.venv/bin/python -m pytest tests/test_review_v04.py -q`.

### R1 — Medium: unrelated TLS changes could fabricate a concern lifecycle

- **Incoming:** `cybercheck/core/comparison.py:481`, `:537`, `:540`.
  **Fixed:** [`_criterion_change`](../cybercheck/core/comparison.py#L482) and
  lifecycle selection at [`:638`](../cybercheck/core/comparison.py#L638).
- **Cause:** all TLS certificate/connection fields formed one observation. Any
  changed field satisfied the evidence-change requirement for every TLS check.
- **Reproduce:** retain the same certificate validity dates; move the assessment
  across its expiry-warning threshold (Passed → Warning); change only the
  negotiated protocol from TLS 1.2 to 1.3. Repeat with cipher, issuer or SAN only.
- **Expected:** show the independent TLS measurement change and an evaluation
  change for unchanged expiry dates; no confirmed new validity concern caused by
  a configuration change. **Actual:** `new_issue` plus `changed_observation`.
- **Impact:** misleading regression/resolution attribution even with plausible
  native assessment data, without a corrupt record.
- **Status:** fixed. Criterion-specific evidence controls lifecycle;
  `criterion_observation_change` is additive, and unrelated observations remain
  visible. `test_review_same_expiry_crosses_time_threshold_while_other_tls_fields_change`
  covers four variants. Existing renewal/protocol/lifecycle tests remain green.

### R2 — Medium: incomplete or contradictory evidence could appear comparable

**Incoming:** `core/comparison.py:82`, `:94`, `:162`, `:171`, `:244`, `:259`,
`:279`. **Fixed:** [`methodology/profile`](../cybercheck/core/comparison.py#L94),
[`DNS/header consistency`](../cybercheck/core/comparison.py#L165),
[`redirect consistency`](../cybercheck/core/comparison.py#L253), and
[`TLS/web completeness`](../cybercheck/core/comparison.py#L279).

The common failure was accepting individually well-typed fields as sufficient,
without checking their meaning together. The following are distinct reproduced
cases within this issue group:

| Reproduction | Expected | Incoming actual / impact |
|---|---|---|
| SPF `state=absent` with `records=["v=spf1 +all"]`, followed by a Passed `-all` record; also `ok` with an empty raw answer and contradictory MX absence | Inconclusive lifecycle | Resolution accepted from internally inconsistent DNS evidence |
| Passed `tls.chain`/`tls.hostname` with endpoint and expiry only, lacking issuer/SAN respectively | Original 100 scores retained, numerical comparison invalid | Evidence marked complete and score comparison valid |
| Validity dates in reverse order | Inconclusive | Impossible validity interval accepted as supporting evidence |
| Warning → Passed CSP/permissions/framing on an `application/json` response | Document-level comparison inconclusive | Header changes labeled resolved despite unsupported document scope |
| Empty raw CSP fields plus nonempty scalar value; conflicting raw/combined values; case-colliding legacy map keys; explicit null combined map | Do not choose one contradictory representation | Arbitrary representation/fallback established a resolution |
| HTTP → HTTPS chain with missing initial method/IP, wrong final status or inconsistent hop method | Incomplete chain, no supported resolution | Resolution accepted from inconsistent redirect scope |
| Explicit null methodology with engine version 0.4, or null legacy scoring profile with version 0.2 | Unknown rules/profile; no supported lifecycle or score delta | Null treated as absent and known rules/profile inferred from version |

**Status:** fixed. Completeness checks now reject these combinations; explicit
unknown metadata no longer uses absent-key fallback. Relevant tests include
`test_review_contradictory_dns_result_cannot_establish_resolution`,
`test_review_partial_certificate_cannot_make_score_comparison_valid`,
`test_review_contradictory_tls_evidence_is_inconclusive`,
`test_review_document_headers_on_nonhtml_cannot_establish_resolution`,
both contradictory-header tests, the inconsistent-redirect test and both explicit
unknown methodology/profile tests. A recorded TLS verification rejection also
keeps certificate evidence incomplete. Known check/category disagreement is
handled conservatively; this is contract hardening, not a separately claimed
exploit. These checks do not authenticate source observations or rerun scanners.

### R3 — Medium: named export fields were not a complete nested allowlist

- **Incoming:** `core/comparison.py:124`, `:130`, `:131`, `:223`.
  **Fixed:** [`_snapshot`](../cybercheck/core/comparison.py#L132) and
  [issuer projection](../cybercheck/core/comparison.py#L306).
- **Cause:** the snapshot copied expected scalar metadata values without checking
  their types. Issuer dictionaries copied every string-valued property.
- **Reproduce:** store `{"body":"SYNTHETIC_PRIVATE_BODY",
  "authorization":"SYNTHETIC_PRIVATE_TOKEN"}` under `engine_version`,
  `http_method` or `get_fallback_enabled`. Alternatively add those two unexpected
  string properties to `evidence.issuer`. Compare and export.
- **Expected:** arbitrary body/credential properties excluded. **Actual:** the
  comparison projection included the canaries; metadata canaries appeared in JSON
  and both language HTML exports. No real secret was used.
- **Impact:** exporting malformed/extended historical data could disclose fields
  outside the documented projection. This did not demonstrate a network path
  that populates those metadata properties from an ordinary target response.
- **Status:** fixed with bounded typed metadata scalars, exact booleans and an
  issuer attribute allowlist. The nested-metadata export test covers three fields
  and all three renderings; `test_review_unexpected_issuer_properties_are_not_exported`
  covers issuer projection. Existing body/cookie/Authorization/URL minimization
  and HTML escaping tests still pass. Allowed strings are not a general DLP system.

### R4 — Medium: structurally corrupt history escaped the storage boundary

- **Incoming:** `models/assessment.py:85`, `:110`; `storage/sqlite.py:21`, `:90`.
  **Fixed:** [`model validation`](../cybercheck/models/assessment.py#L159),
  [`storage loading/identity checks`](../cybercheck/storage/sqlite.py#L22),
  [`UI handling`](../cybercheck/app/comparison.py#L72).
- **Cause:** dataclass construction accepted incorrect field types. Missing
  historical identities/timestamps used constructors intended for new runs.
  Stored payload identity was not checked against its SQLite history index.
- **Reproduce:** load otherwise valid JSON with `selectors=null`, `metadata=[]`,
  a list `check_id`/category, string `scoreable`, or object-valued English title.
  Compare or display it. Separately omit `started_at`, or change the payload
  domain while retaining the indexed domain.
- **Expected:** reject invalid structure with a recoverable storage error,
  preserve the original row, and never invent historical provenance.
  **Actual:** malformed objects were accepted; subsequent code could raise
  `TypeError`/`AttributeError`, treat a truthy string as score eligibility, or
  display invented current chronology. Index/payload disagreement was accepted.
- **Impact:** application failures and unreliable identity, chronology or score
  interpretation. The UI's existing same-domain guard already prevented some
  mismatched-domain comparisons; this is not claimed as a demonstrated bypass.
- **Status:** fixed with typed model validation and index equality checks. Missing
  start time remains empty/unknown; required identities are rejected rather than
  generated. Six structure cases, timestamp and byte-preserving identity tests
  reproduce the storage defects. Four additional real SQLite/Streamlit AppTest
  cases verify corrupt predecessor warnings, selection of another valid pair,
  two downloads for that pair, no downloads for the corrupt pair and exact source
  preservation. These UI cases extend the original invalid-JSON-only coverage.

### R5 — Low: historical input had no supported resource bounds

- **Incoming:** `storage/sqlite.py:23`, `:92`; `models/assessment.py:111`;
  recursive projection/export entry points in `core/comparison.py`.
  **Fixed:** [`models/validation.py`](../cybercheck/models/validation.py),
  [bounded SQLite reads](../cybercheck/storage/sqlite.py#L93) and
  [comparison preflight](../cybercheck/core/comparison.py#L760).
- **Reproduce:** provide a 17 MiB JSON string with a decoder hook, or an otherwise
  valid source with 80 nested metadata containers. **Expected:** bounded rejection
  before expensive downstream processing. **Actual:** the large string reached
  decoding and the deep historical object was accepted. This confirms missing
  bounds, not a demonstrated OOM or remote denial-of-service exploit.
- **Impact:** local loading/rendering could consume resources proportional to
  arbitrary stored input; decoder recursion errors were not classified as corrupt
  history. Practical severity depends on control of the local database/input.
- **Status:** fixed: 16 MiB serialized UTF-8/content budgets, depth 40, 200,000
  values/keys, 512 findings; iterative validation before copies/projection; bounded
  SQLite reads and recoverable native length/decoder recursion errors. Tests cover
  pre-decode rejection, depth, width, finding count, invalid surrogate Unicode,
  valid multilingual round trips and both `get`/`previous` read limits. Native
  SQLite length errors are exercised with a reduced test limit, not enormous
  allocations. The original payload remains unchanged. These limits deliberately
  reject exceptionally large records; they do not certify exact peak memory.

## C. Corrections and maintainability

Corrections are limited to comparison interpretation/projection, historical model
validation/read handling, bilingual error/reason text, documentation and regression
tests. The fictional JSON example was regenerated for the additive criterion
dimension; HTML output remained identical. No schema, dependencies, license,
version number, network implementation or security-check scope changed during
this review.

The incoming comparison core was 687 lines; it is now 812. Its independent
dimensions, supported historical formats and conservative comparability rules
justify significant domain logic. `_compare_finding` remains the largest function
and merits care when adding rules, but a broad refactor would add unnecessary
review risk. Small helpers now isolate demonstrated contract problems: legacy
header consistency, redirect coherence, criterion-specific TLS changes and input
validation. Resource validation is shared between loading and direct comparison,
without dependencies or copies. UI calls the pure comparison API and renderers;
the comparison core has no repository/network/UI imports. No refactor was made
solely for line count. The duplicated header-name map remains protected by the
existing equality regression rather than introducing an unrelated shared API.

## D. Independently executed validation

Local environment: macOS, Python **3.13.14**, existing `.venv`.

| Check | Executed result |
|---|---|
| Incoming full suite | **345 passed**, 4.10 s |
| First independent reproduction batch before fixes | **24 failed**; all were expected red regressions against the incoming implementation |
| Further 16-case batch before follow-up fixes | **9 failed, 31 passed** across the resulting 40 review cases; not every added precaution was a new defect |
| Final focused review suite | **48 passed** |
| Final full suite with coverage | **393 passed, 0 failed**, 8.35 s; 345 existing + 48 review cases |
| Total statement coverage | **95% rounded**: 1,942 / 2,045 statements (94.96%) |
| Selected module coverage | Comparison core **97%**, comparison UI **95%**, renderers **100%**, SQLite **99%**, new validation helper **91%** |
| Ruff lint / format | Passed |
| Dependency compatibility | `pip check`: no broken requirements |
| Locked dependency advisory audit | Exit 0, **No known vulnerabilities found**, 2026-11-16 |
| Whitespace | `git diff --check` passed |
| Fictional comparison generation | Passed offline; JSON updated, both HTML files unchanged |
| Archived-version compatibility | All three requested version pairings loaded/compared/exported; raw rows and source health unchanged |

Commands actually executed:

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest tests/test_review_v04.py -q
.venv/bin/python -m pytest -q --cov=cybercheck --cov-report=term-missing
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m pip check
.venv/bin/pip-audit -r requirements.lock --no-deps --disable-pip --progress-spinner off --cache-dir /tmp/cybercheck-v04-review-pip-audit --timeout 15
git diff --check
.venv/bin/python scripts/generate_comparison_example.py
```

The advisory lookup used network access to public package/advisory services;
assessment comparisons and tests used no live target network. Pip emitted a
non-writable default-cache warning during compatibility checking and pip-audit
recommended hashed lock inputs; both checks exited successfully. Dependencies
were not installed, upgraded or changed.

**Remote CI is separate:** the incoming head `8525ce4` had eight successful checks
(push and PR workflows, each with Python 3.12/3.13/3.14 plus dependency audit),
independently read through `gh pr view`. Updated-head CI must also pass before
merging; its results will be recorded after the correction commit is published.
Local Python 3.12/3.14 runs were not performed. No live third-party scans, OOM
stress test, full browser/accessibility matrix or new visual browser check was
performed in this review. Earlier Chrome checks are historical implementation
validation, not newly executed review results. No final local gate is failed or
blocked. Coverage is evidence of exercised statements, not proof of correctness.

## E. Security assessment

- **Rendering:** Jinja autoescaping is enabled; technical dictionaries use
  `tojson`, and comparison HTML has a restrictive offline CSP with no scripts,
  external styles, images or form actions. Hostile HTML report tests pass in
  both languages. No dynamic template source or `safe` filter is introduced.
- **Privacy:** comparisons copy supported field projections, not entire evidence
  dictionaries. The review closes nested metadata/issuer holes. Cookies,
  arbitrary Authorization headers, bodies, URL credentials/query values/fragments
  are excluded by the exercised comparison paths. Allowed security headers,
  certificate/DNS values, titles and URL paths can still disclose private strings;
  do not treat exports as guaranteed anonymous or secret-free.
- **SQL/files:** history queries use bound parameters. Comparison/export routines
  do not write sources, run shell commands, fetch URLs or construct filesystem
  destinations from stored evidence. Downloads are in-memory data. Repository
  initialization retains its existing private-file/directory behavior; testing
  used temporary databases, never the user's actual assessment history. No new
  path-traversal or SQL-injection path was confirmed.
- **Offline/network invariants:** source diff against fetched `origin/main`
  shows no changes to network transport, SSRF/public-IP validation, DNS rebinding
  checks, TLS verification, request/timeout budgets or GET authorization. The
  original v0.4 engine change records a methodology ID; header-check changes
  record raw fields only. Existing protections and their regression tests pass
  under the suite's unexpected-socket/DNS guard. The comparison core calls no
  scanner. No evidence was found of an unauthorized network regression.
- **Untrusted history:** invalid types/identity and bounded reads fail with a
  recoverable error; no automatic repair, deletion, truncation or source rewrite.
  This does not authenticate a maliciously edited but internally coherent record.

## F. Historical compatibility and preservation

In addition to the automated legacy tests, an independent temporary schema-1
SQLite database was populated with the **exact JSON text** from
`87a1483:docs/examples/assessment.json` (native v0.2) and
`5500bb0:docs/examples/assessment.json` (native v0.3). The native v0.4 example
generator supplied two additional synthetic sources. Their timestamps were set
to December 1, 2026 / January 1, 2027 **before saving** to establish chronology
after the archived v0.3 run; archived source text was not modified. An initial
verification attempt with the generator's October date failed its chronology
assertion; correcting the new fixture dates resolved the test setup, with no
product relaxation of chronological ordering.

| Pair | Result | Score delta |
|---|---|---|
| v0.2 / v0.3 | Partially comparable; 22 exact-ID entries | Suppressed |
| v0.3 / v0.4 | Partially comparable; 22 exact-ID entries | Suppressed |
| v0.4 / v0.4 | Partially comparable overall; 7 entries, including intentionally unsupported legacy framing | Valid for the identical supported scored TLS set |

Each pair was loaded from SQLite, compared and exported to bilingual JSON and
both HTML languages. All `SELECT rowid,*` tuples, including raw payload text,
were identical before and after; UTF-8 payload bytes/hashes and source health
values remained identical. `PRAGMA user_version` stayed **1**. The archived
payloads were 40,278 and 63,426 bytes, with SHA-256 respectively:

```text
v0.2 808705c9f7dc07f785d58a4b3ba7de4c84652d884e31ff26a427771277f71f48
v0.3 b5f1fdc94d3860388fe40d0c3d8227821251537da066a4fe3ba334af00cb3e8d
```

Missing applicability/context/raw framing fields stay unknown or incomplete;
historical DKIM selectors match exact selector IDs. Existing tests cover missing
methodology, unknown IDs, malformed times and absent versus explicit unknown
context, along with original payload preservation. Scores use saved flags and
the existing historical `Assessment.health` view; no new evaluation is applied
to saved findings and no score/payload is persisted again. The model's health
formula itself was unchanged by the review.

Valid native schema-1 history remains readable. Corrupt structures, inconsistent
index identity and inputs above supported limits are deliberately rejected and
preserved for recovery, rather than falsely claiming universal compatibility.
The old list adapter retains its existing keys and now carries conservative
qualifiers as documented by v0.4. No migration was performed.

## G. Remaining risks and limitations

1. Version/methodology labels are coarse recorded declarations, not code-integrity
   proofs. Internally coherent fabricated history cannot be authenticated here.
2. Equivalence covers selected recorded fields, not complete DNS/SPF/DMARC/CSP/TLS
   semantics or causal attribution. Time, client behavior, nonces, caches and
   different backends can change observations. Even criterion-specific deltas
   do not prove an administrator changed configuration.
3. Unknown checks, partial certificates, unsupported raw framing and missing
   context/metadata remain inconclusive. Conservative validation may suppress
   otherwise useful comparisons; it does not reconstruct missing evidence.
4. Resource caps intentionally exclude exceptionally large legitimate artifacts.
   They bound supported processing but are not exact memory/time guarantees;
   Python JSON decoding still allocates within the serialized limit. The local
   database/index and configured parent paths retain their existing trust model.
5. Allowed technical strings/URL paths may be confidential. The standalone full
   assessment report format was not redesigned into a general secret scrubber.
6. Offline AppTest verifies pair selection, pagination, language consistency,
   recovery and export availability. This review does not certify every browser,
   accessibility requirement, live network condition or all future formats.

These are documented scope/provenance limits and maintenance considerations,
not additional confirmed unfixed vulnerabilities. Large-function decomposition
and richer future evidence/provenance formats are suggestions, not required
changes for this PR.

## H. Final recommendation

**Merge PR #7 after updated-head GitHub Actions is green**, retaining the
documented limitations. Do not merge the incoming `8525ce4` without these fixes.
The review changes stay on the existing v0.4 feature branch; no new feature,
schema/dependency/license change, third-party scan, deployment or automatic merge
is part of this work. Myopia Control was not modified.
