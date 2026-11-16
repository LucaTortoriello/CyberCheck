# v0.4 executed validation — assessment comparison

2026-11-16, macOS / Python 3.13.14. Main baseline `5500bb0`, branch
`improvement/cybercheck-v0.4-comparison`. The [audit](COMPARISON_AUDIT_V04.md)
was written before code changes. No live assessment was performed.

## Executed quality checks

| Check | Result |
|---|---|
| Baseline full suite | 265 passed |
| Full suite with coverage | **345 passed, 0 failed**; 80 added cases |
| Total statement coverage | **96%** rounded, 1,767 / 1,848 statements |
| Comparison core coverage | **98%**; comparison UI 95%; comparison report renderers 100% |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed |
| `git diff --check` | Passed |
| `python -m pip check` | No broken requirements found |
| Locked dependency advisory audit | Exit 0: **No known vulnerabilities found** |
| Offline comparison example generation | English/Italian HTML and bilingual JSON generated; stable IDs/dates and explicit synthetic labels |
| Chrome headless HTML | English local report rendered at 1200×1500; screenshot visually inspected |
| Chrome print check | Italian local comparison report produced a valid PDF |

Commands use the existing `.venv`:

```sh
python -m pytest -q --cov=cybercheck --cov-report=term-missing
ruff check .
ruff format --check .
git diff --check
python -m pip check
pip-audit -r requirements.lock --no-deps --disable-pip --progress-spinner off --cache-dir /tmp/cybercheck-v04-pip-audit --timeout 15
python scripts/generate_comparison_example.py
```

Advisories were checked with permitted network access to PyPI and a temporary
writable cache, without modifying the dependency lock. This is a point-in-time
advisory result. Chrome emitted macOS display-link/allocator diagnostics but both
commands exited 0 and generated the inspected artifacts in `/tmp`. This is not a
full accessibility, browser-matrix or full-app visual audit. Streamlit interaction
is covered by offline AppTest cases; no new browser/runtime dependencies were
installed. Remote CI's Python 3.12/3.13/3.14 runs are separate from this local record.

## Required regression coverage

[Core/report cases](../tests/test_comparison.py) and
[Streamlit cases](../tests/test_comparison_app.py) run with the existing autouse
guard rejecting unexpected outbound sockets/DNS. The original 265 cases remain,
including transport, DNS rebinding/SSRF, TLS verification, redirect budgets and
separately authorized GET behavior.

| Requested case | Verified behavior |
|---|---|
| 1–3. SPF, DMARC, MX changes | Measured records change; only comparable supported criteria receive lifecycle labels |
| 4. DNS order | Sorting/deduplication prevents false changes |
| 5. Certificate renewal | Expiration/issuer/SAN changes are observations, not automatic improvements |
| 6. TLS protocol | Negotiated version changes without inferring complete protocol support |
| 7–8. Header added/removed | New/resolved presence criteria with matching method/URL/response scope |
| 9. HEAD versus GET | Changed or missing method/authorization qualifies comparisons; no requests rerun |
| 10–12. Warning/Failed/Passed transitions | Evidence changes are required for new/resolved labels; identical evidence yields evaluation change |
| 13. Unknown becomes measurable | New evidence does not establish when a concern arose |
| 14. Newly introduced finding | Missing baseline is inconclusive, never automatically new |
| 15. Finding disappears | Missing later check never proves resolution |
| 16. Different DKIM selectors | Exact selector IDs only; no title matching |
| 17. Declared context changes | Separate context/applicability axes; no DNS delta invented |
| 18. Scoring profiles | No numerical delta for different/unknown profiles or different evaluated IDs |
| 19. v0.2/v0.3 history | Identical SPF +all becomes an evaluation change, not target improvement |
| 20. Timestamp/UUID/counter noise | No observation change; deterministic comparison for identical saved inputs |
| 21. Malformed/incomplete evidence | No fabricated absence/equivalence; safe exports and inconclusive comparisons |
| 22. Same-domain enforcement | Different domains and reversed known chronology rejected |
| 23. HTML/JSON consistency | Same category counts, source IDs, evidence/reasons, correct escaping and source immutability |
| 24. English/Italian consistency | Bilingual catalog, reason text and report parity checked |

Additional cases cover duplicate IDs, scoped endpoints/content types, partial DNS
inventory, failed lookups versus absence, filtered unrelated TXT, redacted query
parameters, raw framing/multiple HSTS fields, unknown future checks/methodologies,
applicability basis changes, HTTP client-version differences, and redirect changes
at the same initial HTTP endpoint. UI tests cover arbitrary nonconsecutive pairs,
older pages, domain-scoped selection, same/reversed selection, corrupt predecessor
recovery, both languages, exports and valid/invalid score-delta display.

## Historical compatibility and scope

Tests compare the exact stored SQLite row/payload bytes before and after loading,
comparison and both exports. Source objects and original flags/health remain
unchanged. No assessment migration or schema bump occurs. Assessment JSON/HTML
remain separate from the new `assessment_comparison` report schema 1. Existing
comparison list callers keep their familiar status/severity keys via an adapter;
the new API supplies full compatibility and independent dimensions.

Changed areas are comparison core/UI/catalog/template; history integration and
the legacy adapter; raw-header evidence and methodology metadata; source/project
version; README/Italian guide/methodology/audit/validation; tests and explicitly
fictional comparison examples/generator. Network transports, request budgets,
authorization, existing checking rules, context-v1 score calculation, persistence
schema, dependency lock, license and architecture diagrams are unchanged.

Remaining limitations: only supported recorded fields can be compared. Missing
raw framing, incomplete certificate/DNS data, derived SPF lookup estimates,
unrecognized checks/versions and unrecorded metadata remain limited or
inconclusive. Recorded version labels are not binary-integrity proof. Header
nonces, selected backends, caches, network conditions and time can affect results;
there is no full semantic policy equivalence, causal attribution, exploitation
proof or comprehensive security posture determination. Context is user-declared
and not independently verified.
