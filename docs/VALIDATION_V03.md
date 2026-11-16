# v0.3 validation — finding quality and context

Executed locally on macOS, Python **3.13.14**, 2026-11-16. Base main:
`87a1483`. Branch: `improvement/cybercheck-v0.3-finding-quality`.
The [audit](FINDING_QUALITY_AUDIT_V03.md) was written before code changes.
No live assessment or modification of the assessed application was performed.

## Executed gates

| Check | Result |
|---|---|
| Baseline `python -m pytest -q` | 222 passed |
| Final `python -m pytest -q --cov=cybercheck --cov-report=term-missing` | **265 passed, 0 failed**; 43 added cases |
| Coverage | **95%** rounded (1,374 / 1,449 statements); context, TLS, HTTP checks, CLI and report renderer 100% |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed; 61 Python files formatted |
| `git diff --check` | Passed |
| `python -m pip check` | No broken requirements found |
| `pip-audit -r requirements.lock --no-deps --disable-pip --progress-spinner off --cache-dir /tmp/cybercheck-v03-pip-audit --timeout 15` | Exit 0: no known vulnerabilities found |
| `python scripts/generate_examples.py` | Regenerated labeled synthetic HTML/JSON offline |
| Package source version | 0.3.0 in source and project metadata |
| Chrome headless report check | Local synthetic HTML rendered at 1200×1200; screenshot visually inspected |

The initial advisory attempts hit sandbox cache/network restrictions. The final
run used a temporary writable cache and allowed advisory access; the successful
result above is from the completed lookup, not from the failed attempts.
Dependencies and lockfile were not changed. Advisory results are point-in-time.
Chrome emitted macOS display-link diagnostics but exited 0 and wrote the inspected
PNG; this was not a full browser, accessibility, application or print-PDF audit.
Streamlit navigation/form behavior is covered by offline AppTest cases. No new
runtime/browser dependencies were installed. CI's Linux/Python 3.12/3.13/3.14 matrix
is separate from this local result; do not infer remote success from this record.

## Required regression scenarios

All new regressions are in [test_finding_quality.py](../tests/test_finding_quality.py),
alongside the original network, transport, TLS, fallback, storage and UI suites.
An autouse test guard rejects unexpected socket connections and DNS resolution.

| Requested scenario | Verification |
|---|---|
| 1. Web-only name, no MX | Warning/informational observation; receiving applicability NA; raw absence retained |
| 2. No SPF | Informational Warning when context unknown, low Warning with declared sending; conditional action |
| 3. No DMARC | Same severity distinction; exact/organizational queries retained; legacy scope explicit |
| 4. No DKIM selectors | Unknown; no selector queries/guessing even with context |
| 5. Exact-name CAA absent | Optional/informational; unknown applicability; no claimed absent effective policy |
| 6. Declared email context | Separate sending/receiving roles, source=user_declared, independently_verified=false |
| 7. Unknown applicability | Default None values; conditional findings stay Unknown in applicability |
| 8. Shared platform | Known-looking and unfamiliar hostnames get identical unknown ownership/control defaults |
| 9. HEAD 501 + authorized GET 200 | GET method/order preserved; app passes limited criterion; HTML headers evaluated |
| 10. HEAD 501, no GET authorization | HEAD only; connectivity passes, app/header results remain Unknown |
| 11. Optional headers absent | Warnings, no confirmed vulnerability; optional presence and absence equally unscored |
| 12. Successful modern TLS handshake | One mocked handshake; explicit support-not-enumerated evidence; no broader protocol conclusion |
| 13. HTML/JSON consistency | Same applicability, context, bilingual reasons/actions, profile and evidence; rendering does not mutate source |
| 14. Italian/English consistency | Both reports and catalogs checked; critical conditional qualifiers explicitly asserted |
| 15. Optional score | Existing ratio, applicable candidates only, no unknown/error/warning penalty or optional-header dilution |
| 16. Historical compatibility | JSON/SQLite schema 1; exact saved payload, original 50% score and missing applicability retained after render/load |

Additional tests cover raw-evidence/query invariance under context changes, legacy
DMARC errors with modern markers remaining Unknown, inherited sp, parent lookup
errors, syntactically valid +all, wildcard framing policies, malformed optional
evidence, CLI/UI propagation and invalid context rejection before network access.

## Concrete before/after examples

| Evidence | Before | v0.3 new result |
|---|---|---|
| No MX on declared web-only host | Informational Warning; no applicability; action prescribed null MX for non-receivers | Same measured Warning; operational applicability NA; null MX only an option after checking requirements/control |
| No SPF, mail use unknown | Medium Warning; action prescribed one SPF record | Informational Warning; unknown applicability; inventory sending first, consider no-senders policy only if appropriate |
| No DMARC at child/organizational name | Medium Warning; first query lost on fallback; could imply complete absence | Informational Warning by default; both query results retained; current-standard discovery not claimed |
| No DKIM selectors | Correctly Unknown; action requested selectors without usage qualifier | Still Unknown; no discovery; obtain selectors only if relevant, never edit DNS merely to clear result |
| No CAA at input name | Correctly informational and inheritance-limited | Classification preserved; unknown applicability and optional nature explicit; administrator/control review |
| `v=spf1 +all` | Failed/High despite valid syntax | Warning/Medium permissiveness concern; syntax evidence intact |
| Modern DMARC `t=y; pct=999` | Failed legacy pct before unsupported-tag handling | Unknown; legacy diagnostics retained; no instruction to change modern policy for this check |
| Passing HSTS/nosniff plus confirmed TLS failure | Optional passes increased numerator and diluted failure | Headers excluded in context-v1; limited TLS criteria remain eligible |
| CSP `frame-ancestors https://*` | Passed recognized framing heuristic | Warning; wildcard source not asserted to be restrictive; embedding relevance stays conditional |

## Compatibility, scope and remaining limits

Schema version 1, stable finding identifiers and all existing statuses remain.
Context/applicability are optional keys in existing metadata/evidence dictionaries;
summary adds priority IDs. Persisted scoreable flags make new eligibility readable
by the original ratio implementation. Old runs retain original flags/formula and
classifications; rendering never calls new context annotation on historical data.
Cross-profile/context/coverage scores are not directly interchangeable. The HTML
adds applicability and conditional guidance without removing technical evidence;
priority lists omit informational/inapplicable items while full counts remain.

Changed areas: models and engine/context; DNS/email/header/TLS interpretation;
CLI and dashboard; bilingual actions/UI; report renderer/template and synthetic
examples; regression tests; README, Italian guide, methodology, audit/validation;
source/project version. Transport, resolver, SSRF/rebinding protections, budgets,
GET authorization, storage schema, license, dependency lock and architecture
diagrams are unchanged.

Mail usage, DNS ownership/control and user declarations are not independently
verified. Non-sending context does not establish anti-spoofing protection. Effective
CAA and full RFC 9989 discovery remain unimplemented. Sender authentication,
signing/alignment, cryptographic DKIM validation, all IPs/paths, actual application
functions, exploitability, complete TLS support, and full CSP/Permissions-Policy
semantics remain outside these limited checks. No real-world detection accuracy,
penetration-testing capability or comprehensive security guarantee is claimed.
