# v0.2 validation record

Executed on **2026-11-09**, macOS/arm64, Python **3.13.14**, branch `improvement/cybercheck-v0.2`. Baseline: `c96a493`. The original v0.1 record is preserved in [validation/V01.md](validation/V01.md).

## Executed quality gates

| Gate | Actual result |
|---|---|
| Baseline suite before changes | **119 passed**, 93% statement coverage. |
| Final suite in the clean venv | **170 passed**, zero failures/warnings, **94%** rounded statement coverage (1,234 of 1,313 statements; 93.983%). |
| Ruff lint and formatting | Passed against the final source. |
| Dependency compatibility | `python -m pip check`: no broken requirements in the fresh environment. |
| Dependency advisory scan | pip-audit **2.10.1**, exact `requirements.lock`, PyPI advisory lookup: **65 versions audited, zero skips, zero known advisories**. Baseline lock: 46 versions, zero known advisories. |
| Fresh macOS installation | Created `/tmp/cybercheck-v02-clean`; installed the lock, then `pip install --no-deps -e .`; package version **0.2.0** and CLI verified. |
| HTML/JSON exports | Generated through the engine with mocked network; schema-1 round trip, derived-score recomputation, escaping, inconclusive summary and legacy web-evidence redaction tested. |
| Real browser UI | Chrome **156.0.8078.80**, Playwright **1.64.1**, isolated localhost preview with synthetic data: Italian/English and all six navigation views exercised, zero browser page errors. |
| Responsive layout | **1365 × 900** desktop and **390 × 844** mobile: no page-level horizontal overflow; screenshots visually inspected. |
| Browser print/PDF | Synthetic report printed to A4 by Chrome: valid PDF, **18 pages**, **462,861 bytes**; print-preview screenshot inspected. No runtime PDF dependency added. |
| GitHub Actions | Locked Python 3.12/3.13/3.14 jobs plus advisory job prepared. Check the PR's actual run result; local success is not a remote CI result. |
| Live target assessment | **Not run.** Developer confirmed no owned domain is currently available; no third-party target authorized. |

The final clean-environment command was:

```sh
/tmp/cybercheck-v02-clean/bin/pytest -q --cov=cybercheck --cov-report=term-missing
```

All 119 baseline tests remain in the suite, with 51 additional cases. No existing expectation was removed to hide a behavior change. Coverage is a test-completeness indicator, not evidence that every vulnerability is excluded.

## Regression evidence

New tests first reproduced the downgrade, reserved/scoped destination, cookie/token/exception retention and report symlink defects. Parser/history regressions reproduced SPF modifier/macros/underscore dependency issues, invalid supported CIDRs, DMARC version whitespace, malformed/long HSTS, combined CSP, NXDOMAIN success, future-schema downgrade, equal-timestamp ordering and unstable evidence comparisons. The real transport backend contract reproduced missing cleanup before TLS upgrade and ignored shorter caller timeouts before their fixes.

Final tests cover those cases, private report/database creation, legacy export redaction without rewriting the source, Unknown/Error/Not applicable classification, score exclusions, JSON/HTML integrity, recovery from unreadable stored data, bilingual startup errors and save retry without additional network requests. Resource warnings/unraisable exceptions fail the suite; newly added direct SQLite test connections were explicitly closed.

The custom transport uses documented public HTTPX/httpcore interfaces. A memory-stream test verified original Host/SNI, mandatory hostname/chain checks, no response-body consumption, fragmented-header deadline enforcement, the 64 KiB cap and socket cleanup. No TLS verification bypass or relaxed destination policy was introduced.

## Browser artifacts and reproduction

`scripts/browser_smoke.py` runs only against the localhost preview and never starts an assessment. An isolated database contains a clearly labeled synthetic fixture. Outbound browser requests to non-local origins are blocked. See [DEVELOPMENT.md](DEVELOPMENT.md) for reproduction.

Reviewed screenshots are [desktop](screenshots/v02-overview-desktop.png) and [mobile](screenshots/v02-overview-mobile.png). Transient artifacts are under `/tmp/cybercheck-v02-browser/`, including `browser-validation.json`, print preview and `synthetic-report.pdf`. They are synthetic QA outputs, not live security evidence. Chrome automation and selected viewport inspection are not a full accessibility, browser-compatibility or print-pagination audit.

## Remaining boundaries and release decision

No confirmed Critical or High application vulnerability remains unresolved within the reviewed localhost boundary, and the advisory lookup found no known vulnerabilities for the locked versions at execution time. This is not a comprehensive supply-chain review or a third-party certification. Bootstrap/build tools, unknown advisories, OS routing, resolver and trust-store integrity remain outside that result.

DMARC continues to use an explicitly labeled legacy RFC 7489 profile; full current RFC 9989 discovery/testing semantics are not implemented. That Medium limitation remains open and must be considered before a paid accuracy-sensitive offering. SPF remains partial; DKIM publication is not signing verification; HEAD/one-IP results are limited observations. Public hosting still needs ownership verification, authentication, quotas and independent egress isolation.

The engineering changes are suitable for **review**, not an assertion of completed real-world product validation. No live result or false-positive rate is fabricated. The [real-world procedure and pending status](REAL_WORLD_VALIDATION.md) are explicit. No merge into main, release publication, hosted deployment, license change or paid service is authorized by this record.
