# v0.2 technical audit

Audit date: 2026-11-09. Baseline: `c96a493` (`main`); working branch: `improvement/cybercheck-v0.2`. Architecture, license and existing history are preserved.

## Baseline and method

Read the application, engine, checks, transport, persistence, reports, localization, CLI, tests, CI and project documentation. Executed the existing suite before changes: **119 passed, 93% statement coverage**; Ruff lint/format and `pip check` passed. Network behavior is tested with injected DNS, HTTP and TLS mocks. Dependency advisory lookup and a clean install are separate checks, not implied by `pip check`.

The user confirmed that no owned domain is currently available. No live assessment is authorized. The real-world procedure and pending status are recorded separately in `REAL_WORLD_VALIDATION.md`.

## Prioritized findings

Severity describes this local application's impact, not CVSS or the severity of a customer's domain. Confirmed behavior is distinguished from deployment risks and improvements. Fix outcomes and regression coverage are recorded as work proceeds and finalized in `VALIDATION.md`.

| ID | Priority | Classification | Baseline evidence / impact | Action |
|---|---|---|---|---|
| SEC-01 | Medium | Confirmed security-control bug | A chain starting at HTTP can upgrade to HTTPS and subsequently downgrade to HTTP because only the initial scheme is checked. | Remember whether any HTTPS hop has occurred; reject every subsequent downgrade before connection. |
| SEC-02 | Medium | Confirmed information exposure | `WebResponse.evidence()` serializes all response headers, including Set-Cookie, and full redirect queries. Reports/history can retain session cookies or URL tokens unrelated to configuration checks. | Use an evidence header allowlist, redact URL query/userinfo/fragment, sanitize failure diagnostics, and test persisted/exported output. |
| SEC-03 | Medium | Confirmed validation gap; exploitability depends on routing | `public_ip()` accepts reserved IPv6 `4000::1` and an IPv6 zone identifier. Special-purpose classifications also differ across supported Python versions. This violates the public-destination contract; no internal-service access is demonstrated. | Reject reserved/scoped addresses and explicitly block special-purpose/transition ranges consistently. |
| SEC-04 | Medium | Confirmed local file-handling weakness | CLI report writes follow pre-existing symbolic links and create files with default permissions before chmod. Exploitation requires local directory access; this is not a remote arbitrary-write claim. | Create reports exclusively with owner-only permissions and reject symlinks/existing files. |
| SEC-05 | Medium | Confirmed resource cleanup bug | If the shared deadline expires after TCP connection but before the TLS upgrade, the adapter raises without closing its raw stream. Repeated assessments can retain descriptors until collection. | Close on every TLS-upgrade failure, including pre-call timeout; exercise the real adapter with a memory backend. Respect shorter caller timeouts. |
| COR-01 | Medium | Confirmed parsing false positive | SPF duplicate unknown modifiers are reported as invalid although RFC 7208 requires unknown modifiers to be ignored. An equals sign inside a macro can also be mistaken for a modifier. | Recognize actual modifier grammar, limit duplicate validation to defined modifiers, and keep sender macros inconclusive. |
| COR-02 | Medium | Confirmed parsing/coverage defect | Common invalid A/MX CIDRs pass basic SPF checks; `_spf` dependencies are rejected as web hostnames; DMARC discovery does not recognize permitted whitespace around the version separator. | Separate DNS dependency names from web hostname validation; validate supported grammar without claiming a full SPF evaluator. |
| COR-03 | Medium | Confirmed false-positive/error cases | HSTS accepts unmatched quotes and converts an unbounded decimal string with `int()`. Multiple CSP policies are treated as a single policy. | Bound/validate header interpretation, handle multiple enforcing CSP policies, and avoid integer-conversion failures. |
| COR-04 | Medium | Confirmed incorrect success status | An entirely NXDOMAIN DNS inventory is marked Passed. | Report existence uncertainty without turning an absent hostname into a security vulnerability. |
| STO-01 | Medium | Confirmed forward-compatibility bug | Repository startup unconditionally sets SQLite user_version=1, including on a future-version database. | Reject unsupported schemas before changes and preserve version 1 data. |
| STO-02 | Low | Confirmed comparison noise / edge case | Raw headers include changing Date/cookie values; expiry-day counters cause change noise. Serialization changes tuples to lists. Equal timestamps are excluded by previous-assessment lookup. | Compare stable normalized evidence and use insertion order to break timestamp ties. |
| UX-01 | Low | Confirmed misleading progress text | The engine completion callback says results were saved before the UI attempts the database write. | Separate check completion from save completion; offer retry without another assessment. |
| DOC-01 | Low | Confirmed stale documentation | Documentation says the project is unpublished, though the public repository exists. Original validation provenance must remain distinguishable from new results. | Correct publication statements, preserve v0.1 validation, document executed v0.2 gates and pending live validation. |
| STD-01 | Medium | Confirmed standards coverage limitation | Official review found that RFC 9989 (May 2026) supersedes RFC 7489. v0.1 implements the older PSL/pct model, not the current DNS tree walk/testing semantics. | Explicitly label legacy interpretation, leave records using np/psd/t inconclusive, and prioritize a dedicated current-standard migration for v0.3. Do not claim full current DMARC conformance. |
| DEP-01 | Low | Verification / reproducibility limit | Existing lock is version-pinned but is not hash-verified; `pip check` only validates requirement compatibility. pip-audit 2.10.1 audited all 46 baseline lock entries with zero skips and zero known advisories. | Keep an advisory gate and repeat it against the final lock. A point-in-time advisory result is not a complete supply-chain audit. |

No confirmed Critical or High application vulnerability was identified in this code review. This is not a claim that the application has no vulnerabilities. The baseline advisory lookup completed successfully; the final lock and clean install are recorded in `VALIDATION.md`.

## Independent security review

The HTTP transport uses documented HTTPX/httpcore public APIs rather than monkey-patching private connection pools. Retain this adapter: its per-operation deadline and cumulative read cap address behavior that plain inactivity timeouts do not bound. Extend contract tests for backend connection/SNI, TLS failure cleanup, fragmented headers and deadlines. Do not disable verification or relax public-address checks for compatibility.

Existing positive controls include pinned literal-IP connections with original Host/SNI; validation of every redirect; no environment proxies, arbitrary ports, shell execution, GET bodies or selector enumeration; parameterized SQL; escaped report text/JSON evidence; a shared monotonic budget; and localhost binding. These controls must remain intact.

Untrusted evidence and exception messages should not be copied into logs indiscriminately. The review will retain useful exception types and stack locations while minimizing target-controlled diagnostic content. Historical v0.1 reports may already contain cookies; changing future collection does not scrub existing user data automatically.

## Risks and deferred work (not confirmed local exploits)

- Public multi-user hosting would require verified ownership, authentication, egress isolation, concurrency/rate limits and tenant separation. The current localhost application is not ready for that deployment. This is a High deployment risk if the documented boundary is ignored, not an existing hosted-service vulnerability.
- Local routing, OS, configured recursive resolver and CA store remain trusted. DNS rebinding tests cannot establish security against a compromised host or arbitrary VPN routes.
- SPF sender evaluation/macros/fan-out, message-level DKIM alignment, DNSSEC, revocation/CT and multi-IP endpoint coverage remain intentionally partial. Results must state those limits.
- Locally editable databases/reports are not authenticated evidence. Report escaping is tested; a malicious user controlling the local database is outside the ordinary target-input boundary.
- HTML print layout and responsive Streamlit behavior need explicit verification; AppTest coverage alone is not a browser visual review.
- Docker is optional; evaluate its operating burden before adding another supported deployment route.

## Resolution after implementation

SEC-01 through SEC-05, COR-01 through COR-04, STO-01/STO-02, UX-01 and DOC-01 have code/documentation changes and regression coverage. Additional export tests protect old v0.1 web history without mutating the stored source. Transport tests verified literal-IP connection, original hostname/SNI and mandatory certificate validation through the actual HTTPX/httpcore adapter, as well as bounded fragmented headers and cleanup.

STD-01 remains a deliberately scoped **Medium limitation**, with explicit legacy labeling and inconclusive modern-tag handling; full current-standard behavior is a v0.3 priority. DEP-01's final advisory scan covered all 65 locked entries with zero skips and zero known advisories. The application remains a local evaluation tool, with live validation pending because no authorized domain is available. No confirmed Critical or High finding remains unresolved within the reviewed local boundary; neither this review nor a clean advisory result is a guarantee of security.

## References

[SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208), [legacy DMARC RFC 7489](https://www.rfc-editor.org/rfc/rfc7489), [current DMARC RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989), [HSTS RFC 6797](https://www.rfc-editor.org/rfc/rfc6797), [Python IP classifications](https://docs.python.org/3/library/ipaddress.html), [HTTPX extensions](https://www.python-httpx.org/advanced/extensions/), [httpcore backends](https://www.encode.io/httpcore/network-backends/), [pip-audit](https://github.com/pypa/pip-audit).
