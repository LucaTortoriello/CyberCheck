# Architecture and threat boundaries

## Components

```text
Streamlit UI / CLI
        |
        v
core.engine -> checks.email / checks.tls / checks.web / checks.headers
        |                   |
        |              core.dns + core.network + core.transport
        v
models.Assessment / Finding / bilingual Text
        |
        +-> storage.sqlite (JSON payload, indexed assessment metadata)
        +-> reports.render (autoescaped HTML / JSON)
```

- `core/`: normalization, limits, DNS, pinned transport, orchestration and structured logging.
- `checks/`: deterministic interpretation of observed evidence and bounded network execution.
- `models/`: typed dataclasses, stable check IDs, unique finding-instance IDs, statuses and optional score.
- `storage/`: short-lived SQLite connections and parameterized queries. Schema version 1.
- `reports/`: self-contained templates with no remote resources or scripts.
- `app/`: presentation, filters and session state. Does not implement security checks.
- `locales/`: bilingual UI and finding text, persisted so existing assessments can switch language.
- `tests/`: network-blocked unit, integration and Streamlit tests.

An assessment contains immutable observations in normal use. The database can upsert the same assessment ID for retrying persistence; each new assessment and finding instance receives a UUID. Comparisons use stable `check_id` values, including the explicit DKIM selector. Findings record UTC timestamps and references.

## Public-target execution

1. Require an authorization declaration and normalize a domain-only IDNA input.
2. Use the configured recursive resolver with absolute query names and explicit DNS lifetime.
3. For a web destination, resolve both A and AAAA and reject the whole set on any non-public address or incomplete resolution.
4. Use the first validated IP as the literal socket/HTTP destination. Preserve the intended Host and TLS SNI; verification remains enabled.
5. Validate every redirect separately. Only HTTP/80 and HTTPS/443 are possible, and redirect scope is restricted to the initial organizational domain using a bundled PSL, including private suffix boundaries to separate shared-hosting tenants.
6. Consume DNS/HTTP counters and a shared monotonic deadline. Check the deadline on each HTTP socket read/write/TLS operation. HEAD and optional GET header reads are limited to 64 KiB and response bodies are not consumed.
7. Persist minimized observations and render escaped reports. Web evidence uses an allowlist, query/userinfo/fragment redaction and classified diagnostics. Rendering old web history also redacts without rewriting source payloads. Network or policy-block failures are unknown, not vulnerabilities.

The redirect chain remembers whether any HTTPS hop has occurred, so a later HTTP downgrade is blocked even when the initial URL was HTTP. DNS-only SPF dependencies permit service labels such as `_spf`; that validator is never used to weaken web destination validation. HTTPX's original Host/SNI reaches the real httpcore backend, as exercised by public-interface memory-stream tests. The adapter closes raw streams on failed TLS upgrades and respects the shorter of caller timeout and remaining budget.

HTTPS HEAD 405/501 can trigger one explicitly authorized GET fallback chain, disabled by default. It starts at the final HEAD URL; GET requires HTTPS at every hop and uses the same validation, IP pinning, certificate verification and budgets. HEAD and GET share one redirect allowance. The response stream is closed immediately without body reads; some body bytes may arrive with headers and are discarded. GET can have side effects despite this constraint. `http.https` records connectivity independently of the new unscored `http.application` response finding; browser headers require an eligible HTTPS 2xx response. Schema version 1 is retained with additive observation evidence and metadata.

HTTP uses HTTPX plus a small custom transport built on the public httpcore network backend API. This is necessary because HTTPX inactivity timeouts alone do not bound a slow stream's total duration. The httpcore and HTTPX API contracts are exercised with mock transports/backends. Relevant official docs: [HTTPX SNI extension](https://www.python-httpx.org/advanced/extensions/), [HTTPX transports](https://www.python-httpx.org/advanced/transports/) and [httpcore backends](https://www.encode.io/httpcore/network-backends/).

The DNS resolver is trusted local infrastructure, not a target-selected arbitrary server. DNS rebinding cannot change a pinned destination. Routing, VPNs, NAT policies, the OS trust store, and the machine itself remain trusted. A future hosted deployment should also enforce outbound network controls independent of application validation.

## Storage and operational assumptions

This is a single-user localhost application without authentication, tenants or a background queue. Concurrent Streamlit sessions have independent assessment budgets and can create additional traffic; do not expose the server publicly. SQLite connections are short-lived with bounded lock waits. Version 1 is preserved; unsupported future schemas fail before schema changes. Malformed payloads raise a recoverable storage error. Report files are created exclusively at mode 0600, refusing existing files and final symlinks; database files are created privately before SQLite opens them. Parent directories remain trusted. Explicit migrations are required before changing schema version.

Previous-assessment lookup orders equal timestamps by insertion rowid. Comparison normalizes list/tuple serialization, unordered DNS record sets and the certificate expiry countdown, while still detecting certificate date, status, severity and policy changes. Across engine versions, evidence-schema differences may remain visible and are not automatically risk regressions.

Do not store credentials in DNS records, environment examples or reports. Logs contain event, domain, assessment ID, module, exception type and stack locations, without arbitrary exception messages, locals or source-line text. JSON/HTML reports contain observed infrastructure details and are not encrypted at rest. The app never sends mail. JSON adds a derived summary while preserving schema-version-1 model fields; `Assessment.from_dict()` ignores known derived fields and recomputes the optional score.

## Extension points

New check modules return `Finding` instances. Keep scheduling, organizations, alerts and billing outside the core; do not add a plugin framework until a concrete second integration needs it. A later managed service should invoke the same engine in isolated workers after ownership verification and rate limiting. Report branding can change the renderer without changing evidence or scoring.
