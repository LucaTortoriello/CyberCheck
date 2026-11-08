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
6. Consume DNS/HTTP counters and a shared monotonic deadline. Check the deadline on each HTTP socket read/write/TLS operation. HEAD headers are limited to 64 KiB and response bodies are not consumed.
7. Persist observations and render escaped reports. Network or policy-block failures are unknown, not vulnerabilities.

HTTP uses HTTPX plus a small custom transport built on the public httpcore network backend API. This is necessary because HTTPX inactivity timeouts alone do not bound a slow stream's total duration. The httpcore and HTTPX API contracts are exercised with mock transports/backends. Relevant official docs: [HTTPX SNI extension](https://www.python-httpx.org/advanced/extensions/), [HTTPX transports](https://www.python-httpx.org/advanced/transports/) and [httpcore backends](https://www.encode.io/httpcore/network-backends/).

The DNS resolver is trusted local infrastructure, not a target-selected arbitrary server. DNS rebinding cannot change a pinned destination. Routing, VPNs, NAT policies, the OS trust store, and the machine itself remain trusted. A future hosted deployment should also enforce outbound network controls independent of application validation.

## Storage and operational assumptions

This is a single-user localhost application without authentication, tenants or a background queue. Concurrent Streamlit sessions have independent assessment budgets and can create additional traffic; do not expose the server publicly. SQLite connections are short-lived with bounded lock waits. There is no automated schema migration beyond the initial schema; introduce explicit migrations before changing payload contracts or `user_version`.

Do not store credentials in DNS records, environment examples or reports. Logs contain event, domain, assessment ID, module and exception type; unexpected exceptions include local tracebacks for diagnosis. JSON/HTML reports contain observed infrastructure details and are not encrypted at rest. The app never sends mail.

## Extension points

New check modules return `Finding` instances. Keep scheduling, organizations, alerts and billing outside the core; do not add a plugin framework until a concrete second integration needs it. A later managed service should invoke the same engine in isolated workers after ownership verification and rate limiting. Report branding can change the renderer without changing evidence or scoring.
