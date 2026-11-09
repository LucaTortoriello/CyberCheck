# CyberCheck

**Understand a domain's security configuration, with evidence and clear next steps.**

CyberCheck is a working local assessment application for small businesses, freelancers and IT providers. It performs low-impact DNS, email, TLS and web configuration checks, stores assessment history in SQLite, and exports actionable HTML and JSON reports. The interface and HTML reports support Italian (default) and English.

**v0.2 is a reliability and security review of the existing MVP.** See the [technical audit](docs/TECHNICAL_AUDIT_V02.md), [executed validation](docs/VALIDATION.md) and [real-world validation procedure/status](docs/REAL_WORLD_VALIDATION.md). No live domain validation has been performed: the developer has no authorized domain available. DMARC results explicitly use the legacy RFC 7489 profile; full current RFC 9989 support is deferred.

This is a configuration assessment, **not a penetration test, certification, compliance attestation or guarantee of security**. Assess only domains you own or have explicit authorization to review.

## What is included

- SPF discovery, multiple-record and common syntax checks, qualifier inspection, and a bounded static estimate of include/redirect lookup paths.
- Legacy RFC 7489 DMARC policy/percentage, reporting configuration and PSL-based inheritance. Current-standard np/psd/t markers remain inconclusive; this is not a complete RFC 9989 receiver implementation.
- DKIM queries for up to five **explicitly supplied** selectors. No selector guessing; unknown does not mean disabled.
- A/AAAA, NS, MX/null-MX and exact-name CAA observations.
- One verified TLS handshake: trust-chain acceptance, hostname, issuer, validity, expiration and negotiated protocol.
- HTTPS connectivity, bounded HTTP-to-HTTPS redirect checks and six browser security-header observations.
- Searchable/filterable findings with severity, status, timestamps, evidence and specific remediation.
- Local history, consecutive-assessment comparison, printable HTML and evidence-preserving JSON.
- An optional transparent Configuration Health score with visible evaluation coverage.
- A CLI, deterministic offline tests and GitHub Actions.

There are no paid APIs, accounts, payments, mandatory cloud services or hardcoded assessment results. Empty installations start with no assessments.

## Install on macOS

Use Python 3.12 or newer. Python 3.13 is the locally verified baseline; CI is configured for 3.12, 3.13 and 3.14.

```sh
brew install python@3.13
cd /path/to/Cybercheck
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
streamlit run streamlit_app.py
```

Open **http://127.0.0.1:8501**. If the virtual environment already exists, activate it and run the Streamlit command. The server binds to loopback and disables analytics by default. Stop it with `Ctrl+C`. Python 3.13 installation from a fresh temporary venv was executed for this release; see the validation record.

For development using supported dependency ranges instead of the tested version snapshot:

```sh
python -m pip install -e '.[dev,audit]'
```

`requirements.lock` includes development/security tools and exact resolved versions. It is a tested version snapshot, not a hash-verified supply-chain lock; CI uses it on its Python matrix. Streamlit's minimum is now 1.67, matching the API baseline actually tested. `pyproject.toml` defines supported ranges. No environment file is required. Optional shell settings are shown in [.env.example](.env.example); `.env` is not automatically loaded.

## Use the application

1. Open **Nuovo assessment / New Assessment**.
2. Enter a fully qualified domain, without scheme, path, credentials or port.
3. Optionally enter DKIM selectors obtained from the mail provider or a signed message.
4. Confirm ownership or explicit authorization, including related redirects within the organizational domain.
5. Start the assessment. Results are saved locally when complete.
6. Use the top navigation for overview, history, findings, reports and settings. Select Italian or English at the top right.
7. Download HTML or JSON. Open HTML in a browser to print or use its **Save as PDF** print destination. There is no native PDF renderer.

The assessment selector controls which saved run is shown. History compares the selected run with the immediately preceding run for that domain. Evidence changes are observations; they are not automatically security regressions. History is paginated, 25 assessments per page.

## CLI

Replace `your-owned-domain.tld` with an asset you are authorized to assess:

```sh
cybercheck your-owned-domain.tld --authorized --selectors selector1,selector2 --language en --output exports
```

The authorization flag is mandatory. Omit selectors if unknown. Add `--include-score` to include the optional health score in HTML. A completed assessment can contain unknown/error findings; the CLI prints counts and exports evidence, rather than treating network uncertainty as a confirmed vulnerability.

`cybercheck --version` prints the installed version. If history persistence fails after export, the CLI returns a nonzero exit status and explicitly reports that the HTML/JSON files are available. Export files are created owner-only and never overwrite an existing file or follow its symlink.

## Statuses and score

| Status | Meaning |
|---|---|
| Passed | The stated, limited check met its criterion. |
| Failed | Evidence confirms the stated configuration problem. |
| Warning | Contextual hardening, rollout or operational concern; review applicability. |
| Unknown | Insufficient evidence, blocked request or network failure. |
| Error | Unexpected local execution failure in a module. |
| Not applicable | The check does not apply to the observed content. |

Severity describes the potential consequence **of that observation**, not organization-wide risk. `p=none`, missing headers and optional CAA are not classified as critical. `-all` is not prescribed universally. DKIM key publication does not prove message signing, key cryptographic validity or alignment.

The optional score is **100 × passed / (passed + failed)** among explicitly scoreable checks. Warnings, unknowns, errors, inapplicable checks and informational presence-only checks are excluded. An empty denominator yields no score. The UI keeps the score off by default and always shows its coverage when enabled. A high score with low coverage or unscored warnings is incomplete information, **not a probability of avoiding compromise**. See [methodology](docs/METHODOLOGY.md).

## Local data and configuration

Results are stored in `data/cybercheck.sqlite3`, excluded from Git. New database/report files are created owner-only before content is written; final symlinks are refused. Parent directories are trusted local configuration. Future database schemas are rejected without downgrading their version. Unreadable assessments are preserved with a recovery message. Back up the database while the application is stopped. There is no retention scheduler or authentication layer in this local release.

New HTTP evidence retains only relevant header fields; cookies, arbitrary response headers, credentials, URL query values and fragments are omitted/redacted. Exports and UI also redact web evidence read from v0.1 history without rewriting the stored source. Paths, DNS and original v0.1 databases/reports can still be sensitive; do not commit or share raw customer artifacts. If a UI save fails, download the result or use **Retry saving results**, which does not rerun network checks.

| Variable | Default | Allowed range |
|---|---:|---|
| `CYBERCHECK_DB` | `data/cybercheck.sqlite3` | Local path |
| `CYBERCHECK_TIMEOUT` | 5 seconds | 0.1–15 seconds |
| `CYBERCHECK_MAX_DNS` | 48 | 8–100 queries |
| `CYBERCHECK_MAX_HTTP` | 8 | 2–20 requests |
| `CYBERCHECK_MAX_REDIRECTS` | 3 | 0–5 hops per chain |
| `CYBERCHECK_MAX_SECONDS` | 90 | 10–180 seconds |

Queries are sequential and bounded; DNS answers are cached per assessment. HTTP socket operations recheck the overall deadline and limit header reads to 64 KiB. Only one verified TLS handshake is attempted. Limits reset for each assessment; this is not a rate-limited public service.

## Security boundaries

- Public targets only. Localhost, IP-literal inputs, private, loopback, link-local, reserved, multicast, IPv6 zone identifiers and transition/special-purpose ranges are rejected. Special ranges are blocked consistently across supported Python versions, including conservative exclusion of a few special-purpose global exceptions.
- Every HTTP redirect is validated, including DNS resolution and port checks, before connection. Cross-organizational-domain redirects and HTTPS downgrades are blocked.
- All A/AAAA results must be public; partial DNS-family failures fail closed. Connections use a validated literal IP, with the original Host header and TLS SNI/hostname verification. No second hostname resolution can change the network destination.
- Proxy environment variables are ignored. No insecure certificate retry, GET body download, arbitrary shell command, user-defined port, exploitation, port scan or subdomain enumeration.
- The configured local recursive DNS resolver is trusted infrastructure and may itself be private. It is not chosen by target input. The tool does not claim DNSSEC authenticity.
- Authorization is a user declaration, not a verified ownership challenge. Outbound traffic originates on your machine.
- Keep the server on localhost. Public hosting requires authentication, per-user limits, ownership verification, egress isolation and a separate security review.

See [architecture](docs/ARCHITECTURE.md), [methodology](docs/METHODOLOGY.md) and [security policy](SECURITY.md).

## Test and verify

```sh
python -m pytest -q --cov=cybercheck --cov-report=term-missing
ruff check .
ruff format --check .
python -m pip check
pip-audit -r requirements.lock --no-deps --disable-pip --progress-spinner off
```

Tests prohibit outbound socket/DNS connections. They cover validation/SSRF, DNS failures, email policies, TLS verification, the real transport adapter through a memory backend, slow/oversized headers, redirects, cookie/token redaction, report escaping, schema preservation, stable history comparison, CLI output/save failures and Streamlit navigation/forms in both languages. Resource leaks fail the tests. GitHub Actions runs the locked environment on Python 3.12/3.13/3.14 plus an advisory-audit job; local execution does not establish remote CI status.

`pip check` verifies dependency compatibility; `pip-audit` performs a separate network-backed advisory lookup. A service outage is not a clean audit. The successful scan is a point-in-time result, not a guarantee against unknown vulnerabilities. See [developer verification](docs/DEVELOPMENT.md) for optional Chrome/print checks, which do not add a runtime browser or PDF dependency.

No live assessment of third-party domains is required for tests. The local application server can be checked without assessing a domain:

```sh
curl --fail http://127.0.0.1:8501/_stcore/health
```

See [the local validation record](docs/VALIDATION.md) for executed checks and the boundary between mocked verification and live assessment.

## Example output and screenshots

The following screenshot is from the real v0.2 dashboard using an isolated, **labeled synthetic fixture**. It is not a live domain assessment. [Mobile screenshot](docs/screenshots/v02-overview-mobile.png).

![CyberCheck v0.2 overview with labeled synthetic test data](docs/screenshots/v02-overview-desktop.png)

[Example HTML](docs/examples/assessment.html) and [example JSON](docs/examples/assessment.json) are **explicitly synthetic test fixtures, not live observations**. TLS is deliberately unavailable in the fixture; no certificate is fabricated. They are generated offline through the real engine and report renderers:

```sh
python scripts/generate_examples.py
```

For README/product screenshots, start the app, use your own authorized domain, hide sensitive record values as appropriate, and capture Overview, Findings and Reports at desktop width and one mobile width. Store reviewed images under `docs/screenshots/` and add relative image links here. Label synthetic screenshots if test fixtures are ever used; do not present them as customer evidence. Screenshots are not generated from an unauthorized live assessment.

## License and commercial direction

The public project uses **AGPL-3.0-or-later**, unchanged in v0.2. It encourages contribution of covered modifications, including the source offer for modified versions used over a network. It **does not prevent competitors from hosting, distributing or selling compliant copies**. MIT would be a different, permissive licensing choice requiring the maintainer's approval and the necessary rights; this audit does not relicense anything. See the [licensing considerations](docs/LICENSING.md) and [official AGPL text](https://www.gnu.org/licenses/agpl-3.0.html).

The complete community assessment engine remains usable. Future paid value can come from monitoring, operational workflows, managed hosting, support and branding. No paid feature, payment service or multi-tenant architecture is implemented. See [roadmap and commercial validation](docs/ROADMAP.md).

The repository is public at [LucaTortoriello/CyberCheck](https://github.com/LucaTortoriello/CyberCheck). Installing or running it does not provision a cloud or paid service. Feature branches and draft pull requests are separate from approving a release or deploying an application.
