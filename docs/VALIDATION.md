# Local validation record

Executed on 2026-11-08, on macOS with Python 3.13.14 in the project `.venv`.

| Check | Observed result |
|---|---|
| `python -m pytest -q --cov=cybercheck --cov-report=term-missing` | **119 passed**, 93% statement coverage. No failed tests in the final run. |
| `ruff check .` | Passed. |
| `ruff format --check .` | Passed; 43 Python files checked. |
| `python -m pip check` | No broken requirements found. |
| `cybercheck --help` | CLI entry point displayed expected options. |
| `python scripts/generate_examples.py` | Produced clearly labeled synthetic HTML/JSON using mocked network responses. |
| `streamlit run streamlit_app.py --server.headless true` | Server started on `127.0.0.1:8501`. |
| `GET /_stcore/health` on the local server | Returned `ok`. |
| `GET /` on the local server | Returned HTTP 200. |

Tests include domain/selector validation, private/reserved destinations, mixed-family fail-closed DNS, IP pinning with original Host/SNI, redirect rebinding, private-suffix tenant isolation, port/scope/downgrade blocking, HTTP budgets and deadline/header caps, DNS failures, SPF/DMARC/DKIM cases, specific certificate verification errors, header applicability, report escaping, SQLite round trips, history comparison, CLI output, authorization declaration, and Streamlit assessment/navigation/filter/export behavior in both languages.

The initial test run found a logging-field collision on unexpected module failure, an incorrect expected fixture count and an AppTest path assumption. These were corrected. Additional review corrected history picker synchronization and persisted scoring preference state. Regression tests exercise these paths.

No live domain assessment was performed: no owned or specifically authorized live domain was supplied. Tests use injected resolvers, HTTPX/httpcore mocks and TLS mocks, with outbound sockets and real DNS blocked. Example outputs do not represent real findings about example.com; they carry an explicit synthetic-fixture notice and do not fabricate a certificate.

The local HTTP health check verifies the server; AppTest exercises UI execution and interaction. No browser screenshot/visual review, remote CI run, hosted deployment or third-party vulnerability audit is claimed. GitHub Actions is prepared for Python 3.12/3.13/3.14 and must be observed after the owner approves publication.

Before a customer pilot, assess an explicitly authorized domain and have the domain's mail/hosting administrator verify the observed configuration and remediation relevance. See [commercial validation](ROADMAP.md).
