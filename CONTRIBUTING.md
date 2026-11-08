# Contributing

Set up Python 3.12+ and install `python -m pip install -e '.[dev]'` in a virtual environment. Python 3.13 is the local baseline.

Before proposing changes:

```sh
ruff check .
ruff format --check .
python -m pytest -q --cov=cybercheck --cov-report=term-missing
python -m pip check
```

Keep network checks separate from Streamlit and report rendering. New findings need stable check IDs, meaningful evidence, bilingual explanations, specific remediation and honest uncertainty. Add deterministic tests for meaningful behavior and failure cases. Never turn lookup failures into confirmed misconfigurations, weaken certificate verification, introduce shell execution for target input, bypass public-address validation or make automatic selector/subdomain guesses.

Tests must stay offline. The global pytest fixture blocks DNS resolution and outbound sockets; use injected DNS results, HTTPX MockTransport, httpcore MockBackend or explicit TLS mocks. Do not run assessments against third-party domains to test a change. Obtain explicit authorization for live targets.

Reports and logs can expose infrastructure details. Remove personal information, credentials and customer evidence from issues, fixtures and screenshots. Mark synthetic outputs clearly. Update English public documentation and both UI languages for user-visible changes.

The community recommendation is AGPL-3.0-or-later. Contributions retain their respective copyright; no assignment or dual-license permission is assumed. Raise licensing questions before submitting code with incompatible terms.

For vulnerability reports, follow [SECURITY.md](SECURITY.md). The repository is prepared locally; release, publication, hosting and paid integrations require the owner's explicit approval.
