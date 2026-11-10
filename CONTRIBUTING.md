# Contributing

Set up Python 3.12+ in a virtual environment, install `python -m pip install -r requirements.lock`, then `python -m pip install --no-deps -e .`. Python 3.13 is the local baseline. To intentionally resolve supported ranges instead, use `python -m pip install -e '.[dev,audit]'` and review the resulting lock changes.

Before proposing changes:

```sh
ruff check .
ruff format --check .
python -m pytest -q --cov=cybercheck --cov-report=term-missing
python -m pip check
pip-audit -r requirements.lock --no-deps --disable-pip --progress-spinner off
```

Keep network checks separate from Streamlit and report rendering. New findings need stable check IDs, meaningful evidence, bilingual explanations, specific remediation and honest uncertainty. Add deterministic tests for meaningful behavior and failure cases. Never turn lookup failures into confirmed misconfigurations, weaken certificate verification, introduce shell execution for target input, bypass public-address validation or make automatic selector/subdomain guesses.

Tests must stay offline. The global pytest fixture blocks DNS resolution and outbound sockets; use injected DNS results, HTTPX MockTransport, httpcore MockBackend or explicit TLS mocks. Do not run assessments against third-party domains to test a change. Obtain explicit authorization for live targets.

Reports and logs can expose infrastructure details. Remove personal information, credentials and customer evidence from issues, fixtures and screenshots. Mark synthetic outputs clearly. Update English public documentation and both UI languages for user-visible changes.

The community recommendation is AGPL-3.0-or-later. Contributions retain their respective copyright; no assignment or dual-license permission is assumed. Raise licensing questions before submitting code with incompatible terms.

For vulnerability reports, follow [SECURITY.md](SECURITY.md). The public repository uses feature branches and pull requests for review. Do not force-push, merge into main, change licensing/visibility, deploy an app, publish a release or provision paid integrations without the maintainer's explicit approval. See [developer verification](docs/DEVELOPMENT.md).
