# Installation and developer verification

## Reproducible local baseline

Use Python 3.13 on macOS (3.12+ in project metadata), an empty virtual environment and the committed lock:

```sh
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
python -m pip check
cybercheck --version
streamlit run streamlit_app.py
```

The lock pins runtime, test and advisory tools. It is a reviewed version snapshot, not a hash-verified lock or a guarantee about PyPI artifacts. Clean installation was executed for v0.2 on macOS; CI separately exercises Linux/Python versions. Packaging/bootstrap tools are outside the advisory lock's scope. Streamlit's minimum now matches the tested 1.67 API, instead of claiming the older 1.45 width API supports the same calls.

No `.env` loader is implicit. Export the optional variables in `.env.example` in the shell that launches the app. Invalid numeric settings produce a configuration-specific message. Database path/permission/schema errors produce a storage-specific message and preserve existing data. Select a separate `CYBERCHECK_DB` for experiments; do not delete user history as a repair step.

## Quality gates

```sh
ruff check .
ruff format --check .
python -m pytest -q --cov=cybercheck --cov-report=term-missing
python -m pip check
pip-audit -r requirements.lock --no-deps --disable-pip --progress-spinner off
```

The advisory command requires network access and must return success; a timeout is not an audit pass. It audits all pinned entries without resolving a different graph. Tests block outbound sockets/DNS and treat resource leaks/unraisable exceptions as errors. The transport contract suite exercises the real HTTPX/httpcore adapter through public memory-backend interfaces, not only HTTPX MockTransport.

For intentional updates, resolve `python -m pip install -e '.[dev,audit]'` in an otherwise clean environment, review versions, regenerate `python -m pip freeze --exclude cybercheck > requirements.lock`, run the gates and verify another empty venv. Avoid capturing unrelated tools in the lock.

## Synthetic examples and optional browser review

`python scripts/generate_examples.py` uses the real engine/renderer with network mocks and labels outputs as synthetic. It does not seed the ordinary database. Examples are not evidence about example.com and contain no invented certificate.

Use a separate developer-only Playwright environment and an installed Chrome. This is not a runtime or PDF dependency:

```sh
python3.13 -m venv /tmp/cybercheck-browser-tools
/tmp/cybercheck-browser-tools/bin/python -m pip install playwright
```

Load a fixture into an isolated preview database:

```sh
python scripts/generate_examples.py
python - <<'PY'
import json
from pathlib import Path
from cybercheck.models import Assessment
from cybercheck.storage.sqlite import Repository
assessment = Assessment.from_dict(json.loads(Path('docs/examples/assessment.json').read_text()))
Repository('/tmp/cybercheck-preview.sqlite3').save(assessment)
PY
CYBERCHECK_DB=/tmp/cybercheck-preview.sqlite3 streamlit run streamlit_app.py --server.port 8502
```

In another terminal, run `/tmp/cybercheck-browser-tools/bin/python scripts/browser_smoke.py`. It connects only to the localhost preview, never starts an assessment, switches Italian/English, visits all navigation views, checks desktop/mobile overflow, captures screenshots and prints the synthetic report to PDF using Chrome. Artifacts default to `/tmp/cybercheck-v02-browser`. Inspect the screenshots/PDF; automation is not a complete accessibility or cross-browser audit. Keep synthetic labels visible in shared screenshots. Stop the isolated preview when done.

## Docker decision

No Docker image is added in v0.2. The CLI is available on the development machine, but no daemon or image build was required or verified. Docker could standardize Linux packaging, yet Docker Desktop adds a VM and DNS/CA/routing differences precisely where this tool needs transparent evidence. The tested venv route is simpler for the current macOS workflow. Reconsider a small non-root localhost-bound image only when pilots request it, and verify egress/trust independently.

## Review workflow

Use `improvement/cybercheck-v0.2`, focused commits and a review pull request. No force-push, automatic merge, license/visibility change, hosted deployment, release publication or paid service is part of verification. Preserve schema-version-1 history/source evidence; introduce explicit migrations when needed.
