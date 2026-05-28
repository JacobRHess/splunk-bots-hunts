# splunk-bots-hunts

[![hunts](https://github.com/JacobRHess/splunk-bots-hunts/actions/workflows/hunts.yml/badge.svg)](https://github.com/JacobRHess/splunk-bots-hunts/actions/workflows/hunts.yml)
[![codeql](https://github.com/JacobRHess/splunk-bots-hunts/actions/workflows/codeql.yml/badge.svg)](https://github.com/JacobRHess/splunk-bots-hunts/actions/workflows/codeql.yml)
[![python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)
[![license MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Threat hunting walkthroughs for Splunk's *Boss of the SOC v3* dataset.

Every hunt in this repo is a documented investigation: the question, the SPL that answers it, the pivots that got me there, and the ATT&CK techniques touched. CI spins up a Splunk container, ingests fixture events over HEC, runs each hunt's SPL via the REST API, and asserts the expected answer, so the hunts can't silently rot when the SPL syntax changes or a field gets renamed.

## Why hunts and not detections

A detection answers "did this happen?" A hunt answers "what happened?" This repo is a portfolio of the second. Each scenario is a write-up of how I worked through a piece of the BOTSv3 intrusion, not a rule I would deploy to a SIEM.

## Repo layout

```
scenarios/<id>-<slug>/
├── README.md           narrative write-up
├── hunts/*.spl         one SPL per documented hunt
├── dashboards/*.xml    Splunk dashboard XML
├── fixtures/*.jsonl    fixture event slice per index (for CI)
├── answers.yaml        { hunts: [{ file, question, expected, field }] }
└── attack.yaml         { techniques: [{ id, name }] }
```

The full BOTSv3 dataset stays out of git. Fixtures committed alongside each hunt are tiny event slices, just enough to exercise the SPL in CI.

## Local development

Prereqs: Docker Desktop (or native Splunk), Python 3.13, [uv](https://github.com/astral-sh/uv).

```powershell
uv sync
docker compose -f docker/compose.yml up -d
```

Splunk Web is at <http://localhost:8000>. The dev admin password is `changeme` (set `SPLUNK_PASSWORD` env to override). The first time, install the BOTSv3 app via Manage Apps → Install from file; the bundle lives at <https://github.com/splunk/botsv3>.

Run all documented hunts against the running Splunk:

```powershell
uv run python harness/run_hunts.py
```

Generate the ATT&CK coverage page from per-scenario `attack.yaml` files:

```powershell
uv run python harness/attack_aggregate.py
```

## CI

Two workflows, both on push and PR:

`hunts.yml` runs in two jobs:

- **lint** (~1 min): ruff, mypy strict, bandit security linting, pytest with coverage gate (50% minimum on pure-Python paths), pip-audit against the resolved lockfile.
- **validate** (~3 min, runs after lint passes): boots Splunk in Docker, ingests every scenario's fixtures via HEC, runs every hunt's SPL via REST, asserts each answer.

`codeql.yml` runs CodeQL static analysis for Python on push, PR, and weekly.

All third-party actions are SHA-pinned. Workflows declare least-privilege `permissions:` blocks. Concurrency groups cancel in-progress runs when a branch is updated.

## Security notes

- Credentials in the repo are dev-only: `changeme`/`Chang3me!` passwords, fixed HEC token `00000000-...`. Never reuse them outside CI or a local sandbox.
- The Python harness disables TLS verification (`verify=False`) because the Splunk Docker image presents a self-signed cert on its mgmt and HEC endpoints. Bandit's `B501` warning is suppressed for this reason and the suppression is scoped via `pyproject.toml`.
- Coverage on the HTTP-IO functions is excluded via `pragma: no cover`; those paths are exercised end-to-end by the `validate` CI job against a real Splunk container, not unit-tested with mocks.
- `pip-audit --strict` runs on every PR. Vulnerability findings break the build.
- Hunt fixtures are slices of BOTSv3 public data. Nothing in the repo contains real customer or production telemetry.

## Status

Two scenarios shipped. Adding more as the dataset gets worked through.
