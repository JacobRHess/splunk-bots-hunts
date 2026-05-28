# splunk-bots-hunts

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

The full ~10GB BOTSv3 dataset stays out of git. Fixtures committed alongside each hunt are tiny event slices, just enough to exercise the SPL in CI.

## Local development

Prereqs: Docker Desktop, Python 3.13, [uv](https://github.com/astral-sh/uv).

```powershell
uv sync
docker compose -f docker/compose.yml up -d
```

Splunk Web is at <http://localhost:8000> (admin / `changeme` unless you set `SPLUNK_PASSWORD`). The first time, install the BOTSv3 app via Manage Apps → Install from file. Get the bundle from <https://github.com/splunk/botsv3>.

Run all documented hunts against the running Splunk:

```powershell
uv run python harness/run_hunts.py
```

Generate the ATT&CK coverage page from per-scenario `attack.yaml` files:

```powershell
uv run python harness/attack_aggregate.py
```

## CI

`.github/workflows/hunts.yml` runs on every PR:

1. Boot Splunk in Docker
2. Wait for `:8089` to become healthy
3. Ingest each scenario's fixtures via HEC
4. Run every hunt's SPL, assert each answer
5. `ruff check`

## Status

Early. Scaffold is in, first scenario is in progress.
