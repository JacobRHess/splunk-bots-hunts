"""Extract Splunk search results as a JSONL fixture for CI hunt validation.

Each output line is one event: the original `_raw` JSON merged with `_sourcetype`
and `_time` keys that `harness/ingest_fixtures.py` strips into HEC payload params.

Usage:
    uv run python tools/extract_fixture.py \\
        --spl 'search index=botsv3 sourcetype=aws:cloudtrail ...' \\
        --sourcetype aws:cloudtrail \\
        --output scenarios/01-aws-recon-bstoll/fixtures/main.jsonl
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SID_RE = re.compile(r"<sid>(.+?)</sid>")
SEARCH_TIMEOUT_SECONDS = 180


def run_search(  # pragma: no cover
    host: str, user: str, password: str, spl: str
) -> list[dict[str, Any]]:
    session = requests.Session()
    session.auth = (user, password)
    session.verify = False

    query = spl.strip()
    if not (query.startswith("search") or query.startswith("|")):
        query = f"search {query}"

    create = session.post(
        f"{host}/services/search/jobs",
        data={"search": query},
        timeout=30,
    )
    create.raise_for_status()
    match = SID_RE.search(create.text)
    if not match:
        raise RuntimeError(f"No sid in response: {create.text}")
    sid = match.group(1)

    deadline = time.monotonic() + SEARCH_TIMEOUT_SECONDS
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError(f"Search {sid} did not complete within {SEARCH_TIMEOUT_SECONDS}s")
        status = session.get(
            f"{host}/services/search/jobs/{sid}",
            params={"output_mode": "json"},
            timeout=10,
        ).json()
        if status["entry"][0]["content"]["isDone"]:
            break
        time.sleep(1)

    results = session.get(
        f"{host}/services/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": "0"},
        timeout=60,
    ).json()
    return list(results.get("results", []))


def main() -> int:  # pragma: no cover
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spl", required=True, help="SPL search (must return _raw + _time)")
    parser.add_argument(
        "--sourcetype", required=True, help="Sourcetype to label fixture events with"
    )
    parser.add_argument("--output", required=True, type=Path, help="Output JSONL path")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Emit fixture lines as raw events (for WinEventLog, syslog, Sysmon XML)",
    )
    parser.add_argument("--host", default=os.environ.get("SPLUNK_HOST", "https://localhost:8089"))
    parser.add_argument("--user", default=os.environ.get("SPLUNK_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("SPLUNK_PASSWORD", "changeme"))
    args = parser.parse_args()

    results = run_search(args.host, args.user, args.password, args.spl)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with args.output.open("w", encoding="utf-8") as f:
        for row in results:
            event = build_fixture_event(row, args.sourcetype, raw_mode=args.raw)
            if event is None:
                continue
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
            written += 1

    print(f"Wrote {written} events to {args.output}")
    return 0


def build_fixture_event(
    row: dict[str, Any], sourcetype: str, *, raw_mode: bool
) -> dict[str, Any] | None:
    """Turn one Splunk search row into a fixture event dict (or None to skip)."""
    raw = row.get("_raw")
    if not raw:
        return None
    if raw_mode:
        event: dict[str, Any] = {"_raw": raw, "_sourcetype": sourcetype}
    else:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        event = parsed
        event["_sourcetype"] = sourcetype
    t = row.get("_time")
    if t is not None:
        with contextlib.suppress(TypeError, ValueError):
            event["_time"] = int(float(t))
    host = row.get("host")
    if host:
        event["_host"] = host
    source = row.get("source")
    if source:
        event["_source"] = source
    return event


if __name__ == "__main__":
    sys.exit(main())
