"""Ingest scenario fixture events into Splunk via HEC."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "00000000-0000-0000-0000-000000000000")
SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"

# Splunk needs a moment after HEC ingest before events are searchable
POST_INGEST_SETTLE_SECONDS = 3


def post_event(session: requests.Session, payload: dict[str, Any]) -> None:
    response = session.post(HEC_URL, json=payload, timeout=10)
    response.raise_for_status()


def main() -> int:
    if not SCENARIOS.exists():
        print(f"No scenarios directory at {SCENARIOS}")
        return 0

    session = requests.Session()
    session.headers["Authorization"] = f"Splunk {HEC_TOKEN}"
    session.verify = False

    count = 0
    for scenario in sorted(SCENARIOS.iterdir()):
        if not scenario.is_dir():
            continue
        fixtures_dir = scenario / "fixtures"
        if not fixtures_dir.exists():
            continue
        for fixture in sorted(fixtures_dir.glob("*.jsonl")):
            index = fixture.stem
            for raw in fixture.read_text().splitlines():
                line = raw.strip()
                if not line:
                    continue
                event = json.loads(line)
                payload: dict[str, Any] = {
                    "event": event,
                    "index": index,
                    "sourcetype": event.pop("_sourcetype", "_json"),
                }
                if "_time" in event:
                    payload["time"] = event.pop("_time")
                post_event(session, payload)
                count += 1

    print(f"Ingested {count} events")
    if count:
        time.sleep(POST_INGEST_SETTLE_SECONDS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
