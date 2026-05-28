"""Run documented hunts against Splunk and assert expected answers."""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "https://localhost:8089")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "changeme")
SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
SID_RE = re.compile(r"<sid>(.+?)</sid>")
SEARCH_TIMEOUT_SECONDS = 120


def run_search(spl: str) -> list[dict[str, Any]]:  # pragma: no cover
    session = requests.Session()
    session.auth = (SPLUNK_USER, SPLUNK_PASSWORD)
    session.verify = False

    query = spl.strip()
    if not (query.startswith("search") or query.startswith("|")):
        query = f"search {query}"

    create = session.post(
        f"{SPLUNK_HOST}/services/search/jobs",
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
            f"{SPLUNK_HOST}/services/search/jobs/{sid}",
            params={"output_mode": "json"},
            timeout=10,
        ).json()
        if status["entry"][0]["content"]["isDone"]:
            break
        time.sleep(1)

    results = session.get(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": "0"},
        timeout=30,
    ).json()
    return list(results.get("results", []))


def _extract_answer(results: list[dict[str, Any]], field: str | None) -> Any:
    if not results:
        return None
    if field:
        return results[0].get(field)
    return results[0]


def main() -> int:  # pragma: no cover
    if not SCENARIOS.exists():
        print(f"No scenarios directory at {SCENARIOS}")
        return 0

    failures: list[str] = []
    passes = 0
    for scenario in sorted(SCENARIOS.iterdir()):
        if not scenario.is_dir():
            continue
        answers_file = scenario / "answers.yaml"
        if not answers_file.exists():
            continue
        with answers_file.open() as f:
            answers = yaml.safe_load(f) or {}
        for hunt in answers.get("hunts", []):
            spl_path = scenario / "hunts" / hunt["file"]
            if not spl_path.exists():
                failures.append(f"{scenario.name}/{hunt['file']}: missing SPL file")
                continue
            spl = spl_path.read_text()
            results = run_search(spl)
            actual = _extract_answer(results, hunt.get("field"))
            expected = hunt["expected"]
            if str(actual) != str(expected):
                failures.append(
                    f"{scenario.name}/{hunt['file']}: expected {expected!r}, got {actual!r}"
                )
            else:
                passes += 1
                print(f"PASS  {scenario.name}/{hunt['file']}")

    print(f"\n{passes} passed, {len(failures)} failed")
    if failures:
        print("FAILURES:")
        for failure in failures:
            print(f"  {failure}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
