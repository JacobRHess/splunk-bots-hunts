"""Run the deployable detections against ingested fixtures and assert behaviour.

Each detection declares ``fixture_expect: fires`` (should return at least one
result on the fixture slice) or ``silent`` (should return none, a true-negative
on benign data). This is the detection-engineering counterpart to run_hunts:
hunts assert an answer, detections assert fire/no-fire. Run after fixtures are
ingested into the Docker Splunk.
"""
from __future__ import annotations

import sys
from pathlib import Path

from harness import iter_scenarios, load_yaml
from harness.run_hunts import SEARCH_ERRORS, run_search

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
# The fixture slice carries 2018 timestamps (or none); query the full window.
FIXTURE_EARLIEST = "0"


def _expectation_met(row_count: int, expect: str) -> bool:
    if expect == "fires":
        return row_count >= 1
    if expect == "silent":
        return row_count == 0
    raise ValueError(f"unknown fixture_expect: {expect!r}")


def main() -> int:  # pragma: no cover
    if not SCENARIOS.exists():
        print(f"No scenarios directory at {SCENARIOS}")
        return 0

    failures: list[str] = []
    passes = 0
    for scenario in iter_scenarios(SCENARIOS):
        data = load_yaml(scenario / "detections.yaml")
        for det in data.get("detections", []):
            name = det.get("id") or det.get("name", "?")
            expect = det.get("fixture_expect", "fires")
            try:
                rows = run_search(det["search"], earliest=FIXTURE_EARLIEST, latest="now")
            except SEARCH_ERRORS as exc:
                failures.append(f"{scenario.name}/{name}: search error: {exc}")
                continue
            if _expectation_met(len(rows), expect):
                passes += 1
                print(f"PASS  {scenario.name}/{name}  ({expect}, {len(rows)} rows)")
            else:
                failures.append(
                    f"{scenario.name}/{name}: expected {expect}, got {len(rows)} rows"
                )

    print(f"\n{passes} passed, {len(failures)} failed")
    if failures:
        print("FAILURES:")
        for failure in failures:
            print(f"  {failure}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
