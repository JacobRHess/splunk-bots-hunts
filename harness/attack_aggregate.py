"""Aggregate ATT&CK technique coverage across scenarios into a markdown table."""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "attack-coverage.md"


def main() -> int:
    names: dict[str, str] = {}
    scenarios: dict[str, list[str]] = defaultdict(list)

    if SCENARIOS.exists():
        for scenario in sorted(SCENARIOS.iterdir()):
            if not scenario.is_dir():
                continue
            attack_file = scenario / "attack.yaml"
            if not attack_file.exists():
                continue
            with attack_file.open() as f:
                data = yaml.safe_load(f) or {}
            for technique in data.get("techniques", []):
                tid = technique.get("id")
                if not tid:
                    continue
                names[tid] = technique.get("name", "")
                scenarios[tid].append(scenario.name)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# ATT&CK coverage",
        "",
        f"Techniques covered: **{len(names)}**",
        "",
        "| Technique | Name | Scenarios |",
        "|---|---|---|",
    ]
    for tid in sorted(names):
        scenarios_cell = ", ".join(scenarios[tid])
        lines.append(f"| {tid} | {names[tid]} | {scenarios_cell} |")
    OUTPUT.write_text("\n".join(lines) + "\n")
    print(f"Wrote {OUTPUT} ({len(names)} techniques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
