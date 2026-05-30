"""Generate a MITRE ATT&CK Navigator layer from the per-scenario attack.yaml.

Output (docs/attack-navigator-layer.json) can be uploaded directly to
https://mitre-attack.github.io/attack-navigator/ ("Open Existing Layer"). Each
technique is scored by how many scenarios touch it and commented with which.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from harness import iter_scenarios, load_yaml

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "attack-navigator-layer.json"
GRADIENT = ["#dbeafe", "#58a6ff", "#1f6feb"]


def collect_coverage(scenarios_dir: Path) -> dict[str, list[str]]:
    """Map ATT&CK technique id -> sorted list of scenario slugs that cover it."""
    coverage: dict[str, list[str]] = {}
    for path in iter_scenarios(scenarios_dir):
        data = load_yaml(path / "attack.yaml")
        for technique in data.get("techniques", []):
            tid = technique.get("id")
            if tid:
                coverage.setdefault(tid, [])
                if path.name not in coverage[tid]:
                    coverage[tid].append(path.name)
    return {tid: sorted(scn) for tid, scn in coverage.items()}


def build_layer(coverage: dict[str, list[str]]) -> dict[str, object]:
    techniques = [
        {
            "techniqueID": tid,
            "score": len(scenarios),
            "comment": "covered by " + ", ".join(scenarios),
            "enabled": True,
        }
        for tid, scenarios in sorted(coverage.items())
    ]
    max_score = max((len(s) for s in coverage.values()), default=1)
    return {
        "name": "splunk-bots-hunts coverage",
        "versions": {"attack": "16", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques exercised by the splunk-bots-hunts scenarios over BOTS v3.",
        "techniques": techniques,
        "gradient": {"colors": GRADIENT, "minValue": 0, "maxValue": max_score},
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#161b22",
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def main() -> int:  # pragma: no cover
    coverage = collect_coverage(SCENARIOS)
    layer = build_layer(coverage)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT} ({len(coverage)} techniques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
