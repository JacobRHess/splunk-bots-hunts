"""Tests for the ATT&CK Navigator layer generator."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from harness import build_attack_layer
from harness.build_attack_layer import build_layer, collect_coverage


def _write_attack(scenario_dir: Path, techniques: list[dict[str, str]]) -> None:
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "attack.yaml").write_text(yaml.safe_dump({"techniques": techniques}))


def test_collect_coverage_dedups_and_sorts(tmp_path: Path) -> None:
    scenarios = tmp_path / "scenarios"
    _write_attack(scenarios / "01-a", [{"id": "T1059", "name": "PowerShell"}])
    _write_attack(scenarios / "02-b", [{"id": "T1059", "name": "PowerShell"}])
    _write_attack(scenarios / "03-c", [{"id": "T1496", "name": "Resource Hijacking"}])
    coverage = collect_coverage(scenarios)
    assert coverage["T1059"] == ["01-a", "02-b"]
    assert coverage["T1496"] == ["03-c"]


def test_build_layer_scores_and_gradient() -> None:
    layer = build_layer({"T1059": ["01-a", "02-b"], "T1496": ["03-c"]})
    assert layer["domain"] == "enterprise-attack"
    techniques = {t["techniqueID"]: t for t in layer["techniques"]}
    assert techniques["T1059"]["score"] == 2
    assert techniques["T1496"]["score"] == 1
    assert "01-a" in techniques["T1059"]["comment"]
    assert layer["gradient"]["maxValue"] == 2


def test_build_layer_empty() -> None:
    layer = build_layer({})
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1


def test_committed_layer_is_up_to_date() -> None:
    expected = build_layer(collect_coverage(build_attack_layer.SCENARIOS))
    actual = json.loads(build_attack_layer.OUTPUT.read_text(encoding="utf-8"))
    assert actual == expected, "docs/attack-navigator-layer.json is stale - regenerate it"
