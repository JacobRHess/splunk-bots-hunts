"""Tests for the ATT&CK aggregator markdown generator."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from harness import attack_aggregate


def _write_attack_yaml(scenario_dir: Path, techniques: list[dict[str, str]]) -> None:
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "attack.yaml").write_text(yaml.safe_dump({"techniques": techniques}))


def test_aggregate_writes_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scenarios = tmp_path / "scenarios"
    _write_attack_yaml(
        scenarios / "01-test",
        [
            {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
            {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
        ],
    )
    output = tmp_path / "docs" / "attack-coverage.md"

    monkeypatch.setattr(attack_aggregate, "SCENARIOS", scenarios)
    monkeypatch.setattr(attack_aggregate, "OUTPUT", output)

    assert attack_aggregate.main() == 0

    text = output.read_text()
    assert "Techniques covered: **2**" in text
    assert "T1078.004" in text
    assert "Cloud Infrastructure Discovery" in text
    assert "01-test" in text


def test_aggregate_empty_scenarios(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(attack_aggregate, "SCENARIOS", tmp_path / "scenarios")
    monkeypatch.setattr(attack_aggregate, "OUTPUT", tmp_path / "out.md")

    assert attack_aggregate.main() == 0
    assert "Techniques covered: **0**" in (tmp_path / "out.md").read_text()


def test_aggregate_dedups_techniques_across_scenarios(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenarios = tmp_path / "scenarios"
    _write_attack_yaml(scenarios / "01-a", [{"id": "T1078", "name": "Valid Accounts"}])
    _write_attack_yaml(scenarios / "02-b", [{"id": "T1580", "name": "Cloud Discovery"}])
    _write_attack_yaml(scenarios / "03-c", [{"id": "T1078", "name": "Valid Accounts"}])
    output = tmp_path / "out.md"

    monkeypatch.setattr(attack_aggregate, "SCENARIOS", scenarios)
    monkeypatch.setattr(attack_aggregate, "OUTPUT", output)

    assert attack_aggregate.main() == 0
    text = output.read_text()
    assert "Techniques covered: **2**" in text
    assert "01-a, 03-c" in text
    assert "02-b" in text


def test_aggregate_skips_scenario_without_attack_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenarios = tmp_path / "scenarios"
    (scenarios / "01-skip-me").mkdir(parents=True)
    _write_attack_yaml(scenarios / "02-keep", [{"id": "T9999", "name": "X"}])
    output = tmp_path / "out.md"

    monkeypatch.setattr(attack_aggregate, "SCENARIOS", scenarios)
    monkeypatch.setattr(attack_aggregate, "OUTPUT", output)

    assert attack_aggregate.main() == 0
    text = output.read_text()
    assert "Techniques covered: **1**" in text
    assert "02-keep" in text
    assert "01-skip-me" not in text
