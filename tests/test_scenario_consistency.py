"""Consistency guards over the real scenarios/ tree.

These catch drift that unit tests on the harness can't: an answer pointing at a
missing SPL, a hunt with no answer, an answers `field` that the SPL never
projects, a hunt querying a sourcetype no fixture provides, or a README answer
table that disagrees with answers.yaml. Drift here means CI lied about a hunt.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"

SCENARIO_DIRS = sorted(p for p in SCENARIOS.iterdir() if p.is_dir()) if SCENARIOS.exists() else []
SCENARIO_IDS = [p.name for p in SCENARIO_DIRS]


def _answers(scenario: Path) -> list[dict[str, str]]:
    data = yaml.safe_load((scenario / "answers.yaml").read_text()) or {}
    hunts: list[dict[str, str]] = data.get("hunts", [])
    return hunts


def _norm_question(text: str) -> str:
    """Compare question strings ignoring markdown code spans and whitespace."""
    return re.sub(r"\s+", " ", text.replace("`", "").replace("*", "")).strip().lower()


def test_scenarios_exist() -> None:
    # Guards the parametrized tests below: an empty tree would silently collect zero cases.
    assert SCENARIO_DIRS, "no scenarios found"


def test_top_readme_scenario_count_matches() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7}
    m = re.search(r"\b(\w+) scenarios shipped\b", readme, re.IGNORECASE)
    assert m, "top-level README has no 'N scenarios shipped' status line"
    stated = words.get(m.group(1).lower())
    assert stated == len(SCENARIO_DIRS), (
        f"README says '{m.group(1)} scenarios shipped' but there are {len(SCENARIO_DIRS)}"
    )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_answers_and_hunts_are_a_bijection(scenario: Path) -> None:
    answer_files = {h["file"] for h in _answers(scenario)}
    spl_files = {p.name for p in (scenario / "hunts").glob("*.spl")}
    assert answer_files == spl_files, (
        f"{scenario.name}: answers.yaml and hunts/ disagree "
        f"(only in answers: {answer_files - spl_files}, only on disk: {spl_files - answer_files})"
    )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_each_hunt_projects_its_answer_field(scenario: Path) -> None:
    for hunt in _answers(scenario):
        field = hunt.get("field")
        if not field:
            continue
        spl = (scenario / "hunts" / hunt["file"]).read_text()
        assert re.search(rf"fields {re.escape(field)}\b", spl), (
            f"{scenario.name}/{hunt['file']}: answer field '{field}' is never projected "
            f"with `| fields {field}`"
        )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_hunt_sourcetypes_exist_in_fixtures(scenario: Path) -> None:
    fixture = scenario / "fixtures" / "main.jsonl"
    sourcetypes = {
        json.loads(line).get("_sourcetype")
        for line in fixture.read_text().splitlines()
        if line.strip()
    }
    for hunt in _answers(scenario):
        spl = (scenario / "hunts" / hunt["file"]).read_text()
        for match in re.findall(r"sourcetype=(\S+)", spl):
            assert match in sourcetypes, (
                f"{scenario.name}/{hunt['file']}: queries sourcetype '{match}' "
                f"but no fixture event provides it (have: {sorted(sourcetypes)})"
            )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_readme_answer_table_matches_answers_yaml(scenario: Path) -> None:
    readme = (scenario / "README.md").read_text(encoding="utf-8")
    for hunt in _answers(scenario):
        # The README hunt table cites each SPL file in a `code` span on its row;
        # the expected answer must appear (also in a code span) on that same row.
        row = next((ln for ln in readme.splitlines() if hunt["file"] in ln and "|" in ln), None)
        assert row is not None, f"{scenario.name}: {hunt['file']} not referenced in README table"
        assert f"`{hunt['expected']}`" in row, (
            f"{scenario.name}/{hunt['file']}: README row answer disagrees with "
            f"answers.yaml expected '{hunt['expected']}'\n  row: {row}"
        )
        # The README question cell must match answers.yaml (the CI source of truth),
        # ignoring markdown code spans and whitespace. Cell layout: | # | file | question | answer |
        cells = [c.strip() for c in row.split("|")]
        question_cell = cells[3] if len(cells) > 4 else ""
        assert _norm_question(question_cell) == _norm_question(hunt["question"]), (
            f"{scenario.name}/{hunt['file']}: README question text disagrees with answers.yaml\n"
            f"  README: {question_cell}\n  answers: {hunt['question']}"
        )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_readme_cites_every_attack_technique(scenario: Path) -> None:
    readme = (scenario / "README.md").read_text(encoding="utf-8")
    attack = yaml.safe_load((scenario / "attack.yaml").read_text()) or {}
    for technique in attack.get("techniques", []):
        tid = technique.get("id")
        if not tid:
            continue
        assert tid in readme, (
            f"{scenario.name}: attack.yaml lists {tid} but the README never mentions it"
        )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_detections_are_well_formed(scenario: Path) -> None:
    det_file = scenario / "detections.yaml"
    if not det_file.exists():
        return
    data = yaml.safe_load(det_file.read_text()) or {}
    detections = data.get("detections", [])
    assert detections, f"{scenario.name}: detections.yaml has no detections"
    attack = yaml.safe_load((scenario / "attack.yaml").read_text()) or {}
    declared = {t.get("id") for t in attack.get("techniques", [])}
    for det in detections:
        for key in ("id", "name", "search", "fixture_expect", "attack"):
            assert det.get(key), f"{scenario.name}: detection missing '{key}': {det.get('name')}"
        assert det["fixture_expect"] in ("fires", "silent"), (
            f"{scenario.name}/{det['id']}: fixture_expect must be fires|silent"
        )
        # SPL is stored without a leading `search`/index (the runner scopes it),
        # so a detection must not pin its own time window.
        assert "earliest=" not in det["search"], (
            f"{scenario.name}/{det['id']}: detection search should not hardcode earliest="
        )
        # Every ATT&CK tag a detection claims must be declared in attack.yaml, the
        # same source the Navigator layer reads, so coverage can't silently drift.
        for tid in det["attack"]:
            assert tid in declared, (
                f"{scenario.name}/{det['id']}: ATT&CK {tid} not in attack.yaml"
            )


@pytest.mark.parametrize("scenario", SCENARIO_DIRS, ids=SCENARIO_IDS)
def test_readme_h1_number_matches_directory(scenario: Path) -> None:
    readme = (scenario / "README.md").read_text(encoding="utf-8")
    h1 = next((ln for ln in readme.splitlines() if ln.startswith("# ")), "")
    number = scenario.name.split("-", 1)[0]
    assert re.match(rf"#\s*0*{int(number)}\b", h1), (
        f"{scenario.name}: README H1 '{h1}' does not start with scenario number {number}"
    )
