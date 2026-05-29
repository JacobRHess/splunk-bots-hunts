"""Tests for the Splunk app generator and drift guards over the committed app."""
from __future__ import annotations

import configparser

from harness import build_splunk_app
from harness.build_splunk_app import (
    APP_DIR,
    SCENARIOS,
    Detection,
    _oneline,
    _severity,
    load_detections,
    load_views,
    render_app_conf,
    render_meta,
    render_nav,
    render_savedsearches,
)


def _det(**kw: object) -> Detection:
    base: dict[str, object] = dict(
        scenario="01-x",
        name="Test detection",
        description="multi\n  line\n  desc",
        search="sourcetype=x foo=bar\n| stats count by host",
        cron="*/15 * * * *",
        earliest="-24h",
        latest="now",
        severity=4,
        risk=65,
        attack=["T1059.001"],
    )
    base.update(kw)
    return Detection(**base)  # type: ignore[arg-type]


def test_oneline_collapses_whitespace() -> None:
    assert _oneline("a\n  b   c\n") == "a b c"


def test_severity_thresholds() -> None:
    assert _severity(80) == 5
    assert _severity(60) == 4
    assert _severity(10) == 3


def test_render_savedsearches_stanza() -> None:
    out = render_savedsearches([_det()])
    assert "[BOTS - Test detection]" in out
    # search is collapsed to one line and scoped to the dataset index for deployment
    assert "search = index=botsv3 sourcetype=x foo=bar | stats count by host" in out
    assert 'action.correlationsearch.annotations = {"mitre_attack":["T1059.001"]}' in out
    assert "action.correlationsearch.enabled = 1" in out
    assert "action.correlationsearch.label = BOTS - Test detection" in out
    assert "action.risk = 1" in out
    assert "action.risk.param._risk_score = 65" in out
    assert "cron_schedule = */15 * * * *" in out
    assert "# source: 01-x" in out


def test_render_savedsearches_is_valid_ini() -> None:
    out = render_savedsearches([_det(), _det(name="Second", scenario="02-y")])
    parser = configparser.ConfigParser(strict=True)
    parser.read_string(out)
    assert "BOTS - Test detection" in parser.sections()
    assert "BOTS - Second" in parser.sections()


def test_render_nav_marks_first_default() -> None:
    nav = render_nav(["a", "b"])
    assert '<view name="a" default="true"/>' in nav
    assert '<view name="b"/>' in nav
    assert "<saved/>" in nav


def test_render_app_conf_and_meta() -> None:
    assert "[launcher]" in render_app_conf()
    assert "export = system" in render_meta()


# ---- drift guards over the committed splunk_app/ ----

def test_committed_savedsearches_up_to_date() -> None:
    expected = render_savedsearches(load_detections(SCENARIOS))
    actual = (APP_DIR / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    assert actual.splitlines() == expected.splitlines(), "savedsearches.conf is stale"


def test_committed_savedsearches_is_valid_ini() -> None:
    text = (APP_DIR / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    configparser.ConfigParser(strict=True).read_string(text)


def test_committed_views_match_scenario_dashboards() -> None:
    views = load_views(SCENARIOS)
    assert views, "no scenario dashboards found"
    for name, xml in views:
        committed = (APP_DIR / "default" / "data" / "ui" / "views" / f"{name}.xml").read_text(
            encoding="utf-8"
        )
        assert committed.splitlines() == xml.splitlines(), f"view {name}.xml drifted from source"


def test_committed_nav_up_to_date() -> None:
    names = [n for n, _ in load_views(SCENARIOS)]
    expected = render_nav(names)
    actual = (APP_DIR / "default" / "data" / "ui" / "nav" / "default.xml").read_text(
        encoding="utf-8"
    )
    assert actual.splitlines() == expected.splitlines()


def test_build_splunk_app_module_constants() -> None:
    assert build_splunk_app.APP == "froth_bots_hunts"
