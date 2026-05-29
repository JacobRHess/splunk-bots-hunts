"""Well-formedness checks for the XML the Splunk app ships.

A malformed dashboard or nav file installs into Splunk as a broken view with no
error until a user opens it. Parsing every dashboard, generated app view, and
the nav here turns that into a CI failure.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DASHBOARDS = sorted(ROOT.glob("scenarios/*/dashboards/*.xml"))
APP_VIEWS = sorted((ROOT / "splunk_app").glob("**/data/ui/views/*.xml"))
NAV = ROOT / "splunk_app" / "froth_bots_hunts" / "default" / "data" / "ui" / "nav" / "default.xml"


@pytest.mark.parametrize("xml_file", DASHBOARDS, ids=[p.name for p in DASHBOARDS])
def test_scenario_dashboards_well_formed(xml_file: Path) -> None:
    root = ET.parse(xml_file).getroot()
    assert root.tag in ("form", "dashboard"), f"{xml_file.name}: unexpected root <{root.tag}>"


@pytest.mark.parametrize("xml_file", APP_VIEWS, ids=[p.name for p in APP_VIEWS])
def test_app_views_well_formed(xml_file: Path) -> None:
    ET.parse(xml_file)


def test_app_has_a_view_per_dashboard() -> None:
    assert len(APP_VIEWS) == len(DASHBOARDS), "app views and scenario dashboards out of sync"


def test_nav_well_formed() -> None:
    root = ET.parse(NAV).getroot()
    assert root.tag == "nav"
