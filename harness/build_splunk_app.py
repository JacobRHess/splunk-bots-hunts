"""Assemble an installable Splunk app from the scenario sources.

Output: splunk_app/froth_bots_hunts/ — a drop-in app (copy to
$SPLUNK_HOME/etc/apps and restart) containing the four scenario dashboards as
views, plus every scenario detection as a scheduled saved search with ATT&CK
annotations. Generated from scenarios/*/dashboards/*.xml and
scenarios/*/detections.yaml so the app never drifts from the documented hunts.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"
APP = "froth_bots_hunts"
APP_DIR = ROOT / "splunk_app" / APP
VERSION = "0.1.0"


@dataclass
class Detection:
    scenario: str
    name: str
    description: str
    search: str
    cron: str
    earliest: str
    latest: str
    severity: int
    attack: list[str]


def _oneline(text: str) -> str:
    return " ".join(text.split())


def _severity(risk: int) -> int:
    if risk >= 80:
        return 5
    if risk >= 60:
        return 4
    return 3


def load_detections(scenarios_dir: Path) -> list[Detection]:  # pragma: no cover
    detections: list[Detection] = []
    if not scenarios_dir.exists():
        return detections
    for path in sorted(scenarios_dir.iterdir()):
        det_file = path / "detections.yaml"
        if not path.is_dir() or not det_file.exists():
            continue
        data = yaml.safe_load(det_file.read_text()) or {}
        for det in data.get("detections", []):
            detections.append(
                Detection(
                    scenario=path.name,
                    name=det["name"],
                    description=det.get("description", ""),
                    search=det["search"],
                    cron=det.get("cron", "*/15 * * * *"),
                    earliest=str(det.get("earliest", "-60m")),
                    latest=str(det.get("latest", "now")),
                    severity=_severity(int(det.get("risk", 50))),
                    attack=list(det.get("attack", [])),
                )
            )
    return detections


def load_views(scenarios_dir: Path) -> list[tuple[str, str]]:  # pragma: no cover
    views: list[tuple[str, str]] = []
    if not scenarios_dir.exists():
        return views
    for path in sorted(scenarios_dir.iterdir()):
        for dash in sorted((path / "dashboards").glob("*.xml")):
            views.append((dash.stem, dash.read_text(encoding="utf-8")))
    return views


def render_app_conf() -> str:
    return (
        "[install]\nis_configured = 0\n\n"
        "[ui]\nis_visible = 1\nlabel = Frothly BOTS Hunts\n\n"
        "[launcher]\nauthor = Jacob Hess\n"
        "description = Threat-hunting dashboards and detections for Splunk Boss of the SOC v3.\n"
        f"version = {VERSION}\n"
    )


def render_savedsearches(detections: list[Detection]) -> str:
    stanzas: list[str] = []
    for det in detections:
        annotations = json.dumps({"mitre_attack": det.attack}, separators=(",", ":"))
        stanzas.append(
            "\n".join(
                [
                    f"[BOTS - {det.name}]",
                    f"description = {_oneline(det.description)}",
                    f"search = {_oneline(det.search)}",
                    "disabled = 0",
                    "enableSched = 1",
                    f"cron_schedule = {det.cron}",
                    f"dispatch.earliest_time = {det.earliest}",
                    f"dispatch.latest_time = {det.latest}",
                    "counttype = number of events",
                    "relation = greater than",
                    "quantity = 0",
                    "alert.track = 1",
                    f"alert.severity = {det.severity}",
                    "action.notable = 1",
                    f"action.correlationsearch.annotations = {annotations}",
                    f"request.ui_dispatch_app = {APP}",
                    f"# source: {det.scenario}",
                ]
            )
        )
    return "\n\n".join(stanzas) + "\n"


def render_nav(view_names: list[str]) -> str:
    lines = ["<nav>"]
    for i, name in enumerate(view_names):
        default = ' default="true"' if i == 0 else ""
        lines.append(f'  <view name="{name}"{default}/>')
    lines.append("  <saved/>")
    lines.append('  <view name="search"/>')
    lines.append("</nav>")
    return "\n".join(lines) + "\n"


def render_meta() -> str:
    return (
        "[]\naccess = read : [ * ], write : [ admin, power ]\nexport = system\n\n"
        "[views]\nexport = system\n\n"
        "[savedsearches]\nexport = system\n"
    )


def render_app_readme(view_names: list[str], detection_count: int) -> str:
    views = "\n".join(f"- `{n}`" for n in view_names)
    return (
        f"# {APP}\n\n"
        "Generated Splunk app for the splunk-bots-hunts portfolio. Do not edit by "
        f"hand: regenerate with `uv run python harness/build_splunk_app.py`.\n\n"
        "## Install\n\n"
        f"Copy `{APP}/` to `$SPLUNK_HOME/etc/apps/` and restart Splunk, or upload the "
        "folder as an app package via Manage Apps.\n\n"
        f"## Contents\n\n- {detection_count} scheduled detections "
        "(`default/savedsearches.conf`), each ATT&CK-annotated.\n"
        f"- {len(view_names)} dashboards (`default/data/ui/views/`):\n{views}\n"
    )


def main() -> int:  # pragma: no cover
    detections = load_detections(SCENARIOS)
    views = load_views(SCENARIOS)
    view_names = [name for name, _ in views]

    (APP_DIR / "default" / "data" / "ui" / "views").mkdir(parents=True, exist_ok=True)
    (APP_DIR / "default" / "data" / "ui" / "nav").mkdir(parents=True, exist_ok=True)
    (APP_DIR / "metadata").mkdir(parents=True, exist_ok=True)

    (APP_DIR / "default" / "app.conf").write_text(render_app_conf(), encoding="utf-8")
    (APP_DIR / "default" / "savedsearches.conf").write_text(
        render_savedsearches(detections), encoding="utf-8"
    )
    (APP_DIR / "default" / "data" / "ui" / "nav" / "default.xml").write_text(
        render_nav(view_names), encoding="utf-8"
    )
    (APP_DIR / "metadata" / "default.meta").write_text(render_meta(), encoding="utf-8")
    (APP_DIR / "README.md").write_text(
        render_app_readme(view_names, len(detections)), encoding="utf-8"
    )
    for name, xml in views:
        (APP_DIR / "default" / "data" / "ui" / "views" / f"{name}.xml").write_text(
            xml, encoding="utf-8"
        )

    print(f"Wrote {APP_DIR} ({len(detections)} detections, {len(views)} views)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
