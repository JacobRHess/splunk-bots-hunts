"""Assemble an installable Splunk app from the scenario sources.

Output: splunk_app/froth_bots_hunts/ — a drop-in app (copy to
$SPLUNK_HOME/etc/apps and restart) containing the six scenario dashboards as
views, plus every scenario detection as a scheduled saved search with ATT&CK
annotations. Generated from scenarios/*/dashboards/*.xml and
scenarios/*/detections.yaml so the app never drifts from the documented hunts.
"""
from __future__ import annotations

import csv
import io
import json
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from xml.sax import saxutils

from harness import iter_scenarios, load_yaml

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"
APP = "froth_bots_hunts"
APP_DIR = ROOT / "splunk_app" / APP
VERSION = "0.2.0"
# Detection logic in detections.yaml is index-less so it can be tested against
# the HEC-ingested fixtures; the deployed saved search is scoped to the dataset.
DEPLOY_INDEX = "botsv3"

# CIM eventtypes: tag each BOTS v3 sourcetype this project hunts into the Splunk
# Common Information Model so the data can drive `| tstats ... from datamodel=...`
# and slot into Enterprise Security. (eventtype name, defining search, [CIM tags]).
EVENTTYPES: list[tuple[str, str, list[str]]] = [
    ("frothly_aws_cloudtrail", "sourcetype=aws:cloudtrail", ["change", "cloud"]),
    ("frothly_o365_management", "sourcetype=ms:o365:management", ["change", "cloud"]),
    ("frothly_aad_signin", "sourcetype=ms:aad:signin", ["authentication", "cloud"]),
    (
        "frothly_wineventlog_security",
        "sourcetype=WinEventLog:Security",
        ["authentication", "endpoint"],
    ),
    (
        "frothly_sysmon",
        'sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
        ["endpoint", "process"],
    ),
    ("frothly_stream_dns", "sourcetype=stream:dns", ["network", "resolution", "dns"]),
]

# Search macros that DRY the logic repeated across hunts, detections, and
# dashboards. `frothly_index` single-sources the deploy index; `rfc1918(1)`
# replaces the inline three-way cidrmatch; `cryptomining_pools` and
# `frothly_users` name the squishy bits the searches key on.
MACROS: list[tuple[str, str, str]] = [
    ("frothly_index", "", f"index={DEPLOY_INDEX}"),
    (
        "rfc1918(1)",
        "ip",
        'cidrmatch("10.0.0.0/8",$ip$) OR cidrmatch("172.16.0.0/12",$ip$) '
        'OR cidrmatch("192.168.0.0/16",$ip$)',
    ),
    ("cryptomining_pools", "", '(query="*coinhive.com" OR query="*minexmr.com")'),
    ("frothly_users", "", 'UserId="*@froth.ly"'),
]

# Curated reference lookups (analyst-maintained context, not telemetry). Identity
# roles let detections separate employees from service/admin accounts; the asset
# table maps the compromised hosts to an owner and criticality. Both are real
# Frothly identities/hosts seen across the scenarios.
IDENTITY_FIELDS = ("identity", "role", "team", "home_country")
IDENTITIES: list[tuple[str, ...]] = [
    ("bstoll@froth.ly", "employee", "sales", "US"),
    ("bgist@froth.ly", "employee", "engineering", "US"),
    ("fyodor@froth.ly", "employee", "engineering", "US"),
    ("klagerfield@froth.ly", "employee", "marketing", "US"),
    ("btun@froth.ly", "employee", "operations", "US"),
    ("mkraeusen@froth.ly", "employee", "brewing", "US"),
    ("abel@froth.ly", "admin", "it", "US"),
    ("DevilFish-ApplicationAccount@namprd17.prod.outlook.com", "service", "microsoft", ""),
]
ASSET_FIELDS = ("host", "owner", "criticality", "zone")
ASSETS: list[tuple[str, ...]] = [
    ("BSTOLL-L", "bstoll@froth.ly", "medium", "workstation"),
    ("FYODOR-L", "fyodor@froth.ly", "medium", "workstation"),
    ("BGIST-L", "bgist@froth.ly", "medium", "workstation"),
]


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
    risk: int
    attack: list[str]


# Enterprise Security notable urgency keyed by the 1-5 alert severity.
_NOTABLE_URGENCY = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}


def _oneline(text: str) -> str:
    return " ".join(text.split())


def _xml_text(text: str) -> str:
    """Escape text destined for an XML element body (``&`` ``<`` ``>``).

    Detection names and titles come from the scenario YAML; without this a name
    containing ``&`` or ``<`` would emit malformed dashboard XML.
    """
    return saxutils.escape(text)


def _cdata(spl: str) -> str:
    """Wrap a search in CDATA, neutralising any literal ``]]>`` that would
    otherwise close the section early."""
    return "<![CDATA[" + spl.replace("]]>", "]]]]><![CDATA[>") + "]]>"


def _severity(risk: int) -> int:
    if risk >= 80:
        return 5
    if risk >= 60:
        return 4
    return 3


def load_detections(scenarios_dir: Path) -> list[Detection]:  # pragma: no cover
    detections: list[Detection] = []
    for path in iter_scenarios(scenarios_dir):
        data = load_yaml(path / "detections.yaml")
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
                    risk=int(det.get("risk", 50)),
                    attack=list(det.get("attack", [])),
                )
            )
    return detections


def load_views(scenarios_dir: Path) -> list[tuple[str, str]]:  # pragma: no cover
    views: list[tuple[str, str]] = []
    for path in iter_scenarios(scenarios_dir):
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
        annotations = json.dumps(
            {"mitre_attack": det.attack, "analytic_story": [det.scenario]},
            separators=(",", ":"),
        )
        deployed_search = f"index={DEPLOY_INDEX} {_oneline(det.search)}"
        description = _oneline(det.description)
        stanzas.append(
            "\n".join(
                [
                    f"[BOTS - {det.name}]",
                    f"description = {description}",
                    f"search = {deployed_search}",
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
                    f"action.notable.param.rule_title = BOTS - {det.name}",
                    f"action.notable.param.rule_description = {description}",
                    f"action.notable.param.severity = {_NOTABLE_URGENCY[det.severity]}",
                    "action.notable.param.nes_fields = user,src,dest,host,UserId,ClientIP",
                    "action.notable.param.drilldown_name = View the matching events",
                    f"action.notable.param.drilldown_search = {deployed_search}",
                    "action.risk = 1",
                    f"action.risk.param._risk_score = {det.risk}",
                    "action.correlationsearch.enabled = 1",
                    f"action.correlationsearch.label = BOTS - {det.name}",
                    f"action.correlationsearch.annotations = {annotations}",
                    f"request.ui_dispatch_app = {APP}",
                    f"# source: {det.scenario}",
                ]
            )
        )
    return "\n\n".join(stanzas) + "\n"


def _search_link(spl: str) -> str:
    """A deep-link into the Search app that opens ``spl`` over the dataset window.

    Used as a single-value drilldown so a red KPI tile is one click from the
    events behind it. The query is URL-encoded; ``&`` is XML-escaped to ``&amp;``.
    """
    encoded = urllib.parse.quote(f"search {spl}")
    return f"search?q={encoded}&amp;earliest=-10y&amp;latest=now"


def render_overview(detections: list[Detection]) -> str:
    """A single-pane KPI board: one single-value tile per detection, red when firing.

    Each tile drills down to the events behind it in the Search app.
    """
    panels = []
    for det in detections:
        deployed = f"index={DEPLOY_INDEX} {_oneline(det.search)}"
        panels.append(
            "    <panel>\n"
            "      <single>\n"
            f"        <title>{_xml_text(det.name)}</title>\n"
            "        <search>\n"
            f"          <query>{_cdata(deployed + ' | stats count')}</query>\n"
            "          <earliest>-10y</earliest>\n"
            "          <latest>now</latest>\n"
            "        </search>\n"
            '        <option name="colorBy">value</option>\n'
            '        <option name="rangeColors">["0x53a051","0xdc4e41"]</option>\n'
            '        <option name="rangeValues">[1]</option>\n'
            '        <option name="useColors">1</option>\n'
            "        <drilldown>\n"
            f'          <link target="_blank">{_search_link(deployed)}</link>\n'
            "        </drilldown>\n"
            "      </single>\n"
            "    </panel>"
        )
    rows = [
        "  <row>\n" + "\n".join(panels[i : i + 3]) + "\n  </row>" for i in range(0, len(panels), 3)
    ]
    return (
        "<dashboard>\n"
        "  <label>Frothly intrusion overview</label>\n"
        "  <description>One KPI per shipped detection across the six BOTS v3 scenarios. "
        "Red means the detection is firing on the data in the selected window.</description>\n"
        + "\n".join(rows)
        + "\n</dashboard>\n"
    )


def _kpi_panel(title: str, query: str, drill: str) -> str:
    return (
        "    <panel>\n"
        "      <single>\n"
        f"        <title>{_xml_text(title)}</title>\n"
        "        <search>\n"
        f"          <query>{_cdata(query)}</query>\n"
        "          <earliest>$tr.earliest$</earliest>\n"
        "          <latest>$tr.latest$</latest>\n"
        "        </search>\n"
        '        <option name="colorBy">value</option>\n'
        '        <option name="rangeColors">["0x53a051","0xdc4e41"]</option>\n'
        '        <option name="rangeValues">[1]</option>\n'
        '        <option name="useColors">1</option>\n'
        "        <drilldown>\n"
        f'          <link target="_blank">{_search_link(drill)}</link>\n'
        "        </drilldown>\n"
        "      </single>\n"
        "    </panel>"
    )


def _table_panel(title: str, query: str, drill: str) -> str:
    return (
        "    <panel>\n"
        "      <table>\n"
        f"        <title>{_xml_text(title)}</title>\n"
        "        <search>\n"
        f"          <query>{_cdata(query)}</query>\n"
        "          <earliest>$tr.earliest$</earliest>\n"
        "          <latest>$tr.latest$</latest>\n"
        "        </search>\n"
        '        <option name="drilldown">row</option>\n'
        "        <drilldown>\n"
        f'          <link target="_blank">{_search_link(drill)}</link>\n'
        "        </drilldown>\n"
        "      </table>\n"
        "    </panel>"
    )


def render_investigation() -> str:
    """A single board that pivots the whole intrusion by entity, using the app's
    own CIM eventtypes, the ``frothly_*`` macros, and the identity/asset lookups.

    This is the analyst's starting point: the headline cloud signals up top, then
    who and what they touched, enriched with role and asset context the lookups
    carry. Every panel drills through to the underlying events.
    """
    kpis = [
        _kpi_panel(
            "Anonymous O365 link retrievals",
            "`frothly_index` `frothly_o365_management` Operation=AnonymousLinkUsed "
            "UserId=anonymous | stats dc(ClientIP)",
            "`frothly_index` `frothly_o365_management` Operation=AnonymousLinkUsed "
            "UserId=anonymous",
        ),
        _kpi_panel(
            "Foreign Azure AD sign-ins",
            "`frothly_index` `frothly_aad_signin` loginStatus=Success "
            "NOT (location.country=US OR location.country=CA) | stats count",
            "`frothly_index` `frothly_aad_signin` loginStatus=Success "
            "NOT (location.country=US OR location.country=CA)",
        ),
        _kpi_panel(
            "AWS console logins without MFA",
            "`frothly_index` `frothly_aws_cloudtrail` eventName=ConsoleLogin "
            "additionalEventData.MFAUsed=No | stats count",
            "`frothly_index` `frothly_aws_cloudtrail` eventName=ConsoleLogin "
            "additionalEventData.MFAUsed=No",
        ),
    ]
    identity_query = (
        "`frothly_index` `frothly_o365_management` `frothly_users` "
        "| stats count values(Operation) as operations by UserId "
        "| lookup frothly_identities identity as UserId OUTPUT role team "
        "| sort -count"
    )
    asset_query = (
        "`frothly_index` `frothly_wineventlog_security` "
        "| stats count by host "
        "| lookup frothly_assets host OUTPUT owner criticality zone "
        "| sort -count"
    )
    tables = [
        _table_panel("Cloud identities and roles (O365)", identity_query, identity_query),
        _table_panel("Endpoint hosts, owners, and criticality", asset_query, asset_query),
    ]
    narrative = (
        "    <panel>\n"
        '      <html>\n'
        '        <div style="padding:4px 8px">\n'
        "          <p>One intrusion across six scenarios on 2018-08-20. "
        "<b>bstoll</b> ties the cloud-to-endpoint thread (AWS recon, the BSTOLL-L "
        "laptop, the Coinhive miner); <b>fyodor</b> ties the PowerShell implant to "
        "the Azure AD sign-ins and the O365 mailbox abuse; <b>bgist</b> carries the "
        "stolen cloud accounts into the anonymous OneDrive share.</p>\n"
        "          <p>KPI tiles turn red when a signal is present in the selected "
        "window. The tables enrich raw activity with the role and asset context the "
        "<code>frothly_identities</code> and <code>frothly_assets</code> lookups "
        "carry. Click any panel to pivot to the underlying events.</p>\n"
        "        </div>\n"
        "      </html>\n"
        "    </panel>"
    )
    rows = [
        "  <row>\n" + "\n".join(kpis) + "\n  </row>",
        "  <row>\n" + "\n".join(tables) + "\n  </row>",
        "  <row>\n" + narrative + "\n  </row>",
    ]
    return (
        "<form>\n"
        "  <label>Frothly intrusion investigation</label>\n"
        "  <description>Entity-centric view of the BOTS v3 intrusion, enriched with "
        "identity and asset lookups. Start here, then drill into a scenario.</description>\n"
        '  <fieldset submitButton="false">\n'
        '    <input type="time" token="tr">\n'
        "      <default>\n"
        "        <earliest>-10y</earliest>\n"
        "        <latest>now</latest>\n"
        "      </default>\n"
        "    </input>\n"
        "  </fieldset>\n"
        + "\n".join(rows)
        + "\n</form>\n"
    )


def render_nav(view_names: list[str]) -> str:
    lines = ["<nav>"]
    for i, name in enumerate(view_names):
        default = ' default="true"' if i == 0 else ""
        lines.append(f'  <view name="{name}"{default}/>')
    lines.append("  <saved/>")
    lines.append('  <view name="search"/>')
    lines.append("</nav>")
    return "\n".join(lines) + "\n"


def render_macros() -> str:
    stanzas = []
    for name, args, definition in MACROS:
        lines = [f"[{name}]", f"definition = {definition}", "iseval = 0"]
        if args:
            lines.insert(1, f"args = {args}")
        stanzas.append("\n".join(lines))
    return "\n\n".join(stanzas) + "\n"


def render_eventtypes() -> str:
    stanzas = [f"[{name}]\nsearch = {search}" for name, search, _ in EVENTTYPES]
    return "\n\n".join(stanzas) + "\n"


def render_tags() -> str:
    stanzas = []
    for name, _, cim_tags in EVENTTYPES:
        if not cim_tags:
            continue
        body = "\n".join(f"{tag} = enabled" for tag in cim_tags)
        stanzas.append(f"[eventtype={name}]\n{body}")
    return "\n\n".join(stanzas) + "\n"


def render_transforms() -> str:
    return (
        "[frothly_identities]\nfilename = identities.csv\n"
        "case_sensitive_match = false\n\n"
        "[frothly_assets]\nfilename = assets.csv\n"
        "case_sensitive_match = false\n"
    )


def _render_csv(fields: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    buffer = io.StringIO()
    # QUOTE_MINIMAL with a fixed LF terminator: correctly quotes any field that
    # contains a comma, quote, or newline rather than corrupting the row.
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(fields)
    writer.writerows(rows)
    return buffer.getvalue()


def render_meta() -> str:
    objects = ["views", "savedsearches", "macros", "eventtypes", "tags", "transforms", "lookups"]
    blocks = ["[]\naccess = read : [ * ], write : [ admin, power ]\nexport = system"]
    blocks.extend(f"[{obj}]\nexport = system" for obj in objects)
    return "\n\n".join(blocks) + "\n"


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
        "(`default/savedsearches.conf`), each ATT&CK-annotated and configured as an "
        "Enterprise Security correlation search with notable + risk actions.\n"
        f"- {len(view_names)} dashboards (`default/data/ui/views/`):\n{views}\n"
        "- CIM mapping: `eventtypes.conf` + `tags.conf` tag each BOTS v3 sourcetype into "
        "the Authentication, Network Resolution, Endpoint, and Change data models.\n"
        "- Search macros (`macros.conf`): `frothly_index`, `rfc1918(1)`, "
        "`cryptomining_pools`, `frothly_users`.\n"
        "- Context lookups (`lookups/`): `identities.csv` (employee/admin/service roles) "
        "and `assets.csv` (host owner + criticality), defined in `transforms.conf`.\n"
    )


def main() -> int:  # pragma: no cover
    detections = load_detections(SCENARIOS)
    views = load_views(SCENARIOS)
    # The generated overview and investigation boards lead the nav; the
    # per-scenario dashboards follow.
    nav_views = ["overview", "investigation", *[name for name, _ in views]]

    default_dir = APP_DIR / "default"
    views_dir = default_dir / "data" / "ui" / "views"
    lookups_dir = APP_DIR / "lookups"
    views_dir.mkdir(parents=True, exist_ok=True)
    (default_dir / "data" / "ui" / "nav").mkdir(parents=True, exist_ok=True)
    (APP_DIR / "metadata").mkdir(parents=True, exist_ok=True)
    lookups_dir.mkdir(parents=True, exist_ok=True)

    (default_dir / "app.conf").write_text(render_app_conf(), encoding="utf-8")
    (default_dir / "savedsearches.conf").write_text(
        render_savedsearches(detections), encoding="utf-8"
    )
    (default_dir / "macros.conf").write_text(render_macros(), encoding="utf-8")
    (default_dir / "eventtypes.conf").write_text(render_eventtypes(), encoding="utf-8")
    (default_dir / "tags.conf").write_text(render_tags(), encoding="utf-8")
    (default_dir / "transforms.conf").write_text(render_transforms(), encoding="utf-8")
    (lookups_dir / "identities.csv").write_text(
        _render_csv(IDENTITY_FIELDS, IDENTITIES), encoding="utf-8"
    )
    (lookups_dir / "assets.csv").write_text(_render_csv(ASSET_FIELDS, ASSETS), encoding="utf-8")
    (views_dir / "overview.xml").write_text(render_overview(detections), encoding="utf-8")
    (views_dir / "investigation.xml").write_text(render_investigation(), encoding="utf-8")
    (default_dir / "data" / "ui" / "nav" / "default.xml").write_text(
        render_nav(nav_views), encoding="utf-8"
    )
    (APP_DIR / "metadata" / "default.meta").write_text(render_meta(), encoding="utf-8")
    (APP_DIR / "README.md").write_text(
        render_app_readme(nav_views, len(detections)), encoding="utf-8"
    )
    for name, xml in views:
        (views_dir / f"{name}.xml").write_text(xml, encoding="utf-8")

    print(f"Wrote {APP_DIR} ({len(detections)} detections, {len(views) + 2} views)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
