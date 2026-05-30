"""Tests for the Splunk app generator and drift guards over the committed app."""
from __future__ import annotations

import configparser
import xml.etree.ElementTree as ET

from harness import build_splunk_app
from harness.build_splunk_app import (
    APP_DIR,
    ASSET_FIELDS,
    ASSETS,
    IDENTITIES,
    IDENTITY_FIELDS,
    SCENARIOS,
    Detection,
    _oneline,
    _render_csv,
    _search_link,
    _severity,
    load_detections,
    load_views,
    render_app_conf,
    render_eventtypes,
    render_investigation,
    render_macros,
    render_meta,
    render_nav,
    render_overview,
    render_savedsearches,
    render_tags,
    render_transforms,
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
    assert (
        'action.correlationsearch.annotations = '
        '{"mitre_attack":["T1059.001"],"analytic_story":["01-x"]}'
    ) in out
    assert "action.correlationsearch.enabled = 1" in out
    assert "action.correlationsearch.label = BOTS - Test detection" in out
    assert "action.risk = 1" in out
    assert "action.risk.param._risk_score = 65" in out
    assert "cron_schedule = */15 * * * *" in out
    assert "# source: 01-x" in out


def test_render_savedsearches_notable_params() -> None:
    out = render_savedsearches([_det()])
    assert "action.notable.param.rule_title = BOTS - Test detection" in out
    assert "action.notable.param.severity = high" in out  # severity 4 -> high
    assert "action.notable.param.nes_fields = user,src,dest,host,UserId,ClientIP" in out
    # the drilldown opens the same deployed (index-scoped) search
    assert (
        "action.notable.param.drilldown_search = "
        "index=botsv3 sourcetype=x foo=bar | stats count by host"
    ) in out


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
    meta = render_meta()
    # every shipped knowledge object is exported so it is visible app-wide
    for obj in ("macros", "eventtypes", "tags", "transforms", "lookups"):
        assert f"[{obj}]\nexport = system" in meta


def test_render_macros_includes_args_only_when_present() -> None:
    out = render_macros()
    parser = configparser.ConfigParser(strict=True)
    parser.read_string(out)
    assert parser["frothly_index"]["definition"] == "index=botsv3"
    assert "args" not in parser["frothly_index"]
    # rfc1918 takes an ip argument
    assert parser["rfc1918(1)"]["args"] == "ip"
    assert "cidrmatch" in parser["rfc1918(1)"]["definition"]


def test_render_eventtypes_and_tags_align() -> None:
    et = configparser.ConfigParser(strict=True)
    et.read_string(render_eventtypes())
    assert et["frothly_aad_signin"]["search"] == "sourcetype=ms:aad:signin"
    tags = render_tags()
    # the auth eventtypes carry the CIM authentication tag
    assert "[eventtype=frothly_aad_signin]\nauthentication = enabled" in tags
    assert "[eventtype=frothly_stream_dns]" in tags and "dns = enabled" in tags


def test_render_transforms_defines_both_lookups() -> None:
    out = render_transforms()
    parser = configparser.ConfigParser(strict=True)
    parser.read_string(out)
    assert parser["frothly_identities"]["filename"] == "identities.csv"
    assert parser["frothly_assets"]["filename"] == "assets.csv"


def test_render_csv_header_and_rows() -> None:
    csv = _render_csv(IDENTITY_FIELDS, IDENTITIES)
    lines = csv.strip().splitlines()
    assert lines[0] == "identity,role,team,home_country"
    assert len(lines) == len(IDENTITIES) + 1
    assert "fyodor@froth.ly,employee,engineering,US" in lines
    # the service account is labelled so detections can exclude it
    assert any(row.endswith("service,microsoft,") for row in lines)


def test_assets_csv_covers_scenario_hosts() -> None:
    csv = _render_csv(ASSET_FIELDS, ASSETS)
    for host in ("BSTOLL-L", "FYODOR-L", "BGIST-L"):
        assert f"{host}," in csv


def test_search_link_is_xml_safe_and_encoded() -> None:
    link = _search_link("index=botsv3 sourcetype=x foo=bar")
    assert link.startswith("search?q=")
    assert "&amp;earliest=-10y" in link  # & escaped for XML
    assert " " not in link  # query is URL-encoded


def test_render_overview_tiles_drill_down() -> None:
    out = render_overview([_det()])
    assert "<drilldown>" in out and "<link target=\"_blank\">search?q=" in out


def test_render_investigation_uses_macros_and_lookups() -> None:
    out = render_investigation()
    root = ET.fromstring(out)
    assert root.tag == "form"
    assert "Frothly intrusion investigation" in out
    assert "`frothly_index`" in out  # uses the deploy-index macro
    assert "lookup frothly_identities" in out and "lookup frothly_assets" in out
    assert out.count("<drilldown>") >= 3  # every panel pivots to events


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
    names = ["overview", "investigation", *[n for n, _ in load_views(SCENARIOS)]]
    expected = render_nav(names)
    actual = (APP_DIR / "default" / "data" / "ui" / "nav" / "default.xml").read_text(
        encoding="utf-8"
    )
    assert actual.splitlines() == expected.splitlines()


def _committed(*parts: str) -> str:
    return (APP_DIR.joinpath(*parts)).read_text(encoding="utf-8")


def test_committed_macros_up_to_date() -> None:
    assert _committed("default", "macros.conf").splitlines() == render_macros().splitlines()


def test_committed_eventtypes_up_to_date() -> None:
    assert _committed("default", "eventtypes.conf").splitlines() == render_eventtypes().splitlines()


def test_committed_tags_up_to_date() -> None:
    assert _committed("default", "tags.conf").splitlines() == render_tags().splitlines()


def test_committed_transforms_up_to_date() -> None:
    assert _committed("default", "transforms.conf").splitlines() == render_transforms().splitlines()


def test_committed_lookups_up_to_date() -> None:
    assert _committed("lookups", "identities.csv").splitlines() == _render_csv(
        IDENTITY_FIELDS, IDENTITIES
    ).splitlines()
    assert _committed("lookups", "assets.csv").splitlines() == _render_csv(
        ASSET_FIELDS, ASSETS
    ).splitlines()


def test_committed_investigation_up_to_date() -> None:
    actual = _committed("default", "data", "ui", "views", "investigation.xml")
    assert actual.splitlines() == render_investigation().splitlines(), "investigation.xml is stale"
    ET.fromstring(actual)  # and it parses


def test_committed_confs_are_valid_ini() -> None:
    for conf in ("macros.conf", "eventtypes.conf", "tags.conf", "transforms.conf"):
        configparser.ConfigParser(strict=True).read_string(_committed("default", conf))


def test_render_overview_is_a_kpi_per_detection() -> None:
    out = render_overview([_det(), _det(name="Second", scenario="02-y")])
    assert "<dashboard>" in out and "Frothly intrusion overview" in out
    assert out.count("<single>") == 2
    assert "<title>Test detection</title>" in out
    assert "<![CDATA[" in out  # search wrapped in CDATA so `>=` etc. don't break the XML


def test_committed_overview_up_to_date() -> None:
    expected = render_overview(load_detections(SCENARIOS))
    actual = (APP_DIR / "default" / "data" / "ui" / "views" / "overview.xml").read_text(
        encoding="utf-8"
    )
    assert actual.splitlines() == expected.splitlines(), "overview.xml is stale"


def test_build_splunk_app_module_constants() -> None:
    assert build_splunk_app.APP == "froth_bots_hunts"
