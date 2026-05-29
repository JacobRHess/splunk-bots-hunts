"""Tests for the static HTML report generator's pure helpers."""
from __future__ import annotations

from harness import build_report
from harness.build_report import Hunt, Scenario

README = """# 03 — A scenario title

## The thread

First paragraph of the thread.
Still the same paragraph.

Second paragraph that should be ignored.

## How I worked it

Steps.
"""


def test_parse_title_strips_number_prefix() -> None:
    assert build_report.parse_title(README) == "A scenario title"


def test_parse_title_handles_missing_h1() -> None:
    assert build_report.parse_title("no heading here") == ""


def test_parse_summary_takes_first_section_paragraph() -> None:
    summary = build_report.parse_summary(README)
    assert summary == "First paragraph of the thread. Still the same paragraph."
    assert "Second paragraph" not in summary
    assert "How I worked it" not in summary


def test_parse_summary_breaks_on_next_section_without_blank_line() -> None:
    # paragraph runs straight into the next '## ' heading with no blank line between
    md = "# 01 — T\n## The thread\nfirst line\nsecond line\n## How I worked it\nsteps\n"
    assert build_report.parse_summary(md) == "first line second line"


def test_parse_summary_empty_when_no_section() -> None:
    assert build_report.parse_summary("# Title only\n\nbody with no ## section\n") == ""


def _scenario(number: str, techniques: list[tuple[str, str]]) -> Scenario:
    return Scenario(
        slug=f"{number}-x",
        number=number,
        title=f"Scenario {number}",
        summary="summary",
        hunts=[Hunt(file="01-a.spl", question="Q?", expected="ans", field="f", spl="search x")],
        techniques=techniques,
        detections=["A detection"],
    )


def test_build_matrix_dedups_and_tracks_coverage() -> None:
    scenarios = [
        _scenario("01", [("T1059", "PowerShell"), ("T1027", "Obfuscation")]),
        _scenario("02", [("T1059", "PowerShell")]),
    ]
    techniques, coverage = build_report.build_matrix(scenarios)
    assert techniques == [("T1027", "Obfuscation"), ("T1059", "PowerShell")]
    assert coverage["T1059"] == {"01", "02"}
    assert coverage["T1027"] == {"01"}


def test_committed_report_is_up_to_date() -> None:
    # The generated docs/index.html is committed so GitHub Pages can serve it.
    # Guard against it drifting from the scenario sources. splitlines() normalizes
    # the LF/CRLF difference between git's working tree and the generator's output.
    expected = build_report.render(build_report.load_scenarios())
    actual = build_report.OUTPUT.read_text(encoding="utf-8")
    assert actual.splitlines() == expected.splitlines(), (
        "docs/index.html is stale - regenerate with `uv run python harness/build_report.py`"
    )


def test_strip_md_removes_inline_markdown() -> None:
    assert build_report._strip_md("`code` and **bold** text") == "code and bold text"
    assert build_report._strip_md("see [scenario 01](../01-x/) here") == "see scenario 01 here"


def test_render_includes_scenarios_and_hunts() -> None:
    scenarios = [_scenario("01", [("T1059", "PowerShell")])]
    html_out = build_report.render(scenarios)
    assert "Scenario 01" in html_out
    assert "T1059" in html_out
    assert "Q?" in html_out
    assert "search x" in html_out
    assert "</html>" in html_out


def test_render_matrix_is_accessible() -> None:
    scenarios = [_scenario("01", [("T1059", "PowerShell")])]
    html_out = build_report.render(scenarios)
    assert 'scope="col"' in html_out  # column headers
    assert 'scope="row"' in html_out  # technique row headers
    assert "covered" in html_out  # screen-reader text for matrix cells
    assert 'aria-expanded' in html_out  # hunt toggle state
    assert "<main" in html_out


def test_render_empty_state() -> None:
    html_out = build_report.render([])
    assert "No scenarios yet" in html_out
    assert "</html>" in html_out


def test_render_escapes_html_in_content() -> None:
    scenarios = [
        Scenario(
            slug="01-x",
            number="01",
            title="Title <b>",
            summary="sum & more",
            hunts=[Hunt(file="01-a.spl", question="a < b", expected="x>y", field=None, spl="<x>")],
            techniques=[],
            detections=["Det <i>"],
        )
    ]
    html_out = build_report.render(scenarios)
    assert "Title &lt;b&gt;" in html_out  # title escaped, not injected as a tag
    assert "Det &lt;i&gt;" in html_out  # detection name escaped
    assert "sum &amp; more" in html_out
    assert "a &lt; b" in html_out
    assert "&lt;x&gt;" in html_out  # SPL body escaped
