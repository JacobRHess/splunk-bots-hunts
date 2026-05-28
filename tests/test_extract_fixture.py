"""Tests for the extract_fixture row->event builder."""
from __future__ import annotations

from tools.extract_fixture import build_fixture_event


def test_raw_mode_wraps_raw_text() -> None:
    row = {"_raw": "raw text", "_time": "1534745797.000", "host": "BSTOLL-L"}
    event = build_fixture_event(row, "WinEventLog:Security", raw_mode=True)
    assert event is not None
    assert event["_raw"] == "raw text"
    assert event["_sourcetype"] == "WinEventLog:Security"
    assert event["_time"] == 1534745797
    assert event["_host"] == "BSTOLL-L"


def test_json_mode_parses_raw_into_event() -> None:
    row = {"_raw": '{"eventName": "GetBucketAcl"}', "host": "BSTOLL-L", "source": "cloudtrail"}
    event = build_fixture_event(row, "aws:cloudtrail", raw_mode=False)
    assert event is not None
    assert event["eventName"] == "GetBucketAcl"
    assert event["_sourcetype"] == "aws:cloudtrail"
    assert event["_host"] == "BSTOLL-L"
    assert event["_source"] == "cloudtrail"


def test_skips_row_with_no_raw() -> None:
    assert build_fixture_event({}, "_json", raw_mode=False) is None
    assert build_fixture_event({"_raw": ""}, "_json", raw_mode=False) is None


def test_skips_invalid_json_in_json_mode() -> None:
    assert build_fixture_event({"_raw": "not json"}, "_json", raw_mode=False) is None


def test_skips_json_array_in_json_mode() -> None:
    assert build_fixture_event({"_raw": "[1, 2, 3]"}, "_json", raw_mode=False) is None


def test_ignores_unparseable_time() -> None:
    row = {"_raw": "x", "_time": "not-a-number"}
    event = build_fixture_event(row, "_json", raw_mode=True)
    assert event is not None
    assert "_time" not in event


def test_omits_host_when_absent() -> None:
    event = build_fixture_event({"_raw": "x"}, "_json", raw_mode=True)
    assert event is not None
    assert "_host" not in event
    assert "_source" not in event
