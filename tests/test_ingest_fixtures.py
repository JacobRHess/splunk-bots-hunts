"""Tests for ingest_fixtures classifier logic."""
from __future__ import annotations

from harness.ingest_fixtures import classify_event


def test_classify_raw_event_extracts_metadata() -> None:
    event = {
        "_sourcetype": "WinEventLog:Security",
        "_raw": "raw text",
        "_host": "BSTOLL-L",
        "_source": "WinEventLog:Security",
    }
    sourcetype, t, raw, host, source, body = classify_event(event)

    assert sourcetype == "WinEventLog:Security"
    assert raw == "raw text"
    assert host == "BSTOLL-L"
    assert source == "WinEventLog:Security"
    assert t is None
    assert body == {}


def test_classify_json_event_keeps_body_fields() -> None:
    event = {
        "_sourcetype": "_json",
        "_time": 1534745797,
        "EventCode": "4624",
        "Logon_Type": "5",
    }
    sourcetype, t, raw, host, source, body = classify_event(event)

    assert sourcetype == "_json"
    assert t == 1534745797
    assert raw is None
    assert host is None
    assert source is None
    assert body == {"EventCode": "4624", "Logon_Type": "5"}


def test_classify_defaults_sourcetype_to_json() -> None:
    sourcetype, *_, body = classify_event({"foo": "bar"})
    assert sourcetype == "_json"
    assert body == {"foo": "bar"}


def test_classify_mutates_input() -> None:
    event = {"_sourcetype": "x", "keep": "me"}
    classify_event(event)
    assert "_sourcetype" not in event
    assert event == {"keep": "me"}
