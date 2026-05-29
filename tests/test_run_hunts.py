"""Tests for run_hunts pure-Python helpers."""
from __future__ import annotations

from harness.run_hunts import _extract_answer, _matches


def test_extract_answer_field_present() -> None:
    rows = [{"sourceIPAddress": "1.2.3.4", "count": "5"}]
    assert _extract_answer(rows, "sourceIPAddress") == "1.2.3.4"


def test_extract_answer_field_missing() -> None:
    assert _extract_answer([{"a": "b"}], "missing") is None


def test_extract_answer_no_field_returns_first_row() -> None:
    row = {"a": "1", "b": "2"}
    assert _extract_answer([row], None) == row


def test_extract_answer_empty_rows() -> None:
    assert _extract_answer([], "x") is None
    assert _extract_answer([], None) is None


def test_extract_answer_only_uses_first_row() -> None:
    rows = [{"x": "first"}, {"x": "second"}]
    assert _extract_answer(rows, "x") == "first"


def test_matches_exact_string() -> None:
    assert _matches("bstoll", "bstoll")
    assert not _matches("bstoll", "other")


def test_matches_numeric_forms() -> None:
    assert _matches("16", 16)
    assert _matches(16, "16")
    assert _matches("16.0", "16")
    assert not _matches("16", "17")


def test_matches_strips_whitespace() -> None:
    assert _matches("  FYODOR-L.froth.ly\n", "FYODOR-L.froth.ly")


def test_matches_none_never_matches() -> None:
    assert not _matches(None, "anything")
    assert not _matches(None, "None")


def test_matches_non_numeric_distinct_strings() -> None:
    assert not _matches("HKLM:\\Software", "HKLM:\\System")
