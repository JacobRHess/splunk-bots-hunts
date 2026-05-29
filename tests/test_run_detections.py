"""Tests for the detection runner's expectation helper."""
from __future__ import annotations

import pytest

from harness.run_detections import _expectation_met


def test_fires_needs_at_least_one_row() -> None:
    assert _expectation_met(1, "fires")
    assert _expectation_met(9, "fires")
    assert not _expectation_met(0, "fires")


def test_silent_needs_zero_rows() -> None:
    assert _expectation_met(0, "silent")
    assert not _expectation_met(1, "silent")


def test_unknown_expectation_raises() -> None:
    with pytest.raises(ValueError, match="unknown fixture_expect"):
        _expectation_met(1, "maybe")
