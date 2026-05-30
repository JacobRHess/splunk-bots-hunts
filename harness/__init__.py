"""Shared helpers for the scenario harness.

The build/run scripts all walk the same ``scenarios/<NN>-<slug>/`` tree and read
the same YAML files. These two helpers single-source "what counts as a scenario"
(a numbered directory) and the tolerant-load convention so the loaders can't
drift apart.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

_SCENARIO_DIR = re.compile(r"^\d+-")


def iter_scenarios(scenarios_dir: Path) -> Iterator[Path]:
    """Yield each numbered scenario directory under ``scenarios_dir``, sorted by name.

    A scenario is a directory whose name starts with the ``NN-`` ordinal prefix
    (``01-aws-recon-bstoll``); anything else in the tree is skipped.
    """
    if not scenarios_dir.exists():
        return
    for path in sorted(scenarios_dir.iterdir()):
        if path.is_dir() and _SCENARIO_DIR.match(path.name):
            yield path


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, returning an empty dict if it is missing or empty."""
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
