"""Shared result-writing for every script in experiments/.

Each experiment writes ONE JSON file to experiments/results/<name>.json --
the raw numbers behind whatever docs/EVIDENCE_AND_EVALUATION.md cites, so a
claim in that document can always be traced back to the exact data that
produced it, not just the script that could theoretically reproduce it.
Reuses aginiti/logging_utils.py's JSON-safety rules (dataclasses, enums,
datetimes) rather than reinventing serialization.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from aginiti.logging_utils import _json_safe

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def save_result(name: str, payload: dict) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    payload = dict(payload)
    payload.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    path = os.path.join(RESULTS_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_json_safe(payload), f, indent=2)
    return path
