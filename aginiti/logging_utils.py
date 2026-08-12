"""Persistent, complete result logging. Every trial's full decision trace,
raw target transcripts, and final Security State Graph are written to disk
as JSON -- not just a terminal print that scrolls away. This is the durable
record the benchmark report (scripts/generate_report.py) reads back to
produce verifiable proof of what actually happened, not a summary claim.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum

from aginiti.campaign import CampaignResult


def _json_safe(obj):
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _json_safe(v) for k, v in asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def campaign_result_to_dict(condition: str, trial: int, seed: int | None, result: CampaignResult) -> dict:
    return {
        "condition": condition,
        "trial": trial,
        "seed": seed,
        "outcome": result.outcome,
        "steps_executed": result.steps_executed,
        "prompts_used": result.prompts_used,
        "operators_executed": result.operators_executed,
        "operators_considered_total": result.operators_considered_total,
        "decision_log": [_json_safe(d) for d in result.decision_log],
        "execution_log": [_json_safe(e) for e in result.execution_log],
        "final_claims": [
            {"key": c.key, "object": c.object, "status": c.status.value,
             "confidence": c.confidence.value, "id": c.id, "supersedes": c.supersedes,
             # 2026-08-12, added ahead of the next benchmark run (severity is one of its
             # named metrics): these 4 dimensions were fully wired into the SSG and the
             # Target Profile/graph-export reports, but this trial-log serializer -- the
             # one every experiment's own analysis script actually reads -- never carried
             # them, so a saved trial file couldn't answer "how severe was this finding"
             # without re-running the whole campaign against a live target to re-derive it.
             "security_boundary": result.ssg.claim_boundary.get(c.key),
             "owasp_llm_category": result.ssg.claim_owasp_category.get(c.key),
             "attack_category": result.ssg.claim_attack_category.get(c.key),
             "mitre_atlas_technique": result.ssg.claim_atlas_technique.get(c.key),
             # 2026-08-12 hardening-pass fix: failure_diagnosis (Issue 4, added
             # earlier the same day) was never added here -- the exact same
             # "new taxonomy dimension, old serializer" bug this file's own
             # comment above already documents being fixed once for the other
             # four dimensions. A saved trial file couldn't answer "why did
             # this specific attempt fail" without re-running the campaign.
             "failure_diagnosis": result.ssg.claim_failure_diagnosis.get(c.key)}
            for c in result.ssg.claims
        ],
        # Headline rollups, same SSG methods target_profile.py's report now calls --
        # computed once here so an analysis script reading the saved JSON doesn't have
        # to reconstruct an SSG from final_claims just to re-derive them.
        "highest_boundary_crossed": result.ssg.highest_boundary_crossed(),
        "owasp_category_summary": result.ssg.owasp_category_summary(),
        "attack_category_summary": result.ssg.attack_category_summary(),
        "confirmed_atlas_techniques": result.ssg.confirmed_atlas_techniques(),
        "graph_size": result.ssg.size(),
        "ground_truth_mission_achieved": (
            result.execution_log[-1].ground_truth_mission_achieved if result.execution_log else False
        ),
    }


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run_dir(run_id: str, base: str = "runs") -> str:
    path = os.path.join(base, run_id)
    os.makedirs(path, exist_ok=True)
    return path


def save_trial(run_dir_path: str, condition: str, trial: int, seed: int | None,
                result: CampaignResult) -> str:
    record = campaign_result_to_dict(condition, trial, seed, result)
    path = os.path.join(run_dir_path, f"{condition}_trial{trial:02d}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return path


def save_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_json_safe(obj), f, indent=2)


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
