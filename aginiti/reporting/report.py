"""Loads a benchmark run's on-disk JSON logs and computes the summary
directly from what's actually there. Always recomputed from the raw trial
files rather than trusted from summary.json, so a report can be generated
from a run that's still in progress or was interrupted partway through
(e.g. an API rate limit) -- partial, verifiable data beats a promise that
the full run would have looked a certain way.

Moved here from aginiti/core/report.py -- report-generation code belongs
in aginiti/reporting/ alongside markdown_report.py, mia_metrics.py, and
interrogation_reparse.py, not scattered into core/. aginiti/core/report.py
remains a backward-compatible re-export shim.
"""
from __future__ import annotations

import glob
import os
from collections import Counter

from aginiti.core.stats import compare_to_aginiti
from aginiti.core.trial_logging import load_json

CONDITION_ORDER = ("random", "static", "memory_guided", "aginiti")
CONDITION_LABELS = {
    "random": "Random",
    "static": "Static enumeration",
    "memory_guided": "Memory-guided",
    "aginiti": "Aginiti",
}


def load_run(run_dir_path: str) -> dict:
    meta = {}
    for fname in ("meta.json", "summary.json"):
        fpath = os.path.join(run_dir_path, fname)
        if os.path.exists(fpath):
            meta = load_json(fpath)
            break

    mission_keys = tuple(meta.get("mission", {}).get("success_criteria", ()))

    trials_by_condition: dict[str, list[dict]] = {c: [] for c in CONDITION_ORDER}
    for fpath in sorted(glob.glob(os.path.join(run_dir_path, "*_trial*.json"))):
        record = load_json(fpath)
        cond = record.get("condition")
        if cond in trials_by_condition:
            trials_by_condition[cond].append(record)

    summaries = {c: _summarize(trials_by_condition[c], mission_keys) for c in CONDITION_ORDER}

    comparisons = []
    aginiti_summary = summaries["aginiti"]
    if aginiti_summary["trials"] > 0:
        for c in ("random", "static", "memory_guided"):
            if summaries[c]["trials"] > 0:
                comparisons.append(compare_to_aginiti(
                    aginiti_summary["successes"], aginiti_summary["trials"],
                    CONDITION_LABELS[c], summaries[c]["successes"], summaries[c]["trials"],
                ))

    return {
        "run_id": meta.get("run_id", os.path.basename(run_dir_path.rstrip("/\\"))),
        "mission": meta.get("mission", {}),
        "n_trials_planned": meta.get("n_trials"),
        "base_seed": meta.get("base_seed"),
        "trials_by_condition": trials_by_condition,
        "summaries": summaries,
        "comparisons": comparisons,
    }


def _winning_path(trial: dict, mission_keys: tuple[str, ...]) -> str | None:
    if trial.get("outcome") != "SUCCESS":
        return None
    confirmed = {c["key"] for c in trial.get("final_claims", []) if c.get("status") == "confirmed"}
    for key in mission_keys:
        if key in confirmed:
            return key
    return None


def _summarize(trials: list[dict], mission_keys: tuple[str, ...] = ()) -> dict:
    n = len(trials)
    successes = [t for t in trials if t.get("outcome") == "SUCCESS"]
    correct = sum(
        1 for t in trials
        if (t.get("outcome") == "SUCCESS") == bool(t.get("ground_truth_mission_achieved"))
    )

    # Search efficiency: how much of what was "considered" actually got
    # run, and how much of what got run actually taught the SSG something
    # (vs. burning a prompt on an operator whose evidence confirmed
    # nothing at all -- not even a defender-block claim).
    rejected = [t["operators_considered_total"] - len(t["operators_executed"]) for t in trials]
    useful_counts, executed_counts = [], []
    for t in trials:
        executed_counts.append(len(t["operators_executed"]))
        exec_log = t.get("execution_log", [])
        useful_counts.append(sum(1 for e in exec_log if e.get("confirmed_keys")))

    winning_paths = Counter(
        wp for t in trials if (wp := _winning_path(t, mission_keys)) is not None
    )

    total_useful = sum(useful_counts)
    total_executed = sum(executed_counts)

    return {
        "trials": n,
        "successes": len(successes),
        "success_rate": (len(successes) / n) if n else 0.0,
        "mean_prompts_used": (sum(t["prompts_used"] for t in trials) / n) if n else 0.0,
        "mean_prompts_used_on_success": (
            sum(t["prompts_used"] for t in successes) / len(successes) if successes else None
        ),
        "mean_operators_executed": (sum(executed_counts) / n) if n else 0.0,
        "mean_operators_considered": (
            sum(t["operators_considered_total"] for t in trials) / n
        ) if n else 0.0,
        "mean_operators_rejected": (sum(rejected) / n) if n else 0.0,
        "mean_useful_observations": (sum(useful_counts) / n) if n else 0.0,
        "signal_efficiency": (total_useful / total_executed) if total_executed else 0.0,
        "belief_accuracy": (correct / n) if n else 0.0,
        "winning_paths": dict(winning_paths),
    }
