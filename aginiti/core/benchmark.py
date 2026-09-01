"""The 4-condition benchmark (design doc Section 20): Random, Static
enumeration, Memory-guided, and Aginiti run against the SAME reference
target under the SAME budget, repeated trials, same seed per trial index
across all 4 conditions so the policy is the only thing that varies.

This is the experiment that actually tests the Core Hypothesis / RQ1
(Section 5.1) -- everything before this was just proving the plumbing works.

Resumable by design: a free-tier API key's daily token budget does not
reliably cover a full multi-trial x 4-condition run in one sitting (Section
21.5 treats API cost as a tracked project budget, not unlimited -- this is
that constraint showing up for real). `resume_run_id` skips any
(condition, trial) pair whose JSON file already exists on disk and replays
prior memory_guided executions into a fresh OperatorMemory before
continuing, so a run interrupted by a rate limit picks up exactly where it
left off instead of burning tokens re-doing finished trials.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from aginiti.core.campaign import run_campaign
from aginiti.core.trial_logging import load_json, new_run_id, run_dir, save_json, save_trial
from aginiti.core.mission import Mission
from aginiti.operators.definitions import build_library
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.memory_guided_policy import MemoryGuidedPolicy, OperatorMemory
from aginiti.core.policies.random_policy import RandomPolicy
from aginiti.core.policies.static_policy import StaticPolicy
from aginiti.reporting.report import load_run

CONDITIONS = ("random", "static", "memory_guided", "aginiti")


def _demo_agent(seed: int):
    """Lazily imports DemoAgent -- see aginiti/core/campaign.py's
    `_default_demo_agent` for the full rationale (2026-08-20, Slice C):
    `benchmarks/` is excluded from the published wheel, and this whole
    module is itself shipped inside the `aginiti` package
    (`aginiti.core.benchmark`), so a top-level import here would break
    `import aginiti.core.benchmark` for any real pip install even though
    `run_benchmark()` is, by design, always specifically benchmarking
    against the reference DemoAgent target (unlike run_campaign, it takes
    no agent= override -- that's this module's actual job, not a
    convenience default)."""
    from benchmarks.agents.demo_agent import DemoAgent
    return DemoAgent(seed=seed)


def _build_policy(condition: str, memory: OperatorMemory, seed: int):
    if condition == "random":
        return RandomPolicy(seed=seed)
    if condition == "static":
        return StaticPolicy()
    if condition == "memory_guided":
        return MemoryGuidedPolicy(memory, seed=seed)
    if condition == "aginiti":
        return AginitiPolicy()
    raise ValueError(f"unknown condition: {condition}")


@dataclass
class ConditionSummary:
    condition: str
    trials: int
    successes: int
    success_rate: float
    mean_prompts_used: float
    mean_prompts_used_on_success: float | None
    mean_operators_executed: float
    mean_operators_considered: float
    mean_operators_rejected: float
    mean_useful_observations: float
    signal_efficiency: float  # fraction of executed operators that confirmed at least one effect
    belief_accuracy: float  # fraction of trials where the claimed outcome matched ground truth
    winning_paths: dict  # {mission_claim_key: count of SUCCESS trials that won via it}


def run_benchmark(mission: Mission, n_trials: int = 5, base_seed: int = 1000,
                   max_steps: int = 25, log_base_dir: str = "runs",
                   resume_run_id: str | None = None) -> dict:
    library = build_library()
    mission_meta = {
        "goal": mission.goal,
        "success_criteria": list(mission.success_criteria),
        "budget": mission.budget,
        "risk_threshold": mission.risk_threshold.value,
    }

    if resume_run_id:
        run_id = resume_run_id
        out_dir = run_dir(run_id, base=log_base_dir)
        meta_path = os.path.join(out_dir, "meta.json")
        if os.path.exists(meta_path):
            mission_meta = load_json(meta_path).get("mission", mission_meta)
    else:
        run_id = new_run_id()
        out_dir = run_dir(run_id, base=log_base_dir)
        # Written immediately, before any trial runs, so a report can be generated
        # from a partial/interrupted run -- not just from a clean completion.
        save_json(f"{out_dir}/meta.json", {
            "run_id": run_id, "mission": mission_meta, "n_trials": n_trials,
            "base_seed": base_seed, "conditions": list(CONDITIONS),
        })

    memory = OperatorMemory()  # persists across memory_guided's own trials, per its design
    for record in _existing_trials(out_dir, "memory_guided"):
        for e in record.get("execution_log", []):
            memory.record(e["operator_id"], e["overall_success"])

    for trial in range(n_trials):
        seed = base_seed + trial  # identical seed across all 4 conditions at this trial index
        for condition in CONDITIONS:
            trial_path = os.path.join(out_dir, f"{condition}_trial{trial:02d}.json")
            if os.path.exists(trial_path):
                print(f"[{run_id}] trial {trial} | {condition:14s} -> (already logged, skipping)")
                continue
            agent = _demo_agent(seed=seed)
            policy = _build_policy(condition, memory, seed)
            t0 = time.time()
            result = run_campaign(mission, library, agent=agent, policy=policy,
                                   max_steps=max_steps, seed=seed)
            elapsed = time.time() - t0
            save_trial(out_dir, condition, trial, seed, result)
            if condition == "memory_guided":
                for exec_result in result.execution_log:
                    memory.record(exec_result.operator_id, exec_result.overall_success)
            print(f"[{run_id}] trial {trial} | {condition:14s} -> {result.outcome:16s} "
                  f"({result.prompts_used} prompts, {elapsed:.1f}s)")

    data = load_run(out_dir)
    summaries = [ConditionSummary(condition=c, **data["summaries"][c]) for c in CONDITIONS]
    summary_record = {
        "run_id": run_id,
        "mission": mission_meta,
        "n_trials": n_trials,
        "base_seed": base_seed,
        "conditions": [vars(s) for s in summaries],
    }
    save_json(f"{out_dir}/summary.json", summary_record)
    return {"run_id": run_id, "out_dir": out_dir, "summaries": summaries}


def _existing_trials(out_dir: str, condition: str) -> list[dict]:
    if not os.path.isdir(out_dir):
        return []
    records = []
    for fname in sorted(os.listdir(out_dir)):
        if fname.startswith(f"{condition}_trial") and fname.endswith(".json"):
            records.append(load_json(os.path.join(out_dir, fname)))
    return records
