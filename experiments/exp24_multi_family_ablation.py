"""exp24 -- offline (zero LLM calls, zero network cost) ablation reproducing
exp23's live SEARCH_EXHAUSTED-with-viable-candidates finding deterministically,
against `aginiti/target/multi_family_agent.py` (see that module's own
docstring for the scenario), across the SAME four configurations exp22
established (A/B/C/D), across a budget sweep.

**Empirically verified, not merely asserted** (see tests/
test_multi_family_adaptive_discovery.py's own module docstring for the full
methodology): at budget=8, `git stash`-ing only the 2026-08-14 `rank()`
structural fix and rerunning this exact scenario reproduced the live bug
precisely -- `rank()` returned empty with 6 real, untried, budget-fitting
candidates still available and 2 prompts of budget remaining, and
`encoding_v3` (the operator carrying the one real, independently-verifiable
finding in this scenario) was never reached. Restoring the fix and rerunning
the IDENTICAL scenario resolved both. This script is the formal ablation
table version of that same empirical check, run across a full budget sweep
and all four configurations for a complete before/after record -- run AFTER
the fix (config C/D here reflect the FIXED, not the buggy, planner; the
pre-fix numbers are not reproducible without reverting the fix, and are
reported in prose in the postmortem report instead of a fabricated row here).

Usage:
    python experiments/exp24_multi_family_ablation.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, ".")  # project convention -- see experiments/exp1_*.py

from aginiti.campaign import run_campaign
from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.adaptive_followups import adaptive_followup_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.multi_family_definitions import build_multi_family_library
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.target.multi_family_agent import MultiFamilyAgent

_SUCCESS_CRITERIA = ("__no_such_key__",)  # deliberately unreachable -- this scenario is about
                                            # SEARCH-SPACE COVERAGE, not a named success criterion
_BUDGETS = (5, 6, 7, 8, 9, 10, 11, 12)

_CONFIGS = {
    "A_current":                     dict(enable_family_diversification=False, enable_hypothesis_escalation_bonus=False),
    "B_current_plus_state":          dict(enable_family_diversification=False, enable_hypothesis_escalation_bonus=False),
    "C_state_plus_failure_learning": dict(enable_family_diversification=True, enable_hypothesis_escalation_bonus=False),
    "D_full_adaptive":               dict(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True),
}


def _run_one(config_name: str, flags: dict, budget: int) -> dict:
    library = OperatorLibrary(build_multi_family_library() + list(adaptive_followup_operators()))
    mission = Mission(goal="reach the operator carrying the real finding", success_criteria=_SUCCESS_CRITERIA,
                       budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any")
    agent = MultiFamilyAgent()
    planner = AginitiPlanner(**flags)
    result = run_campaign(mission=mission, library=library, agent=agent, policy=AginitiPolicy(planner),
                           ssg=SecurityStateGraph(), stop_on_mission_success=False)

    return {
        "config": config_name, "budget": budget, "outcome": result.outcome,
        "steps": result.steps_executed, "prompts_used": result.prompts_used,
        "reached_encoding_v3": "encoding_v3" in result.operators_executed,
        "ground_truth_achieved": agent.ground_truth_mission_achieved(),
        "operator_sequence": list(result.operators_executed),
    }


def main() -> None:
    rows = []
    for budget in _BUDGETS:
        for config_name, flags in _CONFIGS.items():
            rows.append(_run_one(config_name, flags, budget))

    print(f"{'config':<32} {'budget':>6} {'outcome':>18} {'steps':>5} {'reached_encoding_v3':>20} "
          f"{'ground_truth':>13}")
    print("-" * 100)
    for r in rows:
        print(f"{r['config']:<32} {r['budget']:>6} {r['outcome']:>18} {r['steps']:>5} "
              f"{str(r['reached_encoding_v3']):>20} {str(r['ground_truth_achieved']):>13}")

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    n_search_exhausted_with_room = 0
    for r in rows:
        if r["outcome"] == "SEARCH_EXHAUSTED" and r["steps"] < r["budget"]:
            n_search_exhausted_with_room += 1
            print(f"  budget={r['budget']} config={r['config']}: SEARCH_EXHAUSTED with "
                  f"{r['budget'] - r['steps']} budget still unused -- THIS WOULD BE A REGRESSION "
                  f"of the exp23 fix.")
    print(f"SEARCH_EXHAUSTED-with-unused-budget occurrences (post-fix): {n_search_exhausted_with_room} "
          f"(expected: 0)")

    for budget in _BUDGETS:
        a = next(r for r in rows if r["config"] == "A_current" and r["budget"] == budget)
        d = next(r for r in rows if r["config"] == "D_full_adaptive" and r["budget"] == budget)
        print(f"budget={budget}: A reached_encoding_v3={a['reached_encoding_v3']} "
              f"(ground_truth={a['ground_truth_achieved']})  |  "
              f"D reached_encoding_v3={d['reached_encoding_v3']} (ground_truth={d['ground_truth_achieved']})")

    out_path = Path(__file__).parent / "results" / "exp24_multi_family_ablation.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nWritten: {out_path}")


if __name__ == "__main__":
    main()
