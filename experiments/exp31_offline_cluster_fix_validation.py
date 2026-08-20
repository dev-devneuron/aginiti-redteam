"""exp31 -- OFFLINE, zero-cost validation that `technique_cluster_
diversification_term` (`aginiti/graph/novelty.py`, 2026-08-14) causally
improves WITHIN-family technique diversity. Companion to exp30 (which
validates the CROSS-family fix) -- these are two SEPARATE, real gaps
found in the same exp28 postmortem, fixed by two separate mechanisms, and
validated separately here on purpose (conflating them into one scenario
would make it impossible to tell which fix is doing the work).

============================================================================
WHAT THIS PROVES, STATED PRECISELY: using `aginiti/target/technique_
cluster_scenario_agent.py` (a synthetic target shaped to match the
SPECIFIC exp28 finding family_diversification_term cannot touch -- 5
near-duplicate wrapper variants sharing one `technique_cluster`, at a
real severity edge (weight 8) over 3 genuinely different same-family
techniques (weight 3, no cluster) -- deliberately single-family so
nothing family_diversification_term contributes can differ between
candidates), this script runs FOUR conditions at a tight budget (5,
exactly the cluster's own size):

  pre_fix_aginiti  -- enable_technique_cluster_diversification=False
                      (the exact behavior before this fix existed).
  post_fix_aginiti -- enable_technique_cluster_diversification=True.
  random           -- RandomPolicy, 20 seeded trials.
  static            -- StaticPolicy, 1 trial (deterministic).

Metric: does the campaign find BOTH real findings (the cluster's one real
hypothesis AND the singleton's one real hypothesis) within budget -- a
genuine binary outcome difference, not just a coverage/ordering one (see
exp30 for why that was the right metric THERE; here a binary win is
actually achievable at a realistic budget, confirmed empirically before
writing this script).

Usage:
    python experiments/exp31_offline_cluster_fix_validation.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, ".")

from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.technique_cluster_scenario_definitions import build_technique_cluster_library
from aginiti.operators.library import OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.random_policy import RandomPolicy
from aginiti.core.policies.static_policy import StaticPolicy
from benchmarks.agents.technique_cluster_scenario_agent import TechniqueClusterScenarioAgent

_ROOT = Path(__file__).parent.parent
_RESULTS_DIR = _ROOT / "runs_exp31_offline_cluster_fix_validation"
_RESULTS_DIR.mkdir(exist_ok=True)

_BUDGET = 5  # exactly the cluster's own size -- see module docstring
_N_RANDOM_TRIALS = 20


def _run_once(policy, budget: int) -> dict:
    mission = Mission(goal="offline cluster-diversity validation", success_criteria=("__unreachable__",),
                       budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any")
    library = OperatorLibrary(build_technique_cluster_library())
    agent = TechniqueClusterScenarioAgent()
    result = run_campaign(mission=mission, library=library, agent=agent, policy=policy,
                           ssg=SecurityStateGraph(), max_steps=budget, stop_on_mission_success=True)
    return {
        "operators_executed": result.operators_executed,
        "distinct_findings_found": agent.distinct_findings_found(),
        "ground_truth_mission_achieved": agent.ground_truth_mission_achieved(),
    }


def main() -> None:
    rows = {
        "pre_fix_aginiti": [_run_once(
            AginitiPolicy(AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True,
                                          enable_technique_cluster_diversification=False)), _BUDGET)],
        "post_fix_aginiti": [_run_once(
            AginitiPolicy(AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True,
                                          enable_technique_cluster_diversification=True)), _BUDGET)],
        "static": [_run_once(StaticPolicy(), _BUDGET)],
        "random": [_run_once(RandomPolicy(seed=4000 + i), _BUDGET) for i in range(_N_RANDOM_TRIALS)],
    }

    (_RESULTS_DIR / "exp31_results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")

    print(f"\n{'=' * 90}\nexp31 -- offline technique-cluster-diversity validation (budget={_BUDGET})\n{'=' * 90}")
    print(f"{'condition':<18} {'n':<4} {'both_findings_found':<22} {'avg_findings':<14}")
    for cond, trials in rows.items():
        n = len(trials)
        both = sum(1 for t in trials if t["distinct_findings_found"] == 2)
        avg = sum(t["distinct_findings_found"] for t in trials) / n
        print(f"{cond:<18} {n:<4} {both}/{n:<20} {avg:<14.2f}")

    print(f"\npre_fix_aginiti  sequence: {rows['pre_fix_aginiti'][0]['operators_executed']}")
    print(f"post_fix_aginiti sequence: {rows['post_fix_aginiti'][0]['operators_executed']}")
    print(f"static           sequence: {rows['static'][0]['operators_executed']}")
    print(f"\nWritten: {_RESULTS_DIR / 'exp31_results.json'}")


if __name__ == "__main__":
    main()
