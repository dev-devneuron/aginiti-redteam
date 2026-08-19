"""exp30 -- OFFLINE, zero-cost validation that the 2026-08-14 `PROACTIVE_
COVERAGE_BONUS` fix (`aginiti/graph/novelty.py`) causally improves family
coverage, run BEFORE spending any live budget on a corrected live
experiment (see `experiments/exp29_rq1_hardened_agent_live_fresh_state.py`
for the live follow-up this offline check exists to justify running).

============================================================================
WHAT THIS PROVES, STATED PRECISELY -- no more, no less: using
`aginiti/target/family_coverage_scenario_agent.py` (a synthetic target
deliberately shaped to match exp28's real `hardened_agent` finding -- a
15-member family whose first attempt already succeeds, sitting alongside
a 26-member family that's never been touched), this script runs FOUR
conditions at the SAME budget exp28 actually used (18):

  pre_fix_aginiti  -- AginitiPlanner with family_diversification_term()
                      monkeypatched back to its exact pre-2026-08-14
                      behavior (0.0 for a genuinely untried family unless
                      another family ALREADY looks_saturated).
  post_fix_aginiti -- AginitiPlanner with the current, fixed code.
  random           -- RandomPolicy, 20 seeded trials (this scenario has no
                      target-side randomness, so 20 different orderings is
                      what gives this condition genuine statistical power,
                      unlike aginiti/static which are fully deterministic
                      given the scenario -- confirmed, not assumed, by
                      exp28's own postmortem).
  static            -- StaticPolicy, 1 trial (deterministic by design, see
                      random_policy.py/static_policy.py's own docstrings
                      -- repeating it would not add information).

Two metrics, matching exp28's own `_distinct_findings` proxy plus the
literal complaint that motivated the fix ("it never reached... several
other attack families"):

  1. distinct_families_touched -- how many of the 2 families got ANY
     attempt within budget.
  2. step_family_b_first_touched -- how EARLY the second family first got
     sampled (None if never within budget) -- this is where the fix's
     real, but modest, effect actually shows up (see the script's own
     printed caveat below): the fix does not turn the planner into a
     breadth-first search of the whole library. It costs roughly one
     extra step to take ONE early exploratory sample of a second family
     before returning to systematically drain whichever family still has
     high-value untried members -- a real, verified, honest improvement
     over pre-fix code's ZERO early samples of any second family, not a
     complete fix for "explore every family early."

Usage:
    python experiments/exp30_offline_planner_fix_validation.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, ".")

import aginiti.graph.novelty as nv
from aginiti.campaign import run_campaign
from aginiti.graph.attack_category import operator_primary_family
from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.family_coverage_scenario_definitions import build_family_coverage_library
from aginiti.operators.library import OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.random_policy import RandomPolicy
from aginiti.policies.static_policy import StaticPolicy
from aginiti.target.family_coverage_scenario_agent import FamilyCoverageScenarioAgent

_ROOT = Path(__file__).parent.parent
_RESULTS_DIR = _ROOT / "runs_exp30_offline_planner_fix_validation"
_RESULTS_DIR.mkdir(exist_ok=True)

# Two budgets, deliberately: 18 matches exp28/29's own real live budget
# (the number that actually matters for judging the live follow-up), but
# at that budget EVERY condition -- including the fully non-adaptive
# `static` checklist -- is forced into family_b anyway, simply because
# family_a only has 15 members and 18 > 15. That makes 18 uninformative
# for isolating the fix's own effect (confirmed empirically: all 4
# conditions tie on distinct_families_touched at budget=18 below). 10 is
# comfortably inside family_a's size, so it's the budget that actually
# shows whether something OTHER than "eventually running out of same-
# family options" pushed toward a second family.
_BUDGETS = (10, 18)
_N_RANDOM_TRIALS = 20

_pre_fix_family_diversification_term = None  # filled in by _install_pre_fix_term()


def _pre_fix_term(attack_category, belief):
    """The EXACT pre-2026-08-14 family_diversification_term() body,
    reproduced here (not imported -- the original no longer exists in
    novelty.py) so this script can A/B against the real fix rather than
    only asserting it changed something. See aginiti/graph/novelty.py's
    own module docstring for the real diff."""
    if attack_category is None:
        return 0.0
    stats = belief.family(attack_category)
    if stats.looks_saturated:
        extra_attempts = stats.confirmed_total - 1
        penalty = min(nv.MAX_SATURATION_PENALTY, nv.SATURATION_PENALTY_PER_EXTRA_ATTEMPT * extra_attempts)
        return -penalty
    if stats.attempted == 0:
        any_other_saturated = any(
            other.looks_saturated for name, other in belief.family_stats.items() if name != attack_category
        )
        if any_other_saturated:
            return nv.DIVERSIFICATION_BONUS
        return 0.0
    return 0.0


def _run_once(policy, budget: int) -> dict:
    mission = Mission(goal="offline family-coverage validation", success_criteria=("__unreachable__",),
                       budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any")
    library = OperatorLibrary(build_family_coverage_library())
    agent = FamilyCoverageScenarioAgent()
    result = run_campaign(mission=mission, library=library, agent=agent, policy=policy,
                           ssg=SecurityStateGraph(), max_steps=budget, stop_on_mission_success=True)

    families_touched = []
    step_b_first = None
    for i, op_id in enumerate(result.operators_executed):
        op = library.get(op_id)
        fam = operator_primary_family(op)
        if fam not in families_touched:
            families_touched.append(fam)
        if op_id.startswith("family_b_probe") and step_b_first is None:
            step_b_first = i

    return {
        "operators_executed": result.operators_executed,
        "distinct_families_touched": len(families_touched),
        "families_touched": families_touched,
        "step_family_b_first_touched": step_b_first,
        "distinct_secrets_found": agent.distinct_secrets_found(),
        "ground_truth_mission_achieved": agent.ground_truth_mission_achieved(),
    }


def _run_all_conditions(budget: int) -> dict:
    rows = {}

    # -- pre_fix_aginiti: monkeypatch, run, ALWAYS restore immediately -----
    real_term = nv.family_diversification_term
    nv.family_diversification_term = _pre_fix_term
    try:
        planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
        rows["pre_fix_aginiti"] = [_run_once(AginitiPolicy(planner), budget)]
    finally:
        nv.family_diversification_term = real_term  # restore the REAL fixed code immediately

    # -- post_fix_aginiti: current, unmodified code -------------------------
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    rows["post_fix_aginiti"] = [_run_once(AginitiPolicy(planner), budget)]

    # -- static: deterministic, one trial is genuinely representative -------
    rows["static"] = [_run_once(StaticPolicy(), budget)]

    # -- random: N seeded trials -- this IS where real variance lives -------
    rows["random"] = [_run_once(RandomPolicy(seed=2000 + i), budget) for i in range(_N_RANDOM_TRIALS)]

    return rows


def main() -> None:
    all_results = {}

    for budget in _BUDGETS:
        rows = _run_all_conditions(budget)
        all_results[str(budget)] = rows

        print(f"\n{'=' * 90}\nexp30 -- offline family-coverage validation (budget={budget})\n{'=' * 90}")
        print(f"{'condition':<18} {'n':<4} {'avg_families_touched':<22} {'pct_touched_family_b':<22} {'avg_secrets_found':<18}")
        for cond, trials in rows.items():
            n = len(trials)
            avg_fams = sum(t["distinct_families_touched"] for t in trials) / n
            pct_b = 100.0 * sum(1 for t in trials if t["step_family_b_first_touched"] is not None) / n
            avg_secrets = sum(t["distinct_secrets_found"] for t in trials) / n
            print(f"{cond:<18} {n:<4} {avg_fams:<22.2f} {pct_b:<22.1f} {avg_secrets:<18.2f}")

        print(f"\npre_fix_aginiti  sequence: {rows['pre_fix_aginiti'][0]['operators_executed']}")
        print(f"post_fix_aginiti sequence: {rows['post_fix_aginiti'][0]['operators_executed']}")
        print(f"static           sequence: {rows['static'][0]['operators_executed']}")

    (_RESULTS_DIR / "exp30_results.json").write_text(json.dumps(all_results, indent=2), encoding="utf-8")

    print(f"\n{'=' * 90}")
    print("CAVEAT, stated honestly rather than left implicit: this scenario has only 2")
    print("families, matching the real op-count of hardened_agent's direct_prompt_attack (15)")
    print("and encoding_attack (26) -- but real exp28 also revealed a SEPARATE, WITHIN-family")
    print("gap (most of direct_prompt_attack's own 15 distinct techniques -- system_prompt_")
    print("extraction, session_isolation_probe, secret_pattern_fishing, own_domain_verbatim_")
    print("probe -- were never tried either, even though they share a family with what WAS")
    print("tried). Family-level diversification structurally cannot fix that: it only pushes")
    print("toward OTHER untried families, never toward untried MEMBERS of an already-attempted")
    print("family. This run validates the cross-family fix only -- it does not claim to have")
    print("closed the within-family gap.")
    print(f"\nWritten: {_RESULTS_DIR / 'exp30_results.json'}")


if __name__ == "__main__":
    main()
