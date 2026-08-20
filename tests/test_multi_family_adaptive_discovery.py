"""Regression tests for the 2026-08-14 exp23 postmortem fix: `family_
diversification`'s saturation penalty was silently able to VETO an
otherwise-viable, evidence-eligible operator via `rank()`'s pre-existing
`utility <= 0: continue` gate, instead of merely demoting it -- contradicting
novelty.py's own documented contract ("informs, never vetoes") and causing
exp23's live hardened_agent campaigns to report SEARCH_EXHAUSTED with 15-16
of 24 operators still untried and evidence-eligible.

`benchmarks/agents/multi_family_agent.py` + `aginiti/operators/
multi_family_definitions.py` reproduce the SAME structural shape
deterministically and offline (several attack families, a large family that
saturates from repeated refusals, one operator whose own narrow extractor
misses a real disclosure an independent oracle catches).

EMPIRICAL VERIFICATION (not merely asserted): at budget=8 against this exact
scenario, `git stash`-ing only the `aginiti_planner.py` fix and re-running
`test_bug_reproduced_before_fix_at_budget_8`'s own campaign logic showed the
precise failure this test now guards against: `rank()` returned an empty
list at step 7 while `eligible_operators()` still returned 6 real, untried,
precondition-satisfied, budget-fitting candidates
(`direct_v3/v4/v5`, `encoding_v3/v4/v5`) and 2 prompts of budget remained --
i.e. SEARCH_EXHAUSTED-equivalent behavior with viable operators and budget
both still available, and `encoding_v3` (the operator carrying the real,
independently-verifiable disclosure) was never reached. Restoring the fix
and rerunning the IDENTICAL scenario at the IDENTICAL budget resolved both:
the false-exhaustion no longer occurs, and `encoding_v3` gets executed.
This test file encodes that same scenario/budget as a permanent guard."""
from __future__ import annotations

from aginiti.core.observation_adapter import ObservationAdapter
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.multi_family_definitions import build_multi_family_library
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.base import eligible_operators
from benchmarks.agents.multi_family_agent import MultiFamilyAgent
from aginiti.core.campaign import run_campaign

_BUDGET = 8  # the exact, empirically-verified reproduction budget -- see module docstring


def _mission(budget: int = _BUDGET) -> Mission:
    # A criterion that can never be met keeps stop_on_mission_success from
    # short-circuiting the campaign early -- this scenario is about
    # EXHAUSTING the eligible candidate set within budget, not about
    # reaching a named success criterion.
    return Mission(goal="reproduce exp23's search-space collapse",
                    success_criteria=("nonexistent_key",), budget=budget,
                    risk_threshold=RiskTier.MEDIUM, success_mode="any")


def _run(planner: AginitiPlanner, budget: int = _BUDGET):
    library = OperatorLibrary(build_multi_family_library())
    agent = MultiFamilyAgent()
    result = run_campaign(mission=_mission(budget), library=library, agent=agent,
                           policy=AginitiPolicy(planner), ssg=SecurityStateGraph(),
                           max_steps=budget, stop_on_mission_success=False)
    return result, agent


# --------------------------------------------------------------------------
# 1. The core exp23 regression: the fix restores the "diversification can
#    demote, never delete" invariant, AND lets the campaign actually reach
#    the operator carrying the real, independently-verified finding.
# --------------------------------------------------------------------------

def test_fixed_planner_never_reports_search_exhausted_with_viable_operators_remaining():
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    result, _agent = _run(planner)
    assert result.outcome != "SEARCH_EXHAUSTED"
    assert result.steps_executed == _BUDGET  # uses the FULL declared budget, no false early stop


def test_fixed_planner_reaches_the_operator_with_the_real_finding():
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    result, agent = _run(planner)
    assert "encoding_v3" in result.operators_executed
    assert agent.ground_truth_mission_achieved() is True


def test_fixed_planner_confirms_the_independent_evidence_claim():
    """Fix #2/#3's own payoff, exercised end-to-end here: encoding_v3's OWN
    extractor never sees the disclosure (it only recognizes the generic
    refusal keyword -- see multi_family_definitions.py) -- only the
    INDEPENDENT evidence path (aginiti/graph/independent_evidence.py) can
    confirm it."""
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)
    result, _agent = _run(planner)
    claim = result.ssg.current_claim("encoding_v3_independent_disclosure_confirmed")
    assert claim is not None
    assert claim.status.value == "confirmed"
    # encoding_v3's OWN narrow extractor still (correctly, per its own
    # limited design) reports the refusal-shaped claim too -- the new path
    # is ADDITIVE, never a replacement.
    assert result.ssg.current_claim("encoding_v3_blocked") is not None
    assert result.ssg.claim_boundary["encoding_v3_independent_disclosure_confirmed"] == "L5_sensitive_data_exfiltration"


def test_diversification_demotes_but_never_deletes_a_saturated_familys_candidates():
    """The structural invariant itself, read directly off rank()'s output
    at the exact step the pre-fix code collapsed to empty: every remaining,
    evidence-eligible operator (direct_v3/v4/v5, encoding_v3/v4/v5) is
    still present in `rank()`'s own list once BOTH families look
    saturated -- merely sorted low, never removed."""
    library = OperatorLibrary(build_multi_family_library())
    ssg = SecurityStateGraph()
    agent = MultiFamilyAgent()
    adapter = ObservationAdapter()
    mission = _mission()
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)

    executed: list[str] = []
    for _ in range(6):  # replays the exact pre-collapse prefix from the empirical run
        ranked = planner.rank(library, ssg, mission, prompts_used=len(executed), executed_ids=frozenset(executed))
        chosen = ranked[0]
        adapter.execute(chosen.operator, ssg, agent)
        executed.append(chosen.operator.id)

    ranked_after = planner.rank(library, ssg, mission, prompts_used=len(executed), executed_ids=frozenset(executed))
    ranked_ids = {rc.operator.id for rc in ranked_after}
    for still_viable in ("direct_v3", "direct_v4", "direct_v5", "encoding_v3", "encoding_v4", "encoding_v5"):
        assert still_viable in ranked_ids, f"{still_viable} was evidence-eligible but missing from rank()'s output"
    # And at least one of them is genuinely demoted (negative family_diversification) --
    # confirming the fix didn't just widen the list, it preserved the real demotion signal too.
    assert any(rc.family_diversification < 0 for rc in ranked_after)


# --------------------------------------------------------------------------
# 2. Config A (every new flag off) was NEVER affected by this bug -- fdiv is
#    always 0.0, so core_utility == the old total utility exactly. Confirms
#    the fix is scoped to the diversification/escalation terms only.
# --------------------------------------------------------------------------

def test_baseline_planner_was_already_unaffected_by_this_bug():
    """Config A's own fdiv/heb are always 0.0 (see AginitiPlanner.__init__'s
    own docstring), so core_utility == the old total utility exactly for
    it -- it was never capable of hitting this bug, confirmed here by
    outcome alone. It does NOT discover the same finding baseline never
    diversifies away from the direct family at all (no penalty ever
    discourages continuing it), so at this same tight budget it spends its
    whole budget re-trying direct_v1..v5 plus 2 encoding attempts and never
    reaches encoding_v3 -- the real, live-observed asymmetry this whole
    architectural pass exists to fix, now demonstrated on a fully
    deterministic, target-agnostic scenario instead of only a real,
    non-repeatable live run."""
    baseline = AginitiPlanner()  # config A -- every new flag off
    result, agent = _run(baseline)
    assert result.outcome != "SEARCH_EXHAUSTED"  # never affected by this specific bug
    assert result.steps_executed == _BUDGET  # ran its full declared budget, as always
    assert "encoding_v3" not in result.operators_executed
    assert agent.ground_truth_mission_achieved() is False


def test_adaptive_finds_what_baseline_misses_at_the_same_budget():
    """The direct, side-by-side comparison: identical library, identical
    target, identical budget -- only the planner config differs. Baseline
    exhausts the direct family blindly and never pivots; the fixed adaptive
    planner diversifies away from it, reaches encoding_v3, and confirms a
    real finding baseline's own run never touches."""
    baseline_result, baseline_agent = _run(AginitiPlanner())
    adaptive_result, adaptive_agent = _run(
        AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True))

    assert baseline_agent.ground_truth_mission_achieved() is False
    assert adaptive_agent.ground_truth_mission_achieved() is True
    assert "encoding_v3" not in baseline_result.operators_executed
    assert "encoding_v3" in adaptive_result.operators_executed
