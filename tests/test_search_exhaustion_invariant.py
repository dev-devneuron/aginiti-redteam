"""The general invariant requested directly following exp23: "Remaining
budget + eligible operators > 0 must not produce SEARCH_EXHAUSTED." Checked
at EVERY step of EVERY campaign across a budget sweep (not just the final
outcome of one scenario -- see test_multi_family_adaptive_discovery.py for
the specific exp23 reproduction), and against BOTH the hidden_state_agent
and multi_family_agent synthetic scenarios, so this is a property of
`AginitiPlanner.rank()` itself, not an artifact of one target's shape.

Also exercises `AginitiPlanner.diagnose()` (aginiti/graph/candidate_
status.py): every operator NOT in `rank()`'s own output must have a
recorded, valid exclusion reason -- "if an operator is intentionally
excluded, record exactly why," checked structurally rather than by eye."""
from __future__ import annotations

import pytest

from aginiti.core.observation_adapter import ObservationAdapter
from aginiti.core.graph.candidate_status import CandidateStatus
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.hidden_state_definitions import build_hidden_state_library
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.multi_family_definitions import build_multi_family_library
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.base import eligible_operators
from aginiti.target.hidden_state_agent import HiddenStateAgent
from aginiti.target.multi_family_agent import MultiFamilyAgent

_SCENARIOS = {
    "multi_family": (build_multi_family_library, MultiFamilyAgent),
    "hidden_state": (build_hidden_state_library, HiddenStateAgent),
}
_CONFIGS = {
    "A_baseline": dict(enable_family_diversification=False, enable_hypothesis_escalation_bonus=False),
    "D_full_adaptive": dict(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True),
}


def _drive_and_check_invariant(build_library, build_agent, flags: dict, budget: int) -> None:
    """The precise invariant this guards is narrower than "any eligible
    operator" -- two PRE-EXISTING, already-validated hard gates
    (`budget_feasible()`'s provable chain-infeasibility bound, and
    `core_utility <= 0`'s "no evidence-based value left") are legitimate,
    explicit, evidence-based reasons an eligible operator can still be
    excluded (exactly the "unless there is an explicit, evidence-based
    reason" clause of the requirement this test encodes) -- see aginiti/
    graph/candidate_status.py's own taxonomy. What must NEVER happen is an
    operator with genuine remaining `core_utility > 0` (real evidence-based
    value) disappearing from `rank()`'s output solely because a soft
    exploration nudge (family_diversification/hypothesis_escalation_bonus)
    pushed its TOTAL utility negative -- that is exactly, and only, the
    exp23 bug. `planner._score()` is read directly (white-box, same
    discipline test_hidden_state_adaptive_discovery.py already uses reading
    `RankedCandidate.family_diversification`) so this test can tell the two
    apart precisely instead of approximating with a looser proxy."""
    library = OperatorLibrary(build_library())
    ssg = SecurityStateGraph()
    agent = build_agent()
    adapter = ObservationAdapter()
    mission = Mission(goal="invariant sweep", success_criteria=("__no_such_key__",),
                       budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any")
    planner = AginitiPlanner(**flags)

    executed: list[str] = []
    for step in range(budget + 2):
        prompts_used = len(executed)
        budget_remaining = budget - prompts_used
        alpha, beta = planner._schedule(ssg, prompts_used, mission.budget)
        recency_window = max(4, 2 * mission.budget)
        belief = None
        if planner.enable_family_diversification:
            from aginiti.core.graph.target_belief import TargetBeliefState
            belief = TargetBeliefState.from_ssg(ssg, library)

        elig = eligible_operators(library, ssg, mission, prompts_used, frozenset(executed))
        genuinely_viable = []
        for op in elig:
            if not planner.budget_feasible(op, mission, library, budget_remaining):
                continue  # provable chain infeasibility -- a legitimate, explicit, evidence-based exclusion
            core_utility, _fdiv, _heb, _tcdiv, _terms = planner._score(op, mission, ssg, library, alpha, beta,
                                                                          belief, recency_window)
            if core_utility > 0:
                genuinely_viable.append(op)

        ranked = planner.rank(library, ssg, mission, prompts_used, frozenset(executed))

        if genuinely_viable:
            assert ranked, (
                f"INVARIANT VIOLATED: {len(genuinely_viable)} genuinely-viable operator(s) "
                f"({[o.id for o in genuinely_viable]}, each with real remaining core_utility > 0 "
                f"and a provably feasible chain) but rank() returned an empty list -- this is "
                f"exactly the exp23 SEARCH_EXHAUSTED-with-viable-candidates bug."
            )

        if not ranked:
            break
        chosen = ranked[0]
        adapter.execute(chosen.operator, ssg, agent)
        executed.append(chosen.operator.id)


@pytest.mark.parametrize("scenario_name", list(_SCENARIOS))
@pytest.mark.parametrize("config_name", list(_CONFIGS))
@pytest.mark.parametrize("budget", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 20])
def test_remaining_budget_and_eligible_operators_never_produce_search_exhausted(
        scenario_name, config_name, budget):
    build_library, build_agent = _SCENARIOS[scenario_name]
    _drive_and_check_invariant(build_library, build_agent, _CONFIGS[config_name], budget)


# --------------------------------------------------------------------------
# diagnose() auditability: every excluded operator has a real, valid reason.
# --------------------------------------------------------------------------

def test_diagnose_accounts_for_every_operator_with_a_valid_reason():
    library = OperatorLibrary(build_multi_family_library())
    ssg = SecurityStateGraph()
    agent = MultiFamilyAgent()
    adapter = ObservationAdapter()
    mission = Mission(goal="diagnose sweep", success_criteria=("__no_such_key__",),
                       budget=8, risk_threshold=RiskTier.MEDIUM, success_mode="any")
    planner = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)

    executed: list[str] = []
    for _ in range(6):  # up to and including the exact pre-collapse prefix
        ranked = planner.rank(library, ssg, mission, len(executed), frozenset(executed))
        if not ranked:
            break
        chosen = ranked[0]
        adapter.execute(chosen.operator, ssg, agent)
        executed.append(chosen.operator.id)

    diagnostics = planner.diagnose(library, ssg, mission, len(executed), frozenset(executed))
    by_id = {d.operator_id: d for d in diagnostics}

    # Every operator in the library is accounted for -- none silently missing.
    assert set(by_id) == {op.id for op in library}

    # Already-executed operators are labeled as such, not lumped in with
    # anything else.
    for op_id in executed:
        assert by_id[op_id].status == CandidateStatus.ALREADY_EXECUTED

    # Every operator that rank() actually returned is labeled RANKED here --
    # diagnose() must never silently disagree with rank()'s own output.
    ranked_now = planner.rank(library, ssg, mission, len(executed), frozenset(executed))
    ranked_ids = {rc.operator.id for rc in ranked_now}
    for op_id in ranked_ids:
        assert by_id[op_id].status == CandidateStatus.RANKED, (
            f"{op_id} was in rank()'s own output but diagnose() disagreed: {by_id[op_id].status}"
        )

    # Every diagnostic carries a real, non-empty explanation -- not a bare status code.
    for d in diagnostics:
        assert d.detail and len(d.detail) > 10
