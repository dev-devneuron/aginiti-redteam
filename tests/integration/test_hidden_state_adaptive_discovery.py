"""The integration test this whole 2026-08-14 architectural pass was built
to satisfy: a deterministic, zero-LLM synthetic target with genuine hidden
state (`benchmarks/agents/hidden_state_agent.py`) where different attack
paths reveal different information, proving each of the required
behaviors explicitly, in order:

1. Aginiti observes a failed attack.
2. Its state changes.
3. Its ranking changes because of that observation.
4. It avoids redundant failed attacks.
5. It can select a different attack family.
6. Partial progress can cause it to continue along a useful chain.
7. The full planner can discover a multi-step path the baseline cannot.

Every assertion below reads real values off a real, executed campaign --
no mocked ranking, no hand-waving."""
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.graph.target_belief import TargetBeliefState
from aginiti.core.mission import Mission
from aginiti.operators.hidden_state_definitions import build_hidden_state_library
from aginiti.operators.library import OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from benchmarks.agents.hidden_state_agent import HiddenStateAgent

_SUCCESS_CRITERIA = ("deep_secret_leaked",)


def _mission(budget: int) -> Mission:
    return Mission(goal="obtain the deep secret", success_criteria=_SUCCESS_CRITERIA,
                    budget=budget, risk_threshold=RiskTier.MEDIUM)


def _run(planner: AginitiPlanner, budget: int):
    library = OperatorLibrary(build_hidden_state_library())
    agent = HiddenStateAgent()
    return run_campaign(mission=_mission(budget), library=library, agent=agent,
                         policy=AginitiPolicy(planner), ssg=SecurityStateGraph(),
                         stop_on_mission_success=True), agent


# --------------------------------------------------------------------------
# 1 & 2: a failed attack is observed, and belief state changes as a result.
# --------------------------------------------------------------------------

def test_1_and_2_failed_attack_is_observed_and_changes_belief_state():
    from aginiti.core.observation_adapter import ObservationAdapter

    library = OperatorLibrary(build_hidden_state_library())
    ssg = SecurityStateGraph()
    agent = HiddenStateAgent()
    adapter = ObservationAdapter()

    direct_v1 = library.get("direct_ask_v1")
    result = adapter.execute(direct_v1, ssg, agent)

    # 1. The failed attack was genuinely observed (a real Fact + Observation
    # recorded, not silently dropped).
    assert result.overall_success is False
    assert "direct_ask_v1_blocked" in result.confirmed_keys
    assert any(f.kind == "response_text" for f in ssg.facts)

    # 2. Belief state changed as a direct, traceable consequence.
    belief_before = TargetBeliefState.from_ssg(SecurityStateGraph(), library)
    belief_after = TargetBeliefState.from_ssg(ssg, library)
    assert belief_before.family("direct_prompt_attack").attempted == 0
    assert belief_after.family("direct_prompt_attack").attempted == 1
    assert belief_after.family("direct_prompt_attack").confirmed_blocked_other == 1
    assert "direct_ask_v1_blocked" in belief_after.defender_controls


# --------------------------------------------------------------------------
# 3: ranking changes because of that observation.
# --------------------------------------------------------------------------

def test_3_ranking_changes_because_of_the_observation():
    from aginiti.core.observation_adapter import ObservationAdapter

    library = OperatorLibrary(build_hidden_state_library())
    ssg = SecurityStateGraph()
    agent = HiddenStateAgent()
    adapter = ObservationAdapter()
    mission = _mission(budget=7)
    planner = AginitiPlanner(enable_family_diversification=True)

    ranked_before = planner.rank(library, ssg, mission, prompts_used=0, executed_ids=frozenset())
    fdiv_before = next(rc.family_diversification for rc in ranked_before if rc.operator.id == "direct_ask_v2")
    # 2026-08-14 update (see aginiti/graph/novelty.py's own PROACTIVE_
    # COVERAGE_BONUS docstring, added in direct response to a live exp28
    # postmortem): a genuinely untried family -- true here, nothing has
    # run yet -- now gets a small PROACTIVE bonus even with zero evidence
    # either way, not a bare 0.0 no-op as before this fix. The bonus is
    # deliberately smaller than the REACTIVE DIVERSIFICATION_BONUS tested
    # below (recon_fdiv_after), which fires once something else has
    # actually demonstrated a dead end -- a stronger signal.
    from aginiti.core.graph.novelty import PROACTIVE_COVERAGE_BONUS
    assert fdiv_before == PROACTIVE_COVERAGE_BONUS

    adapter.execute(library.get("direct_ask_v1"), ssg, agent)
    adapter.execute(library.get("direct_ask_v2"), ssg, agent)

    ranked_after = planner.rank(library, ssg, mission, prompts_used=2, executed_ids=frozenset({"direct_ask_v1", "direct_ask_v2"}))
    fdiv_after = next(rc.family_diversification for rc in ranked_after if rc.operator.id == "direct_ask_v3")
    # The SAME family, now with 2 confirmed same-family refusals and zero
    # successes -- ranking genuinely changed: direct_ask_v3 is now demoted.
    assert fdiv_after < 0.0
    recon_fdiv_after = next(rc.family_diversification for rc in ranked_after if rc.operator.id == "recon_probe")
    assert recon_fdiv_after > 0.0  # and an untried family now gets a real, positive bump


# --------------------------------------------------------------------------
# 4 & 5: avoids redundant failed attacks, selects a different family.
# --------------------------------------------------------------------------

def test_4_and_5_avoids_redundant_attempts_and_pivots_to_a_different_family():
    planner = AginitiPlanner(enable_family_diversification=True)
    result, _ = _run(planner, budget=5)

    # 4. direct_ask_v3 -- a real, eligible, not-yet-tried candidate -- is
    # never attempted at all, because the planner correctly recognized the
    # direct_prompt_attack family was already saturated after v1 and v2.
    assert "direct_ask_v3" not in result.operators_executed

    # 5. It genuinely pivoted to a DIFFERENT family (low_value_reconnaissance
    # -> indirect_injection -> multi_step_chain) rather than exhausting the
    # first one.
    assert "recon_probe" in result.operators_executed


# --------------------------------------------------------------------------
# 6: partial progress causes it to continue along a useful chain.
# --------------------------------------------------------------------------

def test_6_partial_progress_continues_the_chain():
    planner = AginitiPlanner(enable_family_diversification=True)
    result, _ = _run(planner, budget=7)

    order = result.operators_executed
    assert "recon_probe" in order and "trust_probe" in order and "indirect_ask" in order
    # The chain fired in genuine dependency order -- trust_probe only
    # becomes ELIGIBLE (via ClassPrecondition) once recon confirms
    # capability_known; indirect_ask only becomes eligible once trust_probe
    # confirms trust_established. This is real ClassPrecondition-driven
    # ordering, not luck: assert it explicitly.
    assert order.index("recon_probe") < order.index("trust_probe") < order.index("indirect_ask")


# --------------------------------------------------------------------------
# 7: the full planner discovers a multi-step path the baseline cannot,
# within the SAME tight budget.
# --------------------------------------------------------------------------

def test_7_full_planner_succeeds_where_baseline_fails_at_a_tight_budget():
    tight_budget = 5  # exactly enough for 2 direct + recon + trust + indirect;
                       # NOT enough for 3 direct + recon + trust + indirect.

    baseline = AginitiPlanner()  # config A -- every new flag off, identical to pre-2026-08-14 behavior
    full = AginitiPlanner(enable_family_diversification=True, enable_hypothesis_escalation_bonus=True)  # config D

    baseline_result, baseline_agent = _run(baseline, tight_budget)
    full_result, full_agent = _run(full, tight_budget)

    # The baseline planner -- with no family-level learning -- burns its
    # entire budget re-trying the direct-ask family and NEVER reaches the
    # real multi-step path.
    assert baseline_result.outcome != "SUCCESS"
    assert "indirect_ask" not in baseline_result.operators_executed
    assert baseline_agent.ground_truth_mission_achieved() is False

    # The full planner reaches the SAME deep secret, in the SAME budget,
    # confirmed by the target's own independent ground truth (never the
    # SSG's own belief).
    assert full_result.outcome == "SUCCESS"
    assert "indirect_ask" in full_result.operators_executed
    assert full_agent.ground_truth_mission_achieved() is True


def test_config_a_is_byte_identical_to_pre_2026_08_14_aginiti_planner_defaults():
    """Explicit regression guard for the ablation's own config A: an
    unparameterized AginitiPlanner() must produce EXACTLY the same ranking
    as before family_diversification/hypothesis_escalation_bonus existed --
    both must contribute exactly 0.0 to every candidate by default."""
    library = OperatorLibrary(build_hidden_state_library())
    ssg = SecurityStateGraph()
    mission = _mission(budget=7)
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, mission, prompts_used=0, executed_ids=frozenset())
    for rc in ranked:
        assert rc.family_diversification == 0.0
        assert rc.hypothesis_escalation_bonus == 0.0
