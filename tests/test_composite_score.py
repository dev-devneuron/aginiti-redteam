"""aginiti/composite_score.py -- the "Mission success x security boundary x
business impact x cost x evidence quality" scoring formula (Issue 5 of the
2026-08-12 architectural directive)."""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.adapters.base import SendResult
from aginiti.campaign import run_campaign
from aginiti.composite_score import composite_campaign_score
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.graph.target_graph import START
from aginiti.mission import Mission
from aginiti.operators.discovery_chain_definitions import build_discovery_chain_library
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.random_policy import RandomPolicy


@dataclass
class _EchoAdapter:
    ssg: SecurityStateGraph
    mission_key: str
    suppressed_claim_keys: frozenset[str] = field(default_factory=frozenset)

    def send(self, channel: str, prompt: str) -> SendResult:
        suppressed_prompts = {f"__confirmed__{key}" for key in self.suppressed_claim_keys}
        return SendResult(final_text="" if prompt in suppressed_prompts else prompt)

    def ground_truth_mission_achieved(self) -> bool:
        return self.ssg.is_confirmed(self.mission_key)


def _mission(budget: int = 12) -> Mission:
    return Mission(goal="composite score test", success_criteria=("chain_data_exfiltrated",),
                    budget=budget, risk_threshold=RiskTier.LOW, constraints=())


def test_a_full_successful_chain_scores_strictly_between_zero_and_one_on_every_factor():
    ssg = SecurityStateGraph()
    library = build_discovery_chain_library()
    mission = _mission(budget=12)
    agent = _EchoAdapter(ssg=ssg, mission_key="chain_data_exfiltrated")

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)
    score = composite_campaign_score(result, mission)

    assert score.mission_success == 1.0
    assert score.security_boundary_score == 1.0  # L5 is the max rank (5/5)
    assert score.business_impact_score == 1.0
    assert 0.0 < score.cost_efficiency_score < 1.0  # used SOME but not zero budget
    assert score.evidence_quality_score > 0.0
    assert score.composite > 0.0
    # Multiplicative: composite can never exceed the smallest factor.
    assert score.composite <= min(score.mission_success, score.security_boundary_score,
                                    score.business_impact_score, score.cost_efficiency_score,
                                    score.evidence_quality_score)


def test_a_failed_mission_scores_exactly_zero_no_matter_what_else_happened():
    ssg = SecurityStateGraph()
    library = build_discovery_chain_library()
    mission = _mission(budget=3)  # too small to ever complete the 6-stage chain
    agent = _EchoAdapter(ssg=ssg, mission_key="chain_data_exfiltrated")

    result = run_campaign(mission, library, agent=agent, policy=RandomPolicy(seed=1), max_steps=3, ssg=ssg)
    score = composite_campaign_score(result, mission)

    assert score.mission_success == 0.0
    assert score.composite == 0.0  # zero, full stop -- no partial credit for a non-success


def test_composite_score_is_never_negative_even_at_zero_budget():
    ssg = SecurityStateGraph()
    library = build_discovery_chain_library()
    mission = _mission(budget=0)
    agent = _EchoAdapter(ssg=ssg, mission_key="chain_data_exfiltrated")

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=1, ssg=ssg)
    score = composite_campaign_score(result, mission)
    assert score.cost_efficiency_score == 0.0
    assert score.composite == 0.0


def test_faster_win_scores_higher_than_a_slower_win_all_else_equal():
    """The same mission, same library, same eventual outcome -- but a
    campaign that gets there with a bigger budget cushion should score a
    HIGHER cost_efficiency_score (and therefore composite), all else
    equal. Modeled here by comparing the discovery chain's real prompt
    cost against a hypothetically much larger budget for the same run."""
    ssg_a, ssg_b = SecurityStateGraph(), SecurityStateGraph()
    library_a, library_b = build_discovery_chain_library(), build_discovery_chain_library()
    mission_tight = _mission(budget=8)   # exactly enough (8 steps observed in the dry run)
    mission_loose = _mission(budget=40)  # same mission, much more slack
    agent_a = _EchoAdapter(ssg=ssg_a, mission_key="chain_data_exfiltrated")
    agent_b = _EchoAdapter(ssg=ssg_b, mission_key="chain_data_exfiltrated")

    result_a = run_campaign(mission_tight, library_a, agent=agent_a, policy=AginitiPolicy(),
                             max_steps=20, ssg=ssg_a)
    result_b = run_campaign(mission_loose, library_b, agent=agent_b, policy=AginitiPolicy(),
                             max_steps=20, ssg=ssg_b)
    score_a = composite_campaign_score(result_a, mission_tight)
    score_b = composite_campaign_score(result_b, mission_loose)

    assert score_a.mission_success == score_b.mission_success == 1.0
    assert score_b.cost_efficiency_score > score_a.cost_efficiency_score
    assert score_b.composite > score_a.composite


def test_any_mode_mission_success_is_a_strict_boolean_not_diluted_by_untried_criteria():
    """Regression lock for the fix found while running Issue 2's
    graduated-difficulty benchmark: an "any"-mode mission with 5
    independent criteria, where only ONE is ever attempted and it WINS,
    must score mission_success=1.0 (the mission's own is_satisfied()
    agrees) -- NOT 1/5=0.2, which the pre-fix formula produced by reusing
    business_impact's fractional logic for both modes."""
    from aginiti.composite_score import CompositeScore, composite_campaign_score

    ssg = SecurityStateGraph()
    from aginiti.graph.security_boundary import BOUNDARY_L2

    library = OperatorLibrary([
        Operator(id="only_attempt", description="x", prompt="x", channel="direct", preconditions=(),
                 effects_success=(ClaimEffect("win_a", ClaimStatus.CONFIRMED, security_boundary=BOUNDARY_L2),),
                 effects_failure=(),
                 cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=(START, "win_a"),
                 extractor=lambda raw: ["win_a::confirmed"]),  # deterministic -- no live LLM judge call
    ])
    mission = Mission(goal="any-mode test", success_criteria=("win_a", "win_b", "win_c", "win_d", "win_e"),
                       budget=5, risk_threshold=RiskTier.LOW, constraints=(), success_mode="any")
    agent = _EchoAdapter(ssg=ssg, mission_key="win_a")

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)
    score = composite_campaign_score(result, mission)

    assert result.outcome == "SUCCESS"
    assert score.mission_success == 1.0  # NOT 0.2
    assert score.business_impact_score == 1 / 5  # the separate, still-fractional signal
    assert score.composite > 0.0


def test_as_dict_round_trips_every_field():
    ssg = SecurityStateGraph()
    library = build_discovery_chain_library()
    mission = _mission(budget=12)
    agent = _EchoAdapter(ssg=ssg, mission_key="chain_data_exfiltrated")
    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)
    score = composite_campaign_score(result, mission)
    d = score.as_dict()
    assert set(d) == {"mission_success", "security_boundary_score", "business_impact_score",
                       "cost_efficiency_score", "evidence_quality_score", "composite"}
