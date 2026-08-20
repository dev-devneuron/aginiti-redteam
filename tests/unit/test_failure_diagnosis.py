"""Structured failure-diagnosis taxonomy (aginiti/graph/failure_diagnosis.py)
and the planner term that reads it (AginitiPlanner.failure_evidence_penalty)
-- Issue 4 of the 2026-08-12 architectural directive: "give the planner
better feedback from failure.\""""
from __future__ import annotations

from aginiti.core.graph.failure_diagnosis import (
    ACTIVELY_REFUSED,
    BLOCKED_BY_APPROVAL_GATE,
    BLOCKED_BY_NETWORK_EGRESS,
    BLOCKED_BY_PRIVILEGE,
    NOT_RETRIEVED,
    is_generalizable,
    validate,
)
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator
from aginiti.core.planner.aginiti_planner import AginitiPlanner

CONFIRMED = ClaimStatus.CONFIRMED


def _mission() -> Mission:
    return Mission(goal="x", success_criteria=("mission_done",), budget=10,
                    risk_threshold=RiskTier.LOW, constraints=())


def _op_with_failure_diagnosis(op_id: str, diagnosis: str | None) -> Operator:
    return Operator(
        id=op_id, description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(f"{op_id}_win", CONFIRMED, weight=3),),
        effects_failure=(ClaimEffect(f"{op_id}_blocked", CONFIRMED, weight=1, failure_diagnosis=diagnosis),),
        cost_prompts=1, risk_tier=RiskTier.LOW,
    )


# -- taxonomy module itself -------------------------------------------

def test_generalizable_diagnoses_are_exactly_the_three_named_by_the_user():
    assert is_generalizable(BLOCKED_BY_PRIVILEGE)
    assert is_generalizable(BLOCKED_BY_NETWORK_EGRESS)
    assert is_generalizable(BLOCKED_BY_APPROVAL_GATE)
    assert not is_generalizable(NOT_RETRIEVED)
    assert not is_generalizable(ACTIVELY_REFUSED)
    assert not is_generalizable(None)


def test_validate_rejects_unknown_diagnosis():
    assert validate(BLOCKED_BY_PRIVILEGE)
    assert not validate("made_up_category")


# -- SSG threading -------------------------------------------------------

def test_assert_claim_records_failure_diagnosis_tag():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k_blocked", "true", CONFIRMED, failure_diagnosis=BLOCKED_BY_PRIVILEGE)
    assert ssg.claim_failure_diagnosis["k_blocked"] == BLOCKED_BY_PRIVILEGE
    assert ssg.confirmed_failure_diagnoses() == {"k_blocked": BLOCKED_BY_PRIVILEGE}


def test_confirmed_failure_diagnoses_excludes_unconfirmed_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k_blocked", "true", ClaimStatus.HYPOTHESIZED, failure_diagnosis=BLOCKED_BY_PRIVILEGE)
    assert ssg.confirmed_failure_diagnoses() == {}


# -- planner term ----------------------------------------------------------

def test_failure_evidence_penalty_is_zero_with_no_diagnosis_tag():
    ssg = SecurityStateGraph()
    op = _op_with_failure_diagnosis("a", None)
    assert AginitiPlanner().failure_evidence_penalty(op, ssg) == 0.0


def test_failure_evidence_penalty_is_zero_when_nothing_confirmed_yet():
    ssg = SecurityStateGraph()
    op = _op_with_failure_diagnosis("a", BLOCKED_BY_PRIVILEGE)
    assert AginitiPlanner().failure_evidence_penalty(op, ssg) == 0.0


def test_failure_evidence_penalty_demotes_a_different_operator_with_the_same_diagnosis():
    """The actual generalization: operator B never names operator A, but
    both would plausibly fail for the SAME structural reason -- once A's
    failure is confirmed with a generalizable diagnosis, B is demoted too."""
    ssg = SecurityStateGraph()
    op_a = _op_with_failure_diagnosis("op_a", BLOCKED_BY_PRIVILEGE)
    op_b = _op_with_failure_diagnosis("op_b", BLOCKED_BY_PRIVILEGE)

    planner = AginitiPlanner()
    assert planner.failure_evidence_penalty(op_b, ssg) == 0.0  # before any evidence

    ssg.assert_claim("op_a_blocked", "true", CONFIRMED, failure_diagnosis=BLOCKED_BY_PRIVILEGE)
    assert planner.failure_evidence_penalty(op_b, ssg) < 0.0  # after -- real demotion


def test_failure_evidence_penalty_does_not_generalize_across_different_diagnoses():
    ssg = SecurityStateGraph()
    op_b = _op_with_failure_diagnosis("op_b", BLOCKED_BY_NETWORK_EGRESS)
    ssg.assert_claim("op_a_blocked", "true", CONFIRMED, failure_diagnosis=BLOCKED_BY_PRIVILEGE)
    assert AginitiPlanner().failure_evidence_penalty(op_b, ssg) == 0.0


def test_not_retrieved_never_demotes_anything():
    """The deliberately-excluded, non-generalizable category: a bare
    "content wasn't retrieved this attempt" is uninformative about whether
    a DIFFERENT operator's content would be, so it must never demote."""
    ssg = SecurityStateGraph()
    op_b = _op_with_failure_diagnosis("op_b", NOT_RETRIEVED)
    ssg.assert_claim("op_a_blocked", "true", CONFIRMED, failure_diagnosis=NOT_RETRIEVED)
    assert AginitiPlanner().failure_evidence_penalty(op_b, ssg) == 0.0


def test_demotion_changes_the_planners_actual_ranking_order():
    """End-to-end proof this reaches rank(), not just the isolated term:
    two otherwise-identical candidates, one demoted by confirmed evidence
    for the SAME structural block, must rank BELOW the other."""
    from aginiti.operators.library import OperatorLibrary

    ssg = SecurityStateGraph()
    op_b = _op_with_failure_diagnosis("op_b", BLOCKED_BY_APPROVAL_GATE)
    op_c = _op_with_failure_diagnosis("op_c", None)  # otherwise identical, no diagnosis tag
    library = OperatorLibrary([op_b, op_c])
    mission = _mission()

    ssg.assert_claim("op_a_blocked", "true", CONFIRMED, failure_diagnosis=BLOCKED_BY_APPROVAL_GATE)

    ranked = AginitiPlanner().rank(library, ssg, mission, prompts_used=0)
    ranked_ids = [c.operator.id for c in ranked]
    assert ranked_ids.index("op_c") < ranked_ids.index("op_b")  # undemoted candidate ranks first
