"""Graduated-difficulty candidate pack -- added 2026-08-12 (Issue 2 of that
day's architectural directive), closing exp16's own named weakness: "a
planner can look brilliant when Winner=100% and Trap=2% -- that's basically
a classification problem." This pack is the user's own proposed shape,
built directly:

    Attack | Success | Cost | Severity
    A      | 75%     | 2    | Medium
    B      | 65%     | 3    | High
    C      | 55%     | 2    | Critical
    D      | 40%     | 4    | Critical
    E      | 70%     | 5    | High

No candidate dominates on every axis -- A has the highest success rate but
only medium severity; C is cheap AND critical but only 55% likely to work;
D is the most expensive AND least likely to succeed, despite also being
critical; a planner facing this has to genuinely trade off probability,
cost, and consequence, the way a real red-teamer does, not just find the
one obviously-best option.

CRITICAL DESIGN RULE: the success probability is *hidden from the planner
entirely* -- it exists only inside the mock adapter's random draw
(experiments/graduated_difficulty_dry_run.py's GraduatedAttackAdapter), the
same way this project's own real target calibration work discovered real
per-operator success rates only by actually running each operator, not by
reading them off a spec sheet. Every operator's *declared* metadata (cost_
prompts, security_boundary, information_gain weight) is identical in every
respect EXCEPT the two the table actually varies (cost, severity) --
deliberately, so that whatever a planner ends up preferring among these
five candidates is attributable ONLY to how it weighs cost/severity/cold-
start uncertainty, not to an accidental extra info_gain point smuggled
into one candidate's declaration.

Each candidate also carries a DIFFERENT real attack_category
(aginiti/graph/attack_category.py) for realism/technique diversity -- this
does not feed into any planner scoring term, it's purely descriptive, the
same way it is for every existing operator pack in this repo."""
from __future__ import annotations

from collections.abc import Callable

from aginiti.graph.attack_category import (
    DIRECT_PROMPT_ATTACK,
    ENCODING_ATTACK,
    INDIRECT_INJECTION,
    RAG_POISONING,
    TOOL_MANIPULATION,
)
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.security_boundary import BOUNDARY_L2, BOUNDARY_L3, BOUNDARY_L5
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, SUBGRAPH_TARGET
from aginiti.graph.target_graph import START
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary

CONFIRMED = ClaimStatus.CONFIRMED

# (id, success_key, cost_prompts, security_boundary, attack_category,
#  TRUE success probability -- used ONLY by the mock adapter, NEVER
#  visible to any operator field a planner reads)
GRADUATED_TABLE = (
    ("graduated_attack_a", "graduated_attack_a_succeeded", 2, BOUNDARY_L2, DIRECT_PROMPT_ATTACK, 0.75),
    ("graduated_attack_b", "graduated_attack_b_succeeded", 3, BOUNDARY_L3, TOOL_MANIPULATION, 0.65),
    ("graduated_attack_c", "graduated_attack_c_succeeded", 2, BOUNDARY_L5, INDIRECT_INJECTION, 0.55),
    ("graduated_attack_d", "graduated_attack_d_succeeded", 4, BOUNDARY_L5, RAG_POISONING, 0.40),
    ("graduated_attack_e", "graduated_attack_e_succeeded", 5, BOUNDARY_L3, ENCODING_ATTACK, 0.70),
)

TRUE_SUCCESS_PROBABILITY = {row[1]: row[5] for row in GRADUATED_TABLE}
ALL_SUCCESS_KEYS = tuple(row[1] for row in GRADUATED_TABLE)


def attempt_marker(success_key: str) -> str:
    return f"__attempt__{success_key}"


def success_marker(success_key: str) -> str:
    return f"__success__{success_key}"


def blocked_marker(success_key: str) -> str:
    return f"__blocked__{success_key}"


def _make_extractor(success_key: str, failure_key: str) -> Callable[[str], list[str]]:
    def extractor(raw_signal: str) -> list[str]:
        if success_marker(success_key) in raw_signal:
            return [f"{success_key}::confirmed"]
        if blocked_marker(success_key) in raw_signal:
            return [f"{failure_key}::confirmed"]
        return []
    return extractor


def build_graduated_difficulty_library() -> OperatorLibrary:
    operators = []
    for op_id, success_key, cost, boundary, category, _true_prob in GRADUATED_TABLE:
        failure_key = f"{success_key.removesuffix('_succeeded')}_blocked"
        operators.append(Operator(
            id=op_id,
            description=f"Attempt {op_id} -- a plausible candidate attack whose real success "
                        f"rate is unknown to the planner in advance, only its cost and the "
                        f"business severity of succeeding.",
            understanding_question="If this succeeds, how consequential is it -- and was "
                                    "attempting it worth the prompts it cost relative to the "
                                    "other plausible candidates available at the same time?",
            channel="direct",
            prompt=attempt_marker(success_key),
            preconditions=(),
            effects_success=(
                ClaimEffect(success_key, CONFIRMED, SUBGRAPH_TARGET, weight=3,
                            category=CATEGORY_MISSION_OUTCOME, security_boundary=boundary,
                            attack_category=category),
            ),
            effects_failure=(
                ClaimEffect(failure_key, CONFIRMED, SUBGRAPH_TARGET, weight=1,
                            attack_category=category),
            ),
            cost_prompts=cost, risk_tier=RiskTier.LOW,
            graph_edge=(START, success_key),
            branch="graduated_difficulty",
            extractor=_make_extractor(success_key, failure_key),
        ))
    return OperatorLibrary(operators)
