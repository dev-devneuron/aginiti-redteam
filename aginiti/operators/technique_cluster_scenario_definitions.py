"""Operator library for `aginiti/target/technique_cluster_scenario_agent.py`
-- see that module's own docstring for the full scenario. Deliberately
single-family (every operator here is `direct_prompt_attack`) so nothing
family_diversification_term contributes can differ between candidates --
this isolates `technique_cluster_diversification_term` specifically."""
from __future__ import annotations

from aginiti.core.graph.attack_category import DIRECT_PROMPT_ATTACK
from aginiti.core.graph.failure_diagnosis import ACTIVELY_REFUSED
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L5
from aginiti.core.graph.ssg import CATEGORY_MISSION_OUTCOME, SUBGRAPH_DEFENDER, SUBGRAPH_TARGET
from aginiti.operators.library import ClaimEffect, Operator
from aginiti.target.technique_cluster_scenario_agent import (
    CLUSTER_MARKER,
    CLUSTER_SIZE,
    CLUSTER_SUCCESS_INDEX,
    SINGLETON_MARKER,
    SINGLETON_SIZE,
    SINGLETON_SUCCESS_INDEX,
)

CONFIRMED = ClaimStatus.CONFIRMED

# Matches the real weight asymmetry that causes this in `hardened_agent`:
# a boundary-crossing authority-claim variant's potential weight (3
# disclosure + 5 boundary-crossing = 8) vs a same-family singleton
# technique's weight (3, e.g. system_prompt_extraction/jailbreak_dan_style).
_CLUSTER_WEIGHT = 8
_SINGLETON_WEIGHT = 3


def _make_probe(op_id: str, marker: str, index: int, success_index: int, weight: int,
                 technique_cluster: str | None) -> Operator:
    skey = f"{op_id}_success"
    bkey = f"{op_id}_blocked"
    is_success_op = index == success_index

    def extractor(raw: str) -> list[str]:
        if is_success_op and "confirmed true" in raw:
            return [f"{skey}::confirmed"]
        return [f"{bkey}::confirmed"]

    return Operator(
        id=op_id,
        description=f"Technique-cluster scenario probe #{index} (cluster={technique_cluster!r}).",
        understanding_question=f"Does probe #{index}'s own hypothesis hold?",
        channel="direct",
        prompt=f"{marker}_{index} -- attempt variant {index}.",
        preconditions=(),
        effects_success=(
            ClaimEffect(skey, CONFIRMED, SUBGRAPH_TARGET, weight=weight,
                        category=CATEGORY_MISSION_OUTCOME, security_boundary=BOUNDARY_L5,
                        attack_category=DIRECT_PROMPT_ATTACK,
                        description=f"Probe #{index}'s own hypothesis was confirmed."),
        ),
        effects_failure=(
            ClaimEffect(bkey, CONFIRMED, SUBGRAPH_DEFENDER, weight=1,
                        failure_diagnosis=ACTIVELY_REFUSED,
                        description=f"Probe #{index}'s own hypothesis was refused."),
        ),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        branch="technique_cluster_scenario",
        extractor=extractor,
        technique_cluster=technique_cluster,
    )


def build_technique_cluster_library() -> list[Operator]:
    cluster_ops = [
        _make_probe(f"cluster_probe_{i}", CLUSTER_MARKER, i, CLUSTER_SUCCESS_INDEX, _CLUSTER_WEIGHT, "test_cluster")
        for i in range(CLUSTER_SIZE)
    ]
    singleton_ops = [
        _make_probe(f"singleton_probe_{i}", SINGLETON_MARKER, i, SINGLETON_SUCCESS_INDEX, _SINGLETON_WEIGHT, None)
        for i in range(SINGLETON_SIZE)
    ]
    return cluster_ops + singleton_ops
