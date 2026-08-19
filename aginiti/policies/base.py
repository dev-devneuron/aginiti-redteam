"""Shared substrate for all 4 benchmark conditions (design doc Section 20).

Precondition/constraint gating (which operators are even eligible right
now) is common infrastructure every condition gets for free -- it is not
the thing under test. What differs between Random, Static enumeration,
Memory-guided, and Aginiti is only *which eligible operator gets ranked
first*. Sharing `eligible_operators` across all four is what makes RQ1's
ablation actually isolate the planning policy, rather than confounding it
with "which condition even gets to attempt which operator."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import Operator, OperatorLibrary

_RISK_ORDER = {RiskTier.LOW: 0, RiskTier.MEDIUM: 1, RiskTier.HIGH: 2, RiskTier.DESTRUCTIVE: 3}


def satisfies_constraints(operator: Operator, mission: Mission, budget_remaining: int) -> bool:
    if _RISK_ORDER[operator.risk_tier] > _RISK_ORDER[mission.risk_threshold]:
        return False
    if operator.cost_prompts > budget_remaining:
        return False
    if "no_destructive_actions" in mission.constraints and operator.risk_tier == RiskTier.DESTRUCTIVE:
        return False
    if operator.risk_tier == RiskTier.DESTRUCTIVE:
        return False  # Phase 0 has no human-approval loop -- destructive never auto-runs
    return True


def eligible_operators(library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
                        prompts_used: int, executed_ids: frozenset[str]) -> list[Operator]:
    budget_remaining = mission.budget - prompts_used
    out = []
    for op in library.candidates(ssg):  # precondition check
        if op.id in executed_ids:
            continue  # deterministic operator against unchanged state -> no new info (see AginitiPlanner)
        if not satisfies_constraints(op, mission, budget_remaining):
            continue
        out.append(op)
    return out


@dataclass
class Candidate:
    operator: Operator
    score: float
    meta: dict = field(default_factory=dict)


class Policy(Protocol):
    name: str

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        ...
