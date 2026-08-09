"""Adapts AginitiPlanner (the SSG-driven constrained-utility planner) into
the shared Policy interface so the benchmark harness can drive all 4
conditions through the identical campaign loop."""
from __future__ import annotations

from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.planner.aginiti_planner import AginitiPlanner
from aginiti.policies.base import Candidate


class AginitiPolicy:
    """Wraps any AginitiPlanner (or subclass -- see aginiti/planner/variants.py
    for the pure-parameterization variants used by experiments/ and RQ1b) as
    a Policy. `name` defaults to "aginiti" for backward compatibility with
    every existing caller that does AginitiPolicy() with no arguments; pass
    an explicit name when wrapping a variant, so benchmark/report output can
    tell conditions apart."""

    def __init__(self, planner: AginitiPlanner | None = None, name: str = "aginiti"):
        self.planner = planner or AginitiPlanner()
        self.name = name

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        ranked = self.planner.rank(library, ssg, mission, prompts_used, executed_ids)
        return [
            Candidate(
                operator=rc.operator,
                score=rc.utility,
                meta={"info_gain": rc.info_gain, "business_impact": rc.business_impact,
                      "path_progress": rc.path_progress, "emergent_impact": rc.emergent_impact,
                      "potential_progress": rc.potential_progress, "chain_value": rc.chain_value,
                      "branch_interest": rc.branch_interest, "severity_priority": rc.severity_priority,
                      "alpha": rc.alpha, "beta": rc.beta},
            )
            for rc in ranked
        ]
