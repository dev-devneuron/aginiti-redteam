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
    name = "aginiti"

    def __init__(self, planner: AginitiPlanner | None = None):
        self.planner = planner or AginitiPlanner()

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        ranked = self.planner.rank(library, ssg, mission, prompts_used, executed_ids)
        return [
            Candidate(
                operator=rc.operator,
                score=rc.utility,
                meta={"info_gain": rc.info_gain, "business_impact": rc.business_impact,
                      "path_progress": rc.path_progress, "alpha": rc.alpha, "beta": rc.beta},
            )
            for rc in ranked
        ]
