"""Adapts BayesianBanditPlanner (aginiti/planner/bayesian_planner.py --
Thompson-Sampling operator selection, built in direct response to this
project's own external/internal audit of AginitiPlanner's ad hoc weighted
sum) into the shared Policy interface, exactly the same way AginitiPolicy
adapts AginitiPlanner -- same composition pattern, so the identical
campaign loop drives this as a clean 6th benchmark condition without any
harness changes."""
from __future__ import annotations

from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.planner.bayesian_planner import BayesianBanditPlanner
from aginiti.policies.base import Candidate


class BayesianPolicy:
    name = "bayesian"

    def __init__(self, planner: BayesianBanditPlanner | None = None, seed: int | None = None):
        self.planner = planner or BayesianBanditPlanner(seed=seed)

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        ranked = self.planner.rank(library, ssg, mission, prompts_used, executed_ids)
        return [
            Candidate(
                operator=rc.operator, score=rc.score,
                meta={"alpha": rc.alpha, "beta": rc.beta, "posterior_mean": rc.posterior_mean,
                      "thompson_sample": rc.thompson_sample, "info_gain_nudge": rc.info_gain_nudge},
            )
            for rc in ranked
        ]
