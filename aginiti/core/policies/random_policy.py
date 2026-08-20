"""Random baseline (design doc Section 20): "Uniform random selection among
operators whose preconditions currently hold. The floor baseline -- required
for any ablation to be meaningful." """
from __future__ import annotations

import random

from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.core.policies.base import Candidate, eligible_operators


class RandomPolicy:
    name = "random"

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        elig = eligible_operators(library, ssg, mission, prompts_used, executed_ids)
        self._rng.shuffle(elig)
        return [Candidate(operator=op, score=0.0) for op in elig]
