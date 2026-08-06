"""Memory-guided baseline (design doc Section 20): "Operator selection
weighted by historical success rate only, with no access to the Security
State Graph. Representative of the AutoRedTeamer mechanism" (Section 3:
"its memory is attack-outcome memory -- what has worked before -- not
target-state memory -- what exists in this deployment").

`OperatorMemory` is deliberately cross-campaign/cross-trial: attack-outcome
memory is supposed to accumulate across engagements, unlike the SSG which
Aginiti starts fresh each campaign (Section 6.2). The benchmark harness owns
one OperatorMemory instance for the whole memory-guided condition and
updates it after every trial.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.policies.base import Candidate, eligible_operators


@dataclass
class OperatorMemory:
    successes: dict[str, int] = field(default_factory=dict)
    executions: dict[str, int] = field(default_factory=dict)

    def record(self, operator_id: str, success: bool) -> None:
        self.executions[operator_id] = self.executions.get(operator_id, 0) + 1
        if success:
            self.successes[operator_id] = self.successes.get(operator_id, 0) + 1

    def success_rate(self, operator_id: str) -> float:
        # Laplace-smoothed: an untried operator starts at a neutral 0.5,
        # not 0 -- otherwise memory-guided would never try anything new.
        s = self.successes.get(operator_id, 0)
        n = self.executions.get(operator_id, 0)
        return (s + 1) / (n + 2)


class MemoryGuidedPolicy:
    name = "memory_guided"

    def __init__(self, memory: OperatorMemory | None = None, seed: int | None = None):
        self.memory = memory or OperatorMemory()
        self._rng = random.Random(seed)

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        elig = eligible_operators(library, ssg, mission, prompts_used, executed_ids)
        if not elig:
            return []
        weights = [self.memory.success_rate(op.id) for op in elig]
        # Weighted sample without replacement: repeatedly draw-and-remove so
        # the FULL ranking is success-rate-weighted, not just the top pick.
        pool = list(zip(elig, weights))
        ordered: list[Candidate] = []
        while pool:
            total = sum(w for _, w in pool)
            r = self._rng.uniform(0, total)
            upto = 0.0
            for i, (op, w) in enumerate(pool):
                upto += w
                if upto >= r:
                    ordered.append(Candidate(operator=op, score=w))
                    pool.pop(i)
                    break
            else:
                op, w = pool.pop()
                ordered.append(Candidate(operator=op, score=w))
        return ordered
