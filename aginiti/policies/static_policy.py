"""Static-enumeration baseline (design doc Section 20): "Fixed-order
execution of the full operator library. Representative of garak / PyRIT-
style systematic probing." The declared order is the operator library's own
insertion order (aginiti/operators/definitions.py) -- a fixed checklist,
never re-ranked by anything observed during the campaign."""
from __future__ import annotations

from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.policies.base import Candidate, eligible_operators


class StaticPolicy:
    name = "static"

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str]) -> list[Candidate]:
        elig_ids = {op.id for op in eligible_operators(library, ssg, mission, prompts_used, executed_ids)}
        # `library` iterates in its fixed declared order -- that order IS the checklist.
        ordered = [op for op in library if op.id in elig_ids]
        return [Candidate(operator=op, score=float(len(ordered) - i)) for i, op in enumerate(ordered)]
