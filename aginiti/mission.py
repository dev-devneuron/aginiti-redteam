"""Mission (design doc Section 15's field reference).

`success_mode="any"` is what makes a mission genuinely branching: several
distinct compromise types (a payroll write, a secret exfiltration, an
unauthorized workflow trigger, a credential reset) each independently
satisfy it, rather than requiring one single linear AND-chain. Default
stays "all" for backward-compatible single-path missions.
"""
from __future__ import annotations

from dataclasses import dataclass

from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph


@dataclass(frozen=True)
class Mission:
    goal: str
    success_criteria: tuple[str, ...]  # claim keys; see success_mode for how they combine
    budget: int  # prompts
    risk_threshold: RiskTier
    constraints: tuple[str, ...] = ("no_destructive_actions",)
    success_mode: str = "all"  # "all" (every criterion confirmed) | "any" (at least one)

    def is_satisfied(self, ssg: SecurityStateGraph) -> bool:
        if not self.success_criteria:
            return False
        checks = (ssg.is_confirmed(k) for k in self.success_criteria)
        return any(checks) if self.success_mode == "any" else all(checks)
