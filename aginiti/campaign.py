"""Campaign loop (design doc Section 16.1) tying policy + adapter + SSG +
mission together, with decision-trace logging (Section 25.2).

Generalized over `Policy` (aginiti/policies/base.py) rather than hardwired
to AginitiPlanner, so the exact same loop mechanics drive all 4 benchmark
conditions (Section 20: "identical budget, repeated trials... only the
metrics collected differ by condition") -- the policy is the only thing
that varies.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.adapter.observation_adapter import ExecutionResult, ObservationAdapter
from aginiti.adapters.base import BaseAdapter
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.base import Policy
from aginiti.target.demo_agent import DemoAgent


@dataclass
class DecisionLogEntry:
    step: int
    candidates_considered: int
    chosen_operator_id: str
    score: float
    meta: dict = field(default_factory=dict)


@dataclass
class CampaignResult:
    outcome: str  # SUCCESS | BUDGET_EXHAUSTED | SEARCH_EXHAUSTED
    steps_executed: int
    prompts_used: int
    operators_executed: list[str]
    operators_considered_total: int
    decision_log: list[DecisionLogEntry] = field(default_factory=list)
    execution_log: list[ExecutionResult] = field(default_factory=list)
    ssg: SecurityStateGraph = None


def run_campaign(mission: Mission, library: OperatorLibrary, agent: BaseAdapter | None = None,
                  policy: Policy | None = None, max_steps: int = 25,
                  seed: int | None = None, adapter: ObservationAdapter | None = None) -> CampaignResult:
    """`agent` is any BaseAdapter (aginiti/adapters/base.py) -- the mock
    DemoAgent by default, but a real target's adapter works identically;
    nothing else in the campaign loop changes."""
    ssg = SecurityStateGraph()
    agent = agent or DemoAgent(seed=seed)
    policy = policy or AginitiPolicy()
    adapter = adapter or ObservationAdapter()

    prompts_used = 0
    step = 0
    decision_log: list[DecisionLogEntry] = []
    execution_log: list[ExecutionResult] = []
    operators_executed: list[str] = []
    considered_total = 0

    while step < max_steps:
        if mission.is_satisfied(ssg):
            return CampaignResult("SUCCESS", step, prompts_used, operators_executed,
                                   considered_total, decision_log, execution_log, ssg)

        ranked = policy.rank(library, ssg, mission, prompts_used, frozenset(operators_executed))
        considered_total += len(ranked)

        if not ranked:
            budget_remaining = mission.budget - prompts_used
            min_cost = min((op.cost_prompts for op in library), default=1)
            outcome = "BUDGET_EXHAUSTED" if budget_remaining < min_cost else "SEARCH_EXHAUSTED"
            return CampaignResult(outcome, step, prompts_used, operators_executed,
                                   considered_total, decision_log, execution_log, ssg)

        chosen = ranked[0]
        step += 1
        result = adapter.execute(chosen.operator, ssg, agent, seed=seed)
        prompts_used += result.cost_prompts
        operators_executed.append(chosen.operator.id)
        execution_log.append(result)
        decision_log.append(DecisionLogEntry(
            step=step,
            candidates_considered=len(ranked),
            chosen_operator_id=chosen.operator.id,
            score=chosen.score,
            meta=chosen.meta,
        ))

    return CampaignResult("BUDGET_EXHAUSTED", step, prompts_used, operators_executed,
                           considered_total, decision_log, execution_log, ssg)
