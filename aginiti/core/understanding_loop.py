"""The first version of the closed understanding<->exploitation loop:

    Plan (gap-aware) -> Execute -> Learn (re-synthesize) -> Repeat

Deliberately NOT built into campaign.py's run_campaign(): that loop is
shared substrate for all 4 benchmark conditions, including the frozen RQ1
protocol (analysis_plan.md), which was pre-registered before insight
synthesis existed. Adding automatic per-step LLM synthesis calls there
would silently change that benchmark's token-budget and timing
characteristics. This is a new, separate loop for understanding-oriented
campaigns (DVAA and beyond) -- not a replacement for the generic one.

What makes this a LOOP rather than "run everything, then summarize once":
after every single probe, insights are re-synthesized from the freshly-
updated graph, and the next probe is chosen by AginitiPlanner.rank() --
which now (aginiti/planner/aginiti_planner.py's gap_priority) reads those
insights back. A knowledge gap discovered in round 2 can change which
operator gets picked in round 3. That is the concrete mechanism behind
"every validated hypothesis should reshape the exploit planner" -- not a
narrative, a read path the planner's utility function actually has.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.core.observation_adapter import ExecutionResult, ObservationAdapter
from aginiti.adapters.base import BaseAdapter
from aginiti.core.graph.insights import synthesize_insights
from aginiti.core.graph.schema import Insight
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner


@dataclass
class UnderstandingRound:
    round_num: int
    chosen_operator_id: str
    execution: ExecutionResult
    new_insights: list[Insight] = field(default_factory=list)


@dataclass
class UnderstandingLoopResult:
    ssg: SecurityStateGraph
    rounds: list[UnderstandingRound] = field(default_factory=list)
    prompts_used: int = 0


def run_understanding_loop(mission: Mission, library: OperatorLibrary, agent: BaseAdapter,
                            target_name: str, ssg: SecurityStateGraph | None = None,
                            adapter: ObservationAdapter | None = None,
                            max_rounds: int = 10, seed: int | None = None) -> UnderstandingLoopResult:
    """One probe per round, chosen by the gap-aware planner against the
    CURRENT graph, followed immediately by re-synthesis -- not a batch of
    probes followed by one synthesis pass at the end. Stops when no
    eligible operator has positive utility left (mirrors
    `stop_on_mission_success=False` campaigns: mission satisfaction is
    metadata here, never a stop condition) or `max_rounds` is hit.

    `ssg` defaults to a fresh graph but can be a reloaded one, same
    resumability contract as `run_campaign`. `adapter` defaults to a real
    ObservationAdapter but is injectable -- same reason campaign.py's is:
    offline tests substitute a fake that never touches the judge LLM."""
    ssg = ssg or SecurityStateGraph()
    adapter = adapter or ObservationAdapter()
    planner = AginitiPlanner()
    rounds: list[UnderstandingRound] = []
    prompts_used = 0

    for round_num in range(1, max_rounds + 1):
        executed_ids = frozenset(ssg.operator_stats)
        ranked = planner.rank(library, ssg, mission, prompts_used, executed_ids)
        if not ranked:
            break

        chosen = ranked[0].operator
        result = adapter.execute(chosen, ssg, agent, seed=seed)
        prompts_used += result.cost_prompts

        new_insights = synthesize_insights(ssg, target_name, library=library,
                                            executed_ids=frozenset(ssg.operator_stats), seed=seed)
        rounds.append(UnderstandingRound(round_num, chosen.id, result, new_insights))

    return UnderstandingLoopResult(ssg, rounds, prompts_used)
