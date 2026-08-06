"""The constrained-utility planner (design doc Section 12, 17).

a* = argmax over candidates(G_t) of [alpha_t * I(a) + beta_t * (B(a) + PP(a))]
subject to: risk(a) <= mission.risk_threshold
            cost(a) <= budget_remaining
            risk_tier(a) == destructive => human_approved(a)

Risk and budget are hard constraints on the candidate set, not penalty terms
inside the maximized quantity (Section 12.2's reasoning: folding risk into
the same scalar as business impact lets a large predicted impact numerically
outweigh a dangerous action, which is the wrong behavior).

alpha_t decays and beta_t rises across the campaign (Section 12.1, Figure
12.1) -- Phase 0 uses prompts-used-as-fraction-of-budget as the step signal.

PP(a) -- path progress -- is what makes this genuine graph reasoning rather
than flat claim-key ranking: it asks a real BFS shortest-path question over
aginiti/graph/target_graph.py's currently-CONFIRMED subgraph -- "if this
operator succeeds, does it shorten (or newly create) the known path to any
mission target" -- not just "does its key match an unmet criterion."
"""
from __future__ import annotations

from dataclasses import dataclass

from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.graph.target_graph import build_graph, min_distance_to_any, shortest_distances
from aginiti.mission import Mission
from aginiti.operators.library import Operator, OperatorLibrary
from aginiti.policies.base import eligible_operators


@dataclass
class RankedCandidate:
    operator: Operator
    utility: float
    info_gain: float
    business_impact: float
    path_progress: float
    alpha: float
    beta: float


class AginitiPlanner:
    def _schedule(self, prompts_used: int, budget: int) -> tuple[float, float]:
        frac = min(1.0, prompts_used / budget) if budget else 1.0
        alpha = max(0.05, 1.0 - frac)
        beta = min(1.0, 0.05 + frac)
        return alpha, beta

    def information_gain(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """Equation 14.1: sum of per-claim-type weight over predicted Claims
        not yet resolved (still unknown or only hypothesized) -- a claim
        already confirmed/refuted has no new information left to gain."""
        total = 0.0
        for effect in (*operator.effects_success, *operator.effects_failure):
            current = ssg.current_claim(effect.key)
            if current is None or current.status == ClaimStatus.HYPOTHESIZED:
                total += effect.weight
        return total

    def business_impact(self, operator: Operator, mission: Mission, ssg: SecurityStateGraph) -> float:
        """Fraction of currently-unmet mission success-criteria this operator
        is predicted to satisfy if it succeeds."""
        unmet = [k for k in mission.success_criteria if not ssg.is_confirmed(k)]
        if not unmet:
            return 0.0
        hits = sum(1 for e in operator.effects_success if e.key in unmet)
        return hits / len(unmet)

    def path_progress(self, operator: Operator, mission: Mission,
                       ssg: SecurityStateGraph, library: OperatorLibrary) -> float:
        """Real graph-traversal reasoning: does executing `operator` shorten
        (or newly create) the currently-known shortest path to ANY mission
        target node, over the SSG's confirmed subgraph. This is what lets
        the planner answer "which trust edge should I exploit next" as an
        actual BFS computation rather than a flat claim-key match."""
        if operator.graph_edge is None:
            return 0.0
        targets = mission.success_criteria
        if not targets:
            return 0.0

        baseline_graph = build_graph(library, ssg)
        baseline_min = min_distance_to_any(shortest_distances(baseline_graph), targets)

        hypothetical_graph = build_graph(library, ssg, extra_edge=operator.graph_edge)
        hypothetical_min = min_distance_to_any(shortest_distances(hypothetical_graph), targets)

        if hypothetical_min is None:
            return 0.0  # doesn't connect toward any mission target at all
        if baseline_min is None:
            return 3.0  # makes a previously-unreachable mission target reachable for the first time
        if hypothetical_min < baseline_min:
            return 1.0  # shortens an already-known path
        return 0.0

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str] = frozenset()) -> list[RankedCandidate]:
        alpha, beta = self._schedule(prompts_used, mission.budget)
        ranked = []
        for op in eligible_operators(library, ssg, mission, prompts_used, executed_ids):
            ig = self.information_gain(op, ssg)
            bi = self.business_impact(op, mission, ssg)
            pp = self.path_progress(op, mission, ssg, library)
            utility = alpha * ig + beta * (bi + pp)
            if utility <= 0:
                continue  # zero predicted value left -- a rational planner has no reason to run it
            ranked.append(RankedCandidate(op, utility, ig, bi, pp, alpha, beta))
        ranked.sort(key=lambda c: c.utility, reverse=True)
        return ranked
