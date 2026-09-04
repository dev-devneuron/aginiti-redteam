"""Pure-parameterization planner variants -- each one zeroes out some subset
of AginitiPlanner's utility terms rather than introducing a new mechanism.
No new reasoning; same rank()/utility formula, different coefficients.

Two of these (GreedyInfoGainPlanner, GreedyBusinessImpactPlanner) are RQ1b
exactly as scoped in analysis_plan.md ("pure parameterizations of the
existing formula (no new mechanism): Greedy-Information-Gain (alpha=1,
beta=0, fixed), Greedy-Business-Impact (alpha=0, beta=1, fixed)") -- gated
there on RQ1 running first, but implementing the classes themselves has no
such dependency, and the controlled experiments in experiments/ need them
now as baselines distinct from the four benchmark-harness policies.

BFSOnlyPlanner is a third variant experiments/ needed that RQ1b doesn't
name: pure graph-structure reasoning (path_progress alone), isolating
"does reasoning about shortest-path-to-mission-target help on its own" from
"does knowing which claims are still unresolved help" (information_gain)
or "does knowing the mission's own unmet criteria help" (business_impact).

All three explicitly zero `emergent_impact` (a later addition to
AginitiPlanner's utility, motivated by experiments/
exp7_consequence_propagation_gap.py) and
`branch_interest` (a later addition, "planner consumes CampaignBeliefState")
for the same reason they already zero gap_priority/hypothesis_priority:
staying TRUE pure parameterizations of the formula as it existed when each
was designed, not silently absorbing whatever new term gets added to the
base class later. GreedyInfoGainPlanner doesn't need the explicit
emergent_impact override (beta=0 already zeroes every beta-scaled term),
but branch_interest is UNSCALED (added directly, same as gap_priority/
hypothesis_priority) -- beta=0 does NOT zero it, so all three variants
override it explicitly, including GreedyInfoGainPlanner.

`potential_progress` (potential-based reward shaping --
see aginiti_planner.py's own module docstring) is BETA-SCALED, same group
as path_progress/emergent_impact/business_impact -- so it follows
emergent_impact's exact precedent, not branch_interest's: GreedyInfoGainPlanner
doesn't need an explicit override (beta=0 already zeroes it), but
GreedyBusinessImpactPlanner and BFSOnlyPlanner both have beta=1, so they
override it explicitly to stay pure parameterizations of the formula as it
existed when each was designed, same reasoning as their emergent_impact
overrides.

`chain_value` (value-informed potential-based reward
shaping -- see aginiti_planner.py's own module docstring and
chain_value()'s docstring) is ALPHA-SCALED, same basket as information_gain
-- the OPPOSITE grouping from potential_progress despite both being
reward-shaping terms, because chain_value represents speculative,
not-yet-confirmed lookahead value (alpha's role), not confirmed-adjacent
structural progress (beta's role). This means alpha=0 already zeroes it
for GreedyBusinessImpactPlanner (no override needed, same as
information_gain needing none there) -- but GreedyInfoGainPlanner has
alpha=1, so it DOES need an explicit override, same reasoning as its
branch_interest override: chain_value is derived from business_impact
(the mission's own unmet success-criteria, computed on the downstream
operator), which is exactly the kind of "reasons about the mission's own
success criteria" this class's own docstring says it deliberately never
does. BFSOnlyPlanner also overrides it explicitly, for the same
explicit-purity reasoning it already applies to information_gain despite
alpha=0 covering it mathematically.

Same reasoning applies to `_schedule()`'s discovery-based overrides (also
motivated by the mock-target RQ1 finding): all three variants
here already fully override `_schedule()` with a FIXED alpha/beta, so
AginitiPlanner's new trust-edge/mission-outcome-triggered dynamic
scheduling never applies to them -- deliberately, since these three exist
specifically to isolate what a FIXED weighting does, not to inherit the
base class's evolving behavior.
"""
from __future__ import annotations

from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import Operator
from aginiti.core.planner.aginiti_planner import AginitiPlanner


class GreedyInfoGainPlanner(AginitiPlanner):
    """alpha=1, beta=0, fixed -- ranks purely by how much is still unknown
    about each operator's predicted effects. Never reasons about the
    mission's own success criteria or graph-structural progress toward it."""

    def _schedule(self, ssg: SecurityStateGraph, prompts_used: int, budget: int) -> tuple[float, float]:
        return 1.0, 0.0

    def gap_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def hypothesis_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def branch_interest(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def chain_value(self, operator, mission, ssg, library) -> float:
        return 0.0  # alpha-scaled but not automatically zeroed by beta=0 -- see module docstring

    def severity_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0  # unscaled additive term, same reasoning as gap_priority/hypothesis_priority above

    def failure_evidence_penalty(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0  # unscaled additive term -- same "pure
        # parameterization, never silently absorb a new base-class term" discipline as
        # severity_priority immediately above. Do not let this override lapse when
        # failure_evidence_penalty changes -- these three classes' whole reason to exist is
        # staying true ablations of the formula as it existed when each was designed, so a
        # new unscaled term silently leaking in defeats that purpose without ever raising
        # an error, exactly the kind of "looks fine, quietly wrong" bug worth guarding
        # against explicitly.

    def family_diversification(self, operator, belief) -> float:
        return 0.0  # unscaled additive term -- structurally already 0.0
        # via enable_family_diversification defaulting False, but explicit here for the
        # SAME "never silently absorb a new base-class term" reason failure_evidence_
        # penalty's own comment names -- guards against a future default change.

    def hypothesis_escalation_bonus(self, operator, ssg, recency_window) -> float:
        return 0.0  # unscaled additive term -- see family_diversification's
        # own comment immediately above for the reasoning.


class GreedyBusinessImpactPlanner(AginitiPlanner):
    """alpha=0, beta=1, fixed -- "exploit-first": ranks purely by predicted
    contribution to unmet mission success-criteria plus path-shortening,
    ignoring how much is still unknown. Always chases the mission target
    directly rather than spending budget on general reconnaissance."""

    def _schedule(self, ssg: SecurityStateGraph, prompts_used: int, budget: int) -> tuple[float, float]:
        return 0.0, 1.0

    def gap_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def hypothesis_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def emergent_impact(self, operator, mission, ssg, library) -> float:
        return 0.0

    def potential_progress(self, operator, mission, library) -> float:
        return 0.0

    def branch_interest(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def severity_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def failure_evidence_penalty(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0  # see GreedyInfoGainPlanner's own override for the full reasoning

    def family_diversification(self, operator, belief) -> float:
        return 0.0  # see GreedyInfoGainPlanner's own override for the full reasoning

    def hypothesis_escalation_bonus(self, operator, ssg, recency_window) -> float:
        return 0.0  # see GreedyInfoGainPlanner's own override for the full reasoning


class BFSOnlyPlanner(AginitiPlanner):
    """Ranks purely by path_progress -- real graph-structure BFS reasoning
    toward a mission target, with no information-gain or business-impact
    term at all. Isolates whether graph-structure reasoning alone explains
    any advantage AginitiPlanner shows over the baselines."""

    def information_gain(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def business_impact(self, operator: Operator, mission: Mission, ssg: SecurityStateGraph) -> float:
        return 0.0

    def gap_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def hypothesis_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def emergent_impact(self, operator, mission, ssg, library) -> float:
        return 0.0

    def potential_progress(self, operator, mission, library) -> float:
        return 0.0

    def branch_interest(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def chain_value(self, operator, mission, ssg, library) -> float:
        return 0.0  # alpha=0 already zeroes this; explicit for the same purity reasoning as information_gain above

    def severity_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0

    def failure_evidence_penalty(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        return 0.0  # see GreedyInfoGainPlanner's own override for the full reasoning

    def family_diversification(self, operator, belief) -> float:
        return 0.0  # see GreedyInfoGainPlanner's own override for the full reasoning

    def hypothesis_escalation_bonus(self, operator, ssg, recency_window) -> float:
        return 0.0  # see GreedyInfoGainPlanner's own override for the full reasoning

    def _schedule(self, ssg: SecurityStateGraph, prompts_used: int, budget: int) -> tuple[float, float]:
        return 0.0, 1.0  # beta must be nonzero for path_progress's beta*(bi+pp) term to count at all
