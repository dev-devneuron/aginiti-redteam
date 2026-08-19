"""The constrained-utility planner (design doc Section 12, 17).

a* = argmax over candidates(G_t) of
     [alpha_t * (I(a) + CV(a)) + beta_t * (B(a) + PP(a) + EP(a) + PoP(a)) + GP(a) + HP(a) + BI(a) + SP(a)]
subject to: risk(a) <= mission.risk_threshold
            cost(a) <= budget_remaining
            budget_feasible(a) -- see budget_feasible()'s own docstring
            risk_tier(a) == destructive => human_approved(a)

budget_feasible(a) -- added 2026-08-09, live-diagnosed on branching_chat_rag:
`cost(a) <= budget_remaining` alone only checks THIS operator's own cost,
not whether the rest of the chain it starts can still fit -- AginitiPlanner
repeatedly spent its LAST prompt starting a 2-step RAG-poisoning chain's
first half, a mathematically guaranteed failure, while a genuinely
completable single-step alternative sat unchosen in the same candidate
set. Same hard-constraint treatment as cost/risk (excluded from the
candidate set entirely, never a soft penalty inside the maximized
quantity) -- an admissible/optimistic bound (prices remaining hops at the
library's cheapest operator), so it only ever prunes a chain that is
PROVABLY unwinnable within budget even in the best case, never a false
negative.

PoP(a) -- potential progress -- POTENTIAL-BASED REWARD SHAPING (Ng, Harada
& Russell 1999), added 2026-08-08 to close a real gap in PP/EP themselves:
build_graph() (aginiti/graph/target_graph.py) only includes an edge once its
operator's success is CONFIRMED, but eligible_operators() lets an operator
become a candidate once its precondition is merely met (often HYPOTHESIZED,
a strictly weaker bar). In that window -- precondition satisfied, but the
PREDECESSOR's own edge not yet CONFIRMED -- a genuinely on-path operator's
graph_edge doesn't touch the confirmed-reachable frontier, so PP/EP score it
0.0, identical to an unrelated dead end. That's a sparse-reward problem in
exactly the RL sense: only the action immediately adjacent to already-proven
progress gets a nonzero graph-based signal.

PoP(a) = max(0, Phi(v) - Phi(u)) for operator.graph_edge = (u, v), where
Phi(node) = -distance(node -> nearest target), computed via ONE multi-source
BFS (aginiti/graph/target_graph.py's distance_to_nearest_target) per rank()
call over build_static_graph()'s library-wide graph -- EVERY declared
graph_edge, confirmed or not. This static graph is the library's own FIXED
prior structural hypothesis (an operator's author wrote graph_edge to mean
"what confirming this implies structurally," independent of proof), playing
the same role a relaxed-problem heuristic plays for A* search: admissible/
optimistic, never adjusted by confirmed/refuted evidence mid-campaign. Per
the shaping theorem, adding Phi(s')-Phi(s) to any reward never changes which
policy is optimal -- it only densifies the signal along the way, so PoP can
only ever help distinguish a correctly-placed stepping stone from a genuine
dead end, never mislead the search. Undiscounted (gamma=1) throughout: this
planner has no time-discount concept anywhere else, and gamma=1 shaping over
a step-count graph IS a static distance-to-goal heuristic.

"target" in Phi's distance computation means the UNION of mission.success_
criteria and emergent_targets(library) -- fixed same-day, in self-review,
after shipping a first version scoped to named targets only: the sparsity
gap PoP exists to close is caused by build_graph()'s confirmed-only filter,
which afflicts emergent_impact's stepping stones exactly as much as
path_progress's, so scoping PoP to named targets alone would have been an
INCOMPLETE fix to the very problem it was written to solve. Folded into ONE
shared Phi rather than a second PP/EP-style split term: unlike PP vs EP
(two independent before/after BFS comparisons that must stay separate to
avoid double-crediting the same node), Phi is a single distance-to-nearest-
target computation -- taking the union of target sets has no analogous
double-counting risk, so one term is the more complete AND the simpler
design, not a compromise between the two.

Deliberately a SEPARATE term from PP/EP, not a rewrite: PP/EP still answer
"does the PROVEN graph change right now" (matches confirmed/refuted reality,
useful for late-campaign exploitation); PoP answers "how promising is this
edge structurally, regardless of whether the story has caught up to it yet"
-- same "new term sits alongside what it extends" pattern as GP/HP/BI below,
and (notably) the only term in this whole formula that reads library
structure alone, never ssg -- a constant per operator for a fixed library,
by design.

BI(a) -- branch interest -- added 2026-08-08, closing a gap a live trace
proved was real: three prior milestones (CampaignBeliefState, deterministic
branch propagation, the gated Reasoning Layer) all correctly populated
ssg.belief, and NONE of it changed a single ranking decision, because
nothing in this formula ever read it. See `branch_interest()`'s own
docstring for exactly what it reads and, as importantly, what it
deliberately does NOT read (branch-level risk stays out of this scalar,
same reasoning as the risk/budget hard-constraints below).

Risk and budget are hard constraints on the candidate set, not penalty terms
inside the maximized quantity (Section 12.2's reasoning: folding risk into
the same scalar as business impact lets a large predicted impact numerically
outweigh a dangerous action, which is the wrong behavior).

alpha_t decays and beta_t rises across the campaign (Section 12.1, Figure
12.1) -- Phase 0 originally used prompts-used-as-fraction-of-budget as the
ONLY step signal. **Changed 2026-08-07**, directly in response to the
mock-target RQ1 finding (docs/EVIDENCE_AND_EVALUATION.md Section 0):
elapsed-budget-fraction alone kept Aginiti exploring broadly for most of a
campaign even after effectively finding a working path, while
Static-enumeration's fixed order reached the same path immediately and won
on cost. `_schedule()` now also reacts to DISCOVERY events -- a CONFIRMED
trust_edge or mission_outcome claim anywhere in the graph overrides the
time-based schedule toward exploitation -- see `_schedule()`'s own
docstring for the exact priority and reasoning.

PP(a) -- path progress -- is what makes this genuine graph reasoning rather
than flat claim-key ranking: it asks a real BFS shortest-path question over
aginiti/graph/target_graph.py's currently-CONFIRMED subgraph -- "if this
operator succeeds, does it shorten (or newly create) the known path to any
mission target" -- not just "does its key match an unmet criterion."

EP(a) -- emergent impact -- is the same BFS question asked against a BROADER
target set: every claim key ANY operator in the library tags as a
CATEGORY_MISSION_OUTCOME-shaped compromise, not only the specific ones a
human wrote into Mission.success_criteria in advance. Added 2026-08-07 after
experiments/exp7_consequence_propagation_gap.py demonstrated directly that
without it, a real stepping-stone toward an unnamed-but-recognized
compromise gets identical utility to a genuine dead end -- the concrete gap
behind "chain findings together into realistic attack paths" (see
docs/ROADMAP.md Phase 4). PP(a) and EP(a) stay separate, individually
testable terms rather than one merged concept, same pattern as GP/HP below.

CV(a) -- chain value -- added 2026-08-09, closing a gap experiments/
exp17_hardened_target.py demonstrated live: PoP's Phi is purely
topological (-hop-distance-to-target), so it credits every "one hop
closer" edge identically regardless of what's actually at the far end --
it can tell a stepping stone from a dead end, but not a GOOD stepping
stone from a mediocre one. A "plant" operator (its own effect is a setup
claim, not itself a mission-outcome claim) therefore scored info_gain=1.0
against a same-cost single-step option's info_gain=4.0, and was outscored
~3.8x at mission start independent of how valuable its own downstream
chain actually was. CV(a) gives a plant operator DISCOUNTED credit now
for what its declared downstream operator would itself be worth if
reached (via this planner's own information_gain/business_impact methods
-- no new value model), grounded in Wiewiora, Cottrell & Elkan (2003,
"Principled Methods for Advising RL Agents": potential-based shaping with
Phi is exactly equivalent to initializing the value function with Phi,
so a value-informed Phi is strictly more useful than a topological one).
Joins I(a) in alpha's basket (speculative/still-unconfirmed value,
exactly what alpha already weights), not beta's (reserved for
CONFIRMED-adjacent structural progress). See chain_value()'s own
docstring for the full derivation, the discount constant's justification,
and why it is deliberately a single hop of lookahead.
"""
from __future__ import annotations

from dataclasses import dataclass

from aginiti.graph.hypothesis import HypothesisStatus
from aginiti.graph.novelty import operator_family_diversification, operator_technique_cluster_diversification
from aginiti.graph.schema import IMPORTANCE_WEIGHT, ClaimStatus, InsightCategory
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.graph.target_belief import TargetBeliefState
from aginiti.graph.target_graph import (
    build_graph,
    build_static_graph,
    distance_to_nearest_target,
    min_distance_to_any,
    shortest_distances,
)
from aginiti.mission import Mission
from aginiti.operators.library import Operator, OperatorLibrary
from aginiti.policies.base import eligible_operators


# Kept equal to IMPORTANCE_WEIGHT["high"] (schema.py), honoring this constant's
# own original stated intent ("same scale as a high importance gap") -- moved
# from 2.0 to 4.0 in lockstep with that 2026-08-09 rescale, not independently
# re-guessed.
_HYPOTHESIS_WEIGHT = IMPORTANCE_WEIGHT["high"]

# Discount applied to a plant operator's borrowed downstream value in
# chain_value() (see that method's own docstring). Deliberately set to
# Hypothesis's own default prior_confidence=0.5 (aginiti/graph/hypothesis.py)
# -- this project's EXISTING "maximally uncertain, no evidence yet"
# convention, reused here rather than independently guessed: reaching a
# plant's own downstream trigger is exactly that kind of not-yet-evidenced
# proposition at the moment the plant is first considered.
_CHAIN_VALUE_DISCOUNT = 0.5

# Per-boundary-rank increment for severity_priority() -- L5 (rank 5) caps
# at 1.0, the same order of magnitude as IMPORTANCE_WEIGHT["low"] --
# deliberately small next to a real business_impact/info_gain gap; see
# severity_priority()'s own docstring for the full reasoning.
_SEVERITY_WEIGHT_PER_LEVEL = 0.2

# failure_evidence_penalty()'s magnitude -- deliberately the SAME order of
# magnitude as severity_priority's max (1.0 at L5, rank 5 * 0.2), not an
# independently-guessed number: a confirmed structural block (a REAL
# negative signal) should be able to fully offset a candidate's max
# severity-driven appeal, forcing genuine reconsideration rather than
# blindly re-attempting something evidence already suggests is blocked --
# but, matching every hard-constraint/soft-nudge split already established
# in this module ("risk and budget are hard constraints... not penalty
# terms inside the maximized quantity"), this stays a SOFT, bounded nudge,
# not a hard exclusion: a candidate with strong OTHER evidence (high
# info_gain, on-path chain_value) can still outrank a demoted one, exactly
# as intended -- the penalty should inform, not veto.
_FAILURE_PENALTY_WEIGHT = 1.0

# hypothesis_escalation_bonus()'s magnitude -- added 2026-08-14 (Issue: "make
# genuine attack-chain construction VISIBLE in ranking, not merely possible").
# Deliberately larger than severity_priority/failure_evidence_penalty's 1.0
# ceiling: this fires only in the specific moment a ClassPrecondition-gated
# operator's eligibility just opened up from a RECENT confirmation -- i.e. a
# genuine "a follow-up just became available" event, not a generic tiebreaker
# -- so it's calibrated to compete with gap_priority/hypothesis_priority's own
# _HYPOTHESIS_WEIGHT ceiling (4.0) rather than the smaller nudge-class terms.
_HYPOTHESIS_ESCALATION_WEIGHT = 3.0


@dataclass
class RankedCandidate:
    operator: Operator
    utility: float
    info_gain: float
    business_impact: float
    path_progress: float
    emergent_impact: float
    potential_progress: float
    chain_value: float
    gap_priority: float
    hypothesis_priority: float
    branch_interest: float
    severity_priority: float
    failure_evidence_penalty: float
    family_diversification: float
    hypothesis_escalation_bonus: float
    alpha: float
    beta: float
    # Appended at the end (not interleaved with the original fields above)
    # deliberately -- this dataclass is constructed POSITIONALLY at its one
    # call site (rank(), below); adding a field at the end keeps every
    # existing positional argument's meaning unchanged.
    technique_cluster_diversification: float = 0.0


class AginitiPlanner:
    """`info_gain_normalization` -- ablation added 2026-08-09 in response to
    a real, user-raised hypothesis grounded in exp12-14's finding that
    declared claim weights could overwhelm potential_progress: raw
    `sum(effect.weight for unresolved effects)` gives an operator that
    happens to declare MANY predicted effects a structural info_gain
    advantage over one that declares FEW, independent of whether any of
    those effects is what actually matters -- exactly backwards for a
    sparse-reward prerequisite step (plant_canary() -> retrieve_document()
    -> trigger_tool() -> observe_exfiltration(), the user's own example),
    whose value lies in what it unlocks, not in how many things it itself
    predicts.

    CONFIRMED as a real, not hypothetical, pattern before building this:
    surveyed every operator library in this repo (47 operators) --
    anythingllm_rag_document_plant, anythingllm_automatic_exfil_document_
    plant, anythingllm_markdown_exfil_document_plant (the EXACT plant
    operators chain_value() was built for), memory_plant_instruction
    (DVAA), and mcp_tool_discovery (MCP) all declare exactly ONE effect,
    while indirect_prompt_injection, a2a_identity_spoof, mcp_no_auth_check,
    consensus_duplicate_vote_stuffing, path_traversal_relative/absolute
    each declare THREE -- a real, existing, cross-target 1-vs-3 (up to 3x)
    differential, not a made-up scenario.

    "sum" (default, UNCHANGED behavior) matches every weight/schedule
    calibration already validated elsewhere (IMPORTANCE_WEIGHT's doubling,
    _HYPOTHESIS_WEIGHT, exp16's "obvious winner" tie-break) -- kept as the
    default per this project's own standing rule (don't change a working
    calibration because one experiment looked bad; prove a replacement
    generalizes first). "mean" divides by the number of still-unresolved
    effects instead of summing them -- crediting the AVERAGE informativeness
    of what this operator would teach, not a count bonus for teaching more
    things. See tests/test_aginiti_planner.py's info_gain_normalization
    tests and experiments/info_gain_normalization_dry_run.py for the
    ablation test + cross-target regression this was evaluated against
    before any default was considered."""

    def __init__(self, info_gain_normalization: str = "sum",
                 enable_family_diversification: bool = False,
                 enable_hypothesis_escalation_bonus: bool = False,
                 enable_technique_cluster_diversification: bool = False) -> None:
        """`enable_family_diversification`/`enable_hypothesis_escalation_
        bonus` -- added 2026-08-14, both default False so an unparameterized
        `AginitiPlanner()` is BYTE-IDENTICAL in ranking behavior to every
        version of this class before this pair existed (config "A" in the
        ablation this pair exists to support -- see experiments/
        exp22_adaptive_planner_ablation.py). Independently toggleable,
        per the explicit instruction that drove them both:

        - `enable_family_diversification` turns on
          `family_diversification()` (aginiti/graph/novelty.py): demotes a
          candidate whose ATTACK FAMILY (attack_category) already looks
          saturated (2+ same-family confirmations, zero successes) and
          gives a small bonus to a genuinely untried family once another
          one looks saturated -- the deterministic "stop burning budget on
          semantically-equivalent attacks, investigate another boundary"
          mechanism.
        - `enable_hypothesis_escalation_bonus` turns on
          `hypothesis_escalation_bonus()`: rewards a `ClassPrecondition`-
          gated operator whose eligibility just opened up from a RECENTLY
          confirmed claim -- makes genuine, discovered (not hard-coded)
          chain continuation an explicit, visible ranking preference
          rather than something that merely becomes possible.
        - `enable_technique_cluster_diversification` -- added later the SAME
          day, in direct response to a real live finding `enable_family_
          diversification` cannot touch: `attack_category` families can
          legitimately contain several near-duplicate WRAPPER variants of
          ONE underlying technique (e.g. hardened_agent_definitions.py's 5
          `authority_claim_probe_*` templates around the same question) --
          turns on `technique_cluster_diversification()`
          (aginiti/graph/novelty.py): an escalating penalty for repeatedly
          re-sampling the SAME author-declared `Operator.technique_cluster`,
          regardless of success (unlike family-level saturation, a cluster
          is NOT success-immune -- see that function's own docstring for
          why). A true no-op for every operator that doesn't set
          `technique_cluster` (the default, common case), so this is safe
          to enable independently of the other two."""
        if info_gain_normalization not in ("sum", "mean"):
            raise ValueError(f'info_gain_normalization must be "sum" or "mean", got {info_gain_normalization!r}')
        self.info_gain_normalization = info_gain_normalization
        self.enable_family_diversification = enable_family_diversification
        self.enable_hypothesis_escalation_bonus = enable_hypothesis_escalation_bonus
        self.enable_technique_cluster_diversification = enable_technique_cluster_diversification

    def _recently_confirmed_in_category(self, ssg: SecurityStateGraph, category: str,
                                         recency_window: int) -> bool:
        """Is there a CONFIRMED claim in this category within the last
        `recency_window` entries of ssg.claims? Fixes the self-documented
        v1 imprecision this method used to carry as `_any_confirmed_in_
        category` ("it doesn't matter how long ago the trust edge was
        confirmed"). ssg.claims is append-only, so recency
        is measured by position, not wall-clock time -- matching this
        project's existing convention of measuring campaign progress in
        steps/prompts, never real time (see _schedule's own budget-
        fraction fallback, PoP's undiscounted gamma=1 framing). Uses
        current_claim() (already handles supersession by scanning for the
        LATEST record per key) so a claim that was confirmed recently but
        has SINCE been superseded/refuted correctly stops counting."""
        keys = {k for k, c in ssg.claim_category.items() if c == category}
        if not keys:
            return False
        total = len(ssg.claims)
        cutoff = max(0, total - recency_window)
        for key in keys:
            claim = ssg.current_claim(key)
            if claim is None or claim.status != ClaimStatus.CONFIRMED:
                continue
            idx = ssg.claims.index(claim)
            if idx >= cutoff:
                return True
        return False

    def _schedule(self, ssg: SecurityStateGraph, prompts_used: int, budget: int) -> tuple[float, float]:
        """alpha/beta start from the original time-based default (explore
        early, exploit late as budget is consumed) but are overridden by
        DISCOVERY events -- added in direct response to the mock-target RQ1
        finding (2026-08-07, docs/EVIDENCE_AND_EVALUATION.md Section 0):
        Aginiti kept exploring broadly for most of a campaign's budget even
        after effectively finding a working path, because elapsed-budget-
        fraction was the ONLY signal driving explore/exploit balance --
        never what had actually been learned. Static-enumeration's fixed
        order happened to reach the SAME trust-edge-then-exploit chain
        immediately and won on cost as a direct, traced result.

        Priority, most aggressive override first:
          - A CONFIRMED trust_edge claim anywhere in the graph is the
            strongest, most specific signal observed across every real
            chain built in this project so far (mock/Slack, DVAA/A2A,
            DVAA/consensus all end with confirm-trust immediately followed
            by the exploit) -- pushes hard toward exploitation (0.2/0.8).
          - A CONFIRMED mission_outcome claim (something already worked,
            but a multi-path mission may have more left to find, per
            emergent_impact's same reasoning) pushes moderately (0.4/0.6).
          - Otherwise, the original time-based schedule, unchanged.

        RECENCY FIX (2026-08-09, internal-audit finding): the original v1
        simplification -- "any CONFIRMED claim in this category, EVER" --
        was a monotonic, history-free check, documented as a known but
        deliberately-accepted gap. Now scoped to claims confirmed within
        `_RECENCY_WINDOW_CLAIMS` entries of ssg.claims (recency measured
        by position, matching this project's step-based rather than
        wall-clock-based convention elsewhere): a trust edge confirmed
        early in the CURRENT campaign still counts (single campaigns
        rarely generate anywhere near this many claims, so behavior within
        one campaign is essentially unchanged from before -- this
        primarily matters for a RESUMED, long-lived graph, exactly the
        "graph outlives the campaign" usage this project is built for,
        where an old claim from a much earlier session should no longer
        push toward exploitation as if it just happened). Window scales
        with `budget` rather than being a bare fixed constant, so it stays
        proportionate to how much history a given mission could plausibly
        accumulate."""
        recency_window = max(4, 2 * budget)
        if self._recently_confirmed_in_category(ssg, CATEGORY_TRUST_EDGE, recency_window):
            return 0.2, 0.8
        if self._recently_confirmed_in_category(ssg, CATEGORY_MISSION_OUTCOME, recency_window):
            return 0.4, 0.6
        frac = min(1.0, prompts_used / budget) if budget else 1.0
        alpha = max(0.05, 1.0 - frac)
        beta = min(1.0, 0.05 + frac)
        return alpha, beta

    def information_gain(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """Equation 14.1: sum (or, under info_gain_normalization="mean" --
        see this class's own docstring -- the MEAN) of per-claim-type
        weight over predicted Claims not yet resolved (still unknown or
        only hypothesized) -- a claim already confirmed/refuted has no new
        information left to gain. "sum" is the original, still-default
        formula: an operator that declares more still-open effects
        accumulates more info_gain purely from declaring more of them.
        "mean" instead credits the AVERAGE per-effect weight, so declaring
        many low-value effects no longer outscores declaring one
        high-value effect the way "sum" lets it."""
        total = 0.0
        count = 0
        for effect in (*operator.effects_success, *operator.effects_failure):
            current = ssg.current_claim(effect.key)
            if current is None or current.status == ClaimStatus.HYPOTHESIZED:
                total += effect.weight
                count += 1
        if self.info_gain_normalization == "mean" and count > 0:
            return total / count
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

    def emergent_targets(self, library: OperatorLibrary) -> tuple[str, ...]:
        """Claim keys ANY operator in the library declares as a
        CATEGORY_MISSION_OUTCOME-categorized CONFIRMED effect -- the
        library's own structural notion of "this would be a real
        compromise," independent of which specific ones a human named in
        Mission.success_criteria up front. This is what lets a
        stepping-stone toward an unnamed-but-recognized compromise be told
        apart from a genuine dead end -- a real, evidence-backed gap found
        by experiments/exp7_consequence_propagation_gap.py: two operators
        with identical declared weight and no shared target got IDENTICAL
        utility, because business_impact/path_progress only ever look at
        the fixed criteria a human wrote down in advance."""
        return tuple(sorted({
            effect.key
            for op in library
            for effect in (*op.effects_success, *op.effects_failure)
            if effect.category == CATEGORY_MISSION_OUTCOME and effect.status == ClaimStatus.CONFIRMED
        }))

    def emergent_impact(self, operator: Operator, mission: Mission,
                         ssg: SecurityStateGraph, library: OperatorLibrary) -> float:
        """Same BFS mechanism as path_progress, but against
        emergent_targets() instead of only mission.success_criteria --
        rewards an operator for shortening the path toward ANY compromise
        the library itself recognizes as mission-outcome-shaped, not just
        the ones a human anticipated when writing the Mission. Targets
        already covered by mission.success_criteria are excluded here to
        avoid double-counting path_progress's own credit for the same node.
        This is deliberately NOT a replacement for path_progress -- a
        separate, individually-inspectable term, same pattern as
        gap_priority/hypothesis_priority sitting alongside the terms they
        extend rather than folding silently into them."""
        if operator.graph_edge is None:
            return 0.0
        targets = tuple(k for k in self.emergent_targets(library) if k not in mission.success_criteria)
        if not targets:
            return 0.0

        baseline_graph = build_graph(library, ssg)
        baseline_min = min_distance_to_any(shortest_distances(baseline_graph), targets)

        hypothetical_graph = build_graph(library, ssg, extra_edge=operator.graph_edge)
        hypothetical_min = min_distance_to_any(shortest_distances(hypothetical_graph), targets)

        if hypothetical_min is None:
            return 0.0
        if baseline_min is None:
            return 3.0
        if hypothetical_min < baseline_min:
            return 1.0
        return 0.0

    def potential_progress(self, operator: Operator, mission: Mission, library: OperatorLibrary) -> float:
        """Potential-based reward shaping (Ng, Harada & Russell 1999) --
        see this module's own docstring for the full derivation and why
        it's a separate term from path_progress/emergent_impact, not a
        replacement. Phi(node) = -distance(node -> nearest target) over
        build_static_graph()'s library-wide graph (every declared
        graph_edge, confirmed or not); this operator's shaping term is
        Phi(v) - Phi(u) for graph_edge=(u, v), clamped at 0 -- same "only
        ever helps, never hurts" rule as branch_interest. Deliberately
        takes NO ssg parameter: this is the one term in the whole formula
        that depends purely on library structure, not campaign state --
        a constant per operator for a fixed library and mission.

        SELF-REVIEW FIX (2026-08-08, same day as this term was added):
        the first version of this method scoped `targets` to
        mission.success_criteria ONLY -- but emergent_impact exists
        precisely because a stepping-stone toward an UNNAMED, library-
        recognized compromise is exactly as real a target as a named one
        (experiments/exp7_consequence_propagation_gap.py), and that gap
        is caused by the SAME confirmed-only build_graph() limitation
        this whole term exists to route around. Leaving potential_progress
        scoped to named targets only would have closed the sparsity gap
        for path_progress but left it wide open for emergent_impact's
        targets -- an incomplete fix to the same underlying problem.
        Folded emergent_targets() into ONE shared Phi instead of adding a
        second, separately-scaled term (unlike PP/EP, which stay split to
        avoid double-counting a shared BFS comparison): Phi has no such
        double-counting risk, since it's a single distance-to-nearest-
        target computation over the union, not two independent
        before/after comparisons -- the simpler, more complete design,
        not a rescoped version of PP/EP's split for its own sake."""
        if operator.graph_edge is None:
            return 0.0
        named_targets = mission.success_criteria
        emergent = tuple(k for k in self.emergent_targets(library) if k not in named_targets)
        targets = named_targets + emergent
        if not targets:
            return 0.0
        u, v = operator.graph_edge
        static_graph = build_static_graph(library)
        distances = distance_to_nearest_target(static_graph, targets)
        if u not in distances or v not in distances:
            # No static path from this endpoint to any target at all --
            # neutral, not penalized (an operator can be valuable for
            # other terms -- info_gain, gap_priority -- while sitting
            # off the shortest-path skeleton entirely).
            return 0.0
        return max(0.0, distances[u] - distances[v])

    def chain_value(self, operator: Operator, mission: Mission, ssg: SecurityStateGraph,
                     library: OperatorLibrary) -> float:
        """Value-informed extension of potential-based reward shaping --
        added 2026-08-09 in direct response to a real, live-diagnosed
        finding (experiments/exp17_hardened_target.py): potential_progress's
        Phi is PURELY topological (-hop-distance-to-nearest-target). It
        treats every "one hop closer" edge as worth exactly the same
        credit, whether the far end is a high-value compromise or a
        near-worthless one -- it cannot tell a GOOD stepping stone from a
        mediocre one, only a stepping stone from a dead end.

        Wiewiora, Cottrell & Elkan (2003, "Principled Methods for
        Advising Reinforcement Learning Agents") proved potential-based
        shaping with Phi is EXACTLY equivalent to initializing the value
        function with Phi -- the closer Phi approximates real downstream
        value, the more useful the shaping actually is. A purely
        topological Phi is a weak, uninformed initialization.

        Confirmed live on exp17: a "plant" operator (its own declared
        effect is a setup claim, not a mission-outcome claim) scores
        info_gain=1.0, business_impact=0.0, path_progress=0.0 -- ONLY
        potential_progress credits it at all (1.0, discounted 20x by
        beta=0.05 early in a mission), while a same-cost, single-step
        operator whose effect directly IS a mission-outcome claim scores
        info_gain=4.0, business_impact=0.2, weighted by alpha=1.0 at the
        same point. Net: any plant was outscored ~3.8x by any
        immediately-resolving single-step option at mission start,
        regardless of how good the plant's OWN downstream chain actually
        is -- structurally unable to ever prefer a multi-step chain over
        a single-step option this way, even one where the chain is the
        clearly better bet.

        This term closes that gap the way the theory says to: give a
        plant operator partial credit NOW for what its own declared
        downstream operator(s) would be worth if reached -- computed via
        THIS SAME planner's existing information_gain()/business_impact()
        methods (no new value model; reuses exactly what already scores
        every other candidate) -- discounted by _CHAIN_VALUE_DISCOUNT
        (0.5, this project's existing "maximally uncertain, no evidence
        yet" convention -- see that constant's own comment -- not an
        independently-guessed number).

        Deliberately ONE hop of lookahead, not a recursive downstream
        walk: every chain in this project's operator library today is
        exactly two steps (plant, then trigger) -- see the anythingllm_*
        chain definition modules. A single one-hop backup matches the
        actual chain depth that exists, rather than adding untested
        recursive machinery for a case that doesn't exist yet. If a
        longer chain is added later, this intentionally still only
        credits one hop ahead of ANY given operator -- exactly what a
        single Bellman backup does, and safely conservative: it can only
        ever UNDER-credit a longer chain, never fabricate value that
        isn't backed by a real declared downstream operator.

        Finds "downstream" operators structurally, via graph_edge
        adjacency (this operator's edge target == the candidate
        downstream operator's edge source) -- the same graph_edge
        machinery path_progress/potential_progress already read, not a
        new precondition-parsing mechanism. Sits ALONGSIDE
        potential_progress, never replaces it -- same "new term added
        independently, not folded silently into an existing one"
        pattern as every other term in this module. Only ever helps,
        never hurts: 0.0 for any operator with no graph_edge, or whose
        edge has no declared downstream operator in this library."""
        if operator.graph_edge is None:
            return 0.0
        _, v = operator.graph_edge
        best = 0.0
        for downstream in library:
            if downstream.id == operator.id or downstream.graph_edge is None:
                continue
            u2, _ = downstream.graph_edge
            if u2 != v:
                continue
            value = self.information_gain(downstream, ssg) + self.business_impact(downstream, mission, ssg)
            best = max(best, value)
        return _CHAIN_VALUE_DISCOUNT * best

    def budget_feasible(self, operator: Operator, mission: Mission, library: OperatorLibrary,
                         budget_remaining: int) -> bool:
        """Hard feasibility pruning (2026-08-09) -- closes a real,
        live-diagnosed gap: `eligible_operators()` (aginiti/policies/
        base.py) already excludes an operator whose OWN cost exceeds
        remaining budget, but nothing anywhere checked whether the REST of
        a multi-step chain that operator starts can still fit. Confirmed
        live on branching_chat_rag: with 1 prompt of budget left,
        AginitiPlanner repeatedly spent it starting
        anythingllm_rag_document_plant (cost 1) -- the FIRST half of a
        2-step chain that needs anythingllm_rag_injection_trigger to ever
        pay off -- a mathematically guaranteed failure, when a genuinely
        completable single-step alternative was sitting right there,
        unchosen, in the same candidate set.

        Reuses build_static_graph()/distance_to_nearest_target() exactly
        as potential_progress() does -- the library's own fixed,
        optimistic structural graph, not gated on confirmed evidence
        (same relaxed-problem-heuristic role as PoP's Phi). The bound is
        deliberately ADMISSIBLE/OPTIMISTIC, never a false negative: it
        prices every remaining hop at `min(op.cost_prompts for op in
        library)`, the cheapest any operator in this library could
        possibly cost, so it only ever rules out a candidate whose chain
        is unwinnable even in the absolute best case. An operator with no
        graph_edge (every flat, single-step probe) is trivially always
        feasible -- this term has nothing to say about a candidate that
        isn't part of a declared chain at all.

        Deliberately a HARD gate on the candidate set (rank() uses this to
        `continue`, not to discount utility), matching this module's own
        stated design ("Risk and budget are hard constraints... not
        penalty terms inside the maximized quantity") -- the same
        principle already applied to operator.cost_prompts itself, now
        extended to the operator's downstream chain cost."""
        if operator.graph_edge is None:
            return True  # not part of a declared chain; nothing for this term to prune
        if operator.cost_prompts > budget_remaining:
            return True  # eligible_operators() already excludes this candidate; not this method's call to make
        _, v = operator.graph_edge
        named_targets = mission.success_criteria
        emergent = tuple(k for k in self.emergent_targets(library) if k not in named_targets)
        targets = named_targets + emergent
        if not targets:
            return True
        static_graph = build_static_graph(library)
        distances = distance_to_nearest_target(static_graph, targets)
        if v not in distances:
            return True  # no static path toward any target at all; not this term's question to answer
        remaining_hops = distances[v]
        if remaining_hops == 0:
            return True  # this operator's own success already reaches a target
        min_hop_cost = min((op.cost_prompts for op in library if op.cost_prompts > 0), default=1)
        remaining_after_this = budget_remaining - operator.cost_prompts
        return remaining_after_this >= remaining_hops * min_hop_cost

    def gap_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """How much do currently-open KNOWLEDGE_GAP insights want THIS
        operator run next? Sums importance-weighted contributions from
        every gap whose `related_probe_id` names this operator. This is
        what makes synthesized understanding actually reshape planning:
        without it, an Insight is read-only commentary the planner never
        sees -- Claims are the only thing `rank()` reasons over. A gap
        tagged importance="high" pointing at an unexplored operator now
        pulls that operator up the ranking on its own, independent of
        what info_gain/business_impact/path_progress alone would say.

        Uses `insight.priority_weight` (a fine-grained numeric nudge WITHIN
        the importance bucket -- schema.py's Insight docstring) when a
        caller set one, falling back to the coarse 3-bucket lookup exactly
        as before when it's None -- true for every insight the Reasoning
        Layer forms today, so that pathway is completely unaffected. Added
        2026-08-09 to fix a live-diagnosed collapse: aginiti/graph/
        priors.py's cold-start seeding could put a KNOWN, always-defended
        trap operator in the exact same bucket ("medium") as a real,
        reliably-working operator, making AginitiPlanner's very first pick
        a coin flip on shuffle order between them -- confirmed live on
        branching_chat_rag (memory_context_leakage_probe, a known trap,
        and system_prompt_extraction, a real win, both scored exactly
        5.0125). priority_weight breaks that tie deterministically without
        changing this method's contract for anything that doesn't set it."""
        total = 0.0
        for insight in ssg.insights:
            if insight.category == InsightCategory.KNOWLEDGE_GAP and insight.related_probe_id == operator.id:
                if insight.priority_weight is not None:
                    total += insight.priority_weight
                else:
                    total += IMPORTANCE_WEIGHT.get(insight.importance, 0.5)
        return total

    def hypothesis_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """"Which experiment maximizes expected information gain about an
        open hypothesis?" as an actual computation: sums
        uncertainty-weighted contributions from every OPEN hypothesis
        that names this operator as one of its `experiments`.
        Hypothesis.uncertainty peaks at confidence=0.5 (maximally
        undecided -- testing it teaches the most) and is 0 once resolved
        (nothing left to learn), so a hypothesis close to being settled
        stops competing for the planner's attention on its own, without
        any extra bookkeeping here."""
        total = 0.0
        for hyp in ssg.hypotheses.values():
            if hyp.status == HypothesisStatus.OPEN and operator.id in hyp.experiments:
                total += hyp.uncertainty * _HYPOTHESIS_WEIGHT
        return total

    def branch_interest(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """The fix for a gap a live trace proved was real (2026-08-08):
        aginiti/graph/belief_state.py's deterministic branch propagation
        and gated Reasoning Layer both correctly populate
        ssg.belief.branches, but nothing in this planner read any of it --
        a full campaign produced an identical operator sequence to the
        pre-belief-state baseline, to the prompt. This is what actually
        closes that gap: how much has THIS operator's branch (payroll/
        github/helpdesk/... -- see Operator.branch) proven itself worth
        pursuing, from everything confirmed anywhere in that branch so
        far, including same-category evidence found in OTHER branches
        (milestone 2's cross-branch propagation) and the Reasoning
        Layer's own judgment calls (milestone 3's branch_signal).

        Reads ssg.belief.branch_signal() -- CampaignBeliefState's
        encapsulated accessor (2026-08-08 design tightening), never
        `.branches[...]` directly. That keeps BranchBelief's internal
        fields and update rules free to change shape later without this
        method needing to change too, and it's what makes
        `.exploration_signal` (not `.priority`) the only thing reachable
        here: `.priority` folds branch-level risk in as a subtraction,
        and this module's own docstring is explicit that risk must be a
        hard constraint on candidates, never a penalty folded into the
        maximized scalar. Untagged operators (operator.branch is None --
        every DVLA/DVAA/MCP operator today) and never-seen branches both
        resolve to the same all-zero signal, a true no-op: this term
        only ever helps a branch-tagged, evidenced candidate, never hurts
        one relative to before this method existed."""
        return ssg.belief.branch_signal(operator.branch).exploration_signal

    def severity_priority(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """Added 2026-08-09 -- closes a real, named gap: this planner had
        NO awareness whatsoever of finding severity. Every term above asks
        "does this resolve something unknown" or "does this satisfy the
        mission" -- none of them ask "if this succeeds, how serious is
        what it would prove," so a planner facing two comparably-likely,
        comparably-costed options with no other tiebreaker had literally
        nothing to prefer the more consequential one with. See aginiti/
        graph/security_boundary.py for the L0 (model behavior) through L5
        (confirmed exfiltration) taxonomy this reads.

        A modest, bounded, additive nudge -- NOT a dominant term and
        deliberately NOT alpha/beta-scaled: this is a tiebreaker among
        otherwise-comparable options, not a license to chase a dangerous
        or expensive long-shot over a cheap, reliable win. Risk stays a
        HARD constraint via risk_tier/risk_threshold exactly as this
        module's own docstring already establishes for every other term
        -- severity_priority never overrides that, it only helps choose
        among candidates that already cleared it.

        best_rank = the highest security_boundary rank among this
        operator's STILL-UNRESOLVED effects (a claim already confirmed or
        refuted has nothing left to prove, matching information_gain's own
        "already resolved -> no credit" rule). Untagged operators (no
        effect carries a security_boundary at all -- the overwhelming
        majority of this repo's operators today, by that module's own
        deliberately-incremental design) score exactly 0.0, a true no-op:
        this term only ever helps a severity-tagged candidate, never
        penalizes an untagged one relative to before this method existed.
        L0 itself also scores 0.0 (rank 0) -- the least severe class earns
        no special priority, only genuinely elevated severity above it
        does. Bounded at 1.0 for L5 (rank 5 * 0.2), the same order of
        magnitude as IMPORTANCE_WEIGHT["low"], intentionally small next to
        a real business_impact/info_gain gap."""
        from aginiti.graph.security_boundary import rank as boundary_rank

        best_rank = -1
        for effect in (*operator.effects_success, *operator.effects_failure):
            if effect.security_boundary is None:
                continue
            current = ssg.current_claim(effect.key)
            if current is not None and current.status != ClaimStatus.HYPOTHESIZED:
                continue  # already resolved -- nothing left to prove
            best_rank = max(best_rank, boundary_rank(effect.security_boundary))
        if best_rank < 0:
            return 0.0
        return _SEVERITY_WEIGHT_PER_LEVEL * best_rank

    def failure_evidence_penalty(self, operator: Operator, ssg: SecurityStateGraph) -> float:
        """Added 2026-08-12 at explicit user direction (Issue 4 of that
        day's architectural directive: "give the planner better feedback
        from failure"): "A failure shouldn't simply mean 'attack failed.'
        It should produce structured evidence... Then the planner should
        ask: given what I just learned, what attack path is now more
        promising?"

        Before this, a failure only ever removed ONE candidate from
        contention -- the executed_ids one-shot-per-operator rule stops
        Aginiti from blindly re-running the EXACT SAME operator, but
        nothing generalized that evidence to a DIFFERENT operator that
        would plausibly fail for the SAME structural reason. This closes
        that gap: if a CONFIRMED failure claim anywhere in the graph
        carries a GENERALIZABLE failure_diagnosis tag (aginiti/graph/
        failure_diagnosis.py -- blocked_by_privilege, blocked_by_network_
        egress, blocked_by_approval_gate; NOT not_retrieved/
        actively_refused, which are deliberately excluded as
        non-generalizable, see that module's own docstring), and THIS
        candidate's own prospective failure effect carries the IDENTICAL
        tag, that's real, specific evidence the same mechanism plausibly
        blocks this candidate too -- demote it.

        Reuses the exact tag-matching idea ClassPrecondition already
        established for POSITIVE evidence (aginiti/operators/library.py)
        -- this is the same mechanism applied to NEGATIVE evidence: "any
        claim matching this semantic tag" rather than one exact key,
        generalizing across operators that were never wired to reference
        each other.

        A negative, bounded, additive nudge -- same "soft nudge, not a
        hard exclusion" discipline as severity_priority (see
        _FAILURE_PENALTY_WEIGHT's own comment): a genuinely strong
        candidate on every other term can still outrank a demoted one.
        Untagged operators (no failure effect carries a failure_diagnosis
        at all -- every operator in this repo before Issue 4) score
        exactly 0.0, a true no-op."""
        from aginiti.graph.failure_diagnosis import is_generalizable

        prospective_diagnoses = {
            effect.failure_diagnosis for effect in operator.effects_failure
            if is_generalizable(effect.failure_diagnosis)
        }
        if not prospective_diagnoses:
            return 0.0
        for key, diagnosis in ssg.claim_failure_diagnosis.items():
            if diagnosis not in prospective_diagnoses:
                continue
            claim = ssg.current_claim(key)
            if claim is not None and claim.status == ClaimStatus.CONFIRMED:
                return -_FAILURE_PENALTY_WEIGHT
        return 0.0

    def family_diversification(self, operator: Operator, belief: TargetBeliefState) -> float:
        """Thin wrapper over aginiti/graph/novelty.py's pure function --
        see that module's own docstring for the full reasoning. Returns
        0.0 unconditionally when `enable_family_diversification` is off,
        matching every other opt-in term's "untagged/disabled -> true
        no-op" discipline."""
        if not self.enable_family_diversification:
            return 0.0
        return operator_family_diversification(operator, belief)

    def technique_cluster_diversification(self, operator: Operator, belief: TargetBeliefState) -> float:
        """Thin wrapper over aginiti/graph/novelty.py's pure function --
        see that module's own docstring (the "second addition this same
        day" section) for the full reasoning and why this is deliberately
        NOT success-immune the way family_diversification is. Returns 0.0
        unconditionally when `enable_technique_cluster_diversification` is
        off, matching every other opt-in term's discipline."""
        if not self.enable_technique_cluster_diversification:
            return 0.0
        return operator_technique_cluster_diversification(operator, belief)

    def _recently_satisfied_class_precondition(self, cpre, ssg: SecurityStateGraph,
                                                 recency_window: int) -> bool:
        """Same semantic-tag matching `Operator.preconditions_met()` already
        performs for ELIGIBILITY (aginiti/operators/library.py's
        ClassPrecondition) -- scoped here to whether a MATCHING claim was
        confirmed RECENTLY (mirrors `_recently_confirmed_in_category`'s own
        position-based recency window above), i.e. did this operator's
        eligibility genuinely just open up versus having sat eligible for a
        while already. Deliberately a parallel implementation rather than a
        call into Operator's own private `_class_precondition_met` -- that
        method has no recency concept to thread through."""
        from aginiti.graph.security_boundary import rank as boundary_rank

        candidate_keys = set(ssg.claim_category) | set(ssg.claim_attack_category) | set(ssg.claim_boundary)
        total = len(ssg.claims)
        cutoff = max(0, total - recency_window)
        for key in candidate_keys:
            if cpre.category is not None and ssg.claim_category.get(key) != cpre.category:
                continue
            if cpre.attack_category is not None and ssg.claim_attack_category.get(key) != cpre.attack_category:
                continue
            if cpre.min_security_boundary_rank is not None:
                level = ssg.claim_boundary.get(key)
                if level is None or boundary_rank(level) < cpre.min_security_boundary_rank:
                    continue
            claim = ssg.current_claim(key)
            if claim is None or claim.status != ClaimStatus.CONFIRMED:
                continue
            idx = ssg.claims.index(claim)
            if idx >= cutoff:
                return True
        return False

    def hypothesis_escalation_bonus(self, operator: Operator, ssg: SecurityStateGraph,
                                     recency_window: int) -> float:
        """Rewards a `ClassPrecondition`-gated operator whose eligibility
        just opened up from a claim confirmed RECENTLY -- see this class's
        __init__ docstring for the full motivation. 0.0 for any operator
        with no precondition_classes at all (every operator predating
        2026-08-12's ClassPrecondition mechanism, and most still today),
        or when disabled -- a true no-op either way."""
        if not self.enable_hypothesis_escalation_bonus:
            return 0.0
        if not operator.precondition_classes:
            return 0.0
        for cpre in operator.precondition_classes:
            if self._recently_satisfied_class_precondition(cpre, ssg, recency_window):
                return _HYPOTHESIS_ESCALATION_WEIGHT
        return 0.0

    def _score(self, op: Operator, mission: Mission, ssg: SecurityStateGraph, library: OperatorLibrary,
               alpha: float, beta: float, belief: TargetBeliefState | None,
               recency_window: int) -> tuple[float, float, float, dict]:
        """The formula, computed exactly ONCE per (operator, rank-call) --
        shared by `rank()` and `diagnose()` so the two can never silently
        drift apart (the same "MUST mirror" duplication risk schema.py's
        own IMPORTANCE_WEIGHT consolidation comment warns against).

        Returns (core_utility, fdiv, heb, tcdiv, terms): `core_utility` is
        every term GROUNDED IN ACCUMULATED EVIDENCE about this specific
        candidate -- info gain, structural graph progress, gap/hypothesis
        pull, severity, and an EXACT failure-diagnosis tag match. `fdiv`
        (family_diversification), `heb` (hypothesis_escalation_bonus), and
        `tcdiv` (technique_cluster_diversification) are kept OUT of
        `core_utility` on purpose: they are exploration/redirection NUDGES
        over a FAMILY (or cluster) of candidates (novelty.py's own stated
        contract: "informs, never vetoes"), not evidence about this one
        candidate's own remaining value. See `rank()`'s own comment for
        why collapsing them back into one number before pruning is exactly
        the bug exp23 found live."""
        ig = self.information_gain(op, ssg)
        bi = self.business_impact(op, mission, ssg)
        pp = self.path_progress(op, mission, ssg, library)
        ep = self.emergent_impact(op, mission, ssg, library)
        pop = self.potential_progress(op, mission, library)
        cv = self.chain_value(op, mission, ssg, library)
        gp = self.gap_priority(op, ssg)
        hp = self.hypothesis_priority(op, ssg)
        bri = self.branch_interest(op, ssg)
        sp = self.severity_priority(op, ssg)
        fep = self.failure_evidence_penalty(op, ssg)
        fdiv = self.family_diversification(op, belief) if belief is not None else 0.0
        heb = self.hypothesis_escalation_bonus(op, ssg, recency_window)
        tcdiv = self.technique_cluster_diversification(op, belief) if belief is not None else 0.0
        # cv joins ig in alpha's basket, not beta's: it is speculative
        # lookahead value (like ig, resolving what's currently unknown),
        # not yet-confirmed structural progress (what beta's bi/pp/ep/pop
        # terms are reserved for) -- see chain_value()'s own docstring. sp
        # and fep join gp/hp/bri as unscaled additive nudges -- see each
        # one's own docstring for why they must never be alpha/beta-weighted.
        core_utility = alpha * (ig + cv) + beta * (bi + pp + ep + pop) + gp + hp + bri + sp + fep
        terms = dict(info_gain=ig, business_impact=bi, path_progress=pp, emergent_impact=ep,
                     potential_progress=pop, chain_value=cv, gap_priority=gp, hypothesis_priority=hp,
                     branch_interest=bri, severity_priority=sp, failure_evidence_penalty=fep)
        return core_utility, fdiv, heb, tcdiv, terms

    def rank(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
              prompts_used: int, executed_ids: frozenset[str] = frozenset()) -> list[RankedCandidate]:
        alpha, beta = self._schedule(ssg, prompts_used, mission.budget)
        budget_remaining = mission.budget - prompts_used
        recency_window = max(4, 2 * mission.budget)
        # Computed ONCE per rank() call, not per-candidate -- all three
        # nudge terms below read this same snapshot; TargetBeliefState.
        # from_ssg is a single linear scan over ssg.claims, negligible next
        # to the BFS calls path_progress/emergent_impact already run per
        # candidate. Built whenever EITHER family- or cluster-level
        # diversification is enabled -- both read the same snapshot.
        belief = (TargetBeliefState.from_ssg(ssg, library)
                  if self.enable_family_diversification or self.enable_technique_cluster_diversification
                  else None)
        ranked = []
        for op in eligible_operators(library, ssg, mission, prompts_used, executed_ids):
            if not self.budget_feasible(op, mission, library, budget_remaining):
                continue  # provably can't complete this chain within remaining budget -- see budget_feasible()
            core_utility, fdiv, heb, tcdiv, terms = self._score(op, mission, ssg, library, alpha, beta,
                                                                   belief, recency_window)
            # STRUCTURAL invariant (2026-08-14 fix, exp23 postmortem):
            # the feasibility gate below reads ONLY core_utility -- the
            # evidence-grounded terms -- never fdiv/heb. Before this fix,
            # `utility <= 0: continue` tested the FULL sum including fdiv/
            # heb, so family_diversification's saturation penalty (bounded
            # at -3.0) could push an otherwise-viable candidate's total
            # below zero and SILENTLY REMOVE IT from the ranked list --
            # exactly what novelty.py's own docstring says this term must
            # never do ("informs, never vetoes... a candidate with a
            # genuinely large advantage can still outrank a demoted one").
            # Live-confirmed cause of exp23's SEARCH_EXHAUSTED-with-budget-
            # remaining failure (3/3 D_full_adaptive hardened_agent
            # campaigns, 15-16 of 24 operators still untried each time):
            # once two families looked saturated, every member of both
            # dropped below zero here and vanished, not merely demoted.
            #
            # Now: diversification/escalation can only ever influence
            # WHERE a candidate sorts among the survivors (even pushing its
            # final utility negative), never WHETHER it survives at all --
            # only genuine evidence-based infeasibility (unmet precondition,
            # already executed, provable budget/chain infeasibility, or
            # core_utility itself <= 0) can remove a candidate. This is also
            # what restores principled exploration (item 6 of that
            # postmortem) for free, with no new mechanism: once every
            # currently-favored candidate is executed or genuinely
            # infeasible, the next-best SURVIVING candidate -- even one from
            # a "saturated" family -- naturally rises to the top of what's
            # left, instead of the campaign reporting SEARCH_EXHAUSTED while
            # real candidates remain.
            if core_utility <= 0:
                continue  # no evidence-based value left -- a rational planner has no reason to run it
            utility = core_utility + fdiv + heb + tcdiv
            ranked.append(RankedCandidate(op, utility, terms["info_gain"], terms["business_impact"],
                                           terms["path_progress"], terms["emergent_impact"],
                                           terms["potential_progress"], terms["chain_value"],
                                           terms["gap_priority"], terms["hypothesis_priority"],
                                           terms["branch_interest"], terms["severity_priority"],
                                           terms["failure_evidence_penalty"], fdiv, heb, alpha, beta,
                                           technique_cluster_diversification=tcdiv))
        ranked.sort(key=lambda c: c.utility, reverse=True)
        return ranked

    def diagnose(self, library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
                 prompts_used: int, executed_ids: frozenset[str] = frozenset()) -> list:
        """Read-only accounting over EVERY operator in `library` (not just
        what survived into `rank()`'s own output) -- added 2026-08-14 at
        explicit direction: "If an operator is intentionally excluded,
        record exactly why." Shares `_score()` with `rank()`, so this can
        never silently disagree with what actually got ranked -- it only
        adds the classification/reason `rank()` itself has no reason to
        carry. See aginiti/graph/candidate_status.py for the full status
        taxonomy and why each one is a genuinely different situation (an
        already-tried operator, a structurally-impossible one, and a
        currently-low-value-but-still-viable one are NOT the same thing,
        and collapsing them into "not chosen" is exactly what made exp23's
        premature SEARCH_EXHAUSTED unreadable from the outside)."""
        from aginiti.graph.candidate_status import CandidateDiagnostic, CandidateStatus
        from aginiti.policies.base import satisfies_constraints

        alpha, beta = self._schedule(ssg, prompts_used, mission.budget)
        budget_remaining = mission.budget - prompts_used
        recency_window = max(4, 2 * mission.budget)
        belief = (TargetBeliefState.from_ssg(ssg, library)
                  if self.enable_family_diversification or self.enable_technique_cluster_diversification
                  else None)
        out = []
        for op in library:
            if op.id in executed_ids:
                out.append(CandidateDiagnostic(op.id, CandidateStatus.ALREADY_EXECUTED,
                                                "one-shot rule: deterministic operator against "
                                                "unchanged state -> no new info"))
                continue
            if not op.preconditions_met(ssg):
                out.append(CandidateDiagnostic(op.id, CandidateStatus.PRECONDITION_NOT_MET,
                                                "exact-key or class precondition not yet satisfied -- "
                                                "may become eligible later as evidence accumulates"))
                continue
            if op.cost_prompts > budget_remaining:
                out.append(CandidateDiagnostic(op.id, CandidateStatus.COST_EXCEEDS_BUDGET,
                                                f"cost_prompts={op.cost_prompts} > budget_remaining={budget_remaining}"))
                continue
            if not satisfies_constraints(op, mission, budget_remaining):
                out.append(CandidateDiagnostic(op.id, CandidateStatus.RISK_EXCEEDS_THRESHOLD,
                                                f"risk_tier={op.risk_tier.value} exceeds "
                                                f"mission.risk_threshold={mission.risk_threshold.value}, or "
                                                "destructive tier with no human-approval loop"))
                continue
            if not self.budget_feasible(op, mission, library, budget_remaining):
                out.append(CandidateDiagnostic(op.id, CandidateStatus.CHAIN_BUDGET_INFEASIBLE,
                                                "budget_feasible(): the rest of this operator's declared "
                                                "chain provably cannot complete within remaining budget, "
                                                "even in the best case"))
                continue
            core_utility, fdiv, heb, tcdiv, _terms = self._score(op, mission, ssg, library, alpha, beta,
                                                                    belief, recency_window)
            if core_utility <= 0:
                out.append(CandidateDiagnostic(op.id, CandidateStatus.EVIDENCE_EXHAUSTED,
                                                f"core_utility={core_utility:.3f} <= 0: every predicted "
                                                "effect already resolved and/or a confirmed exact "
                                                "failure-diagnosis match -- genuinely no evidence-based "
                                                "value left, independent of exploration terms"))
                continue
            utility = core_utility + fdiv + heb + tcdiv
            out.append(CandidateDiagnostic(op.id, CandidateStatus.RANKED,
                                            f"utility={utility:.3f} (core={core_utility:.3f}, "
                                            f"family_diversification={fdiv:.3f}, "
                                            f"hypothesis_escalation_bonus={heb:.3f}, "
                                            f"technique_cluster_diversification={tcdiv:.3f}) -- ranked, "
                                            "regardless of how low utility itself is"))
        return out
