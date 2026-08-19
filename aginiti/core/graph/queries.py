"""Analyst-facing queries over a SecurityStateGraph.

This module is where "the graph is the source of truth, the campaign is
one consumer" becomes concrete: every function here reads a graph (plus,
where the question needs it, the OperatorLibrary/Mission that produced it)
and returns a plain answer -- no campaign object required, nothing
executed against a target. `recommend_next` is the interesting case: it
reuses AginitiPlanner's own utility math, but as a read-only projection
("what would the planner do") rather than the thing that actually drives
an autonomous loop. The planner becomes one query among several, not the
privileged center of the architecture.

All of these answer directly from what's already in the graph -- Facts for
`observed_tools` (schema.py's Fact/Observation/Claim tiering), Claims for
everything else. `observed_tools` is honest about a real limitation: it
reports which tools were actually INVOKED, but answering "observed but
never exercised" in full needs the target's complete tool inventory,
which BaseAdapter has no way to enumerate today (DVLA's tools live inside
a LangChain agent object, not a declared list). Extending BaseAdapter
with an optional `list_tools()` is a reasonable next step but a separate,
adapter-contract-level change -- not bundled in here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.core.graph.schema import Claim, ClaimStatus
from aginiti.core.graph.ssg import (
    CATEGORY_CAPABILITY,
    CATEGORY_MISSION_OUTCOME,
    CATEGORY_TRUST_EDGE,
    SUBGRAPH_DEFENDER,
    SecurityStateGraph,
)
from aginiti.core.mission import Mission
from aginiti.operators.library import Operator, OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner, RankedCandidate


def latest_claims(ssg: SecurityStateGraph) -> list[Claim]:
    """One entry per key -- the current (latest) version of each claim, per
    the append-only log's "later wins" rule (same rule ssg.current_claim
    applies per-key; this does it for every key at once). Public: reused
    by aginiti/graph/insights.py's synthesis step, not just internally
    here."""
    latest: dict[str, Claim] = {}
    for claim in ssg.claims:
        latest[claim.key] = claim
    return list(latest.values())


def trust_assumptions(ssg: SecurityStateGraph) -> list[Claim]:
    """Which trust relationships has the agent revealed, in whatever
    direction the evidence settled on (CONFIRMED = it trusts the source;
    REFUTED = it doesn't; HYPOTHESIZED = raised but not yet resolved)."""
    return [c for c in latest_claims(ssg) if ssg.claim_category.get(c.key) == CATEGORY_TRUST_EDGE]


def disproven_assumptions(ssg: SecurityStateGraph) -> list[Claim]:
    """Claims the evidence actively refuted -- assumptions that turned out
    false, distinct from ones merely never confirmed."""
    return [c for c in latest_claims(ssg) if c.status == ClaimStatus.REFUTED]


def unverified_capabilities(ssg: SecurityStateGraph) -> list[Claim]:
    """Claims still HYPOTHESIZED -- capabilities or relationships the agent
    appears to have but that no operator has yet confirmed or refuted.
    "Reachable but unverified," in the analyst's terms."""
    return [c for c in latest_claims(ssg) if c.status == ClaimStatus.HYPOTHESIZED]


def consistent_defenses(ssg: SecurityStateGraph) -> list[Claim]:
    """Defender-subgraph claims that got CONFIRMED -- controls that
    actually fired and blocked an attempt, not just controls a campaign
    hypothesized might exist."""
    return [
        c for c in latest_claims(ssg)
        if c.status == ClaimStatus.CONFIRMED and ssg.claim_subgraph.get(c.key) == SUBGRAPH_DEFENDER
    ]


def capabilities(ssg: SecurityStateGraph) -> list[Claim]:
    """Plain capability claims (the default category: "the agent has/
    exposes some tool or access") -- what the target can apparently do,
    independent of whether that capability turned out to matter for the
    mission."""
    return [c for c in latest_claims(ssg) if ssg.claim_category.get(c.key, CATEGORY_CAPABILITY) == CATEGORY_CAPABILITY]


def reachable_actions(ssg: SecurityStateGraph) -> list[Claim]:
    """Mission-outcome-category claims that got CONFIRMED -- concrete
    compromises actually reached, as opposed to ones merely attempted.
    Security evaluation's whole contribution, reduced to a single query
    over the same graph everything else reads from."""
    return [
        c for c in latest_claims(ssg)
        if c.status == ClaimStatus.CONFIRMED and ssg.claim_category.get(c.key) == CATEGORY_MISSION_OUTCOME
    ]


def unexplored_frontier(ssg: SecurityStateGraph, library: OperatorLibrary,
                         executed_ids: frozenset[str] = frozenset()) -> list[Operator]:
    """Operators whose preconditions are currently met but that have never
    been executed against this graph -- attack paths shown as reachable
    that no campaign has actually walked. Same rule export.py's frontier
    computation uses, factored out so it's queryable standalone instead of
    only as a byproduct of generating a visualization. `executed_ids`
    defaults to empty (every eligible operator counts as unexplored) --
    pass `frozenset(ssg.operator_stats)` to exclude ones this graph has
    already run."""
    return [op for op in library if op.id not in executed_ids and op.preconditions_met(ssg)]


def observed_tools(ssg: SecurityStateGraph) -> list[str]:
    """Tool names actually INVOKED across the graph's whole history (from
    "tool_call"-kind Facts), in first-observed order -- as opposed to a
    capability merely mentioned in response text. Reads the graph alone,
    no execution log required: this is what "Facts are first-class"
    concretely buys -- see the module docstring for why this can't yet
    answer "vs. never exercised" in full."""
    seen: list[str] = []
    for fact in ssg.facts:
        if fact.kind != "tool_call":
            continue
        name = fact.data.get("tool")
        if name and name not in seen:
            seen.append(name)
    return seen


def recommend_next(library: OperatorLibrary, ssg: SecurityStateGraph, mission: Mission,
                    prompts_used: int = 0, executed_ids: frozenset[str] = frozenset(),
                    n: int = 5) -> list[RankedCandidate]:
    """"If I had N more operator executions, where should I spend them?" --
    AginitiPlanner's own utility ranking against the graph's CURRENT state,
    exposed as a read-only analyst query instead of only being used
    internally to pick the next action in an autonomous campaign loop.
    Nothing is executed; this only ranks what's eligible right now.
    `executed_ids` defaults to empty -- pass `frozenset(ssg.operator_stats)`
    to correctly exclude operators this graph has already run."""
    ranked = AginitiPlanner().rank(library, ssg, mission, prompts_used, executed_ids)
    return ranked[:n]


@dataclass
class SecurityQuestion:
    question: str
    # The question is the stable identity; probes are disposable -- one or
    # MORE operators can answer the same question (they don't today in
    # DVLA's library, but the data model has to be right before that
    # ever happens, not retrofitted after). "Doctors don't care about
    # blood tests, they care about whether the patient has diabetes";
    # operators are the blood tests.
    probe_ids: list[str] = field(default_factory=list)
    status: str = "unanswered"  # "answered" | "partially_answered" | "unanswered"
    claims: list[Claim] = field(default_factory=list)
    confidence: str | None = None  # the answering claim's confidence band, if answered


def security_questions(ssg: SecurityStateGraph, library: OperatorLibrary,
                        executed_ids: frozenset[str] = frozenset()) -> list[SecurityQuestion]:
    """Reframes the graph as a set of asked-and-(maybe)-answered security
    questions, keyed by the QUESTION TEXT rather than by operator: every
    operator declaring the same `understanding_question` contributes to
    one shared record, with combined evidence from whichever of them have
    run. This is the graph read as reasoning in progress, not just a bag
    of claims -- "does the agent trust Slack?" with its current answer and
    confidence, rather than a bare `planner_trusts_slack: confirmed` fact.

    - "unanswered": none of the question's probes have run against this
      graph yet.
    - "partially_answered": at least one ran, but only produced
      HYPOTHESIZED effects so far -- a first signal, not yet resolved.
    - "answered": at least one of the contributing claims reached
      CONFIRMED/REFUTED.

    Operators with no `understanding_question` set don't contribute --
    not every operator in the older mock library has one yet."""
    by_question: dict[str, SecurityQuestion] = {}
    order: list[str] = []
    for op in library:
        if not op.understanding_question:
            continue
        if op.understanding_question not in by_question:
            by_question[op.understanding_question] = SecurityQuestion(op.understanding_question)
            order.append(op.understanding_question)
        q = by_question[op.understanding_question]
        q.probe_ids.append(op.id)
        if op.id not in executed_ids:
            continue
        for claim in (ssg.current_claim(k) for k in op.predicted_keys()):
            if claim is not None and claim not in q.claims:
                q.claims.append(claim)

    out = []
    for question in order:
        q = by_question[question]
        answered_any = any(pid in executed_ids for pid in q.probe_ids)
        resolved = [c for c in q.claims if c.status != ClaimStatus.HYPOTHESIZED]
        if resolved:
            q.status, pick = "answered", resolved[0]
        elif q.claims or answered_any:
            q.status, pick = "partially_answered", (q.claims[0] if q.claims else None)
        else:
            q.status, pick = "unanswered", None
        q.confidence = pick.confidence.value if pick else None
        out.append(q)
    return out
