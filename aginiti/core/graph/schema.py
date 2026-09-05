"""Data structures for the Security State Graph (design doc Section 15).

Two categories of node, per Section 10.2:
  - Structural nodes (Asset, Capability, TrustEdge, Workflow, DefenderControl)
    represent something believed to exist. They never carry confidence.
  - Claim nodes are assertions *about* a structural node (or about the graph
    in general), carrying status + a confidence value that is always derived
    from linked Observations (Section 11) -- never set directly.

Claims and Observations are append-only (Section 10.3): a revised belief
creates a new Claim that supersedes the prior one rather than mutating it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# Canonical importance-bucket weights -- the single
# source of truth for how a KNOWLEDGE_GAP insight's `importance` string maps to
# a numeric weight, and for the valid range `priority_weight` may occupy within
# each bucket. Previously duplicated (aginiti_planner.py's own
# _GAP_IMPORTANCE_WEIGHT, priors.py's own _BUCKET_BASE/_BUCKET_SPAN) with only a
# "MUST mirror" comment enforcing consistency -- a real internal-audit finding
# (nothing stopped the two copies from silently drifting apart). Both modules
# now import from here instead of redeclaring; schema.py is the right home
# since it's the most foundational graph module both already depend on, so this
# introduces no new import direction. IMPORTANCE_BUCKET_SPAN bounds how far
# `priority_weight` (Insight, below) may stray from its bucket's base value --
# enforced in Insight.__post_init__, not just by caller discipline, closing the
# other half of that same audit finding.
#
# Values DOUBLED from an earlier scale (0.5/1.0/2.0 -> 1.0/2.0/4.0) -- a real,
# quantified architectural ceiling an internal audit found in AginitiPlanner: at
# move 1 (alpha=1.0), a single-step operator's alpha*info_gain can reach 4.0,
# while gap_priority's old max (2.2, "high" bucket + full rank nudge) could
# NEVER reach that regardless of how strong the cold-start prior was --
# meaning a confident prior could only ever break a tie among EQUAL-info_gain
# candidates, never overrule a genuinely stronger prior on a LOWER-info_gain
# one. Confirmed by live offline test (same repo, same real operators): an
# operator with a "high" prior and a low declared info_gain LOST to a
# no-prior operator with high info_gain under the old weights (3.02 vs 4.03),
# and WON under the doubled weights (5.02 vs 4.03) -- the exact, quantified
# fix, not a re-guess. 4.0 specifically chosen (not some other multiple) to
# match info_gain's own observed real-operator ceiling in this project's
# actual libraries, so "high" now competes on the SAME order of magnitude
# instead of a smaller, arbitrary one -- a calibration target, not a re-guess.
# This was deliberately tried BEFORE building a larger, more complex
# alternative (aginiti/core/planner/bayesian_planner.py's Thompson-Sampling
# planner) -- per "if it can be done simply,
# don't overcomplicate it," a 3-number change that fixes the same diagnosed
# problem is the right first fix to make, not a new module, even though the
# Bayesian planner remains available (and may still offer real value beyond
# this specific ceiling -- genuine uncertainty-aware exploration, principled
# prior+evidence combination -- that a constant rescale can't provide) for a
# future live comparison to actually decide between.
IMPORTANCE_WEIGHT: dict[str, float] = {"low": 1.0, "medium": 2.0, "high": 4.0}
IMPORTANCE_BUCKET_SPAN = 0.4


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ClaimStatus(str, Enum):
    HYPOTHESIZED = "hypothesized"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class ConfidenceBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


_id_counters: dict[str, int] = {}


def next_id(prefix: str) -> str:
    n = _id_counters.get(prefix, 0) + 1
    _id_counters[prefix] = n
    return f"{prefix}_{n:04d}"


def bump_id_counter(prefix: str, id_str: str) -> None:
    """Advances the counter for `prefix` past whatever number is embedded in
    `id_str`, so newly-generated ids in a resumed process don't collide with
    ids already present in a graph loaded from disk (persistence.load_ssg
    calls this for every id it reads back in). No-ops on malformed ids."""
    try:
        n = int(id_str.rsplit("_", 1)[-1])
    except ValueError:
        return
    if n > _id_counters.get(prefix, 0):
        _id_counters[prefix] = n


# --------------------------------------------------------------------------
# Structural nodes (Section 15, "Asset / Capability / TrustEdge / Workflow /
# DefenderControl"). These exist independently of any Claim about them and
# are never mutated once created -- a campaign either discovers a structural
# node or it doesn't.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    id: str
    type: str  # tool | memory_store | api | credential | document
    name: str


@dataclass(frozen=True)
class Capability:
    id: str
    name: str  # rag | reflection | planning | tool_calling | memory_persistent | ...


@dataclass(frozen=True)
class TrustEdge:
    id: str
    trust_type: str  # trusts_input_from | delegates_to | authenticates_via
    source: str  # node id
    target: str  # node id


@dataclass(frozen=True)
class Workflow:
    id: str
    name: str
    approval_required: bool
    steps: tuple[str, ...] = ()


@dataclass(frozen=True)
class DefenderControl:
    id: str
    type: str  # prompt_filter | rate_limiter | output_filter | approval_gate | human_review | logging | monitoring


StructuralNode = Asset | Capability | TrustEdge | Workflow | DefenderControl


# --------------------------------------------------------------------------
# Fact / Observation / Claim -- the Behavior-derived Security Graph's three
# tiers, in increasing order of interpretation:
#
#   Fact        objectively recorded, no judgment involved (a tool was
#               called with these literal args; the target emitted this
#               literal text). Immutable, and recorded whether or not
#               anything is ever inferred from it.
#   Observation the judge's interpretation EVENT: "this raw signal is
#               evidence for/against claim key X." Links Facts to Claims.
#   Claim       the belief itself -- a status + confidence that EVOLVES as
#               more Observations arrive, versioned via `supersedes` rather
#               than mutated.
#
# Facts and Beliefs (Claims) are deliberately not equal citizens: a Fact
# never has a status or confidence, because it isn't a conclusion -- only
# Claims are. This is what lets the graph answer "what did we literally
# see" independent of "what did Aginiti conclude from it," which matters
# more as campaigns get longer and inference chains get deeper.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Fact:
    """A directly-observed data point -- e.g. a tool call with its literal
    args, or the target's raw response text -- recorded independent of any
    interpretation. `kind` distinguishes what shape `data` is ("tool_call",
    "response_text", ...); new kinds can be added without touching this
    class. Never revised: a fact is either recorded or it isn't."""
    id: str
    timestamp: datetime
    operator_execution_id: str
    kind: str
    data: dict

    @staticmethod
    def create(operator_execution_id: str, kind: str, data: dict) -> "Fact":
        return Fact(id=next_id("fact"), timestamp=_now(),
                    operator_execution_id=operator_execution_id, kind=kind, data=data)


@dataclass(frozen=True)
class Observation:
    id: str
    timestamp: datetime
    operator_execution_id: str
    raw_signal: str
    supports: tuple[str, ...] = ()      # claim keys this observation strengthens
    contradicts: tuple[str, ...] = ()   # claim keys this observation weakens

    @staticmethod
    def create(operator_execution_id: str, raw_signal: str,
               supports: tuple[str, ...] = (), contradicts: tuple[str, ...] = ()) -> "Observation":
        return Observation(
            id=next_id("obs"),
            timestamp=_now(),
            operator_execution_id=operator_execution_id,
            raw_signal=raw_signal,
            supports=supports,
            contradicts=contradicts,
        )


class InsightCategory(str, Enum):
    # What the agent appears to DO, synthesized across claims -- e.g. "the
    # agent consistently validates user identity before privileged tool use."
    BEHAVIORAL = "behavioral"
    # What that behavior IMPLIES for security risk -- e.g. "unauthorized
    # disclosure via impersonation appears unlikely under current observations."
    SECURITY = "security"
    # What ISN'T known yet -- a security-relevant topic no claim in this
    # graph touches (memory persistence, delegated trust, approval
    # workflows, ...). Deliberately the category expected to matter most:
    # a knowledge gap is what makes the graph ACTIVE rather than a passive
    # summary -- it's a candidate probe, not just an absence.
    KNOWLEDGE_GAP = "knowledge_gap"


@dataclass(frozen=True)
class Insight:
    """A fourth tier above Claim: synthesized higher-order knowledge --
    what a set of claims collectively IMPLY (or, for KNOWLEDGE_GAP, what
    they collectively DON'T cover), in the sentence a security engineer
    would actually write, rather than the raw claim keys themselves. E.g.
    several trust_edge claims individually confirmed ("release_bot_trusted",
    "admin_bot_trusted", ...) might synthesize into a BEHAVIORAL insight:
    "this agent trusts any automated system that claims internal origin,
    without independently verifying intent."

    Every BEHAVIORAL/SECURITY insight is grounded: `derived_from` names the
    exact claim keys it was synthesized from, so it's always traceable back
    to the Fact/Observation/Claim evidence chain underneath it -- never an
    ungrounded model guess presented as fact. KNOWLEDGE_GAP insights are
    necessarily different: they're about ABSENCE, so `derived_from` is
    typically empty; instead `related_probe_id` names an operator (from the
    current library) that would help close this specific gap, if the
    library already has one -- this is the literal mechanism behind "gaps
    naturally generate the next probes." When no operator matches,
    `related_probe_id` stays None, which is itself a finding: the current
    operator library has no way to test this yet.

    Insights are themselves append-only and are never asserted as ground
    truth; they're the graph's best current synthesis, revisable exactly
    like a Claim if a later campaign contradicts them (a future revision,
    not modeled yet, would supersede rather than overwrite -- same
    discipline as Claim).

    `statement` is deliberately not the whole story: a bare conclusion
    ("the agent validates input") reads like a report, not reasoning. The
    fields below carry the reasoning behind it -- BEHAVIORAL/SECURITY
    insights get `confidence` (how sure THIS synthesis is, distinct from
    any underlying claim's own confidence band), `alternative_explanations`
    (other things that could explain the same evidence -- e.g. model-level
    safety vs. a validation wrapper vs. the tool itself rejecting bad
    input, when the evidence alone can't distinguish them), and
    `evidence_still_missing` (specific things NOT yet tested that bound
    how far this conclusion can be trusted -- e.g. "only one user role
    tested," "no delegated authority tested" -- so a claim like
    "unauthorized access appears unlikely" earns its confidence instead of
    overclaiming past what N observed attempts actually support).
    KNOWLEDGE_GAP insights get `importance` (how much closing this gap
    would matter) alongside `related_probe_id`. A KNOWLEDGE_GAP can
    optionally also carry `prior_belief` -- an educated guess at the
    likely answer, formed from BACKGROUND reasoning rather than direct
    evidence (e.g. "probably persists memory, because the adapter is
    built on LangGraph" -- LangGraph's checkpointing is publicly known
    behavior, not something observed against this specific target). That
    turns a bare "unknown" into a testable hypothesis: `confidence` doubles
    as the prior's confidence in this case (explicitly a PRE-evidence
    estimate, not a claim's own confidence band). Fields not meaningful
    for a given category are simply left None/empty, same pattern as
    ClaimEffect's fields not all mattering for every effect.

    Turning a hypothesis into an accepted/rejected conclusion once real
    evidence arrives needs a stable identity for the hypothesis across
    separate synthesis runs, which isn't modeled yet -- deliberately
    future work, same scope class as letting the operator library evolve
    itself. Today, a hypothesis is a richer gap description, not yet a
    tracked, resolvable claim in its own right."""
    id: str
    category: InsightCategory
    statement: str
    derived_from: tuple[str, ...] = ()  # claim keys this synthesis is grounded in
    confidence: str | None = None  # BEHAVIORAL/SECURITY: confidence in this synthesis; KNOWLEDGE_GAP: prior confidence
    alternative_explanations: tuple[str, ...] = ()  # BEHAVIORAL/SECURITY: other explanations for the same evidence
    evidence_still_missing: tuple[str, ...] = ()  # BEHAVIORAL/SECURITY: specific untested conditions bounding this conclusion
    importance: str | None = None  # KNOWLEDGE_GAP: low/medium/high -- how much closing this gap would matter
    prior_belief: str | None = None  # KNOWLEDGE_GAP: an educated guess at the answer, from background reasoning
    related_probe_id: str | None = None  # KNOWLEDGE_GAP: an unexplored operator id that would help, if any
    # KNOWLEDGE_GAP, optional: a fine-grained numeric nudge WITHIN `importance`'s bucket,
    # None for every insight the Reasoning Layer forms (unchanged -- still bucket-only, display stays
    # exactly "importance: high" etc. in target_profile.py). Exists to fix a real, live-diagnosed bug:
    # aginiti/core/graph/priors.py's cold-start seeding asked an LLM for independent low/medium/high labels,
    # and a known-defended trap operator landed in the SAME bucket as a real, reliable win (both
    # "medium") purely because 3 discrete buckets are too coarse to express a preference between two
    # options the model would still rank differently if asked directly -- confirmed live on
    # branching_chat_rag: memory_context_leakage_probe (a KNOWN, always-defended trap) and
    # system_prompt_extraction (a real win) both scored EXACTLY 5.0125, making AginitiPlanner's step-1
    # choice between them a coin flip on shuffle order, not a reasoned pick. Relative/ranked judgments
    # are the well-established fix for this class of LLM-scoring collapse (comparative judgments are
    # more reliable than absolute Likert-style labels); see priors.py for how this gets computed and
    # aginiti_planner.py's gap_priority() for how it's consumed (falls back to the bucket lookup
    # whenever this is None, so every existing caller/insight is completely unaffected).
    priority_weight: float | None = None
    generated_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        """Enforces the ONE safety property priority_weight exists to
        guarantee -- that a nudge can never cross a bucket boundary --
        at construction time, not just by trusting the one caller
        (priors.py) that currently computes it correctly. A future
        caller passing an inconsistent (importance, priority_weight)
        pair now fails loudly here instead of silently corrupting
        gap_priority()'s ranking with an out-of-bucket value."""
        if self.priority_weight is None or self.importance not in IMPORTANCE_WEIGHT:
            return  # nothing to check -- bucket-only insight, or importance itself unset/invalid (unrelated concern)
        base = IMPORTANCE_WEIGHT[self.importance]
        lo, hi = base - IMPORTANCE_BUCKET_SPAN / 2, base + IMPORTANCE_BUCKET_SPAN / 2
        if not (lo <= self.priority_weight <= hi):
            raise ValueError(
                f"priority_weight={self.priority_weight!r} is outside the valid range "
                f"[{lo}, {hi}] for importance={self.importance!r} -- would silently let this "
                f"insight outrank/underrank a different bucket's insight, exactly the property "
                f"priority_weight exists to prevent."
            )

    @staticmethod
    def create(category: InsightCategory, statement: str, derived_from: tuple[str, ...] = (),
               confidence: str | None = None, alternative_explanations: tuple[str, ...] = (),
               evidence_still_missing: tuple[str, ...] = (), importance: str | None = None,
               prior_belief: str | None = None, related_probe_id: str | None = None,
               priority_weight: float | None = None) -> "Insight":
        return Insight(id=next_id("insight"), category=category, statement=statement,
                       derived_from=derived_from, confidence=confidence,
                       alternative_explanations=alternative_explanations,
                       evidence_still_missing=evidence_still_missing, importance=importance,
                       prior_belief=prior_belief,
                       related_probe_id=related_probe_id, priority_weight=priority_weight,
                       generated_at=_now())


@dataclass(frozen=True)
class Claim:
    """An assertion. `key` is the stable subject/predicate identity used for
    precondition lookups and for finding "the current claim" (Section 10.3) --
    it plays the role of (subject_node_id, predicate) from the doc's field
    reference, collapsed into one string for the vertical slice (e.g.
    "payroll_api_exists", "planner_trusts_slack").
    """
    id: str
    key: str
    object: str
    status: ClaimStatus
    confidence: ConfidenceBand
    supersedes: str | None = None

    @staticmethod
    def create(key: str, object_: str, status: ClaimStatus,
               confidence: ConfidenceBand, supersedes: str | None = None) -> "Claim":
        return Claim(
            id=next_id("claim"),
            key=key,
            object=object_,
            status=status,
            confidence=confidence,
            supersedes=supersedes,
        )
