"""CampaignBeliefState -- a lightweight, planner-facing CACHE of derived
understanding, not a new source of truth. SecurityStateGraph (Fact/
Observation/Claim/Insight/Hypothesis, aginiti/graph/ssg.py) remains the
sole authoritative evidence store; everything in this file is, by design,
reconstructable from it. That is the acid test for whether something
belongs here: if it can't be recomputed from ssg's own append-only log
plus a bounded number of LLM calls, it does not belong in this file.

Two hygiene rules this module exists to enforce (2026-08-07 design review,
directly in response to the concern "six months later you'll have Claims /
Hypotheses / Insights / BeliefState / PlannerState / MissionState /
CampaignState and nobody knows where truth lives"):

  1. The planner never reads `summary`. It is a string for HUMANS --
     explainability, debugging, reporting -- and must not be consulted by
     any ranking function. Every field a planner term is allowed to read
     is a plain float or a plain string/None value, never prose.
  2. This module stays deliberately small. There is exactly ONE new
     mutable object here (CampaignBeliefState), living on
     SecurityStateGraph next to `hypotheses` (see ssg.py) -- not a
     parallel subsystem alongside it.

Milestone 1 (current state of this file): the object exists and is wired
into SecurityStateGraph and the campaign loop, but nothing populates
`branches` or `open_questions` yet, and nothing reads them -- pure
plumbing, no behavior change. `cursor` is deterministic bookkeeping
(advanced every step by aginiti/campaign.py) so milestones 2 and 3 have a
stable anchor to diff against; it carries no reasoning of its own.

Deliberately NOT persisted (aginiti/graph/persistence.py, see its own
comment): a cache that has to survive to disk to remain trustworthy isn't
a cache, it's a second source of truth in disguise. A resumed campaign
starts with a fresh, empty CampaignBeliefState; from milestone 2 onward
it catches back up from the full claim history already on the reloaded
graph the first time it's needed -- slower on resume, never a question of
which copy is authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aginiti.core.graph.schema import IMPORTANCE_WEIGHT, Claim, ClaimStatus

if TYPE_CHECKING:
    # Deferred: aginiti.core.graph.ssg imports THIS module (SecurityStateGraph
    # carries a CampaignBeliefState), and aginiti.operators.library imports
    # aginiti.core.graph.ssg -- a module-level import of either here would be a
    # circular import. TYPE_CHECKING is always False at runtime, so this
    # never executes; it exists purely so type checkers/IDEs resolve the
    # hints below.
    from aginiti.core.graph.ssg import SecurityStateGraph
    from aginiti.operators.library import OperatorLibrary


@dataclass
class BranchBelief:
    """Structured, planner-facing summary of one branch/system's current
    standing. All three stored fields are plain floats -- no prose -- so a
    planner term can read them with zero interpretation.

    `priority` is deliberately a property, not a stored field: storing it
    separately from interest/confidence/risk would let it silently drift
    out of sync with the values it's derived from -- the exact "second
    source of truth" failure mode this whole module exists to avoid.

    Milestone 2 defines the actual interest/confidence/risk UPDATE rules
    (deterministic branch propagation); this class only defines the
    shape, so nothing here is populated or read yet."""
    interest: float = 0.0    # how much unresolved value this branch still looks like it has
    confidence: float = 0.0  # how settled the current model of this branch is (0 = still murky)
    risk: float = 0.0        # observed defender/detection pressure specific to this branch

    @property
    def priority(self) -> float:
        """Single scalar for REPORTING/debugging -- rewards interest,
        damps by how unsettled (1 - confidence) and by risk. Deliberately
        NOT what the planner reads (see `exploration_signal` below): this
        one folds risk in as a subtraction, which is exactly the pattern
        aginiti/planner/aginiti_planner.py's own module docstring warns
        against for the master utility scalar ("folding risk into the
        same scalar as business impact lets a large predicted impact
        numerically outweigh a dangerous action, which is the wrong
        behavior") -- risk/budget are hard constraints on candidates
        there, never a penalty term inside the maximized quantity. This
        risk-inclusive number is fine for a human reading a report; it
        would quietly violate that principle if fed into the formula."""
        return self.interest * (0.5 + 0.5 * self.confidence) - self.risk

    @property
    def exploration_signal(self) -> float:
        """What AginitiPlanner.branch_interest() actually reads (2026-08-08,
        "planner consumes CampaignBeliefState"): the same interest/
        confidence shape as `priority`, deliberately WITHOUT the risk
        subtraction -- risk stays a hard constraint elsewhere in the
        planner (risk_tier vs. mission.risk_threshold), never folded into
        this scalar. Always >= 0, since interest and confidence are
        themselves always >= 0."""
        return self.interest * (0.5 + 0.5 * self.confidence)


@dataclass(frozen=True)
class BranchSignal:
    """The ONLY view of branch-level belief anything OUTSIDE this module
    should read (2026-08-08 design tightening) -- aginiti/planner/
    aginiti_planner.py's branch_interest() reads this, never
    CampaignBeliefState.branches or a BranchBelief directly. This is what
    "the belief state exposes planner-facing signals while keeping its
    internal representation encapsulated" means concretely: BranchBelief's
    stored fields (interest/confidence/risk) and its update rules can
    change shape freely later -- add decay, add new evidence types,
    restructure entirely -- without touching a single planner-side caller,
    as long as this shape's meaning stays stable.

    Deliberately just three plain floats/ints, no prose, mirroring
    BranchBelief's own "no interpretation needed" discipline."""
    exploration_signal: float  # what branch_interest() reads -- risk-excluded, see BranchBelief.exploration_signal
    uncertainty: float         # 1 - confidence: how much is still unsettled about this branch (0 = fully resolved)
    open_gap_count: int        # how many current open_questions point at this branch


@dataclass
class OpenQuestion:
    """One structured, still-unresolved thing worth knowing -- the
    planner-facing counterpart to a KNOWLEDGE_GAP Insight
    (aginiti/graph/schema.py, Insight.category == KNOWLEDGE_GAP), but
    shaped for consumption rather than narration: no prose `statement`
    field at all.

    `related_probe_id` being None is itself meaningful -- see
    aginiti/graph/insights.py's own docstring: "the current operator
    library has no way to test this yet." That same signal is exactly
    what a future operator-suggestion milestone would scan for; this
    class does not need to change to support that later."""
    topic: str
    branch: str | None
    importance: str | None  # "low" | "medium" | "high", or None if unrated
    related_probe_id: str | None


@dataclass
class CampaignBeliefState:
    """Derived working memory for one campaign's planner -- see this
    file's module docstring for what it is and, as importantly, what it
    deliberately is NOT (a second source of truth, a parallel subsystem,
    something a planner term reads prose from).

    `hypothesis_links` maps a branch tag to the ssg.hypotheses keys
    relevant to it -- a reference, not a copy: the Hypothesis objects
    themselves stay exactly where they already live (SecurityStateGraph.
    hypotheses), this just indexes them by branch for O(1) planner reads
    instead of a linear scan per candidate (what gap_priority/
    hypothesis_priority do today)."""
    branches: dict[str, BranchBelief] = field(default_factory=dict)
    open_questions: list[OpenQuestion] = field(default_factory=list)
    hypothesis_links: dict[str, tuple[str, ...]] = field(default_factory=dict)
    summary: str = ""  # HUMANS ONLY -- no planner term may read this field.
    cursor: str | None = None  # id of the most recent claim accounted for by DETERMINISTIC processing (milestone 2)
    # Separate from `cursor` on purpose: this tracks what the REASONING
    # LAYER (an LLM call, gated -- see should_run_reasoning_pass below) has
    # accounted for, which advances far less often than `cursor` (every
    # step, unconditionally). Sharing one cursor between both would mean
    # the reasoning layer's diff is always empty, since deterministic
    # propagation already races ahead of it every single step.
    reasoned_cursor: str | None = None

    def branch_signal(self, branch: str | None) -> BranchSignal:
        """The encapsulated read path (2026-08-08): everything outside
        this module -- the planner, future reporting code -- calls THIS,
        never `self.branches[...]` directly. `branch=None` (an untagged
        operator) and an unknown/never-seen branch both return the same
        all-zero signal -- a true no-op, not a KeyError, matching
        BranchBelief's own "no belief yet" default."""
        # open_gap_count is computed independent of whether a BranchBelief
        # entry exists -- a branch can have open questions before it ever
        # earns any interest/confidence data (e.g. the Reasoning Layer
        # names a gap in a branch nothing has been confirmed in yet).
        gap_count = sum(1 for q in self.open_questions if q.branch == branch) if branch is not None else 0
        belief = self.branches.get(branch) if branch is not None else None
        if belief is None:
            return BranchSignal(exploration_signal=0.0, uncertainty=1.0, open_gap_count=gap_count)
        return BranchSignal(
            exploration_signal=belief.exploration_signal,
            uncertainty=1.0 - belief.confidence,
            open_gap_count=gap_count,
        )


# --------------------------------------------------------------------------
# Milestone 2: deterministic branch propagation. Zero LLM calls -- this is
# the "free tier" from the architecture review: it runs every step,
# unconditionally, and is what directly answers the human-pentester example
# that motivated this whole redesign -- "Slack trusts external users... if
# Slack trusts outsiders, GitHub's release-bot probably has similar trust
# assumptions" -- as a mechanical rule over the claim-category taxonomy
# that already exists (aginiti/graph/ssg.py's CATEGORY_* constants), not a
# semantic judgment call.
#
# Loosely inspired by belief propagation / sum-product message passing
# (Pearl) -- branches act as nodes, a same-category confirmation sends a
# "message" to every other branch with an unresolved claim of that same
# category -- but this is NOT a literal implementation of BP: there is no
# factor graph, no conditional probability table, and no iteration to a
# fixed point. It borrows the PRINCIPLE (local evidence propagates as
# messages along explicit relations, not a single global constant), not
# the machinery. Overclaiming the connection would be exactly the kind of
# "facts, no cover-ups" violation this project has committed to avoiding.
# --------------------------------------------------------------------------

_CONFIDENCE_STEP = 0.34  # ~3 resolved claims settles a branch to confidence=1.0
_OWN_BRANCH_INTEREST_BOOST = 2.0
_CROSS_BRANCH_INTEREST_BOOST = 1.0  # half of own-branch: a same-category pattern
                                     # found ELSEWHERE is a weaker signal than a
                                     # direct confirmation in this branch itself
_RISK_STEP = 1.0
_INTEREST_DECAY = 0.9  # retained fraction per step -- see _decay_interest()'s docstring

# Cap on `interest` (2026-08-09 fix -- a real bug found by a live full-system
# dry run, not a theoretical worry): interest grows +_OWN_BRANCH_INTEREST_BOOST
# per same-branch confirmation and decays by _INTEREST_DECAY per step with NO
# cap, so its steady-state ceiling under repeated same-branch confirmations is
# _OWN_BRANCH_INTEREST_BOOST / (1 - _INTEREST_DECAY) = 2.0 / 0.1 = 20.0 -- roughly
# 5x every OTHER term's own deliberately-bounded max (gap_priority/
# hypothesis_priority both cap at IMPORTANCE_WEIGHT["high"] = 4.0-4.2). This sat
# completely latent for the whole project's life because branch_interest was
# confirmed EXACTLY 0.0 across every one of exp15's 150 real trials (missions
# too short/shallow to ever accumulate same-branch momentum) -- only surfaced
# once a genuinely deeper live campaign (8 operators, several sharing one
# branch) actually exercised it: BayesianBanditPlanner's alpha reached 19.9 for
# an untried operator purely from this one term, before any real evidence on
# it at all. Capped at the SAME ceiling as gap_priority/hypothesis_priority
# (IMPORTANCE_WEIGHT["high"], schema.py's single canonical scale) rather than a
# newly-invented number, exactly the same "only ever helps, bounded like every
# other term" discipline `confidence` already follows two lines below via its
# own `min(1.0, ...)` clamp.
_MAX_BRANCH_INTEREST = IMPORTANCE_WEIGHT["high"]


def _decay_interest(belief: CampaignBeliefState) -> None:
    """Lifecycle for `interest` (2026-08-08 design question: "if interest
    increases after a confirmation, when does it decay or get retired? I
    don't want stale evidence permanently biasing the planner"). Answer:
    exponential recency decay, applied to EVERY known branch at the start
    of every step, before this step's own boosts (if any) are added on
    top -- standard, simple, well-understood (the same shape as an
    eligibility trace / recency weighting), not a novel mechanism invented
    for this.

    Only `interest` decays. `confidence` and `risk` deliberately do NOT:
    confidence represents how much has been LEARNED about a branch, which
    doesn't become less true with time, and risk represents demonstrated
    defender pushback, which also doesn't just fade -- decaying either
    would mean "forgetting" real evidence, not retiring a stale lead.
    `interest` is different in kind: it's "how promising does this still
    look right now," which SHOULD fade if nothing new has reinforced it,
    exactly the staleness this question was about.

    A branch that keeps getting reinforced every step stays roughly flat
    or grows (each +2.0/+1.0 boost outweighs a 10% decay); one that goes
    quiet after an initial hit fades geometrically toward zero rather than
    staying permanently elevated from one long-past confirmation."""
    for belief_entry in belief.branches.values():
        belief_entry.interest *= _INTEREST_DECAY


def _branch_of(library: "OperatorLibrary", claim_key: str) -> str | None:
    """Which branch declared the operator whose effect produced this claim
    key? O(#operators) per lookup -- fine at this library's scale (tens of
    operators), and only called for claims that just changed, not every
    candidate every step. Returns None for an untagged library (DVLA/DVAA/
    MCP haven't been branch-tagged yet) -- a deliberate no-op, not an
    error; see Operator.branch's own docstring."""
    for op in library:
        if op.branch is None:
            continue
        for effect in (*op.effects_success, *op.effects_failure):
            if effect.key == claim_key:
                return op.branch
    return None


def _branches_with_unresolved_category(ssg: "SecurityStateGraph", library: "OperatorLibrary",
                                        category: str, exclude_branch: str) -> set[str]:
    """Every OTHER branch that declares at least one effect of `category`
    whose claim is still unresolved (no claim yet, or only HYPOTHESIZED) --
    same "unresolved" definition AginitiPlanner.information_gain already
    uses, so this reads as one consistent notion of "still unknown"
    throughout the codebase rather than a second, subtly different one."""
    branches: set[str] = set()
    for op in library:
        if op.branch is None or op.branch == exclude_branch:
            continue
        for effect in (*op.effects_success, *op.effects_failure):
            if effect.category != category:
                continue
            current = ssg.current_claim(effect.key)
            if current is None or current.status == ClaimStatus.HYPOTHESIZED:
                branches.add(op.branch)
    return branches


def update_branch_beliefs(ssg: "SecurityStateGraph", library: "OperatorLibrary",
                           new_claims: list[Claim]) -> None:
    """Milestone 2 entry point, called once per campaign step (aginiti/
    campaign.py) with exactly the Claims that were newly appended THIS
    step. Deterministic, zero LLM calls, safe to call every step regardless
    of outcome.

    Rules (deliberately small -- three, matching exactly what the
    architecture review scoped for this milestone, nothing extra):
      1. Any newly resolved claim (CONFIRMED or REFUTED) raises its own
         branch's `confidence` -- that branch is better understood either
         way, win or lose.
      2. A newly CONFIRMED trust_edge or mission_outcome claim raises its
         own branch's `interest` (this branch just proved valuable) AND
         sends a smaller boost to every OTHER branch with an unresolved
         claim of that SAME category -- the "similar trust pattern
         elsewhere" propagation.
      3. A newly CONFIRMED defender_control claim raises its own branch's
         `risk` ONLY -- deliberately NOT propagated cross-branch. Whether a
         block means "back off everywhere" or "something valuable is
         guarded exactly here, push harder" is a judgment call a fixed
         rule cannot make safely -- reserved for the Reasoning Layer
         (milestone 3), not guessed at here."""
    # Deferred import: aginiti.core.graph.ssg defines these constants but also
    # imports THIS module (SecurityStateGraph.belief) -- importing them at
    # module level would be circular. Safe here: by the time this function
    # is actually CALLED, aginiti.core.graph.ssg is already fully loaded.
    from aginiti.core.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE

    belief = ssg.belief
    _decay_interest(belief)
    for claim in new_claims:
        branch = _branch_of(library, claim.key)
        if branch is None:
            continue  # untagged library -- no-op, not an error

        own = belief.branches.setdefault(branch, BranchBelief())

        if claim.status in (ClaimStatus.CONFIRMED, ClaimStatus.REFUTED):
            own.confidence = min(1.0, own.confidence + _CONFIDENCE_STEP)

        if claim.status != ClaimStatus.CONFIRMED:
            continue  # rules 2 and 3 only fire on a genuine confirmation

        category = ssg.claim_category.get(claim.key)
        if category in (CATEGORY_TRUST_EDGE, CATEGORY_MISSION_OUTCOME):
            own.interest = min(_MAX_BRANCH_INTEREST, own.interest + _OWN_BRANCH_INTEREST_BOOST)
            for other_branch in _branches_with_unresolved_category(ssg, library, category, exclude_branch=branch):
                other = belief.branches.setdefault(other_branch, BranchBelief())
                other.interest = min(_MAX_BRANCH_INTEREST, other.interest + _CROSS_BRANCH_INTEREST_BOOST)
        elif category == CATEGORY_DEFENDER_CONTROL:
            own.risk += _RISK_STEP


# --------------------------------------------------------------------------
# Milestone 3 (redesigned per the PentestGPT architecture review): the
# gated, INCREMENTAL Reasoning Layer. Two pieces live here, deliberately
# separated from the LLM call itself (aginiti/graph/insights.py's
# run_reasoning_pass):
#   - should_run_reasoning_pass(): a pure, deterministic GATE. Decides
#     whether an LLM call is warranted; never makes one itself. This is
#     what keeps the reasoning layer cheap -- most steps (recon, decoys,
#     failed attempts) never reach it at all.
#   - apply_reasoning_verdict(): the ONLY place a reasoning pass's output
#     is allowed to mutate ssg.belief -- same discipline as
#     update_branch_beliefs above, so every write to
#     CampaignBeliefState.branches happens in exactly one file regardless
#     of which caller (deterministic or LLM-driven) triggered it.
# --------------------------------------------------------------------------

_STALENESS_THRESHOLD = 8  # claims accumulated since the last reasoning pass before a full-resync fallback fires
_REASONING_INTEREST_DELTA = 1.5  # same order of magnitude as milestone 2's own boosts (1.0-2.0)


def should_run_reasoning_pass(ssg: "SecurityStateGraph", new_claims: list[Claim],
                               staleness_threshold: int = _STALENESS_THRESHOLD) -> bool:
    """Two trigger conditions, matching the PentestGPT architecture
    review's redesign of this milestone (session record, not yet a docs/
    file):
      1. Event-triggered: `new_claims` (this step's newly appended claims)
         contains a CONFIRMED trust_edge, mission_outcome, or
         defender_control claim -- the three cases milestone 2's
         deterministic propagation either can't resolve (defender_control's
         back-off-vs-push-harder ambiguity) or where a real synthesis pass
         is worth its cost (high-value confirmations).
      2. Staleness fallback: enough claims have accumulated since the last
         reasoning pass that letting the belief state go stale
         indefinitely risks the same failure mode PentestGPT's own
         published evaluation names as its single LARGEST failure category
         ("session context loss," 74/195 failures) -- self-correction
         discipline borrowed from that review, not guessed at."""
    from aginiti.core.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE

    for claim in new_claims:
        if claim.status != ClaimStatus.CONFIRMED:
            continue
        if ssg.claim_category.get(claim.key) in (CATEGORY_TRUST_EDGE, CATEGORY_MISSION_OUTCOME, CATEGORY_DEFENDER_CONTROL):
            return True

    cursor = ssg.belief.reasoned_cursor
    if cursor is None:
        return len(ssg.claims) >= staleness_threshold
    idx = next((i for i, c in enumerate(ssg.claims) if c.id == cursor), None)
    unreasoned_count = len(ssg.claims) - (idx + 1) if idx is not None else len(ssg.claims)
    return unreasoned_count >= staleness_threshold


def apply_reasoning_verdict(ssg: "SecurityStateGraph", library: "OperatorLibrary", result) -> None:
    """Applies one run_reasoning_pass() result to CampaignBeliefState.
    `result` is duck-typed (needs `.updated_summary`, `.branch_signal`,
    read via attribute access only) rather than imported as a type --
    aginiti.core.graph.insights already imports aginiti.core.graph.ssg, which
    imports this module, so importing insights.py's return type here at
    module level would be circular. Same reasoning as this file's other
    TYPE_CHECKING-guarded imports.

    `open_questions` and `hypothesis_links` are fully REBUILT from
    ssg.insights/ssg.hypotheses every call, not incrementally patched --
    both are cheap (small collections) and this is the same "safe to
    recompute, never drifts" discipline the rest of this module follows:
    a bug here produces a stale value until the next call, never a
    silently wrong one that compounds."""
    belief = ssg.belief
    op_branch = {op.id: op.branch for op in library if op.branch is not None}

    if result.updated_summary:
        belief.summary = result.updated_summary

    known_branches = set(op_branch.values())
    for signal in result.branch_signal:
        branch = signal.get("branch")
        if branch not in known_branches:
            continue  # hallucinated/unknown branch name -- discard, don't guess
        b = belief.branches.setdefault(branch, BranchBelief())
        if signal.get("direction") == "up":
            b.interest += _REASONING_INTEREST_DELTA
        else:
            b.interest = max(0.0, b.interest - _REASONING_INTEREST_DELTA)

    belief.open_questions = [
        OpenQuestion(
            topic=insight.statement.split(":", 1)[0].strip(),
            # Branch-scoped via the SAME related_probe_id a gap already
            # carries (2026-08-08 -- previously always None, a real gap
            # closed here, not a new mechanism: the operator a gap points
            # at already tells us which branch it's about). Stays None
            # only when related_probe_id itself is None ("the operator
            # library has no way to test this yet" -- see insights.py) or
            # points at an untagged operator.
            branch=op_branch.get(insight.related_probe_id),
            importance=insight.importance,
            related_probe_id=insight.related_probe_id,
        )
        for insight in ssg.insights
        if insight.category.value == "knowledge_gap"
    ]

    links: dict[str, set[str]] = {}
    for stmt_key, hyp in ssg.hypotheses.items():
        for branch in {op_branch[op_id] for op_id in hyp.experiments if op_id in op_branch}:
            links.setdefault(branch, set()).add(stmt_key)
    belief.hypothesis_links = {branch: tuple(sorted(keys)) for branch, keys in links.items()}
