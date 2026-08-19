"""Per-candidate exclusion accounting -- added 2026-08-14 at explicit
direction following exp23's live hardened_agent findings: "If an operator
is intentionally excluded, record exactly why."

Before this, every reason an operator failed to appear in `AginitiPlanner.
rank()`'s output collapsed into the same observable outcome: "not in the
list." A human reading a campaign's decision log could not tell an
operator that was structurally impossible (a precondition that will never
be met) apart from one that was merely already tried, or one that is
currently low-value but perfectly viable later, or one a diversification
nudge temporarily deprioritized (which, after the same fix, no longer
excludes it at all -- see aginiti_planner.py's `rank()`/`_score()`). That
conflation is exactly what made exp23's premature SEARCH_EXHAUSTED
unreadable from the outside: the campaign COULD say a step count and an
outcome string, but not WHY 15-16 of 24 operators were unaccounted for.

`AginitiPlanner.diagnose()` is the read-only companion to `rank()` that
produces this status for every operator in the library, not only the
survivors -- see that method's own docstring. This module holds only the
taxonomy and the plain data carrier; it has no behavior of its own and
imports nothing from aginiti_planner.py (diagnose() imports THIS module,
not the other way around, avoiding a cycle).

Deliberately small and directly traceable to a real, distinct code path
each -- not a speculative, finer-grained taxonomy invented ahead of
evidence that more categories are needed (same discipline
failure_diagnosis.py's own docstring names explicitly)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CandidateStatus(str, Enum):
    # "already tried" -- deterministic operator against unchanged state
    # would teach nothing new; not infeasible, just redundant right now.
    ALREADY_EXECUTED = "already_executed"
    # "temporarily impossible, not permanently" -- a precondition (exact-key
    # or ClassPrecondition) isn't satisfied YET. May become eligible later
    # purely from evidence accumulating elsewhere in the campaign.
    PRECONDITION_NOT_MET = "precondition_not_met"
    # Policy-level exclusion: this candidate's risk tier exceeds what the
    # mission allows, or it's a destructive action with no human-approval
    # loop -- a constraint on the CAMPAIGN, not a fact about the target.
    RISK_EXCEEDS_THRESHOLD = "risk_exceeds_threshold"
    # This operator's own cost alone doesn't fit the remaining budget --
    # the simplest, least ambiguous infeasibility.
    COST_EXCEEDS_BUDGET = "cost_exceeds_budget"
    # budget_feasible()'s structural bound: the REST of the chain this
    # operator starts provably can't complete within remaining budget, even
    # in the best case (an admissible/optimistic bound -- see that method's
    # own docstring). Genuinely infeasible, not merely low-value.
    CHAIN_BUDGET_INFEASIBLE = "chain_budget_infeasible"
    # core_utility (the evidence-grounded terms ONLY -- info gain, graph
    # progress, gap/hypothesis pull, severity, an exact failure-diagnosis
    # tag match) is <= 0: genuinely no predicted value left given real
    # accumulated evidence about THIS candidate specifically. This is the
    # ONLY status that reflects "evidence says this is a dead end" --
    # everything else above is a structural/policy fact, not an evidence
    # judgment, and RANKED (below) never reaches this bar at all.
    EVIDENCE_EXHAUSTED = "evidence_exhausted"
    # Survived every filter above -- appears in rank()'s own output.
    # Deliberately does NOT imply "currently attractive": exploration/
    # redirection nudges (family_diversification, hypothesis_escalation_
    # bonus) can still push this candidate's own utility very low, or even
    # negative, and it will simply sort near the bottom -- being RANKED
    # only ever means "not evidence-excluded," never "high-priority."
    RANKED = "ranked"


@dataclass(frozen=True)
class CandidateDiagnostic:
    operator_id: str
    status: CandidateStatus
    detail: str
