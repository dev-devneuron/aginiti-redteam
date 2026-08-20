"""Hypothesis -- the first genuinely MUTABLE, persistent-identity object in
the graph. Everything in schema.py (Fact/Observation/Claim/Insight) is
append-only: a revised belief creates a new version rather than mutating
the old one. A Hypothesis breaks that pattern on purpose.

Without a stable identity, "accept" or "reject" has no referent. Insight's
KNOWLEDGE_GAP entries can describe an unknown with a prior_belief, but
each synthesis call mints a brand-new Insight -- there is nothing to
UPDATE when evidence arrives, only more entries to append. A Hypothesis
is created once (get-or-create, keyed by a normalized statement, via
SecurityStateGraph.form_hypothesis), then mutates in place as evidence
accumulates: confidence moves, status resolves to ACCEPTED or REJECTED.
That is what "model revision after every observation" concretely means --
not a new Insight every time, the SAME object updated.

This is a deliberately minimal v1: confidence is a single float (not a
real Bayesian posterior -- a documented simplification, same spirit as
ConfidenceBand's own "replaceable later without a schema change"), and
resolution is a simple step-update against two thresholds. What it does
have, precisely because it isn't append-only: a hypothesis started in
round 1 can be resolved by evidence that arrives in round 5, and every
consumer sees the SAME object update, not a growing list of near-duplicate
guesses (the exact problem the Insight-dedup fix and this file both push
back against, from different angles).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from aginiti.core.graph.schema import ClaimStatus, next_id

_CONFIDENCE_STEP = 0.25
_ACCEPT_THRESHOLD = 0.8
_REJECT_THRESHOLD = 0.2


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_statement(statement: str) -> str:
    """The stable identity key a hypothesis is looked up by -- lowercased,
    punctuation-stripped, whitespace-collapsed, so trivial rewording across
    synthesis calls still resolves to the SAME tracked object."""
    return " ".join(re.sub(r"[^a-z0-9 ]", "", statement.lower()).split())


class HypothesisStatus(str, Enum):
    OPEN = "open"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class Hypothesis:
    id: str
    statement: str
    target_claim_key: str  # the claim key whose resolution tests this hypothesis
    expected_status: ClaimStatus  # what CONFIRMED-direction (the hypothesis being TRUE) looks like
    status: HypothesisStatus = HypothesisStatus.OPEN
    confidence: float = 0.5  # 0.0-1.0, continuous
    experiments: tuple[str, ...] = ()  # operator ids that could test this -- "one question, many experiments"
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)

    def apply_claim_status(self, status: ClaimStatus) -> None:
        """Updates confidence/evidence/status in place from a newly-
        observed status on `target_claim_key`. HYPOTHESIZED moves nothing
        -- a provisional claim isn't resolution either direction yet."""
        if self.status != HypothesisStatus.OPEN or status == ClaimStatus.HYPOTHESIZED:
            return
        if status == self.expected_status:
            self.supporting_evidence = self.supporting_evidence + (self.target_claim_key,)
            self.confidence = min(1.0, self.confidence + _CONFIDENCE_STEP)
        else:
            self.contradicting_evidence = self.contradicting_evidence + (self.target_claim_key,)
            self.confidence = max(0.0, self.confidence - _CONFIDENCE_STEP)
        self.updated_at = _now()
        if self.confidence >= _ACCEPT_THRESHOLD:
            self.status = HypothesisStatus.ACCEPTED
        elif self.confidence <= _REJECT_THRESHOLD:
            self.status = HypothesisStatus.REJECTED

    @property
    def uncertainty(self) -> float:
        """1.0 at confidence=0.5 (maximally undecided -- testing it is
        maximally informative), 0.0 at confidence=0 or 1 (already
        resolved, nothing left to learn). Used by the planner's
        hypothesis_priority as an information-gain proxy."""
        if self.status != HypothesisStatus.OPEN:
            return 0.0
        return 1.0 - abs(self.confidence - 0.5) * 2

    @staticmethod
    def create(statement: str, target_claim_key: str, expected_status: ClaimStatus,
               experiments: tuple[str, ...], prior_confidence: float = 0.5) -> "Hypothesis":
        return Hypothesis(id=next_id("hyp"), statement=statement, target_claim_key=target_claim_key,
                          expected_status=expected_status, confidence=prior_confidence,
                          experiments=experiments)
