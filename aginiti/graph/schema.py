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

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


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


_id_counters: dict[str, itertools.count] = {}


def next_id(prefix: str) -> str:
    counter = _id_counters.setdefault(prefix, itertools.count(1))
    return f"{prefix}_{next(counter):04d}"


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
# Claim / Observation (Section 15)
# --------------------------------------------------------------------------


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
