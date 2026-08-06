"""The Security State Graph store (design doc Section 10, 16.2).

Append-only: Claims and Observations are never mutated or deleted. "Current
state" for a given claim key is a query over the append log (latest claim
with that key), not a stored table -- this is what Section 10.3 calls a
"free consequence" of the provenance design.

Confidence (Section 11.2, v0): a bounded, weighted count of supporting minus
contradicting Observations for a claim key, mapped to a discrete band. This
is the documented simplification the design doc flags as replaceable later
without a schema change.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.graph.schema import (
    Claim,
    ClaimStatus,
    ConfidenceBand,
    Observation,
    StructuralNode,
    next_id,
)

# Section 10.1's five sub-graphs, used to tag which claims/nodes belong to
# which view. "operator_self" and "mission" are tracked as separate
# structures below rather than as claim tags, since they aren't
# subject/predicate assertions about the target.
SUBGRAPH_TARGET = "target"
SUBGRAPH_DEFENDER = "defender"


def _confidence_band(net_score: int) -> ConfidenceBand:
    bounded = max(0, min(net_score, 4))
    if bounded <= 1:
        return ConfidenceBand.LOW
    if bounded in (2, 3):
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.HIGH


@dataclass
class OperatorStats:
    executions: int = 0
    successes: int = 0
    failures: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / self.executions if self.executions else 0.0


@dataclass
class SecurityStateGraph:
    structural_nodes: dict[str, StructuralNode] = field(default_factory=dict)
    claims: list[Claim] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    operator_stats: dict[str, OperatorStats] = field(default_factory=dict)
    claim_subgraph: dict[str, str] = field(default_factory=dict)  # claim key -> subgraph tag

    # -- structural nodes ----------------------------------------------
    def add_structural_node(self, node: StructuralNode) -> StructuralNode:
        self.structural_nodes[node.id] = node
        return node

    def nodes_of_type(self, cls: type) -> list[StructuralNode]:
        return [n for n in self.structural_nodes.values() if isinstance(n, cls)]

    # -- claims / observations -------------------------------------------
    def current_claim(self, key: str) -> Claim | None:
        for claim in reversed(self.claims):
            if claim.key == key:
                return claim
        return None

    def current_status(self, key: str) -> ClaimStatus | None:
        claim = self.current_claim(key)
        return claim.status if claim else None

    def is_confirmed(self, key: str) -> bool:
        return self.current_status(key) == ClaimStatus.CONFIRMED

    def record_observation(
        self,
        operator_execution_id: str,
        raw_signal: str,
        supports: tuple[str, ...] = (),
        contradicts: tuple[str, ...] = (),
    ) -> Observation:
        """Append-only ingest of one Observation (Section 16.2's update()).
        Any claim key referenced in supports/contradicts gets a new Claim
        version whose confidence is recomputed from every Observation ever
        linked to that key. Status is left as-is here -- callers that need
        to assert a status transition (hypothesized -> confirmed, etc.)
        should call `assert_claim` for that key immediately after, or before,
        recording the observation, using this same observation's id.
        """
        obs = Observation.create(operator_execution_id, raw_signal, supports, contradicts)
        self.observations.append(obs)
        for key in set(supports) | set(contradicts):
            self._recompute_confidence(key)
        return obs

    def assert_claim(self, key: str, object_: str, status: ClaimStatus,
                      subgraph: str = SUBGRAPH_TARGET) -> Claim:
        """Create a new Claim version for `key` with an explicit status.
        Confidence is derived from whatever Observations already reference
        this key (0 if none yet -> LOW)."""
        prior = self.current_claim(key)
        net = self._net_observation_score(key)
        claim = Claim.create(
            key=key,
            object_=object_,
            status=status,
            confidence=_confidence_band(net),
            supersedes=prior.id if prior else None,
        )
        self.claims.append(claim)
        self.claim_subgraph[key] = subgraph
        return claim

    def _net_observation_score(self, key: str) -> int:
        supports = sum(1 for o in self.observations if key in o.supports)
        contradicts = sum(1 for o in self.observations if key in o.contradicts)
        return supports - contradicts

    def _recompute_confidence(self, key: str) -> None:
        prior = self.current_claim(key)
        if prior is None:
            # An Observation arrived referencing a key with no Claim yet --
            # hypothesize it (Section 14, Step 2: first Observation creates
            # a hypothesized Claim at low confidence).
            self.assert_claim(key, object_="true", status=ClaimStatus.HYPOTHESIZED)
            return
        net = self._net_observation_score(key)
        band = _confidence_band(net)
        if band == prior.confidence:
            return  # no-op: avoid noisy no-op claim versions
        claim = Claim.create(
            key=key,
            object_=prior.object,
            status=prior.status,
            confidence=band,
            supersedes=prior.id,
        )
        self.claims.append(claim)

    # -- operator (self) graph -------------------------------------------
    def record_operator_execution(self, operator_id: str, success: bool) -> None:
        stats = self.operator_stats.setdefault(operator_id, OperatorStats())
        stats.executions += 1
        if success:
            stats.successes += 1
        else:
            stats.failures += 1

    # -- views -------------------------------------------------------------
    def defender_claims(self) -> list[Claim]:
        keys = {k for k, sg in self.claim_subgraph.items() if sg == SUBGRAPH_DEFENDER}
        return [c for c in self.claims if c.key in keys]

    def target_claims(self) -> list[Claim]:
        keys = {k for k, sg in self.claim_subgraph.items() if sg == SUBGRAPH_TARGET}
        return [c for c in self.claims if c.key in keys]

    def size(self) -> int:
        """Graph size (Claims + Observations), used for the Figure 14.1-style
        growth trace."""
        return len(self.claims) + len(self.observations)
