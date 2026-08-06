"""Exports a completed (or in-progress) campaign's Security State Graph into
a generic, adapter-agnostic node-link structure for visualization.

This is deliberately built from only three things: the SSG (claims), the
OperatorLibrary (preconditions/effects) that produced them, and the
execution log (which specific operator RUN confirmed which key). Neither
the SSG nor the library know or care which BaseAdapter generated the
underlying data -- a mock campaign and a DVLA campaign export to the exact
same shape. That's the point: the graph is the product surface, and it has
to look identical regardless of which adapter is behind it.

Node/edge semantics:
  - Every claim key with a current (latest) status becomes a node --
    labeled, with status/confidence/evidence attached, reflecting what the
    SSG currently believes.
  - Every EXECUTION that confirmed a key becomes an edge from its
    operator's precondition key(s) (or the virtual "start" node, if none)
    to that key. Edges are attributed per-execution, not re-derived from
    final claim state -- two operators can declare overlapping effects on
    the same key, and only the execution(s) that actually confirmed it
    should get credit for that edge, not every operator that merely
    predicted it.
  - Operators that are currently eligible but have NOT been executed form
    the "frontier" -- the "recommended next probes" surface, without
    leaking undiscovered structure the campaign never actually confirmed.
"""
from __future__ import annotations

from aginiti.graph.ssg import SUBGRAPH_TARGET, SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary

START = "start"


def _evidence_for(ssg: SecurityStateGraph, key: str, limit: int = 3) -> list[dict]:
    items = []
    for obs in ssg.observations:
        if key in obs.supports:
            items.append({"raw_signal": obs.raw_signal, "polarity": "supports", "timestamp": obs.timestamp.isoformat()})
        elif key in obs.contradicts:
            items.append({"raw_signal": obs.raw_signal, "polarity": "contradicts", "timestamp": obs.timestamp.isoformat()})
    return items[-limit:]


def _resolve_effects(op, entry: dict) -> list:
    """Returns the actual ClaimEffect objects confirmed by this execution,
    preferring the direction-preserving `confirmed_effects` field
    ({key, status} pairs). Falls back to bare `confirmed_keys` for legacy
    records that predate that field -- ambiguous when an operator declares
    the same key in both directions (e.g. probe_slack_trust), in which case
    the success-direction effect is preferred and the ambiguity is real,
    not silently resolved as correct."""
    all_effects = (*op.effects_success, *op.effects_failure)
    if entry.get("confirmed_effects"):
        by_id = {(e.key, e.status.value): e for e in all_effects}
        return [by_id[(d["key"], d["status"])] for d in entry["confirmed_effects"]
                if (d["key"], d["status"]) in by_id]
    # Legacy fallback: bare keys only, direction ambiguous when an operator
    # declares both directions for the same key.
    by_key_success_first: dict[str, object] = {}
    for e in (*op.effects_failure, *op.effects_success):  # success inserted LAST wins ties
        by_key_success_first[e.key] = e
    return [by_key_success_first[k] for k in entry.get("confirmed_keys", []) if k in by_key_success_first]


def export_ssg_for_visualization(ssg: SecurityStateGraph, library: OperatorLibrary, mission: Mission,
                                  execution_log: list[dict]) -> dict:
    """`execution_log`: one entry per operator EXECUTION, each with at least
    `operator_id` and (ideally) `confirmed_effects` ({key,status} pairs) --
    works whether it comes from a live `CampaignResult.execution_log`
    (normalize ExecutionResult -> dict first) or a saved trial JSON's
    `execution_log` (already this shape).
    """
    op_by_id = {op.id: op for op in library}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    executed_ids: list[str] = []

    for entry in execution_log:
        op = op_by_id.get(entry.get("operator_id"))
        if op is None:
            continue
        executed_ids.append(op.id)
        sources = [p.key for p in op.preconditions] or [START]

        for effect in _resolve_effects(op, entry):
            key = effect.key
            claim = ssg.current_claim(key)
            if claim is None:
                continue
            outcome = "success" if effect in op.effects_success else "failure"
            for src in sources:
                edges.append({"from": src, "to": key, "operator_id": op.id, "outcome": outcome})
            if key not in nodes:
                nodes[key] = {
                    "key": key,
                    "status": claim.status.value,
                    "confidence": claim.confidence.value,
                    "subgraph": ssg.claim_subgraph.get(key, SUBGRAPH_TARGET),
                    "object": claim.object,
                    "evidence": _evidence_for(ssg, key),
                }

    executed_set = set(executed_ids)
    frontier = [
        {"operator_id": op.id, "description": op.description,
         "requires": [p.key for p in op.preconditions]}
        for op in library
        if op.id not in executed_set and op.preconditions_met(ssg)
    ]

    return {
        "start_node": START,
        "nodes": list(nodes.values()),
        "edges": edges,
        "frontier": frontier,
        "mission_targets": list(mission.success_criteria),
    }
