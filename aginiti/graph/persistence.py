"""Persists a SecurityStateGraph to/from JSON so it can outlive a single
campaign process.

This is the concrete mechanism behind the "graph is the source of truth,
the campaign is one consumer" shift: a graph built today can be reloaded
tomorrow (or by a different consumer -- an analyst query, a regression
check) without needing the campaign, adapter, or LLM client that produced
it. Only the SSG's own state is serialized; nothing about which adapter or
campaign wrote it, since the graph is deliberately adapter-agnostic (same
principle as export.py's export_ssg_for_visualization).

`ssg.belief` (aginiti/graph/belief_state.py, CampaignBeliefState) is
DELIBERATELY excluded from this file, on purpose, not an oversight: it is
documented as a derived cache over the state that IS serialized here, so
persisting it would create a second copy of understanding that could go
stale relative to the graph it was derived from. A resumed campaign loads
a fresh, empty CampaignBeliefState and rebuilds whatever it needs from the
full claim history already present on the reloaded graph.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from aginiti.graph.hypothesis import Hypothesis, HypothesisStatus
from aginiti.graph.schema import (
    Asset,
    Capability,
    Claim,
    ClaimStatus,
    ConfidenceBand,
    DefenderControl,
    Fact,
    Insight,
    InsightCategory,
    Observation,
    TrustEdge,
    Workflow,
    bump_id_counter,
)
from aginiti.graph.ssg import OperatorStats, SecurityStateGraph

_STRUCTURAL_TYPES = {cls.__name__: cls for cls in (Asset, Capability, TrustEdge, Workflow, DefenderControl)}


def save_ssg(ssg: SecurityStateGraph, path: str | Path) -> None:
    data = {
        "facts": [
            {**asdict(f), "timestamp": f.timestamp.isoformat()}
            for f in ssg.facts
        ],
        "claims": [
            {**asdict(c), "status": c.status.value, "confidence": c.confidence.value}
            for c in ssg.claims
        ],
        "observations": [
            {**asdict(o), "timestamp": o.timestamp.isoformat()}
            for o in ssg.observations
        ],
        "insights": [
            {**asdict(i), "category": i.category.value, "generated_at": i.generated_at.isoformat()}
            for i in ssg.insights
        ],
        "hypotheses": {
            norm_key: {
                **asdict(h), "status": h.status.value, "expected_status": h.expected_status.value,
                "created_at": h.created_at.isoformat(), "updated_at": h.updated_at.isoformat(),
            }
            for norm_key, h in ssg.hypotheses.items()
        },
        "operator_stats": {op_id: asdict(stats) for op_id, stats in ssg.operator_stats.items()},
        "claim_subgraph": ssg.claim_subgraph,
        "claim_category": ssg.claim_category,
        # "_cls" (not "type") because Asset/DefenderControl both already
        # have a field literally named `type` -- tagging under that key
        # would get silently overwritten by the field's own value.
        "structural_nodes": [{"_cls": type(n).__name__, **asdict(n)} for n in ssg.structural_nodes.values()],
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_ssg(path: str | Path) -> SecurityStateGraph:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    ssg = SecurityStateGraph()

    for f in data.get("facts", []):
        fact = Fact(
            id=f["id"], timestamp=datetime.fromisoformat(f["timestamp"]),
            operator_execution_id=f["operator_execution_id"], kind=f["kind"], data=f["data"],
        )
        ssg.facts.append(fact)
        bump_id_counter("fact", fact.id)

    for c in data.get("claims", []):
        claim = Claim(
            id=c["id"], key=c["key"], object=c["object"],
            status=ClaimStatus(c["status"]), confidence=ConfidenceBand(c["confidence"]),
            supersedes=c.get("supersedes"),
        )
        ssg.claims.append(claim)
        bump_id_counter("claim", claim.id)

    for o in data.get("observations", []):
        obs = Observation(
            id=o["id"], timestamp=datetime.fromisoformat(o["timestamp"]),
            operator_execution_id=o["operator_execution_id"], raw_signal=o["raw_signal"],
            supports=tuple(o.get("supports", ())), contradicts=tuple(o.get("contradicts", ())),
        )
        ssg.observations.append(obs)
        bump_id_counter("obs", obs.id)
        # operator_execution_id shares the "exec" id space minted by
        # ObservationAdapter.execute() (next_id("exec")) -- must be bumped
        # too, or a resumed session's first new execution can collide with
        # an id already present in the loaded graph.
        bump_id_counter("exec", obs.operator_execution_id)

    for i in data.get("insights", []):
        insight = Insight(
            id=i["id"], category=InsightCategory(i["category"]), statement=i["statement"],
            derived_from=tuple(i.get("derived_from", ())),
            confidence=i.get("confidence"),
            alternative_explanations=tuple(i.get("alternative_explanations", ())),
            evidence_still_missing=tuple(i.get("evidence_still_missing", ())),
            importance=i.get("importance"),
            prior_belief=i.get("prior_belief"),
            related_probe_id=i.get("related_probe_id"),
            priority_weight=i.get("priority_weight"),  # absent in graphs saved before 2026-08-09 -> None, safe default
            generated_at=datetime.fromisoformat(i["generated_at"]),
        )
        ssg.insights.append(insight)
        bump_id_counter("insight", insight.id)

    for norm_key, h in data.get("hypotheses", {}).items():
        hyp = Hypothesis(
            id=h["id"], statement=h["statement"], target_claim_key=h["target_claim_key"],
            expected_status=ClaimStatus(h["expected_status"]), status=HypothesisStatus(h["status"]),
            confidence=h["confidence"], experiments=tuple(h.get("experiments", ())),
            supporting_evidence=tuple(h.get("supporting_evidence", ())),
            contradicting_evidence=tuple(h.get("contradicting_evidence", ())),
            created_at=datetime.fromisoformat(h["created_at"]),
            updated_at=datetime.fromisoformat(h["updated_at"]),
        )
        ssg.hypotheses[norm_key] = hyp
        bump_id_counter("hyp", hyp.id)

    for op_id, stats in data.get("operator_stats", {}).items():
        ssg.operator_stats[op_id] = OperatorStats(**stats)

    ssg.claim_subgraph.update(data.get("claim_subgraph", {}))
    ssg.claim_category.update(data.get("claim_category", {}))

    for n in data.get("structural_nodes", []):
        cls = _STRUCTURAL_TYPES.get(n.get("_cls"))
        if cls is None:
            continue
        kwargs = {k: v for k, v in n.items() if k != "_cls"}
        if "steps" in kwargs and kwargs["steps"] is not None:
            kwargs["steps"] = tuple(kwargs["steps"])
        node = cls(**kwargs)
        ssg.structural_nodes[node.id] = node

    return ssg
