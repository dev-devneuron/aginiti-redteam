"""Round-trip tests for aginiti/graph/persistence.py -- the mechanism that
lets a SecurityStateGraph outlive a single campaign process. No live API
calls: builds a graph by hand, saves it, reloads it into a fresh process-
equivalent object, and checks nothing was lost or silently corrupted.
"""
import json

from aginiti.graph.persistence import load_ssg, save_ssg
from aginiti.graph.schema import (
    Asset,
    ClaimStatus,
    ConfidenceBand,
    DefenderControl,
    InsightCategory,
    bump_id_counter,
    next_id,
)
from aginiti.graph.ssg import CATEGORY_TRUST_EDGE, SUBGRAPH_DEFENDER, SUBGRAPH_TARGET, SecurityStateGraph


def _built_graph() -> SecurityStateGraph:
    ssg = SecurityStateGraph()
    ssg.record_fact("exec_0001", "tool_call", {"tool": "lookup", "args": {"id": 1}})
    ssg.record_observation("exec_0001", "raw signal one", supports=("access",))
    ssg.assert_claim("access", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_TARGET)
    ssg.assert_claim("trusts_slack", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_TARGET,
                      category=CATEGORY_TRUST_EDGE)
    ssg.assert_claim("filter_present", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_DEFENDER)
    ssg.record_operator_execution("recon", success=True)
    ssg.record_operator_execution("exploit", success=False)
    ssg.add_structural_node(Asset(id="asset_1", type="tool", name="payroll_api"))
    ssg.add_structural_node(DefenderControl(id="ctrl_1", type="prompt_filter"))
    ssg.record_insight(InsightCategory.BEHAVIORAL,
                        "the agent trusts internal-looking sources without verification",
                        derived_from=("trusts_slack",), confidence="medium",
                        alternative_explanations=("model-level safety", "wrapper validation"),
                        evidence_still_missing=("indirect trust-boundary testing", "only one user role tested"))
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "memory persistence unknown",
                        importance="high", prior_belief="probably persists memory",
                        confidence="low", related_probe_id="probe_memory", priority_weight=4.15)
    ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                         experiments=("probe_memory",), prior_confidence=0.6)
    ssg.assert_claim("memory_persists", "true", ClaimStatus.CONFIRMED)  # resolves it to ACCEPTED
    return ssg


def test_round_trip_preserves_claims_observations_and_tags(tmp_path):
    ssg = _built_graph()
    path = tmp_path / "graph.json"
    save_ssg(ssg, path)
    loaded = load_ssg(path)

    assert {c.key for c in loaded.claims} == {c.key for c in ssg.claims}
    access = loaded.current_claim("access")
    assert access.status == ClaimStatus.CONFIRMED
    assert access.confidence == ConfidenceBand.LOW

    assert loaded.claim_subgraph["filter_present"] == SUBGRAPH_DEFENDER
    assert loaded.claim_category["trusts_slack"] == CATEGORY_TRUST_EDGE

    assert len(loaded.observations) == 1
    assert loaded.observations[0].raw_signal == "raw signal one"
    assert loaded.observations[0].supports == ("access",)

    assert loaded.operator_stats["recon"].successes == 1
    assert loaded.operator_stats["exploit"].failures == 1

    assert len(loaded.facts) == 1
    assert loaded.facts[0].kind == "tool_call"
    assert loaded.facts[0].data == {"tool": "lookup", "args": {"id": 1}}

    assert len(loaded.insights) == 2
    behavioral = loaded.insights[0]
    assert behavioral.category == InsightCategory.BEHAVIORAL
    assert behavioral.statement == "the agent trusts internal-looking sources without verification"
    assert behavioral.derived_from == ("trusts_slack",)
    assert behavioral.confidence == "medium"
    assert behavioral.alternative_explanations == ("model-level safety", "wrapper validation")
    assert behavioral.evidence_still_missing == ("indirect trust-boundary testing", "only one user role tested")

    gap = loaded.insights[1]
    assert gap.category == InsightCategory.KNOWLEDGE_GAP
    assert gap.importance == "high"
    assert gap.prior_belief == "probably persists memory"
    assert gap.confidence == "low"
    assert gap.related_probe_id == "probe_memory"
    assert gap.priority_weight == 4.15  # 2026-08-09 field: round-trips like any other Insight field

    assert len(loaded.hypotheses) == 1
    hyp = next(iter(loaded.hypotheses.values()))
    assert hyp.statement == "agent persists memory"
    assert hyp.target_claim_key == "memory_persists"
    assert hyp.status.value == "accepted"  # 0.6 + 0.25 = 0.85 >= accept threshold
    assert hyp.confidence == 0.85
    assert hyp.experiments == ("probe_memory",)
    assert hyp.supporting_evidence == ("memory_persists",)


def test_round_trip_defaults_priority_weight_to_none_for_a_graph_saved_before_the_field_existed(tmp_path):
    # A KNOWLEDGE_GAP insight saved by an older version of this project
    # (or by anything that never sets priority_weight, e.g. the Reasoning
    # Layer today) has no "priority_weight" key in its JSON at all --
    # load_ssg must default it to None, not KeyError.
    ssg = SecurityStateGraph()
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "old-style gap", importance="medium",
                        related_probe_id="probe_x")
    path = tmp_path / "graph.json"
    save_ssg(ssg, path)

    raw = json.loads(path.read_text())
    del raw["insights"][0]["priority_weight"]  # simulate a pre-2026-08-09 saved file
    path.write_text(json.dumps(raw))

    loaded = load_ssg(path)
    assert loaded.insights[0].priority_weight is None


def test_round_trip_preserves_structural_nodes(tmp_path):
    ssg = _built_graph()
    path = tmp_path / "graph.json"
    save_ssg(ssg, path)
    loaded = load_ssg(path)

    asset = loaded.structural_nodes["asset_1"]
    assert asset.type == "tool"
    assert asset.name == "payroll_api"
    control = loaded.structural_nodes["ctrl_1"]
    assert control.type == "prompt_filter"


def test_saved_file_is_plain_json(tmp_path):
    ssg = _built_graph()
    path = tmp_path / "graph.json"
    save_ssg(ssg, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data["claims"], list)
    assert data["claims"][0]["status"] in ("hypothesized", "confirmed", "refuted")


def test_load_ssg_bumps_id_counters_past_loaded_ids_to_avoid_collisions(tmp_path):
    # Regression test: without this, a fresh process's next_id("claim")
    # would restart at claim_0001 and collide with an id already present
    # in the loaded graph -- confusing at best, ambiguous at worst if that
    # id is ever used as a lookup key by a future consumer.
    ssg = SecurityStateGraph()
    for key in ("k1", "k2", "k3"):
        ssg.assert_claim(key, "true", ClaimStatus.CONFIRMED)  # each call mints a new claim id internally
    path = tmp_path / "graph.json"
    save_ssg(ssg, path)
    highest_claim_id = max(c.id for c in ssg.claims)

    load_ssg(path)  # this call must bump the "claim"/"obs"/"exec" counters
    new_id = next_id("claim")
    assert new_id > highest_claim_id


def test_bump_id_counter_ignores_malformed_ids():
    bump_id_counter("weird", "not-a-standard-id")  # must not raise
