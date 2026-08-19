from aginiti.adapter.observation_adapter import ExecutionResult
from aginiti.graph.attack_category import ENCODING_ATTACK
from aginiti.graph.export import START, export_ssg_for_visualization
from aginiti.graph.mitre_atlas_refs import DIRECT_PROMPT_INJECTION
from aginiti.graph.owasp_llm_taxonomy import LLM01_PROMPT_INJECTION
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.security_boundary import BOUNDARY_L0
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, SUBGRAPH_DEFENDER, SUBGRAPH_TARGET, SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition


def _op(op_id, preconditions=(), effects_success=(), effects_failure=()):
    return Operator(
        id=op_id, description=f"do {op_id}", prompt="x", channel="direct",
        preconditions=preconditions, effects_success=effects_success,
        effects_failure=effects_failure, cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def _mission():
    return Mission(goal="test", success_criteria=("mission_win",), budget=20, risk_threshold=RiskTier.LOW)


def _exec(operator_id, confirmed_keys=None, confirmed_effects=None):
    return {
        "operator_id": operator_id,
        "confirmed_keys": confirmed_keys or [],
        "confirmed_effects": confirmed_effects or [],
    }


def test_executed_operator_with_no_precondition_edges_from_start():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "raw", supports=("access",))
    library = OperatorLibrary([recon])

    export = export_ssg_for_visualization(ssg, library, _mission(), [_exec("recon", ["access"])])

    assert export["edges"] == [{"from": START, "to": "access", "operator_id": "recon", "outcome": "success"}]
    node = next(n for n in export["nodes"] if n["key"] == "access")
    assert node["status"] == "hypothesized"


def test_executed_operator_with_precondition_edges_from_that_key():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    confirm = _op("confirm", preconditions=(Precondition("access", ClaimStatus.HYPOTHESIZED),),
                   effects_success=(ClaimEffect("access", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "raw1", supports=("access",))
    ssg.assert_claim("access", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([recon, confirm])

    export = export_ssg_for_visualization(
        ssg, library, _mission(), [_exec("recon", ["access"]), _exec("confirm", ["access"])],
    )

    confirm_edge = next(e for e in export["edges"] if e["operator_id"] == "confirm")
    assert confirm_edge["from"] == "access"
    assert confirm_edge["to"] == "access"


def test_edge_attributed_to_the_execution_that_actually_confirmed_it_not_final_state():
    # Two operators declare overlapping effects on the same key. Only the
    # one whose OWN confirmed_keys includes it should get an edge -- this
    # is the exact misattribution bug found against real data (an operator
    # that was blocked when it ran must not appear to have "succeeded"
    # just because a DIFFERENT operator later confirmed the same key).
    blunt = _op("blunt", effects_success=(ClaimEffect("win", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),),
                effects_failure=(ClaimEffect("blunt_blocked", ClaimStatus.CONFIRMED, SUBGRAPH_DEFENDER),))
    clever = _op("clever", effects_success=(ClaimEffect("win", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.assert_claim("win", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("blunt_blocked", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_DEFENDER)
    library = OperatorLibrary([blunt, clever])

    # blunt actually FAILED (only confirmed blunt_blocked); clever actually WON.
    execution_log = [_exec("blunt", ["blunt_blocked"]), _exec("clever", ["win"])]
    export = export_ssg_for_visualization(ssg, library, _mission(), execution_log)

    win_edges = [e for e in export["edges"] if e["to"] == "win"]
    assert len(win_edges) == 1
    assert win_edges[0]["operator_id"] == "clever"  # not "blunt"


def test_same_key_opposite_directions_uses_confirmed_effects_not_bare_keys():
    # probe_slack_trust-style operator: declares the SAME key in both
    # directions. Regression test for a real bug -- effects_by_key keyed
    # only by claim key let the failure-direction effect silently clobber
    # the success-direction one, mislabeling a real success as a failure.
    probe = _op("probe",
                effects_success=(ClaimEffect("trust", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),),
                effects_failure=(ClaimEffect("trust", ClaimStatus.REFUTED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.assert_claim("trust", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([probe])

    # The execution actually confirmed the SUCCESS direction.
    entry = _exec("probe", confirmed_effects=[{"key": "trust", "status": "confirmed"}])
    export = export_ssg_for_visualization(ssg, library, _mission(), [entry])

    edge = export["edges"][0]
    assert edge["outcome"] == "success"  # not "failure"


def test_frontier_lists_eligible_unexecuted_operators_only():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    locked = _op("locked", preconditions=(Precondition("access", ClaimStatus.HYPOTHESIZED),))
    unreachable = _op("unreachable", preconditions=(Precondition("nope", ClaimStatus.CONFIRMED),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "raw", supports=("access",))
    library = OperatorLibrary([recon, locked, unreachable])

    export = export_ssg_for_visualization(ssg, library, _mission(), [_exec("recon", ["access"])])
    frontier_ids = {f["operator_id"] for f in export["frontier"]}
    assert frontier_ids == {"locked"}


def test_evidence_attached_to_node():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "the agent mentioned payroll access", supports=("access",))
    library = OperatorLibrary([recon])

    export = export_ssg_for_visualization(ssg, library, _mission(), [_exec("recon", ["access"])])
    node = next(n for n in export["nodes"] if n["key"] == "access")
    assert node["evidence"][0]["raw_signal"] == "the agent mentioned payroll access"
    assert node["evidence"][0]["polarity"] == "supports"


def test_defender_subgraph_tag_preserved():
    blocked = _op("blocked", effects_failure=(ClaimEffect("filter_present", ClaimStatus.CONFIRMED, SUBGRAPH_DEFENDER),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "blocked", contradicts=("filter_present",))
    ssg.assert_claim("filter_present", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_DEFENDER)
    library = OperatorLibrary([blocked])

    export = export_ssg_for_visualization(ssg, library, _mission(), [_exec("blocked", ["filter_present"])])
    node = next(n for n in export["nodes"] if n["key"] == "filter_present")
    assert node["subgraph"] == SUBGRAPH_DEFENDER


# --- taxonomy fields on exported nodes (2026-08-12 architecture-review fix: the
# visualization export never carried security_boundary/owasp_llm_category/
# attack_category/mitre_atlas_technique even though the SSG had all four) --------

def test_untagged_node_exports_all_four_taxonomy_fields_as_none():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "raw", supports=("access",))
    library = OperatorLibrary([recon])

    export = export_ssg_for_visualization(ssg, library, _mission(), [_exec("recon", ["access"])])
    node = next(n for n in export["nodes"] if n["key"] == "access")

    assert node["security_boundary"] is None
    assert node["owasp_llm_category"] is None
    assert node["attack_category"] is None
    assert node["mitre_atlas_technique"] is None


def test_tagged_node_exports_all_four_taxonomy_fields():
    op = _op("encoding_probe", effects_success=(
        ClaimEffect("encoded_instruction_followed", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET,
                    category=CATEGORY_MISSION_OUTCOME, security_boundary=BOUNDARY_L0,
                    owasp_llm_category=LLM01_PROMPT_INJECTION, attack_category=ENCODING_ATTACK,
                    mitre_atlas_technique=DIRECT_PROMPT_INJECTION),
    ))
    ssg = SecurityStateGraph()
    ssg.assert_claim("encoded_instruction_followed", "true", ClaimStatus.CONFIRMED,
                      category=CATEGORY_MISSION_OUTCOME, security_boundary=BOUNDARY_L0,
                      owasp_llm_category=LLM01_PROMPT_INJECTION, attack_category=ENCODING_ATTACK,
                      mitre_atlas_technique=DIRECT_PROMPT_INJECTION)
    library = OperatorLibrary([op])

    export = export_ssg_for_visualization(
        ssg, library, _mission(),
        [_exec("encoding_probe", confirmed_effects=[{"key": "encoded_instruction_followed", "status": "confirmed"}])],
    )
    node = next(n for n in export["nodes"] if n["key"] == "encoded_instruction_followed")

    assert node["security_boundary"] == BOUNDARY_L0
    assert node["owasp_llm_category"] == LLM01_PROMPT_INJECTION
    assert node["attack_category"] == ENCODING_ATTACK
    assert node["mitre_atlas_technique"] == DIRECT_PROMPT_INJECTION


# --- accepts a live CampaignResult.execution_log (ExecutionResult objects) directly,
# not just a saved-trial-JSON's plain dicts (2026-08-12 architecture-review fix --
# found via a real dry run: calling this with a live campaign's own execution_log,
# exactly as its own docstring said was supported, raised AttributeError) ----------

def test_accepts_a_live_execution_result_object_not_just_a_dict():
    recon = _op("recon", effects_success=(ClaimEffect("access", ClaimStatus.HYPOTHESIZED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.record_observation("exec_1", "raw", supports=("access",))
    library = OperatorLibrary([recon])

    live_entry = ExecutionResult(
        operator_id="recon", operator_execution_id="exec_1", raw_signal="raw",
        confirmed_keys=["access"], overall_success=True, ground_truth_mission_achieved=False,
        cost_prompts=1, confirmed_effects=[{"key": "access", "status": "hypothesized"}],
    )

    export = export_ssg_for_visualization(ssg, library, _mission(), [live_entry])

    assert export["edges"] == [{"from": START, "to": "access", "operator_id": "recon", "outcome": "success"}]
    node = next(n for n in export["nodes"] if n["key"] == "access")
    assert node["status"] == "hypothesized"


def test_mixed_dict_and_execution_result_entries_both_work_in_the_same_call():
    op1 = _op("op1", effects_success=(ClaimEffect("k1", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),))
    op2 = _op("op2", effects_success=(ClaimEffect("k2", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET),))
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("k2", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([op1, op2])

    dict_entry = _exec("op1", confirmed_effects=[{"key": "k1", "status": "confirmed"}])
    object_entry = ExecutionResult(
        operator_id="op2", operator_execution_id="exec_2", raw_signal="raw",
        confirmed_keys=["k2"], overall_success=True, ground_truth_mission_achieved=False,
        cost_prompts=1, confirmed_effects=[{"key": "k2", "status": "confirmed"}],
    )

    export = export_ssg_for_visualization(ssg, library, _mission(), [dict_entry, object_entry])

    assert {n["key"] for n in export["nodes"]} == {"k1", "k2"}
