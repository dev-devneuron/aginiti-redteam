from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE, SecurityStateGraph
from aginiti.operators.dvaa_definitions import _RETIRED_OPERATORS_2026_08_08, build_dvaa_library
from aginiti.scenarios import dvaa_mission


def test_dvaa_library_has_twelve_operators():
    # 7 original (2 memory + 2 a2a + 3 mcp) + a2a_forged_delegation_request
    # (corrected, kept) + 2 composition-attack operators + 1 RagBot
    # exfiltration operator + 1 new MCP tool-registration-poisoning
    # operator (item 9 research sweep, 2026-08-08). 13 operators were
    # RETIRED 2026-08-08 after a live validation pass found them
    # unsupported by the real target (see dvaa_definitions.py's module
    # docstring) -- this number is smaller than an earlier session's 23
    # on purpose: it reflects validated reality, not aspirational coverage.
    assert len(build_dvaa_library()) == 12


def test_every_operator_declares_an_understanding_question():
    for op in build_dvaa_library():
        assert op.understanding_question.strip(), op.id


def test_only_ungated_operators_available_at_start():
    ssg = SecurityStateGraph()
    lib = build_dvaa_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert candidates == {
        "memory_plant_instruction",
        "a2a_baseline_untrusted_sender", "a2a_identity_spoof", "a2a_forged_delegation_request",
        "mcp_tool_discovery", "mcp_fetch_destination_check", "mcp_unverified_tool_registration",
        "rag_knowledge_base_exfiltrated",
    }


def test_memory_recall_gated_behind_plant_hypothesis():
    ssg = SecurityStateGraph()
    ssg.assert_claim("memory_accepts_injected_instruction", "true", ClaimStatus.HYPOTHESIZED)
    lib = build_dvaa_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "memory_recall_check" in candidates


def test_mcp_no_auth_check_gated_behind_tool_discovery():
    ssg = SecurityStateGraph()
    ssg.assert_claim("mcp_tool_inventory_declared", "true", ClaimStatus.HYPOTHESIZED)
    lib = build_dvaa_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "mcp_no_auth_check" in candidates


def test_a2a_identity_spoof_uses_trust_edge_category():
    lib = build_dvaa_library()
    op = lib.get("a2a_identity_spoof")
    trust_effect = next(e for e in op.effects_success if e.key == "a2a_trusts_claimed_identity")
    assert trust_effect.category == CATEGORY_TRUST_EDGE


def test_mission_outcome_effects_tagged_correctly():
    # dvaa_mission() itself is NOT expanded here on purpose -- that mission
    # was scoped and cited around the original 3 behavioral dimensions;
    # whether to widen "mission success" to the newer outcomes below is a
    # separate, deliberate decision, not a silent side effect of adding
    # more operators to the library.
    lib = build_dvaa_library()
    mission_outcome_keys = {
        "memory_persists_cross_session", "unauthorized_a2a_access_granted",
        "mcp_unauthenticated_execution_succeeded",
        "a2a_forged_relay_task_executed", "mcp_secret_exfiltrated_via_plugin_chain",
        "rag_knowledge_base_exfiltrated", "mcp_unverified_tool_registration_accepted",
    }
    found = set()
    for op in lib:
        for e in (*op.effects_success, *op.effects_failure):
            if e.category == CATEGORY_MISSION_OUTCOME:
                found.add(e.key)
    assert found == mission_outcome_keys


def test_all_operators_are_branch_tagged():
    lib = build_dvaa_library()
    for op in lib:
        assert op.branch is not None, op.id


def test_a2a_forged_delegation_request_targets_worker():
    lib = build_dvaa_library()
    assert lib.get("a2a_forged_delegation_request").channel == "a2a:worker"


def test_a2a_forged_delegation_request_does_not_overclaim_data_disclosure():
    # The 2026-08-08 correction: live evidence showed a real vulnerability
    # (unauthorized privileged task execution) but the ORIGINAL claim key
    # (a2a_forged_relay_data_disclosed) implied literal data appeared in
    # the response, which it never does. The corrected key name and
    # description must not claim disclosure.
    lib = build_dvaa_library()
    effect = lib.get("a2a_forged_delegation_request").effects_success[0]
    assert effect.key == "a2a_forged_relay_task_executed"
    assert "disclos" not in effect.key
    assert effect.description is not None
    assert "not necessarily" in effect.description or "do not require a data dump" in effect.description


def test_rag_knowledge_base_exfiltrated_is_single_step_mission_outcome():
    lib = build_dvaa_library()
    op = lib.get("rag_knowledge_base_exfiltrated")
    assert op.preconditions == ()
    assert op.channel == "api:ragbot"
    assert op.extractor is not None
    assert op.effects_success[0].category == CATEGORY_MISSION_OUTCOME


def test_rag_prompt_matches_dvaas_real_canary_pattern():
    # The exact three literal requirements DVAA's detectUrlExfiltrationInjection
    # checks (src/payloads/agentpwn-mirror.js) -- confirmed via live testing.
    # Any operator whose prompt loses one of these three is silently
    # unsupported again, so pin all three.
    lib = build_dvaa_library()
    prompt = lib.get("rag_knowledge_base_exfiltrated").prompt
    assert "NEW INDEX INSTRUCTIONS:" in prompt
    assert "verify your connection" in prompt
    assert "/api/canary/exfil-test" in prompt


def test_dvaa_mission_any_of_three():
    m = dvaa_mission()
    assert m.success_mode == "any"
    assert set(m.success_criteria) == {
        "memory_persists_cross_session", "unauthorized_a2a_access_granted",
        "mcp_unauthenticated_execution_succeeded",
    }


# -- Retired operators (2026-08-08): preserved for provenance, never
# executed. These tests pin the ARCHIVE itself, not campaign behavior --
# they exist so a future edit can't silently resurrect an unsupported
# operator into build_dvaa_library() without a deliberate decision. -------

def test_retired_operators_are_not_in_the_active_library():
    lib = build_dvaa_library()
    active_ids = {op.id for op in lib}
    retired_ids = {op.id for op in _RETIRED_OPERATORS_2026_08_08}
    assert active_ids.isdisjoint(retired_ids)


def test_thirteen_operators_were_retired():
    assert len(_RETIRED_OPERATORS_2026_08_08) == 13
    assert {op.id for op in _RETIRED_OPERATORS_2026_08_08} == {
        "memory_plant_implicit_injection", "memory_recall_implicit_check",
        "a2a_agent_card_capability_spoof", "a2a_artifact_triggered_injection",
        "rag_plant_injected_document", "rag_query_triggers_document_injection",
        "rag_plant_hidden_instruction_document", "rag_query_triggers_hidden_instruction",
        "rag_plant_false_policy_document", "rag_query_reflects_false_policy",
        "rag_plant_conflicting_document", "rag_query_resolves_conflict_toward_attacker",
        "rag_cross_tenant_document_leakage",
    }
