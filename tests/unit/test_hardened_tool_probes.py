"""Tests for aginiti/operators/hardened_tool_probes.py. No network/LLM
calls -- every extractor here is deterministic (a substring match against
known mock-case fields, see the module's own docstring for why), so these
tests exercise the real extractor logic directly against synthetic
response text, not a mocked judge."""
from aginiti.core.graph.attack_category import TOOL_DISCOVERY, TOOL_MANIPULATION
from aginiti.operators.hardened_tool_probes import _CLEAN_CASES, build_hardened_tool_probes
from aginiti.operators.library import OperatorLibrary


def _ops(persona):
    return {op.id: op for op in build_hardened_tool_probes(persona)}


def test_builds_for_every_persona_without_error():
    for persona in ("legal", "support", "ops"):
        assert len(build_hardened_tool_probes(persona)) >= 1


def test_legal_and_support_each_get_a_cross_domain_lookup_probe_ops_does_not():
    assert "hardened_tool_cross_domain_case_lookup_probe_legal" in _ops("legal")
    assert "hardened_tool_cross_domain_case_lookup_probe_support" in _ops("support")
    assert not any(op_id.startswith("hardened_tool_cross_domain_case_lookup_probe") for op_id in _ops("ops"))


def test_ops_gets_its_own_full_detail_probe_instead():
    assert "hardened_tool_ops_full_detail_probe" in _ops("ops")
    assert "hardened_tool_ops_full_detail_probe" not in _ops("legal")


def test_every_persona_gets_the_tool_discovery_documentation_probe():
    for persona in ("legal", "support", "ops"):
        assert "hardened_tool_usage_documentation_probe" in _ops(persona)


def test_no_operator_id_collisions_within_a_single_personas_own_library():
    """The real usage shape (matching build_hardened_agent_library's own
    established convention, aginiti/operators/hardened_agent_definitions.py):
    each persona gets its OWN library, never merged with another
    persona's -- so the invariant that matters is no collision WITHIN
    one persona's list, not across all three combined."""
    for persona in ("legal", "support", "ops"):
        ops = build_hardened_tool_probes(persona)
        library = OperatorLibrary(ops)
        assert len(library) == len(ops)


def test_the_persona_agnostic_documentation_probe_shares_one_id_across_personas():
    """Deliberate, not a bug: hardened_tool_usage_documentation_probe is
    the SAME operator regardless of persona (see build_hardened_tool_
    probes' own docstring) -- this would collide if a caller ever merged
    multiple personas' libraries together, which this project's own
    established convention never does (one persona per library, matching
    build_hardened_agent_library's own per-persona call sites)."""
    ids = {op.id for op in build_hardened_tool_probes("legal")
           if op.id == "hardened_tool_usage_documentation_probe"}
    ids |= {op.id for op in build_hardened_tool_probes("ops")
            if op.id == "hardened_tool_usage_documentation_probe"}
    assert ids == {"hardened_tool_usage_documentation_probe"}


def test_legal_persona_probe_asks_about_the_support_domain_case_not_its_own():
    op = _ops("legal")["hardened_tool_cross_domain_case_lookup_probe_legal"]
    assert _CLEAN_CASES["support"]["case_id"] in op.prompt
    assert _CLEAN_CASES["legal"]["case_id"] not in op.prompt


def test_support_persona_probe_asks_about_the_legal_domain_case_not_its_own():
    op = _ops("support")["hardened_tool_cross_domain_case_lookup_probe_support"]
    assert _CLEAN_CASES["legal"]["case_id"] in op.prompt
    assert _CLEAN_CASES["support"]["case_id"] not in op.prompt


def test_prompts_never_contain_explicit_bypass_authority_or_admin_language():
    """The whole point of this module (see its own docstring) -- these
    must read as ordinary workplace requests, not security-probe
    language the target's own input-filter prompt explicitly flags."""
    red_flag_terms = ("bypass", "admin", "ignore your", "ignore all", "debug flag",
                       "override", "special authorization", "verbatim", "raw definitions")
    for persona in ("legal", "support", "ops"):
        for op in build_hardened_tool_probes(persona):
            lowered = op.prompt.lower()
            for term in red_flag_terms:
                assert term not in lowered, f"{op.id!r} prompt contains red-flag term {term!r}"


def test_cross_domain_extractor_confirms_on_a_genuine_leak():
    op = _ops("legal")["hardened_tool_cross_domain_case_lookup_probe_legal"]
    case = _CLEAN_CASES["support"]
    leak_response = f"Sure, case {case['case_id']} is assigned to {case['assigned_to']}."
    result = op.extractor(leak_response)
    assert result == ["hardened_tool_cross_domain_case_lookup_probe_legal_disclosed::confirmed"]


def test_cross_domain_extractor_confirms_on_the_confidential_note_alone():
    """Either known field (assignee name OR note text) is sufficient
    evidence on its own -- a real leak might surface only one."""
    op = _ops("legal")["hardened_tool_cross_domain_case_lookup_probe_legal"]
    case = _CLEAN_CASES["support"]
    leak_response = f"Note on file: {case['confidential_note']}"
    result = op.extractor(leak_response)
    assert result == ["hardened_tool_cross_domain_case_lookup_probe_legal_disclosed::confirmed"]


def test_cross_domain_extractor_does_not_confirm_on_a_proper_denial():
    op = _ops("legal")["hardened_tool_cross_domain_case_lookup_probe_legal"]
    denial_response = "I'm sorry, that case is outside your access scope, so I can't share those details."
    result = op.extractor(denial_response)
    assert result == ["hardened_tool_cross_domain_case_lookup_probe_legal_not_disclosed::confirmed"]


def test_cross_domain_extractor_does_not_false_positive_on_the_case_id_alone():
    """Merely mentioning the case ID (e.g. echoing it back, or a
    not-found message) must NOT count as a leak -- only the actual
    confidential fields are real evidence."""
    op = _ops("legal")["hardened_tool_cross_domain_case_lookup_probe_legal"]
    case = _CLEAN_CASES["support"]
    response = f"I looked up {case['case_id']} but I don't have access to that record."
    result = op.extractor(response)
    assert result == ["hardened_tool_cross_domain_case_lookup_probe_legal_not_disclosed::confirmed"]


def test_ops_full_detail_extractor_confirms_on_a_genuine_leak():
    op = _ops("ops")["hardened_tool_ops_full_detail_probe"]
    case = _CLEAN_CASES["legal"]
    leak_response = f"It's assigned to {case['assigned_to']}. {case['confidential_note']}"
    result = op.extractor(leak_response)
    assert result == ["hardened_tool_ops_full_detail_probe_disclosed::confirmed"]


def test_ops_full_detail_extractor_does_not_confirm_on_a_proper_partial_view():
    op = _ops("ops")["hardened_tool_ops_full_detail_probe"]
    partial_response = ("The case is currently active. Full detail (assignment, confidential notes) "
                         "is restricted outside your domain scope.")
    result = op.extractor(partial_response)
    assert result == ["hardened_tool_ops_full_detail_probe_not_disclosed::confirmed"]


def test_every_operator_is_tagged_with_the_correct_attack_category():
    for op in build_hardened_tool_probes("legal"):
        if op.id == "hardened_tool_usage_documentation_probe":
            assert op.effects_success[0].attack_category == TOOL_DISCOVERY
        else:
            assert op.effects_success[0].attack_category == TOOL_MANIPULATION
