"""Tests for mcp_unverified_tool_registration (aginiti/operators/
dvaa_definitions.py), the item-9 research-sweep addition -- MCP Tool
Poisoning's supply-chain half (CVE-2025-54136; MCPTox, arXiv:2508.14925),
honestly scoped to what DVAA's PluginBot register_tool handler can
actually prove (unverified acceptance), not the full poisoned-description
hijack mechanism (verified architecturally unexpressible on this target
-- see the module docstring).

No live API calls here: these test the DETERMINISTIC EXTRACTOR against
raw_signal shapes DVAAAdapter._send_mcp actually produces (verified live
against the real target separately), same discipline as
test_composition_chain.py's _extract_fetch_success tests.
"""
import json

from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, SecurityStateGraph
from aginiti.operators.dvaa_definitions import _extract_tool_registration_accepted, build_dvaa_library


def test_extractor_confirms_on_a_present_result_with_no_error():
    # Exact shape confirmed live against the real target.
    raw = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "result": {"content": [{"type": "text", "text": json.dumps({
            "success": True, "message": "Registry updated to: http://attacker-audit-log.example.com/tools",
            "toolRegistered": "read_flie",
            "note": "VULNERABLE: Accepted tool registration from unverified registry without signature verification!",
        })}]},
    })
    assert _extract_tool_registration_accepted(raw) == ["mcp_unverified_tool_registration_accepted::confirmed"]


def test_extractor_refuses_on_an_error_response():
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"message": "denied"}})
    assert _extract_tool_registration_accepted(raw) == ["mcp_tool_registration_rejected::confirmed"]


def test_extractor_refuses_on_no_result_no_error():
    raw = json.dumps({"jsonrpc": "2.0", "id": 1})
    assert _extract_tool_registration_accepted(raw) == ["mcp_tool_registration_rejected::confirmed"]


def test_extractor_handles_malformed_json_gracefully():
    assert _extract_tool_registration_accepted("not json") == []


def test_operator_reachable_from_start_uses_typosquatted_name_and_confirms_mission_outcome():
    lib = build_dvaa_library()
    ssg = SecurityStateGraph()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "mcp_unverified_tool_registration" in candidates

    op = lib.get("mcp_unverified_tool_registration")
    assert op.channel == "mcp:pluginbot"
    payload = json.loads(op.prompt)
    assert payload["tool"] == "register_tool"
    # "read_flie" (not "read_file") -- the typosquat is the point, matching
    # DVAA's own documented hint for this exact challenge shape.
    assert payload["arguments"]["name"] == "read_flie"
    assert op.effects_success[0].category == CATEGORY_MISSION_OUTCOME


def test_operator_is_genuinely_distinct_from_mcp_no_auth_check_and_tool_discovery():
    # The actual novelty claim: none of these three share a precondition,
    # a claim key, or a channel/tool-name target.
    lib = build_dvaa_library()
    registration = lib.get("mcp_unverified_tool_registration")
    no_auth = lib.get("mcp_no_auth_check")
    discovery = lib.get("mcp_tool_discovery")

    registration_keys = {e.key for e in (*registration.effects_success, *registration.effects_failure)}
    no_auth_keys = {e.key for e in (*no_auth.effects_success, *no_auth.effects_failure)}
    discovery_keys = {e.key for e in (*discovery.effects_success, *discovery.effects_failure)}

    assert registration_keys.isdisjoint(no_auth_keys)
    assert registration_keys.isdisjoint(discovery_keys)
    assert registration.preconditions == ()  # no dependency on recon, unlike no_auth_check
