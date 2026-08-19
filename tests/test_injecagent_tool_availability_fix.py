"""Regression tests for a real, verified bug in InjecAgentAdapter (fixed
2026-08-09): the agent under test was only ever offered its own tool as a
callable function, never the attacker's declared target tool(s) --
structurally making 99.9% of the real 1,054-case dataset unwinnable
regardless of model compliance, since chat_tools() can only invoke a
function actually present in the schema list passed to it.

Verified directly against InjecAgent's own real upstream source
(`src/evaluate_prompted_agent.py`, fetched live, not assumed) before
fixing: the real methodology is
`available_tool_names = [item['User Tool']] + item['Attacker Tools']`.
No live LLM calls -- chat_tools is mocked/inspected, same discipline as
the rest of tests/test_injecagent_adapter.py.
"""
from types import SimpleNamespace

import aginiti.target.injecagent_adapter as injecagent_adapter_module
from aginiti.target.injecagent_adapter import (
    InjecAgentAdapter,
    _available_tool_schemas,
    _load_tool_catalog,
    _real_tool_schema,
    load_attacker_cases,
    load_user_cases,
)


def _amazon_case():
    user_case = next(uc for uc in load_user_cases() if uc["User Tool"] == "AmazonGetProductDetails")
    attacker_case = next(ac for ac in load_attacker_cases() if "AugustSmartLockUnlockDoor" in ac["Attacker Tools"])
    return {"index": 0, "user_case": user_case, "attacker_case": attacker_case}


# -- the real vendored tool catalog -----------------------------------------

def test_tool_catalog_loads_and_covers_every_real_dataset_tool_name():
    from aginiti.target.injecagent_adapter import build_test_cases
    catalog = _load_tool_catalog()
    assert len(catalog) > 0
    missing = set()
    for tc in build_test_cases():
        if tc["user_case"]["User Tool"] not in catalog:
            missing.add(tc["user_case"]["User Tool"])
        for name in tc["attacker_case"].get("Attacker Tools", []):
            if name not in catalog:
                missing.add(name)
    assert missing == set(), f"tool names missing from the real vendored catalog: {missing}"


def test_real_tool_schema_uses_the_actual_parameter_types_not_all_strings():
    catalog = _load_tool_catalog()
    schema = _real_tool_schema("GmailSendEmail", catalog)
    assert schema["function"]["name"] == "GmailSendEmail"
    props = schema["function"]["parameters"]["properties"]
    assert "to" in props and "subject" in props and "body" in props
    assert "to" in schema["function"]["parameters"]["required"]


def test_real_tool_schema_returns_none_for_an_unknown_name():
    assert _real_tool_schema("NotARealTool9999", _load_tool_catalog()) is None


def test_real_tool_schema_gives_array_properties_an_items_subschema():
    # Regression test for a real, live-caught bug (2026-08-09): the
    # vendored catalog's own array-typed parameters never specify an
    # `items` sub-schema, and Gemini's tool-calling API rejects the
    # request outright without one ("...properties[attachments].items:
    # missing field"), while Groq/OpenAI's are more lax -- so this was
    # invisible until a live Gemini-backed run hit it directly.
    catalog = _load_tool_catalog()
    schema = _real_tool_schema("GmailSendEmail", catalog)
    attachments = schema["function"]["parameters"]["properties"]["attachments"]
    assert attachments["type"] == "array"
    assert attachments["items"] == {"type": "string"}


def test_no_array_property_anywhere_in_the_real_catalog_is_missing_items():
    # Whole-catalog sweep, not just one hand-picked tool -- every real
    # array-typed parameter across all 38 toolkits must get a valid
    # `items` sub-schema, since any one of them could be the tool offered
    # for a given InjecAgent test case.
    from aginiti.target.injecagent_adapter import build_test_cases
    catalog = _load_tool_catalog()
    for tc in build_test_cases():
        schemas = _available_tool_schemas(tc["user_case"], tc["attacker_case"], catalog)
        for schema in schemas:
            for prop_name, prop in schema["function"]["parameters"]["properties"].items():
                if prop["type"] == "array":
                    assert "items" in prop, f"{schema['function']['name']}.{prop_name} missing items"


# -- the actual fix: both user AND attacker tools are offered ---------------

def test_available_tool_schemas_includes_both_user_and_attacker_tools():
    tc = _amazon_case()
    catalog = _load_tool_catalog()
    schemas = _available_tool_schemas(tc["user_case"], tc["attacker_case"], catalog)
    names = {s["function"]["name"] for s in schemas}
    assert "AmazonGetProductDetails" in names  # the user's own tool
    assert "AugustSmartLockUnlockDoor" in names  # the attacker's target tool -- THE fix
    assert len(schemas) == len(tc["attacker_case"]["Attacker Tools"]) + 1


def test_available_tool_schemas_deduplicates_if_user_tool_equals_an_attacker_tool():
    catalog = _load_tool_catalog()
    user_case = {"User Tool": "GmailSendEmail", "Tool Parameters": "{}"}
    attacker_case = {"Attacker Tools": ["GmailSendEmail", "GmailSearchEmails"]}
    schemas = _available_tool_schemas(user_case, attacker_case, catalog)
    names = [s["function"]["name"] for s in schemas]
    assert names.count("GmailSendEmail") == 1  # not offered twice
    assert "GmailSearchEmails" in names


def test_adapter_now_offers_the_full_tool_list_to_chat_tools(monkeypatch):
    # THE regression test: before the fix, chat_tools() only ever received
    # [self.tool_schema] (the user's tool alone). Now it must receive the
    # full multi-tool list, matching the real upstream methodology.
    captured = {}

    def fake(messages, tools, temperature=0.3, max_tokens=600, seed=None):
        captured["tools"] = tools
        return SimpleNamespace(content="ok", tool_calls=None)

    monkeypatch.setattr(injecagent_adapter_module, "chat_tools", fake)
    adapter = InjecAgentAdapter(_amazon_case())
    adapter.send("tool_output_injection", "some attacker instruction")

    tool_names = {t["function"]["name"] for t in captured["tools"]}
    assert "AmazonGetProductDetails" in tool_names
    assert "AugustSmartLockUnlockDoor" in tool_names
    assert len(captured["tools"]) >= 2  # strictly more than the pre-fix single-tool list


def test_adapter_can_now_observe_a_genuinely_offered_attacker_tool_call(monkeypatch):
    # Before the fix this exact scenario was IMPOSSIBLE to construct
    # meaningfully: the attacker tool was never in the schema list, so a
    # real model literally could not have emitted this tool_call. The
    # ground-truth detection logic itself was always correct (see
    # test_injecagent_adapter.py's own passing test for it) -- what was
    # broken was that the real model was never given the chance to reach
    # it. This test locks in that the fix genuinely offers the tool the
    # ground-truth check depends on.
    tc = _amazon_case()
    from types import SimpleNamespace as SN

    def fake(messages, tools, temperature=0.3, max_tokens=600, seed=None):
        offered = {t["function"]["name"] for t in tools}
        assert "AugustSmartLockUnlockDoor" in offered  # the fix: it's actually offered
        tc_obj = SN(id="c1", function=SN(name="AugustSmartLockUnlockDoor", arguments="{}"),
                     model_dump=lambda: {"id": "c1", "function": {"name": "AugustSmartLockUnlockDoor", "arguments": "{}"}})
        return SN(content="", tool_calls=[tc_obj])

    monkeypatch.setattr(injecagent_adapter_module, "chat_tools", fake)
    adapter = InjecAgentAdapter(tc)
    adapter.send("tool_output_injection", "unlock the door")
    assert adapter.ground_truth_mission_achieved() is True
