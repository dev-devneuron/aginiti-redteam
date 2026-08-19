"""Offline tests for aginiti/gemini_client.py's message/tool conversion --
no live API calls. Mirrors test_llm_client.py's discipline: this module's
job is translating between Aginiti's OpenAI-shaped message/tool
conventions and the Gemini SDK's native shapes, and that translation is
exactly what can silently corrupt a live experiment if it's wrong (see the
module's own comments for two real bugs found live: automatic-function-
calling silently swallowing responses, and default "thinking" intermittently
consuming the entire output budget -- both fixed, neither obviously
testable offline, but the conversion logic that surrounds them is).
"""
import json

from aginiti import gemini_client


def test_to_contents_first_system_message_becomes_system_instruction():
    messages = [{"role": "system", "content": "You are a helpful bot."}]
    system_instruction, contents = gemini_client._to_contents(messages)
    assert system_instruction == "You are a helpful bot."
    assert contents == []


def test_to_contents_later_system_message_becomes_tagged_user_note():
    messages = [
        {"role": "system", "content": "Base prompt."},
        {"role": "user", "content": "hi"},
        {"role": "system", "content": "Suspicion escalated."},
    ]
    _, contents = gemini_client._to_contents(messages)
    assert len(contents) == 2
    assert contents[1].role == "user"
    assert "[SYSTEM NOTE] Suspicion escalated." in contents[1].parts[0].text


def test_to_contents_user_and_assistant_roles_map_correctly():
    messages = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi there"},
    ]
    _, contents = gemini_client._to_contents(messages)
    assert contents[0].role == "user"
    assert contents[0].parts[0].text == "hello"
    assert contents[1].role == "model"
    assert contents[1].parts[0].text == "hi there"


def test_to_contents_assistant_tool_calls_become_function_call_parts():
    messages = [{
        "role": "assistant", "content": "",
        "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "lookup", "arguments": '{"id": "42"}'}}],
    }]
    _, contents = gemini_client._to_contents(messages)
    assert contents[0].role == "model"
    part = contents[0].parts[0]
    assert part.function_call.name == "lookup"
    assert dict(part.function_call.args) == {"id": "42"}


def test_to_contents_tool_result_becomes_function_response_part():
    messages = [
        {"role": "user", "content": "look it up"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "call_1", "name": "lookup", "content": json.dumps({"result": "ok"})},
    ]
    _, contents = gemini_client._to_contents(messages)
    tool_result_content = contents[-1]
    assert tool_result_content.role == "user"
    fr = tool_result_content.parts[0].function_response
    assert fr.name == "lookup"
    assert fr.response == {"result": "ok"}


def test_to_contents_multiple_consecutive_tool_results_grouped_into_one_turn():
    messages = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "a", "arguments": "{}"}},
            {"id": "2", "type": "function", "function": {"name": "b", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "1", "name": "a", "content": "{}"},
        {"role": "tool", "tool_call_id": "2", "name": "b", "content": "{}"},
    ]
    _, contents = gemini_client._to_contents(messages)
    # Both tool results should collapse into the SAME trailing user-role turn.
    assert contents[-1].role == "user"
    assert len(contents[-1].parts) == 2


def test_to_gemini_tools_converts_openai_shaped_schema():
    tools = [{
        "type": "function",
        "function": {"name": "lookup", "description": "look something up",
                     "parameters": {"type": "object", "properties": {"id": {"type": "string"}}}},
    }]
    gemini_tool = gemini_client._to_gemini_tools(tools)
    assert len(gemini_tool.function_declarations) == 1
    decl = gemini_tool.function_declarations[0]
    assert decl.name == "lookup"
    assert decl.description == "look something up"


def test_tool_call_shim_model_dump_matches_groq_shape():
    shim = gemini_client._ToolCallShim("lookup", {"id": "42"})
    dumped = shim.model_dump()
    assert dumped["function"]["name"] == "lookup"
    assert json.loads(dumped["function"]["arguments"]) == {"id": "42"}
    assert dumped["id"] == shim.id
    assert shim.function.arguments == json.dumps({"id": "42"})


def test_message_shim_reports_no_tool_calls_as_none():
    shim = gemini_client._MessageShim("just text", None)
    assert shim.content == "just text"
    assert shim.tool_calls is None


def test_message_shim_empty_tool_call_list_normalizes_to_none():
    shim = gemini_client._MessageShim(None, [])
    assert shim.tool_calls is None
