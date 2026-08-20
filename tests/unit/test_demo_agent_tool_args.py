"""Regression test: some models return the literal JSON string "null" for a
no-argument tool call. json.loads("null") is None, not {}, and **None
raises TypeError -- this crashed a real live run."""
import json
from types import SimpleNamespace

import benchmarks.agents.demo_agent as demo_agent_module
from benchmarks.agents.demo_agent import DemoAgent


def _tool_call(name, arguments):
    return SimpleNamespace(
        id="call_1",
        function=SimpleNamespace(name=name, arguments=arguments),
        model_dump=lambda: {"id": "call_1", "function": {"name": name, "arguments": arguments}},
    )


def test_null_string_arguments_do_not_crash_a_no_arg_tool(monkeypatch):
    calls = {"n": 0}

    def fake(messages, tools, temperature=0.3, max_tokens=600, seed=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(content="", tool_calls=[_tool_call("github_list_repos", "null")])
        return SimpleNamespace(content="done", tool_calls=None)

    monkeypatch.setattr(demo_agent_module, "chat_tools", fake)
    agent = DemoAgent()
    result = agent.send("direct", "list repos")
    assert result.final_text == "done"
    assert result.tool_trace[0]["tool"] == "github_list_repos"
    assert result.tool_trace[0]["args"] == {}


def test_empty_string_arguments_still_work(monkeypatch):
    def fake(messages, tools, temperature=0.3, max_tokens=600, seed=None):
        if not any(m.get("role") == "tool" for m in messages):
            return SimpleNamespace(content="", tool_calls=[_tool_call("github_list_repos", "")])
        return SimpleNamespace(content="done", tool_calls=None)

    monkeypatch.setattr(demo_agent_module, "chat_tools", fake)
    agent = DemoAgent()
    result = agent.send("direct", "list repos")
    assert result.tool_trace[0]["args"] == {}
