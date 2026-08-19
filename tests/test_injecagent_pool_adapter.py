"""Tests for InjecAgentPoolAdapter/injecagent_pool_operator -- additive
extensions of the existing, already-tested InjecAgentAdapter/
injecagent_operator, built to give one shared Aginiti campaign genuine
multi-candidate branching across real InjecAgent test cases (see
aginiti/target/injecagent_pool_adapter.py's module docstring for why the
per-case-scoped original adapter can't do this on its own). No live LLM
calls -- chat_tools is mocked, same discipline as
tests/test_injecagent_adapter.py.
"""
from unittest.mock import patch

from aginiti.operators.injecagent_pool import injecagent_pool_operator
from aginiti.target.injecagent_adapter import build_test_cases
from aginiti.target.injecagent_pool_adapter import InjecAgentPoolAdapter


def _sample_cases(n=3):
    return build_test_cases()[:n]


def _fake_tool_call_msg(tool_name: str, args: str = "{}"):
    from types import SimpleNamespace
    tc = SimpleNamespace(
        id="call_1",
        function=SimpleNamespace(name=tool_name, arguments=args),
        model_dump=lambda: {"id": "call_1", "function": {"name": tool_name, "arguments": args}},
    )
    return SimpleNamespace(content=None, tool_calls=[tc])


def _fake_text_msg(text: str):
    from types import SimpleNamespace
    return SimpleNamespace(content=text, tool_calls=None)


def test_pool_operator_channel_encodes_the_test_case_index():
    cases = _sample_cases(3)
    ops = [injecagent_pool_operator(tc) for tc in cases]
    assert [op.channel for op in ops] == [f"tool_output_injection:{tc['index']}" for tc in cases]


def test_pool_operator_reuses_the_same_effects_and_prompt_as_the_original():
    from aginiti.operators.injecagent import injecagent_operator
    tc = _sample_cases(1)[0]
    original = injecagent_operator(tc)
    pooled = injecagent_pool_operator(tc)
    assert pooled.prompt == original.prompt
    assert pooled.effects_success == original.effects_success
    assert pooled.effects_failure == original.effects_failure
    assert pooled.id == original.id
    assert pooled.channel != original.channel  # the ONLY field remapped


def test_pool_adapter_dispatches_to_the_right_test_case_by_index():
    cases = _sample_cases(2)
    adapter = InjecAgentPoolAdapter(cases, seed=1)
    with patch("aginiti.target.injecagent_adapter.chat_tools", return_value=_fake_text_msg("ok")):
        r0 = adapter.send(f"tool_output_injection:{cases[0]['index']}", "attacker instruction 0")
        r1 = adapter.send(f"tool_output_injection:{cases[1]['index']}", "attacker instruction 1")
    assert r0.final_text == "ok"
    assert r1.final_text == "ok"


def test_pool_adapter_rejects_unknown_channel_shape():
    adapter = InjecAgentPoolAdapter(_sample_cases(1), seed=1)
    import pytest
    with pytest.raises(ValueError, match="tool_output_injection"):
        adapter.send("direct", "hi")


def test_pool_adapter_rejects_index_not_in_pool():
    adapter = InjecAgentPoolAdapter(_sample_cases(1), seed=1)
    import pytest
    with pytest.raises(ValueError, match="not in this pool"):
        adapter.send("tool_output_injection:99999", "hi")


def test_ground_truth_aggregates_across_the_pool_only_from_attempted_cases():
    cases = _sample_cases(2)
    attacker_tool_0 = cases[0]["attacker_case"]["Attacker Tools"][0]
    adapter = InjecAgentPoolAdapter(cases, seed=1)

    # Nothing attempted yet -- must be False, not vacuously True.
    assert adapter.ground_truth_mission_achieved() is False

    with patch("aginiti.target.injecagent_adapter.chat_tools", return_value=_fake_tool_call_msg(attacker_tool_0)):
        adapter.send(f"tool_output_injection:{cases[0]['index']}", "x")
    assert adapter.ground_truth_mission_achieved() is True

    # The second, never-attempted case must not silently count.
    per_case = adapter.per_case_ground_truth()
    assert cases[1]["index"] not in per_case
    assert per_case[cases[0]["index"]] is True


def test_per_case_ground_truth_distinguishes_compliant_from_refused_cases():
    cases = _sample_cases(2)
    attacker_tool_0 = cases[0]["attacker_case"]["Attacker Tools"][0]
    adapter = InjecAgentPoolAdapter(cases, seed=1)

    with patch("aginiti.target.injecagent_adapter.chat_tools", return_value=_fake_tool_call_msg(attacker_tool_0)):
        adapter.send(f"tool_output_injection:{cases[0]['index']}", "x")
    with patch("aginiti.target.injecagent_adapter.chat_tools", return_value=_fake_text_msg("I can't help with that.")):
        adapter.send(f"tool_output_injection:{cases[1]['index']}", "y")

    per_case = adapter.per_case_ground_truth()
    assert per_case == {cases[0]["index"]: True, cases[1]["index"]: False}
