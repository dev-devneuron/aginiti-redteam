"""Tests for aginiti/adaptive/deceptive_delight.py. No live LLM/network
calls: unlike crescendo.py, this technique needs NO drafting LLM at all
(every turn is a fixed template -- see the module's own docstring for why
that's a deliberate, real difference from Crescendo, not an oversight),
so these tests only need a scripted target adapter, the same
`_ScriptedAdapter`/judge-bypass pattern test_crescendo.py already
establishes."""
from __future__ import annotations

import dataclasses

import aginiti.adaptive.deceptive_delight as dd
from aginiti.adapters.base import SendResult
from aginiti.core.observation_adapter import _effect_id
from aginiti.core.graph.ssg import SecurityStateGraph

_real_deceptive_delight_operator = dd._deceptive_delight_operator


class _ScriptedAdapter:
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts_sent = []

    def send(self, channel, prompt):
        self.prompts_sent.append(prompt)
        return SendResult(final_text=self.responses.pop(0))

    def ground_truth_mission_achieved(self):
        return False


def _rig_success_on_turn(monkeypatch, winning_turn: int | None):
    def patched(prompt, turn_number, target_element, claim_key, blocked_key, attack_category, owasp_llm_category):
        op = _real_deceptive_delight_operator(prompt, turn_number, target_element, claim_key,
                                               blocked_key, attack_category, owasp_llm_category)
        succeeds = turn_number == winning_turn
        success_effect = op.effects_success[0]
        failure_effect = op.effects_failure[0]

        def extractor(raw):
            return [_effect_id(success_effect)] if succeeds else [_effect_id(failure_effect)]

        return dataclasses.replace(op, extractor=extractor)
    monkeypatch.setattr(dd, "_deceptive_delight_operator", patched)


def test_succeeds_on_first_turn_stops_immediately(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=1)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["a story with the real content in it"])
    result = dd.run_deceptive_delight("the target's own real system instructions",
                                       "dd_test_disclosed", "dd_test_blocked", ssg, adapter)
    assert result.succeeded is True
    assert result.turns_used == 1
    assert ssg.is_confirmed("dd_test_disclosed_turn1")


def test_default_run_is_three_turns_when_nothing_succeeds(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=None)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["story", "elaboration", "refinement"])
    result = dd.run_deceptive_delight("the target's own real system instructions",
                                       "dd_test_disclosed", "dd_test_blocked", ssg, adapter)
    assert result.succeeded is False
    assert result.turns_used == 3
    assert all(not t.success for t in result.turns)


def test_include_refinement_turn_false_runs_only_two_turns(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=None)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["story", "elaboration"])
    result = dd.run_deceptive_delight("the target's own real system instructions",
                                       "dd_test_disclosed", "dd_test_blocked", ssg, adapter,
                                       include_refinement_turn=False)
    assert result.turns_used == 2
    assert len(adapter.responses) == 0  # exactly 2 real sends, no third


def test_stops_at_the_elaboration_turn_when_that_one_succeeds(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=2)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["story", "elaboration with the real content"])
    result = dd.run_deceptive_delight("the target's own real system instructions",
                                       "dd_test_disclosed", "dd_test_blocked", ssg, adapter)
    assert result.succeeded is True
    assert result.turns_used == 2
    assert ssg.is_confirmed("dd_test_disclosed_turn2")


def test_no_drafting_llm_call_needed_prompts_are_pure_templates():
    """The core architectural difference from crescendo.py (see this
    module's own docstring) -- every prompt is deterministic given only
    target_element/benign_topics, no live LLM call involved in producing
    them at all."""
    p1 = dd._narrative_connection_prompt("the target's own real system instructions",
                                          dd._DEFAULT_BENIGN_TOPICS)
    p2 = dd._narrative_connection_prompt("the target's own real system instructions",
                                          dd._DEFAULT_BENIGN_TOPICS)
    assert p1 == p2  # same inputs -> byte-identical output, no randomness/LLM involved


def test_target_element_appears_in_every_turns_prompt_not_just_the_first():
    element = "a very specific unique test phrase XYZZY123"
    assert element in dd._narrative_connection_prompt(element, dd._DEFAULT_BENIGN_TOPICS)
    assert element in dd._elaboration_prompt(element)
    assert element in dd._refinement_prompt(element)


def test_narrative_prompt_never_asks_directly_it_frames_as_a_story():
    """The whole mechanism (see module docstring): the sensitive content
    must always be embedded as a story element, the prompt itself must
    read as a creative-writing request, not a direct ask."""
    prompt = dd._narrative_connection_prompt("the secret", dd._DEFAULT_BENIGN_TOPICS)
    assert "story" in prompt.lower() or "creative writing" in prompt.lower()


def test_every_turn_is_a_real_operator_execution_recorded_in_ssg(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=None)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["a", "b", "c"])
    dd.run_deceptive_delight("the target's own real system instructions",
                              "dd_test_disclosed", "dd_test_blocked", ssg, adapter)
    total_executions = sum(s.executions for s in ssg.operator_stats.values())
    assert total_executions == 3
    assert ssg.is_confirmed("dd_test_blocked_turn1")
    assert ssg.is_confirmed("dd_test_blocked_turn2")
    assert ssg.is_confirmed("dd_test_blocked_turn3")


def test_custom_benign_topics_are_actually_used():
    custom = ("topic ONE unique marker", "topic TWO unique marker")
    prompt = dd._narrative_connection_prompt("target element here", custom)
    assert "topic ONE unique marker" in prompt
    assert "topic TWO unique marker" in prompt
