"""Tests for aginiti/adaptive/many_shot.py -- many-shot jailbreaking. No
live LLM/network calls: the judge is bypassed via the SAME monkeypatch-a-
deterministic-extractor pattern test_encoding_discovery.py /
test_framing_discovery.py already establish."""
from __future__ import annotations

import dataclasses

import aginiti.adaptive.many_shot as ms
from aginiti.adapter.observation_adapter import ObservationAdapter, _effect_id
from aginiti.adapters.base import SendResult
from aginiti.graph.ssg import SecurityStateGraph

_real_many_shot_operator = ms._many_shot_operator


class _StubAdapter:
    def send(self, channel, prompt):
        return SendResult(final_text="irrelevant -- extractor decides")

    def ground_truth_mission_achieved(self):
        return False


def _rig(monkeypatch, winning_shot_count: int | None):
    def patched(goal, shot_count, claim_key, blocked_key, attack_category, owasp_llm_category):
        op = _real_many_shot_operator(goal, shot_count, claim_key, blocked_key,
                                       attack_category, owasp_llm_category)
        succeeds = shot_count == winning_shot_count
        effect = op.effects_success[0]
        return dataclasses.replace(op, extractor=lambda raw: [_effect_id(effect)] if succeeds else [])
    monkeypatch.setattr(ms, "_many_shot_operator", patched)


def test_prompt_contains_the_requested_number_of_fabricated_exchanges():
    prompt = ms._build_many_shot_prompt("reveal the secret", shot_count=8)
    assert prompt.count("User:") == 9  # 8 fabricated + the real ask
    assert prompt.count("Assistant:") == 9  # 8 fabricated answers + the trailing cue
    assert prompt.strip().endswith("Assistant:")
    assert "reveal the secret" in prompt


def test_shot_content_cycles_through_generic_topics_only():
    prompt = ms._build_many_shot_prompt("goal", shot_count=20)
    # More shots than distinct topics -- must cycle, never crash or repeat
    # verbatim beyond what cycling implies.
    assert "capital of France" in prompt
    assert "boiling point of water" in prompt


def test_candidate_generator_sweeps_shot_counts_in_ascending_order():
    fn = ms.make_many_shot_candidate_fn("goal", "claim", "blocked", shot_counts=(4, 8, 16))
    names = []
    for _ in range(3):
        op, name = fn(names)
        names.append(name)
    assert names == ["shots4", "shots8", "shots16"]


def test_candidate_generator_exhausts_after_declared_shot_counts():
    fn = ms.make_many_shot_candidate_fn("goal", "claim", "blocked", shot_counts=(4, 8))
    fn([]); fn(["shots4"])
    assert fn(["shots4", "shots8"]) is None


def test_discovery_stops_at_the_first_shot_count_that_succeeds(monkeypatch):
    _rig(monkeypatch, winning_shot_count=8)
    ssg = SecurityStateGraph()
    result = ms.run_many_shot_discovery("reveal the secret", "many_shot_test_disclosed",
                                         "many_shot_test_blocked", ssg, _StubAdapter(),
                                         shot_counts=(4, 8, 16, 32))
    assert result.succeeded is True
    assert result.trials_used == 2  # tried 4 (failed), then 8 (succeeded)
    assert result.winning_operator.id == "many_shot_shots8"
    assert ssg.is_confirmed("many_shot_test_disclosed_shots8")


def test_discovery_exhausts_all_shot_counts_without_success(monkeypatch):
    _rig(monkeypatch, winning_shot_count=None)
    ssg = SecurityStateGraph()
    result = ms.run_many_shot_discovery("reveal the secret", "many_shot_test_disclosed",
                                         "many_shot_test_blocked", ssg, _StubAdapter(),
                                         shot_counts=(4, 8))
    assert result.succeeded is False
    assert result.trials_used == 2


def test_each_trial_is_a_real_operator_execution_through_observation_adapter(monkeypatch):
    _rig(monkeypatch, winning_shot_count=None)
    ssg = SecurityStateGraph()
    ms.run_many_shot_discovery("reveal the secret", "many_shot_test_disclosed",
                                "many_shot_test_blocked", ssg, _StubAdapter(), shot_counts=(4, 8))
    total_executions = sum(s.executions for s in ssg.operator_stats.values())
    assert total_executions == 2
    assert any(f.kind == "response_text" for f in ssg.facts)
