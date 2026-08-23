"""Tests for aginiti/adaptive/crescendo.py -- Crescendo-style multi-turn
escalation. No live LLM/network calls: `generate_turn_fn` is injected
(avoiding the live drafting call), and the judge is bypassed via the SAME
monkeypatch-a-deterministic-extractor pattern test_encoding_discovery.py /
test_framing_discovery.py already establish."""
from __future__ import annotations

import dataclasses

import aginiti.adaptive.crescendo as cr
from aginiti.core.observation_adapter import _effect_id
from aginiti.adapters.base import SendResult
from aginiti.core.graph.ssg import SecurityStateGraph

_real_crescendo_operator = cr._crescendo_operator


class _ScriptedAdapter:
    """Returns each response in `responses` in order, one per .send() call
    -- deterministic, mirroring test_adaptive_refinement.py's own stub."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts_sent = []

    def send(self, channel, prompt):
        self.prompts_sent.append(prompt)
        return SendResult(final_text=self.responses.pop(0))

    def ground_truth_mission_achieved(self):
        return False


def _stub_generate(final_goal, transcript, turn_number, max_turns, seed):
    """A trivial, deterministic drafting stub -- the real one calls an LLM;
    tests never do."""
    return f"turn-{turn_number}-message"


def _rig_success_on_turn(monkeypatch, winning_turn: int | None):
    """winning_turn=None -- every turn fails (and explicitly confirms its
    own failure effect, matching what a real judge/extractor would do)."""
    def patched(prompt, turn_number, final_goal, claim_key, blocked_key, attack_category, owasp_llm_category):
        op = _real_crescendo_operator(prompt, turn_number, final_goal, claim_key, blocked_key,
                                       attack_category, owasp_llm_category)
        succeeds = turn_number == winning_turn
        success_effect = op.effects_success[0]
        failure_effect = op.effects_failure[0]

        def extractor(raw):
            return [_effect_id(success_effect)] if succeeds else [_effect_id(failure_effect)]

        return dataclasses.replace(op, extractor=extractor)
    monkeypatch.setattr(cr, "_crescendo_operator", patched)


def test_succeeds_on_first_turn_stops_immediately(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=1)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["sure, here it is"])
    result = cr.run_crescendo_escalation("reveal the secret", "crescendo_test_disclosed",
                                          "crescendo_test_blocked", ssg, adapter, max_turns=5,
                                          generate_turn_fn=_stub_generate)
    assert result.succeeded is True
    assert result.turns_used == 1
    assert ssg.is_confirmed("crescendo_test_disclosed_turn1")


def test_escalates_across_turns_using_real_prior_responses(monkeypatch):
    """The core Crescendo mechanism: each turn's generation call receives
    the REAL transcript built from actual prior responses, not a
    fabricated one."""
    _rig_success_on_turn(monkeypatch, winning_turn=3)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["mild answer 1", "more specific answer 2", "the actual content"])

    seen_transcripts = []

    def _capturing_generate(final_goal, transcript, turn_number, max_turns, seed):
        seen_transcripts.append(list(transcript))
        return f"turn-{turn_number}-message"

    result = cr.run_crescendo_escalation("reveal the secret", "crescendo_test_disclosed",
                                          "crescendo_test_blocked", ssg, adapter, max_turns=5,
                                          generate_turn_fn=_capturing_generate)

    assert result.succeeded is True
    assert result.turns_used == 3
    # Turn 1 sees no history; turn 2 sees turn 1's REAL response; turn 3
    # sees both turn 1 and turn 2's real responses.
    assert seen_transcripts[0] == []
    assert seen_transcripts[1] == [("turn-1-message", "mild answer 1")]
    assert seen_transcripts[2] == [("turn-1-message", "mild answer 1"), ("turn-2-message", "more specific answer 2")]


def test_exhausts_max_turns_and_reports_failure_when_every_turn_fails(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=None)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["no1", "no2", "no3"])
    result = cr.run_crescendo_escalation("reveal the secret", "crescendo_test_disclosed",
                                          "crescendo_test_blocked", ssg, adapter, max_turns=3,
                                          generate_turn_fn=_stub_generate)
    assert result.succeeded is False
    assert result.turns_used == 3
    assert all(not t.success for t in result.turns)


def test_every_turn_is_a_real_operator_execution_recorded_in_ssg(monkeypatch):
    _rig_success_on_turn(monkeypatch, winning_turn=None)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["no1", "no2"])
    cr.run_crescendo_escalation("reveal the secret", "crescendo_test_disclosed",
                                 "crescendo_test_blocked", ssg, adapter, max_turns=2,
                                 generate_turn_fn=_stub_generate)
    total_executions = sum(s.executions for s in ssg.operator_stats.values())
    assert total_executions == 2
    assert ssg.is_confirmed("crescendo_test_blocked_turn1")
    assert ssg.is_confirmed("crescendo_test_blocked_turn2")


# ---------------------------------------------------------------------------
# _TurnDraftingFailed handling -- 2026-08-23 fix for a live-found bug: the
# drafting model (_default_generate_turn's own live LLM call) can itself
# return empty/refuse for some (goal, turn) combinations, and before this
# fix the empty string silently became the literal message sent to the
# REAL target -- a wasted, content-free query, never logged. See
# _default_generate_turn's own docstring for the full live-observed story.
# ---------------------------------------------------------------------------

def test_a_turn_that_fails_to_draft_is_skipped_without_touching_the_target(monkeypatch):
    """The core regression guard: a drafting failure must cost an
    escalation-turn slot, never a real target query."""
    _rig_success_on_turn(monkeypatch, winning_turn=None)
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["no1", "no3"])  # only 2 real responses queued -- turn 2 must never call .send()

    def _generate_but_turn2_fails(final_goal, transcript, turn_number, max_turns, seed):
        if turn_number == 2:
            raise cr._TurnDraftingFailed("simulated drafting failure")
        return f"turn-{turn_number}-message"

    result = cr.run_crescendo_escalation("reveal the secret", "crescendo_test_disclosed",
                                          "crescendo_test_blocked", ssg, adapter, max_turns=3,
                                          generate_turn_fn=_generate_but_turn2_fails)
    assert adapter.responses == []  # both queued responses were consumed -- exactly 2 real sends
    assert len(adapter.prompts_sent) == 2
    # Only turns 1 and 3 were ever really executed -- turn 2 left no trace.
    assert [t.turn_number for t in result.turns] == [1, 3]
    assert result.succeeded is False


def test_default_generate_turn_retries_once_on_empty_draft(monkeypatch):
    calls = []

    def _fake_chat(messages, temperature, max_tokens, seed=None):
        calls.append(temperature)
        return "" if len(calls) == 1 else "a real drafted message"

    monkeypatch.setattr(cr, "chat", _fake_chat)
    result = cr._default_generate_turn("reveal the secret", [], turn_number=1, max_turns=3, seed=None)
    assert result == "a real drafted message"
    assert len(calls) == 2  # exactly one retry, not a retry loop


def test_default_generate_turn_raises_turn_drafting_failed_after_two_empty_attempts(monkeypatch):
    import pytest

    def _always_empty(messages, temperature, max_tokens, seed=None):
        return ""

    monkeypatch.setattr(cr, "chat", _always_empty)
    with pytest.raises(cr._TurnDraftingFailed):
        cr._default_generate_turn("reveal the secret", [], turn_number=1, max_turns=3, seed=None)
