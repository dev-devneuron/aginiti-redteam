"""Tests for the AnythingLLM RAG document-poisoning operator pack
(aginiti/operators/anythingllm_definitions.py) -- deterministic-extractor
correctness and precondition wiring, no live server or LLM calls.
"""
from aginiti.adapter.observation_adapter import ObservationAdapter
from aginiti.adapters.base import SendResult
from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.anythingllm_definitions import build_anythingllm_library


class _ScriptedAgent:
    """Returns each SendResult in `responses`, in order, one per call to
    send() -- same scripted-fake-agent pattern used throughout this suite
    (e.g. test_evidence_provenance.py's _FakeAgent, generalized to a
    sequence for a two-step plant/trigger operator pair)."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def send(self, channel, prompt):
        self.sent.append((channel, prompt))
        return self._responses.pop(0)

    def ground_truth_mission_achieved(self):
        return False


CANARY = "AGINITI-CANARY-test123"


def _lib():
    return build_anythingllm_library(CANARY)


def test_plant_operator_uses_plant_channel_and_embeds_the_canary_in_the_prompt():
    lib = _lib()
    op = lib._by_id["anythingllm_rag_document_plant"]
    assert op.channel == "plant"
    assert CANARY in op.prompt
    assert op.preconditions == ()


def test_plant_operator_extractor_confirms_on_real_success_shape():
    lib = _lib()
    op = lib._by_id["anythingllm_rag_document_plant"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text="{'success': True, 'error': None, 'documents': [...]}", tool_trace=[]),
    ])

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == ["anythingllm_document_planted"]
    assert result.overall_success is True
    assert result.reasoning == "deterministic extraction (no judge call)"


def test_plant_operator_extractor_does_not_confirm_on_failure_shape():
    lib = _lib()
    op = lib._by_id["anythingllm_rag_document_plant"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text="{'success': False, 'error': 'Invalid file type', 'documents': []}", tool_trace=[]),
    ])

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == []
    assert result.overall_success is False


def test_trigger_operator_precondition_requires_plant_confirmed():
    lib = _lib()
    trigger_op = lib._by_id["anythingllm_rag_injection_trigger"]
    ssg = SecurityStateGraph()

    assert trigger_op.preconditions_met(ssg) is False  # nothing planted yet

    ssg.assert_claim("anythingllm_document_planted", "true", ClaimStatus.CONFIRMED)
    assert trigger_op.preconditions_met(ssg) is True


def test_trigger_operator_confirms_injection_executed_when_canary_present():
    lib = _lib()
    op = lib._by_id["anythingllm_rag_injection_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text=f"Here is the checklist. {CANARY}", tool_trace=[]),
    ])

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == ["anythingllm_rag_injection_executed"]
    assert result.overall_success is True


def test_trigger_operator_confirms_not_retrieved_when_canary_absent():
    lib = _lib()
    op = lib._by_id["anythingllm_rag_injection_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text="Here is the checklist, no canary here.", tool_trace=[]),
    ])

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == ["anythingllm_rag_injection_not_retrieved"]
    assert result.overall_success is False


def test_trigger_operator_never_confirms_from_synthetic_recovery_text():
    # Evidence-provenance gate (see test_evidence_provenance.py) applies here
    # too: even if adapter-synthesized recovery text happened to contain the
    # canary substring verbatim, it must never be treated as the target
    # having genuinely followed the planted instruction.
    lib = _lib()
    op = lib._by_id["anythingllm_rag_injection_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text=f"[Aginiti: synthetic recovery text] {CANARY}", tool_trace=[], is_synthetic=True),
    ])

    result = ObservationAdapter().execute(op, ssg, agent)

    assert result.confirmed_keys == []
    assert result.overall_success is False


def test_full_plant_then_trigger_sequence_end_to_end():
    lib = _lib()
    plant_op = lib._by_id["anythingllm_rag_document_plant"]
    trigger_op = lib._by_id["anythingllm_rag_injection_trigger"]
    ssg = SecurityStateGraph()
    agent = _ScriptedAgent([
        SendResult(final_text="{'success': True, 'error': None, 'documents': [...]}", tool_trace=[]),
        SendResult(final_text=f"The checklist includes... {CANARY}", tool_trace=[]),
    ])

    r1 = ObservationAdapter().execute(plant_op, ssg, agent)
    assert r1.overall_success is True
    assert trigger_op.preconditions_met(ssg) is True

    r2 = ObservationAdapter().execute(trigger_op, ssg, agent)
    assert r2.overall_success is True
    assert agent.sent == [("plant", plant_op.prompt), ("direct", trigger_op.prompt)]
