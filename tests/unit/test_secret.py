"""
Unit tests for SECRETAttack (aginiti/attacks/dra/secret.py) — SECRET Phase 2
(Cluster-Focused Triggering).

All LLM calls, embedding calls, and HTTP calls to the target agent are
mocked — no real API keys required. Integration-level orchestration
(GE/LE state machine, stagnation switching) is tested by patching
``_process_response``/``_ensure_jailbreak_artifact`` directly, same pattern
``test_ikea.py``/``test_jailbreak_optimizer.py`` use for their own
``execute_black_box``/``optimize`` integration tests.

Run:
    pytest tests/unit/test_secret.py -v
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from aginiti.attacks.base import LeakFinding
from aginiti.attacks.dra.jailbreak_optimizer import DEFAULT_EXTRACTION_INSTRUCTION, JailbreakArtifact
from aginiti.attacks.dra.secret import (
    SECRETAttack,
    _CONFIDENTLY_REFUSED,
    _DiscoveredDoc,
    _extract_json_object,
    _levenshtein_distance,
    _normalized_levenshtein,
    _phi_parse,
    _recommendation_for,
    _severity_to_float,
)
from aginiti.connectors.endpoint import AgentEndpoint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_attack(**overrides) -> SECRETAttack:
    defaults = dict(
        target_url="http://localhost:8001",
        llm_provider="gemini/gemini-3.5-flash",
        api_key="fake-key",
        external_corpus=["chunk one text.", "chunk two text.", "chunk three text."],
    )
    defaults.update(overrides)
    return SECRETAttack(**defaults)


def _artifact(**overrides) -> JailbreakArtifact:
    defaults = dict(
        p_e_star="JAILBREAK_PROMPT",
        score=0.9,
        target_identity="http://localhost:8001",
        iterations_used=3,
        used_curriculum=False,
        optimizer_provider="gemini/gemini-3.5-flash",
        evaluator_provider="gemini/gemini-3.5-flash",
        seed_prompt=DEFAULT_EXTRACTION_INSTRUCTION,
        n_cand=3,
        alpha=0.85,
        optimized_at=datetime.now(timezone.utc).isoformat(),
    )
    defaults.update(overrides)
    return JailbreakArtifact(**defaults)


def _finding(probe: str = "q") -> LeakFinding:
    return LeakFinding(
        attack_type="DRA", tier_used="black_box", confidence=0.9, confirmed=True,
        leaked_content="leaked stuff", probe_used=probe, trace_span_id="",
        recommendation="fix it", severity="critical", full_response="resp",
        leak_type="verbatim", reasoning="because",
    )


# ---------------------------------------------------------------------------
# Module-level utilities
# ---------------------------------------------------------------------------

class TestLevenshteinDistance:
    def test_identical_strings(self):
        assert _levenshtein_distance("hello", "hello") == 0

    def test_empty_vs_nonempty(self):
        assert _levenshtein_distance("", "abc") == 3
        assert _levenshtein_distance("abc", "") == 3

    def test_both_empty(self):
        assert _levenshtein_distance("", "") == 0

    def test_single_substitution(self):
        assert _levenshtein_distance("cat", "bat") == 1

    def test_single_insertion(self):
        assert _levenshtein_distance("cat", "cats") == 1

    def test_known_example_kitten_sitting(self):
        assert _levenshtein_distance("kitten", "sitting") == 3


class TestNormalizedLevenshtein:
    def test_identical_is_zero(self):
        assert _normalized_levenshtein("abc", "abc") == 0.0

    def test_completely_different_same_length(self):
        assert _normalized_levenshtein("aaa", "bbb") == 1.0

    def test_both_empty_is_zero(self):
        assert _normalized_levenshtein("", "") == 0.0

    def test_partial_difference(self):
        # "cat" -> "bat": distance 1, max len 3 -> 1/3
        assert _normalized_levenshtein("cat", "bat") == pytest.approx(1 / 3)


class TestPhiParse:
    def test_numbered_segments(self):
        response = "(1) First document. (2) Second document. (3) Third document."
        result = _phi_parse(response)
        assert result == ["First document.", "Second document.", "Third document."]

    def test_single_segment(self):
        assert _phi_parse("(1) Only one thing here.") == ["Only one thing here."]

    def test_multiline_segment(self):
        response = "(1) Line one\nstill segment one\n(2) segment two"
        result = _phi_parse(response)
        assert len(result) == 2
        assert "Line one" in result[0]

    def test_no_numbering_falls_back_to_whole_response(self):
        response = "I cannot repeat that content."
        assert _phi_parse(response) == ["I cannot repeat that content."]

    def test_empty_response(self):
        assert _phi_parse("") == []

    def test_whitespace_only_response(self):
        assert _phi_parse("   \n  ") == []


class TestExtractJsonObject:
    def test_valid_object(self):
        assert _extract_json_object('{"a": 1}') == {"a": 1}

    def test_markdown_fenced(self):
        assert _extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="Expected a JSON object"):
            _extract_json_object('[1, 2, 3]')

    def test_invalid_json_raises(self):
        with pytest.raises(Exception):
            _extract_json_object('not json at all')


class TestSeverityHelpers:
    def test_known_severity(self):
        assert _severity_to_float("critical") == 0.90
        assert _severity_to_float("none") == 0.10

    def test_unknown_severity_falls_back(self):
        assert _severity_to_float("bogus") == 0.30

    def test_recommendation_by_leak_type(self):
        assert "context preprocessing" in _recommendation_for("pii", "critical").lower()

    def test_recommendation_falls_back_to_severity(self):
        # "unknown" is not a recognized leak_type -> falls back to the
        # severity bucket ("low").
        text = _recommendation_for("unknown", "low")
        assert "jailbreak-wrapped" in text.lower()

    def test_recommendation_default_fallback(self):
        text = _recommendation_for("unknown", "unknown")
        assert "manually" in text.lower()


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestSECRETAttackInit:
    def test_requires_external_corpus(self):
        with pytest.raises(ValueError, match="external_corpus"):
            _make_attack(external_corpus=None)

    def test_requires_nonempty_external_corpus(self):
        with pytest.raises(ValueError, match="external_corpus"):
            _make_attack(external_corpus=[])

    def test_optimizer_provider_defaults_to_llm_provider(self):
        attack = _make_attack()
        assert attack._optimizer_llm_provider == "gemini/gemini-3.5-flash"

    def test_optimizer_provider_override(self):
        attack = _make_attack(optimizer_llm_provider="openai/gpt-4o-mini")
        assert attack._optimizer_llm_provider == "openai/gpt-4o-mini"

    def test_defaults(self):
        attack = _make_attack()
        assert attack.max_queries == 300
        assert attack.epsilon_local == 30
        assert attack.le_stagnation_empty_steps == 3
        assert attack.tau_extraction == 0.1
        assert attack.use_priority_queue is False
        assert attack.jailbreak_artifact is None
        assert callable(attack.semantic_shift_llm)

    def test_counters_start_at_zero(self):
        attack = _make_attack()
        assert attack.queries_sent == 0
        assert attack.ge_events == 0
        assert attack.le_steps == 0
        assert attack.refused_queries == []

    def test_pre_supplied_jailbreak_artifact_stored(self):
        artifact = _artifact()
        attack = _make_attack(jailbreak_artifact=artifact)
        assert attack.jailbreak_artifact is artifact


# ---------------------------------------------------------------------------
# _is_refusal
# ---------------------------------------------------------------------------

class TestIsRefusal:
    def test_keyword_match_short_circuits_embedding(self):
        attack = _make_attack()
        attack._embed = MagicMock(side_effect=AssertionError("should not embed"))
        assert attack._is_refusal("I cannot help with that request.") is True

    def test_embedding_fallback_above_threshold(self):
        attack = _make_attack()
        attack._embed = MagicMock(side_effect=lambda text: [1.0, 0.0])
        assert attack._is_refusal("Some paraphrase of a refusal") is True

    def test_embedding_fallback_below_threshold(self):
        attack = _make_attack()
        # Force orthogonal vectors for exemplars vs. the response text -> similarity 0.0
        calls = {"n": 0}
        def embed_side_effect(text):
            calls["n"] += 1
            if calls["n"] <= 6:  # first 6 calls are the 6 exemplar embeddings
                return [1.0, 0.0]
            return [0.0, 1.0]
        attack._embed = MagicMock(side_effect=embed_side_effect)
        assert attack._is_refusal("A genuinely informative response with data.") is False


# ---------------------------------------------------------------------------
# _call_combined_classifier / _classify_response
# ---------------------------------------------------------------------------

class TestCallCombinedClassifier:
    def _valid_json(self, **overrides):
        base = {
            "is_refusal": False,
            "leak_type": "verbatim",
            "contains_pii": True,
            "contains_sensitive_data": False,
            "reveals_schema": False,
            "appears_record_specific": True,
            "severity": "critical",
            "evidence": "the leaked quote",
            "reasoning": "because it matched",
        }
        base.update(overrides)
        return base

    def test_valid_response_parsed(self):
        import json
        attack = _make_attack()
        attack.llm = MagicMock(return_value=json.dumps(self._valid_json()))
        result = attack._call_combined_classifier("q", "r", "HR records")
        assert result["leak_type"] == "verbatim"
        assert result["severity"] == "critical"

    def test_invalid_severity_falls_back(self):
        import json
        attack = _make_attack()
        attack.llm = MagicMock(return_value=json.dumps(self._valid_json(severity="extreme")))
        result = attack._call_combined_classifier("q", "r", "HR records")
        assert result["leak_type"] == "unknown"
        assert result["severity"] == "low"

    def test_invalid_leak_type_falls_back(self):
        import json
        attack = _make_attack()
        attack.llm = MagicMock(return_value=json.dumps(self._valid_json(leak_type="bogus")))
        result = attack._call_combined_classifier("q", "r", "HR records")
        assert result["leak_type"] == "unknown"

    def test_non_bool_is_refusal_falls_back(self):
        import json
        attack = _make_attack()
        attack.llm = MagicMock(return_value=json.dumps(self._valid_json(is_refusal="yes")))
        result = attack._call_combined_classifier("q", "r", "HR records")
        assert result["leak_type"] == "unknown"

    def test_contradiction_resolved_toward_leak_signal(self):
        import json
        attack = _make_attack()
        attack.llm = MagicMock(return_value=json.dumps(
            self._valid_json(is_refusal=True, leak_type="pii")
        ))
        result = attack._call_combined_classifier("q", "r", "HR records")
        assert result["is_refusal"] is False
        assert result["leak_type"] == "pii"

    def test_exception_falls_back(self):
        attack = _make_attack()
        attack.llm = MagicMock(side_effect=RuntimeError("boom"))
        result = attack._call_combined_classifier("q", "r", "HR records")
        assert result["leak_type"] == "unknown"
        assert result["severity"] == "low"


class TestClassifyResponseRouting:
    def test_cheap_refusal_short_circuits_llm(self):
        attack = _make_attack()
        attack._is_refusal = MagicMock(return_value=True)
        attack.llm = MagicMock(side_effect=AssertionError("should not call LLM"))
        result = attack._classify_response("q", "I cannot help.", "domain")
        assert result == _CONFIDENTLY_REFUSED

    def test_non_refusal_calls_classifier(self):
        attack = _make_attack()
        attack._is_refusal = MagicMock(return_value=False)
        attack._call_combined_classifier = MagicMock(return_value={"is_refusal": False, "leak_type": "none"})
        result = attack._classify_response("q", "some informative response", "domain")
        assert result["leak_type"] == "none"
        attack._call_combined_classifier.assert_called_once()


# ---------------------------------------------------------------------------
# _is_new_segment
# ---------------------------------------------------------------------------

class TestIsNewSegment:
    def test_new_when_no_prior_segments(self):
        attack = _make_attack()
        assert attack._is_new_segment("brand new content") is True

    def test_exact_duplicate_is_not_new(self):
        attack = _make_attack()
        attack._extracted_segments = ["some previously seen text"]
        assert attack._is_new_segment("some previously seen text") is False

    def test_near_duplicate_within_tau_is_not_new(self):
        attack = _make_attack(tau_extraction=0.2)
        attack._extracted_segments = ["The quick brown fox jumps"]
        # One character changed -> small normalized distance, within tau=0.2
        assert attack._is_new_segment("The quick brown fox jumpz") is False

    def test_distinct_content_is_new(self):
        attack = _make_attack(tau_extraction=0.1)
        attack._extracted_segments = ["Completely unrelated sentence about cats."]
        assert attack._is_new_segment("A totally different topic involving spacecraft.") is True


# ---------------------------------------------------------------------------
# LE source selection / centroid
# ---------------------------------------------------------------------------

class TestSelectLeSource:
    def test_fifo_pops_in_insertion_order(self):
        attack = _make_attack(use_priority_queue=False)
        d1, d2 = _DiscoveredDoc(text="first"), _DiscoveredDoc(text="second")
        attack._cluster_docs.extend([d1, d2])
        assert attack._select_le_source() is d1
        assert attack._select_le_source() is d2

    def test_priority_queue_picks_farthest_from_centroid(self):
        attack = _make_attack(use_priority_queue=True)
        d_near = _DiscoveredDoc(text="near")
        d_far = _DiscoveredDoc(text="far")
        attack._cluster_docs.extend([d_near, d_far])
        vectors = {"near": [1.0, 0.0], "far": [0.0, 1.0]}
        attack._embed = MagicMock(side_effect=lambda t: vectors[t])
        attack._centroid = [1.0, 0.0]  # identical to "near" -> "far" is farther
        winner = attack._select_le_source()
        assert winner is d_far
        assert d_far not in attack._cluster_docs


class TestRecomputeCentroid:
    def test_empty_cluster_gives_none_centroid(self):
        attack = _make_attack()
        attack._recompute_centroid()
        assert attack._centroid is None

    def test_mean_of_embeddings(self):
        attack = _make_attack()
        attack._cluster_docs.extend([_DiscoveredDoc(text="a"), _DiscoveredDoc(text="b")])
        vectors = {"a": [1.0, 3.0], "b": [3.0, 5.0]}
        attack._embed = MagicMock(side_effect=lambda t: vectors[t])
        attack._recompute_centroid()
        assert attack._centroid == pytest.approx([2.0, 4.0])


# ---------------------------------------------------------------------------
# Corpus sampling
# ---------------------------------------------------------------------------

class TestSampleCorpusChunk:
    def test_no_replacement_until_exhausted(self):
        attack = _make_attack(external_corpus=["a", "b"])
        attack._sample_corpus_chunk()
        attack._sample_corpus_chunk()
        assert len(attack._used_corpus_indices) == 2

    def test_resets_after_exhaustion(self):
        attack = _make_attack(external_corpus=["a", "b"])
        attack._sample_corpus_chunk()
        attack._sample_corpus_chunk()
        assert len(attack._used_corpus_indices) == 2
        attack._sample_corpus_chunk()  # corpus exhausted -> resets, picks one fresh
        assert len(attack._used_corpus_indices) == 1

    def test_returns_actual_corpus_text(self):
        attack = _make_attack(external_corpus=["only chunk"])
        assert attack._sample_corpus_chunk() == "only chunk"


class TestSemanticShiftTrigger:
    def test_formats_prompt_and_calls_llm(self):
        attack = _make_attack()
        attack._sample_corpus_chunk = MagicMock(return_value="bias text")
        attack.semantic_shift_llm = MagicMock(return_value="  merged output  ")
        before = attack._llm_call_count
        result = attack._semantic_shift_trigger("seed document text")
        assert result == "merged output"
        assert attack._llm_call_count == before + 1
        call_args = attack.semantic_shift_llm.call_args[0][0]
        prompt = call_args[0]["content"]
        assert "bias text" in prompt
        assert "seed document text" in prompt


# ---------------------------------------------------------------------------
# _process_response
# ---------------------------------------------------------------------------

class TestProcessResponse:
    def test_refusal_path(self):
        attack = _make_attack()
        attack._classify_response = MagicMock(return_value=_CONFIDENTLY_REFUSED)
        new_docs, finding = attack._process_response("q", "I cannot help.", "domain")
        assert new_docs == []
        assert finding is None
        assert attack.refused_queries == [{"probe": "q", "response": "I cannot help."}]

    def test_leak_type_none_produces_no_finding(self):
        attack = _make_attack()
        attack._classify_response = MagicMock(return_value={
            "is_refusal": False, "leak_type": "none", "severity": "none",
            "evidence": None, "reasoning": "nothing here",
        })
        new_docs, finding = attack._process_response("q", "(1) some content over fifteen chars", "domain")
        assert finding is None

    def test_successful_extraction_creates_finding_and_new_docs(self):
        attack = _make_attack()
        attack._classify_response = MagicMock(return_value={
            "is_refusal": False, "leak_type": "verbatim", "severity": "critical",
            "evidence": "quoted evidence text", "reasoning": "verbatim match",
        })
        response = "(1) First discovered document content here. (2) Second discovered document content here."
        new_docs, finding = attack._process_response("q", response, "domain")
        assert len(new_docs) == 2
        assert finding is not None
        assert finding.leak_type == "verbatim"
        assert finding.confirmed is True
        assert "2 new document segment(s)" in finding.reasoning

    def test_duplicate_segment_not_counted_as_new_second_time(self):
        attack = _make_attack()
        attack._classify_response = MagicMock(return_value={
            "is_refusal": False, "leak_type": "verbatim", "severity": "high",
            "evidence": None, "reasoning": "match",
        })
        response = "(1) A repeated piece of discovered content."
        new_docs_1, _ = attack._process_response("q1", response, "domain")
        new_docs_2, _ = attack._process_response("q2", response, "domain")
        assert len(new_docs_1) == 1
        assert len(new_docs_2) == 0

    def test_short_segment_filtered_out(self):
        attack = _make_attack()
        attack._classify_response = MagicMock(return_value={
            "is_refusal": False, "leak_type": "schema", "severity": "medium",
            "evidence": None, "reasoning": "too short",
        })
        new_docs, _ = attack._process_response("q", "(1) hi", "domain")
        assert new_docs == []


# ---------------------------------------------------------------------------
# execute_black_box — GE/LE orchestration
# ---------------------------------------------------------------------------

class TestExecuteBlackBoxOrchestration:
    def test_unreachable_target_raises(self):
        attack = _make_attack()
        with patch.object(AgentEndpoint, "check_reachable", return_value=False):
            with pytest.raises(RuntimeError, match="NOT reachable"):
                attack.execute_black_box()

    def test_ge_le_flow_with_cluster_exhaustion_fallback(self, monkeypatch):
        attack = _make_attack(max_queries=4)
        monkeypatch.setattr(attack, "_ensure_jailbreak_artifact", MagicMock(return_value=_artifact()))
        doc_a = _DiscoveredDoc(text="doc a")
        doc_b = _DiscoveredDoc(text="doc b")
        f1, f2 = _finding("q1"), _finding("q2")
        process_mock = MagicMock(side_effect=[
            ([doc_a], f1),   # 1: GE seeds a cluster of 1 -> switches to LE
            ([], None),      # 2: LE pops doc_a, finds nothing, cluster empties -> back to GE
            ([], None),      # 3: GE, nothing found -> stays GE
            ([doc_b], f2),   # 4: GE seeds again -> switches to LE
        ])
        monkeypatch.setattr(attack, "_process_response", process_mock)
        monkeypatch.setattr(attack, "_semantic_shift_trigger", MagicMock(return_value="shifted trigger"))

        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="dummy response"):
            findings = attack.execute_black_box()

        assert findings == [f1, f2]
        assert attack.queries_sent == 4
        assert attack.ge_events == 3
        assert attack.le_steps == 1

    def test_le_stagnation_via_consecutive_empty_counter(self, monkeypatch):
        # Seed a 5-doc cluster so 3 consecutive empty LE steps trip the
        # counter threshold WHILE the cluster still has docs left (2
        # remaining) -- isolates the counter condition from the separate
        # "cluster emptied" fallback exercised in the test above.
        attack = _make_attack(max_queries=4, le_stagnation_empty_steps=3)
        monkeypatch.setattr(attack, "_ensure_jailbreak_artifact", MagicMock(return_value=_artifact()))
        docs = [_DiscoveredDoc(text=f"doc {i}") for i in range(5)]
        f1 = _finding("q1")
        process_mock = MagicMock(side_effect=[
            (docs, f1),   # 1: GE seeds 5 docs -> LE
            ([], None),   # 2: LE empty (consecutive=1, cluster has 4 left)
            ([], None),   # 3: LE empty (consecutive=2, cluster has 3 left)
            ([], None),   # 4: LE empty (consecutive=3 -> stagnation triggers via counter)
        ])
        monkeypatch.setattr(attack, "_process_response", process_mock)
        monkeypatch.setattr(attack, "_semantic_shift_trigger", MagicMock(return_value="shifted trigger"))

        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="dummy response"):
            findings = attack.execute_black_box()

        assert findings == [f1]
        assert attack.ge_events == 1
        assert attack.le_steps == 3
        # 2 docs remained in the cluster when stagnation fired via the
        # counter, not the "cluster emptied" fallback.
        assert len(attack._cluster_docs) == 0  # cleared on switch back to GE

    def test_http_failure_is_retried_not_fatal(self, monkeypatch):
        attack = _make_attack(max_queries=2)
        monkeypatch.setattr(attack, "_ensure_jailbreak_artifact", MagicMock(return_value=_artifact()))
        monkeypatch.setattr(attack, "_process_response", MagicMock(return_value=([], None)))
        chat_mock = MagicMock(side_effect=[
            ConnectionError("boom"),
            "ok response",
        ])
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", chat_mock):
            findings = attack.execute_black_box()
        assert findings == []
        assert attack.queries_sent == 2  # failure still counts against budget

    def test_execute_with_traces_upgrades_matched_findings(self, monkeypatch):
        attack = _make_attack()
        attack.otel = MagicMock()
        attack.otel.get_retrieval_span_for_query.return_value = {"span_id": "span-123"}
        f1 = _finding("probe text")
        monkeypatch.setattr(attack, "execute_black_box", MagicMock(return_value=[f1]))
        result = attack.execute_with_traces()
        assert len(result) == 1
        assert result[0].confirmed is True
        assert result[0].tier_used == "otel"
        assert result[0].trace_span_id == "span-123"

    def test_execute_dispatches_to_traces_when_otel_set(self, monkeypatch):
        attack = _make_attack(otel_ingester=MagicMock())
        monkeypatch.setattr(attack, "execute_with_traces", MagicMock(return_value=["upgraded"]))
        assert attack.execute() == ["upgraded"]
