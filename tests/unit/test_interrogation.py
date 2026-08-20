"""
Unit tests for InterrogationAttack (aginiti/attacks/mia/interrogation.py).

All LLM calls (attacker + shadow) and HTTP calls to the target agent are
mocked — no real API keys required.

Run:
    pytest tests/unit/test_interrogation.py -v
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aginiti.attacks.base import LeakFinding
from aginiti.attacks.mia.interrogation import (
    InterrogationAttack,
    _calibration_cache_key,
    _compose_query,
    _extract_json_list,
    _parse_yes_no_unk,
)
from aginiti.connectors.endpoint import AgentEndpoint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_attack(**overrides) -> InterrogationAttack:
    """Construct an InterrogationAttack with patched litellm.completion."""
    defaults = dict(
        target_url="http://localhost:8005",
        llm_provider="gemini/gemini-3.5-flash",
        api_key="fake-key",
        non_member_reference_docs=[
            {"id": "nm_1", "text": "A document about unrelated topic one."},
            {"id": "nm_2", "text": "A document about unrelated topic two."},
        ],
    )
    defaults.update(overrides)
    with patch("litellm.completion", return_value=MagicMock()):
        return InterrogationAttack(**defaults)


def _redirect_cache(monkeypatch, tmp_path):
    """Redirect the calibration disk cache to a pytest tmp_path."""
    def _fake_path(cache_key: str) -> Path:
        return tmp_path / f"{cache_key}.json"
    monkeypatch.setattr(
        "aginiti.attacks.mia.interrogation._calibration_cache_path", _fake_path
    )


# ---------------------------------------------------------------------------
# Module-level utility tests
# ---------------------------------------------------------------------------

class TestParseYesNoUnk:
    def test_clean_yes(self):
        assert _parse_yes_no_unk("Yes, that is correct.") == "yes"

    def test_clean_no(self):
        assert _parse_yes_no_unk("No, that is not mentioned.") == "no"

    def test_unk_phrase(self):
        assert _parse_yes_no_unk("I don't know.") == "unk"

    def test_unk_phrase_do_not_know_variant(self):
        assert _parse_yes_no_unk("I do not know the answer.") == "unk"

    def test_case_insensitive(self):
        assert _parse_yes_no_unk("YES.") == "yes"
        assert _parse_yes_no_unk("no") == "no"

    def test_no_substring_inside_know_is_not_a_false_positive(self):
        # Regression guard: a naive `"no" in text.lower()` check would
        # incorrectly match "no" inside "know" — \bno\b must not.
        assert _parse_yes_no_unk("I don't know that.") == "unk"

    def test_no_substring_inside_not_is_not_a_false_positive(self):
        # "not" contains "no" as a raw substring but is not the word "no".
        assert _parse_yes_no_unk("That is not correct, actually yes it is.") in ("yes", "unk")
        # Specifically: "not" alone (no standalone "no") must not register as "no".
        assert _parse_yes_no_unk("Yes, that is not disputed.") == "yes"

    def test_no_substring_inside_cannot_is_not_a_false_positive(self):
        assert _parse_yes_no_unk("Yes, I cannot dispute that.") == "yes"

    def test_ambiguous_both_yes_and_no_treated_as_unk(self):
        assert _parse_yes_no_unk("Yes and no, it depends.") == "unk"

    def test_off_format_output_treated_as_unk(self):
        assert _parse_yes_no_unk("The weather is nice today.") == "unk"

    def test_trailing_punctuation_tolerated(self):
        assert _parse_yes_no_unk("Yes.") == "yes"
        assert _parse_yes_no_unk("Yes!") == "yes"


class TestParseYesNoUnkReportedSpeechFallback:
    """
    Added 2026-08-13 — live-verified against a real 100-document
    hardened_agent benchmark run. hardened_agent frequently answers in
    indirect reported-speech style ("the consumer asserts that X") without
    ever saying "yes"/"no" literally; the fallback recognizes this pattern
    rather than giving up as "unk". Test text below is real, captured
    verbatim from that run (support persona, 50+50, n=30 — see
    benchmarks/scaled_evals/results/mia_benchmark_support_..._20260812T181049Z.json).
    """

    def test_reported_speech_affirmative_real_capture(self):
        text = (
            "Based on the provided context, the consumer asserts that the three "
            "credit bureaus are required to authenticate (as well as verify and "
            "validate) the accounts."
        )
        assert _parse_yes_no_unk(text) == "yes"

    def test_reported_speech_negative_real_capture(self):
        text = (
            "According to the provided context, the consumer asserts that it is "
            "not acceptable (or authorized) to treat these reporting accounts as "
            "unconfirmed or unverified."
        )
        assert _parse_yes_no_unk(text) == "no"

    def test_reported_speech_affirmative_second_real_capture(self):
        text = (
            "Based on the provided context, the consumer states that incorrect "
            "and inaccurate information is being reported on their credit report "
            "in violation of the law."
        )
        assert _parse_yes_no_unk(text) == "yes"

    def test_direct_yes_no_still_take_priority_over_fallback(self):
        # A direct "Yes"/"No" is found first -- the reported-speech fallback
        # must never override a direct, unambiguous answer.
        assert _parse_yes_no_unk("Yes, the consumer states that X is true.") == "yes"
        assert _parse_yes_no_unk("No, the consumer states that X is true.") == "no"

    def test_explicit_i_dont_know_still_wins_over_fallback(self):
        text = "I don't know. The consumer states that this may be true."
        assert _parse_yes_no_unk(text) == "unk"

    def test_no_recognized_connective_still_falls_back_to_unk(self):
        text = "The provided context discusses account verification procedures."
        assert _parse_yes_no_unk(text) == "unk"

    def test_negation_outside_the_clause_does_not_leak_in(self):
        # "not" appears BEFORE the connective, outside the inspected clause.
        text = "This is not the first time. The consumer states that the debt was paid in full."
        assert _parse_yes_no_unk(text) == "yes"

    def test_clause_trimmed_at_sentence_boundary(self):
        # A negation in a LATER, unrelated sentence must not leak into the
        # verdict for the reported clause itself.
        text = "The consumer states that the account was opened properly. It was not disputed until later."
        assert _parse_yes_no_unk(text) == "yes"


class TestComposeQuery:
    def test_single_space_no_delimiter(self):
        s_star = "Advancements in green energy technologies."
        p = "Does the report mention solar panels?"
        assert _compose_query(s_star, p) == f"{s_star} {p}"

    def test_pagerank_table4_golden_fixture(self):
        # Literal fixture from the paper's Table 4 (PageRank survey paper),
        # confirmed 2026-07-30 — see plans/mia-interrogation-attack.md §6.
        s_star = (
            "I want to ask about Comprehensive survey of PageRank issues, "
            "models, solution methods, and future research areas."
        )
        p_i = (
            "Does the paper act as a companion or extension to the "
            "\"Inside PageRank\" paper by Bianchini et al.? Please answer "
            "with \"Yes,\" \"No,\" or \"I don't know\""
        )
        composed = _compose_query(s_star, p_i)
        assert composed == s_star + " " + p_i
        assert composed.startswith("I want to ask about Comprehensive survey of PageRank")
        assert "Does the paper act as a companion" in composed
        # No newline, no extra delimiter inserted.
        assert "\n" not in composed


class TestExtractJsonList:
    def test_valid_json(self):
        assert _extract_json_list('{"questions": ["a", "b"]}', "questions") == ["a", "b"]

    def test_markdown_fenced(self):
        text = '```json\n{"questions": ["a"]}\n```'
        assert _extract_json_list(text, "questions") == ["a"]

    def test_missing_key_raises(self):
        with pytest.raises(ValueError, match="not found"):
            _extract_json_list('{"other": []}', "questions")

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="empty"):
            _extract_json_list('{"questions": []}', "questions")


class TestCalibrationCacheKey:
    def test_deterministic_for_same_inputs(self):
        docs = [{"id": "a", "text": "hello"}, {"id": "b", "text": "world"}]
        k1 = _calibration_cache_key(docs, 30, 6.0, 0.1, "gemini/gemini-3.5-flash")
        k2 = _calibration_cache_key(docs, 30, 6.0, 0.1, "gemini/gemini-3.5-flash")
        assert k1 == k2

    def test_changes_when_doc_text_changes(self):
        docs_a = [{"id": "a", "text": "hello"}]
        docs_b = [{"id": "a", "text": "different text"}]
        k1 = _calibration_cache_key(docs_a, 30, 6.0, 0.1, "gemini/gemini-3.5-flash")
        k2 = _calibration_cache_key(docs_b, 30, 6.0, 0.1, "gemini/gemini-3.5-flash")
        assert k1 != k2

    def test_changes_when_n_changes(self):
        docs = [{"id": "a", "text": "hello"}]
        k1 = _calibration_cache_key(docs, 30, 6.0, 0.1, "p")
        k2 = _calibration_cache_key(docs, 20, 6.0, 0.1, "p")
        assert k1 != k2

    def test_independent_of_doc_order(self):
        docs_1 = [{"id": "a", "text": "hello"}, {"id": "b", "text": "world"}]
        docs_2 = [{"id": "b", "text": "world"}, {"id": "a", "text": "hello"}]
        k1 = _calibration_cache_key(docs_1, 30, 6.0, 0.1, "p")
        k2 = _calibration_cache_key(docs_2, 30, 6.0, 0.1, "p")
        assert k1 == k2


# ---------------------------------------------------------------------------
# InterrogationAttack.__init__
# ---------------------------------------------------------------------------

class TestInterrogationAttackInit:
    def test_requires_non_empty_reference_docs(self):
        with pytest.raises(ValueError, match="non_member_reference_docs"):
            _make_attack(non_member_reference_docs=[])

    def test_reference_doc_missing_text_raises(self):
        with pytest.raises(ValueError, match="non-empty 'text'"):
            _make_attack(non_member_reference_docs=[{"id": "a"}])

    def test_shadow_llm_defaults_to_main_provider(self):
        attack = _make_attack()
        assert attack._shadow_llm_provider == attack._llm_provider

    def test_shadow_llm_override(self):
        attack = _make_attack(shadow_llm_provider="openai/gpt-4o-mini")
        assert attack._shadow_llm_provider == "openai/gpt-4o-mini"

    def test_warns_when_shadow_matches_main_provider(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            _make_attack(llm_provider="gemini/gemini-3.5-flash")
        assert any("shadow_llm_provider" in r.message for r in caplog.records)

    def test_no_warning_when_shadow_differs(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            _make_attack(
                llm_provider="gemini/gemini-3.5-flash",
                shadow_llm_provider="openai/gpt-4o-mini",
            )
        assert not any("shadow_llm_provider" in r.message for r in caplog.records)

    def test_default_hyperparameters(self):
        attack = _make_attack()
        assert attack.n_probe_questions == 30
        assert attack.lambda_unk == 6.0
        assert attack.fpr_target == 0.1

    def test_non_member_results_starts_empty(self):
        attack = _make_attack()
        assert attack.non_member_results == []


# ---------------------------------------------------------------------------
# Stage A
# ---------------------------------------------------------------------------

class TestGenerateRetrievalSummary:
    def test_returns_stripped_text(self):
        attack = _make_attack()
        attack.llm = lambda msgs, **kw: '  "A short summary."  '
        result = attack._generate_retrieval_summary("some document text")
        assert result == "A short summary."

    def test_increments_llm_call_count(self):
        attack = _make_attack()
        attack.llm = lambda msgs, **kw: "summary"
        before = attack._llm_call_count
        attack._generate_retrieval_summary("text")
        assert attack._llm_call_count == before + 1


class TestGenerateProbeQuestions:
    def test_returns_questions_list(self):
        attack = _make_attack()
        payload = json.dumps({"questions": [f"Q{i}?" for i in range(30)]})
        attack.llm = lambda msgs, **kw: payload
        result = attack._generate_probe_questions("some document text")
        assert len(result) == 30
        assert result[0] == "Q0?"

    def test_truncates_to_n_probe_questions_if_more_returned(self):
        attack = _make_attack(n_probe_questions=5)
        payload = json.dumps({"questions": [f"Q{i}?" for i in range(30)]})
        attack.llm = lambda msgs, **kw: payload
        result = attack._generate_probe_questions("text")
        assert len(result) == 5

    def test_fewer_than_requested_logs_warning_but_proceeds(self, caplog):
        import logging
        attack = _make_attack(n_probe_questions=30)
        payload = json.dumps({"questions": ["Q1?", "Q2?"]})
        attack.llm = lambda msgs, **kw: payload
        with caplog.at_level(logging.WARNING):
            result = attack._generate_probe_questions("text")
        assert len(result) == 2
        assert any("returned 2 questions" in r.message for r in caplog.records)

    def test_bad_json_raises_after_retries(self):
        attack = _make_attack()
        attack.llm = lambda msgs, **kw: "not json"
        with pytest.raises(ValueError):
            attack._generate_probe_questions("text")


# ---------------------------------------------------------------------------
# Stage B
# ---------------------------------------------------------------------------

class TestGenerateGroundTruthAnswers:
    def test_one_call_per_probe(self):
        attack = _make_attack()
        calls = []

        def shadow(msgs, **kw):
            calls.append(msgs)
            return "Yes"

        attack.shadow_llm = shadow
        probes = ["Q1?", "Q2?", "Q3?"]
        result = attack._generate_ground_truth_answers("doc text", probes)
        assert len(calls) == 3
        assert result == ["yes", "yes", "yes"]

    def test_mixed_answers_parsed_correctly(self):
        attack = _make_attack()
        responses = iter(["Yes", "No", "I don't know."])
        attack.shadow_llm = lambda msgs, **kw: next(responses)
        result = attack._generate_ground_truth_answers("doc text", ["Q1?", "Q2?", "Q3?"])
        assert result == ["yes", "no", "unk"]

    def test_uses_shadow_llm_not_main_llm(self):
        attack = _make_attack()
        attack.llm = MagicMock(side_effect=AssertionError("should not call main llm"))
        attack.shadow_llm = lambda msgs, **kw: "Yes"
        attack._generate_ground_truth_answers("doc text", ["Q1?"])  # should not raise

    def test_increments_shadow_call_count(self):
        attack = _make_attack()
        attack.shadow_llm = lambda msgs, **kw: "Yes"
        before = attack._shadow_llm_call_count
        attack._generate_ground_truth_answers("doc text", ["Q1?", "Q2?"])
        assert attack._shadow_llm_call_count == before + 2


# ---------------------------------------------------------------------------
# Stage C
# ---------------------------------------------------------------------------

class TestScoreDocument:
    def test_all_matches_no_unk(self):
        attack = _make_attack(lambda_unk=6.0)
        score = attack._score_document(["yes", "no", "yes"], ["yes", "no", "yes"])
        assert score == pytest.approx(1.0)

    def test_all_mismatches_no_unk(self):
        attack = _make_attack(lambda_unk=6.0)
        score = attack._score_document(["yes", "no"], ["no", "yes"])
        assert score == pytest.approx(0.0)

    def test_unk_response_penalized(self):
        attack = _make_attack(lambda_unk=6.0)
        # g="yes", r="unk": no match (+0), UNK penalty (-6) => -6 for this term
        score = attack._score_document(["yes"], ["unk"])
        assert score == pytest.approx(-6.0)

    def test_both_unk_matches_and_penalizes_per_formula(self):
        attack = _make_attack(lambda_unk=6.0)
        # g="unk", r="unk": match (+1) AND UNK penalty (-6) => -5, per the
        # literal formula (both terms evaluated independently) — see
        # _score_document's docstring.
        score = attack._score_document(["unk"], ["unk"])
        assert score == pytest.approx(-5.0)

    def test_mixed_realistic_case(self):
        attack = _make_attack(lambda_unk=6.0)
        g = ["yes", "no", "yes", "no", "yes"]
        r = ["yes", "no", "no", "unk", "yes"]
        # matches: idx0(+1), idx1(+1), idx4(+1) = +3; idx2 mismatch (0);
        # idx3 unk: no match (0) + penalty (-6) = -6. total = 3 - 6 = -3, /5
        score = attack._score_document(g, r)
        assert score == pytest.approx(-3.0 / 5.0)

    def test_empty_lists_raise(self):
        attack = _make_attack()
        with pytest.raises(ValueError, match="non-empty"):
            attack._score_document([], [])

    def test_mismatched_lengths_raise(self):
        attack = _make_attack()
        with pytest.raises(ValueError, match="same length"):
            attack._score_document(["yes", "no"], ["yes"])


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

class TestCalibrateThreshold:
    def _stub_stage_abc(self, attack, scores):
        """Patch _run_stage_abc_for_document to return canned scores in order."""
        it = iter(scores)

        def fake(endpoint, doc_text, doc_title=""):
            return next(it), "s*", []

        attack._run_stage_abc_for_document = fake

    def test_computes_percentile_threshold(self, monkeypatch, tmp_path):
        attack = _make_attack(
            non_member_reference_docs=[
                {"id": f"nm_{i}", "text": f"text {i}"} for i in range(10)
            ],
            fpr_target=0.1,
        )
        _redirect_cache(monkeypatch, tmp_path)
        scores = [0.1 * i for i in range(10)]  # 0.0 .. 0.9
        self._stub_stage_abc(attack, scores)
        endpoint = MagicMock()
        threshold, returned_scores = attack._calibrate_threshold(endpoint)
        # FPR=0.1 -> 90th percentile -> index 9 -> highest score (0.9)
        assert threshold == pytest.approx(0.9)
        assert returned_scores == scores

    def test_warns_on_degenerate_zero_variance_distribution(self, monkeypatch, tmp_path, caplog):
        # Regression test for the 2026-08-08 live-run finding: a
        # non-member reference set that all scores identically (e.g. every
        # doc cleanly denied -> score 0.0) has zero discriminative spread.
        import logging
        attack = _make_attack(
            non_member_reference_docs=[
                {"id": "nm_1", "text": "a"}, {"id": "nm_2", "text": "b"},
                {"id": "nm_3", "text": "c"}, {"id": "nm_4", "text": "d"},
                {"id": "nm_5", "text": "e"},
            ],
        )
        _redirect_cache(monkeypatch, tmp_path)
        self._stub_stage_abc(attack, [0.0, 0.0, 0.0, 0.0, 0.0])
        endpoint = MagicMock()
        with caplog.at_level(logging.WARNING):
            attack._calibrate_threshold(endpoint)
        assert any("zero discriminative spread" in r.message for r in caplog.records)

    def test_no_degenerate_warning_when_scores_vary(self, monkeypatch, tmp_path, caplog):
        import logging
        attack = _make_attack(
            non_member_reference_docs=[
                {"id": "nm_1", "text": "a"}, {"id": "nm_2", "text": "b"},
                {"id": "nm_3", "text": "c"}, {"id": "nm_4", "text": "d"},
                {"id": "nm_5", "text": "e"},
            ],
        )
        _redirect_cache(monkeypatch, tmp_path)
        self._stub_stage_abc(attack, [0.0, 0.1, 0.2, 0.3, 0.4])
        endpoint = MagicMock()
        with caplog.at_level(logging.WARNING):
            attack._calibrate_threshold(endpoint)
        assert not any("zero discriminative spread" in r.message for r in caplog.records)

    def test_warns_on_small_reference_set(self, monkeypatch, tmp_path, caplog):
        import logging
        attack = _make_attack(
            non_member_reference_docs=[{"id": "nm_1", "text": "a"}],
        )
        _redirect_cache(monkeypatch, tmp_path)
        self._stub_stage_abc(attack, [0.0])
        endpoint = MagicMock()
        with caplog.at_level(logging.WARNING):
            attack._calibrate_threshold(endpoint)
        assert any("recommends 5-10+" in r.message for r in caplog.records)

    def test_caches_to_disk(self, monkeypatch, tmp_path):
        attack = _make_attack(fpr_target=0.1)
        _redirect_cache(monkeypatch, tmp_path)
        self._stub_stage_abc(attack, [0.1, 0.2])
        endpoint = MagicMock()
        threshold1, _ = attack._calibrate_threshold(endpoint)

        # Second call should hit the cache -- stub raises if called again.
        attack._run_stage_abc_for_document = MagicMock(
            side_effect=AssertionError("should not recompute -- cache should hit")
        )
        threshold2, _ = attack._calibrate_threshold(endpoint)
        assert threshold1 == threshold2

    def test_force_recalibrate_bypasses_cache(self, monkeypatch, tmp_path):
        attack = _make_attack(fpr_target=0.1)
        _redirect_cache(monkeypatch, tmp_path)
        self._stub_stage_abc(attack, [0.1, 0.2])
        endpoint = MagicMock()
        attack._calibrate_threshold(endpoint)

        self._stub_stage_abc(attack, [0.5, 0.6])
        threshold2, scores2 = attack._calibrate_threshold(endpoint, force_recalibrate=True)
        assert scores2 == [0.5, 0.6]

    def test_expired_cache_recomputes(self, monkeypatch, tmp_path):
        attack = _make_attack(
            fpr_target=0.1, calibration_cache_ttl_seconds=1,
        )
        _redirect_cache(monkeypatch, tmp_path)
        self._stub_stage_abc(attack, [0.1, 0.2])
        endpoint = MagicMock()
        attack._calibrate_threshold(endpoint)

        # Manually age the cache file past the 1-second TTL.
        from aginiti.attacks.mia.interrogation import _calibration_cache_key
        key = _calibration_cache_key(
            attack.non_member_reference_docs, attack.n_probe_questions,
            attack.lambda_unk, attack.fpr_target, attack._shadow_llm_provider,
        )
        cache_path = tmp_path / f"{key}.json"
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        data["calibrated_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=10)
        ).isoformat()
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        self._stub_stage_abc(attack, [0.7, 0.8])
        _threshold, scores = attack._calibrate_threshold(endpoint)
        assert scores == [0.7, 0.8]


# ---------------------------------------------------------------------------
# _make_finding
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def _detail(self):
        return [
            {"probe_question": "Q1?", "composed_query": "s* Q1?",
             "shadow_answer": "yes", "target_response": "Yes.",
             "target_answer": "yes", "match": True},
            {"probe_question": "Q2?", "composed_query": "s* Q2?",
             "shadow_answer": "no", "target_response": "I don't know.",
             "target_answer": "unk", "match": False},
        ]

    def test_basic_fields(self):
        attack = _make_attack(fpr_target=0.1)
        finding = attack._make_finding("doc_1", 0.7, 0.5, "s* summary", self._detail())
        assert isinstance(finding, LeakFinding)
        assert finding.attack_type == "MIA"
        assert finding.tier_used == "black_box"
        assert finding.confirmed is True
        assert finding.leak_type == "membership"
        assert finding.severity == "medium"
        assert finding.probe_used == "s* summary"
        assert finding.trace_span_id == ""
        assert "doc_1" in finding.leaked_content

    def test_confidence_is_zero_at_threshold(self):
        attack = _make_attack()
        finding = attack._make_finding("doc_1", 0.5, 0.5, "s*", self._detail())
        assert finding.confidence == pytest.approx(0.0)

    def test_confidence_approaches_one_near_max(self):
        attack = _make_attack()
        finding = attack._make_finding("doc_1", 0.99, 0.5, "s*", self._detail())
        assert finding.confidence == pytest.approx((0.99 - 0.5) / (1 - 0.5))

    def test_confidence_clamped_to_one(self):
        attack = _make_attack()
        finding = attack._make_finding("doc_1", 5.0, 0.5, "s*", self._detail())
        assert finding.confidence == 1.0

    def test_full_response_is_valid_json_detail(self):
        attack = _make_attack()
        finding = attack._make_finding("doc_1", 0.7, 0.5, "s*", self._detail())
        parsed = json.loads(finding.full_response)
        assert len(parsed) == 2
        assert parsed[0]["match"] is True

    def test_reasoning_mentions_match_count(self):
        attack = _make_attack()
        finding = attack._make_finding("doc_1", 0.7, 0.5, "s*", self._detail())
        assert "1/2" in finding.reasoning


# ---------------------------------------------------------------------------
# execute_black_box
# ---------------------------------------------------------------------------

class TestExecuteBlackBox:
    def test_requires_documents(self):
        attack = _make_attack()
        with pytest.raises(ValueError, match="documents"):
            attack.execute_black_box()

    def test_documents_entry_requires_text(self):
        attack = _make_attack()
        with pytest.raises(ValueError, match="non-empty 'text'"):
            attack.execute_black_box(documents=[{"id": "a"}])

    def test_full_loop_confirms_and_rejects_correctly(self, monkeypatch, tmp_path):
        attack = _make_attack(
            non_member_reference_docs=[{"id": "nm_1", "text": "unrelated text"}],
            n_probe_questions=2,
        )
        _redirect_cache(monkeypatch, tmp_path)

        # Stub the shared Stage A->B->C runner directly -- isolates
        # execute_black_box's own routing/aggregation logic from Stage
        # A/B/C's internals (covered separately above).
        call_log = []

        def fake_stage_abc(endpoint, doc_text, doc_title=""):
            call_log.append(doc_text)
            if doc_text == "member candidate text":
                return 0.9, "s* member", [
                    {"probe_question": "Q?", "composed_query": "s* Q?",
                     "shadow_answer": "yes", "target_response": "Yes.",
                     "target_answer": "yes", "match": True},
                ]
            if doc_text == "unrelated text":
                # The calibration reference doc -- gives threshold=0.5,
                # distinct from both candidates' scores below.
                return 0.5, "s* ref", [
                    {"probe_question": "Q?", "composed_query": "s* Q?",
                     "shadow_answer": "yes", "target_response": "No.",
                     "target_answer": "no", "match": False},
                ]
            return 0.1, "s* other", [
                {"probe_question": "Q?", "composed_query": "s* Q?",
                 "shadow_answer": "yes", "target_response": "No.",
                 "target_answer": "no", "match": False},
            ]

        attack._run_stage_abc_for_document = fake_stage_abc

        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            findings = attack.execute_black_box(documents=[
                {"id": "candidate_member", "text": "member candidate text"},
                {"id": "candidate_non_member", "text": "not-a-member text"},
            ])

        # calibration call (1 reference doc) + 2 candidate docs = 3 calls
        assert len(call_log) == 3
        assert len(findings) == 1
        assert findings[0].leak_type == "membership"
        assert "candidate_member" in findings[0].leaked_content
        assert len(attack.non_member_results) == 1
        assert attack.non_member_results[0]["id"] == "candidate_non_member"
        assert attack.non_member_results[0]["verdict"] == "non_member"

    def test_boundary_tie_is_non_member_not_member(self, monkeypatch, tmp_path):
        # Regression test for the real bug found live 2026-08-08: a
        # genuinely non-member candidate landing EXACTLY on the calibrated
        # threshold (e.g. both score 0.0 because the target cleanly denies
        # every non-member probe) must NOT be classified as a confirmed
        # member. Strict `>`, not `>=`.
        attack = _make_attack(
            non_member_reference_docs=[{"id": "nm_1", "text": "reference doc"}],
        )
        _redirect_cache(monkeypatch, tmp_path)

        def fake_stage_abc(endpoint, doc_text, doc_title=""):
            # Every document -- the calibration reference AND the
            # candidate -- scores exactly 0.0, replicating the live
            # reference_agent_blackbox run where a target that cleanly
            # denies every probe produces a degenerate all-zero
            # distribution.
            return 0.0, "s*", [
                {"probe_question": "Q?", "composed_query": "s* Q?",
                 "shadow_answer": "yes", "target_response": "No record found.",
                 "target_answer": "no", "match": False},
            ]

        attack._run_stage_abc_for_document = fake_stage_abc
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            findings = attack.execute_black_box(
                documents=[{"id": "definitely_not_a_member", "text": "fake doc"}]
            )

        assert findings == []
        assert len(attack.non_member_results) == 1
        assert attack.non_member_results[0]["id"] == "definitely_not_a_member"
        assert attack.non_member_results[0]["score"] == attack.non_member_results[0]["threshold"]

    def test_non_member_results_carries_full_audit_detail(self, monkeypatch, tmp_path):
        attack = _make_attack(
            non_member_reference_docs=[{"id": "nm_1", "text": "reference doc"}],
        )
        _redirect_cache(monkeypatch, tmp_path)

        def fake_stage_abc(endpoint, doc_text, doc_title=""):
            if doc_text == "reference doc":
                return 0.9, "s* ref", [
                    {"probe_question": "Q?", "composed_query": "s* Q?",
                     "shadow_answer": "yes", "target_response": "Yes.",
                     "target_answer": "yes", "match": True},
                ]
            return 0.0, "s*", [
                {"probe_question": "Q1?", "composed_query": "s* Q1?",
                 "shadow_answer": "yes", "target_response": "No.",
                 "target_answer": "no", "match": False},
                {"probe_question": "Q2?", "composed_query": "s* Q2?",
                 "shadow_answer": "yes", "target_response": "I don't know.",
                 "target_answer": "unk", "match": False},
            ]

        attack._run_stage_abc_for_document = fake_stage_abc
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            attack.execute_black_box(documents=[{"id": "candidate", "text": "candidate text"}])

        result = attack.non_member_results[0]
        assert result["matches"] == 0
        assert result["unk_count"] == 1
        assert result["n"] == 2
        assert len(result["detail"]) == 2

    def test_raises_if_target_unreachable(self):
        attack = _make_attack()
        with patch.object(AgentEndpoint, "check_reachable", return_value=False):
            with pytest.raises(RuntimeError, match="NOT reachable"):
                attack.execute_black_box(documents=[{"id": "a", "text": "some text"}])

    def test_resets_non_member_results_between_runs(self, monkeypatch, tmp_path):
        attack = _make_attack(
            non_member_reference_docs=[{"id": "nm_1", "text": "unrelated"}],
        )
        _redirect_cache(monkeypatch, tmp_path)

        def fake(endpoint, doc_text, doc_title=""):
            # Reference doc scores high (threshold=0.9); every candidate
            # scores low (0.0) -- always clearly a non-member.
            if doc_text == "unrelated":
                return 0.9, "s* ref", [
                    {"probe_question": "Q?", "composed_query": "s* Q?",
                     "shadow_answer": "yes", "target_response": "Yes.",
                     "target_answer": "yes", "match": True},
                ]
            return 0.0, "s*", [
                {"probe_question": "Q?", "composed_query": "s* Q?",
                 "shadow_answer": "yes", "target_response": "No.",
                 "target_answer": "no", "match": False},
            ]

        attack._run_stage_abc_for_document = fake
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            attack.execute_black_box(documents=[{"id": "a", "text": "text a"}])
            assert len(attack.non_member_results) == 1
            attack.execute_black_box(documents=[{"id": "b", "text": "text b"}])
            assert len(attack.non_member_results) == 1  # reset, not accumulated
            assert attack.non_member_results[0]["id"] == "b"


# ---------------------------------------------------------------------------
# score_documents (added 2026-08-12) -- threshold-free raw scoring, for
# benchmark workflows that need (score, true_label) pairs directly rather
# than a calibrated membership verdict.
# ---------------------------------------------------------------------------

class TestScoreDocuments:
    def test_requires_documents(self):
        attack = _make_attack()
        with pytest.raises(ValueError, match="at least one document"):
            attack.score_documents([])

    def test_documents_entry_requires_text(self):
        attack = _make_attack()
        with pytest.raises(ValueError, match="non-empty 'text'"):
            attack.score_documents([{"id": "a"}])

    def test_raises_if_target_unreachable(self):
        attack = _make_attack()
        with patch.object(AgentEndpoint, "check_reachable", return_value=False):
            with pytest.raises(RuntimeError, match="NOT reachable"):
                attack.score_documents([{"id": "a", "text": "some text"}])

    def test_does_not_touch_calibration_or_reference_docs(self):
        # score_documents must not call _calibrate_threshold at all -- it
        # has no notion of a threshold/reference set, unlike execute_black_box.
        attack = _make_attack()
        attack._calibrate_threshold = MagicMock(
            side_effect=AssertionError("must not be called")
        )

        def fake_stage_abc(endpoint, doc_text, doc_title=""):
            return 0.5, "s*", [
                {"probe_question": "Q?", "composed_query": "s* Q?",
                 "shadow_answer": "yes", "target_response": "Yes.",
                 "target_answer": "yes", "match": True},
            ]

        attack._run_stage_abc_for_document = fake_stage_abc
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            attack.score_documents([{"id": "a", "text": "some text"}])
        attack._calibrate_threshold.assert_not_called()

    def test_returns_score_per_document_in_order(self):
        attack = _make_attack()

        def fake_stage_abc(endpoint, doc_text, doc_title=""):
            scores = {"first text": 0.8, "second text": -0.3}
            return scores[doc_text], f"s* for {doc_text}", [
                {"probe_question": "Q?", "composed_query": "s* Q?",
                 "shadow_answer": "yes", "target_response": "Yes.",
                 "target_answer": "yes", "match": True},
            ]

        attack._run_stage_abc_for_document = fake_stage_abc
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            results = attack.score_documents([
                {"id": "doc_a", "text": "first text"},
                {"id": "doc_b", "text": "second text"},
            ])

        assert [r["id"] for r in results] == ["doc_a", "doc_b"]
        assert results[0]["score"] == pytest.approx(0.8)
        assert results[1]["score"] == pytest.approx(-0.3)
        assert results[0]["s_star"] == "s* for first text"
        assert "detail" in results[0]

    def test_resets_llm_call_counts_between_calls(self):
        attack = _make_attack()

        def fake_stage_abc(endpoint, doc_text, doc_title=""):
            attack._llm_call_count += 2
            attack._shadow_llm_call_count += 3
            return 0.1, "s*", []

        attack._run_stage_abc_for_document = fake_stage_abc
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            attack.score_documents([{"id": "a", "text": "text a"}])
            assert attack._llm_call_count == 2
            assert attack._shadow_llm_call_count == 3
            attack.score_documents([{"id": "b", "text": "text b"}, {"id": "c", "text": "text c"}])
            assert attack._llm_call_count == 4  # reset then 2 docs x 2
            assert attack._shadow_llm_call_count == 6

    def test_default_id_when_missing(self):
        attack = _make_attack()
        attack._run_stage_abc_for_document = lambda endpoint, doc_text, doc_title="": (
            0.0, "s*", []
        )
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            results = attack.score_documents([{"text": "no id given"}])
        assert results[0]["id"] == "doc_0"


# ---------------------------------------------------------------------------
# execute_with_traces
# ---------------------------------------------------------------------------

class TestExecuteWithTraces:
    def test_calls_execute_black_box_internally(self, monkeypatch, tmp_path):
        attack = _make_attack(
            non_member_reference_docs=[{"id": "nm_1", "text": "unrelated"}],
            otel_ingester=MagicMock(get_retrieval_span_for_query=MagicMock(return_value=None)),
        )
        _redirect_cache(monkeypatch, tmp_path)
        captured = {}

        def fake_execute_black_box(**kwargs):
            captured.update(kwargs)
            return []

        attack.execute_black_box = fake_execute_black_box
        result = attack.execute_with_traces(documents=[{"id": "a", "text": "t"}])
        assert result == []
        assert captured["documents"] == [{"id": "a", "text": "t"}]

    def test_upgrades_tier_and_span_when_match_found(self):
        finding = LeakFinding(
            attack_type="MIA", tier_used="black_box", confidence=0.8,
            confirmed=True, leaked_content="x", probe_used="s* summary",
            trace_span_id="", recommendation="r", severity="medium",
            leak_type="membership", reasoning="r",
        )
        otel = MagicMock()
        otel.get_retrieval_span_for_query.return_value = {"span_id": "span-123"}
        attack = _make_attack(otel_ingester=otel)
        attack.execute_black_box = lambda **kw: [finding]

        result = attack.execute_with_traces(documents=[{"id": "a", "text": "t"}])
        assert len(result) == 1
        assert result[0].tier_used == "otel"
        assert result[0].trace_span_id == "span-123"

    def test_no_upgrade_when_no_span_match(self):
        finding = LeakFinding(
            attack_type="MIA", tier_used="black_box", confidence=0.8,
            confirmed=True, leaked_content="x", probe_used="s* summary",
            trace_span_id="", recommendation="r", severity="medium",
            leak_type="membership", reasoning="r",
        )
        otel = MagicMock()
        otel.get_retrieval_span_for_query.return_value = None
        attack = _make_attack(otel_ingester=otel)
        attack.execute_black_box = lambda **kw: [finding]

        result = attack.execute_with_traces(documents=[{"id": "a", "text": "t"}])
        assert result[0].tier_used == "black_box"
        assert result[0].trace_span_id == ""


# ---------------------------------------------------------------------------
# execute() dispatch (BaseAttack contract)
# ---------------------------------------------------------------------------

class TestExecuteDispatch:
    def test_no_otel_dispatches_to_black_box(self):
        attack = _make_attack()
        attack.execute_black_box = MagicMock(return_value=["sentinel"])
        attack.execute_with_traces = MagicMock(side_effect=AssertionError("wrong dispatch"))
        result = attack.execute(documents=[{"id": "a", "text": "t"}])
        assert result == ["sentinel"]

    def test_otel_dispatches_to_with_traces(self):
        attack = _make_attack(otel_ingester=MagicMock())
        attack.execute_black_box = MagicMock(side_effect=AssertionError("wrong dispatch"))
        attack.execute_with_traces = MagicMock(return_value=["sentinel"])
        result = attack.execute(documents=[{"id": "a", "text": "t"}])
        assert result == ["sentinel"]
