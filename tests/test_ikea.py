"""
Unit tests for IKEAAttack (aginiti/attacks/dra/ikea.py).

All LLM and embedding calls are mocked — no real API keys required.
HTTP calls to the target agent are mocked via unittest.mock.patch.object.

Run:
    pytest tests/test_ikea.py -v
"""

import json
import math
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import litellm
import pytest

from aginiti.attacks.base import LeakFinding
from aginiti.attacks.dra.ikea import (
    IKEAAttack,
    _cosine,
    _extract_json_list,
    _extract_json_object,
    _recommendation_for,
    _REFUSAL_EXEMPLARS,
    _REFUSAL_PHRASES,
    _severity_to_float,
)
from aginiti.connectors.endpoint import AgentEndpoint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_embed_response(vector: list[float]) -> MagicMock:
    resp = MagicMock()
    resp.data = [{"embedding": vector}]
    return resp


def _unit(n: int, pos: int) -> list[float]:
    """Return a unit vector of length n with a 1 at position pos."""
    v = [0.0] * n
    v[pos] = 1.0
    return v


def _make_attack(**overrides) -> IKEAAttack:
    """Construct an IKEAAttack with patched litellm.completion."""
    defaults = dict(
        target_url="http://localhost:8001",
        llm_provider="gemini/gemini-2.5-flash",
        api_key="fake-key",
        topic="HR records",
    )
    defaults.update(overrides)
    with patch("litellm.completion", return_value=MagicMock()):
        return IKEAAttack(**defaults)


# ---------------------------------------------------------------------------
# Module-level utility tests
# ---------------------------------------------------------------------------

class TestCosine:
    def test_identical_vectors(self):
        v = [1.0, 2.0, 3.0]
        assert _cosine(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        assert _cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)

    def test_zero_vector_returns_zero(self):
        assert _cosine([0.0, 0.0], [1.0, 2.0]) == 0.0

    def test_opposite_vectors(self):
        assert _cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)

    def test_known_value(self):
        # [1,0] vs [1,1]/sqrt(2) → cos(45°) = sqrt(2)/2
        result = _cosine([1.0, 0.0], [1.0, 1.0])
        assert result == pytest.approx(1.0 / math.sqrt(2), rel=1e-6)


class TestExtractJsonList:
    def test_plain_json(self):
        raw = '{"anchor words": ["salary", "benefits"]}'
        assert _extract_json_list(raw, "anchor words") == ["salary", "benefits"]

    def test_markdown_fenced(self):
        raw = '```json\n{"questions": ["q1", "q2"]}\n```'
        assert _extract_json_list(raw, "questions") == ["q1", "q2"]

    def test_missing_key_raises(self):
        raw = '{"other": ["x"]}'
        with pytest.raises(ValueError, match="not found"):
            _extract_json_list(raw, "anchor words")

    def test_empty_list_raises(self):
        raw = '{"anchor words": []}'
        with pytest.raises(ValueError, match="empty"):
            _extract_json_list(raw, "anchor words")

    def test_invalid_json_raises(self):
        with pytest.raises(Exception):
            _extract_json_list("not json at all", "anchor words")


# ---------------------------------------------------------------------------
# IKEAAttack construction
# ---------------------------------------------------------------------------

class TestIKEAAttackInit:
    def test_stores_all_hyperparams(self):
        attack = _make_attack()
        assert attack.theta_top == 0.3
        assert attack.theta_inter == 0.5
        # 0.40, not the paper's 0.7 — recalibrated for all-MiniLM-L6-v2's lower
        # cosine-similarity range, then lowered again from an earlier 0.5
        # guess (2026-07-13) using the empirical "best sim=" distribution
        # from a live run (see the comment above theta_anchor's default in
        # IKEAAttack.__init__).
        assert attack.theta_anchor == 0.40
        assert attack.theta_u == 0.5
        assert attack.p == 10.0
        assert attack.kappa == 7.0
        assert attack.delta_o == 0.7
        assert attack.delta_u == 0.7
        assert attack.beta == 1.0
        assert attack.gamma == 0.5
        assert attack.tau_q == 0.6
        assert attack.tau_y == 0.6
        # 0.90, not the earlier 0.78 — recalibrated for all-MiniLM-L6-v2's
        # higher similarity compression (see theta_refusal's docstring in
        # IKEAAttack.__init__).
        assert attack.theta_refusal == 0.90
        assert attack.max_queries == 256
        assert attack.n_anchor_candidates == 20
        assert attack.n_query_candidates == 5
        assert attack.n_mutation_candidates == 10
        # None -> auto = max_q * 8, resolved per-run in execute_black_box.
        assert attack.max_llm_calls is None
        assert attack.max_trdm_iterations == 5

    def test_max_llm_calls_explicit_override_stored(self):
        attack = _make_attack(max_llm_calls=100)
        assert attack.max_llm_calls == 100

    def test_embed_key_falls_back_to_api_key(self):
        attack = _make_attack(api_key="my-key", embed_api_key=None)
        assert attack._embed_key == "my-key"

    def test_embed_key_explicit_override(self):
        attack = _make_attack(api_key="llm-key", embed_api_key="embed-key")
        assert attack._embed_key == "embed-key"

    def test_embed_model_default(self):
        attack = _make_attack()
        assert attack._embed_model == "chromadb/all-MiniLM-L6-v2"

    def test_topic_stored(self):
        attack = _make_attack(topic="patient records")
        assert attack.topic == "patient records"

    def test_embed_cache_initialized_empty(self):
        attack = _make_attack()
        assert attack._embed_cache == {}

    def test_otel_ingester_stored(self):
        mock_otel = MagicMock()
        attack = _make_attack(otel_ingester=mock_otel)
        assert attack.otel is mock_otel


# ---------------------------------------------------------------------------
# _is_refusal
# ---------------------------------------------------------------------------

class TestIsRefusal:
    def setup_method(self):
        self.attack = _make_attack()
        # Keyword-matched phrases below never reach this mock (the keyword
        # check short-circuits first) — this only governs the semantic
        # fallback path (restored 2026-07-13, theta_refusal=0.90).
        def mock_embed(text: str) -> list[float]:
            if text in _REFUSAL_EXEMPLARS:
                return [1.0, 0.0]
            if "isn't part of what's stored" in text.lower():
                # cos=0.95 to the exemplars — within the genuine-refusal band
                # (0.92-0.97) this threshold was calibrated against, above
                # theta_refusal=0.90.
                return [0.95, 0.3122498999]
            if "based on the provided employee records" in text.lower():
                # cos=0.80 to the exemplars — within the partial-answer band
                # (0.75-0.85) that shares boilerplate with a refusal but is
                # genuinely informative. Must stay below theta_refusal=0.90.
                return [0.8, 0.6]
            return [0.0, 1.0]  # informative/factual response — orthogonal to refusals
        self.attack._embed = mock_embed

    def test_detects_i_dont_know(self):
        assert self.attack._is_refusal("I don't know the answer to that.")

    def test_detects_i_cannot(self):
        assert self.attack._is_refusal("I cannot provide that information.")

    def test_detects_i_am_unable(self):
        assert self.attack._is_refusal("I am unable to answer that question.")

    def test_case_insensitive(self):
        assert self.attack._is_refusal("I CANNOT PROVIDE THIS.")

    def test_keyword_match_short_circuits_before_embedding(self):
        attack = _make_attack()
        attack._embed = MagicMock(side_effect=AssertionError("should not embed"))
        assert attack._is_refusal("I cannot provide that information.")
        attack._embed.assert_not_called()

    def test_passes_normal_hr_response(self):
        response = (
            "Emma Thompson is a Software Engineer in the Engineering department. "
            "Her annual salary is $152,000 and her SSN is 423-58-9167."
        )
        assert not self.attack._is_refusal(response)

    def test_passes_short_factual_answer(self):
        assert not self.attack._is_refusal("The employee's hire date is 2018-06-04.")

    def test_catches_paraphrase_via_semantic_fallback(self):
        # Regression test: a refusal-flavored paraphrase that shares no exact
        # substring with any _REFUSAL_PHRASES entry, so only the semantic
        # fallback catches it.
        text = "That particular detail isn't part of what's stored in these employee records."
        assert not any(phrase in text.lower() for phrase in _REFUSAL_PHRASES)
        assert self.attack._is_refusal(text)

    def test_boilerplate_sharing_partial_answer_is_not_a_refusal(self):
        # The exact 2026-07-12 false-positive scenario this recalibration
        # (theta_refusal 0.78 -> 0.90) fixes: a genuine partial answer shares
        # boilerplate with a refusal (cos~0.80 to the exemplars in MiniLM's
        # space) but must NOT be flagged.
        text = "Based on the provided employee records, the salary figures do not include bonuses."
        assert not self.attack._is_refusal(text)

    def test_paraphrase_below_threshold_is_not_a_refusal(self):
        self.attack.theta_refusal = 0.99  # stricter than the mocked ~0.95 similarity
        text = "That particular detail isn't part of what's stored in these employee records."
        assert not self.attack._is_refusal(text)

    def test_over_broad_phrases_no_longer_trigger_false_positives(self):
        # These specific phrasings (removed from the broader pre-2026-07-12
        # _REFUSAL_PHRASES list) must not match on keyword grounds, and none
        # of them share the "based on the provided employee records" framing
        # that scores high on the semantic fallback, so they resolve to the
        # orthogonal "informative" vector in the mock above.
        genuine_responses = [
            "The records do not specify a start date, but the hire date is listed as 2018-06-04.",
            "The document does not mention a manager name, though the department is Engineering.",
            "No relevant disciplinary actions were found; the employee's performance rating is Outstanding.",
            "There is no information on remote work, but the office location is listed as Boston, MA.",
        ]
        for text in genuine_responses:
            assert not self.attack._is_refusal(text), f"should NOT be a refusal: {text!r}"


# ---------------------------------------------------------------------------
# _call_llm_for_json
# ---------------------------------------------------------------------------

class TestCallLlmForJson:
    def setup_method(self):
        self.attack = _make_attack()

    def test_parses_valid_json(self):
        self.attack.llm = lambda msgs, **kw: '{"anchor words": ["salary", "hire date"]}'
        result = self.attack._call_llm_for_json("prompt", key="anchor words")
        assert result == ["salary", "hire date"]

    def test_retries_on_bad_json_then_succeeds(self):
        responses = iter(["not json", '{"anchor words": ["ok"]}'])
        self.attack.llm = lambda msgs, **kw: next(responses)
        result = self.attack._call_llm_for_json("prompt", key="anchor words", retries=3)
        assert result == ["ok"]

    def test_raises_after_all_retries_fail(self):
        self.attack.llm = lambda msgs, **kw: "not json"
        with pytest.raises(ValueError, match="failed to return parseable JSON"):
            self.attack._call_llm_for_json("prompt", key="anchor words", retries=3)


# ---------------------------------------------------------------------------
# _init_anchors
# ---------------------------------------------------------------------------

class TestInitAnchors:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack.theta_top = 0.5
        self.attack.theta_inter = 0.9
        # These tests exercise filtering, not the anchor cache — isolate each
        # to a throwaway path so they never collide with a real
        # .cache/ikea_anchors/ file (same-topic "HR records" collisions
        # across test runs would otherwise make these flaky; see
        # TestAnchorCache for dedicated cache-behavior coverage).
        self._cache_patcher = patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path",
            side_effect=lambda topic: Path(tempfile.gettempdir())
            / f"ikea_test_cache_{uuid.uuid4().hex}.json",
        )
        self._cache_patcher.start()

    def teardown_method(self):
        self._cache_patcher.stop()

    def _stub_llm(self, anchors: list[str]) -> None:
        payload = json.dumps({"anchor words": anchors})
        self.attack.llm = lambda msgs, **kw: payload

    def test_filters_low_similarity_candidates(self):
        # topic → dim 0; "good" anchor is similar (dim 0 heavy);
        # "bad" anchor is orthogonal (dim 1 only)
        self._stub_llm(["good anchor", "bad anchor"])

        def mock_embed(text: str) -> list[float]:
            if text in ("HR records", "good anchor"):
                return [1.0, 0.0]
            return [0.0, 1.0]  # bad anchor is orthogonal → cosine=0 < 0.5

        self.attack._embed = mock_embed
        result = self.attack._init_anchors("HR records")
        assert result == ["good anchor"]

    def test_diversity_filter_removes_near_duplicates(self):
        # Set theta_top=0.0 so all candidates pass step 1; this test
        # validates the greedy diversity filter (step 2) in isolation.
        self.attack.theta_top = 0.0
        self.attack.theta_inter = 0.5
        self._stub_llm(["anchor_a", "anchor_b", "anchor_c"])

        def mock_embed(text: str) -> list[float]:
            if text == "HR records":
                return [1.0, 0.0, 0.0]
            if text in ("anchor_a", "anchor_b"):
                # Nearly identical → cosine ≈ 1.0 > theta_inter, so anchor_b is dropped
                return [0.8, 0.2, 0.0]
            # anchor_c is orthogonal to anchor_a → cosine = 0 ≤ theta_inter, so it's kept
            return [0.0, 0.0, 1.0]

        self.attack._embed = mock_embed
        result = self.attack._init_anchors("HR records")
        assert "anchor_a" in result
        assert "anchor_b" not in result
        assert "anchor_c" in result

    def test_raises_if_empty_after_filtering(self):
        self._stub_llm(["irrelevant"])
        self.attack._embed = lambda text: [0.0, 1.0] if text != "HR records" else [1.0, 0.0]
        with pytest.raises(ValueError, match="empty set"):
            self.attack._init_anchors("HR records")


# ---------------------------------------------------------------------------
# _init_anchors — anchor cache (added 2026-07-13)
# ---------------------------------------------------------------------------

class TestAnchorCache:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack.theta_top = 0.0
        self.attack.theta_inter = 0.9
        self.attack._embed = lambda text: [1.0, 0.0]

    def _stub_llm(self, anchors: list[str]) -> None:
        payload = json.dumps({"anchor words": anchors})
        self.attack.llm = lambda msgs, **kw: payload

    def test_cache_miss_generates_and_writes_cache_file(self, tmp_path):
        cache_file = tmp_path / "topic.json"
        self._stub_llm(["anchor_a"])
        with patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path", return_value=cache_file
        ):
            result = self.attack._init_anchors("HR records")
        assert result == ["anchor_a"]
        assert cache_file.exists()
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        assert data["topic"] == "HR records"
        assert data["anchors"] == ["anchor_a"]
        assert "generated_at" in data

    def test_cache_hit_skips_llm_call(self, tmp_path):
        cache_file = tmp_path / "topic.json"
        cache_file.write_text(
            json.dumps({
                "topic": "HR records",
                "anchors": ["cached_anchor"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }),
            encoding="utf-8",
        )
        self.attack.llm = MagicMock(side_effect=AssertionError("should not call LLM"))
        with patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path", return_value=cache_file
        ):
            result = self.attack._init_anchors("HR records")
        assert result == ["cached_anchor"]
        self.attack.llm.assert_not_called()

    def test_stale_cache_triggers_regeneration(self, tmp_path):
        # TTL is 7 days (raised from 24h on 2026-07-13) — use 8 days to
        # exercise staleness under the current default.
        cache_file = tmp_path / "topic.json"
        stale_time = datetime.now(timezone.utc) - timedelta(days=8)
        cache_file.write_text(
            json.dumps({
                "topic": "HR records",
                "anchors": ["stale_anchor"],
                "generated_at": stale_time.isoformat(),
            }),
            encoding="utf-8",
        )
        self._stub_llm(["fresh_anchor"])
        with patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path", return_value=cache_file
        ):
            result = self.attack._init_anchors("HR records")
        assert result == ["fresh_anchor"]

    def test_within_7_day_ttl_cache_still_used(self, tmp_path):
        cache_file = tmp_path / "topic.json"
        recent_time = datetime.now(timezone.utc) - timedelta(days=6)
        cache_file.write_text(
            json.dumps({
                "topic": "HR records",
                "anchors": ["cached_anchor"],
                "generated_at": recent_time.isoformat(),
            }),
            encoding="utf-8",
        )
        self.attack.llm = MagicMock(side_effect=AssertionError("should not call LLM"))
        with patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path", return_value=cache_file
        ):
            result = self.attack._init_anchors("HR records")
        assert result == ["cached_anchor"]

    def test_force_refresh_skips_fresh_cache(self, tmp_path):
        cache_file = tmp_path / "topic.json"
        cache_file.write_text(
            json.dumps({
                "topic": "HR records",
                "anchors": ["cached_anchor"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }),
            encoding="utf-8",
        )
        self._stub_llm(["fresh_anchor"])
        with patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path", return_value=cache_file
        ):
            result = self.attack._init_anchors("HR records", force_refresh=True)
        assert result == ["fresh_anchor"]


# ---------------------------------------------------------------------------
# _generate_query
# ---------------------------------------------------------------------------

class TestGenerateQuery:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack.theta_anchor = 0.5

    def _stub_llm(self, questions: list[str]) -> None:
        payload = json.dumps({"questions": questions})
        self.attack.llm = lambda msgs, **kw: payload

    def test_returns_best_candidate(self):
        # q1 has sim 0.9 to anchor; q2 has sim 0.6 — should return q1
        self._stub_llm(["q1", "q2"])

        def mock_embed(text: str) -> list[float]:
            if text == "salary":
                return [1.0, 0.0]
            if text == "q1":
                return [0.9, 0.1]   # high sim to anchor
            return [0.6, 0.4]       # q2: lower sim

        self.attack._embed = mock_embed
        result = self.attack._generate_query("salary", "HR records")
        assert result == "q1"

    def test_retries_when_no_candidate_passes_threshold(self):
        call_count = {"n": 0}

        def llm_side_effect(msgs, **kw):
            call_count["n"] += 1
            if call_count["n"] < 3:
                return json.dumps({"questions": ["low_q"]})
            return json.dumps({"questions": ["good_q"]})

        self.attack.llm = llm_side_effect

        def mock_embed(text: str) -> list[float]:
            if text == "salary":
                return [1.0, 0.0]
            if text == "good_q":
                return [0.8, 0.2]
            return [0.1, 0.9]  # low_q is below threshold

        self.attack._embed = mock_embed
        result = self.attack._generate_query("salary", "HR records")
        assert result == "good_q"
        assert call_count["n"] == 3

    def test_raises_if_no_candidate_after_all_retries(self):
        self._stub_llm(["weak_q"])
        # weak_q always below theta_anchor
        self.attack._embed = lambda text: [1.0, 0.0] if text == "salary" else [0.0, 1.0]
        with pytest.raises(ValueError, match="theta_anchor"):
            self.attack._generate_query("salary", "HR records")


# ---------------------------------------------------------------------------
# _er_sample
# ---------------------------------------------------------------------------

class TestErSample:
    def setup_method(self):
        self.attack = _make_attack()

    def test_returns_one_anchor_from_set(self):
        d_anchor = ["salary", "performance", "department"]
        self.attack._embed = lambda text: [1.0, 0.0]
        result = self.attack._er_sample(d_anchor, h_t=[])
        assert result in d_anchor

    def test_uniform_on_empty_history(self):
        d_anchor = ["a"]
        self.attack._embed = lambda text: [1.0, 0.0]
        result = self.attack._er_sample(d_anchor, h_t=[])
        assert result == "a"

    def test_penalizes_anchors_near_refused_queries(self):
        # "salary" is close to a refused query; "department" is orthogonal
        refused_q = "tell me salaries"
        self.attack._embed = lambda text: {
            "salary": [1.0, 0.0],
            "department": [0.0, 1.0],
            refused_q: [0.95, 0.05],   # similar to "salary"
            "refusal text": [0.5, 0.5],
        }.get(text, [0.5, 0.5])
        self.attack._is_refusal = lambda text: text == "refusal text"
        self.attack.delta_o = 0.5
        self.attack.p = 100.0  # large penalty
        self.attack.beta = 1.0

        h_t = [(refused_q, "refusal text")]
        # Run many times and check department wins overwhelmingly
        counts = {"salary": 0, "department": 0}
        for _ in range(200):
            result = self.attack._er_sample(["salary", "department"], h_t)
            counts[result] += 1
        assert counts["department"] > counts["salary"]

    def test_penalizes_anchors_near_unrelated_responses(self):
        # "salary" is close to an unrelated query; "name" is orthogonal
        unrelated_q = "ask about pay"
        unrelated_y = "irrelevant answer"  # low sim to q
        self.attack._embed = lambda text: {
            "salary": [1.0, 0.0],
            "name": [0.0, 1.0],
            unrelated_q: [0.9, 0.1],
            unrelated_y: [0.0, 1.0],  # low cosine to q → classified as unrelated
        }.get(text, [0.5, 0.5])
        self.attack._is_refusal = lambda text: False
        self.attack.delta_u = 0.5
        self.attack.kappa = 100.0
        self.attack.theta_u = 0.5

        h_t = [(unrelated_q, unrelated_y)]
        counts = {"salary": 0, "name": 0}
        for _ in range(200):
            result = self.attack._er_sample(["salary", "name"], h_t)
            counts[result] += 1
        assert counts["name"] > counts["salary"]


# ---------------------------------------------------------------------------
# _trdm_stop
# ---------------------------------------------------------------------------

class TestTrdmStop:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack._is_refusal = lambda text: text == "REFUSED"
        self.attack.tau_q = 0.8
        self.attack.tau_y = 0.8

    def test_stops_on_refusal(self):
        self.attack._embed = lambda text: [1.0, 0.0]
        assert self.attack._trdm_stop("q", "REFUSED", []) is True

    def test_false_on_empty_history_good_response(self):
        self.attack._embed = lambda text: [1.0, 0.0]
        assert self.attack._trdm_stop("q", "good response", []) is False

    def test_stops_when_query_too_similar_to_history(self):
        # Current q is nearly identical to a previous query in h_l_prev
        self.attack._embed = lambda text: {
            "q_new": [1.0, 0.0],
            "q_old": [0.99, 0.01],   # cosine ≈ 1.0 > tau_q
            "y_old": [0.0, 1.0],
        }.get(text, [0.5, 0.5])
        assert self.attack._trdm_stop(
            "q_new", "good", [("q_old", "y_old")]
        ) is True

    def test_stops_when_response_too_similar_to_history(self):
        self.attack._embed = lambda text: {
            "q_new": [0.0, 1.0],
            "q_old": [1.0, 0.0],     # orthogonal to q_new — query check passes
            "y_new": [1.0, 0.0],
            "y_old": [0.99, 0.01],   # almost identical to y_new
        }.get(text, [0.5, 0.5])
        assert self.attack._trdm_stop(
            "q_new", "y_new", [("q_old", "y_old")]
        ) is True

    def test_continues_when_sufficiently_different(self):
        self.attack._embed = lambda text: {
            "q_new": [1.0, 0.0, 0.0],
            "q_old": [0.0, 1.0, 0.0],   # orthogonal
            "y_new": [0.0, 0.0, 1.0],
            "y_old": [0.0, 1.0, 0.0],   # orthogonal to y_new
        }.get(text, [0.5, 0.5, 0.0])
        assert self.attack._trdm_stop(
            "q_new", "y_new", [("q_old", "y_old")]
        ) is False


# ---------------------------------------------------------------------------
# _trdm_mutate
# ---------------------------------------------------------------------------

class TestTrdmMutate:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack.gamma = 0.5
        self.attack.n_mutation_candidates = 3

    def _stub_llm(self, anchors: list[str]) -> None:
        payload = json.dumps({"anchor words": anchors})
        self.attack.llm = lambda msgs, **kw: payload

    def test_returns_argmin_query_similarity_in_trust_region(self):
        # q → [1,0], y → [0,1], s(q,y)=0, trust_threshold = 0.5*0 = 0
        # All candidates qualify (s(w,y) >= 0); pick one closest to q
        # cand_a: [0.9, 0.1] — high sim to q (avoid)
        # cand_b: [0.1, 0.9] — low sim to q (prefer) ← argmin
        self.attack._embed = lambda text: {
            "q": [1.0, 0.0],
            "y": [0.0, 1.0],
            "cand_a": [0.9, 0.1],
            "cand_b": [0.1, 0.9],
            "cand_c": [0.5, 0.5],
        }.get(text, [0.5, 0.5])
        self._stub_llm(["cand_a", "cand_b", "cand_c"])
        result = self.attack._trdm_mutate("q", "y", "HR records")
        assert result == "cand_b"

    def test_returns_none_when_trust_region_empty(self):
        # gamma * s(q,y) is very high; no candidate qualifies
        self.attack.gamma = 2.0  # trust_threshold = 2 * s(q,y) > any real cosine
        self.attack._embed = lambda text: {
            "q": [1.0, 0.0],
            "y": [0.8, 0.6],
            "cand": [0.0, 1.0],  # s(cand, y) = 0.6; threshold = 2*0.8 = 1.6 → fails
        }.get(text, [0.5, 0.5])
        self._stub_llm(["cand"])
        assert self.attack._trdm_mutate("q", "y", "HR records") is None

    def test_returns_none_on_llm_json_failure(self):
        self.attack.llm = lambda msgs, **kw: "not json"
        self.attack._embed = lambda text: [1.0, 0.0]
        assert self.attack._trdm_mutate("q", "y", "HR records") is None


# ---------------------------------------------------------------------------
# _mutate_and_generate_query (combined TRDM mutation + query gen, 2026-07-13)
# ---------------------------------------------------------------------------

class TestMutateAndGenerateQuery:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack.gamma = 0.5
        self.attack.theta_anchor = 0.5
        self.attack.n_mutation_candidates = 3

    def _stub_llm(self, mutations: list[dict]) -> None:
        payload = json.dumps({"mutations": mutations})
        self.attack.llm = lambda msgs, **kw: payload

    def test_returns_winning_anchor_and_query(self):
        # q -> [1,0], y -> [0,1], s(q,y)=0, trust_threshold = 0.5*0 = 0
        # both anchors qualify; cand_b is farther from q (argmin) -> winner
        self.attack._embed = lambda text: {
            "q": [1.0, 0.0],
            "y": [0.0, 1.0],
            "cand_a": [0.9, 0.1],
            "cand_b": [0.1, 0.9],
            "q_for_b": [0.1, 0.9],   # close to cand_b -> passes theta_anchor
        }.get(text, [0.5, 0.5])
        self._stub_llm([
            {"anchor": "cand_a", "questions": ["q_for_a"]},
            {"anchor": "cand_b", "questions": ["q_for_b"]},
        ])
        result = self.attack._mutate_and_generate_query("q", "y", "HR records")
        assert result == ("cand_b", "q_for_b")

    def test_returns_none_when_no_anchor_in_trust_region(self):
        self.attack.gamma = 2.0  # trust_threshold way above any real cosine
        self.attack._embed = lambda text: {
            "q": [1.0, 0.0],
            "y": [0.8, 0.6],
            "cand": [0.0, 1.0],
        }.get(text, [0.5, 0.5])
        self._stub_llm([{"anchor": "cand", "questions": ["some question"]}])
        assert self.attack._mutate_and_generate_query("q", "y", "HR records") is None

    def test_returns_none_when_winning_anchors_questions_all_fail_theta_anchor(self):
        self.attack._embed = lambda text: {
            "q": [1.0, 0.0],
            "y": [0.0, 1.0],
            "cand": [0.1, 0.9],
            "bad_question": [1.0, 0.0],  # orthogonal to cand's own embedding
        }.get(text, [0.5, 0.5])
        self._stub_llm([{"anchor": "cand", "questions": ["bad_question"]}])
        assert self.attack._mutate_and_generate_query("q", "y", "HR records") is None

    def test_returns_none_on_invalid_json_after_retries(self):
        self.attack.llm = lambda msgs, **kw: "not json"
        self.attack._embed = lambda text: [1.0, 0.0]
        assert self.attack._mutate_and_generate_query("q", "y", "HR records") is None

    def test_returns_none_when_mutations_key_missing(self):
        self.attack.llm = lambda msgs, **kw: json.dumps({"other_key": []})
        self.attack._embed = lambda text: [1.0, 0.0]
        assert self.attack._mutate_and_generate_query("q", "y", "HR records") is None

    def test_increments_llm_call_count_once_per_attempt(self):
        self.attack.llm = lambda msgs, **kw: "not json"
        self.attack._embed = lambda text: [1.0, 0.0]
        before = self.attack._llm_call_count
        self.attack._mutate_and_generate_query("q", "y", "HR records")
        # 3 retries on failure, matching _generate_query's retry budget.
        assert self.attack._llm_call_count == before + 3


# ---------------------------------------------------------------------------
# _extract_json_object
# ---------------------------------------------------------------------------

class TestExtractJsonObject:
    def test_plain_json_object(self):
        raw = '{"leak_type": "pii", "severity": "critical"}'
        assert _extract_json_object(raw) == {"leak_type": "pii", "severity": "critical"}

    def test_markdown_fenced(self):
        raw = '```json\n{"leak_type": "none", "severity": "none"}\n```'
        assert _extract_json_object(raw) == {"leak_type": "none", "severity": "none"}

    def test_non_object_raises(self):
        with pytest.raises(ValueError, match="Expected a JSON object"):
            _extract_json_object('["not", "an", "object"]')

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _extract_json_object("not json at all")


# ---------------------------------------------------------------------------
# _severity_to_float / _recommendation_for
# ---------------------------------------------------------------------------

class TestSeverityToFloat:
    @pytest.mark.parametrize("severity,expected", [
        ("critical", 0.90),
        ("high", 0.75),
        ("medium", 0.55),
        ("low", 0.30),
        ("none", 0.10),
    ])
    def test_known_severities(self, severity, expected):
        assert _severity_to_float(severity) == expected

    def test_unknown_severity_defaults_low(self):
        assert _severity_to_float("garbage") == 0.30


class TestRecommendationFor:
    def test_leak_type_takes_priority(self):
        rec = _recommendation_for("pii", "critical")
        assert "IMMEDIATE" in rec
        assert "PII redaction" in rec

    def test_verbatim_leak_type(self):
        assert "output similarity detection" in _recommendation_for("verbatim", "critical")

    def test_sensitive_data_leak_type(self):
        assert "semantic filtering" in _recommendation_for("sensitive_data", "high")

    def test_schema_leak_type(self):
        assert "system prompt" in _recommendation_for("schema", "medium")

    def test_none_leak_type(self):
        assert _recommendation_for("none", "none") == "No action required for this finding."

    def test_unknown_leak_type_falls_back_to_severity(self):
        # The _classify_leak failure fallback always pairs "unknown" with
        # severity="low" — this must resolve via the severity lookup.
        rec = _recommendation_for("unknown", "low")
        assert "benign exfiltration" in rec

    def test_unrecognized_combination_uses_default(self):
        rec = _recommendation_for("something_else", "also_unknown")
        assert rec == (
            "Review manually — leak classification returned an unrecognized "
            "result; treat with caution until confirmed."
        )


# ---------------------------------------------------------------------------
# _classify_leak
# ---------------------------------------------------------------------------

class TestClassifyLeak:
    def setup_method(self):
        self.attack = _make_attack()

    def _classification(self, **overrides):
        base = {
            "leak_type": "pii",
            "contains_pii": True,
            "contains_sensitive_data": True,
            "reveals_schema": False,
            "appears_record_specific": True,
            "severity": "critical",
            "evidence": "SSN: 423-58-9167",
            "reasoning": "Response discloses a specific SSN.",
        }
        base.update(overrides)
        return json.dumps(base)

    def test_valid_classification_returned_as_is(self):
        self.attack.llm = lambda msgs, **kw: self._classification()
        result = self.attack._classify_leak("q", "y", "HR records")
        assert result["leak_type"] == "pii"
        assert result["severity"] == "critical"
        assert result["evidence"] == "SSN: 423-58-9167"

    def test_markdown_fenced_response_parsed(self):
        self.attack.llm = lambda msgs, **kw: f"```json\n{self._classification()}\n```"
        result = self.attack._classify_leak("q", "y", "HR records")
        assert result["leak_type"] == "pii"

    def test_invalid_json_falls_back_to_low(self):
        self.attack.llm = lambda msgs, **kw: "not json"
        result = self.attack._classify_leak("q", "y", "HR records")
        assert result["severity"] == "low"
        assert result["leak_type"] == "unknown"
        assert result["evidence"] is None

    def test_invalid_severity_falls_back_to_low(self):
        self.attack.llm = lambda msgs, **kw: self._classification(severity="extreme")
        result = self.attack._classify_leak("q", "y", "HR records")
        assert result["severity"] == "low"
        assert result["leak_type"] == "unknown"

    def test_invalid_leak_type_falls_back_to_low(self):
        self.attack.llm = lambda msgs, **kw: self._classification(leak_type="made_up")
        result = self.attack._classify_leak("q", "y", "HR records")
        assert result["severity"] == "low"
        assert result["leak_type"] == "unknown"

    def test_llm_exception_never_propagates(self):
        self.attack.llm = MagicMock(side_effect=RuntimeError("API down"))
        result = self.attack._classify_leak("q", "y", "HR records")
        assert result["severity"] == "low"
        assert result["leak_type"] == "unknown"

    def test_increments_llm_call_count(self):
        self.attack.llm = lambda msgs, **kw: self._classification()
        before = self.attack._llm_call_count
        self.attack._classify_leak("q", "y", "HR records")
        assert self.attack._llm_call_count == before + 1

    def test_domain_and_response_interpolated_into_prompt(self):
        captured = {}

        def llm(msgs, **kw):
            captured["prompt"] = msgs[0]["content"]
            return self._classification()

        self.attack.llm = llm
        self.attack._classify_leak("q", "the response text", "patient medical consultations")
        assert "patient medical consultations" in captured["prompt"]
        assert "the response text" in captured["prompt"]


# ---------------------------------------------------------------------------
# _make_finding
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def setup_method(self):
        self.attack = _make_attack()

    def _stub_classify(self, **overrides):
        result = {
            "leak_type": "pii",
            "severity": "critical",
            "evidence": "SSN: 423-58-9167",
            "reasoning": "Discloses a specific SSN.",
        }
        result.update(overrides)
        self.attack._classify_leak = MagicMock(return_value=result)
        return result

    def test_all_fields_present(self):
        self._stub_classify()
        finding = self.attack._make_finding("probe query", "response text", "HR records")
        assert finding.attack_type == "DRA"
        assert finding.tier_used == "black_box"
        assert finding.probe_used == "probe query"
        assert isinstance(finding.confidence, float)
        assert finding.severity in ("critical", "high", "medium", "low", "none")
        assert len(finding.recommendation) > 0

    def test_domain_passed_through_to_classifier(self):
        self._stub_classify()
        self.attack._make_finding("q", "y", "patient medical consultations")
        self.attack._classify_leak.assert_called_once_with("q", "y", "patient medical consultations")

    def test_confidence_derived_from_severity_not_cosine(self):
        # Confidence must equal _severity_to_float(severity), regardless of
        # what _embed returns — the old cosine-based path is gone entirely.
        self.attack._embed = lambda text: [1.0, 0.0]  # would have been cosine=1.0
        self._stub_classify(severity="medium")
        finding = self.attack._make_finding("q", "y", "HR records")
        assert finding.severity == "medium"
        assert finding.confidence == pytest.approx(0.55)

    def test_leaked_content_uses_evidence_quote(self):
        self._stub_classify(evidence="SSN: 423-58-9167")
        finding = self.attack._make_finding("q", "full response text here", "HR records")
        assert finding.leaked_content == "SSN: 423-58-9167"
        assert finding.full_response == "full response text here"

    def test_leaked_content_falls_back_to_truncated_response_when_no_evidence(self):
        long_response = "x" * 500
        self._stub_classify(evidence=None)
        finding = self.attack._make_finding("q", long_response, "HR records")
        assert finding.leaked_content == long_response[:300]
        assert len(finding.leaked_content) == 300

    def test_confirmed_true_for_pii_verbatim_and_sensitive_data(self):
        # sensitive_data added 2026-07-17: it represents an actual data
        # disclosure (diagnoses, financials, HR decisions — see the
        # classifier prompt's severity guide), just without a full
        # identifiable individual attached the way "pii" requires. Only
        # "schema" (structure/field names, no real data) and "none"/
        # "unknown" (no disclosure) should stay unconfirmed.
        for lt in ("pii", "verbatim", "sensitive_data"):
            self._stub_classify(leak_type=lt)
            finding = self.attack._make_finding("q", "y", "HR records")
            assert finding.confirmed is True, lt

    def test_confirmed_false_for_other_leak_types(self):
        for lt in ("none", "schema", "unknown"):
            self._stub_classify(leak_type=lt)
            finding = self.attack._make_finding("q", "y", "HR records")
            assert finding.confirmed is False, lt

    def test_leak_type_and_reasoning_stored(self):
        self._stub_classify(leak_type="sensitive_data", reasoning="Discloses a diagnosis.")
        finding = self.attack._make_finding("q", "y", "HR records")
        assert finding.leak_type == "sensitive_data"
        assert finding.reasoning == "Discloses a diagnosis."

    def test_recommendation_matches_leak_type(self):
        self._stub_classify(leak_type="pii", severity="critical")
        finding = self.attack._make_finding("q", "y", "HR records")
        assert "IMMEDIATE" in finding.recommendation
        assert "PII redaction" in finding.recommendation


# ---------------------------------------------------------------------------
# leak_prefilter (added 2026-07-13)
# ---------------------------------------------------------------------------

class TestLeakPrefilter:
    def setup_method(self):
        self.attack = _make_attack()
        self.attack._classify_leak = MagicMock(return_value={
            "leak_type": "pii", "severity": "critical",
            "evidence": "SSN: 423-58-9167", "reasoning": "real classification",
        })

    def test_none_prefilter_always_classifies(self):
        # Default (no prefilter configured) — unchanged behavior.
        assert self.attack.leak_prefilter is None
        finding = self.attack._make_finding("q", "y", "HR records")
        self.attack._classify_leak.assert_called_once()
        assert finding.leak_type == "pii"
        assert self.attack.prefilter_skips == 0

    def test_prefilter_true_still_classifies(self):
        self.attack.leak_prefilter = lambda text: True
        finding = self.attack._make_finding("q", "y", "HR records")
        self.attack._classify_leak.assert_called_once()
        assert finding.leak_type == "pii"
        assert self.attack.prefilter_skips == 0

    def test_prefilter_false_skips_classification(self):
        self.attack.leak_prefilter = lambda text: False
        finding = self.attack._make_finding("q", "irrelevant response", "HR records")
        self.attack._classify_leak.assert_not_called()
        assert finding.leak_type == "none"
        assert finding.severity == "none"
        assert finding.confirmed is False
        assert self.attack.prefilter_skips == 1

    def test_prefilter_receives_the_response_text(self):
        seen = {}
        self.attack.leak_prefilter = lambda text: seen.setdefault("text", text) and False
        self.attack._make_finding("q", "the actual agent response", "HR records")
        assert seen["text"] == "the actual agent response"

    def test_prefilter_skips_counted_across_multiple_findings(self):
        self.attack.leak_prefilter = lambda text: "keep" in text
        self.attack._make_finding("q1", "skip me", "HR records")
        self.attack._make_finding("q2", "keep me", "HR records")
        self.attack._make_finding("q3", "skip me too", "HR records")
        assert self.attack.prefilter_skips == 2
        assert self.attack._classify_leak.call_count == 1

    def test_prefilter_reset_per_execute_black_box_run(self):
        # Reuses the same _make_attack() pattern as TestExecuteBlackBox but
        # only checks the counter reset, not the full loop.
        self.attack.prefilter_skips = 7
        self.attack._llm_call_count = 3
        with patch.object(AgentEndpoint, "check_reachable", return_value=False):
            with pytest.raises(RuntimeError):
                self.attack.execute_black_box(topic="HR records", max_queries=1)
        assert self.attack.prefilter_skips == 0


# ---------------------------------------------------------------------------
# _llm_cap_reached
# ---------------------------------------------------------------------------

class TestLlmCapReached:
    def setup_method(self):
        self.attack = _make_attack()

    def test_false_below_cap(self):
        self.attack._llm_call_count = 5
        assert self.attack._llm_cap_reached(10) is False

    def test_true_at_cap(self):
        self.attack._llm_call_count = 10
        assert self.attack._llm_cap_reached(10) is True

    def test_true_above_cap(self):
        self.attack._llm_call_count = 15
        assert self.attack._llm_cap_reached(10) is True

    def test_logs_warning_when_reached(self, caplog):
        import logging
        self.attack._llm_call_count = 10
        with caplog.at_level(logging.WARNING):
            self.attack._llm_cap_reached(10)
        assert any("LLM CAP" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# execute_black_box
# ---------------------------------------------------------------------------

class TestExecuteBlackBox:
    def setup_method(self):
        self.attack = _make_attack(topic="HR records")
        # execute_black_box calls the real _init_anchors, which reads/writes
        # the anchor cache — isolate to a throwaway path so this suite never
        # touches the real .cache/ikea_anchors/ directory (see TestAnchorCache
        # for dedicated cache-behavior coverage).
        self._cache_patcher = patch(
            "aginiti.attacks.dra.ikea._anchor_cache_path",
            side_effect=lambda topic: Path(tempfile.gettempdir())
            / f"ikea_test_cache_{uuid.uuid4().hex}.json",
        )
        self._cache_patcher.start()

    def teardown_method(self):
        self._cache_patcher.stop()

    def _stub_attack(
        self,
        anchor_response: str = '{"anchor words": ["salary"]}',
        query_response: str = '{"questions": ["What are employee salaries?"]}',
        agent_response: str = "Emma Thompson earns $152,000.",
        classify_response: str = json.dumps({
            "leak_type": "sensitive_data",
            "contains_pii": False,
            "contains_sensitive_data": True,
            "reveals_schema": False,
            "appears_record_specific": True,
            "severity": "high",
            "evidence": None,
            "reasoning": "test reasoning",
        }),
        n_chains: int = 1,
    ):
        """Wire minimal mocks for one complete ERS→query→chat→TRDM cycle."""
        call_count = {"n": 0}

        def llm_side_effect(msgs, **kw):
            prompt = msgs[0]["content"]
            if "leak_type" in prompt:
                return classify_response
            if "anchor words" in prompt and "Query" not in prompt:
                return anchor_response
            if "questions" in prompt:
                return query_response
            # TRDM mutation (returns None-triggering bad JSON after n_chains chains)
            return "not json"

        self.attack.llm = llm_side_effect
        # Embeddings: everything similar enough to pass all thresholds
        self.attack._embed = lambda text: [1.0, 0.0]
        self.attack._is_refusal = lambda text: False

        return agent_response

    def test_returns_list_of_leak_findings(self):
        agent_resp = self._stub_attack()
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value=agent_resp):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=2)
        assert isinstance(findings, list)
        assert all(isinstance(f, LeakFinding) for f in findings)

    def test_skips_refused_responses(self):
        self._stub_attack(agent_response="I don't know.")
        self.attack._is_refusal = lambda text: "don't know" in text.lower()
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="I don't know."):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=3)
        # Refused responses should not appear as findings
        assert all("don't know" not in f.leaked_content.lower() for f in findings)

    def test_respects_max_queries(self):
        self._stub_attack()
        max_q = 5
        call_log = []

        def chat_side_effect(msg, **kw):
            call_log.append(msg)
            return "Employee record: Name: John Doe."

        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", side_effect=chat_side_effect):
            self.attack.execute_black_box(topic="HR records", max_queries=max_q)

        assert len(call_log) <= max_q

    def test_raises_on_empty_topic(self):
        attack = _make_attack(topic="")
        with pytest.raises(ValueError, match="topic must be provided"):
            attack.execute_black_box()

    def test_raises_on_empty_topic_kwarg(self):
        attack = _make_attack(topic="")
        with pytest.raises(ValueError, match="topic must be provided"):
            attack.execute_black_box(topic="")

    def test_topic_kwarg_overrides_init_topic(self):
        self._stub_attack()
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="Some record."):
            # Should not raise even though init topic is "HR records"
            findings = self.attack.execute_black_box(topic="patient records", max_queries=2)
        assert isinstance(findings, list)

    def test_finding_fields_correct(self):
        agent_resp = "Emma Thompson earns $152,000."
        self._stub_attack(agent_response=agent_resp)
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value=agent_resp):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=2)
        if findings:
            f = findings[0]
            assert f.attack_type == "DRA"
            assert f.tier_used == "black_box"
            assert f.confirmed is True
            assert f.trace_span_id == ""
            assert f.leaked_content == agent_resp

    def test_endpoint_closed_after_run(self):
        self._stub_attack()
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="some response"), \
             patch.object(AgentEndpoint, "close") as mock_close:
            self.attack.execute_black_box(topic="HR records", max_queries=2)
        mock_close.assert_called_once()

    def test_max_llm_calls_stops_loop_early(self, caplog):
        # Every chain in this stub ends after 1 probe anyway (the combined
        # mutate+query call always fails -> "not json" fallback), so without
        # a cap this would run all 50 probes. A very low cap must stop it
        # far short of that, having burned no more than a small, bounded
        # number of extra calls past the threshold.
        self._stub_attack()
        self.attack.max_llm_calls = 3
        import logging
        with caplog.at_level(logging.WARNING), \
             patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="some response"):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=50)
        assert len(findings) < 50
        assert self.attack._llm_call_count < 15  # bounded overshoot, not unbounded
        assert any("LLM CAP" in r.message or "max_llm_calls" in r.message for r in caplog.records)

    def test_max_llm_calls_default_auto_scales_with_max_queries(self):
        self._stub_attack()
        assert self.attack.max_llm_calls is None
        # Sanity: with the generous auto default (max_q * 8), a tiny 2-query
        # run must complete normally, without early-stopping.
        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", return_value="some response"):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=2)
        assert len(findings) <= 2

    def test_max_trdm_iterations_caps_a_chain(self):
        # Craft embeddings so _trdm_stop never fires (every distinct text
        # gets its own orthogonal vector) and the combined mutate+query call
        # always succeeds, so the ONLY thing that can end a chain is the
        # hard iteration cap — without it, one chain would run to
        # max_queries in a single unbroken pass.
        self.attack.max_trdm_iterations = 2
        self.attack.theta_top = 0.0
        self.attack.theta_anchor = 0.0
        self.attack.gamma = 0.0

        vec_cache: dict[str, list[float]] = {}
        counter = {"n": 0}

        def fresh_vec(text):
            if text not in vec_cache:
                idx = counter["n"]
                counter["n"] += 1
                v = [0.0] * (idx + 1)
                v[idx] = 1.0
                vec_cache[text] = v
            return vec_cache[text]

        self.attack._embed = fresh_vec
        self.attack._is_refusal = lambda text: False

        mutation_call_n = {"n": 0}
        query_gen_call_n = {"n": 0}

        def llm_side_effect(msgs, **kw):
            prompt = msgs[0]["content"]
            if "leak_type" in prompt:
                return json.dumps({
                    "leak_type": "none", "contains_pii": False,
                    "contains_sensitive_data": False, "reveals_schema": False,
                    "appears_record_specific": False, "severity": "none",
                    "evidence": None, "reasoning": "no leak",
                })
            if "For EACH keyword concept" in prompt:
                mutation_call_n["n"] += 1
                n = mutation_call_n["n"]
                return json.dumps({"mutations": [
                    {"anchor": f"anchor_{n}", "questions": [f"question_{n}"]}
                ]})
            if "anchor words" in prompt and "Query" not in prompt:
                return json.dumps({"anchor words": ["initial_anchor"]})
            if "questions" in prompt:
                query_gen_call_n["n"] += 1
                return json.dumps({"questions": [f"initial_question_{query_gen_call_n['n']}"]})
            return "not json"

        self.attack.llm = llm_side_effect

        chat_call_n = {"n": 0}

        def chat_side_effect(msg, **kw):
            chat_call_n["n"] += 1
            return f"response_{chat_call_n['n']}"

        with patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", side_effect=chat_side_effect):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=20)

        assert len(findings) == 20
        # If the iteration cap were NOT enforced, this stub would sustain a
        # single unbroken chain all the way to max_queries=20, so
        # _generate_query's initial-of-chain path would fire exactly once.
        # With max_trdm_iterations=2 (chain length capped at 3 probes),
        # multiple chains must have started instead.
        assert query_gen_call_n["n"] > 1

    def test_persistent_llm_failure_degrades_to_partial_findings(self, caplog):
        # Added 2026-07-13: a live run showed litellm.RateLimitError (raised
        # by BaseAttack._call after retries+failover are exhausted — see
        # aginiti/attacks/base.py) propagating straight out of
        # execute_black_box uncaught, crashing the whole attack with ZERO
        # findings saved even though several had already been collected.
        # This must now degrade gracefully: keep whatever findings exist,
        # stop the loop, and return normally instead of raising.
        self._stub_attack()
        chat_call_n = {"n": 0}

        def chat_side_effect(msg, **kw):
            chat_call_n["n"] += 1
            return "Emma Thompson earns $152,000."

        def llm_side_effect(msgs, **kw):
            prompt = msgs[0]["content"]
            if "leak_type" in prompt:
                return json.dumps({
                    "leak_type": "sensitive_data", "contains_pii": False,
                    "contains_sensitive_data": True, "reveals_schema": False,
                    "appears_record_specific": True, "severity": "high",
                    "evidence": None, "reasoning": "test",
                })
            if "anchor words" in prompt and "Query" not in prompt:
                return '{"anchor words": ["salary", "benefits", "bonus"]}'
            if "questions" in prompt:
                # First anchor's query generation succeeds; every call after
                # that raises, simulating the attacker LLM becoming
                # permanently unavailable mid-run (e.g. a TPD exhaustion with
                # no fallback provider configured).
                if chat_call_n["n"] == 0:
                    return '{"questions": ["What are employee salaries?"]}'
                raise litellm.RateLimitError(
                    message="rate limit exceeded, try again in 7m12s",
                    llm_provider="groq", model="llama-3.3-70b-versatile",
                )
            return "not json"

        self.attack.llm = llm_side_effect
        self.attack._embed = lambda text: [1.0, 0.0]
        self.attack._is_refusal = lambda text: False
        self.attack.max_trdm_iterations = 0  # force a fresh chain (and fresh
                                              # _generate_query call) every probe

        import logging
        with caplog.at_level(logging.ERROR), \
             patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat", side_effect=chat_side_effect):
            findings = self.attack.execute_black_box(topic="HR records", max_queries=50)

        # Must NOT raise — must return whatever it collected before the LLM
        # became unavailable, with 0 < len(findings) < 50 (proof it stopped
        # early rather than either crashing or somehow completing all 50).
        assert isinstance(findings, list)
        assert 0 < len(findings) < 50
        assert any("LLM UNAVAILABLE" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# execute() dispatch
# ---------------------------------------------------------------------------

class TestExecuteDispatch:
    def test_dispatches_to_black_box_without_otel(self):
        attack = _make_attack(topic="HR records")
        with patch.object(attack, "execute_black_box", return_value=[]) as mock_bb:
            attack.execute(topic="HR records")
        mock_bb.assert_called_once_with(topic="HR records")

    def test_dispatches_to_traces_with_otel(self):
        mock_otel = MagicMock()
        attack = _make_attack(topic="HR records", otel_ingester=mock_otel)
        with patch.object(attack, "execute_with_traces", return_value=[]) as mock_tr:
            attack.execute(topic="HR records")
        mock_tr.assert_called_once_with(topic="HR records")


# ---------------------------------------------------------------------------
# execute_with_traces
# ---------------------------------------------------------------------------

class TestExecuteWithTraces:
    def setup_method(self):
        self.mock_otel = MagicMock()
        self.attack = _make_attack(topic="HR records", otel_ingester=self.mock_otel)

    def _sample_finding(self, probe: str = "q", content: str = "y") -> LeakFinding:
        return LeakFinding(
            attack_type="DRA",
            tier_used="black_box",
            confidence=0.7,
            confirmed=False,
            leaked_content=content,
            probe_used=probe,
            trace_span_id="",
            recommendation="test recommendation",
            severity="high",
        )

    def test_calls_execute_black_box_internally(self):
        with patch.object(self.attack, "execute_black_box", return_value=[]) as mock_bb:
            self.attack.execute_with_traces(topic="HR records")
        mock_bb.assert_called_once_with(topic="HR records")

    def test_upgrades_confirmed_when_span_found(self):
        finding = self._sample_finding()
        self.mock_otel.get_retrieval_span_for_query.return_value = {"span_id": "span-abc"}

        with patch.object(self.attack, "execute_black_box", return_value=[finding]):
            results = self.attack.execute_with_traces(topic="HR records")

        assert len(results) == 1
        assert results[0].confirmed is True
        assert results[0].tier_used == "otel"
        assert results[0].severity == "critical"
        assert results[0].trace_span_id == "span-abc"

    def test_finding_unchanged_when_no_span(self):
        finding = self._sample_finding()
        self.mock_otel.get_retrieval_span_for_query.return_value = None

        with patch.object(self.attack, "execute_black_box", return_value=[finding]):
            results = self.attack.execute_with_traces(topic="HR records")

        assert results[0].confirmed is False
        assert results[0].tier_used == "black_box"
        assert results[0].trace_span_id == ""

    def test_mixed_span_results(self):
        f1 = self._sample_finding(probe="q1")
        f2 = self._sample_finding(probe="q2")

        def span_side_effect(query):
            return {"span_id": "span-001"} if query == "q1" else None

        self.mock_otel.get_retrieval_span_for_query.side_effect = span_side_effect

        with patch.object(self.attack, "execute_black_box", return_value=[f1, f2]):
            results = self.attack.execute_with_traces(topic="HR records")

        assert results[0].confirmed is True
        assert results[1].confirmed is False

    def test_original_findings_not_mutated(self):
        finding = self._sample_finding()
        self.mock_otel.get_retrieval_span_for_query.return_value = {"span_id": "s"}

        with patch.object(self.attack, "execute_black_box", return_value=[finding]):
            self.attack.execute_with_traces(topic="HR records")

        # dataclasses.replace() creates a new object — original must be unchanged
        assert finding.confirmed is False
        assert finding.tier_used == "black_box"
