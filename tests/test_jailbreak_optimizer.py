"""
Unit tests for JailbreakOptimizer (aginiti/attacks/dra/jailbreak_optimizer.py)
— SECRET Phase 1.

All LLM calls and HTTP calls to the target agent are mocked — no real API
keys required. Internal orchestration (curriculum two-stage flow, cache
hit/miss) is tested by patching ``_run_algorithm1`` directly, same pattern
``test_ikea.py``/``test_interrogation.py`` use for their own
``execute_black_box`` integration tests (patch the sub-methods, verify
orchestration, not re-derive full LLM output parsing at that layer).

Run:
    pytest tests/test_jailbreak_optimizer.py -v
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aginiti.attacks.dra.jailbreak_optimizer import (
    DEFAULT_EXTRACTION_INSTRUCTION,
    JailbreakArtifact,
    JailbreakOptimizer,
    _jailbreak_cache_key,
    _parse_candidates,
    _parse_score,
)
from aginiti.connectors.endpoint import AgentEndpoint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_optimizer(**overrides) -> JailbreakOptimizer:
    """
    Construct a JailbreakOptimizer with no network calls — __init__ only
    builds LLM closures (via _LLMInitHelper), it never invokes litellm, so
    no patching is needed at construction time (unlike IKEAAttack/
    InterrogationAttack, which don't call litellm at construction either,
    but this is worth stating explicitly since it differs from a naive
    expectation).
    """
    defaults = dict(
        target_url="http://localhost:8001",
        optimizer_llm_provider="gemini/gemini-3.5-flash",
        optimizer_api_key="fake-key",
    )
    defaults.update(overrides)
    return JailbreakOptimizer(**defaults)


def _redirect_cache(monkeypatch, tmp_path):
    def _fake_path(cache_key: str) -> Path:
        return tmp_path / f"{cache_key}.json"
    monkeypatch.setattr(
        "aginiti.attacks.dra.jailbreak_optimizer._jailbreak_cache_path", _fake_path
    )


# ---------------------------------------------------------------------------
# Module-level parsing
# ---------------------------------------------------------------------------

class TestParseScore:
    def test_valid_score(self):
        assert _parse_score("<score>0.85</score>") == 0.85

    def test_score_with_surrounding_text(self):
        assert _parse_score("I think the score is <score>0.5</score> based on...") == 0.5

    def test_integer_score(self):
        assert _parse_score("<score>1</score>") == 1.0

    def test_clamped_above_one(self):
        assert _parse_score("<score>1.5</score>") == 1.0

    def test_clamped_below_zero(self):
        assert _parse_score("<score>-0.3</score>") == 0.0

    def test_missing_tag_returns_zero(self):
        assert _parse_score("I cannot assist with that.") == 0.0

    def test_unparseable_value_returns_zero(self):
        assert _parse_score("<score>not-a-number</score>") == 0.0

    def test_case_insensitive_tag(self):
        assert _parse_score("<SCORE>0.7</SCORE>") == 0.7


class TestParseCandidates:
    def test_single_candidate(self):
        assert _parse_candidates("<answer>Do the thing</answer>") == ["Do the thing"]

    def test_multiple_candidates(self):
        raw = "<answer>First one</answer>\n<answer>Second one</answer>"
        assert _parse_candidates(raw) == ["First one", "Second one"]

    def test_no_candidates(self):
        assert _parse_candidates("I refuse to generate that.") == []

    def test_strips_whitespace(self):
        assert _parse_candidates("<answer>  padded text  </answer>") == ["padded text"]

    def test_empty_answer_tags_skipped(self):
        raw = "<answer></answer><answer>real one</answer>"
        assert _parse_candidates(raw) == ["real one"]

    def test_multiline_candidate(self):
        raw = "<answer>Line one\nLine two</answer>"
        assert _parse_candidates(raw) == ["Line one\nLine two"]


# ---------------------------------------------------------------------------
# Cache key
# ---------------------------------------------------------------------------

class TestJailbreakCacheKey:
    def _base_args(self):
        return dict(
            target_identity="http://localhost:8001",
            optimizer_provider="gemini/gemini-3.5-flash",
            evaluator_provider="gemini/gemini-3.5-flash",
            seed_prompt=DEFAULT_EXTRACTION_INSTRUCTION,
            n_iter=20, n_cand=3, alpha=0.85,
            use_curriculum=False, curriculum_weak_model_provider=None,
        )

    def test_deterministic(self):
        args = self._base_args()
        assert _jailbreak_cache_key(**args) == _jailbreak_cache_key(**args)

    def test_changes_with_target_identity(self):
        a = self._base_args()
        b = {**a, "target_identity": "http://localhost:9999"}
        assert _jailbreak_cache_key(**a) != _jailbreak_cache_key(**b)

    def test_changes_with_alpha(self):
        a = self._base_args()
        b = {**a, "alpha": 0.5}
        assert _jailbreak_cache_key(**a) != _jailbreak_cache_key(**b)

    def test_changes_with_curriculum_flag(self):
        a = self._base_args()
        b = {**a, "use_curriculum": True, "curriculum_weak_model_provider": "gemini/gemini-3.5-flash"}
        assert _jailbreak_cache_key(**a) != _jailbreak_cache_key(**b)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestJailbreakOptimizerInit:
    def test_defaults(self):
        opt = _make_optimizer()
        assert opt.seed_prompt == DEFAULT_EXTRACTION_INSTRUCTION
        assert opt.n_iter == 20
        assert opt.n_cand == 3
        assert opt.alpha == 0.85
        assert opt.use_curriculum is False
        assert callable(opt.optimizer_llm)
        assert callable(opt.evaluator_llm)

    def test_evaluator_defaults_to_optimizer_provider(self):
        opt = _make_optimizer()
        assert opt._evaluator_provider == "gemini/gemini-3.5-flash"

    def test_evaluator_provider_override(self):
        opt = _make_optimizer(evaluator_llm_provider="openai/gpt-4o-mini")
        assert opt._evaluator_provider == "openai/gpt-4o-mini"

    def test_curriculum_requires_weak_model_provider(self):
        with pytest.raises(ValueError, match="curriculum_weak_model_provider"):
            _make_optimizer(use_curriculum=True)

    def test_curriculum_with_weak_model_provider_succeeds(self):
        opt = _make_optimizer(
            use_curriculum=True,
            curriculum_weak_model_provider="gemini/gemini-3.5-flash",
        )
        assert opt.use_curriculum is True

    def test_call_counters_start_at_zero(self):
        opt = _make_optimizer()
        assert opt.optimizer_call_count == 0
        assert opt.evaluator_call_count == 0
        assert opt.target_query_count == 0


# ---------------------------------------------------------------------------
# _format_trajectory
# ---------------------------------------------------------------------------

class TestFormatTrajectory:
    def test_single_entry(self):
        opt = _make_optimizer()
        result = opt._format_trajectory([(0.2, "seed instruction")])
        assert result == 'Step 1: Score=0.2000, Instruction: "seed instruction"'

    def test_multiple_entries_numbered_in_order(self):
        opt = _make_optimizer()
        history = [(0.1, "a"), (0.5, "b"), (0.9, "c")]
        result = opt._format_trajectory(history)
        lines = result.split("\n")
        assert lines[0].startswith("Step 1:")
        assert lines[1].startswith("Step 2:")
        assert lines[2].startswith("Step 3:")
        assert "0.9000" in lines[2]


# ---------------------------------------------------------------------------
# _score_response / _generate_candidates
# ---------------------------------------------------------------------------

class TestScoreResponse:
    def test_calls_evaluator_and_parses(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(return_value="<score>0.65</score>")
        result = opt._score_response("some candidate", "some response")
        assert result == 0.65
        assert opt.evaluator_call_count == 1

    def test_increments_call_count_each_time(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(return_value="<score>0.5</score>")
        opt._score_response("a", "b")
        opt._score_response("c", "d")
        assert opt.evaluator_call_count == 2


class TestGenerateCandidates:
    def test_parses_on_first_attempt(self):
        opt = _make_optimizer()
        opt.optimizer_llm = MagicMock(
            return_value="<answer>cand one</answer><answer>cand two</answer>"
        )
        result = opt._generate_candidates([(0.1, "seed")], n_cand=2)
        assert result == ["cand one", "cand two"]
        assert opt.optimizer_call_count == 1

    def test_retries_on_empty_then_succeeds(self):
        opt = _make_optimizer()
        opt.optimizer_llm = MagicMock(side_effect=[
            "I refuse.",
            "still nothing",
            "<answer>finally worked</answer>",
        ])
        result = opt._generate_candidates([(0.1, "seed")], n_cand=1)
        assert result == ["finally worked"]
        assert opt.optimizer_call_count == 3

    def test_returns_empty_after_exhausting_retries(self):
        opt = _make_optimizer()
        opt.optimizer_llm = MagicMock(return_value="no tags here")
        result = opt._generate_candidates([(0.1, "seed")], n_cand=1)
        assert result == []
        assert opt.optimizer_call_count == 3


# ---------------------------------------------------------------------------
# _run_algorithm1 — Algorithm 1's core loop
# ---------------------------------------------------------------------------

class TestRunAlgorithm1:
    def test_zero_iterations_returns_seed(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(return_value="<score>0.3</score>")
        query_fn = MagicMock(return_value="some response")
        p_e, score, iters, history = opt._run_algorithm1(
            query_fn, "seed prompt", n_iter=0, n_cand=2, alpha=0.85,
        )
        assert p_e == "seed prompt"
        assert score == 0.3
        assert iters == 0
        assert history == [(0.3, "seed prompt")]
        query_fn.assert_called_once_with("seed prompt")

    def test_early_stop_when_candidate_clears_alpha(self):
        opt = _make_optimizer()
        # Seed scores low; iteration 1 produces two candidates, one clears alpha.
        opt.evaluator_llm = MagicMock(side_effect=[
            "<score>0.10</score>",  # seed
            "<score>0.90</score>",  # candidate A
            "<score>0.40</score>",  # candidate B
        ])
        opt.optimizer_llm = MagicMock(
            return_value="<answer>candidate A</answer><answer>candidate B</answer>"
        )
        query_fn = MagicMock(return_value="response text")
        p_e, score, iters, history = opt._run_algorithm1(
            query_fn, "seed prompt", n_iter=20, n_cand=2, alpha=0.85,
        )
        assert p_e == "candidate A"
        assert score == 0.90
        assert iters == 1
        # Selective history update: seed + only the iteration's best candidate.
        assert len(history) == 2

    def test_history_sorted_ascending_by_score(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(side_effect=[
            "<score>0.50</score>",  # seed
            "<score>0.30</score>",  # iter1 best (lower than seed)
            "<score>0.80</score>",  # iter2 best (higher than seed)
        ])
        opt.optimizer_llm = MagicMock(side_effect=[
            "<answer>low candidate</answer>",
            "<answer>high candidate</answer>",
        ])
        query_fn = MagicMock(return_value="resp")
        p_e, score, iters, history = opt._run_algorithm1(
            query_fn, "seed prompt", n_iter=2, n_cand=1, alpha=2.0,  # alpha unreachable
        )
        scores = [s for s, _ in history]
        assert scores == sorted(scores)
        assert iters == 2
        # Best overall (max after ascending sort) must be the highest score seen.
        assert score == 0.80
        assert p_e == "high candidate"

    def test_all_candidates_score_zero_history_unchanged_that_iteration(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(side_effect=[
            "<score>0.20</score>",  # seed
            "<score>0.00</score>",  # candidate scores exactly 0
        ])
        opt.optimizer_llm = MagicMock(return_value="<answer>dud candidate</answer>")
        query_fn = MagicMock(return_value="resp")
        p_e, score, iters, history = opt._run_algorithm1(
            query_fn, "seed prompt", n_iter=1, n_cand=1, alpha=0.85,
        )
        # No candidate exceeded the running best (0.0), so nothing new appended.
        assert len(history) == 1
        assert p_e == "seed prompt"
        assert score == 0.20

    def test_no_candidates_from_optimizer_does_not_crash(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(return_value="<score>0.20</score>")
        opt.optimizer_llm = MagicMock(return_value="no answer tags at all")
        query_fn = MagicMock(return_value="resp")
        p_e, score, iters, history = opt._run_algorithm1(
            query_fn, "seed prompt", n_iter=1, n_cand=2, alpha=0.85,
        )
        assert p_e == "seed prompt"
        assert len(history) == 1
        # query_fn was only called once, for the seed — never for candidates,
        # since none were generated.
        query_fn.assert_called_once_with("seed prompt")

    def test_runs_full_n_iter_when_alpha_unreachable(self):
        opt = _make_optimizer()
        opt.evaluator_llm = MagicMock(return_value="<score>0.10</score>")
        opt.optimizer_llm = MagicMock(return_value="<answer>candidate</answer>")
        query_fn = MagicMock(return_value="resp")
        _p_e, _score, iters, _history = opt._run_algorithm1(
            query_fn, "seed prompt", n_iter=3, n_cand=1, alpha=0.99,
        )
        assert iters == 3


# ---------------------------------------------------------------------------
# optimize() — cache + orchestration
# ---------------------------------------------------------------------------

class TestOptimizeCache:
    def test_cache_hit_skips_network_entirely(self, monkeypatch, tmp_path):
        opt = _make_optimizer()
        _redirect_cache(monkeypatch, tmp_path)
        cache_key = _jailbreak_cache_key(
            opt.target_url, opt._optimizer_provider, opt._evaluator_provider,
            opt.seed_prompt, opt.n_iter, opt.n_cand, opt.alpha,
            opt.use_curriculum, opt._curriculum_weak_model_provider,
        )
        artifact = JailbreakArtifact(
            p_e_star="cached prompt", score=0.91, target_identity=opt.target_url,
            iterations_used=4, used_curriculum=False,
            optimizer_provider=opt._optimizer_provider,
            evaluator_provider=opt._evaluator_provider,
            seed_prompt=opt.seed_prompt, n_cand=opt.n_cand, alpha=opt.alpha,
            optimized_at=datetime.now(timezone.utc).isoformat(),
        )
        (tmp_path / f"{cache_key}.json").write_text(
            json.dumps(artifact.__dict__), encoding="utf-8"
        )
        run_mock = MagicMock()
        monkeypatch.setattr(opt, "_run_algorithm1", run_mock)

        result = opt.optimize()

        assert result.p_e_star == "cached prompt"
        assert result.score == 0.91
        run_mock.assert_not_called()

    def test_expired_cache_triggers_recompute(self, monkeypatch, tmp_path):
        opt = _make_optimizer()
        _redirect_cache(monkeypatch, tmp_path)
        cache_key = _jailbreak_cache_key(
            opt.target_url, opt._optimizer_provider, opt._evaluator_provider,
            opt.seed_prompt, opt.n_iter, opt.n_cand, opt.alpha,
            opt.use_curriculum, opt._curriculum_weak_model_provider,
        )
        stale_time = datetime.now(timezone.utc) - timedelta(days=8)
        artifact = JailbreakArtifact(
            p_e_star="stale prompt", score=0.5, target_identity=opt.target_url,
            iterations_used=1, used_curriculum=False,
            optimizer_provider=opt._optimizer_provider,
            evaluator_provider=opt._evaluator_provider,
            seed_prompt=opt.seed_prompt, n_cand=opt.n_cand, alpha=opt.alpha,
            optimized_at=stale_time.isoformat(),
        )
        (tmp_path / f"{cache_key}.json").write_text(
            json.dumps(artifact.__dict__), encoding="utf-8"
        )
        monkeypatch.setattr(
            opt, "_run_algorithm1",
            MagicMock(return_value=("fresh prompt", 0.88, 2, [(0.88, "fresh prompt")])),
        )
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            result = opt.optimize()
        assert result.p_e_star == "fresh prompt"
        assert result.score == 0.88

    def test_force_refresh_bypasses_fresh_cache(self, monkeypatch, tmp_path):
        opt = _make_optimizer()
        _redirect_cache(monkeypatch, tmp_path)
        cache_key = _jailbreak_cache_key(
            opt.target_url, opt._optimizer_provider, opt._evaluator_provider,
            opt.seed_prompt, opt.n_iter, opt.n_cand, opt.alpha,
            opt.use_curriculum, opt._curriculum_weak_model_provider,
        )
        artifact = JailbreakArtifact(
            p_e_star="cached prompt", score=0.91, target_identity=opt.target_url,
            iterations_used=4, used_curriculum=False,
            optimizer_provider=opt._optimizer_provider,
            evaluator_provider=opt._evaluator_provider,
            seed_prompt=opt.seed_prompt, n_cand=opt.n_cand, alpha=opt.alpha,
            optimized_at=datetime.now(timezone.utc).isoformat(),
        )
        (tmp_path / f"{cache_key}.json").write_text(
            json.dumps(artifact.__dict__), encoding="utf-8"
        )
        monkeypatch.setattr(
            opt, "_run_algorithm1",
            MagicMock(return_value=("forced fresh", 0.77, 3, [(0.77, "forced fresh")])),
        )
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            result = opt.optimize(force_refresh=True)
        assert result.p_e_star == "forced fresh"

    def test_writes_cache_after_fresh_run(self, monkeypatch, tmp_path):
        opt = _make_optimizer()
        _redirect_cache(monkeypatch, tmp_path)
        monkeypatch.setattr(
            opt, "_run_algorithm1",
            MagicMock(return_value=("new prompt", 0.6, 1, [(0.6, "new prompt")])),
        )
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            opt.optimize()
        cache_key = _jailbreak_cache_key(
            opt.target_url, opt._optimizer_provider, opt._evaluator_provider,
            opt.seed_prompt, opt.n_iter, opt.n_cand, opt.alpha,
            opt.use_curriculum, opt._curriculum_weak_model_provider,
        )
        assert (tmp_path / f"{cache_key}.json").exists()


class TestOptimizeOrchestration:
    def test_unreachable_target_raises(self, monkeypatch, tmp_path):
        opt = _make_optimizer()
        _redirect_cache(monkeypatch, tmp_path)
        run_mock = MagicMock()
        monkeypatch.setattr(opt, "_run_algorithm1", run_mock)
        with patch.object(AgentEndpoint, "check_reachable", return_value=False):
            with pytest.raises(RuntimeError, match="NOT reachable"):
                opt.optimize()
        run_mock.assert_not_called()
        assert not list(tmp_path.glob("*.json"))

    def test_no_curriculum_runs_algorithm1_once(self, monkeypatch, tmp_path):
        opt = _make_optimizer()
        _redirect_cache(monkeypatch, tmp_path)
        run_mock = MagicMock(
            return_value=("real prompt", 0.9, 5, [(0.9, "real prompt")])
        )
        monkeypatch.setattr(opt, "_run_algorithm1", run_mock)
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            artifact = opt.optimize()
        assert run_mock.call_count == 1
        assert artifact.used_curriculum is False
        assert artifact.curriculum_weak_p_e is None
        assert artifact.p_e_star == "real prompt"

    def test_curriculum_runs_algorithm1_twice_and_chains_seed(self, monkeypatch, tmp_path):
        opt = _make_optimizer(
            use_curriculum=True,
            curriculum_weak_model_provider="gemini/gemini-3.5-flash",
        )
        _redirect_cache(monkeypatch, tmp_path)
        run_mock = MagicMock(side_effect=[
            ("weak_pe", 0.5, 3, [(0.1, "seed"), (0.5, "weak_pe")]),
            ("real_pe", 0.95, 2, [(0.3, "weak_pe"), (0.95, "real_pe")]),
        ])
        monkeypatch.setattr(opt, "_run_algorithm1", run_mock)
        with patch.object(AgentEndpoint, "check_reachable", return_value=True):
            artifact = opt.optimize()

        assert run_mock.call_count == 2
        # Stage 1 (weak model) is seeded with the configured seed_prompt.
        stage1_seed = run_mock.call_args_list[0][0][1]
        assert stage1_seed == opt.seed_prompt
        # Stage 2 (real target) is seeded with stage 1's winning prompt.
        stage2_seed = run_mock.call_args_list[1][0][1]
        assert stage2_seed == "weak_pe"

        assert artifact.used_curriculum is True
        assert artifact.p_e_star == "real_pe"
        assert artifact.score == 0.95
        assert artifact.iterations_used == 2
        assert artifact.curriculum_weak_p_e == "weak_pe"
        assert artifact.curriculum_iterations_used == 3


# ---------------------------------------------------------------------------
# JailbreakArtifact — basic dataclass sanity
# ---------------------------------------------------------------------------

class TestJailbreakArtifact:
    def test_fields_roundtrip(self):
        artifact = JailbreakArtifact(
            p_e_star="prompt", score=0.7, target_identity="http://x",
            iterations_used=2, used_curriculum=False,
            optimizer_provider="gemini/gemini-3.5-flash",
            evaluator_provider="gemini/gemini-3.5-flash",
            seed_prompt=DEFAULT_EXTRACTION_INSTRUCTION, n_cand=3, alpha=0.85,
            optimized_at="2026-08-09T00:00:00+00:00",
        )
        assert artifact.p_e_star == "prompt"
        assert artifact.curriculum_weak_p_e is None
        assert artifact.curriculum_iterations_used is None
