import litellm
import pytest
from unittest.mock import patch, MagicMock

from aginiti.attacks.base import LeakFinding, BaseAttack, _rate_limit_wait_seconds


# ---------------------------------------------------------------------------
# LeakFinding
# ---------------------------------------------------------------------------

def _make_finding(**overrides) -> LeakFinding:
    defaults = dict(
        attack_type="DRA",
        tier_used="black_box",
        confidence=0.85,
        confirmed=True,
        leaked_content="SSN: 423-58-9167",
        probe_used="What is Emma Thompson's SSN?",
        trace_span_id="",
        recommendation="Add PII redaction layer before LLM output.",
        severity="critical",
    )
    defaults.update(overrides)
    return LeakFinding(**defaults)


def test_leak_finding_construction():
    f = _make_finding()
    assert f.attack_type == "DRA"
    assert f.tier_used == "black_box"
    assert f.confidence == 0.85
    assert f.confirmed is True
    assert f.trace_span_id == ""
    assert f.severity == "critical"


def test_leak_finding_otel_tier():
    f = _make_finding(tier_used="otel", trace_span_id="span-abc123", confirmed=False)
    assert f.tier_used == "otel"
    assert f.trace_span_id == "span-abc123"
    assert f.confirmed is False


def test_leak_finding_all_attack_types():
    for at in ("DRA", "MIA", "FIA"):
        f = _make_finding(attack_type=at)
        assert f.attack_type == at


def test_leak_finding_all_severities():
    for sev in ("critical", "high", "medium", "low"):
        f = _make_finding(severity=sev)
        assert f.severity == sev


def test_leak_finding_requires_all_fields():
    with pytest.raises(TypeError):
        LeakFinding(attack_type="DRA")  # missing required fields


# ---------------------------------------------------------------------------
# BaseAttack — abstract + dispatch
# ---------------------------------------------------------------------------

class _BlackBoxOnlyAttack(BaseAttack):
    """Concrete subclass that returns a fixed black-box finding."""

    def execute_black_box(self, **kwargs) -> list[LeakFinding]:
        return [_make_finding(tier_used="black_box")]

    def execute_with_traces(self, **kwargs) -> list[LeakFinding]:
        return [_make_finding(tier_used="otel", trace_span_id="span-001")]


def _make_attack(otel_ingester=None) -> _BlackBoxOnlyAttack:
    # Patch litellm.completion so no real API call is made during __init__
    with patch("litellm.completion", return_value=MagicMock()):
        return _BlackBoxOnlyAttack(
            target_url="http://localhost:8001",
            llm_provider="gemini/gemini-2.5-flash",
            api_key="fake-key",
            otel_ingester=otel_ingester,
        )


def test_base_attack_is_abstract():
    with pytest.raises(TypeError):
        BaseAttack(  # type: ignore[abstract]
            target_url="http://localhost:8001",
            llm_provider="gemini/gemini-2.5-flash",
            api_key="key",
        )


def test_execute_dispatches_black_box_when_no_otel():
    attack = _make_attack(otel_ingester=None)
    results = attack.execute()
    assert len(results) == 1
    assert results[0].tier_used == "black_box"


def test_execute_dispatches_traces_when_otel_present():
    attack = _make_attack(otel_ingester=object())  # any truthy value
    results = attack.execute()
    assert len(results) == 1
    assert results[0].tier_used == "otel"
    assert results[0].trace_span_id == "span-001"


def test_llm_callable_is_stored():
    attack = _make_attack()
    assert callable(attack.llm)


def test_llm_callable_wraps_litellm():
    fake_response = MagicMock()
    fake_response.choices[0].message.content = "hello"

    attack = _make_attack()
    with patch("litellm.completion", return_value=fake_response) as mock_completion:
        result = attack.llm(messages=[{"role": "user", "content": "test"}])

    mock_completion.assert_called_once()
    assert result == "hello"


def test_otel_ingester_stored():
    sentinel = object()
    attack = _make_attack(otel_ingester=sentinel)
    assert attack.otel is sentinel


# ---------------------------------------------------------------------------
# _rate_limit_wait_seconds (added 2026-07-13)
# ---------------------------------------------------------------------------

def _rate_limit_error(message: str) -> litellm.RateLimitError:
    return litellm.RateLimitError(
        message=message, llm_provider="groq", model="llama-3.3-70b-versatile"
    )


class TestRateLimitWaitSeconds:
    def test_parses_milliseconds(self):
        exc = _rate_limit_error("... Please try again in 485ms. Need more tokens?")
        assert _rate_limit_wait_seconds(exc) == pytest.approx(1.485)

    def test_parses_seconds(self):
        exc = _rate_limit_error("... Please try again in 2s. Upgrade to Dev Tier ...")
        assert _rate_limit_wait_seconds(exc) == pytest.approx(3.0)

    def test_parses_minutes_uncapped(self):
        # 1m + 1s safety margin = 61s — no longer capped at 60s (2026-07-13
        # revision: a real TPD-scale wait can legitimately be multi-minute).
        exc = _rate_limit_error("... Please try again in 1m. ...")
        assert _rate_limit_wait_seconds(exc) == pytest.approx(61.0)

    def test_no_hint_falls_back_to_60s(self):
        exc = _rate_limit_error("Rate limit exceeded with no timing hint at all.")
        assert _rate_limit_wait_seconds(exc) == 60.0

    def test_case_insensitive(self):
        exc = _rate_limit_error("... PLEASE TRY AGAIN IN 5S ...")
        assert _rate_limit_wait_seconds(exc) == pytest.approx(6.0)

    def test_parses_compound_minutes_and_seconds(self):
        # Groq's TPD errors report compound durations like "7m12s" — the old
        # regex only captured the first "<number><unit>" token (just "7m",
        # silently dropping the "12s"). Real log values: 7m12s, 2m4.416s,
        # 1m6.528s, 4m19.2s, 3m22.176s, 2m25.152s.
        exc = _rate_limit_error("... Please try again in 7m12s. Visit ...")
        assert _rate_limit_wait_seconds(exc) == pytest.approx(433.0)

    def test_parses_compound_minutes_and_fractional_seconds(self):
        exc = _rate_limit_error("... Please try again in 2m4.416s. Visit ...")
        assert _rate_limit_wait_seconds(exc) == pytest.approx(125.416)


# ---------------------------------------------------------------------------
# _call — rate-limit retry behavior (added 2026-07-13)
# ---------------------------------------------------------------------------

class TestCallRateLimitRetry:
    def _fake_response(self, content: str) -> MagicMock:
        resp = MagicMock()
        resp.choices[0].message.content = content
        return resp

    def test_succeeds_immediately_with_no_rate_limit(self):
        attack = _make_attack()
        with patch("litellm.completion", return_value=self._fake_response("ok")):
            result = attack.llm(messages=[{"role": "user", "content": "hi"}])
        assert result == "ok"

    def test_retries_after_rate_limit_then_succeeds(self):
        attack = _make_attack()
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise _rate_limit_error("... try again in 10ms ...")
            return self._fake_response("recovered")

        with patch("litellm.completion", side_effect=side_effect), \
             patch("time.sleep") as mock_sleep:
            result = attack.llm(messages=[{"role": "user", "content": "hi"}])

        assert result == "recovered"
        assert call_count["n"] == 3
        assert mock_sleep.call_count == 2  # one sleep per failed attempt

    def test_exhausts_retries_and_raises_last_error(self):
        attack = _make_attack()
        with patch(
            "litellm.completion",
            side_effect=_rate_limit_error("... try again in 10ms ..."),
        ), patch("time.sleep"):
            with pytest.raises(litellm.RateLimitError):
                attack.llm(messages=[{"role": "user", "content": "hi"}])

    def test_non_rate_limit_error_propagates_without_retry(self):
        attack = _make_attack()
        with patch("litellm.completion", side_effect=ValueError("boom")), \
             patch("time.sleep") as mock_sleep:
            with pytest.raises(ValueError, match="boom"):
                attack.llm(messages=[{"role": "user", "content": "hi"}])
        mock_sleep.assert_not_called()

    def test_sleep_duration_derived_from_error_hint(self):
        attack = _make_attack()
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise _rate_limit_error("... try again in 2s ...")
            return self._fake_response("ok")

        with patch("litellm.completion", side_effect=side_effect), \
             patch("time.sleep") as mock_sleep:
            attack.llm(messages=[{"role": "user", "content": "hi"}])

        mock_sleep.assert_called_once_with(pytest.approx(3.0))

    def test_repeated_failures_escalate_wait_time(self):
        # Same "try again in 2s" hint every time (3.0s base), but the call
        # keeps failing — each repeat must wait LONGER than the last, not
        # retry with the same too-short interval forever.
        attack = _make_attack()
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] < 4:
                raise _rate_limit_error("... try again in 2s ...")
            return self._fake_response("ok")

        with patch("litellm.completion", side_effect=side_effect), \
             patch("time.sleep") as mock_sleep:
            attack.llm(messages=[{"role": "user", "content": "hi"}])

        waits = [call.args[0] for call in mock_sleep.call_args_list]
        assert waits == [pytest.approx(3.0), pytest.approx(6.0), pytest.approx(12.0)]

    def test_escalation_capped_at_failover_threshold(self):
        # Escalation is capped at the failover threshold (90s), not a flat
        # 60s — waits are only ever slept through below that threshold, so
        # there's no point escalating past it (a wait that long fails over
        # instead; see TestFailoverProvider below).
        attack = _make_attack()
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] < 6:
                raise _rate_limit_error("... try again in 30s ...")
            return self._fake_response("ok")

        with patch("litellm.completion", side_effect=side_effect), \
             patch("time.sleep") as mock_sleep:
            attack.llm(messages=[{"role": "user", "content": "hi"}])

        waits = [call.args[0] for call in mock_sleep.call_args_list]
        assert all(w <= 90.0 for w in waits)
        assert waits[-1] == 90.0

    def test_logs_resumed_message_after_wait(self, caplog):
        import logging
        attack = _make_attack()
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise _rate_limit_error("... try again in 2s ...")
            return self._fake_response("ok")

        with caplog.at_level(logging.INFO), \
             patch("litellm.completion", side_effect=side_effect), \
             patch("time.sleep"):
            attack.llm(messages=[{"role": "user", "content": "hi"}])

        assert any("resumed after" in r.message for r in caplog.records)

    def test_num_retries_defaults_to_zero(self):
        attack = _make_attack()
        with patch(
            "litellm.completion", return_value=self._fake_response("ok")
        ) as mock_completion:
            attack.llm(messages=[{"role": "user", "content": "hi"}])
        assert mock_completion.call_args.kwargs["num_retries"] == 0

    def test_num_retries_caller_override_respected(self):
        attack = _make_attack()
        with patch(
            "litellm.completion", return_value=self._fake_response("ok")
        ) as mock_completion:
            attack.llm(messages=[{"role": "user", "content": "hi"}], num_retries=2)
        assert mock_completion.call_args.kwargs["num_retries"] == 2


# ---------------------------------------------------------------------------
# Fallback provider failover on long (TPD-scale) waits (added 2026-07-13)
# ---------------------------------------------------------------------------

def _make_attack_with_fallback() -> _BlackBoxOnlyAttack:
    with patch("litellm.completion", return_value=MagicMock()):
        return _BlackBoxOnlyAttack(
            target_url="http://localhost:8001",
            llm_provider="groq/llama-3.3-70b-versatile",
            api_key="fake-groq-key",
            fallback_llm_provider="gemini/gemini-3.5-flash",
            fallback_api_key="fake-gemini-key",
        )


class TestFailoverProvider:
    def _fake_response(self, content: str) -> MagicMock:
        resp = MagicMock()
        resp.choices[0].message.content = content
        return resp

    def test_long_wait_fails_over_to_backup_without_sleeping(self):
        attack = _make_attack_with_fallback()

        def side_effect(*args, **kwargs):
            if kwargs.get("model") == "groq/llama-3.3-70b-versatile":
                raise _rate_limit_error("... try again in 7m12s ...")
            return self._fake_response("from backup")

        with patch("litellm.completion", side_effect=side_effect) as mock_completion, \
             patch("time.sleep") as mock_sleep:
            result = attack.llm(messages=[{"role": "user", "content": "hi"}])

        assert result == "from backup"
        mock_sleep.assert_not_called()
        models_tried = [c.kwargs["model"] for c in mock_completion.call_args_list]
        assert models_tried == ["groq/llama-3.3-70b-versatile", "gemini/gemini-3.5-flash"]

    def test_long_wait_with_no_fallback_raises_immediately(self):
        attack = _make_attack()  # no fallback configured
        with patch(
            "litellm.completion",
            side_effect=_rate_limit_error("... try again in 7m12s ..."),
        ) as mock_completion, patch("time.sleep") as mock_sleep:
            with pytest.raises(litellm.RateLimitError):
                attack.llm(messages=[{"role": "user", "content": "hi"}])

        mock_sleep.assert_not_called()
        assert mock_completion.call_count == 1  # no retry burned on a doomed wait

    def test_backup_also_rate_limited_raises(self):
        attack = _make_attack_with_fallback()
        with patch(
            "litellm.completion",
            side_effect=_rate_limit_error("... try again in 7m12s ..."),
        ), patch("time.sleep") as mock_sleep:
            with pytest.raises(litellm.RateLimitError):
                attack.llm(messages=[{"role": "user", "content": "hi"}])
        mock_sleep.assert_not_called()

    def test_short_wait_still_retries_primary_before_any_failover(self):
        # Below the failover threshold, behavior is unchanged: sleep + retry
        # on the primary, never touching the fallback provider at all.
        attack = _make_attack_with_fallback()
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise _rate_limit_error("... try again in 2s ...")
            return self._fake_response("recovered on primary")

        with patch("litellm.completion", side_effect=side_effect) as mock_completion, \
             patch("time.sleep") as mock_sleep:
            result = attack.llm(messages=[{"role": "user", "content": "hi"}])

        assert result == "recovered on primary"
        mock_sleep.assert_called_once()
        models_tried = [c.kwargs["model"] for c in mock_completion.call_args_list]
        assert models_tried == ["groq/llama-3.3-70b-versatile"] * 2


def test_suppress_debug_info_enabled():
    # litellm's own noisy "Give Feedback / Get Help" print block fires on
    # every mapped exception unless this flag is set — verified by grepping
    # litellm's source (exception_mapping_utils.py, get_llm_provider_logic.py
    # both gate the print on `litellm.suppress_debug_info is False`).
    assert litellm.suppress_debug_info is True
