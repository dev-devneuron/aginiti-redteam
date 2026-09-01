"""Offline test for experiments/groq_quota.py's rate-limit classification --
no live calls, just exception-shape checks.

Simplified 2026-08-20 alongside the LiteLLM migration: litellm.RateLimitError
is now a single, unified exception type across every provider LiteLLM routes
to (confirmed directly against aginiti/providers/llm.py's own tests), so
groq_quota.py's is_rate_limit_error() no longer needs to check two separate
provider-specific exception shapes (the old groq.RateLimitError /
google.genai.errors.ClientError-with-code-429 pair) -- one isinstance check
covers Groq and Gemini alike."""
import litellm

from experiments.groq_quota import is_rate_limit_error


def _rate_limit_error(provider: str = "groq") -> litellm.RateLimitError:
    return litellm.RateLimitError("rate limited", llm_provider=provider, model="some-model")


def test_litellm_rate_limit_error_is_recognized_regardless_of_provider():
    assert is_rate_limit_error(_rate_limit_error("groq")) is True
    assert is_rate_limit_error(_rate_limit_error("gemini")) is True


def test_unrelated_exception_is_not_a_rate_limit_error():
    assert is_rate_limit_error(ValueError("something else went wrong")) is False
    assert is_rate_limit_error(litellm.NotFoundError("not found", llm_provider="groq", model="some-model")) is False
