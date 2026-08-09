"""Offline test for experiments/groq_quota.py's provider-agnostic
rate-limit classification -- no live calls, just exception-shape checks."""
from google.genai.errors import ClientError as GeminiClientError

from experiments.groq_quota import is_rate_limit_error


def test_gemini_429_is_a_rate_limit_error():
    exc = GeminiClientError(429, {"error": {"message": "rate limited", "status": "RESOURCE_EXHAUSTED"}})
    assert is_rate_limit_error(exc) is True


def test_gemini_404_is_not_a_rate_limit_error():
    exc = GeminiClientError(404, {"error": {"message": "not found", "status": "NOT_FOUND"}})
    assert is_rate_limit_error(exc) is False


def test_unrelated_exception_is_not_a_rate_limit_error():
    assert is_rate_limit_error(ValueError("something else went wrong")) is False
