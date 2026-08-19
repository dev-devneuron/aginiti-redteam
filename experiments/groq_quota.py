"""Shared quota-awareness helper for every live experiment in experiments/.

Added directly in response to hitting Groq's per-organization daily token
cap mid-Experiment-3 (all 8 pooled keys in .env share one org --
`docs/ROADMAP.md`'s "How we got here" already documented this exact
constraint from earlier in the project; this is it recurring for real,
not a new failure mode). Two concrete improvements this buys:

1. `preflight_check()` -- one minimal, cheap call before committing to a
   whole multi-trial experiment, so a still-exhausted quota is reported
   cleanly ("try again in ~38m") instead of burning partway into a real
   campaign and crashing with an unhandled traceback (exactly what
   happened to Experiment 3's `static_trial00`).
2. `is_rate_limit_error()` -- lets each experiment's main loop catch a
   rate-limit error specifically mid-run, save whatever trials already
   completed (they're already written to disk as each one finishes, per
   the resumable design), and exit with a clear, actionable message rather
   than a stack trace -- so a partial run is always still a resumable,
   reported result, not a failure to clean up after.

Provider-agnostic since `aginiti/gemini_client.py` was added: Groq raises
`groq.RateLimitError`; Gemini's SDK raises `google.genai.errors.ClientError`
for every 4xx, with the actual HTTP status on `.code` (429 specifically for
rate limits, confirmed live -- `.status` reads "RESOURCE_EXHAUSTED"). Both
are checked here so every experiment script's rate-limit handling works
unmodified regardless of which provider `AGINITI_LLM_PROVIDER` selects.
"""
from __future__ import annotations

import re

from google.genai.errors import ClientError as GeminiClientError
from groq import RateLimitError as GroqRateLimitError

from aginiti.llm_client import chat_json

_RETRY_AFTER_RE = re.compile(r"try again in ([0-9.]+m)?([0-9.]+s)?", re.IGNORECASE)


def _parse_retry_after(message: str) -> str | None:
    match = _RETRY_AFTER_RE.search(message)
    if not match:
        return None
    minutes, seconds = match.groups()
    parts = [p for p in (minutes, seconds) if p]
    return " ".join(parts) if parts else None


def is_rate_limit_error(exc: BaseException) -> bool:
    if isinstance(exc, GroqRateLimitError):
        return True
    if isinstance(exc, GeminiClientError) and getattr(exc, "code", None) == 429:
        return True
    return False


def preflight_check(max_tokens: int = 500) -> tuple[bool, str]:
    """A chat_json call requesting a token budget close to a REAL operator/
    judge call's typical size (~500-2000 tokens observed in this project's
    own 429 errors), not a trivial handful. This was tightened after a real
    false-positive: an earlier version used max_tokens=20 and kept reporting
    "quota available" because _call_with_rotation() could always find SOME
    pooled key with a sliver of room left for a 20-token request, even when
    every pooled key's org was independently too close to its own cap for
    the ~1955-token first real call of an actual campaign step to fit --
    the preflight passed, then the campaign immediately 429'd anyway. A
    larger, more realistic probe size makes "ok" actually predictive of
    whether a live experiment can make real progress, not just whether the
    pool has ANY tokens left anywhere."""
    try:
        chat_json([{"role": "user", "content": "Reply with JSON {\"ok\": true}"}], max_tokens=max_tokens)
        return True, "quota available"
    except (GroqRateLimitError, GeminiClientError) as e:
        if not is_rate_limit_error(e):
            raise
        retry_after = _parse_retry_after(str(e))
        eta = f" -- retry in ~{retry_after}" if retry_after else ""
        return False, f"Quota still exhausted{eta}. Raw: {e}"
