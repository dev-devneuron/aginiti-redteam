"""LiteLLM-backed drop-in replacement for the old `aginiti.llm_client` /
`aginiti.gemini_client` pair (retired 2026-08-20 as part of
plans/integration-plan.md's LiteLLM-unification resolution -- see that
plan's "2. Unifying the LLM Provider Layer" section).

Same three call shapes, same public interface, same behavior -- every
existing call site only needs its import path changed
(`from aginiti.llm_client import chat_json` ->
`from aginiti.core.llm import chat_json`), nothing about how callers use
these functions changes:
  - `chat`      : plain text-in, text-out.
  - `chat_json` : text-in, JSON-out (structured verdicts, claim extraction).
  - `chat_tools`: text-in, tool-call-out (tool-selection loops).

All three accept an optional `seed` (same reason as before: the benchmark
harness passes the same seed for a given trial index to every policy, so
trial k's target/judge face the same sampling draw regardless of which
policy chose the operators).

**What changed under the hood, what didn't:**
- Provider calls now go through `litellm.completion()` instead of the
  hand-rolled `groq` SDK client + a hand-rolled `google-genai` translation
  layer. LiteLLM already returns an OpenAI-compatible response for every
  provider it supports -- `.choices[0].message.content` and
  `.choices[0].message.tool_calls[].id/.function.name/.function.arguments`
  (a JSON string) `/.model_dump()` -- for Gemini exactly as much as for
  Groq, since LiteLLM does the message/tool-schema translation internally.
  This is why `gemini_client.py`'s ~230 lines of hand-rolled `_to_contents`/
  `_ToolCallShim`/`_MessageShim`/`_to_gemini_tools` translation don't have
  an equivalent here at all -- they're simply not needed anymore.
- Key rotation (`GROQ_API_KEY`, `GROQ_API_KEY_2`, `GROQ_API_KEY_3`, ...
  pooled, rotate to the next key on a RateLimitError, sticky current
  index) is unchanged in behavior, reimplemented against
  `litellm.RateLimitError` instead of `groq.RateLimitError`.
- `AGINITI_LLM_PROVIDER=gemini` still routes every call shape through
  Gemini instead of Groq -- unchanged.
- Automatic Groq->Gemini fallback when the ENTIRE Groq key pool is
  rate-limited is unchanged: not sticky (a later call still tries Groq
  first), `last_fallback_reason()` still inspectable, the underlying
  RateLimitError still raised unchanged if no GEMINI_API_KEY is set.
  This is a genuinely different fallback trigger than
  `BaseAttack._init_llm`'s (that one fails over on a *long hinted wait*
  from a single provider; this one fails over once every key in a POOL is
  exhausted) -- deliberately NOT unified into one shared mechanism in this
  pass, since the two triggers mean different things. See this module's
  and `_init_llm`'s docstrings if a future pass wants to reconcile them.
- `warn_if_parse_error` is copied verbatim -- pure post-processing logic,
  never touched the provider layer.

Model strings: `GROQ_MODEL` env var (default `"llama-3.3-70b-versatile"`)
becomes LiteLLM model string `f"groq/{GROQ_MODEL}"`; `GEMINI_MODEL` (default
`"gemini-2.5-flash"`) becomes `f"gemini/{GEMINI_MODEL}"`. Same env var
names as before, so no .env changes needed for existing deployments.
"""
from __future__ import annotations

import json
import os
import warnings

import litellm
from dotenv import load_dotenv

from aginiti.core.observability import get_logger

load_dotenv()
_logger = get_logger("core.llm")

_GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
_PROVIDER = os.environ.get("AGINITI_LLM_PROVIDER", "groq").lower()

_current_idx = 0
# Set to a short string describing the most recent automatic Groq->Gemini
# fallback (e.g. "chat_json: groq pool exhausted, used gemini"), or None if
# the last call never needed one -- inspectable, not just silent.
_last_fallback_reason: str | None = None


def _gemini_available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def _load_groq_keys() -> list[str]:
    keys = []
    primary = os.environ.get("GROQ_API_KEY")
    if primary:
        keys.append(primary)
    i = 2
    while True:
        k = os.environ.get(f"GROQ_API_KEY_{i}")
        if not k:
            break
        keys.append(k)
        i += 1
    if not keys:
        raise RuntimeError(
            "No GROQ_API_KEY (or GROQ_API_KEY_2, GROQ_API_KEY_3, ...) set. "
            "Put at least one in your .env."
        )
    return keys


def _call_with_rotation(model: str, messages: list[dict], **kwargs):
    """Tries the current Groq key first, then rotates through the rest of
    the pool on litellm.RateLimitError. Sticks with whichever key last
    worked, same as the retired llm_client.py's _call_with_rotation."""
    global _current_idx
    keys = _load_groq_keys()
    last_err: litellm.RateLimitError | None = None
    for attempt in range(len(keys)):
        idx = (_current_idx + attempt) % len(keys)
        try:
            result = litellm.completion(model=model, messages=messages, api_key=keys[idx], **kwargs)
            _current_idx = idx
            return result
        except litellm.RateLimitError as e:
            last_err = e
            continue
    raise last_err


def _seed_kwargs(seed: int | None) -> dict:
    return {"seed": seed} if seed is not None else {}


def chat(messages: list[dict], temperature: float = 0.4, max_tokens: int = 1024,
         seed: int | None = None) -> str:
    global _last_fallback_reason
    kwargs = dict(temperature=temperature, max_tokens=max_tokens, num_retries=0, timeout=60,
                  **_seed_kwargs(seed))
    if _PROVIDER == "gemini":
        _last_fallback_reason = None
        resp = litellm.completion(model=f"gemini/{_GEMINI_MODEL}", messages=messages, **kwargs)
        return resp.choices[0].message.content or ""
    try:
        resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages, **kwargs)
        _last_fallback_reason = None
        return resp.choices[0].message.content or ""
    except litellm.RateLimitError:
        if not _gemini_available():
            raise
        _last_fallback_reason = "chat: groq pool exhausted, used gemini"
        _logger.warning(_last_fallback_reason)
        resp = litellm.completion(model=f"gemini/{_GEMINI_MODEL}", messages=messages, **kwargs)
        return resp.choices[0].message.content or ""


def chat_json(messages: list[dict], temperature: float = 0.0, max_tokens: int = 400,
              seed: int | None = None) -> dict:
    """Chat call constrained to return a single JSON object."""
    global _last_fallback_reason
    kwargs = dict(temperature=temperature, max_tokens=max_tokens, num_retries=0, timeout=60,
                  response_format={"type": "json_object"}, **_seed_kwargs(seed))

    def _parse(resp) -> dict:
        raw = resp.choices[0].message.content or "{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_parse_error": True, "_raw": raw}

    if _PROVIDER == "gemini":
        _last_fallback_reason = None
        resp = litellm.completion(model=f"gemini/{_GEMINI_MODEL}", messages=messages, **kwargs)
        return _parse(resp)
    try:
        resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages, **kwargs)
        _last_fallback_reason = None
        return _parse(resp)
    except litellm.RateLimitError:
        if not _gemini_available():
            raise
        _last_fallback_reason = "chat_json: groq pool exhausted, used gemini"
        _logger.warning(_last_fallback_reason)
        resp = litellm.completion(model=f"gemini/{_GEMINI_MODEL}", messages=messages, **kwargs)
        return _parse(resp)


def chat_tools(messages: list[dict], tools: list[dict], temperature: float = 0.3,
               max_tokens: int = 600, seed: int | None = None):
    """Chat call that may return tool calls. Returns the raw message object
    so the caller can inspect both `.content` and `.tool_calls` -- LiteLLM's
    response.choices[0].message already has this exact OpenAI-compatible
    shape for every provider, Gemini included, so no shim classes are
    needed here (unlike the retired gemini_client.py)."""
    global _last_fallback_reason
    kwargs = dict(tools=tools, tool_choice="auto", temperature=temperature, max_tokens=max_tokens,
                  num_retries=0, timeout=60, **_seed_kwargs(seed))
    if _PROVIDER == "gemini":
        _last_fallback_reason = None
        resp = litellm.completion(model=f"gemini/{_GEMINI_MODEL}", messages=messages, **kwargs)
        return resp.choices[0].message
    try:
        resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages, **kwargs)
        _last_fallback_reason = None
        return resp.choices[0].message
    except litellm.RateLimitError:
        if not _gemini_available():
            raise
        _last_fallback_reason = "chat_tools: groq pool exhausted, used gemini"
        _logger.warning(_last_fallback_reason)
        resp = litellm.completion(model=f"gemini/{_GEMINI_MODEL}", messages=messages, **kwargs)
        return resp.choices[0].message


def last_fallback_reason() -> str | None:
    """Inspectable record of whether the MOST RECENT chat/chat_json/
    chat_tools call needed the automatic Groq->Gemini fallback -- None if
    it didn't (either it succeeded on Groq directly, or the provider was
    already gemini)."""
    return _last_fallback_reason


def warn_if_parse_error(verdict: dict, caller: str) -> None:
    """Copied verbatim from the retired llm_client.py -- pure post-
    processing of a chat_json result, never touched the provider layer, so
    nothing about the LiteLLM migration changes this function's behavior.

    chat_json falls back to {"_parse_error": True, "_raw": <unparseable
    text>} when a response fails to parse as JSON. Every caller across this
    codebase reads a specific key via `.get(key, default)`, which the
    parse-error dict just happens to also satisfy -- so a truncation/parse
    failure must be surfaced explicitly here, or it's silently
    indistinguishable from a genuine negative verdict. Deliberately does not
    raise: a single call failing must never crash an otherwise-fine
    campaign."""
    if verdict.get("_parse_error"):
        message = (
            f"{caller}: chat_json response failed to parse as JSON (likely truncated -- "
            f"check max_tokens for this call shape) and was silently treated as empty by "
            f"every downstream .get(key, default) read. Raw response started: "
            f"{str(verdict.get('_raw', ''))[:200]!r}"
        )
        warnings.warn(message, RuntimeWarning, stacklevel=2)
        _logger.warning(message)
