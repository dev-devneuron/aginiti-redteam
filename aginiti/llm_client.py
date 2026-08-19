"""Thin wrapper around the Groq chat-completions API, with automatic
multi-key rotation on rate limits.

Three call shapes are used throughout Aginiti:
  - `chat`      : plain text-in, text-out (used by the demo target's final
                  responses and by narrative-report generation).
  - `chat_json` : text-in, JSON-out, used wherever a caller needs a
                  structured verdict (the Observation Adapter's success/
                  failure judgement, claim extraction).
  - `chat_tools`: text-in, tool-call-out, used by the reference target agent
                  to decide which mock tool to invoke.

All three accept an optional `seed` (see module docstring history: the
benchmark harness passes the same seed for a given trial index to every
condition, so trial k's target and judge face the same sampling draw
regardless of which policy is choosing operators).

Key rotation: a free-tier key's daily token budget (100k) does not cover a
real benchmark in one sitting (we hit this twice for real, then repeatedly
during the RQ1-adjacent live experiments -- see docs/ROADMAP.md's "How we
got here"). `GROQ_API_KEY`, `GROQ_API_KEY_2`, `GROQ_API_KEY_3`, ... are
pooled -- on a RateLimitError from the current key, the same request is
retried on the next key in the pool before giving up. This multiplies the
effective daily budget by the number of keys, but the whole pool can still
be collectively exhausted, which is what actually happened.

Provider switch: set `AGINITI_LLM_PROVIDER=gemini` to route all three call
shapes through `aginiti/gemini_client.py` instead -- added specifically to
unblock live experiments when the Groq pool is exhausted, not to replace
Groq as the default. Every existing call site
(`from aginiti.llm_client import chat_json` etc.) is unchanged either way;
only this module's dispatch changes. Default remains Groq.

Automatic Gemini fallback (2026-08-09): manually swapping AnythingLLM's own
server-side key or re-exporting AGINITI_LLM_PROVIDER by hand, every single
time the ENTIRE Groq pool hit its rolling daily cap, happened so many
times across this project's live-benchmark history (see docs/ROADMAP.md)
that it earned its own real fix rather than another manual workaround.
When the default provider is Groq and EVERY key in the pool raises
RateLimitError, each of `chat`/`chat_json`/`chat_tools` now falls back to
`gemini_client`'s equivalent call automatically, for that one call only --
`_PROVIDER` itself is never mutated, so a later call still tries Groq
first (a key may have recovered, or a differently-shaped call may fit
under the remaining quota). Silent only in the sense of "no manual
intervention required" -- `_last_fallback_reason` records what happened,
inspectable by callers/tests that care, and the underlying RateLimitError
is still raised unchanged if no GEMINI_API_KEY is configured at all (no
silent swallow into a confusing unrelated failure).
"""
import json
import os
import warnings

from dotenv import load_dotenv
from groq import Groq, RateLimitError

from aginiti.core.observability import get_logger

load_dotenv()
_logger = get_logger("llm_client")

_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
_clients: list[Groq] | None = None
_current_idx = 0
_PROVIDER = os.environ.get("AGINITI_LLM_PROVIDER", "groq").lower()
# Set to a short string describing the most recent automatic Groq->Gemini
# fallback (e.g. "chat_json: groq pool exhausted, used gemini"), or None
# if the last call never needed one. Inspectable, not just silent --
# tests and callers that want to know a fallback happened can check this
# instead of it being invisible.
_last_fallback_reason: str | None = None


def _gemini_available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def _load_keys() -> list[str]:
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
            "Put at least one in Aginiti-Extended/.env"
        )
    return keys


def _get_clients() -> list[Groq]:
    global _clients
    if _clients is None:
        _clients = [Groq(api_key=k) for k in _load_keys()]
    return _clients


def _call_with_rotation(make_request):
    """`make_request(client) -> response`. Tries the current key first, then
    rotates through the rest of the pool on RateLimitError. Sticks with
    whichever key last worked so subsequent calls don't re-try exhausted
    keys from scratch every time."""
    global _current_idx
    clients = _get_clients()
    last_err: RateLimitError | None = None
    for attempt in range(len(clients)):
        idx = (_current_idx + attempt) % len(clients)
        try:
            result = make_request(clients[idx])
            _current_idx = idx
            return result
        except RateLimitError as e:
            last_err = e
            continue
    raise last_err


def _groq_chat(messages: list[dict], temperature: float = 0.4, max_tokens: int = 1024,
                seed: int | None = None) -> str:
    resp = _call_with_rotation(lambda c: c.chat.completions.create(
        model=_MODEL, messages=messages, temperature=temperature, max_tokens=max_tokens,
        **({"seed": seed} if seed is not None else {}),
    ))
    return resp.choices[0].message.content or ""


def _groq_chat_json(messages: list[dict], temperature: float = 0.0, max_tokens: int = 400,
                     seed: int | None = None) -> dict:
    resp = _call_with_rotation(lambda c: c.chat.completions.create(
        model=_MODEL, messages=messages, temperature=temperature, max_tokens=max_tokens,
        response_format={"type": "json_object"},
        **({"seed": seed} if seed is not None else {}),
    ))
    raw = resp.choices[0].message.content or "{}"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_parse_error": True, "_raw": raw}


def _groq_chat_tools(messages: list[dict], tools: list[dict], temperature: float = 0.3,
                      max_tokens: int = 600, seed: int | None = None):
    resp = _call_with_rotation(lambda c: c.chat.completions.create(
        model=_MODEL, messages=messages, tools=tools, tool_choice="auto",
        temperature=temperature, max_tokens=max_tokens,
        **({"seed": seed} if seed is not None else {}),
    ))
    return resp.choices[0].message


def chat(messages: list[dict], temperature: float = 0.4, max_tokens: int = 1024,
         seed: int | None = None) -> str:
    global _last_fallback_reason
    if _PROVIDER == "gemini":
        from aginiti import gemini_client
        _last_fallback_reason = None
        return gemini_client.chat(messages, temperature=temperature, max_tokens=max_tokens, seed=seed)
    try:
        result = _groq_chat(messages, temperature=temperature, max_tokens=max_tokens, seed=seed)
        _last_fallback_reason = None
        return result
    except RateLimitError:
        if not _gemini_available():
            raise
        from aginiti import gemini_client
        _last_fallback_reason = "chat: groq pool exhausted, used gemini"
        _logger.warning(_last_fallback_reason)
        return gemini_client.chat(messages, temperature=temperature, max_tokens=max_tokens, seed=seed)


def chat_json(messages: list[dict], temperature: float = 0.0, max_tokens: int = 400,
              seed: int | None = None) -> dict:
    """Chat call constrained to return a single JSON object."""
    global _last_fallback_reason
    if _PROVIDER == "gemini":
        from aginiti import gemini_client
        _last_fallback_reason = None
        return gemini_client.chat_json(messages, temperature=temperature, max_tokens=max_tokens, seed=seed)
    try:
        result = _groq_chat_json(messages, temperature=temperature, max_tokens=max_tokens, seed=seed)
        _last_fallback_reason = None
        return result
    except RateLimitError:
        if not _gemini_available():
            raise
        from aginiti import gemini_client
        _last_fallback_reason = "chat_json: groq pool exhausted, used gemini"
        _logger.warning(_last_fallback_reason)
        return gemini_client.chat_json(messages, temperature=temperature, max_tokens=max_tokens, seed=seed)


def chat_tools(messages: list[dict], tools: list[dict], temperature: float = 0.3,
               max_tokens: int = 600, seed: int | None = None):
    """Chat call that may return tool calls. Returns the raw message object
    so the caller can inspect both `.content` and `.tool_calls`."""
    global _last_fallback_reason
    if _PROVIDER == "gemini":
        from aginiti import gemini_client
        _last_fallback_reason = None
        return gemini_client.chat_tools(messages, tools, temperature=temperature, max_tokens=max_tokens, seed=seed)
    try:
        result = _groq_chat_tools(messages, tools, temperature=temperature, max_tokens=max_tokens, seed=seed)
        _last_fallback_reason = None
        return result
    except RateLimitError:
        if not _gemini_available():
            raise
        from aginiti import gemini_client
        _last_fallback_reason = "chat_tools: groq pool exhausted, used gemini"
        _logger.warning(_last_fallback_reason)
        return gemini_client.chat_tools(messages, tools, temperature=temperature, max_tokens=max_tokens, seed=seed)


def last_fallback_reason() -> str | None:
    """Inspectable record of whether the MOST RECENT chat/chat_json/
    chat_tools call needed the automatic Groq->Gemini fallback -- None if
    it didn't (either it succeeded on Groq directly, or the provider was
    already gemini)."""
    return _last_fallback_reason


def warn_if_parse_error(verdict: dict, caller: str) -> None:
    """2026-08-09 fix: chat_json falls back to {"_parse_error": True,
    "_raw": <unparseable text, usually truncated at max_tokens>} when a
    response fails to parse as JSON -- and every caller across this
    codebase was found, via a live audit, to silently treat that fallback
    identically to a genuine empty/negative verdict (every consumer reads
    a specific key via `.get(key, default)`, which the parse-error dict
    just happens to also satisfy). Confirmed live and FIXED at its most
    damaging call site (aginiti/graph/insights.py's Reasoning Layer,
    where a real 400-token default was silently discarding well-reasoned,
    correctly-cited insights, misrepresenting a genuine finding as
    "nothing to report"). This shared helper is the single place every
    other `chat_json` caller (aginiti/graph/priors.py, aginiti/adapter/
    observation_adapter.py's judge, and any future one) now calls right
    after their own chat_json call, so a truncation/parse failure is
    ALWAYS at least visible (via warnings.warn -- greppable, pytest-
    catchable) instead of silently indistinguishable from a real negative
    result. Deliberately does not raise: a single call failing must never
    crash an otherwise-fine campaign."""
    if verdict.get("_parse_error"):
        message = (
            f"{caller}: chat_json response failed to parse as JSON (likely truncated -- "
            f"check max_tokens for this call shape) and was silently treated as empty by "
            f"every downstream .get(key, default) read. Raw response started: "
            f"{str(verdict.get('_raw', ''))[:200]!r}"
        )
        warnings.warn(message, RuntimeWarning, stacklevel=2)
        # Additive, 2026-08-09: the warnings.warn above is kept exactly as
        # it was (still greppable/pytest.warns-catchable, still what every
        # existing test here targets) -- this also routes the same signal
        # through the structured logger, so a deploying application that
        # configured logging (but doesn't run under pytest's warning
        # capture) still sees it.
        _logger.warning(message)
