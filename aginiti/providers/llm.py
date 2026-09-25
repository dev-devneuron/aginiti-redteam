"""LiteLLM-backed LLM provider client for Aginiti's own reasoning calls
(query/anchor generation, judge verdicts, claim extraction) -- how Aginiti
powers its own attacker/judge LLM calls, as distinct from
`aginiti/connectors/endpoint.py`'s `AgentEndpoint`, which talks to the
*target under test*. See `aginiti/providers/` package docs for the
`connectors/` vs `providers/` split.

Originally a drop-in replacement for the retired `aginiti.llm_client` /
`aginiti.gemini_client` pair (LiteLLM-unification, see
`plans/integration-plan.md` "2. Unifying the LLM Provider Layer"); moved
here from `aginiti/core/llm.py` as part of the `connectors/` vs.
`providers/` split -- `aginiti/core/llm.py` remains a backward-compatible
re-export shim.

Same three call shapes, same public interface, same behavior:
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
  pooled, sticky current index) reimplemented against litellm's exception
  types instead of `groq`'s own, and broadened from rotating on
  `litellm.RateLimitError` alone to also rotating on
  `litellm.AuthenticationError`/`litellm.BadRequestError` -- see
  `_ROTATABLE_ERRORS` below for why (a real expired-key failure,
  live-observed, was getting retried forever at the same key instead of
  skipped).
- `AGINITI_LLM_PROVIDER=gemini` still routes every call shape through
  Gemini instead of Groq -- unchanged.
- Automatic fallback when the ENTIRE Groq key pool fails (rate limits,
  bad keys, and transient 5xx/timeout/connection errors, each retried
  across the pool with a short backoff first): goes to the first
  configured key among Gemini/OpenAI/Anthropic/Mistral. Not sticky (a
  later call still tries Groq first), `last_fallback_reason()` still
  inspectable, the underlying error still raised unchanged if no other
  provider's key is set.
  This is a genuinely different fallback trigger than
  `BaseAttack._init_llm`'s (that one fails over on a *long hinted wait*
  from a single provider; this one fails over once every key in a POOL is
  exhausted) -- deliberately NOT unified into one shared mechanism in this
  pass, since the two triggers mean different things. See this module's
  and `_init_llm`'s docstrings if a future pass wants to reconcile them.
- `warn_if_parse_error` is copied verbatim -- pure post-processing logic,
  never touched the provider layer.

Model strings: `GROQ_MODEL` env var (default `"openai/gpt-oss-20b"`)
becomes LiteLLM model string `f"groq/{GROQ_MODEL}"`; `GEMINI_MODEL` (default
`"gemini-2.5-flash"`) becomes `f"gemini/{GEMINI_MODEL}"`. Same env var
names as before, so no .env changes needed for existing deployments.

**Default-model fix (live-verified against this project's own Groq
account, plans/PLAN.md):** the previous default, `llama-3.3-70b-versatile`,
no longer exists on Groq at all (404, confirmed live) -- and the model this
project's own docs had already suggested as its replacement,
`llama-3.1-8b-instant`, is ALSO gone (also confirmed live, not assumed).
Queried this project's Groq account's real current catalog directly
(`GET /openai/v1/models`): no `llama-3.x` chat model exists on it
anymore. Every remaining general-purpose chat-capable model on that
catalog is a reasoning model (emits hidden `<think>`-style tokens before
real content). `openai/gpt-oss-20b` was chosen over the other candidates
tried live: `qwen/qwen3.6-27b` has substantially heavier reasoning
overhead for the same trivial task (live-measured ~970 chars of hidden
reasoning vs. gpt-oss-20b's leaner output), and `groq/compound-mini`
(genuinely non-reasoning, token-efficient) turned out to flatly reject
tool-calling ("`tool calling` is not supported with this model") --
disqualifying for `chat_tools`, which every DemoAgent/InjecAgent call
site needs. `_GROQ_MODEL` is one shared default across all three call
shapes (`chat`/`chat_json`/`chat_tools`), so it has to work for all three
-- `openai/gpt-oss-20b` is the one live-verified to. Real cost of this
choice: reasoning overhead means `chat_json` callers passing a small
`max_tokens` can genuinely hit `json_validate_failed` ("max completion
tokens reached before generating a valid document") if their budget is
too tight for the hidden reasoning tokens -- observed live in
`observation_adapter._judge()` at its own default budget. Not resolved
in this module; if it recurs, the fix is a larger `max_tokens` at the
call site, not a change here.
"""
from __future__ import annotations

import json
import os
import time
import warnings

import litellm
from dotenv import load_dotenv

from aginiti.core.observability import get_logger

load_dotenv()
_logger = get_logger("providers.llm")

_GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")
_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
_OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
_ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")
_MISTRAL_MODEL = os.environ.get("MISTRAL_MODEL", "mistral-small-latest")
_PROVIDER = os.environ.get("AGINITI_LLM_PROVIDER", "groq").lower()

# Which env var holds the key for each provider this module can route to,
# and which model string it uses when selected. Groq isn't listed here --
# it has its own key-pool/rotation machinery (_load_groq_keys/
# _call_with_rotation) rather than a single api_key, so it's handled as a
# special case in _resolve_active_provider() and each chat*() function,
# not through this simple lookup.
_PROVIDER_ENV_KEYS = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}
_PROVIDER_MODELS = {
    "gemini": _GEMINI_MODEL,
    "openai": _OPENAI_MODEL,
    "anthropic": _ANTHROPIC_MODEL,
    "mistral": _MISTRAL_MODEL,
}
# Priority when auto-detecting (AGINITI_LLM_PROVIDER unset/"groq" and no
# GROQ_API_KEY present) -- first configured key wins. Matches aginiti/
# cli.py's own provider-priority order.
_AUTO_DETECT_ORDER = ("gemini", "openai", "anthropic", "mistral")

# Any-provider override: a full LiteLLM model string (e.g.
# "deepseek/deepseek-chat", "openrouter/meta-llama/llama-3.1-70b-instruct",
# "azure/<deployment>") plus the key for it. Takes priority over every
# built-in provider above when set, so a user can route through ANY
# provider LiteLLM supports without this module needing a hardcoded entry
# (or knowing that provider's own env var name) for it. The key is passed
# explicitly as `api_key`; if it's unset, LiteLLM falls back to that
# provider's own standard env var, which also covers keyless local models
# such as "ollama/llama3". Shared with aginiti/cli.py and
# aginiti/operators/deep_attack_operators.py so the judge, the attacks and
# the deep-attack operators all route to the same model.
CUSTOM_MODEL_ENV = "AGINITI_LLM_MODEL"
CUSTOM_KEY_ENV = "AGINITI_LLM_API_KEY"

_current_idx = 0
# Set to a short string describing the most recent automatic Groq->other-
# provider fallback (e.g. "chat_json: groq unavailable (RateLimitError),
# used gemini"), or None if
# the last call never needed one -- inspectable, not just silent.
_last_fallback_reason: str | None = None


def _gemini_available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def _available_fallback_provider() -> str | None:
    """Find the first available non-Groq fallback provider (Gemini, OpenAI, Anthropic, Mistral)."""
    for provider in _AUTO_DETECT_ORDER:
        if os.environ.get(_PROVIDER_ENV_KEYS[provider]):
            return provider
    return None


def _resolve_active_provider() -> str:
    """
    Which provider chat()/chat_json()/chat_tools() actually use for THIS
    call -- checked fresh every call (not cached), so a `.env` edit or a
    key added mid-process takes effect immediately.

    An explicit ``AGINITI_LLM_PROVIDER`` set to anything other than
    ``"groq"`` (its default) is honored unconditionally: ``"gemini"`` is
    the original behavior; ``"openai"``/``"anthropic"``/``"mistral"`` are
    new alternatives, routed the same way.

    Otherwise (``_PROVIDER == "groq"`` -- covers both the real default and
    an explicit ``AGINITI_LLM_PROVIDER=groq``, which this module has never
    distinguished from each other): use Groq if ``GROQ_API_KEY`` is
    actually set, preserving the original default and its multi-key
    rotation pool exactly as before. If it ISN'T set, auto-detect the
    first available key among the other 4 supported providers instead of
    letting ``_load_groq_keys()`` raise -- this is the fix for a real,
    live-reported crash: a user who configured only ``GEMINI_API_KEY``
    (or only OPENAI/ANTHROPIC/MISTRAL) got a hard ``RuntimeError`` on
    ``aginiti scan``'s very first judge call, even though a perfectly
    usable key was sitting right there in their `.env`. If truly nothing
    is configured anywhere, still returns "groq" so the existing,
    already-descriptive ``_load_groq_keys()`` error is what the user sees,
    rather than inventing a second, redundant error message here.

    ``AGINITI_LLM_MODEL`` (see ``CUSTOM_MODEL_ENV``) outranks all of the
    above: when set, every call goes to that exact LiteLLM model string and
    this returns ``"custom"``.
    """
    if os.environ.get(CUSTOM_MODEL_ENV):
        return "custom"
    if _PROVIDER != "groq" and _PROVIDER in _PROVIDER_ENV_KEYS:
        return _PROVIDER
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    for provider in _AUTO_DETECT_ORDER:
        if os.environ.get(_PROVIDER_ENV_KEYS[provider]):
            return provider
    return "groq"


def _model_string(provider: str) -> str:
    """LiteLLM model string for any provider except groq (groq's own
    model string is built from _GROQ_MODEL directly at each call site,
    since it's paired with the key-rotation pool, not this lookup)."""
    if provider == "custom":
        return os.environ[CUSTOM_MODEL_ENV]
    return f"{provider}/{_PROVIDER_MODELS[provider]}"


def _api_key_kwargs(provider: str) -> dict:
    """Explicit `api_key` for the any-provider override; built-in providers
    let LiteLLM read their own standard env var, as before."""
    if provider == "custom" and os.environ.get(CUSTOM_KEY_ENV):
        return {"api_key": os.environ[CUSTOM_KEY_ENV]}
    return {}


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


# Errors worth rotating/retrying past: rate limits, auth/bad-key errors,
# transient 500/503 server errors, timeouts, and connection glitches.
_ROTATABLE_ERRORS = (
    litellm.RateLimitError,
    litellm.AuthenticationError,
    litellm.BadRequestError,
    litellm.InternalServerError,
    litellm.ServiceUnavailableError,
    litellm.APIConnectionError,
    litellm.Timeout,
    litellm.APIError,
)


def _call_with_rotation(model: str, messages: list[dict], **kwargs):
    """Tries the current Groq key first, then rotates through the rest of
    the pool on a rotatable error (rate limits, 500/503 outages, bad keys).
    Includes short exponential backoff between attempts to smooth over transient glitches."""
    global _current_idx
    keys = _load_groq_keys()
    last_err: Exception | None = None
    num_attempts = max(len(keys), 3)
    for attempt in range(num_attempts):
        idx = (_current_idx + attempt) % len(keys)
        try:
            result = litellm.completion(model=model, messages=messages, api_key=keys[idx], **kwargs)
            _current_idx = idx
            return result
        except _ROTATABLE_ERRORS as e:
            last_err = e
            if attempt < num_attempts - 1:
                time.sleep(min(1.0 * (attempt + 1), 3.0))
            continue
    assert last_err is not None  # unreachable with an empty pool: _load_groq_keys() already raises
    raise last_err


def _seed_kwargs(seed: int | None) -> dict:
    return {"seed": seed} if seed is not None else {}


def chat(messages: list[dict], temperature: float = 0.4, max_tokens: int = 1024,
         seed: int | None = None) -> str:
    global _last_fallback_reason
    kwargs = dict(temperature=temperature, max_tokens=max_tokens, num_retries=0, timeout=60,
                  **_seed_kwargs(seed))
    active = _resolve_active_provider()
    if active != "groq":
        _last_fallback_reason = None
        resp = litellm.completion(model=_model_string(active), messages=messages,
                                  **_api_key_kwargs(active), **kwargs)
        return resp.choices[0].message.content or ""
    try:
        resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages, **kwargs)
        _last_fallback_reason = None
        return resp.choices[0].message.content or ""
    except _ROTATABLE_ERRORS as exc:
        fallback = _available_fallback_provider()
        if not fallback:
            raise
        _last_fallback_reason = f"chat: groq unavailable ({type(exc).__name__}), used {fallback}"
        _logger.warning(_last_fallback_reason)
        resp = litellm.completion(model=_model_string(fallback), messages=messages, **kwargs)
        return resp.choices[0].message.content or ""


def chat_json(messages: list[dict], temperature: float = 0.0, max_tokens: int = 400,
              seed: int | None = None) -> dict:
    """Chat call constrained to return a single JSON object.

    Truncation retry: if response was cut off by token limit, retry once with doubled tokens.
    On Groq transient 500/rate-limit failure, seamlessly falls back to available secondary provider."""
    global _last_fallback_reason
    kwargs = dict(temperature=temperature, max_tokens=max_tokens, num_retries=0, timeout=60,
                  response_format={"type": "json_object"}, **_seed_kwargs(seed))

    def _parse(resp) -> dict:
        raw = resp.choices[0].message.content or "{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_parse_error": True, "_raw": raw}

    def _truncated(resp) -> bool:
        try:
            return resp.choices[0].finish_reason == "length"
        except (AttributeError, IndexError):
            return False

    active = _resolve_active_provider()
    if active != "groq":
        _last_fallback_reason = None
        model = _model_string(active)
        key_kwargs = _api_key_kwargs(active)
        resp = litellm.completion(model=model, messages=messages, **key_kwargs, **kwargs)
        result = _parse(resp)
        if "_parse_error" in result and _truncated(resp):
            _logger.warning("chat_json: response truncated at max_tokens=%d -- retrying "
                             "once with max_tokens=%d", max_tokens, max_tokens * 2)
            resp = litellm.completion(model=model, messages=messages, **key_kwargs,
                                       **{**kwargs, "max_tokens": max_tokens * 2})
            result = _parse(resp)
        return result
    try:
        resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages, **kwargs)
        _last_fallback_reason = None
        result = _parse(resp)
        if "_parse_error" in result and _truncated(resp):
            _logger.warning("chat_json: response truncated at max_tokens=%d -- retrying "
                             "once with max_tokens=%d", max_tokens, max_tokens * 2)
            resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages,
                                        **{**kwargs, "max_tokens": max_tokens * 2})
            result = _parse(resp)
        return result
    except _ROTATABLE_ERRORS as exc:
        fallback = _available_fallback_provider()
        if not fallback:
            raise
        _last_fallback_reason = f"chat_json: groq unavailable ({type(exc).__name__}), used {fallback}"
        _logger.warning(_last_fallback_reason)
        fallback_model = _model_string(fallback)
        resp = litellm.completion(model=fallback_model, messages=messages, **kwargs)
        result = _parse(resp)
        if "_parse_error" in result and _truncated(resp):
            _logger.warning("chat_json: response truncated at max_tokens=%d -- retrying "
                             "once with max_tokens=%d", max_tokens, max_tokens * 2)
            resp = litellm.completion(model=fallback_model, messages=messages,
                                       **{**kwargs, "max_tokens": max_tokens * 2})
            result = _parse(resp)
        return result


def chat_tools(messages: list[dict], tools: list[dict], temperature: float = 0.3,
               max_tokens: int = 600, seed: int | None = None):
    """Chat call that may return tool calls."""
    global _last_fallback_reason
    kwargs = dict(tools=tools, tool_choice="auto", temperature=temperature, max_tokens=max_tokens,
                  num_retries=0, timeout=60, **_seed_kwargs(seed))
    active = _resolve_active_provider()
    if active != "groq":
        _last_fallback_reason = None
        resp = litellm.completion(model=_model_string(active), messages=messages,
                                  **_api_key_kwargs(active), **kwargs)
        return resp.choices[0].message
    try:
        resp = _call_with_rotation(f"groq/{_GROQ_MODEL}", messages, **kwargs)
        _last_fallback_reason = None
        return resp.choices[0].message
    except _ROTATABLE_ERRORS as exc:
        fallback = _available_fallback_provider()
        if not fallback:
            raise
        _last_fallback_reason = f"chat_tools: groq unavailable ({type(exc).__name__}), used {fallback}"
        _logger.warning(_last_fallback_reason)
        resp = litellm.completion(model=_model_string(fallback), messages=messages, **kwargs)
        return resp.choices[0].message


def active_provider_name() -> str:
    """Public wrapper around `_resolve_active_provider()` -- which provider
    the NEXT chat/chat_json/chat_tools call will actually use, for callers
    that want to log/display it (e.g. observation_adapter._judge()) without
    reaching into a private helper. For the any-provider override this is
    the configured model string itself (e.g. "deepseek/deepseek-chat"),
    which says more than a bare "custom"."""
    active = _resolve_active_provider()
    return _model_string(active) if active == "custom" else active


def last_fallback_reason() -> str | None:
    """Inspectable record of whether the MOST RECENT chat/chat_json/
    chat_tools call needed the automatic Groq->other-provider fallback -- None if
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
