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
real benchmark in one sitting (we hit this twice for real). `GROQ_API_KEY`,
`GROQ_API_KEY_2`, `GROQ_API_KEY_3`, ... are pooled -- on a RateLimitError
from the current key, the same request is retried on the next key in the
pool before giving up. This multiplies the effective daily budget by the
number of keys, and is transparent to every caller.
"""
import json
import os

from dotenv import load_dotenv
from groq import Groq, RateLimitError

load_dotenv()

_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
_clients: list[Groq] | None = None
_current_idx = 0


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


def chat(messages: list[dict], temperature: float = 0.4, max_tokens: int = 1024,
         seed: int | None = None) -> str:
    resp = _call_with_rotation(lambda c: c.chat.completions.create(
        model=_MODEL, messages=messages, temperature=temperature, max_tokens=max_tokens,
        **({"seed": seed} if seed is not None else {}),
    ))
    return resp.choices[0].message.content or ""


def chat_json(messages: list[dict], temperature: float = 0.0, max_tokens: int = 400,
              seed: int | None = None) -> dict:
    """Chat call constrained to return a single JSON object."""
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


def chat_tools(messages: list[dict], tools: list[dict], temperature: float = 0.3,
               max_tokens: int = 600, seed: int | None = None):
    """Chat call that may return tool calls. Returns the raw message object
    so the caller can inspect both `.content` and `.tool_calls`."""
    resp = _call_with_rotation(lambda c: c.chat.completions.create(
        model=_MODEL, messages=messages, tools=tools, tool_choice="auto",
        temperature=temperature, max_tokens=max_tokens,
        **({"seed": seed} if seed is not None else {}),
    ))
    return resp.choices[0].message
