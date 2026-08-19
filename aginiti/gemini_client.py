"""Gemini-backed implementation of the same three call shapes
`aginiti/llm_client.py` exposes (`chat`, `chat_json`, `chat_tools`) --
added specifically to unblock RQ1-adjacent live experiments when Groq's
per-organization daily token cap is exhausted (see `docs/ROADMAP.md`'s
"How we got here" for the repeated, documented history of that
constraint). Every caller (`aginiti/target/demo_agent.py`,
`aginiti/adapter/observation_adapter.py`, `aginiti/graph/insights.py`)
already imports these three functions from `aginiti.llm_client`, never
from a specific provider -- `llm_client.py` picks this module when
`AGINITI_LLM_PROVIDER=gemini` is set, and every call site is unchanged.

The interface contract this module has to honor exactly, because callers
depend on the concrete shape, not just "a string comes back":
  - `chat_tools()` must return an object with `.content` (str | None) and
    `.tool_calls` (list | None), where each tool call has `.id`,
    `.function.name`, `.function.arguments` (a JSON string, matching
    OpenAI/Groq's wire format even though Gemini's native format is a
    parsed dict), and `.model_dump()` (used when the caller re-serializes
    the assistant turn back into conversation history).
  - `messages` is always the OpenAI-style list of
    {"role": "system"|"user"|"assistant"|"tool", "content": ...} dicts
    Aginiti already uses everywhere -- this module translates that into
    Gemini's `contents` format on every call, since callers keep their own
    conversation history in the OpenAI shape (see `DemoAgent.history`),
    not in a Gemini-native one.
"""
from __future__ import annotations

import json
import os
import uuid

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
_client: genai.Client | None = None

# gemini-2.5-flash defaults to a dynamic "thinking" budget that shares the
# same max_output_tokens cap as the visible response. Found live,
# reproduced 8/8 on a fixed config: for a straightforward tool-selection
# call, thinking intermittently consumed the ENTIRE token budget, leaving
# genuinely zero tokens for visible output -- STOP finish_reason, no error,
# no safety block, just an empty response every few calls. Disabling
# thinking made the same call 8/8 reliable. None of Aginiti's LLM call
# sites need extended reasoning (judge verdicts, tool selection, and
# insight synthesis are all direct, single-step decisions), so this is the
# correct default here, not a narrow workaround.
_NO_THINKING = types.ThinkingConfig(thinking_budget=0)


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("No GEMINI_API_KEY set. Put it in Aginiti-Extended/.env")
        _client = genai.Client(api_key=api_key)
    return _client


def _to_contents(messages: list[dict]) -> tuple[str | None, list[types.Content]]:
    """OpenAI-shaped messages -> (system_instruction, Gemini contents).
    A system message that isn't the very first one (e.g. a mid-conversation
    suspicion-escalation reminder in DemoAgent's history) has no Gemini
    equivalent -- Gemini's system_instruction is a single top-level config,
    not a per-turn role -- so it's folded in as a tagged user-role note
    instead of silently dropped."""
    system_parts: list[str] = []
    contents: list[types.Content] = []
    pending_function_responses: list[types.Part] = []

    def _flush_function_responses():
        if pending_function_responses:
            contents.append(types.Content(role="user", parts=list(pending_function_responses)))
            pending_function_responses.clear()

    for i, msg in enumerate(messages):
        role = msg.get("role")
        content = msg.get("content") or ""
        if role == "system":
            if i == 0:
                system_parts.append(content)
            else:
                _flush_function_responses()
                contents.append(types.Content(role="user", parts=[types.Part(text=f"[SYSTEM NOTE] {content}")]))
        elif role == "user":
            _flush_function_responses()
            contents.append(types.Content(role="user", parts=[types.Part(text=content)]))
        elif role == "assistant":
            _flush_function_responses()
            tool_calls = msg.get("tool_calls") or []
            parts = []
            if content:
                parts.append(types.Part(text=content))
            for tc in tool_calls:
                fn = tc.get("function", {})
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                parts.append(types.Part(function_call=types.FunctionCall(name=fn.get("name", ""), args=args)))
            if not parts:
                parts = [types.Part(text="")]
            contents.append(types.Content(role="model", parts=parts))
        elif role == "tool":
            # Gemini matches a function_response to its function_call by
            # `name`, grouped into the SAME user-role turn -- accumulate
            # until the next non-tool message forces a flush.
            try:
                response_obj = json.loads(content)
            except json.JSONDecodeError:
                response_obj = {"result": content}
            if not isinstance(response_obj, dict):
                response_obj = {"result": response_obj}
            pending_function_responses.append(
                types.Part(function_response=types.FunctionResponse(name=msg.get("name", ""), response=response_obj))
            )
    _flush_function_responses()

    system_instruction = "\n\n".join(system_parts) if system_parts else None
    return system_instruction, contents


def chat(messages: list[dict], temperature: float = 0.4, max_tokens: int = 1024,
         seed: int | None = None) -> str:
    system_instruction, contents = _to_contents(messages)
    config = types.GenerateContentConfig(
        temperature=temperature, max_output_tokens=max_tokens,
        system_instruction=system_instruction, thinking_config=_NO_THINKING,
        **({"seed": seed} if seed is not None else {}),
    )
    resp = _get_client().models.generate_content(model=_MODEL, contents=contents, config=config)
    return resp.text or ""


def chat_json(messages: list[dict], temperature: float = 0.0, max_tokens: int = 400,
              seed: int | None = None) -> dict:
    system_instruction, contents = _to_contents(messages)
    config = types.GenerateContentConfig(
        temperature=temperature, max_output_tokens=max_tokens,
        system_instruction=system_instruction, response_mime_type="application/json",
        thinking_config=_NO_THINKING,
        **({"seed": seed} if seed is not None else {}),
    )
    resp = _get_client().models.generate_content(model=_MODEL, contents=contents, config=config)
    raw = resp.text or "{}"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_parse_error": True, "_raw": raw}


class _FunctionShim:
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class _ToolCallShim:
    """Mimics the subset of Groq/OpenAI's ChatCompletionMessageToolCall
    shape every caller in this project actually reads: `.id`,
    `.function.name`, `.function.arguments` (a JSON string), and
    `.model_dump()` (used to re-serialize the turn back into history)."""

    def __init__(self, name: str, args: dict):
        self.id = f"call_{uuid.uuid4().hex[:24]}"
        self.type = "function"
        self.function = _FunctionShim(name, json.dumps(args))

    def model_dump(self) -> dict:
        return {"id": self.id, "type": self.type,
                "function": {"name": self.function.name, "arguments": self.function.arguments}}


class _MessageShim:
    def __init__(self, content: str | None, tool_calls: list[_ToolCallShim] | None):
        self.content = content
        self.tool_calls = tool_calls or None


def _to_gemini_tools(tools: list[dict]) -> types.Tool:
    """OpenAI-shaped tool schemas
    ({"type": "function", "function": {"name", "description", "parameters"}})
    -> a single Gemini Tool with one FunctionDeclaration per entry."""
    declarations = []
    for t in tools:
        fn = t.get("function", t)
        declarations.append(types.FunctionDeclaration(
            name=fn["name"], description=fn.get("description", ""),
            parameters=fn.get("parameters", {"type": "object", "properties": {}}),
        ))
    return types.Tool(function_declarations=declarations)


def chat_tools(messages: list[dict], tools: list[dict], temperature: float = 0.3,
               max_tokens: int = 600, seed: int | None = None):
    system_instruction, contents = _to_contents(messages)
    config = types.GenerateContentConfig(
        temperature=temperature, max_output_tokens=max_tokens,
        system_instruction=system_instruction, tools=[_to_gemini_tools(tools)],
        # The SDK's automatic-function-calling feature (it tries to match
        # declared tools against local Python callables and execute them
        # itself) was found, live, to silently swallow the entire response
        # -- STOP finish_reason, zero output tokens, no error, no safety
        # rating -- once a specific 9-tool set was passed (reproduced,
        # bisected to exactly this combination; not a schema or safety-
        # filter issue, confirmed by testing both directly). Aginiti always
        # handles tool_calls manually (see DemoAgent._run_tool_loop), so
        # this feature is never wanted here regardless -- disabling it is
        # the correct configuration, not just a workaround for the bug.
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        thinking_config=_NO_THINKING,
        **({"seed": seed} if seed is not None else {}),
    )
    resp = _get_client().models.generate_content(model=_MODEL, contents=contents, config=config)

    candidate = resp.candidates[0] if resp.candidates else None
    parts = candidate.content.parts if candidate and candidate.content else []
    text_parts = [p.text for p in parts if getattr(p, "text", None)]
    fn_calls = [p.function_call for p in parts if getattr(p, "function_call", None) is not None]

    content = "".join(text_parts) if text_parts else None
    tool_calls = [_ToolCallShim(fc.name, dict(fc.args or {})) for fc in fn_calls] if fn_calls else None
    return _MessageShim(content, tool_calls)
