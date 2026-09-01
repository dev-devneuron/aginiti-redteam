# aginiti/providers — how Aginiti powers its own reasoning

This package holds Aginiti's own LLM and embedding provider clients: the
calls the *attacker/judge side* of the library makes to generate queries,
grade responses, extract claims, and compute similarity — not the calls
made to whatever target agent is under test.

| Module | What it does |
|---|---|
| `llm.py` | LiteLLM-backed `chat` / `chat_json` / `chat_tools`, with pooled-key rotation and automatic Groq→Gemini fallback. |
| `embedding.py` | `embed_texts` — routes `chromadb/*` models to local ONNX, every other `<provider>/*` to `litellm.embedding()`. |

## Why a separate package from `connectors/`

`aginiti/connectors/endpoint.py`'s `AgentEndpoint` is a different concern
entirely: it's how Aginiti talks to the **target under test** over HTTP.
This package is how Aginiti powers **its own** reasoning. Conflating the
two under one `connectors/` directory would blur a distinction every
attack module and adapter already depends on (compare LangChain's
`llms/`/`embeddings/` vs. its retriever/tool connectors, or PyRIT's
`prompt_target` vs. model-access split — PyRIT is already cited elsewhere
in this codebase, see `aginiti/transforms/converters.py`).

`utils/` was considered and rejected as a name for this code: LLM/
embedding provider routing is domain-specific integration logic (key
rotation, provider-string parsing, fallback triggers), not generic
helpers a `utils/` label would suggest.

## Backward compatibility

`aginiti/core/llm.py` and `aginiti/connectors/embedding.py` remain as
thin re-export shims pointing here, so external code importing the old
paths keeps working. New code — inside this library or a consumer of
it — should import from `aginiti.providers.llm` / `aginiti.providers.embedding`
directly.

## LLM provider abstraction

Every LLM call in this package goes through
[LiteLLM](https://docs.litellm.ai/) — never a hardcoded provider SDK or an
assumed response shape. See the repo root `README.md` for supported
providers and the required environment variables.
