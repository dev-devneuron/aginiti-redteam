# aginiti/connectors — how Aginiti talks to the target under test

This directory is scoped to exactly one concern: HTTP communication with
the **target agent being evaluated**. It is the opposite side of the line
from `aginiti/providers/`, which holds how Aginiti powers its **own**
reasoning (LLM/embedding calls) — see `aginiti/providers/README.md` for
the full split rationale.

| Module | What it does |
|---|---|
| `endpoint.py` (`AgentEndpoint`) | Generic HTTP client for a black-box target agent. Default: POST `{request_key: message}` to `base_url + endpoint`, expect a flat JSON response. `headers`/`send_fn` support authenticated or non-flat-JSON targets without assuming any one target's specific schema — see the class's own docstring before adding a target-specific parameter here; keep it generic. |
| `embedding.py` | Backward-compatible re-export shim — the real implementation moved to `aginiti/providers/embedding.py`. |

`AgentEndpoint` must not assume the target's schema matches this project's
own reference agents exactly — it's meant to support "any HTTP-accessible
agent" (the Tier 1 promise), authenticated or not.
