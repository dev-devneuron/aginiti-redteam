"""
hardened_agent — upgraded benchmark target (port 8004).

Start:
    uvicorn benchmarks.scaled_evals.agents.hardened_agent.main:app --port 8004

Or directly:
    python -m benchmarks.scaled_evals.agents.hardened_agent.main

Prepare and seed first:
    python benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py
    python -m benchmarks.scaled_evals.agents.hardened_agent.seed

Unlike healthcare_agent, every request must be authenticated as one of the
three personas (see personas.py) via
``Authorization: Bearer <HARDENED_AGENT_{LEGAL,SUPPORT,OPS}_API_KEY>`` — a
request with no/unrecognized key gets 401, not a degraded-but-still-answered
response.

Five independently-toggleable defenses, all on by default — flip any of
these to false for an on/off ablation comparison (see
plans/vanilla-target-agent.md §1.2/§2.2/§9/§11 and the conversation-memory
addition), no code changes needed between runs:
    HARDENED_AGENT_RATE_LIMIT_ENABLED=false   # 429 once a persona exceeds its window
    HARDENED_AGENT_REDACTION_ENABLED=false    # output-side PII regex scrubbing
    HARDENED_AGENT_MEMORY_ENABLED=false       # per-persona conversation history
    HARDENED_AGENT_RBAC_ENABLED=false         # persona-scoped retrieval filter (simulates
                                               # a RAG deployment where access control was
                                               # never wired into the retrieval layer)
    HARDENED_AGENT_GUARDRAIL_ENABLED=false    # system-prompt instruction not to reveal
                                               # PII/secrets/confidential data, regardless
                                               # of how the request is phrased — domain- and
                                               # attack-agnostic (see agent.py's
                                               # _GUARDRAIL_SUFFIX docstring)

Graceful LLM-call error handling (agent.py's try/except around
litellm.completion()) is deliberately NOT one of these toggles — it's
operational robustness, not a security defense under test, so there's no
ablation value in turning it off; it stays on unconditionally.
"""
from dotenv import load_dotenv

load_dotenv()  # before agent.py reads AGENT_MODEL / toggle env vars

import logging

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .agent import (
    GUARDRAIL_ENABLED,
    MEMORY_ENABLED,
    RATE_LIMIT_ENABLED,
    REDACTION_ENABLED,
    HardenedAgent,
    RateLimiter,
)
from .personas import RBAC_ENABLED, resolve_persona

logger = logging.getLogger(__name__)

app = FastAPI(title="Aginiti Reference Agent — hardened_agent", version="0.1.0")
_agent = HardenedAgent()
_rate_limiter = RateLimiter()

logger.info(
    "hardened_agent starting — rbac=%s rate_limit=%s redaction=%s memory=%s guardrail=%s",
    RBAC_ENABLED, RATE_LIMIT_ENABLED, REDACTION_ENABLED, MEMORY_ENABLED, GUARDRAIL_ENABLED,
)


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, authorization: str | None = Header(default=None)) -> ChatResponse:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    api_key = authorization.removeprefix("Bearer ").strip()
    persona = resolve_persona(api_key)
    if persona is None:
        raise HTTPException(status_code=401, detail="Unrecognized API key")

    if RATE_LIMIT_ENABLED and not _rate_limiter.check(persona):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    return ChatResponse(response=_agent.query(req.message, persona=persona))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/config")
def config():
    """Exposes which defenses are currently active — lets a benchmark
    runner script confirm the target's actual toggle state before spending
    API budget on a run, rather than trust that an env var was set
    correctly. Not a secret-bearing endpoint — no API keys or persona
    scopes are revealed here, only which layers are on/off."""
    return {
        "rbac_enabled": RBAC_ENABLED,
        "rate_limit_enabled": RATE_LIMIT_ENABLED,
        "redaction_enabled": REDACTION_ENABLED,
        "memory_enabled": MEMORY_ENABLED,
        "guardrail_enabled": GUARDRAIL_ENABLED,
    }


if __name__ == "__main__":
    uvicorn.run(
        "benchmarks.scaled_evals.agents.hardened_agent.main:app",
        host="0.0.0.0",
        port=8004,
        reload=False,
    )
