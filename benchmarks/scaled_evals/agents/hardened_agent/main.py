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
three personas (see personas.py) via EITHER
``Authorization: Bearer <HARDENED_AGENT_{LEGAL,SUPPORT,OPS}_API_KEY>`` (the
original long-lived static key, still fully supported) OR a short-lived
session token minted via ``POST /auth/session`` (see agent.py's
SessionStore docstring) — a request with no/
unrecognized/expired credential gets 401, not a degraded-but-still-answered
response.

Seven independently-toggleable defenses, all on by default — flip any of
these to false for an on/off ablation comparison (see
plans/vanilla-target-agent.md §1.2/§2.2/§9/§11 and the conversation-memory
addition), no code changes needed between runs:
    HARDENED_AGENT_RATE_LIMIT_ENABLED=false   # 429 once a persona exceeds its window
    HARDENED_AGENT_REDACTION_ENABLED=false    # output-side PII/secret regex scrubbing
    HARDENED_AGENT_MEMORY_ENABLED=false       # per-persona conversation history
    HARDENED_AGENT_RBAC_ENABLED=false         # persona-scoped retrieval filter (simulates
                                               # a RAG deployment where access control was
                                               # never wired into the retrieval layer)
    HARDENED_AGENT_GUARDRAIL_ENABLED=false    # system-prompt instruction not to reveal
                                               # PII/secrets/confidential data, regardless
                                               # of how the request is phrased — domain- and
                                               # attack-agnostic (see agent.py's
                                               # _GUARDRAIL_SUFFIX docstring)
    HARDENED_AGENT_INPUT_FILTER_ENABLED=false # dedicated pre-flight classifier that can
                                               # hard-block a request before retrieval/
                                               # generation ever runs — a genuinely SEPARATE
                                               # layer from GUARDRAIL_ENABLED's soft prompt-
                                               # level nudge (see agent.py's
                                               # INPUT_FILTER_ENABLED docstring)
    HARDENED_AGENT_AUDIT_LOG_ENABLED=false    # structured JSONL request log (metadata only,
                                               # never raw question/answer text — see
                                               # agent.py's audit_log() docstring). Not really
                                               # part of the ablation matrix (logging doesn't
                                               # change what gets answered) — toggle exists for
                                               # local dev/test convenience.

Other production-realism additions, not togglable ablations
(they don't have an "off" state that makes sense to compare against):
    HARDENED_AGENT_SESSION_TTL_SECONDS=900    # session-token lifetime (POST/DELETE
                                               # /auth/session — see agent.py's SessionStore)
A handful of synthetic "canary" secrets (fake API key / webhook URL / case
PIN / ops credential) are planted in the seeded corpus alongside the real
CUAD/CFPB documents — see hardened_dataset_canaries.json and seed.py for
how they're merged in, and that JSON file's own docstring for why some are
deliberately NOT caught by output redaction (guaranteed, format-agnostic
ground truth for genuine end-to-end disclosure) while one deliberately IS
(tests whether redaction catches a recognizable secret shape).

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
    AUDIT_LOG_ENABLED,
    GUARDRAIL_ENABLED,
    INPUT_FILTER_ENABLED,
    MEMORY_ENABLED,
    RATE_LIMIT_ENABLED,
    REDACTION_ENABLED,
    SESSION_TOKEN_PREFIX,
    SESSION_TTL_SECONDS,
    TOOL_RBAC_ENABLED,
    TOOLS_ENABLED,
    HardenedAgent,
    RateLimiter,
    SessionStore,
    audit_log,
)
from .personas import RBAC_ENABLED, resolve_persona

logger = logging.getLogger(__name__)

app = FastAPI(title="Aginiti Reference Agent — hardened_agent", version="0.1.0")
_agent = HardenedAgent()
_rate_limiter = RateLimiter()
_sessions = SessionStore()

logger.info(
    "hardened_agent starting — rbac=%s rate_limit=%s redaction=%s memory=%s guardrail=%s "
    "input_filter=%s audit_log=%s session_ttl=%ss tools=%s tool_rbac=%s",
    RBAC_ENABLED, RATE_LIMIT_ENABLED, REDACTION_ENABLED, MEMORY_ENABLED, GUARDRAIL_ENABLED,
    INPUT_FILTER_ENABLED, AUDIT_LOG_ENABLED, SESSION_TTL_SECONDS, TOOLS_ENABLED, TOOL_RBAC_ENABLED,
)


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


class SessionResponse(BaseModel):
    session_token: str
    expires_in_seconds: float
    persona: str


def _resolve_caller(authorization: str | None) -> str:
    """Shared auth resolution for `/chat` and `DELETE /auth/session` --
    accepts EITHER a long-lived persona API key (existing behavior,
    unlimited TTL) OR a short-lived `sess_`-prefixed session token minted
    by `POST /auth/session` (see agent.py's SessionStore docstring for the
    full design). Raises HTTPException(401) either way on failure, same
    as the original inline check this replaces."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    if token.startswith(SESSION_TOKEN_PREFIX):
        persona = _sessions.resolve(token)
        if persona is None:
            raise HTTPException(status_code=401, detail="Session expired or invalid — request a new one via POST /auth/session")
        return persona

    persona = resolve_persona(token)
    if persona is None:
        raise HTTPException(status_code=401, detail="Unrecognized API key")
    return persona


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, authorization: str | None = Header(default=None)) -> ChatResponse:
    persona = _resolve_caller(authorization)

    if RATE_LIMIT_ENABLED and not _rate_limiter.check(persona):
        audit_log("chat_rejected", persona=persona, reason="rate_limited")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    return ChatResponse(response=_agent.query(req.message, persona=persona))


@app.post("/auth/session", response_model=SessionResponse)
def create_session(authorization: str | None = Header(default=None)) -> SessionResponse:
    """Exchange a persona's long-lived static API key for a short-lived
    session token (see agent.py's SessionStore docstring). Requires the
    STATIC key specifically -- a session token cannot be used to mint
    another session token (no session-token-renewal chain), matching how
    a real OAuth refresh flow still anchors back to a real credential, not
    an already-issued short-lived token renewing itself indefinitely."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    api_key = authorization.removeprefix("Bearer ").strip()
    if api_key.startswith(SESSION_TOKEN_PREFIX):
        raise HTTPException(status_code=401, detail="A session token cannot be used to mint another session — use your persona's static API key.")
    persona = resolve_persona(api_key)
    if persona is None:
        raise HTTPException(status_code=401, detail="Unrecognized API key")
    token, ttl = _sessions.issue(persona)
    audit_log("session_created", persona=persona)
    return SessionResponse(session_token=token, expires_in_seconds=ttl, persona=persona)


@app.delete("/auth/session", status_code=204)
def revoke_session(authorization: str | None = Header(default=None)) -> None:
    """Revoke a session token early (logout) — idempotent (revoking an
    already-expired/unknown token is not an error, matching a real logout
    endpoint). Requires a session token specifically, not a persona's
    static key (there is nothing to "revoke" for a static key)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    if not token.startswith(SESSION_TOKEN_PREFIX):
        raise HTTPException(status_code=400, detail="Not a session token")
    _sessions.revoke(token)
    audit_log("session_revoked")


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
        "input_filter_enabled": INPUT_FILTER_ENABLED,
        "audit_log_enabled": AUDIT_LOG_ENABLED,
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "tools_enabled": TOOLS_ENABLED,
        "tool_rbac_enabled": TOOL_RBAC_ENABLED,
    }


if __name__ == "__main__":
    uvicorn.run(
        "benchmarks.scaled_evals.agents.hardened_agent.main:app",
        host="0.0.0.0",
        port=8004,
        reload=False,
    )
