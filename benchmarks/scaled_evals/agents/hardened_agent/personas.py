"""
Persona -> access-scope mapping for ``hardened_agent`` (RBAC).

Three personas, each with a genuinely different visibility scope — not a
flat "more vs. less access" hierarchy. See
``plans/vanilla-target-agent.md`` §2.4 for the full reasoning; summary:

- ``legal``   — CUAD (legal/contract) documents ONLY.
- ``support`` — CFPB (support-ticket/complaint) documents ONLY.
                ``legal`` and ``support`` share ZERO document overlap by
                construction (see ``prepare_hardened_dataset.py`` — every
                record is tagged with exactly one ``source``) — this is the
                **disjoint-boundary test**: does querying as one persona
                ever surface the other's documents?
- ``ops``     — a *subset* of BOTH domains (never full access to either),
                marked via the ``ops_visible`` flag at dataset-prep time.
                This is the **aggregation-risk test**: individually-
                authorized access to two systems whose combination could
                surface something neither domain alone would.

API keys are read from environment variables, never hardcoded — set
``HARDENED_AGENT_LEGAL_API_KEY`` / ``HARDENED_AGENT_SUPPORT_API_KEY`` /
``HARDENED_AGENT_OPS_API_KEY`` in your ``.env`` (see repo-root
``.env.example``). A caller authenticates by sending
``Authorization: Bearer <one of these keys>``, same convention this
project already uses for its `AgentEndpoint`/`endpoint_kwargs` connector
work.
"""
from __future__ import annotations

import os

# Maps each persona to the ChromaDB `where` metadata filter that scopes its
# retrieval — see prepare_hardened_dataset.py for where `source`/
# `ops_visible` are set on each record.
_PERSONA_CHROMA_FILTERS: dict[str, dict] = {
    "legal": {"source": "cuad"},
    "support": {"source": "cfpb"},
    "ops": {"ops_visible": True},
}

PERSONAS = tuple(_PERSONA_CHROMA_FILTERS)

# Toggle with HARDENED_AGENT_RBAC_ENABLED (default: enabled) — same on/off
# ablation pattern as the other three defenses (agent.py's
# RATE_LIMIT_ENABLED/REDACTION_ENABLED/MEMORY_ENABLED). Added 2026-08-07 in
# response to a direct question: with RBAC always on, there was no way to
# measure what IKEA achieves against a RAG agent that has every OTHER
# defense (rate limiting, redaction, memory-based caution) but where RBAC
# specifically is missing or misconfigured — a real, common failure mode
# ("the retrieval layer forgot to apply the access-scope filter"), distinct
# from "no defenses at all." Authentication itself (resolve_persona, 401 on
# a bad/missing key) is NOT gated by this — a misconfigured-RBAC deployment
# still authenticates callers, it just fails to scope what an authenticated
# caller can retrieve. Off => every persona effectively shares the same,
# fully-open retrieval scope.
RBAC_ENABLED = os.getenv(
    "HARDENED_AGENT_RBAC_ENABLED", "true"
).lower() not in ("false", "0", "no")


def _api_key_env_var(persona: str) -> str:
    return f"HARDENED_AGENT_{persona.upper()}_API_KEY"


def resolve_persona(api_key: str) -> str | None:
    """Maps a bearer API key back to its persona name, or None if the key
    doesn't match any configured persona."""
    if not api_key:
        return None
    for persona in PERSONAS:
        expected = os.environ.get(_api_key_env_var(persona))
        if expected and api_key == expected:
            return persona
    return None


def chroma_filter_for(persona: str) -> dict | None:
    """Raises KeyError for an unrecognized persona — callers should only
    ever pass a value already validated by resolve_persona(). The persona
    is still validated even when RBAC is toggled off below (an unknown
    persona is a bug regardless of the RBAC ablation setting) — only the
    filter actually applied to retrieval changes.

    Returns None (no ChromaDB `where` filter — full, unscoped corpus) when
    RBAC_ENABLED is false, simulating a RAG deployment where access-control
    scoping was never wired into the retrieval layer."""
    if persona not in _PERSONA_CHROMA_FILTERS:
        raise KeyError(persona)
    return _PERSONA_CHROMA_FILTERS[persona] if RBAC_ENABLED else None
