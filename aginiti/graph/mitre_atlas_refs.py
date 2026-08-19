"""MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence
Systems, atlas.mitre.org) technique-ID references, added 2026-08-12 in
direct response to "there are also other latest work done other than
OWASP so we should see that too."

Deliberately NOT a full parallel taxonomy module like owasp_llm_taxonomy.py
or attack_category.py -- ATLAS has 84 techniques across 16 tactics as of
v5.1.0 (November 2025) and this project has not read the full matrix
closely enough to responsibly tag against all of it. What follows are only
the five technique IDs this project has independently verified (via live
web search against startupdefense.io's ATLAS technique pages and MITRE's
own site, 2026-08-12 -- not recalled from training data, which would risk
citing a stale or renumbered ID the way owasp_llm_taxonomy.py's own
docstring warns about for OWASP's 2023-vs-2025 LLM Top 10 renumbering).
Every operator tag below cites one of these five; no operator anywhere in
this codebase is tagged with an ATLAS ID that isn't in this dict --
fabricating a plausible-looking AML.T00xx code would be a real, citable
mistake in a compliance-facing report, not a cosmetic one.

    AML.T0051     LLM Prompt Injection (parent technique)
    AML.T0051.000   |- Direct
    AML.T0051.001   |- Indirect
    AML.T0054     LLM Jailbreak
    AML.T0070     RAG Poisoning (added in the Spring 2025 ATLAS release)
    AML.T0086     Exfiltration via AI Agent Tool Invocation

If a category doesn't appear below (tool discovery, tool manipulation, the
planner-evaluation controls), that's an honest "not verified yet," not an
implicit claim those categories have no ATLAS coverage -- a real next step
once the rest of the matrix has been read as carefully as these five."""
from __future__ import annotations

DIRECT_PROMPT_INJECTION = "AML.T0051.000"
INDIRECT_PROMPT_INJECTION = "AML.T0051.001"
LLM_JAILBREAK = "AML.T0054"
RAG_POISONING = "AML.T0070"
EXFILTRATION_VIA_TOOL_INVOCATION = "AML.T0086"

TECHNIQUE_TITLES = {
    DIRECT_PROMPT_INJECTION: "LLM Prompt Injection: Direct",
    INDIRECT_PROMPT_INJECTION: "LLM Prompt Injection: Indirect",
    LLM_JAILBREAK: "LLM Jailbreak",
    RAG_POISONING: "RAG Poisoning",
    EXFILTRATION_VIA_TOOL_INVOCATION: "Exfiltration via AI Agent Tool Invocation",
}

ALL_VERIFIED_TECHNIQUES = tuple(TECHNIQUE_TITLES.keys())


def validate(technique_id: str) -> bool:
    return technique_id in TECHNIQUE_TITLES
