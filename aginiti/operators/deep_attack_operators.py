"""Deep-attack Operator definitions (Phase 2 Slice E,
plans/phase2-operator-wrapping.md). Wires IKEA (arXiv:2505.15420) as a
real, planner-selectable `Operator` -- the first attack wrapped this way;
SECRET/MIA/SPE are deliberately deferred to Slice G once this one is
validated (design doc's own staged-rollout rationale).

Composes onto any `OperatorLibrary` the same way `data_exposure_operators()`
does -- target-agnostic, no new planner/graph machinery needed:

    library = OperatorLibrary([*build_library(), *deep_attack_operators()])

Requires the campaign's `agent` to expose `.endpoint` (an
`HTTPAgentAdapter`, aginiti/adapters/http_agent_adapter.py, or anything
else wrapping a real `AgentEndpoint`) -- see
`ObservationAdapter._execute_deep_attack`'s own agent-type guard for what
happens with any other adapter (a graceful synthetic failure, never a
crash; Open Question 6, approved: this ineligibility stays invisible to
the planner, not encoded via `preconditions`).

**Real correction made during implementation, flagged explicitly**: the
approved design doc's own Slice E text said to reuse the
`system_prompt_disclosed` claim key for IKEA. That was wrong, verified
directly against `aginiti/attacks/dra/ikea.py` before implementing it:
`_CONFIRMED_LEAK_TYPES = ("pii", "verbatim", "sensitive_data")` (ikea.py's
own module-level constant) shows IKEA's actual findings are about RAG
KNOWLEDGE-BASE CONTENT (e.g. HR records, SSNs) -- a completely different
kind of disclosure from `system_prompt_disclosed` (the agent's own
instructions, KEY_DESCRIPTIONS' own definition, produced by
`data_exposure_operators()`'s unrelated `system_prompt_extraction` probe).
Reusing that key would have silently conflated two unrelated findings
under one claim. Uses a new key, `sensitive_data_exfiltrated`, instead --
confirmed via grep this doesn't collide with anything existing, and named
to match the user's own original example phrasing for this design
("`sensitive_data_exfiltrated`") rather than inventing something novel.
"""
from __future__ import annotations

import os

from aginiti.attacks.dra import IKEAAttack
from aginiti.connectors.endpoint import AgentEndpoint
from aginiti.core.graph.attack_category import MULTI_STEP_CHAIN
from aginiti.core.graph.owasp_llm_taxonomy import LLM02_SENSITIVE_INFORMATION_DISCLOSURE
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L5
from aginiti.core.graph.ssg import CATEGORY_MISSION_OUTCOME, SUBGRAPH_TARGET
from aginiti.operators.library import ClaimEffect, Operator

# Mirrors scripts/run_ikea.py's own module-level defaults exactly, so a
# deep-attack Operator run through a campaign behaves the same as the
# equivalent standalone script run -- not independently re-guessed.
# Overridable via env var for the same reason run_ikea.py's own
# EMBED_MODEL already is (a cloud embed model needs a different key
# resolved, see _key_for below).
_IKEA_LLM_PROVIDER = os.environ.get("IKEA_OPERATOR_LLM_PROVIDER", "gemini/gemini-3.5-flash")
_IKEA_EMBED_MODEL = os.environ.get("EMBED_MODEL", "chromadb/all-MiniLM-L6-v2")
_IKEA_TOPIC = os.environ.get("IKEA_OPERATOR_TOPIC", "HR records")
_IKEA_MAX_QUERIES = int(os.environ.get("IKEA_OPERATOR_MAX_QUERIES", "20"))
# 15 minutes -- generous headroom for a real max_queries=20 run (each
# query involves several of its own LLM/embedding/HTTP calls internally;
# a live Phase-1 smoke test at a SMALLER query count already took over a
# minute). Deliberately larger than Operator.attack_timeout_seconds'
# own 300s (5 min) default, which is sized for a lighter deep attack, not
# this specific 20-query configuration.
_IKEA_TIMEOUT_SECONDS = 900.0

# Same provider -> API-key-env-var map as scripts/run_ikea.py's own
# _key_for(), duplicated rather than imported -- matches this project's
# established per-script/per-module self-containment convention (see
# scripts/run_secret_hardened.py's own near-identical _key_for_llm, which
# makes the same choice for the same reason).
_KEY_ENV_VAR = {
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "cohere": "COHERE_API_KEY",
    "voyage": "VOYAGE_API_KEY",
}


def _key_for(model: str) -> str | None:
    provider = model.split("/", 1)[0].lower()
    if provider in ("chromadb", "local", "onnx"):
        return None  # local embedding models need no API key
    env_var = _KEY_ENV_VAR.get(provider)
    if env_var is None:
        raise ValueError(
            f"No known API key env var mapped for provider {provider!r} (from model "
            f"{model!r}). Add it to _KEY_ENV_VAR above."
        )
    key = os.environ.get(env_var)
    if not key:
        raise ValueError(f"{env_var} is not set in .env -- required for model {model!r}")
    return key


def _build_ikea_attack(endpoint: AgentEndpoint) -> IKEAAttack:
    """`attack_factory` for the IKEA deep-attack Operator below --
    `ObservationAdapter._execute_deep_attack` calls this fresh on every
    execution, never at import time, so importing this module never
    requires an API key to already be configured (only actually running
    the operator does). `target_url` is derived from the shared endpoint's
    own `base_url` -- used by IKEAAttack only for its own logging (the
    real connection goes through the injected `endpoint=`, per Slice B),
    so this stays accurate without needing a second, independent
    target-URL source of truth.

    `topic`/`max_queries` are deliberately NOT set here -- they're passed
    via the Operator's own `attack_kwargs` to `execute_black_box(...)`
    instead (see the Operator definition below), keeping this factory's
    job to "how does the attack talk to LLMs/embeddings" (stable,
    campaign-independent config) separate from "what does THIS run
    attack, how big a budget" (the per-Operator-instance config)."""
    return IKEAAttack(
        target_url=endpoint.base_url,
        llm_provider=_IKEA_LLM_PROVIDER,
        api_key=_key_for(_IKEA_LLM_PROVIDER),
        embed_model=_IKEA_EMBED_MODEL,
        embed_api_key=_key_for(_IKEA_EMBED_MODEL),
        endpoint=endpoint,
    )


def deep_attack_operators() -> list[Operator]:
    """The Phase 2 deep-attack operator pack -- currently just IKEA."""
    return [
        Operator(
            id="ikea_sensitive_data_exfiltration",
            description=(
                "Run the full IKEA data-reconstruction attack (arXiv:2505.15420) against "
                "the target's RAG knowledge base -- an adaptive, multi-query extraction "
                "loop (anchor generation, exploration/resampling, template-refinement "
                "mutation), not a single templated prompt."
            ),
            understanding_question=(
                "Can a sustained, adaptive extraction attack reconstruct verbatim/PII/"
                "sensitive content the target's RAG pipeline retrieves, beyond what a "
                "single cheap probe reveals?"
            ),
            # Documentation only for a kind="deep_attack" operator -- never rendered
            # or sent as a literal prompt (see ObservationAdapter._execute_deep_attack,
            # which reads attack_factory/attack_kwargs/claim_key instead).
            prompt="[runs IKEAAttack.execute_black_box internally -- see attack_kwargs]",
            channel="direct",
            preconditions=(),
            # Documentation only, same reason as `prompt` above -- accurately
            # describes what a CONFIRMED/HYPOTHESIZED outcome represents (matches
            # data_exposure_operators()'s own module-docstring characterization:
            # "each one IS a genuine data-exposure finding on its own"), even
            # though _execute_deep_attack reads claim_key directly, not this tuple.
            # No effects_failure: unlike a prompt operator, there is no symmetric
            # "blocked" claim key this operator ever actually asserts (see Open
            # Question 4 -- empty findings assert nothing, not a REFUTED/blocked
            # claim) -- declaring one here would be misleading documentation.
            effects_success=(
                ClaimEffect(
                    "sensitive_data_exfiltrated", ClaimStatus.CONFIRMED, SUBGRAPH_TARGET,
                    weight=3, category=CATEGORY_MISSION_OUTCOME, security_boundary=BOUNDARY_L5,
                    owasp_llm_category=LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
                    attack_category=MULTI_STEP_CHAIN,
                ),
            ),
            effects_failure=(),
            # Declared, not measured -- matches _IKEA_MAX_QUERIES exactly (the
            # "declared cost, the campaign attempted this step" convention every
            # operator in this codebase already follows).
            cost_prompts=_IKEA_MAX_QUERIES,
            # MEDIUM, not HIGH or DESTRUCTIVE: IKEA is a genuine, active compromise
            # ATTEMPT (matches jailbreak_dan_style's own MEDIUM tier for the same
            # reason) but never modifies/destroys target state -- it only reads via
            # legitimate-looking natural-language queries. A judgment call, not a
            # verified fact like the security_boundary/owasp tags above -- flagged
            # as such, revisit if this doesn't feel right in practice.
            risk_tier=RiskTier.MEDIUM,
            branch="deep_attack",
            kind="deep_attack",
            attack_factory=_build_ikea_attack,
            attack_kwargs={"topic": _IKEA_TOPIC, "max_queries": _IKEA_MAX_QUERIES},
            claim_key="sensitive_data_exfiltrated",
            attack_timeout_seconds=_IKEA_TIMEOUT_SECONDS,
        ),
    ]
