"""Attack-surface / methodology taxonomy, added 2026-08-12 at explicit
user direction to organize Aginiti's operator library around the named
categories the tool needs to be strong (and demonstrably intelligent) at:
direct prompt attacks, encoding attacks, RAG poisoning, indirect injection,
tool discovery, tool manipulation, markdown/network exfiltration,
multi-step chains, decoy attacks, known-defended attacks, and low-value
reconnaissance.

Deliberately a SEPARATE, additive dimension from security_boundary.py
(how deep a finding went) and owasp_llm_taxonomy.py (which OWASP LLM Top
10 risk it maps to) -- same discipline as those two modules establish:
this answers "what KIND of attack methodology is this," a question
neither of the other two dimensions answers. An effect can carry all
three independently. See mitre_atlas_refs.py for a fourth, narrower
dimension (verified MITRE ATLAS technique IDs, applied only where a real
citation exists -- not fabricated).

The last three categories (DECOY, KNOWN_DEFENDED, LOW_VALUE_RECON) are not
"attacks" in the offensive sense -- they are Aginiti's own established
planner-evaluation controls (see aginiti/operators/definitions.py's
`branch="decoy"` operators and this project's own docs/EVIDENCE_AND_
EVALUATION.md discussion of "known-defended trap" operators like
memory_context_leakage_probe). Naming them alongside the real attack
categories, rather than in a separate module, is deliberate: it makes
"is this operator pulling its weight, or is it structurally a control/
low-value probe" a single, queryable fact instead of tribal knowledge
buried in code comments and test names.

Deliberately opt-in, same as every taxonomy module before it: only
retrofitted onto operators this project can honestly justify a category
for, not blanket-applied from a desk-guess."""
from __future__ import annotations

# -- real attack methodologies -------------------------------------------
DIRECT_PROMPT_ATTACK = "direct_prompt_attack"
ENCODING_ATTACK = "encoding_attack"
RAG_POISONING = "rag_poisoning"
INDIRECT_INJECTION = "indirect_injection"
TOOL_DISCOVERY = "tool_discovery"
TOOL_MANIPULATION = "tool_manipulation"
MARKDOWN_NETWORK_EXFILTRATION = "markdown_network_exfiltration"
MULTI_STEP_CHAIN = "multi_step_chain"

# -- planner-evaluation controls, not offensive techniques -----------------
DECOY = "decoy"
KNOWN_DEFENDED = "known_defended"
LOW_VALUE_RECONNAISSANCE = "low_value_reconnaissance"

ALL_CATEGORIES = (
    DIRECT_PROMPT_ATTACK, ENCODING_ATTACK, RAG_POISONING, INDIRECT_INJECTION,
    TOOL_DISCOVERY, TOOL_MANIPULATION, MARKDOWN_NETWORK_EXFILTRATION, MULTI_STEP_CHAIN,
    DECOY, KNOWN_DEFENDED, LOW_VALUE_RECONNAISSANCE,
)

# Categories that represent a genuine offensive technique -- used to filter
# "real attack coverage" reporting away from the 3 planner-control
# categories, which should never count toward "how many attack techniques
# does Aginiti cover."
OFFENSIVE_CATEGORIES = (
    DIRECT_PROMPT_ATTACK, ENCODING_ATTACK, RAG_POISONING, INDIRECT_INJECTION,
    TOOL_DISCOVERY, TOOL_MANIPULATION, MARKDOWN_NETWORK_EXFILTRATION, MULTI_STEP_CHAIN,
)

CATEGORY_TITLES = {
    DIRECT_PROMPT_ATTACK: "Direct Prompt Attack",
    ENCODING_ATTACK: "Encoding / Transformation Attack",
    RAG_POISONING: "RAG Poisoning",
    INDIRECT_INJECTION: "Indirect Injection",
    TOOL_DISCOVERY: "Tool Discovery",
    TOOL_MANIPULATION: "Tool Manipulation",
    MARKDOWN_NETWORK_EXFILTRATION: "Markdown / Network Exfiltration",
    MULTI_STEP_CHAIN: "Multi-Step Chain",
    DECOY: "Decoy (planner-evaluation control)",
    KNOWN_DEFENDED: "Known-Defended (planner-evaluation control)",
    LOW_VALUE_RECONNAISSANCE: "Low-Value Reconnaissance (planner-evaluation control)",
}


def validate(category: str) -> bool:
    return category in ALL_CATEGORIES


def is_offensive(category: str) -> bool:
    return category in OFFENSIVE_CATEGORIES


def operator_primary_family(operator) -> str | None:
    """The single `attack_category` an operator itself represents: its own
    declared SUCCESS effect's tag if one is set, else its own declared
    FAILURE effect's tag, else None -- the ONE canonical place this rule
    lives. Added 2026-08-14 to close a real, live duplication risk: this
    exact "success effect's tag first, else a failure effect's" logic was
    independently inlined in THREE places (aginiti/graph/novelty.py's
    `operator_family_diversification`, aginiti/graph/target_belief.py's
    `_operator_family_map`, and now aginiti/adapter/observation_adapter.py's
    independent-evidence attribution) before this existed -- exactly the
    "MUST mirror" duplication pattern schema.py's own IMPORTANCE_WEIGHT
    consolidation comment warns against silently drifting apart. Takes a
    bare `Operator` (imported lazily by callers to avoid a circular import
    with aginiti/operators/library.py, which does not import this module)."""
    for effect in operator.effects_success:
        if effect.attack_category is not None:
            return effect.attack_category
    for effect in operator.effects_failure:
        if effect.attack_category is not None:
            return effect.attack_category
    return None
