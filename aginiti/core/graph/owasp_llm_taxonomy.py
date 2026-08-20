"""OWASP Top 10 for LLM Applications (2025 edition, v2.0, published
2024-11-18) tagging -- added 2026-08-12 after exp19's real comparison
against garak surfaced a genuine gap: garak tags every probe with
industry-standard taxonomy (AVID, OWASP LLM Top 10, CWE, a MISP-compatible
`--taxonomy` flag); Aginiti's own L0-L5 security_boundary system (see
security_boundary.py) is real and useful but maps to nothing an outside
security/compliance team already recognizes. This closes that gap.

Deliberately a SEPARATE, additive dimension from security_boundary.py, the
same way security_boundary itself is separate from CATEGORY_* (ssg.py):
OWASP_LLM answers "which OWASP LLM Top 10 risk category is this," L0-L5
answers "how deep did this go if real," CATEGORY_* answers "what kind of
graph fact is this." An effect can carry all three independently.

The 10 categories below were verified against OWASP's own current 2025
list (genai.owasp.org), not assumed from an older (2023) version whose
category numbers/names had since been reordered and partly merged
(Overreliance was folded into LLM09:2025 Misinformation, for example) --
citing a stale category number in a compliance-facing report would be a
real, embarrassing mistake, not a cosmetic one.

Deliberately opt-in, same discipline as security_boundary.py: only
retrofitted onto operators this project has genuinely live-tested and can
justify a mapping for, not blanket-applied to the whole repo from a
desk-guess."""
from __future__ import annotations

LLM01_PROMPT_INJECTION = "LLM01:2025_prompt_injection"
LLM02_SENSITIVE_INFORMATION_DISCLOSURE = "LLM02:2025_sensitive_information_disclosure"
LLM03_SUPPLY_CHAIN = "LLM03:2025_supply_chain"
LLM04_DATA_AND_MODEL_POISONING = "LLM04:2025_data_and_model_poisoning"
LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05:2025_improper_output_handling"
LLM06_EXCESSIVE_AGENCY = "LLM06:2025_excessive_agency"
LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07:2025_system_prompt_leakage"
LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES = "LLM08:2025_vector_and_embedding_weaknesses"
LLM09_MISINFORMATION = "LLM09:2025_misinformation"
LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2025_unbounded_consumption"

ALL_CATEGORIES = (
    LLM01_PROMPT_INJECTION, LLM02_SENSITIVE_INFORMATION_DISCLOSURE, LLM03_SUPPLY_CHAIN,
    LLM04_DATA_AND_MODEL_POISONING, LLM05_IMPROPER_OUTPUT_HANDLING, LLM06_EXCESSIVE_AGENCY,
    LLM07_SYSTEM_PROMPT_LEAKAGE, LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES, LLM09_MISINFORMATION,
    LLM10_UNBOUNDED_CONSUMPTION,
)

CATEGORY_TITLES = {
    LLM01_PROMPT_INJECTION: "Prompt Injection",
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE: "Sensitive Information Disclosure",
    LLM03_SUPPLY_CHAIN: "Supply Chain",
    LLM04_DATA_AND_MODEL_POISONING: "Data and Model Poisoning",
    LLM05_IMPROPER_OUTPUT_HANDLING: "Improper Output Handling",
    LLM06_EXCESSIVE_AGENCY: "Excessive Agency",
    LLM07_SYSTEM_PROMPT_LEAKAGE: "System Prompt Leakage",
    LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES: "Vector and Embedding Weaknesses",
    LLM09_MISINFORMATION: "Misinformation",
    LLM10_UNBOUNDED_CONSUMPTION: "Unbounded Consumption",
}


def validate(category: str) -> bool:
    return category in ALL_CATEGORIES
