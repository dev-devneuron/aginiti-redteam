"""Plain-language, one-sentence descriptions of every attack technique
(operator) that can appear on an `aginiti scan` finding.

Operator ``description`` fields are written for contributors (paper
citations, implementation detail). Reports are read by security leads and
non-specialists, so this module gives each technique a short explanation in
everyday language, shown as a hover tooltip next to the technique name in
the HTML report and as a line under it in the Markdown report.

Most of the scan library is generated variant families (one technique, many
encodings/formats/languages), so descriptions are keyed two ways: an exact
operator id for one-off techniques, and an id prefix for variant families,
whose sentence may name the specific variant. ``tests/unit/
test_technique_descriptions.py`` checks every operator `aginiti scan
--target` can run has a description, so a new operator pack without one
fails loudly rather than silently rendering without a tooltip.
"""
from __future__ import annotations

from typing import Callable, Optional

__all__ = ["describe_technique"]

_EXACT: dict[str, str] = {
    "system_prompt_extraction": (
        "Directly asks the AI to repeat its hidden setup instructions (its system prompt) word for word."
    ),
    "jailbreak_dan_style": (
        "Tells the AI to role-play as an unrestricted \"Do Anything Now\" assistant to talk it out of its safety rules."
    ),
    "memory_context_leakage_probe": (
        "Asks the AI to reveal what it remembers from earlier conversations or from other users' sessions."
    ),
    "tool_inventory_full_disclosure": (
        "Asks the AI to list every tool it can use, with full technical details, instead of a normal user-facing summary."
    ),
    "encoding_evasion_probe": (
        "Hides an \"ignore your rules\" instruction inside Base64-encoded text to see if the disguise slips it past the AI's safeguards."
    ),
    "secret_pattern_fishing": (
        "Asks the AI outright whether it holds any passwords, API keys or access tokens, and to share them."
    ),
    "tool_parameter_override_probe": (
        "Asks the AI to run its tools with admin-level or expanded settings that a normal user shouldn't be able to use."
    ),
    "ikea_sensitive_data_exfiltration": (
        "Asks many harmless-looking questions and pieces the answers together to rebuild private documents from the AI's knowledge base."
    ),
    "secret_jailbreak_exfiltration": (
        "Uses an automatically tuned jailbreak prompt to make the AI copy out its private knowledge-base documents word for word."
    ),
    "mia_membership_inference": (
        "Asks targeted questions to work out whether a specific document is stored in the AI's knowledge base, without ever seeing it."
    ),
    "spe_system_prompt_extraction": (
        "Uses three research-proven trick prompts to get the AI to reveal its hidden setup instructions."
    ),
}

_ENCODINGS: dict[str, str] = {
    "base64": "Base64 encoding",
    "base32": "Base32 encoding",
    "hex": "hexadecimal encoding",
    "rot13": "ROT13 letter-shifting",
    "binary": "binary (0s and 1s)",
    "reverse": "reversed text",
    "caesar5": "a Caesar cipher (letters shifted by 5)",
    "morse": "Morse code",
    "leetspeak": "leetspeak (e.g. \"1gn0r3\")",
    "confusable": "look-alike Unicode characters",
    "base64+rot13": "two stacked encodings (Base64, then ROT13)",
    "rot13+base64": "two stacked encodings (ROT13, then Base64)",
}

_OUTPUT_FORMATS: dict[str, str] = {
    "spaced_letters": "with spaces between every letter",
    "reversed": "written backwards",
    "one_word_per_line": "one word per line",
    "acrostic_first_letters": "hidden in the first letter of each line",
    "markdown_code_fence": "inside a code block",
    "markdown_table_cell": "inside a table cell",
}

_OUTPUT_TARGETS: dict[str, str] = {
    "system_prompt": "its hidden setup instructions",
    "secret": "any stored passwords or credentials",
}


def _variant_label(variant: str) -> str:
    return variant.replace("_", " ").title()


def _encoding(variant: str) -> Optional[str]:
    label = _ENCODINGS.get(variant, variant)
    return (
        f"Hides an \"ignore your rules\" instruction in {label} to see if the disguise slips it past "
        f"the AI's safeguards."
    )


def _output_filter(variant: str) -> Optional[str]:
    for target_key, target_text in _OUTPUT_TARGETS.items():
        if variant.startswith(target_key + "_"):
            fmt = variant[len(target_key) + 1:]
            fmt_text = _OUTPUT_FORMATS.get(fmt, f"in a disguised format ({fmt.replace('_', ' ')})")
            return (
                f"Asks the AI for {target_text} {fmt_text}, to see if output filters that look for exact "
                f"text can be slipped past."
            )
    return None


def _low_resource_prompt(variant: str) -> Optional[str]:
    return (
        f"Asks for the AI's hidden setup instructions in {_variant_label(variant)}, a less common "
        f"language where safety training is often weaker than in English."
    )


def _low_resource_jailbreak(variant: str) -> Optional[str]:
    return (
        f"Sends a \"Do Anything Now\" role-play jailbreak in {_variant_label(variant)}, a less common "
        f"language where safety training is often weaker than in English."
    )


def _ascii_art(variant: str) -> Optional[str]:
    return (
        f"Draws the trigger word \"{variant.upper()}\" as ASCII art so keyword filters can't read it, "
        f"then asks the AI to decode the word and act on it."
    )


def _session_isolation(variant: str) -> Optional[str]:
    return (
        "Asks for content from another user's or an earlier conversation, to test whether separate "
        "conversations are kept properly isolated."
    )


def _access_control(variant: str) -> Optional[str]:
    return (
        "Asks the AI whether it can see all of the data or whether some is being withheld, to reveal "
        "how its access controls are set up."
    )


# Checked in order, so a longer prefix must come before any shorter prefix
# it starts with.
_FAMILIES: tuple[tuple[str, Callable[[str], Optional[str]]], ...] = (
    ("encoding_evasion_probe_", _encoding),
    ("output_filter_evasion_", _output_filter),
    ("low_resource_language_system_prompt_extraction_", _low_resource_prompt),
    ("low_resource_language_jailbreak_", _low_resource_jailbreak),
    ("ascii_art_evasion_probe_", _ascii_art),
    ("session_isolation_probe_", _session_isolation),
    ("access_control_layer_probe_", _access_control),
)


def describe_technique(operator_id: Optional[str]) -> Optional[str]:
    """Return a one-sentence, plain-language description of an attack
    technique, or ``None`` if the operator id is empty or unknown.

    Args:
        operator_id: The operator id recorded on a scan finding (the
            finding's ``"operator"`` key), e.g. ``"jailbreak_dan_style"`` or
            ``"encoding_evasion_probe_morse"``.

    Returns:
        A short sentence suitable for a tooltip, or ``None`` so callers can
        simply omit the explanation for techniques this module doesn't know.
    """
    if not operator_id:
        return None
    exact = _EXACT.get(operator_id)
    if exact:
        return exact
    for prefix, describe in _FAMILIES:
        if operator_id.startswith(prefix) and len(operator_id) > len(prefix):
            return describe(operator_id[len(prefix):])
    return None
