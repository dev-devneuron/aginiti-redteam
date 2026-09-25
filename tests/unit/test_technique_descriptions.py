"""Tests for aginiti/reporting/technique_descriptions.py."""
from __future__ import annotations

import pytest

from aginiti.core.campaign_builder import all_target_agnostic_operators
from aginiti.reporting.technique_descriptions import describe_technique


@pytest.mark.parametrize("op", all_target_agnostic_operators(), ids=lambda op: op.id)
def test_every_scan_operator_has_a_description(op):
    """Every operator `aginiti scan --target` can run must have a
    plain-language description, so no finding renders without one."""
    desc = describe_technique(op.id)
    assert desc, f"no plain-language description for operator {op.id!r}"
    assert desc.endswith(".")
    assert len(desc) <= 200, "keep descriptions to a single short sentence"


def test_variant_families_name_the_specific_variant():
    assert "Morse code" in describe_technique("encoding_evasion_probe_morse")
    assert "Zulu" in describe_technique("low_resource_language_jailbreak_zulu")
    assert "Scots Gaelic" in describe_technique("low_resource_language_system_prompt_extraction_scots_gaelic")
    assert '"BYPASS"' in describe_technique("ascii_art_evasion_probe_bypass")
    assert "table cell" in describe_technique("output_filter_evasion_secret_markdown_table_cell")
    assert "setup instructions" in describe_technique("output_filter_evasion_system_prompt_reversed")


def test_exact_id_wins_over_family_prefix():
    """`encoding_evasion_probe` (the original single operator) is an exact
    id, distinct from the `encoding_evasion_probe_<variant>` family."""
    assert "Base64" in describe_technique("encoding_evasion_probe")


@pytest.mark.parametrize("operator_id", [None, "", "not_a_real_operator", "encoding_evasion_probe_"])
def test_unknown_or_empty_ids_return_none(operator_id):
    assert describe_technique(operator_id) is None
