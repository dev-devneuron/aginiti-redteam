from aginiti.core.graph.owasp_llm_taxonomy import LLM01_PROMPT_INJECTION, LLM07_SYSTEM_PROMPT_LEAKAGE
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.low_resource_language_evasion import (
    _JAILBREAK_VARIANTS,
    _SYSTEM_PROMPT_VARIANTS,
    build_low_resource_language_operators,
)
from aginiti.operators.library import OperatorLibrary


def test_returns_one_operator_per_system_prompt_variant_plus_one_per_jailbreak_variant():
    ops = build_low_resource_language_operators()
    assert len(ops) == len(_SYSTEM_PROMPT_VARIANTS) + len(_JAILBREAK_VARIANTS)


def test_every_generated_operator_has_a_unique_id_and_claim_key():
    ops = build_low_resource_language_operators()
    ids = [op.id for op in ops]
    keys = [op.effects_success[0].key for op in ops]
    assert len(ids) == len(set(ids))
    assert len(keys) == len(set(keys))


def test_system_prompt_variants_are_tagged_llm07_leakage_jailbreak_variants_llm01():
    ops = {op.id: op for op in build_low_resource_language_operators()}
    for slug, *_ in _SYSTEM_PROMPT_VARIANTS:
        op = ops[f"low_resource_language_system_prompt_extraction_{slug}"]
        assert op.effects_success[0].owasp_llm_category == LLM07_SYSTEM_PROMPT_LEAKAGE
    for slug, *_ in _JAILBREAK_VARIANTS:
        op = ops[f"low_resource_language_jailbreak_{slug}"]
        assert op.effects_success[0].owasp_llm_category == LLM01_PROMPT_INJECTION


def test_generated_prompt_actually_contains_the_translated_text_not_english():
    ops = {op.id: op for op in build_low_resource_language_operators()}
    zulu_op = ops["low_resource_language_system_prompt_extraction_zulu"]
    # The English trigger phrase this technique exists to avoid must never
    # appear in the actual prompt sent -- only in code comments/back-
    # translations, never in what the target receives.
    assert "system instructions" not in zulu_op.prompt.lower()
    assert "Ngicela" in zulu_op.prompt  # the real Zulu text is present


def test_every_variant_ships_its_own_back_translation_in_the_description():
    """The module's own stated discipline (see its docstring): every
    translation must carry a verifiable English back-translation, not be
    presented as opaque, unverifiable foreign text."""
    for op in build_low_resource_language_operators():
        assert "Back-translation" in op.description


def test_all_variants_share_one_technique_cluster():
    ops = build_low_resource_language_operators()
    clusters = {op.technique_cluster for op in ops}
    assert clusters == {"low_resource_language_variants"}


def test_generated_operators_are_target_agnostic_direct_channel():
    for op in build_low_resource_language_operators():
        assert op.channel == "direct"
        assert op.preconditions == ()


def test_generated_claim_keys_do_not_collide_with_data_exposures_own_english_operators():
    english_keys = {e.key for op in data_exposure_operators() for e in op.effects_success}
    generated_keys = {op.effects_success[0].key for op in build_low_resource_language_operators()}
    assert english_keys.isdisjoint(generated_keys)


def test_merges_cleanly_into_an_operator_library_alongside_data_exposure_operators():
    ops = [*data_exposure_operators(), *build_low_resource_language_operators()]
    library = OperatorLibrary(ops)
    assert len(library) == len(ops)  # no id collisions silently dropped one


def test_custom_variants_can_be_passed_in_without_touching_the_module_defaults():
    custom = (("test_lang", "Test Language", "translated text here", "Back-translation: 'test'"),)
    ops = build_low_resource_language_operators(system_prompt_variants=custom, jailbreak_variants=())
    assert len(ops) == 1
    assert ops[0].id == "low_resource_language_system_prompt_extraction_test_lang"
    assert ops[0].prompt == "translated text here"
