from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.output_filter_evasion import (
    _SECRET_VARIANTS,
    _SYSTEM_PROMPT_VARIANTS,
    output_filter_evasion_operators,
)


def test_returns_one_operator_per_declared_variant():
    ops = output_filter_evasion_operators()
    assert len(ops) == len(_SYSTEM_PROMPT_VARIANTS) + len(_SECRET_VARIANTS)


def test_every_generated_operator_has_a_unique_id_and_claim_key():
    ops = output_filter_evasion_operators()
    ids = [op.id for op in ops]
    keys = [op.effects_success[0].key for op in ops]
    assert len(ids) == len(set(ids))
    assert len(keys) == len(set(keys))


def test_generated_operators_are_target_agnostic_direct_channel_no_extractor():
    for op in output_filter_evasion_operators():
        assert op.channel == "direct"
        assert op.preconditions == ()
        # Judge-evaluated, same discipline as data_exposure.py -- detecting
        # a reformatted secret requires semantic understanding, not a
        # deterministic keyword extractor.
        assert op.extractor is None


def test_system_prompt_variants_actually_ask_for_the_system_prompt():
    ops = {op.id: op for op in output_filter_evasion_operators()}
    for variant_name, _instruction in _SYSTEM_PROMPT_VARIANTS:
        op = ops[f"output_filter_evasion_system_prompt_{variant_name}"]
        assert "system prompt" in op.prompt.lower()


def test_reversed_variant_explicitly_asks_for_reversed_output():
    ops = {op.id: op for op in output_filter_evasion_operators()}
    op = ops["output_filter_evasion_system_prompt_reversed"]
    assert "backwards" in op.prompt.lower()


def test_generated_claim_keys_do_not_collide_with_data_exposure_operators():
    original_keys = {e.key for op in data_exposure_operators() for e in op.effects_success}
    generated_keys = {op.effects_success[0].key for op in output_filter_evasion_operators()}
    assert original_keys.isdisjoint(generated_keys)


def test_merges_cleanly_into_an_operator_library_alongside_data_exposure_operators():
    ops = [*data_exposure_operators(), *output_filter_evasion_operators()]
    library = OperatorLibrary(ops)
    assert len(library) == len(ops)  # no id collisions silently dropped one


def test_each_operator_has_a_distinct_understanding_question():
    ops = output_filter_evasion_operators()
    questions = [op.understanding_question for op in ops]
    assert len(questions) == len(set(questions))
    assert all(q for q in questions)
