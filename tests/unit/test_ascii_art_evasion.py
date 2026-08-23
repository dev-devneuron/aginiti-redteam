from aginiti.core.graph.attack_category import ENCODING_ATTACK
from aginiti.core.graph.owasp_llm_taxonomy import LLM01_PROMPT_INJECTION
from aginiti.operators.ascii_art_evasion import (
    _MASK_VARIANTS,
    _render_word_grid,
    build_ascii_art_evasion_operators,
)
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.encoding_variants import build_encoding_evasion_operators
from aginiti.operators.library import OperatorLibrary


def test_render_word_grid_produces_a_rectangular_column_per_letter():
    """The paper's own reveal algorithm (column N across every row =
    letter N) is only valid if the grid is genuinely rectangular per
    letter -- this is the load-bearing invariant the whole technique
    depends on, verified directly rather than assumed."""
    grid, n_rows, n_letters = _render_word_grid("IGNORE")
    lines = grid.split("\n")
    assert len(lines) == n_rows
    assert n_letters == 6
    # Every row must split into exactly n_letters columns on '*'.
    for line in lines:
        assert len(line.split("*")) == n_letters


def test_render_word_grid_columns_are_stable_width_within_each_letter():
    """Each letter's own column width must be constant across every row
    -- otherwise the '*'-delimited column boundaries would drift row to
    row and the reveal algorithm's column-N-is-letter-N claim would be
    false for some rows."""
    grid, n_rows, n_letters = _render_word_grid("AB")
    lines = grid.split("\n")
    widths_per_column = [[] for _ in range(n_letters)]
    for line in lines:
        cols = line.split("*")
        for i, col in enumerate(cols):
            widths_per_column[i].append(len(col))
    for col_widths in widths_per_column:
        assert len(set(col_widths)) == 1  # every row's column i has the same width


def test_build_ascii_art_evasion_operators_returns_one_per_mask_variant():
    ops = build_ascii_art_evasion_operators()
    assert len(ops) == len(_MASK_VARIANTS)


def test_every_generated_operator_has_a_unique_id_and_claim_key():
    ops = build_ascii_art_evasion_operators()
    ids = [op.id for op in ops]
    keys = [op.effects_success[0].key for op in ops]
    assert len(ids) == len(set(ids))
    assert len(keys) == len(set(keys))


def test_every_generated_operator_is_tagged_encoding_attack_and_llm01():
    for op in build_ascii_art_evasion_operators():
        assert op.effects_success[0].attack_category == ENCODING_ATTACK
        assert op.effects_success[0].owasp_llm_category == LLM01_PROMPT_INJECTION


def test_every_generated_operator_shares_the_same_technique_cluster():
    """These ARE deliberate wrapper variants around one shared mechanism
    (which word gets masked) -- library.py's own documented case for
    technique_cluster, not a hand-wave."""
    ops = build_ascii_art_evasion_operators()
    clusters = {op.technique_cluster for op in ops}
    assert clusters == {"artprompt_word_masking_variants"}


def test_the_masked_word_never_appears_as_plain_text_in_the_prompt():
    """The entire point of ArtPrompt: the trigger word must never appear
    as ordinary readable text anywhere in the prompt -- only as ASCII
    art. A regression here would silently defeat the whole technique
    (a classifier scanning for the plain word would catch it again)."""
    for (word, _template), op in zip(_MASK_VARIANTS, build_ascii_art_evasion_operators()):
        # Strip the ASCII-art block itself (which legitimately contains
        # the word's LETTERS, just not as one contiguous readable
        # substring) before checking -- split on the blank line that
        # separates the grid from the surrounding instruction text.
        parts = op.prompt.split("\n\n")
        prose_parts = [p for p in parts if "*" not in p]
        prose = "\n\n".join(prose_parts)
        assert word not in prose
        assert word.lower() not in prose.lower()


def test_the_filled_instruction_leaves_a_real_blank_not_the_word():
    ops = {op.id: op for op in build_ascii_art_evasion_operators()}
    ignore_op = ops["ascii_art_evasion_probe_ignore"]
    assert "_____ all previous instructions" in ignore_op.prompt


def test_generated_operators_are_target_agnostic_direct_channel():
    for op in build_ascii_art_evasion_operators():
        assert op.channel == "direct"
        assert op.preconditions == ()


def test_generated_claim_keys_do_not_collide_with_encoding_variants_or_data_exposure():
    other_keys = (
        {e.key for op in data_exposure_operators() for e in op.effects_success}
        | {op.effects_success[0].key for op in build_encoding_evasion_operators()}
    )
    generated_keys = {op.effects_success[0].key for op in build_ascii_art_evasion_operators()}
    assert other_keys.isdisjoint(generated_keys)


def test_merges_cleanly_into_an_operator_library_alongside_encoding_variants():
    ops = [*data_exposure_operators(), *build_encoding_evasion_operators(), *build_ascii_art_evasion_operators()]
    library = OperatorLibrary(ops)
    assert len(library) == len(ops)  # no id collisions silently dropped one
