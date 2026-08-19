"""Tests for aginiti/operators/session_isolation_probe.py -- CWE-488
("Exposure of Data Element to Wrong Session") probes. Judge-evaluated (no
deterministic extractor -- see the module's own docstring for why), so
these tests check structural correctness (unique ids, well-formed effects,
correct claim-key wiring), not extraction logic."""
from aginiti.operators.session_isolation_probe import (
    _VARIANTS,
    session_isolation_probe_operators,
)


def test_returns_one_operator_per_variant():
    operators = session_isolation_probe_operators()
    assert len(operators) == len(_VARIANTS)


def test_operator_ids_are_unique():
    operators = session_isolation_probe_operators()
    ids = [op.id for op in operators]
    assert len(ids) == len(set(ids))


def test_every_operator_has_a_nonempty_prompt_and_no_extractor():
    for op in session_isolation_probe_operators():
        assert op.prompt.strip() != ""
        assert op.extractor is None  # judge-evaluated, by design


def test_success_effect_weight_is_lower_than_a_confirmed_disclosure():
    """weight=2, not weight=3 -- reflects the module's own documented
    lower-confidence stance (a judge call alone can't distinguish a real
    cross-session leak from fabricated content)."""
    for op in session_isolation_probe_operators():
        assert op.effects_success[0].weight == 2


def test_claim_keys_are_variant_specific_not_shared():
    operators = session_isolation_probe_operators()
    success_keys = {op.effects_success[0].key for op in operators}
    failure_keys = {op.effects_failure[0].key for op in operators}
    assert len(success_keys) == len(operators)
    assert len(failure_keys) == len(operators)
