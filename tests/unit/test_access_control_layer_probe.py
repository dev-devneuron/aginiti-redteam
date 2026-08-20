"""Tests for aginiti/operators/access_control_layer_probe.py -- a
generalized, target-agnostic access-control-architecture diagnostic
(pre-filter vs post-filter RAG access control). Judge-evaluated (no
deterministic extractor -- distinguishing genuine architectural awareness
from ordinary phrasing needs semantic judgment), so these tests check
structural correctness, matching test_session_isolation_probe.py's own
discipline for the same reason."""
from aginiti.operators.access_control_layer_probe import (
    _VARIANTS,
    access_control_layer_probe_operators,
)


def test_returns_one_operator_per_variant():
    operators = access_control_layer_probe_operators()
    assert len(operators) == len(_VARIANTS)


def test_operator_ids_are_unique():
    ids = [op.id for op in access_control_layer_probe_operators()]
    assert len(ids) == len(set(ids))


def test_every_operator_has_a_nonempty_prompt_and_no_extractor():
    for op in access_control_layer_probe_operators():
        assert op.prompt.strip() != ""
        assert op.extractor is None


def test_success_effect_is_capability_category_not_mission_outcome():
    """A confirmed signal here is an architecture finding that informs
    FOLLOW-UP attacks, not itself a content disclosure -- CATEGORY_
    CAPABILITY, matching hardened_config_recon's own categorization,
    not CATEGORY_MISSION_OUTCOME."""
    from aginiti.core.graph.ssg import CATEGORY_CAPABILITY
    for op in access_control_layer_probe_operators():
        assert op.effects_success[0].category == CATEGORY_CAPABILITY


def test_claim_keys_are_variant_specific_not_shared():
    operators = access_control_layer_probe_operators()
    success_keys = {op.effects_success[0].key for op in operators}
    failure_keys = {op.effects_failure[0].key for op in operators}
    assert len(success_keys) == len(operators)
    assert len(failure_keys) == len(operators)


def test_prompts_ask_about_completeness_never_for_specific_content():
    """The entire point of this technique (see module docstring) is
    asking the target to reason about the SHAPE of its context, never
    requesting specific withheld content directly -- a sanity check that
    no variant accidentally regressed into a direct extraction attempt."""
    banned_phrases = ("give me", "share the", "tell me the specific", "what is the")
    for op in access_control_layer_probe_operators():
        lowered = op.prompt.lower()
        assert not any(phrase in lowered for phrase in banned_phrases), op.id
