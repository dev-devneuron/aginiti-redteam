"""Tests the judge's candidate-framing logic in isolation (no live API
calls) -- specifically a regression test for a real bug: HYPOTHESIZED-status
effects were framed as "evidence this is FALSE" instead of TRUE, which
silently broke recon_capabilities (whose only effect is HYPOTHESIZED) in
every single campaign until caught by a full benchmark run.
"""
from aginiti.adapter.observation_adapter import _build_candidates, _effect_id
from aginiti.operators.definitions import build_library


def test_hypothesized_effect_is_framed_as_true_not_false():
    op = build_library().get("recon_capabilities")
    candidates = _build_candidates(op)
    assert len(candidates) == 1
    assert "TRUE" in candidates[0]["meaning"]
    assert "FALSE" not in candidates[0]["meaning"]


def test_confirmed_effect_is_framed_as_true():
    op = build_library().get("indirect_prompt_injection")
    candidates = {c["id"]: c["meaning"] for c in _build_candidates(op)}
    confirmed_id = _effect_id(op.effects_success[0])
    assert "TRUE" in candidates[confirmed_id]
    assert "FALSE" not in candidates[confirmed_id]


def test_refuted_effect_is_framed_as_false():
    op = build_library().get("confirm_tool_reachability")
    candidates = {c["id"]: c["meaning"] for c in _build_candidates(op)}
    refuted_id = _effect_id(op.effects_failure[0])  # payroll_api_exists::refuted
    assert refuted_id.endswith("::refuted")
    assert "FALSE" in candidates[refuted_id]


def test_every_operator_in_the_live_library_frames_hypothesized_and_confirmed_as_true():
    # Broad sweep: no effect in the real library should ever be framed FALSE
    # unless its status is actually REFUTED.
    for op in build_library():
        for c in _build_candidates(op):
            is_refuted = c["id"].endswith("::refuted")
            assert ("FALSE" in c["meaning"]) == is_refuted, c
