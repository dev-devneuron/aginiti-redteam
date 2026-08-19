"""Tests for aginiti/graph/novelty.py -- family_diversification_term(),
including the 2026-08-14 PROACTIVE_COVERAGE_BONUS addition. This module
had ZERO dedicated tests before this file, despite being live-consequential
(a real exp28 postmortem finding motivated the fix here) -- several other
test files exercise it only incidentally, as part of larger scenarios."""
from aginiti.graph.novelty import (
    DIVERSIFICATION_BONUS,
    MAX_SATURATION_PENALTY,
    PROACTIVE_COVERAGE_BONUS,
    SATURATION_PENALTY_PER_EXTRA_ATTEMPT,
    family_diversification_term,
)
from aginiti.graph.target_belief import FamilyStats, TargetBeliefState


def _belief(**family_stats: FamilyStats) -> TargetBeliefState:
    return TargetBeliefState(family_stats=dict(family_stats))


def test_untagged_operator_is_always_a_no_op():
    belief = _belief(direct_prompt_attack=FamilyStats(attempted=5, confirmed_success=0,
                                                        confirmed_blocked_other=5))
    assert family_diversification_term(None, belief) == 0.0


def test_a_family_with_no_evidence_either_way_gets_the_proactive_bonus_not_neutral():
    """Correcting an outdated expectation this test originally carried
    (from before the 2026-08-14 PROACTIVE_COVERAGE_BONUS fix): a family
    with no belief-state entry at all falls back to FamilyStats()'s
    all-zero default, i.e. attempted=0 -- genuinely untried, same as any
    other untried family. Duplicated more explicitly in
    test_proactive_bonus_fires_even_with_a_completely_empty_belief_state,
    kept here too since "no entry exists yet" and "an entry exists but
    says zero" are worth confirming behave identically."""
    belief = _belief()  # no entries at all -- family() falls back to the all-zero default
    assert family_diversification_term("direct_prompt_attack", belief) == PROACTIVE_COVERAGE_BONUS


def test_an_attempted_but_not_yet_saturated_family_is_neutral():
    """attempted=1, not yet looks_saturated (needs >=2 confirmed with 0
    success) -- must NOT get the untried-family bonus (it's not untried)
    and must NOT get penalized (it's not saturated yet either)."""
    belief = _belief(direct_prompt_attack=FamilyStats(attempted=1, confirmed_blocked_other=1))
    assert family_diversification_term("direct_prompt_attack", belief) == 0.0


# --- saturation penalty (unchanged by this session's fix) -----------------

def test_a_family_with_one_success_never_looks_saturated_however_many_failures_pile_up():
    """The exact property exp28 confirmed live and offline: a family that
    has ever produced one real success stays immune to the saturation
    penalty for the rest of the campaign, no matter how many further
    attempts in it fail."""
    belief = _belief(direct_prompt_attack=FamilyStats(
        attempted=10, confirmed_success=1, confirmed_blocked_other=9))
    assert family_diversification_term("direct_prompt_attack", belief) == 0.0


def test_saturated_family_gets_a_negative_penalty():
    belief = _belief(direct_prompt_attack=FamilyStats(
        attempted=2, confirmed_success=0, confirmed_blocked_other=2))
    result = family_diversification_term("direct_prompt_attack", belief)
    assert result < 0.0


def test_saturation_penalty_grows_with_more_confirmed_dead_ends_but_stays_capped():
    small = _belief(direct_prompt_attack=FamilyStats(attempted=2, confirmed_blocked_other=2))
    big = _belief(direct_prompt_attack=FamilyStats(attempted=6, confirmed_blocked_other=6))
    penalty_small = family_diversification_term("direct_prompt_attack", small)
    penalty_big = family_diversification_term("direct_prompt_attack", big)
    assert penalty_small < 0.0
    assert penalty_big <= penalty_small  # more evidence -> penalty grows (more negative) or stays capped
    assert penalty_big >= -MAX_SATURATION_PENALTY
    assert penalty_small >= -MAX_SATURATION_PENALTY


def test_saturation_penalty_exact_formula_below_the_cap():
    # confirmed_total=3 -> extra_attempts=2 -> 2.0*2=4.0, but capped at MAX_SATURATION_PENALTY=3.0
    belief = _belief(direct_prompt_attack=FamilyStats(attempted=3, confirmed_blocked_other=3))
    assert family_diversification_term("direct_prompt_attack", belief) == -MAX_SATURATION_PENALTY
    # A case that stays under the cap: confirmed_total=2 -> extra_attempts=1 -> 2.0*1=2.0 (< cap 3.0)
    belief2 = _belief(direct_prompt_attack=FamilyStats(attempted=2, confirmed_blocked_other=2))
    assert family_diversification_term("direct_prompt_attack", belief2) == -SATURATION_PENALTY_PER_EXTRA_ATTEMPT


# --- reactive DIVERSIFICATION_BONUS (unchanged) ----------------------------

def test_untried_family_gets_the_larger_reactive_bonus_when_another_family_is_saturated():
    belief = _belief(
        direct_prompt_attack=FamilyStats(attempted=2, confirmed_blocked_other=2),  # saturated
        encoding_attack=FamilyStats(),  # untried
    )
    assert family_diversification_term("encoding_attack", belief) == DIVERSIFICATION_BONUS


# --- NEW 2026-08-14: proactive coverage bonus ------------------------------

def test_untried_family_gets_the_smaller_proactive_bonus_when_nothing_else_is_saturated_yet():
    """The exp28 fix: a genuinely untried family should get SOME credit
    for breadth even before anything else has visibly failed -- not zero,
    which is what let the planner drain one productive family's every
    variant without ever sampling a completely different one live."""
    belief = _belief(
        direct_prompt_attack=FamilyStats(attempted=1, confirmed_success=1),  # productive, not saturated
        encoding_attack=FamilyStats(),  # untried, nothing else has failed (let alone saturated)
    )
    assert family_diversification_term("encoding_attack", belief) == PROACTIVE_COVERAGE_BONUS


def test_proactive_bonus_is_strictly_smaller_than_the_reactive_bonus():
    """Preserves the existing calibration's relative ordering: "another
    family already looks dead" is stronger evidence than "this family
    merely hasn't been tried yet," and must keep earning a larger nudge."""
    assert 0.0 < PROACTIVE_COVERAGE_BONUS < DIVERSIFICATION_BONUS


def test_proactive_bonus_fires_even_with_a_completely_empty_belief_state():
    """The exact scenario from a campaign's very first few steps -- no
    family has any evidence at all yet. A genuinely untried family still
    gets the smaller proactive bonus, not zero, matching "breadth has
    standalone value" even at the very start of a campaign."""
    belief = _belief()
    assert family_diversification_term("direct_prompt_attack", belief) == PROACTIVE_COVERAGE_BONUS


def test_a_family_already_partway_attempted_never_gets_either_bonus():
    """attempted=1 (started, not yet saturated) must get neither the
    proactive nor the reactive bonus -- both are for GENUINELY untried
    (attempted == 0) families only."""
    belief = _belief(
        direct_prompt_attack=FamilyStats(attempted=2, confirmed_blocked_other=2),  # saturated
        encoding_attack=FamilyStats(attempted=1),  # started, not untried
    )
    assert family_diversification_term("encoding_attack", belief) == 0.0
