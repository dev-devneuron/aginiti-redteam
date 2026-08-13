"""Family-level diversification: a deterministic, modular scoring function
answering "have I already effectively learned what THIS attack family has
to teach, and if so, is there a genuinely untried family worth pivoting
to instead." Added 2026-08-14, directly operationalizing the pattern
named explicitly in this project's own architectural direction:

    "direct disclosure refused -> likely direct-disclosure guardrail ->
     avoid semantically equivalent attacks -> investigate another
     boundary/path."

**Why this is a separate mechanism from `AginitiPlanner.failure_evidence_
penalty()`, not a duplicate of it.** That term fires only when a
candidate's own prospective failure carries the IDENTICAL, GENERALIZABLE
`failure_diagnosis` tag (`blocked_by_privilege`/`blocked_by_network_
egress`/`blocked_by_approval_gate`) as something already CONFIRMED
elsewhere -- a precise, single-tag match. `actively_refused` and
`not_retrieved` are DELIBERATELY excluded from it (see failure_diagnosis.
py's own docstring: a single refusal of ONE request is not, by itself,
proof a differently-phrased request would also be refused). That
exclusion is correct at the single-attempt level -- but it also means
nothing in this codebase currently generalizes ACROSS MULTIPLE
non-generalizable refusals in the SAME attack family. Two, three, four
`direct_prompt_attack` operators all coming back `actively_refused` is a
real, accumulating pattern a red-teamer would read as "this family looks
guarded" even though no SINGLE one of those refusals proves it alone --
exactly the gap this module closes, using `attack_category` (an existing,
independently-maintained taxonomy dimension every operator pack already
tags) as the family boundary, not a new one invented for this purpose.

Deliberately modular and pluggable (per explicit instruction): a single
pure function, no class, no hidden state, taking a `TargetBeliefState`
snapshot it never mutates. Swappable for a different equivalence notion
later (e.g. embedding-based prompt similarity) without touching
AginitiPlanner's own code, the same way `Operator.extractor` is a
swappable strategy rather than baked into ObservationAdapter.
"""
from __future__ import annotations

from aginiti.graph.target_belief import TargetBeliefState

# Bounded, soft nudges -- same discipline as every other additive term in
# aginiti/planner/aginiti_planner.py: informs, never vetoes (a candidate
# with a genuinely large weight/severity/business-impact advantage can
# still outrank a demoted one). Calibrated to IMPORTANCE_WEIGHT["high"]
# (4.0, schema.py's own canonical ceiling for a "this matters a lot"
# signal -- the same scale hypothesis_escalation_bonus's own
# _HYPOTHESIS_ESCALATION_WEIGHT uses), not to failure_evidence_penalty's
# smaller 1.0 ceiling: family-level saturation is AGGREGATED evidence
# across multiple distinct operators (by construction, looks_saturated
# never fires on fewer than 2 independent confirmations), a materially
# stronger signal than one exact-tag match, so it earns a materially
# larger ceiling -- confirmed empirically necessary, not an arbitrary
# bump: at the smaller, failure_evidence_penalty-matched scale this
# module originally shipped with, the demonstration scenario in
# experiments/exp22_adaptive_planner_ablation.py never actually changed
# which operator ranked first, because a single bounded nudge that size
# cannot overcome a real multi-point info_gain/business_impact gap --
# exactly the "soft nudge, not a veto" property working as designed, just
# calibrated too low to matter in a realistic case. Re-verified this
# level is enough via that same scenario before treating it as final.
SATURATION_PENALTY_PER_EXTRA_ATTEMPT = 2.0
MAX_SATURATION_PENALTY = 3.0
DIVERSIFICATION_BONUS = 2.5


def family_diversification_term(attack_category: str | None, belief: TargetBeliefState) -> float:
    """Returns a single signed float to add into the planner's utility sum:
    negative if `attack_category` looks saturated (accumulating evidence
    of a family-wide block, see TargetBeliefState.FamilyStats.looks_
    saturated), a small positive bump if it's a genuinely UNTRIED family
    while at least one OTHER family already looks saturated (a real reason
    to prefer it over sticking with a technique that keeps failing, not a
    default "novelty for its own sake" preference), 0.0 otherwise -- a
    true no-op for an untagged operator or a family with no accumulated
    evidence either way, matching every other term's "only ever helps or
    is silent, never surprises" discipline."""
    if attack_category is None:
        return 0.0

    stats = belief.family(attack_category)
    if stats.looks_saturated:
        # Grows with how much evidence has piled up (more confirmed
        # blocks -> more confident this family is a dead end), but capped
        # -- a soft nudge must stay overridable by a genuinely strong
        # candidate on every other term, never an absolute veto.
        extra_attempts = stats.confirmed_total - 1  # first confirmation alone never triggers looks_saturated
        penalty = min(MAX_SATURATION_PENALTY, SATURATION_PENALTY_PER_EXTRA_ATTEMPT * extra_attempts)
        return -penalty

    if stats.attempted == 0:
        any_other_saturated = any(
            other.looks_saturated for name, other in belief.family_stats.items() if name != attack_category
        )
        if any_other_saturated:
            return DIVERSIFICATION_BONUS

    return 0.0


def operator_family_diversification(operator, belief: TargetBeliefState) -> float:
    """Convenience wrapper reading the operator's own predicted family the
    same way AginitiPlanner already reads other per-effect metadata --
    the family an unresolved SUCCESS effect declares if there is one,
    else whatever a FAILURE effect declares (mirrors severity_priority's
    own "still-unresolved effects only" scoping, so an operator that has
    already fully resolved contributes nothing new here either)."""
    from aginiti.graph.schema import ClaimStatus

    candidate_family = None
    for effect in (*operator.effects_success, *operator.effects_failure):
        if effect.attack_category is None:
            continue
        candidate_family = effect.attack_category
        break
    return family_diversification_term(candidate_family, belief)
