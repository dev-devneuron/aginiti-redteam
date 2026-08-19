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

**2026-08-14 addition: `PROACTIVE_COVERAGE_BONUS`, closing a real gap
found via a live postmortem (exp28, `docs/EXP26_RESULTS.md`'s successor
analysis) -- not a "backwards" mechanism, a genuinely MISSING one.**
`looks_saturated` requires >=2 CONFIRMED outcomes with ZERO successes --
correct and unchanged: a family that has produced even one real finding
must never be demoted, or a planner would abandon a technique that's
actively working. But that correctness has a real, unaddressed
consequence: once ANY family has one success, nothing here previously
gave the planner any reason to also sample a DIFFERENT, completely
untried family, as long as the successful family still had untried
members with undiminished per-operator info_gain -- live-confirmed on
`hardened_agent` (legal persona, exp28): after one authority-claim
variant succeeded, the planner spent its entire remaining budget draining
the rest of that family plus one other high-weight family, never once
touching `encoding_variants.py`'s base pipelines, `data_exposure.py`'s
core probes, `session_isolation_probe.py`, or `access_control_layer_
probe.py` -- structural under-coverage of the operator library, not a
sign the target was well-defended against those families (they were
simply never tried).

The fix is NOT a bigger saturation penalty (that would risk abandoning a
genuinely productive family too early, the exact failure mode `looks_
saturated`'s 2-confirmation threshold exists to prevent) -- it's a
SEPARATE, smaller, unconditional nudge FOR breadth, independent of
whether anything else has failed yet. A genuinely untried family always
has SOME standalone value for building a complete picture of the target's
defenses -- the same reasoning a human red-teamer applies ("I found one
way in, but I should still map the rest of the surface before I'm done")
-- not contingent on first watching something else visibly fail.
Deliberately smaller than `DIVERSIFICATION_BONUS` (which fires on the
STRONGER, reactive "something already looks dead" signal): a bare "this
happens to be untried" fact is real but weaker evidence than "another
family has already demonstrated 2+ dead-end confirmations," so it earns a
smaller nudge, not an equal one -- preserves the existing calibration's
relative ordering rather than replacing it.
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
# The 2026-08-14 addition (see module docstring). Deliberately smaller
# than DIVERSIFICATION_BONUS -- see the reasoning above for why the two
# are not, and should not be, the same magnitude.
PROACTIVE_COVERAGE_BONUS = 1.0


def family_diversification_term(attack_category: str | None, belief: TargetBeliefState) -> float:
    """Returns a single signed float to add into the planner's utility sum:
    negative if `attack_category` looks saturated (accumulating evidence
    of a family-wide block, see TargetBeliefState.FamilyStats.looks_
    saturated); a bounded positive bump if it's a genuinely UNTRIED family
    -- the larger `DIVERSIFICATION_BONUS` if at least one OTHER family
    already looks saturated (a real reason to prefer it over sticking with
    a technique that keeps failing), otherwise the smaller `PROACTIVE_
    COVERAGE_BONUS` (untried families have standalone breadth value even
    when nothing has failed yet -- see module docstring's 2026-08-14
    addition); 0.0 otherwise -- a true no-op for an untagged operator or a
    family that's neither untried nor saturated, matching every other
    term's "only ever helps or is silent, never surprises" discipline."""
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
        return DIVERSIFICATION_BONUS if any_other_saturated else PROACTIVE_COVERAGE_BONUS

    return 0.0


def operator_family_diversification(operator, belief: TargetBeliefState) -> float:
    """Convenience wrapper reading the operator's own predicted family via
    aginiti/graph/attack_category.py's `operator_primary_family()` -- the
    ONE canonical place that "success effect's tag first, else a failure
    effect's" rule lives (2026-08-14: previously duplicated inline here)."""
    from aginiti.graph.attack_category import operator_primary_family

    return family_diversification_term(operator_primary_family(operator), belief)


# ============================================================================
# 2026-08-14, second addition this same day: technique_cluster_diversification
# -- a FINER-grained sibling of family_diversification_term, closing a
# SEPARATE gap the PROACTIVE_COVERAGE_BONUS fix above cannot touch.
#
# Root-caused directly from `hardened_agent`'s real operator declarations
# (aginiti/operators/hardened_agent_definitions.py), not guessed: exp28's
# `aginiti` condition tried `hardened_cross_boundary_probe` then FIVE
# `hardened_authority_claim_probe_*` variants back to back before anything
# else. This is NOT the same bug PROACTIVE_COVERAGE_BONUS fixes (that one
# is about CROSS-family breadth) -- all six of these operators share the
# SAME attack_category (direct_prompt_attack), so family_diversification_
# term is already a no-op for all of them the moment the first one is
# tried (attempted != 0 for the rest of the campaign). The real reason the
# planner kept choosing them is that `_make_verbatim_probe` legitimately
# gives each one its OWN distinct claim key AND a real severity edge over
# most siblings in the same family (weight=3 disclosure + weight=5 EXTRA
# for an RBAC-boundary crossing = potential weight 8, vs weight=3 for
# `system_prompt_extraction`/`jailbreak_dan_style`/`secret_pattern_
# fishing` elsewhere in the SAME family) -- objectively higher expected
# value, correctly ranked first. That part is NOT a bug. The actual gap:
# all 5 authority-claim variants are near-duplicate WRAPPERS around the
# exact same underlying question (`_AUTHORITY_CLAIM_TEMPLATES` -- only the
# social-engineering framing differs), testing ONE real hypothesis
# ("does an unverified authority claim bypass RBAC") -- not 5 independent
# ones. Nothing before this addition ever recognized that redundancy.
#
# **Why this must NOT reuse family_diversification_term's `looks_
# saturated` rule verbatim (a cluster is not a small family):** a family
# legitimately contains many DIFFERENT techniques, so one success there
# must never demote the rest (see the reasoning above `DIVERSIFICATION_
# BONUS`/`PROACTIVE_COVERAGE_BONUS`) -- correct and unchanged. A
# `technique_cluster`, by construction and by author's own explicit
# opt-in tag, is a set of NEAR-DUPLICATE wrappers around ONE hypothesis.
# Once that ONE hypothesis is confirmed -- by ANY single variant, success
# or failure -- every additional same-cluster attempt has genuinely
# DIMINISHED (not zero, not permanently-immune) marginal value: a second
# framing might still be worth trying once (different wording occasionally
# does matter), but burning 4 more slots on the 3rd/4th/5th wrapper of an
# ALREADY-ANSWERED question is not exploration, it's redundant re-asking.
# So this term applies a smooth, escalating penalty from the very FIRST
# same-cluster attempt onward -- deliberately NOT success-immune, the one
# real, disclosed way this term's shape differs from family-level
# saturation.
# ============================================================================
CLUSTER_PENALTY_PER_ATTEMPT = 1.5
MAX_CLUSTER_PENALTY = 3.0


def technique_cluster_diversification_term(technique_cluster: str | None, belief: TargetBeliefState) -> float:
    """Returns a single signed float to add into the planner's utility
    sum: 0.0 for an untagged operator (technique_cluster is None -- the
    common, default case, a true no-op matching every other opt-in term's
    discipline) or for a cluster's first-ever attempt (nothing redundant
    yet); otherwise a bounded, escalating NEGATIVE penalty -- grows with
    how many prior attempts this SAME cluster has already accumulated,
    regardless of whether any of them succeeded (see module docstring for
    why cluster-level redundancy is NOT success-immune the way family-
    level saturation is)."""
    if technique_cluster is None:
        return 0.0

    stats = belief.cluster(technique_cluster)
    if stats.attempted == 0:
        return 0.0

    penalty = min(MAX_CLUSTER_PENALTY, CLUSTER_PENALTY_PER_ATTEMPT * stats.attempted)
    return -penalty


def operator_technique_cluster_diversification(operator, belief: TargetBeliefState) -> float:
    """Convenience wrapper reading the operator's own declared
    `technique_cluster` -- same "one canonical wrapper" pattern as
    `operator_family_diversification`."""
    return technique_cluster_diversification_term(operator.technique_cluster, belief)
