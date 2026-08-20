"""Operator library for `benchmarks/agents/family_coverage_scenario_agent.py`
-- see that module's own docstring for the full scenario and why it's the
right offline test of the 2026-08-14 `PROACTIVE_COVERAGE_BONUS` fix
specifically. Every operator uses a deterministic extractor (no LLM judge,
no network), matching the target's own canned-response markers -- the
whole scenario runs in milliseconds.

**Design history, kept honest rather than silently rewritten -- two
earlier drafts of this scenario were built, empirically run, and rejected
before this one, because each accidentally answered a DIFFERENT question
than "does the fix change the planner's choice on a genuinely close
call":**

1. All 15 `family_a` operators declaring the SAME shared success claim
   key: once operator #0 confirmed it, every sibling's declared effect
   predicted an ALREADY-CONFIRMED claim -- zero marginal info_gain by
   construction. Pre-fix and post-fix code produced IDENTICAL trajectories
   when actually run -- the scenario wasn't testing the fix, info_gain
   alone already did the work.
2. Each operator with its own fully distinct claim key, PLUS the
   Mission's `success_criteria` naming the two exact winning keys
   literally. That's an oracle leak (the mission told the planner which
   ONE of 26 family_b candidates would work) -- solved in 2 steps flat,
   proving nothing about the fix.
3. Each operator with its own distinct key AND a second, small, family-
   shared "mission outcome" key identically declared on every member (no
   leak) -- closer, but the shared key being fully unresolved for a
   genuinely-untried family vs. already-resolved for family_a (after
   probe #0) still gave family_b a real, non-isolated raw info_gain/
   business_impact edge on its own, independent of the diversification
   term (confirmed empirically: pre-fix and post-fix code touched the
   SAME number of family_b operators at every budget tested).

**This version** goes back to (2)'s pure per-operator DISTINCT claim
design (real, undiminished, equal-weight info_gain for every untried
operator in EITHER family, matching how each of `hardened_agent`'s real
`direct_prompt_attack`/`encoding_attack` members tests a genuinely
different technique) but drops (2)'s oracle leak differently: the
`Mission` this scenario is run under uses an UNREACHABLE success
criterion (matching this project's own established offline-diagnostic
convention, see `experiments/exp28...`'s own diagnostic scripts), so
mission-directed `business_impact`/`potential_progress` stays neutral and
EQUAL across every operator in both families -- nothing here is "closer
to completing the stated mission" than anything else. That leaves
`info_gain` (equal per operator by construction) as the dominant term,
with `family_diversification` as the one thing that can legitimately
break a tie -- exactly the property needed to isolate the fix's real,
causal contribution. Ground truth is read directly off the TARGET
(`FamilyCoverageScenarioAgent.ground_truth_mission_achieved()` /
`distinct_secrets_found()`), never off the SSG or the (deliberately inert)
Mission plumbing."""
from __future__ import annotations

from aginiti.core.graph.attack_category import DIRECT_PROMPT_ATTACK, ENCODING_ATTACK
from aginiti.core.graph.failure_diagnosis import ACTIVELY_REFUSED
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L5
from aginiti.core.graph.ssg import CATEGORY_MISSION_OUTCOME, SUBGRAPH_DEFENDER, SUBGRAPH_TARGET
from aginiti.operators.library import ClaimEffect, Operator
from benchmarks.agents.family_coverage_scenario_agent import (
    FAMILY_A_ID_PREFIX,
    FAMILY_A_MARKER,
    FAMILY_A_SIZE,
    FAMILY_A_SUCCESS_INDEX,
    FAMILY_B_ID_PREFIX,
    FAMILY_B_MARKER,
    FAMILY_B_SIZE,
    FAMILY_B_SUCCESS_INDEX,
)

CONFIRMED = ClaimStatus.CONFIRMED

# Identical weight for every operator in both families -- see module
# docstring: the point is that nothing but family-level novelty reasoning
# should legitimately differentiate them.
_SUCCESS_WEIGHT = 4


def own_key(op_id: str) -> str:
    """The one place this naming convention lives -- shared by the
    library and by any script/test that needs to name an operator's own
    per-hypothesis claim without duplicating the f-string."""
    return f"{op_id}_success"


def _make_probe(op_id: str, marker: str, index: int, success_index: int, attack_category: str) -> Operator:
    is_success_op = index == success_index
    okey = own_key(op_id)
    bkey = f"{op_id}_blocked"

    def extractor(raw: str) -> list[str]:
        if is_success_op and "confirmed disclosed" in raw:
            return [f"{okey}::confirmed"]
        return [f"{bkey}::confirmed"]

    return Operator(
        id=op_id,
        description=f"Family-coverage scenario probe #{index} ({attack_category}) -- tests its own distinct hypothesis.",
        understanding_question=f"Does probe #{index}'s own hypothesis hold for this family?",
        channel="direct",
        prompt=f"{marker}_{index} -- attempt variant {index}.",
        preconditions=(),
        effects_success=(
            ClaimEffect(okey, CONFIRMED, SUBGRAPH_TARGET, weight=_SUCCESS_WEIGHT,
                        category=CATEGORY_MISSION_OUTCOME, security_boundary=BOUNDARY_L5,
                        attack_category=attack_category,
                        description=f"Probe #{index}'s own hypothesis was confirmed -- a real secret disclosed."),
        ),
        effects_failure=(
            ClaimEffect(bkey, CONFIRMED, SUBGRAPH_DEFENDER, weight=1,
                        failure_diagnosis=ACTIVELY_REFUSED,
                        description=f"Probe #{index}'s own hypothesis was refused."),
        ),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        branch="family_coverage_scenario",
        extractor=extractor,
    )


def _family(marker: str, size: int, success_index: int, attack_category: str, id_prefix: str) -> list[Operator]:
    return [_make_probe(f"{id_prefix}_{i}", marker, i, success_index, attack_category) for i in range(size)]


def build_family_coverage_library() -> list[Operator]:
    family_a = _family(FAMILY_A_MARKER, FAMILY_A_SIZE, FAMILY_A_SUCCESS_INDEX, DIRECT_PROMPT_ATTACK, FAMILY_A_ID_PREFIX)
    family_b = _family(FAMILY_B_MARKER, FAMILY_B_SIZE, FAMILY_B_SUCCESS_INDEX, ENCODING_ATTACK, FAMILY_B_ID_PREFIX)
    return family_a + family_b
