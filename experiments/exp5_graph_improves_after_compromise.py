"""Experiment 5 -- does the graph keep improving after the mission is
already satisfied, instead of stopping the moment a compromise lands?

Claim under test (docs/ARCHITECTURE.md's stop_on_mission_success discussion;
docs/EVIDENCE_AND_EVALUATION.md's "Adaptive planning"): running past a
satisfied mission (`stop_on_mission_success=False`, what
run_understanding_loop always does) produces measurably more understanding
than stopping at first success would have.

Zero additional live cost: this is a RETROSPECTIVE analysis of a graph
already produced by a real live run -- runs/dvaa_ssg.json, from the DVAA
memory/A2A/MCP understanding-loop run (7/7 operators). Claims are
append-only and were never reordered, so the saved claims list's order IS
the chronological execution order; this script finds the exact point in
that order where `dvaa_mission()`'s success criteria first become
satisfied (i.e. the point at which a stop_on_mission_success=True campaign
would have returned SUCCESS and stopped), then compares what the graph
knew AT that point against what it ended up knowing by the time all 7
operators had run.

Claim objects don't carry an individual timestamp (schema.py), so
Insights (which DO carry generated_at, but can't be cleanly time-aligned
to a specific claim index without one) are classified differently: a
BEHAVIORAL/SECURITY insight is counted as "explainable from pre-
satisfaction evidence alone" if every claim key in its `derived_from` was
already resolved by the cutoff index, and "required later evidence"
otherwise. This is an honest, documented proxy, not a claim of exact
temporal ordering.
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")

from aginiti.core.graph.persistence import load_ssg
from aginiti.core.graph.schema import ClaimStatus, InsightCategory
from aginiti.core.graph.ssg import CATEGORY_MISSION_OUTCOME, CATEGORY_TRUST_EDGE
from aginiti.core.scenarios import dvaa_mission
from experiments.results_io import save_result

GRAPH_PATH = "runs/dvaa_ssg.json"


def main() -> None:
    ssg = load_ssg(GRAPH_PATH)
    mission = dvaa_mission()

    cutoff_index = None
    for i, claim in enumerate(ssg.claims):
        if claim.key in mission.success_criteria and claim.status == ClaimStatus.CONFIRMED:
            cutoff_index = i
            break
    if cutoff_index is None:
        raise RuntimeError("mission was never satisfied in this graph -- experiment design assumption violated")

    def _distinct_resolved_keys(claims) -> set[str]:
        latest: dict[str, ClaimStatus] = {}
        for c in claims:
            latest[c.key] = c.status
        return {k for k, s in latest.items() if s != ClaimStatus.HYPOTHESIZED}

    resolved_at_cutoff = _distinct_resolved_keys(ssg.claims[:cutoff_index + 1])
    resolved_final = _distinct_resolved_keys(ssg.claims)
    gained_after = resolved_final - resolved_at_cutoff

    def _security_relevant_keys(claims) -> set[str]:
        latest: dict[str, ClaimStatus] = {}
        for c in claims:
            latest[c.key] = c.status
        return {
            k for k, s in latest.items()
            if s == ClaimStatus.CONFIRMED and ssg.claim_category.get(k) in (CATEGORY_TRUST_EDGE, CATEGORY_MISSION_OUTCOME)
        }

    security_at_cutoff = _security_relevant_keys(ssg.claims[:cutoff_index + 1])
    security_final = _security_relevant_keys(ssg.claims)
    security_gained_after = security_final - security_at_cutoff

    grounded_insights = [i for i in ssg.insights if i.category in (InsightCategory.BEHAVIORAL, InsightCategory.SECURITY)]
    pre_explainable = [i for i in grounded_insights if set(i.derived_from) <= resolved_at_cutoff]
    needed_later_evidence = [i for i in grounded_insights if not (set(i.derived_from) <= resolved_at_cutoff)]

    n_gaps = sum(1 for i in ssg.insights if i.category == InsightCategory.KNOWLEDGE_GAP)

    print("=== Experiment 5: does the graph keep improving after the mission is satisfied? ===")
    print(f"Mission first satisfied at claim index {cutoff_index} of {len(ssg.claims)} "
          f"(operator round ~{cutoff_index // 2 + 1} of 7, approx.)")
    print(f"Trigger: {ssg.claims[cutoff_index].key} CONFIRMED "
          f"(one of {mission.success_criteria}, success_mode={mission.success_mode})")
    print()
    print(f"Distinct claim keys resolved AT the satisfaction point: {len(resolved_at_cutoff)}")
    print(f"Distinct claim keys resolved by the END of the run:     {len(resolved_final)}")
    print(f"Gained by continuing past the satisfied mission:        {len(gained_after)} -> {sorted(gained_after)}")
    print()
    print(f"Security-relevant (trust_edge/mission_outcome) CONFIRMED claims at cutoff: {len(security_at_cutoff)} "
          f"-> {sorted(security_at_cutoff)}")
    print(f"Security-relevant CONFIRMED claims by the end:                             {len(security_final)} "
          f"-> {sorted(security_final)}")
    print(f"NEW security-relevant findings gained by continuing:                       "
          f"{len(security_gained_after)} -> {sorted(security_gained_after)}")
    print()
    print(f"Behavioral/Security insights explainable from pre-satisfaction evidence alone: "
          f"{len(pre_explainable)}/{len(grounded_insights)}")
    print(f"Behavioral/Security insights that needed post-satisfaction evidence:           "
          f"{len(needed_later_evidence)}/{len(grounded_insights)}")
    print(f"Knowledge-gap insights synthesized across the whole run: {n_gaps}")

    path = save_result("exp5_graph_improves_after_compromise", {
        "graph_source": GRAPH_PATH,
        "mission_success_criteria": mission.success_criteria,
        "cutoff_claim_index": cutoff_index,
        "total_claims": len(ssg.claims),
        "trigger_claim_key": ssg.claims[cutoff_index].key,
        "resolved_at_cutoff": sorted(resolved_at_cutoff),
        "resolved_final": sorted(resolved_final),
        "gained_after": sorted(gained_after),
        "security_relevant_at_cutoff": sorted(security_at_cutoff),
        "security_relevant_final": sorted(security_final),
        "security_relevant_gained_after": sorted(security_gained_after),
        "n_grounded_insights": len(grounded_insights),
        "n_insights_pre_explainable": len(pre_explainable),
        "n_insights_needed_later_evidence": len(needed_later_evidence),
        "insights_needed_later_evidence": [i.statement for i in needed_later_evidence],
        "n_knowledge_gap_insights": n_gaps,
    })
    print(f"\nsaved to {path}")


if __name__ == "__main__":
    main()
