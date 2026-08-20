"""Experiment 7 -- before building exploit-chain-search machinery for
"multi-step exploitation," find out precisely what's missing. Zero live
cost, same style as Experiment 1: a controlled test of AginitiPlanner.rank()
itself, not a live campaign.

Two claims get separated here that "multi-step exploitation" usually
conflates:

  (a) "Can the planner find a path of more than one hop toward a KNOWN
      target?" -- already YES. `path_progress` (aginiti/planner/
      aginiti_planner.py) runs real BFS (aginiti/graph/target_graph.py)
      over the CONFIRMED subgraph, which naturally has shortest paths of
      ANY length, not just one hop -- recomputed every round as the
      confirmed subgraph grows. This is genuine multi-hop reasoning,
      already proven in unit tests (test_aginiti_planner.py's
      "shortens a known path" / "makes target newly reachable" cases).

  (b) "Can the planner recognize a NEW valuable target that a compromise
      just revealed, when that target wasn't named in the mission up
      front?" -- this was the real, previously-untested question. PHASE 1
      below answers it directly: NO, at the time this experiment was first
      run (2026-08-07). `Mission.success_criteria` (aginiti/mission.py) is
      a FROZEN tuple, fixed at authoring time by a human; `business_impact`
      and `path_progress` are both computed strictly against it -- an
      operator that unlocks a genuinely more valuable follow-on compromise
      scored identically to a genuine dead end with equal declared weight.

FIX (same day): `AginitiPlanner.emergent_impact()` -- same BFS mechanism as
path_progress, but against every CATEGORY_MISSION_OUTCOME-tagged claim key
in the library, not only the ones a human named in advance. PHASE 2 below
re-runs the identical scenario to check the fix.

Honest nuance PHASE 2 makes explicit, not hidden: `build_graph()` (shared by
path_progress and emergent_impact) only adds an edge once its confirming
operator's effect is CONFIRMED in the graph -- Aginiti's belief about
connectivity is never assumed in advance. So at a genuine COLD START (this
exact chain never probed at all, nothing confirmed anywhere), the fix does
NOT yet distinguish the stepping stone from the dead end either -- neither
does path_progress for an equally cold, equally multi-hop, never-touched
chain toward a NAMED target (the same "greedy, incrementally-discovered"
character the whole planner already has). What the fix changes is the state
AFTER the downstream edge has been established by anything else (a separate
probe, a knowledge-gap-driven exploration, an earlier round of the same
campaign) -- from that point on, the stepping stone is correctly
distinguished, where before nothing ever would have.
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")

from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import CATEGORY_MISSION_OUTCOME, SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from experiments.results_io import save_result


def _op(op_id, edge, effects_success, weight_note=""):
    return Operator(
        id=op_id, description=f"{op_id} {weight_note}".strip(), prompt="x", channel="direct",
        preconditions=(), effects_success=effects_success, effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW, graph_edge=edge,
    )


def _build_scenario():
    # The named mission target -- what a human declared worth reaching.
    # Deliberately modest weight/impact, same as any ordinary operator.
    named_target = _op(
        "reach_named_target", ("start", "named_target"),
        effects_success=(ClaimEffect("named_target_reached", ClaimStatus.CONFIRMED,
                                      weight=1, category=CATEGORY_MISSION_OUTCOME),),
    )
    # The stepping-stone: on its own, declares nothing special -- just an
    # ordinary capability claim, weight=1, same as any recon probe. Its
    # REAL value (unlockable follow-on compromise) is invisible to the
    # planner because nothing in Mission.success_criteria names it.
    stepping_stone = _op(
        "probe_admin_panel", ("start", "admin_panel_found"),
        effects_success=(ClaimEffect("admin_panel_found", ClaimStatus.CONFIRMED, weight=1),),
        weight_note="(unlocks a follow-on compromise worth far more than the named mission target)",
    )
    # What the stepping-stone actually unlocks: a MUCH more valuable
    # compromise (weight=5, a real mission-outcome-shaped claim) -- but it
    # is NEVER named in mission.success_criteria.
    followup_exploit = _op(
        "exploit_admin_panel", ("admin_panel_found", "full_account_takeover"),
        effects_success=(ClaimEffect("full_account_takeover", ClaimStatus.CONFIRMED,
                                      weight=5, category=CATEGORY_MISSION_OUTCOME),),
    )
    # The control: structurally identical declared weight to the stepping
    # stone (weight=1, one CONFIRMED effect, no preconditions, one hop from
    # start), but genuinely a dead end -- nothing depends on it.
    dead_end = _op(
        "probe_decommissioned_endpoint", ("start", "decommissioned_endpoint_found"),
        effects_success=(ClaimEffect("decommissioned_endpoint_found", ClaimStatus.CONFIRMED, weight=1),),
        weight_note="(genuinely nothing else in the library depends on this)",
    )
    library = OperatorLibrary([named_target, stepping_stone, followup_exploit, dead_end])
    mission = Mission(goal="reach the named target", success_criteria=("named_target_reached",),
                       budget=10, risk_threshold=RiskTier.LOW)
    return library, mission


def _rank_both(library, mission, ssg):
    planner = AginitiPlanner()
    ranked = planner.rank(library, ssg, mission, prompts_used=0)
    by_id = {r.operator.id: r for r in ranked}
    return by_id["probe_admin_panel"], by_id["probe_decommissioned_endpoint"]


def _report(label, stepping, dead_end):
    print(f"--- {label} ---")
    print(f"probe_admin_panel (real stepping stone): utility={stepping.utility:.3f} "
          f"business_impact={stepping.business_impact:.3f} path_progress={stepping.path_progress:.3f} "
          f"emergent_impact={stepping.emergent_impact:.3f}")
    print(f"probe_decommissioned_endpoint (genuine dead end): utility={dead_end.utility:.3f} "
          f"business_impact={dead_end.business_impact:.3f} path_progress={dead_end.path_progress:.3f} "
          f"emergent_impact={dead_end.emergent_impact:.3f}")
    identical = stepping.utility == dead_end.utility
    print(f"IDENTICAL utility: {identical}")
    return identical


def main() -> None:
    library, mission = _build_scenario()

    print("=== Experiment 7: what's actually missing for \"multi-step exploitation\" ===\n")

    # Phase 1: cold start, nothing confirmed -- the ORIGINAL finding.
    cold_ssg = SecurityStateGraph()
    cold_stepping, cold_dead_end = _rank_both(library, mission, cold_ssg)
    cold_identical = _report("Phase 1: cold start (original finding, unaffected by the fix)",
                              cold_stepping, cold_dead_end)

    print()

    # Phase 2: the downstream edge has been established (e.g. by an earlier
    # round of the same campaign, or a separate probe) -- the state
    # emergent_impact actually changes.
    warm_ssg = SecurityStateGraph()
    warm_ssg.assert_claim("full_account_takeover", "true", ClaimStatus.CONFIRMED)
    warm_stepping, warm_dead_end = _rank_both(library, mission, warm_ssg)
    warm_identical = _report("Phase 2: downstream edge already established (fix's real effect)",
                              warm_stepping, warm_dead_end)

    print()
    print("Finding: real multi-hop BFS reasoning already existed (path_progress) for targets named in "
          "advance. The gap was that nothing propagated a confirmed compromise's consequences into what "
          "counts as mission-relevant DURING a campaign. emergent_impact closes this ONCE the relevant "
          "downstream structure has been established -- honestly, not from a total cold start, since "
          "Aginiti's graph never assumes connectivity it hasn't actually confirmed (the same character "
          "path_progress itself already has for an equally untouched multi-hop chain toward a named "
          "target).")

    path = save_result("exp7_consequence_propagation_gap", {
        "phase1_cold_start": {
            "stepping_stone_utility": cold_stepping.utility,
            "dead_end_utility": cold_dead_end.utility,
            "identical_utility": cold_identical,
        },
        "phase2_after_downstream_edge_established": {
            "stepping_stone_utility": warm_stepping.utility,
            "stepping_stone_emergent_impact": warm_stepping.emergent_impact,
            "dead_end_utility": warm_dead_end.utility,
            "dead_end_emergent_impact": warm_dead_end.emergent_impact,
            "identical_utility": warm_identical,
        },
        "finding": "Before the fix: the planner could not distinguish an operator that unlocks a "
                   "genuinely more valuable follow-on compromise from a structurally-identical dead end, "
                   "because business_impact/path_progress are both computed strictly against "
                   "Mission.success_criteria. After adding emergent_impact (2026-08-07): the planner "
                   "correctly distinguishes them ONCE the downstream edge has been established elsewhere "
                   "in the graph -- not from a genuine cold start, honestly, since build_graph() never "
                   "assumes an edge that hasn't actually been confirmed.",
    })
    print(f"\nsaved to {path}")


if __name__ == "__main__":
    main()
