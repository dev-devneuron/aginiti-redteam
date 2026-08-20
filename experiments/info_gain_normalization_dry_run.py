"""Offline regression dry run for the info_gain_normalization ablation
("sum" vs "mean" -- see AginitiPlanner's own class docstring for the full
hypothesis). Pure formula computation, no live API calls, no campaign
execution -- fast, and exactly what's needed to check generalization
across targets BEFORE deciding whether "mean" should ever become the
default. Run: `python experiments/info_gain_normalization_dry_run.py`

For each target library, builds a representative mission the same way
exp16/exp17 already do (success_criteria = every library-declared
mission_outcome-category claim key), then computes rank() at move 1
(fresh SSG, no confirmed evidence yet) under BOTH normalization modes and
reports: does the ranking order change, and specifically, does the
1-effect "plant/prerequisite"-shaped operator's relative standing improve
under "mean" without breaking any already-validated calibration (the
well-evidenced-operator-wins shape from exp16, IMPORTANCE_WEIGHT's own
scale)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aginiti.core.graph.schema import RiskTier
from aginiti.core.mission import Mission
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.dvaa_consensus_definitions import build_dvaa_consensus_library
from aginiti.operators.dvaa_definitions import build_dvaa_library
from aginiti.operators.dvla_definitions import build_dvla_library
from aginiti.operators.mcp_filesystem_definitions import build_filesystem_mcp_library
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.graph.ssg import SecurityStateGraph


def _mission_from_library(library, budget=10):
    criteria = tuple(sorted({
        e.key for op in library for e in op.effects_success if e.category == "mission_outcome"
    }))
    return Mission(goal="regression dry run", success_criteria=criteria, success_mode="any",
                   budget=budget, risk_threshold=RiskTier.MEDIUM)


TARGETS = {
    "DVLA": lambda: build_dvla_library(),
    "DVAA": lambda: build_dvaa_library(),
    "DVAA-consensus": lambda: build_dvaa_consensus_library(),
    "MCP-filesystem": lambda: build_filesystem_mcp_library(
        allowed_root="/workspace", inside_file_path="/workspace/notes.txt",
        inside_file_content="team notes", outside_file_path="/etc/shadow",
        secret_marker="SECRET_MARKER_XYZ"),
    "AnythingLLM-chat-rag": lambda: build_anythingllm_library("CANARY_DRYRUN"),
}


def _run_one(name, library):
    mission = _mission_from_library(library)
    print(f"\n=== {name} ({len(library)} operators, {len(mission.success_criteria)} mission-outcome criteria) ===")
    for mode in ("sum", "mean"):
        planner = AginitiPlanner(info_gain_normalization=mode)
        ssg = SecurityStateGraph()
        ranked = planner.rank(library, ssg, mission, prompts_used=0)
        top = ranked[0] if ranked else None
        print(f"  [{mode:4s}] top pick: "
              f"{top.operator.id if top else '(none eligible)':45s} "
              f"util={top.utility:.2f} ig={top.info_gain:.2f}" if top else f"  [{mode:4s}] no eligible candidates")
        # Show every 1-effect operator's rank position and utility under this mode.
        for i, c in enumerate(ranked):
            n_effects = len(c.operator.effects_success) + len(c.operator.effects_failure)
            if n_effects == 1:
                print(f"         1-effect op {c.operator.id:45s} rank={i+1}/{len(ranked)} "
                      f"util={c.utility:.2f} ig={c.info_gain:.2f}")


def main():
    for name, builder in TARGETS.items():
        try:
            library = builder()
        except Exception as exc:  # noqa: BLE001
            print(f"\n=== {name}: SKIPPED ({exc}) ===")
            continue
        _run_one(name, library)


if __name__ == "__main__":
    main()
