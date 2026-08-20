"""Runs the understanding loop live against DVAA's standalone consensus/
voting scenario server (scenarios/consensus-manipulation/vulnerable/
voting.js, port 3055) -- a genuinely new behavioral dimension
(coordination/consensus among nominally-independent actors), not a new
protocol. Only this scenario server needs to be running (not the main
DVAA fleet), since this operator library's only channel is
"consensus:voting".

Setup (one-time): npm install (from the DVAA repo root).
Start: node scenarios/consensus-manipulation/vulnerable/voting.js
"""
from __future__ import annotations

import os

from aginiti.adapters.dvaa_adapter import DVAAAdapter
from aginiti.core.graph.persistence import save_ssg
from aginiti.core.graph.target_profile import build_target_profile, render_markdown
from aginiti.operators.dvaa_consensus_definitions import build_dvaa_consensus_library
from aginiti.core.scenarios import dvaa_consensus_mission
from aginiti.core.understanding_loop import run_understanding_loop

TARGET_NAME = "DVAA Consensus/Voting Scenario (scenarios/consensus-manipulation)"


def main() -> None:
    library = build_dvaa_consensus_library()
    mission = dvaa_consensus_mission()

    print(f"=== running the understanding loop live against {TARGET_NAME} ===")
    agent = DVAAAdapter()
    result = run_understanding_loop(mission, library, agent=agent, target_name=TARGET_NAME,
                                     max_rounds=len(library))

    for r in result.rounds:
        gap_summary = ", ".join(f"[{i.category.value}] {i.statement[:70]}" for i in r.new_insights) or "(none)"
        print(f"round {r.round_num}: chose {r.chosen_operator_id} "
              f"(success={r.execution.overall_success}) -- raw: {r.execution.raw_signal[:120]} "
              f"-- new insights: {gap_summary}")

    print(f"\nprompts_used={result.prompts_used} rounds={len(result.rounds)} "
          f"ground_truth_mission_achieved={agent.ground_truth_mission_achieved()}")

    os.makedirs("runs", exist_ok=True)
    graph_path = os.path.join("runs", "dvaa_consensus_ssg.json")
    save_ssg(result.ssg, graph_path)
    print(f"saved graph to {graph_path}")

    profile = build_target_profile(result.ssg, library, mission, target_name=TARGET_NAME,
                                    prompts_used=result.prompts_used)
    markdown = render_markdown(profile)
    profile_path = os.path.join("runs", "dvaa_consensus_target_profile.md")
    with open(profile_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    print(f"wrote {profile_path}\n")
    print(markdown)


if __name__ == "__main__":
    main()
