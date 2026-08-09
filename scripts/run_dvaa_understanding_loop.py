"""Runs the first version of the closed understanding<->exploitation loop
(Plan -> Execute -> Learn -> Repeat) live against DVAA, then builds and
prints a Behavioral Security Assessment from the resulting graph.

Requires a local DVAA server already running (npm start / npm run
start:all from a clone of opena2a-org/damn-vulnerable-ai-agent) on its
default ports.
"""
from __future__ import annotations

import os

from aginiti.adapters.dvaa_adapter import DVAAAdapter
from aginiti.graph.persistence import save_ssg
from aginiti.graph.target_profile import build_target_profile, render_markdown
from aginiti.operators.dvaa_definitions import build_dvaa_library
from aginiti.scenarios import dvaa_mission
from aginiti.understanding_loop import run_understanding_loop

TARGET_NAME = "DVAA (damn-vulnerable-ai-agent)"


def main() -> None:
    library = build_dvaa_library()
    mission = dvaa_mission()

    print(f"=== running the understanding loop live against {TARGET_NAME} ===")
    agent = DVAAAdapter()
    result = run_understanding_loop(mission, library, agent=agent, target_name=TARGET_NAME,
                                     max_rounds=len(library))

    for r in result.rounds:
        gap_summary = ", ".join(f"[{i.category.value}] {i.statement[:70]}" for i in r.new_insights) or "(none)"
        print(f"round {r.round_num}: chose {r.chosen_operator_id} "
              f"(success={r.execution.overall_success}) -- new insights: {gap_summary}")

    print(f"\nprompts_used={result.prompts_used} rounds={len(result.rounds)} "
          f"ground_truth_mission_achieved={agent.ground_truth_mission_achieved()}")

    os.makedirs("runs", exist_ok=True)
    graph_path = os.path.join("runs", "dvaa_ssg.json")
    save_ssg(result.ssg, graph_path)
    print(f"saved graph to {graph_path}")

    profile = build_target_profile(result.ssg, library, mission, target_name=TARGET_NAME,
                                    prompts_used=result.prompts_used)
    markdown = render_markdown(profile)
    profile_path = os.path.join("runs", "dvaa_target_profile.md")
    with open(profile_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    print(f"wrote {profile_path}\n")
    print(markdown)


if __name__ == "__main__":
    main()
