"""Generates a Target Profile from a live, understanding-mode DVLA campaign.

"Understanding-mode" means `stop_on_mission_success=False`: the campaign
keeps probing past a satisfied mission until the operator library is
genuinely exhausted, instead of stopping the instant it "wins" -- the
early-exit fix that makes mission success metadata rather than a stop
condition (Target -> Evidence Collection -> SSG -> Understanding ->
(optional) Security Evaluation).

Also proves the graph-outlives-its-campaign story concretely: the graph is
saved to disk, then reloaded into a BRAND NEW SecurityStateGraph object --
simulating a separate process/consumer that never ran the campaign -- and
the Target Profile is built entirely from that reloaded copy. Nothing
below the reload line touches the campaign, the adapter, or an LLM call.
"""
from __future__ import annotations

import os

from aginiti.adapters.dvla_adapter import DVLAAdapter
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.insights import synthesize_insights
from aginiti.core.graph.persistence import load_ssg, save_ssg
from aginiti.core.graph.target_profile import build_target_profile, render_markdown
from aginiti.operators.dvla_definitions import build_dvla_library
from aginiti.core.scenarios import dvla_mission

TARGET_NAME = "damn-vulnerable-llm-agent"


def main() -> None:
    library = build_dvla_library()
    mission = dvla_mission()

    print("=== running live understanding-mode campaign against DVLA ===")
    result = run_campaign(mission, library, agent=DVLAAdapter(), stop_on_mission_success=False)
    print(f"outcome={result.outcome} steps={result.steps_executed} prompts={result.prompts_used} "
          f"operators_executed={result.operators_executed}")

    os.makedirs("runs", exist_ok=True)
    graph_path = os.path.join("runs", "dvla_ssg.json")
    save_ssg(result.ssg, graph_path)
    print(f"\nsaved graph to {graph_path}")

    # Simulate a separate consumer: a fresh graph object, no campaign, no
    # adapter, no LLM client -- just the file on disk.
    reloaded = load_ssg(graph_path)
    print(f"reloaded independently: {len(reloaded.facts)} facts, {len(reloaded.claims)} claims, "
          f"{len(reloaded.observations)} observations")

    executed_ids = frozenset(reloaded.operator_stats)
    insights = synthesize_insights(reloaded, target_name=TARGET_NAME, library=library,
                                    executed_ids=executed_ids)
    print(f"synthesized {len(insights)} insight(s): "
          f"{sum(1 for i in insights if i.category.value == 'behavioral')} behavioral, "
          f"{sum(1 for i in insights if i.category.value == 'security')} security, "
          f"{sum(1 for i in insights if i.category.value == 'knowledge_gap')} knowledge gaps")
    save_ssg(reloaded, graph_path)  # persist the insights alongside the rest of the graph

    profile = build_target_profile(reloaded, library, mission, target_name=TARGET_NAME,
                                    prompts_used=result.prompts_used)
    markdown = render_markdown(profile)

    profile_path = os.path.join("runs", "dvla_target_profile.md")
    with open(profile_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    print(f"wrote {profile_path}\n")
    print(markdown)


if __name__ == "__main__":
    main()
