"""Generates the interactive SSG graph visualization.

Three modes:
  --dvla                              Run a fresh live campaign against the
                                      real damn-vulnerable-llm-agent target
                                      and export from it directly.
  --from-run RUN_ID TRIAL_JSON_NAME   Reconstruct a SecurityStateGraph from
                                      an already-saved trial JSON (works
                                      offline, no API calls -- used to
                                      bootstrap the visualization from real
                                      prior campaign data without spending
                                      quota).
  (default, no args)                 Run a fresh live campaign against the
                                      MOCK (dev fixture only) and export
                                      directly from the resulting live
                                      SecurityStateGraph.

The reconstruction path loses a little fidelity relative to a live export
(observation supports/contradicts direction is approximated from
confirmed_keys since older serialized runs didn't store the split; claim
subgraph tags are looked up from the CURRENT operator library's effect
declarations, not the historical one) -- both are noted in the generated
page's footer, not hidden.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from aginiti.core.graph.export import export_ssg_for_visualization
from aginiti.core.graph.schema import Claim, ClaimStatus, ConfidenceBand, Observation
from aginiti.core.graph.ssg import SUBGRAPH_TARGET, SecurityStateGraph
from aginiti.operators.definitions import build_library
from aginiti.core.scenarios import dvla_mission, multi_path_mission


def _subgraph_lookup(library) -> dict[str, str]:
    lookup = {}
    for op in library:
        for effect in (*op.effects_success, *op.effects_failure):
            lookup.setdefault(effect.key, effect.subgraph)
    return lookup


def reconstruct_ssg_from_trial(trial: dict, library) -> tuple[SecurityStateGraph, list[dict]]:
    ssg = SecurityStateGraph()
    subgraph_lookup = _subgraph_lookup(library)

    latest_per_key: dict[str, dict] = {}
    for c in trial["final_claims"]:
        latest_per_key[c["key"]] = c  # last occurrence in append order wins

    for key, c in latest_per_key.items():
        ssg.claims.append(Claim(
            id=c["id"], key=key, object=c["object"],
            status=ClaimStatus(c["status"]), confidence=ConfidenceBand(c["confidence"]),
            supersedes=c["supersedes"],
        ))
        ssg.claim_subgraph[key] = subgraph_lookup.get(key, SUBGRAPH_TARGET)

    for i, e in enumerate(trial["execution_log"]):
        # Approximation: older serialized runs didn't store the supports/
        # contradicts split, only a flat confirmed_keys list + overall
        # success. Treat confirmed keys as "supports" -- loses REFUTED-
        # direction fidelity for reconstructed (not live) exports.
        ssg.observations.append(Observation(
            id=f"reconstructed_obs_{i}", timestamp=datetime.now(timezone.utc),
            operator_execution_id=e.get("operator_execution_id", f"exec_{i}"),
            raw_signal=e["raw_signal"], supports=tuple(e.get("confirmed_keys", [])),
        ))

    return ssg, trial["execution_log"]


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--dvla":
        from aginiti.adapters.dvla_adapter import DVLAAdapter
        from aginiti.core.campaign import run_campaign
        from aginiti.operators.dvla_definitions import build_dvla_library
        library = build_dvla_library()
        mission = dvla_mission()
        result = run_campaign(mission, library, agent=DVLAAdapter())
        ssg = result.ssg
        # export_ssg_for_visualization() accepts result.execution_log's ExecutionResult
        # objects directly since the 2026-08-12 architecture-review fix (aginiti/graph/
        # export.py's _entry_get()) -- no manual dict-normalization needed here anymore.
        execution_log = result.execution_log
        source_note = ("live campaign against WithSecureLabs/damn-vulnerable-llm-agent -- "
                        "a real, independently-developed external target, not the mock")
    elif len(sys.argv) >= 3 and sys.argv[1] == "--from-run":
        library = build_library()
        mission = multi_path_mission()
        run_id, trial_name = sys.argv[2], sys.argv[3]
        path = os.path.join("runs", run_id, trial_name)
        with open(path, encoding="utf-8") as f:
            trial = json.load(f)
        ssg, execution_log = reconstruct_ssg_from_trial(trial, library)
        source_note = f"reconstructed from runs/{run_id}/{trial_name} (real campaign transcript, not synthetic)"
    else:
        library = build_library()
        mission = multi_path_mission()
        from aginiti.core.campaign import run_campaign
        result = run_campaign(mission, library)
        ssg = result.ssg
        execution_log = result.execution_log
        source_note = "live campaign against the mock (dev fixture, not the research target)"

    export = export_ssg_for_visualization(ssg, library, mission, execution_log)
    export["source_note"] = source_note

    os.makedirs("runs", exist_ok=True)
    json_path = os.path.join("runs", "graph_export.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)

    template_path = os.path.join("aginiti", "graph", "templates", "graph_view.html")
    with open(template_path, encoding="utf-8") as f:
        template = f.read()
    html = template.replace("/*__GRAPH_DATA_JSON__*/", json.dumps(export))
    html_path = os.path.join("runs", "graph_view.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"wrote {json_path} and {html_path}  ({source_note})")
    print(f"nodes={len(export['nodes'])} edges={len(export['edges'])} frontier={len(export['frontier'])}")


if __name__ == "__main__":
    main()
