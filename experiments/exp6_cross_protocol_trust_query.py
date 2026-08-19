"""Experiment 6 -- does ONE query, with zero protocol-specific code, surface
the same "trusts a claimed identity without verification" finding across
three structurally unrelated protocols?

Claim under test (docs/EVIDENCE_AND_EVALUATION.md, "Cross-protocol
reasoning"): the CATEGORY_TRUST_EDGE taxonomy generalizes across targets --
already established via source inspection (three operator libraries tag
CATEGORY_TRUST_EDGE independently). This experiment demonstrates the
CONSUMER side: `aginiti.core.graph.queries.trust_assumptions()`, called
identically against three independently-produced graphs, surfaces all
three findings with no per-target branching in the query itself.

SCOPE, stated plainly: this demonstrates that Aginiti's OWN taxonomy and
query layer generalize. It does NOT demonstrate that other tools (garak,
BloodHound, etc.) cannot do the same thing -- this project has not run
those tools and makes no claim about them here. See
docs/EVIDENCE_AND_EVALUATION.md's comparison-table caveat.

Sources:
  - DVAA (A2A):        runs/dvaa_ssg.json (a2a_trusts_claimed_identity)
  - DVAA (consensus):  runs/dvaa_consensus_ssg.json (consensus_trusts_claimed_voter_identity)
  - Mock target (Slack): reconstructed from experiments/results/exp3_raw/
    -- the first Experiment 3 trial whose final_claims confirm
    planner_trusts_slack (that experiment already runs the mock target
    live; this script does not re-run anything, only reads what's already
    on disk). campaign_result_to_dict()'s final_claims doesn't carry
    claim_category, so it's re-attached here from the SAME source the live
    run used (aginiti/operators/definitions.py's own ClaimEffect
    declarations) -- not invented, just carried over from the one place
    it's actually declared.
"""
from __future__ import annotations

import glob
import json
import sys

sys.path.insert(0, ".")

from aginiti.core.graph.persistence import load_ssg
from aginiti.core.graph.queries import trust_assumptions
from aginiti.core.graph.schema import Claim, ClaimStatus, ConfidenceBand
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.definitions import build_library
from experiments.results_io import save_result

EXP3_RAW_GLOB = "experiments/results/exp3_raw/*.json"


def _mock_target_graph() -> SecurityStateGraph | None:
    """Reconstructs a minimal, query-ready SSG from whichever Experiment 3
    trial first confirmed a trust-edge claim -- not a full replay, just
    enough for trust_assumptions() to work identically to the other two
    graphs: claims + claim_category, the only two fields that query reads."""
    library = build_library()
    category_by_key = {}
    for op in library:
        for effect in (*op.effects_success, *op.effects_failure):
            if effect.category is not None:
                category_by_key[effect.key] = effect.category

    for path in sorted(glob.glob(EXP3_RAW_GLOB)):
        record = json.load(open(path, encoding="utf-8"))
        trust_claims = [c for c in record.get("final_claims", [])
                        if category_by_key.get(c["key"]) == "trust_edge" and c["status"] == "confirmed"]
        if not trust_claims:
            continue
        ssg = SecurityStateGraph()
        for c in record["final_claims"]:
            category = category_by_key.get(c["key"])
            if category is None:
                continue  # only reconstruct what this experiment needs: categorized claims
            claim = Claim(id=c["id"], key=c["key"], object=c["object"],
                          status=ClaimStatus(c["status"]), confidence=ConfidenceBand(c["confidence"]),
                          supersedes=c.get("supersedes"))
            ssg.claims.append(claim)
            ssg.claim_category[c["key"]] = category
        return ssg, path
    return None, None


def main() -> None:
    dvaa_ssg = load_ssg("runs/dvaa_ssg.json")
    consensus_ssg = load_ssg("runs/dvaa_consensus_ssg.json")
    mock_ssg, mock_source = _mock_target_graph()

    graphs = {"DVAA (A2A)": dvaa_ssg, "DVAA (consensus/voting)": consensus_ssg}
    if mock_ssg is not None:
        graphs["Mock target (Slack)"] = mock_ssg
    else:
        print("NOTE: no Experiment 3 trial with a confirmed trust-edge claim found on disk yet -- "
              "run experiments/exp3_understanding_first_vs_baselines.py first for the third data point. "
              "Proceeding with the two available real-target graphs.")

    print("=== Experiment 6: the SAME query, zero protocol-specific code, across targets ===")
    print("query: aginiti.core.graph.queries.trust_assumptions(ssg)\n")

    rows = []
    for name, ssg in graphs.items():
        results = trust_assumptions(ssg)
        confirmed = [c for c in results if c.status == ClaimStatus.CONFIRMED]
        print(f"{name}:")
        for c in results:
            print(f"  - {c.key}: {c.status.value}")
        rows.append({
            "target": name,
            "trust_claims_found": [{"key": c.key, "status": c.status.value} for c in results],
            "confirmed_count": len(confirmed),
        })
        print()

    all_confirmed_something = all(r["confirmed_count"] > 0 for r in rows)
    print(f"Every graph produced at least one CONFIRMED trust-edge finding via the identical query: "
          f"{all_confirmed_something}")

    path = save_result("exp6_cross_protocol_trust_query", {
        "mock_target_source_trial": mock_source,
        "rows": rows,
        "all_graphs_confirmed_trust_edge": all_confirmed_something,
        "scope_caveat": "Demonstrates Aginiti's own taxonomy/query generalize across its own targets. "
                        "Makes no claim about other tools (not run, not compared here).",
    })
    print(f"\nsaved to {path}")


if __name__ == "__main__":
    main()
