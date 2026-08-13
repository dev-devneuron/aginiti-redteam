"""
Offline re-parser for an existing ``scripts/run_mia_benchmark.py`` results
JSON — recovers responses misclassified as "unk" by the shipped
yes/no/unk parser (``aginiti.attacks.mia.interrogation._parse_yes_no_unk``,
which requires the literal word "yes"/"no") using
``aginiti.reporting.mia_reparse``'s reported-speech regex fallback.

**Zero new API calls** — re-parses the ALREADY-CAPTURED ``target_response``
text stored in the input file, recomputes each document's score and the
top-level metrics, and writes a NEW file. The original input file is never
modified.

Usage:
    python scripts/reparse_mia_results.py <path-to-results.json>
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aginiti.reporting.mia_reparse import reparse_results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Path to an existing run_mia_benchmark.py results JSON.")
    parser.add_argument(
        "--lambda-unk", type=float, default=6.0,
        help="lambda_unk used by the original run (default: 6.0, "
             "InterrogationAttack's own default -- pass the actual value if "
             "the run overrode it; not currently recorded in run metadata).",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    report = json.loads(in_path.read_text(encoding="utf-8"))

    reparsed = reparse_results(report, lambda_unk=args.lambda_unk)

    flips = reparsed["reparse"]["parser_fix"]
    all_metrics = reparsed["reparse"]["all_metrics_side_by_side"]

    print("=" * 78)
    print(f"REPARSE: {in_path.name}")
    print(f"  probes flipped unk->yes : {flips['probes_flipped_unk_to_yes']}")
    print(f"  probes flipped unk->no  : {flips['probes_flipped_unk_to_no']}")
    print(f"  total flipped           : {flips['probes_flipped_total']}")
    print()
    header = f"  {'metric':<20}"
    for label in all_metrics:
        header += f"{label[:18]:>20}"
    print(header)
    for key in ("auc_roc", "tpr_at_fpr_0_5pct", "tpr_at_fpr_1pct", "tpr_at_fpr_5pct", "accuracy_at_fpr10"):
        row = f"  {key:<20}"
        for label, m in all_metrics.items():
            row += f"{m[key]:>20.4f}" if m else f"{'n/a':>20}"
        print(row)
    print("=" * 78)

    out_path = in_path.with_name(in_path.stem + "_reparsed.json")
    out_path.write_text(json.dumps(reparsed, indent=2), encoding="utf-8")
    print(f"\nOriginal file untouched: {in_path}")
    print(f"Reparsed results saved to: {out_path}")


if __name__ == "__main__":
    main()
