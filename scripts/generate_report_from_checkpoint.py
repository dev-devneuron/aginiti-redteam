"""
One-off recovery script: generates the full IKEA benchmark report (JSON +
Markdown, matching exactly what run_benchmark() would have written) directly
from an existing checkpoint file, with NO live attack execution at all.

Built 2026-08-14 after compute_metrics() stalled for hours on two separate
occasions against a 256-finding / 560-document run (real ROUGE-L cost, not a
hang — see scripts/run_benchmark.py's inline comments). Since the checkpoint
already holds every real finding, there is no need to re-run the attack (or
even wait inside the same stuck process) to get the final report -- this
script just does the post-attack half of run_benchmark()'s work, standalone.

Usage:
    python scripts/generate_report_from_checkpoint.py <checkpoint.json> <output.json> \
        --ground-truth <gt.json> --topic "..." --total-queries N --queries-sent N \
        [--persona legal] [--extra-metadata-json '{"key": "value"}']
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from pathlib import Path

# Must happen before importing run_benchmark's logger-using functions --
# without this, compute_metrics()'s [SCORING] progress logs (added
# 2026-08-16) are silently suppressed by Python's default WARNING level,
# and this multi-hour script would give zero visibility while it runs.
logging.basicConfig(level=logging.INFO, format="%(message)s")

sys.path.insert(0, str(Path(__file__).parent))
from run_benchmark import (  # noqa: E402
    _load_ground_truth, compute_metrics, _print_summary,
)
from aginiti.attacks.base import LeakFinding  # noqa: E402
from aginiti.reporting import generate_markdown_report  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", help="Path to the .checkpoint.json (a plain list of LeakFinding dicts).")
    parser.add_argument("output", help="Path to write the final report JSON.")
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--topic", required=True)
    parser.add_argument("--total-queries", type=int, required=True)
    parser.add_argument("--queries-sent", type=int, required=True)
    parser.add_argument("--llm-provider", default="gemini/gemini-3.5-flash")
    parser.add_argument("--embed-model", default="chromadb/all-MiniLM-L6-v2")
    parser.add_argument("--extra-metadata-json", default="{}",
                        help="JSON dict merged into run_metadata (e.g. persona/toggle state).")
    args = parser.parse_args()

    print(f"Loading checkpoint from {args.checkpoint} ...")
    old_findings = json.loads(Path(args.checkpoint).read_text(encoding="utf-8"))
    findings = [LeakFinding(**f) for f in old_findings]
    print(f"Loaded {len(findings)} findings.")

    gt_path = Path(args.ground_truth)
    gt_docs = _load_ground_truth(gt_path)
    print(f"Loaded {len(gt_docs)} ground-truth documents from {gt_path}")

    refused_queries: list[dict] = []  # not in the checkpoint format -- unknown here, left empty

    print("Computing metrics (this is the slow step -- ROUGE-L against a large corpus takes real time) ...")
    metrics_error = None
    try:
        metrics = compute_metrics(
            findings=findings, gt_docs=gt_docs, total_queries=args.total_queries,
            embed_model=args.embed_model, embed_api_key=None,
            llm_provider=args.llm_provider, queries_sent=args.queries_sent,
        )
    except Exception as exc:
        metrics_error = f"{type(exc).__name__}: {exc}"
        metrics = None
        print(f"compute_metrics failed: {metrics_error} -- writing findings WITHOUT metrics.")

    extra_metadata = json.loads(args.extra_metadata_json)
    dataset_label = gt_path.stem
    report = {
        "run_metadata": {
            "attack": "ikea",
            "dataset": dataset_label,
            "dataset_size": len(gt_docs),
            "topic": args.topic,
            "total_queries": args.total_queries,
            "queries_sent": args.queries_sent,
            "llm_provider": args.llm_provider,
            "embed_model": args.embed_model,
            "fatal_error": None,
            "metrics_error": metrics_error,
            "recovered_from_checkpoint": True,
            **extra_metadata,
        },
        "metrics": metrics,
        "findings": [dataclasses.asdict(f) for f in findings],
        "refused_queries": refused_queries,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote results to {out_path}")

    md_path = out_path.with_suffix(".md")
    generate_markdown_report(report, md_path)
    print(f"Wrote Markdown report to {md_path}")

    redacted_md_path = out_path.with_name(out_path.stem + "_redacted.md")
    generate_markdown_report(report, redacted_md_path, redact=True)
    print(f"Wrote redacted Markdown report to {redacted_md_path}")

    _print_summary(metrics, args.total_queries, dataset_label, args.embed_model, n_findings=len(findings))


if __name__ == "__main__":
    main()
