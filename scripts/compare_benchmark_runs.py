"""
Side-by-side comparison table across two or more benchmark result JSON files
(``scripts/run_benchmark.py`` output schema — ``run_metadata`` + ``metrics``
+ ``findings``).

Built as a separate, standalone script rather than a change to
``aginiti/reporting/markdown_report.py``: that module renders ONE run's
report (a deliberate, single-run contract); comparing multiple saved runs is
benchmarking tooling, not a library-facing report shape, so it lives here in
``scripts/`` instead. See ``plans/onyx-integration.md`` §3.8.

Usage:
    python scripts/compare_benchmark_runs.py \\
        --label "healthcare_agent" benchmarks/scaled_evals/results/ikea_healthcare_50q_....json \\
        --label "Onyx" benchmarks/scaled_evals/results/ikea_onyx_50q_....json \\
        --output benchmarks/scaled_evals/results/comparison_healthcare_vs_onyx.md

Prints the table to stdout and, if ``--output`` is given, also writes it as
a standalone Markdown file. Always includes the same hardcoded IKEA paper
baseline column ``scripts/run_benchmark.py`` shows in its own per-run
summary (reused from there, not duplicated).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Same import-fallback pattern as scripts/run_healthcare_benchmark.py — works
# whether invoked as `python scripts/compare_benchmark_runs.py` (script's own
# dir goes on sys.path, "scripts" is not importable as a package from there)
# or as `python -m scripts.compare_benchmark_runs` (repo root on sys.path).
sys.path.insert(0, str(Path(__file__).parent))
try:
    from scripts.run_benchmark import _PAPER_TABLE1
except ImportError:
    from run_benchmark import _PAPER_TABLE1

_METRIC_ROWS = [
    ("ASR", "asr", "{:.0%}"),
    ("EE", "ee", "{:.4f}"),
    ("CRR (mean)", "crr_mean", "{:.4f}"),
    ("SS (mean)", "ss_mean", "{:.4f}"),
    ("Confirmed leaks", "confirmed_leaks", "{}"),
    ("Total findings", "total_findings", "{}"),
]


def _load(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "metrics" not in data or "run_metadata" not in data:
        raise ValueError(
            f"{path} doesn't look like a scripts/run_benchmark.py results file "
            "(expected 'run_metadata' and 'metrics' keys)."
        )
    return data


def build_comparison_table(runs: list[tuple[str, dict]]) -> str:
    """``runs`` is a list of (label, report_dict) pairs, in display order."""
    headers = ["Metric"] + [label for label, _ in runs] + ["Paper baseline*"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for display_name, key, fmt in _METRIC_ROWS:
        row = [display_name]
        for _, report in runs:
            value = report["metrics"].get(key)
            row.append(fmt.format(value) if value is not None else "—")
        paper_value = _PAPER_TABLE1.get(key)
        row.append(fmt.format(paper_value) if paper_value is not None else "—")
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    lines.append(
        "*Paper baseline: IKEA (Wang et al., ICLR 2026, arXiv:2505.15420) "
        "Table 1 (LLaMA + all-mpnet-base-v2, "
        "No Defense) — hardcoded, not measured. Not directly comparable to "
        "either run above: different embedding model on both sides "
        "(all-MiniLM-L6-v2 here vs. all-mpnet-base-v2 in the paper), and "
        "possibly a different embedding model on the TARGET side between the "
        "two runs above too (see each run's own Methodology section for "
        "what its target actually used — do not assume they match)."
    )
    lines.append("")
    lines.append("## Run details")
    lines.append("| | " + " | ".join(label for label, _ in runs) + " |")
    lines.append("|---|" + "|".join(["---"] * len(runs)) + "|")
    for field, display in [("agent_url", "Target"), ("queries_sent", "Queries sent"),
                            ("embed_model", "Attacker embed model"), ("llm_provider", "Attacker LLM")]:
        row = [display]
        for _, report in runs:
            row.append(str(report["run_metadata"].get(field, "—")))
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--label", nargs=2, action="append", metavar=("LABEL", "PATH"),
                        required=True, dest="labeled_paths",
                        help="A display label + results JSON path. Repeat for each run "
                             "(at least 2). Example: --label Onyx results/onyx_run.json")
    parser.add_argument("--output", default=None,
                        help="Optional path to also write the table as a standalone .md file.")
    args = parser.parse_args()

    if len(args.labeled_paths) < 2:
        raise SystemExit("Need at least two --label LABEL PATH pairs to compare.")

    runs = [(label, _load(path)) for label, path in args.labeled_paths]
    table = build_comparison_table(runs)

    print(table)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        header = f"# Benchmark comparison — {' vs. '.join(label for label, _ in runs)}\n\n"
        out_path.write_text(header + table, encoding="utf-8")
        print(f"Wrote comparison table to {out_path}")


if __name__ == "__main__":
    main()
