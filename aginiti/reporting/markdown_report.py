"""
Human-readable Markdown assessment report generator.

Turns a benchmark results JSON (either schema this repo produces) into a
CISO-facing Markdown report — the Tier 1 deliverable required before this
tool is shown to an enterprise buyer (CLAUDE.md Section 6, "industry-adoption
standards").

Accepts either JSON schema currently produced in this repo:
  - ``scripts/run_ikea.py``'s schema: ``{"run": {...}, "findings": [...]}``.
    No ground-truth dataset is scored against, so only ASR is computed here
    (finding_count / max_queries); EE/CRR/SS are not available.
  - ``scripts/run_benchmark.py``'s schema: ``{"run_metadata": {...},
    "metrics": {...}, "findings": [...]}``. Full EE/ASR/CRR/SS against a
    ground-truth dataset, plus the paper-baseline comparison.

**2026-07-13 rewrite:** findings are now classified by an LLM-as-judge
(``IKEAAttack._classify_leak``, see aginiti/attacks/dra/ikea.py) rather than
by query-response embedding similarity. This report reflects that: only
findings with ``leak_type != "none"`` are shown as numbered findings, bucketed
into Critical/High/Medium sections; everything else is rolled into a single
"Non-Findings" summary line rather than listed individually.

Authorized use only — see the root README and aginiti/attacks/dra/README.md
for this tool's scope and safety notes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# OWASP LLM Top 10 (2025) mapping, keyed by LeakFinding.attack_type. DRA
# (Data Reconstruction Attack) extracts sensitive content from a RAG store,
# which is squarely LLM06:2025. MIA/FIA are not yet implemented in this
# library (see CLAUDE.md build-status table) — no mapping guessed for them
# ahead of time; _OWASP_DEFAULT covers any attack_type not in this dict.
_OWASP_MAPPING = {
    "DRA": "LLM06:2025 - Sensitive Information Disclosure",
}
_OWASP_DEFAULT = "OWASP LLM Top 10 mapping not yet defined for this attack type"

# Paper-reported reference numbers (arXiv:2505.15420 Table 1, LLaMA + MPNet,
# No Defense row) — same source scripts/run_benchmark.py uses. Hardcoded, not
# measured; shown for context only.
_PAPER_BASELINE = {"asr": 0.92, "ee": 0.87, "crr": 0.28, "ss": 0.71}

# Attack registry key -> display name. Only "ikea" exists today. NOTE: cites
# the paper as "arXiv:2505.15420" only — every other reference to this paper
# in this codebase (CLAUDE.md, docs/, ikea.py) cites it as an arXiv preprint,
# with no ICLR (or any venue) acceptance documented anywhere in this project.
# Do not add a venue/year claim here without a verified source.
_ATTACK_DISPLAY_NAMES = {
    "ikea": "IKEA (Silent Leaks, arXiv:2505.15420)",
}

_FULL_RESPONSE_TRUNCATE_CHARS = 200


def _format_runtime(seconds: float) -> str:
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs}s"


def _truncate(text: str, n: int) -> str:
    text = text or ""
    return text[:n] + ("..." if len(text) > n else "")


def _normalize(report: dict) -> dict:
    """Extract a common shape from either JSON schema this repo produces."""
    if "run_metadata" in report:
        meta = report["run_metadata"]
        return {
            "target": meta["agent_url"],
            "queries": meta["total_queries"],
            "runtime_seconds": meta["runtime_seconds"],
            "timestamp": meta["timestamp"],
            "embed_model": meta["embed_model"],
            "llm_provider": meta.get("llm_provider", ""),
            "attack": meta["attack"],
            "findings": report["findings"],
            "metrics": report.get("metrics"),
        }
    if "run" in report:
        meta = report["run"]
        return {
            "target": meta["target_url"],
            "queries": meta["max_queries"],
            "runtime_seconds": meta["duration_seconds"],
            "timestamp": meta["started_at"],
            "embed_model": meta.get("embed_model", ""),
            "llm_provider": meta.get("llm_provider", ""),
            "attack": "ikea",
            "findings": report["findings"],
            "metrics": None,
        }
    raise ValueError(
        "Unrecognized report schema — expected a 'run_metadata' key "
        "(scripts/run_benchmark.py output) or a 'run' key "
        "(scripts/run_ikea.py output)."
    )


def _bucket(findings: list[dict]) -> dict[str, list[dict]]:
    """
    Split findings (already filtered to leak_type != "none") into
    Critical/High/Medium buckets.

    Priority order (judgment call — the three named sections in the spec
    overlap at the edges, e.g. a leak_type="sensitive_data" finding the
    classifier marked severity="critical"): every leak_type != "none"
    finding must land in exactly one bucket, none silently dropped.

    1. leak_type in (pii, verbatim), or severity == "critical" -> Critical
       (pii/verbatim are inherently the most severe categories regardless
       of what severity string the classifier attached).
    2. severity == "high" -> High.
    3. Everything else (medium, low, or any other value) -> Medium, as the
       catch-all so a leak_type="schema"/"sensitive_data" finding with
       severity="low" is still surfaced rather than disappearing.
    """
    buckets: dict[str, list[dict]] = {"critical": [], "high": [], "medium": []}
    for f in findings:
        leak_type = f.get("leak_type", "unknown")
        severity = f.get("severity", "")
        if leak_type in ("pii", "verbatim") or severity == "critical":
            buckets["critical"].append(f)
        elif severity == "high":
            buckets["high"].append(f)
        else:
            buckets["medium"].append(f)
    return buckets


def _render_finding(f: dict, index: int, attack_code: str) -> list[str]:
    sev = f.get("severity", "").upper()
    owasp = _OWASP_MAPPING.get(f.get("attack_type", ""), _OWASP_DEFAULT)
    lines = [
        f"### Finding {attack_code}-{index:03d} [{sev}]",
        f"**Probe:** \"{f.get('probe_used', '')}\"",
        f"**What leaked:** {f.get('leaked_content', '')}",
        f"**Why flagged:** {f.get('reasoning', '')}",
        f"**Confidence:** {f.get('confidence', 0):.2f}",
        f"**OWASP LLM:** {owasp}",
        f"**Remediation:** {f.get('recommendation', '')}",
        f"**Full response (truncated):** "
        f"{_truncate(f.get('full_response', ''), _FULL_RESPONSE_TRUNCATE_CHARS)}",
        "",
    ]
    return lines


def generate_markdown_report(report: dict, output_path: str | Path) -> str:
    """
    Render ``report`` as a human-readable Markdown assessment report and
    write it to ``output_path``.

    ``report`` is a benchmark results dict in either schema this repo
    produces (see module docstring). Returns the rendered Markdown string.
    """
    data = _normalize(report)
    findings = data["findings"]

    # "Confirmed leaks only" (spec) — leak_type="none" findings are real
    # LeakFinding objects (every non-refused response gets classified) but
    # are deliberately excluded from the Risk Summary / numbered findings,
    # and rolled into a single Non-Findings summary line instead.
    reportable = [f for f in findings if f.get("leak_type", "none") != "none"]
    non_findings_count = len(findings) - len(reportable)

    severity_order = ["critical", "high", "medium", "low"]
    severity_counts = {s: 0 for s in severity_order}
    for f in reportable:
        sev = f.get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    date_str = data["timestamp"][:10] if data["timestamp"] else ""
    attack_display = _ATTACK_DISPLAY_NAMES.get(data["attack"], data["attack"])
    attack_code = data["attack"].upper()

    lines: list[str] = []
    lines.append("# Aginiti DRA Assessment Report")
    lines.append(f"**Target:** {data['target']}")
    lines.append(f"**Date:** {date_str}")
    lines.append(f"**Attack:** {attack_display}")
    lines.append(
        f"**Queries:** {data['queries']} | "
        f"**Runtime:** {_format_runtime(data['runtime_seconds'])}"
    )
    lines.append("")

    lines.append("## Risk Summary")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in severity_order:
        if severity_counts[sev] > 0:
            lines.append(f"| {sev.capitalize()} | {severity_counts[sev]} |")
    if not reportable:
        lines.append("| (none) | 0 |")
    lines.append("")

    metrics = data["metrics"]
    lines.append("## Key Metrics")
    lines.append("| Metric | Value | Paper Baseline |")
    lines.append("|--------|-------|----------------|")
    if metrics is not None:
        lines.append(
            f"| ASR | {metrics['asr'] * 100:.0f}% | "
            f"{_PAPER_BASELINE['asr'] * 100:.0f}% |"
        )
        lines.append(f"| EE | {metrics['ee']:.2f} | {_PAPER_BASELINE['ee']:.2f}* |")
        lines.append(
            f"| CRR | {metrics['crr_mean']:.2f} | {_PAPER_BASELINE['crr']:.2f} |"
        )
        lines.append(f"| SS | {metrics['ss_mean']:.2f} | {_PAPER_BASELINE['ss']:.2f} |")
    else:
        asr = (len(findings) / data["queries"]) if data["queries"] else 0.0
        lines.append(f"| ASR | {asr * 100:.0f}% | {_PAPER_BASELINE['asr'] * 100:.0f}% |")
    lines.append(
        f"| Classifier | LLM-as-judge ({data['llm_provider']}) | — |"
    )
    lines.append("")
    if metrics is not None:
        lines.append(
            "*Paper used all-mpnet-base-v2 embeddings on both attacker and "
            "target. See Methodology below."
        )
    else:
        lines.append(
            "*EE/CRR/SS require scoring against a ground-truth dataset, not "
            "available for this run. Use `scripts/run_benchmark.py` against "
            "a ground-truth dataset (e.g. HealthCareMagic-1k) for full "
            "metric scoring."
        )
    lines.append("")

    buckets = _bucket(reportable)

    lines.append("## Critical Findings")
    if not buckets["critical"]:
        lines.append("No critical findings in this run.")
        lines.append("")
    else:
        for i, f in enumerate(buckets["critical"], start=1):
            lines.extend(_render_finding(f, i, attack_code))

    lines.append("## High Findings")
    if not buckets["high"]:
        lines.append("No high-severity findings in this run.")
        lines.append("")
    else:
        for i, f in enumerate(buckets["high"], start=1):
            lines.extend(_render_finding(f, i, attack_code))

    lines.append("## Medium Findings")
    if not buckets["medium"]:
        lines.append("No medium-severity findings in this run.")
        lines.append("")
    else:
        for i, f in enumerate(buckets["medium"], start=1):
            lines.extend(_render_finding(f, i, attack_code))

    lines.append("## Non-Findings Summary")
    lines.append(
        f"{non_findings_count} of {len(findings)} responses contained no "
        "evidence of protected data leakage."
    )
    lines.append("")

    lines.append("## Methodology")
    tiers = {f.get("tier_used", "black_box") for f in findings} or {"black_box"}
    if tiers == {"black_box"}:
        lines.append(
            "Attack type: Data Reconstruction (DRA), Tier 1 black-box. "
            "No access to retriever, embedding model, or system prompt required."
        )
    else:
        lines.append(
            "Attack type: Data Reconstruction (DRA), Tier 2 (OTel-confirmed) "
            "for findings cross-referenced against retrieval spans; "
            "unconfirmed findings remain Tier 1 black-box."
        )
    lines.append(
        f"Embedding model: `{data['embed_model']}` (local ONNX, no API cost). "
        "The IKEA paper used all-mpnet-base-v2 — this project's default is "
        "all-MiniLM-L6-v2 (same family, smaller), used symmetrically on both "
        "attacker and target, so numbers differ from the paper's Table 1 for "
        "embedding-space reasons, not an attacker/target mismatch."
    )
    lines.append(
        f"Leak classification: every non-refused response is separately "
        f"reviewed by an LLM-as-judge ({data['llm_provider']}) that "
        "determines leak_type, severity, and the specific evidence quote — "
        "severity is no longer derived from query-response embedding "
        "similarity, which measured topical relevance, not confirmed "
        "leakage. Adds one LLM call per non-refused response."
    )

    markdown = "\n".join(lines) + "\n"

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    return markdown


def generate_markdown_report_from_file(json_path: str | Path) -> Path:
    """
    Load a benchmark results JSON from disk and write the corresponding
    Markdown report alongside it (same path, ``.md`` suffix instead of
    ``.json``). Returns the output path.
    """
    json_path = Path(json_path)
    report = json.loads(json_path.read_text(encoding="utf-8"))
    output_path = json_path.with_suffix(".md")
    generate_markdown_report(report, output_path)
    return output_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m aginiti.reporting.markdown_report <results.json>")
        sys.exit(1)
    written = generate_markdown_report_from_file(sys.argv[1])
    print(f"Wrote {written}")
