"""
Human-readable Markdown assessment report generator.

Turns a benchmark results JSON (either schema this repo produces) into a
CISO-facing Markdown report — the Tier 1 deliverable required before this
tool is shown to an enterprise buyer (CLAUDE.md Section 6, "industry-adoption
standards").

Accepts either JSON schema currently produced in this repo:
  - ``scripts/run_ikea.py``'s schema: ``{"run": {...}, "findings": [...]}``.
    No ground-truth dataset is scored against, so only ASR is computed here
    (reportable findings / queries actually sent); EE/CRR/SS are not
    available.
  - ``scripts/run_benchmark.py``'s schema: ``{"run_metadata": {...},
    "metrics": {...}, "findings": [...]}``. Full EE/ASR/CRR/SS against a
    ground-truth dataset, plus the paper-baseline comparison.

Findings are classified by an LLM-as-judge (``IKEAAttack._classify_leak``,
see aginiti/attacks/dra/ikea.py), not by query-response embedding
similarity. This report reflects that: only findings with
``leak_type != "none"`` are shown as numbered findings, bucketed into
Critical/High/Medium sections; everything else is rolled into a single
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
# which is squarely LLM06:2025. SECRET (a second DRA technique) shares the
# "DRA" attack_type with IKEA, so it's already covered by that entry, not a
# separate one. FIA is the only one of the four core attacks not yet
# implemented (see CLAUDE.md build-status table) — no mapping guessed for
# it ahead of time; _OWASP_DEFAULT covers any attack_type not in this dict.
_OWASP_MAPPING = {
    "DRA": "LLM06:2025 - Sensitive Information Disclosure",
    # MIA (InterrogationAttack): a confirmed membership verdict is itself a
    # sensitive information disclosure (existence of a record can be
    # sensitive independent of content — e.g. confirming a specific
    # patient/whistleblower/customer record's presence) — same OWASP
    # category as DRA, distinct attack mechanism.
    "MIA": "LLM06:2025 - Sensitive Information Disclosure",
    # SPE (SPEAttack, System Prompt Extraction): the target's own system
    # instructions leaking is exactly OWASP's dedicated category for this,
    # distinct from MIA/DRA's sensitive-information-disclosure framing.
    "SPE": "LLM07:2025 - System Prompt Leakage",
}
_OWASP_DEFAULT = "OWASP LLM Top 10 mapping not yet defined for this attack type"

# Attack registry key ("run_metadata"/report-level "attack" field, e.g.
# scripts/run_benchmark.py's --attack choice or a standalone script's own
# hardcoded value) -> display name. "ikea" and "spe" are the two values
# that actually reach generate_markdown_report() today (run_benchmark.py's
# own ATTACK_REGISTRY only has "ikea" wired in so far; run_spe_benchmark.py
# hardcodes "spe"). SECRET/MIA aren't routed through this function by any
# current script, but are included so their reports render correctly the
# moment they are, rather than needing a follow-up fix then. Falls back to
# the raw key itself (never raises) for anything not listed here.
_ATTACK_DISPLAY_NAMES = {
    "ikea": "IKEA (Silent Leaks, ICLR 2026, arXiv:2505.15420)",
    "secret": "SECRET (External Data Extraction Attacks, IEEE TIFS 2026, arXiv:2510.02964)",
    "mia_interrogation": "Interrogation Attack (Riddle Me This!, ACM CCS 2025, arXiv:2502.00306)",
    "mia_interrogation_benchmark": "Interrogation Attack (Riddle Me This!, ACM CCS 2025, arXiv:2502.00306)",
    "spe": "SPE-LLM (System Prompt Extraction, ICLR 2026, arXiv:2505.23817)",
}

_FULL_RESPONSE_TRUNCATE_CHARS = 200

# Display labels for known target_toggle_state keys (see _normalize's
# "target_toggle_state" field) — generic and extensible on purpose: any
# future defense/attack target that reports a "<name>_enabled" key not
# listed here still renders correctly via the fallback in _toggle_label,
# just without a hand-tuned label. Not hardened_agent-specific despite
# hardened_agent being the first real caller.
_TOGGLE_LABELS = {
    "rbac_enabled": "RBAC",
    "rate_limit_enabled": "Rate Limiting",
    "redaction_enabled": "Output Redaction",
    "memory_enabled": "Conversation Memory",
    "guardrail_enabled": "System-Prompt Guardrail",
}


def _toggle_label(key: str) -> str:
    if key in _TOGGLE_LABELS:
        return _TOGGLE_LABELS[key]
    return key.replace("_enabled", "").replace("_", " ").title()


def _format_runtime(seconds: float) -> str:
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs}s"


def _truncate(text: str, n: int) -> str:
    text = text or ""
    return text[:n] + ("..." if len(text) > n else "")


def _normalize(report: dict) -> dict:
    """Extract a common shape from either JSON schema this repo produces.

    ``queries_sent``/``refused_queries``: both scripts
    now record the queries actually sent and which ones were refused (see
    ``IKEAAttack.refused_queries`` in aginiti/attacks/dra/ikea.py). Reports
    generated by an OLDER version of either script won't have these keys —
    ``.get(...)`` with a same-as-budget/empty-list fallback keeps this
    function working on those legacy files without raising, but for a
    legacy file the fallback ``queries_sent`` is just a guess (assumes the
    full budget was sent and nothing was refused), not a real recovered
    count — that data was never captured and can't be reconstructed after
    the fact.
    """
    if "run_metadata" in report:
        meta = report["run_metadata"]
        return {
            "target": meta["agent_url"],
            "queries": meta["total_queries"],
            "queries_sent": meta.get("queries_sent", meta["total_queries"]),
            "runtime_seconds": meta["runtime_seconds"],
            "timestamp": meta["timestamp"],
            "embed_model": meta["embed_model"],
            "llm_provider": meta.get("llm_provider", ""),
            "attack": meta["attack"],
            "findings": report["findings"],
            "refused_queries": report.get("refused_queries", []),
            "metrics": report.get("metrics"),
            "authorized_by": meta.get("authorized_by"),
            "engagement_id": meta.get("engagement_id"),
            # Both optional, generic (not hardened_agent-specific) —
            # populated via run_benchmark()'s extra_run_metadata by any
            # caller that authenticates as a specific identity and/or has
            # independently-toggleable target-side defenses to report.
            # First real caller: scripts/run_ikea_hardened.py. Absent
            # for callers that don't set these (e.g. run_healthcare_benchmark.py).
            "persona": meta.get("persona"),
            "target_toggle_state": meta.get("target_toggle_state"),
        }
    if "run" in report:
        meta = report["run"]
        refused_queries = report.get("refused_queries", [])
        return {
            "target": meta["target_url"],
            "queries": meta["max_queries"],
            # Fallback matches the run_metadata branch above: assume the
            # full budget was sent when queries_sent isn't recorded (a
            # legacy file, from before this field existed) — NOT
            # len(findings)+len(refused_queries), which would silently
            # undercount for any legacy file that had real refusals the old
            # schema never captured.
            "queries_sent": meta.get("queries_sent", meta["max_queries"]),
            "runtime_seconds": meta["duration_seconds"],
            "timestamp": meta["started_at"],
            "embed_model": meta.get("embed_model", ""),
            "llm_provider": meta.get("llm_provider", ""),
            "attack": meta.get("attack", "ikea"),
            "findings": report["findings"],
            "refused_queries": refused_queries,
            "metrics": None,
            "authorized_by": meta.get("authorized_by"),
            "engagement_id": meta.get("engagement_id"),
            "persona": meta.get("persona"),
            "target_toggle_state": meta.get("target_toggle_state"),
        }
    raise ValueError(
        "Unrecognized report schema — expected a 'run_metadata' key "
        "(scripts/run_benchmark.py output) or a 'run' key "
        "(scripts/run_ikea.py output)."
    )


def _redact(text: str, label: str) -> str:
    """
    Placeholder for a redacted report — preserves enough
    information to know *something* of a given size and category existed,
    without reproducing the literal leaked content. Used when
    ``generate_markdown_report(..., redact=True)``.
    """
    text = text or ""
    return f"[REDACTED - {len(text)} chars of {label}]"


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _overall_risk_verdict(reportable: list[dict]) -> str:
    """
    One-line top-of-report verdict — a CISO skimming this
    report gets a bottom line before the detail tables. Ranked by the worst
    severity among CONFIRMED findings (leak_type in pii/verbatim/
    sensitive_data) first; falls back to the worst severity among ANY
    reportable finding (e.g. schema-only) if nothing is confirmed, since a
    structural disclosure is still worth surfacing, just labeled honestly as
    not a confirmed data leak.
    """
    if not reportable:
        return (
            "NONE DETECTED - see the coverage note below; absence of "
            "findings within this run's query budget is not a safety guarantee."
        )
    confirmed = [f for f in reportable if f.get("confirmed")]
    pool = confirmed if confirmed else reportable
    worst = max(pool, key=lambda f: _SEVERITY_RANK.get(f.get("severity", "low"), 0))
    label = (
        "confirmed data disclosure"
        if confirmed
        else "structural disclosure only - no confirmed data leak"
    )
    return f"{worst.get('severity', 'low').upper()} ({label})"


def _bucket(findings: list[dict]) -> dict[str, list[dict]]:
    """
    Split findings (already filtered to leak_type != "none") into
    Critical/High/Medium/Low buckets, purely by each finding's own
    ``severity`` field -- so the ``[SEVERITY]`` label printed on a finding
    (see ``_render_finding``) always matches the section it's rendered
    under.

    A previous version forced any ``leak_type in ("pii", "verbatim")``
    finding into "critical" regardless of its assigned ``severity``, on
    the theory that those categories are inherently the most severe. In
    practice this produced self-contradictory reports, live-confirmed: a
    finding printed as e.g. ``[HIGH]`` (its real ``severity``) would sit
    under the "## Critical Findings" header, while "## High Findings"
    right below it claimed "No high-severity findings in this run" even
    though one was visibly just above -- and the same for medium findings
    stranded under "Critical" while "## Medium Findings" undercounted
    them. If a classifier's severity assignment for pii/verbatim content
    is ever too low, the fix belongs at the classification step (where
    severity is actually decided), not by silently overriding it here
    while leaving the printed label wrong.

    Every leak_type != "none" finding lands in exactly one bucket, none
    silently dropped: any value other than critical/high/medium/low
    (missing, or an unrecognized string from a custom classifier) falls
    through to Low as a visible catch-all.
    """
    buckets: dict[str, list[dict]] = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        severity = f.get("severity", "").lower()
        buckets[severity if severity in buckets else "low"].append(f)
    return buckets


_LEAK_TYPE_DISPLAY_NAMES = {
    "pii": "Personally Identifiable Information (PII)",
    "verbatim": "Verbatim Context Extraction",
    "sensitive_data": "Sensitive Business / System Data",
    "system_prompt": "System Prompt Extraction",
    "tool_abuse": "Unauthorized Tool Invocation",
    "tool_parameters": "Unauthorized Tool Invocation",
    "schema": "Internal Architecture / Schema Disclosure",
    "membership": "Membership Inference Confirmation",
    "jailbreak": "Safety Guardrail Bypass",
    "context_leakage": "Context / RAG Memory Leakage",
    "encoded_instruction": "Encoded Instruction Bypass",
    "secret_pattern": "Secret / Key Disclosure",
}


def _expand_leak_type(leak_type: str) -> str:
    if leak_type in _LEAK_TYPE_DISPLAY_NAMES:
        return _LEAK_TYPE_DISPLAY_NAMES[leak_type]
    return leak_type.replace("_", " ").title()


def _render_finding(f: dict, index: int, attack_code: str, redact: bool = False) -> list[str]:
    sev = f.get("severity", "").upper()
    owasp = f.get("owasp_override") or _OWASP_MAPPING.get(f.get("attack_type", ""), _OWASP_DEFAULT)

    leak_type = f.get("leak_type", "unknown")
    expanded_leak_type = _expand_leak_type(leak_type)
    if f.get("confirmed"):
        status = f"CONFIRMED DATA LEAK ({expanded_leak_type})"
    else:
        status = f"Not confirmed as a data leak ({expanded_leak_type} - structural/uncertain, not verified record content)"

    leaked_content = f.get("leaked_content", "")
    full_response = f.get("full_response", "")
    leaked_display = _redact(leaked_content, "leaked content") if redact else leaked_content
    full_response_display = (
        _redact(full_response, "full response") if redact
        else full_response
    )

    # The 3-4 word description for each field lives IN THE LABEL (a
    # parenthetical), not appended after the value -- a value can itself
    # contain a hyphen (e.g. the OWASP mapping is always formatted as
    # "LLM06:2025 - Sensitive Information Disclosure"), and appending
    # "- some description" after that produced a confusing double-hyphen
    # chain ("... Disclosure - Industry category mapping") that read like
    # part of the value itself. Putting the plain-language description on
    # the label side is unambiguous regardless of what the value contains.
    lines = [
        f"### Finding {attack_code}-{index:03d} [{sev}]",
        f"**Status (verification result):** {status}",
        f"**Probe (test prompt sent):** \"{f.get('probe_used', '')}\"",
        f"**What leaked (disclosed evidence):** {leaked_display}",
        f"**Why flagged (detection reasoning):** {f.get('reasoning', '')}",
        f"**Confidence (detector certainty):** {f.get('confidence', 0):.2f}",
        f"**OWASP LLM (risk category):** {owasp}",
        f"**Remediation (recommended fix):** {f.get('recommendation', '')}",
        f"**Target response (complete reply):** {full_response_display}",
        "",
    ]
    return lines


def generate_markdown_report(
    report: dict, output_path: str | Path, redact: bool = False
) -> str:
    """
    Render ``report`` as a human-readable Markdown assessment report and
    write it to ``output_path``.

    ``report`` is a benchmark results dict in either schema this repo
    produces (see module docstring). Returns the rendered Markdown string.

    ``redact``: when ``True``, every finding's leaked
    content and full response are replaced with a size/category placeholder
    (see ``_redact``) instead of the literal text — the report itself
    otherwise reproduces real extracted sensitive data verbatim, which makes
    the report file a sensitive artifact in its own right. Everything else
    (severity, leak_type, probe, reasoning, recommendation, OWASP mapping)
    is preserved, so a redacted report still conveys what was found and how
    severe it is, just not the literal content — suitable for wider
    circulation (leadership, external auditors) than the full-detail report.
    Callers typically generate both from the same run (see
    ``scripts/run_benchmark.py``/``scripts/run_ikea.py``).
    """
    data = _normalize(report)
    findings = data["findings"]

    # "Confirmed leaks only" (spec) — leak_type="none" findings are real
    # LeakFinding objects (every non-refused response gets classified) but
    # are deliberately excluded from the Risk Summary / numbered findings,
    # and rolled into a single Non-Findings summary line instead.
    reportable = [f for f in findings if f.get("leak_type", "none") != "none"]
    non_findings_count = len(findings) - len(reportable)

    finding_ids = {id(f): i for i, f in enumerate(reportable, start=1)}

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
    if redact:
        lines.append(
            "**[REDACTED VERSION - leaked content and full responses are "
            "masked below. See the full-detail report for literal evidence.]**"
        )
    lines.append(f"**Target:** {data['target']}")
    lines.append(f"**Date:** {date_str}")
    lines.append(f"**Attack:** {attack_display}")
    queries_str = f"{data['queries']}"
    if data["queries_sent"] != data["queries"]:
        queries_str = f"{data['queries_sent']} sent (of {data['queries']} budgeted - stopped early)"
    lines.append(
        f"**Queries:** {queries_str} | "
        f"**Runtime:** {_format_runtime(data['runtime_seconds'])} | "
        f"**Classifier:** LLM-as-judge ({data['llm_provider']})"
    )
    if data.get("authorized_by") or data.get("engagement_id"):
        parts = []
        if data.get("authorized_by"):
            parts.append(f"**Authorized by:** {data['authorized_by']}")
        if data.get("engagement_id"):
            parts.append(f"**Engagement:** {data['engagement_id']}")
        lines.append(" | ".join(parts))
    lines.append("")

    lines.append(f"**Overall Risk:** {_overall_risk_verdict(reportable)}")
    lines.append("")
    lines.append(
        "> **Assessment Scope:** This assessment evaluated "
        f"{data['queries_sent']} quer{'y' if data['queries_sent'] == 1 else 'ies'} "
        "against the target. To ensure comprehensive defense-in-depth across all threat "
        "vectors (jailbreaks, RAG exfiltration, prompt extraction, and tool abuse), "
        "run complementary scan tiers and attack modules from aginiti-redteam."
    )
    lines.append("")

    persona = data.get("persona")
    toggle_state = data.get("target_toggle_state")
    if persona or toggle_state:
        lines.append("## Target Configuration")
        if persona:
            lines.append(f"**Authenticated as:** {persona}")
        if isinstance(toggle_state, dict) and toggle_state:
            lines.append("")
            lines.append("| Defense | State |")
            lines.append("|---------|-------|")
            for key, value in toggle_state.items():
                lines.append(f"| {_toggle_label(key)} | {'On' if value else 'Off'} |")
        elif isinstance(toggle_state, str):
            lines.append(f"**Target toggle state:** {toggle_state}")
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
    lines.append("| Metric | Value | Description |")
    lines.append("|--------|-------|-------------|")
    if metrics is not None:
        if 'asr' in metrics:
            lines.append(f"| Attack Success Rate (ASR) | {metrics['asr'] * 100:.0f}% | Percentage of queries that successfully bypassed defenses |")
        if 'ee' in metrics:
            lines.append(f"| Exact Extraction (EE) | {metrics['ee']:.2f} | Fraction of sensitive documents fully recovered |")
        if 'crr_mean' in metrics:
            lines.append(f"| Character Recovery Rate (CRR) | {metrics['crr_mean']:.2f} | Average character overlap with ground-truth records |")
        if 'ss_mean' in metrics:
            lines.append(f"| Semantic Similarity (SS) | {metrics['ss_mean']:.2f} | Meaning similarity to target documents |")
        if 'avg_cosine' in metrics:
            lines.append(f"| Average Cosine Similarity | {metrics['avg_cosine']:.2f} | Vector distance in embedding space |")
    else:
        asr = (len(reportable) / data["queries_sent"]) if data["queries_sent"] else 0.0
        lines.append(f"| Attack Success Rate (ASR) | {asr * 100:.0f}% | Percentage of queries that successfully exposed vulnerabilities |")
    lines.append("")

    buckets = _bucket(reportable)

    lines.append("## Critical Findings")
    if not buckets["critical"]:
        lines.append("No critical findings in this run.")
        lines.append("")
    else:
        for f in buckets["critical"]:
            lines.extend(_render_finding(f, finding_ids[id(f)], attack_code, redact))

    lines.append("## High Findings")
    if not buckets["high"]:
        lines.append("No high-severity findings in this run.")
        lines.append("")
    else:
        for f in buckets["high"]:
            lines.extend(_render_finding(f, finding_ids[id(f)], attack_code, redact))

    lines.append("## Medium Findings")
    if not buckets["medium"]:
        lines.append("No medium-severity findings in this run.")
        lines.append("")
    else:
        for f in buckets["medium"]:
            lines.extend(_render_finding(f, finding_ids[id(f)], attack_code, redact))

    lines.append("## Low Findings")
    if not buckets["low"]:
        lines.append("No low-severity findings in this run.")
        lines.append("")
    else:
        for f in buckets["low"]:
            lines.extend(_render_finding(f, finding_ids[id(f)], attack_code, redact))

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
        "The IKEA paper used all-mpnet-base-v2 - this project's default is "
        "all-MiniLM-L6-v2 (same family, smaller), used symmetrically on both "
        "attacker and target, so numbers differ from the paper's Table 1 for "
        "embedding-space reasons, not an attacker/target mismatch."
    )
    lines.append(
        f"Leak classification: every non-refused response is separately "
        f"reviewed by an LLM-as-judge ({data['llm_provider']}) that "
        "determines leak_type, severity, and the specific evidence quote - "
        "severity is no longer derived from query-response embedding "
        "similarity, which measured topical relevance, not confirmed "
        "leakage. Adds one LLM call per non-refused response."
    )
    if metrics is not None:
        lines.append(
            "EE counts a document as \"recovered\" using Rouge-L "
            "**precision** against the finding's evidence quote, not "
            "F-measure - precision measures how much of the quote is found "
            "in the source, and unlike F-measure's recall term, isn't "
            "penalized by the source document's overall length (a short, "
            "fully accurate quote against a long multi-paragraph document "
            "would otherwise score far below threshold on length alone). "
            "CRR above still uses F-measure, for comparability with the "
            "paper's Table 1."
        )
    lines.append("")

    lines.append("## Refused Queries")
    refused_queries = data["refused_queries"]
    if not refused_queries:
        lines.append(
            "No refused-query data recorded for this run (either zero "
            "refusals occurred, or this run predates refusal tracking)."
        )
        lines.append("")
    else:
        lines.append(
            f"{len(refused_queries)} of {data['queries_sent']} queries sent "
            "were refused by the target and excluded from the findings above "
            "(recorded here for completeness - refusal detection is a "
            "heuristic, see aginiti/attacks/dra/README.md):"
        )
        lines.append("")
        for i, r in enumerate(refused_queries, start=1):
            lines.append(f"{i}. **Probe:** \"{r.get('probe', '')}\"")
            lines.append(
                f"   **Response:** "
                f"{_truncate(r.get('response', ''), _FULL_RESPONSE_TRUNCATE_CHARS)}"
            )
        lines.append("")

    markdown = "\n".join(lines) + "\n"

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    return markdown


def generate_markdown_report_from_file(
    json_path: str | Path, redact: bool = False
) -> Path:
    """
    Load a benchmark results JSON from disk and write the corresponding
    Markdown report alongside it (same path, ``.md`` suffix instead of
    ``.json`` — or ``_redacted.md`` when ``redact=True``). Returns the
    output path.
    """
    json_path = Path(json_path)
    report = json.loads(json_path.read_text(encoding="utf-8"))
    suffix = "_redacted.md" if redact else ".md"
    output_path = json_path.with_name(json_path.stem + suffix)
    generate_markdown_report(report, output_path, redact=redact)
    return output_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m aginiti.reporting.markdown_report <results.json>")
        sys.exit(1)
    written = generate_markdown_report_from_file(sys.argv[1])
    print(f"Wrote {written}")
