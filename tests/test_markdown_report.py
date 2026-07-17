"""
Unit tests for aginiti/reporting/markdown_report.py.

No API keys or network access required — operates purely on in-memory dicts
and tmp_path-backed files.
"""

import json

import pytest

from aginiti.reporting.markdown_report import (
    _bucket,
    _format_runtime,
    _normalize,
    _truncate,
    generate_markdown_report,
    generate_markdown_report_from_file,
)


def _finding(
    severity="high",
    confidence=0.7,
    attack_type="DRA",
    tier_used="black_box",
    probe="probe text",
    leaked="leaked content",
    recommendation="recommendation text",
    leak_type="sensitive_data",
    full_response="the complete agent response text",
    reasoning="test reasoning",
):
    return {
        "attack_type": attack_type,
        "tier_used": tier_used,
        "confidence": confidence,
        "confirmed": False,
        "leaked_content": leaked,
        "probe_used": probe,
        "trace_span_id": "",
        "recommendation": recommendation,
        "severity": severity,
        "full_response": full_response,
        "leak_type": leak_type,
        "reasoning": reasoning,
    }


def _run_benchmark_schema(findings, metrics=None):
    return {
        "run_metadata": {
            "attack": "ikea",
            "agent_url": "http://localhost:8003",
            "dataset": "healthcaremagic_1k",
            "dataset_size": 1000,
            "topic": "patient medical consultations",
            "total_queries": 20,
            "llm_provider": "gemini/gemini-3.5-flash",
            "embed_model": "chromadb/all-MiniLM-L6-v2",
            "theta_inter": 0.6,
            "theta_anchor": None,
            "timestamp": "2026-07-12T10:18:44.038704+00:00",
            "runtime_seconds": 477.4,
        },
        "metrics": metrics or {
            "asr": 0.55, "ee": 0.34, "crr_mean": 0.2, "crr_std": 0.05,
            "ss_mean": 0.6, "ss_std": 0.1, "total_findings": len(findings),
            "refusals_filtered": 20 - len(findings), "ee_hit_threshold": 0.3,
        },
        "findings": findings,
    }


def _run_ikea_schema(findings):
    return {
        "run": {
            "started_at": "2026-07-12T15:13:16.553776+00:00",
            "finished_at": "2026-07-12T15:21:27.649785+00:00",
            "duration_seconds": 491.096009,
            "target_url": "http://localhost:8001",
            "topic": "HR records",
            "max_queries": 20,
            "llm_provider": "gemini/gemini-3.5-flash",
            "embed_model": "chromadb/all-MiniLM-L6-v2",
            "finding_count": len(findings),
        },
        "findings": findings,
    }


class TestFormatRuntime:
    def test_formats_minutes_and_seconds(self):
        assert _format_runtime(491.096) == "8m 11s"

    def test_formats_zero(self):
        assert _format_runtime(0) == "0m 0s"

    def test_rounds_to_nearest_second(self):
        assert _format_runtime(59.6) == "1m 0s"


class TestTruncate:
    def test_short_text_unchanged(self):
        assert _truncate("short", 200) == "short"

    def test_long_text_truncated_with_ellipsis(self):
        text = "x" * 250
        result = _truncate(text, 200)
        assert result == "x" * 200 + "..."

    def test_none_treated_as_empty(self):
        assert _truncate(None, 200) == ""


class TestNormalize:
    def test_run_benchmark_schema(self):
        data = _normalize(_run_benchmark_schema([_finding()]))
        assert data["target"] == "http://localhost:8003"
        assert data["queries"] == 20
        assert data["runtime_seconds"] == 477.4
        assert data["attack"] == "ikea"
        assert data["metrics"] is not None
        assert data["llm_provider"] == "gemini/gemini-3.5-flash"

    def test_run_ikea_schema(self):
        data = _normalize(_run_ikea_schema([_finding()]))
        assert data["target"] == "http://localhost:8001"
        assert data["queries"] == 20
        assert data["runtime_seconds"] == 491.096009
        assert data["attack"] == "ikea"
        assert data["metrics"] is None
        assert data["llm_provider"] == "gemini/gemini-3.5-flash"

    def test_unrecognized_schema_raises(self):
        with pytest.raises(ValueError, match="Unrecognized report schema"):
            _normalize({"something_else": {}})


class TestBucket:
    def test_pii_and_verbatim_go_to_critical_regardless_of_severity(self):
        findings = [
            _finding(leak_type="pii", severity="medium"),
            _finding(leak_type="verbatim", severity="low"),
        ]
        buckets = _bucket(findings)
        assert len(buckets["critical"]) == 2
        assert buckets["high"] == []
        assert buckets["medium"] == []

    def test_severity_critical_goes_to_critical_bucket(self):
        findings = [_finding(leak_type="sensitive_data", severity="critical")]
        buckets = _bucket(findings)
        assert len(buckets["critical"]) == 1

    def test_severity_high_goes_to_high_bucket(self):
        findings = [_finding(leak_type="sensitive_data", severity="high")]
        buckets = _bucket(findings)
        assert len(buckets["high"]) == 1

    def test_everything_else_falls_through_to_medium(self):
        findings = [
            _finding(leak_type="schema", severity="medium"),
            _finding(leak_type="sensitive_data", severity="low"),
        ]
        buckets = _bucket(findings)
        assert len(buckets["medium"]) == 2

    def test_no_finding_silently_dropped(self):
        findings = [
            _finding(leak_type="pii", severity="critical"),
            _finding(leak_type="verbatim", severity="high"),
            _finding(leak_type="sensitive_data", severity="high"),
            _finding(leak_type="sensitive_data", severity="medium"),
            _finding(leak_type="schema", severity="low"),
        ]
        buckets = _bucket(findings)
        total_bucketed = sum(len(v) for v in buckets.values())
        assert total_bucketed == len(findings)


class TestGenerateMarkdownReport:
    def test_writes_file_and_returns_string(self, tmp_path):
        report = _run_ikea_schema([_finding(severity="critical", leak_type="pii")])
        out_path = tmp_path / "report.md"
        markdown = generate_markdown_report(report, out_path)
        assert out_path.exists()
        assert out_path.read_text(encoding="utf-8") == markdown

    def test_header_fields(self, tmp_path):
        report = _run_ikea_schema([_finding()])
        markdown = generate_markdown_report(report, tmp_path / "r.md")
        assert "# Aginiti DRA Assessment Report" in markdown
        assert "**Target:** http://localhost:8001" in markdown
        assert "**Date:** 2026-07-12" in markdown
        assert "IKEA (Silent Leaks, arXiv:2505.15420)" in markdown
        assert "**Queries:** 20" in markdown
        assert "8m 11s" in markdown

    def test_risk_summary_excludes_none_leak_type(self, tmp_path):
        findings = [
            _finding(leak_type="pii", severity="critical"),
            _finding(leak_type="none", severity="low"),
            _finding(leak_type="none", severity="low"),
        ]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        risk_summary = markdown.split("## Risk Summary")[1].split("## Key Metrics")[0]
        assert "| Critical | 1 |" in risk_summary
        assert "Low" not in risk_summary

    def test_risk_summary_severity_counts(self, tmp_path):
        findings = [
            _finding(leak_type="pii", severity="critical"),
            _finding(leak_type="pii", severity="critical"),
            _finding(leak_type="sensitive_data", severity="high"),
        ]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "| Critical | 2 |" in markdown
        assert "| High | 1 |" in markdown

    def test_metrics_table_with_ground_truth(self, tmp_path):
        report = _run_benchmark_schema([_finding()])
        markdown = generate_markdown_report(report, tmp_path / "r.md")
        assert "| ASR | 55% | 92% |" in markdown
        assert "| EE | 0.34 | 0.87* |" in markdown
        assert "| CRR | 0.20 | 0.28 |" in markdown
        assert "| SS | 0.60 | 0.71 |" in markdown

    def test_metrics_table_without_ground_truth_shows_asr_only(self, tmp_path):
        findings = [_finding(), _finding()]  # 2 findings / 20 queries = 10%
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "| ASR | 10% | 92% |" in markdown
        assert "EE/CRR/SS require scoring against a ground-truth dataset" in markdown

    def test_classifier_row_shows_llm_provider(self, tmp_path):
        markdown = generate_markdown_report(_run_ikea_schema([_finding()]), tmp_path / "r.md")
        assert "| Classifier | LLM-as-judge (gemini/gemini-3.5-flash) | — |" in markdown

    def test_critical_findings_section(self, tmp_path):
        findings = [_finding(leak_type="pii", severity="critical", probe="p1")]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "## Critical Findings" in markdown
        assert "Finding IKEA-001 [CRITICAL]" in markdown

    def test_high_findings_section(self, tmp_path):
        findings = [_finding(leak_type="sensitive_data", severity="high", probe="p1")]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "## High Findings" in markdown
        assert "Finding IKEA-001 [HIGH]" in markdown

    def test_medium_findings_section(self, tmp_path):
        findings = [_finding(leak_type="schema", severity="medium", probe="p1")]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "## Medium Findings" in markdown
        assert "Finding IKEA-001 [MEDIUM]" in markdown

    def test_none_leak_type_excluded_from_all_sections(self, tmp_path):
        findings = [_finding(leak_type="none", severity="low", probe="p-none")]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert '"p-none"' not in markdown
        assert "No critical findings in this run." in markdown
        assert "No high-severity findings in this run." in markdown
        assert "No medium-severity findings in this run." in markdown

    def test_non_findings_summary(self, tmp_path):
        findings = [
            _finding(leak_type="pii", severity="critical"),
            _finding(leak_type="none", severity="low"),
            _finding(leak_type="none", severity="low"),
        ]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "## Non-Findings Summary" in markdown
        assert "2 of 3 responses contained no evidence of protected data leakage." in markdown

    def test_owasp_mapping_for_dra(self, tmp_path):
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding(severity="critical", leak_type="pii", attack_type="DRA")]),
            tmp_path / "r.md",
        )
        assert "LLM06:2025 - Sensitive Information Disclosure" in markdown

    def test_owasp_default_for_unknown_attack_type(self, tmp_path):
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding(severity="critical", leak_type="pii", attack_type="XYZ")]),
            tmp_path / "r.md",
        )
        assert "OWASP LLM Top 10 mapping not yet defined" in markdown

    def test_finding_includes_all_labeled_fields(self, tmp_path):
        findings = [_finding(
            severity="critical",
            leak_type="pii",
            probe="What is the salary?",
            leaked="Emma earns $152,000.",
            confidence=0.83,
            recommendation="Restrict retrieval to authorized users.",
            reasoning="Discloses a specific salary figure.",
            full_response="x" * 250,
        )]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert '**Probe:** "What is the salary?"' in markdown
        assert "**What leaked:** Emma earns $152,000." in markdown
        assert "**Why flagged:** Discloses a specific salary figure." in markdown
        assert "**Confidence:** 0.83" in markdown
        assert "**Remediation:** Restrict retrieval to authorized users." in markdown
        assert "**Full response (truncated):** " + "x" * 200 + "..." in markdown
        # Old label must not appear.
        assert "**Leaked:**" not in markdown

    def test_methodology_tier1_black_box(self, tmp_path):
        markdown = generate_markdown_report(_run_ikea_schema([_finding()]), tmp_path / "r.md")
        assert "Tier 1 black-box" in markdown
        assert "chromadb/all-MiniLM-L6-v2" in markdown

    def test_methodology_tier2_otel(self, tmp_path):
        findings = [_finding(tier_used="otel")]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "Tier 2 (OTel-confirmed)" in markdown

    def test_methodology_mentions_leak_classification(self, tmp_path):
        markdown = generate_markdown_report(_run_ikea_schema([_finding()]), tmp_path / "r.md")
        assert "LLM-as-judge" in markdown
        assert "gemini/gemini-3.5-flash" in markdown


class TestGenerateMarkdownReportFromFile:
    def test_reads_json_and_writes_md_alongside(self, tmp_path):
        json_path = tmp_path / "run_20260712T151316Z.json"
        report = _run_ikea_schema([_finding(severity="critical", leak_type="pii")])
        json_path.write_text(json.dumps(report), encoding="utf-8")

        out_path = generate_markdown_report_from_file(json_path)

        assert out_path == json_path.with_suffix(".md")
        assert out_path.exists()
        assert "Aginiti DRA Assessment Report" in out_path.read_text(encoding="utf-8")
