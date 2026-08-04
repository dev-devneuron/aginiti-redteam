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
    _overall_risk_verdict,
    _redact,
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
    confirmed=False,
):
    return {
        "attack_type": attack_type,
        "tier_used": tier_used,
        "confidence": confidence,
        "confirmed": confirmed,
        "leaked_content": leaked,
        "probe_used": probe,
        "trace_span_id": "",
        "recommendation": recommendation,
        "severity": severity,
        "full_response": full_response,
        "leak_type": leak_type,
        "reasoning": reasoning,
    }


def _run_benchmark_schema(
    findings, metrics=None, queries_sent=None, refused_queries=None,
    authorized_by=None, engagement_id=None,
):
    run_metadata = {
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
    }
    if queries_sent is not None:
        run_metadata["queries_sent"] = queries_sent
    if authorized_by is not None:
        run_metadata["authorized_by"] = authorized_by
    if engagement_id is not None:
        run_metadata["engagement_id"] = engagement_id
    report = {
        "run_metadata": run_metadata,
        "metrics": metrics or {
            "asr": 0.55, "ee": 0.34, "crr_mean": 0.2, "crr_std": 0.05,
            "ss_mean": 0.6, "ss_std": 0.1, "total_findings": len(findings),
            "refusals_filtered": 20 - len(findings), "ee_hit_threshold": 0.3,
        },
        "findings": findings,
    }
    if refused_queries is not None:
        report["refused_queries"] = refused_queries
    return report


def _run_ikea_schema(
    findings, queries_sent=None, refused_queries=None,
    authorized_by=None, engagement_id=None,
):
    run = {
        "started_at": "2026-07-12T15:13:16.553776+00:00",
        "finished_at": "2026-07-12T15:21:27.649785+00:00",
        "duration_seconds": 491.096009,
        "target_url": "http://localhost:8001",
        "topic": "HR records",
        "max_queries": 20,
        "llm_provider": "gemini/gemini-3.5-flash",
        "embed_model": "chromadb/all-MiniLM-L6-v2",
        "finding_count": len(findings),
    }
    if queries_sent is not None:
        run["queries_sent"] = queries_sent
    if authorized_by is not None:
        run["authorized_by"] = authorized_by
    if engagement_id is not None:
        run["engagement_id"] = engagement_id
    report = {
        "run": run,
        "findings": findings,
    }
    if refused_queries is not None:
        report["refused_queries"] = refused_queries
    return report


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

    def test_run_benchmark_schema_queries_sent_falls_back_to_budget(self):
        # A legacy file with no queries_sent field: fall back to the budget
        # (total_queries), matching the old pre-fix assumption -- NOT a
        # findings-derived count, which would silently undercount for any
        # legacy file that had real (uncaptured) refusals.
        data = _normalize(_run_benchmark_schema([_finding()]))
        assert data["queries_sent"] == 20
        assert data["refused_queries"] == []

    def test_run_benchmark_schema_queries_sent_explicit(self):
        data = _normalize(_run_benchmark_schema([_finding()], queries_sent=13))
        assert data["queries_sent"] == 13

    def test_run_ikea_schema_queries_sent_falls_back_to_budget(self):
        data = _normalize(_run_ikea_schema([_finding()]))
        assert data["queries_sent"] == 20
        assert data["refused_queries"] == []

    def test_run_ikea_schema_refused_queries_passthrough(self):
        refused = [{"probe": "p1", "response": "I don't know."}]
        data = _normalize(_run_ikea_schema([_finding()], refused_queries=refused))
        assert data["refused_queries"] == refused


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

    def test_methodology_mentions_precision_based_ee_for_scored_runs(self, tmp_path):
        markdown = generate_markdown_report(_run_benchmark_schema([_finding()]), tmp_path / "r.md")
        assert "precision" in markdown.split("## Methodology")[1]

    def test_methodology_omits_ee_precision_note_when_unscored(self, tmp_path):
        # run_ikea.py's schema has no ground-truth metrics at all -- EE isn't
        # computed, so the precision-vs-fmeasure note shouldn't appear.
        markdown = generate_markdown_report(_run_ikea_schema([_finding()]), tmp_path / "r.md")
        methodology = markdown.split("## Methodology")[1]
        assert "Rouge-L **precision**" not in methodology


class TestQueriesSentHeader:
    def test_shows_single_value_when_queries_sent_equals_budget(self, tmp_path):
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], queries_sent=20), tmp_path / "r.md"
        )
        assert "**Queries:** 20 |" in markdown
        assert "stopped early" not in markdown

    def test_shows_both_values_when_run_stopped_early(self, tmp_path):
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], queries_sent=13), tmp_path / "r.md"
        )
        assert "**Queries:** 13 sent (of 20 budgeted — stopped early) |" in markdown

    def test_asr_without_ground_truth_uses_queries_sent_not_budget(self, tmp_path):
        # 1 finding / 5 actually sent = 20%, not 1/20 (budget) = 5%.
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], queries_sent=5), tmp_path / "r.md"
        )
        assert "| ASR | 20% | 92% |" in markdown


class TestRefusedQueriesSection:
    def test_no_data_message_when_absent(self, tmp_path):
        markdown = generate_markdown_report(_run_ikea_schema([_finding()]), tmp_path / "r.md")
        assert "## Refused Queries" in markdown
        section = markdown.split("## Refused Queries")[1]
        assert "No refused-query data recorded" in section

    def test_renders_each_refused_probe_and_response(self, tmp_path):
        refused = [
            {"probe": "What medications are prescribed?", "response": "I don't know."},
            {"probe": "What is the treatment plan?", "response": "I cannot answer that."},
        ]
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], refused_queries=refused), tmp_path / "r.md"
        )
        section = markdown.split("## Refused Queries")[1]
        assert '**Probe:** "What medications are prescribed?"' in section
        assert "**Response:** I don't know." in section
        assert '**Probe:** "What is the treatment plan?"' in section
        assert "**Response:** I cannot answer that." in section

    def test_refused_response_truncated_when_long(self, tmp_path):
        refused = [{"probe": "p", "response": "x" * 250}]
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], refused_queries=refused), tmp_path / "r.md"
        )
        section = markdown.split("## Refused Queries")[1]
        assert "x" * 200 + "..." in section

    def test_section_is_last_in_the_document(self, tmp_path):
        refused = [{"probe": "p", "response": "r"}]
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], refused_queries=refused), tmp_path / "r.md"
        )
        headings = [line for line in markdown.splitlines() if line.startswith("## ")]
        assert headings[-1] == "## Refused Queries"


class TestGenerateMarkdownReportFromFile:
    def test_reads_json_and_writes_md_alongside(self, tmp_path):
        json_path = tmp_path / "run_20260712T151316Z.json"
        report = _run_ikea_schema([_finding(severity="critical", leak_type="pii")])
        json_path.write_text(json.dumps(report), encoding="utf-8")

        out_path = generate_markdown_report_from_file(json_path)

        assert out_path == json_path.with_suffix(".md")
        assert out_path.exists()
        assert "Aginiti DRA Assessment Report" in out_path.read_text(encoding="utf-8")

    def test_redact_writes_to_redacted_suffix(self, tmp_path):
        json_path = tmp_path / "run_20260712T151316Z.json"
        report = _run_ikea_schema([_finding(severity="critical", leak_type="pii")])
        json_path.write_text(json.dumps(report), encoding="utf-8")

        out_path = generate_markdown_report_from_file(json_path, redact=True)

        assert out_path == json_path.with_name("run_20260712T151316Z_redacted.md")
        assert out_path.exists()


class TestGlobalFindingIds:
    def test_ids_unique_across_severity_buckets(self, tmp_path):
        # Regression test: before the fix, each severity section numbered
        # findings independently starting at 1, so a High finding and a
        # Medium finding could both render as "IKEA-001".
        findings = [
            _finding(leak_type="sensitive_data", severity="high", probe="high-probe"),
            _finding(leak_type="sensitive_data", severity="medium", probe="medium-probe"),
        ]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "Finding IKEA-001 [HIGH]" in markdown
        assert "Finding IKEA-002 [MEDIUM]" in markdown
        assert "Finding IKEA-001 [MEDIUM]" not in markdown

    def test_ids_assigned_in_query_order_across_all_three_buckets(self, tmp_path):
        findings = [
            _finding(leak_type="sensitive_data", severity="medium", probe="p-medium"),
            _finding(leak_type="pii", severity="critical", probe="p-critical"),
            _finding(leak_type="sensitive_data", severity="high", probe="p-high"),
        ]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "Finding IKEA-001 [MEDIUM]" in markdown
        assert "Finding IKEA-002 [CRITICAL]" in markdown
        assert "Finding IKEA-003 [HIGH]" in markdown


class TestCoverageNote:
    def test_present_and_mentions_query_count(self, tmp_path):
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], queries_sent=20), tmp_path / "r.md"
        )
        assert "Coverage note" in markdown
        assert "sampled 20 queries" in markdown
        assert "not exhaustive" in markdown

    def test_singular_query_wording(self, tmp_path):
        markdown = generate_markdown_report(
            _run_ikea_schema([_finding()], queries_sent=1), tmp_path / "r.md"
        )
        assert "sampled 1 query " in markdown


class TestConfirmedVsSchemaStatus:
    def test_confirmed_leak_shows_confirmed_status(self, tmp_path):
        findings = [_finding(leak_type="pii", severity="critical", confirmed=True)]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "**Status:** CONFIRMED DATA LEAK (pii)" in markdown

    def test_unconfirmed_schema_shows_not_confirmed_status(self, tmp_path):
        findings = [_finding(leak_type="schema", severity="medium", confirmed=False)]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "**Status:** Not confirmed as a data leak (schema" in markdown
        assert "CONFIRMED DATA LEAK" not in markdown


class TestAuthorizationMetadata:
    def test_shown_when_present(self, tmp_path):
        report = _run_ikea_schema(
            [_finding()], authorized_by="Jane Doe (CISO)", engagement_id="ENG-042",
        )
        markdown = generate_markdown_report(report, tmp_path / "r.md")
        assert "**Authorized by:** Jane Doe (CISO)" in markdown
        assert "**Engagement:** ENG-042" in markdown
        assert "Not recorded for this run" not in markdown

    def test_warning_shown_when_absent(self, tmp_path):
        markdown = generate_markdown_report(_run_ikea_schema([_finding()]), tmp_path / "r.md")
        assert "**Authorization:** Not recorded for this run" in markdown

    def test_partial_metadata_only_shows_supplied_field(self, tmp_path):
        report = _run_ikea_schema([_finding()], authorized_by="Jane Doe (CISO)")
        markdown = generate_markdown_report(report, tmp_path / "r.md")
        assert "**Authorized by:** Jane Doe (CISO)" in markdown
        assert "**Engagement:**" not in markdown


class TestOverallRiskVerdict:
    def test_none_detected_when_no_reportable_findings(self):
        assert "NONE DETECTED" in _overall_risk_verdict([])

    def test_confirmed_finding_drives_verdict(self):
        findings = [
            _finding(leak_type="schema", severity="high", confirmed=False),
            _finding(leak_type="pii", severity="critical", confirmed=True),
        ]
        verdict = _overall_risk_verdict(findings)
        assert verdict.startswith("CRITICAL")
        assert "confirmed data disclosure" in verdict

    def test_falls_back_to_unconfirmed_when_nothing_confirmed(self):
        findings = [_finding(leak_type="schema", severity="medium", confirmed=False)]
        verdict = _overall_risk_verdict(findings)
        assert verdict.startswith("MEDIUM")
        assert "structural disclosure only" in verdict

    def test_rendered_at_top_of_report(self, tmp_path):
        findings = [_finding(leak_type="pii", severity="critical", confirmed=True)]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "**Overall Risk:** CRITICAL (confirmed data disclosure)" in markdown
        # Must appear before the Risk Summary table, not buried after findings.
        assert markdown.index("**Overall Risk:**") < markdown.index("## Risk Summary")


class TestRedact:
    def test_redact_helper_masks_length_and_label(self):
        assert _redact("some leaked text", "leaked content") == \
            "[REDACTED — 16 chars of leaked content]"

    def test_redact_helper_handles_empty_and_none(self):
        assert _redact("", "leaked content") == "[REDACTED — 0 chars of leaked content]"
        assert _redact(None, "leaked content") == "[REDACTED — 0 chars of leaked content]"

    def test_redacted_report_masks_leaked_content_and_response(self, tmp_path):
        findings = [_finding(
            leak_type="pii", severity="critical",
            leaked="Emma earns $152,000.", full_response="Sure, Emma earns $152,000 per year.",
        )]
        markdown = generate_markdown_report(
            _run_ikea_schema(findings), tmp_path / "r.md", redact=True
        )
        assert "Emma earns $152,000" not in markdown
        assert "[REDACTED" in markdown
        assert "[REDACTED VERSION" in markdown  # header banner

    def test_non_redacted_report_has_no_banner_or_masking(self, tmp_path):
        findings = [_finding(leak_type="pii", severity="critical", leaked="Emma earns $152,000.")]
        markdown = generate_markdown_report(_run_ikea_schema(findings), tmp_path / "r.md")
        assert "Emma earns $152,000." in markdown
        assert "[REDACTED VERSION" not in markdown

    def test_redacted_report_preserves_non_sensitive_fields(self, tmp_path):
        findings = [_finding(
            leak_type="pii", severity="critical", probe="What is the salary?",
            reasoning="Discloses a specific figure.", recommendation="Restrict retrieval.",
        )]
        markdown = generate_markdown_report(
            _run_ikea_schema(findings), tmp_path / "r.md", redact=True
        )
        assert '**Probe:** "What is the salary?"' in markdown
        assert "**Why flagged:** Discloses a specific figure." in markdown
        assert "**Remediation:** Restrict retrieval." in markdown
