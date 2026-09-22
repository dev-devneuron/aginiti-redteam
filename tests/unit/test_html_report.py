"""Tests for aginiti/reporting/html_report.py -- the self-contained HTML
assessment report, generated from the exact same normalized data as
generate_markdown_report (see that module's own test file for the shared
_normalize/_bucket/_overall_risk_verdict fixtures this mirrors)."""
from __future__ import annotations

from aginiti.reporting import generate_html_report


def _finding(**overrides) -> dict:
    defaults = dict(
        attack_type="DRA", tier_used="black_box", confidence=0.8, confirmed=True,
        leaked_content="leaked text", probe_used="probe text", trace_span_id="",
        recommendation="fix it", severity="high", full_response="full response text",
        leak_type="pii", reasoning="because it leaked",
    )
    defaults.update(overrides)
    return defaults


def _run_ikea_schema(findings: list[dict], max_queries: int = 20, queries_sent=None) -> dict:
    return {
        "run": {
            "target_url": "http://localhost:8001", "max_queries": max_queries,
            "duration_seconds": 42.0, "started_at": "2026-09-22T00:00:00Z",
            "embed_model": "chromadb/all-MiniLM-L6-v2", "llm_provider": "gemini/gemini-3.5-flash",
            "attack": "ikea", **({"queries_sent": queries_sent} if queries_sent is not None else {}),
        },
        "findings": findings,
    }


class TestGenerateHtmlReport:
    def test_writes_a_file_and_returns_the_same_html(self, tmp_path):
        out_path = tmp_path / "report.html"
        html = generate_html_report(_run_ikea_schema([_finding()]), out_path)

        assert out_path.exists()
        assert out_path.read_text(encoding="utf-8") == html
        assert html.startswith("<!doctype html>")

    def test_no_paper_baseline_anywhere(self, tmp_path):
        html = generate_html_report(_run_ikea_schema([_finding()]), tmp_path / "r.html")
        assert "Paper Baseline" not in html
        assert "92%" not in html

    def test_critical_finding_sorts_into_critical_section(self, tmp_path):
        html = generate_html_report(
            _run_ikea_schema([_finding(severity="critical", leak_type="verbatim")]), tmp_path / "r.html",
        )
        critical_section = html.split("<h3>Critical")[1].split("<h3>High")[0]
        assert "Finding IKEA-001" in critical_section

    def test_high_finding_does_not_land_in_critical_section(self, tmp_path):
        # Regression check mirroring the markdown generator's own fix: a
        # [HIGH] finding must render in the High section, not Critical,
        # even though its leak_type (verbatim) used to force it there.
        html = generate_html_report(
            _run_ikea_schema([_finding(severity="high", leak_type="verbatim")]), tmp_path / "r.html",
        )
        critical_section = html.split("<h3>Critical")[1].split("<h3>High")[0]
        high_section = html.split("<h3>High")[1].split("<h3>Medium")[0]
        assert "Finding IKEA-001" not in critical_section
        assert "Finding IKEA-001" in high_section

    def test_non_reportable_finding_excluded_from_findings_but_counted_in_non_findings(self, tmp_path):
        findings = [_finding(leak_type="pii"), _finding(leak_type="none", confirmed=False)]
        html = generate_html_report(_run_ikea_schema(findings), tmp_path / "r.html")
        assert "1 of 2 responses contained no evidence" in html

    def test_redact_masks_leaked_content_and_full_response(self, tmp_path):
        html = generate_html_report(
            _run_ikea_schema([_finding(leaked_content="Emma Thompson SSN 423-58-9167")]),
            tmp_path / "r.html", redact=True,
        )
        assert "Emma Thompson" not in html
        assert "REDACTED" in html
        assert "REDACTED VERSION" in html  # the banner

    def test_html_special_characters_are_escaped(self, tmp_path):
        html = generate_html_report(
            _run_ikea_schema([_finding(leaked_content="<script>alert(1)</script>")]), tmp_path / "r.html",
        )
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_asr_uses_reportable_not_raw_findings(self, tmp_path):
        findings = [
            _finding(leak_type="pii"),
            _finding(leak_type="none", confirmed=False),
            _finding(leak_type="none", confirmed=False),
        ]
        html = generate_html_report(_run_ikea_schema(findings), tmp_path / "r.html")
        assert "<td>ASR</td><td>5%</td>" in html  # 1 reportable / 20 budget

    def test_owasp_override_used_when_present(self, tmp_path):
        finding = _finding(attack_type="CAMPAIGN", owasp_override="LLM07:2025 - System Prompt Leakage")
        html = generate_html_report(_run_ikea_schema([finding]), tmp_path / "r.html")
        assert "LLM07:2025 - System Prompt Leakage" in html

    def test_no_findings_shows_none_detected_and_empty_buckets(self, tmp_path):
        html = generate_html_report(_run_ikea_schema([]), tmp_path / "r.html")
        assert "NONE DETECTED" in html
        assert "No critical-severity findings in this run." in html
        assert "No low-severity findings in this run." in html
