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
        critical_section = html.split("Critical Findings")[1].split("High Findings")[0]
        assert "Finding IKEA-001" in critical_section

    def test_high_finding_does_not_land_in_critical_section(self, tmp_path):
        html = generate_html_report(
            _run_ikea_schema([_finding(severity="high", leak_type="verbatim")]), tmp_path / "r.html",
        )
        critical_section = html.split("Critical Findings")[1].split("High Findings")[0]
        high_section = html.split("High Findings")[1].split("Medium Findings")[0]
        assert "Finding IKEA-001" not in critical_section
        assert "Finding IKEA-001" in high_section

    def test_non_reportable_finding_excluded_from_findings_but_counted_in_non_findings(self, tmp_path):
        findings = [_finding(leak_type="pii"), _finding(leak_type="none", confirmed=False)]
        html = generate_html_report(_run_ikea_schema(findings), tmp_path / "r.html")
        assert "1 of 2" in html
        assert "contained no evidence" in html

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
        assert "5%" in html  # 1 reportable / 20 budget
        assert "Attack Success Rate (ASR)" in html

    def test_owasp_override_used_when_present(self, tmp_path):
        finding = _finding(attack_type="CAMPAIGN", owasp_override="LLM07:2025 - System Prompt Leakage")
        html = generate_html_report(_run_ikea_schema([finding]), tmp_path / "r.html")
        assert "LLM07:2025 - System Prompt Leakage" in html

    def test_pdf_download_button_present_and_wired_to_window_print(self, tmp_path):
        """Client-side window.print(), not a server-generated .pdf file --
        this report is designed to be a standalone, shareable artifact, so
        the download option has to work even for a recipient who only has
        this one .html file (no sibling .pdf, no Python environment)."""
        html = generate_html_report(_run_ikea_schema([_finding()]), tmp_path / "r.html")
        assert 'onclick="window.print()"' in html
        assert "Download PDF" in html

    def test_pdf_button_hidden_and_light_theme_forced_when_printing(self, tmp_path):
        """@media print must win over the dark-mode block even when the
        viewer's OS prefers dark -- see the CSS comment for why this needs
        !important rather than a plain :root override."""
        html = generate_html_report(_run_ikea_schema([_finding()]), tmp_path / "r.html")
        print_block = html.split("@media print")[1].split("</style>")[0]
        assert ".pdf-download-btn" in print_block
        assert "display: none" in print_block
        assert "!important" in print_block

    def test_finding_shows_operator_chip_when_present(self, tmp_path):
        """`aginiti scan` findings carry an "operator" key (set by cli.py's
        _collect_scan_findings) naming the exact technique that produced
        the finding -- a scan mixes many techniques in one report, so
        attack_type alone ("CAMPAIGN"/"DRA"/etc.) isn't specific enough."""
        finding = _finding(operator="secret_jailbreak_exfiltration")
        html = generate_html_report(_run_ikea_schema([finding]), tmp_path / "r.html")
        assert '<span class="finding-operator-chip">' in html
        assert "secret_jailbreak_exfiltration" in html.split('class="finding-operator-chip">')[1].split("</span>")[0]

    def test_operator_chip_has_info_tooltip_with_plain_language_description(self, tmp_path):
        finding = _finding(operator="jailbreak_dan_style")
        html = generate_html_report(_run_ikea_schema([finding]), tmp_path / "r.html")
        chip = html.split('<span class="finding-operator-chip">')[1].split('<span class="finding-owasp-chip">')[0]
        assert 'class="technique-info" tabindex="0"' in chip
        assert "Do Anything Now" in chip.split('class="technique-tooltip"')[1]

    def test_unknown_operator_renders_chip_without_info_icon(self, tmp_path):
        finding = _finding(operator="some_custom_operator")
        html = generate_html_report(_run_ikea_schema([finding]), tmp_path / "r.html")
        chip = html.split('<span class="finding-operator-chip">')[1].split('<span class="finding-owasp-chip">')[0]
        assert "some_custom_operator" in chip
        assert 'class="technique-info"' not in chip

    def test_technique_info_icon_hidden_when_printing(self, tmp_path):
        html = generate_html_report(_run_ikea_schema([_finding()]), tmp_path / "r.html")
        print_block = html.split("@media print")[1].split("</style>")[0]
        assert ".technique-info" in print_block

    def test_finding_omits_operator_chip_when_absent(self, tmp_path):
        """A standalone `aginiti attack <technique>` report never sets
        "operator" per-finding (the run's one technique is already in the
        header) -- must not render an empty chip for it. The CSS class
        itself is always present (static stylesheet); only the rendered
        <span> tag must be absent."""
        html = generate_html_report(_run_ikea_schema([_finding()]), tmp_path / "r.html")
        assert '<span class="finding-operator-chip">' not in html

    def test_no_findings_shows_none_detected_and_empty_buckets(self, tmp_path):
        html = generate_html_report(_run_ikea_schema([]), tmp_path / "r.html")
        assert "NONE DETECTED" in html
        assert "No critical-severity findings in this assessment run." in html
        assert "No low-severity findings in this assessment run." in html
