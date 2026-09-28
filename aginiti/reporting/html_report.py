"""
Self-contained HTML assessment report generator.

Generates an executive-ready, modern HTML assessment report dashboard
from the exact same normalized data as generate_markdown_report.

Features:
- Responsive dashboard layout (max-width: 1200px, responsive CSS grid)
- Color-coded severity tiers (Critical, High, Medium, Low, Secure)
- Executive KPI summary cards (Risk level, ASR, Queries/Runtime, Findings breakdown)
- Two-column overview panel (Target details & Risk summary)
- Structured, visually distinct finding cards with boxed test probes,
  highlighted evidence, detection rationale, confidence scores, and remediation.
- Built-in light/dark theme support with crisp typography and zero external runtime dependencies.
- Free of emojis and em-dashes for maximum executive polish.
"""
from __future__ import annotations

import html as _html
from pathlib import Path

from aginiti.reporting.markdown_report import (
    _ATTACK_DISPLAY_NAMES,
    _DEFENSE_DESCRIPTIONS,
    _FULL_RESPONSE_TRUNCATE_CHARS,
    _LEAK_TYPE_DISPLAY_NAMES,
    _OWASP_DEFAULT,
    _OWASP_MAPPING,
    _expand_leak_type,
    _format_runtime,
    _normalize,
    _overall_risk_verdict,
    _redact,
    _toggle_label,
    _truncate,
    _bucket,
)
from aginiti.reporting.technique_descriptions import describe_technique

_STYLE = """
:root {
  --bg: #f8fafc;
  --surface: #ffffff;
  --surface-subtle: #f1f5f9;
  --surface-card: #ffffff;
  --border: #e2e8f0;
  --border-strong: #cbd5e1;
  --text: #0f172a;
  --text-secondary: #475569;
  --text-muted: #64748b;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  
  --sev-critical-bg: #fef2f2;
  --sev-critical-border: #fecaca;
  --sev-critical-text: #991b1b;
  --sev-critical-badge: #dc2626;

  --sev-high-bg: #fff7ed;
  --sev-high-border: #fed7aa;
  --sev-high-text: #9a3412;
  --sev-high-badge: #ea580c;

  --sev-medium-bg: #fffbeb;
  --sev-medium-border: #fde68a;
  --sev-medium-text: #92400e;
  --sev-medium-badge: #d97706;

  --sev-low-bg: #eff6ff;
  --sev-low-border: #bfdbfe;
  --sev-low-text: #1e40af;
  --sev-low-badge: #2563eb;

  --sev-clean-bg: #ecfdf5;
  --sev-clean-border: #a7f3d0;
  --sev-clean-text: #065f46;
  --sev-clean-badge: #059669;

  --code-bg: #0f172a;
  --code-text: #f8fafc;

  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", Roboto, Helvetica, Arial, sans-serif;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #090d16;
    --surface: #111827;
    --surface-subtle: #1e293b;
    --surface-card: #111827;
    --border: #1f293d;
    --border-strong: #334155;
    --text: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;

    --sev-critical-bg: #450a0a;
    --sev-critical-border: #7f1d1d;
    --sev-critical-text: #fca5a5;
    --sev-critical-badge: #ef4444;

    --sev-high-bg: #431407;
    --sev-high-border: #7c2d12;
    --sev-high-text: #fdba74;
    --sev-high-badge: #f97316;

    --sev-medium-bg: #451a03;
    --sev-medium-border: #78350f;
    --sev-medium-text: #fde68a;
    --sev-medium-badge: #f59e0b;

    --sev-low-bg: #172554;
    --sev-low-border: #1e3a8a;
    --sev-low-text: #93c5fd;
    --sev-low-badge: #3b82f6;

    --sev-clean-bg: #064e3b;
    --sev-clean-border: #065f46;
    --sev-clean-text: #6ee7b7;
    --sev-clean-badge: #10b981;

    --code-bg: #030712;
    --code-text: #f3f4f6;
  }
}

:root[data-theme="dark"] {
  --bg: #090d16;
  --surface: #111827;
  --surface-subtle: #1e293b;
  --surface-card: #111827;
  --border: #1f293d;
  --border-strong: #334155;
  --text: #f8fafc;
  --text-secondary: #cbd5e1;
  --text-muted: #94a3b8;

  --sev-critical-bg: #450a0a;
  --sev-critical-border: #7f1d1d;
  --sev-critical-text: #fca5a5;
  --sev-critical-badge: #ef4444;

  --sev-high-bg: #431407;
  --sev-high-border: #7c2d12;
  --sev-high-text: #fdba74;
  --sev-high-badge: #f97316;

  --sev-medium-bg: #451a03;
  --sev-medium-border: #78350f;
  --sev-medium-text: #fde68a;
  --sev-medium-badge: #f59e0b;

  --sev-low-bg: #172554;
  --sev-low-border: #1e3a8a;
  --sev-low-text: #93c5fd;
  --sev-low-badge: #3b82f6;

  --sev-clean-bg: #064e3b;
  --sev-clean-border: #065f46;
  --sev-clean-text: #6ee7b7;
  --sev-clean-badge: #10b981;

  --code-bg: #030712;
  --code-text: #f3f4f6;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  font-size: 15px;
  -webkit-font-smoothing: antialiased;
}

.dashboard-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2.5rem 1.5rem 6rem;
}

/* Header */
.top-header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 1.5rem;
  margin-bottom: 2rem;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 1rem;
}
.brand-eyebrow {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  font-weight: 700;
  margin-bottom: 0.35rem;
}
.report-title {
  font-size: 1.85rem;
  font-weight: 700;
  color: var(--text);
  letter-spacing: -0.02em;
}
.header-meta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}
.meta-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.35rem 0.75rem;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.82rem;
  color: var(--text-secondary);
}

/* PDF download -- window.print() rather than a server-generated file: this
   report is designed to be a standalone, shareable artifact (see the
   module docstring), and a recipient who only has this one .html file
   (forwarded, uploaded, opened on a different machine) has no sibling
   .pdf sitting next to it and no Python environment to generate one --
   the browser's own print-to-PDF always works, with no dependency on
   Chrome/Edge being installed wherever the ORIGINAL report was created
   (unlike aginiti/reporting/pdf_export.py's headless-browser subprocess
   approach, which is a CLI-time convenience for a different use case,
   not a fit for a button on the page itself). */
.pdf-download-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 0.9rem;
  background: var(--text);
  color: var(--surface);
  border: 1px solid var(--text);
  border-radius: var(--radius-sm);
  font-size: 0.85rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  white-space: nowrap;
}
.pdf-download-btn:hover {
  opacity: 0.85;
}
.pdf-download-btn svg {
  width: 15px;
  height: 15px;
  flex-shrink: 0;
}
.meta-chip strong {
  color: var(--text);
}

/* Redacted Banner */
.redacted-banner {
  background: var(--sev-high-bg);
  border: 1px solid var(--sev-high-border);
  color: var(--sev-high-text);
  padding: 0.85rem 1.25rem;
  border-radius: var(--radius-md);
  margin-bottom: 1.5rem;
  font-weight: 600;
  font-size: 0.88rem;
}

/* KPI Cards Grid */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.25rem;
  margin-bottom: 2rem;
}
.kpi-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 1.25rem 1.4rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.03);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.kpi-label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  font-weight: 700;
  margin-bottom: 0.5rem;
}
.kpi-value {
  font-size: 1.65rem;
  font-weight: 700;
  color: var(--text);
  line-height: 1.2;
}
.kpi-subtext {
  font-size: 0.84rem;
  color: var(--text-secondary);
  margin-top: 0.35rem;
}

/* Severity Pill */
.sev-pill {
  display: inline-block;
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 0.25rem 0.65rem;
  border-radius: 999px;
  line-height: 1.2;
}
.sev-pill.critical { background: var(--sev-critical-bg); color: var(--sev-critical-text); border: 1px solid var(--sev-critical-border); }
.sev-pill.high { background: var(--sev-high-bg); color: var(--sev-high-text); border: 1px solid var(--sev-high-border); }
.sev-pill.medium { background: var(--sev-medium-bg); color: var(--sev-medium-text); border: 1px solid var(--sev-medium-border); }
.sev-pill.low { background: var(--sev-low-bg); color: var(--sev-low-text); border: 1px solid var(--sev-low-border); }
.sev-pill.clean { background: var(--sev-clean-bg); color: var(--sev-clean-text); border: 1px solid var(--sev-clean-border); }

/* Two-column Overview */
.overview-grid {
  display: grid;
  grid-template-columns: 1.2fr 1fr;
  gap: 1.5rem;
  margin-bottom: 2rem;
}
@media (max-width: 860px) {
  .overview-grid {
    grid-template-columns: 1fr;
  }
}
.panel-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 1.4rem;
}
.panel-title {
  font-size: 1rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

/* Detail Table */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88rem;
}
th, td {
  padding: 0.65rem 0.85rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  font-weight: 700;
  background: var(--surface-subtle);
}
td {
  color: var(--text-secondary);
}
td:first-child {
  color: var(--text);
  font-weight: 600;
}
tr:last-child td {
  border-bottom: none;
}
.tablewrap {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow-x: auto;
}

/* Scope Banner */
.scope-banner {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 4px solid var(--sev-low-badge);
  border-radius: var(--radius-md);
  padding: 1.1rem 1.35rem;
  margin-bottom: 2.25rem;
  font-size: 0.88rem;
  color: var(--text-secondary);
}
.scope-banner strong {
  color: var(--text);
}

/* Findings Section */
.section-heading {
  font-size: 1.3rem;
  font-weight: 700;
  color: var(--text);
  margin: 2.5rem 0 1.25rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.section-count {
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-muted);
}

.bucket-heading {
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--text);
  margin: 1.75rem 0 0.85rem;
}
.empty-bucket {
  background: var(--surface-subtle);
  border: 1px dashed var(--border);
  border-radius: var(--radius-sm);
  padding: 1rem 1.25rem;
  color: var(--text-muted);
  font-size: 0.88rem;
  margin-bottom: 1.25rem;
}

/* Finding Card */
.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: 1.5rem;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,0.02);
}
.finding-header {
  padding: 0.9rem 1.25rem;
  background: var(--surface-subtle);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
}
.finding-id-group {
  display: flex;
  align-items: center;
  gap: 0.65rem;
}
.finding-id {
  font-weight: 700;
  font-size: 0.98rem;
  color: var(--text);
}
.finding-owasp-chip {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-muted);
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 0.2rem 0.6rem;
  border-radius: var(--radius-sm);
}
.finding-operator-chip {
  font-size: 0.76rem;
  font-weight: 600;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  color: var(--sev-low-text);
  background: var(--sev-low-bg);
  border: 1px solid var(--sev-low-border);
  padding: 0.22rem 0.65rem;
  border-radius: var(--radius-sm);
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
}
.technique-info {
  position: relative;
  display: inline-flex;
  cursor: help;
  outline: none;
}
.technique-info-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.05rem;
  height: 1.05rem;
  border-radius: 50%;
  border: 1.5px solid currentColor;
  font-family: Georgia, "Times New Roman", serif;
  font-style: italic;
  font-weight: 700;
  font-size: 0.72rem;
  line-height: 1;
}
.technique-info:focus-visible .technique-info-icon {
  outline: 2px solid var(--sev-low-text);
  outline-offset: 2px;
}
.technique-tooltip {
  visibility: hidden;
  opacity: 0;
  position: absolute;
  top: calc(100% + 0.5rem);
  right: -0.5rem;
  z-index: 20;
  width: max-content;
  max-width: min(18rem, 75vw);
  padding: 0.55rem 0.7rem;
  border-radius: var(--radius-sm);
  background: var(--text);
  color: var(--surface);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 0.78rem;
  font-weight: 500;
  line-height: 1.45;
  white-space: normal;
  text-align: left;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.18);
  transition: opacity 0.12s ease;
  pointer-events: none;
}
.technique-info:hover .technique-tooltip,
.technique-info:focus .technique-tooltip,
.technique-info:focus-within .technique-tooltip {
  visibility: visible;
  opacity: 1;
}

.finding-status-bar {
  padding: 0.6rem 1.25rem;
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.finding-status-bar.confirmed {
  background: var(--sev-critical-bg);
  color: var(--sev-critical-text);
  border-color: var(--sev-critical-border);
}
.finding-status-bar.unconfirmed {
  background: var(--sev-medium-bg);
  color: var(--sev-medium-text);
  border-color: var(--sev-medium-border);
}

.finding-body {
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.field-label {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--text-muted);
}
.field-content {
  font-size: 0.9rem;
  color: var(--text);
}

/* Probe Box */
.probe-box {
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1rem;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.86rem;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
}

/* Leak Evidence Box */
.field-label.leak-label {
  color: var(--sev-critical-badge);
  font-weight: 700;
}
.leak-box {
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  border-left: 4px solid var(--sev-critical-badge);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1rem;
  font-size: 0.88rem;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
  font-weight: 500;
}

/* Remediation Box */
.remediation-box {
  background: var(--sev-low-bg);
  border: 1px solid var(--sev-low-border);
  border-left: 4px solid var(--sev-low-badge);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1rem;
  font-size: 0.88rem;
  color: var(--sev-low-text);
}

/* Details Grid inside card */
.card-details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  padding: 0.75rem 0;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}

/* Response Box */
.response-preview {
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1rem;
  font-size: 0.86rem;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
}

/* Non-Findings and Refusal */
.summary-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 1.25rem 1.4rem;
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
}

footer {
  margin-top: 4rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
  text-align: center;
  font-size: 0.8rem;
  color: var(--text-muted);
}

@media print {
  /* Force the light palette regardless of the viewer's OS dark-mode
     setting: a dark background sent to a printer/PDF wastes ink, and
     every severity color below was tuned for contrast against the light
     surfaces. !important on each custom property, not just a plain
     :root override, because the dark-mode block above is
     ":root:not([data-theme=\"light\"])" -- higher selector specificity
     than a bare ":root" here would otherwise still win even though this
     rule comes later in the stylesheet. */
  :root {
    --bg: #f8fafc !important;
    --surface: #ffffff !important;
    --surface-subtle: #f1f5f9 !important;
    --surface-card: #ffffff !important;
    --border: #e2e8f0 !important;
    --border-strong: #cbd5e1 !important;
    --text: #0f172a !important;
    --text-secondary: #475569 !important;
    --text-muted: #64748b !important;
    --sev-critical-bg: #fef2f2 !important;
    --sev-critical-border: #fecaca !important;
    --sev-critical-text: #991b1b !important;
    --sev-critical-badge: #dc2626 !important;
    --sev-high-bg: #fff7ed !important;
    --sev-high-border: #fed7aa !important;
    --sev-high-text: #9a3412 !important;
    --sev-high-badge: #ea580c !important;
    --sev-medium-bg: #fffbeb !important;
    --sev-medium-border: #fde68a !important;
    --sev-medium-text: #92400e !important;
    --sev-medium-badge: #d97706 !important;
    --sev-low-bg: #eff6ff !important;
    --sev-low-border: #bfdbfe !important;
    --sev-low-text: #1e40af !important;
    --sev-low-badge: #2563eb !important;
    --sev-clean-bg: #ecfdf5 !important;
    --sev-clean-border: #a7f3d0 !important;
    --sev-clean-text: #065f46 !important;
    --sev-clean-badge: #059669 !important;
    --code-bg: #0f172a !important;
    --code-text: #f8fafc !important;
  }

  body {
    background: #ffffff;
  }

  /* Every severity badge/card background on this report is load-bearing
     information (which finding is critical vs. low), not decoration --
     browsers strip background colors by default when printing unless a
     page opts back in explicitly. */
  * {
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  .pdf-download-btn,
  .technique-info {
    display: none;
  }

  .dashboard-container {
    max-width: none;
    padding: 0.5rem 0 2rem;
  }

  .finding-card, .kpi-card, .summary-card, .panel-card {
    break-inside: avoid;
  }
}
"""


def _esc(text) -> str:
    return _html.escape(str(text if text is not None else ""))


def _render_finding_card(f: dict, index: int, attack_code: str, redact: bool) -> str:
    sev = f.get("severity", "low").lower()
    sev_upper = sev.upper()
    owasp = f.get("owasp_override") or _OWASP_MAPPING.get(f.get("attack_type", ""), _OWASP_DEFAULT)
    leak_type = f.get("leak_type", "unknown")
    expanded_leak_type = _expand_leak_type(leak_type)
    
    is_confirmed = bool(f.get("confirmed"))
    if is_confirmed:
        status_label = f"CONFIRMED DATA LEAK ({expanded_leak_type}) - Verified Target Vulnerability"
        status_class = "confirmed"
    else:
        status_label = f"Structural / Partial Observation ({expanded_leak_type} - Unverified Record Content)"
        status_class = "unconfirmed"

    leaked_content = f.get("leaked_content", "")
    full_response = f.get("full_response", "")
    leaked_display = _redact(leaked_content, "leaked content") if redact else leaked_content
    full_response_display = (
        _redact(full_response, "full response") if redact
        else full_response
    )

    # Only present for `aginiti scan` findings (_collect_scan_findings in
    # cli.py) -- see markdown_report.py's identical note for why a
    # standalone `aginiti attack <technique>` report doesn't need this
    # (already states its one technique elsewhere, no per-finding key set).
    operator = f.get("operator")
    technique_desc = describe_technique(operator)
    # Focusable (tabindex) rather than hover-only, so the explanation is
    # also reachable by keyboard and by tapping on touch screens.
    technique_info_html = (
        f'<span class="technique-info" tabindex="0" role="note" aria-label="{_esc(technique_desc)}">'
        f'<span class="technique-info-icon" aria-hidden="true">i</span>'
        f'<span class="technique-tooltip" aria-hidden="true">{_esc(technique_desc)}</span>'
        f'</span>'
        if technique_desc else ""
    )
    operator_chip_html = (
        f'<span class="finding-operator-chip"><strong>Technique:</strong> {_esc(operator)}'
        f'{technique_info_html}</span>'
        if operator else ""
    )

    operator_grid_html = (
        f'<div class="field-group">'
        f'<span class="field-label">Attack Technique (Operator)</span>'
        f'<div class="field-content"><code style="background: var(--surface-subtle); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem;">{_esc(operator)}</code></div>'
        f'</div>'
        if operator else ""
    )

    return f"""
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-id-group">
          <span class="finding-id">Finding {_esc(attack_code)}-{index:03d}</span>
          <span class="sev-pill {sev}">{_esc(sev_upper)}</span>
        </div>
        <div style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap;">
          {operator_chip_html}
          <span class="finding-owasp-chip">{_esc(owasp)}</span>
        </div>
      </div>

      <div class="finding-status-bar {status_class}">
        {_esc(status_label)}
      </div>

      <div class="finding-body">
        <div class="field-group">
          <span class="field-label">Attacker Test Probe</span>
          <div class="probe-box">{_esc(f.get('probe_used', ''))}</div>
        </div>

        <div class="field-group">
          <span class="field-label leak-label">Extracted Evidence (What Leaked)</span>
          <div class="leak-box">{_esc(leaked_display)}</div>
        </div>

        <div class="card-details-grid">
          {operator_grid_html}
          <div class="field-group">
            <span class="field-label">Certainty Score</span>
            <div class="field-content"><strong>{f.get('confidence', 0):.2f}</strong> / 1.00</div>
          </div>
          <div class="field-group">
            <span class="field-label">Detection Rationale</span>
            <div class="field-content">{_esc(f.get('reasoning', ''))}</div>
          </div>
        </div>

        <div class="field-group">
          <span class="field-label">Recommended Remediation</span>
          <div class="remediation-box">{_esc(f.get('recommendation', ''))}</div>
        </div>

        <div class="field-group">
          <span class="field-label">Target Response</span>
          <div class="response-preview">{_esc(full_response_display)}</div>
        </div>
      </div>
    </div>"""


def _render_bucket_section(title: str, findings: list[dict], attack_code: str,
                            finding_ids: dict, redact: bool) -> str:
    sev_key = title.lower()
    if not findings:
        return f'<h3 class="bucket-heading">{_esc(title)} Findings</h3><div class="empty-bucket">No {title.lower()}-severity findings in this assessment run.</div>'
    cards = "".join(
        _render_finding_card(f, finding_ids[id(f)], attack_code, redact) for f in findings
    )
    return f'<h3 class="bucket-heading">{_esc(title)} Findings ({len(findings)})</h3>{cards}'


def generate_html_report(report: dict, output_path: str | Path, redact: bool = False) -> str:
    """
    Render ``report`` as an executive HTML assessment report dashboard
    and write it to ``output_path``. Returns the rendered HTML string.
    """
    data = _normalize(report)
    findings = data["findings"]

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

    queries_str = f"{data['queries']}"
    if data["queries_sent"] != data["queries"]:
        queries_str = f"{data['queries_sent']} sent (of {data['queries']} budgeted - stopped early)"

    auth_html = ""
    if data.get("authorized_by") or data.get("engagement_id"):
        parts = []
        if data.get("authorized_by"):
            parts.append(f"Authorized by: <strong>{_esc(data['authorized_by'])}</strong>")
        if data.get("engagement_id"):
            parts.append(f"Engagement: <strong>{_esc(data['engagement_id'])}</strong>")
        auth_html = f'<div class="meta-chip">{" | ".join(parts)}</div>'

    # Risk verdict and color
    risk_verdict = _overall_risk_verdict(reportable)
    risk_sev = "clean"
    if reportable:
        confirmed = [f for f in reportable if f.get("confirmed")]
        pool = confirmed if confirmed else reportable
        worst_sev = max(pool, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.get("severity", "low"), 0)).get("severity", "low").lower()
        risk_sev = worst_sev if worst_sev in severity_order else "low"

    # ASR calculation
    metrics = data["metrics"]
    if metrics is not None and "asr" in metrics:
        asr_val = metrics["asr"]
    else:
        asr_val = (len(reportable) / data["queries_sent"]) if data["queries_sent"] else 0.0
    asr_pct = f"{asr_val * 100:.0f}%"

    # Risk Summary Rows
    risk_summary_rows = "".join(
        f'<tr><td><span class="sev-pill {sev}">{sev.capitalize()}</span></td><td><strong>{severity_counts[sev]}</strong></td></tr>'
        for sev in severity_order if severity_counts[sev] > 0
    ) or '<tr><td><span class="sev-pill clean">None</span></td><td><strong>0</strong></td></tr>'

    # Metrics Table Rows
    metrics_rows = f"<tr><td>Attack Success Rate (ASR)</td><td><strong>{asr_pct}</strong></td><td>Percentage of test queries that bypassed defenses</td></tr>"
    if metrics is not None:
        if "ee" in metrics:
            metrics_rows += f"<tr><td>Exact Extraction (EE)</td><td><strong>{metrics['ee']:.2f}</strong></td><td>Fraction of sensitive documents fully recovered</td></tr>"
        if "crr_mean" in metrics:
            metrics_rows += f"<tr><td>Character Recovery Rate (CRR)</td><td><strong>{metrics['crr_mean']:.2f}</strong></td><td>Average character overlap with ground truth</td></tr>"
        if "ss_mean" in metrics:
            metrics_rows += f"<tr><td>Semantic Similarity (SS)</td><td><strong>{metrics['ss_mean']:.2f}</strong></td><td>Semantic similarity to target documents</td></tr>"
        if "avg_cosine" in metrics:
            metrics_rows += f"<tr><td>Avg Cosine Similarity</td><td><strong>{metrics['avg_cosine']:.2f}</strong></td><td>Vector distance in embedding space</td></tr>"

    # Target Configuration
    target_config_html = ""
    persona = data.get("persona")
    toggle_state = data.get("target_toggle_state")
    target_profile = data.get("target_profile")
    target_desc = data.get("target_description")
    if target_profile or target_desc or persona or toggle_state:
        profile_badge_class = "clean"
        if target_profile and "Hardened" in target_profile:
            profile_badge_class = "clean"
        elif target_profile and "Vanilla" in target_profile:
            profile_badge_class = "medium"
        else:
            profile_badge_class = "low"

        profile_html = ""
        if target_profile:
            profile_html = (
                f'<div style="margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">'
                f'<span style="font-weight: 600; color: var(--text-primary);">Security Profile:</span>'
                f'<span class="sev-pill {profile_badge_class}" style="font-size: 0.85rem; padding: 0.25rem 0.65rem;">'
                f'{_esc(target_profile)}</span>'
                f'</div>'
            )

        desc_html = f'<p style="margin-bottom: 0.75rem; color: var(--text-secondary);">{_esc(target_desc)}</p>' if target_desc else ""
        persona_html = f'<p style="margin-bottom: 0.75rem; color: var(--text-secondary);">Authenticated Persona: <strong>{_esc(persona)}</strong></p>' if persona else ""

        rows = ""
        if isinstance(toggle_state, dict) and toggle_state:
            rows = "".join(
                f"<tr><td><strong>{_esc(_toggle_label(k))}</strong></td>"
                f"<td><span class=\"sev-pill {'clean' if v else 'low'}\">{'Active' if v else 'Disabled'}</span></td>"
                f"<td style=\"color: var(--text-secondary);\">{_esc(_DEFENSE_DESCRIPTIONS.get(k, ''))}</td></tr>"
                for k, v in toggle_state.items()
            )
        toggle_table = f'<div class="tablewrap" style="margin-top: 0.5rem;"><table><tr><th>Defense Layer</th><th>Status</th><th>What it does</th></tr>{rows}</table></div>' if rows else ""

        target_config_html = f"""
        <div class="panel-card" style="margin-bottom: 2rem;">
          <h2 class="panel-title">Target Configuration & Security Posture</h2>
          {profile_html}
          {desc_html}
          {persona_html}
          {toggle_table}
        </div>"""

    # Findings Buckets
    buckets = _bucket(reportable)
    findings_html = "".join(
        _render_bucket_section(title, buckets[key], attack_code, finding_ids, redact)
        for key, title in [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
    )

    # Refused Queries
    refused_queries = data["refused_queries"]
    if not refused_queries:
        refused_html = "<p style=\"color: var(--text-muted);\">No refused queries recorded for this run.</p>"
    else:
        items = "".join(
            f'<li style="margin-bottom: 0.75rem;"><strong>Probe:</strong> {_esc(r.get("probe", ""))}<br>'
            f'<span style="color: var(--text-muted);">Response:</span> {_esc(_truncate(r.get("response", ""), _FULL_RESPONSE_TRUNCATE_CHARS))}</li>'
            for r in refused_queries
        )
        refused_html = (
            f"<p style=\"margin-bottom: 0.75rem;\"><strong>{len(refused_queries)} of {data['queries_sent']}</strong> queries were blocked/refused by target guardrails:</p><ol style=\"padding-left: 1.25rem;\">{items}</ol>"
        )

    # Methodology attack description
    tiers = {f.get("tier_used", "black_box") for f in findings} or {"black_box"}
    tier_desc = "Tier 1 Black-Box Assessment (No privileged backend or system prompt access required)" if tiers == {"black_box"} else "Tier 2 Telemetry-Verified Assessment"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aginiti Security Assessment Report - {_esc(attack_display)}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="dashboard-container">
  
  <header class="top-header">
    <div>
      <div class="brand-eyebrow">Aginiti Red Team | Security Assessment Report</div>
      <h1 class="report-title">{_esc(attack_display)}</h1>
    </div>
    <div class="header-meta">
      <div class="meta-chip">Date: <strong>{_esc(date_str)}</strong></div>
      <div class="meta-chip">Target: <strong>{_esc(data['target'])}</strong></div>
      {auth_html}
      <button class="pdf-download-btn" onclick="window.print()" title="Opens the browser's print dialog -- choose 'Save as PDF' as the destination">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><polyline points="7 10 12 15 17 10"/><path d="M5 21h14"/></svg>
        Download PDF
      </button>
    </div>
  </header>

  {f'<div class="redacted-banner">REDACTED VERSION - Leaked sensitive content and raw target outputs are masked in this report.</div>' if redact else ''}

  <!-- KPI Cards Row -->
  <section class="kpi-grid">
    <div class="kpi-card">
      <span class="kpi-label">Overall Risk Rating</span>
      <div class="kpi-value"><span class="sev-pill {risk_sev}">{_esc(risk_verdict)}</span></div>
      <span class="kpi-subtext">Highest confirmed finding severity</span>
    </div>

    <div class="kpi-card">
      <span class="kpi-label">Attack Success Rate (ASR)</span>
      <div class="kpi-value">{asr_pct}</div>
      <span class="kpi-subtext">{len(reportable)} of {data['queries_sent']} queries exposed vulnerabilities</span>
    </div>

    <div class="kpi-card">
      <span class="kpi-label">Query Budget & Runtime</span>
      <div class="kpi-value">{data['queries_sent']} Queries</div>
      <span class="kpi-subtext">Completed in {_format_runtime(data['runtime_seconds'])}</span>
    </div>

    <div class="kpi-card">
      <span class="kpi-label">Verified Findings</span>
      <div class="kpi-value">{len(reportable)} Total</div>
      <span class="kpi-subtext">
        <span class="sev-pill critical" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">{severity_counts['critical']} Crit</span>
        <span class="sev-pill high" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">{severity_counts['high']} High</span>
        <span class="sev-pill medium" style="font-size: 0.68rem; padding: 0.15rem 0.4rem;">{severity_counts['medium']} Med</span>
      </span>
    </div>
  </section>

  <!-- Overview Details & Risk Summary -->
  <section class="overview-grid">
    <div class="panel-card">
      <h2 class="panel-title">Assessment Execution Details</h2>
      <div class="tablewrap">
        <table>
          <tr><td>Target Endpoint</td><td><code>{_esc(data['target'])}</code></td></tr>
          <tr><td>Evaluation Classifier</td><td>LLM-as-judge ({_esc(data['llm_provider'])})</td></tr>
          <tr><td>Assessment Tier</td><td>{_esc(tier_desc)}</td></tr>
          <tr><td>Embedding Engine</td><td><code>{_esc(data['embed_model'] or 'chromadb/all-MiniLM-L6-v2')}</code> (Local ONNX)</td></tr>
        </table>
      </div>
    </div>

    <div class="panel-card">
      <h2 class="panel-title">Vulnerability Severity Distribution</h2>
      <div class="tablewrap">
        <table>
          <tr><th>Severity Tier</th><th>Confirmed Count</th></tr>
          {risk_summary_rows}
        </table>
      </div>
    </div>
  </section>

  <!-- Scope Banner -->
  <div class="scope-banner">
    <strong>Assessment Scope:</strong> This run evaluated <strong>{data['queries_sent']} queries</strong> against the target. To ensure comprehensive defense-in-depth across all threat surfaces (jailbreaks, RAG exfiltration, prompt leakage, and tool abuse), execute complementary scan tiers and attack modules from aginiti-redteam.
  </div>

  {target_config_html}

  <!-- Key Metrics Table -->
  <div class="panel-card" style="margin-bottom: 2.5rem;">
    <h2 class="panel-title">Key Performance & Security Metrics</h2>
    <div class="tablewrap">
      <table>
        <tr><th>Metric</th><th>Value</th><th>Description</th></tr>
        {metrics_rows}
      </table>
    </div>
  </div>

  <!-- Detailed Findings -->
  <section>
    <div class="section-heading">
      <span>Vulnerability Findings & Evidence</span>
      <span class="section-count">{len(reportable)} reportable findings</span>
    </div>
    {findings_html}
  </section>

  <!-- Non-Findings Summary -->
  <div class="summary-card">
    <h2 class="panel-title">Non-Findings & Safe Responses</h2>
    <p style="color: var(--text-secondary);"><strong>{non_findings_count} of {len(findings)}</strong> target responses contained no evidence of data leakage, prompt disclosure, or unauthorized actions.</p>
  </div>

  <!-- Refused Queries -->
  <div class="summary-card">
    <h2 class="panel-title">Guardrail Defenses & Refused Queries</h2>
    {refused_html}
  </div>

  <footer>
    Aginiti Red Team Assessment Engine - Authorized Security Testing Report
  </footer>

</div>
</body>
</html>
"""

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_doc, encoding="utf-8")
    return html_doc
