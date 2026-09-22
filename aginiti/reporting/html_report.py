"""
Self-contained HTML assessment report generator.

Same data, same sections, same severity-sorted findings as
``generate_markdown_report`` (this module reuses that one's normalization/
bucketing/verdict helpers directly, so the two can never silently drift
apart on what a finding's severity or OWASP mapping is) -- rendered as a
single, dependency-free HTML file instead of Markdown, styled to match this
project's own monochrome documentation design system (no emoji, no color-
coded severity, plain bordered sections) so a report opens straight into a
browser looking like a finished document, not a code dump.

Every ``aginiti attack``/``aginiti scan`` run auto-saves this alongside the
``.md`` report (see ``aginiti/cli.py``) -- open ``aginiti_assessment_report.html``
directly in a browser for the readable version; the ``.md`` stays the
plain-text/diffable/git-friendly copy.
"""
from __future__ import annotations

import html as _html
from pathlib import Path

from aginiti.reporting.markdown_report import (
    _ATTACK_DISPLAY_NAMES,
    _FULL_RESPONSE_TRUNCATE_CHARS,
    _OWASP_DEFAULT,
    _OWASP_MAPPING,
    _format_runtime,
    _normalize,
    _overall_risk_verdict,
    _redact,
    _toggle_label,
    _truncate,
    _bucket,
)

_STYLE = """
:root{
  --bg:#ffffff; --surface:#ffffff; --surface-2:#f6f6f7; --surface-3:#efeff1;
  --border:#e5e5e7; --border-strong:#d4d4d8;
  --text:#0a0a0a; --text-dim:#52525b; --text-faint:#8f8f97;
  --radius:8px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Inter",Roboto,sans-serif;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0a0a0a; --surface:#0a0a0a; --surface-2:#161616; --surface-3:#1e1e20;
    --border:#26262a; --border-strong:#333338;
    --text:#f5f5f6; --text-dim:#a3a3ac; --text-faint:#6c6c74;
  }
}
:root[data-theme="dark"]{
  --bg:#0a0a0a; --surface:#0a0a0a; --surface-2:#161616; --surface-3:#1e1e20;
  --border:#26262a; --border-strong:#333338;
  --text:#f5f5f6; --text-dim:#a3a3ac; --text-faint:#6c6c74;
}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);line-height:1.65;font-size:15px;-webkit-font-smoothing:antialiased;}
main{max-width:760px;margin:0 auto;padding:3rem 1.5rem 6rem;}
h1,h2,h3{font-weight:600;line-height:1.3;color:var(--text);letter-spacing:-.01em;}
h1{font-size:1.7rem;margin:0 0 .3rem;}
h2{font-size:1.2rem;margin:2.2rem 0 .9rem;padding-top:1.6rem;border-top:1px solid var(--border);}
h3{font-size:.98rem;margin:1.4rem 0 .7rem;}
p{margin:0 0 .8rem;color:var(--text-dim);}
code{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.85em;background:var(--surface-2);border:1px solid var(--border);border-radius:4px;padding:.1em .4em;color:var(--text);}
.eyebrow{font-size:.74rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-faint);font-weight:600;margin:0 0 .5rem;}
.redacted-banner{border:1px solid var(--border-strong);border-radius:var(--radius);padding:.7rem 1rem;margin-bottom:1.3rem;font-size:.85rem;font-weight:600;}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.9rem;margin:1.3rem 0 1.6rem;padding:1rem 1.1rem;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius);}
.meta div{display:flex;flex-direction:column;gap:.15rem;}
.meta dt{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint);font-weight:600;}
.meta dd{margin:0;font-size:.88rem;color:var(--text);}
.risk-banner{border:1px solid var(--border-strong);border-radius:var(--radius);padding:1rem 1.2rem;margin-bottom:1.2rem;}
.risk-banner .eyebrow{margin-bottom:.3rem;}
.risk-banner .value{font-size:1.15rem;font-weight:700;color:var(--text);}
.note{border:1px solid var(--border);border-radius:var(--radius);padding:.85rem 1rem;margin:0 0 1.3rem;background:var(--surface-2);font-size:.87rem;}
.note p:last-child{margin-bottom:0;}
table{border-collapse:collapse;width:100%;margin:0 0 1rem;font-size:.86rem;}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1.3rem;}
.tablewrap table{margin-bottom:0;}
th,td{text-align:left;padding:.55rem .75rem;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text-dim);}
th{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-faint);font-weight:600;background:var(--surface-2);}
td:first-child{color:var(--text);font-weight:500;}
tr:last-child td{border-bottom:none;}
.finding{border:1px solid var(--border);border-radius:10px;margin-bottom:1rem;overflow:hidden;}
.finding-head{padding:.8rem 1.05rem;background:var(--surface-2);border-bottom:1px solid var(--border);display:flex;align-items:baseline;justify-content:space-between;gap:.6rem;flex-wrap:wrap;}
.finding-head .id{font-weight:700;font-size:.92rem;color:var(--text);}
.finding-head .sev{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-faint);font-weight:700;border:1px solid var(--border-strong);border-radius:20px;padding:.15rem .6rem;}
.finding-body{padding:1rem 1.05rem 1.1rem;}
.finding-body dl{margin:0;}
.finding-body dt{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint);font-weight:700;margin:.85rem 0 .3rem;}
.finding-body dt:first-child{margin-top:0;}
.finding-body dd{margin:0;color:var(--text);font-size:.88rem;white-space:pre-wrap;}
.empty-bucket{color:var(--text-faint);font-size:.87rem;margin-bottom:1rem;}
footer{border-top:1px solid var(--border);padding-top:1.1rem;margin-top:2.4rem;color:var(--text-faint);font-size:.78rem;}
"""


def _esc(text) -> str:
    return _html.escape(str(text if text is not None else ""))


def _render_finding_card(f: dict, index: int, attack_code: str, redact: bool) -> str:
    sev = f.get("severity", "").upper()
    owasp = f.get("owasp_override") or _OWASP_MAPPING.get(f.get("attack_type", ""), _OWASP_DEFAULT)
    leak_type = f.get("leak_type", "unknown")
    status = (
        f"CONFIRMED DATA LEAK ({leak_type})" if f.get("confirmed")
        else f"Not confirmed as a data leak ({leak_type} — structure/uncertain, not verified record content)"
    )
    leaked_content = f.get("leaked_content", "")
    full_response = f.get("full_response", "")
    leaked_display = _redact(leaked_content, "leaked content") if redact else leaked_content
    full_response_display = (
        _redact(full_response, "full response") if redact
        else _truncate(full_response, _FULL_RESPONSE_TRUNCATE_CHARS)
    )
    return f"""
    <div class="finding">
      <div class="finding-head">
        <span class="id">Finding {_esc(attack_code)}-{index:03d}</span>
        <span class="sev">{_esc(sev)}</span>
      </div>
      <div class="finding-body">
        <dl>
          <dt>Status</dt><dd>{_esc(status)}</dd>
          <dt>Probe</dt><dd>{_esc(f.get('probe_used', ''))}</dd>
          <dt>What leaked</dt><dd>{_esc(leaked_display)}</dd>
          <dt>Why flagged</dt><dd>{_esc(f.get('reasoning', ''))}</dd>
          <dt>Confidence</dt><dd>{f.get('confidence', 0):.2f}</dd>
          <dt>OWASP LLM</dt><dd>{_esc(owasp)}</dd>
          <dt>Remediation</dt><dd>{_esc(f.get('recommendation', ''))}</dd>
          <dt>Full response (truncated)</dt><dd>{_esc(full_response_display)}</dd>
        </dl>
      </div>
    </div>"""


def _render_bucket_section(title: str, findings: list[dict], attack_code: str,
                            finding_ids: dict, redact: bool) -> str:
    if not findings:
        return f'<h3>{_esc(title)}</h3><p class="empty-bucket">No {title.lower()}-severity findings in this run.</p>'
    cards = "".join(
        _render_finding_card(f, finding_ids[id(f)], attack_code, redact) for f in findings
    )
    return f"<h3>{_esc(title)} ({len(findings)})</h3>{cards}"


def generate_html_report(report: dict, output_path: str | Path, redact: bool = False) -> str:
    """
    Render ``report`` (same schema as ``generate_markdown_report``) as a
    self-contained HTML assessment report and write it to ``output_path``.
    Returns the rendered HTML string.

    Mirrors ``generate_markdown_report`` section-for-section (same Overall
    Risk verdict, Risk Summary, Key Metrics, severity-bucketed findings,
    Non-Findings Summary, Methodology, Refused Queries) -- the two are
    generated from the exact same normalized data, so they never disagree
    with each other. ``redact`` behaves identically: leaked content and
    full responses are replaced with a size/category placeholder instead
    of the literal text.
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
        queries_str = f"{data['queries_sent']} sent (of {data['queries']} budgeted — stopped early)"

    if data.get("authorized_by") or data.get("engagement_id"):
        parts = []
        if data.get("authorized_by"):
            parts.append(f"Authorized by {data['authorized_by']}")
        if data.get("engagement_id"):
            parts.append(f"Engagement {data['engagement_id']}")
        auth_str = " · ".join(parts)
    else:
        auth_str = "Not recorded for this run — confirm this test was authorized before relying on this report."

    metrics = data["metrics"]
    metrics_rows = ""
    if metrics is not None:
        if "asr" in metrics:
            metrics_rows += f"<tr><td>ASR</td><td>{metrics['asr'] * 100:.0f}%</td></tr>"
        if "ee" in metrics:
            metrics_rows += f"<tr><td>EE</td><td>{metrics['ee']:.2f}</td></tr>"
        if "crr_mean" in metrics:
            metrics_rows += f"<tr><td>CRR</td><td>{metrics['crr_mean']:.2f}</td></tr>"
        if "ss_mean" in metrics:
            metrics_rows += f"<tr><td>SS</td><td>{metrics['ss_mean']:.2f}</td></tr>"
        if "avg_cosine" in metrics:
            metrics_rows += f"<tr><td>Avg Cosine</td><td>{metrics['avg_cosine']:.2f}</td></tr>"
    else:
        asr = (len(reportable) / data["queries_sent"]) if data["queries_sent"] else 0.0
        metrics_rows += f"<tr><td>ASR</td><td>{asr * 100:.0f}%</td></tr>"
    metrics_rows += f"<tr><td>Classifier</td><td>LLM-as-judge ({_esc(data['llm_provider'])})</td></tr>"

    risk_summary_rows = "".join(
        f"<tr><td>{sev.capitalize()}</td><td>{severity_counts[sev]}</td></tr>"
        for sev in severity_order if severity_counts[sev] > 0
    ) or "<tr><td>(none)</td><td>0</td></tr>"

    target_config_html = ""
    persona = data.get("persona")
    toggle_state = data.get("target_toggle_state")
    if persona or toggle_state:
        rows = ""
        if isinstance(toggle_state, dict) and toggle_state:
            rows = "".join(
                f"<tr><td>{_esc(_toggle_label(k))}</td><td>{'On' if v else 'Off'}</td></tr>"
                for k, v in toggle_state.items()
            )
        toggle_html = f'<div class="tablewrap"><table>{rows}</table></div>' if rows else (
            f"<p>Target toggle state: {_esc(toggle_state)}</p>" if isinstance(toggle_state, str) else ""
        )
        target_config_html = f"""
    <h2>Target Configuration</h2>
    {f'<p>Authenticated as {_esc(persona)}</p>' if persona else ''}
    {toggle_html}"""

    buckets = _bucket(reportable)
    findings_html = "".join(
        _render_bucket_section(title, buckets[key], attack_code, finding_ids, redact)
        for key, title in [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
    )

    tiers = {f.get("tier_used", "black_box") for f in findings} or {"black_box"}
    if tiers == {"black_box"}:
        methodology_attack = (
            "Attack type: Data Reconstruction (DRA), Tier 1 black-box. "
            "No access to retriever, embedding model, or system prompt required."
        )
    else:
        methodology_attack = (
            "Attack type: Data Reconstruction (DRA), Tier 2 (OTel-confirmed) "
            "for findings cross-referenced against retrieval spans; "
            "unconfirmed findings remain Tier 1 black-box."
        )

    refused_queries = data["refused_queries"]
    if not refused_queries:
        refused_html = (
            "<p>No refused-query data recorded for this run "
            "(either zero refusals occurred, or this run predates refusal tracking).</p>"
        )
    else:
        items = "".join(
            f"<li><strong>Probe:</strong> {_esc(r.get('probe', ''))}<br>"
            f"<strong>Response:</strong> {_esc(_truncate(r.get('response', ''), _FULL_RESPONSE_TRUNCATE_CHARS))}</li>"
            for r in refused_queries
        )
        refused_html = (
            f"<p>{len(refused_queries)} of {data['queries_sent']} queries sent were refused by the "
            "target and excluded from the findings above (recorded here for completeness — refusal "
            "detection is a heuristic, see aginiti/attacks/dra/README.md):</p><ol>" + items + "</ol>"
        )

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aginiti Assessment Report — {_esc(attack_display)}</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
  <p class="eyebrow">Aginiti Assessment Report</p>
  <h1>{_esc(attack_display)}</h1>
  {f'<div class="redacted-banner">REDACTED VERSION — leaked content and full responses are masked below. See the full-detail report for literal evidence.</div>' if redact else ''}

  <div class="meta">
    <div><dt>Target</dt><dd>{_esc(data['target'])}</dd></div>
    <div><dt>Date</dt><dd>{_esc(date_str)}</dd></div>
    <div><dt>Queries</dt><dd>{_esc(queries_str)}</dd></div>
    <div><dt>Runtime</dt><dd>{_esc(_format_runtime(data['runtime_seconds']))}</dd></div>
    <div><dt>Authorization</dt><dd>{_esc(auth_str)}</dd></div>
  </div>

  <div class="risk-banner">
    <p class="eyebrow">Overall Risk</p>
    <p class="value">{_esc(_overall_risk_verdict(reportable))}</p>
  </div>

  <div class="note">
    <p>Coverage note: this assessment sampled {data['queries_sent']} quer{'y' if data['queries_sent'] == 1 else 'ies'}
    against the target — it is not exhaustive. Absence of a finding for a given query means no leak was found
    within this query budget, not that the system is safe on that topic.</p>
  </div>
  {target_config_html}

  <h2>Risk Summary</h2>
  <div class="tablewrap"><table><tr><th>Severity</th><th>Count</th></tr>{risk_summary_rows}</table></div>

  <h2>Key Metrics</h2>
  <div class="tablewrap"><table><tr><th>Metric</th><th>Value</th></tr>{metrics_rows}</table></div>

  <h2>Findings</h2>
  {findings_html}

  <h2>Non-Findings Summary</h2>
  <p>{non_findings_count} of {len(findings)} responses contained no evidence of protected data leakage.</p>

  <h2>Methodology</h2>
  <p>{_esc(methodology_attack)}</p>
  <p>Embedding model: <code>{_esc(data['embed_model'])}</code> (local ONNX, no API cost).</p>
  <p>Leak classification: every non-refused response is separately reviewed by an LLM-as-judge
    ({_esc(data['llm_provider'])}) that determines leak_type, severity, and the specific evidence quote.</p>

  <h2>Refused Queries</h2>
  {refused_html}

  <footer>Authorized use only — this report documents a security test of the target named above.</footer>
</main>
</body>
</html>
"""

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_doc, encoding="utf-8")
    return html_doc
