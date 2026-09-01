# aginiti/reporting — assessment reports and benchmark metrics

Report-generation code, consolidated here from `aginiti/core/` (a
directory-reorg move — `core/report.py` and `core/pdf_export.py` remain
as backward-compatible re-export shims at their old paths).

| Module | What it does |
|---|---|
| `markdown_report.py` | `generate_markdown_report()` — turns a benchmark results JSON into a CISO-facing Markdown report, the Tier 1 deliverable. |
| `pdf_export.py` | `html_to_pdf()` — renders a self-contained HTML report to PDF via a headless Chrome/Edge, no extra Python dependencies. |
| `report.py` | `load_run()` — loads a benchmark run's on-disk JSON logs and computes the summary directly from what's actually there (always recomputed, so a report can be generated from a partial/interrupted run). |
| `mia_metrics.py` | Population-level MIA benchmark metrics — AUC-ROC, TPR@fixed-FPR, Accuracy@fixed-FPR — matching the Interrogation Attack paper's own methodology (Naseh et al., ACM CCS 2025, arXiv:2502.00306). |
| `interrogation_reparse.py` | Offline re-parsing of already-captured MIA benchmark responses against the current yes/no/unknown classifier, without re-running any live queries. |
