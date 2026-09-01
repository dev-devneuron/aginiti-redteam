"""Renders a self-contained HTML report to PDF via a headless Chromium-based
browser's native print-to-pdf (Chrome or Edge, whichever is found) -- no
extra Python dependencies, since every Windows box either has one already.

Moved here from aginiti/core/pdf_export.py -- report-generation code
belongs in aginiti/reporting/, not core/. aginiti/core/pdf_export.py
remains a backward-compatible re-export shim.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

_CANDIDATE_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]


def _find_browser() -> str:
    for name in ("chrome", "google-chrome", "msedge", "chromium"):
        found = shutil.which(name)
        if found:
            return found
    for path in _CANDIDATE_PATHS:
        if os.path.exists(path):
            return path
    raise RuntimeError(
        "No Chrome/Edge/Chromium found for PDF export. Install one, or set "
        "AGINITI_BROWSER_PATH to its executable."
    )


def html_to_pdf(html_path: str, pdf_path: str | None = None) -> str:
    browser = os.environ.get("AGINITI_BROWSER_PATH") or _find_browser()
    html_abs = str(pathlib.Path(html_path).resolve())
    pdf_abs = str(pathlib.Path(pdf_path or html_path.replace(".html", ".pdf")).resolve())
    url = pathlib.Path(html_abs).as_uri()

    result = subprocess.run(
        [browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
         f"--print-to-pdf={pdf_abs}", url],
        capture_output=True, text=True, timeout=60,
    )
    if not os.path.exists(pdf_abs):
        raise RuntimeError(f"PDF export failed: {result.stderr or result.stdout}")
    return pdf_abs
