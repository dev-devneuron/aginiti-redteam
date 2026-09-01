"""Backward-compatible re-export shim.

This module moved to ``aginiti.reporting.pdf_export`` -- report-generation
code belongs in ``aginiti/reporting/``, not ``core/``. Every internal call
site imports from ``aginiti.reporting.pdf_export`` directly; this shim
exists only so external code importing the old ``aginiti.core.pdf_export``
path keeps working. New code should import from
``aginiti.reporting.pdf_export`` instead.
"""
from aginiti.reporting.pdf_export import html_to_pdf, _find_browser

__all__ = ["html_to_pdf"]
