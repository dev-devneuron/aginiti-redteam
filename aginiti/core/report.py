"""Backward-compatible re-export shim.

This module moved to ``aginiti.reporting.report`` -- report-generation
code belongs in ``aginiti/reporting/`` alongside ``markdown_report.py``,
``mia_metrics.py``, and ``interrogation_reparse.py``, not scattered into
``core/``. Every internal call site imports from
``aginiti.reporting.report`` directly; this shim exists only so external
code importing the old ``aginiti.core.report`` path keeps working. New
code should import from ``aginiti.reporting.report`` instead.
"""
from aginiti.reporting.report import (
    CONDITION_LABELS,
    CONDITION_ORDER,
    load_run,
    _summarize,
    _winning_path,
)

__all__ = ["CONDITION_LABELS", "CONDITION_ORDER", "load_run"]
