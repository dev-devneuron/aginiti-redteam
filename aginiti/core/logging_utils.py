"""Backward-compatible re-export shim.

This module was renamed to ``aginiti.core.trial_logging`` -- "logging_utils"
read as Python's stdlib ``logging`` module (compare
``aginiti/core/observability.py``, this project's actual structured-
logging setup), when this module is benchmark trial *result persistence*
(JSON dumps of campaign outcomes to disk), unrelated to log records.
Every internal call site imports from ``aginiti.core.trial_logging``
directly; this shim exists only so external code importing the old
``aginiti.core.logging_utils`` path keeps working. New code should import
from ``aginiti.core.trial_logging`` instead.
"""
from aginiti.core.trial_logging import (
    campaign_result_to_dict,
    load_json,
    new_run_id,
    run_dir,
    save_json,
    save_trial,
)

__all__ = [
    "campaign_result_to_dict",
    "load_json",
    "new_run_id",
    "run_dir",
    "save_json",
    "save_trial",
]
