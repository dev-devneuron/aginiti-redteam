"""Adaptive prompt refinement. See aginiti/adaptive/refinement.py's module
docstring for the design rationale (PAIR/TAP-inspired feedback loop)."""
from __future__ import annotations

from aginiti.adaptive.refinement import (
    AdaptiveRefinementResult,
    RefinementAttempt,
    run_adaptive_refinement,
)

__all__ = ["AdaptiveRefinementResult", "RefinementAttempt", "run_adaptive_refinement"]
