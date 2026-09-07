"""Shared result protocol and trial-recording helper for aginiti/adaptive/.

The eight search engines in this package (`variant_discovery`,
`encoding_discovery`, `many_shot`, `refinement`, `crescendo`,
`deceptive_delight`, `framing_discovery`, `membership_inference`) resolve to
four distinct result dataclasses in active use -- `VariantDiscoveryResult`
(also reused directly by `encoding_discovery`/`many_shot`),
`AdaptiveRefinementResult`, `CrescendoResult`, `DeceptiveDelightResult`, and
`MembershipInferenceResult` -- each invented independently, with no common
shape to reason about them uniformly. `aginiti/core/assessment.py`
(`run_full_assessment`) already needs to treat these uniformly across its
phases, reading `.trials_used`/`.attempts_used`/`.turns_used` and
`.succeeded`/`.winning_operator` off four differently-named-but-equivalent
properties.

`AdaptiveEngineResult` below is modeled directly on the existing
`Policy(Protocol)` in `aginiti/core/policies/base.py` -- the established
pattern this codebase already uses for "several independently-implemented
classes share one behavioral shape without a common base class." Every
result class above conforms structurally (Python's `Protocol`, not
inheritance) by adding a handful of additive fields/properties; nothing
existing is renamed.

`score` is part of the Protocol even though only `MembershipInferenceResult`
has a real one today (a continuous membership-confidence score, no
early-stop concept) -- the four stop-on-success engines' `score` property
simply returns `None`, the same "honestly `None` when it doesn't apply to
this category" pattern already used for `Insight`
(`aginiti/core/graph/schema.py`) and for `MembershipInferenceResult.succeeded`
itself (the real membership verdict is a separate, threshold-calibrated
decision made downstream by `calibrate_threshold_from_held_out`, not
something the engine itself decides -- see that module's own docstring).

`finalize_on_success()` is the literal shared trial-recording helper Issue
#8 asked for. Before this helper existed, the four stop-on-success engines
(`variant_discovery`, `refinement`, `crescendo`, `deceptive_delight`) each
hand-rolled the identical 3-4 line success block -- and it had already
drifted: only `variant_discovery.py` recorded `winning_operator`, even
though the winning `Operator` is in scope at the identical point in all
four loops. Routing every stop-on-success loop through this one helper
makes that class of bug structurally impossible going forward.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from aginiti.core.observation_adapter import ExecutionResult
from aginiti.operators.library import Operator


@runtime_checkable
class AdaptiveEngineResult(Protocol):
    """Structural shape every adaptive-search result conforms to. Checked
    via `isinstance()` (enabled by `@runtime_checkable`), not inheritance --
    a class satisfies this Protocol simply by having these attributes/
    properties, matching how `Policy(Protocol)` is already independently
    satisfied by five unrelated classes elsewhere in this codebase."""

    succeeded: bool | None
    score: float | None
    winning_operator: Operator | None
    final_result: ExecutionResult | None

    @property
    def steps_used(self) -> int: ...


def finalize_on_success(result: AdaptiveEngineResult, operator: Operator,
                         exec_result: ExecutionResult) -> bool:
    """Records `exec_result` as `result.final_result` unconditionally; if
    `exec_result.overall_success`, additionally marks `result.succeeded =
    True` and `result.winning_operator = operator`. Returns
    `exec_result.overall_success`, so a stop-on-success loop can write
    `if finalize_on_success(result, operator, exec_result): <break/return>`
    in place of its own hand-rolled block."""
    result.final_result = exec_result
    if exec_result.overall_success:
        result.succeeded = True
        result.winning_operator = operator
        return True
    return False
