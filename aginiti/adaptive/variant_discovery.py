"""A generic, reusable "try candidates adaptively until one works" engine,
built at explicit user direction: rather than building a
bespoke adaptive-search mechanism separately for each attack category
(encoding, RAG-poisoning framing, tool-manipulation phrasing, ...), this
module factors out the one thing every such search actually needs --
execute a candidate Operator, record what happened, stop the moment one
succeeds, and hand the CALLER's own domain logic the full trial history so
IT can decide what to try next -- and lets each domain plug in its own
candidate-generation strategy.

See aginiti/adaptive/encoding_discovery.py for the flagship application
(adaptive encoding-chain discovery, replacing a static enumerated payload
list with a search that SYNTHESIZES new stacked transforms based on what's
already been tried). aginiti/adaptive/refinement.py (PAIR-style single-
target prompt rewriting) solves an adjacent but different problem -- that
module rewrites the SAME operator's wording using the target's own
response as feedback; this module searches across a FAMILY of distinct
candidate operators (different encodings, different framings) and does not
require an LLM call at all if the candidate-generation strategy doesn't
need one (encoding_discovery.py's does not -- it's pure combinatorics).

Design mirrors run_adaptive_refinement() exactly: reuses ObservationAdapter/
SecurityStateGraph unchanged, so every trial (successful or not) produces a
normal Observation and a normal claim, and the full trace is always kept,
never just the final outcome."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from aginiti.core.observation_adapter import ExecutionResult, ObservationAdapter
from aginiti.adapters.base import BaseAdapter
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.observability import get_logger
from aginiti.operators.library import Operator

_logger = get_logger("variant_discovery")


@dataclass
class VariantTrial:
    trial_number: int
    operator_id: str
    variant_name: str
    raw_signal: str
    success: bool


@dataclass
class VariantDiscoveryResult:
    trials: list[VariantTrial] = field(default_factory=list)
    succeeded: bool = False
    winning_operator: Operator | None = None
    final_result: ExecutionResult | None = None

    @property
    def trials_used(self) -> int:
        return len(self.trials)


def run_variant_discovery(
    next_candidate_fn: Callable[[list[VariantTrial]], tuple[Operator, str] | None],
    ssg: SecurityStateGraph,
    target_adapter: BaseAdapter,
    max_trials: int = 10,
    seed: int | None = None,
    adapter: ObservationAdapter | None = None,
) -> VariantDiscoveryResult:
    """Calls `next_candidate_fn(trial_history)` for up to `max_trials`
    rounds. It must return `(operator, variant_name)` for the next
    candidate to try, or `None` when it has genuinely run out of ideas
    (search space exhausted) -- receiving the FULL history each call is
    what lets a domain-specific strategy react to what's already failed
    (e.g. "every single-transform attempt so far got blocked -- try a
    stacked combination next") rather than blindly replaying a fixed list.
    Stops the instant any trial succeeds."""
    adapter = adapter or ObservationAdapter()
    result = VariantDiscoveryResult()
    for trial_number in range(1, max_trials + 1):
        candidate = next_candidate_fn(result.trials)
        if candidate is None:
            _logger.info("variant discovery: candidate strategy exhausted after %d trials",
                         len(result.trials))
            break
        operator, variant_name = candidate
        exec_result = adapter.execute(operator, ssg, target_adapter, seed=seed)
        result.trials.append(VariantTrial(
            trial_number=trial_number,
            operator_id=operator.id,
            variant_name=variant_name,
            raw_signal=exec_result.raw_signal,
            success=exec_result.overall_success,
        ))
        result.final_result = exec_result
        if exec_result.overall_success:
            result.succeeded = True
            result.winning_operator = operator
            _logger.info("variant discovery succeeded: variant=%s trial=%d/%d",
                         variant_name, trial_number, max_trials)
            return result
    if not result.succeeded:
        _logger.info("variant discovery exhausted budget without success: trials=%d",
                     len(result.trials))
    return result
