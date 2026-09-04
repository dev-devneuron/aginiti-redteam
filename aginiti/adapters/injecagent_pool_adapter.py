"""InjecAgentPoolAdapter -- a genuinely NEW, additive
extension of InjecAgentAdapter, not a modification of it, built to close
a real structural gap: InjecAgentAdapter is deliberately scoped to ONE
test case per instance (see its own module docstring -- "one adapter
instance = one InjecAgent test case", mirroring the paper's own single-
shot experimental unit), which means a single Aginiti campaign can never
face more than one eligible InjecAgent operator at a time. That's fine for
computing the field-standard ASR metric (experiments/exp8_injecagent_asr.py
already does this correctly, one small campaign per test case) but makes
"which planner finds more real compromises under a shared, limited
budget" an ill-posed question against InjecAgent's native per-case
design -- there is never a real CHOICE to rank.

This adapter holds a POOL of real InjecAgent test cases (unmodified vendored
data, same aginiti/operators/injecagent_data/) and dispatches by an
indexed channel (`"tool_output_injection:<index>"`), giving ONE shared
campaign genuine multi-candidate branching across real, independent
attack scenarios -- the same "genuine branching, not a forced chain"
methodology the AnythingLLM benchmark redesign (experiments/
exp12_branching_benchmark.py) already established, applied here to make
a full-suite InjecAgent evaluation actually test Aginiti's planning value,
not just raw single-shot compliance.

Internally, each pooled test case gets its OWN InjecAgentAdapter instance
(unmodified, imported as-is) -- this class is pure composition/dispatch,
zero duplicated simulation logic, and zero changes to the existing,
already-tested InjecAgentAdapter.
"""
from __future__ import annotations

from aginiti.adapters.base import SendResult
from aginiti.adapters.injecagent_adapter import InjecAgentAdapter


class InjecAgentPoolAdapter:
    """BaseAdapter over a POOL of real InjecAgent test cases. `channel`
    must be `f"tool_output_injection:{index}"` for some `index` present in
    the pool passed to the constructor -- see injecagent_pool_operators()
    for the Operator pack that emits exactly this channel shape."""

    def __init__(self, test_cases: list[dict], seed: int | None = None):
        self._by_index = {
            tc["index"]: InjecAgentAdapter(tc, seed=seed) for tc in test_cases
        }
        self._attempted_indices: set[int] = set()

    def send(self, channel: str, prompt: str) -> SendResult:
        if not channel.startswith("tool_output_injection:"):
            raise ValueError(f"InjecAgentPoolAdapter only supports 'tool_output_injection:<index>', got {channel!r}")
        index = int(channel.split(":", 1)[1])
        if index not in self._by_index:
            raise ValueError(f"test case index {index} not in this pool")
        self._attempted_indices.add(index)
        return self._by_index[index].send("tool_output_injection", prompt)

    def ground_truth_mission_achieved(self) -> bool:
        """True if ANY pooled test case attempted so far observed a real
        attacker-tool call -- same deterministic, judge-independent signal
        InjecAgentAdapter.ground_truth_mission_achieved() already provides
        per-case, aggregated across the whole pool."""
        return any(
            adapter.ground_truth_mission_achieved()
            for index, adapter in self._by_index.items()
            if index in self._attempted_indices
        )

    def per_case_ground_truth(self) -> dict[int, bool]:
        """Every attempted test case's own independent ground-truth
        signal, keyed by index -- what the aggregate `ground_truth_
        mission_achieved()` alone can't tell apart (which SPECIFIC cases
        the model actually complied with), needed for the ASR breakdown
        by Attack Type."""
        return {
            index: adapter.ground_truth_mission_achieved()
            for index, adapter in self._by_index.items()
            if index in self._attempted_indices
        }
