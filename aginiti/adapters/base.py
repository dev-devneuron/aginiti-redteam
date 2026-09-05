"""BaseAdapter: the interface every target -- mock or real -- must implement
for Aginiti's ObservationAdapter and campaign loop to drive it.

This is the architectural boundary that makes Aginiti framework-agnostic
(or is meant to): the planner, the SSG, and the operator/graph_edge model
never touch a target directly. They only ever call `adapter.send(...)` and
`adapter.ground_truth_mission_achieved()`. A new framework or a new real
target needs a new adapter -- a class implementing this shape -- plus an
operator library written against ITS actual vulnerabilities. Nothing about
the planner changes.

`benchmarks/agents/demo_agent.py`'s `DemoAgent` already implements this shape
by duck typing (it predates this file); it's the reference MockAdapter --
kept as a fast, free, deterministic regression fixture, not the thing
benchmark results get reported from going forward.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class SendResult:
    final_text: str
    tool_trace: list[dict] = field(default_factory=list)
    # The minimum clean provenance abstraction this architecture was
    # missing -- found via a REAL false positive (DVLA's
    # tool_inventory_full_disclosure): DVLAAdapter's own API-error-recovery
    # text got fed to a DIFFERENT operator's judge (system_prompt_extraction)
    # in the same campaign and was misread as a genuine system-prompt leak.
    # `final_text` alone can't tell ObservationAdapter whether a string is
    # the TARGET's own visible output or something Aginiti's own adapter
    # code synthesized on the target's behalf (an API-error recovery
    # message, a "[max tool-call rounds reached]" budget cutoff, etc.) --
    # both looked identical to every downstream consumer (the judge, the
    # extractor, a human reading logs). is_synthetic=True is a hard
    # instruction to ObservationAdapter: never let this text confirm or
    # refute ANY claim, no matter how compelling it reads. Every adapter
    # that ever constructs `final_text` itself (rather than relaying the
    # target's own response verbatim) must set this -- see DVLAAdapter's
    # APIStatusError handler, demo_agent.py's and injecagent_adapter.py's
    # "[max tool-call rounds reached]" fallback for the three sites this
    # was retrofitted onto. Defaults to False (genuine target output) so
    # every adapter that never synthesizes anything -- DVAAAdapter,
    # McpStdioAdapter, both confirmed by audit to always either relay a
    # real response or raise, never fabricate one -- needs no changes.
    is_synthetic: bool = False


class BaseAdapter(Protocol):
    def send(self, channel: str, prompt: str) -> SendResult:
        """Deliver one operator's action to the target; return what the
        target visibly said back. `channel="direct"` must always be
        supported -- a plain conversational turn. Other channel values are
        adapter-specific indirect surfaces THIS target actually exposes
        (e.g. "slack", "github_issue" for the mock; a real target may
        expose none, in which case its operator library only ever uses
        "direct" and gets its sophistication from the crafted prompt
        content itself -- see the DVLA adapter's ReAct-loop-hijack
        operators for an example of that). An operator library is written
        against one specific adapter's channel set, not a universal one.
        """
        ...

    def ground_truth_mission_achieved(self) -> bool:
        """Independent-of-SSG check: did the underlying system actually
        reach a compromised state, checked by inspecting the target's own
        real state (a DB row, a tool call log, a file) -- never by asking
        the SSG what it believes. This is what the benchmark harness uses
        to catch a hallucinated SUCCESS (Section 19's "planner
        hallucination" failure mode) independently of the judge's verdict.
        """
        ...

    # record_suspicious_event() is deliberately NOT part of this Protocol:
    # it's an optional extension, not every real target's adapter
    # implements a suspicion-escalation mechanic (DVLA's doesn't; the
    # mock's does). ObservationAdapter calls it via getattr(..., None) and
    # no-ops when absent -- implement it if your adapter has an analogous
    # "the target gets more cautious after repeated flagged attempts"
    # dynamic to model.

    # independent_evidence_check(raw_text: str) -> list[IndependentFinding]
    # is ALSO deliberately NOT part of this Protocol, same optional-
    # extension discipline (aginiti/core/graph/independent_evidence.py
    # -- see that module's own docstring for the full motivation and the
    # Fact/Observation/Claim/Evidence pipeline it feeds). Implement it only
    # if your adapter has an independent, non-LLM oracle (a fuzzy/verbatim
    # content-disclosure index, a structured-data check, ...) capable of
    # catching real evidence a specific operator's own narrow extractor
    # might miss from the SAME response text. ObservationAdapter calls it
    # via getattr(..., None) on every non-synthetic response and no-ops
    # when absent -- every existing adapter is completely unaffected.
