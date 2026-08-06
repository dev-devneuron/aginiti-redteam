"""BaseAdapter: the interface every target -- mock or real -- must implement
for Aginiti's ObservationAdapter and campaign loop to drive it.

This is the architectural boundary that makes Aginiti framework-agnostic
(or is meant to): the planner, the SSG, and the operator/graph_edge model
never touch a target directly. They only ever call `adapter.send(...)` and
`adapter.ground_truth_mission_achieved()`. A new framework or a new real
target needs a new adapter -- a class implementing this shape -- plus an
operator library written against ITS actual vulnerabilities. Nothing about
the planner changes.

`aginiti/target/demo_agent.py`'s `DemoAgent` already implements this shape
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
