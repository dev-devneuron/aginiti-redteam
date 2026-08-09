"""Operator pack for InjecAgentPoolAdapter -- reuses
aginiti/operators/injecagent.py's `injecagent_operator()` completely
unmodified (same real test-case data, same effects/description/weight
shape) and only remaps `channel` to the pool adapter's indexed dispatch
shape (`"tool_output_injection:<index>"`), via `dataclasses.replace` on
the frozen Operator -- zero duplicated logic, zero changes to the
existing, already-tested single-case generator.
"""
from __future__ import annotations

from dataclasses import replace

from aginiti.operators.injecagent import injecagent_operator
from aginiti.operators.library import Operator


def injecagent_pool_operator(test_case: dict) -> Operator:
    op = injecagent_operator(test_case)
    return replace(op, channel=f"tool_output_injection:{test_case['index']}")
