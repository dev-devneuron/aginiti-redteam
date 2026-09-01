"""OperatorLibrary — a queryable collection of Operators (design doc
Section 13, 15's Operator field reference).

The Operator schema itself (`Operator`, `ClaimEffect`, `Precondition`,
`ClassPrecondition`) moved to `aginiti/operators/base.py` as part of the
open-source-readiness directory reorg -- this module held both the schema
and the container undifferentiated before that split. Re-exported below
for backward compatibility: every existing `from aginiti.operators.library
import Operator, ClaimEffect, ...` across this codebase's ~140 operator-
definition files keeps working unchanged, since almost every one of those
files needs both the schema AND `OperatorLibrary` in the same import.
New code should import the schema from `aginiti.operators.base` directly
when it doesn't also need `OperatorLibrary` in the same line; see
`aginiti/operators/base.py`'s own docstring for a worked Operator example.
"""
from __future__ import annotations

from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.base import ClaimEffect, ClassPrecondition, Operator, Precondition

__all__ = ["ClaimEffect", "ClassPrecondition", "Operator", "Precondition", "OperatorLibrary"]


class OperatorLibrary:
    def __init__(self, operators: list[Operator]):
        self._by_id = {op.id: op for op in operators}

    def __iter__(self):
        return iter(self._by_id.values())

    def __len__(self):
        return len(self._by_id)

    def get(self, operator_id: str) -> Operator:
        return self._by_id[operator_id]

    def candidates(self, ssg: SecurityStateGraph) -> list[Operator]:
        return [op for op in self._by_id.values() if op.preconditions_met(ssg)]

    def by_category(self, *categories: str) -> "OperatorLibrary":
        """Filter to operators whose attack methodology matches one of the
        given `attack_category` values (see aginiti/core/graph/
        attack_category.py's `ALL_CATEGORIES`/`CATEGORY_TITLES` for the
        11 named groups: 8 real offensive techniques -- direct_prompt_
        attack, encoding_attack, rag_poisoning, indirect_injection,
        tool_discovery, tool_manipulation, markdown_network_exfiltration,
        multi_step_chain -- plus 3 planner-evaluation controls -- decoy,
        known_defended, low_value_reconnaissance). Returns a NEW
        OperatorLibrary; does not mutate self, matching `candidates()`'s
        own read-only style above.

        Deliberately reuses `attack_category.py`'s own canonical
        `operator_primary_family()` rather than re-deriving "which
        category does this operator belong to" here -- that function's own
        docstring exists specifically because this exact rule (first
        tagged effects_success entry, else first tagged effects_failure
        entry) had already been independently reinvented three times
        before it was consolidated; a fourth inline copy here would be
        exactly the drift that consolidation was meant to prevent.
        Imported locally, not at module level, for the same circular-
        import reason `operator_primary_family`'s own docstring states
        (attack_category.py -> this module has no reverse edge).

        An operator with no tagged attack_category at all (still common on
        the older, pre-2026-08-12 DemoAgent mock library -- see this
        project's own scripts/run_campaign.py module docstring, 'Tier
        classification', for the same caveat stated about --tier)
        `operator_primary_family()` returns None for, and None can never
        equal a real category string, so such an operator is silently
        excluded from every category filter rather than raising -- the
        same "untagged means excluded, not an error" contract every other
        opt-in taxonomy field in this codebase already follows.

        Raises ValueError immediately (not a silent empty result) for a
        caller mistake -- no categories given, or a category name that
        does not exist -- so a typo is caught at the call site instead of
        surfacing later as "the library filtered down to nothing and I
        don't know why"."""
        from aginiti.core.graph.attack_category import ALL_CATEGORIES, operator_primary_family

        if not categories:
            raise ValueError(
                "by_category() needs at least one category -- see "
                "aginiti.core.graph.attack_category.ALL_CATEGORIES for the full list."
            )
        unknown = [c for c in categories if c not in ALL_CATEGORIES]
        if unknown:
            raise ValueError(
                f"Unknown attack_category value(s): {unknown!r}. Valid categories are: "
                f"{sorted(ALL_CATEGORIES)}."
            )
        wanted = set(categories)
        return OperatorLibrary([
            op for op in self._by_id.values() if operator_primary_family(op) in wanted
        ])
