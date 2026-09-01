"""Verifies aginiti/operators/library.py's backward-compatible re-export of
the Operator schema (Operator, ClaimEffect, Precondition, ClassPrecondition)
from aginiti/operators/base.py -- the split extracted the schema out of
library.py (which now holds only OperatorLibrary), and library.py's
re-export is what keeps every existing operator-definition file's
`from aginiti.operators.library import Operator, ClaimEffect, ...` working
unchanged. Asserts real re-export (same objects), not copies."""
import aginiti.operators.base as base
import aginiti.operators.library as library


def test_library_reexports_same_objects_as_base():
    assert library.Operator is base.Operator
    assert library.ClaimEffect is base.ClaimEffect
    assert library.Precondition is base.Precondition
    assert library.ClassPrecondition is base.ClassPrecondition


def test_operator_still_constructible_via_either_import_path():
    from aginiti.core.graph.schema import ClaimStatus, RiskTier

    op_via_base = base.Operator(
        id="x", description="d", prompt="p", channel="direct",
        preconditions=(), effects_success=(base.ClaimEffect("k", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    op_via_library = library.Operator(
        id="x", description="d", prompt="p", channel="direct",
        preconditions=(), effects_success=(library.ClaimEffect("k", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )
    assert type(op_via_base) is type(op_via_library)
