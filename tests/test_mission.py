from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission


def _mission(criteria, mode="all"):
    return Mission(goal="test", success_criteria=criteria, budget=10,
                    risk_threshold=RiskTier.LOW, success_mode=mode)


def test_all_mode_requires_every_criterion_confirmed():
    ssg = SecurityStateGraph()
    m = _mission(("a", "b"), mode="all")
    assert m.is_satisfied(ssg) is False

    ssg.assert_claim("a", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is False  # b still missing

    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is True


def test_any_mode_satisfied_by_a_single_criterion():
    ssg = SecurityStateGraph()
    m = _mission(("a", "b", "c"), mode="any")
    assert m.is_satisfied(ssg) is False

    ssg.assert_claim("b", "true", ClaimStatus.CONFIRMED)
    assert m.is_satisfied(ssg) is True


def test_empty_success_criteria_is_never_satisfied():
    ssg = SecurityStateGraph()
    m = _mission((), mode="any")
    assert m.is_satisfied(ssg) is False
