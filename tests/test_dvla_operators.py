from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.dvla_definitions import build_dvla_library
from aginiti.scenarios import dvla_mission


def test_dvla_library_has_three_operators():
    assert len(build_dvla_library()) == 3


def test_only_recon_available_at_start():
    ssg = SecurityStateGraph()
    lib = build_dvla_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert candidates == {"recon_capabilities"}


def test_attacks_unlock_after_recon_hypothesis():
    # library.candidates() checks preconditions only, not execution history
    # (that's the policy layer's job via eligible_operators) -- recon has
    # no precondition, so it stays a candidate even after its hypothesis
    # is established.
    ssg = SecurityStateGraph()
    ssg.assert_claim("dvla_capability_known", "true", ClaimStatus.HYPOTHESIZED)
    lib = build_dvla_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert candidates == {"recon_capabilities", "direct_override_request", "sql_injection_argument"}


def test_dvla_mission_any_of_two_flags():
    m = dvla_mission()
    assert m.success_mode == "any"
    assert set(m.success_criteria) == {"unauthorized_transaction_disclosed", "secret_data_exfiltrated"}
    assert m.budget < 9  # tight relative to the 3-operator library, per the discipline established earlier
