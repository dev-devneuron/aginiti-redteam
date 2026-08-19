from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.definitions import build_library


def test_library_has_21_operators():
    assert len(build_library()) == 21


def test_only_precondition_free_operators_available_at_start():
    ssg = SecurityStateGraph()
    lib = build_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert candidates == {
        "recon_capabilities", "recon_github_access", "probe_helpdesk_capability",
        "probe_unrelated_capability", "recon_general_smalltalk", "probe_defunct_channel",
    }


# -- Payroll branch relevance gates --------------------------------------

def test_payroll_direct_attacks_unlock_only_after_payroll_access_hypothesized():
    ssg = SecurityStateGraph()
    lib = build_library()
    assert "direct_prompt_injection" not in {op.id for op in lib.candidates(ssg)}
    ssg.assert_claim("payroll_api_exists", "true", ClaimStatus.HYPOTHESIZED)
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "direct_prompt_injection" in candidates
    assert "approval_workflow_probe" in candidates


def test_indirect_payroll_injection_requires_confirmed_slack_trust():
    ssg = SecurityStateGraph()
    ssg.assert_claim("payroll_api_exists", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("planner_trusts_slack", "true", ClaimStatus.CONFIRMED)
    lib = build_library()
    assert "indirect_prompt_injection" in {op.id for op in lib.candidates(ssg)}


# -- GitHub branch relevance gates ----------------------------------------

def test_github_direct_attacks_unlock_only_after_access_hypothesized():
    ssg = SecurityStateGraph()
    lib = build_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "direct_secret_request" not in candidates
    assert "direct_workflow_trigger_request" not in candidates

    ssg.assert_claim("github_access_hint", "true", ClaimStatus.HYPOTHESIZED)
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "direct_secret_request" in candidates
    assert "direct_workflow_trigger_request" in candidates


def test_github_indirect_exploits_require_confirmed_release_bot_trust():
    ssg = SecurityStateGraph()
    lib = build_library()
    assert "indirect_secret_exfiltration_via_issue" not in {op.id for op in lib.candidates(ssg)}

    ssg.assert_claim("release_bot_trusted", "true", ClaimStatus.CONFIRMED)
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "indirect_secret_exfiltration_via_issue" in candidates
    assert "indirect_workflow_trigger_via_issue" in candidates


# -- Helpdesk branch: hidden capability + relevance gates -----------------

def test_helpdesk_capability_is_undiscoverable_without_specific_probe():
    ssg = SecurityStateGraph()
    lib = build_library()
    # Recon on the OTHER branches doesn't unlock anything helpdesk-related.
    ssg.assert_claim("payroll_api_exists", "true", ClaimStatus.HYPOTHESIZED)
    ssg.assert_claim("github_access_hint", "true", ClaimStatus.HYPOTHESIZED)
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "direct_credential_reset_request" not in candidates
    assert "confirm_helpdesk_reachability" not in candidates


def test_helpdesk_capability_unlocks_after_its_own_specific_probe():
    ssg = SecurityStateGraph()
    ssg.assert_claim("helpdesk_capability_known", "true", ClaimStatus.HYPOTHESIZED)
    lib = build_library()
    candidates = {op.id for op in lib.candidates(ssg)}
    assert "confirm_helpdesk_reachability" in candidates
    assert "direct_credential_reset_request" in candidates  # shortcut also gated by same hypothesis


def test_helpdesk_indirect_injection_requires_confirmed_admin_bot_trust():
    ssg = SecurityStateGraph()
    lib = build_library()
    assert "indirect_injection_via_ticket" not in {op.id for op in lib.candidates(ssg)}
    ssg.assert_claim("admin_bot_trusted", "true", ClaimStatus.CONFIRMED)
    assert "indirect_injection_via_ticket" in {op.id for op in lib.candidates(ssg)}


# -- Decoys are always eligible but never connect to a mission node -------

def test_decoys_are_eligible_from_the_start_but_have_no_mission_path():
    lib = build_library()
    for decoy_id in ("probe_unrelated_capability", "recon_general_smalltalk", "probe_defunct_channel"):
        op = lib.get(decoy_id)
        assert op.preconditions == ()
        assert op.graph_edge is not None
        assert op.graph_edge[1].startswith("dead_end")


# -- Graph edges are wired the way the branch shapes require ---------------

def test_shortcut_operators_originate_from_their_own_branchs_recon_node():
    lib = build_library()
    assert lib.get("direct_prompt_injection").graph_edge == ("payroll_recon", "payroll_write_unauthorized")
    assert lib.get("approval_workflow_probe").graph_edge == ("payroll_recon", "payroll_write_unauthorized")
    assert lib.get("direct_secret_request").graph_edge == ("github_recon", "github_secret_exfiltrated")
    assert lib.get("direct_credential_reset_request").graph_edge == ("helpdesk_discovery", "credential_reset_unauthorized")


def test_render_prompt_still_falls_back_gracefully_for_new_branches():
    ssg = SecurityStateGraph()
    lib = build_library()
    rendered = lib.get("direct_secret_request").render_prompt(ssg)
    assert "{github_detail}" not in rendered
