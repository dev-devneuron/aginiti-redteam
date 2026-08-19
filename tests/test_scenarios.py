from aginiti.scenarios import multi_path_mission


def test_multi_path_mission_uses_any_success_mode_with_four_criteria():
    m = multi_path_mission()
    assert m.success_mode == "any"
    assert set(m.success_criteria) == {
        "payroll_write_unauthorized", "github_secret_exfiltrated",
        "unauthorized_workflow_triggered", "credential_reset_unauthorized",
    }
    assert m.budget < 21  # tighter than the full operator library's worst-case cost
