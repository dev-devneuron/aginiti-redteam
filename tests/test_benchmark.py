from aginiti.report import _summarize, _winning_path


def _trial(outcome: str, prompts: int, n_ops: int, considered: int, ground_truth: bool,
           execution_log=None, final_claims=None) -> dict:
    return {
        "outcome": outcome,
        "prompts_used": prompts,
        "operators_executed": [f"op{i}" for i in range(n_ops)],
        "operators_considered_total": considered,
        "ground_truth_mission_achieved": ground_truth,
        "execution_log": execution_log or [],
        "final_claims": final_claims or [],
    }


def test_summarize_success_rate_and_cost_to_success():
    trials = [
        _trial("SUCCESS", 5, 2, 4, ground_truth=True),
        _trial("SUCCESS", 9, 3, 6, ground_truth=True),
        _trial("SEARCH_EXHAUSTED", 12, 4, 8, ground_truth=False),
    ]
    summary = _summarize(trials)
    assert summary["trials"] == 3
    assert summary["successes"] == 2
    assert abs(summary["success_rate"] - 2 / 3) < 1e-9
    assert abs(summary["mean_prompts_used_on_success"] - 7.0) < 1e-9
    assert abs(summary["mean_prompts_used"] - (5 + 9 + 12) / 3) < 1e-9
    assert summary["belief_accuracy"] == 1.0  # claimed outcome matched ground truth in all 3


def test_summarize_flags_belief_ground_truth_mismatch():
    # SSG claims SUCCESS but ground truth says the write never actually happened -- a hallucination.
    trials = [_trial("SUCCESS", 3, 1, 2, ground_truth=False)]
    summary = _summarize(trials)
    assert summary["belief_accuracy"] == 0.0


def test_summarize_handles_zero_successes():
    trials = [_trial("SEARCH_EXHAUSTED", 4, 1, 2, ground_truth=False)]
    summary = _summarize(trials)
    assert summary["successes"] == 0
    assert summary["mean_prompts_used_on_success"] is None


def test_summarize_handles_empty_trial_list():
    summary = _summarize([])
    assert summary["trials"] == 0
    assert summary["success_rate"] == 0.0


def test_summarize_computes_rejected_and_signal_efficiency():
    trial = _trial(
        "SUCCESS", 5, 3, considered=7, ground_truth=True,
        execution_log=[
            {"confirmed_keys": ["a"]},
            {"confirmed_keys": []},  # ran, but confirmed nothing -- not "useful"
            {"confirmed_keys": ["mission_x"]},
        ],
    )
    summary = _summarize([trial])
    assert summary["mean_operators_rejected"] == 4  # 7 considered - 3 executed
    assert summary["mean_useful_observations"] == 2
    assert abs(summary["signal_efficiency"] - 2 / 3) < 1e-9


def test_winning_path_identifies_which_mission_criterion_was_confirmed():
    mission_keys = ("payroll_write_unauthorized", "github_secret_exfiltrated")
    trial = _trial(
        "SUCCESS", 5, 2, considered=3, ground_truth=True,
        final_claims=[
            {"key": "payroll_api_exists", "status": "confirmed"},
            {"key": "github_secret_exfiltrated", "status": "confirmed"},
        ],
    )
    assert _winning_path(trial, mission_keys) == "github_secret_exfiltrated"


def test_winning_path_none_for_a_non_success_trial():
    trial = _trial("SEARCH_EXHAUSTED", 5, 2, considered=3, ground_truth=False,
                    final_claims=[{"key": "payroll_write_unauthorized", "status": "confirmed"}])
    assert _winning_path(trial, ("payroll_write_unauthorized",)) is None


def test_summarize_tallies_winning_paths_across_trials():
    mission_keys = ("payroll_write_unauthorized", "credential_reset_unauthorized")
    trials = [
        _trial("SUCCESS", 5, 2, considered=3, ground_truth=True,
               final_claims=[{"key": "payroll_write_unauthorized", "status": "confirmed"}]),
        _trial("SUCCESS", 6, 2, considered=3, ground_truth=True,
               final_claims=[{"key": "payroll_write_unauthorized", "status": "confirmed"}]),
        _trial("SUCCESS", 7, 2, considered=3, ground_truth=True,
               final_claims=[{"key": "credential_reset_unauthorized", "status": "confirmed"}]),
    ]
    summary = _summarize(trials, mission_keys)
    assert summary["winning_paths"] == {"payroll_write_unauthorized": 2, "credential_reset_unauthorized": 1}
