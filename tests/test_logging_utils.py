import json
import tempfile
from pathlib import Path

from aginiti.adapter.observation_adapter import ExecutionResult
from aginiti.campaign import CampaignResult, DecisionLogEntry
from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.logging_utils import campaign_result_to_dict, save_trial


def _fake_result() -> CampaignResult:
    ssg = SecurityStateGraph()
    ssg.assert_claim("payroll_write_unauthorized", "true", ClaimStatus.CONFIRMED)
    exec_result = ExecutionResult(
        operator_id="direct_prompt_injection",
        operator_execution_id="exec_0001",
        raw_signal="I've processed it.",
        confirmed_keys=["payroll_write_unauthorized"],
        overall_success=True,
        ground_truth_mission_achieved=True,
        cost_prompts=1,
        reasoning="test",
    )
    decision = DecisionLogEntry(step=1, candidates_considered=3, chosen_operator_id="direct_prompt_injection",
                                 score=4.05, meta={"info_gain": 4.0, "alpha": 1.0})
    return CampaignResult(
        outcome="SUCCESS", steps_executed=1, prompts_used=1,
        operators_executed=["direct_prompt_injection"], operators_considered_total=3,
        decision_log=[decision], execution_log=[exec_result], ssg=ssg,
    )


def test_campaign_result_serializes_to_json_safely():
    result = _fake_result()
    record = campaign_result_to_dict("aginiti", 0, 42, result)
    json.dumps(record)  # must not raise
    assert record["outcome"] == "SUCCESS"
    assert record["ground_truth_mission_achieved"] is True
    assert record["final_claims"][0]["status"] == "confirmed"


def test_save_trial_writes_readable_json_file():
    result = _fake_result()
    with tempfile.TemporaryDirectory() as tmp:
        path = save_trial(tmp, "aginiti", 0, 42, result)
        assert Path(path).exists()
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["condition"] == "aginiti"
        assert loaded["trial"] == 0
