import json
import tempfile
from pathlib import Path

from aginiti.adapter.observation_adapter import ExecutionResult
from aginiti.campaign import CampaignResult, DecisionLogEntry
from aginiti.graph.attack_category import DIRECT_PROMPT_ATTACK
from aginiti.graph.mitre_atlas_refs import DIRECT_PROMPT_INJECTION
from aginiti.graph.owasp_llm_taxonomy import LLM01_PROMPT_INJECTION
from aginiti.graph.schema import ClaimStatus
from aginiti.graph.security_boundary import BOUNDARY_L0
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.logging_utils import campaign_result_to_dict, save_trial


def _fake_result() -> CampaignResult:
    ssg = SecurityStateGraph()
    ssg.assert_claim("payroll_write_unauthorized", "true", ClaimStatus.CONFIRMED,
                      security_boundary=BOUNDARY_L0, owasp_llm_category=LLM01_PROMPT_INJECTION,
                      attack_category=DIRECT_PROMPT_ATTACK, mitre_atlas_technique=DIRECT_PROMPT_INJECTION)
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


def test_campaign_result_serializes_taxonomy_tags_per_claim():
    # 2026-08-12 fix: this data existed in the SSG but the trial-log serializer never
    # carried it, so a saved trial file couldn't answer "how severe was this finding"
    # without re-running the whole campaign against a live target.
    result = _fake_result()
    record = campaign_result_to_dict("aginiti", 0, 42, result)
    claim = record["final_claims"][0]
    assert claim["security_boundary"] == BOUNDARY_L0
    assert claim["owasp_llm_category"] == LLM01_PROMPT_INJECTION
    assert claim["attack_category"] == DIRECT_PROMPT_ATTACK
    assert claim["mitre_atlas_technique"] == DIRECT_PROMPT_INJECTION


def test_campaign_result_serializes_taxonomy_rollups():
    result = _fake_result()
    record = campaign_result_to_dict("aginiti", 0, 42, result)
    assert record["highest_boundary_crossed"] == BOUNDARY_L0
    assert record["owasp_category_summary"] == {LLM01_PROMPT_INJECTION: 1}
    assert record["attack_category_summary"] == {DIRECT_PROMPT_ATTACK: 1}
    assert record["confirmed_atlas_techniques"] == {"payroll_write_unauthorized": DIRECT_PROMPT_INJECTION}


def test_untagged_claims_serialize_taxonomy_fields_as_none():
    ssg = SecurityStateGraph()
    ssg.assert_claim("untagged_key", "true", ClaimStatus.CONFIRMED)
    result = CampaignResult(outcome="SUCCESS", steps_executed=0, prompts_used=0,
                             operators_executed=[], operators_considered_total=0, ssg=ssg)
    record = campaign_result_to_dict("aginiti", 0, 42, result)
    claim = record["final_claims"][0]
    assert claim["security_boundary"] is None
    assert claim["owasp_llm_category"] is None
    assert claim["attack_category"] is None
    assert claim["mitre_atlas_technique"] is None
    assert record["highest_boundary_crossed"] is None


def test_save_trial_writes_readable_json_file():
    result = _fake_result()
    with tempfile.TemporaryDirectory() as tmp:
        path = save_trial(tmp, "aginiti", 0, 42, result)
        assert Path(path).exists()
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["condition"] == "aginiti"
        assert loaded["trial"] == 0
