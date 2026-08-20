from aginiti.core.observation_adapter import ObservationAdapter, _effect_id
from aginiti.adapters.base import SendResult
from aginiti.adaptive.refinement import run_adaptive_refinement
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.library import ClaimEffect, Operator

SUCCESS_EFFECT = ClaimEffect("adaptive_test_claim", ClaimStatus.CONFIRMED)


def _make_operator(prompt="original prompt"):
    return Operator(
        id="adaptive_test_op", description="test intent", prompt=prompt, channel="direct",
        preconditions=(), effects_success=(SUCCESS_EFFECT,), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw_signal: [_effect_id(SUCCESS_EFFECT)] if raw_signal == "SUCCESS" else [],
    )


class _ScriptedAdapter:
    """Returns each response in `responses` in order, one per .send() call --
    deterministic, no live LLM call, mirroring test_security_boundary.py's
    _StubAdapter pattern."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts_sent = []

    def send(self, channel, prompt):
        self.prompts_sent.append(prompt)
        return SendResult(final_text=self.responses.pop(0))

    def ground_truth_mission_achieved(self):
        return False


def _stub_refine(intent, previous_prompt, target_response, attempt_number, seed):
    return f"refined-{attempt_number + 1}"


def test_succeeds_on_first_attempt_never_calls_refine():
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["SUCCESS"])
    result = run_adaptive_refinement(_make_operator(), ssg, adapter, max_attempts=3, refine_fn=_stub_refine)

    assert result.succeeded is True
    assert result.attempts_used == 1
    assert adapter.prompts_sent == ["original prompt"]
    assert result.attempts[0].success is True


def test_refines_after_failure_and_succeeds_on_second_attempt():
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["FAIL_TEXT", "SUCCESS"])
    result = run_adaptive_refinement(_make_operator(), ssg, adapter, max_attempts=3, refine_fn=_stub_refine)

    assert result.succeeded is True
    assert result.attempts_used == 2
    assert adapter.prompts_sent == ["original prompt", "refined-2"]
    assert result.attempts[0].success is False
    assert result.attempts[1].success is True


def test_exhausts_budget_and_reports_failure_when_every_attempt_fails():
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["FAIL1", "FAIL2", "FAIL3"])
    result = run_adaptive_refinement(_make_operator(), ssg, adapter, max_attempts=3, refine_fn=_stub_refine)

    assert result.succeeded is False
    assert result.attempts_used == 3
    assert adapter.prompts_sent == ["original prompt", "refined-2", "refined-3"]
    assert all(a.success is False for a in result.attempts)


def test_default_max_attempts_is_three():
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["FAIL1", "FAIL2", "FAIL3"])
    result = run_adaptive_refinement(_make_operator(), ssg, adapter, refine_fn=_stub_refine)
    assert result.attempts_used == 3


def test_final_result_reflects_the_last_attempt_and_ssg_claim_is_confirmed_on_success():
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["FAIL_TEXT", "SUCCESS"])
    result = run_adaptive_refinement(_make_operator(), ssg, adapter, max_attempts=3, refine_fn=_stub_refine)

    assert result.final_result is not None
    assert result.final_result.overall_success is True
    claim = ssg.current_claim("adaptive_test_claim")
    assert claim is not None
    assert claim.status == ClaimStatus.CONFIRMED


def test_every_attempt_including_failures_is_recorded_as_a_real_operator_execution():
    # Confirms the loop doesn't bypass ObservationAdapter's own bookkeeping --
    # every attempt (success or not) shows up in operator_stats.
    ssg = SecurityStateGraph()
    adapter = _ScriptedAdapter(["FAIL1", "FAIL2", "FAIL3"])
    run_adaptive_refinement(_make_operator(), ssg, adapter, max_attempts=3, refine_fn=_stub_refine)
    total_executions = sum(s.executions for s in ssg.operator_stats.values())
    assert total_executions == 3
