"""Tests the judge's candidate-framing logic in isolation (no live API
calls) -- specifically a regression test for a real bug: HYPOTHESIZED-status
effects were framed as "evidence this is FALSE" instead of TRUE, which
silently broke recon_capabilities (whose only effect is HYPOTHESIZED) in
every single campaign until caught by a full benchmark run.
"""
import time
from unittest.mock import patch

from aginiti.attacks.base import BaseAttack, LeakFinding
from aginiti.core.observation_adapter import KEY_DESCRIPTIONS, ObservationAdapter, _build_candidates, _effect_id
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.definitions import build_library
from aginiti.operators.library import ClaimEffect, Operator


def test_hypothesized_effect_is_framed_as_true_not_false():
    op = build_library().get("recon_capabilities")
    candidates = _build_candidates(op)
    assert len(candidates) == 1
    assert "TRUE" in candidates[0]["meaning"]
    assert "FALSE" not in candidates[0]["meaning"]


def test_confirmed_effect_is_framed_as_true():
    op = build_library().get("indirect_prompt_injection")
    candidates = {c["id"]: c["meaning"] for c in _build_candidates(op)}
    confirmed_id = _effect_id(op.effects_success[0])
    assert "TRUE" in candidates[confirmed_id]
    assert "FALSE" not in candidates[confirmed_id]


def test_refuted_effect_is_framed_as_false():
    op = build_library().get("confirm_tool_reachability")
    candidates = {c["id"]: c["meaning"] for c in _build_candidates(op)}
    refuted_id = _effect_id(op.effects_failure[0])  # payroll_api_exists::refuted
    assert refuted_id.endswith("::refuted")
    assert "FALSE" in candidates[refuted_id]


def test_every_operator_in_the_live_library_frames_hypothesized_and_confirmed_as_true():
    # Broad sweep: no effect in the real library should ever be framed FALSE
    # unless its status is actually REFUTED.
    for op in build_library():
        for c in _build_candidates(op):
            is_refuted = c["id"].endswith("::refuted")
            assert ("FALSE" in c["meaning"]) == is_refuted, c


def test_hypothesized_effect_gets_a_linked_observation_not_just_a_claim():
    # Regression test: a HYPOTHESIZED-status confirmed effect (e.g.
    # recon_capabilities) was excluded from both supports and contradicts,
    # so its Observation never linked to the claim it produced -- the claim
    # existed (via assert_claim) but showed zero evidence in the graph
    # export, even though real evidence caused it. Found by inspecting a
    # real DVLA campaign's exported graph, where the node had an extracted
    # detail but an empty evidence list.
    op = build_library().get("recon_capabilities")
    ssg = SecurityStateGraph()
    fake_verdict = {
        "confirmed_effect_ids": ["payroll_api_exists::hypothesized"],
        "details": {}, "reasoning": "mentions payroll",
    }
    with patch("aginiti.core.observation_adapter.chat_json", return_value=fake_verdict), \
         patch.object(type(op), "render_prompt", return_value="x"):
        from types import SimpleNamespace

        class FakeAgent:
            def send(self, channel, prompt):
                return SimpleNamespace(final_text="I have payroll access.", tool_trace=[])

            def ground_truth_mission_achieved(self):
                return False

        result = ObservationAdapter().execute(op, ssg, FakeAgent())

    assert result.overall_success is True
    obs = ssg.observations[-1]
    assert "payroll_api_exists" in obs.supports  # not silently dropped


# -- 2026-08-08 architecture audit: per-effect description overrides the
# global KEY_DESCRIPTIONS dict, so programmatically-generated operator
# packs (e.g. aginiti/operators/injecagent.py) never need to mutate it.

def test_build_candidates_prefers_the_effects_own_description():
    key = "some_novel_key_never_in_key_descriptions"
    assert key not in KEY_DESCRIPTIONS
    op = Operator(
        id="x", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect(key, ClaimStatus.CONFIRMED, description="a specific grounded description"),),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )

    candidates = _build_candidates(op)

    assert "a specific grounded description" in candidates[0]["meaning"]
    assert key not in KEY_DESCRIPTIONS  # building/using the operator never mutated the global dict


def test_build_candidates_falls_back_to_key_descriptions_when_effect_description_is_none():
    op = build_library().get("recon_capabilities")
    assert op.effects_success[0].description is None  # hand-authored operators don't set it
    candidates = _build_candidates(op)
    assert "payroll" in candidates[0]["meaning"].lower()  # resolved via the global dict as before


# -- _judge parse-error handling (2026-08-09) --------------------------------
# This is the ground-truth mechanism for every benchmark this project has
# run -- a truncated/malformed chat_json response used to silently produce
# confirmed_effect_ids=[] (identical to a genuine "nothing confirmed"
# verdict), which could misreport a real success as a failure with no
# visible sign anything went wrong.

def test_judge_warns_on_a_parse_error_instead_of_silently_reporting_nothing_confirmed():
    import warnings

    from aginiti.core.observation_adapter import _judge

    op = build_library().get("recon_capabilities")
    with patch("aginiti.core.observation_adapter.chat_json",
               return_value={"_parse_error": True, "_raw": '{"confirmed_effect_ids": ["a'}):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            verdict = _judge(op, "some agent response", seed=1)

    assert verdict["confirmed_effect_ids"] == []  # still degrades safely, never fabricates a confirmation
    assert any("parse" in str(w.message).lower() for w in caught)


def test_judge_does_not_warn_on_a_genuine_empty_verdict():
    import warnings

    from aginiti.core.observation_adapter import _judge

    op = build_library().get("recon_capabilities")
    with patch("aginiti.core.observation_adapter.chat_json",
               return_value={"confirmed_effect_ids": [], "details": {}, "reasoning": "no evidence found"}):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _judge(op, "some agent response", seed=1)

    assert not any("parse" in str(w.message).lower() for w in caught)


def test_judge_max_tokens_scales_with_candidate_count():
    from aginiti.core.observation_adapter import _judge

    single_effect_op = build_library().get("recon_capabilities")
    assert len(single_effect_op.effects_success) + len(single_effect_op.effects_failure) == 1

    calls = {}

    def _capture(messages, max_tokens=None, seed=None):
        calls["max_tokens"] = max_tokens
        return {"confirmed_effect_ids": [], "details": {}, "reasoning": "x"}

    with patch("aginiti.core.observation_adapter.chat_json", side_effect=_capture):
        _judge(single_effect_op, "x", seed=1)
    single_tokens = calls["max_tokens"]

    # Synthetic operator with many candidate effects (real ones here top
    # out around 3 -- too few to clear the 500-token floor and actually
    # demonstrate scaling).
    multi_effect_op = Operator(
        id="synthetic_multi", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=tuple(ClaimEffect(f"k{i}", ClaimStatus.CONFIRMED) for i in range(8)),
        effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
    )

    with patch("aginiti.core.observation_adapter.chat_json", side_effect=_capture):
        _judge(multi_effect_op, "x", seed=1)
    multi_tokens = calls["max_tokens"]

    assert multi_tokens > single_tokens


def test_a_confirmed_finding_is_logged(caplog):
    # 2026-08-09 production-readiness addition: this is the single
    # highest-signal event the library produces -- a deploying application
    # attaching its own handler to "aginiti" must be able to alert on it,
    # not just discover it by reading a saved trial JSON afterward.
    import logging

    from aginiti.adapters.base import SendResult

    effect = ClaimEffect("logging_test_claim", ClaimStatus.CONFIRMED)
    op = Operator(
        id="logging_test_op", description="test", prompt="x", channel="direct", preconditions=(),
        effects_success=(effect,), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw_signal: [_effect_id(effect)],
    )

    class _StubAdapter:
        def send(self, channel, prompt):
            return SendResult(final_text="it worked")

        def ground_truth_mission_achieved(self):
            return False

    ssg = SecurityStateGraph()
    with caplog.at_level(logging.WARNING, logger="aginiti.observation_adapter"):
        result = ObservationAdapter().execute(op, ssg, _StubAdapter(), seed=1)

    assert result.overall_success is True
    assert "finding confirmed" in caplog.text
    assert "logging_test_op" in caplog.text
    assert "logging_test_claim" in caplog.text


def test_agent_send_raising_is_caught_and_never_crashes_execute():
    """2026-08-12 hardening-pass fix: ObservationAdapter.execute() now
    catches ANY exception agent.send() raises (the single choke point
    every operator execution passes through) and converts it into an
    explicit is_synthetic non-event -- regardless of which adapter is
    plugged in, and regardless of whether that specific adapter bothered
    to protect itself. Before this fix, this test would have raised
    RuntimeError straight out of execute()."""
    effect = ClaimEffect("some_claim", ClaimStatus.CONFIRMED)
    op = Operator(
        id="flaky_op", description="test", prompt="x", channel="direct", preconditions=(),
        effects_success=(effect,), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw_signal: [_effect_id(effect)],
    )

    class _CrashingAdapter:
        def send(self, channel, prompt):
            raise RuntimeError("target connection reset")

        def ground_truth_mission_achieved(self):
            return False

    ssg = SecurityStateGraph()
    result = ObservationAdapter().execute(op, ssg, _CrashingAdapter(), seed=1)  # must not raise

    assert result.overall_success is False
    assert result.confirmed_keys == []
    assert "no judge/extractor call" in result.reasoning
    assert "RuntimeError" in result.raw_signal
    # No claim confirmed OR refuted -- a target-side failure is a genuine
    # non-event, never misread as "attack failed" (a false defender-
    # control claim) or "attack succeeded."
    assert ssg.current_claim("some_claim") is None
    # The Fact is still recorded, for audit trail -- is_synthetic blocks
    # INTERPRETATION, never RECORDING.
    assert any(f.kind == "response_text" for f in ssg.facts)


def test_agent_send_raising_still_charges_cost_and_continues_the_campaign():
    """A target-side failure still consumes the attempted operator's
    budget (a real attempt was made) and the campaign keeps going --
    this is the actual end-to-end proof that run_campaign() survives a
    crashing adapter instead of propagating the exception."""
    from aginiti.core.campaign import run_campaign
    from aginiti.core.mission import Mission
    from aginiti.operators.library import OperatorLibrary
    from aginiti.core.policies.static_policy import StaticPolicy

    flaky = Operator(
        id="flaky", description="x", prompt="x", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("flaky_win", ClaimStatus.CONFIRMED),), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw: ["flaky_win::confirmed"],
    )
    backup = Operator(
        id="backup", description="x", prompt="__confirmed__backup_win", channel="direct", preconditions=(),
        effects_success=(ClaimEffect("backup_win", ClaimStatus.CONFIRMED),), effects_failure=(),
        cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw: ["backup_win::confirmed"] if "__confirmed__backup_win" in raw else [],
    )
    library = OperatorLibrary([flaky, backup])
    mission = Mission(goal="x", success_criteria=("backup_win",), budget=5, risk_threshold=RiskTier.LOW,
                       constraints=())

    class _AlwaysCrashesOnFlaky:
        def send(self, channel, prompt):
            if prompt == "x":  # flaky's prompt
                raise ConnectionError("target down")
            return type("R", (), {"final_text": prompt, "tool_trace": [], "is_synthetic": False})()

        def ground_truth_mission_achieved(self):
            return False

    result = run_campaign(mission, library, agent=_AlwaysCrashesOnFlaky(), policy=StaticPolicy(),
                           max_steps=5)  # must not raise
    assert result.outcome == "SUCCESS"
    assert "flaky" in result.operators_executed  # attempted, charged its cost
    assert "backup" in result.operators_executed  # campaign continued past the crash
    assert result.prompts_used == 2


# ---------------------------------------------------------------------------
# _execute_deep_attack (Phase 2 Slice D, plans/phase2-operator-wrapping.md)
# -- ObservationAdapter.execute() dispatching to a wrapped deep attack via
# operator.kind == "deep_attack", zero network: attack.execute_black_box is
# a stub returning canned LeakFinding objects, never a real BaseAttack
# subclass or a real target.
# ---------------------------------------------------------------------------

class _StubDeepAttack(BaseAttack):
    """A minimal BaseAttack subclass that never calls litellm/AgentEndpoint
    -- deliberately skips super().__init__() (this stub needs none of
    BaseAttack's own LLM/endpoint plumbing) while still satisfying the ABC
    by implementing both abstract methods, same pattern as
    tests/unit/test_base.py's own _BlackBoxOnlyAttack."""

    def __init__(self, findings=None, raise_exc=None, sleep_seconds=0.0):
        self._findings = findings if findings is not None else []
        self._raise_exc = raise_exc
        self._sleep_seconds = sleep_seconds
        self.execute_black_box_call_count = 0

    def execute_black_box(self, **kwargs):
        self.execute_black_box_call_count += 1
        if self._sleep_seconds:
            time.sleep(self._sleep_seconds)
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._findings

    def execute_with_traces(self, **kwargs):
        raise NotImplementedError("deep_attack operators only ever call execute_black_box")


def _leak_finding(confirmed: bool) -> LeakFinding:
    return LeakFinding(
        attack_type="DRA", tier_used="black_box",
        confidence=0.9 if confirmed else 0.2, confirmed=confirmed,
        leaked_content="evidence" if confirmed else "", probe_used="a probe",
        trace_span_id="", recommendation="", severity="high" if confirmed else "low",
    )


class _StubEndpoint:
    """Stands in for a real AgentEndpoint -- the deep-attack bridge never
    calls anything on it directly (attack_factory owns that), it only
    needs to exist and be passed through by identity."""


class _AgentWithEndpoint:
    """A BaseAdapter-shaped agent exposing .endpoint, like HTTPAgentAdapter."""

    def __init__(self, endpoint=None):
        self.endpoint = endpoint if endpoint is not None else _StubEndpoint()

    def send(self, channel, prompt):
        raise AssertionError("a deep_attack operator must never call agent.send() directly")

    def ground_truth_mission_achieved(self):
        return False


class _AgentWithoutEndpoint:
    """A BaseAdapter-shaped agent with no .endpoint -- every concrete
    adapter other than HTTPAgentAdapter today (AnythingLLM,
    HardenedAgentAdapter, ...)."""

    def send(self, channel, prompt):
        raise AssertionError("a deep_attack operator must never call agent.send() directly")

    def ground_truth_mission_achieved(self):
        return False


def _deep_attack_operator(attack_factory, claim_key="test_deep_attack_claim",
                           cost_prompts=5, attack_timeout_seconds=300.0, **overrides):
    defaults = dict(
        id="test_deep_attack_op", description="a wrapped deep attack",
        prompt="[runs a stub attack's execute_black_box, not a single templated prompt]",
        channel="direct", preconditions=(), effects_success=(), effects_failure=(),
        cost_prompts=cost_prompts, risk_tier=RiskTier.LOW,
        kind="deep_attack", attack_factory=attack_factory, attack_kwargs={},
        claim_key=claim_key, attack_timeout_seconds=attack_timeout_seconds,
    )
    defaults.update(overrides)
    return Operator(**defaults)


def test_deep_attack_kind_dispatches_away_from_the_prompt_pipeline():
    # The dispatch itself: kind="deep_attack" must never reach render_prompt/
    # _send/_judge -- confirmed by using an agent whose send() raises if
    # ever called at all (see _AgentWithEndpoint above).
    stub = _StubDeepAttack(findings=[_leak_finding(confirmed=True)])
    op = _deep_attack_operator(attack_factory=lambda ep: stub)
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())

    assert stub.execute_black_box_call_count == 1
    assert result.overall_success is True


def test_agent_without_endpoint_fails_gracefully_without_calling_the_factory():
    factory_calls = []
    op = _deep_attack_operator(attack_factory=lambda ep: factory_calls.append(ep) or _StubDeepAttack())
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithoutEndpoint())

    assert factory_calls == []  # never reached -- the guard fires first
    assert result.overall_success is False
    assert result.confirmed_keys == []
    assert "requires an adapter exposing .endpoint" in result.reasoning
    assert result.cost_prompts == 5  # still charged -- the campaign attempted this step
    assert ssg.current_claim("test_deep_attack_claim") is None


def test_attack_factory_exception_fails_gracefully():
    def _raising_factory(ep):
        raise ValueError("bad target_url configuration")

    op = _deep_attack_operator(attack_factory=_raising_factory)
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())

    assert result.overall_success is False
    assert "ValueError" in result.reasoning
    assert result.cost_prompts == 5


def test_execute_black_box_exception_fails_gracefully_not_a_crash():
    stub = _StubDeepAttack(raise_exc=ConnectionError("target down mid-run"))
    op = _deep_attack_operator(attack_factory=lambda ep: stub)
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())  # must not raise

    assert result.overall_success is False
    assert "ConnectionError" in result.reasoning
    assert "ConnectionError" in result.raw_signal
    assert result.cost_prompts == 5
    assert ssg.current_claim("test_deep_attack_claim") is None
    # The failure is still an audited event, same as a crashing prompt-type
    # adapter's own Fact-recording discipline.
    assert any(f.kind == "response_text" for f in ssg.facts)


def test_execute_black_box_timeout_fails_gracefully_not_a_hang():
    stub = _StubDeepAttack(findings=[_leak_finding(confirmed=True)], sleep_seconds=0.3)
    op = _deep_attack_operator(attack_factory=lambda ep: stub, attack_timeout_seconds=0.05)
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())  # must not raise or hang

    assert result.overall_success is False
    assert "timed out" in result.reasoning
    assert result.cost_prompts == 5
    assert ssg.current_claim("test_deep_attack_claim") is None


def test_confirmed_finding_asserts_confirmed_claim():
    op = _deep_attack_operator(
        attack_factory=lambda ep: _StubDeepAttack(findings=[_leak_finding(confirmed=True)])
    )
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())

    assert result.overall_success is True
    assert result.confirmed_keys == ["test_deep_attack_claim"]
    claim = ssg.current_claim("test_deep_attack_claim")
    assert claim is not None
    assert claim.status == ClaimStatus.CONFIRMED
    assert result.cost_prompts == 5
    assert result.ground_truth_mission_achieved is False  # from _AgentWithEndpoint's own stub


def test_unconfirmed_finding_asserts_hypothesized_claim_not_nothing():
    op = _deep_attack_operator(
        attack_factory=lambda ep: _StubDeepAttack(findings=[_leak_finding(confirmed=False)])
    )
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())

    # A non-refused-but-unconfirmed finding is real, if provisional, evidence
    # -- overall_success is specifically about CONFIRMED for a deep attack
    # (unlike a lightweight recon operator, where HYPOTHESIZED can itself be
    # the declared success effect).
    assert result.overall_success is False
    claim = ssg.current_claim("test_deep_attack_claim")
    assert claim is not None
    assert claim.status == ClaimStatus.HYPOTHESIZED


def test_empty_findings_asserts_no_claim_at_all():
    op = _deep_attack_operator(attack_factory=lambda ep: _StubDeepAttack(findings=[]))
    ssg = SecurityStateGraph()

    result = ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())

    assert result.overall_success is False
    assert result.confirmed_keys == []
    assert ssg.current_claim("test_deep_attack_claim") is None
    # Distinct from the guard/exception/timeout failure paths: this is a
    # real, completed execution that legitimately found nothing -- the
    # supplementary structured Fact still gets recorded (unlike a genuine
    # crash), and cost is still charged.
    assert any(f.kind == "deep_attack_execution" for f in ssg.facts)
    assert result.cost_prompts == 5


def test_attack_kwargs_are_forwarded_to_execute_black_box():
    captured_kwargs = {}

    class _CapturingAttack(_StubDeepAttack):
        def execute_black_box(self, **kwargs):
            captured_kwargs.update(kwargs)
            return super().execute_black_box(**kwargs)

    op = _deep_attack_operator(
        attack_factory=lambda ep: _CapturingAttack(findings=[]),
        attack_kwargs={"max_queries": 20, "topic": "HR records"},
    )
    ssg = SecurityStateGraph()

    ObservationAdapter().execute(op, ssg, _AgentWithEndpoint())

    assert captured_kwargs == {"max_queries": 20, "topic": "HR records"}


def test_endpoint_is_passed_to_attack_factory_by_identity():
    # The whole point of Slice A/B/D together: the SAME AgentEndpoint the
    # campaign/planner side is using must reach the wrapped attack.
    received_endpoints = []
    fake_endpoint = _StubEndpoint()

    def factory(ep):
        received_endpoints.append(ep)
        return _StubDeepAttack(findings=[])

    op = _deep_attack_operator(attack_factory=factory)
    ssg = SecurityStateGraph()

    ObservationAdapter().execute(op, ssg, _AgentWithEndpoint(endpoint=fake_endpoint))

    assert received_endpoints == [fake_endpoint]
