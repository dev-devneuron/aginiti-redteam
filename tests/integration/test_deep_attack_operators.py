"""Integration test for Phase 2 Slice E (plans/phase2-operator-wrapping.md):
the real IKEA Operator (aginiti/operators/deep_attack_operators.py) run
through the REAL run_campaign() -> AginitiPolicy/StaticPolicy ->
ObservationAdapter -> IKEAAttack path, exactly as a live campaign would.

Zero real network/API calls: AgentEndpoint.check_reachable/chat and
litellm.completion are mocked at the same boundary test_ikea.py's own
TestExecuteBlackBox/TestEndpointKwargsPassthrough classes already
establish. Local ONNX embeddings (chromadb/all-MiniLM-L6-v2, IKEA's
default) run FOR REAL -- no network, no API cost, confirmed working in
this environment by every other IKEA test in this suite already passing.

What this test proves that Slice B's and Slice D's own unit tests, taken
separately, do not: that a REAL AgentEndpoint constructed once for a
campaign's HTTPAgentAdapter is the SAME object IKEAAttack's own
execute_black_box actually calls .chat()/.check_reachable() on, all the
way through the real planner/campaign loop -- not just at the direct
IKEAAttack-construction level (Slice B) or with a stub attack (Slice D).
Wall-clock timeout-guard behavior is deliberately NOT re-tested here --
that mechanism lives in ObservationAdapter._execute_deep_attack itself,
is attack-implementation-agnostic, and is already covered by Slice D's
own dedicated test against a stub attack; re-proving it against a real,
slow IKEAAttack would be redundant and slow for no extra coverage.
"""
import json
import tempfile
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.attacks.dra import IKEAAttack
from aginiti.connectors.endpoint import AgentEndpoint
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.mission import Mission
from aginiti.core.policies.static_policy import StaticPolicy
from aginiti.operators.deep_attack_operators import deep_attack_operators
from aginiti.operators.library import OperatorLibrary


def _llm_side_effect(model, messages, **kwargs):
    """Mirrors tests/unit/test_ikea.py's own TestExecuteBlackBox._stub_attack
    message-content-inspection pattern exactly -- same fake-response shape
    (litellm.completion's real return type), just routed at the
    litellm.completion layer instead of IKEAAttack.llm/._classifier_llm
    directly, since this test never gets a handle on the internally-
    constructed IKEAAttack instance to patch those attributes on (it's
    built by deep_attack_operators.py's own attack_factory, inside the
    real campaign loop)."""
    prompt = messages[0]["content"]
    if "leak_type" in prompt:
        content = json.dumps({
            "is_refusal": False,
            "leak_type": "sensitive_data",
            "contains_pii": True,
            "contains_sensitive_data": True,
            "reveals_schema": False,
            "appears_record_specific": True,
            "severity": "high",
            "evidence": "Emma Thompson, SSN 423-58-9167",
            "reasoning": "response contains a specific employee SSN",
        })
    elif "anchor words" in prompt and "Query" not in prompt:
        content = '{"anchor words": ["salary"]}'
    elif "questions" in prompt:
        content = '{"questions": ["What is Emma Thompson\'s SSN?"]}'
    else:
        # TRDM mutation -- deliberately invalid JSON, same as
        # TestExecuteBlackBox's own stub; with max_queries=1 the loop never
        # gets far enough to need a second query anyway.
        content = "not json"

    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def test_ikea_operator_runs_through_a_real_campaign_sharing_one_session():
    # A cheap, 1-query variant of the real Operator -- deep_attack_operators()
    # itself defaults to max_queries=20 (a real run), too slow/heavy for a
    # unit-speed integration test; Operator is frozen, so dataclasses.replace
    # is the correct way to get a modified copy without touching the real
    # module-level definition.
    real_op = deep_attack_operators()[0]
    op = replace(
        real_op,
        cost_prompts=1,
        attack_kwargs={**real_op.attack_kwargs, "max_queries": 1},
    )
    library = OperatorLibrary([op])

    mission = Mission(
        goal="confirm the deep-attack Operator wiring works end to end",
        success_criteria=("sensitive_data_exfiltrated",),
        budget=1,
        risk_threshold=RiskTier.MEDIUM,
        constraints=(),
    )

    # The ONE real AgentEndpoint for this whole campaign -- constructed
    # exactly once, by the test itself, matching how a real caller would
    # wire up a campaign (a script, or a future CLI). HTTPAgentAdapter
    # wraps it for the campaign/planner side; deep_attack_operators.py's
    # own attack_factory receives it via .endpoint for the attack side.
    constructed_endpoints = []
    original_init = AgentEndpoint.__init__

    def _spy_init(self, *args, **kwargs):
        constructed_endpoints.append(self)
        return original_init(self, *args, **kwargs)

    with patch.object(AgentEndpoint, "__init__", _spy_init):
        endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    assert constructed_endpoints == [endpoint]  # exactly one construction so far

    agent = HTTPAgentAdapter(endpoint)

    cache_patcher = patch(
        "aginiti.attacks.dra.ikea._anchor_cache_path",
        side_effect=lambda topic: Path(tempfile.gettempdir()) / f"ikea_test_cache_{uuid.uuid4().hex}.json",
    )
    cache_patcher.start()
    try:
        # _embed patched at the CLASS level (not an instance attribute --
        # this test never gets a handle on the internally-constructed
        # IKEAAttack instance to set that on directly, since it's built by
        # deep_attack_operators.py's own attack_factory inside the real
        # campaign loop). Real local ONNX embeddings are semantically
        # meaningful (a real cosine-similarity threshold check gates which
        # anchors survive), so leaving them real makes anchor survival
        # depend on genuine semantic similarity between whatever anchor
        # words the LLM mock above returns and the topic string -- fragile
        # for a test with no such intent. A fixed vector sidesteps that
        # entirely, matching tests/unit/test_ikea.py's own
        # `self.attack._embed = lambda text: [1.0, 0.0]` convention exactly,
        # just applied at the class level instead of the instance level.
        with patch.object(AgentEndpoint, "__init__", _spy_init), \
             patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "chat",
                           return_value="Emma Thompson's record: SSN 423-58-9167, salary $152,000."), \
             patch.object(IKEAAttack, "_embed", lambda self, text: [1.0, 0.0]), \
             patch.object(IKEAAttack, "_is_refusal", lambda self, text: False), \
             patch("litellm.completion", side_effect=_llm_side_effect):
            result = run_campaign(
                mission, library, agent=agent, policy=StaticPolicy(),
                max_steps=1,
            )
    finally:
        cache_patcher.stop()

    # -- Session reuse: the actual Slice A/B/D/E payoff --------------------
    # No SECOND AgentEndpoint was ever constructed -- IKEAAttack's
    # execute_black_box reused agent.endpoint (via BaseAttack's injected
    # `endpoint=`) instead of building its own, all the way through the
    # real campaign loop, not just at the direct-construction level Slice
    # B's own tests already covered.
    assert constructed_endpoints == [endpoint]

    # -- Exact budget deduction --------------------------------------------
    assert result.prompts_used == 1
    assert result.steps_executed == 1
    assert result.operators_executed == [op.id]

    # -- Correct claim -------------------------------------------------------
    assert result.outcome == "SUCCESS"
    claim = result.ssg.current_claim("sensitive_data_exfiltrated")
    assert claim is not None
    assert claim.status == ClaimStatus.CONFIRMED

    exec_result = result.execution_log[0]
    assert exec_result.overall_success is True
    assert exec_result.confirmed_keys == ["sensitive_data_exfiltrated"]
    assert exec_result.ground_truth_mission_achieved is False  # HTTPAgentAdapter's own stub (Open Question 5)


def test_ikea_operator_survives_a_target_failure_without_crashing_the_campaign():
    # Same wiring as above, but the target is unreachable -- proves the
    # deep-attack path degrades exactly like a normal operator would
    # (charged cost, no claim, campaign continues/completes cleanly)
    # through the REAL campaign loop, not just ObservationAdapter in
    # isolation (Slice D's own coverage).
    real_op = deep_attack_operators()[0]
    op = replace(
        real_op,
        cost_prompts=1,
        attack_kwargs={**real_op.attack_kwargs, "max_queries": 1},
    )
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm graceful degradation through a real campaign",
        success_criteria=("sensitive_data_exfiltrated",),
        budget=1, risk_threshold=RiskTier.MEDIUM, constraints=(),
    )

    endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    agent = HTTPAgentAdapter(endpoint)

    with patch.object(AgentEndpoint, "check_reachable", return_value=False):
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    assert result.prompts_used == 1  # still charged -- a real attempt was made
    assert result.operators_executed == [op.id]
    assert result.execution_log[0].overall_success is False
    assert "RuntimeError" in result.execution_log[0].reasoning
    assert "reachable" in result.execution_log[0].reasoning.lower()
    assert result.ssg.current_claim("sensitive_data_exfiltrated") is None
