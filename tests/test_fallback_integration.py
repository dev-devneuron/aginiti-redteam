"""Integration test closing a real internal-audit gap: the Groq->Gemini
auto-fallback (aginiti/llm_client.py) and a REAL planner had never been
exercised together inside an actual run_campaign() call -- every live
benchmark this session ran forced AGINITI_LLM_PROVIDER=gemini specifically
to avoid the ~130s/call Groq-pool-exhaustion tax, which meant the fallback
mechanism was only ever proven in isolation (a bare llm_client.chat_json
call), never in the context of a real campaign loop making MULTIPLE
different chat_json calls (cold-start priors, then the Reasoning Layer)
through a real planner's own ranking logic.

No live network calls: Groq is mocked exhausted (same _always_rate_limited_
clients pattern as tests/test_llm_client.py), Gemini's own chat_json is
mocked to return controlled verdicts, and the target/judge round trip is
bypassed via the project's own established _FakeAdapter (same pattern as
tests/test_campaign.py) -- this isolates the ONE thing actually under
test (does a full run_campaign() call, with cold-start priors AND the
Reasoning Layer both enabled, correctly complete when every LLM call has
to fall back) from target/judge concerns already covered elsewhere.
"""
import httpx
import pytest
from groq import RateLimitError

from aginiti import llm_client
from aginiti.core.observation_adapter import ExecutionResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.mission import Mission
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.core.policies.aginiti_policy import AginitiPolicy


def _rate_limit_error() -> RateLimitError:
    # Same construction as tests/test_llm_client.py's own helper -- the
    # real groq.RateLimitError requires a genuine httpx.Response (its
    # __init__ reads response.request), not response=None.
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(429, request=request, json={"error": {"message": "rate limited"}})
    return RateLimitError("rate limited", response=response, body=None)


class _FakeClient:
    def __init__(self, side_effect):
        self.chat = type("Chat", (), {
            "completions": type("Completions", (), {"create": staticmethod(lambda **kw: side_effect())})()
        })()


def _always_rate_limited_clients(n=2):
    def always_limited():
        raise _rate_limit_error()
    return [_FakeClient(always_limited) for _ in range(n)]


class _FakeAdapter:
    """Bypasses the real target/judge round trip entirely (same pattern as
    tests/test_campaign.py) -- this test is about the fallback+planner
    integration, not target/judge behavior, which is covered elsewhere."""

    def __init__(self):
        self.calls = 0

    def execute(self, operator, ssg, agent, seed=None):
        self.calls += 1
        for effect in operator.effects_success:
            ssg.assert_claim(effect.key, effect.object, effect.status, subgraph=effect.subgraph)
        return ExecutionResult(
            operator_id=operator.id, operator_execution_id=f"exec_{self.calls}",
            raw_signal="fake", confirmed_keys=[e.key for e in operator.effects_success],
            overall_success=True, ground_truth_mission_achieved=True, cost_prompts=operator.cost_prompts,
        )


def test_real_campaign_with_a_real_planner_completes_when_every_groq_key_is_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key-for-this-test")
    llm_client._clients = _always_rate_limited_clients()

    import aginiti.gemini_client as gemini_client

    priors_verdict = {"priorities": {}, "rank": [], "reasoning": {}}
    monkeypatch.setattr(gemini_client, "chat_json",
                         lambda messages, temperature, max_tokens, seed: priors_verdict)

    library = OperatorLibrary(data_exposure_operators())
    mission = Mission(goal="fallback integration test", success_criteria=("system_prompt_disclosed",),
                       success_mode="any", budget=3, risk_threshold=RiskTier.MEDIUM)

    result = run_campaign(
        mission, library, agent=object(), policy=AginitiPolicy(), adapter=_FakeAdapter(),
        max_steps=mission.budget, seed=1, enable_reasoning_layer=True,
        target_briefing="Target: a test system.",
    )

    # The real assertion: the campaign ran to completion using a REAL
    # planner (AginitiPolicy, which reads gap_priority -- itself populated
    # by the fallback-served seed_target_priors call), not a crash or a
    # silently-empty result.
    assert result.outcome == "SUCCESS"
    assert result.steps_executed >= 1
    assert llm_client.last_fallback_reason() == "chat_json: groq pool exhausted, used gemini"
    # And the provider itself was never mutated by the fallback -- still
    # "groq" by default, just routed around per-call (see llm_client.py's
    # own docstring on why this distinction matters).
    assert llm_client._PROVIDER == "groq"


def test_real_campaign_raises_cleanly_when_groq_exhausted_and_no_gemini_key_configured(monkeypatch):
    # The other real-world case: no fallback available at all -- must fail
    # loudly (a clear RateLimitError), not silently produce a bogus result.
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    llm_client._clients = _always_rate_limited_clients()

    library = OperatorLibrary(data_exposure_operators())
    mission = Mission(goal="fallback integration test", success_criteria=("system_prompt_disclosed",),
                       success_mode="any", budget=3, risk_threshold=RiskTier.MEDIUM)

    with pytest.raises(RateLimitError):
        run_campaign(
            mission, library, agent=object(), policy=AginitiPolicy(), adapter=_FakeAdapter(),
            max_steps=mission.budget, seed=1, enable_reasoning_layer=True,
            target_briefing="Target: a test system.",
        )
