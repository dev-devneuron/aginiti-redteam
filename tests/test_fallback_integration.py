"""Integration test closing a real internal-audit gap: the Groq->Gemini
auto-fallback (aginiti/core/llm.py, post-LiteLLM-migration -- see that
module's docstring) and a REAL planner had never been exercised together
inside an actual run_campaign() call -- every live benchmark this session
ran forced AGINITI_LLM_PROVIDER=gemini specifically to avoid the
~130s/call Groq-pool-exhaustion tax, which meant the fallback mechanism
was only ever proven in isolation (a bare chat_json call), never in the
context of a real campaign loop making MULTIPLE different chat_json calls
(cold-start priors, then the Reasoning Layer) through a real planner's own
ranking logic.

No live network calls: litellm.completion is mocked to raise
litellm.RateLimitError for every groq/ model and return a controlled
verdict for every gemini/ model, and the target/judge round trip is
bypassed via the project's own established _FakeAdapter (same pattern as
tests/test_campaign.py) -- this isolates the ONE thing actually under
test (does a full run_campaign() call, with cold-start priors AND the
Reasoning Layer both enabled, correctly complete when every LLM call has
to fall back) from target/judge concerns already covered elsewhere.
"""
import litellm
import pytest

from aginiti.core import llm as core_llm
from aginiti.core.observation_adapter import ExecutionResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.mission import Mission
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.core.policies.aginiti_policy import AginitiPolicy


def _rate_limit_error() -> litellm.RateLimitError:
    return litellm.RateLimitError("rate limited", llm_provider="groq", model="llama-3.3-70b-versatile")


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
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    core_llm._current_idx = 0
    core_llm._last_fallback_reason = None

    priors_verdict = {"priorities": {}, "rank": [], "reasoning": {}}

    def fake_completion(model, messages, **kwargs):
        if model.startswith("groq/"):
            raise _rate_limit_error()
        assert model.startswith("gemini/")
        content = __import__("json").dumps(priors_verdict)
        message = type("Msg", (), {"content": content, "tool_calls": None})()
        choice = type("Choice", (), {"message": message})()
        return type("Resp", (), {"choices": [choice]})()

    monkeypatch.setattr(litellm, "completion", fake_completion)

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
    assert core_llm.last_fallback_reason() == "chat_json: groq pool exhausted, used gemini"
    # And the provider itself was never mutated by the fallback -- still
    # "groq" by default, just routed around per-call (see aginiti/core/
    # llm.py's own docstring on why this distinction matters).
    assert core_llm._PROVIDER == "groq"


def test_real_campaign_raises_cleanly_when_groq_exhausted_and_no_gemini_key_configured(monkeypatch):
    # The other real-world case: no fallback available at all -- must fail
    # loudly (a clear RateLimitError), not silently produce a bogus result.
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "k0")
    core_llm._current_idx = 0
    core_llm._last_fallback_reason = None
    monkeypatch.setattr(litellm, "completion", lambda model, messages, **kw: (_ for _ in ()).throw(_rate_limit_error()))

    library = OperatorLibrary(data_exposure_operators())
    mission = Mission(goal="fallback integration test", success_criteria=("system_prompt_disclosed",),
                       success_mode="any", budget=3, risk_threshold=RiskTier.MEDIUM)

    with pytest.raises(litellm.RateLimitError):
        run_campaign(
            mission, library, agent=object(), policy=AginitiPolicy(), adapter=_FakeAdapter(),
            max_steps=mission.budget, seed=1, enable_reasoning_layer=True,
            target_briefing="Target: a test system.",
        )
