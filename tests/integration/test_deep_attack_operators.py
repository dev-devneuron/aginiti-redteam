"""Integration tests for Phase 2 Slice E/G (plans/phase2-operator-wrapping.md):
the real deep-attack Operators (aginiti/operators/deep_attack_operators.py)
run through the REAL run_campaign() -> AginitiPolicy/StaticPolicy ->
ObservationAdapter -> BaseAttack subclass path, exactly as a live campaign
would. IKEA (Slice E) is covered by the two tests below this docstring;
SECRET/Interrogation(MIA)/SPE-LLM (Slice G) each get an equivalent pair
further down the file.

Zero real network/API calls in any of these: AgentEndpoint.check_reachable/
chat/close and litellm.completion are mocked at the same boundary each
attack's own tests/unit/test_*.py file already establishes. IKEA's local
ONNX embeddings (chromadb/all-MiniLM-L6-v2) run FOR REAL -- no network, no
API cost, confirmed working in this environment already.

What every test in this file proves that each attack's own Slice B/G unit
tests, taken separately, do not: that a REAL AgentEndpoint constructed once
for a campaign's HTTPAgentAdapter is the SAME object the wrapped attack's
own execute_black_box actually calls .chat()/.check_reachable() on, all
the way through the real planner/campaign loop -- not just at the direct
attack-construction level. The Slice G tests additionally assert
`AgentEndpoint.close` is never called on the shared endpoint -- the second,
independent bug this module's own docstring documents (a latent
finally-block bug that survived Slice E's own review for IKEA, and would
have shipped in the other three attacks too without this cross-attack
audit).

Each attack's own internal computation (Stage A/B/C for MIA, GE/LE cluster
search for SECRET, IKEA's ERS/TRDM) is bypassed via a class-level patch of
the SAME private method each attack's own unit-test suite already patches
for its own full-loop orchestration tests (e.g. `_process_response` for
SECRET, `_run_stage_abc_for_document` for MIA) -- this file's job is
proving the Operator-wrapping plumbing, not re-proving attack internals
already covered elsewhere.

Wall-clock timeout-guard behavior is deliberately NOT re-tested here for
any attack -- that mechanism lives in
ObservationAdapter._execute_deep_attack itself, is attack-implementation-
agnostic, and is already covered by Slice D's own dedicated test against a
stub attack.

Real, live-caught bug in THIS file, fixed 2026-08-21 (found by GitHub
Actions CI, not locally -- see the module-level `_fake_api_keys` fixture
below for the full story): every IKEA/SECRET/MIA test here uses the REAL
`deep_attack_operators()` Operators, whose `attack_factory` calls
`aginiti.operators.deep_attack_operators._key_for()` to resolve a REAL
API key from the environment (GEMINI_API_KEY / GROQ_API_KEY) BEFORE any
of the mocked internals below (litellm.completion, _process_response,
_run_stage_abc_for_document, ...) ever run -- mocking those deeper calls
was never enough, since attack CONSTRUCTION itself needs a key. This
passed locally (a real `.env` with real keys) but failed in CI (no
`.env`, no secrets configured) with `ValueError: GEMINI_API_KEY is not
set` -- the exact same class of environment-leakage bug as
tests/unit/test_dvla_adapter.py's own real-key requirement, caught in
that file earlier the same day and, ironically, not re-checked for here
before this file was written.
"""
import json
import tempfile
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.attacks.base import LeakFinding
from aginiti.attacks.dra import IKEAAttack, SECRETAttack
from aginiti.attacks.dra.jailbreak_optimizer import DEFAULT_EXTRACTION_INSTRUCTION, JailbreakArtifact
from aginiti.attacks.mia import InterrogationAttack
from aginiti.connectors.endpoint import AgentEndpoint
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.mission import Mission
from aginiti.core.policies.static_policy import StaticPolicy
from aginiti.operators.deep_attack_operators import deep_attack_operators
from aginiti.operators.library import Operator, OperatorLibrary


@pytest.fixture(autouse=True)
def _fake_api_keys():
    """No test in this file should ever require a real API key -- every
    LLM/HTTP call an attack_factory-built attack instance would make is
    already mocked elsewhere in each test (litellm.completion,
    _process_response, _run_stage_abc_for_document, AgentEndpoint.chat).
    The one thing that was NOT mocked, and the actual CI failure this
    fixture fixes: `_key_for()` (aginiti/operators/deep_attack_operators.py)
    resolves a real GEMINI_API_KEY/GROQ_API_KEY from the environment at
    attack-CONSTRUCTION time, before any of those other mocks are even
    reached. Patched here, autouse, so every test in this file (present and
    future) is protected the same way, rather than repeating this patch
    inline 6+ times. Return value is never actually used as a real key --
    every attack's own outbound calls are mocked, so it only ever needs to
    be a syntactically-plausible non-empty string."""
    with patch("aginiti.operators.deep_attack_operators._key_for", return_value="test-fake-api-key"):
        yield


def _spy_on_endpoint_construction():
    """Returns (patcher_context_manager_factory, constructed_endpoints) --
    same spy technique test_ikea_operator_runs_through_a_real_campaign_
    sharing_one_session already established, factored out so every new
    Slice G test below can reuse it without repeating the boilerplate."""
    constructed = []
    original_init = AgentEndpoint.__init__

    def _spy_init(self, *args, **kwargs):
        constructed.append(self)
        return original_init(self, *args, **kwargs)

    return _spy_init, constructed


def _deep_attack_op(operator_id: str, **overrides) -> Operator:
    """Look up one real Operator from deep_attack_operators() by id and
    return a cheap-variant copy (dataclasses.replace) with the given
    overrides -- same pattern the original IKEA tests use inline, factored
    out since Slice G repeats it 3 more times."""
    real_op = next(op for op in deep_attack_operators() if op.id == operator_id)
    return replace(real_op, **overrides)


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


# ---------------------------------------------------------------------------
# SECRET (Slice G)
# ---------------------------------------------------------------------------

def _artifact(**overrides) -> JailbreakArtifact:
    """Same helper as tests/unit/test_secret.py's own _artifact() --
    duplicated rather than imported (this project's established
    self-containment convention for test fixtures, matching how
    deep_attack_operators.py itself duplicates scripts/run_secret.py's
    corpus rather than importing it)."""
    defaults = dict(
        p_e_star="JAILBREAK_PROMPT",
        score=0.9,
        target_identity="http://fake-target:8001",
        iterations_used=1,
        used_curriculum=False,
        optimizer_provider="gemini/gemini-3.5-flash",
        evaluator_provider="gemini/gemini-3.5-flash",
        seed_prompt=DEFAULT_EXTRACTION_INSTRUCTION,
        n_cand=2,
        alpha=0.85,
        optimized_at=datetime.now(timezone.utc).isoformat(),
    )
    defaults.update(overrides)
    return JailbreakArtifact(**defaults)


def _secret_finding() -> LeakFinding:
    return LeakFinding(
        attack_type="DRA", tier_used="black_box", confidence=0.9, confirmed=True,
        leaked_content="leaked stuff", probe_used="q", trace_span_id="",
        recommendation="fix it", severity="critical", full_response="resp",
        leak_type="verbatim", reasoning="because",
    )


def test_secret_operator_runs_through_a_real_campaign_sharing_one_session():
    # Phase 1 (jailbreak optimization -- its own SEPARATE, independent
    # AgentEndpoint, per this module's own docstring's flagged limitation)
    # is bypassed entirely via _ensure_jailbreak_artifact, so this test
    # exercises ONLY Phase 2 (CFT), which is the part that DOES honor the
    # injected/shared endpoint (Slice G's own fix). Phase 1's own separate-
    # session limitation is a known, documented gap, not something this
    # test needs to re-prove.
    op = _deep_attack_op(
        "secret_jailbreak_exfiltration",
        cost_prompts=1,
        attack_kwargs={"domain": "HR records", "max_queries": 1},
    )
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm the SECRET deep-attack Operator wiring works end to end",
        success_criteria=("sensitive_data_exfiltrated",),
        budget=1, risk_threshold=RiskTier.MEDIUM, constraints=(),
    )

    spy_init, constructed_endpoints = _spy_on_endpoint_construction()
    with patch.object(AgentEndpoint, "__init__", spy_init):
        endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    assert constructed_endpoints == [endpoint]

    agent = HTTPAgentAdapter(endpoint)

    with patch.object(AgentEndpoint, "__init__", spy_init), \
         patch.object(AgentEndpoint, "check_reachable", return_value=True), \
         patch.object(AgentEndpoint, "chat", return_value="some response"), \
         patch.object(AgentEndpoint, "close") as mock_close, \
         patch.object(SECRETAttack, "_ensure_jailbreak_artifact",
                       lambda self, force_refresh: _artifact()), \
         patch.object(SECRETAttack, "_process_response",
                       lambda self, query, response, domain: ([], _secret_finding())):
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    # -- Session reuse: no second AgentEndpoint constructed for Phase 2 ----
    assert constructed_endpoints == [endpoint]
    # -- The second Slice G bug fix: the shared session must survive ------
    mock_close.assert_not_called()

    assert result.prompts_used == 1
    assert result.outcome == "SUCCESS"
    claim = result.ssg.current_claim("sensitive_data_exfiltrated")
    assert claim is not None
    assert claim.status == ClaimStatus.CONFIRMED
    assert result.execution_log[0].overall_success is True


def test_secret_operator_survives_a_target_failure_without_crashing_the_campaign():
    op = _deep_attack_op(
        "secret_jailbreak_exfiltration",
        cost_prompts=1,
        attack_kwargs={"domain": "HR records", "max_queries": 1},
    )
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm graceful degradation through a real campaign",
        success_criteria=("sensitive_data_exfiltrated",),
        budget=1, risk_threshold=RiskTier.MEDIUM, constraints=(),
    )

    endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    agent = HTTPAgentAdapter(endpoint)

    # Preflight check_reachable() fails BEFORE _ensure_jailbreak_artifact is
    # ever reached (secret.py's own control flow), so no further mocking is
    # needed -- same minimal-failure-path shape as IKEA's own equivalent test.
    with patch.object(AgentEndpoint, "check_reachable", return_value=False):
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    assert result.prompts_used == 1
    assert result.execution_log[0].overall_success is False
    assert "RuntimeError" in result.execution_log[0].reasoning
    assert result.ssg.current_claim("sensitive_data_exfiltrated") is None


# ---------------------------------------------------------------------------
# Interrogation / MIA (Slice G)
# ---------------------------------------------------------------------------

def test_mia_operator_runs_through_a_real_campaign_sharing_one_session():
    # _run_stage_abc_for_document is patched at the CLASS level (this test
    # never gets a handle on the internally-factory-constructed
    # InterrogationAttack instance) -- same technique
    # tests/unit/test_interrogation.py's own TestExecuteBlackBox uses at
    # the INSTANCE level for its equivalent full-loop orchestration tests.
    # Captures the `endpoint` argument it's called with (calibration AND
    # the real candidate document both route through this one function) as
    # a second, more direct proof of session identity than the
    # AgentEndpoint-construction spy alone provides for this attack.
    seen_endpoints = []

    def fake_stage_abc(self, endpoint, doc_text, doc_title=""):
        seen_endpoints.append(endpoint)
        if doc_text == "member candidate text":
            return 1.0, "s*", [
                {"probe_question": "Q?", "composed_query": "s* Q?", "shadow_answer": "yes",
                 "target_response": "Yes.", "target_answer": "yes", "match": True},
            ]
        return 0.0, "s*", [
            {"probe_question": "Q?", "composed_query": "s* Q?", "shadow_answer": "yes",
             "target_response": "No.", "target_answer": "no", "match": False},
        ]

    op = _deep_attack_op(
        "mia_membership_inference",
        cost_prompts=1,
        attack_kwargs={"documents": [{"id": "candidate_member", "text": "member candidate text"}]},
    )
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm the MIA deep-attack Operator wiring works end to end",
        success_criteria=("membership_confirmed",),
        budget=1, risk_threshold=RiskTier.MEDIUM, constraints=(),
    )

    spy_init, constructed_endpoints = _spy_on_endpoint_construction()
    with patch.object(AgentEndpoint, "__init__", spy_init):
        endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    agent = HTTPAgentAdapter(endpoint)

    with patch.object(AgentEndpoint, "__init__", spy_init), \
         patch.object(AgentEndpoint, "check_reachable", return_value=True), \
         patch.object(AgentEndpoint, "close") as mock_close, \
         patch.object(InterrogationAttack, "_run_stage_abc_for_document", fake_stage_abc):
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    # -- Session reuse: no second AgentEndpoint constructed ----------------
    assert constructed_endpoints == [endpoint]
    # -- Every call into Stage A/B/C (calibration + the real candidate) ---
    # received the SAME shared endpoint object, not an independently
    # constructed one.
    assert seen_endpoints  # at least one call happened
    assert all(ep is endpoint for ep in seen_endpoints)
    # -- The second Slice G bug fix: the shared session must survive ------
    mock_close.assert_not_called()

    assert result.prompts_used == 1
    assert result.outcome == "SUCCESS"
    claim = result.ssg.current_claim("membership_confirmed")
    assert claim is not None
    assert claim.status == ClaimStatus.CONFIRMED
    assert result.execution_log[0].overall_success is True


def test_mia_operator_survives_a_target_failure_without_crashing_the_campaign():
    op = _deep_attack_op(
        "mia_membership_inference",
        cost_prompts=1,
        attack_kwargs={"documents": [{"id": "candidate_member", "text": "member candidate text"}]},
    )
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm graceful degradation through a real campaign",
        success_criteria=("membership_confirmed",),
        budget=1, risk_threshold=RiskTier.MEDIUM, constraints=(),
    )

    endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    agent = HTTPAgentAdapter(endpoint)

    with patch.object(AgentEndpoint, "check_reachable", return_value=False):
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    assert result.prompts_used == 1
    assert result.execution_log[0].overall_success is False
    assert "RuntimeError" in result.execution_log[0].reasoning
    assert result.ssg.current_claim("membership_confirmed") is None


# ---------------------------------------------------------------------------
# SPE-LLM (Slice G)
# ---------------------------------------------------------------------------

def test_spe_operator_runs_through_a_real_campaign_sharing_one_session():
    # SPE-LLM is LLM-less (no litellm mocking needed at all) -- the only
    # thing to fake is the target's own chat response. Chosen to trip the
    # heuristic classifier's "confirmed" path: not a refusal phrase, >50
    # chars, contains several instructional keywords.
    fake_response = (
        "You are a helpful HR assistant. Your system instructions define your "
        "role, context, and response guidelines for assisting employees."
    )

    op = _deep_attack_op("spe_system_prompt_extraction", cost_prompts=1)
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm the SPE deep-attack Operator wiring works end to end",
        success_criteria=("system_prompt_disclosed",),
        budget=1, risk_threshold=RiskTier.LOW, constraints=(),
    )

    spy_init, constructed_endpoints = _spy_on_endpoint_construction()
    with patch.object(AgentEndpoint, "__init__", spy_init):
        endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    agent = HTTPAgentAdapter(endpoint)

    with patch.object(AgentEndpoint, "__init__", spy_init), \
         patch.object(AgentEndpoint, "check_reachable", return_value=True), \
         patch.object(AgentEndpoint, "chat", return_value=fake_response), \
         patch.object(AgentEndpoint, "close") as mock_close:
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    # -- Session reuse: no second AgentEndpoint constructed ----------------
    assert constructed_endpoints == [endpoint]
    # -- The second Slice G bug fix: the shared session must survive ------
    # (this is the exact attack where the bug was FIRST found -- see
    # deep_attack_operators.py's own docstring -- so this assertion is the
    # most directly load-bearing one in this whole file.)
    mock_close.assert_not_called()

    assert result.prompts_used == 1
    assert result.outcome == "SUCCESS"
    claim = result.ssg.current_claim("system_prompt_disclosed")
    assert claim is not None
    assert claim.status == ClaimStatus.CONFIRMED
    assert result.execution_log[0].overall_success is True


def test_spe_operator_survives_a_target_failure_without_crashing_the_campaign():
    op = _deep_attack_op("spe_system_prompt_extraction", cost_prompts=1)
    library = OperatorLibrary([op])
    mission = Mission(
        goal="confirm graceful degradation through a real campaign",
        success_criteria=("system_prompt_disclosed",),
        budget=1, risk_threshold=RiskTier.LOW, constraints=(),
    )

    endpoint = AgentEndpoint(base_url="http://fake-target:8001")
    agent = HTTPAgentAdapter(endpoint)

    with patch.object(AgentEndpoint, "check_reachable", return_value=False):
        result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=1)

    assert result.prompts_used == 1
    assert result.execution_log[0].overall_success is False
    assert "RuntimeError" in result.execution_log[0].reasoning
    assert result.ssg.current_claim("system_prompt_disclosed") is None
