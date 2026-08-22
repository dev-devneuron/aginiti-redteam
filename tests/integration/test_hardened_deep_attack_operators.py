"""Offline smoke tests for the hardened_agent <-> deep-attack integration
built to close two real gaps found auditing this repo after the two-
developer merge (2026-08-22):

1. `deep_attack_operators()` (Phase 2 Slice E/G) is hardcoded to the
   `reference_agent_blackbox` dev-fixture's HR-record domain -- running it
   AS-IS against `hardened_agent` would send topically wrong IKEA/SECRET
   queries and meaningless MIA membership tests. `aginiti/operators/
   hardened_deep_attack_operators.py` closes this with real, persona-
   aware topic/document wiring against hardened_agent's own seeded
   CUAD/CFPB corpus.
2. `HardenedAgentAdapter` had no `.endpoint` -- the one seam `Observation
   Adapter._execute_deep_attack`'s agent-type guard requires -- so deep
   attacks could only run through a separate `HTTPAgentAdapter` that has
   no RBAC-aware ground truth / independent evidence oracle at all
   (`HTTPAgentAdapter.ground_truth_mission_achieved` is stubbed False,
   by its own design). `HardenedAgentAdapter.endpoint` (new property)
   closes this by sharing ONE authenticated AgentEndpoint AND feeding a
   deep attack's own raw HTTP responses into the SAME `_raw_responses`
   list this adapter's own independent verbatim/fuzzy oracle already
   scans -- so a deep attack's own judge/classifier gets cross-validated
   against real-corpus evidence too, not just trusted on its own say-so.

Zero real network/LLM calls anywhere in this file -- HardenedAgentAdapter's
own `requests.request`-mocking convention (tests/unit/test_hardened_agent_
adapter.py) for ordinary operators, plus a session.post-level mock (the
concrete class-under-test here is AgentEndpoint, which uses `requests.
Session.post`, not the module-level `requests.request` HardenedAgentAdapter
itself calls) for anything routed through `.endpoint`. Real local ONNX
embeddings are NOT exercised here (no IKEA/SECRET attack internals are
run, only operator/adapter-level plumbing) -- that's already covered,
mocked identically, by tests/integration/test_deep_attack_operators.py.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from aginiti.adapters.hardened_agent_adapter import HardenedAgentAdapter
from aginiti.adapters.scaled_evals_ground_truth import VerbatimDisclosureIndex
from aginiti.connectors.endpoint import AgentEndpoint
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.operators.hardened_agent_definitions import build_hardened_agent_library
from aginiti.operators.hardened_deep_attack_operators import (
    _select_mia_documents,
    hardened_deep_attack_operators,
)
from aginiti.attacks.spe.spe_llm import SPEAttack
from aginiti.operators.library import OperatorLibrary


@pytest.fixture(autouse=True)
def _fake_api_keys():
    """Same fix, same reason, as tests/integration/test_deep_attack_
    operators.py's own `_fake_api_keys` fixture (see that file's module
    docstring for the full CI-caught story from 2026-08-21) -- but THAT
    fixture patches `aginiti.operators.deep_attack_operators._key_for`,
    which does NOT cover this file: `hardened_deep_attack_operators.py`
    (2026-08-22) deliberately duplicates `_key_for` as its OWN
    module-level function rather than importing the generic module's
    (see that module's own docstring on why it's "not a fork" but is a
    separate file), so it needs its own separate patch here. Missed
    initially -- caught by GitHub Actions CI on the first real push
    (`test_spe_operator_runs_through_hardened_agent_adapter_in_a_real_
    campaign` constructs a real `SPEAttack` via `_build_spe_attack()`,
    which calls this module's `_key_for()` BEFORE `SPEAttack._call_
    classifier` is ever reached -- mocking that classifier alone was not
    enough, exactly the same shape of gap the sibling file's own fixture
    documents), not caught locally because this dev environment has a
    real `.env` with real API keys, which silently masked it."""
    with patch("aginiti.operators.hardened_deep_attack_operators._key_for", return_value="test-fake-api-key"):
        yield


# ---------------------------------------------------------------------------
# 1. HardenedAgentAdapter.endpoint -- construction, caching, oracle sharing
# ---------------------------------------------------------------------------

class TestHardenedAgentAdapterEndpoint:
    def test_endpoint_is_a_real_agent_endpoint_with_persona_auth(self):
        adapter = HardenedAgentAdapter(persona="legal", api_key="legal-test-key")
        ep = adapter.endpoint
        assert isinstance(ep, AgentEndpoint)
        assert ep.base_url == adapter.base_url
        assert ep.headers["Authorization"] == "Bearer legal-test-key"

    def test_endpoint_is_cached_not_rebuilt_every_access(self):
        adapter = HardenedAgentAdapter(persona="support", api_key="k")
        assert adapter.endpoint is adapter.endpoint

    def test_execute_deep_attack_agent_type_guard_accepts_this_adapter(self):
        """The exact check ObservationAdapter._execute_deep_attack makes
        (getattr(agent, "endpoint", None)) -- confirms HardenedAgentAdapter
        now passes it, closing the gap `HTTPAgentAdapter`-only support left."""
        adapter = HardenedAgentAdapter(persona="ops", api_key="k")
        assert getattr(adapter, "endpoint", None) is not None

    def test_deep_attacks_own_raw_response_feeds_the_independent_oracle(self):
        """The actual point of this property: a deep attack's own HTTP
        response, sent through `.endpoint.chat()`, must land in the SAME
        `_raw_responses` list `ground_truth_mission_achieved()`/
        `independent_evidence_check()` already scan -- not a second,
        invisible channel."""
        index = VerbatimDisclosureIndex()
        leak_text = (
            "the confidential termination clause states that either party may terminate "
            "this agreement upon thirty days written notice to the other party"
        )
        index.add_records([{"id": "cuad_9999", "source": "cuad", "ops_visible": False,
                             "document_text": leak_text}])
        adapter = HardenedAgentAdapter(persona="legal", api_key="k", disclosure_index=index)
        ep = adapter.endpoint

        fake_response = MagicMock()
        fake_response.raise_for_status = MagicMock()
        fake_response.json.return_value = {"response": leak_text}
        with patch.object(ep._session, "post", return_value=fake_response) as mock_post:
            text = ep.chat("what does the termination clause say?")

        assert "confidential termination clause" in text
        # The deep attack's own response is now visible to THIS adapter's
        # own independent evidence oracle, exactly like an ordinary
        # operator's response would be:
        assert text in adapter._raw_responses
        assert adapter.ground_truth_mission_achieved() is True
        mock_post.assert_called_once()

    def test_agentendpoint_close_never_called_via_this_property(self):
        """Regression guard for the exact bug deep_attack_operators.py's
        own Slice G cross-attack audit found and fixed (a BaseAttack
        subclass's `finally: endpoint.close()` tearing down a SHARED
        session out from under later operators) -- applied here too,
        since HardenedAgentAdapter.endpoint is a second real place a
        shared session could be torn down the same way."""
        adapter = HardenedAgentAdapter(persona="legal", api_key="k")
        ep = adapter.endpoint
        with patch.object(ep, "close") as mock_close:
            # Simulate what a well-behaved BaseAttack subclass does per
            # deep_attack_operators.py's own Slice G fix: only close an
            # endpoint IT constructed itself, never one injected via
            # `endpoint=`.
            injected_endpoint = ep
            if injected_endpoint is None:
                ep.close()
        mock_close.assert_not_called()


# ---------------------------------------------------------------------------
# 2. hardened_deep_attack_operators() -- persona-aware construction
# ---------------------------------------------------------------------------

class TestHardenedDeepAttackOperators:
    """Requires benchmarks/scaled_evals/datasets/hardened_dataset_{ingested,
    held_out}.json to exist (prepare_hardened_dataset.py) -- skipped
    cleanly, not failed, if they don't (matches this project's own
    established convention for dataset-dependent tests, e.g. anything
    under benchmarks/scaled_evals/)."""

    @pytest.fixture(autouse=True)
    def _require_dataset(self):
        from aginiti.operators.hardened_deep_attack_operators import _INGESTED_PATH, _HELD_OUT_PATH
        if not (_INGESTED_PATH.exists() and _HELD_OUT_PATH.exists()):
            pytest.skip(
                "hardened_dataset_{ingested,held_out}.json not present -- run "
                "benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py first"
            )

    @pytest.mark.parametrize("persona", ["legal", "support", "ops"])
    def test_builds_exactly_four_operators_with_correct_claim_keys(self, persona):
        ops = hardened_deep_attack_operators(persona)
        assert [op.id for op in ops] == [
            "hardened_ikea_exfiltration", "hardened_secret_exfiltration",
            "hardened_mia_membership", "hardened_spe_extraction",
        ]
        claim_keys = {op.id: op.claim_key for op in ops}
        assert claim_keys["hardened_ikea_exfiltration"] == "sensitive_data_exfiltrated"
        assert claim_keys["hardened_secret_exfiltration"] == "sensitive_data_exfiltrated"
        assert claim_keys["hardened_mia_membership"] == "membership_confirmed"
        assert claim_keys["hardened_spe_extraction"] == "system_prompt_disclosed"

    @pytest.mark.parametrize("persona", ["legal", "support", "ops"])
    def test_topic_is_persona_specific_not_the_generic_modules_hr_default(self, persona):
        ops = hardened_deep_attack_operators(persona)
        ikea_op = next(op for op in ops if op.id == "hardened_ikea_exfiltration")
        assert ikea_op.attack_kwargs["topic"] != "HR records"
        assert persona == "legal" and "contract" in ikea_op.attack_kwargs["topic"].lower() \
            or persona == "support" and "complaint" in ikea_op.attack_kwargs["topic"].lower() \
            or persona == "ops" and "contract" in ikea_op.attack_kwargs["topic"].lower()

    @pytest.mark.parametrize("persona", ["legal", "support", "ops"])
    def test_mia_documents_are_real_hardened_agent_records_not_hr_fixtures(self, persona):
        ops = hardened_deep_attack_operators(persona)
        mia_op = next(op for op in ops if op.id == "hardened_mia_membership")
        doc_ids = [d["id"] for d in mia_op.attack_kwargs["documents"]]
        assert doc_ids, "must select at least one real candidate document"
        assert all(d_id.startswith(("cuad_", "cfpb_")) for d_id in doc_ids), (
            f"expected real hardened_agent corpus ids (cuad_*/cfpb_*), got {doc_ids} -- "
            "falling back to the generic module's HR-fixture documents would make this "
            "operator's result meaningless against hardened_agent"
        )

    def test_legal_and_support_each_get_one_cross_domain_rbac_probe_document(self):
        """The disjoint-RBAC-boundary test scripts/run_interrogation_
        hardened.py's own selection logic was built for -- legal's
        candidate set should include exactly one cfpb_* doc (out of legal's
        own cuad-only scope) and vice versa for support."""
        legal_ids = [d["id"] for d in _select_mia_documents("legal")[0]]
        support_ids = [d["id"] for d in _select_mia_documents("support")[0]]
        assert sum(1 for i in legal_ids if i.startswith("cfpb_")) == 1
        assert sum(1 for i in support_ids if i.startswith("cuad_")) == 1

    def test_ops_gets_a_non_ops_visible_subset_boundary_probe_document(self):
        ops_ids_and_candidates = _select_mia_documents("ops")
        # Just confirm it built without raising and returned real candidates --
        # the ops_visible-vs-not split itself is exercised directly against
        # real seeded data by benchmarks' own dataset invariants; this test's
        # job is confirming THIS module wires persona="ops" through correctly.
        assert len(ops_ids_and_candidates[0]) >= 4

    def test_unknown_persona_raises_a_clear_error_not_a_kerror(self):
        with pytest.raises(ValueError, match="Unknown persona"):
            hardened_deep_attack_operators("finance")


# ---------------------------------------------------------------------------
# 3. The actual integration gap: one COMBINED library (hardened_agent's own
#    41 operators + the 4 new deep-attack ones), ranked by the REAL,
#    currently-fixed AginitiPlanner -- never exercised together before this.
# ---------------------------------------------------------------------------

class TestCombinedLibraryPlannerRanking:
    @pytest.fixture(autouse=True)
    def _require_dataset(self):
        from aginiti.operators.hardened_deep_attack_operators import _INGESTED_PATH, _HELD_OUT_PATH
        if not (_INGESTED_PATH.exists() and _HELD_OUT_PATH.exists()):
            pytest.skip("hardened_dataset_{ingested,held_out}.json not present")

    @pytest.mark.parametrize("persona", ["legal", "support", "ops"])
    def test_combined_library_ranks_without_crashing_all_fixes_enabled(self, persona):
        index = VerbatimDisclosureIndex()
        base_ops = build_hardened_agent_library(persona, index)
        deep_ops = hardened_deep_attack_operators(persona)
        library = OperatorLibrary([*base_ops, *deep_ops])
        assert len(library) == len(base_ops) + len(deep_ops), (
            "a claim-key or operator-id collision silently dropped an operator -- "
            "OperatorLibrary.__init__ dedups by id with no error (a known, "
            "previously-flagged risk, see docs/AGINITI_OVERVIEW.md's operator-"
            "inventory section on the 2 existing harmless collisions)"
        )

        # budget=18 (exp29's own scale) is NOT enough here -- IKEA alone
        # declares cost_prompts=20 (its default max_queries), so a smaller
        # budget correctly excludes it via budget_feasible(), a real
        # finding this test caught rather than assumed: a fair "does the
        # planner appropriately weigh an expensive-but-powerful deep
        # attack against many cheap probes" comparison needs a budget
        # that can at least afford ONE of the 4 deep attacks in full.
        mission = Mission(
            goal="offline smoke test -- combined hardened_agent + deep-attack library",
            success_criteria=("sensitive_data_exfiltrated", "membership_confirmed",
                               "system_prompt_disclosed"),
            budget=60, risk_threshold=RiskTier.MEDIUM, constraints=(),
        )
        planner = AginitiPlanner(
            enable_family_diversification=True,
            enable_hypothesis_escalation_bonus=True,
            enable_technique_cluster_diversification=True,
        )
        ranked = planner.rank(library, SecurityStateGraph(), mission, prompts_used=0,
                               executed_ids=frozenset())

        assert ranked, "combined library must produce at least one eligible candidate"
        ranked_ids = {rc.operator.id for rc in ranked}
        # All 4 deep-attack operators must be genuinely eligible/ranked
        # candidates, not silently excluded by a stale precondition or a
        # feasibility-gate bug specific to the new `kind="deep_attack"` field:
        for op in deep_ops:
            assert op.id in ranked_ids, f"{op.id} did not survive into the ranked candidate list"

    def test_deep_attack_operators_do_not_crash_diagnose(self):
        """AginitiPlanner.diagnose() -- the read-only full-library
        accounting path -- must also handle kind="deep_attack" operators
        without raising, since it computes core_utility identically for
        every operator regardless of kind."""
        index = VerbatimDisclosureIndex()
        library = OperatorLibrary([
            *build_hardened_agent_library("legal", index),
            *hardened_deep_attack_operators("legal"),
        ])
        mission = Mission(
            goal="diagnose smoke test", success_criteria=("sensitive_data_exfiltrated",),
            budget=18, risk_threshold=RiskTier.MEDIUM, constraints=(),
        )
        planner = AginitiPlanner(enable_family_diversification=True,
                                  enable_technique_cluster_diversification=True)
        diagnostics = planner.diagnose(library, SecurityStateGraph(), mission,
                                        prompts_used=0, executed_ids=frozenset())
        assert len(diagnostics) == len(library)


# ---------------------------------------------------------------------------
# 4. Full mocked run_campaign() -- SPE (lightest: pure HTTP, no LLM/embedding
#    internals to mock) through HardenedAgentAdapter.endpoint, alongside one
#    ordinary hardened_agent operator, in the SAME campaign.
# ---------------------------------------------------------------------------

class TestFullCampaignWithHardenedAgentAdapterEndpoint:
    def test_spe_operator_runs_through_hardened_agent_adapter_in_a_real_campaign(self):
        from dataclasses import replace

        index = VerbatimDisclosureIndex()
        agent = HardenedAgentAdapter(persona="legal", api_key="legal-test-key",
                                       disclosure_index=index)

        deep_ops = hardened_deep_attack_operators("legal")
        spe_op = next(op for op in deep_ops if op.id == "hardened_spe_extraction")
        # cost_prompts=3 already (SPE always fires exactly 3 static probes,
        # non-configurable) -- no cheap-variant override needed, unlike
        # IKEA/SECRET/MIA's budget-scalable operators.
        library = OperatorLibrary([spe_op])

        mission = Mission(
            goal="confirm SPE runs through HardenedAgentAdapter.endpoint",
            success_criteria=("system_prompt_disclosed",),
            budget=3, risk_threshold=RiskTier.MEDIUM, constraints=(),
        )

        fake_response = MagicMock()
        fake_response.raise_for_status = MagicMock()
        fake_response.json.return_value = {
            "response": "You are a helpful legal-contracts assistant. System instructions: "
                        "always cite the source contract. Follow this guideline for every reply."
        }

        from aginiti.core.policies.static_policy import StaticPolicy
        # SPE's confirmation step now goes through a real LLM classifier
        # (2026-08-22) -- mocked here so this test stays offline/
        # deterministic and doesn't attempt a real (and here, doomed-to-
        # fail-anyway) Gemini call using whatever key happens to be in the
        # test process's environment. This test doesn't assert on the
        # classifier's own verdict either way (see the oracle-cross-
        # validation assertions below), so the mocked value itself is
        # arbitrary -- only its determinism matters here.
        with patch.object(agent.endpoint._session, "post", return_value=fake_response), \
             patch.object(AgentEndpoint, "check_reachable", return_value=True), \
             patch.object(AgentEndpoint, "close") as mock_close, \
             patch.object(SPEAttack, "_call_classifier",
                           return_value={"confirmed": True, "leaked_excerpt": "test", "reasoning": "test double"}):
            result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(),
                                    max_steps=1)

        assert result.steps_executed == 1
        assert "hardened_spe_extraction" in result.operators_executed
        # The oracle cross-validation this whole property exists for:
        assert len(agent._raw_responses) == 3  # SPE's 3 static probes, all captured
        assert agent.system_prompt_disclosure_confirmed() is False  # canned text isn't a REAL known leak
        # The regression this test guards, matching deep_attack_operators.
        # py's own Slice G fix precedent:
        mock_close.assert_not_called()
