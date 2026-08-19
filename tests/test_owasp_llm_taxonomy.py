from aginiti.core.graph.owasp_llm_taxonomy import (
    ALL_CATEGORIES,
    CATEGORY_TITLES,
    LLM01_PROMPT_INJECTION,
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
    LLM05_IMPROPER_OUTPUT_HANDLING,
    LLM06_EXCESSIVE_AGENCY,
    LLM07_SYSTEM_PROMPT_LEAKAGE,
    LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES,
    validate,
)
from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.anythingllm_automatic_definitions import build_anythingllm_automatic_library
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.anythingllm_markdown_exfil_definitions import build_anythingllm_markdown_exfil_library
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.dvaa_definitions import build_dvaa_library


# --- pure taxonomy logic -----------------------------------------------------

def test_all_categories_are_the_ten_2025_owasp_llm_categories():
    assert len(ALL_CATEGORIES) == 10
    assert len(set(ALL_CATEGORIES)) == 10  # no duplicates


def test_every_category_has_a_title():
    for category in ALL_CATEGORIES:
        assert category in CATEGORY_TITLES
        assert CATEGORY_TITLES[category]


def test_validate_accepts_real_categories_and_rejects_junk():
    assert validate(LLM01_PROMPT_INJECTION) is True
    assert validate("not_a_real_category") is False


# --- SecurityStateGraph wiring ------------------------------------------------

def test_assert_claim_records_owasp_category_only_when_given():
    ssg = SecurityStateGraph()
    ssg.assert_claim("no_owasp_key", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("tagged_key", "true", ClaimStatus.CONFIRMED, owasp_llm_category=LLM01_PROMPT_INJECTION)
    assert "no_owasp_key" not in ssg.claim_owasp_category
    assert ssg.claim_owasp_category["tagged_key"] == LLM01_PROMPT_INJECTION


def test_confirmed_owasp_categories_excludes_unconfirmed_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("hyp_key", "true", ClaimStatus.HYPOTHESIZED, owasp_llm_category=LLM02_SENSITIVE_INFORMATION_DISCLOSURE)
    ssg.assert_claim("confirmed_key", "true", ClaimStatus.CONFIRMED, owasp_llm_category=LLM07_SYSTEM_PROMPT_LEAKAGE)
    confirmed = ssg.confirmed_owasp_categories()
    assert "hyp_key" not in confirmed
    assert confirmed["confirmed_key"] == LLM07_SYSTEM_PROMPT_LEAKAGE


def test_confirmed_owasp_categories_reflects_the_latest_status_after_supersession():
    ssg = SecurityStateGraph()
    ssg.assert_claim("flappy_key", "true", ClaimStatus.CONFIRMED, owasp_llm_category=LLM06_EXCESSIVE_AGENCY)
    assert "flappy_key" in ssg.confirmed_owasp_categories()
    ssg.assert_claim("flappy_key", "false", ClaimStatus.REFUTED)
    assert "flappy_key" not in ssg.confirmed_owasp_categories()


def test_owasp_category_summary_counts_confirmed_claims_per_category():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED, owasp_llm_category=LLM01_PROMPT_INJECTION)
    ssg.assert_claim("k2", "true", ClaimStatus.CONFIRMED, owasp_llm_category=LLM01_PROMPT_INJECTION)
    ssg.assert_claim("k3", "true", ClaimStatus.CONFIRMED, owasp_llm_category=LLM07_SYSTEM_PROMPT_LEAKAGE)
    ssg.assert_claim("k4", "true", ClaimStatus.HYPOTHESIZED, owasp_llm_category=LLM02_SENSITIVE_INFORMATION_DISCLOSURE)
    summary = ssg.owasp_category_summary()
    assert summary == {LLM01_PROMPT_INJECTION: 2, LLM07_SYSTEM_PROMPT_LEAKAGE: 1}


def test_owasp_category_summary_is_empty_before_anything_confirmed():
    ssg = SecurityStateGraph()
    assert ssg.owasp_category_summary() == {}


# --- real operator library retrofit -------------------------------------------

def test_system_prompt_extraction_is_tagged_llm07_system_prompt_leakage():
    op = next(op for op in data_exposure_operators() if op.id == "system_prompt_extraction")
    assert op.effects_success[0].owasp_llm_category == LLM07_SYSTEM_PROMPT_LEAKAGE


def test_tool_inventory_full_disclosure_is_tagged_llm02_sensitive_information_disclosure():
    op = next(op for op in data_exposure_operators() if op.id == "tool_inventory_full_disclosure")
    assert op.effects_success[0].owasp_llm_category == LLM02_SENSITIVE_INFORMATION_DISCLOSURE


def test_jailbreak_and_encoding_probes_are_tagged_llm01_prompt_injection():
    dan = next(op for op in data_exposure_operators() if op.id == "jailbreak_dan_style")
    encoding = next(op for op in data_exposure_operators() if op.id == "encoding_evasion_probe")
    assert dan.effects_success[0].owasp_llm_category == LLM01_PROMPT_INJECTION
    assert encoding.effects_success[0].owasp_llm_category == LLM01_PROMPT_INJECTION


def test_rag_chain_plant_is_llm08_vector_and_embedding_weaknesses():
    plant = next(op for op in build_anythingllm_library("X") if op.id == "anythingllm_rag_document_plant")
    assert plant.effects_success[0].owasp_llm_category == LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES


def test_rag_chain_trigger_is_llm01_prompt_injection():
    trigger = next(op for op in build_anythingllm_library("X") if op.id == "anythingllm_rag_injection_trigger")
    assert trigger.effects_success[0].owasp_llm_category == LLM01_PROMPT_INJECTION


def test_automatic_chain_trigger_is_llm06_excessive_agency():
    trigger = next(op for op in build_anythingllm_automatic_library("X", "http://listener")
                   if op.id == "anythingllm_automatic_indirect_tool_exfil_trigger")
    assert trigger.effects_success[0].owasp_llm_category == LLM06_EXCESSIVE_AGENCY


def test_markdown_exfil_trigger_is_llm05_improper_output_handling():
    trigger = next(op for op in build_anythingllm_markdown_exfil_library("X", "http://listener")
                   if op.id == "anythingllm_markdown_image_exfil_trigger")
    assert trigger.effects_success[0].owasp_llm_category == LLM05_IMPROPER_OUTPUT_HANDLING


def test_a2a_identity_spoof_is_tagged_llm06_excessive_agency():
    op = next(op for op in build_dvaa_library() if op.id == "a2a_identity_spoof")
    categories = {e.key: e.owasp_llm_category for e in op.effects_success}
    assert categories["a2a_trusts_claimed_identity"] == LLM06_EXCESSIVE_AGENCY
    assert categories["unauthorized_a2a_access_granted"] == LLM06_EXCESSIVE_AGENCY


# --- end-to-end through the real adapter path (mirrors
# test_security_boundary.py's equivalent test -- exercises the same
# assert_claim call site in ObservationAdapter.execute() that now also
# threads owasp_llm_category through) ------------------------------------

def test_observation_adapter_propagates_owasp_category_onto_the_ssg_claim():
    from aginiti.core.observation_adapter import ObservationAdapter, _effect_id
    from aginiti.adapters.base import SendResult
    from aginiti.operators.library import ClaimEffect, Operator

    effect = ClaimEffect("owasp_test_claim", ClaimStatus.CONFIRMED, owasp_llm_category=LLM02_SENSITIVE_INFORMATION_DISCLOSURE)
    op = Operator(
        id="owasp_test_op", description="test", prompt="x", channel="direct", preconditions=(),
        effects_success=(effect,), effects_failure=(), cost_prompts=1, risk_tier=RiskTier.LOW,
        extractor=lambda raw_signal: [_effect_id(effect)],
    )

    class _StubAdapter:
        def send(self, channel, prompt):
            return SendResult(final_text="it worked")

        def ground_truth_mission_achieved(self):
            return False

    ssg = SecurityStateGraph()
    result = ObservationAdapter().execute(op, ssg, _StubAdapter(), seed=1)

    assert result.overall_success is True
    assert ssg.claim_owasp_category.get("owasp_test_claim") == LLM02_SENSITIVE_INFORMATION_DISCLOSURE
