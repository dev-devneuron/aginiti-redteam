from aginiti.graph.attack_category import (
    ALL_CATEGORIES,
    CATEGORY_TITLES,
    DECOY,
    DIRECT_PROMPT_ATTACK,
    ENCODING_ATTACK,
    INDIRECT_INJECTION,
    KNOWN_DEFENDED,
    LOW_VALUE_RECONNAISSANCE,
    MULTI_STEP_CHAIN,
    OFFENSIVE_CATEGORIES,
    RAG_POISONING,
    TOOL_DISCOVERY,
    TOOL_MANIPULATION,
    is_offensive,
    validate,
)
from aginiti.graph.mitre_atlas_refs import (
    DIRECT_PROMPT_INJECTION,
    EXFILTRATION_VIA_TOOL_INVOCATION,
    LLM_JAILBREAK,
    RAG_POISONING as ATLAS_RAG_POISONING,
)
from aginiti.graph.mitre_atlas_refs import validate as validate_atlas
from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.anythingllm_automatic_definitions import build_anythingllm_automatic_library
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.definitions import build_library
from aginiti.operators.dvaa_definitions import build_dvaa_library
from aginiti.operators.encoding_variants import build_encoding_evasion_operators


# --- pure taxonomy logic -----------------------------------------------------

def test_all_eleven_categories_present_and_unique():
    assert len(ALL_CATEGORIES) == 11
    assert len(set(ALL_CATEGORIES)) == 11


def test_every_category_has_a_title():
    for category in ALL_CATEGORIES:
        assert category in CATEGORY_TITLES and CATEGORY_TITLES[category]


def test_validate_accepts_real_categories_and_rejects_junk():
    assert validate(DIRECT_PROMPT_ATTACK) is True
    assert validate("not_a_real_category") is False


def test_offensive_categories_exclude_the_three_planner_controls():
    assert DECOY not in OFFENSIVE_CATEGORIES
    assert KNOWN_DEFENDED not in OFFENSIVE_CATEGORIES
    assert LOW_VALUE_RECONNAISSANCE not in OFFENSIVE_CATEGORIES
    assert len(OFFENSIVE_CATEGORIES) == 8


def test_is_offensive_matches_the_offensive_categories_tuple():
    assert is_offensive(ENCODING_ATTACK) is True
    assert is_offensive(DECOY) is False


def test_mitre_atlas_validate_accepts_only_verified_ids():
    assert validate_atlas(DIRECT_PROMPT_INJECTION) is True
    assert validate_atlas("AML.T9999") is False


# --- SecurityStateGraph wiring ------------------------------------------------

def test_assert_claim_records_attack_category_and_atlas_technique_only_when_given():
    ssg = SecurityStateGraph()
    ssg.assert_claim("bare_key", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("tagged_key", "true", ClaimStatus.CONFIRMED,
                      attack_category=ENCODING_ATTACK, mitre_atlas_technique=DIRECT_PROMPT_INJECTION)
    assert "bare_key" not in ssg.claim_attack_category
    assert "bare_key" not in ssg.claim_atlas_technique
    assert ssg.claim_attack_category["tagged_key"] == ENCODING_ATTACK
    assert ssg.claim_atlas_technique["tagged_key"] == DIRECT_PROMPT_INJECTION


def test_confirmed_attack_categories_excludes_unconfirmed_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("hyp_key", "true", ClaimStatus.HYPOTHESIZED, attack_category=RAG_POISONING)
    ssg.assert_claim("confirmed_key", "true", ClaimStatus.CONFIRMED, attack_category=TOOL_MANIPULATION)
    confirmed = ssg.confirmed_attack_categories()
    assert "hyp_key" not in confirmed
    assert confirmed["confirmed_key"] == TOOL_MANIPULATION


def test_confirmed_attack_categories_reflects_latest_status_after_supersession():
    ssg = SecurityStateGraph()
    ssg.assert_claim("flappy_key", "true", ClaimStatus.CONFIRMED, attack_category=MULTI_STEP_CHAIN)
    assert "flappy_key" in ssg.confirmed_attack_categories()
    ssg.assert_claim("flappy_key", "false", ClaimStatus.REFUTED)
    assert "flappy_key" not in ssg.confirmed_attack_categories()


def test_attack_category_summary_counts_confirmed_claims_per_category():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED, attack_category=ENCODING_ATTACK)
    ssg.assert_claim("k2", "true", ClaimStatus.CONFIRMED, attack_category=ENCODING_ATTACK)
    ssg.assert_claim("k3", "true", ClaimStatus.CONFIRMED, attack_category=DECOY)
    ssg.assert_claim("k4", "true", ClaimStatus.HYPOTHESIZED, attack_category=RAG_POISONING)
    assert ssg.attack_category_summary() == {ENCODING_ATTACK: 2, DECOY: 1}


def test_confirmed_atlas_techniques_excludes_unconfirmed_claims():
    ssg = SecurityStateGraph()
    ssg.assert_claim("hyp_key", "true", ClaimStatus.HYPOTHESIZED, mitre_atlas_technique=LLM_JAILBREAK)
    ssg.assert_claim("confirmed_key", "true", ClaimStatus.CONFIRMED, mitre_atlas_technique=ATLAS_RAG_POISONING)
    confirmed = ssg.confirmed_atlas_techniques()
    assert "hyp_key" not in confirmed
    assert confirmed["confirmed_key"] == ATLAS_RAG_POISONING


# --- real operator library retrofit -------------------------------------------

def test_tool_inventory_full_disclosure_is_tagged_tool_discovery():
    op = next(op for op in data_exposure_operators() if op.id == "tool_inventory_full_disclosure")
    assert op.effects_success[0].attack_category == TOOL_DISCOVERY


def test_memory_context_leakage_probe_is_tagged_known_defended():
    op = next(op for op in data_exposure_operators() if op.id == "memory_context_leakage_probe")
    assert op.effects_success[0].attack_category == KNOWN_DEFENDED


def test_jailbreak_dan_style_is_tagged_direct_prompt_attack_and_atlas_jailbreak():
    op = next(op for op in data_exposure_operators() if op.id == "jailbreak_dan_style")
    effect = op.effects_success[0]
    assert effect.attack_category == DIRECT_PROMPT_ATTACK
    assert effect.mitre_atlas_technique == LLM_JAILBREAK


def test_tool_parameter_override_probe_is_tagged_tool_manipulation():
    op = next(op for op in data_exposure_operators() if op.id == "tool_parameter_override_probe")
    assert op.effects_success[0].attack_category == TOOL_MANIPULATION


def test_rag_chain_plant_is_rag_poisoning_and_trigger_is_indirect_injection():
    plant = next(op for op in build_anythingllm_library("X") if op.id == "anythingllm_rag_document_plant")
    trigger = next(op for op in build_anythingllm_library("X") if op.id == "anythingllm_rag_injection_trigger")
    assert plant.effects_success[0].attack_category == RAG_POISONING
    assert plant.effects_success[0].mitre_atlas_technique == ATLAS_RAG_POISONING
    assert trigger.effects_success[0].attack_category == INDIRECT_INJECTION


def test_automatic_chain_trigger_is_tagged_with_verified_exfil_technique():
    trigger = next(op for op in build_anythingllm_automatic_library("X", "http://listener")
                   if op.id == "anythingllm_automatic_indirect_tool_exfil_trigger")
    assert trigger.effects_success[0].mitre_atlas_technique == EXFILTRATION_VIA_TOOL_INVOCATION


def test_mcp_tool_discovery_is_tagged_tool_discovery():
    op = next(op for op in build_dvaa_library() if op.id == "mcp_tool_discovery")
    assert op.effects_success[0].attack_category == TOOL_DISCOVERY


def test_mcp_exfiltrate_via_plugin_fetch_is_tagged_multi_step_chain_with_verified_exfil_technique():
    # The tool-chaining composition attack (STAC, arXiv:2509.25624): a real 2-step
    # cross-tool chain (mcp_execute_read_secret_config -> this operator), the DVAA
    # analogue of anythingllm_multitool_definitions.py's MULTI_STEP_CHAIN tag.
    op = next(op for op in build_dvaa_library() if op.id == "mcp_exfiltrate_via_plugin_fetch")
    effect = op.effects_success[0]
    assert effect.attack_category == MULTI_STEP_CHAIN
    assert effect.mitre_atlas_technique == EXFILTRATION_VIA_TOOL_INVOCATION


def test_mock_library_decoys_are_tagged_decoy():
    decoys = {op.id: op for op in build_library() if op.branch == "decoy"}
    assert set(decoys) == {"probe_unrelated_capability", "recon_general_smalltalk", "probe_defunct_channel"}
    for op in decoys.values():
        assert op.effects_success[0].attack_category == DECOY


def test_mock_library_recon_operators_are_tagged_low_value_reconnaissance():
    recon = next(op for op in build_library() if op.id == "recon_capabilities")
    assert recon.effects_success[0].attack_category == LOW_VALUE_RECONNAISSANCE


def test_encoding_variants_are_tagged_encoding_attack_with_direct_injection_technique():
    ops = build_encoding_evasion_operators()
    for op in ops:
        effect = op.effects_success[0]
        assert effect.attack_category == ENCODING_ATTACK
        assert effect.mitre_atlas_technique == DIRECT_PROMPT_INJECTION


# --- end-to-end through the real adapter path ---------------------------------

def test_observation_adapter_propagates_attack_category_and_atlas_technique():
    from aginiti.adapter.observation_adapter import ObservationAdapter, _effect_id
    from aginiti.adapters.base import SendResult
    from aginiti.operators.library import ClaimEffect, Operator

    effect = ClaimEffect("attack_cat_test_claim", ClaimStatus.CONFIRMED,
                          attack_category=RAG_POISONING, mitre_atlas_technique=ATLAS_RAG_POISONING)
    op = Operator(
        id="attack_cat_test_op", description="test", prompt="x", channel="direct", preconditions=(),
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
    assert ssg.claim_attack_category.get("attack_cat_test_claim") == RAG_POISONING
    assert ssg.claim_atlas_technique.get("attack_cat_test_claim") == ATLAS_RAG_POISONING
