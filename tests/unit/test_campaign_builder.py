"""
Tests for aginiti/core/campaign_builder.py -- the shared --agent-url/--tier/
--attack-category -> (library, mission, agent) derivation used by both
`aginiti scan` and scripts/run_campaign.py.
"""
from __future__ import annotations

import pytest

from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.core.campaign_builder import (
    CampaignBuildError,
    TIER_CHOICES,
    all_target_agnostic_operators,
    build_campaign,
    classify_tier,
)


class TestBuildCampaignDefaults:
    def test_no_args_returns_the_original_demo_agent_setup(self):
        library, mission, agent = build_campaign()

        assert agent is None  # run_campaign() falls back to DemoAgent itself
        assert list(library)  # non-empty -- build_library()'s own operators
        assert mission.budget > 0

    def test_budget_override_applies_even_on_the_default_path(self):
        _, mission, _ = build_campaign(budget=3)

        assert mission.budget == 3


class TestBuildCampaignAgentUrl:
    def test_agent_url_switches_to_an_http_adapter_and_target_agnostic_library(self):
        library, mission, agent = build_campaign(agent_url="http://localhost:9999")

        assert isinstance(agent, HTTPAgentAdapter)
        # All 8 channel="direct" packs (47 operators), not just the
        # original 2 (data_exposure + deep_attack, 11 operators) --
        # see all_target_agnostic_operators()'s own docstring for why the
        # other 6 were previously missing from a real --target scan.
        assert len(list(library)) == len(all_target_agnostic_operators())
        assert mission.success_criteria  # derived from the loaded operators

    def test_budget_override_applies_on_the_agent_url_path(self):
        _, mission, _ = build_campaign(agent_url="http://localhost:9999", budget=7)

        assert mission.budget == 7


class TestTierFiltering:
    def test_data_leakage_tier_keeps_only_matching_operators(self):
        library, _, _ = build_campaign(agent_url="http://localhost:9999", tier="data_leakage")

        assert list(library)
        assert all(classify_tier(op) == "data_leakage" for op in library)

    def test_full_assessment_tier_applies_no_filter(self):
        filtered, _, _ = build_campaign(agent_url="http://localhost:9999", tier="full_assessment")
        unfiltered, _, _ = build_campaign(agent_url="http://localhost:9999")

        assert len(list(filtered)) == len(list(unfiltered))

    def test_every_advertised_tier_choice_is_a_real_classify_tier_output_or_full_assessment(self):
        # TIER_CHOICES is argparse's `choices=` list -- every value it
        # advertises must be something classify_tier can actually produce
        # (or the escape-hatch "full_assessment"), or --tier X would be a
        # valid CLI flag that can never match anything.
        assert set(TIER_CHOICES) == {
            "data_leakage", "unauthorized_actions", "discovery_recon", "full_assessment",
        }

    def test_full_assessment_tier_includes_all_47_target_agnostic_operators(self):
        library, _, _ = build_campaign(agent_url="http://localhost:9999", tier="full_assessment")

        assert len(list(library)) == len(all_target_agnostic_operators()) == 47

    def test_data_leakage_tier_includes_output_filter_and_session_isolation_operators(self):
        library, _, _ = build_campaign(agent_url="http://localhost:9999", tier="data_leakage")
        ids = {op.id for op in library}

        assert any(i.startswith("output_filter_evasion_") for i in ids)
        assert any(i.startswith("session_isolation_probe_") for i in ids)

    def test_unauthorized_actions_tier_includes_encoding_and_low_resource_evasion_operators(self):
        library, _, _ = build_campaign(agent_url="http://localhost:9999", tier="unauthorized_actions")
        ids = {op.id for op in library}

        assert any(i.startswith("encoding_evasion_probe_") for i in ids)
        assert any(i.startswith("ascii_art_evasion_probe_") for i in ids)
        # low_resource_language_evasion's system-prompt-extraction variants
        # classify as data_leakage, not unauthorized_actions -- only its
        # jailbreak variants belong here (see classify_tier's own docstring
        # for why both land correctly via the OWASP tag alone).
        assert any(i.startswith("low_resource_language_jailbreak_") for i in ids)

    def test_discovery_recon_tier_includes_access_control_layer_probes(self):
        library, _, _ = build_campaign(agent_url="http://localhost:9999", tier="discovery_recon")
        ids = {op.id for op in library}

        assert any(i.startswith("access_control_layer_probe_") for i in ids)


class TestAttackCategoryFiltering:
    def test_zero_matching_operators_raises_campaign_build_error(self):
        with pytest.raises(CampaignBuildError, match="attack-category"):
            build_campaign(agent_url="http://localhost:9999", attack_category=["decoy"])

    def test_matching_category_returns_a_filtered_library(self):
        library, _, _ = build_campaign(
            agent_url="http://localhost:9999", attack_category=["tool_manipulation"],
        )

        assert list(library)


class TestTierZeroMatch:
    def test_tier_with_zero_matches_raises_campaign_build_error(self, monkeypatch):
        # Force every operator to classify to a tier with none of the
        # loaded operators actually tagged for it -- exercises the same
        # zero-match guard as attack_category's, without depending on the
        # operator packs never happening to cover discovery_recon (they do
        # today, but that's incidental, not something this test should rely
        # on).
        import aginiti.core.campaign_builder as cb

        monkeypatch.setattr(cb, "classify_tier", lambda op: "unauthorized_actions")

        with pytest.raises(CampaignBuildError, match="tier"):
            build_campaign(agent_url="http://localhost:9999", tier="data_leakage")
