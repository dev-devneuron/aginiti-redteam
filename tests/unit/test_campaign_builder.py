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
    build_campaign,
    classify_tier,
)
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.deep_attack_operators import deep_attack_operators


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
        expected_size = len(data_exposure_operators()) + len(deep_attack_operators())
        assert len(list(library)) == expected_size
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
