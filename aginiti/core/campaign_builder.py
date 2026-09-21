"""
Shared ``--agent-url`` / ``--tier`` / ``--attack-category`` -> (library,
mission, agent) derivation, used by both ``aginiti scan`` (``aginiti/cli.py``)
and the git-clone-only ``scripts/run_campaign.py``.

This logic originally lived only in ``scripts/run_campaign.py`` (see that
file's own module docstring for the full rationale behind tier
classification, attack-category classification, and mission derivation --
this module is a direct extraction, not a redesign). Factored out here so
the CLI and the script can never silently drift apart on what "tier X" or
"attack category Y" actually means -- there is exactly one place this
mapping is defined.
"""
from __future__ import annotations

import dataclasses
from typing import Optional

from aginiti.adapters.base import BaseAdapter
from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.connectors.endpoint import AgentEndpoint
from aginiti.core.graph.attack_category import (
    ALL_CATEGORIES,
    CATEGORY_TITLES,
    LOW_VALUE_RECONNAISSANCE,
    OFFENSIVE_CATEGORIES,
    TOOL_DISCOVERY,
    TOOL_MANIPULATION,
)
from aginiti.core.graph.owasp_llm_taxonomy import (
    LLM01_PROMPT_INJECTION,
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
    LLM06_EXCESSIVE_AGENCY,
    LLM07_SYSTEM_PROMPT_LEAKAGE,
)
from aginiti.core.graph.schema import RiskTier
from aginiti.core.mission import Mission
from aginiti.core.scenarios import multi_path_mission
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.deep_attack_operators import deep_attack_operators
from aginiti.operators.definitions import build_library
from aginiti.operators.library import Operator, OperatorLibrary

TIER_CHOICES = ["data_leakage", "unauthorized_actions", "discovery_recon", "full_assessment"]

_RECON_ATTACK_CATEGORIES = {TOOL_DISCOVERY, LOW_VALUE_RECONNAISSANCE}
_UNAUTHORIZED_ACTION_OWASP = {LLM01_PROMPT_INJECTION, LLM06_EXCESSIVE_AGENCY}
_DATA_LEAKAGE_OWASP = {LLM02_SENSITIVE_INFORMATION_DISCLOSURE, LLM07_SYSTEM_PROMPT_LEAKAGE}


class CampaignBuildError(ValueError):
    """Raised when --tier/--attack-category matches zero operators."""


def classify_tier(op: Operator) -> Optional[str]:
    """
    Classify one operator into a coarse tier from tags it already carries on
    its first ``effects_success`` ClaimEffect (``owasp_llm_category``,
    ``attack_category``) -- not a new field on ``Operator``. Checked in this
    order because a couple of operators would otherwise match more than one
    tier (e.g. a tool-inventory-disclosure probe is both LLM02-tagged and a
    TOOL_DISCOVERY recon probe; recon is the more specific/useful bucket for
    it). An operator with none of these tags falls into no specific tier --
    included only under ``full_assessment``/no filter.
    """
    if not op.effects_success:
        return None
    effect = op.effects_success[0]
    if effect.attack_category in _RECON_ATTACK_CATEGORIES:
        return "discovery_recon"
    if effect.owasp_llm_category in _UNAUTHORIZED_ACTION_OWASP or effect.attack_category == TOOL_MANIPULATION:
        return "unauthorized_actions"
    if effect.owasp_llm_category in _DATA_LEAKAGE_OWASP:
        return "data_leakage"
    return None


def _success_keys(op: Operator) -> set[str]:
    """The claim key(s) that count as this operator succeeding -- deep-attack
    operators declare exactly one (``op.claim_key``); prompt operators may
    declare more than one ``effects_success`` ClaimEffect."""
    if op.kind == "deep_attack":
        return {op.claim_key} if op.claim_key else set()
    return {e.key for e in op.effects_success}


def print_attack_categories() -> None:
    """Print all attack_category names with a one-line description each --
    the ``--list-attack-categories`` / ``--list-attack-categories`` output,
    factored out so both entry points print exactly the same thing."""
    print("Valid attack categories:\n")
    for category in sorted(ALL_CATEGORIES):
        suffix = " (offensive technique)" if category in OFFENSIVE_CATEGORIES else ""
        print(f"  {category:<32} {CATEGORY_TITLES[category]}{suffix}")


def build_campaign(
    agent_url: Optional[str] = None,
    tier: Optional[str] = None,
    attack_category: Optional[list[str]] = None,
    budget: Optional[int] = None,
) -> tuple[OperatorLibrary, Mission, Optional[BaseAdapter]]:
    """
    Resolve ``(library, mission, agent)`` from the same
    ``--agent-url``/``--tier``/``--attack-category`` semantics documented in
    ``scripts/run_campaign.py``'s own module docstring.

    Omitting all three reproduces the exact original zero-flag behavior:
    the in-memory ``DemoAgent`` scenario library and ``multi_path_mission()``.
    Passing ``agent_url`` switches the operator library to the two
    target-agnostic packs (``data_exposure_operators()`` +
    ``deep_attack_operators()``) and derives a ``Mission`` whose
    ``success_criteria`` come from whatever operators survive filtering.

    Raises ``CampaignBuildError`` if ``tier`` or ``attack_category`` matches
    zero operators in the loaded library.
    """
    used_defaults = agent_url is None and tier is None and attack_category is None

    if used_defaults:
        library = OperatorLibrary(build_library())
        mission = multi_path_mission()
        agent = None
    else:
        if agent_url:
            operators = [*data_exposure_operators(), *deep_attack_operators()]
            endpoint = AgentEndpoint(base_url=agent_url)
            agent = HTTPAgentAdapter(endpoint)
        else:
            # --tier/--attack-category without --agent-url: still exercise
            # the DemoAgent scenario library, just filtered.
            operators = build_library()
            agent = None

        if tier and tier != "full_assessment":
            operators = [op for op in operators if classify_tier(op) == tier]
            if not operators:
                raise CampaignBuildError(
                    f"--tier {tier!r} matched zero operators in the loaded library. "
                    f"(Tier classification only covers operators tagged with "
                    f"owasp_llm_category/attack_category.)"
                )

        if attack_category:
            operators = list(OperatorLibrary(operators).by_category(*attack_category))
            if not operators:
                raise CampaignBuildError(
                    f"--attack-category {attack_category!r} matched zero operators in the "
                    f"loaded library. (Operators with no attack_category tag never match, "
                    f"most commonly on the older DemoAgent mock library.)"
                )

        library = OperatorLibrary(operators)

        success_criteria = tuple(sorted({key for op in operators for key in _success_keys(op)}))
        scope_note = (
            f" (tier: {tier})" if tier
            else f" (attack categories: {', '.join(attack_category)})" if attack_category
            else ""
        )
        mission = Mission(
            goal=f"Demonstrate a concrete compromise against the target{scope_note}.",
            success_criteria=success_criteria,
            # 25: comfortably admits a mix of cheap data_exposure probes
            # (cost_prompts=1 each) alongside one deep-attack operator
            # (cost_prompts ~3-20) without an explicit budget override.
            budget=25,
            risk_threshold=RiskTier.MEDIUM,
            success_mode="any",
        )

    if budget is not None:
        mission = dataclasses.replace(mission, budget=budget)

    return library, mission, agent
