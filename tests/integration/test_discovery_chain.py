"""Regression test for the discovery-chain pack (aginiti/operators/
discovery_chain_definitions.py) -- the pytest-suite counterpart to
experiments/discovery_chain_dry_run.py's manual walkthrough. Proves the
6-step chain (discover capability -> establish trust -> poison retrieved
context -> trigger tool -> reach sensitive resource -> exfiltrate)
completes via AginitiPlanner using ONLY ClassPrecondition semantic-tag
gating past stage 1, and that either of two independently-authored,
mutually-substitutable stage-2 "establish trust" operators unlocks the
identical downstream chain."""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from aginiti.adapters.base import SendResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L5
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.operators.discovery_chain_definitions import build_discovery_chain_library
from aginiti.core.policies.aginiti_policy import AginitiPolicy


@dataclass
class _EchoAdapter:
    ssg: SecurityStateGraph
    mission_key: str
    suppressed_claim_keys: frozenset[str] = field(default_factory=frozenset)

    def send(self, channel: str, prompt: str) -> SendResult:
        suppressed_prompts = {f"__confirmed__{key}" for key in self.suppressed_claim_keys}
        return SendResult(final_text="" if prompt in suppressed_prompts else prompt)

    def ground_truth_mission_achieved(self) -> bool:
        return self.ssg.is_confirmed(self.mission_key)


def _mission() -> Mission:
    return Mission(
        goal="discovery chain test", success_criteria=("chain_data_exfiltrated",),
        budget=12, risk_threshold=RiskTier.LOW, constraints=(),
    )


@pytest.mark.parametrize("suppressed_trust_key", ["chain_trust_forged_ticket", "chain_trust_vendor_session"])
def test_discovery_chain_completes_via_either_interchangeable_trust_operator(suppressed_trust_key):
    ssg = SecurityStateGraph()
    library = build_discovery_chain_library()
    agent = _EchoAdapter(ssg=ssg, mission_key="chain_data_exfiltrated",
                          suppressed_claim_keys=frozenset({suppressed_trust_key}))

    result = run_campaign(_mission(), library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)

    assert result.outcome == "SUCCESS"
    assert ssg.is_confirmed("chain_data_exfiltrated")
    assert agent.ground_truth_mission_achieved()
    assert ssg.highest_boundary_crossed() == BOUNDARY_L5

    downstream_stages = {"chain_poison_retrieved_context", "chain_trigger_tool_via_poisoned_context",
                          "chain_reach_sensitive_resource", "chain_exfiltrate_data"}
    assert downstream_stages.issubset(set(result.operators_executed))

    # The non-suppressed trust operator is the one that actually confirmed.
    surviving_key = ("chain_trust_vendor_session" if suppressed_trust_key == "chain_trust_forged_ticket"
                      else "chain_trust_forged_ticket")
    assert ssg.is_confirmed(surviving_key)
    assert not ssg.is_confirmed(suppressed_trust_key)


def test_no_operator_past_stage_1_uses_an_exact_key_precondition():
    """The literal "don't tell Aginiti the chain" check: every operator in
    this pack other than the single entry point has an EMPTY exact-key
    `preconditions` tuple -- any gating past stage 1 is class-based only."""
    library = build_discovery_chain_library()
    entry_points = {"chain_discover_capability", "chain_decoy_recon", "chain_decoy_known_defended"}
    for op in library:
        if op.id in entry_points:
            continue
        assert op.preconditions == (), f"{op.id} should have no exact-key preconditions"
        assert len(op.precondition_classes) >= 1, f"{op.id} should be class-gated"
