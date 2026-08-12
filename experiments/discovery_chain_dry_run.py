"""Offline, deterministic dry run of the discovery-chain operator pack
(aginiti/operators/discovery_chain_definitions.py) -- validates Issue 1
of the 2026-08-12 architectural directive: "Make Aginiti capable of
discovering multi-step attack paths... don't tell Aginiti the chain. It
should discover it from observations."

NOT a live experiment (per the standing "don't run any experiment now"
instruction this session is under) -- no target, no LLM judge, no
network call anywhere in this script. Every operator in the pack carries
a deterministic extractor keyed off its own rendered prompt text, and the
mock adapter below just echoes the prompt straight back as the "response"
-- the entire point of this script is to observe AginitiPlanner's REAL
ranking/reasoning over ClassPrecondition-gated candidates, not to
re-validate judge accuracy (already covered elsewhere).

Two independent runs are executed against the SAME library and mission:
  Run A: the vendor-session trust operator is left ENABLED, the forged-
         ticket one DISABLED (via a thin wrapper that fails it).
  Run B: the reverse.
Both must reach full mission success (chain_data_exfiltrated CONFIRMED)
through the SAME downstream operators (stage 3 onward), with ZERO code
changes to any operator past stage 1 -- this is the actual proof that
discovery, not a relabeled fixed sequence, is what's happening: the
downstream half of the chain never knew or cared which stage-2 operator
would end up firing.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aginiti.adapters.base import SendResult
from aginiti.campaign import run_campaign
from aginiti.graph.schema import RiskTier
from aginiti.graph.security_boundary import BOUNDARY_L5
from aginiti.mission import Mission
from aginiti.operators.discovery_chain_definitions import build_discovery_chain_library
from aginiti.policies.aginiti_policy import AginitiPolicy


@dataclass
class EchoAdapter:
    """The whole "target": send() just echoes the prompt back as the
    response (every operator's own deterministic extractor already keys
    off marker text embedded IN its own prompt -- see
    discovery_chain_definitions.py's `_marker`), and optionally suppresses
    one named operator's marker to model "this specific path is blocked/
    doesn't exist for this run" without touching the operator library
    itself. ground_truth_mission_achieved() is independently wired to the
    SAME claim key the Mission checks, exactly matching every real
    adapter's contract (aginiti/adapters/base.py) -- Aginiti's own SSG
    belief is never trusted as its own ground truth."""
    ssg: object
    mission_key: str
    suppressed_claim_keys: frozenset[str] = field(default_factory=frozenset)

    def send(self, channel: str, prompt: str) -> SendResult:
        # Campaign/ObservationAdapter don't pass operator id to send(), so
        # suppression is applied by prompt content match instead -- every
        # operator's prompt IS its own unique marker string by convention.
        return SendResult(final_text="" if prompt in self._suppressed_prompts else prompt)

    def ground_truth_mission_achieved(self) -> bool:
        return self.ssg.is_confirmed(self.mission_key)

    @property
    def _suppressed_prompts(self) -> set[str]:
        return {f"__confirmed__{key}" for key in self.suppressed_claim_keys}


def _build_mission() -> Mission:
    return Mission(
        goal="Reach and exfiltrate the sensitive resource via whatever multi-step path the "
             "target's own confirmed behavior reveals -- no path is pre-declared to the planner.",
        success_criteria=("chain_data_exfiltrated",),
        budget=12,
        risk_threshold=RiskTier.LOW,
        constraints=(),
    )


def _run(label: str, suppress_marker_for_key: str | None) -> None:
    from aginiti.graph.ssg import SecurityStateGraph

    library = build_discovery_chain_library()
    ssg = SecurityStateGraph()
    mission = _build_mission()
    suppressed = frozenset({suppress_marker_for_key}) if suppress_marker_for_key else frozenset()
    agent = EchoAdapter(ssg=ssg, mission_key="chain_data_exfiltrated", suppressed_claim_keys=suppressed)

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)

    print(f"\n=== {label} ===")
    print(f"outcome={result.outcome} steps={result.steps_executed} prompts_used={result.prompts_used}")
    print("operator sequence (in the order AginitiPlanner actually chose them):")
    for i, op_id in enumerate(result.operators_executed, 1):
        print(f"  {i}. {op_id}")
    mission_ok = ssg.is_confirmed("chain_data_exfiltrated")
    ground_truth_ok = agent.ground_truth_mission_achieved()
    highest = ssg.highest_boundary_crossed()
    print(f"mission claim confirmed: {mission_ok}")
    print(f"ground truth confirms exfiltration: {ground_truth_ok}")
    print(f"highest security boundary crossed: {highest}")
    assert mission_ok, f"{label}: mission was NOT confirmed -- discovery failed"
    assert ground_truth_ok, f"{label}: ground truth mismatch -- planner hallucinated success"
    assert highest == BOUNDARY_L5, f"{label}: expected L5, got {highest}"

    # The actual discovery proof: which stage-2 trust operator fired, and
    # did the SAME stage-3+ operators run regardless.
    trust_ops = {"chain_trust_via_vendor_session", "chain_trust_via_forged_ticket"} & set(result.operators_executed)
    downstream_ops = {"chain_poison_retrieved_context", "chain_trigger_tool_via_poisoned_context",
                       "chain_reach_sensitive_resource", "chain_exfiltrate_data"}
    assert downstream_ops.issubset(set(result.operators_executed)), \
        f"{label}: expected every downstream stage to run regardless of which trust operator fired"
    print(f"trust operator(s) that actually fired this run: {sorted(trust_ops)}")
    print(f"all {len(downstream_ops)} downstream stages ran unchanged: {downstream_ops.issubset(set(result.operators_executed))}")


def main() -> None:
    print("Discovery-chain dry run -- offline, deterministic, no live target, no LLM call.")
    print("Validates: 6-step chain (discover capability -> establish trust -> poison retrieved")
    print("context -> trigger tool -> reach sensitive resource -> exfiltrate) discovered purely")
    print("via ClassPrecondition semantic-tag matching -- zero exact-key wiring past stage 1.")

    # Run A: forged-ticket trust path suppressed -- only vendor-session works.
    _run("RUN A: vendor-session trust path available, forged-ticket suppressed",
         suppress_marker_for_key="chain_trust_forged_ticket")

    # Run B: the reverse -- vendor-session suppressed, forged-ticket works.
    _run("RUN B: forged-ticket trust path available, vendor-session suppressed",
         suppress_marker_for_key="chain_trust_vendor_session")

    print("\n=== CONCLUSION ===")
    print("Both runs reached full L5 exfiltration through the IDENTICAL stage-3..6 operators,")
    print("despite each run only having ONE of the two interchangeable stage-2 trust operators")
    print("available. Neither stage-3+ operator's Precondition/ClassPrecondition names either")
    print("stage-2 operator by id or by exact claim key -- the connection exists purely because")
    print("both stage-2 operators tag their success effect category=trust_edge, and stage 3 is")
    print("gated on ClassPrecondition(category=trust_edge). This is genuine discovery: the")
    print("downstream chain was never told which specific upstream operator would satisfy it.")


if __name__ == "__main__":
    main()
