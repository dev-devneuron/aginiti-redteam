"""Offline, deterministic dry run of the two new agentic primitive types
(aginiti/operators/agentic_primitives_definitions.py) -- validates Issue 3
of the 2026-08-12 architectural directive: approval gates and untrusted
tool-output content, composed via Issue 1's ClassPrecondition discovery
mechanism (proving that mechanism generalizes to a SECOND, independently-
authored operator pack, not just the original discovery_chain_
definitions.py demo).

NOT a live experiment -- no target, no LLM judge, no network call. Also
NOT a claim about any real target's actual behavior (DVAA or otherwise) --
see the operator pack's own module docstring for why mapping these onto a
real target's endpoints is explicitly deferred pending live source
verification, not done here.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aginiti.adapters.base import SendResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.failure_diagnosis import BLOCKED_BY_APPROVAL_GATE
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.security_boundary import BOUNDARY_L3
from aginiti.core.mission import Mission
from aginiti.operators.agentic_primitives_definitions import build_agentic_primitives_library
from aginiti.core.policies.aginiti_policy import AginitiPolicy


@dataclass
class EchoAdapter:
    ssg: object
    mission_key: str
    suppressed_claim_keys: frozenset = field(default_factory=frozenset)

    def send(self, channel: str, prompt: str) -> SendResult:
        suppressed_prompts = {f"__confirmed__{key}" for key in self.suppressed_claim_keys}
        return SendResult(final_text="" if prompt in suppressed_prompts else prompt)

    def ground_truth_mission_achieved(self) -> bool:
        return self.ssg.is_confirmed(self.mission_key)


def _mission() -> Mission:
    return Mission(
        goal="Reach and bypass an approval-gated sensitive action via whatever multi-step path the "
             "target's own confirmed behavior reveals.",
        success_criteria=("agentic_approval_gate_bypassed",),
        budget=12, risk_threshold=RiskTier.LOW, constraints=(),
    )


def _run(label: str, suppress_key: str | None) -> None:
    from aginiti.core.graph.ssg import SecurityStateGraph

    library = build_agentic_primitives_library()
    ssg = SecurityStateGraph()
    mission = _mission()
    suppressed = frozenset({suppress_key}) if suppress_key else frozenset()
    agent = EchoAdapter(ssg=ssg, mission_key="agentic_approval_gate_bypassed", suppressed_claim_keys=suppressed)

    result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)

    print(f"\n=== {label} ===")
    print(f"outcome={result.outcome} steps={result.steps_executed} prompts_used={result.prompts_used}")
    for i, op_id in enumerate(result.operators_executed, 1):
        print(f"  {i}. {op_id}")
    print(f"mission confirmed: {ssg.is_confirmed('agentic_approval_gate_bypassed')}")
    print(f"ground truth: {agent.ground_truth_mission_achieved()}")
    print(f"highest boundary crossed: {ssg.highest_boundary_crossed()}")


def main() -> None:
    print("Agentic-primitives dry run -- offline, deterministic, no live target, no LLM call.")
    print("Validates: approval-gate + untrusted-tool-output primitives compose via Issue 1's")
    print("ClassPrecondition mechanism in a SECOND, independently-authored operator pack.")

    _run("RUN A: full chain available (bypass SUCCEEDS)", suppress_key=None)
    _run("RUN B: approval-gate bypass attempt is BLOCKED (BLOCKED_BY_APPROVAL_GATE)",
         suppress_key="agentic_approval_gate_bypassed")

    print("\n=== Run B failure diagnosis check ===")
    from aginiti.core.graph.ssg import SecurityStateGraph
    library = build_agentic_primitives_library()
    ssg = SecurityStateGraph()
    mission = _mission()
    agent = EchoAdapter(ssg=ssg, mission_key="agentic_approval_gate_bypassed",
                         suppressed_claim_keys=frozenset({"agentic_approval_gate_bypassed"}))
    run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=12, ssg=ssg)
    diagnoses = ssg.confirmed_failure_diagnoses()
    print(f"confirmed failure diagnoses: {diagnoses}")
    assert diagnoses.get("agentic_approval_gate_enforced") == BLOCKED_BY_APPROVAL_GATE
    print("Confirmed: the blocked bypass attempt is recorded with a structured, generalizable")
    print("diagnosis (BLOCKED_BY_APPROVAL_GATE) -- not just a generic '*_blocked' fact -- and")
    print("AginitiPlanner.failure_evidence_penalty() (Issue 4) would demote ANY other candidate")
    print("in the library that shares this same prospective failure_diagnosis tag.")


if __name__ == "__main__":
    main()
