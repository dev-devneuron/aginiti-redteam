"""Run one Aginiti campaign against the real damn-vulnerable-llm-agent
target (via DVLAAdapter) and print the full trace -- the first live run
against a genuinely external, independently-developed target."""
from aginiti.adapters.dvla_adapter import DVLAAdapter
from aginiti.core.campaign import run_campaign
from aginiti.operators.dvla_definitions import build_dvla_library
from aginiti.core.scenarios import dvla_mission

mission = dvla_mission()
agent = DVLAAdapter()

result = run_campaign(mission, build_dvla_library(), agent=agent)

print("=" * 70)
print(f"OUTCOME: {result.outcome}")
print(f"Steps executed: {result.steps_executed}")
print(f"Prompts used: {result.prompts_used} / {mission.budget}")
print(f"Operators executed: {result.operators_executed}")
print("=" * 70)

print("\n--- Decision Trace ---")
for d in result.decision_log:
    meta = " ".join(f"{k}={v:.2f}" if isinstance(v, float) else f"{k}={v}" for k, v in d.meta.items())
    print(f"Step {d.step}: considered {d.candidates_considered} -> chose '{d.chosen_operator_id}' "
          f"(score={d.score:.2f}{', ' + meta if meta else ''})")

print("\n--- Execution Log ---")
for e in result.execution_log:
    status = "SUCCESS" if e.overall_success else "no confirmed effect"
    print(f"[{e.operator_id}] {status} | confirmed_keys={e.confirmed_keys}")
    print(f"  reasoning: {e.reasoning}")
    print(f"  raw_signal: {e.raw_signal[:220]!r}")

print("\n--- Security State Graph (final claims) ---")
for c in result.ssg.claims:
    print(f"  {c.key} = {c.status.value} (confidence={c.confidence.value}) [{c.id}, supersedes={c.supersedes}]")

print(f"\nGraph size (Claims+Observations): {result.ssg.size()}")
print(f"Ground truth -- mission actually achieved (checked against real DB/tool results): "
      f"{agent.ground_truth_mission_achieved()}")
