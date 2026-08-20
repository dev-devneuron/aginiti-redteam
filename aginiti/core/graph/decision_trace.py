"""DecisionTrace -- a structured record answering "why did the planner
choose THIS operator, right now, given what just happened" using ONLY
values already computed by AginitiPlanner.rank() and TargetBeliefState.
from_ssg() -- never a generated LLM sentence. Added 2026-08-14 in direct
response to the explicit instruction: "Do not rely on a vague LLM
explanation. The underlying state/ranking should support the explanation."

Every field below is built by FORMATTING real, already-computed numbers
and tags (a `RankedCandidate`'s per-term breakdown, a `TargetBeliefState`
snapshot) -- never by asking a model to narrate. This is the same
discipline `belief_state.py`'s `summary` field already establishes
("a string for HUMANS... must not be consulted by any ranking function")
applied in the other direction: a string FOR humans, BUILT FROM values
the ranking function already used, not text a model separately invented
that might not actually correspond to what happened.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DecisionTrace:
    step: int
    observation: str
    updated_belief: str
    hypothesis: str
    selected_operator: str
    reason: str
    # Full numeric breakdown backing `reason` -- every number in the
    # formatted string above traces back to one of these keys. Kept
    # alongside the prose so an automated ablation/analysis script can
    # read the raw values without re-parsing formatted text.
    utility_breakdown: dict = field(default_factory=dict)

    def render(self) -> str:
        """The exact `Observation: / Updated belief: / Hypothesis: /
        Selected operator: / Reason:` shape named explicitly in the
        architectural direction this was built from."""
        return (
            f"Observation:\n{self.observation}\n\n"
            f"Updated belief:\n{self.updated_belief}\n\n"
            f"Hypothesis:\n{self.hypothesis}\n\n"
            f"Selected operator:\n{self.selected_operator}\n\n"
            f"Reason:\n{self.reason}"
        )


def _format_belief_summary(belief) -> str:
    """`belief` is a TargetBeliefState. Formats its (already human-facing,
    per that module's own rule) summarize() dict into readable lines --
    string formatting only, no new derivation happens here."""
    s = belief.summarize()
    lines = []
    if s["capabilities"]:
        lines.append(f"capabilities confirmed: {', '.join(s['capabilities'])}")
    if s["trust_edges"]:
        lines.append(f"trust edges confirmed: {', '.join(s['trust_edges'])}")
    if s["mission_outcomes"]:
        lines.append(f"mission outcomes confirmed: {', '.join(s['mission_outcomes'])}")
    if s["defender_controls"]:
        lines.append(f"defender controls confirmed: {', '.join(s['defender_controls'])}")
    if s["partial_progress"]:
        lines.append(f"partial/unresolved: {', '.join(s['partial_progress'])}")
    saturated = [name for name, f in s["families"].items() if f["looks_saturated"]]
    if saturated:
        lines.append(f"attack families that look saturated (blocked, no successes): {', '.join(saturated)}")
    if not lines:
        lines.append("no resolved evidence yet")
    return "\n".join(f"- {line}" for line in lines)


def _format_reason(chosen_meta: dict, family_diversification_active: bool,
                    hypothesis_escalation_active: bool) -> str:
    """Builds the reason string strictly from the RankedCandidate/Candidate
    meta dict AginitiPolicy already produces (aginiti/policies/
    aginiti_policy.py) -- the same numbers `rank()` used to pick this
    operator over every other candidate, just formatted for a human."""
    parts = []
    dominant = sorted(
        ((k, v) for k, v in chosen_meta.items() if k not in ("alpha", "beta") and isinstance(v, (int, float))),
        key=lambda kv: abs(kv[1]), reverse=True,
    )
    top_terms = [f"{k}={v:.2f}" for k, v in dominant[:4] if v != 0]
    if top_terms:
        parts.append("Highest-magnitude utility terms: " + ", ".join(top_terms) + ".")
    fdiv = chosen_meta.get("family_diversification", 0.0)
    if family_diversification_active and fdiv < 0:
        parts.append(f"Demoted ({fdiv:.2f}) for belonging to an attack family that already looks saturated.")
    elif family_diversification_active and fdiv > 0:
        parts.append(f"Boosted ({fdiv:.2f}) as a genuinely untried family after another one saturated.")
    heb = chosen_meta.get("hypothesis_escalation_bonus", 0.0)
    if hypothesis_escalation_active and heb > 0:
        parts.append(f"Boosted ({heb:.2f}) because a semantic precondition it depends on was just confirmed.")
    fep = chosen_meta.get("failure_evidence_penalty", 0.0)
    if fep < 0:
        parts.append(f"Demoted ({fep:.2f}) for sharing a confirmed failure diagnosis with another candidate.")
    if not parts:
        parts.append("Highest overall utility among eligible candidates this step.")
    return " ".join(parts)


def build_decision_trace(step: int, ssg, chosen_operator_id: str, chosen_meta: dict,
                          last_fact_text: str | None,
                          belief=None, family_diversification_active: bool = False,
                          hypothesis_escalation_active: bool = False) -> DecisionTrace:
    """Pure function: builds one DecisionTrace from data the campaign loop
    already has in hand at the moment it just executed `chosen_operator_id`
    for the PREVIOUS step and is about to rank again -- called by
    aginiti/policies/aginiti_policy.py with the belief state it already
    computed for this same rank() call, so no extra work happens twice.

    `belief` is optional (None when family_diversification is disabled --
    computing a TargetBeliefState the trace's own text would show as "no
    saturated families" either way when the term itself is off would be
    actively misleading, so this path is explicit rather than silently
    reusing whatever belief happens to be in scope)."""
    from aginiti.core.graph.target_belief import TargetBeliefState

    if belief is None:
        belief = TargetBeliefState.from_ssg(ssg)

    observation = (last_fact_text or "(no prior observation -- first step of this campaign)")
    if len(observation) > 300:
        observation = observation[:300] + "..."

    hyps = belief.open_hypotheses
    if hyps:
        hypothesis_text = "; ".join(h.statement for h in hyps[:3])
    else:
        hypothesis_text = "no open hypotheses currently tracked"

    return DecisionTrace(
        step=step,
        observation=observation,
        updated_belief=_format_belief_summary(belief),
        hypothesis=hypothesis_text,
        selected_operator=chosen_operator_id,
        reason=_format_reason(chosen_meta, family_diversification_active, hypothesis_escalation_active),
        utility_breakdown=dict(chosen_meta),
    )
