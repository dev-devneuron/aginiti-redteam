"""The Target Profile (rendered as a "Behavioral Security Assessment" --
"profile" undersells it, but the Python name stays as-is here rather than
a mechanical rename across every call site on a naming preference alone):
Aginiti's primary product artifact.

Not a report generated as an afterthought from the graph -- the thing the
graph exists to produce. Everything else (the interactive visualization,
the campaign loop, the planner) is plumbing that feeds this or consumes
it. A Target Profile answers, in one document: what does Aginiti
understand about this target right now?

Built entirely from the seven-plus analyst queries (aginiti/graph/
queries.py) over a SecurityStateGraph -- no campaign object required, and
it reads the same whether the graph came from a live run just now or was
reloaded from disk days later (aginiti/graph/persistence.py). Security
evaluation (reachable_actions) is one section among several, not the
document's organizing principle: a target with an empty reachable_actions
section still gets a full profile, because "we mapped this and found no
compromise" is itself a complete, useful answer -- not a failed run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from aginiti.adapter.observation_adapter import KEY_DESCRIPTIONS
from aginiti.graph.attack_category import CATEGORY_TITLES as ATTACK_CATEGORY_TITLES
from aginiti.graph.hypothesis import Hypothesis
from aginiti.graph.mitre_atlas_refs import TECHNIQUE_TITLES as ATLAS_TECHNIQUE_TITLES
from aginiti.graph.owasp_llm_taxonomy import CATEGORY_TITLES as OWASP_CATEGORY_TITLES
from aginiti.graph.queries import (
    SecurityQuestion,
    capabilities,
    consistent_defenses,
    disproven_assumptions,
    latest_claims,
    observed_tools,
    reachable_actions,
    recommend_next,
    security_questions,
    trust_assumptions,
    unexplored_frontier,
    unverified_capabilities,
)
from aginiti.graph.schema import Claim, ClaimStatus, Insight, InsightCategory
from aginiti.graph.security_boundary import BOUNDARY_DESCRIPTIONS
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.library import Operator, OperatorLibrary
from aginiti.planner.aginiti_planner import RankedCandidate


def _describe(key: str) -> str:
    return KEY_DESCRIPTIONS.get(key, key)


@dataclass
class TargetProfile:
    target_name: str
    generated_at: datetime
    operators_executed: int
    operators_total: int
    coverage: float  # operators_executed / operators_total, 0.0 if the library is empty
    # Understanding metrics -- a first step toward "coverage = how well we
    # understand the target" instead of "how many operators ran." Not a
    # complete replacement (that needs history/diffing across campaigns,
    # deliberately not built yet -- see insights.py's module docstring
    # discussion), but this already separates "we ran N probes" from "we
    # resolved M of the questions those probes raised."
    distinct_claim_keys: int = 0
    resolved_claims: int = 0     # CONFIRMED or REFUTED -- an actual answer, not just a raised question
    unresolved_claims: int = 0   # still HYPOTHESIZED
    # Populated from whatever's already in ssg.insights -- synthesis
    # itself (aginiti/graph/insights.py's synthesize_insights) requires an
    # LLM call and is a separate, explicit step the caller runs BEFORE
    # building the profile, not something build_target_profile triggers
    # implicitly. Keeps this function pure/offline-testable, consistent
    # with every other query in this module.
    higher_order_insights: list[Insight] = field(default_factory=list)
    # The graph read as reasoning in progress: each probe with a declared
    # understanding_question paired with its current answer (if any) and
    # confidence -- see queries.py's security_questions for the framing.
    security_questions: list[SecurityQuestion] = field(default_factory=list)
    # Persistent-identity objects (aginiti/graph/hypothesis.py) -- unlike
    # every list above, these MUTATE: the same Hypothesis a caller saw
    # last week may show a different status/confidence today, because
    # `assert_claim` updates it automatically as evidence arrives.
    hypotheses: list[Hypothesis] = field(default_factory=list)
    capabilities: list[Claim] = field(default_factory=list)
    trust_relationships: list[Claim] = field(default_factory=list)
    tools_observed: list[str] = field(default_factory=list)
    observed_defenses: list[Claim] = field(default_factory=list)
    reachable_actions: list[Claim] = field(default_factory=list)
    unverified: list[Claim] = field(default_factory=list)
    disproven: list[Claim] = field(default_factory=list)
    unexplored_frontier: list[Operator] = field(default_factory=list)
    recommended_next_probes: list[RankedCandidate] = field(default_factory=list)
    # Severity/taxonomy rollups (added 2026-08-12 architecture review -- these SSG query
    # methods, aginiti/graph/ssg.py's highest_boundary_crossed()/owasp_category_summary()/
    # attack_category_summary()/confirmed_atlas_techniques(), existed and were fully tested
    # but were never actually called from Aginiti's own primary product artifact until now;
    # see this module's own docstring for why that's the thing that matters). None/empty
    # means "nothing tagged has been confirmed yet," never a fabricated floor -- same
    # honest-absence discipline as security_boundary.py's own highest_level().
    highest_boundary: str | None = None
    owasp_findings: dict[str, int] = field(default_factory=dict)
    attack_category_findings: dict[str, int] = field(default_factory=dict)
    atlas_techniques_confirmed: dict[str, str] = field(default_factory=dict)
    # claim key -> a pre-formatted "[L5] [LLM06] [markdown_network_exfiltration] [AML.T0086]"
    # suffix, only for keys that carry at least one tag -- computed once here (where ssg is
    # in scope) so render_markdown/_claim_line can stay pure functions of the profile alone,
    # never needing the ssg passed back in.
    claim_tags: dict[str, str] = field(default_factory=dict)


def _build_claim_tags(ssg: SecurityStateGraph) -> dict[str, str]:
    """One formatted `[L5] [LLM06] [markdown_network_exfiltration] [AML.T0086]`-style suffix
    per claim key that carries at least one of the four taxonomy dimensions -- built from
    whichever of security_boundary/owasp_llm_category/attack_category/mitre_atlas_technique
    is actually set for that key (any subset; a key doesn't need all four)."""
    keys = set(ssg.claim_boundary) | set(ssg.claim_owasp_category) | \
        set(ssg.claim_attack_category) | set(ssg.claim_atlas_technique)
    tags: dict[str, str] = {}
    for key in keys:
        parts = []
        if key in ssg.claim_boundary:
            parts.append(f"[{ssg.claim_boundary[key].split('_', 1)[0]}]")  # "L5_..." -> "[L5]"
        if key in ssg.claim_owasp_category:
            parts.append(f"[{ssg.claim_owasp_category[key].split(':', 1)[0]}]")  # "LLM06:2025_..." -> "[LLM06]"
        if key in ssg.claim_attack_category:
            parts.append(f"[{ssg.claim_attack_category[key]}]")
        if key in ssg.claim_atlas_technique:
            parts.append(f"[{ssg.claim_atlas_technique[key]}]")
        tags[key] = " ".join(parts)
    return tags


def build_target_profile(ssg: SecurityStateGraph, library: OperatorLibrary, mission: Mission,
                          target_name: str, executed_ids: frozenset[str] | None = None,
                          prompts_used: int = 0, next_probe_count: int = 5) -> TargetProfile:
    """`executed_ids` defaults to the graph's own execution history
    (`ssg.operator_stats`) -- correct for a graph reloaded standalone from
    disk, where there's no live campaign object to ask."""
    if executed_ids is None:
        executed_ids = frozenset(ssg.operator_stats)
    total = len(library)
    all_claims = latest_claims(ssg)
    resolved = sum(1 for c in all_claims if c.status != ClaimStatus.HYPOTHESIZED)

    return TargetProfile(
        target_name=target_name,
        generated_at=datetime.now(timezone.utc),
        operators_executed=len(executed_ids),
        operators_total=total,
        coverage=(len(executed_ids) / total) if total else 0.0,
        distinct_claim_keys=len(all_claims),
        resolved_claims=resolved,
        unresolved_claims=len(all_claims) - resolved,
        higher_order_insights=list(ssg.insights),
        security_questions=security_questions(ssg, library, executed_ids=executed_ids),
        hypotheses=list(ssg.hypotheses.values()),
        capabilities=capabilities(ssg),
        trust_relationships=trust_assumptions(ssg),
        tools_observed=observed_tools(ssg),
        observed_defenses=consistent_defenses(ssg),
        reachable_actions=reachable_actions(ssg),
        unverified=unverified_capabilities(ssg),
        disproven=disproven_assumptions(ssg),
        unexplored_frontier=unexplored_frontier(ssg, library, executed_ids=executed_ids),
        recommended_next_probes=recommend_next(library, ssg, mission, prompts_used=prompts_used,
                                                executed_ids=executed_ids, n=next_probe_count),
        highest_boundary=ssg.highest_boundary_crossed(),
        owasp_findings=ssg.owasp_category_summary(),
        attack_category_findings=ssg.attack_category_summary(),
        atlas_techniques_confirmed=ssg.confirmed_atlas_techniques(),
        claim_tags=_build_claim_tags(ssg),
    )


def _claim_line(c: Claim, claim_tags: dict[str, str] | None = None) -> str:
    tag_suffix = f" {claim_tags[c.key]}" if claim_tags and claim_tags.get(c.key) else ""
    return f"- **{_describe(c.key)}** -- {c.status.value} ({c.confidence.value} confidence){tag_suffix}"


def _frontier_line(op: Operator) -> str:
    line = f"- **{op.id}** -- {op.description}"
    if op.understanding_question:
        line += f" _Question: {op.understanding_question}_"
    return line


def _question_line(q: SecurityQuestion) -> str:
    via = ", ".join(q.probe_ids)
    line = f"- **{q.question}** _(via {via})_ -- {q.status.replace('_', ' ')}"
    if q.confidence:
        line += f", confidence: {q.confidence}"
    if q.claims:
        line += "  \n  Evidence: " + ", ".join(f"{c.key} ({c.status.value})" for c in q.claims)
    return line


def _insight_block(ins: Insight) -> str:
    """Behavioral/security insights render as a small reasoning block --
    conclusion, then confidence/grounding, then alternatives and what
    evidence is still missing -- instead of a flat generated-sounding
    sentence, per the explicit push for reasoning over conclusions."""
    lines = [f"- **{ins.statement}**"]
    meta = []
    if ins.confidence:
        meta.append(f"confidence: {ins.confidence}")
    if ins.derived_from:
        meta.append(f"grounded in: {', '.join(ins.derived_from)}")
    if meta:
        lines.append("  _" + "; ".join(meta) + "_")
    if ins.alternative_explanations:
        lines.append(f"  Alternative explanations: {'; '.join(ins.alternative_explanations)}")
    if ins.evidence_still_missing:
        lines.append("  Known limitations: " + "; ".join(ins.evidence_still_missing))
    return "  \n".join(lines)


def _gap_block(ins: Insight, still_unexplored: set[str]) -> str:
    """`still_unexplored` -- ids from the profile's OWN unexplored_frontier
    -- lets this distinguish "a probe exists and hasn't run yet" from "a
    probe existed when this gap was synthesized but has since run": an
    Insight is append-only (schema.py), so an old gap's related_probe_id
    is never mutated after the fact -- rendering has to account for
    staleness, not the historical record itself."""
    lines = [f"- **{ins.statement}**"]
    meta = [f"importance: {ins.importance}"] if ins.importance else []
    if ins.related_probe_id and ins.related_probe_id in still_unexplored:
        meta.append(f"probe available: **{ins.related_probe_id}**")
    elif ins.related_probe_id:
        meta.append(f"probe **{ins.related_probe_id}** has since run -- re-evaluate whether this gap is closed")
    else:
        meta.append("no probe in the current library addresses this yet")
    lines.append("  _" + "; ".join(meta) + "_")
    if ins.prior_belief:
        prior_conf = f" (confidence: {ins.confidence})" if ins.confidence else ""
        lines.append(f"  Prior belief{prior_conf}: {ins.prior_belief}")
    return "  \n".join(lines)


def _hypothesis_line(h: Hypothesis) -> str:
    evidence_bits = []
    if h.supporting_evidence:
        evidence_bits.append(f"supporting: {', '.join(h.supporting_evidence)}")
    if h.contradicting_evidence:
        evidence_bits.append(f"contradicting: {', '.join(h.contradicting_evidence)}")
    evidence = f" ({'; '.join(evidence_bits)})" if evidence_bits else ""
    return (f"- **{h.statement}** -- {h.status.value}, confidence: {h.confidence:.2f} "
            f"_(testable via: {', '.join(h.experiments)})_{evidence}")


def _severity_summary_lines(profile: TargetProfile) -> list[str]:
    """The headline severity/taxonomy rollup -- "how deep did this go, and
    which risk categories does the confirmed evidence actually span" --
    answered from the same SSG methods build_target_profile() now calls
    (see TargetProfile's own field docstrings). Every sub-line is an
    honest "none of this has been classified/confirmed yet" when the
    underlying data is empty, never a fabricated zero-severity floor."""
    lines = ["## Severity & taxonomy summary"]
    if profile.highest_boundary:
        desc = BOUNDARY_DESCRIPTIONS.get(profile.highest_boundary, "")
        lines.append(f"**Deepest boundary crossed:** `{profile.highest_boundary}` -- {desc}")
    else:
        lines.append("**Deepest boundary crossed:** _none classified yet -- either nothing tagged has "
                      "been confirmed, or the confirmed findings so far predate this taxonomy's rollout "
                      "onto their operators._")
    lines.append("")
    if profile.owasp_findings:
        lines.append("**OWASP LLM Top 10 (2025) findings:**")
        for category, count in sorted(profile.owasp_findings.items(), key=lambda kv: -kv[1]):
            title = OWASP_CATEGORY_TITLES.get(category, category)
            lines.append(f"- {category} ({title}): {count} confirmed finding{'s' if count != 1 else ''}")
    else:
        lines.append("**OWASP LLM Top 10 (2025) findings:** _none tagged and confirmed yet._")
    lines.append("")
    if profile.attack_category_findings:
        lines.append("**Attack category breakdown:**")
        for category, count in sorted(profile.attack_category_findings.items(), key=lambda kv: -kv[1]):
            title = ATTACK_CATEGORY_TITLES.get(category, category)
            lines.append(f"- {title}: {count} confirmed")
    else:
        lines.append("**Attack category breakdown:** _none tagged and confirmed yet._")
    lines.append("")
    if profile.atlas_techniques_confirmed:
        lines.append("**MITRE ATLAS techniques confirmed:**")
        for technique in sorted(set(profile.atlas_techniques_confirmed.values())):
            title = ATLAS_TECHNIQUE_TITLES.get(technique, technique)
            lines.append(f"- `{technique}` -- {title}")
    else:
        lines.append("**MITRE ATLAS techniques confirmed:** _none cross-referenced and confirmed yet._")
    return lines


def render_markdown(profile: TargetProfile) -> str:
    lines: list[str] = []
    lines.append(f"# Behavioral Security Assessment: {profile.target_name}")
    lines.append(f"_Generated {profile.generated_at.isoformat()}_")
    lines.append("")
    lines.append(f"**Probe coverage:** {profile.operators_executed}/{profile.operators_total} "
                  f"known probes run ({profile.coverage:.0%})  \n"
                  f"**Understanding:** {profile.resolved_claims}/{profile.distinct_claim_keys} raised "
                  f"questions resolved, {profile.unresolved_claims} still open")
    lines.append("")

    lines.extend(_severity_summary_lines(profile))
    lines.append("")

    lines.append("## Security questions")
    if profile.security_questions:
        lines.append("\n".join(_question_line(q) for q in profile.security_questions))
    else:
        lines.append("_No operator in this library declares an understanding_question yet._")
    lines.append("")

    behavioral = [i for i in profile.higher_order_insights if i.category == InsightCategory.BEHAVIORAL]
    security = [i for i in profile.higher_order_insights if i.category == InsightCategory.SECURITY]
    gaps = [i for i in profile.higher_order_insights if i.category == InsightCategory.KNOWLEDGE_GAP]

    lines.append("## Behavioral insights")
    lines.append("\n".join(_insight_block(ins) for ins in behavioral)
                 or "_No synthesis run yet, or nothing worth synthesizing beyond the raw claims below._")
    lines.append("")

    lines.append("## Security insights")
    lines.append("\n".join(_insight_block(ins) for ins in security)
                 or "_No synthesis run yet, or nothing worth synthesizing beyond the raw claims below._")
    lines.append("")

    lines.append("## Knowledge gaps")
    if gaps:
        # 2026-08-09 fix -- a real data-quality bug a live full-system dry
        # run surfaced: a fresh cold-start seeding (aginiti/graph/priors.py)
        # records one KNOWLEDGE_GAP insight per operator in the library, and
        # once a campaign actually runs several of those probes, the SAME
        # gaps stay listed here forever (Insight is append-only, by design
        # -- see _gap_block's own docstring) with only a per-item
        # "probe has since run -- re-evaluate" note. On one real 8-operator
        # dry-run campaign, 8 of 29 listed "gaps" (28%) were already-resolved
        # cold-start priors, interspersed with genuinely open ones, directly
        # undermining this section's own stated purpose two lines below
        # ("expected to be the most valuable one over time"). Fix is
        # presentation-only -- reuses the SAME still_unexplored data
        # _gap_block already computed, zero change to how gaps are
        # recorded -- split into what's still actionable vs. what's just a
        # historical record, instead of interleaving them.
        still_unexplored = {op.id for op in profile.unexplored_frontier}
        open_gaps = [ins for ins in gaps
                     if ins.related_probe_id is None or ins.related_probe_id in still_unexplored]
        stale_gaps = [ins for ins in gaps if ins not in open_gaps]
        lines.append("\n".join(_gap_block(ins, still_unexplored) for ins in open_gaps)
                     or "_None open -- every gap raised so far already has a probe result; see "
                        "'Resolved since raised' below._")
        if stale_gaps:
            lines.append("")
            lines.append(f"### Resolved since raised ({len(stale_gaps)})")
            lines.append("_Kept for the historical record (Insight is append-only) -- each of these "
                          "already has a probe result now; check the relevant claim/insight above "
                          "rather than treating these as open questions._")
            lines.append("\n".join(_gap_block(ins, still_unexplored) for ins in stale_gaps))
    else:
        lines.append("_No synthesis run yet for this graph -- see aginiti/graph/insights.py's "
                     "synthesize_insights(). This section is expected to be the most valuable one over "
                     "time: a gap either points at an existing probe worth running next, or names a hole "
                     "in the operator library itself._")
    lines.append("")

    lines.append("## Hypotheses")
    if profile.hypotheses:
        lines.append("\n".join(_hypothesis_line(h) for h in profile.hypotheses))
    else:
        lines.append("_None formed yet -- a knowledge gap becomes a testable hypothesis once synthesis "
                     "gives it a prior belief (see aginiti/graph/insights.py)._")
    lines.append("")

    lines.append("## Capabilities discovered")
    lines.append("\n".join(_claim_line(c, profile.claim_tags) for c in profile.capabilities) or "_None observed._")
    lines.append("")

    lines.append("## Trust relationships")
    lines.append("\n".join(_claim_line(c, profile.claim_tags) for c in profile.trust_relationships)
                 or "_No trust-delegation behavior observed in this target -- not necessarily absent, "
                    "just not exercised by the probes run so far._")
    lines.append("")

    lines.append("## Tool behavior")
    if profile.tools_observed:
        lines.append("Tools actually invoked during evidence collection:")
        lines.append("\n".join(f"- `{t}`" for t in profile.tools_observed))
    else:
        lines.append("_No tool invocations observed._")
    lines.append("")

    lines.append("## Observed defenses")
    lines.append("\n".join(_claim_line(c, profile.claim_tags) for c in profile.observed_defenses) or "_None fired._")
    lines.append("")

    lines.append("## Reachable actions (security evaluation)")
    lines.append(
        "\n".join(_claim_line(c, profile.claim_tags) for c in profile.reachable_actions)
        or "_No compromise reached by the probes run so far. This is a security-evaluation "
           "consequence of the understanding below, not a separate verdict on the target._"
    )
    lines.append("")

    lines.append("## Reachable but unverified")
    lines.append("\n".join(_claim_line(c, profile.claim_tags) for c in profile.unverified) or "_None outstanding._")
    lines.append("")

    lines.append("## Assumptions disproven")
    lines.append("\n".join(_claim_line(c, profile.claim_tags) for c in profile.disproven) or "_None refuted so far._")
    lines.append("")

    lines.append("## Unexplored")
    if profile.unexplored_frontier:
        lines.append("\n".join(_frontier_line(op) for op in profile.unexplored_frontier))
    else:
        lines.append("_Every currently-reachable probe has been run._")
    lines.append("")

    lines.append("## Recommended next probes")
    if profile.recommended_next_probes:
        lines.append("\n".join(
            f"{i}. **{r.operator.id}** -- {r.operator.description}"
            + (f" _Question: {r.operator.understanding_question}_" if r.operator.understanding_question else "")
            + f" (utility={r.utility:.2f}: info_gain={r.info_gain:.2f}, "
              f"business_impact={r.business_impact:.2f}, path_progress={r.path_progress:.2f}, "
              f"emergent_impact={r.emergent_impact:.2f})"
            for i, r in enumerate(profile.recommended_next_probes, 1)
        ))
    else:
        lines.append("_No eligible probe has positive predicted value left._")

    return "\n".join(lines) + "\n"
