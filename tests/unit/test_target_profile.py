"""Tests for the Target Profile (aginiti/graph/target_profile.py) -- the
primary product artifact synthesized from the graph. No live API calls:
built entirely from hand-constructed SSGs/libraries, same pattern as
test_graph_queries.py.
"""
from aginiti.core.graph.schema import ClaimStatus, InsightCategory, RiskTier
from aginiti.core.graph.ssg import (
    CATEGORY_DEFENDER_CONTROL,
    CATEGORY_MISSION_OUTCOME,
    CATEGORY_TRUST_EDGE,
    CATEGORY_WORKFLOW,
    SUBGRAPH_DEFENDER,
    SecurityStateGraph,
)
from aginiti.core.graph.attack_category import ENCODING_ATTACK, MARKDOWN_NETWORK_EXFILTRATION
from aginiti.core.graph.mitre_atlas_refs import EXFILTRATION_VIA_TOOL_INVOCATION
from aginiti.core.graph.owasp_llm_taxonomy import LLM01_PROMPT_INJECTION, LLM06_EXCESSIVE_AGENCY
from aginiti.core.graph.security_boundary import BOUNDARY_L0, BOUNDARY_L5
from aginiti.core.graph.target_profile import build_target_profile, render_markdown
from aginiti.core.mission import Mission
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition


def _op(op_id, preconditions=(), effects_success=(), effects_failure=(), understanding_question=""):
    return Operator(
        id=op_id, description=f"do {op_id}", understanding_question=understanding_question,
        prompt="x", channel="direct", preconditions=preconditions, effects_success=effects_success,
        effects_failure=effects_failure, cost_prompts=1, risk_tier=RiskTier.LOW,
    )


def _mission():
    return Mission(goal="test", success_criteria=("compromise",), budget=10, risk_threshold=RiskTier.LOW)


def test_build_target_profile_computes_coverage_from_executed_ids():
    recon = _op("recon")
    unrun = _op("unrun", preconditions=(Precondition("nope", ClaimStatus.CONFIRMED),))
    library = OperatorLibrary([recon, unrun])
    ssg = SecurityStateGraph()
    ssg.record_operator_execution("recon", success=True)

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")

    assert profile.operators_executed == 1
    assert profile.operators_total == 2
    assert profile.coverage == 0.5


def test_build_target_profile_defaults_executed_ids_from_graph_history():
    # No executed_ids passed -- must be derived from ssg.operator_stats,
    # the correct behavior for a graph reloaded standalone from disk.
    op = _op("recon")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.record_operator_execution("recon", success=True)

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")

    assert profile.operators_executed == 1


def test_build_target_profile_populates_all_sections():
    ssg = SecurityStateGraph()
    ssg.assert_claim("plain_cap", "true", ClaimStatus.CONFIRMED)
    ssg.assert_claim("trusts_x", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    ssg.assert_claim("blocked", "true", ClaimStatus.CONFIRMED, subgraph=SUBGRAPH_DEFENDER,
                      category=CATEGORY_DEFENDER_CONTROL)
    ssg.assert_claim("compromise", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    # Tagged with a non-capability category, purely to isolate this test's
    # sections cleanly -- category and status are orthogonal dimensions,
    # so an untagged (default-capability) claim would legitimately show up
    # in BOTH `capabilities` and `unverified`/`disproven` simultaneously.
    ssg.assert_claim("maybe", "true", ClaimStatus.HYPOTHESIZED, category=CATEGORY_WORKFLOW)
    ssg.assert_claim("disproven_thing", "true", ClaimStatus.REFUTED, category=CATEGORY_WORKFLOW)
    ssg.record_fact("exec_1", "tool_call", {"tool": "lookup", "args": {}})
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")

    assert [c.key for c in profile.capabilities] == ["plain_cap"]
    assert [c.key for c in profile.trust_relationships] == ["trusts_x"]
    assert [c.key for c in profile.observed_defenses] == ["blocked"]
    assert [c.key for c in profile.reachable_actions] == ["compromise"]
    assert [c.key for c in profile.unverified] == ["maybe"]
    assert [c.key for c in profile.disproven] == ["disproven_thing"]
    assert profile.tools_observed == ["lookup"]


def test_render_markdown_handles_a_fully_empty_profile_without_crashing():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([_op("recon")])
    profile = build_target_profile(ssg, library, _mission(), target_name="empty-target")

    md = render_markdown(profile)

    assert "empty-target" in md
    assert "None observed" in md or "No trust-delegation" in md  # empty-section fallback text present
    assert "0/1 known probes run (0%)" in md


def test_render_markdown_includes_behavioral_and_security_insights_when_present():
    ssg = SecurityStateGraph()
    ssg.assert_claim("trusts_x", "true", ClaimStatus.CONFIRMED, category=CATEGORY_TRUST_EDGE)
    ssg.record_insight(InsightCategory.BEHAVIORAL, "the agent trusts any source claiming internal origin",
                        derived_from=("trusts_x",))
    ssg.record_insight(InsightCategory.SECURITY, "impersonation-based disclosure appears unlikely",
                        derived_from=("trusts_x",))
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "Behavioral insights" in md
    assert "the agent trusts any source claiming internal origin" in md
    assert "Security insights" in md
    assert "impersonation-based disclosure appears unlikely" in md
    assert "trusts_x" in md  # grounding citation visible


def test_render_markdown_includes_knowledge_gaps_with_and_without_a_matched_probe():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "memory persistence unknown",
                        related_probe_id="probe_memory")
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "multi-agent comms unknown", related_probe_id=None)
    library = OperatorLibrary([_op("recon"), _op("probe_memory")])  # probe_memory genuinely still unexplored

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "Knowledge gaps" in md
    assert "memory persistence unknown" in md
    assert "probe available: **probe_memory**" in md
    assert "multi-agent comms unknown" in md
    assert "no probe in the current library addresses this yet" in md


def test_render_markdown_marks_a_gaps_related_probe_stale_once_it_has_run():
    # Regression test: an Insight is append-only, so an old gap's
    # related_probe_id is never mutated after the probe it named has since
    # executed -- rendering has to detect that staleness itself.
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.record_insight(InsightCategory.KNOWLEDGE_GAP, "memory persistence unknown",
                        related_probe_id="probe_memory")
    ssg.record_operator_execution("probe_memory", success=True)  # ran AFTER the gap was recorded
    library = OperatorLibrary([_op("probe_memory")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target",
                                    executed_ids=frozenset({"probe_memory"}))
    md = render_markdown(profile)

    assert "probe available: **probe_memory**" not in md
    assert "probe **probe_memory** has since run" in md


def test_render_markdown_includes_full_insight_reasoning_fields():
    ssg = SecurityStateGraph()
    ssg.assert_claim("k1", "true", ClaimStatus.CONFIRMED)
    ssg.record_insight(InsightCategory.BEHAVIORAL, "the agent inspects tool arguments before execution",
                        derived_from=("k1",), confidence="medium",
                        alternative_explanations=("model-level safety", "wrapper validation"),
                        evidence_still_missing=("only one user role tested", "no delegated authority tested"))
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "confidence: medium" in md
    assert "Alternative explanations: model-level safety; wrapper validation" in md
    assert "Known limitations: only one user role tested; no delegated authority tested" in md


def test_render_markdown_includes_security_questions_section():
    op = _op("probe", effects_success=(ClaimEffect("trusts_x", ClaimStatus.CONFIRMED, weight=1),),
             understanding_question="Does the agent trust X?")
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()
    ssg.assert_claim("trusts_x", "true", ClaimStatus.CONFIRMED)
    ssg.record_operator_execution("probe", success=True)

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "Security questions" in md
    assert "Does the agent trust X?" in md
    assert "answered" in md
    assert "trusts_x (confirmed)" in md


def test_render_markdown_notes_when_no_synthesis_has_run():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "No synthesis run yet" in md


def test_render_markdown_includes_recommended_probes():
    op = _op("recon", effects_success=(ClaimEffect("compromise", ClaimStatus.CONFIRMED, weight=3),))
    library = OperatorLibrary([op])
    ssg = SecurityStateGraph()

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "recon" in md
    assert "Recommended next probes" in md


def test_render_markdown_shows_hypotheses_section_empty_state():
    ssg = SecurityStateGraph()
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "## Hypotheses" in md
    assert "None formed yet" in md


def test_render_markdown_shows_an_open_hypothesis_with_its_experiments():
    ssg = SecurityStateGraph()
    ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                         experiments=("probe_memory",), prior_confidence=0.6)
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "agent persists memory" in md
    assert "open, confidence: 0.60" in md
    assert "testable via: probe_memory" in md


def test_render_markdown_shows_a_resolved_hypothesis_with_its_evidence():
    ssg = SecurityStateGraph()
    ssg.form_hypothesis("agent persists memory", "memory_persists", ClaimStatus.CONFIRMED,
                         experiments=("probe_memory",), prior_confidence=0.6)
    ssg.assert_claim("memory_persists", "true", ClaimStatus.CONFIRMED)
    library = OperatorLibrary([_op("recon")])

    profile = build_target_profile(ssg, library, _mission(), target_name="test-target")
    md = render_markdown(profile)

    assert "accepted, confidence: 0.85" in md
    assert "supporting: memory_persists" in md


# --- severity/taxonomy summary (2026-08-12 architecture-review fix: these SSG methods
# existed and were fully tested but were never called from build_target_profile/
# render_markdown until now) ------------------------------------------------------

def test_build_target_profile_is_blind_by_default_when_nothing_is_tagged():
    ssg = SecurityStateGraph()
    ssg.assert_claim("untagged_finding", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME)
    profile = build_target_profile(ssg, OperatorLibrary([_op("recon")]), _mission(), target_name="t")

    assert profile.highest_boundary is None
    assert profile.owasp_findings == {}
    assert profile.attack_category_findings == {}
    assert profile.atlas_techniques_confirmed == {}
    assert profile.claim_tags == {}


def test_build_target_profile_populates_severity_and_taxonomy_rollups():
    ssg = SecurityStateGraph()
    ssg.assert_claim("l0_finding", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME,
                      security_boundary=BOUNDARY_L0, owasp_llm_category=LLM01_PROMPT_INJECTION,
                      attack_category=ENCODING_ATTACK)
    ssg.assert_claim("l5_finding", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME,
                      security_boundary=BOUNDARY_L5, owasp_llm_category=LLM06_EXCESSIVE_AGENCY,
                      attack_category=MARKDOWN_NETWORK_EXFILTRATION,
                      mitre_atlas_technique=EXFILTRATION_VIA_TOOL_INVOCATION)
    profile = build_target_profile(ssg, OperatorLibrary([_op("recon")]), _mission(), target_name="t")

    assert profile.highest_boundary == BOUNDARY_L5
    assert profile.owasp_findings == {LLM01_PROMPT_INJECTION: 1, LLM06_EXCESSIVE_AGENCY: 1}
    assert profile.attack_category_findings == {ENCODING_ATTACK: 1, MARKDOWN_NETWORK_EXFILTRATION: 1}
    assert profile.atlas_techniques_confirmed == {"l5_finding": EXFILTRATION_VIA_TOOL_INVOCATION}
    assert profile.claim_tags["l0_finding"] == "[L0] [LLM01] [encoding_attack]"
    assert profile.claim_tags["l5_finding"] == \
        f"[L5] [LLM06] [{MARKDOWN_NETWORK_EXFILTRATION}] [{EXFILTRATION_VIA_TOOL_INVOCATION}]"


def test_render_markdown_shows_an_honest_absence_when_nothing_is_tagged():
    ssg = SecurityStateGraph()
    profile = build_target_profile(ssg, OperatorLibrary([_op("recon")]), _mission(), target_name="t")
    md = render_markdown(profile)

    assert "## Severity & taxonomy summary" in md
    assert "none classified yet" in md
    assert "none tagged and confirmed yet" in md
    assert "none cross-referenced and confirmed yet" in md


def test_render_markdown_shows_the_deepest_boundary_and_taxonomy_breakdowns():
    ssg = SecurityStateGraph()
    ssg.assert_claim("l5_finding", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME,
                      security_boundary=BOUNDARY_L5, owasp_llm_category=LLM06_EXCESSIVE_AGENCY,
                      attack_category=MARKDOWN_NETWORK_EXFILTRATION,
                      mitre_atlas_technique=EXFILTRATION_VIA_TOOL_INVOCATION)
    profile = build_target_profile(ssg, OperatorLibrary([_op("recon")]), _mission(), target_name="t")
    md = render_markdown(profile)

    assert "`L5_sensitive_data_exfiltration`" in md
    assert "Sensitive-data exfiltration" in md  # BOUNDARY_DESCRIPTIONS text, not just the raw code
    assert "LLM06:2025_excessive_agency" in md
    assert "Excessive Agency" in md
    assert "Markdown / Network Exfiltration" in md
    assert "`AML.T0086`" in md
    assert "Exfiltration via AI Agent Tool Invocation" in md


def test_render_markdown_tags_reachable_action_lines_with_their_taxonomy():
    ssg = SecurityStateGraph()
    ssg.assert_claim("l5_finding", "true", ClaimStatus.CONFIRMED, category=CATEGORY_MISSION_OUTCOME,
                      security_boundary=BOUNDARY_L5, attack_category=MARKDOWN_NETWORK_EXFILTRATION)
    profile = build_target_profile(ssg, OperatorLibrary([_op("recon")]), _mission(), target_name="t")
    md = render_markdown(profile)

    reachable_section = md[md.index("## Reachable actions"):md.index("## Reachable but unverified")]
    assert f"[L5] [{MARKDOWN_NETWORK_EXFILTRATION}]" in reachable_section
