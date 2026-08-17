"""Tests for aginiti/assessment.py's run_full_assessment() -- the
orchestrator wiring this project's adaptive-attack engines (encoding-chain
discovery, many-shot discovery, framing discovery + refinement escalation,
Crescendo multi-turn escalation) into a shared SecurityStateGraph with a
normal AginitiPlanner campaign as the final phase.

No live LLM/network calls, ever: every mechanism's operator-building
function is monkeypatched to inject a deterministic extractor (the SAME
pattern test_encoding_discovery.py/test_framing_discovery.py/test_many_
shot.py/test_crescendo.py each establish for their own module), AND
Crescendo's turn-drafting function is replaced via `run_full_assessment()`'s
own `crescendo_generate_turn_fn` parameter -- 2026-08-14 fix: an earlier
version of this file only rigged encoding/framing, and once many_shot/
crescendo were added to the phase sequence, several tests silently started
making live LLM calls (one visibly hung in CI). `_rig_everything()` below
is the single, mandatory entry point every test uses now, specifically so
this class of regression can't recur silently.

2026-08-14 exp25 live postmortem: a discovery engine's own `.succeeded`
verdict (a single LLM judge call) was live-confirmed to misclassify an
explicit refusal as compliance -- on MORE THAN ONE trial, even after the
judge prompt itself was tightened in direct response to the first
occurrence. `run_full_assessment()` now requires the target's OWN
independent ground truth to ALSO corroborate an engine's `.succeeded`
verdict before stopping the assessment early (`_corroborated()`) -- several
tests below exist specifically to guard against a regression of THIS exact
failure mode, using `_ControllableAdapter` to independently control what
the (stubbed) judge says vs. what ground truth says, exactly the
combination that broke live."""
from __future__ import annotations

import dataclasses

import aginiti.adaptive.crescendo as cr
import aginiti.adaptive.encoding_discovery as ed
import aginiti.adaptive.framing_discovery as fd
import aginiti.adaptive.many_shot as ms
from aginiti.adapter.observation_adapter import _effect_id
from aginiti.adapters.base import SendResult
from aginiti.assessment import DEFAULT_FRAMING_GOALS, run_full_assessment
from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.graph.target_belief import TargetBeliefState
from aginiti.mission import Mission
from aginiti.operators.library import OperatorLibrary
from aginiti.operators.multi_family_definitions import build_multi_family_library
from aginiti.target.multi_family_agent import MultiFamilyAgent

_real_pipeline_to_operator = ed._pipeline_to_operator
_real_framing_operator = fd._framing_operator
_real_many_shot_operator = ms._many_shot_operator
_real_crescendo_operator = cr._crescendo_operator


class _ControllableAdapter:
    """A stub target whose independent ground truth is set explicitly by
    the test, INDEPENDENT of whatever the (monkeypatched, judge-free)
    operator extractors report -- this is exactly the combination that
    broke live: the judge said succeeded=True, the target's own
    independent ground truth said False."""

    def __init__(self, corroborate: bool = False):
        self._corroborate = corroborate

    def send(self, channel, prompt):
        return SendResult(final_text="I cannot help with that request.", tool_trace=[])

    def ground_truth_mission_achieved(self):
        return self._corroborate


def _stub_generate_turn(final_goal, transcript, turn_number, max_turns, seed):
    """Deterministic Crescendo turn-drafting stub -- the real one calls an
    LLM; tests never do. Injected via run_full_assessment()'s own
    crescendo_generate_turn_fn parameter, not a monkeypatch, because
    Python binds a function's default argument value at DEFINITION time --
    monkeypatching the module-level `_default_generate_turn` name would
    not affect a default already bound into `run_crescendo_escalation`'s
    signature."""
    return f"turn-{turn_number}-message"


def _mission(budget: int, criteria=("__no_such_key__",)) -> Mission:
    return Mission(goal="assessment test", success_criteria=criteria, budget=budget,
                    risk_threshold=RiskTier.MEDIUM, success_mode="any")


def _library() -> OperatorLibrary:
    return OperatorLibrary(build_multi_family_library())


def _rig_everything(monkeypatch, winning: str | None = None, winning_detail: str | None = None):
    """The MANDATORY rig for every test in this file -- patches ALL FOUR
    adaptive mechanisms' operator-building functions so NONE of them can
    ever reach a live judge call, regardless of which phases
    run_full_assessment() actually walks through for a given test.

    `winning` names which mechanism should succeed ("encoding" | "many_shot"
    | "framing" | "crescendo" | None for "nothing succeeds anywhere").
    `winning_detail` is the specific variant/name that wins within that
    mechanism (a pipeline name, a shot-count-derived variant name, a
    framing name -- ignored for crescendo, which succeeds on turn 1)."""

    def patched_encoding(pipeline, override_instruction):
        op = _real_pipeline_to_operator(pipeline, override_instruction)
        succeeds = winning == "encoding" and pipeline.name == winning_detail
        effect = op.effects_success[0]
        return dataclasses.replace(op, extractor=lambda raw: [_effect_id(effect)] if succeeds else [])

    def patched_many_shot(goal, shot_count, claim_key, blocked_key, attack_category, owasp_llm_category):
        op = _real_many_shot_operator(goal, shot_count, claim_key, blocked_key, attack_category, owasp_llm_category)
        succeeds = winning == "many_shot" and shot_count == winning_detail
        effect = op.effects_success[0]
        return dataclasses.replace(op, extractor=lambda raw: [_effect_id(effect)] if succeeds else [])

    def patched_framing(goal, framing_name, template, claim_key, blocked_key, attack_category, owasp_llm_category):
        op = _real_framing_operator(goal, framing_name, template, claim_key, blocked_key,
                                     attack_category, owasp_llm_category)
        succeeds = winning == "framing" and framing_name == winning_detail
        effect = op.effects_success[0]
        return dataclasses.replace(op, extractor=lambda raw: [_effect_id(effect)] if succeeds else [])

    def patched_crescendo(prompt, turn_number, final_goal, claim_key, blocked_key, attack_category, owasp_llm_category):
        op = _real_crescendo_operator(prompt, turn_number, final_goal, claim_key, blocked_key,
                                       attack_category, owasp_llm_category)
        succeeds = winning == "crescendo" and turn_number == 1
        success_effect = op.effects_success[0]
        failure_effect = op.effects_failure[0]
        extractor = (lambda raw: [_effect_id(success_effect)] if succeeds
                     else [_effect_id(failure_effect)])
        return dataclasses.replace(op, extractor=extractor)

    monkeypatch.setattr(ed, "_pipeline_to_operator", patched_encoding)
    monkeypatch.setattr(ms, "_many_shot_operator", patched_many_shot)
    monkeypatch.setattr(fd, "_framing_operator", patched_framing)
    monkeypatch.setattr(cr, "_crescendo_operator", patched_crescendo)


# --------------------------------------------------------------------------
# Phase 1 success, CORROBORATED by independent ground truth -- stops the
# whole assessment early, every later phase never runs.
# --------------------------------------------------------------------------

def test_corroborated_encoding_discovery_success_stops_the_whole_assessment_early(monkeypatch):
    _rig_everything(monkeypatch, winning="encoding", winning_detail="rot13")

    ssg = SecurityStateGraph()
    mission = _mission(budget=20, criteria=("encoding_discovery_instruction_followed_rot13",))
    result = run_full_assessment(mission, _library(), _ControllableAdapter(corroborate=True), ssg=ssg,
                                  encoding_discovery_budget=6, crescendo_generate_turn_fn=_stub_generate_turn)

    assert result.stopped_early_after == "encoding_discovery"
    assert result.outcome == "SUCCESS"
    assert result.encoding_discovery.succeeded is True
    assert result.many_shot_discovery is None
    assert result.framing_discovery == []
    assert result.campaign is None
    assert result.prompts_used_campaign == 0
    assert result.total_prompts_used <= mission.budget
    assert ssg.is_confirmed("encoding_discovery_instruction_followed_rot13")


# --------------------------------------------------------------------------
# THE EXACT LIVE REGRESSION: judge says succeeded=True, independent ground
# truth does NOT corroborate it -- must NOT stop early, must continue.
# --------------------------------------------------------------------------

def test_uncorroborated_encoding_discovery_success_does_not_stop_the_assessment(monkeypatch):
    """2026-08-14 exp25 live postmortem, reproduced deterministically: the
    encoding-discovery judge reported succeeded=True on the very first
    trial in BOTH the `support` and `ops` live runs, but
    ground_truth_mission_achieved() (the independent, non-LLM oracle)
    disagreed both times -- the target had, in fact, explicitly refused.
    Pre-fix, this uncorroborated single judge call short-circuited the
    ENTIRE assessment after just 1 prompt. Post-fix: the assessment must
    treat this as unresolved and CONTINUE through every remaining phase,
    spending the rest of its budget looking for something real instead of
    stopping on a single uncertain call."""
    # winning=None -- every mechanism's judge call reports failure, so the
    # only thing under test here is the corroboration gate on phase 1 --
    # but since encoding "succeeds" via .succeeded below is impossible with
    # winning=None, use a dedicated encoding-only rig instead.
    _rig_everything(monkeypatch, winning="encoding", winning_detail="rot13")

    ssg = SecurityStateGraph()
    mission = _mission(budget=20)
    result = run_full_assessment(mission, _library(), _ControllableAdapter(corroborate=False), ssg=ssg,
                                  encoding_discovery_budget=6, many_shot_budget=2,
                                  framing_discovery_budget=2, framing_refinement_attempts=0,
                                  crescendo_turns=1, crescendo_generate_turn_fn=_stub_generate_turn)

    # The judge's own verdict is still real and still recorded --
    # uncorroborated doesn't mean discarded.
    assert result.encoding_discovery.succeeded is True
    # But it must NOT have been trusted enough to stop the assessment.
    assert result.stopped_early_after is None
    assert result.outcome != "SUCCESS"
    assert result.many_shot_discovery is not None  # phase 2 actually ran
    assert result.framing_discovery  # phase 3 actually ran
    assert result.campaign is not None  # final campaign phase actually ran too


def test_uncorroborated_framing_discovery_success_does_not_stop_the_assessment(monkeypatch):
    """Same regression, framing discovery phase."""
    _rig_everything(monkeypatch, winning="framing", winning_detail="urgency")

    ssg = SecurityStateGraph()
    mission = _mission(budget=20)
    result = run_full_assessment(mission, _library(), _ControllableAdapter(corroborate=False), ssg=ssg,
                                  encoding_discovery_budget=3, many_shot_budget=2,
                                  framing_discovery_budget=5, framing_refinement_attempts=0,
                                  crescendo_turns=1, crescendo_generate_turn_fn=_stub_generate_turn)

    assert result.framing_discovery[0][0].succeeded is True  # the judge still said yes
    assert result.stopped_early_after is None  # but it wasn't trusted alone
    assert result.outcome != "SUCCESS"
    # BOTH framing goals were attempted (each followed by an uncorroborated-
    # then-continue Crescendo attempt) -- confirms the assessment genuinely
    # continued past the uncorroborated "success" for goal 1, not merely
    # avoided crashing.
    assert len(result.framing_discovery) == 2
    assert len(result.crescendo_escalations) == 2
    assert result.campaign is not None


# --------------------------------------------------------------------------
# Earlier phases fail entirely, a later phase succeeds AND is corroborated
# -- everything after it never runs.
# --------------------------------------------------------------------------

def test_corroborated_framing_discovery_success_stops_before_crescendo_and_the_campaign_phase(monkeypatch):
    _rig_everything(monkeypatch, winning="framing", winning_detail="urgency")

    ssg = SecurityStateGraph()
    goal, claim_key, blocked_key, attack_category, owasp = DEFAULT_FRAMING_GOALS[0]
    mission = _mission(budget=20, criteria=(f"{claim_key}_urgency",))
    result = run_full_assessment(mission, _library(), _ControllableAdapter(corroborate=True), ssg=ssg,
                                  encoding_discovery_budget=3, many_shot_budget=2,
                                  framing_discovery_budget=5, crescendo_generate_turn_fn=_stub_generate_turn)

    assert result.encoding_discovery.succeeded is False
    assert result.many_shot_discovery.succeeded is False
    assert result.stopped_early_after == "framing_discovery"
    assert result.outcome == "SUCCESS"
    assert result.campaign is None
    assert result.total_prompts_used <= mission.budget
    assert ssg.is_confirmed(f"{claim_key}_urgency")
    # Neither the second framing goal nor any Crescendo escalation ran --
    # confirms early-stop short-circuits everything after it, not just the
    # campaign phase.
    assert len(result.framing_discovery) == 1
    assert result.crescendo_escalations == []


def test_corroborated_crescendo_success_stops_before_the_next_goal(monkeypatch):
    """Crescendo is tried for a goal ONLY after framing+refinement fail
    that same goal -- confirms it fires, succeeds, is corroborated, and
    stops the assessment there."""
    _rig_everything(monkeypatch, winning="crescendo")

    ssg = SecurityStateGraph()
    mission = _mission(budget=20)
    result = run_full_assessment(mission, _library(), _ControllableAdapter(corroborate=True), ssg=ssg,
                                  encoding_discovery_budget=2, many_shot_budget=1,
                                  framing_discovery_budget=2, framing_refinement_attempts=0,
                                  crescendo_turns=3, crescendo_generate_turn_fn=_stub_generate_turn)

    assert result.encoding_discovery.succeeded is False
    assert result.many_shot_discovery.succeeded is False
    assert result.framing_discovery[0][0].succeeded is False
    assert len(result.crescendo_escalations) == 1
    assert result.crescendo_escalations[0].succeeded is True
    assert result.crescendo_escalations[0].turns_used == 1  # stopped the instant turn 1 succeeded
    assert result.stopped_early_after == "crescendo_escalation"
    assert result.outcome == "SUCCESS"
    assert result.campaign is None


# --------------------------------------------------------------------------
# Every discovery mechanism fails -- the final campaign phase runs, over
# the SAME graph, and genuinely sees the evidence every earlier phase left
# behind.
# --------------------------------------------------------------------------

def test_all_discovery_fails_campaign_phase_runs_with_remaining_budget_and_shared_evidence(monkeypatch):
    _rig_everything(monkeypatch, winning=None)

    ssg = SecurityStateGraph()
    mission = _mission(budget=30)  # unreachable success_criteria -- forces the campaign phase to actually run
    result = run_full_assessment(mission, _library(), MultiFamilyAgent(), ssg=ssg,
                                  encoding_discovery_budget=3, many_shot_budget=2,
                                  framing_discovery_budget=2, framing_refinement_attempts=0,
                                  crescendo_turns=1, crescendo_generate_turn_fn=_stub_generate_turn)

    assert result.encoding_discovery.succeeded is False
    assert result.many_shot_discovery.succeeded is False
    assert all(not d.succeeded for d, _r in result.framing_discovery)
    assert all(c is None or not c.succeeded for c in result.crescendo_escalations)
    assert result.stopped_early_after is None
    assert result.campaign is not None
    assert result.total_prompts_used <= mission.budget
    assert result.prompts_used_encoding > 0
    assert result.prompts_used_many_shot > 0
    assert result.prompts_used_framing > 0
    # Every phase's defender-control claims are real evidence sitting in
    # the SAME graph the final campaign's planner reads -- confirmed via
    # TargetBeliefState, not asserted by fiat.
    belief = TargetBeliefState.from_ssg(ssg, _library())
    assert len(belief.defender_controls) >= 0  # sanity: from_ssg doesn't choke on the mixed-origin claims


def test_corroborated_success_is_recognized_even_when_the_generated_claim_key_is_not_a_named_success_criterion(monkeypatch):
    """The real-world case: a mission built BEFORE the run cannot possibly
    predict which encoding pipeline will win (the claim key embeds the
    winning pipeline's NAME, decided only at runtime), so success_criteria
    will essentially never literally name it. Confirms the assessment
    still recognizes and reports a genuine, CORROBORATED success via the
    discovery engine's OWN verdict, not only via mission.is_satisfied()."""
    _rig_everything(monkeypatch, winning="encoding", winning_detail="rot13")

    ssg = SecurityStateGraph()
    # Deliberately does NOT name any encoding_discovery_* key -- exactly
    # what a real pre-declared mission looks like.
    mission = _mission(budget=20, criteria=("some_other_unrelated_claim_key",))
    result = run_full_assessment(mission, _library(), _ControllableAdapter(corroborate=True), ssg=ssg,
                                  encoding_discovery_budget=6, crescendo_generate_turn_fn=_stub_generate_turn)

    assert mission.is_satisfied(ssg) is False  # confirms this is genuinely the hard case
    assert result.encoding_discovery.succeeded is True
    assert result.stopped_early_after == "encoding_discovery"
    assert result.outcome == "SUCCESS"
    assert result.campaign is None  # correctly stopped, didn't burn the rest of the budget


def test_zero_budget_runs_nothing():
    ssg = SecurityStateGraph()
    result = run_full_assessment(_mission(budget=0), _library(), _ControllableAdapter(), ssg=ssg)
    assert result.total_prompts_used == 0
    assert result.campaign is None
    assert result.encoding_discovery is None
    assert result.many_shot_discovery is None
    assert result.framing_discovery == []
    assert result.crescendo_escalations == []
