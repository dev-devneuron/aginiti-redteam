"""Tests for experiments/exp12_branching_benchmark.py's mission/library
builders -- pure, offline, no live calls. Guards the specific design
properties this benchmark redesign exists to deliver (see the module's own
docstring for the exp11 diagnosis these fix): genuine multi-way branching
at step 1 (not a forced single-eligible-operator chain), and mission1's
tightened success_mode="all" over only the reachable keys.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

from exp12_branching_benchmark import (  # noqa: E402
    _mission_branching_automatic_rag,
    _mission_branching_chat_rag,
    _mission_single_step_comprehensive,
)


def test_mission1_has_all_six_data_exposure_operators():
    mission, library = _mission_single_step_comprehensive(seed=1)
    assert {op.id for op in library} == {
        "system_prompt_extraction", "jailbreak_dan_style", "memory_context_leakage_probe",
        "tool_inventory_full_disclosure", "encoding_evasion_probe", "secret_pattern_fishing",
    }


def test_mission1_success_mode_is_all_over_only_the_reachable_keys():
    mission, _ = _mission_single_step_comprehensive(seed=1)
    assert mission.success_mode == "all"
    assert set(mission.success_criteria) == {
        "system_prompt_disclosed", "jailbreak_safety_bypassed",
        "tool_schema_overdisclosed", "encoded_instruction_followed",
    }
    # The two operators independently confirmed defended against this
    # target must NOT be required for success -- that would make the
    # mission unwinnable by design, a floor effect just as uninformative
    # as exp11's ceiling effect.
    assert "context_leakage_confirmed" not in mission.success_criteria
    assert "secret_pattern_disclosed" not in mission.success_criteria


def test_mission2_has_genuine_branching_at_step_one():
    # The exact bug this redesign fixes: exp11's chat_rag_chain had exactly
    # ONE eligible operator at every step. Here, at a fresh SSG, the plant
    # operator (no precondition) and all 3 distractors (no precondition)
    # must ALL be eligible together -- only the trigger (precondition-
    # gated on the plant) should be excluded until the plant confirms.
    from aginiti.graph.ssg import SecurityStateGraph
    from aginiti.policies.base import eligible_operators
    from aginiti.mission import Mission

    mission, library = _mission_branching_chat_rag(seed=1, canary="X")
    ssg = SecurityStateGraph()
    elig = eligible_operators(library, ssg, mission, prompts_used=0, executed_ids=frozenset())
    elig_ids = {op.id for op in elig}
    assert elig_ids == {
        "anythingllm_rag_document_plant", "system_prompt_extraction",
        "jailbreak_dan_style", "memory_context_leakage_probe",
    }
    assert "anythingllm_rag_injection_trigger" not in elig_ids  # precondition not yet met


def test_mission3_has_genuine_branching_at_step_one():
    from aginiti.graph.ssg import SecurityStateGraph
    from aginiti.policies.base import eligible_operators

    mission, library = _mission_branching_automatic_rag(seed=1, canary="Y")
    ssg = SecurityStateGraph()
    elig = eligible_operators(library, ssg, mission, prompts_used=0, executed_ids=frozenset())
    elig_ids = {op.id for op in elig}
    assert elig_ids == {
        "anythingllm_automatic_exfil_document_plant", "system_prompt_extraction",
        "tool_inventory_full_disclosure", "secret_pattern_fishing",
    }
    assert "anythingllm_automatic_indirect_tool_exfil_trigger" not in elig_ids


def test_mission2_and_mission3_use_distinct_distractor_sets():
    # Guards against accidentally testing the exact same distractor
    # operators twice under a different mode label, which would make the
    # two missions redundant rather than genuinely distinct.
    _, lib2 = _mission_branching_chat_rag(seed=1, canary="X")
    _, lib3 = _mission_branching_automatic_rag(seed=1, canary="Y")
    ids2 = {op.id for op in lib2} - {"anythingllm_rag_document_plant", "anythingllm_rag_injection_trigger"}
    ids3 = {op.id for op in lib3} - {"anythingllm_automatic_exfil_document_plant",
                                       "anythingllm_automatic_indirect_tool_exfil_trigger"}
    assert ids2 != ids3
    assert "memory_context_leakage_probe" in ids2 and "memory_context_leakage_probe" not in ids3
    assert "secret_pattern_fishing" in ids3 and "secret_pattern_fishing" not in ids2
