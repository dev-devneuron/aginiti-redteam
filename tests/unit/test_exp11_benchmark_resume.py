"""Regression test for a real infrastructure bug caught on the FIRST live
run of experiments/exp11_live_anythingllm_planner_benchmark.py: 27/90
trials hit a genuine Groq daily-quota 429 (the target org's TPD limit
exhausted mid-run, a real external constraint, not a code defect), and
each failure wrote an error-record JSON file. The benchmark's resumability
(same convention as aginiti/benchmark.py) originally treated "trial file
exists" as "trial done" -- which would have silently and PERMANENTLY
skipped every failed trial on every future resume, since the error file's
mere existence looked identical to a real completed result. Fixed by
requiring the on-disk record to carry a real `outcome` field before it
counts as done.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))

from exp11_live_anythingllm_planner_benchmark import (  # noqa: E402
    CONDITIONS,
    _make_canary,
    _trial_is_complete,
)


def test_missing_file_is_not_complete(tmp_path):
    assert _trial_is_complete(str(tmp_path / "does-not-exist.json")) is False


def test_error_only_record_is_not_complete(tmp_path):
    # The EXACT shape a live 429/workspace-create/campaign failure writes --
    # see main()'s except blocks -- no `outcome` key at all.
    path = tmp_path / "trial.json"
    path.write_text(json.dumps({"mission": "m", "condition": "c", "trial": 0, "seed": 1,
                                 "error": "429 Rate limit reached... TPD Limit 100000, Used 99818"}))
    assert _trial_is_complete(str(path)) is False


def test_real_result_record_is_complete(tmp_path):
    # The EXACT shape save_trial/campaign_result_to_dict writes on success.
    path = tmp_path / "trial.json"
    path.write_text(json.dumps({"condition": "c", "trial": 0, "seed": 1, "outcome": "SUCCESS",
                                 "steps_executed": 2, "prompts_used": 2, "operators_executed": [],
                                 "operators_considered_total": 2, "decision_log": [], "execution_log": [],
                                 "final_claims": [], "graph_size": {}, "ground_truth_mission_achieved": True}))
    assert _trial_is_complete(str(path)) is True


def test_budget_exhausted_outcome_also_counts_as_complete(tmp_path):
    # Any real outcome value counts, not just "SUCCESS" -- a genuine
    # BUDGET_EXHAUSTED/SEARCH_EXHAUSTED result must never be re-run either.
    path = tmp_path / "trial.json"
    path.write_text(json.dumps({"outcome": "SEARCH_EXHAUSTED", "prompts_used": 3}))
    assert _trial_is_complete(str(path)) is True


# ---------------------------------------------------------------------------
# Regression test for a second, real infrastructure bug caught on the SAME
# first live run: mission3's ground-truth oracle checks a shared, cross-
# process listener log file that persists for the whole benchmark run.
# Reusing one canary across a trial's five sibling conditions meant one
# condition's genuine real exfiltration success silently made
# ground_truth_mission_achieved() return True for every OTHER condition at
# that same trial too -- confirmed live: random/static both showed
# ground_truth=True at (automatic_tool_exfil_chain, trial=1) purely because
# aginiti/greedy_info_gain, sharing that same canary, genuinely triggered
# it, even though random/static's own deterministic extractor correctly
# said "not_triggered" for their own campaigns. This never corrupted the
# actual success/outcome numbers (mission.is_satisfied() only reads the
# deterministic extractor's confirmed claims, never ground truth) -- only
# the ground-truth-disagreement metric, and only for mission3.
# ---------------------------------------------------------------------------

def test_canary_is_unique_per_condition_not_just_per_trial():
    seen = set()
    for condition in CONDITIONS:
        canary = _make_canary("automatic_tool_exfil_chain", condition, trial=1, seed=5001)
        assert canary not in seen, f"canary collision: {condition} reused a sibling condition's canary"
        seen.add(canary)
    assert len(seen) == len(CONDITIONS)


def test_canary_is_unique_per_trial_for_the_same_condition():
    seen = set()
    for trial in range(3):
        canary = _make_canary("automatic_tool_exfil_chain", "aginiti", trial, seed=5000 + trial)
        assert canary not in seen
        seen.add(canary)


def test_canary_is_unique_per_mission_for_the_same_condition_and_trial():
    m1 = _make_canary("single_step_data_exposure", "aginiti", trial=0, seed=5000)
    m2 = _make_canary("chat_rag_chain", "aginiti", trial=0, seed=5000)
    m3 = _make_canary("automatic_tool_exfil_chain", "aginiti", trial=0, seed=5000)
    assert len({m1, m2, m3}) == 3
