"""Regression tests for the graduated-difficulty candidate pack (Issue 2
of the 2026-08-12 architectural directive) -- the pytest counterpart to
experiments/graduated_difficulty_dry_run.py's Monte Carlo sweep. These
tests lock in the STRUCTURAL claims (no operator dominates on every axis;
success probability is never leaked into any operator field; AginitiPolicy
consistently prefers the candidate severity_priority favors) with small,
fast, deterministic trial counts -- the full N=300 sweep with interpretive
commentary lives in the experiments/ script, not here."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from aginiti.adapters.base import SendResult
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.operators.graduated_difficulty_definitions import (
    ALL_SUCCESS_KEYS,
    GRADUATED_TABLE,
    TRUE_SUCCESS_PROBABILITY,
    attempt_marker,
    blocked_marker,
    build_graduated_difficulty_library,
    success_marker,
)
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.static_policy import StaticPolicy


@dataclass
class _GraduatedAdapter:
    ssg: SecurityStateGraph
    rng: random.Random
    true_probability: dict = field(default_factory=lambda: dict(TRUE_SUCCESS_PROBABILITY))

    def send(self, channel: str, prompt: str) -> SendResult:
        for key, p in self.true_probability.items():
            if attempt_marker(key) in prompt:
                return SendResult(final_text=success_marker(key) if self.rng.random() < p
                                   else blocked_marker(key))
        return SendResult(final_text="")

    def ground_truth_mission_achieved(self) -> bool:
        return any(self.ssg.is_confirmed(k) for k in self.true_probability)


def test_no_candidate_dominates_on_every_axis():
    """The literal A-E table property: sort by success probability and by
    (negative) cost and by severity rank -- no single candidate is #1 on
    all three, which is what makes this a genuine tradeoff instead of an
    obvious-winner benchmark (exp16's own named failure mode)."""
    from aginiti.core.graph.security_boundary import rank as boundary_rank

    by_success = sorted(GRADUATED_TABLE, key=lambda row: -row[5])
    by_cost = sorted(GRADUATED_TABLE, key=lambda row: row[2])
    by_severity = sorted(GRADUATED_TABLE, key=lambda row: -boundary_rank(row[3]))

    best_on_all_three = {by_success[0][0]} & {by_cost[0][0]} & {by_severity[0][0]}
    assert not best_on_all_three, "a single candidate should not win on every axis at once"


def test_operator_declarations_never_leak_the_true_success_probability():
    """The true probability must exist ONLY in TRUE_SUCCESS_PROBABILITY /
    the mock adapter -- never as a readable field on the Operator itself
    (info_gain weight, description text, anything). A planner that could
    read it would trivially "solve" this benchmark, defeating its purpose."""
    library = build_graduated_difficulty_library()
    for op in library:
        assert not hasattr(op, "success_probability")
        for effect in (*op.effects_success, *op.effects_failure):
            assert not hasattr(effect, "success_probability")
        # every declared weight is identical across candidates -- the ONLY
        # things that vary are cost_prompts and security_boundary.
        assert op.effects_success[0].weight == 3
        assert op.effects_failure[0].weight == 1


def test_aginiti_policy_first_pick_is_deterministic_and_severity_driven():
    """With every other scored term tied by construction (see the pack's
    own module docstring), AginitiPolicy's first pick should be the SAME
    operator on every trial (it never reads the stochastic outcome before
    making its first choice) -- and it should be one of the two Critical-
    severity candidates (graduated_attack_c or _d), not the highest-raw-
    declared-probability one (which it can't see) or an arbitrary one."""
    first_picks = set()
    for trial in range(10):
        ssg = SecurityStateGraph()
        library = build_graduated_difficulty_library()
        from experiments.graduated_difficulty_dry_run import _mission  # reuse the real mission shape
        mission = _mission()
        agent = _GraduatedAdapter(ssg=ssg, rng=random.Random(trial))
        result = run_campaign(mission, library, agent=agent, policy=AginitiPolicy(), max_steps=5, ssg=ssg)
        assert result.operators_executed
        first_picks.add(result.operators_executed[0])

    assert first_picks == {"graduated_attack_c"} or first_picks == {"graduated_attack_d"}


def test_static_policy_always_tries_declaration_order_first():
    ssg = SecurityStateGraph()
    library = build_graduated_difficulty_library()
    from experiments.graduated_difficulty_dry_run import _mission
    mission = _mission()
    agent = _GraduatedAdapter(ssg=ssg, rng=random.Random(0))
    result = run_campaign(mission, library, agent=agent, policy=StaticPolicy(), max_steps=5, ssg=ssg)
    assert result.operators_executed[0] == "graduated_attack_a"  # first in GRADUATED_TABLE


def test_budget_never_allows_attempting_all_five():
    from experiments.graduated_difficulty_dry_run import BUDGET
    total_cost = sum(row[2] for row in GRADUATED_TABLE)
    assert BUDGET < total_cost, "the whole point is a budget that forces real prioritization"
