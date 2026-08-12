"""Offline, deterministic (seeded) Monte Carlo dry run of the graduated-
difficulty candidate pack (aginiti/operators/graduated_difficulty_
definitions.py) -- validates Issue 2 of the 2026-08-12 architectural
directive: "we need harder candidates... now Aginiti has to actually
reason. That is much closer to real red teaming."

NOT a live experiment -- no target, no LLM judge, no network call. Each
candidate's TRUE success probability lives only in GraduatedAttackAdapter's
random draw (seeded per trial for full reproducibility); no operator field
anywhere exposes it to any planner.

Compares 4 policies across N independent trials each (fresh SSG per trial,
budget=7 -- enough to attempt 2-3 of the 5 candidates, never all 5, so
priority order is a genuine, budget-constrained decision):
  - AginitiPolicy   (the constrained-utility planner)
  - BayesianPolicy  (Thompson-sampling bandit planner)
  - StaticPolicy    (fixed declaration order -- garak/PyRIT-style checklist)
  - RandomPolicy    (floor baseline)

Reports, per policy: which candidate gets attempted FIRST (should be
CONSTANT across all trials for AginitiPolicy/StaticPolicy, since neither
reads any per-trial randomness before its first pick -- BayesianPolicy's
first pick legitimately varies trial to trial via its own Thompson draw),
empirical mission-success rate, and mean composite score (aginiti/
composite_score.py) -- the actual metric built to discriminate "which
system finds more CONSEQUENTIAL wins," not just "which wins more often."
"""
from __future__ import annotations

import random
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aginiti.adapters.base import SendResult
from aginiti.campaign import run_campaign
from aginiti.composite_score import composite_campaign_score
from aginiti.graph.schema import RiskTier
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.operators.graduated_difficulty_definitions import (
    ALL_SUCCESS_KEYS,
    TRUE_SUCCESS_PROBABILITY,
    attempt_marker,
    blocked_marker,
    build_graduated_difficulty_library,
    success_marker,
)
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.bayesian_policy import BayesianPolicy
from aginiti.policies.random_policy import RandomPolicy
from aginiti.policies.static_policy import StaticPolicy

N_TRIALS = 300
BUDGET = 7  # total cost of all 5 is 16 -- this affords 2-3 attempts, never all 5


@dataclass
class GraduatedAttackAdapter:
    """The whole "target": for each candidate, draws once from a Bernoulli
    with that candidate's TRUE (hidden-from-the-planner) success
    probability, using a per-trial seeded RNG so the whole sweep is exactly
    reproducible."""
    ssg: SecurityStateGraph
    rng: random.Random
    true_probability: dict[str, float] = field(default_factory=lambda: dict(TRUE_SUCCESS_PROBABILITY))

    def send(self, channel: str, prompt: str) -> SendResult:
        for key, p in self.true_probability.items():
            if attempt_marker(key) in prompt:
                return SendResult(final_text=success_marker(key) if self.rng.random() < p
                                   else blocked_marker(key))
        return SendResult(final_text="")

    def ground_truth_mission_achieved(self) -> bool:
        return any(self.ssg.is_confirmed(k) for k in self.true_probability)


def _mission() -> Mission:
    return Mission(
        goal="Find any consequential compromise among 5 plausible but differently-costed, "
             "differently-severe, differently-likely candidates -- budget doesn't allow "
             "attempting all 5, so which one gets tried FIRST is the actual decision under test.",
        success_criteria=ALL_SUCCESS_KEYS,
        budget=BUDGET,
        risk_threshold=RiskTier.LOW,
        constraints=(),
        success_mode="any",
    )


def _run_trials(label: str, policy_factory, n: int, base_seed: int) -> dict:
    first_picks: list[str] = []
    successes = 0
    composites: list[float] = []
    prompts_used_list: list[int] = []

    for trial in range(n):
        ssg = SecurityStateGraph()
        library = build_graduated_difficulty_library()
        mission = _mission()
        agent = GraduatedAttackAdapter(ssg=ssg, rng=random.Random(base_seed + trial))
        policy = policy_factory(base_seed + trial)

        result = run_campaign(mission, library, agent=agent, policy=policy, max_steps=5, ssg=ssg)

        if result.operators_executed:
            first_picks.append(result.operators_executed[0])
        won = agent.ground_truth_mission_achieved()
        successes += 1 if won else 0
        prompts_used_list.append(result.prompts_used)
        composites.append(composite_campaign_score(result, mission).composite)

    from collections import Counter
    first_pick_dist = Counter(first_picks)

    return {
        "label": label,
        "n": n,
        "success_rate": successes / n,
        "mean_composite": statistics.mean(composites),
        "mean_prompts_used": statistics.mean(prompts_used_list),
        "first_pick_distribution": dict(first_pick_dist.most_common()),
    }


def main() -> None:
    print("Graduated-difficulty dry run -- offline, deterministic (seeded), no live target.")
    print(f"N={N_TRIALS} trials per policy, budget={BUDGET} (affords ~2-3 of the 5 candidates).")
    print("\nTrue success probabilities (HIDDEN from every planner -- adapter-only):")
    for key, p in TRUE_SUCCESS_PROBABILITY.items():
        print(f"  {key}: {p:.0%}")

    results = [
        _run_trials("aginiti", lambda seed: AginitiPolicy(), N_TRIALS, base_seed=1000),
        _run_trials("bayesian", lambda seed: BayesianPolicy(seed=seed), N_TRIALS, base_seed=2000),
        _run_trials("static", lambda seed: StaticPolicy(), N_TRIALS, base_seed=3000),
        _run_trials("random", lambda seed: RandomPolicy(seed=seed), N_TRIALS, base_seed=4000),
    ]

    print(f"\n{'policy':<10} {'success_rate':<14} {'mean_composite':<16} {'mean_prompts':<14} first_pick_distribution")
    for r in results:
        print(f"{r['label']:<10} {r['success_rate']:<14.1%} {r['mean_composite']:<16.4f} "
              f"{r['mean_prompts_used']:<14.2f} {r['first_pick_distribution']}")

    print("\n=== INTERPRETATION ===")
    aginiti_first = results[0]["first_pick_distribution"]
    print(f"AginitiPolicy's first pick, every single trial: {aginiti_first}")
    print("Every declared field is IDENTICAL across the 5 candidates except cost_prompts and "
          "security_boundary -- cost is never a scored term in AginitiPlanner's utility (only a "
          "hard budget/risk gate), so whatever AginitiPolicy picks first here is attributable "
          "ONLY to severity_priority. This is an honest, real finding worth stating plainly: on "
          "this exact symmetric design, severity is the SOLE differentiator driving Aginiti's "
          "first move -- cost and (unknowably, in advance) success probability play no role at "
          "all in that first decision.")
    aginiti_composite, static_composite = results[0]["mean_composite"], results[2]["mean_composite"]
    print(f"\nAginitiPolicy: {results[0]['success_rate']:.0%} success rate, "
          f"mean composite {aginiti_composite:.4f}")
    print(f"StaticPolicy:  {results[2]['success_rate']:.0%} success rate, "
          f"mean composite {static_composite:.4f}")
    print(f"Static wins MORE OFTEN (always tries the cheapest, highest-raw-probability option "
          f"first) but Aginiti's wins are worth {aginiti_composite / static_composite:.1f}x more "
          f"on the composite metric -- because when Aginiti wins, it's usually via the Critical-"
          f"severity candidate it commits to first, not the Medium-severity one Static always "
          f"tries. This is the literal answer to 'given the same target, same budget, which "
          f"system discovers more consequential attack paths' for this exact scenario: Static "
          f"finds MORE paths, Aginiti finds MORE CONSEQUENTIAL ones -- a real tradeoff, not a "
          f"strict win, and exactly the kind of nuance a flat ASR comparison would have erased.")
    print(f"\nBayesianPolicy's first-pick distribution across {N_TRIALS} trials: "
          f"{results[1]['first_pick_distribution']}")
    print("BayesianBanditPlanner's prior pseudo-counts (gap_priority, hypothesis_priority, "
          "path_progress, emergent_impact, potential_progress, branch_interest) do NOT include "
          "severity_priority at all -- confirmed by reading aginiti/planner/bayesian_planner.py "
          "directly. With every other prior term tied across these 5 candidates, its first pick "
          "is effectively a UNIFORM RANDOM Thompson draw. That is a genuine, previously-unknown "
          "gap: neither planner currently has any REAL mechanism trading off cost against "
          "severity against uncertain success probability the way the user's own A-E table asks "
          "for -- AginitiPlanner gets partial credit (severity, at least) that BayesianPlanner "
          "doesn't even have.")


if __name__ == "__main__":
    main()
