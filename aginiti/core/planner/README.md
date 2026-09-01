# aginiti/core/planner — candidate-ranking policies

| Module | What it does |
|---|---|
| `aginiti_planner.py` (`AginitiPlanner`) | The constrained-utility planner: `a* = argmax` over eligible candidates of a weighted-sum utility, subject to risk-tier/budget/human-approval constraints. `budget_feasible()` additionally checks that the REST of a chain an operator starts can still fit, not just the operator's own cost. See its own module docstring for the full utility formula (design doc Section 12, 17). |
| `bayesian_planner.py` | A Bayesian bandit planner — built in direct response to a self-conducted audit of `AginitiPlanner` finding two concrete, evidenced issues; see its own docstring for what and why. |
| `variants.py` | Pure-parameterization variants of `AginitiPlanner` — each zeroes out some subset of the utility's terms rather than introducing new reasoning (e.g. `GreedyInfoGainPlanner`, `GreedyBusinessImpactPlanner`), used for RQ1b ablations. |

Every planner here implements the `Policy` interface
(`aginiti/core/policies/base.py`) so `aginiti/core/campaign.py`'s
`run_campaign()` loop drives all of them identically.
