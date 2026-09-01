# aginiti/core/policies — the 4-condition benchmark's shared substrate

`base.py` is the reference `base.py` for this directory: shared
precondition/constraint gating (which operators are even eligible right
now) is common infrastructure every benchmark condition gets for free —
it is not the thing under test. What differs between the 4 conditions
below is only *which eligible operator gets ranked first*, so sharing
`eligible_operators` across all of them is what makes the RQ1 ablation
actually isolate the planning policy rather than confounding it with
"which condition even gets to attempt which operator."

| Module | Condition (design doc Section 20) |
|---|---|
| `random_policy.py` | Random — uniform selection among eligible operators. The floor baseline. |
| `static_policy.py` | Static enumeration — fixed insertion order, never re-ranked by anything observed. Representative of garak/PyRIT-style systematic probing. |
| `memory_guided_policy.py` | Memory-guided — weighted by historical success rate only, no SSG access. Representative of the AutoRedTeamer mechanism. |
| `aginiti_policy.py` | Adapts `AginitiPlanner` (`aginiti/core/planner/aginiti_planner.py`) into this shared `Policy` interface. |
| `bayesian_policy.py` | Adapts `BayesianBanditPlanner` (Thompson-sampling operator selection) into the same interface. |

Every policy implements the same shape so `aginiti/core/campaign.py`'s
`run_campaign()` loop drives all of them through identical mechanics.
