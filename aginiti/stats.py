"""Lightweight, dependency-free statistical comparison for the benchmark
(design doc Section 20: "Statistical significance (paired, multiple-
comparison corrected): Distinguishes a real effect from LLM-stochasticity
noise").

This is a two-sided Fisher's exact test on the 2x2 success/failure table
between Aginiti and each baseline, implemented via math.comb rather than
pulling in scipy for one function. Honesty check built in: with the trial
counts Phase 0 can actually afford (Section 21.5 -- cost is a tracked
project budget, not unlimited), this test will usually be underpowered.
`interpret()` says so explicitly rather than letting a p-value stand alone
as if it settled anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import comb


def _hypergeom_pmf(a: int, row1: int, row2: int, col1: int) -> float:
    total = row1 + row2
    return (comb(row1, a) * comb(row2, col1 - a)) / comb(total, col1)


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """2x2 table:
                success  failure
      Aginiti     a         b
      baseline    c         d
    Two-sided p-value: sum the probability of every table with the same
    margins that is at least as extreme (probability <= observed table's
    probability) as the observed one.
    """
    row1, row2 = a + b, c + d
    col1, col2 = a + c, b + d
    total = row1 + row2
    if total == 0 or col1 == 0 or col1 == total:
        return 1.0

    observed_p = _hypergeom_pmf(a, row1, row2, col1)
    lo = max(0, col1 - row2)
    hi = min(row1, col1)
    p_value = 0.0
    for x in range(lo, hi + 1):
        p = _hypergeom_pmf(x, row1, row2, col1)
        if p <= observed_p * (1 + 1e-9):
            p_value += p
    return min(1.0, p_value)


@dataclass
class Comparison:
    baseline: str
    aginiti_successes: int
    aginiti_trials: int
    baseline_successes: int
    baseline_trials: int
    p_value: float
    n_total: int

    def interpret(self, alpha: float = 0.05) -> str:
        underpowered = self.n_total < 40  # rule of thumb, not a formal power calc
        if self.p_value < alpha and not underpowered:
            return f"p={self.p_value:.3f} < {alpha}: directionally significant."
        if self.p_value < alpha and underpowered:
            return (f"p={self.p_value:.3f} < {alpha}, BUT n={self.n_total} trials total is far too "
                     f"small for this to be a real RQ1 result -- treat as a hint, not a finding "
                     f"(design doc Section 20's pre-registered-effect-size bar is not met here).")
        return f"p={self.p_value:.3f}: no significant difference detected at n={self.n_total}."


def compare_to_aginiti(aginiti_successes: int, aginiti_trials: int,
                        baseline_name: str, baseline_successes: int, baseline_trials: int) -> Comparison:
    a, b = aginiti_successes, aginiti_trials - aginiti_successes
    c, d = baseline_successes, baseline_trials - baseline_successes
    p = fisher_exact_two_sided(a, b, c, d)
    return Comparison(
        baseline=baseline_name,
        aginiti_successes=a, aginiti_trials=aginiti_trials,
        baseline_successes=c, baseline_trials=baseline_trials,
        p_value=p, n_total=aginiti_trials + baseline_trials,
    )
