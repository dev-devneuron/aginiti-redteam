# aginiti/core — the campaign engine (Adaptive Mode)

The autonomous orchestrator that builds and reasons over a Security State
Graph (SSG) of the target, ranks candidate `Operator`s, and executes a
multi-step campaign — Aginiti's Tier-2+ "Adaptive Mode," distinct from
running a single deep attack from `aginiti/attacks/` directly (see root
`README.md`'s Direct Mode vs. Adaptive Mode section for the user-facing
version of this split).

## Subpackages

| Directory | What it holds |
|---|---|
| `graph/` | The Security State Graph itself: `schema.py` (`Claim`, `ClaimStatus`, `Observation`), `ssg.py` (the append-only store), and every typed taxonomy dimension a claim can carry (`attack_category.py`, `owasp_llm_taxonomy.py`, `security_boundary.py`, `mitre_atlas_refs.py`, `failure_diagnosis.py`, `novelty.py`, ...). |
| `planner/` | `aginiti_planner.py` — the constrained-utility planner (`a* = argmax ...` subject to risk/budget/approval constraints) — plus `bayesian_planner.py` and `variants.py`. |
| `policies/` | `base.py` — shared eligibility/constraint-gating substrate for all 4 benchmark conditions (Random, Static, Memory-guided, Aginiti) — plus one concrete policy per condition. What differs between conditions is only *which eligible operator gets ranked first*; everything else is shared here so the comparison actually isolates the planning policy. |

## Top-level modules

| Module | What it does |
|---|---|
| `campaign.py` | `run_campaign()` — the loop tying policy + adapter + SSG + mission together, with decision-trace logging. Generalized over `Policy`, not hardwired to `AginitiPlanner`, so the same loop mechanics drive every benchmark condition. |
| `mission.py` | `Mission` — goal, success criteria (`success_mode="any"` for genuinely branching missions), budget, risk threshold. |
| `observation_adapter.py` | Turns one operator execution into an `Observation` applied to the SSG — the black-box-fidelity boundary (Tier 1: text in, text out, no internals). |
| `finding_translation.py` | Pure `LeakFinding -> ClaimStatus` bridge, the pattern that lets a deep `aginiti/attacks/` result feed into the SSG as a first-class claim. |
| `understanding_loop.py` | The closed Plan→Execute→Learn loop — deliberately NOT built into `campaign.py`'s main loop; see its own docstring for why. |
| `assessment.py` | `run_full_assessment()` — orchestrates the `aginiti/adaptive/` search engines together. |
| `composite_score.py` | Severity-weighted campaign scoring (a system-prompt leak and an exfiltrated customer record are not equally severe "successes"). |
| `scenarios.py` | Shared `Mission` definitions so every script tests against the same scenario. |
| `stats.py` | Dependency-free paired, multiple-comparison-corrected statistical comparison for benchmark runs. |
| `observability.py` | This project's structured-logging setup (`logging`-based, library-safe — never calls `basicConfig()` or attaches handlers at import time). |
| `benchmark.py` | The 4-condition benchmark runner (Random / Static / Memory-guided / Aginiti). |

`report.py`, `pdf_export.py`, and `logging_utils.py` remain here only as
backward-compatible re-export shims — the real implementations moved to
`aginiti/reporting/` and `aginiti/core/trial_logging.py` respectively; see
those modules' own docstrings.
