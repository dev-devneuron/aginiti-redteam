# aginiti/core/graph — the Security State Graph (SSG)

The evidentiary core of Adaptive Mode: an append-only store of what has
been observed about a target, and every typed dimension a claim in it can
carry.

## Core store

| Module | What it holds |
|---|---|
| `schema.py` | `Claim`, `ClaimStatus`, `Observation` — the base data structures (Section 15). Two node categories: append-only facts and the beliefs derived from them. |
| `ssg.py` | `SecurityStateGraph` — the append-only store itself. Claims and Observations are never mutated or deleted; "current state" for a claim key is a query over the log, not a stored table. |
| `persistence.py` | Save/load a `SecurityStateGraph` to/from JSON so it can outlive a single campaign process. |
| `export.py` | Exports a graph into a generic, adapter-agnostic node-link structure for visualization (see `templates/graph_view.html`). |

## Derived/cached understanding (not new sources of truth)

| Module | What it holds |
|---|---|
| `belief_state.py` | `CampaignBeliefState` — a lightweight, planner-facing cache of derived understanding over the SSG. |
| `target_belief.py` | `TargetBeliefState` — a stateful, campaign-level model of what's actually been learned, built exclusively from the SSG's own evidence. |
| `target_graph.py` | A lightweight directed graph derived from CONFIRMED structural claims — answers "what path exists from here" questions. |
| `target_profile.py` | The rendered target-facing "Behavioral Security Assessment." |
| `hypothesis.py` | `Hypothesis` — the one genuinely mutable, persistent-identity object in the graph (a revised belief updates in place, unlike the append-only Fact/Observation/Claim). |
| `insights.py` | Synthesizes `Insight`s — the tier above Fact/Observation/Claim. |
| `priors.py` | Cold-start context seeding so a fresh SSG's candidate ranking isn't uninformative on turn one. |
| `candidate_status.py` | Per-candidate exclusion accounting — why an operator was skipped, not just that it was. |
| `decision_trace.py` | `DecisionTrace` — a structured record of why the planner chose a given operator, from values `AginitiPlanner.rank()` already computed. |
| `independent_evidence.py` | `IndependentFinding` — lets an adapter report evidence independent of a specific operator's own extractor. |
| `queries.py` | Analyst-facing read queries over a `SecurityStateGraph`. |

## Typed taxonomy dimensions a claim/effect can carry

| Module | Dimension |
|---|---|
| `attack_category.py` | Which of the 11 attack methodologies (8 offensive + 3 planner-evaluation controls). |
| `owasp_llm_taxonomy.py` | OWASP Top 10 for LLM Applications (2025) category. |
| `security_boundary.py` | `BOUNDARY_L0`..`L5` — which real-world trust boundary a confirmed effect represents. |
| `mitre_atlas_refs.py` | Verified MITRE ATLAS technique IDs (deliberately incomplete — only confirmed, never guessed). |
| `failure_diagnosis.py` | The 5-category taxonomy for *why* an effect represents a failure. |
| `novelty.py` | Family/technique-cluster-level saturation so the planner doesn't keep sampling near-duplicate variants forever. |

All opt-in, orthogonal dimensions — `None` on any of them means "not yet
tagged," never an error; see `aginiti/operators/base.py`'s `ClaimEffect`
for where an operator sets these.
