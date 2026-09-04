"""Synthetic, in-process mock targets used by tests/experiments/campaigns
(design doc Section 21.1 et al.) -- DemoAgent plus deterministic, zero-LLM
scenario agents that validate specific planner fixes offline
(FamilyCoverageScenarioAgent, HiddenStateAgent, MultiFamilyAgent,
TechniqueClusterScenarioAgent).

Relocated here from `aginiti/target/` (integration Slice C, see
plans/integration-plan.md and plans/PLAN.md): these are dev/benchmark
fixtures, not shipped library code -- `pyproject.toml`'s
`[tool.setuptools.packages.find]` only includes `aginiti*`, so a real
`pip install aginiti-redteam` never ships this package. This mirrors the
same "core stays lean" principle already applied to
`benchmarks/dev_fixtures/` and `benchmarks/scaled_evals/` (FastAPI/Uvicorn/
Faker moved to the `dev` extra for the same reason).

The two real BaseAdapter implementations that used to live alongside these
in `aginiti/target/` (`injecagent_adapter.py`, `injecagent_pool_adapter.py`)
moved to `aginiti/adapters/` instead in the same slice -- they're
target-connector code, not target simulations, so they belong with the
other adapters, not here.
"""
