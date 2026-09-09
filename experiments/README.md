# experiments — offline, reproducible planner validation scripts

This directory used to also hold this project's own internal research
archive (live, target-dependent experiment scripts and their raw result
dumps) — pruned from the public repo since none of it was documented or
reproducible for an outside contributor, and the conclusions it produced
already live in [`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md) in cited,
public form. What's left here is deliberately different: every script below
is fully offline and deterministic — **no target, no LLM judge, no network
call, no API key** — so anyone can run one directly and reproduce the exact
finding it reports.

| Script | What it validates |
|---|---|
| `graduated_difficulty_dry_run.py` | Compares 4 planner policies (Aginiti, Bayesian, Static, Random) over a synthetic 5-candidate library with hidden, seeded success probabilities — the real finding behind `docs/ARCHITECTURE.md`'s composite-score claim: Static wins more often, but Aginiti's wins are worth more because it commits to the highest-severity candidate first. |
| `discovery_chain_dry_run.py` | Confirms `ClassPrecondition`'s semantic-tag gating genuinely generalizes — two independently-authored, mutually substitutable "establish trust" operators both unlock the same downstream chain, over `aginiti/operators/discovery_chain_definitions.py`. |
| `agentic_primitives_dry_run.py` | Same generalization check applied to a second, independently-authored operator pack (`aginiti/operators/agentic_primitives_definitions.py`) — approval gates and untrusted tool-output content. |
| `info_gain_normalization_dry_run.py` | A pure-formula regression check on `AginitiPlanner`'s info-gain normalization mode ("sum" vs "mean"), run against multiple target libraries to check the ranking behavior generalizes before either mode becomes the default. |

Run any of them directly:

```bash
python experiments/graduated_difficulty_dry_run.py
```

`graduated_difficulty_dry_run.py`'s own `_mission()`/`BUDGET` fixture is
also reused directly by
[`tests/integration/test_graduated_difficulty.py`](../tests/integration/test_graduated_difficulty.py)
— it's real, tested code, not a standalone demo.
