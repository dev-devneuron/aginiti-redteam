# aginiti/attacks — deep, paper-faithful attack implementations

Every module here is a standalone, `BaseAttack`-subclass implementation of
a published attack technique — heavyweight, runnable on its own against a
real HTTP target with its own query budget and calibration, not a
lightweight planner-selectable `Operator` (see `aginiti/operators/`) or a
stateful runtime search engine (see `aginiti/adaptive/`). See root
`CLAUDE.md` (§"attacks/ vs. operators/ vs. adaptive/") for the full
three-way distinction.

## `base.py` — the shared, locked contract

`LeakFinding` (a dataclass every attack emits) and `BaseAttack` (the ABC
every attack subclasses, including its `execute()` black-box-vs-traces
dispatch and shared `_init_llm` provider setup) are **locked** — field
names, types, and dispatch logic must not change without explicit
sign-off. This is the reference `base.py` for the whole codebase; read it
before writing a new `base.py` anywhere else.

## Attacks implemented

| Directory | Attack | Paper |
|---|---|---|
| `dra/` | IKEA (Data Reconstruction) | Wang et al., ICLR 2026 (arXiv:2505.15420) |
| `dra/` | SECRET (2nd DRA technique) | He et al., IEEE TIFS 2026 (arXiv:2510.02964) |
| `mia/` | Interrogation Attack (Membership Inference) | Naseh et al., ACM CCS 2025 (arXiv:2502.00306) |
| `spe/` | SPE-LLM (System Prompt Extraction) | Das, Amini, Wu, ICLR 2026 (arXiv:2505.23817) |

Each subdirectory has its own `README.md` with usage, paper mapping, and
safety notes — start there for a specific attack.

## Tier architecture (applies to every attack here)

- **Tier 1 — black-box / endpoint only.** Every attack must produce real
  findings with zero instrumentation. Never optional or secondary.
- **Tier 2 — endpoint + OTel traces.** An enhancement layer upgrading
  evidentiary confidence — `execute_with_traces()` must call
  `execute_black_box()` internally and only post-process the result, never
  reimplement extraction logic.

Authorized use only — every attack here is intended exclusively for
security testing of systems you own or have explicit written permission
to test.
