# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it reaches 1.0. Pre-1.0, minor version bumps may include breaking
changes.

## [Unreleased]

### Changed — open-source readiness pass

Directory reorganization and documentation work to bring the codebase up
to public-repository standards ahead of wider adoption:

- Removed 4 dead, untracked directories left over from an earlier
  codebase merge (`aginiti/{adapter,graph,planner,policies}/`),
  superseded by `aginiti/{adapters,core/graph,core/planner,core/policies}/`.
- `aginiti/__version__` now resolves dynamically from installed package
  metadata instead of a hardcoded string that had drifted out of sync
  with `pyproject.toml`.
- New `aginiti/providers/` package for LLM/embedding provider client code
  (`llm.py`, `embedding.py`) — separated from `aginiti/connectors/`, which
  now stays scoped to talking to the target under test (`endpoint.py`).
- Consolidated `aginiti/core/report.py` and `aginiti/core/pdf_export.py`
  into `aginiti/reporting/`, alongside the other report-generation
  modules already there.
- Renamed `aginiti/core/logging_utils.py` to `aginiti/core/trial_logging.py`
  — the old name read as Python's stdlib `logging` module; this module is
  benchmark trial result persistence, unrelated to log records.
- Moved `aginiti/target_hardening/` to `benchmarks/target_hardening/` — a
  benchmark-target hardening fixture, not an offensive red-team module, so
  it belongs under `benchmarks/` rather than the `aginiti/` attack-library
  namespace.
- Extracted the `Operator` schema (`Operator`, `ClaimEffect`,
  `Precondition`, `ClassPrecondition`) from `aginiti/operators/library.py`
  into a new `aginiti/operators/base.py`; `library.py` now holds only
  `OperatorLibrary`.
- Every move above left a backward-compatible re-export shim at the old
  import path (except `target_hardening/`, never part of the published
  wheel, so there was no external caller to protect).
- All four core attack papers (IKEA, SECRET, Interrogation/MIA, SPE-LLM)
  now cited venue-first (published venue, arXiv ID as secondary reference)
  throughout the codebase, rather than arXiv-only.
- Added a `README.md` to every `aginiti/` subdirectory that lacked one.
- Documented the deliberate duplication between
  `aginiti/attacks/mia/interrogation.py` (primary, paper-faithful) and
  `aginiti/adaptive/membership_inference.py` (a planner-composable
  restatement for adaptive campaigns) — both retained, cross-referenced.

## [0.1.2] and earlier

Initial public functionality, published to PyPI as `aginiti-redteam`:

- Core attack library: `LeakFinding`/`BaseAttack` (`aginiti/attacks/base.py`),
  the shared LLM-provider abstraction via LiteLLM, and the Tier 1
  (black-box) / Tier 2 (+ OTel traces) architecture.
- Four attack implementations: IKEA (Data Reconstruction), SECRET (a
  second DRA technique via jailbreak-optimized extraction), the
  Interrogation Attack (Membership Inference), and SPE-LLM (System Prompt
  Extraction).
- The Adaptive Mode campaign engine: Security State Graph, planner,
  policies, and the `Operator`/`OperatorLibrary` framework, composing
  ~140 operator-definition files across real and reference targets.
- Reference agents and benchmark fixtures (`benchmarks/dev_fixtures/`,
  `benchmarks/scaled_evals/`) for local development and reproducible
  benchmarking against the HealthCareMagic-1k dataset.
- Markdown assessment report generation.

See `docs/BENCHMARKS.md` for measured results and `README.md` for usage.
