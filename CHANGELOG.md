# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it reaches 1.0. Pre-1.0, minor version bumps may include breaking
changes.

## [Unreleased]

## [0.2.0]

### Added — `aginiti/adaptive/` result-shape consistency (issues #8, #26, #27)

- New `aginiti/adaptive/base.py`: `AdaptiveEngineResult`, a `typing.Protocol`
  (modeled on `Policy(Protocol)` in `aginiti/core/policies/base.py`) that
  every result class in `aginiti/adaptive/` now conforms to structurally —
  `succeeded`, `score`, `winning_operator`, `final_result`, and a
  `steps_used` property — plus `finalize_on_success()`, the shared
  trial-recording helper every stop-on-success loop now routes through.
  Closes a real bug found along the way: 3 of the 4 stop-on-success engines
  (`refinement.py`, `crescendo.py`, `deceptive_delight.py`) hand-rolled the
  same success block and silently never recorded `winning_operator`, even
  though the operator was in scope at that exact line.
- `aginiti/adaptive/framing_discovery.py`: `run_framing_discovery()`'s ad
  hoc tuple return replaced with `FramingDiscoveryResult`, a dataclass
  composed *over* its underlying `VariantDiscoveryResult`/
  `AdaptiveRefinementResult` (not duplicating their fields) that also
  conforms to `AdaptiveEngineResult`. **Breaking:** `FullAssessmentResult
  .framing_discovery` (`aginiti/core/assessment.py`) changed type from
  `list[tuple[...]]` to `list[FramingDiscoveryResult]` — any external code
  unpacking that field as a tuple needs updating to attribute access.
- `aginiti/adaptive/variant_discovery.py`: added `VariantTrial.prompt_sent`
  — the one genuinely missing field found when evaluating full field-level
  consolidation of all six `aginiti/adaptive/` result classes into one
  dataclass. The rest of that consolidation, and rebuilding
  `refinement.py`/`crescendo.py`/`deceptive_delight.py` atop
  `variant_discovery.py`'s own engine, were evaluated and declined — see
  `aginiti/adaptive/README.md` for the full reasoning (in short:
  `refinement.py`'s "one claim key, retried with different wording" model
  is a real architectural mismatch with `variant_discovery.py`'s "one claim
  key per candidate" model, not just similarly-shaped loops).

### Changed — `experiments/` pruned to the reproducible core

- Removed roughly 1,275 files from `experiments/` — an undocumented
  internal research archive of dated, session-specific scripts never meant
  for public consumption — keeping only the 4 scripts that are offline,
  deterministic, reproducible with no target/API key required, and still
  exercised by the test suite: `agentic_primitives_dry_run.py`,
  `discovery_chain_dry_run.py`, `graduated_difficulty_dry_run.py`,
  `info_gain_normalization_dry_run.py`. Added `experiments/README.md`
  explaining the split. `experiments/` was never part of the published
  wheel (`pyproject.toml`'s `[tool.setuptools.packages.find]` only
  includes `aginiti*`), so this has no effect on `pip install
  aginiti-redteam`.

### Fixed — `aginiti/reporting/` cleanup

- `_OWASP_MAPPING`'s header comment claimed MIA/FIA were unimplemented;
  SECRET actually shares DRA's `attack_type` and is implemented — only FIA
  remains genuinely unmapped. Corrected, and while verifying it, found a
  real *live* gap: SPE findings (`attack_type="SPE"`, produced today by
  `run_spe_benchmark.py`) had no OWASP mapping at all — added
  `"SPE": "LLM07:2025 - System Prompt Leakage"`.
- Added missing `_ATTACK_DISPLAY_NAMES` entries for `secret`,
  `mia_interrogation`, `mia_interrogation_benchmark`, and `spe`.
- `aginiti/reporting/__init__.py` now exports the package's full public
  surface (`generate_markdown_report`, `generate_markdown_report_from_file`,
  `compute_mia_benchmark_metrics`, `html_to_pdf`, `load_run`,
  `CONDITION_LABELS`, `CONDITION_ORDER`) instead of just the two
  markdown-report functions.
- Moved `aginiti/reporting/interrogation_reparse.py` to
  `scripts/interrogation_reparse.py` — a narrow offline migration tool
  (re-scores an old results JSON with the current parser), not part of the
  library's runtime public API, so it has no business shipping inside the
  installable `aginiti*` wheel. Never documented as public API, but
  flagged here in case anyone imported it directly: use
  `scripts/interrogation_reparse.py` from a git checkout instead.

### Added — GitHub Pages documentation site

- Published a single-page framework documentation site (`docs/index.html`,
  live at the repository's GitHub Pages URL), split into a contributor
  guide and a framework-user guide covering installation, configuration,
  every attack's parameters, the adaptive campaign engine, and a full
  gotchas/FAQ reference.

### Fixed — documentation accuracy pass

- SPE-LLM (System Prompt Extraction) was a fully shipped, tested fourth
  attack that had never been added to the top-level narrative docs after
  landing — `README.md`'s standalone-attack-library section and repo
  tree, `docs/ARCHITECTURE.md`'s attack catalog and repo layout,
  `docs/BENCHMARKS.md`'s citation table, `docs/ROADMAP.md`'s shipped
  list, `docs/index.html`, and `CLAUDE.md`'s attack module registry /
  build status all only described three attacks (IKEA, SECRET,
  Interrogation). Added throughout.
- Corrected the test-count claim (stale "1,827") to the actual current
  1,857 across `README.md`, `README_pypi.md`, `docs/BENCHMARKS.md`, and
  `docs/index.html`, and the cited-paper count ("9+") to "10+" to include
  SPE-LLM's paper.
- `README_pypi.md`'s IKEA example passed a retired Groq model string
  (`llama-3.3-70b-versatile`, confirmed 404 on Groq's current catalog —
  see `aginiti/providers/llm.py`'s own default-model rationale) and a
  `target_url` with a `/chat` suffix that `AgentEndpoint` already appends
  itself (would have resolved to `/chat/chat`) — both fixed.
- `aginiti/providers/embedding.py` is the canonical home of `embed_texts`
  since the open-source-readiness reorg; `CLAUDE.md`'s locked-decisions
  section and build-status table still pointed at the old
  `aginiti/connectors/embedding.py` path (now a backward-compatible
  shim, not the canonical location) — corrected.
- `docs/benchmarking.md` was renamed to `docs/BENCHMARKS.md` during the
  open-source readiness pass; `CLAUDE.md` and `CONTRIBUTING.md` still
  linked the old, now-nonexistent filename — corrected.
- README.md's "Standalone attack library" heading's auto-generated GitHub
  anchor was fragile (broke the moment the heading text changed, taking
  its own in-page cross-reference down with it) — simplified the heading
  so its anchor no longer depends on the exact attack-name list in the
  parenthetical.

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
