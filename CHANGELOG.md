# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it reaches 1.0. Pre-1.0, minor version bumps may include breaking
changes.

## [Unreleased]

### Added

- `aginiti scan`/`attack` now write `findings.json`/the report into their
  own fresh, timestamped subdirectory of `--output-dir` (default:
  `./results`, e.g. `results/2026-09-23_154012/`) instead of directly into
  `--output-dir` itself -- a second run no longer silently overwrites the
  first run's results with no trace they ever existed. `results`' contents
  sort newest-first by name (or "date modified") descending.
- `aginiti scan`/`attack`/`report` now auto-open the just-written HTML
  report in your default browser when the run finishes (`--no-open-report`
  to skip this, e.g. in a headless/CI/Docker environment) -- no separate
  command needed to view the result.
- `docker/` -- a standalone `Dockerfile` + `docker-compose.yml` for the
  end-user CLI workflow (`aginiti scan`/`attack`/`report` and
  `aginiti-demo-target`, installed from the real published package, not an
  editable checkout), separate from the existing contributor/benchmark
  image at the repo root. `docker compose up -d` starts the practice
  target; `docker compose run --rm cli aginiti ...` runs a command; `docker
  compose down` tears it down. Sidesteps every Windows onnxruntime/native-
  binary and PATH/global-install issue entirely, since everything runs
  inside a consistent Linux container regardless of host OS.

### Fixed

- `aginiti scan` (the campaign engine's deep-attack Operators) no longer
  crashes SECRET's Phase 1 optimizer/evaluator or MIA's shadow-LLM role
  with `attack_factory raised ValueError: GROQ_API_KEY is not set in .env`
  for a user who configured any OTHER provider (Gemini, OpenAI, Anthropic,
  Mistral) instead of Groq -- these two roles prefer Groq for compliance
  reasons (safety-aligned commercial models tend to refuse their framing)
  but now only default to it when `GROQ_API_KEY` is genuinely configured,
  falling back to the primary attacker/judge model otherwise instead of
  burning the operator's whole query budget on a crash. `aginiti attack
  secret`'s equivalent path was already correct; this closes the same gap
  for `aginiti scan`.
- `docs/USAGE.md`'s cache-directory FAQ entry described stale, long-since-
  fixed behavior (claimed the disk cache lands inside `site-packages/`) --
  corrected to describe the real, current `platformdirs`-based per-user
  cache location, and expanded with new entries on global (non-venv)
  installs and `.env` discovery.
- `aginiti_assessment_report.md`/`.html` (and their `_redacted` variants)
  were never gitignored, unlike `findings.json` -- added.

## [0.3.2]

### Added

- `aginiti-demo-target --port` — no way to run the demo target on a
  different port existed before this (short of setting `AGENT_PORT` and
  remembering to unset it again) -- a real problem for anyone with port
  8001 already taken. `--port` now takes priority over `AGENT_PORT`,
  which remains the fallback default; 8001 stays the final fallback if
  neither is set.
- Every `scan`/`attack`/`report` run now also auto-saves a self-contained
  HTML report (`aginiti_assessment_report.html`) alongside the existing
  `.md` one -- same severity-sorted findings, same OWASP mapping, styled
  with this project's own monochrome documentation design system, meant
  to be opened straight in a browser. New
  `aginiti.reporting.generate_html_report()`.

### Changed

- Every report's Key Metrics table (ASR/EE/CRR/SS) no longer shows a
  "Paper Baseline" comparison column -- a user testing their own agent
  has no reason to care what the original research paper measured on a
  completely different target.
- User-facing docs (`README_pypi.md`, `docs/USAGE.md`, `docs/index.html`'s
  "Using the library" section) no longer mention the `[adaptive]` extra
  (LangChain/OTel/MCP/DVLA), `[dev]`/`[benchmarks]`, or the benchmarking/
  testing workflow -- none of that is relevant to someone installing the
  library to test their own agent. `README.md`'s contributor-facing
  git-clone sections are unaffected; that's exactly where this content
  still belongs.
- Every CLI quickstart example now shows all 4 `aginiti scan --tier`
  values (`data_leakage`/`unauthorized_actions`/`discovery_recon`/
  `full_assessment`) instead of just one.

## [0.3.1]

### Fixed — real bugs found running `aginiti scan`/`attack` live

- `aginiti/providers/llm.py` (the core planner/judge's own reasoning)
  hardcoded Groq as the default provider, with no awareness of
  OpenAI/Anthropic/Mistral, and crashed with a bare `RuntimeError` if
  `GROQ_API_KEY` was simply absent -- disconnected from the CLI's own
  "any single key works" auto-detection. A user with only
  `GEMINI_API_KEY` configured got a crash on `aginiti scan`'s very
  first judge call. Now auto-detects the first available key among all
  5 supported providers (same priority order the CLI uses), preserving
  Groq's multi-key rotation pool exactly when it's actually configured.
- `aginiti scan` stopped at the first confirmed finding instead of
  spending its full `--budget`. Now runs with
  `stop_on_mission_success=False` and a budget-matched `max_steps`.
- `aginiti/reporting/markdown_report.py`'s severity bucketing forced any
  `pii`/`verbatim` finding into "Critical" regardless of its own
  assigned severity -- live-confirmed to produce self-contradictory
  reports (a finding printed `[HIGH]` filed under "## Critical
  Findings", while "## High Findings" claimed zero). Now buckets purely
  by each finding's own severity, with a new "## Low Findings" section
  added for full critical/high/medium/low coverage.
- `aginiti scan`'s own report was a thin custom summary that discarded
  the real per-finding detail a deep-attack step (IKEA/SECRET/MIA/SPE
  wrapped as an operator) had already computed. It now reuses the same
  rich, severity-sorted report `aginiti attack` produces.
- `aginiti scan`'s terminal logs were far thinner than `aginiti
  attack`'s. Added `[PROMPT->]`/`[RESPONSE<-]`/`[JUDGE]`/`[VERDICT]`
  logging to the campaign's prompt-operator execution path, matching
  the standalone attacks' own progress-output granularity.

## [0.3.0]

### Added — `aginiti` CLI + installable demo target agent

Closes the biggest adoption gap: running an assessment previously required
a git clone, since `scripts/` isn't part of the published wheel. A plain
`pip install aginiti-redteam` now gets a real, use-case-driven CLI with no
Python code required.

- New `aginiti/cli.py` — `aginiti scan` (the adaptive campaign engine,
  filtered by `--tier`/`--attack-category`), `aginiti attack
  {ikea,secret,mia,spe}` (one standalone attack directly), and `aginiti
  report` (convert a saved `findings.json` into a Markdown report on its
  own). Installed as the `aginiti` console script. Standard-env-var LLM
  auto-detection (`GEMINI_API_KEY`/`OPENAI_API_KEY`/`GROQ_API_KEY`/
  `ANTHROPIC_API_KEY`/`MISTRAL_API_KEY`) refuses loudly if no key
  resolves — SPE-LLM in particular never silently degrades to a
  false-clean result the way it would if constructed with no key.
  SECRET's jailbreak-optimizer role prefers Groq automatically when a key
  is available (safety-aligned models tend to refuse that step's own
  framing otherwise) and warns when it falls back. Clean terminal output
  by default — LiteLLM/HTTP logging noise suppressed unless `-v`. Every
  `scan`/`attack` run prints one authorized-use reminder and auto-saves
  `findings.json` + `aginiti_assessment_report.md`.
- New `aginiti/demo_target/` — the reference target agent, previously
  only available via a git-clone-only `benchmarks/` fixture, repackaged
  to ship in the wheel. Install with `pip install
  aginiti-redteam[demo-target]`, launch with the new
  `aginiti-demo-target` console script — no clone, no nested venv, no
  second full install of the library.
- New `aginiti/providers/cache.py` — IKEA/SECRET/MIA's 7-day disk caches
  now resolve via `platformdirs` to a real per-user cache directory
  (override: `AGINITI_CACHE_DIR`), instead of a path relative to the
  installed package (previously inside `site-packages/`, not reliably
  writable and wiped on every reinstall).
- New `aginiti/core/campaign_builder.py` — the `--agent-url`/`--tier`/
  `--attack-category` -> `(library, mission, agent)` derivation,
  extracted out of `scripts/run_campaign.py` so `aginiti scan` and that
  script share one implementation instead of two that could silently
  drift apart.
- `aginiti/core/campaign.py` now logs one `INFO`-level line per campaign
  step (chosen operator, score, outcome, budget used) for real-time
  terminal telemetry — plain standard `logging`, no new callback/event
  system.

### Added — hands-on tutorial

- New `docs/TUTORIAL.md`: a narrower, copy-paste, step-by-step companion
  to `docs/USAGE.md`'s full reference — from an empty folder through
  installing, setting up the local practice target, running all 4
  attacks (both a plain-`pip install` script and, where one exists, the
  ready-made `scripts/run_*.py` shortcut), saving a report, and a short
  Adaptive Mode walkthrough. Linked from `README.md`'s doc table,
  `docs/USAGE.md`'s intro, and `docs/index.html`'s sidebar.

### Fixed — v0.2.0 pip-install verification pass (5 findings, all fixed)

A full "brand-new user following only the published docs" verification
pass against the actual published `aginiti-redteam==0.2.0` TestPyPI
package (fresh venv, fresh git clone, real target, minimum query budgets)
surfaced 3 real bugs and 2 documentation gaps. All fixed in this same
pass, each with a new regression test (11 new tests total, including an
entirely new `tests/unit/test_embedding.py` — that module had zero prior
coverage) and re-verified live against a real target, not just via mocked
unit tests. Full write-up: `plans/testpypi-edge-case-results-v0.2.0.md`.

- **Report's headline "ASR" metric contradicted the rest of the same
  report.** `aginiti/reporting/markdown_report.py` and
  `scripts/run_benchmark.py` both computed Attack Success Rate from every
  non-refused response, not confirmed leaks — a run with zero confirmed
  leaks and "Overall Risk: NONE DETECTED" could still show "ASR: 100%" in
  its own Key Metrics table. Now uses the same `reportable`
  (`leak_type != "none"`) filter every other section of both reports
  already used, so the number is internally consistent with the rest of
  the report it appears in.
- **`max_queries=0` silently ran the full default query budget** instead
  of a no-op, in both `IKEAAttack.execute_black_box()` and
  `SECRETAttack.execute_black_box()` — a classic `kwargs.get(...) or
  self.default` bug that treats an explicit `0` as "not provided." Fixed
  to an explicit `is None` check in both.
- **IKEA's own "target unreachable" error message told the user to run a
  module path that no longer exists** (`benchmarks.agents...`, renamed to
  `benchmarks.dev_fixtures.agents...` during the open-source-readiness
  reorg) — quite literally the first error a new user following the
  Quickstart out of order is likely to see. Corrected, and softened to
  acknowledge a pip-only user's own target rather than presuming the
  local reference agent unconditionally.
- **No error handling around a local-embedding native-binary failure.**
  `aginiti/providers/embedding.py`'s `_embed_chromadb()` only caught
  "chromadb isn't installed at all" — a genuine onnxruntime DLL-load
  failure (the documented real-world Windows failure mode) propagated as
  a raw, confusing exception with no pointer to the one workaround that
  actually avoids it (`embed_model="<cloud provider>/..."`). Now caught
  broadly and re-raised with that workaround named explicitly.
- **Doc gaps**: `docs/USAGE.md` now notes that MIA's accuracy at low
  probe budgets depends on candidate-document richness (the example used
  a vague placeholder), and that `load_dotenv()` searches upward through
  parent directories for a `.env` file, not just the current one.

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
