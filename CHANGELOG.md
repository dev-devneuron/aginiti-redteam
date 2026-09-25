# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it reaches 1.0. Pre-1.0, minor version bumps may include breaking
changes.

## [Unreleased]

### Added

- HTML report: an info icon on each finding's Technique chip shows a
  one-sentence, plain-language explanation of that technique on hover
  (or keyboard focus/tap); the Markdown report prints the same sentence
  under the technique name. Descriptions live in
  `aginiti/reporting/technique_descriptions.py` and cover every operator
  `aginiti scan --target` can run (enforced by a test).
- Any-LLM-provider support: `AGINITI_LLM_MODEL` (a LiteLLM
  `provider/model` string) + `AGINITI_LLM_API_KEY` route the judge,
  planner, `aginiti attack` and all `aginiti scan` deep-attack operators
  to any provider LiteLLM supports. Both quickstart scripts now offer this
  after the Groq/OpenAI/Gemini prompts (with examples), and check the
  configured LLM answers before starting the scan.

### Fixed

- `quickstart.ps1`: the health check polled `http://localhost`, which on
  Windows tries IPv6 first and stalls ~2s against the IPv4-only target --
  longer than the probe timeout -- so every probe failed and the script
  shut down a healthy target after ~3 minutes. Both scripts now use
  `127.0.0.1` for the health check and scan target, and fail fast if the
  target process exits during startup.
- `quickstart.sh`: under `curl ... | bash` in WSL, the `netstat.exe` port
  check consumed the rest of the piped script, so it exited silently
  after installing. The script body is now wrapped in `main()`, prompts
  read from `/dev/tty`, `.env` loading works on macOS's bash 3.2, and a
  Python >= 3.10 check and pre-seed failure message were added.
- `aginiti scan` now points all four deep-attack operators (SPE included,
  previously missed by `--model`) at the resolved model when no
  per-operator override is set, instead of a hardcoded Gemini default
  that failed for users without a Gemini key.
- LLM resilience: the Groq path retries transient 5xx/timeout/connection
  errors with backoff and falls back to any configured provider (not only
  Gemini); priors/insight passes degrade gracefully on LLM errors; a
  single failed judge call is recorded as unconfirmed, but three
  consecutive judge failures abort the scan rather than reporting
  unevaluated steps as clean.

- `quickstart.sh` (macOS/Linux/WSL) and `quickstart.ps1` (Windows
  PowerShell) -- one-command demo scripts that create/reuse an isolated
  venv, install `aginiti-redteam[demo-target]`, pre-seed the local ONNX
  embedding model and ChromaDB collection, pick a free port for the
  hardened demo target (prompting for another one if 8001 is taken),
  launch it in the background, run a full `aginiti scan --tier
  full_assessment --budget 50` against it, and shut the target down on
  exit -- the `curl ... | bash` / `irm ... | iex` one-liners now shown in
  both READMEs. Both scripts also guard against an orphaned demo target
  left behind by a killed earlier run of themselves (matched by command
  line, not PID, so it's safe to run unconditionally), and verify after
  their own readiness poll that the process actually answering on the
  chosen port is the one they just started, not something else that
  happened to be listening there.
- `aginiti scan`/`attack` now probe the target's `/health` endpoint
  before running (`aginiti/cli.py`'s `_probe_target_profile`) and print a
  structured "Target System Profile & Security Posture" banner
  classifying it as the Hardened Demo Agent, the Vanilla Demo Agent, or
  an external black-box target -- the same `target_profile`/
  `target_description`/`target_toggle_state` metadata now also flows into
  `findings.json`'s `run_metadata` and renders as a "Target Configuration
  & Security Posture" panel (with per-defense-layer status and a
  one-line description of what each layer actually does) in both the
  Markdown and HTML reports.
- `aginiti scan --target`/`scripts/run_campaign.py --agent-url` now load
  all 8 `channel="direct"` operator packs (47 operators total) instead of
  just 2 (`data_exposure_operators()` + `deep_attack_operators()`, 11
  operators) -- the other 6 (`encoding_variants`, `ascii_art_evasion`,
  `low_resource_language_evasion`, `output_filter_evasion`,
  `session_isolation_probe`, `access_control_layer_probe`) were already
  built and already `channel="direct"`-compatible (verified directly),
  just never wired into `campaign_builder.build_campaign()`'s
  `--agent-url` branch -- a real `--target` scan was silently missing
  over three-quarters of this project's own target-agnostic technique
  library. New `campaign_builder.all_target_agnostic_operators()` is the
  single list both entry points load. `classify_tier()` needed no changes
  to correctly bucket the additional 36 operators (verified: every one of
  them already carries an `owasp_llm_category` tag that the existing
  tier logic classifies correctly, in addition to their `attack_category`
  tag) -- live-verified against a running target: an
  `access_control_layer_probe` operator (previously unreachable from
  `aginiti scan`) was selected and produced a real confirmed finding.
- The HTML assessment report now has a "Download PDF" button in its
  header, using the browser's own `window.print()` rather than a
  server-generated `.pdf` file: this report is designed to be a
  standalone, shareable artifact, and a recipient who only has the one
  `.html` file (forwarded, uploaded, opened on a different machine) has
  no sibling `.pdf` sitting next to it and no Python environment to
  generate one -- the browser's built-in print-to-PDF always works, with
  no dependency on Chrome/Edge being installed wherever the report was
  originally created (unlike `aginiti/reporting/pdf_export.py`'s
  existing headless-browser subprocess approach, which remains a
  separate, CLI-time convenience for a different use case). New
  `@media print` rules force the light color palette regardless of the
  viewer's OS dark-mode setting (severity colors were tuned for contrast
  against light surfaces, and a dark background wastes ink/toner), keep
  every severity badge/card background from being silently stripped
  (`print-color-adjust: exact`), hide the button itself in the printed
  output, and avoid finding/KPI cards splitting awkwardly across page
  breaks. Live-verified end to end: rendered a real report through
  Chrome's headless `--print-to-pdf`, then rendered the resulting PDF
  pages to PNG for visual inspection -- confirmed the button is absent,
  colors and severity styling are fully intact, and cards don't split
  mid-card.

### Changed

- `docs/index.html` rewritten to be CLI-first, matching the README's own
  recent rewrite: removed the "If you cloned the repo -- the original
  CLI" section, which presented `python scripts/run_campaign.py` as a
  peer option to `aginiti scan` right after `aginiti scan` was already
  shown in full -- exactly the "separate script per attack" workflow the
  CLI replaced. The CLI & environment-variable reference table was headed
  "Flag (git checkout only)" while listing real `aginiti scan` flags
  available from a plain `pip install` -- actively misleading, not just
  outdated; rewritten as the actual `aginiti scan`/`attack` flag
  reference (also added `--output-dir`/`--redact`/`--no-open-report`,
  which existed on the CLI but weren't documented here at all). The
  Adaptive Mode Python example hand-built `[*data_exposure_operators(),
  *deep_attack_operators()]` (11 operators) -- updated to
  `all_target_agnostic_operators()` (47 operators/8 packs), the same
  single-source-of-truth list `aginiti scan --target` now loads. Fixed a
  results-table claim ("11 named attack methodologies... ArtPrompt,
  Crescendo, PAIR...") that conflated the `--attack-category` taxonomy's
  11 real values with an unrelated, partially-inaccurate paper-name list
  -- same shape of overclaim already found and fixed in README.md.
  Stale counts (1,925 tests, pre-expansion operator-pack sizing) updated
  throughout. `docs/USAGE.md`'s own "Reference" section had the identical
  gap (only documented `scripts/run_campaign.py`'s flags, no `aginiti
  scan`/`attack` table at all) -- fixed the same way.
- `docs/ARCHITECTURE.md`: fixed a broken example
  (`OperatorLibrary.by_category(...)` called as a class method --
  `by_category` is an instance method, this raises `TypeError`) and a
  stale `python scripts/run_campaign.py` CLI reference.
- `docs/ROADMAP.md`: moved "a dedicated `aginiti` CLI wrapper" from "Next
  up" to "Shipped" -- it shipped.
- `docs/TUTORIAL.md`, `docs/USAGE.md`, `docs/BENCHMARKS.md`: corrected
  stale test counts and the same pre-expansion "11 techniques" operator-
  pack sizing claim `aginiti scan --budget`'s own docs made.
- Moved 3 local-only, gitignored dev-journal files (`how-it-works.md`,
  `integration_executive_summary.md`, `feature-implementation.md`) from
  `docs/` to `plans/` and deleted an empty scratch file (`docs/issues.md`)
  for local clarity -- confirmed via `git ls-files docs/` that none of
  these (nor `executive-presentation.md`/`secret_spe_benchmarks.md`,
  left in place) were ever part of the public repo; this is pure local
  housekeeping with no effect on git history either way. Separately
  flagged, not changed: `docs/testing_your_own_onyx_deployment.md` is
  also gitignored despite reading as genuinely current, well-scoped,
  public-facing content -- looks like an accidental inclusion in the
  same gitignore block, left for a maintainer decision.

### Fixed

- `aginiti attack ikea` and `aginiti attack mia` crashed with
  `AttributeError: '...Attack' object has no attribute 'queries_sent'`
  right after the attack finished, before `findings.json`/the reports
  ever got written -- `_cmd_attack_ikea`/`_cmd_attack_mia` in
  `aginiti/cli.py` read `attack.queries_sent` directly, but only
  `SECRETAttack` actually sets that attribute; `IKEAAttack` and
  `InterrogationAttack` (MIA) never did (confirmed by inspecting each
  class's `__init__`). `aginiti attack spe` already worked around this
  with `getattr(attack, "queries_sent", len(findings))` -- the ikea/mia
  call sites now use the same safe pattern. Existing CLI tests didn't
  catch this because they mock the attack classes, and a `MagicMock`
  auto-generates any attribute a caller asks for instead of raising
  `AttributeError` the way the real classes do.
- `benchmarks/scaled_evals/agents/hardened_agent/main.py`'s
  `_resolve_caller` was changed (locally, uncommitted) to default to
  `HARDENED_AGENT_DEFAULT_PERSONA` ("legal") on ANY auth failure --
  including a malformed/unrecognized/expired credential, not just a
  missing one -- silently contradicting the module's own docstring ("a
  request with no/unrecognized/expired credential gets 401") and
  defeating this target's purpose as an auth/RBAC bypass test fixture (a
  bad token would appear to "work" instead of being rejected). Narrowed
  back to only default when NO `Authorization` header is offered at all
  (the actual intent -- letting `aginiti scan` black-box-test this
  target without first minting a token); a header that IS present but
  wrong still raises 401 as before.
- `aginiti/reporting/markdown_report.py`'s new `_DEFENSE_DESCRIPTIONS`
  dict (one-line descriptions of what each defense layer does, e.g.
  "Pre-flight classifier blocking adversarial/malicious prompts before
  processing") was defined but never referenced anywhere, in either
  report. Wired into both the Markdown "Active Defense Layers" table
  (new "What it does" column) and the HTML report's defense-layer table.
- 3 `TestTargetConfiguration` tests in `tests/unit/test_markdown_report.py`
  and 1 operator-chip test in `tests/unit/test_html_report.py` asserted
  the PRE-existing "## Target Configuration" / "**Authenticated as:**" /
  "On"/"Off" markdown and the plain (no "Technique:" prefix) HTML chip
  markup -- both already changed (locally, uncommitted) to "## Target
  Configuration & Security Posture" / "**Authenticated Persona:**" /
  "Active"/"Disabled" and the "<strong>Technique:</strong> ..." chip
  format. Updated the tests to match the new, intentional format instead
  of reverting it.
- Stale test-count claims (`1,925`/`1,997`/`2,004`/`2000`) across
  `README.md`, `README_pypi.md`, `docs/BENCHMARKS.md`, `docs/TUTORIAL.md`,
  and `docs/index.html` corrected to the current count (2,010, re-verified
  via `pytest tests/ --collect-only -q` at fix time rather than reused
  from an earlier planning pass).
- SECRET's Phase 1 (jailbreak optimization) could still fail even after
  0.3.3's optimizer-model fix, this time from Groq rate-limiting rather
  than refusal: `_resolve_secret_optimizer`/`_resolve_role_model` picked
  ONE Groq key (`GROQ_API_KEY`) for the optimizer/evaluator role, even
  when `.env` had a full rotation pool configured (`GROQ_API_KEY_2`,
  `_3`, ...) for exactly this reason. Phase 1 makes `n_iter * n_cand`
  optimizer calls plus a comparable number of evaluator calls before
  Phase 2 ever starts -- easily enough to exhaust a single free-tier
  key's TPM limit on its own (live-reproduced: `Rate limit reached for
  model openai/gpt-oss-20b... TPM: Limit 8000`). `aginiti/providers/
  llm.py`'s `_call_with_rotation` already solved this exact problem for
  the campaign/judge role, and `BaseAttack._init_llm` already had a
  matching `api_keys` rotation-pool parameter (used by SECRET's
  `semantic_shift_api_keys` and MIA's `shadow_llm_api_keys`) -- just
  never finished wiring into `BaseAttack.__init__` itself, or into
  SECRET's optimizer/evaluator role specifically, on either the `aginiti
  attack secret` or `aginiti scan`/`hardened_deep_attack_operators.py`
  path. `BaseAttack.__init__` now forwards an additive `api_keys`
  parameter; `JailbreakOptimizer`/`SECRETAttack` gained matching
  `optimizer_api_keys`/`evaluator_api_keys` parameters (evaluator
  defaults to the optimizer's pool, same precedent as its single-key
  default); `MIA_OPERATOR_SHADOW_LLM_PROVIDER`'s pool now flows through
  too. All additive, every existing single-key caller unchanged. Live-
  verified against a running hardened target: a rate-limited call now
  logs `[RATE LIMIT] key 1/29 rate-limited ... rotating to the next key
  immediately` and continues, instead of the whole optimizer call
  failing outright.

## [0.3.3]

### Changed

- Every `--help` screen (`aginiti --help`, and every subcommand/technique's
  own) rewritten for a reader with no knowledge of this project's internals
  and no particular technical background -- the previous text assumed
  familiarity with internal terms (Operator, RAG, "Phase 1 optimizer") and
  in the top-level description even included literal file paths and
  reST-style double-backtick markup meant for a documentation renderer, not
  a plain terminal. `--target` (previously undocumented on every `aginiti
  attack` technique) and every other flag now has a plain-language
  description; each technique's own description explains what it actually
  does before mentioning its source paper. The technical module docstring
  developers see in the source is unchanged; a new, separate
  `_CLI_DESCRIPTION` constant is what `--help` actually shows.
- Markdown/HTML report generation: removed the hardcoded "Authorization:
  Not recorded for this run" line (omitted entirely when not supplied,
  instead of a discouraging placeholder); the assessment-scope note is now
  concise and points users toward running complementary scan tiers/attack
  modules instead of reading as a disclaimer; the Key Metrics table now
  spells out "Attack Success Rate (ASR)" with a plain-language description
  column, moved the Classifier field out of Key Metrics into the report
  header, and only ever shows EE/CRR/SS when real ground-truth metrics are
  present (`aginiti scan`/`aginiti attack` never populate them, only
  `scripts/run_benchmark.py`'s own ground-truth-scored runs do); every
  finding's field label (Status, Probe, What leaked, Why flagged,
  Confidence, OWASP LLM, Remediation) now carries a short plain-language
  description in the label itself, not appended after the value (appending
  after the OWASP LLM field's own value, which already contains a hyphen,
  produced a confusing double-hyphen chain -- fixed by moving the
  description to the label side, which is unambiguous regardless of what
  the value contains); every `leak_type` status tag (e.g. `pii`) now always
  expands to its full plain-language name (e.g. "Personally Identifiable
  Information (PII)"), with a safe Title Case fallback for any value not
  in the lookup table. Remaining stray em-dashes in report *output* text
  (not source comments/docstrings) replaced with plain hyphens.
- `aginiti-demo-target --hardened` (the default, `--vanilla`, is unchanged
  and byte-for-byte identical to before this addition) -- an A/B-comparison
  mode with 4 defenses adapted from `benchmarks/scaled_evals/agents/
  hardened_agent/agent.py`: an LLM input-filter classifier (blocks before
  retrieval/generation run), a system-prompt guardrail against PII/secret
  disclosure, output redaction (DLP) for SSNs/emails/phone numbers/card-
  shaped digit runs/API-key-shaped tokens, and a short conversation-memory
  window with a caution nudge against systematic information harvesting.
  A 5th, a sliding-window rate limiter (20 requests/minute per client IP),
  is enforced in `main.py` at the request boundary, before any retrieval/
  generation work runs. RBAC/tool-calling/session-expiry/audit-logging
  were deliberately not ported -- this target has no personas or tools to
  scope, unlike the benchmark target those exist for. `GET /health` now
  reports the active mode (`{"status": "ok", "hardened": true|false}`). No
  new dependencies (regex/rate-limiter/memory are all stdlib).
- `aginiti scan` now runs a second (third, ...) round once every eligible
  operator has run and budget remains, instead of stopping the moment the
  ~11-operator target-agnostic pack runs dry -- `aginiti scan --budget 100`
  previously topped out around 20-40 prompts used no matter how large
  `--budget` was. Only the 4 deep-attack operators (IKEA/SECRET/MIA/SPE)
  become re-eligible each round -- the cheap prompt probes
  (`system_prompt_extraction` etc.) keep their permanent one-shot rule,
  since a repeat run of a fixed prompt against unchanged target state is
  provably redundant, not just unlikely to help. New `run_campaign(...,
  enable_multi_pass=True)` parameter (default `False` -- every existing
  caller, including the benchmark suite, is unaffected); `aginiti scan` is
  the only caller that passes it. Terminal logging now shows the round
  number alongside the step (`[step N | round M] ...`).
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

- `aginiti scan --model` previously did nothing for the deep-attack
  Operators (IKEA/SECRET/MIA) -- dead code, confirmed and fixed: their LLM
  provider config was read from bare MODULE-LEVEL constants, computed
  exactly once, the first time `deep_attack_operators.py` was ever
  imported anywhere in the process -- which happens far earlier than
  expected, via `aginiti/cli.py`'s own `_build_parser()` (built before any
  argument is even parsed), so the env var `--model` set afterward had
  nothing left to affect. Every env-derived value now resolves fresh each
  time `deep_attack_operators()`/`hardened_deep_attack_operators()` run
  (once per `aginiti scan` invocation), via a small per-attack config
  dataclass instead of a module-level constant -- see
  `deep_attack_operators.py`'s own module docstring for the full
  root-cause writeup. `aginiti scan`'s deep-attack Operators otherwise
  keep their existing fixed, small query caps (IKEA 20 / SECRET 10 / MIA
  4 probe questions) regardless of `--budget`, unchanged and by design --
  that cap is what stops a single Operator from silently consuming an
  entire scan's budget by itself. Use `aginiti attack` directly (its own
  `--queries`/`--phase1-iter`/`--probes`, never capped) for a deep run of
  one specific technique.

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
- `aginiti attack secret`'s Phase 1 (jailbreak optimization) silently
  produced nothing when only a Groq key was available: `cli.py`'s
  `_resolve_secret_optimizer` hardcoded `groq/openai/gpt-oss-120b` for the
  optimizer/evaluator role, but that model is safety-aligned enough to
  refuse the Optimizer's own "author a jailbreak candidate" framing too --
  reproduced live against `hardened_agent`, 100% of Phase 1 LLM calls
  returned "I'm sorry, but I can't help with that.", so Phase 1 finished
  with score=0.0000 and Phase 2 then sent 15/15 un-jailbroken probes,
  all refused, 0 findings. `deep_attack_operators.py` (the same role,
  reached via `aginiti scan`) had already been fixed to use
  `groq/openai/gpt-oss-20b`, which is confirmed to comply -- `cli.py` had
  its own separate hardcoded copy of the model string that was never
  updated when that fix landed, so `aginiti scan` was unaffected but
  `aginiti attack secret` still had the bug. `cli.py` now imports the one
  shared constant instead of hardcoding a second copy, so the two paths
  can't drift again. (The prior entry above, "`aginiti attack secret`'s
  equivalent path was already correct," was about a different failure
  mode -- crashing when `GROQ_API_KEY` wasn't set at all -- and didn't
  cover this one.)

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
