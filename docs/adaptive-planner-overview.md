# Aginiti — Phase 0

An adaptive Security State Graph planner for autonomous red-teaming of
agentic AI systems. Phase 0's job (design doc Section 5.1/RQ1) is to test
one thing: does SSG-driven adaptive planning beat Random / Static-enumeration
/ Memory-guided baselines against the same target under the same budget.
This repo has the SSG core, a 6-operator library, a reference demo target
(mock Payroll/Slack/GitHub agent), Aginiti's constrained-utility planner,
the 3 baseline policies, and a 4-condition benchmark harness with
persistent per-trial logging.

## Setup

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

`.env` needs a `GROQ_API_KEY`. Use a key dedicated to this project, not a
shared one -- see "API budget" below for why.

`requirements.txt` is pinned to exact versions verified against this
project's own test suite (see that file's own header) -- re-verify by
running the full suite before bumping any of them.

## Development

Run the full suite: `pytest tests/` (655+ tests, no live API calls).

A local pre-commit hook that runs the suite before every commit is
tracked at `scripts/pre-commit` (git doesn't version-control
`.git/hooks/` itself, so install it once per clone: `cp scripts/pre-commit
.git/hooks/pre-commit && chmod +x .git/hooks/pre-commit`). CI
(`.github/workflows/tests.yml`) runs the same suite on push/PR once this
repo has a GitHub remote to be hosted on.

The library logs via Python's standard `logging` module under the
`"aginiti"` logger (see `aginiti/observability.py`) -- attach your own
handler to see it; nothing is emitted by default (library-logging best
practice, not a bug):

```python
import logging
logging.getLogger("aginiti").addHandler(logging.StreamHandler())
logging.getLogger("aginiti").setLevel(logging.INFO)
```

## Run one campaign

```bash
set PYTHONPATH=.
.venv\Scripts\python scripts\run_campaign.py
```

Prints the decision trace, execution log, and final Security State Graph
for one Aginiti campaign against the demo target. Outcome and path taken
vary run to run (the target is a live LLM) -- that variance is expected
and is itself something the benchmark measures (design doc Section 19,
"Target stochasticity").

## Run the 4-condition benchmark

```bash
set PYTHONPATH=.
.venv\Scripts\python scripts\run_benchmark.py 3
```

Runs `n_trials` campaigns for each of Random / Static / Memory-guided /
Aginiti against the same target, same budget, same seed per trial index
across conditions (Section 21.5). Every trial's full decision trace, raw
target transcripts, judge verdicts, and final SSG claims are written to
`runs/<run_id>/<condition>_trial<NN>.json`.

**If you hit a rate limit partway through**, rerun with the run_id as a
second argument -- it skips every (condition, trial) already logged on disk
and continues from exactly where it stopped, at zero extra token cost for
the completed trials:

```bash
.venv\Scripts\python scripts\run_benchmark.py 3 20260806T121030Z
```

## Generate the report

```bash
.venv\Scripts\python scripts\generate_report.py [run_id]
```

Reads `runs/<run_id>/*.json` (works on a partial/interrupted run too) and
writes a self-contained `runs/<run_id>/report.html`: summary comparison
table, success-rate chart, a Fisher's-exact comparison of Aginiti vs. each
baseline, and every trial's raw evidence in expandable sections -- so the
summary numbers can be checked against what the target actually said, not
just trusted.

## Multi-key rotation -- and a real caveat

`GROQ_API_KEY`, `GROQ_API_KEY_2`, `GROQ_API_KEY_3`, ... in `.env` are pooled
(`aginiti/llm_client.py`) -- on a rate limit from the current key, the same
request is automatically retried on the next key before giving up. The code
does what it says.

**But this only multiplies your real budget if the keys are on genuinely
separate Groq organizations.** We verified empirically that Groq's 100k
tokens/day limit is enforced per-organization, not per-key: every rate-limit
error this project hit, across three keys presumed independent, referenced
the identical `org_...` id in the error message. Multiple keys generated
from the same Groq account/signup share one quota pool -- rotating between
them buys nothing. To actually get more daily budget, the keys need to come
from separate Groq accounts (different signups/emails), or you upgrade the
one org to a paid tier. Verify by comparing the `org_...` id in a 429 error
across your keys, or by forcing a large request on each key directly and
checking whether they exhaust in lockstep.

## Bugs found by the benchmark itself, not by manual testing

Worth recording because both are the kind of thing that only shows up at
scale, not in a single manual run -- exactly why the benchmark harness
exists:

- **Effect-clobbering bug**: an operator that declares the same claim key
  with opposite statuses on success vs. failure (`confirm_tool_reachability`:
  confirmed on success, refuted on failure) was looked up by key alone in a
  dict, so the failure effect silently overwrote the success effect. Fixed
  by giving each effect a direction-qualified identity (`key::status`).
- **Judge polarity bug**: the judge's candidate-framing logic labeled any
  effect not at CONFIRMED status as "evidence this is FALSE" -- including
  HYPOTHESIZED effects, which are still a positive claim, just at
  provisional confidence. Since `recon_capabilities` (the operator every
  campaign must run first) only has a HYPOTHESIZED effect, this silently
  broke recon in a data-dependent fraction of campaigns. It didn't show up
  in single manual runs by luck, but a 20-campaign benchmark batch hit 0%
  recon success and made the bug impossible to miss. Fixed: only REFUTED is
  negative polarity now. Regression-tested in `tests/integration/test_observation_adapter.py`.

Runs `20260806T120423Z` and `20260806T121030Z` predate this second fix and
should not be treated as clean data -- see their reports for what they
actually show, but the post-fix runs are the trustworthy ones.

## API budget (read this before running the benchmark)

Each campaign costs roughly 10,000-20,000 Groq tokens (multiple LLM calls
per operator, plus a judge call per operator). A free-tier key's 100k
tokens/day covers **maybe 6-8 campaigns**, not a full multi-trial benchmark
in one sitting. Use a key dedicated to this project (not one shared with
another app) and expect to run a benchmark across `--resume` calls spread
over more than one day, or upgrade the key's tier.

## Layout

```
aginiti/
  graph/        Security State Graph: Claim/Observation schema + append-only store
  operators/    Operator framework + the 6-operator vertical-slice library
  target/       Reference demo target (mock tools + Groq-backed tool-calling agent)
  adapter/      Observation Adapter: operator execution -> judged Observation
  planner/      Aginiti's constrained-utility planner (info gain / business impact / risk+budget)
  policies/     Shared Policy interface + Random / Static / Memory-guided / Aginiti policies
  campaign.py   Campaign loop -- generic over any Policy
  mission.py    Mission definition
  benchmark.py  4-condition benchmark harness, resumable
  report.py     Loads runs/<run_id>/*.json and computes summaries + stats
  stats.py      Dependency-free Fisher's exact test
  logging_utils.py  JSON-safe serialization + persistent per-trial logging
scripts/
  run_campaign.py       Run one Aginiti campaign, print full trace
  run_benchmark.py       Run/resume the 4-condition benchmark
  generate_report.py     Render runs/<run_id>/*.json into report.html
  smoke_test_target.py   Manual check of the demo agent's tool-calling loop
  smoke_test_judge.py    Manual check of the LLM judge's verdict output
tests/          Pure-Python unit tests (SSG, operators, policies, stats, logging), no live API calls
runs/           Per-run JSON logs + generated reports (gitignored)
```

## Known limitations (read before trusting any single run)

- 6 operators only, all funneling toward one mission ("unauthorized payroll
  write"). Not representative of a real operator library's breadth.
- One reference target, purpose-built around this operator library --
  exactly the generalization risk the design doc's own Section 20 flags.
- With only 6 operators and a generous 40-prompt budget, all 4 conditions
  can eventually exhaust the small operator library -- meaning success
  *rate* may not differentiate them as much as *cost to success* does.
  Both are reported; don't read success rate alone.
- Confidence model is the documented v0 simplification (Section 11.2):
  a bounded net-observation count, not a real Bayesian update.
- No human-approval loop for destructive-tier operators -- Phase 0 simply
  never runs them (mission constraints exclude them entirely).
- Trial counts a free API tier can afford are small (single digits per
  condition). The benchmark report's Fisher's-exact column says so
  explicitly -- treat any p-value here as directional, not as a validated
  RQ1 result (design doc Section 20's pre-registered effect-size bar is not
  met at this sample size).
