# Usage Guide

Aginiti is a red-teaming framework for enterprise agentic AI. The `aginiti`
CLI runs a real assessment with no code (`aginiti scan` lets the campaign
engine decide what to try; `aginiti attack` runs one specific, named
technique directly), and the same library underneath is fully usable as
plain Python for scripting your own assessments — **Direct Mode** (one
attack, every parameter by hand) and **Adaptive Mode** (a target + a
budget, it decides). This page covers exactly how to run each, from a
plain `pip install`.

New to the library? [docs/TUTORIAL.md](TUTORIAL.md) is a narrower,
hands-on walkthrough — copy-paste commands from an empty folder through
running every attack and saving a report. This page is the full
reference once you're past that.

---

## Installation

```bash
# CLI + the 4 attacks + campaign engine
pip install aginiti-redteam

# + a local target agent to try it against, no target of your own required
pip install "aginiti-redteam[demo-target]"
```

**Already have your own target agent and don't need the demo one?** The
plain `pip install aginiti-redteam` above already gets you the full
`aginiti` CLI (`aginiti scan`/`attack`/`report`) — skip `[demo-target]`
entirely and just point `--target` at your own URL.

**Prefer not to install Python/pip at all?** [`docker/`](../docker/) runs
the exact same install inside a container — `docker compose up -d` for the
practice target, `docker compose run --rm cli aginiti scan ...` for the
CLI. Also sidesteps every gotcha below tagged Windows-native-binary/PATH
related, since everything runs inside a consistent Linux container
regardless of your host OS.

---

## CLI Quickstart — no code required

```bash
# Start a local target agent to try Aginiti against (seeds itself, then serves on :8001)
aginiti-demo-target
#   Port 8001 already taken? Run it on another one instead:
aginiti-demo-target --port 8010

# In a second terminal: aginiti scan -- let it decide (try this first)
aginiti scan --target http://localhost:8001 --tier data_leakage --budget 15
aginiti scan --target http://localhost:8001 --tier unauthorized_actions --budget 15
aginiti scan --target http://localhost:8001 --tier discovery_recon --budget 10
aginiti scan --target http://localhost:8001 --tier full_assessment --budget 20

# ...or aginiti attack -- you decide, one technique at a time
aginiti attack spe --target http://localhost:8001
aginiti attack ikea --target http://localhost:8001 --topic "HR records" --queries 10
aginiti attack secret --target http://localhost:8001 --domain "HR records" --queries 5
aginiti attack mia --target http://localhost:8001 --dataset candidates.json --probes 3

# Regenerate a report for a past run, without re-running anything (rarely needed)
aginiti report --input results/<run>/findings.json
```

Every `scan`/`attack` run auto-saves `findings.json`, a severity-sorted,
OWASP-mapped `aginiti_assessment_report.md`, and the same report as
`aginiti_assessment_report.html` (for opening straight in a browser — no
Markdown viewer needed) into their own fresh, timestamped subdirectory of
`./results` (`--output-dir` to redirect elsewhere) — e.g.
`results/20260923_154012/findings.json` — so a later run never overwrites
an earlier one's results; `results`' contents sort newest-first by name
(or "date modified") descending. The HTML report opens in your default
browser automatically the moment the run finishes — `--no-open-report` to
skip this (e.g. in a headless/CI environment), or reopen a past run's
report later:

```bash
Start-Process results\20260923_154012\aginiti_assessment_report.html   # Windows (PowerShell)
open results/20260923_154012/aginiti_assessment_report.html            # macOS
xdg-open results/20260923_154012/aginiti_assessment_report.html        # Linux
```

`aginiti scan --tier` accepts
`data_leakage | unauthorized_actions | discovery_recon | full_assessment`;
`aginiti scan`'s own `--budget` means "how many techniques it gets to try"
(against the real-target pack, 11 techniques today, so above ~15-20 rarely
finds more) — a different number from how deep any one named technique
can go with `aginiti attack` directly (see that attack's own section
below for real ranges). Every subcommand has its own `--help`. Full
walkthrough: [docs/TUTORIAL.md](TUTORIAL.md).

The rest of this page covers the **Python API** underneath the CLI — for
scripting your own assessments, or anything the CLI doesn't expose yet.
`scripts/run_campaign.py` (git-clone only) is `aginiti scan`'s
predecessor — still around for two things the CLI doesn't cover: the
zero-setup mock "DemoAgent" target, and an explicit `--model` override
for the deep-attack operators' own LLM provider.

---

## Configuration

Two completely different things are both called an "API key" here. Keep
them apart.

**1 · Attacker / judge LLM key.** Aginiti's **own reasoning** — generating
probe queries, judging whether a response counts as a leak, ranking
operators. Every attack constructor and the campaign engine both need
one. Routed through [LiteLLM](https://github.com/BerriAI/litellm), so any
supported provider works.

**2 · Target authentication.** If *the agent you're testing* requires its
own auth (a Bearer token, an API key header) to accept requests at all —
nothing to do with Aginiti's own reasoning. Set via `endpoint_kwargs` —
see [Target authentication](#target-authentication).

### Environment variables (attacker/judge key)

Put at least one in your environment or a `.env` file (Aginiti reads it
via `python-dotenv`):

```env
GEMINI_API_KEY=your_key
GROQ_API_KEY=your_key
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key
```

> **`.env` is found by searching upward, not just the current directory.**
> `python-dotenv`'s `load_dotenv()` (called automatically the moment any
> `aginiti` code that needs an LLM is imported) walks up from the current
> working directory looking for a `.env` file, the same way `git` finds
> `.git`. Usually convenient — a script in a subdirectory of your project
> still picks up the project root's `.env` — but worth knowing if you're
> deliberately testing with no key configured: an unrelated `.env` in a
> parent directory can silently supply one anyway.

Then pass the matching provider string as `llm_provider` — LiteLLM's
`provider/model` convention: `gemini/gemini-3.5-flash`,
`groq/openai/gpt-oss-20b`, `openai/gpt-4o`, and so on.

> **`target_url` is a base URL, not an endpoint path.** Pass just the host
> — `http://localhost:8001`. `AgentEndpoint` appends `/chat` itself on
> every call (`chat(message, endpoint="/chat")`); a `target_url` that
> already ends in `/chat` would resolve to `/chat/chat`.

---

## Direct Mode — the 4 attacks

Each is independently runnable against one target. Each takes its query
budget completely differently — this is the part people get wrong.

### IKEA

*Data Reconstruction Attack · ICLR 2026 (arXiv:2505.15420)* — **Query
budget: yes**

Generates natural-sounding, benign-looking queries via embedding-space
resampling to reconstruct records from a RAG knowledge base — no
jailbreak wrapper, designed to read as an ordinary user question.

| Parameter | Where | Required? | Default |
|---|---|---|---|
| `target_url` | constructor | yes | — |
| `llm_provider`, `api_key` | constructor | yes | — |
| `topic` | constructor or call | yes, one of the two | — |
| `max_queries` | constructor or call | no | 256 (paper default) |
| `embed_model` | constructor | no | `chromadb/all-MiniLM-L6-v2` (local, free) |

```python
from aginiti.attacks.dra.ikea import IKEAAttack

attack = IKEAAttack(
    target_url="http://localhost:8001",
    llm_provider="gemini/gemini-3.5-flash",
    api_key="your_key",
)

findings = attack.execute_black_box(
    topic="HR payroll records",
    max_queries=10,  # the query budget lives HERE
)

for f in findings:
    if f.confirmed:
        print(f.severity, f.leaked_content)
```

### SECRET

*Jailbreak-optimized DRA · IEEE TIFS 2026 (arXiv:2510.02964)* — **Query
budget: yes — two phases, two budgets**

An Optimizer/Evaluator LLM loop first calibrates a jailbreak prompt
against the live target (**Phase 1**), then wraps every extraction query
in it and alternates exploration/exploitation to pull knowledge-base
clusters (**Phase 2**). Every query is jailbreak-wrapped — this is not
IKEA's benign-question approach.

| Parameter | Where | Required? | Default |
|---|---|---|---|
| `target_url`, `llm_provider`, `api_key` | constructor | yes | — |
| `external_corpus` | constructor | yes | non-empty `list[str]` |
| `phase1_n_iter` × `phase1_n_cand` | constructor | no | 20 × 3 (paper default) |
| `max_queries` | constructor or call | no | Phase 2's own budget |
| `optimizer_llm_provider` | constructor | no — **but read the box below** | falls back to `llm_provider` |

> **The one thing most likely to bite you.** `optimizer_llm_provider`
> defaults to whatever you passed as `llm_provider`. Safety-aligned
> commercial models (Gemini, GPT) tend to **refuse the Optimizer's own
> "author a jailbreak candidate" framing** — Phase 1 then silently
> produces nothing, and Phase 2 runs on a dud prompt. Point the optimizer
> at a model that will actually comply:

```python
from aginiti.attacks.dra.secret import SECRETAttack

attack = SECRETAttack(
    target_url="http://localhost:8001",
    llm_provider="gemini/gemini-3.5-flash",   # extraction / classification
    api_key="your_gemini_key",
    optimizer_llm_provider="groq/openai/gpt-oss-20b",  # <- set this explicitly
    optimizer_api_key="your_groq_key",
    external_corpus=["unrelated sentence one.", "unrelated sentence two."],
    phase1_n_iter=3, phase1_n_cand=2,   # Phase 1 budget
)

findings = attack.execute_black_box(domain="HR records", max_queries=10)  # Phase 2 budget
```

Phase 1's result is **cached per target** for 7 days — the first run
against a new target pays the full optimizer/evaluator cost; every run
after that reuses it and only Phase 2's budget applies. Force a fresh run
with `force_refresh_phase1=True`.

### Interrogation (MIA)

*Membership Inference · ACM CCS 2025 (arXiv:2502.00306)* — **Query
budget: yes — per document, not a total**

A genuinely different question from the other three: not "what can I
extract," but "does *this specific document I already hold* exist in the
target's knowledge base." Not zero-knowledge — it needs the candidate
text up front.

| Parameter | Where | Required? | Default |
|---|---|---|---|
| `target_url`, `llm_provider`, `api_key` | constructor | yes | — |
| `non_member_reference_docs` | constructor | yes | non-empty, definitely-absent documents to calibrate against |
| `n_probe_questions` | constructor | no | 30 (paper default) — **per document**, not total |
| `documents` | call (`execute_black_box`) | yes | the candidates you're actually testing |
| `shadow_llm_provider` | constructor | no | same family as `llm_provider` — paper wants it *different*; a warning is logged, not an error, if they match |

```python
from aginiti.attacks.mia.interrogation import InterrogationAttack

attack = InterrogationAttack(
    target_url="http://localhost:8001",
    llm_provider="gemini/gemini-3.5-flash",
    api_key="your_key",
    non_member_reference_docs=[{"id": "ref_1", "text": "a fabricated, definitely-absent record..."}],
    n_probe_questions=4,   # <- the real query budget, applied to EACH document below
)

findings = attack.execute_black_box(documents=[
    {"id": "candidate_1", "text": "the full text of the document you're testing..."},
])
# findings = confirmed MEMBERS only; attack.non_member_results holds the rest
```

> **Candidate-document text should be the real, structured document, not a
> summary.** Probe questions are generated *from* this text — a terse
> paraphrase produces weaker, less discriminating questions than the actual
> record (e.g. the full multi-field text a real document would contain).
> This matters most at low `n_probe_questions`, where there's little room
> for one weak question to average out — verified live: the identical
> real, seeded record correctly confirmed as a member at
> `n_probe_questions=1` with its full structured text, but was misclassified
> as non-member with a one-line paraphrase of the same record at the same
> budget.

### SPE-LLM

*System-prompt extraction · 3 static probe templates · ICLR 2026
(arXiv:2505.23817)* — **Query budget: no — fixed at 3**

Three fixed templates — Chain-of-Thought, Extended Sandwich, Few-Shot —
asking the target to reveal its own system prompt. No adaptive loop, no
query parameter to set at all; every run fires exactly 3 probes.

| Parameter | Where | Required? | Default |
|---|---|---|---|
| `target_url` | constructor | yes | — |
| `classifier_llm_provider`, `classifier_api_key` | constructor | no — **but read the box below** | falls back to `llm_provider`, else `gemini/gemini-3.5-flash` |

> **No longer LLM-less — and fails silently without a key.** Older docs
> describe SPE as "LLM-less by design." It isn't anymore — a 10-keyword
> heuristic was replaced with a real LLM judge (the heuristic had real
> false-positive/false-negative problems in practice). Constructing SPE
> with **zero** key arguments does **not** raise, ever — verified live:
> construction succeeds, then each probe's classifier call fails
> internally and is caught, silently falling back to `confirmed=False`.
> The result is indistinguishable from a target that genuinely resisted
> every probe: 3 findings, 0 confirmed, no exception. If you ever see an
> all-clean SPE result, confirm a real key actually reached the classifier
> before trusting it. Pass a key.

```python
from aginiti.attacks.spe.spe_llm import SPEAttack

attack = SPEAttack(
    target_url="http://localhost:8001",
    classifier_llm_provider="gemini/gemini-3.5-flash",
    classifier_api_key="your_key",
)

findings = attack.execute_black_box()  # always exactly 3 probes, no budget to set
```

### Query budgets, compared at a glance

| Attack | Parameter name | Set where | Shape |
|---|---|---|---|
| IKEA | `max_queries` | constructor or call | One number — the whole extraction budget |
| SECRET | `phase1_n_iter` × `phase1_n_cand`, then `max_queries` | constructor, then constructor or call | Two separate budgets — jailbreak calibration, then extraction |
| Interrogation (MIA) | `n_probe_questions` | constructor only | Per document — real total ≈ questions × (candidates + reference docs, first run only) |
| SPE-LLM | *none* | — | Fixed at exactly 3 probes, always |

---

## Adaptive Mode — the campaign engine

Same 4 attacks, plus everything else in the operator library, chosen
automatically by a ranking function instead of by hand.

The engine itself — `run_campaign()` — is plain Python and works from a
bare `pip install`. The convenient `--tier`/`--attack-category`
command-line flags live in `scripts/run_campaign.py`, which is **not part
of the published package** (see the callout in [Installation](#installation))
— that needs a git checkout. Both paths are shown below.

### If you cloned the repo — the CLI

```bash
# Mock target, zero setup — the 2-minute quickstart
python scripts/run_campaign.py

# A real target, filtered to one coarse tier, capped budget
python scripts/run_campaign.py --agent-url http://localhost:8001 \
    --tier data_leakage --budget 20

# ...or a precise attack category instead of a tier (mutually exclusive)
python scripts/run_campaign.py --agent-url http://localhost:8001 \
    --attack-category encoding_attack rag_poisoning --budget 25

# Override the deep-attack operators' own LLM provider
python scripts/run_campaign.py --agent-url http://localhost:8001 \
    --tier full_assessment --budget 40 --model groq/openai/gpt-oss-20b
```

### If you only pip-installed — the Python API

```python
from aginiti.core.campaign import run_campaign
from aginiti.core.mission import Mission
from aginiti.core.graph.schema import RiskTier
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.deep_attack_operators import deep_attack_operators
from aginiti.operators.library import OperatorLibrary
from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
from aginiti.connectors.endpoint import AgentEndpoint

endpoint = AgentEndpoint(base_url="http://localhost:8001")
agent = HTTPAgentAdapter(endpoint)

all_ops = [*data_exposure_operators(), *deep_attack_operators()]
library = OperatorLibrary(all_ops).by_category("encoding_attack", "rag_poisoning")

mission = Mission(
    goal="Assess data-leakage exposure",
    success_criteria=("system_prompt_disclosed", "sensitive_data_exfiltrated"),
    success_mode="any",
    budget=25,
    risk_threshold=RiskTier.MEDIUM,
)

result = run_campaign(mission, library, agent=agent)
print(result.outcome, result.prompts_used)
```

`OperatorLibrary(...).by_category(...)` is an **instance** method — build
the library first, then filter it (not `OperatorLibrary.by_category(...)`
directly on the class).

### Tiers vs. attack categories

Two granularities over the same underlying tags. Pick one — `--tier` and
`--attack-category` are mutually exclusive on the CLI.

**4 coarse tiers:**

| Tier | Derived from |
|---|---|
| `data_leakage` | OWASP LLM02 (sensitive info disclosure) or LLM07 (system-prompt leakage) — includes all 4 Direct Mode attacks plus matching cheap probes |
| `unauthorized_actions` | OWASP LLM01 (prompt injection), LLM06 (excessive agency), or attack_category `tool_manipulation` |
| `discovery_recon` | attack_category `tool_discovery` or `low_value_reconnaissance` |
| `full_assessment` | no filter — same as omitting `--tier` entirely |

**11 precise categories** (run `--list-attack-categories` for this exact
list at any time): `direct_prompt_attack`, `encoding_attack`,
`rag_poisoning`, `indirect_injection`, `tool_discovery`,
`tool_manipulation`, `markdown_network_exfiltration`, `multi_step_chain`
(offensive techniques); `decoy`, `known_defended`,
`low_value_reconnaissance` (planner-evaluation controls).

> **Filtering only fully works on tagged operators.** Both `--tier` and
> `--attack-category` read tags every operator in
> `data_exposure_operators()`/`deep_attack_operators()` carries. The
> original, older mock-target scenario library (`build_library()`)
> predates this tagging effort — an untagged operator is silently
> excluded from a specific filter (never an error) and only shows up
> under `full_assessment`/no filter. If a filter matches zero operators,
> the CLI exits with a clear message rather than running an empty
> campaign.

### Target authentication

If the agent under test needs its own auth header, pass it via
`endpoint_kwargs` — works identically for every attack and for
`AgentEndpoint` directly:

```python
attack = IKEAAttack(
    target_url="https://internal-agent.example.com",
    llm_provider="gemini/gemini-3.5-flash",
    api_key="your_key",
    endpoint_kwargs={"headers": {"Authorization": f"Bearer {target_token}"}},
)
```

---

## Output & results files

What actually lands on disk after a run, and what stays in memory —
verified live, not assumed.

**Findings themselves are in-memory only.** `execute_black_box()` returns
a plain `list[LeakFinding]` — confirmed live: a real run writes **zero**
new files to your working directory. Nothing is auto-saved; that's your
call to make.

### Getting a saved report

Build a `report` dict matching an exact schema, then call
`generate_markdown_report()`:

```python
from aginiti.reporting import generate_markdown_report
import dataclasses, time

started = time.monotonic()
findings = attack.execute_black_box(topic="HR records", max_queries=10)

report = {
    "run_metadata": {
        "attack": "ikea",
        "agent_url": "http://localhost:8001",
        "timestamp": "2026-08-28T00:00:00Z",
        "total_queries": 10,
        "runtime_seconds": time.monotonic() - started,  # required -- omitting this raises KeyError
        "embed_model": "chromadb/all-MiniLM-L6-v2",
        "llm_provider": "gemini/gemini-3.5-flash",
    },
    "findings": [dataclasses.asdict(f) for f in findings],
}
generate_markdown_report(report, "my_report.md")   # pass redact=True for a second, sanitized copy
```

> **The exact required keys, verified by hitting the error.**
> `run_metadata` must include `attack`, `agent_url`, `timestamp`,
> `total_queries`, `runtime_seconds`, and `embed_model` — a report dict
> missing any of these raises a bare `KeyError` (e.g. `KeyError:
> 'runtime_seconds'`) rather than a helpful validation message. Copy the
> shape above rather than improvising one.

If you cloned the repo, `scripts/run_ikea.py`/`run_secret.py`/etc.
already do all of this for you automatically, writing both a full JSON
dump and a Markdown report under `scripts/results/` — that convenience is
script behavior, not library behavior, so it's only there with a git
checkout.

### How many queries did it actually send?

Inconsistent across the four attacks — verified directly against each
class:

| Attack | How to get the real count |
|---|---|
| SECRET | `attack.queries_sent` — the only one of the four with a direct attribute |
| IKEA | no such attribute — use `len(findings) + len(attack.refused_queries)` |
| Interrogation (MIA) | no such attribute — use `len(findings) + len(attack.non_member_results)` for documents tested (multiply by `n_probe_questions` for actual target queries) |
| SPE-LLM | always exactly 3 — `len(findings)` is always 3 |

### Cache files — written automatically, whether you ask or not

Three of the four attacks cache expensive work to disk across runs, with
no way to opt out beyond bypassing it per-call:

| Attack | Caches | TTL | Bypass |
|---|---|---|---|
| IKEA | Generated anchor candidates, per topic | 7 days | `execute_black_box(force_refresh=True)` |
| SECRET | The calibrated jailbreak prompt (Phase 1), per target | 7 days | `force_refresh_phase1=True` |
| Interrogation (MIA) | The calibrated membership threshold, per reference set | 7 days | `execute_black_box(force_recalibrate=True)` |

> **Cache location — a real gap for pip-installed use, verified live.**
> All three resolve their cache path relative to **where the package
> itself is installed**, not your project or a conventional cache
> directory. Confirmed against a real `pip install`: the path resolves to
> `...\Lib\site-packages\.cache\ikea_anchors\...` — inside your venv's own
> install directory. A normal venv is writable, so this doesn't outright
> fail for most setups, but it's worth knowing: the cache is easy to lose
> track of, gets wiped by `pip install --upgrade`/reinstall (defeating a
> 7-day cache's whole point), and can be a hard failure in read-only or
> system-Python environments. No environment-variable override exists yet
> to relocate it — if you hit a permissions error here, your only
> workaround today is running from an environment where your own venv is
> writable (the common case) or bypassing the cache entirely with the
> `force_refresh` flags above.

---

## Reference

**`scripts/run_campaign.py` flags (git checkout only):**

| Flag | Effect |
|---|---|
| `--agent-url` | Target a real HTTP agent; switches the default library to the target-agnostic packs |
| `--tier` | One of the 4 coarse buckets — see [Tiers vs. attack categories](#tiers-vs-attack-categories) |
| `--attack-category` | One or more of the 11 precise categories (space-separated = union) |
| `--list-attack-categories` | Print all 11 with descriptions, exit — no key/network needed |
| `--budget` | Override the mission's prompt budget |
| `--model` | Override IKEA/SECRET/MIA's own primary attacker LLM |

**Environment variables:**

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Attacker/judge LLM (Gemini via LiteLLM) |
| `GROQ_API_KEY` | Attacker/judge LLM (Groq via LiteLLM) — also SECRET's recommended optimizer provider |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Attacker/judge LLM, respective providers |
| `IKEA_OPERATOR_LLM_PROVIDER` etc. | Per-attack operator defaults, read at import time by `deep_attack_operators.py` — set *before* importing it, or use `--model` |
| `SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER` / `MIA_OPERATOR_SHADOW_LLM_PROVIDER` | Only matters for `aginiti scan`/the campaign engine (not `aginiti attack`, which has its own `--optimizer-model`). Prefers Groq for these two specific roles (see the SECRET FAQ entry below for why), but ONLY if `GROQ_API_KEY` is actually set — falls back to your primary attacker/judge model otherwise, it never requires a Groq key. Set explicitly to force a specific model for just this role. |

---

## Gotchas & FAQ

**I pip-installed but `python scripts/run_campaign.py` says "No module
named scripts"**
Expected — `scripts/` isn't part of the published package. Either `git
clone` the repo to get the CLI, or use the equivalent Python API shown in
[Adaptive Mode](#adaptive-mode—the-campaign-engine), which works from
`pip install` alone.

**SECRET's Phase 1 ran but found nothing, even at a generous budget**
Check what model the Optimizer is actually using. If
`optimizer_llm_provider` was left unset, it silently inherited your main
`llm_provider` — and a safety-aligned commercial model will often refuse
the "author a jailbreak" framing outright. Point it at a model that
complies (Groq's `openai/gpt-oss-20b` is confirmed working) — see the
callout in the [SECRET section](#secret) above.

**SPE-LLM raised an error partway through, about an empty API key**
SPE stopped being LLM-less — it now runs a real LLM classifier on every
non-refused probe. Pass `classifier_llm_provider`/`classifier_api_key`
(or plain `llm_provider`/`api_key`) explicitly.

**My `--tier`/`--attack-category` filter matched zero operators**
Most likely you're running against the original mock-target library (no
`--agent-url` passed) — most of its operators predate the
OWASP/attack-category tagging both filters read. Either add
`--agent-url` to switch to the fully-tagged operator packs, or use
`full_assessment`/no filter against the mock target.

**Which attack should I run first against a new target?**
SPE-LLM — no query budget to reason about, cheapest, and a quick read on
whether the system prompt itself leaks. Then IKEA at a small
`max_queries` (5–10) for a first pass at knowledge-base content. Bring in
SECRET and Interrogation once you have a specific document or a
jailbreak-resistant target to test against.

**Do I need Docker / a local target to try any of this?**
No — point `target_url` at any real, HTTP-reachable agent you're
authorized to test. The repo's local reference agents
(`reference_agent_blackbox`, port 8001) exist purely as a free,
zero-consequence target to learn against; nothing about the attacks
themselves requires them.

**Where do my results actually go — and what's this cache folder I
found?**
Two separate things. Your **findings** are in-memory only — nothing is
written unless you call `generate_markdown_report()` yourself (or use the
CLI, which does this for you — see
[Output & results files](#output--results-files) for the exact schema).
Separately, IKEA/SECRET/MIA each cache expensive intermediate work
(anchors, jailbreak prompts, calibration thresholds) automatically, in a
real per-user cache directory resolved via
[`platformdirs`](https://github.com/tox-dev/platformdirs) — e.g.
`%LOCALAPPDATA%\aginiti-redteam\Cache\` on Windows, `~/.cache/aginiti-redteam/`
on Linux, `~/Library/Caches/aginiti-redteam/` on macOS — never inside
your venv or `site-packages`, and never wiped by a reinstall/upgrade.
Override the base directory with `AGINITI_CACHE_DIR`, or bypass the cache
per-call with
`force_refresh=True`/`force_refresh_phase1=True`/`force_recalibrate=True`
if it's ever in your way.

**I `pip install`-ed without a venv (a plain global install) and the
`aginiti`/`aginiti-demo-target` commands aren't found**
Two real, separate causes, in order of likelihood:
1. **You already had an older version installed.** `pip install
   aginiti-redteam` does *not* upgrade an already-satisfied requirement —
   if any version (even a very old one, from before the CLI existed) is
   already sitting in that Python environment, plain `pip install
   aginiti-redteam` silently no-ops with "Requirement already satisfied"
   and you keep the old, command-less version. Always use `pip install
   --upgrade aginiti-redteam` (`-U` for short) to be sure you actually get
   the latest release. Check what's really installed with `pip show
   aginiti-redteam` before assuming anything else is wrong.
2. **The Python install's own Scripts directory isn't on `PATH`.** A venv
   adds its own `Scripts`/`bin` directory to `PATH` automatically on
   activation; a bare global Python install may not have its `Scripts`
   directory (Windows) or `~/.local/bin` (`pip install --user` on
   macOS/Linux) on `PATH` at all. Two ways around it, in order of
   preference:
   - **Use [`pipx`](https://pipx.pypa.io/) instead of plain `pip`** for a
     global CLI install: `pipx install aginiti-redteam` (or `pipx install
     "aginiti-redteam[demo-target]"`). It builds an isolated environment
     for the tool automatically *and* puts its commands on `PATH` for
     you — the standard, purpose-built answer to "I want this CLI
     available everywhere without managing a venv myself."
   - Or run it as a module instead of relying on `PATH` at all: `python -m
     aginiti.cli scan ...` always works as long as `python` itself
     resolves to the right interpreter, regardless of where its `Scripts`
     directory is. (`aginiti-demo-target` doesn't have a module-invocation
     equivalent since it's a separate console script — `python -m
     aginiti.demo_target.main` works the same way for it.)

   Either way, a project-local venv (this guide's default recommendation)
   sidesteps both of these entirely, since it starts from a clean,
   version-pinned, `PATH`-configured environment every time.

**Does a `.env` file still get picked up without a venv?**
Yes, identically either way — `.env` loading
([`python-dotenv`](https://github.com/theskumar/python-dotenv)'s
`load_dotenv()`) searches your **current working directory** (and its
parents) for a `.env` file, completely independent of which Python
interpreter or environment is running. Run the CLI from the directory
containing your `.env` (or `cd` there first) and it's found the same way
whether you're in a venv, a global install, or a `pipx`-managed one.

---

Aginiti Redteam — MIT licensed. [GitHub](https://github.com/dev-devneuron/aginiti-redteam)
