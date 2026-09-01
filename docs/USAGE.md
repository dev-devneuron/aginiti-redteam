# Usage Guide

Aginiti is a red-teaming framework for enterprise agentic AI. Four
research-grade data-leakage attacks you can run standalone (**Direct
Mode**), and an adaptive campaign engine that decides for itself which of
them — and everything else in its operator library — is worth the budget
(**Adaptive Mode**). This page covers exactly how to run each, from a
plain `pip install`.

- **Direct Mode**: run one attack — IKEA, SECRET, Interrogation, or
  SPE-LLM — straight against a target URL. You control every parameter by
  hand. Works from a bare `pip install`.
- **Adaptive Mode**: hand the campaign engine a target and a budget; it
  ranks every eligible operator by expected value, executes the winner,
  and repeats. The `scripts/run_campaign.py` CLI needs a git checkout —
  the same engine is also a plain Python call that works from
  `pip install` alone.

---

## Installation

```bash
# Core library — the 4 attacks, HTTP target adapters, the campaign engine
pip install aginiti-redteam

# + LangChain agents, OTel tracing, MCP stdio servers, the DVLA reference target
pip install aginiti-redteam[adaptive]
```

> **The one thing `pip install` does not give you.** `pip install
> aginiti-redteam` installs the `aginiti` Python package only — no
> `scripts/`, no `aginiti` command, no CLI. Verified directly against a
> clean install: `import scripts.run_campaign` fails with
> `ModuleNotFoundError`. Every attack and the full campaign engine are
> fully usable as a Python library from a plain `pip install` (see the
> code examples throughout this page) — the `--tier`/`--attack-category`
> *command-line* convenience in [Adaptive Mode](#adaptive-mode—the-campaign-engine)
> specifically needs `git clone` + `pip install -e ".[dev]"`. A dedicated
> `aginiti` CLI wrapper that ships with the package is on the roadmap, not
> shipped yet.

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

findings = attack.execute(domain="HR records", max_queries=10)  # Phase 2 budget
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

**Where do my results actually go — and what's this `.cache` folder I
found inside my venv?**
Two separate things. Your **findings** are in-memory only — nothing is
written unless you call `generate_markdown_report()` yourself (see
[Output & results files](#output--results-files) for the exact schema it
needs). Separately, IKEA/SECRET/MIA each cache expensive intermediate
work (anchors, jailbreak prompts, calibration thresholds) automatically,
and that cache currently lands inside your venv's own install directory
(`site-packages/.cache/...`) — a real, known quirk, not a bug in your
setup. Bypass it per-call with
`force_refresh=True`/`force_refresh_phase1=True`/`force_recalibrate=True`
if it's ever in your way.

---

Aginiti Redteam — MIT licensed. [GitHub](https://github.com/dev-devneuron/aginiti-redteam)
