# Tutorial — running Aginiti, start to finish

A hands-on, step-by-step walkthrough: from an empty folder to a real leak
finding on your screen and a saved report. No coding required — every
assessment runs as one command. This is the narrower companion to
[docs/USAGE.md](USAGE.md)'s full reference.

- [What we built — 4 techniques](#what-we-built--4-techniques)
- [1 · Install](#1--install)
- [2 · Get a target](#2--get-a-target)
- [3 · Choose your approach](#3--choose-your-approach)
- [4 · Reports](#4--reports)
- [Benchmarks — the metrics, explained simply](#benchmarks--the-metrics-explained-simply)
- [Cheat sheet](#cheat-sheet--every-command-in-order)

---

## What we built — 4 techniques

Every one of these is a real technique from a published security research
paper — not something invented for this project. Each answers a different
question.

| Technique | What it does |
|---|---|
| **IKEA** | Asks many normal, innocent-sounding questions in a row and pieces together private records from the answers — like a skilled interviewer who never asks anything that sounds suspicious on its own. |
| **SECRET** | First works out a "jailbreak" — a trick prompt that gets the chatbot to drop its guard — then uses that trick over and over to pull real data out. The most powerful, and the most involved to set up. |
| **Interrogation** | Doesn't steal anything new. Answers one narrow question: "does *this exact document I already have* exist in your private database?" — by asking a string of yes/no questions and reading the pattern of answers. |
| **SPE-LLM** | Tries to get the chatbot to reveal its own hidden instructions — the "system prompt" that tells it how to behave, what it's allowed to say, what tools it has. |

> **For a first demo, do them in this order:** SPE-LLM first (cheapest, no
> settings to think about), then IKEA, then Interrogation, and SECRET last
> once you're comfortable — it's the one with the most moving parts. Or
> skip picking entirely and let `aginiti scan` decide for you — see
> Part 3 below.

---

## 1 · Install

One-time setup. About 3 minutes.

1. **Make a new, empty folder for this.** Anywhere is fine — Desktop,
   Documents, wherever.
   ```bash
   mkdir aginiti-demo
   cd aginiti-demo
   ```
2. **Make a virtual environment and turn it on.** A virtual environment is
   just an isolated Python install for this one project, so it can't clash
   with anything else on your machine.
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```
   (Mac/Linux: `source .venv/bin/activate` instead of the second line.)
   Your terminal prompt should now show `(.venv)` at the start — that means
   it worked.
3. **Install Aginiti.** The `[demo-target]` part also gets you a free
   practice chatbot to attack. **Already have your own target agent and
   don't need the demo one?** Just run `pip install aginiti-redteam`
   instead — skip straight to [Option B](#2--get-a-target) below.
   ```bash
   pip install "aginiti-redteam[demo-target]"
   ```
4. **Get an API key.** This is the "brain" behind every assessment — it
   writes the questions and judges the answers. Any one works: Gemini,
   OpenAI, Groq, Anthropic, or Mistral — Aginiti auto-detects whichever
   you set. Gemini's free tier
   ([aistudio.google.com/apikey](https://aistudio.google.com/apikey)) is
   the easiest to get started with if you don't already have one.
5. **Save the key so Aginiti can find it.** Create a file literally
   named `.env` in your `aginiti-demo` folder (any plain text editor —
   Notepad is fine) with this one line:
   ```env
   GEMINI_API_KEY=paste_your_real_key_here
   ```
   Using a different provider? Use its own name instead:
   `OPENAI_API_KEY`, `GROQ_API_KEY`, `ANTHROPIC_API_KEY`, or
   `MISTRAL_API_KEY`.

> **Checkpoint.** Run `aginiti --help` — it should print the list of
> commands. If it does, setup is done.

---

## 2 · Get a target

Every assessment needs a target — a real chatbot to test. Pick whichever
applies.

### Option A — the built-in practice chatbot

A free, throwaway chatbot with 25 fake HR records loaded into it, purely
so there's something safe to test with no real data at risk. One command,
in a **second terminal window** (opened in this same `aginiti-demo`
folder, so it finds the same `.env` file):

```bash
aginiti-demo-target
```

The first run seeds its fake records automatically, then starts serving
on `http://localhost:8001`. Leave this terminal open for the rest of the
demo — go back to your first terminal for everything below.

> **Checkpoint.** Open <http://localhost:8001/health> in a browser — you
> should see `{"status":"ok"}`.

### Option B — your own target

Already have an agent you're authorized to test? Skip the demo target
entirely — every command below takes a `--target` URL, so just use yours
instead of `http://localhost:8001`.

> **Authorized use only.** Only point Aginiti at systems you own or have
> explicit permission to test. Every run prints a one-line reminder of
> this.

---

## 3 · Choose your approach

Two ways to run an assessment — pick based on what you already know. Both
auto-save two files into your current folder when they finish:
`findings.json` (the full structured result) and
`aginiti_assessment_report.md` (a readable report, sorted highest
severity first, mapped to the industry-standard OWASP LLM Top 10 — the
file to open, share, or attach to an email). Nothing extra to write for
that.

### `aginiti scan` — let it decide

**You give it a target and a security concern; it decides for itself
which technique to try, learning as it goes from what worked and what
didn't** — not just the 4 techniques above, but the full pack of probes
built for this (encoding tricks, tool-manipulation probes, recon checks,
and the 4 deep attacks), scored and picked one at a time instead of run
in a fixed order.

**Use this when** you don't yet know what's vulnerable and want the
broadest possible check for a given budget. This is the right starting
point for any new target.

Pick a `--tier` — a broad security concern — and a `--budget` — how many
tries it gets, spent across whichever techniques currently look most
promising. Each technique only runs once per scan against a real target,
so **for this specific starting pack** (11 techniques today — the 4 named
ones plus 7 broader probes) a budget above ~15-20 rarely finds more; it's
a different number from how deep any one named technique itself can go
once you run it directly with `aginiti attack` below.

| Tier | Use this when |
|---|---|
| `data_leakage` | You care about the agent revealing private data, secrets, or its own system prompt. Covers all 4 named techniques automatically, plus more. |
| `unauthorized_actions` | You're worried about the agent being tricked into *doing* something it shouldn't — not just saying something, taking a real action (a tool call, a workflow trigger). |
| `discovery_recon` | You just want to map out what tools and capabilities the target exposes first, before deciding what to test next. Nothing destructive. |
| `full_assessment` | You want the broadest possible sweep — no filter, everything is fair game. Best for a target you're seeing for the first time. |

```bash
aginiti scan --target http://localhost:8001 --tier data_leakage --budget 15
aginiti scan --target http://localhost:8001 --tier unauthorized_actions --budget 15
aginiti scan --target http://localhost:8001 --tier discovery_recon --budget 10
aginiti scan --target http://localhost:8001 --tier full_assessment --budget 20
```

For a more precise pick than a whole tier, run
`aginiti scan --list-attack-categories` to see all 11 named technique
groups with a description, no target or key needed.

### `aginiti attack` — you decide

**Run one specific, named technique directly, with full control over its
own settings.**

**Use this when** you already know which technique you want to test —
for a deep dive, a reproducible demo of one paper's method, or because a
`scan` already flagged this category as promising and you want to push
harder on it specifically with a bigger budget.

**How big a budget?** Unlike `scan`'s pack-size ceiling above, each of
these can genuinely use a much larger budget — going deeper keeps finding
more, it just costs more LLM calls and wall-clock time.

| Technique | Quick check | Typical | Paper's own budget |
|---|---|---|---|
| IKEA (`--queries`) | 5 | 20 | 256 |
| SECRET, Phase 1 (`--phase1-iter`) | 2 | 5 | 20 |
| SECRET, Phase 2 (`--queries`) | 3 | 15 | — |
| Interrogation (`--probes`) | 3 | 15–30 | 30 |
| SPE-LLM | Fixed at exactly 3 — no budget to set | | |

Interrogation's "typical" is a range, not one number, because its real
cost is `documents tested × --probes` — the paper's own default (30) is
worth using in full for a document you actually care about the answer
on; drop to 15 or below only for a first cheap check.

**SPE-LLM — steal the hidden instructions.** Cheapest and simplest —
always asks exactly 3 fixed questions. Good first thing to try on any
new target.

```bash
aginiti attack spe --target http://localhost:8001
```

**IKEA — piece together records from innocent questions.** See how much
private data leaks out through ordinary-sounding questions, with no
jailbreak trick involved at all — closest to how a real curious (or
careless) user might stumble onto something they shouldn't see.

```bash
aginiti attack ikea --target http://localhost:8001 --topic "HR payroll records" --queries 5
```

**What you'll see:** a few seconds of quiet thinking, then either a real
leaked record (name, salary, etc. — all fake data) in the report, or a
message that nothing leaked this time. Both are a valid, working result —
not every run finds something at a small budget, and that's honest, not
a bug.

**Interrogation — is this one document in there?** Not trying to
discover anything new — you already hold a specific document and want to
prove (or disprove) it exists in the target's private database, without
ever asking it to repeat the content back. Needs a small JSON file: the
document you're checking for, plus at least one example that
*definitely isn't* in there. Save as `candidates.json`:

```json
{
  "documents": [
    {"id": "emma_thompson", "text": "HR Employee Record - Emma Thompson\nEmployee ID: EMP-2847\nSSN: 423-58-9167\nDepartment: Engineering\nPosition: Staff Engineer\nAnnual Salary: $152,000\nReporting Manager: David Park"}
  ],
  "non_member_reference_docs": [
    {"id": "ref_1", "text": "HR Employee Record - Oliver Brandt, Employee ID EMP-3302, Finance, Financial Analyst."}
  ]
}
```

```bash
aginiti attack mia --target http://localhost:8001 --dataset candidates.json --probes 3
```

**What you'll see:** a confirmed-member result — because Emma Thompson
really is one of the 25 fake records seeded into the practice chatbot.
This is the clearest demo moment: you're proving the chatbot's private
database contains a document you specified, without ever asking it to
repeat the document back.

> Use the **real, full, multi-line document text** like above, not a
> short summary — the questions asked are generated from this text, so a
> richer document gives a much more reliable answer, especially at a
> small `--probes` budget.

**SECRET — jailbreak, then extract.** The agent already resisted IKEA's
benign-question approach and you want to test the more powerful (and more
involved) case: first inventing a jailbreak trick prompt, then reusing it
to pull data out. The one technique here that needs a second key (Groq) —
do this one last, once you're comfortable with the others.

```bash
aginiti attack secret --target http://localhost:8001 --domain "HR records" --queries 5
```

**What you'll see:** takes noticeably longer than the others (it's doing
more work) — first calibrating a jailbreak, then extracting with it. The
jailbreak is remembered for 7 days, so running the same command again
tomorrow skips straight to the fast part. It automatically uses your Groq
key for the jailbreak step if you added one — Gemini alone tends to
refuse writing jailbreak prompts, even for authorized testing.

> **If you skipped the Groq key:** SECRET still runs, but prints a
> warning and falls back to your main key for the jailbreak step too —
> which usually means it won't find anything. Add `GROQ_API_KEY` to your
> `.env` for this one to actually work.

---

## 4 · Reports

You'll rarely need this on its own — every `scan` and `attack` run above
already auto-saves `aginiti_assessment_report.md` for you. `aginiti
report` exists for the rare case where you want to regenerate one
afterward without re-running anything — most commonly, to also produce a
redacted copy for wider circulation:

```bash
aginiti report --input findings.json --redact
```

---

## Benchmarks — the metrics, explained simply

Beyond "did it leak or not," there are 4 numbers used to measure *how
well* a technique performed, especially useful when comparing against the
original research paper's own numbers:

| Metric | In plain English |
|---|---|
| **ASR** — Attack Success Rate | Out of everything it tried, what fraction actually found a real leak? |
| **CRR** — Content Reconstruction Rate | Of the leaked text, how much matches the original record word-for-word? |
| **SS** — Semantic Similarity | Even when the wording differs, how close in *meaning* is it to the real record? |
| **EE** — Exfiltration Effectiveness | A combined score: did it actually match a real, specific record closely enough to count as a genuine leak? |

These come from the full benchmark runner (`scripts/run_benchmark.py`,
from a git clone — more advanced, costs a bit in API calls, and scores
against a large set of real documents rather than just a couple).
Optional for a first demo; `aginiti scan`/`attack` above are enough to
show it working live.

**What we found when we ran this seriously:**

| | |
|---|---|
| **~5×** | fewer questions needed than guessing blindly, for the same result |
| **98%** | fewer questions blocked by the target's own defenses |
| **4/5** | categories where we matched NVIDIA's own security scanner exactly |
| **1,912** | automated checks, run before every release |

Real, confirmed leaks found on real (not our own) systems during testing:

- **AnythingLLM** (a real, production-style company chatbot platform) — 4
  confirmed ways in, including one that got all the way to actually
  pulling data out through a connected tool.
- **A 19-chatbot company network** — found 12 separate working attack
  methods, including one that needed 2 different tricks chained together.
- **Our own "hardened" test target** (8 layers of real defenses active at
  once — access control, rate limiting, etc.) — still found 2 confirmed
  ways past the access controls, plus confirmed membership-inference
  leaks.

Full numbers, methodology, and citations: [docs/BENCHMARKS.md](BENCHMARKS.md).

---

## Cheat sheet — every command, in order

```bash
# --- one-time setup ---
mkdir aginiti-demo && cd aginiti-demo
python -m venv .venv
.venv\Scripts\activate
pip install "aginiti-redteam[demo-target]"
# create .env with: GEMINI_API_KEY=your_key (+ GROQ_API_KEY=your_key, optional)

# --- Terminal 2: the practice chatbot (leave running) ---
aginiti-demo-target

# --- Terminal 1: aginiti scan -- let it decide (try this first) ---
aginiti scan --target http://localhost:8001 --tier data_leakage --budget 15
aginiti scan --target http://localhost:8001 --tier unauthorized_actions --budget 15
aginiti scan --target http://localhost:8001 --tier discovery_recon --budget 10
aginiti scan --target http://localhost:8001 --tier full_assessment --budget 20

# --- Terminal 1: aginiti attack -- you decide, one technique at a time ---
aginiti attack spe --target http://localhost:8001
aginiti attack ikea --target http://localhost:8001 --topic "HR payroll records" --queries 5
aginiti attack mia --target http://localhost:8001 --dataset candidates.json --probes 3
aginiti attack secret --target http://localhost:8001 --domain "HR records" --queries 5

# --- rarely needed: regenerate a report from a saved findings.json ---
aginiti report --input findings.json --redact

# --- already have your own target? use its URL everywhere above instead ---
aginiti attack spe --target https://your-agent.example.com
```

---

Aginiti Redteam, live on PyPI. Full reference: [docs/USAGE.md](USAGE.md) ·
[docs/BENCHMARKS.md](BENCHMARKS.md) ·
[GitHub](https://github.com/dev-devneuron/aginiti-redteam).
