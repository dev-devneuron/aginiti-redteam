# aginiti/attacks/dra — Data Reconstruction Attacks

This package implements **DRA (Data Reconstruction Attack)** modules for
`aginiti-redteam`. DRA probes extract verbatim or near-verbatim content
from a RAG system's vector store.

> **Authorized use only.** This tooling is intended exclusively for security
> testing of systems you own or have explicit written permission to test. Do
> not run attacks against systems without authorization.

---

## Implemented: IKEA (Silent Leaks)

**Paper:** Wang et al., "Silent Leaks: Implicit Knowledge Extraction Attack
on RAG Systems through Benign Queries," arXiv:2505.15420v2.

### What it does

IKEA extracts knowledge from a RAG system using only benign, natural-sounding
questions — no jailbreaks, no "repeat your context" instructions. It works
entirely through query/response pairs, making it:

- **Stealthy:** queries look like normal user traffic.
- **Durable:** it exploits the vector-space structure of RAG retrieval, not
  vendor-specific safety filters that can be patched.
- **Black-box:** it never needs access to the target's retriever, embedding
  model, or LLM internals.

Two mechanisms guide query generation:

1. **Experience Reflection Sampling (ERS, Sec 3.3):** samples anchor concepts
   with probability weighted away from topics that historically produced
   refused or unrelated responses.
2. **Trust Region Directed Mutation (TRDM, Sec 3.4):** after a productive
   response, generates new anchor concepts inside a cosine-similarity trust
   region around the response embedding, steering toward unexplored nearby
   knowledge. **Mutation prompt rewritten 2026-07-2x** to prefer drilling
   into specific facts/entities the response actually revealed (a named
   individual, case, diagnosis, measurement) over drifting to new,
   unrelated territory — see the `_MUTATION_PROMPT`/
   `_COMBINED_MUTATION_QUERY_PROMPT` comments in `ikea.py` and
   `docs/how-it-works.md` §8 for the live-run evidence this was based on.
   The trust-region filter itself (Eq. 6, applied after generation) is
   unchanged.

### Quick start

```python
from aginiti.attacks.dra import IKEAAttack

attack = IKEAAttack(
    target_url="http://localhost:8001",
    llm_provider="gemini/gemini-3.5-flash",
    api_key="YOUR_GEMINI_API_KEY",
    topic="HR records",
    max_queries=50,         # start small; paper used 256
    # embed_model defaults to "chromadb/all-MiniLM-L6-v2" — local ONNX,
    # no API key, zero embedding cost. Pass embed_model="gemini/..." +
    # embed_api_key=... to use cloud embeddings instead.
)

findings = attack.execute(topic="HR records")

for f in findings:
    print(f.severity, f.confidence, f.probe_used)
    print(f.leaked_content[:200])
    print()
```

> **Embeddings run locally by default.** All of IKEA's ERS/TRDM similarity math
> uses `chromadb/all-MiniLM-L6-v2` via ChromaDB's ONNX runtime — no API key, no
> PyTorch, zero embedding API cost. Only the attacker's LLM calls
> (`llm_provider`) hit a cloud API. See `.env.example` for the model-override variables.

### Tier 2 (OTel) usage

Pass an `otel_ingester` at construction time to upgrade suspected findings
with retrieval span evidence:

```python
from aginiti.instrument import MyOTelIngester  # future task

attack = IKEAAttack(
    target_url="http://localhost:8002",
    llm_provider="gemini/gemini-3.5-flash",
    api_key="YOUR_GEMINI_API_KEY",
    topic="HR records",
    otel_ingester=MyOTelIngester(...),
)
findings = attack.execute(topic="HR records")
# findings with confirmed=True have retrieval span evidence
```

The `otel_ingester` must implement:
```python
def get_retrieval_span_for_query(query: str) -> dict | None:
    # Returns {"span_id": str, ...} or None
    ...
```

---

## Hyperparameters

All parameters use paper defaults (Table 5, Appendix A.1, arXiv:2505.15420)
and can be overridden at construction time.

| Parameter | Default | Source | Meaning |
|---|---|---|---|
| `theta_top` | 0.3 | Table 5 | Min anchor–topic similarity to keep an anchor |
| `theta_inter` | 0.5 | Table 5 | Max inter-anchor similarity (diversity filter) |
| `theta_anchor` | 0.7 | Table 5 | Min query–anchor similarity to accept a query |
| `theta_u` | 0.5 | *inferred* | Query–response similarity threshold for "unrelated" |
| `p` | 10.0 | Table 5 | Penalty for anchors near refused queries |
| `kappa` | 7.0 | Table 5 | Penalty for anchors near unrelated responses |
| `delta_o` | 0.7 | Table 5 | Similarity threshold triggering the outlier penalty |
| `delta_u` | 0.7 | Table 5 | Similarity threshold triggering the unrelated penalty |
| `beta` | 1.0 | Table 5 | ERS softmax temperature |
| `gamma` | 0.5 | Table 5 | TRDM trust region scale factor. **Instrumented but not recalibrated for MiniLM** (2026-07-2x) — `[TRDM-TRUST]` DEBUG logging added to both `_trdm_mutate`/`_mutate_and_generate_query` (same pattern as `theta_anchor`'s recalibration), but the default is intentionally left unchanged pending real measured data — see `docs/how-it-works.md` §8.2 |
| `tau_q` | 0.6 | Table 5 | TRDM stop: max query similarity in local chain |
| `tau_y` | 0.6 | Table 5 | TRDM stop: max response similarity in local chain |
| `theta_refusal` | 0.78 | *project judgment call* | Refusal-exemplar cosine similarity fallback threshold in `_is_refusal` (see below) |
| `max_queries` | 256 | paper experiments | Query budget per run |

`theta_u` is not listed in Table 5; it is inferred from the paper's
description of "unrelated" history classification. `theta_refusal` is not
in the paper at all — phi(y) (the refusal detector) is unspecified there.

### Refusal detection (phi(y))

The paper doesn't specify how to detect a refusal. This library uses a
two-stage approach in `_is_refusal`:

1. A cheap, case-insensitive keyword check (`_REFUSAL_PHRASES`) — zero
   embedding cost, catches common exact phrasings ("I don't know", "cannot
   provide", etc.).
2. If that doesn't match, cosine similarity against a small set of
   canonical refusal sentences (`_REFUSAL_EXEMPLARS`) — catches paraphrases
   the keyword list misses (e.g. "I don't have information on X" shares no
   substring with any phrase in step 1, since the word order differs from
   "no information" / "i have no information"). Classified as a refusal if
   similarity to any exemplar exceeds `theta_refusal`.

A hardcoded phrase list alone cannot enumerate every way a target LLM might
phrase a refusal — this two-stage check remains the fast, free, always-on
first pass (used internally by `_er_sample`/`_trdm_stop` for algorithm
steering, unchanged since before 2026-07-2x), but it does not fully solve
the generalization problem on its own.

**LLM-as-judge upgrade, 2026-07-2x (Tier C1):** the *final*, user-facing
classification (what actually becomes a finding vs. a refused query) now
runs through `_classify_response`, which independently re-verifies refusal
status via an LLM call for any response this two-stage check doesn't
already confidently resolve — see `_COMBINED_CLASSIFIER_PROMPT` and
`plans/tier-c1-combined-refusal-leak-classifier.md`. This does not cost
extra LLM calls: the population that reaches the LLM already required
exactly one call for leak classification before this change; the same call
now also determines refusal status. `_is_refusal` itself is intentionally
left untouched — it's still what `_er_sample`/`_trdm_stop` use for their
own cheap internal steering, deliberately not upgraded to avoid multiplying
LLM cost across repeated re-examination of the same history entries. See
`docs/how-it-works.md` §9 for the full design record, including a
correction made during implementation to an earlier chat-discussed design
that had a real generalization gap.

**Measured limitation (2026-07-07):** a live run against
`benchmarks/dev_fixtures/datasets/ground_truth.json` found 8 refusals recorded as
findings despite step 2 existing — measuring their actual cosine similarity
showed 0.696–0.770, overlapping substantially with genuine informative
responses at 0.620–0.718. In this response style, both refusals and real
answers share heavy boilerplate ("Based on the provided employee
records...") that dominates the embedding, so a small fixed-exemplar
similarity check doesn't cleanly separate them — raising `theta_refusal`
isn't a fix here, since the two distributions overlap. The actual fix was
expanding `_REFUSAL_PHRASES` with the specific phrasings this target
produces ("do not contain information", "do not include information", "do
not mention", etc.) — verified to catch all 8 misses at zero embedding
cost. Step 2 remains as a defense-in-depth fallback for genuinely novel
phrasing, but step 1 (keywords) turned out to be the more reliable signal
for this target's response style, not step 2.

**Follow-up (2026-07-08):** a later run against the same target surfaced 2
more misses through *both* layers ("do not specify", "...do not include
historical documentations...", embedding similarity 0.689/0.736 — still
below `theta_refusal`). Added "do not specify"/"does not specify" and
broadened "do not include"/"does not include" (from the narrower
"...information" variants) to `_REFUSAL_PHRASES`. Verified against all 48
`leaked_content` strings collected across every saved run so far (both
`scripts/results/*.json` files plus the earlier `findings.json`): zero
false positives — every match for these 4 new phrases was a genuine
refusal, none were informative answers. This is empirical against one
target's response style, not a guarantee — a target that genuinely answers
with, say, "the salary figures do not include bonuses" would trip
"do not include" as a false positive. If you point this at a target whose
refusal style isn't covered by `_REFUSAL_PHRASES`, re-run this same
measurement (collect real `leaked_content` samples, check candidate phrases
against all of them for false positives, and check the embedding fallback's
similarity for anything still missed) before trusting either layer —
don't assume the current phrase list or `theta_refusal` generalizes.

---

## Confidence scores and severity — important caveat

Each `LeakFinding` carries a `confidence` score (0.0–1.0) derived from the
cosine similarity between the probe query and the agent's response.

**This is a Tier 1 heuristic, not a measure of data sensitivity.** Because
ERS and TRDM are explicitly designed to bias toward high-relevance responses,
most successful probes will score high on this metric almost by construction.
High confidence indicates the response was topically on-target — not that
sensitive data was leaked.

Severity thresholds (≥0.8 → critical, ≥0.6 → high, ≥0.4 → medium, <0.4 →
low) are **project-defined engineering choices, not derived from the paper**.
They should be treated as configurable.

Use Tier 2 OTel mode (pass an `otel_ingester`) for evidentiary confirmation
(`confirmed=True`) before treating a finding as verified.

---

## Evaluation metrics (for benchmarking)

These are not computed by the attack itself but are used when scoring results
against known ground truth (see `benchmarks/`):

| Metric | Formula | Interpretation |
|---|---|---|
| **EE** (Extraction Efficiency) | unique extracted docs (Rouge-L **precision** > threshold, confirmed leak type) / (k × queries actually sent) | Efficiency per query |
| **ASR** (Attack Success Rate) | non-refused queries / queries actually sent | How often the target responds |
| **CRR** (Chunk Recovery Rate) | Rouge-L **F-measure**(finding, ground-truth doc) | Literal overlap |
| **SS** (Semantic Similarity) | cosine(embed(response), embed(doc)) | Semantic overlap |

IKEA is designed for low CRR (~0.27–0.29 per the paper) and moderate-to-high
SS — it extracts semantic knowledge, not verbatim text.

**Precision, not F-measure, for EE (2026-07-2x):** EE's hit test uses Rouge-L
precision — F-measure's recall term is computed against the whole
ground-truth document's length, which structurally punishes a short (but
accurate) extracted evidence quote against a much longer source document.
CRR keeps F-measure, for comparability with the paper's own reported
numbers. Root-cause writeup, including a verified real example, in
`docs/how-it-works.md` §7.

**"Queries actually sent," not the query budget:** a run that stops early
(rate limit, endpoint failure) shouldn't have ASR/EE computed against
queries it never got to send. `IKEAAttack.refused_queries` (a public
instance attribute, populated during `execute_black_box`, reset per run)
exposes exactly which queries were refused, so callers can compute the
real count — `scripts/run_benchmark.py` and `scripts/run_ikea.py` both do
this and record it (`queries_sent`, alongside `refused_queries` itself) in
their output JSON and Markdown report.

**CRR/SS scope, fixed 2026-07-2x:** both are averaged only over findings
with `leak_type != "none"` — previously they averaged over *every*
finding, including generic non-answers ("there is no information regarding
X") that were never expected to match any ground-truth document, dragging
both metrics down with content that isn't a leak at all. Matches the same
filter `aginiti/reporting/markdown_report.py`'s Risk Summary already
applies. Measured impact on a real run: SS rose 21% (0.4534 → 0.5485) once
restricted to confirmed-leak findings only.

These metrics are computed for you by **`scripts/run_benchmark.py`** (or the
zero-arg preset `scripts/run_healthcare_benchmark.py`), which runs the attack
against a live agent over a public dataset and scores the findings against
ground truth. See **[`docs/BENCHMARKS.md`](../../../docs/BENCHMARKS.md)** for how these
metrics have scored on real, live runs.

---

## Why IKEA was chosen first, over SECRET

*(Moved here from `CLAUDE.md` §4 during a 2026-07-30 scoping pass — see
`CLAUDE.md`'s "Attack module registry" for why: this rationale is
DRA-specific, not a framework-wide rule, and belongs in the module doc a
reader actually consults when working on DRA, not in the project's
top-level governance file.)*

Multiple candidate papers were evaluated for the DRA module before
settling on IKEA:

- **Durability** — IKEA exploits architectural/vector-space properties of
  RAG retrieval that can't be patched by a vendor safety update, unlike
  jailbreak-dependent methods (see "Why this attack is hard to defend
  against" above).
- **Detection evasion** — IKEA bypasses input/output-level defenses by
  design, since every individual query is benign. SECRET's queries are
  jailbreak-wrapped, which is exactly the pattern input-classification
  defenses are built to catch.

No official IKEA code release exists — this implementation is built from
the paper's algorithm description (Sec 3.2–3.4, hyperparameters in
Appendix A.1/Table 5), not ported from a repo.

## Implemented: SECRET (jailbreak-optimized DRA)

**Paper:** He, Chen, Li, Shao, Qi, Li, Tao, Qin, "External Data Extraction
Attacks against Retrieval-Augmented Large Language Models," IEEE TIFS 2026
(arXiv:2510.02964v2). Full algorithm extraction:
`aginiti/attacks/dra/secret-methodology.md`. Full design/sign-off record:
`plans/secret-dra-attack.md`.

### What makes this different from IKEA — read this first

**SECRET is jailbreak-dependent; IKEA is not.** Every SECRET query is
`p_e* ⊕ t_i` — a frozen, adaptively-optimized jailbreak-wrapped extraction
instruction plus a per-query retrieval trigger — not a benign natural
question. It is still zero-knowledge and black-box/Tier 1 like IKEA (no
prior knowledge of any specific document, no retriever/LLM internals
needed), but it needs several auxiliary LLM dependencies IKEA doesn't: an
Optimizer LLM and an Evaluator LLM (Phase 1), a semantic-shift model (Phase
2's Local Exploitation), and a caller-supplied external natural-text corpus
for Global Exploration seeding. See `plans/secret-dra-attack.md` §1 for the
full provider/cost mapping — Phase 1 alone costs tens of auxiliary LLM
calls before Phase 2 spends a single query against the real knowledge base.

The paper's own evidence pushes back on a simple "jailbreak, therefore
fragile" framing — see `secret-methodology.md` §10: several tested
input-side detectors (a perplexity-based detector, Llama-Guard-3-8B) achieve
0% detection against SECRET specifically because its jailbreak prompts are
adaptively optimized, coherent natural language, not a static template or
token-garbage. Still, treat it as a genuinely different threat model from
IKEA's non-jailbreak design, not a strict improvement.

### Two-module architecture

- **`aginiti/attacks/dra/jailbreak_optimizer.py`** — `JailbreakOptimizer`
  (Phase 1, Algorithm 1). **Not a `BaseAttack` subclass** — it's an offline,
  run-once-per-target calibration step producing a cacheable
  `JailbreakArtifact` (the optimized `p_e*` plus provenance), disk-cached
  under `.cache/secret_jailbreak/` (7-day TTL, `force_refresh` escape
  hatch), mirroring `IKEAAttack`'s anchor cache.
- **`aginiti/attacks/dra/secret.py`** — `SECRETAttack` (Phase 2, CFT). The
  actual `BaseAttack` subclass, emitting `LeakFinding`s. Either accepts a
  pre-computed `jailbreak_artifact` or runs `JailbreakOptimizer` internally
  on first use (same "load from cache, or generate if missing" pattern as
  `IKEAAttack._init_anchors`), so `attack.execute()` works end-to-end with
  zero extra ceremony in the common case.

### Quick start

```python
from aginiti.attacks.dra import SECRETAttack

attack = SECRETAttack(
    target_url="http://localhost:8001",
    llm_provider="gemini/gemini-3.5-flash",
    api_key="YOUR_GEMINI_API_KEY",
    # Global Exploration seed corpus -- natural text UNRELATED to the
    # target's domain (paper: Wikipedia). Not bundled -- caller-supplied,
    # same pattern as MIA's non_member_reference_docs.
    external_corpus=[
        "The Eiffel Tower was completed in 1889 for the World's Fair.",
        "Photosynthesis converts light energy into chemical energy.",
        # ... a real engagement needs many more, genuinely diverse chunks
    ],
    max_queries=50,          # Phase 2 budget; start small
    phase1_n_iter=5,         # Phase 1 budget; start small (paper default: 20)
)

findings = attack.execute(domain="HR records")
for f in findings:
    print(f.severity, f.confidence, f.probe_used[:60])
    print(f.leaked_content[:200])

# The p_e* actually used (cached to disk, reusable across runs/targets):
print(attack.jailbreak_artifact.p_e_star, attack.jailbreak_artifact.score)
```

See `scripts/run_secret.py` (dev fixture, port 8001) or
`scripts/run_secret_hardened.py --persona {legal,support,ops}` (hardened
target, port 8004) for runnable, deliberately small smoke-test
configurations (read each script's module docstring's cost warning first).

### Verification status and operational notes

Live-verified against `reference_agent_blackbox` (undefended) — a full
critical-severity finding (verbatim PII extraction) via the complete
GE→LE cluster-discovery pipeline. Also plumbing-verified against
`hardened_agent` with all five defenses active (RBAC, rate limiting,
redaction, memory, guardrail) — authenticates, retrieves within its
RBAC-scoped persona, and runs the full Phase 1 → Phase 2 pipeline without
error. A real per-persona effectiveness benchmark against a defended target
still needs a larger query budget than a plumbing check — see
`scripts/run_secret_hardened.py`'s module docstring. Zero findings at a
small smoke-test budget against a guardrailed target is inconclusive at
that scale, not evidence the defenses specifically blocked anything.

`temperature=0.0` (the paper's stated deterministic-decoding setting, §5)
is enforced on every SECRET-owned auxiliary LLM call — Optimizer,
Evaluator, semantic-shift — deliberately not on target-facing calls
(outside the attacker's control) or the classifier (this project's own
addition, matching IKEA's convention). One thing worth re-checking on a
future LiteLLM/Gemini upgrade: current versions emit a deprecation warning
that `temperature`/`top_p`/`top_k` are "planned for removal" for Gemini 3+
models in favor of system-instruction-based sampling guidance — not an
error today, but worth re-verifying this still applies if that lands.

Full incident history for this project's own maintainers is tracked
separately, not in this file.

### Two genuinely unresolved paper values

The paper's official repo (`github.com/T0hsakar1n/Secret`) contains no
source code as of this writing (re-verified 2026-08-08) — these are
engineering judgment calls, not facts extracted from the paper:

- **`phase1_alpha`** (Phase 1 early-stop score threshold) — no numeric value
  given anywhere in the paper. Default `0.85`, chosen from the Evaluator's
  own 0-1 rubric bands. Tune per target.
- **`tau_extraction`** (this implementation's live self-dedup threshold,
  repurposing the paper's Definition III.1 distance metric — see
  `secret.py`'s module docstring for why this is a genuine interpretation
  gap, not just an unresolved constant) — the paper states `0.1`
  (normalized Levenshtein distance), but its own "set to avoid false
  negatives" framing for a *low* distance value is internally confusing.
  Kept at the paper's stated number pending the official repo's release;
  flagged, not silently trusted.

### Cost

See `plans/secret-dra-attack.md` §1.2 for the full breakdown. In short:
Phase 1 costs roughly 5-6 Optimizer calls + 16 target queries + 16 Evaluator
calls in the average case (37-38 total calls) before Phase 2 spends a
single query against the real knowledge base; curriculum optimization
(`use_curriculum=True`) roughly doubles this. Phase 2 then adds one
classifier LLM call and (during LE steps) one semantic-shift LLM call per
query, on top of `max_queries` target queries. Start with a small
`phase1_n_iter`/`phase1_n_cand`/`max_queries` (see `scripts/run_secret.py`)
before scaling up.

### Not conflated with IKEA or its baselines

Independently verified from the methodology doc (§7): SECRET's paper
doesn't cite IKEA/"Silent Leaks" anywhere, and none of its four baseline
EDEAs (Zeng, Qi, Cohen, Jiang) correspond to it. This is a genuinely
separate technique implementing a different taxonomy entry (Table I:
Structured Repetition + LLM Optimizers + CFT, vs. IKEA's ERS/TRDM anchor
resampling), not a variant or extension of IKEA's algorithm.
