# aginiti/attacks/mia — Membership Inference Attacks

This package implements **MIA (Membership Inference Attack)** modules for
`aginiti-redteam`. MIA probes answer a narrower, different question than
DRA: not "what can I extract from the knowledge base," but "does a
*specific* document I already hold exist in the target's knowledge base."

> **Authorized use only.** This tooling is intended exclusively for security
> testing of systems you own or have explicit written permission to test. Do
> not run attacks against systems without authorization.

---

## Implemented: Interrogation Attack (IA)

**Paper:** Naseh, Peng, Suri, Chaudhari, Oprea, Houmansadr, "Riddle Me This!
Stealthy Membership Inference for Retrieval-Augmented Generation," ACM CCS
2025 (arXiv:2502.00306v2).

### What makes this different from DRA (IKEA) — read this first

**IA is not zero-knowledge, unlike IKEA.** It requires two things upfront,
not as optional extras:

1. **The full text of every candidate document you want to test.** This
   attack confirms or denies membership of a document you already hold —
   it does not discover unknown content.
2. **A non-member reference document set**, from the same distribution as
   the target's real data, used once (calibrated, then cached) to build a
   decision threshold. Without this, the attack's raw aggregation score
   has no principled yes/no cutoff at all.

If what you actually want is "what can this RAG system reveal that I don't
already know about," use `aginiti.attacks.dra.IKEAAttack` instead — that's
what it's for.

### What it does

Three stages, per query-generation-through-decision:

1. **Query Generation** — for each candidate document, generate a short
   natural retrieval-summary lead-in (`s*`) plus `n` (default 30) specific
   yes/no questions grounded in the document's own facts, then compose
   `n` natural-sounding queries: `s* + " " + question`.
2. **Ground-Truth Answer Generation** — a separate **shadow LLM**, given
   the document's full text, answers each question Yes/No/"I don't know."
   This is the attacker's own private oracle — never sent to the target.
3. **Aggregation** — send each composed query to the *target*, parse its
   answer the same way, and score how often the target's answers agree
   with the shadow LLM's — a document that's genuinely in the target's
   knowledge base should produce answers that agree far more often than
   one that isn't. Compare against a calibrated threshold for a final
   membership verdict.

Like IKEA, every individual query is a benign, natural-sounding question —
no jailbreak phrasing. The paper's own stealth evaluation found detection
rates near zero (0.012 against a GPT-4o classifier) specifically because
the queries never reference "the context," "this document," or the RAG
system's internal state at all — they read as genuine questions about the
document's subject matter.

### Quick start

```python
from aginiti.attacks.mia import InterrogationAttack

# Documents known NOT to be in the target's knowledge base — same
# distribution as its real data. Used once to calibrate the decision
# threshold (expensive: n_probe_questions queries per reference doc,
# cached to disk for 7 days afterward — see "Cost" below).
non_member_docs = [
    {"id": "ref_001", "text": "... full text of a document you know is NOT indexed ..."},
    {"id": "ref_002", "text": "..."},
    # more reference documents improve calibration quality
]

attack = InterrogationAttack(
    target_url="http://localhost:8001",
    llm_provider="gemini/gemini-3.5-flash",   # attacker's own query-gen LLM
    api_key="YOUR_GEMINI_API_KEY",
    non_member_reference_docs=non_member_docs,
    # shadow_llm_provider defaults to llm_provider if omitted — recommended
    # to set it to a genuinely different model family (a warning is logged
    # if it matches llm_provider), matching the paper's own design choice
    # of GPT-4o-mini as shadow, separate from every tested victim generator.
)

candidates = [
    {"id": "suspected_doc_1", "text": "... full text of a document you suspect IS indexed ..."},
    {"id": "suspected_doc_2", "text": "..."},
]

findings = attack.execute(documents=candidates)
for f in findings:
    print(f.severity, f.confidence, f.leaked_content)

# Documents that did NOT clear the threshold — tracked for transparency,
# same precedent as IKEAAttack.refused_queries:
for r in attack.non_member_results:
    print(r["id"], "not confirmed as a member (score=%.4f)" % r["score"])
```

> **No embedding model needed.** Unlike IKEA, this attack's decision
> procedure is literal Yes/No/"I don't know" string matching, not cosine
> similarity — `InterrogationAttack` takes no `embed_model` parameter.

### Cost — read before running a real calibration

Calibrating the threshold runs the **full** three-stage pipeline against
**every** document in `non_member_reference_docs` — for `n_probe_questions=30`
and, say, 20 reference documents, that's **600 queries against the live
target** plus 600 shadow-LLM calls, just to calibrate once. This is cached
to disk (`.cache/ia_calibration/`, 7-day TTL by default,
`calibration_cache_ttl_seconds` to change it, `force_recalibrate=True` to
bypass) — re-running against the *same* reference set doesn't re-pay this
cost, but the first run against a new reference set genuinely does. Start
with a small reference set (5-10 documents) to validate the wiring works
before scaling up.

Testing each real candidate document costs `n_probe_questions` queries
against the target plus `n_probe_questions` shadow-LLM calls, on top of
calibration.

**Shadow-LLM call volume dominates at benchmarking scale** (it scales as
`documents × n_probe_questions`, same as target-query volume, while the
attacker LLM stays flat at 2 calls/document) — this is usually the first
thing to hit a free-tier rate limit on a real run. `shadow_llm_api_keys`
(added 2026-08-12) accepts a list of multiple keys for the same provider
(e.g. several free-tier Groq keys) and rotates to the next one immediately
on a rate limit, wrapping back to the first once every key has been tried
— see `BaseAttack._init_llm`'s `api_keys` docstring for the exact
stickiness/rotation semantics. `scripts/run_interrogation_hardened.py`
wires this up automatically from `GROQ_API_KEY_1`, `GROQ_API_KEY_2`, ...
in the environment when the shadow provider is `groq/*`.

### Live verification (2026-08-08) — a real bug found and fixed, read before trusting a small reference set

First live run (`scripts/run_interrogation.py` against
`reference_agent_blackbox`) surfaced a real false positive: a fabricated,
definitely-not-seeded candidate got reported as a confirmed member,
because with only 2 non-member reference documents (both cleanly denied by
the target, same as the fabricated candidate), the calibrated threshold
landed exactly on the score the candidate also got, and the `>=` decision
boundary counted the tie as a match. **Fixed** — the decision is now
strict `score > threshold`, and `_calibrate_threshold` logs a `WARNING`
whenever the non-member reference scores have zero spread or the reference
set has fewer than 5 documents. Full root-cause writeup:
`docs/how-it-works.md` §13.

**Practical implication**: a small (1-4 document) reference set is fine
for a wiring smoke test, but treat its calibrated threshold as
low-confidence — watch the log for the degenerate-distribution warning.
Use 5-10+ documents, ideally with some genuine topical variety, for a real
engagement's calibration.

### Live verification (2026-08-12/13) — a real parsing gap found and fixed at 100-document scale

A full 50-member + 50-non-member `score_documents` benchmark run against
`hardened_agent` (support persona, n=30) surfaced a second real bug:
`_parse_yes_no_unk` requires the literal word "yes"/"no", but
`hardened_agent` frequently answers in indirect reported-speech style
("the consumer asserts that X") that never says "yes"/"no" outright —
misclassified as `unk` even though a human reads it as a clear answer.
Quantified: **~6.6% of all 3,000 probes affected**, roughly equally across
members and non-members (not a directional bias). **Fixed** — the
classifier now has a reported-speech fallback (see its own docstring for
the exact pattern/limitations) that only activates when the direct
yes/no/"I don't know" check has already given up; a direct or explicit
answer always wins first. `aginiti/reporting/mia_reparse.py` exists to
re-score results captured *before* this fix from already-stored response
text (zero new API calls) — new runs don't need it.

**Separately confirmed** (re-running the fix against the same captured
data): fixing this parsing gap did **not** meaningfully move AUC-ROC
(0.560 → 0.536, i.e. no real change) — it corrects per-document score
noise, it does not manufacture separation that wasn't there. The dominant
reason that particular run's AUC was low (0.56, vs. the paper's 0.927-0.995
range) turned out to be a different, unfixed issue: several genuinely
non-member CFPB documents scored a perfect 30/30 match because CFPB
consumer complaints are highly templated (data breaches, unauthorized
accounts, FCBA disputes recur across many real, distinct complaints) — a
probe generated from a held-out document's generic facts can be truthfully
answered "yes" from a *different* real ingested document covering the same
common scenario. This is a corpus/construct-validity property, not
something a parser fix addresses — see `scripts/run_mia_benchmark.py` for
the large-scale scoring workflow this was diagnosed through.

### Hyperparameters

| Parameter | Default | Source | Meaning |
|---|---|---|---|
| `n_probe_questions` | 30 | Paper's headline default | Probe questions generated and scored per document. Used as `n = top_k` with no subsetting step — the official repo's `top_k`-selection is a compute-efficiency mechanism for its own ablation curve, not part of the core algorithm |
| `lambda_unk` | 6.0 | Paper's tested range 5-7 | UNK-response penalty weight in the aggregation formula. Must be > 1 |
| `fpr_target` | 0.1 | Paper's own evaluation methodology | Target false-positive rate for threshold calibration (ROC-style percentile thresholding against the non-member score distribution) |
| `shadow_llm_provider` | `llm_provider` | *project default, warns on same-provider* | Separate model for Stage 2's ground-truth oracle — recommended to differ from the attacker/target's model family |
| `calibration_cache_ttl_seconds` | 7 days | Matches `IKEAAttack`'s anchor cache | How long a calibrated threshold is reused before recomputing |

### Severity and confidence — different meaning than DRA

A confirmed-membership finding always carries `severity="medium"` in this
version. This is deliberate, not a placeholder: MIA confirms *existence*,
not *content* — this attack has no way to know a specific document's
real-world sensitivity (a patient record vs. a public brochure) from
inside itself. That judgment belongs at the reporting/human-review layer.
`confidence` is a normalized distance above the calibrated threshold (0 at
the decision boundary, approaching 1 near the theoretical maximum score) —
not a content-sensitivity signal either.

### What's deferred (see `plans/mia-interrogation-attack.md` for the full record)

- **Appendix-C parametric-knowledge contamination diagnostic** — the
  paper found that some generators (Llama 3.1, specifically) can answer
  probe questions correctly from pretraining memorization alone, even with
  zero retrieval context, which can produce a false-positive membership
  signal. An optional diagnostic (re-run probes against the bare generator
  with no retrieval) is scoped but not built in this version — marked
  `# TODO(v2)` in the code, not silently dropped.
- **Batched Stage 2 (shadow-LLM) calls** — this version makes one shadow-LLM
  call per probe question, matching the paper's own reported cost profile
  exactly. Batching all `n` questions into one call would be cheaper but
  diverges from the paper's measured behavior — a documented future option,
  not done by default. **Not a structural requirement, either way**: each
  shadow call is independently constructed from the same `doc_text` plus one
  `probe`, with no data carried over between iterations
  (`_generate_ground_truth_answers` is a plain loop, not a chain) — batching
  or even concurrent/parallel dispatch is technically straightforward
  whenever it's decided to be worth the tradeoff below. It's currently a
  sequential loop, so call count and wall-clock time both scale the same way
  (`documents × n_probe_questions`); parallelizing would cut wall-clock time
  without changing call count, and is a separate lever from batching (which
  cuts call count itself, at the quality/comparability cost above).

### Benchmarking metrics — paper methodology (§ Table 2)

To report results comparably to the paper's own benchmark table, use these
definitions (not this project's own `execute_black_box` threshold-decision
framing, which answers a different question — see below):

| Metric | Meaning |
|---|---|
| **AUC-ROC** | Area under the Receiver Operating Characteristic curve. Built by sweeping *every* possible score threshold and, at each one, plotting (FPR, TPR) — FPR = fraction of true non-members incorrectly called members at that threshold, TPR = fraction of true members correctly called members. AUC is a single 0–1 scalar summarizing separation quality across *all* thresholds at once (1.0 = perfect ranking, i.e. every member scores above every non-member; 0.5 = no better than random). Needs no single fixed threshold — it evaluates the ranking, not a specific decision. |
| **TPR@X%FPR** (paper reports 0.5%, 1%, 5%) | Pick the specific threshold where FPR on the non-member set equals exactly X%, then report what fraction of true members are caught (TPR) at that operating point. Answers: "if I can only tolerate X% of non-members being falsely flagged, what fraction of real members do I actually catch?" Lower X = stricter/more conservative, generally lower TPR. |
| **Accuracy** (paper fixes the threshold at FPR=10%) | Plain accuracy — (correct members + correct non-members) / total — evaluated at the one threshold that yields 10% FPR on the non-member set. A single fixed-operating-point summary, less informative than the full AUC but easy to state as one number. |
| **Cost / doc, time / doc** | The paper's own reported *attacker-side* auxiliary-LLM cost (probe generation + retrieval summary + ground-truth generation) — **excludes actual target-RAG query latency**, which is target-specific and outside the attack's control. Their reported ~7.85s/doc, $0.017/doc is this auxiliary-only figure, not end-to-end wall time against a live target. |
| **Stealth (classifier detection rate)** | Fraction of the attack's *composed queries* flagged as suspicious/adversarial by a third-party prompt-injection/jailbreak classifier (paper tests GPT-4o-as-classifier and Lakera Guard). Low = queries read as ordinary benign questions, which is IA's core advantage over cruder membership-inference baselines that use obviously adversarial phrasing. |

**These require a large *labeled* test set** (the paper uses 250 members +
250 non-members per dataset/generator cell) scored all at once — AUC/TPR/
Accuracy are population statistics over many (score, true-label) pairs, not
something a handful of documents can resolve. This is a different exercise
from `execute_black_box`'s per-document threshold decision (calibrate a
threshold once from a small non-member reference set, then confirm/deny
each candidate against it) — for a real Table-2-style benchmark, every
document (member and non-member alike) just needs its raw Stage A→B→C score
computed once; AUC needs no threshold at all, and TPR@FPR/Accuracy derive
their threshold from the *same* scored set's own ROC curve, not from a
separately-designated calibration subset. **Now built** (2026-08-12): `InterrogationAttack.score_documents(documents)`
runs Stage A→B→C per document with no threshold/calibration step at all,
returning each document's raw score — the caller supplies the true
member/non-member label. `aginiti.reporting.mia_metrics.compute_mia_benchmark_metrics`
takes those `{"id", "score", "is_member"}` triples and computes AUC-ROC,
TPR@{0.5%,1%,5%}FPR, and Accuracy@FPR=10% exactly as described above
(hand-rolled ROC sweep, no scikit-learn dependency). `scripts/run_mia_benchmark.py`
wires both together end-to-end against `hardened_agent`'s CUAD/CFPB
datasets — see that script's own docstring for usage and its
document-availability caveat (CUAD/legal runs far longer than CFPB/support,
so a 50+50 split needs a much higher `--max-doc-chars` for legal, or fewer
non-members, or a different persona).
