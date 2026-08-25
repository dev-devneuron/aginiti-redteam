# Benchmarks & Results

Aginiti is evaluated against real targets — not synthetic mock scenarios built to make it
look good. Every result below comes from a live run, and every finding is cross-checked
against an independent, non-LLM oracle before it counts.

| | |
|---|---|
| **~5x** | fewer requests than fixed-order enumeration, same ground-truth outcomes |
| **98%** | reduction in requests blocked by the target's own input filter |
| **4/5** | attack categories where Aginiti and NVIDIA's garak agreed exactly |
| **9+** | published, cited research papers implemented as real, working operators |
| **1,827** | tests, fully offline, zero API cost |

---

## Independent verification, not just an LLM judge

A single LLM asked "did this attack work?" is a well-known source of false positives.
Aginiti's evaluation pipeline never relies on one alone:

1. A **deterministic extractor** checks the raw response first, wherever a pattern can be
   checked without a model at all.
2. An **LLM judge** evaluates against a specific, enumerated list of candidate claims —
   never an open-ended "was this bad?"
3. An **independent disclosure oracle** — verbatim or fuzzy matching against a
   ground-truth corpus the target's own answer would need to have leaked from — has the
   final word. Nothing is marked `CONFIRMED` on the judge's opinion alone.

This caught real false positives during development — an LLM judge that once scored a
generic refusal as a jailbreak success, and a fuzzy-match miscalibration that over-counted
boilerplate — both closed before results below were finalized.

## Adaptive planning, proven against a hardened, RBAC-defended target

`hardened_agent` is a production-realistic RAG assistant with **8 independently-toggleable
defense layers**: RBAC-scoped retrieval, output redaction, rate limiting, per-persona
conversation memory, a system-prompt guardrail, a dedicated input-filter classifier,
session/auth expiry, and RBAC-scoped tool-calling. It is not a soft target.

Aginiti's adaptive policy was compared head-to-head against two honest baselines —
**Random** selection and **Static** (fixed-order) enumeration — at equal request budget,
with a fresh target process per trial (no cross-trial memory contamination) and 3 real
RBAC personas as independent trials:

| | Random | Static | **Aginiti** |
|---|---|---|---|
| Ground-truth success | 3/3 | 3/3 | **3/3** |
| Avg. prompts to succeed | 23.0 | 50.7 | **9.7** |
| Avg. blocked by the input filter | 9.3 | 40.7 | **0.7** |

Static enumeration also outright **failed** on one persona — `SEARCH_EXHAUSTED` after
trying every one of its 59 eligible operators — while Random and Aginiti both succeeded
from the identical starting state. The efficiency gap is the headline: Aginiti reached the
same outcomes as fixed enumeration using roughly a fifth of the requests, and almost
entirely avoided attempts the input filter was always going to block — evidence the
utility function is actually steering away from dead ends mid-campaign, not succeeding by
volume.

An earlier, tighter-budget run against the same target showed an even sharper gap: Aginiti
won ground-truth success on all 3 personas tested, against Random's 2/3 and Static's 1/3 —
and was the only policy to reach all 6 of the target's distinct attack families in a
single campaign.

## Validated against NVIDIA's garak

[garak](https://github.com/NVIDIA/garak) is the most widely used open-source LLM
vulnerability scanner. Aginiti was run against the identical hardened target, through the
identical gateway, with no tuning favoring either side.

On every directly comparable category, the two tools **agreed exactly**:

| Category | Aginiti | garak | Agreement |
|---|---|---|---|
| System-prompt extraction | 0% ASR | 0% ASR | ✔ |
| Jailbreak | 0% ASR | 0% ASR | ✔ |
| Indirect/latent injection | 0% ASR | 0% ASR | ✔ |
| Markdown/web exfiltration | 0% ASR | 0% ASR | ✔ |

Neither tool hallucinated a false positive against a genuinely well-defended target — a
real, useful cross-check. Where Aginiti goes further is structural: garak's REST-generator
interface can only ever observe text in, text out. It has no way to see a real tool
invocation or confirmed network egress (L2–L5), which is exactly where Aginiti's strongest
real findings live — including a confirmed automatic-mode tool exfiltration and a
markdown-image exfiltration chain (the [EchoLeak/CVE-2025-32711](https://www.cve.org/CVERecord?id=CVE-2025-32711)
pattern), both independently confirmed via a listener log, not an LLM's word.

## Real findings across real, independently-built targets

- **AnythingLLM** (real, production-shaped RAG/agent platform): four confirmed chains, up
  to **L5 (confirmed exfiltration)** — RAG document-poisoning, automatic-mode tool
  exfiltration, markdown-image exfiltration, and a genuine 3-step multi-tool composition
  chain requiring two different tools to complete. Tested against a hardened, two-round
  gateway built to resemble production, not a soft target.
- **DVAA** (19-agent fleet, 3 real protocols — A2A, MCP, RAG): 12 operators including a
  real 2-step cross-tool composition attack where neither step alone is a mission outcome.
- **`hardened_agent`**: two confirmed RBAC/authorization crossings (a persona receiving
  content never flagged for its own scope) via aggregation probes, plus real RAG
  corpus-membership inference confirmed across all three personas with a clean signal
  separation (member documents scoring 1.0 vs. held-out documents scoring negative).
- **InjecAgent** ([Zhan et al., ACL Findings 2024](https://arxiv.org/abs/2403.02691)):
  1,054 real, vendored indirect-prompt-injection test cases, driven through Aginiti's own
  adapter and campaign loop rather than the paper's own evaluation harness.

## Built on published research, not reinvented in isolation

Every non-trivial technique in Aginiti's catalog is grounded in a specific, cited paper —
implemented as described, in Aginiti's own code, never copied:

| Technique | Source |
|---|---|
| ArtPrompt (ASCII-art token masking) | Jiang et al., ACL 2024 — [arXiv:2402.11753](https://arxiv.org/abs/2402.11753) |
| Crescendo (multi-turn escalation) | Russinovich, Salem, Eldan (Microsoft) — [arXiv:2404.01833](https://arxiv.org/abs/2404.01833) |
| PAIR (adaptive prompt refinement) | Chao et al. — [arXiv:2310.08419](https://arxiv.org/abs/2310.08419) |
| CipherChat / MetaCipher (cipher-family search) | [arXiv:2308.06463](https://arxiv.org/abs/2308.06463), [arXiv:2506.22557](https://arxiv.org/abs/2506.22557) |
| Interrogation Attack (membership inference) | Naseh et al., ACM CCS 2025 — [arXiv:2502.00306](https://arxiv.org/abs/2502.00306) |
| IKEA (data reconstruction) | [arXiv:2505.15420](https://arxiv.org/abs/2505.15420) |
| SECRET (jailbreak-optimized DRA) | IEEE TIFS 2026 — [arXiv:2510.02964](https://arxiv.org/abs/2510.02964) |
| InjecAgent (indirect injection benchmark) | Zhan et al., ACL Findings 2024 — [arXiv:2403.02691](https://arxiv.org/abs/2403.02691) |
| STAC (tool-chain composition) | [arXiv:2509.25624](https://arxiv.org/abs/2509.25624) |

Full citation list, licenses, and exactly what was adapted vs. independently implemented
are in the source of each module's own docstring.

---

Methodology notes: results above use N=3 independent trials per condition (one per RBAC
persona) — real, disclosed evidence, and an area we're actively scaling up; see
[docs/ROADMAP.md](ROADMAP.md).
