# aginiti/adaptive — stateful, multi-step search engines

Distinct from `aginiti/attacks/` (deep, paper-faithful, standalone-runnable
attack implementations) and `aginiti/operators/` (mostly-static,
planner-selectable `Operator` instances — one fixed prompt + typed
effects): modules here are stateful, multi-step *search* engines that
generate new candidates at runtime and stop on success, rather than
picking from a fixed menu. See the root `CLAUDE.md`
(§"attacks/ vs. operators/ vs. adaptive/") for the full three-way
distinction if you're deciding where a new module belongs.

**No `base.py` yet** — genuinely a gap, not an oversight: these 8 modules
don't currently share a common entry-point protocol or result type, unlike
every other directory with a `base.py`. Introducing one (a shared
`AdaptiveEngineResult` + entry-point protocol + trial-recording helper) is
tracked as a deliberately separate, sign-off-gated design decision — see
`plans/open-source-readiness.md` if you're picking this up.

| Module | What it searches |
|---|---|
| `variant_discovery.py` | The generic reusable engine — "try candidates adaptively until one works" — that the two modules below are concrete applications of. |
| `encoding_discovery.py` | Adaptive encoding-chain discovery (which encoding, or stack of encodings, gets past this specific target's defenses). |
| `framing_discovery.py` | Adaptive framing discovery for direct prompt attacks — the second application of `variant_discovery.py`'s engine. |
| `refinement.py` | Feedback-driven retry for a single `Operator`: reads a refusal and tries again differently, rather than firing one fixed prompt and stopping. |
| `crescendo.py` | Multi-turn escalation (Russinovich, Salem, Eldan — Microsoft, arXiv:2404.01833). |
| `deceptive_delight.py` | Deceptive Delight — camouflage-and-distraction jailbreaking (Palo Alto Networks Unit 42, Oct 2024). |
| `many_shot.py` | Many-shot jailbreaking (Anil et al., Anthropic, 2024) — floods context with many fabricated compliant turns; a genuinely different mechanism from every single-turn technique elsewhere in this library. |
| `membership_inference.py` | A planner-composable `Operator` restatement of the Interrogation Attack — see its own module docstring for how this relates to (and does not replace) `aginiti/attacks/mia/interrogation.py`, the primary paper-faithful implementation. |

Each module cites its own research grounding in its module docstring —
check there before assuming a technique's provenance.
