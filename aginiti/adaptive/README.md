# aginiti/adaptive — stateful, multi-step search engines

Distinct from `aginiti/attacks/` (deep, paper-faithful, standalone-runnable
attack implementations) and `aginiti/operators/` (mostly-static,
planner-selectable `Operator` instances — one fixed prompt + typed
effects): modules here are stateful, multi-step *search* engines that
generate new candidates at runtime and stop on success, rather than
picking from a fixed menu. See the root `CLAUDE.md`
(§"attacks/ vs. operators/ vs. adaptive/") for the full three-way
distinction if you're deciding where a new module belongs.

## `base.py` — the shared result protocol

`AdaptiveEngineResult` is a `typing.Protocol` (modeled on `Policy(Protocol)`
in `aginiti/core/policies/base.py`) that every result class in this
directory conforms to structurally: `succeeded`, `score`,
`winning_operator`, `final_result`, and a `steps_used` property. A field
that doesn't apply to a given engine is left honestly `None` rather than
faked — e.g. the four stop-on-success engines' `score` is always `None`
(no continuous-score concept), and `MembershipInferenceResult`'s
`succeeded`/`winning_operator` are always `None` (no early-stop, no single
"winning" probe — see that module's own docstring). Each engine's original,
module-specific counter (`trials_used`/`attempts_used`/`turns_used`/
`queries_used`) is untouched; `steps_used` is a new, additive alias.

`finalize_on_success(result, operator, exec_result)` is the shared
trial-recording helper every stop-on-success loop (`variant_discovery`,
`refinement`, `crescendo`, `deceptive_delight`) routes through, closing a
real bug: before this helper existed, three of those four hand-rolled the
identical success block and silently never recorded `winning_operator`,
even though the operator was in scope at the exact line.

Full field-level consolidation (one literal dataclass instead of five) and
`framing_discovery.py`'s tuple return are explicitly out of scope here —
see the open issues tracking those as separate, deliberately deferred
follow-ups.

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
