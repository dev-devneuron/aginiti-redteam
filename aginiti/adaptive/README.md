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

`framing_discovery.py`'s own `FramingDiscoveryResult` is a sixth conformer,
composed OVER `variant_discovery.py`'s and `refinement.py`'s result objects
(`.discovery` / `.escalated_to`) rather than duplicating their fields — see
that module's own docstring.

**Full field-level consolidation (one literal dataclass instead of six) and
rebuilding `refinement.py`/`crescendo.py`/`deceptive_delight.py` atop
`variant_discovery.py`'s engine were evaluated and declined** (Issue #27,
closed): the blast radius is real (five live experiment scripts read
`.trials`/`.attempts`/`.turns` directly, not just tests and
`assessment.py`), the remaining per-engine field names are meaningful
domain vocabulary (a trial, an attempt, a turn are genuinely different
things) rather than accidental duplication, and `refinement.py`'s
"one claim key, retried with different wording" model is a real
architectural mismatch with `variant_discovery.py`'s "one claim key per
candidate" model, not just similarly-shaped loops — forcing them through
one engine would change what claims land in the SSG for three live-tested,
paper-grounded mechanisms. The one genuinely missing piece,
`VariantTrial.prompt_sent` (the other three trial-record types already had
it), was added on its own.

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
