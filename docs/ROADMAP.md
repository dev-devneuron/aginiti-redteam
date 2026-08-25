# Roadmap

Aginiti already covers more real ground than most agent red-teaming tools attempt — an
adaptive planner, 11 attack methodologies grounded in published research, and a
production-realism hardened target with 8 defense layers, all live-tested. This page is
what's shipped, what's actively being scaled up, and what's next. Every capability below
is either demonstrated against a real target (see [docs/BENCHMARKS.md](BENCHMARKS.md)) or
explicitly marked as in progress — nothing here is claimed on architecture alone.

---

## Shipped

- **Evidence-driven adaptive planning** — a 9-term utility function over a persistent
  Security State Graph, proven to beat fixed enumeration and random sampling on both
  efficiency and coverage against a real, hardened target.
- **Multi-step discovery, not pre-wired chains** — `ClassPrecondition`'s semantic-tag
  gating lets independently-authored operators compose into attack paths no single author
  planned in advance.
- **Composite, severity-weighted scoring** — rewards the highest-consequence finding, not
  just the first one, with a multiplicative score no factor can inflate on its own.
- **Data Reconstruction Attacks** — IKEA and SECRET, both wired as planner-selectable
  operators and as standalone runners with paper-comparable output.
- **Membership Inference** — the Interrogation Attack, live-verified with clean signal
  separation between corpus members and held-out documents.
- **Multi-turn escalation** — Crescendo, Deceptive Delight, and many-shot jailbreaking,
  each a genuinely different mechanism, all real-turn-driven against the live target.
- **A production-realism hardened target** — 8 independently-toggleable defense layers,
  used as the shared benchmark for every policy comparison above.
- **Independent, non-LLM disclosure oracle** — every finding is cross-checked against
  deterministic verbatim/fuzzy matching, never taken on an LLM judge's word alone.
- **Attack-category selector** — pick any of 11 named attack methodologies directly, from
  the CLI or from Python, without hand-assembling an operator list.

## In progress

- **Scaling trial counts.** Current live comparisons run 3 independent trials per
  condition (one per RBAC persona) — real evidence, and the top priority for widening
  right now, alongside a larger, frozen benchmark protocol against an external target.
- **Wiring every discovery engine into one shared campaign.** Most adaptive engines
  (encoding search, framing search, Crescendo, membership inference) already run through
  one orchestrated pipeline over a shared graph; a couple of standalone engines are still
  being folded in so a finding from any phase is immediately visible to every other phase.
- **OTel trace-collector integration** for the scaled-evaluation targets, to upgrade
  black-box findings to white-box-confirmed automatically.

## Next up

- **Feature/Attribute Inference Attack (FIA)** — inferring sensitive attributes about a
  corpus rather than membership or verbatim content.
- **A dedicated `aginiti` CLI wrapper**, so a full assessment is a single command rather
  than a script invocation.
- **Cross-target learning** — carrying a diagnosed failure pattern from one target's
  campaign into the prior for the next, rather than starting cold every time.
- **Broader multi-agent coverage** — extending the current A2A/MCP protocol coverage to
  more real, independently-built multi-agent fleets.

## Contributing

The clearest ways to extend Aginiti:

- **A new operator library** — one module per technique family, composing onto any
  `BaseAdapter`. See `aginiti/operators/` for the existing shape.
- **A new target adapter** — one class per real or mock target; see `aginiti/adapters/`.
- **A new discovery engine** — anything that searches rather than enumerates; see
  `aginiti/adaptive/` for the existing pattern (inject a deterministic stand-in for any
  LLM-drafting call, so it stays fully testable offline).

Every module ships with its own test coverage — the full suite runs offline, in seconds,
at zero API cost (`pytest tests/`). See the root [README](../README.md) for setup.
