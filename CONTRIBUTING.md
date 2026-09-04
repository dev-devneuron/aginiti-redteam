# Contributing to aginiti-redteam

Thanks for your interest in contributing. This is a security tool used to
red-team real enterprise systems — code quality, test coverage, and clear
documentation aren't optional polish here, they're what makes the tool
trustworthy enough for a security team to actually run against systems
they care about.

## Before you start: open an issue first

Work here happens issue-by-issue, not via unsolicited large PRs. Before
writing code:

1. Check the [issue tracker](https://github.com/dev-devneuron/aginiti-redteam/issues)
   for an existing issue covering what you want to do.
2. If none exists, open one describing the problem or proposal. For
   anything nontrivial — a new attack module, a schema change, a directory
   reorganization — expect a short discussion before implementation
   starts, not after.
3. Look for the `good-first-issue` label if you're new to the codebase.

A PR that doesn't reference an issue, or that does something materially
different from what its issue described, will likely need rework.

## Development setup

```bash
git clone https://github.com/dev-devneuron/aginiti-redteam.git
cd aginiti-redteam
pip install -e ".[dev]"
```

Run the test suite (no API key required — all LLM/HTTP calls are mocked):

```bash
pytest tests/ -v
```

See the root `README.md` for the full local-development setup, including
seeding vector stores and starting the reference agents, and
`docs/BENCHMARKS.md` for the optional full-benchmark workflow (which
does need a real `GEMINI_API_KEY` and costs a small amount of API spend).

## Code standards

- **Type hints on every public function/class.** This is a library other
  engineers import and rely on — untyped public APIs are a real adoption
  blocker.
- **Docstrings on every public class/function** — what it does,
  parameters, return type, and for attack modules, which paper/section it
  implements.
- **Tests for every attack module**, at minimum unit tests against the
  reference agents with known ground truth — extraction claims need to be
  verifiable, not just plausible-looking.
- **No silent failures.** If a probe fails, a defense blocks a query, or
  an LLM call errors, surface it as structured information — never
  swallow it silently.
- **Every LLM call goes through [LiteLLM](https://docs.litellm.ai/)** via
  `aginiti/providers/llm.py`'s `_init_llm` pattern. Never hardcode a
  provider SDK or assume a specific response shape.

### Comments and docstrings — write for a future contributor, not for today

A comment answers "why does this code look the way it does," for a reader
with zero context on the PR/conversation that produced it — not "what did
we discover while debugging this." Concretely:

- No first-person narration of a debugging process ("I tried X, it didn't
  work, then I tried Y") and no session-specific narrative in a shipped
  comment.
- No exact dates hardcoded into inline comments or docstrings — git
  history already carries "when." If something is genuinely worth
  recording for future readers, it belongs in `CHANGELOG.md`.
- Citations, paper references, and the rationale behind a locked design
  decision are the exception — that's evergreen, developer-facing content
  and should stay, accurately.

Ask yourself: would this comment make sense to someone reading this file
for the first time on GitHub, who was never part of the PR discussion? If
not, rewrite or cut it.

### Citing the core attack papers

If your change touches one of the four implemented attacks, cite the
paper's actual publication venue first, with the arXiv ID retained as a
secondary reference in parentheses — never arXiv-only:

- **IKEA**: Wang et al., "Silent Leaks: Implicit Knowledge Extraction
  Attack on RAG Systems through Benign Queries," ICLR 2026 (arXiv:2505.15420)
- **SECRET**: He, Chen, Li, Shao, Qi, Li, Tao, Qin, "External Data
  Extraction Attacks against Retrieval-Augmented Large Language Models,"
  IEEE TIFS, vol. 21, pp. 5864–5879, 2026, doi:10.1109/TIFS.2026.3705326
  (arXiv:2510.02964)
- **Interrogation Attack / MIA**: Naseh, Peng, Suri, Chaudhari, Oprea,
  Houmansadr, "Riddle Me This! Stealthy Membership Inference for
  Retrieval-Augmented Generation," ACM CCS 2025 (arXiv:2502.00306)
- **SPE-LLM**: Das, Amini, Wu, "System Prompt Extraction Attacks and
  Defenses in Large Language Models," ICLR 2026 (arXiv:2505.23817)

### Where things go

- `aginiti/attacks/` — deep, paper-faithful, standalone-runnable attack
  implementations. Every attack subclasses `BaseAttack` and emits
  `LeakFinding` (`aginiti/attacks/base.py`) — this is locked; field
  names/types and `execute()`'s dispatch logic don't change without
  explicit maintainer sign-off.
- `aginiti/operators/` — mostly-static, planner-selectable `Operator`
  instances that compose into a campaign. Schema lives in
  `aginiti/operators/base.py`.
- `aginiti/adaptive/` — stateful, multi-step search engines that generate
  new candidates at runtime, distinct from both of the above.

If you're not sure which of these three a new module belongs in, ask in
the issue before writing code — see each directory's own `README.md` for
the full distinction, and don't add a second implementation of an
already-implemented paper without first checking whether one exists (the
`aginiti/attacks/mia/` vs. `aginiti/adaptive/membership_inference.py`
relationship is the one existing example of this being handled correctly
— read either module's docstring for how).

Before creating a new top-level `aginiti/` directory, check whether an
existing one already fits — see each directory's `README.md` for what it
holds.

## Submitting a change

1. Fork the repo and branch from `main`.
2. Make your change, matching the standards above.
3. Run `pytest tests/ -v` — all tests must pass.
4. Open a PR referencing the issue it addresses (e.g. "fixes #42").
5. Keep the PR scoped to that one issue — a PR that also drive-by-fixes
   something unrelated is harder to review and more likely to be asked to
   split up.

## Reporting a security issue in Aginiti itself

This tool is meant for authorized security testing of systems you own or
have explicit permission to test. If you find a vulnerability in
**aginiti-redteam itself** (not in a target you tested with it), please
report it privately rather than opening a public issue — see the contact
information in the repository's GitHub profile.

## Code of Conduct

This project follows the standards in `CODE_OF_CONDUCT.md`.
