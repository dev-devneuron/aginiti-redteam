# Aginiti — Proposed Operator: Invisible Unicode-Tag Data Exfiltration ("ASCII Smuggling")

_Last rewritten 2026-08-13._

**Status: documented follow-up, not yet implemented.** Several rounds of
expansion have landed in the markdown/network-exfiltration family since
this proposal was first written (`docs/ATTACK_LIBRARY.md`'s
`markdown_network_exfiltration` category, the `encoding_attack` chain-
discovery layer) without folding this specific technique in — it remains a
real, well-cited, buildable gap, not overtaken by other work. See `docs/
AGINITI_OVERVIEW.md` §10 for where this sits among the project's other
open gaps. This document is the concrete specification for a genuinely
NEW technique, distinct from the already-implemented
`anythingllm_markdown_exfil_definitions.py`, which uses image-render
auto-fetch — a different mechanism entirely. Implementation has been
deliberately deferred each time it came up, to avoid building and
live-testing against the real AnythingLLM target in the same window a live
benchmark run needed to be protected from resource contention.

## The security property

**Can a poisoned RAG document cause the target LLM to leak real
conversation/document content back to the user in a form a human reviewer
cannot see, but a machine (or the attacker who planted the document) can
decode?**

This is a distinct property from every exfiltration primitive already in
this project:

- `anythingllm_markdown_exfil_definitions.py` (image-render auto-fetch) and
  `anythingllm_automatic_indirect_tool_exfil_trigger` (tool-call to an
  attacker URL) both exfiltrate by causing an outbound NETWORK request the
  attacker's own infrastructure receives directly. Both are visible on
  inspection of the raw response text (a literal `![...](url)` or a
  logged tool call) -- a human or automated reviewer skimming the
  transcript, or a DLP/output-filtering layer scanning the visible text,
  would see the exfiltrated data or the URL carrying it.
- This proposed primitive instead tests whether the target can be made to
  embed the SAME kind of leaked data directly in its own chat response,
  but steganographically hidden using invisible Unicode characters --
  passing human visual review and naive text-based DLP filtering (which
  typically doesn't decode non-printing codepoints) while remaining fully
  present and machine-recoverable in the raw response text the API
  actually returns. No outbound network request is needed at all; the
  channel is the response body itself, later read by whoever has access to
  the raw (not rendered) text -- the attacker who planted the document, if
  they also have any read access to the conversation, or anyone the
  compromised output is later forwarded to.

## Confirmed not already covered

Checked `aginiti/operators/` (`grep -rli "unicode|invisible|zero.width|
ascii.smuggl|tag.block"`): no match. None of the three existing AnythingLLM
operator files (`anythingllm_definitions.py`,
`anythingllm_automatic_definitions.py`,
`anythingllm_markdown_exfil_definitions.py`) touch this mechanism.

## Grounding: this is current, real, and well-documented research

- Unicode Tags block (U+E0000-U+E007F) characters render as *nothing* in
  every mainstream font/UI, but round-trip losslessly through most text
  pipelines (including, per the research below, LLM tokenizers) --
  originally a defunct language-tagging mechanism, repurposed as a covert
  channel.
- Embrace The Red, "Sneaky Bits: Advanced Data Smuggling Techniques (ASCII
  Smuggler Updates)" (2025) and the earlier ASCII Smuggling writeups:
  https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/
- Embrace The Red, "Amp Code: Invisible Prompt Injection Fixed by
  Sourcegraph" (2025) -- a real, shipped product that had exactly this
  invisible-Unicode-tag injection/exfil vector and had to patch it:
  https://embracethered.com/blog/posts/2025/amp-code-fixed-invisible-prompt-injection/
- Promptfoo's red-team plugin catalog treats this as a standing test
  category: https://www.promptfoo.dev/docs/red-team/plugins/ascii-smuggling/
- FireTail, "Ghosts in the Machine: ASCII Smuggling across Various LLMs"
  (2025) -- cross-model survey, reported to Google Sept 2025:
  https://www.firetail.ai/blog/ghosts-in-the-machine-ascii-smuggling-across-various-llms
- Independent reproduction against real chatbots, Aug 2025:
  https://www.gabriel.urdhr.fr/2025/08/20/unicode-tag-smuggling/
- Catalogued as a named technique in the AI Agents Attack Matrix:
  https://ttps.ai/technique/ascii_smuggling.html

This satisfies the same bar the markdown-exfil primitive was held to:
multiple independent, current (2025) sources, at least one documented
real-product vulnerability (not just theoretical), not a single blog post.

## What would make this operator real, not theoretical

Following this project's own evidence discipline (`docs/
EVIDENCE_AND_EVALUATION.md`), an operator claiming this primitive works
needs a ground-truth check that is deterministic and independent of any
LLM judge, mirroring how `anythingllm_markdown_exfil_definitions.py`
double-checks via both a regex on the raw response AND an independent
listener-log confirmation:

1. **Encode/decode helpers** (`chr(0xE0000 + ord(c))` per ASCII byte, and
   the inverse) -- pure functions, unit-testable with no network calls,
   e.g. `aginiti/operators/ascii_smuggling.py`.
2. **Plant document**: a RAG document containing an instruction hidden via
   invisible tag-encoding (invisible to a human opening the document, but
   present in the raw bytes the retriever feeds the model) asking the
   model to append the requested secret/canary to its answer ALSO encoded
   in invisible tag characters.
3. **Deterministic ground truth**: after the target responds, scan the RAW
   response text (not the rendered/visible text) for any run of Unicode
   Tag-block codepoints, decode it, and check whether it contains the
   canary/secret -- exactly analogous to the markdown operator's regex
   check on `![alt](url)`, just checking for a different, non-printing
   pattern instead. This is the ONLY reliable ground truth for this
   primitive: the injected instruction succeeding or failing is not
   something an LLM judge should be trusted to assess, because the entire
   point of the attack is that the payload is invisible to something
   reading it as if it were a human -- exactly the failure mode this
   project's own judge-reliability work (Exp 2, `docs/
  EVIDENCE_AND_EVALUATION.md`) already flagged as a risk for judges asked
  to eyeball text for a needle they can't see.
4. **Live validation, same discipline as every other primitive in this
   project** (`anythingllm_markdown_exfil_definitions.py` was live-verified
   3/3 before being trusted): plant against a real AnythingLLM workspace,
   confirm the target's underlying model (Gemini, per this session's
   target-side config) actually follows an instruction it received purely
   via invisible codepoints, AND that it reproduces the payload back
   invisibly rather than in plain, visible text.

## Why this needs a dedicated pass, not a same-turn add

Live-verifying this requires creating a new AnythingLLM workspace, planting
a document, and running real chat turns against the live target -- the
same infrastructure (and the same rate-limited LLM keys) the exp13
benchmark run currently depends on. Building and testing it in parallel
with a live in-progress benchmark risks exactly the kind of resource
contention / interference the current task is explicitly protecting
against. This is deferred as a clean follow-up task rather than rushed in
under that constraint.
