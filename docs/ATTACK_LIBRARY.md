# Attack library: taxonomy + adaptive discovery

Added 2026-08-12 at explicit direction to organize Aginiti's operator
library around a named set of attack categories, tag it against current
external taxonomies beyond OWASP, and make the categories that most
benefit from it genuinely adaptive rather than static-payload-only.

## The 11-category taxonomy (`aginiti/graph/attack_category.py`)

A fourth, additive tagging dimension on `ClaimEffect`, alongside
`category` (graph-fact kind), `security_boundary` (how deep, L0-L5), and
`owasp_llm_category` (OWASP LLM Top 10 2025). Answers "what attack
METHODOLOGY is this":

| Category | Meaning | Example operators |
|---|---|---|
| `direct_prompt_attack` | Single-turn, user-channel manipulation | `system_prompt_extraction`, `jailbreak_dan_style`, `secret_pattern_fishing` |
| `encoding_attack` | Obfuscation/transformation-based evasion | `encoding_evasion_probe`, every `encoding_variants.py`/`encoding_discovery.py` operator |
| `rag_poisoning` | Planting malicious content into a retrieval index | Every AnythingLLM chain's *plant* step |
| `indirect_injection` | Instruction execution triggered via retrieved/tool-output content | AnythingLLM RAG trigger, every `injecagent.py` operator |
| `tool_discovery` | Enumerating/disclosing available tools | `tool_inventory_full_disclosure`, `mcp_tool_discovery` |
| `tool_manipulation` | Invoking a real tool outside its intended scope/authorization | `tool_parameter_override_probe`, `mcp_no_auth_check`, `mcp_unverified_tool_registration` |
| `markdown_network_exfiltration` | Confirmed data egress via markdown auto-fetch or tool-driven network call | Automatic-mode and markdown-exfil chain triggers |
| `multi_step_chain` | Genuine AND-composition across 2+ independently-confirmed operators | `anythingllm_multitool_relay_confirmed`, `mcp_exfiltrate_via_plugin_fetch` |
| `decoy` | Planner-evaluation control: structurally valid, connects to no mission node | The 3 mock-library decoys |
| `known_defended` | Planner-evaluation control: an operator this project has documented as reliably refused | `memory_context_leakage_probe` |
| `low_value_reconnaissance` | Planner-evaluation control: low intrinsic value but opens a real path | `recon_capabilities`, `recon_github_access`, `probe_helpdesk_capability` |

The last three are not offensive techniques — see `OFFENSIVE_CATEGORIES`/
`is_offensive()` to exclude them from "how many real attack techniques
does Aginiti cover" reporting.

## MITRE ATLAS cross-reference (`aginiti/graph/mitre_atlas_refs.py`)

"Other latest work beyond OWASP": a short, deliberately incomplete list of
**verified** (live-searched, not recalled) MITRE ATLAS technique IDs —
`AML.T0051.000`/`.001` (direct/indirect prompt injection), `AML.T0054`
(jailbreak), `AML.T0070` (RAG poisoning), `AML.T0086` (exfiltration via
tool invocation). Only operators with a real, checkable match are tagged;
an untagged operator means "not yet cross-referenced," never a claim of
no applicable technique.

Also researched but not yet built into a tagging module: **OWASP Top 10
for Agentic Applications 2026** (ASI01 Agent Goal Hijack .. ASI10 Rogue
Agents, released 2025-12-09) and the broader **OWASP Agentic AI Threats
and Mitigations** guide (Feb 2025, covering Agent Design/Memory/Planning &
Autonomy/Tool Use/Deployment). A natural next tagging dimension once
read as carefully as the LLM Top 10 and ATLAS were here.

## Adaptive discovery (`aginiti/adaptive/`)

Three modules, layered:

- **`variant_discovery.py`** — the generic engine. `run_variant_discovery`
  calls a domain-supplied `next_candidate_fn(trial_history)` for up to
  `max_trials` rounds, executing each candidate Operator through the real
  `ObservationAdapter`/SSG path and stopping the instant one succeeds.
  Domain logic decides *what* to try next; this module only owns *whether
  to keep going*.
- **`encoding_discovery.py`** — the flagship application. Where
  `encoding_variants.py` fires a fixed list of 12 pipelines,
  `run_encoding_chain_discovery` SEARCHES: 10 single converters, then
  `SelfCipherPrimerConverter` (pure role-play priming, no literal
  encoding), then SYNTHESIZED cross-family stacks (an "opaque" transform
  paired with a "shape-preserving" one — CipherChat's own family split,
  arXiv:2308.06463) built on the fly from what hasn't been tried yet.
  Research-grounded in CipherChat and MetaCipher (arXiv:2506.22557, 2025
  AAAI — adaptive cipher *selection* reaching SOTA attack success within
  ~10 queries). This is genuinely different in kind from a static
  enumeration, not just a longer list.
- **`framing_discovery.py`** — proves the engine generalizes. Sweeps 5
  structurally different pretexts (direct/authority/urgency/compliance/
  role-play) for the *same* underlying direct-prompt-attack goal, and
  escalates to `refinement.py`'s PAIR-style LLM rewriting if every static
  framing fails.
- **`refinement.py`** (built earlier this session) — PAIR-style (Chao et
  al. 2023) single-operator retry loop, used standalone or as
  `framing_discovery`'s last-resort escalation tier.

All four are fully unit-tested with deterministic stub adapters/
extractors — **no live LLM or target calls in any test**, and none of
this has been run against the live hardened AnythingLLM target yet
(pending explicit approval for the next real experiment).
