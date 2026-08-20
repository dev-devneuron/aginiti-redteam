# Aginiti — Research, Repos & Provenance

_Last rewritten 2026-08-13 (content unchanged from the 2026-08-12 version
this rewrite is based on — every entry below was already checked against a
live source, GitHub API license metadata, arXiv, or a direct web search,
either when the citing code was written or specifically for this document;
nothing here is recalled from training data and presented as verified
without an actual check. Where a check couldn't be completed, that's
stated, not silently skipped). Organized by REUSE TYPE, since "we
referenced this paper's idea" and "we copied and adapted this repo's code"
carry very different obligations — conflating them would itself be a
citation error. Companion to `docs/ATTACK_LIBRARY.md` (the taxonomy these
citations ground) and `docs/EVIDENCE_AND_EVALUATION.md` (where the planner-
level citations, like the reward-shaping papers behind `chain_value`, are
tied to the specific experiments they motivated)._

---

## How to read this document

Four reuse types appear below, each with a different bar:

1. **Code adapted** — source code was read and mechanically translated
   into Aginiti's own architecture. License terms must be preserved.
2. **Data vendored** — real files copied byte-for-byte from an upstream
   repo. License must permit redistribution; attribution preserved via a
   NOTICE file.
3. **Attack pattern/category reused, no code copied** — the CONCEPT (what
   kind of attack this is, roughly how it works) is translated into
   Aginiti's own typed operator shape; the actual prompt text, regex, or
   implementation is original. This is the large majority of entries
   below, and is the explicit, standing discipline this project has
   followed since `data_exposure.py`'s first garak-inspired operators:
   "reuse the ATTACK CATEGORY, not the source text."
4. **Research grounding** — a paper or public finding that motivates a
   design decision (a planner term, a taxonomy dimension, a target-
   hardening choice) without any code or data being borrowed at all.

---

## 1. Code adapted (license terms apply, preserved below)

| Source | What was adapted | License | Where in Aginiti |
|---|---|---|---|
| **Cisco AI Defense, `mcp-scanner`** (github.com/cisco-ai-defense/mcp-scanner) | `mcpscanner/core/analyzers/prompt_defense_analyzer.py`'s 12 `DEFENSE_RULES` (regex patterns + severity/threat-category metadata) and its scanning algorithm — "mechanical translation," their class hierarchy NOT imported | Apache 2.0 (copyright Cisco Systems, Inc.) | `aginiti/static_analysis/prompt_defense.py` — attribution and license terms preserved in the module docstring per Apache 2.0 §4, fetched and dated 2026-08-08 |

This is the **only** entry in this document where Aginiti's own source
code (not just an attack concept) was directly adapted from an external
open-source project. Everywhere else, the reuse is category-level or
data-level, not code-level — deliberate, and worth being precise about,
since the obligations differ.

## 2. Data vendored (real files, unmodified, with license verified)

| Source | What was vendored | License | Where in Aginiti |
|---|---|---|---|
| **InjecAgent** (Zhan, Liang, Ying, Kang — UIUC, ACL Findings 2024, arXiv:2403.02691, github.com/uiuc-kang-lab/InjecAgent) | `user_cases.jsonl` (17 legitimate scenarios), `attacker_cases_dh.jsonl` (30 direct-harm intents), `attacker_cases_ds.jsonl` (32 data-stealing intents), `tools.json` (38 toolkits / 330 tool schemas) — real, unmodified, fetched directly from the raw GitHub content, 1,054 test cases total, matching the paper's own reported count exactly | MIT (confirmed via GitHub API repository metadata at fetch time, not inferred) | `aginiti/operators/injecagent_data/` — full provenance in that directory's own `NOTICE.md`. The paper's own evaluation harness was deliberately NOT vendored; Aginiti drives the same test cases through its own adapter/campaign loop instead (`aginiti/adapters/injecagent_adapter.py`) |
| **WithSecureLabs, `damn-vulnerable-llm-agent`** (github.com/WithSecureLabs/damn-vulnerable-llm-agent) | The target itself (rebuilt on current LangChain `create_agent` after the original's agent class was deprecated) plus a vendored copy of its transaction DB, used only to build ground truth | (real, independently-developed vulnerable-by-design target, not a research paper — used as a live TARGET, not borrowed methodology) | `aginiti/adapters/dvla_adapter.py`, `aginiti/adapters/vendor/dvla_transaction_db.py` |
| **`damn-vulnerable-ai-agent` (DVAA)** | The target itself: a 19-agent fleet spanning API/MCP/A2A/consensus protocols, live-verified before any operator was written against it | (real, independently-developed vulnerable-by-design target) | `aginiti/adapters/dvaa_adapter.py`, `aginiti/operators/dvaa_definitions.py`, `dvaa_consensus_definitions.py` |
| **Official MCP reference implementation** (github.com/modelcontextprotocol/servers) | The real `@modelcontextprotocol/server-filesystem`, run over genuine stdio transport with a real `initialize` handshake | (official protocol reference implementation, used as a live target) | `aginiti/adapters/mcp_stdio_adapter.py`, `aginiti/operators/mcp_filesystem_definitions.py` |

## 3. Attack pattern/category reused (no code copied — the standing discipline)

### From open-source scanners

| Source | Category reused | License (of the source tool) | Aginiti operators |
|---|---|---|---|
| **garak** (NVIDIA, github.com/NVIDIA/garak, Apache 2.0) | `sysprompt_extraction`, `dan` (jailbreak), `encoding` (obfuscation-based evasion), `agent_breaker`/tool-inventory disclosure concern | Apache 2.0 | `system_prompt_extraction`, `jailbreak_dan_style`, `encoding_evasion_probe`, `tool_inventory_full_disclosure` (`data_exposure.py`) |
| **PyRIT** (Microsoft/Azure, github.com/Azure/PyRIT, MIT) | The `PromptConverter` architecture — composable, chainable text-transformation pipeline (not any specific converter's prompt text) | MIT | `aginiti/transforms/converters.py`'s `PromptConverter`/`ConverterPipeline`, and `aginiti/adaptive/refinement.py`'s standalone-retry-loop framing |

### From published jailbreak/red-teaming research

| Paper | What's reused | Where |
|---|---|---|
| **CipherChat** — Yuan, Jiao, Wang, Huang, Yu, Xing, Yang, Wang, Tao, Zhang, "GPT-4 Is Too Smart To Be Safe: Stealthy Chat with LLMs via Cipher" (2023, arXiv:2308.06463) | The finding that cipher/encoding FAMILIES (character encodings vs. substitution ciphers) succeed at different rates, and that pure role-play priming with NO literal encoding ("SelfCipher") often outperforms every literal cipher tested | `aginiti/adaptive/encoding_discovery.py`'s cross-family stack-synthesis strategy and `SelfCipherPrimerConverter` (own wording, not the paper's prompt text) |
| **MetaCipher** — "A Time-Persistent and Universal Multi-Agent Framework for Cipher-Based Jailbreak Attacks for LLMs" (2025, arXiv:2506.22557, AAAI) | The finding that ADAPTIVE cipher selection (not a bigger fixed list) reaches state-of-the-art attack success within ~10 queries — the direct research grounding for building a search instead of a static enumeration | `aginiti/adaptive/encoding_discovery.py`'s whole design rationale (own, much simpler, fully-deterministic selector — not a reimplementation of MetaCipher's RL-trained one) |
| **PAIR** — Chao, Robey, Dobriban, Hassani, Pappas, Wong, "Jailbreaking Black Box Large Language Models in Twenty Queries" (2023, arXiv:2310.08419) | The mechanism: one attacker-LLM conversation that reads the target's LAST response and rewrites the next attempt conditioned on it | `aginiti/adaptive/refinement.py` — implemented as described, own prompt wording |
| **TAP** — Mehrotra et al., "Tree of Attacks: Jailbreaking Black-Box LLMs Automatically" (2023, arXiv:2312.02119) | Named as the natural generalization of PAIR (branching tree search vs. a linear chain) — explicitly NOT implemented, documented as future scope | `aginiti/adaptive/refinement.py`'s own docstring, scoping what it is and isn't |
| **Crescendo** — Russinovich, Salem, Eldan (Microsoft), "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack" (2024, arXiv:2404.01833) | The mechanism: gradual escalation across REAL turns, each drafted live from the target's own actual prior response, distinct from `refinement.py`'s single-operator rewrite loop | **Implemented 2026-08-14**: `aginiti/adaptive/crescendo.py` |
| **Many-shot jailbreaking** — Anil et al. (Anthropic, 2024, "Many-shot Jailbreaking," anthropic.com/research/many-shot-jailbreaking) | The mechanism: embedding many (4/8/16/32 here) fabricated in-context Q&A exchanges into ONE message to exploit long-context in-context learning, rather than a single-turn pretext | **Implemented 2026-08-14**: `aginiti/adaptive/many_shot.py` (deliberately bland/generic shot content — never real harmful examples) |
| **Greshake, Abdelnabi, Mishra, Endres, Holz, Fritz**, "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (AISec '23) | The academic grounding for indirect prompt injection as a real threat class — instructions arriving via retrieved/delegated content rather than a direct request | The mock library's Slack/GitHub-issue-sourced injection probes; DVAA's memory-planting operators; conceptually, every "trigger" half of a plant→trigger chain |
| **Sarraute, Buffet, Hoffmann**, "Penetration Testing == POMDP Solving?" (2011) | Treating adversarial planning as decision-making under partial observability, not deterministic scripting | Why Claims carry a confidence band instead of a boolean; why `AginitiPlanner` computes a utility, not a fixed script |
| **W3C PROV-O** provenance ontology | The entity/activity/derivation model | The Fact → Observation → Claim chain's own structure |

### From RAG access-control / membership-inference research (2026-08-14)

Added in direct response to a principal-engineer re-audit finding that
`hardened_agent`'s RBAC boundary was never once crossed across an entire
live experiment (`exp25`) — traced, by reading the target's actual source
(not guessed), to a real, correctly-implemented control (retrieval-time
metadata filtering + bearer-key-only persona binding), which no
prompt-level attack can defeat. This research pass asked what a
GENERALIZABLE answer to "how do you find out if an agent's RBAC is
actually weak" looks like, grounded in what's currently published, not
assumption.

| Source | What's reused | Where |
|---|---|---|
| **Pinecone**, "RAG with Access Control" (pinecone.io/learn/rag-access-control) | The pre-filter (permission check inside the vector search) vs. post-filter (retrieve-then-filter) distinction — pre-filter is what `hardened_agent` actually does and is WHY its boundary held; post-filter is the common, weaker real-world pattern | **Implemented**: `aginiti/operators/access_control_layer_probe.py` — a diagnostic distinguishing the two architectures via natural completeness/awareness questions, not content extraction |
| **Naseh, Amit, Goldsteen et al.**, "Riddle Me This! Stealthy Membership Inference for Retrieval-Augmented Generation" (2025, arXiv:2502.00306) | The Interrogation Attack's exact mechanism (fetched and read in full, not assumed from the abstract): natural-sounding retrieval-summary + probe-question generation, response-vs-ground-truth scoring `(1/n)Σ[correct − λ·unknown]`, threshold calibration against known non-members | **Implemented 2026-08-14**: `aginiti/adaptive/membership_inference.py`, one disclosed scope reduction (n=8 probes/doc default vs. the paper's n=30, for live-LLM-cost reasons). Live-verified against `hardened_agent`: member doc scored 1.0, three independent held-out non-members scored -0.125/-0.5/-0.5 |
| **Anderson, Amit, Goldsteen**, "Is My Data in Your Retrieval Database? Membership Inference Attacks Against Retrieval Augmented Generation" (2024, arXiv:2405.20446) | Background establishing RAG membership inference as a real, distinct research area | Cited context only — the specific technique implemented is Riddle Me This's, not this paper's own method |
| Hardy, "The Confused Deputy" (ACM SIGOPS Operating Systems Review, 1988) — the classical security concept; Greshake et al., "Not what you've signed up for..." (2023, arXiv:2302.12173) — applied to LLM authority-claim injection | Unverified authority/access claims in a prompt being treated as if they were a credential | **Implemented**: `aginiti/operators/hardened_agent_definitions.py`'s `_build_authority_claim_probes` |
| **"Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework"** (arXiv:2601.11893) | Read in full 2026-08-14 (previously cited from a title/snippet only — corrected here). Proposes SEAgent, a DEFENSIVE attribute-based mandatory-access-control framework for multi-agent systems (information-flow graph, policy enforcement on entity attributes) — names "a variant of the confused deputy problem in multi-agent systems" as a real privilege-escalation pattern, independently corroborating the authority-claim probes above | **Not implemented, and not attack-relevant to implement** — it's the defender's side of this exact problem, the mirror image of what Aginiti tests |
| CWE-488, "Exposure of Data Element to Wrong Session" (MITRE); the March 2023 ChatGPT Redis-client incident (openai.com/index/march-20-chatgpt-outage) — a real, publicly-documented instance of cross-user conversation-history leakage | The general session/memory-isolation vulnerability class | **Implemented**: `aginiti/operators/session_isolation_probe.py`. Live-verified 2026-08-14 against `healthcare_agent`: the "concurrent_other_user" pretext surfaced real, verbatim patient-consultation corpus text (confirmed against the raw dataset) framed as "the other conversation" — NOT a literal memory leak (`healthcare_agent` is stateless, confirmed by source), but a genuine, real disclosure via an indirect-elicitation pretext the direct-question operators didn't produce |

**One disclosed exception to this project's "never reverse-engineer from a
target's exact vulnerable source line" rule**: `aginiti/operators/
redaction_format_evasion.py` (2026-08-14) is deliberately target-specific,
built around the exact 4 regex gaps in `hardened_agent`'s own `redact()`
function (seen incidentally while investigating RBAC, not sought out) —
the user explicitly chose this over a purely generic alternative,
understanding it makes the resulting operators a finding about THIS
implementation, not a generalizable technique. Stated in that module's own
docstring, not hidden; do not point it at another target and report a
"redaction bypass" as if it generalizes.

### From real-world vulnerability research and CVEs

| Source | What's reused | Verification |
|---|---|---|
| **EchoLeak** (CVE-2025-32711, disclosed June 2025, Aim Security) — first documented zero-click prompt-injection exploit in a production LLM system (Microsoft 365 Copilot), chaining markdown-image auto-fetch to achieve unauthenticated data exfiltration | The core mechanism `anythingllm_markdown_exfil_definitions.py` tests: markdown-image auto-render as a client-side exfiltration channel needing no tool permissions at all | Live-confirmed via multiple independent 2025 security-vendor writeups |
| **MCPTox** benchmark (arXiv:2508.14925) — tested 45 live MCP servers / 353 tools, up to 72% attack success on MCP tool-poisoning | Grounds `dvaa_definitions.py`'s `mcp_unverified_tool_registration` (a supply-chain, write-path trust boundary distinct from every other MCP operator in that file) | arXiv abstract confirmed |
| **CVE-2025-54136** — MCP Tool Poisoning | Same operator as above, real CVE citation for the vulnerability class | — |
| **STAC** (arXiv:2509.25624, Oct 2025) — "innocent tools form dangerous chains" | Grounds `mcp_execute_read_secret_config` → `mcp_exfiltrate_via_plugin_fetch`, a genuine 2-step composition attack where NEITHER operator alone is a mission outcome | arXiv abstract confirmed |
| **A2ASecBench** (Zhan et al., ICLR 2026, github.com/SaFo-Lab/A2ASecBench, MIT) | Of 6 named A2A attacks, the 3 that are data-exposure-shaped (not availability/DoS-shaped, out of this project's scope) | License verified via GitHub API |
| **MINJA** (Dong et al., NeurIPS 2025, github.com/dsh3n77/MINJA) | The attack PATTERN only (a memory-poisoning write that never issues an explicit "remember this" command, unlike this file's own pre-existing plant/recall pair) — **no code reused**, since the repo has **no license file** | Verified via GitHub API; the absence of a license is the reason this entry is pattern-only, stated explicitly in the code |
| **agentpwn.com** (`src/payloads/agentpwn-mirror.js`, `APWN-DE-003` URL-exfiltration pattern) | DVAA's own actual, real (not simulated) knowledge-base exfiltration mechanism — read directly from the running target's own source, not an external research artifact | Live-verified via direct source inspection of the actual DVAA install, not assumed from docs |
| **CVE-2026-25253** (OpenClaw agentic-skill RCE), **CVE-2026-35435** (Azure AI Foundry M365 agents privilege escalation) | Investigated, explicitly **NOT adopted** — vendor/framework-specific, not expressible against DVAA's actual architecture; flagged as future target-adoption candidates | Investigated, scoped out on record rather than silently dropped |

### Researched, cited, but NOT yet built into a working operator (honest gaps)

| Source | What it describes | Status |
|---|---|---|
| Embrace The Red, "Sneaky Bits: Advanced Data Smuggling Techniques" (2025); "Amp Code: Invisible Prompt Injection Fixed by Sourcegraph" (2025); Promptfoo's ASCII-smuggling red-team plugin; FireTail, "Ghosts in the Machine: ASCII Smuggling across Various LLMs" (2025); independent Aug-2025 reproduction; AI Agents Attack Matrix's `ascii_smuggling` entry | Invisible Unicode-Tags-block (U+E0000-U+E007F) steganographic data exfiltration — passes human visual review and naive text-based DLP | Fully specified, multiply-sourced (including one real shipped-product fix), **not implemented** — `docs/ATTACK_PROPOSAL_ascii_smuggling_exfil.md` |
| **OWASP Top 10 for Agentic Applications 2026** (ASI01 Agent Goal Hijack … ASI10 Rogue Agents, released 2025-12-09, genai.owasp.org) | The newest agentic-specific risk taxonomy, developed with 100+ industry contributors | Researched (live-verified 2026-08-12), not yet built into a tagging module the way OWASP LLM Top 10 and MITRE ATLAS were |
| **OWASP Agentic AI Threats and Mitigations** (Feb 2025, OWASP Agentic Security Initiative) | A threat-model taxonomy across Agent Design / Agent Memory / Planning & Autonomy / Tool Use / Deployment & Operations | Researched, not yet built into a tagging module |

## 4. Industry taxonomies used as tagging dimensions (not "borrowed," but cited precisely)

| Taxonomy | Version verified | Used for |
|---|---|---|
| **OWASP Top 10 for LLM Applications** | 2025 edition (v2.0, published 2024-11-18) — verified live, NOT assumed from an older 2023 list whose numbering has since changed (e.g. Overreliance was folded into LLM09:2025 Misinformation) | `aginiti/graph/owasp_llm_taxonomy.py`, all 10 categories |
| **MITRE ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems) | v5.1.0 (November 2025) — only 5 technique IDs actually verified and used (`AML.T0051.000`/`.001`, `AML.T0054`, `AML.T0070`, `AML.T0086`); ATLAS has 84 techniques total as of this version, most NOT cross-referenced yet, stated as an honest gap | `aginiti/graph/mitre_atlas_refs.py` |

## 5. Research grounding for the planner and evidence model (no code, no data — pure design motivation)

| Source | Motivates |
|---|---|
| **Ng, Harada & Russell**, "Policy Invariance Under Reward Transformations: Theory and Application to Reward Shaping" (ICML 1999, pp. 278-287) | `potential_progress()`'s use of potential-based reward shaping — a shaping term guaranteed not to distort the optimal policy |
| **Wiewiora, Cottrell & Elkan**, "Principled Methods for Advising Reinforcement Learning Agents" (ICML 2003, pp. 792-799) | `chain_value()`'s design: this paper proves potential-based shaping with Φ is exactly equivalent to initializing the value function with Φ — the direct justification for using a VALUE-INFORMED Φ (a plant's discounted credit for its downstream trigger's real value) rather than a purely topological one |
| **Atsidakou, Katariya, Sanghavi, Kveton**, "Bayesian Fixed-Budget Best-Arm Identification" (arXiv:2211.08572) and "Prior-Dependent Allocations for Bayesian Fixed-Budget Best-Arm Identification in Structured Bandits" (arXiv:2402.05878, 2024) | Framing Aginiti's few-pulls, informative-prior planning problem as Bayesian fixed-budget best-arm identification (`aginiti/planner/bayesian_planner.py`) |
| **Chapelle & Li**, "An Empirical Evaluation of Thompson Sampling" (2011) | Standard baseline reference for the Bayesian planner variant |
| **Derczynski, Galinkin, Martin, Majumdar & Inie**, garak's own paper (arXiv:2406.11036) | `StaticPolicy` baseline's representativeness of systematic-probing tools as a class |
| **PyRIT's own paper** (arXiv:2410.02828) | Same, for composable multi-turn orchestration as a class |
| **Zhou et al.**, "AutoRedTeamer" (arXiv:2503.15754) | `MemoryGuidedPolicy` baseline's representativeness of attack-outcome-memory systems |
| **NetSafe** (Yu et al., 2025) and the broader agentic-security survey literature (arXiv:2510.06445) | Motivating context for DVAA's A2A layer and consensus/voting scenario as a genuinely new behavioral dimension (identity/coordination among nominally-independent agents) |
| BloodHound / attack-graph tooling lineage (Swiler & Phillips 1998, Sandia; Lippmann & Ingols 2005, MIT Lincoln Lab) | `path_progress`/`target_graph.py`'s BFS-over-a-graph design, built from live evidence rather than bulk-collected data |

---

## 6. What this pass checked for gaps, and found

Beyond compiling what was already cited in-code, this document's
preparation (2026-08-12) specifically searched for:

- **The newest agentic-AI-specific taxonomies** — found and added above
  (OWASP Top 10 for Agentic Applications 2026, OWASP Agentic AI Threats
  Feb 2025) as researched-but-not-yet-tagged gaps, not silently omitted.
- **Whether the two reward-shaping citations underlying `chain_value`/
  `potential_progress` are real, correctly titled papers** — both
  independently verified via live search (§5 above), not merely trusted
  from the original docstring.
- **Whether EchoLeak/CVE-2025-32711 is a real, correctly described
  vulnerability** — independently verified via multiple 2025
  security-vendor sources.
- **Whether garak and PyRIT's licenses are what the code claims** — both
  independently re-verified (Apache 2.0 and MIT respectively) directly
  against their GitHub `LICENSE` files.

No additional undisclosed code reuse was found. The one place Aginiti's
own source code was directly adapted from an external open-source
project (`aginiti/static_analysis/prompt_defense.py`, from Cisco's
`mcp-scanner`, Apache 2.0) was already correctly attributed with license
terms preserved before this review — confirmed, not newly discovered.
