# aginiti/operators — planner-selectable Operators

An `Operator` is the planner-agnostic unit of adversarial action: a formal
precondition/effect specification plus the concrete prompt/action used to
attempt it — mostly-static and cheap, composed into a campaign by
`aginiti/core/planner/`, as distinct from `aginiti/attacks/` (deep,
paper-faithful, standalone attacks) and `aginiti/adaptive/` (stateful,
runtime search engines). See root `CLAUDE.md`'s "attacks/ vs. operators/
vs. adaptive/" section for the full three-way distinction.

## Schema (`base.py`) and container (`library.py`)

`base.py` defines the schema — `Operator`, `ClaimEffect`, `Precondition`,
`ClassPrecondition` — with a worked example in its module docstring; read
it before defining a new operator pack. `library.py` holds
`OperatorLibrary`, the queryable collection (`candidates()`,
`by_category()`), and re-exports the schema from `base.py` for backward
compatibility — most existing operator-definition files import both from
`library.py` in one statement, which still works unchanged.

## Deep-attack bridge

`deep_attack_operators.py` and `hardened_deep_attack_operators.py` wrap
`aginiti/attacks/`'s heavyweight attacks (IKEA, SECRET, Interrogation/MIA,
SPE-LLM) as `Operator(kind="deep_attack", ...)` instances, so the planner
can decide a full deep-attack pass is worth the budget instead of a human
always invoking it directly.

## Operator packs, by target/theme

| Files | Target / theme |
|---|---|
| `anythingllm_*.py` | AnythingLLM (real, self-hosted RAG chatbot) — base probes, automatic/markdown/multitool exfiltration chains. |
| `dvaa_*.py`, `dvla_definitions.py` | Damn Vulnerable Agentic Application / Damn Vulnerable LangChain Agent. |
| `hardened_agent_definitions.py`, `hardened_tool_probes.py` | This project's own hardened benchmark fixture (`benchmarks/scaled_evals/agents/hardened_agent/`). |
| `healthcare_agent_definitions.py` | The healthcare benchmark fixture (`benchmarks/scaled_evals/agents/healthcare_agent/`). |
| `injecagent.py`, `injecagent_pool.py` | InjecAgent's indirect-injection test-case corpus (`injecagent_data/` — vendored, see its `NOTICE.md`). |
| `mcp_filesystem_definitions.py` | A real MCP filesystem server target. |
| `data_exposure.py` | General data-exposure probes not tied to one specific target. |
| `access_control_layer_probe.py`, `session_isolation_probe.py` | RBAC/session-isolation probing, target-agnostic. |
| `ascii_art_evasion.py`, `encoding_variants.py`, `low_resource_language_evasion.py`, `output_filter_evasion.py`, `redaction_format_evasion.py` | Encoding/evasion technique families (see each module's own docstring for its specific research grounding). |
| `discovery_chain_definitions.py`, `graduated_difficulty_definitions.py`, `multi_family_definitions.py`, `family_coverage_scenario_definitions.py`, `technique_cluster_scenario_definitions.py` | Cross-cutting scenario packs built to exercise chain-discovery, difficulty-graduation, and coverage properties of the planner itself, not one target's vulnerabilities. |
| `agentic_primitives_definitions.py`, `hidden_state_definitions.py` | Agentic-primitive and hidden-state probing, target-agnostic. |
| `adaptive_followups.py` | Follow-up operators generated in response to what an adaptive search already learned. |
| `definitions.py` | `build_library()` — assembles the full default `OperatorLibrary` from the packs above. |

Each pack's own module docstring states its specific research grounding
and target — check there before assuming provenance from the filename
alone.
