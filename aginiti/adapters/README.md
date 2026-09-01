# aginiti/adapters — talking to a target framework

`BaseAdapter` (`base.py`) is the architectural boundary that makes Aginiti
framework-agnostic: the planner, the Security State Graph, and the
operator/graph-edge model never touch a target directly — they only ever
call `adapter.send(...)` and `adapter.ground_truth_mission_achieved()`.
Supporting a new framework or a new real target means writing a new
adapter (a class implementing `BaseAdapter`'s shape) plus an operator
library written against that target's actual vulnerabilities; nothing
about the planner changes.

| Adapter | Target |
|---|---|
| `http_agent_adapter.py` (`HTTPAgentAdapter`) | Wraps a shared `AgentEndpoint` (`aginiti/connectors/endpoint.py`) so the planner and a deep-attack `Operator` can reuse one HTTP session against any generic endpoint. |
| `anythingllm_adapter.py` | AnythingLLM (real, self-hosted RAG chatbot). |
| `hardened_agent_adapter.py`, `healthcare_agent_adapter.py` | This project's own hardened/healthcare benchmark fixtures (`benchmarks/scaled_evals/agents/`). |
| `dvaa_adapter.py`, `dvla_adapter.py` | Damn Vulnerable Agentic Application / Damn Vulnerable LangChain Agent benchmark targets. |
| `injecagent_adapter.py`, `injecagent_pool_adapter.py` | InjecAgent's indirect-injection test-case corpus (see `aginiti/operators/injecagent_data/NOTICE.md` for provenance), driven through Aginiti's own campaign loop rather than InjecAgent's own evaluation harness. |
| `mcp_stdio_adapter.py` | A real MCP (Model Context Protocol) stdio server. |
| `vendor/` | Vendored third-party target code a specific adapter drives against (currently: DVLA's real transaction DB, verbatim from its upstream repo). |
| `scaled_evals_ground_truth.py` | Shared ground-truth lookup helpers for the `benchmarks/scaled_evals/` adapters above. |

See `base.py`'s own docstring for the exact interface (`send`,
`ground_truth_mission_achieved`, `SendResult`) before writing a new one.
