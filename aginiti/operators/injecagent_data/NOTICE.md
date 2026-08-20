# Provenance

These three files are vendored, unmodified, from:

**InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated
Large Language Model Agents** — Qiusi Zhan, Zhixiang Liang, Zifan Ying,
Daniel Kang (University of Illinois Urbana-Champaign), ACL Findings 2024.
Paper: https://arxiv.org/abs/2403.02691
Repository: https://github.com/uiuc-kang-lab/InjecAgent

Fetched 2026-08-07 directly from:
- `https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/user_cases.jsonl`
- `https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/attacker_cases_dh.jsonl`
- `https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/attacker_cases_ds.jsonl`

**License**: MIT (confirmed via the GitHub API's repository metadata at
fetch time, not inferred). MIT permits vendoring and adaptation with
attribution, which this file provides.

**What is NOT vendored**: InjecAgent's own evaluation harness
(`evaluate_prompted_agent.py`, `evaluate_finetuned_agent.py`,
`src/models.py`) — Aginiti drives these test cases through its own
adapter (`aginiti/adapters/injecagent_adapter.py`) and campaign loop
instead, per the project's own principle: adapt data/attack patterns into
Aginiti's architecture rather than running an external harness alongside
it. `attacker_cases_dh.jsonl` = "direct harm" attack intentions (30
cases), `attacker_cases_ds.jsonl` = "data stealing" attack intentions (32
cases), `user_cases.jsonl` = 17 legitimate user-tool scenarios whose tool
response is used as the injection vector. 17 x 62 = 1,054, matching the
paper's own reported test-case count exactly.

**`tools.json`** (added 2026-08-09): the real, vendored, unmodified tool
catalog, fetched directly from
`https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/tools.json`
-- 38 toolkits, 330 distinct tool operations with formal parameter
schemas. Added after discovering, by reading InjecAgent's own
`src/evaluate_prompted_agent.py` directly (not assumed), that the real
methodology offers the agent BOTH its own tool and the attacker's
declared target tool(s) (`available_tool_names = [item['User Tool']] +
item['Attacker Tools']`) -- `injecagent_adapter.py`'s own tool-schema
construction had only ever built a schema for the user's tool, which
structurally made 99.9% of the 1,054 test cases unwinnable regardless of
model compliance (confirmed live before fixing). This file supplies the
real parameter schemas needed to offer the attacker's tools too, matching
the real methodology.
