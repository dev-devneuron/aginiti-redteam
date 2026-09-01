# aginiti/static_analysis — zero-LLM-cost static checks

| Module | What it does |
|---|---|
| `prompt_defense.py` | Deterministic, zero-LLM-cost analysis: does a target's own system prompt / tool description contain defensive language against 12 common attack-vector categories? The 12 `DEFENSE_RULES` and scanning algorithm are adapted (not merely inspired by) Cisco's open-source [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) project (Apache License 2.0) — only the rule data and scoring logic are reused, not their analyzer class hierarchy. See the module's own docstring for the full attribution and what was deliberately NOT adopted from the same source (their YARA-based checks — different runtime dependency, different threat class). |
