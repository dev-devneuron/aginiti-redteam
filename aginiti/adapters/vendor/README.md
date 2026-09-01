# aginiti/adapters/vendor — vendored third-party target code

Real, vendored (not re-described) source from a third-party vulnerable
target, used as-is so Aginiti's ground-truth oracle can check attack
success against the actual implementation rather than a re-implementation
of it.

| File | Vendored from | Used by |
|---|---|---|
| `dvla_transaction_db.py` | [WithSecureLabs/damn-vulnerable-llm-agent](https://github.com/WithSecureLabs/damn-vulnerable-llm-agent) (Apache License 2.0) — verbatim except two deviations required by the modern LangChain rebuild (see the file's own header comment) | `aginiti/adapters/dvla_adapter.py` (DVLA — Damn Vulnerable LangChain Agent) |

See the file's own header for full attribution and the exact deviations
from the original.
