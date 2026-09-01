# benchmarks/target_hardening — hardened AnythingLLM benchmark fixture

Real, live hardening controls for the AnythingLLM benchmark target: a
reverse-proxy gateway (`gateway_server.py`) and its pure decision logic
(`policy.py`) that sit in front of a live AnythingLLM server, enforcing
document trust labels, retrieval filtering, output redaction, tool-argument
validation, an approval gate, and least-privilege service-account tiers —
the controls a real enterprise AI agent deployment would have at the layer
that can genuinely enforce each one. See `policy.py` and `gateway_server.py`'s
own module docstrings for the full per-control breakdown and rationale.

## Why this lives under `benchmarks/`, not `aginiti/`

This package hardens a benchmark **target** against Aginiti's own attacks —
defensive fixture code for the benchmarking harness, not an offensive
red-team module. `benchmarks/` is excluded from the published
`aginiti-redteam` wheel entirely (`pyproject.toml`'s `packages.find` only
includes `aginiti*`), so it was never part of the installable package's
public surface — moved here (from `aginiti/target_hardening/`) as part of
the open-source-readiness directory reorg, no backward-compatible shim
needed since there was no external caller to protect.

## Running it

```bash
python -m benchmarks.target_hardening.gateway_server
```

Reads `ANYTHINGLLM_BASE_URL`, `ANYTHINGLLM_ADMIN_KEY`, `GATEWAY_PORT` from
the environment. Requires `flask` — install via `requirements.txt` (the
full local dev environment file); not part of any `pip install
aginiti-redteam[...]` extra, since this fixture is dev/benchmark-only.
