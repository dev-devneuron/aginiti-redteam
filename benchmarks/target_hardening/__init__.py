"""Real, live hardening controls for the AnythingLLM benchmark target --
built at explicit user request, to prepare a
harder, more realistic enterprise-grade target for benchmarking.

This package implements the controls a real enterprise AI agent deployment
would have, at whichever layer can genuinely enforce each one:

  - System prompt hardening: already existed (experiments/
    exp17_hardened_target.py's HARDENED_PROMPT, pulled from a live
    "enterprise-hardened" AnythingLLM workspace).
  - URL allowlist / network egress restriction / tool argument validation
    for the agent's own outbound web-scraping tool: enforced SERVER-SIDE,
    directly in the live AnythingLLM collector service (patched, restarted,
    and live-verified -- see the collector's own urlPolicy.js).
    AnythingLLM had ZERO native restriction here before this patch --
    confirmed by reading web-scraping.js and the collector's pre-patch
    handlers directly.
  - Document trust labels / retrieval filtering, output filtering / secret
    redaction, tool-argument validation for upload-link, an approval gate,
    and least-privilege service-account tiers: enforced HERE, at a real
    reverse-proxy gateway (gateway_server.py) that sits in front of the
    live AnythingLLM server. This is the correct place for these controls
    architecturally -- exactly how such a gateway (a DLP/CASB-style proxy)
    is deployed in front of a real enterprise SaaS LLM app -- and the only
    place they CAN be genuinely enforced, since AnythingLLM's own
    API-key-based Developer API has no per-key RBAC (confirmed directly:
    server/utils/middleware/validApiKey.js only checks the key exists,
    never the calling user's role -- an honest, documented finding, not
    assumed).
  - Multi-user mode / RBAC (admin/manager/default): already enabled on the
    live instance (confirmed via GET /api/v1/system: MultiUserMode=true).
    Documented honestly as NOT enforced on the attack surface Aginiti
    actually calls (the same Developer-API RBAC gap above) -- included for
    realism/documentation completeness, not claimed as a functioning
    control on its own.
  - Sandboxing: AnythingLLM's agent tool surface is already inherently
    sandboxed -- confirmed via source: only rag-memory, document-
    summarizer, and web-scraping are ever attached (no shell/filesystem
    execution tool exists at all). The genuinely available lever is WHICH
    of these are enabled per workspace -- least-privilege tool selection,
    a real per-workspace configuration this package's gateway/workspace
    builder can exercise.

policy.py holds pure, dependency-free logic (independently unit-testable,
no Flask/network I/O). gateway_server.py wires it into a real Flask
reverse proxy. See docs/HARDENED_TARGET.md for the full inventory and
what's proposed but not (yet) built.

Moved here from aginiti/target_hardening/ as part of the open-source-
readiness directory reorg: this package hardens a benchmark TARGET
(AnythingLLM) against Aginiti's own attacks -- defensive fixture code for
the benchmarking harness, not an offensive red-team module, so it belongs
under benchmarks/ (not shipped in the published wheel at all) rather than
in the aginiti/ attack-library namespace. No backward-compatible shim was
left at the old aginiti/target_hardening/ path -- unlike the providers/
and reporting/ moves, nothing in this package was ever part of the
installable aginiti-redteam package's public surface (benchmarks/ is
excluded from the wheel by pyproject.toml's packages.find), so there is
no external caller for a shim to protect."""
