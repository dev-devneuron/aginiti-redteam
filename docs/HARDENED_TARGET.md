# Hardened enterprise target (built 2026-08-09, NOT yet used in an experiment)

Built at explicit user request, in response to: "add all hardening dimensions
a real enterprise agent could have that'll be the target for next exp but
don't run the next exp yet." Every control below is real, live-implemented,
and individually verified against the actual running target — nothing here
is simulated or asserted without a direct test. **No experiment has been run
against this target yet.** Aginiti's own planner/policy/operator/weight/
prompt code was not touched by any of this work (freeze still in effect).

## Inventory: the user's requested dimensions, and where each landed

| Dimension | Status | Where it's enforced |
|---|---|---|
| Strong system instructions | Already existed | `experiments/exp17_hardened_target.py`'s `HARDENED_PROMPT`, pulled from a live workspace |
| Indirect/RAG-based injection resistance | **Built + live-verified** | Document trust labeling / retrieval filtering, gateway layer |
| Multiple tools | Already existed | AnythingLLM automatic mode: rag-memory, document-summarizer, web-scraping |
| Realistic trust boundaries | **Built + live-verified** | Least-privilege service-account tiers, gateway layer |
| Multi-step attacks | Already existed | 3 plant→trigger chains, exp17 |
| URL allowlists | **Built + live-verified**, two layers | Collector service (agent's own tool calls) + gateway (upload-link) |
| Network egress restrictions | **Built + live-verified** | Same as above — private/loopback + non-allowlisted hosts blocked |
| Human approval | **Built + live-verified** | Gateway hard-denies admin/user-management actions (honestly modeled: no human present to approve → deny, not silent allow) |
| Sandboxing | Already true, documented | AnythingLLM's agent tool surface has no shell/filesystem-execution plugin at all (confirmed via source) — the real lever is tool selection, not a fabricated sandbox |
| Retrieval filtering | **Built + live-verified** | Gateway: `policy.scan_and_sanitize_document` |
| Document trust labels | **Built + live-verified** | Same — flagged uploads get an explicit untrusted-content header |
| Tool argument validation | **Built + live-verified** | URL allowlist check on both the collector and the gateway's upload-link route |
| Output filtering | **Built + live-verified** | Gateway: `policy.scan_and_redact_output` on every chat response |
| Secret redaction | **Built + live-verified** | Same — realistic vendor-key-shaped patterns, not Aginiti's own canary format |
| Authentication | Already existed | AnythingLLM `MultiUserMode=true` confirmed live |
| Separate service accounts | **Built + live-verified**, with an honest caveat | Gateway-issued keys (`chat_only` / `full`) — see limitation below |
| Least-privilege tools | **Built + live-verified** | Gateway tier capabilities; AnythingLLM's own per-workspace tool selection is also available and untouched |

## Architecture

Three real, independently-running services, none of which required any change to Aginiti's own planner/policy/operator code — only a new adapter `base_url`/`api_key` for the next experiment to point at:

```
Aginiti's adapter (unchanged)
        │  Authorization: Bearer <gateway-issued key>
        ▼
Gateway  (localhost:3002, NEW — aginiti/target_hardening/gateway_server.py)
   • service-account tier check (chat_only vs full) on every request
   • human-approval hard-deny on admin/user-management paths
   • document upload → sanitized before forwarding
   • document upload-link → URL-allowlist checked before forwarding
   • chat response → secret-redacted before returning; raw text + a
     would_have_leaked flag written to a gateway-only audit log
        │  Authorization: Bearer <real admin key, held only by the gateway>
        ▼
AnythingLLM main server (localhost:3001, untouched)
        │  agent's own outbound tool calls (web-scraping)
        ▼
Collector service (localhost:8888, PATCHED — collector/urlPolicy.js)
   • same URL-allowlist / private-IP block, enforced on the ONE outbound
     path the gateway can't see (the agent's own internal tool call)
```

## Honest limitation found and documented, not hidden

AnythingLLM's own Developer API (`/api/v1/...`) has **no per-key RBAC** —
confirmed by reading `server/utils/middleware/validApiKey.js` directly: it
checks only that a key exists, never which user or role it belongs to.
`MultiUserMode` and the Admin/Manager/Default roles are real and enabled,
but they don't gate the exact attack surface Aginiti calls. This is why
"separate service accounts" and "least-privilege" are enforced at the
**gateway** (which I control) rather than claimed as an AnythingLLM-native
property (which would have been a false claim). If the next experiment's
threat model specifically wants to test whether Aginiti can escalate from a
genuinely restricted native session (not just a gateway-modeled one), that
would need real per-user JWT-session auth instead of the Developer API —
flagged here as a real gap, not silently worked around.

## What was deliberately NOT built (proposed, not implemented)

- **Deeper sandboxing** (e.g. a genuinely separate execution context per
  tool call) — not applicable today since no tool in AnythingLLM's agent
  surface executes code at all; would only matter if a code-execution
  plugin were ever added.
- **A real human-in-the-loop approval queue** (vs. the current hard-deny
  simulation) — building an actual approve/deny UI a human would click was
  out of scope for a benchmark target; the hard-deny is the honest
  automated-context equivalent.
- **Real per-user JWT-session auth** replacing the gateway-modeled tiers —
  see the limitation above.

## Verification performed (all live, against the real running target)

- Collector URL policy: direct `CollectorApi.getLinkContent()` call blocked
  `127.0.0.1:8901` (the exfil listener) with the exact policy reason, and
  succeeded against `en.wikipedia.org`. Also verified through a real
  automatic-mode chat turn.
- Gateway: `chat_only` key denied on `/document/upload` and `/admin/*` (403),
  `full` key allowed on both but *also* denied on `/admin/users/new`
  specifically by the approval gate. Document upload containing the exact
  injection sentence from `anythingllm_definitions.py`'s own plant content
  was sanitized before forwarding (confirmed via the gateway's audit log).
  `upload-link` to the exfil listener blocked; to Wikipedia succeeded. A
  fake `sk-`-shaped key in a chat response was redacted in the returned
  text while the raw text was preserved in the gateway's own audit log.
- 21 new unit tests (`tests/test_target_hardening_policy.py`), all passing,
  covering every policy function in isolation. Full suite: 582/582 real
  tests pass (6 unrelated pre-existing `google-genai` import failures in
  this environment).
- Full infrastructure health confirmed after all changes: main AnythingLLM
  server untouched and healthy, collector restarted cleanly (main server's
  workspace/chat state was never touched), gateway healthy, exfil listener
  healthy.

## For the next experiment

Point the adapter's `base_url` at `http://localhost:3002` and `api_key` at
`gw-full-admin-key` (or `gw-chatonly-employee-key` for a deliberately
restricted-privilege condition) instead of AnythingLLM directly — no other
adapter or operator code changes needed. **Not done yet, per instruction.**
