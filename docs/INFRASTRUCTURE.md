# Aginiti — Where the Live Infrastructure Actually Lives

_Added 2026-08-12; not rewritten with the rest of `docs/` on 2026-08-13 —
content unchanged, still fully current. Quick reference for anyone (human
or a future Claude session) trying to run a live campaign against a real
target — the exact question that used to require reading old process
command lines to answer._

## Why this doc exists

Through 2026-08-12, every real target application Aginiti's live
experiments depend on — a live-running AnythingLLM instance, DVAA,
damn-vulnerable-llm-agent, and an MCP filesystem test server — lived inside
an **ephemeral Claude-session temp scratchpad**
(`C:\Users\Omer\AppData\Local\Temp\claude\E--GAIS\<session-id>\scratchpad\`)
rather than anywhere permanent. Two real problems followed directly from
that:

1. **C: drive was down to 10.9GB free** — a 2.3GB AnythingLLM install (with
   its full document/vector-store history from every benchmark run this
   project has ever done) plus DVAA (39MB), damn-vulnerable-llm-agent
   (480MB), the MCP filesystem server (19MB), and a partial Onyx
   investigation clone (84MB) were all sitting on the nearly-full drive.
2. **Nothing here was actually permanent.** A Claude session's own temp
   scratchpad has no durability guarantee — several `.py` files in this
   repo (`gateway_server.py`, `exp2_deterministic_vs_judge.py`,
   `exp11_live_anythingllm_planner_benchmark.py`,
   `exp17_hardened_target.py`) had hardcoded paths into *specific,
   already-dead* prior sessions' scratchpads, and the actual running
   AnythingLLM process turned out to be reading a `.env` whose own
   `STORAGE_DIR` pointed at one of those same ephemeral paths.

Everything below was moved onto `E:\Aginiti-Extended` itself — this
project's own permanent home — verified live after the move (server,
collector, gateway, and listener all restarted from the new location; the
full workspace/document history survived intact; the 837-test suite and a
2/2 live smoke test both passed against the relocated stack).

## Current locations

```
E:\Aginiti-Extended\
  targets\              Vendored, independently-developed target applications
                         (gitignored -- not part of this repo's own history)
    anythingllm\         The real AnythingLLM instance (server + collector).
                          server/.env & collector/.env's STORAGE_DIR now
                          point here, not the old C:\...\Temp\... path.
    dvaa\                damn-vulnerable-ai-agent (19-agent fleet + the
                          standalone consensus/voting scenario server).
    damn-vulnerable-llm-agent\   DVLA (LangChain create_agent pipeline).
    mcp-fs-test\         Official @modelcontextprotocol/server-filesystem
                          reference implementation, set up for stdio-
                          transport testing.
    onyx\                A full Onyx clone from the investigated-but-
                          rejected 5th-target candidacy (needs Docker for
                          Postgres/OpenSearch/Redis/MinIO, not pursued --
                          kept for reference, not actively used).

  infra\                 (gitignored) This project's own operational
                         scripts and logs -- NOT vendored third-party code.
    exfil_listener.py     The canonical exfiltration ground-truth listener
                          (port 8901) -- see its own docstring.
    logs\                 gateway_audit.log, server/collector restart logs,
                          listener logs.
    openwebui_venv\       A Python 3.11 venv from interrupted Open WebUI
                          infra prep (never completed).

  archive\                (gitignored) One-off diagnostic/debugging scripts
                         and dry-run artifacts from earlier sessions, kept
                         for historical reference, not actively maintained.
```

## Ports, and what's running where

| Port | Service | Started from |
|---|---|---|
| 3001 | AnythingLLM server | `targets\anythingllm\server` (`yarn dev`) |
| 8888 | AnythingLLM collector | `targets\anythingllm\collector` (`yarn dev`) |
| 3002 | Aginiti hardening gateway | `python -m aginiti.target_hardening.gateway_server`, run from `E:\Aginiti-Extended` |
| 8901 | Exfiltration ground-truth listener | `python infra\exfil_listener.py` |

Every live experiment (`experiments/exp1[1-9]*.py`, `exp20*.py`) that talks
to AnythingLLM does so **through the gateway** (`localhost:3002`,
gateway-issued keys — `gw-full-admin-key` / `gw-chatonly-employee-key`),
never AnythingLLM's own admin key directly, per `docs/HARDENED_TARGET.md`.

## Restarting after a reboot

```bash
# 1. AnythingLLM server
cd "E:\Aginiti-Extended\targets\anythingllm\server" && yarn dev

# 2. AnythingLLM collector
cd "E:\Aginiti-Extended\targets\anythingllm\collector" && yarn dev

# 3. Exfil listener
python "E:\Aginiti-Extended\infra\exfil_listener.py"

# 4. Gateway (run from the repo root so `aginiti` resolves as a package)
cd "E:\Aginiti-Extended" && python -m aginiti.target_hardening.gateway_server
```

Verify with:
```bash
curl http://localhost:3001/api/ping                                          # AnythingLLM
curl http://localhost:8888/                                                   # collector
curl -H "Authorization: Bearer gw-full-admin-key" http://localhost:3002/api/v1/workspaces   # gateway
curl http://localhost:8901/                                                   # listener
```

## Python environment — also now fully inside the project

Through 2026-08-12, every Python package Aginiti (and garak, its
benchmark-comparison tool) depends on was installed into the **global**
`C:\Python313` interpreter's site-packages, not anywhere project-scoped —
including garak's own ~800MB+ of ML dependencies (torch, transformers,
datasets, accelerate, litellm, ...), 100% specific to this project, sitting
on the same nearly-full C: drive.

A `.venv` already existed at `E:\Aginiti-Extended\.venv` (created early in
the project, mostly populated, just never actually adopted) — completed it
(added `flask`, `garak`) rather than rebuilding from scratch. Verified:
**837/837 tests pass using this venv, and noticeably faster than the global
interpreter (39s vs 90-110s)**, presumably less path-search overhead against
a smaller, project-scoped site-packages.

```bash
# Run anything (tests, scripts, experiments) using the project's own venv:
E:\Aginiti-Extended\.venv\Scripts\python.exe -m pytest -q
E:\Aginiti-Extended\.venv\Scripts\python.exe -m aginiti.target_hardening.gateway_server
E:\Aginiti-Extended\.venv\Scripts\python.exe -m garak --list_probes
```

`scripts/pre-commit` (and the installed `.git/hooks/pre-commit`) now prefer
this venv automatically, falling back to global `python` only if the venv
is missing.

**garak's own data directory** (run reports/hitlogs — real evidence from
the exp19 garak-vs-Aginiti comparison) moved from
`C:\Users\Omer\.local\share\garak\` to
`E:\Aginiti-Extended\infra\garak_data_root\garak\`, via the `XDG_DATA_HOME`
environment variable (set persistently at the Windows user level to
`E:\Aginiti-Extended\infra\garak_data_root` — garak resolves its data dir
as `$XDG_DATA_HOME/garak`, confirmed live). Any future garak run from this
machine writes here automatically, no per-run flag needed.

The exclusively-garak-specific packages (torch, transformers, datasets,
accelerate, litellm, nltk, sympy, cohere, anthropic, mistralai, replicate,
ollama, huggingface_hub, sentencepiece, tokenizers, avidtools, cmd2, wn,
deepl, langdetect, ftfy, and a few smaller ones — ~25 packages, unambiguous
by name, not plausibly shared with anything else on this machine) were
uninstalled from the global C: site-packages once confirmed working from
the venv. Common, potentially-shared packages (`requests`, `click`,
`jinja2`, `pandas`, `flask`, `openai`, `typer`, `boto3`, ...) were
deliberately **left alone globally** — removing those carries real risk of
breaking some other, unrelated tool on this machine that this project has
no visibility into. If you want those fully migrated too, that's a
judgment call for you to make explicitly, not something to do
unilaterally.

## What's still genuinely temporary

Nothing critical. The remaining Claude-session scratchpad content (this
session's own `__pycache__/`) is transient and regenerable — not "project
data" in any sense worth preserving.
