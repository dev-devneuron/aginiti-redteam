# Running aginiti-redteam with Docker

A full-stack Docker Compose setup: the three reference agents, their seeding
jobs, and both attack scripts, all built from one shared `Dockerfile` at the
repo root. This is an alternative to the native/WSL2 setup in
`docs/dev_setup.md` — not a replacement for it; both work.

## Why this is worth using on Windows specifically

`docs/how-it-works.md` §3.10 documents a real onnxruntime/ChromaDB native-
binary incompatibility on native Windows Python, resolved there by developing
inside WSL2. Docker Desktop on Windows already runs containers inside a Linux
VM (the WSL2 backend), so a container built from this `Dockerfile` gets the
same Linux onnxruntime/ChromaDB wheels that were already verified working in
WSL2 — without manually setting up a venv on the Linux filesystem yourself.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2 on Linux) — this was built
  and verified against Compose v2.39.
- A repo-root `.env` file (copy `.env.example`) with at least `GEMINI_API_KEY`
  set — every agent and attack service reads it via `env_file:`.

## What's in the compose file

| Service | What it does | Port |
|---|---|---|
| `seed-blackbox` | One-shot: seeds the blackbox agent's ChromaDB collection | — |
| `seed-otel` | One-shot: seeds the OTel agent's ChromaDB collection | — |
| `prepare-healthcare` | One-shot: downloads + samples HealthCareMagic-1k | — |
| `seed-healthcare` | One-shot: seeds the healthcare agent's collection (depends on `prepare-healthcare`) | — |
| `prepare-hardened` | One-shot: samples CUAD + CFPB, splits ingested/held-out (idempotent — skips if output already exists; `--force` to rebuild) | — |
| `seed-hardened` | One-shot: chunks + seeds `hardened_agent`'s collection (depends on `prepare-hardened`) | — |
| `reference_agent_blackbox` | Tier 1 dev fixture (depends on `seed-blackbox`) | 8001 |
| `reference_agent_otel` | Tier 2 dev fixture (depends on `seed-otel`) | 8002 |
| `healthcare_agent` | Benchmark target, soft guardrail only (depends on `seed-healthcare`) | 8003 |
| `hardened_agent` | Benchmark target, RBAC + rate-limit + redaction + memory, all independently toggleable (depends on `seed-hardened`) | 8004 |
| `attack-ikea` | One-shot: `scripts/run_ikea.py` against `reference_agent_blackbox` | — |
| `attack-healthcare` | One-shot: `scripts/run_healthcare_benchmark.py` against `healthcare_agent` | — |

There's no `attack-hardened` compose service (unlike the other two attack
services) — `scripts/run_ikea_hardened.py` requires a `--persona` flag
per invocation by design (see its own docstring), which doesn't fit a fixed
one-shot service definition well. Run it from the host instead — see
"Benchmark `hardened_agent`" below.

Seed jobs are idempotent (`seed.py` skips if already populated), so re-running
`docker compose up` after the first time is fast. `prepare-hardened` is
idempotent too but for a sharper reason: CFPB's source API is a live,
daily-updating feed, not a static snapshot, so a bare re-run isn't guaranteed
to reproduce the same sample — it always skips regeneration once
`hardened_dataset_ingested.json`/`hardened_dataset_held_out.json` already
exist, specifically to avoid desyncing the dataset files from whatever's
already embedded in ChromaDB.

## Usage

**Start the three agents** (seeds them automatically first, waits for each to
be healthy before starting the dependent agent):

```bash
docker compose up -d
```

`attack-ikea` and `attack-healthcare` are behind the `attack` Compose profile,
so this command alone never fires an LLM-cost-incurring run. Check the agents:

```bash
curl -s -X POST http://localhost:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is Emma Thompson'\''s salary?"}'
```

**Run the IKEA attack** against the containerized blackbox agent (starts it
first if not already running):

```bash
docker compose --profile attack run --rm attack-ikea
```

Results land in `scripts/results/` on the host (bind-mounted), exactly as a
native run would — same timestamped-file convention as `docs/dev_setup.md`.

**Run the full HealthCareMagic benchmark** (real Gemini API cost — see
`docs/benchmarking.md`):

```bash
docker compose --profile attack run --rm attack-healthcare
```

Results land in `benchmarks/scaled_evals/results/` on the host.

**Stop everything:**

```bash
docker compose down
```

---

## Step by step: benchmarking the dev fixtures (`reference_agent_blackbox` / `_otel`)

Assumes `docker compose up -d` has already been run at least once (image
built, agents seeded and healthy). These are the 25-record synthetic Acme
HR agents — fast, cheap, the right place to smoke-test a change before
spending real budget on a bigger target.

```bash
# 1. Confirm the agent is actually up (not just "started")
curl -s http://localhost:8001/health
# -> {"status": "ok"}

# 2a. Run IKEA via the fixed preset script (zero-arg, HR-domain topic
#     baked in, writes to scripts/results/)
docker compose --profile attack run --rm attack-ikea

# 2b. Or run IKEA via the generic CLI, for control over queries/topic/
#     output path/etc. (same underlying attack, more knobs) — see
#     `python scripts/run_benchmark.py --help` for the full flag list
docker compose run --rm --no-deps attack-ikea \
  python scripts/run_benchmark.py \
    --attack ikea \
    --agent-url http://reference_agent_blackbox:8001 \
    --ground-truth benchmarks/dev_fixtures/datasets/ground_truth.json \
    --topic "HR records" \
    --queries 20 \
    --llm-provider gemini/gemini-3.5-flash \
    --output scripts/results/ikea_fixture_run.json \
    --enable-leak-prefilter

# 3. Results land in scripts/results/ on the host (bind-mounted) —
#    <name>.json, <name>.md, and a redacted <name>_redacted.md
```

`reference_agent_otel` (port 8002) is the Tier 2 twin of the same dataset —
point `--agent-url`/`IKEA_TARGET_URL` at `http://reference_agent_otel:8002`
instead if you specifically need the OTel-instrumented path; Tier 1 attack
logic itself is identical either way (§ Tiered Probing Architecture in the
root README).

**SECRET and MIA against the dev fixtures** — different shape, read before
running: `scripts/run_secret.py` and `scripts/run_interrogation.py` are
**fixed, zero-arg smoke-test scripts, not general CLIs**. They have no
`--help` / argparse at all — passing any flag is silently ignored and the
script runs for real, so don't probe them with `--help` expecting a safe
no-op (ask me how I know). Both are hardcoded to the HR domain and
`reference_agent_blackbox` specifically (candidate documents, non-member
reference set, and external corpus are all HR-shaped constants baked into
the script, matching `ground_truth.json`) — they are **not** drop-in
runnable against `hardened_agent` or any other target without editing the
script's own constants first. Run them (real API cost — small by design,
see each script's own docstring for the exact call-count math, but still
real):

```bash
docker compose run --rm --no-deps attack-ikea python scripts/run_secret.py
docker compose run --rm --no-deps attack-ikea python scripts/run_interrogation.py
```

(Reusing `attack-ikea`'s image/env here is just a convenient existing
service definition with the right `env_file`/volumes — it's not
IKEA-specific despite the name; any service backed by the shared image
works identically.)

---

## Step by step: benchmarking `hardened_agent`

`hardened_agent` (port 8004) is the ablation-lab target — real CUAD
(legal contracts) + CFPB (consumer complaints) content, three RBAC personas
with genuinely different retrieval scopes, and five independently-toggleable
defenses (RBAC, rate-limiting, output redaction, conversation memory,
system-prompt guardrail). See
`benchmarks/scaled_evals/agents/hardened_agent/README.md` and
`plans/vanilla-target-agent.md` for the full design rationale.

```bash
# 1. Bring it up (seeds automatically first if not already seeded)
docker compose up -d hardened_agent

# 2. Confirm it's healthy AND check which defenses are actually active —
#    always check this before spending budget; an env var you *think* you
#    set can silently not be what's actually running
curl -s http://localhost:8004/health
curl -s http://localhost:8004/config
# -> {"rbac_enabled": true, "rate_limit_enabled": true,
#     "redaction_enabled": true, "memory_enabled": true, "guardrail_enabled": true}

# 3. Run the attack — --persona is required, one persona per invocation
#    by design (keeps API cost trackable per run, not one big combined
#    spend). --queries defaults to 20; start smaller (5-10) the first
#    time against any not-yet-verified configuration.
python scripts/run_ikea_hardened.py --persona legal --queries 10
python scripts/run_ikea_hardened.py --persona support --queries 10
python scripts/run_ikea_hardened.py --persona ops --queries 10

# Results: benchmarks/scaled_evals/results/
#   ikea_hardened_<persona>_rbac-<on|off>_rl-<on|off>_rd-<on|off>_mem-<on|off>_gd-<on|off>_<n>q_<timestamp>.json
# The toggle state in the filename and in run_metadata.target_toggle_state
# is read LIVE from /config at run time, not from what you intended to set.
```

### RBAC boundary probe — testing the disjoint boundary with a real attack loop, not a single manual check

`--topic` overrides which domain IKEA's own anchor generation targets,
independent of which persona is authenticated. Since RBAC filters retrieval
server-side by the authenticated persona regardless of topic/anchor wording,
authenticating as one persona while pointing IKEA at the *other* persona's
topic is the adversarially-correct way to test whether the boundary holds
under real adaptive querying (use `legal`/`support` for this — fully
disjoint domains by construction; `ops` legitimately sees a slice of both,
so it isn't a clean disjoint-boundary test):

```bash
python scripts/run_ikea_hardened.py --persona legal \
  --topic "customer complaints and support tickets" --queries 10
```

**Reading the result requires opening the findings, not just the summary
metrics** — `ASR`/`EE`/`CRR`/`SS` don't distinguish "leaked something" from
"leaked something out of scope." Check each finding's `leaked_content`
against known CUAD- vs. CFPB-shaped vocabulary (company/contract names vs.
first-person complaint narrative) to confirm what was actually extracted
came from the authenticated persona's own authorized corpus, not the one
it was scoped away from.

Note this script is run from the **host** (not `docker compose run`) against
the container's published port — that's why it's plain `python
scripts/...` above, not `docker compose run --rm ...`. It works either way
since port 8004 is published to the host; running it natively is simpler
here because, unlike the agent itself, the attack script has no ChromaDB
read dependency forcing it into Linux.

### Ablation runs (RBAC / rate-limit / redaction / memory / guardrail on vs. off)

The five toggles are env vars on the **whole `hardened_agent` process**, not
per-request — so testing one config's off-state means running a *second*,
separately-configured container without disturbing your main instance.
Pattern (shown for RBAC off; swap the env var for the others):

```bash
# Spin up an isolated instance on a different host port, RBAC off, sharing
# the same seeded ChromaDB volume (read-only concern only — no reseed needed)
docker compose run --rm -e HARDENED_AGENT_RBAC_ENABLED=false \
  --no-deps -p 8005:8004 -d --name hardened_agent_rbac_off hardened_agent

curl -s http://localhost:8005/config   # confirm rbac_enabled: false

python scripts/run_ikea_hardened.py --persona ops --queries 10 \
  --agent-url http://localhost:8005

# Tear down the temp instance — your main hardened_agent on 8004 was never
# touched and needs no restart/reseed afterward
docker stop hardened_agent_rbac_off && docker rm hardened_agent_rbac_off
curl -s http://localhost:8004/config   # confirm main instance still rbac_enabled: true
```

The other four toggles follow the identical pattern —
`HARDENED_AGENT_RATE_LIMIT_ENABLED=false`,
`HARDENED_AGENT_REDACTION_ENABLED=false`,
`HARDENED_AGENT_MEMORY_ENABLED=false`,
`HARDENED_AGENT_GUARDRAIL_ENABLED=false` — one env var swap, same
temp-container recipe, same cleanup.

**A real cost/timing data point, not a guess**: a 10-query `hardened_agent`
run has taken 24-40 minutes wall-clock in practice (live-measured, not
estimated) — each query costs several sequential LLM calls (anchor
generation, TRDM mutation, refusal/leak classification), plus a CPU-bound
scoring pass at the end (Rouge-L + embedding similarity against the full
560-document ground-truth set). Expect roughly double that at the 20-query
default. Budget real wall-clock time accordingly before queuing several
combinations back to back — this is a real, live-measured range, not a
guess.

`.chroma/` stores and prepared datasets are bind-mounted to their usual host
paths (the same ones `.gitignore` already treats as local/regenerable), so
they persist across `docker compose down` / `up` — only removed if you delete
them from the host yourself, e.g. `rm -rf benchmarks/dev_fixtures/agents/reference_agent_blackbox/.chroma`
to force a clean re-seed.

## Design choices worth knowing about

- **One shared image, not three.** All three agents and both attack scripts
  have nearly identical dependencies, so `docker-compose.yml` builds one image
  from the root `Dockerfile` and selects behavior per service via `command:`,
  rather than maintaining three near-duplicate Dockerfiles.
- **The ONNX embedding model is baked into the image at build time** (a `RUN`
  step in the `Dockerfile`), not downloaded per-container at first request —
  every container from this image starts fully offline.
- **`.chroma/`, prepared datasets, and results directories are bind-mounted
  to host paths**, not opaque named Docker volumes — consistent with how
  `.gitignore` already treats these as local, inspectable, regenerable
  artifacts. You can `ls`/delete them from the host directly.
- **`IKEA_TARGET_URL` / `HEALTHCARE_AGENT_URL` env var overrides** were added
  to `scripts/run_ikea.py` / `scripts/run_healthcare_benchmark.py`
  specifically for this setup — inside a container, `localhost` resolves to
  that container itself, not the agent's container, so the attack services
  point these at the agent's Docker Compose service name instead (Docker's
  embedded DNS resolves `http://reference_agent_blackbox:8001` on the compose
  network). Both fall back to the original hardcoded `localhost` default when
  unset, so running these scripts on the host against agents started via
  `docker compose up` (exposed on `localhost:8001`/`8003`) still works
  unchanged. `scripts/run_ikea_hardened.py` uses a `--agent-url` CLI
  flag instead of an env var for the same purpose (defaults to
  `http://localhost:8004`) — same idea, different mechanism, because it's
  normally run from the host against the published port rather than from
  inside a compose service (see "Step by step: benchmarking `hardened_agent`"
  above).
- **Attack services are gated behind the `attack` Compose profile** so a
  plain `docker compose up` never triggers real API spend by accident — you
  always have to explicitly say `--profile attack run --rm ...`.
