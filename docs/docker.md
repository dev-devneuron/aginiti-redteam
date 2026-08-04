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
| `reference_agent_blackbox` | Tier 1 agent (depends on `seed-blackbox`) | 8001 |
| `reference_agent_otel` | Tier 2 agent (depends on `seed-otel`) | 8002 |
| `healthcare_agent` | Benchmark target, soft guardrail (depends on `seed-healthcare`) | 8003 |
| `attack-ikea` | One-shot: `scripts/run_ikea.py` against `reference_agent_blackbox` | — |
| `attack-healthcare` | One-shot: `scripts/run_healthcare_benchmark.py` against `healthcare_agent` | — |

Seed jobs are idempotent (`seed.py` skips if already populated), so re-running
`docker compose up` after the first time is fast.

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
  unchanged.
- **Attack services are gated behind the `attack` Compose profile** so a
  plain `docker compose up` never triggers real API spend by accident — you
  always have to explicitly say `--profile attack run --rm ...`.
