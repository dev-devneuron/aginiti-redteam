# Single shared image for the whole aginiti-redteam project: the three
# reference agents, seeding scripts, and attack scripts all run from this one
# image via different `command:` overrides in docker-compose.yml — they share
# nearly identical dependencies (chromadb, litellm, fastapi/uvicorn), so a
# separate Dockerfile per agent would just duplicate this file three times.
#
# Runs on Linux inside the container regardless of host OS (Docker Desktop on
# Windows/Mac already runs a Linux VM under the hood). This sidesteps the
# Windows-native-Python onnxruntime/chromadb binary issues documented in
# docs/how-it-works.md §3.10 entirely — no WSL2 setup needed to use this image.
FROM python:3.12-slim

# curl is only used by docker-compose.yml's HTTP healthchecks against each
# agent's GET /health endpoint.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what setuptools needs to resolve the editable install first, so
# this (slow) layer stays cached across changes to scripts/benchmarks/tests.
# pyproject.toml declares readme = "docs/dev_setup.md" and
# [tool.setuptools.packages.find] include = ["aginiti*"] — both must be
# present for `pip install -e` to succeed.
COPY pyproject.toml ./
COPY docs/dev_setup.md docs/dev_setup.md
COPY aginiti ./aginiti

# [benchmarks] extra (datasets + rouge-score) is included because the shared
# image also runs scripts/run_healthcare_benchmark.py, which needs both.
RUN pip install --no-cache-dir -e ".[benchmarks]"

# Now the rest of the source tree: benchmarks/ (agents + datasets), scripts/,
# tests/. Bind-mounted paths in docker-compose.yml (.chroma/, results/,
# prepared dataset JSON) overlay on top of whatever's copied here at runtime.
COPY . .

# Bake the ~90MB ONNX embedding model (chromadb/all-MiniLM-L6-v2) into this
# image at build time. Every agent + attack container derived from this one
# image already has it cached at /root/.cache/chroma/onnx_models/ — no
# runtime download, no first-request latency spike, works fully offline.
#
# Constructing ONNXMiniLM_L6_V2() alone does NOT trigger the download — its
# __init__ only imports onnxruntime/tokenizers/tqdm; the model is fetched
# lazily on first __call__ (verified against chromadb 1.5.9's actual source
# inside a built image: a bare `ONNXMiniLM_L6_V2()` RUN step here left
# ~/.cache/chroma completely empty). Must actually embed a string to force it.
RUN python -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ONNXMiniLM_L6_V2()(['warm up the onnx model cache'])"

ENV PYTHONUNBUFFERED=1

# No CMD/ENTRYPOINT — docker-compose.yml sets the command per service
# (uvicorn for agents, `python -m ...seed` for seeding, `python scripts/...`
# for attacks). Running this image directly with no command is a no-op.
