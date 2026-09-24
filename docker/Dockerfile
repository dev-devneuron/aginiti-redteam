# A separate, minimal image from the repo-root Dockerfile on purpose: that
# one is the CONTRIBUTOR/benchmark image (editable install of this whole
# checkout, `[dev,benchmarks]` extras, the full reference-agent fleet). This
# one is the END-USER image -- installs the real, published PyPI package
# (`aginiti-redteam[demo-target]`), same as `pip install aginiti-redteam`
# would give anyone, so it genuinely represents "I don't want to set up
# Python/pip/a venv at all, I just want the CLI and a target to try it
# against." See docker/docker-compose.yml's own header for the two services
# built from this image (`demo-target`, `cli`).
#
# Runs on Linux inside the container regardless of host OS (Docker Desktop on
# Windows/Mac already runs a Linux VM under the hood) -- this is what
# sidesteps the Windows-native onnxruntime/chromadb DLL issues (see the
# README's Windows note) entirely, with zero WSL2 setup needed.
FROM python:3.12-slim

# curl is only used by docker-compose.yml's HTTP healthcheck against
# demo-target's GET /health endpoint.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# The real published package -- not `pip install -e .` against a copied-in
# source tree, unlike the repo-root Dockerfile. `[demo-target]` pulls in
# fastapi/uvicorn for the practice chatbot; the CLI itself
# (`aginiti scan`/`attack`/`report`) needs nothing beyond the core install.
RUN pip install --no-cache-dir "aginiti-redteam[demo-target]"

# Bake the ~90MB ONNX embedding model (chromadb/all-MiniLM-L6-v2) into this
# image at build time -- every container started from it already has it
# cached at /root/.cache/chroma/onnx_models/, so IKEA/SECRET's embedding-
# space work (and demo-target's own seeding) never pays a first-request
# download latency spike and this image works fully offline for that part.
# Constructing ONNXMiniLM_L6_V2() alone does NOT trigger the download -- the
# model is fetched lazily on first __call__ (same fact the repo-root
# Dockerfile's identical step already verified against chromadb 1.5.9's
# actual source) -- must actually embed a string to force it.
RUN python -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ONNXMiniLM_L6_V2()(['warm up the onnx model cache'])"

# Where docker-compose.yml bind-mounts the host's current directory for the
# `cli` service -- findings.json/the reports land here, so they land on the
# HOST filesystem too, not trapped inside an ephemeral container. Inert for
# the `demo-target` service, which never writes here.
WORKDIR /workspace

ENV PYTHONUNBUFFERED=1

# No CMD/ENTRYPOINT -- docker-compose.yml sets the command per service
# (`aginiti-demo-target` for the target agent; whatever `aginiti scan`/
# `attack`/`report` invocation the user passes to `docker compose run cli
# ...`). Running this image directly with no command is a no-op.
