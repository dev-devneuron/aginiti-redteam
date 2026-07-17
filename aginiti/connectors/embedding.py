"""
Provider-aware text embedding for the aginiti-redteam library.

Routing logic (by the model string's ``<provider>/`` prefix):
  - "chromadb/<model>"  → ChromaDB's built-in ONNX embedding function
                          (default: "chromadb/all-MiniLM-L6-v2")
  - "gemini/<model>"    → litellm.embedding (Gemini API)
  - "openai/<model>"    → litellm.embedding (OpenAI API)
  - "<any>/<model>"     → litellm.embedding (any litellm-supported provider)

The default embed model is "chromadb/all-MiniLM-L6-v2". This runs locally with
no API key, no PyTorch, using ChromaDB's bundled ONNX runtime. The model
(~90MB) downloads on first call and is cached at
``~/.cache/chroma/onnx_models/all-MiniLM-L6-v2/``. Subsequent calls are offline.

For cloud providers, pass ``api_key`` explicitly or set the provider's
environment variable (``GEMINI_API_KEY``, ``OPENAI_API_KEY``, etc.).

This module is the single embedding entry point for the whole library — both
IKEA's attacker-side similarity math and the reference agents' retrieval route
through here (agents use ChromaDB's embedding function directly at the
collection level, which uses the same ONNX model). Do not call
``litellm.embedding()`` or instantiate a ChromaDB embedding function directly
elsewhere — go through ``embed_texts`` so routing stays centralized.
"""
from __future__ import annotations

from typing import Optional

# Module-level cache for ChromaDB embedding functions — avoids reinstantiating
# (and re-loading the ONNX model into memory) on every embed_texts() call
# within the same process.
_CHROMA_EF_CACHE: dict[str, object] = {}


def embed_texts(
    texts: list[str],
    model: str = "chromadb/all-MiniLM-L6-v2",
    api_key: Optional[str] = None,
) -> list[list[float]]:
    """
    Embed a list of texts using the specified model.

    Args:
        texts:   Strings to embed. Returns ``[]`` immediately for empty input.
        model:   Model string in ``"<provider>/<model_name>"`` format.
                 Default: ``"chromadb/all-MiniLM-L6-v2"`` (local ONNX, no key).
        api_key: Required for cloud providers (Gemini, OpenAI, etc.).
                 Ignored for ``"chromadb/"`` models.

    Returns:
        List of float vectors, one per input text, preserving input order.
    """
    if not texts:
        return []

    provider, model_name = _parse_model(model)

    if provider == "chromadb":
        return _embed_chromadb(texts, model_name)

    return _embed_litellm(texts, model, api_key)


def _parse_model(model: str) -> tuple[str, str]:
    """Split ``'provider/model_name'`` into ``(provider, model_name)``."""
    if "/" not in model:
        # Bare model name with no provider prefix — treat as chromadb default.
        return "chromadb", model
    provider, model_name = model.split("/", 1)
    return provider.lower(), model_name


def _embed_chromadb(texts: list[str], model_name: str) -> list[list[float]]:
    """
    Embed using ChromaDB's built-in ONNX embedding function.

    No API key required. Uses onnxruntime (ships transitively with chromadb).
    The model is downloaded once and cached locally by chromadb.

    Model support:
      - ``all-MiniLM-L6-v2`` (default, ~90MB, ONNX-backed via
        ``ONNXMiniLM_L6_V2`` — no PyTorch).
      - Any other name routes through ChromaDB's
        ``SentenceTransformerEmbeddingFunction``, which requires
        ``sentence-transformers`` (NOT a dependency of this project — install it
        yourself if you want e.g. ``all-mpnet-base-v2`` for paper-faithful
        geometry). Documented as opt-in, not a default.

    Raises:
        ImportError: If chromadb is not installed.
    """
    try:
        import chromadb.utils.embedding_functions as ef
    except ImportError as exc:
        raise ImportError(
            "chromadb is required for local ONNX embeddings.\n"
            "Install with: pip install chromadb"
        ) from exc

    if model_name not in _CHROMA_EF_CACHE:
        if model_name == "all-MiniLM-L6-v2":
            # ONNX-backed built-in — the zero-PyTorch default path.
            _CHROMA_EF_CACHE[model_name] = ef.ONNXMiniLM_L6_V2()
        else:
            # Any other model needs sentence-transformers (not bundled). This
            # raises a clear ImportError from ChromaDB if it isn't installed.
            _CHROMA_EF_CACHE[model_name] = ef.SentenceTransformerEmbeddingFunction(
                model_name=model_name
            )
    embedding_fn = _CHROMA_EF_CACHE[model_name]
    # float(x), not list(vec): ChromaDB's embedding function returns numpy
    # arrays, and list(numpy_array) yields numpy.float32 scalars rather than
    # native Python floats. That numpy.float32 silently propagates through
    # every _cosine() computation downstream (LeakFinding.confidence included)
    # and breaks json.dump with "Object of type float32 is not JSON serializable".
    return [[float(x) for x in vec] for vec in embedding_fn(texts)]


def _embed_litellm(
    texts: list[str],
    model: str,
    api_key: Optional[str],
) -> list[list[float]]:
    """
    Embed using litellm — covers Gemini, OpenAI, Mistral, Cohere, etc.

    Args:
        texts:   Strings to embed.
        model:   Full litellm model string, e.g. ``"gemini/gemini-embedding-001"``.
        api_key: Provider API key. If ``None``, litellm reads it from the
                 environment.
    """
    try:
        import litellm
    except ImportError as exc:
        raise ImportError(
            "litellm is required for cloud provider embeddings.\n"
            "Install with: pip install litellm"
        ) from exc
    resp = litellm.embedding(model=model, input=texts, api_key=api_key)
    return [item["embedding"] for item in resp.data]
