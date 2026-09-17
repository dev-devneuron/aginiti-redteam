"""
Unit tests for aginiti/providers/embedding.py -- specifically the local ONNX
embedding failure-handling fix. Patches the real chromadb module's own
``ONNXMiniLM_L6_V2`` construction/call directly, so this stays fast and
offline (no real ONNX model load/inference), matching the rest of this
project's test suite.

Previously (found during the v0.2.0 pip-install verification pass): a
native-binary failure inside chromadb's ONNX embedding function (the
documented real-world Windows failure mode -- a DLL load error, or an
older-CPU incompatibility) propagated as a raw, unhandled exception straight
out of ``embed_texts()``/every caller above it, with nothing pointing at the
one workaround that actually avoids the whole code path
(``embed_model="<cloud provider>/..."``).
"""
import pytest
from unittest.mock import patch, MagicMock

from aginiti.providers.embedding import embed_texts, _CHROMA_EF_CACHE


@pytest.fixture(autouse=True)
def _clear_chroma_ef_cache():
    # The embedding-function cache is module-level and keyed by model name --
    # clear it before and after every test so one test's mocked/broken
    # construction can never leak into another's.
    _CHROMA_EF_CACHE.clear()
    yield
    _CHROMA_EF_CACHE.clear()


class TestEmbedTextsChromadbHappyPath:
    def test_returns_native_python_floats_not_numpy(self):
        fake_instance = MagicMock(return_value=[[0.1, 0.2, 0.3]])
        with patch(
            "chromadb.utils.embedding_functions.ONNXMiniLM_L6_V2",
            return_value=fake_instance,
        ):
            vecs = embed_texts(["hello"], model="chromadb/all-MiniLM-L6-v2")
        assert vecs == [[0.1, 0.2, 0.3]]
        assert all(isinstance(x, float) for x in vecs[0])

    def test_empty_input_returns_empty_list_without_touching_chromadb(self):
        # Must short-circuit before even importing chromadb.
        assert embed_texts([]) == []


class TestEmbedTextsChromadbFailureHandling:
    def test_native_construction_failure_raises_friendly_runtime_error(self):
        # Simulates the real documented Windows failure mode: onnxruntime's
        # native loader fails (DLL load error) the moment ChromaDB tries to
        # construct its ONNX embedding function.
        dll_error = OSError(
            "DLL load failed while importing onnxruntime_pybind11_state: "
            "A dynamic link library (DLL) initialization routine failed."
        )
        with patch(
            "chromadb.utils.embedding_functions.ONNXMiniLM_L6_V2",
            side_effect=dll_error,
        ):
            with pytest.raises(RuntimeError) as exc_info:
                embed_texts(["hello"], model="chromadb/all-MiniLM-L6-v2")
        message = str(exc_info.value)
        # The original exception must not be swallowed -- present in the
        # message and chained via `from exc` (checked separately below).
        assert "DLL load failed" in message
        # The one thing that actually matters for a user hitting this: a
        # clear pointer to the workaround that avoids the whole path.
        assert "embed_model=" in message
        assert "gemini/" in message or "cloud" in message.lower()
        assert exc_info.value.__cause__ is dll_error

    def test_native_call_failure_raises_friendly_runtime_error(self):
        # Construction can succeed while the actual embedding call still
        # fails (a lazier-loading native failure) -- both paths must be
        # caught, not just construction.
        fake_instance = MagicMock(side_effect=RuntimeError("onnxruntime session run failed"))
        with patch(
            "chromadb.utils.embedding_functions.ONNXMiniLM_L6_V2",
            return_value=fake_instance,
        ):
            with pytest.raises(RuntimeError) as exc_info:
                embed_texts(["hello"], model="chromadb/all-MiniLM-L6-v2")
        assert "onnxruntime session run failed" in str(exc_info.value)
        assert "embed_model=" in str(exc_info.value)

    def test_chromadb_itself_missing_still_raises_plain_importerror(self):
        # Must not be swallowed into the new broader RuntimeError -- a
        # genuinely missing chromadb install keeps its own distinct,
        # existing error path (also verifies the `except ImportError: raise`
        # re-raise inside the new broader try/except is doing its job).
        import builtins
        real_import = builtins.__import__

        def blocking_import(name, *args, **kwargs):
            if name.startswith("chromadb"):
                raise ImportError("No module named 'chromadb'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=blocking_import):
            with pytest.raises(ImportError, match="chromadb is required"):
                embed_texts(["hello"], model="chromadb/all-MiniLM-L6-v2")
