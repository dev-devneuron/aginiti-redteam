"""Verifies the backward-compatible re-export shims left behind by the
connectors/ vs. providers/ split (aginiti/core/llm.py -> aginiti.providers.llm,
aginiti/connectors/embedding.py -> aginiti.providers.embedding) actually
re-export the same objects, not copies -- so monkeypatching or mocking the
canonical module is visible through the old import path too, and vice versa.
No live API calls."""
import aginiti.connectors.embedding as embedding_shim
import aginiti.core.llm as llm_shim
import aginiti.providers.embedding as embedding_provider
import aginiti.providers.llm as llm_provider


def test_core_llm_shim_reexports_same_objects():
    assert llm_shim.chat is llm_provider.chat
    assert llm_shim.chat_json is llm_provider.chat_json
    assert llm_shim.chat_tools is llm_provider.chat_tools
    assert llm_shim.last_fallback_reason is llm_provider.last_fallback_reason
    assert llm_shim.warn_if_parse_error is llm_provider.warn_if_parse_error


def test_core_llm_shim_reexports_load_groq_keys():
    # Used directly by aginiti/adapters/dvla_adapter.py via the old path --
    # not in __all__ (private-looking name), but must still resolve.
    assert llm_shim._load_groq_keys is llm_provider._load_groq_keys


def test_connectors_embedding_shim_reexports_same_object():
    assert embedding_shim.embed_texts is embedding_provider.embed_texts
