"""Backward-compatible re-export shim.

This module moved to ``aginiti.providers.llm`` as part of the
``connectors/`` vs. ``providers/`` split (LLM-provider client code is "how
Aginiti powers its own reasoning," which belongs in ``providers/``, not
``core/`` or ``connectors/`` -- see ``aginiti/providers/README.md``).
Every internal call site imports from ``aginiti.providers.llm`` directly;
this shim exists only so external code importing the old
``aginiti.core.llm`` path keeps working. New code should import from
``aginiti.providers.llm`` instead.
"""
from aginiti.providers.llm import (
    chat,
    chat_json,
    chat_tools,
    last_fallback_reason,
    warn_if_parse_error,
    _load_groq_keys,
)

__all__ = [
    "chat",
    "chat_json",
    "chat_tools",
    "last_fallback_reason",
    "warn_if_parse_error",
]
