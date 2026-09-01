"""Backward-compatible re-export shim.

This module moved to ``aginiti.providers.embedding`` as part of the
``connectors/`` vs. ``providers/`` split (embedding-provider client code
is "how Aginiti powers its own reasoning," which belongs in
``providers/`` -- ``connectors/`` stays scoped to talking to the target
under test; see ``aginiti/providers/README.md``). Every internal call
site imports from ``aginiti.providers.embedding`` directly; this shim
exists only so external code importing the old
``aginiti.connectors.embedding`` path keeps working. New code should
import from ``aginiti.providers.embedding`` instead.
"""
from aginiti.providers.embedding import embed_texts

__all__ = ["embed_texts"]
