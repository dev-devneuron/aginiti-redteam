"""
Offline unit tests for benchmarks/scaled_evals/agents/hardened_agent/.

No ChromaDB, no LLM calls, no live agent — pure logic tests for chunking,
redaction, the rate limiter, and persona resolution, same convention as
tests/unit/test_endpoint.py. HardenedAgent itself (which needs a live ChromaDB
collection) is intentionally not instantiated here.
"""
from unittest.mock import patch

import pytest

from benchmarks.scaled_evals.agents.hardened_agent.agent import (
    ConversationMemory,
    HardenedAgent,
    RateLimiter,
    chunk_text,
    redact,
)
from benchmarks.scaled_evals.agents.hardened_agent.personas import (
    PERSONAS,
    chroma_filter_for,
    resolve_persona,
)


class TestChunkText:
    def test_short_text_returns_single_chunk(self):
        text = "just a few words here"
        assert chunk_text(text, chunk_size=200, overlap=40) == [text]

    def test_long_text_splits_into_multiple_chunks(self):
        text = " ".join(f"word{i}" for i in range(500))
        chunks = chunk_text(text, chunk_size=200, overlap=40)
        assert len(chunks) > 1

    def test_chunks_overlap_by_the_configured_amount(self):
        words = [f"word{i}" for i in range(500)]
        text = " ".join(words)
        chunks = chunk_text(text, chunk_size=200, overlap=40)

        first_chunk_words = chunks[0].split()
        second_chunk_words = chunks[1].split()
        # last 40 words of chunk 1 == first 40 words of chunk 2
        assert first_chunk_words[-40:] == second_chunk_words[:40]

    def test_all_words_are_covered_no_gaps(self):
        words = [f"word{i}" for i in range(500)]
        text = " ".join(words)
        chunks = chunk_text(text, chunk_size=200, overlap=40)
        covered = set()
        for chunk in chunks:
            covered.update(chunk.split())
        assert covered == set(words)

    def test_exact_boundary_chunk_size_words_returns_single_chunk(self):
        text = " ".join(f"word{i}" for i in range(200))
        assert chunk_text(text, chunk_size=200, overlap=40) == [text]

    def test_empty_text(self):
        assert chunk_text("", chunk_size=200, overlap=40) == [""]


class TestRedact:
    def test_ssn_redacted(self):
        assert redact("SSN: 423-58-9167") == "SSN: [REDACTED-SSN]"

    def test_email_redacted(self):
        assert redact("Contact: jane.doe@example.com") == "Contact: [REDACTED-EMAIL]"

    def test_phone_redacted(self):
        assert "[REDACTED-PHONE]" in redact("Call 555-123-4567 for details")

    def test_credit_card_redacted(self):
        assert "[REDACTED-CARD]" in redact("Card number 4111 1111 1111 1111 was used")

    def test_non_pii_text_unchanged(self):
        text = "The contract was signed on October 1st by both parties."
        assert redact(text) == text

    def test_multiple_pii_types_in_one_response(self):
        text = "Email jane@example.com or call 555-123-4567. SSN 423-58-9167."
        result = redact(text)
        assert "[REDACTED-EMAIL]" in result
        assert "[REDACTED-PHONE]" in result
        assert "[REDACTED-SSN]" in result
        assert "jane@example.com" not in result
        assert "423-58-9167" not in result


class TestRateLimiter:
    def test_allows_requests_up_to_the_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        assert limiter.check("legal") is True
        assert limiter.check("legal") is True
        assert limiter.check("legal") is True

    def test_blocks_once_limit_exceeded(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check("legal")
        assert limiter.check("legal") is False

    def test_personas_are_tracked_independently(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.check("legal")
        limiter.check("legal")
        assert limiter.check("legal") is False
        # a different persona has its own independent budget
        assert limiter.check("support") is True

    def test_window_slides_and_allows_again_after_expiry(self):
        limiter = RateLimiter(max_requests=1, window_seconds=10)
        with patch("time.monotonic", return_value=1000.0):
            assert limiter.check("legal") is True
            assert limiter.check("legal") is False
        with patch("time.monotonic", return_value=1011.0):  # past the 10s window
            assert limiter.check("legal") is True


class TestPersonas:
    def test_resolve_persona_matches_correct_key(self, monkeypatch):
        monkeypatch.setenv("HARDENED_AGENT_LEGAL_API_KEY", "legal-secret")
        monkeypatch.setenv("HARDENED_AGENT_SUPPORT_API_KEY", "support-secret")
        assert resolve_persona("legal-secret") == "legal"
        assert resolve_persona("support-secret") == "support"

    def test_resolve_persona_returns_none_for_unknown_key(self, monkeypatch):
        monkeypatch.setenv("HARDENED_AGENT_LEGAL_API_KEY", "legal-secret")
        assert resolve_persona("not-a-real-key") is None

    def test_resolve_persona_returns_none_for_empty_key(self):
        assert resolve_persona("") is None

    def test_resolve_persona_returns_none_when_no_keys_configured(self, monkeypatch):
        for persona in PERSONAS:
            monkeypatch.delenv(f"HARDENED_AGENT_{persona.upper()}_API_KEY", raising=False)
        assert resolve_persona("anything") is None

    def test_legal_and_support_filters_are_disjoint(self):
        legal_filter = chroma_filter_for("legal")
        support_filter = chroma_filter_for("support")
        # Different keys/values entirely -> a document matching one filter's
        # `source` value cannot also match the other's (see personas.py's
        # disjoint-boundary design, plans/vanilla-target-agent.md §2.4).
        assert legal_filter != support_filter
        assert legal_filter == {"source": "cuad"}
        assert support_filter == {"source": "cfpb"}

    def test_ops_filter_is_the_cross_domain_subset_flag(self):
        assert chroma_filter_for("ops") == {"ops_visible": True}

    def test_unknown_persona_raises_keyerror(self):
        with pytest.raises(KeyError):
            chroma_filter_for("not-a-persona")

    def test_unknown_persona_raises_keyerror_even_with_rbac_disabled(self, monkeypatch):
        # Auth/validation is independent of the RBAC ablation toggle -- an
        # unrecognized persona is a bug regardless of whether RBAC-the-filter
        # is on or off.
        import benchmarks.scaled_evals.agents.hardened_agent.personas as personas_mod
        monkeypatch.setattr(personas_mod, "RBAC_ENABLED", False)
        with pytest.raises(KeyError):
            chroma_filter_for("not-a-persona")

    def test_rbac_disabled_returns_no_filter_for_every_persona(self, monkeypatch):
        # Regression test for the RBAC on/off ablation toggle (added
        # 2026-08-07): with RBAC off, every persona gets an unfiltered
        # (None) ChromaDB `where` clause, simulating a RAG deployment where
        # access-control scoping was never wired into retrieval.
        import benchmarks.scaled_evals.agents.hardened_agent.personas as personas_mod
        monkeypatch.setattr(personas_mod, "RBAC_ENABLED", False)
        for persona in PERSONAS:
            assert chroma_filter_for(persona) is None

    def test_rbac_enabled_still_returns_persona_scoped_filters(self, monkeypatch):
        import benchmarks.scaled_evals.agents.hardened_agent.personas as personas_mod
        monkeypatch.setattr(personas_mod, "RBAC_ENABLED", True)
        assert chroma_filter_for("legal") == {"source": "cuad"}
        assert chroma_filter_for("support") == {"source": "cfpb"}
        assert chroma_filter_for("ops") == {"ops_visible": True}


class TestConversationMemory:
    def test_empty_history_for_unseen_persona(self):
        memory = ConversationMemory(max_turns=4)
        assert memory.get("legal") == []

    def test_append_and_retrieve(self):
        memory = ConversationMemory(max_turns=4)
        memory.append("legal", "What is clause 5?", "Clause 5 covers termination.")
        assert memory.get("legal") == [("What is clause 5?", "Clause 5 covers termination.")]

    def test_sliding_window_drops_oldest_turns(self):
        memory = ConversationMemory(max_turns=2)
        memory.append("legal", "q1", "a1")
        memory.append("legal", "q2", "a2")
        memory.append("legal", "q3", "a3")
        assert memory.get("legal") == [("q2", "a2"), ("q3", "a3")]

    def test_personas_tracked_independently(self):
        memory = ConversationMemory(max_turns=4)
        memory.append("legal", "legal question", "legal answer")
        memory.append("support", "support question", "support answer")
        assert memory.get("legal") == [("legal question", "legal answer")]
        assert memory.get("support") == [("support question", "support answer")]

    def test_get_returns_a_copy_not_the_live_list(self):
        memory = ConversationMemory(max_turns=4)
        memory.append("legal", "q1", "a1")
        snapshot = memory.get("legal")
        snapshot.append(("tampered", "tampered"))
        assert memory.get("legal") == [("q1", "a1")]


class TestBuildMessages:
    """Exercises HardenedAgent._build_messages() without needing a real
    ChromaDB collection — constructed via __new__ to skip __init__ (which
    requires a live/seeded collection), then only the attributes
    _build_messages actually touches are set manually."""

    def _bare_agent(self) -> HardenedAgent:
        agent = object.__new__(HardenedAgent)
        agent.memory = ConversationMemory(max_turns=4)
        return agent

    def test_no_history_produces_system_plus_one_user_message(self, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", False
        )
        agent = self._bare_agent()
        messages = agent._build_messages("What happened?", "some context", "legal")
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1] == {"role": "user", "content": "Context:\nsome context\n\nQuestion: What happened?"}

    def test_memory_disabled_ignores_existing_history(self, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", False
        )
        agent = self._bare_agent()
        agent.memory.append("legal", "earlier question", "earlier answer")
        messages = agent._build_messages("new question", "ctx", "legal")
        # Only system + the new user turn -- no history injected.
        assert len(messages) == 2

    def test_memory_enabled_injects_prior_turns_in_order(self, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", True
        )
        agent = self._bare_agent()
        agent.memory.append("legal", "q1", "a1")
        agent.memory.append("legal", "q2", "a2")
        messages = agent._build_messages("q3", "ctx", "legal")
        # system, (user q1, assistant a1), (user q2, assistant a2), user q3
        assert len(messages) == 6
        assert messages[1] == {"role": "user", "content": "q1"}
        assert messages[2] == {"role": "assistant", "content": "a1"}
        assert messages[3] == {"role": "user", "content": "q2"}
        assert messages[4] == {"role": "assistant", "content": "a2"}

    def test_guardrail_enabled_appends_anti_leak_instruction_to_system_prompt(self, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.GUARDRAIL_ENABLED", True
        )
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", False
        )
        agent = self._bare_agent()
        messages = agent._build_messages("q", "ctx", "legal")
        # Base groundedness instruction stays present either way -- the
        # guardrail is an ADDITION, not a replacement.
        assert "Answer questions using only the provided" in messages[0]["content"]
        assert "personally identifiable information" in messages[0]["content"]

    def test_guardrail_disabled_leaves_only_the_base_groundedness_prompt(self, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.GUARDRAIL_ENABLED", False
        )
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", False
        )
        agent = self._bare_agent()
        messages = agent._build_messages("q", "ctx", "legal")
        assert "personally identifiable information" not in messages[0]["content"]

    def test_guardrail_and_memory_suffixes_can_both_be_present(self, monkeypatch):
        # Regression check for suffix-concatenation order -- both toggles on
        # at once shouldn't clobber or truncate each other's text.
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.GUARDRAIL_ENABLED", True
        )
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", True
        )
        agent = self._bare_agent()
        messages = agent._build_messages("q", "ctx", "legal")
        content = messages[0]["content"]
        assert "personally identifiable information" in content
        assert "recent conversation history" in content

    def test_memory_enabled_only_injects_the_calling_personas_history(self, monkeypatch):
        monkeypatch.setattr(
            "benchmarks.scaled_evals.agents.hardened_agent.agent.MEMORY_ENABLED", True
        )
        agent = self._bare_agent()
        agent.memory.append("support", "support-only question", "support-only answer")
        messages = agent._build_messages("legal question", "ctx", "legal")
        # legal has no history of its own -- support's history must not leak in.
        assert len(messages) == 2
