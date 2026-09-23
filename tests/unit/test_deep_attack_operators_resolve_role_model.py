"""Unit tests for `_resolve_role_model` (aginiti/operators/deep_attack_
operators.py) -- the fix for a real, live-reported bug: `aginiti scan`
(the campaign engine's deep-attack Operators for SECRET's Phase 1
optimizer/evaluator and MIA's shadow LLM) previously hardcoded a bare
`os.environ.get(ENV_VAR, "groq/openai/gpt-oss-20b")` default and passed
it straight to `_key_for()`, which raises `ValueError` if `GROQ_API_KEY`
isn't set -- crashing the whole operator (and burning its allocated query
budget) for any user who configured a different provider (Gemini, OpenAI,
Anthropic, Mistral) instead of Groq, even though a perfectly usable key
was already available for the operator's own primary model.

These tests exercise `_resolve_role_model` directly, without the
`_key_for` mock every test in `tests/integration/test_deep_attack_
operators.py` applies (that mock would hide the exact bug this module
fixes, since it never lets `_key_for` raise)."""
import pytest

from aginiti.operators import deep_attack_operators as dao

_ALL_PROVIDER_KEYS = (
    "GROQ_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MISTRAL_API_KEY",
)


@pytest.fixture(autouse=True)
def clear_all_provider_keys(monkeypatch):
    for env_var in _ALL_PROVIDER_KEYS:
        monkeypatch.delenv(env_var, raising=False)


class TestResolveRoleModel:
    def test_explicit_env_var_override_is_honored_as_is(self, monkeypatch):
        monkeypatch.setenv("SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "gemini/gemini-3.5-flash")
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        model, key = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "gemini/gemini-3.5-flash"
        assert key == "fake-gemini-key"

    def test_explicit_env_var_override_still_raises_if_its_own_key_missing(self, monkeypatch):
        monkeypatch.setenv("SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "openai/gpt-4o-mini")
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")  # primary key present, but irrelevant

        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            dao._resolve_role_model(
                "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
                "gemini/gemini-3.5-flash",
            )

    def test_defaults_to_groq_when_groq_key_is_available(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")

        model, key = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "groq/openai/gpt-oss-20b"
        assert key == "fake-groq-key"

    def test_falls_back_to_primary_model_when_groq_key_absent(self, monkeypatch, caplog):
        """The exact regression test for the reported bug: a user with only
        GEMINI_API_KEY configured (no Groq key anywhere) must NOT see this
        operator crash -- it should transparently use the primary model
        instead, with a warning, not a raised ValueError."""
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        model, key = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "gemini/gemini-3.5-flash"
        assert key == "fake-gemini-key"

    def test_falls_back_to_any_non_groq_primary_provider(self, monkeypatch):
        """Same fallback, proven for a second, different provider -- not
        special-cased to Gemini alone."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-key")

        model, key = dao._resolve_role_model(
            "MIA_OPERATOR_SHADOW_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "anthropic/claude-3-5-haiku-latest",
        )

        assert model == "anthropic/claude-3-5-haiku-latest"
        assert key == "fake-anthropic-key"

    def test_raises_when_nothing_at_all_is_configured(self, monkeypatch):
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            dao._resolve_role_model(
                "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
                "gemini/gemini-3.5-flash",
            )


class TestBuildSecretAttackUsesFallback:
    def test_build_secret_attack_does_not_crash_without_a_groq_key(self, monkeypatch):
        """End-to-end regression test for the reported `aginiti scan` crash:
        `attack_factory raised ValueError: GROQ_API_KEY is not set in .env`.
        With only GEMINI_API_KEY configured, `_build_secret_attack` must
        successfully construct a SECRETAttack instead of raising."""
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        endpoint = dao.AgentEndpoint(base_url="http://localhost:8001")
        attack = dao._build_secret_attack(endpoint)

        assert attack._optimizer_llm_provider == "gemini/gemini-3.5-flash"
        assert attack._evaluator_llm_provider == "gemini/gemini-3.5-flash"

    def test_build_secret_attack_prefers_groq_when_available(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")

        endpoint = dao.AgentEndpoint(base_url="http://localhost:8001")
        attack = dao._build_secret_attack(endpoint)

        assert attack._optimizer_llm_provider == "groq/openai/gpt-oss-20b"
        assert attack._evaluator_llm_provider == "groq/openai/gpt-oss-20b"


class TestBuildInterrogationAttackUsesFallback:
    def test_build_interrogation_attack_does_not_crash_without_a_groq_key(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        endpoint = dao.AgentEndpoint(base_url="http://localhost:8001")
        attack = dao._build_interrogation_attack(endpoint)

        assert attack._shadow_llm_provider == "gemini/gemini-3.5-flash"
