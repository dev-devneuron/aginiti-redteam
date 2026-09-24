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
    # _resolve_role_model now imports aginiti.providers.llm's
    # _load_groq_keys, which walks GROQ_API_KEY_2, _3, ... with no fixed
    # upper bound -- the first import of that module in a test process also
    # runs its own module-level load_dotenv(), which (on a machine with a
    # real, populated .env, e.g. local dev) pulls real numbered keys into
    # os.environ. Clear a generous range so every test here sees exactly
    # the keys it sets, not whatever a developer's own .env contains.
    for i in range(2, 51):
        monkeypatch.delenv(f"GROQ_API_KEY_{i}", raising=False)


class TestResolveRoleModel:
    def test_explicit_env_var_override_is_honored_as_is(self, monkeypatch):
        monkeypatch.setenv("SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "gemini/gemini-3.5-flash")
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        model, key, keys = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "gemini/gemini-3.5-flash"
        assert key == "fake-gemini-key"
        assert keys is None

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

        model, key, keys = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "groq/openai/gpt-oss-20b"
        assert key == "fake-groq-key"
        assert keys == ["fake-groq-key"]

    def test_returns_the_full_groq_key_pool_when_multiple_keys_configured(self, monkeypatch):
        """The actual fix this module exists for: a single free-tier Groq
        key's TPM limit is easy to exhaust across Phase 1's optimizer +
        evaluator calls -- .env commonly has GROQ_API_KEY_2, _3, ... for
        exactly this reason. Every configured key must come back, not just
        the first."""
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key-1")
        monkeypatch.setenv("GROQ_API_KEY_2", "fake-groq-key-2")
        monkeypatch.setenv("GROQ_API_KEY_3", "fake-groq-key-3")

        model, key, keys = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "groq/openai/gpt-oss-20b"
        assert key == "fake-groq-key-1"
        assert keys == ["fake-groq-key-1", "fake-groq-key-2", "fake-groq-key-3"]

    def test_falls_back_to_primary_model_when_groq_key_absent(self, monkeypatch, caplog):
        """The exact regression test for the reported bug: a user with only
        GEMINI_API_KEY configured (no Groq key anywhere) must NOT see this
        operator crash -- it should transparently use the primary model
        instead, with a warning, not a raised ValueError."""
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        model, key, keys = dao._resolve_role_model(
            "SECRET_OPERATOR_OPTIMIZER_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "gemini/gemini-3.5-flash",
        )

        assert model == "gemini/gemini-3.5-flash"
        assert key == "fake-gemini-key"
        assert keys is None

    def test_falls_back_to_any_non_groq_primary_provider(self, monkeypatch):
        """Same fallback, proven for a second, different provider -- not
        special-cased to Gemini alone."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-key")

        model, key, keys = dao._resolve_role_model(
            "MIA_OPERATOR_SHADOW_LLM_PROVIDER", "groq/openai/gpt-oss-20b",
            "anthropic/claude-3-5-haiku-latest",
        )

        assert model == "anthropic/claude-3-5-haiku-latest"
        assert key == "fake-anthropic-key"
        assert keys is None

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
        attack = dao._build_secret_attack(endpoint, dao._load_secret_config())

        assert attack._optimizer_llm_provider == "gemini/gemini-3.5-flash"
        assert attack._evaluator_llm_provider == "gemini/gemini-3.5-flash"

    def test_build_secret_attack_prefers_groq_when_available(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")

        endpoint = dao.AgentEndpoint(base_url="http://localhost:8001")
        attack = dao._build_secret_attack(endpoint, dao._load_secret_config())

        assert attack._optimizer_llm_provider == "groq/openai/gpt-oss-20b"
        assert attack._evaluator_llm_provider == "groq/openai/gpt-oss-20b"

    def test_build_secret_attack_wires_the_full_groq_key_pool_through(self, monkeypatch):
        """Regression test for the rate-limit bug this fix closes: a single
        Groq key was being used for Phase 1 even when .env had several
        (GROQ_API_KEY_2, _3, ...) -- SECRETAttack must receive all of them,
        not just the first, and forward the same pool to the evaluator by
        default."""
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key-1")
        monkeypatch.setenv("GROQ_API_KEY_2", "fake-groq-key-2")

        endpoint = dao.AgentEndpoint(base_url="http://localhost:8001")
        attack = dao._build_secret_attack(endpoint, dao._load_secret_config())

        assert attack._optimizer_api_keys == ["fake-groq-key-1", "fake-groq-key-2"]
        assert attack._evaluator_api_keys == ["fake-groq-key-1", "fake-groq-key-2"]


class TestBuildInterrogationAttackUsesFallback:
    def test_build_interrogation_attack_does_not_crash_without_a_groq_key(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")

        endpoint = dao.AgentEndpoint(base_url="http://localhost:8001")
        attack = dao._build_interrogation_attack(endpoint, dao._load_mia_config())

        assert attack._shadow_llm_provider == "gemini/gemini-3.5-flash"


class TestConfigResolvedFreshNotFrozenAtImportTime:
    """Regression tests for a second, independently-confirmed bug (also
    reported live, as `aginiti scan --budget 20` running SECRET at a fixed
    max_queries=10 regardless of --budget): every `_IKEA_LLM_PROVIDER`-style
    value used to be a bare MODULE-LEVEL constant, computed exactly once,
    the first time `deep_attack_operators.py` was ever imported anywhere in
    the process -- which happens far earlier than any caller expects, via
    `aginiti/cli.py`'s own `_build_parser()` -> `campaign_builder.
    TIER_CHOICES` -> this module's top-level import chain, well before
    `argparse` even parses `--model`/any other flag. Setting an env var
    from Python AFTER that point (exactly what `_cmd_scan`'s `--model`
    handling does, and what a user's own `.env`/shell env var is doing by
    the time `aginiti scan` actually runs) used to have zero effect. These
    tests simulate exactly that: import the
    module first (as it always already is, in any real process), THEN set
    an env var, THEN call `deep_attack_operators()` -- proving the env var
    is genuinely honored, not frozen from whatever `os.environ` looked
    like at first import."""

    def test_max_queries_env_var_set_after_import_is_honored(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        # dao is already imported at module scope above, exactly like a
        # real process -- this monkeypatch happens strictly AFTER that.
        monkeypatch.setenv("SECRET_OPERATOR_MAX_QUERIES", "37")

        ops = dao.deep_attack_operators()
        secret_op = next(o for o in ops if o.id == "secret_jailbreak_exfiltration")

        assert secret_op.attack_kwargs["max_queries"] == 37

    def test_cost_prompts_declared_to_the_campaign_tracks_the_same_override(self, monkeypatch):
        """The campaign's own budget bookkeeping reads cost_prompts, not
        attack_kwargs -- both must agree, or the campaign would charge a
        different budget than the operator actually uses."""
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("SECRET_OPERATOR_MAX_QUERIES", "37")
        monkeypatch.setenv("SECRET_OPERATOR_PHASE1_N_ITER", "1")
        monkeypatch.setenv("SECRET_OPERATOR_PHASE1_N_CAND", "1")

        ops = dao.deep_attack_operators()
        secret_op = next(o for o in ops if o.id == "secret_jailbreak_exfiltration")

        assert secret_op.cost_prompts == 1 * 1 + 37

    def test_ikea_max_queries_env_var_set_after_import_is_honored(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("IKEA_OPERATOR_MAX_QUERIES", "42")

        ops = dao.deep_attack_operators()
        ikea_op = next(o for o in ops if o.id == "ikea_sensitive_data_exfiltration")

        assert ikea_op.attack_kwargs["max_queries"] == 42
        assert ikea_op.cost_prompts == 42

    def test_mia_probe_questions_env_var_set_after_import_is_honored(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-key")
        monkeypatch.setenv("MIA_OPERATOR_N_PROBE_QUESTIONS", "9")

        ops = dao.deep_attack_operators()
        mia_op = next(o for o in ops if o.id == "mia_membership_inference")

        # cost_prompts = len(fixture candidate docs) * n_probe_questions --
        # 3 fixture docs are baked into this module (see _MIA_CANDIDATE_DOCUMENTS).
        assert mia_op.cost_prompts == 3 * 9

    def test_model_env_var_set_after_import_reaches_the_attack_factory(self, monkeypatch):
        """The exact scenario `aginiti scan --model ...` relies on: cli.py
        sets IKEA_OPERATOR_LLM_PROVIDER via os.environ AFTER this module
        has already been imported (via _build_parser()'s own earlier
        TIER_CHOICES import) -- the bound attack_factory must still use the
        new value, not whatever was frozen at that earlier import."""
        monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-key")
        monkeypatch.setenv("IKEA_OPERATOR_LLM_PROVIDER", "openai/gpt-4o-mini")

        ops = dao.deep_attack_operators()
        ikea_op = next(o for o in ops if o.id == "ikea_sensitive_data_exfiltration")

        # attack_factory is a functools.partial with `config` pre-bound --
        # inspect its keywords directly rather than constructing the real
        # attack (which would need a working AgentEndpoint).
        assert ikea_op.attack_factory.keywords["config"].llm_provider == "openai/gpt-4o-mini"
