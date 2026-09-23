"""Tests for aginiti/demo_target/main.py's --port/--vanilla/--hardened
argument handling and the AGENT_HARDENED mode toggle."""
from __future__ import annotations
from unittest.mock import patch

import pytest

from aginiti.demo_target.main import _is_hardened, _parse_args, main


class TestParseArgs:
    def test_no_port_flag_leaves_port_none(self, monkeypatch):
        # None, not a hardcoded 8001 -- main() falls back to the AGENT_PORT
        # env var (then 8001) only when --port was genuinely omitted; this
        # keeps that fallback logic in main() itself, not duplicated here.
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target"])
        args = _parse_args()
        assert args.port is None

    def test_port_flag_is_parsed_as_int(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--port", "8010"])
        args = _parse_args()
        assert args.port == 8010

    def test_no_mode_flag_leaves_both_false(self, monkeypatch):
        # Neither flag forced -- main() leaves AGENT_HARDENED exactly as the
        # environment already has it in this case (see main()'s own
        # docstring), rather than this parser making that decision.
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target"])
        args = _parse_args()
        assert args.vanilla is False
        assert args.hardened is False

    def test_vanilla_flag_parsed(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--vanilla"])
        args = _parse_args()
        assert args.vanilla is True
        assert args.hardened is False

    def test_hardened_flag_parsed(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--hardened"])
        args = _parse_args()
        assert args.hardened is True
        assert args.vanilla is False

    def test_vanilla_and_hardened_together_is_rejected(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--vanilla", "--hardened"])
        with pytest.raises(SystemExit):
            _parse_args()

    def test_hardened_and_port_together(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--hardened", "--port", "8010"])
        args = _parse_args()
        assert args.hardened is True
        assert args.port == 8010


class TestIsHardened:
    def test_defaults_to_false_when_unset(self, monkeypatch):
        monkeypatch.delenv("AGENT_HARDENED", raising=False)
        assert _is_hardened() is False

    @pytest.mark.parametrize("falsy_value", ["false", "False", "0", "no", "NO"])
    def test_falsy_string_values_are_false(self, monkeypatch, falsy_value):
        monkeypatch.setenv("AGENT_HARDENED", falsy_value)
        assert _is_hardened() is False

    @pytest.mark.parametrize("truthy_value", ["true", "True", "1", "yes", "anything-else"])
    def test_other_string_values_are_true(self, monkeypatch, truthy_value):
        monkeypatch.setenv("AGENT_HARDENED", truthy_value)
        assert _is_hardened() is True


class TestMainModeWiring:
    """main() itself (seed()/uvicorn.run() mocked out -- no real server,
    no real ChromaDB seeding) -- verifies --hardened/--vanilla actually set
    AGENT_HARDENED before the server starts, and that omitting both leaves
    a pre-existing AGENT_HARDENED (e.g. set directly in a docker-compose
    environment, no CLI flag at all) untouched rather than silently
    overriding it."""

    def test_hardened_flag_sets_env_var(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--hardened"])
        monkeypatch.delenv("AGENT_HARDENED", raising=False)
        with patch("aginiti.demo_target.main.uvicorn.run"), \
             patch("aginiti.demo_target.seed.seed"):
            main()
        assert _is_hardened() is True

    def test_vanilla_flag_sets_env_var(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target", "--vanilla"])
        monkeypatch.setenv("AGENT_HARDENED", "true")  # prove --vanilla overrides it
        with patch("aginiti.demo_target.main.uvicorn.run"), \
             patch("aginiti.demo_target.seed.seed"):
            main()
        assert _is_hardened() is False

    def test_no_mode_flag_leaves_existing_env_var_untouched(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["aginiti-demo-target"])
        monkeypatch.setenv("AGENT_HARDENED", "true")  # e.g. set by docker-compose directly
        with patch("aginiti.demo_target.main.uvicorn.run"), \
             patch("aginiti.demo_target.seed.seed"):
            main()
        assert _is_hardened() is True
