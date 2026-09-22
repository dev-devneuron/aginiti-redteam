"""Tests for aginiti/demo_target/main.py's --port argument handling."""
from __future__ import annotations

from aginiti.demo_target.main import _parse_args


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
