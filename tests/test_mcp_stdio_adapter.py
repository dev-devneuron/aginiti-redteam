"""Tests for the pure, offline-testable pieces of McpStdioAdapter
(aginiti/adapters/mcp_stdio_adapter.py). The adapter's actual send()
requires a live subprocess + real MCP handshake -- that's proven by the
live run against the official filesystem server, not mocked here, same
as this project's other real-target adapters lean on live verification
for the network/protocol layer.
"""
import pytest
from mcp.types import TextContent

from aginiti.adapters.mcp_stdio_adapter import content_blocks_to_text, parse_channel


def test_parse_channel_accepts_matching_server():
    parse_channel("mcp:filesystem", expected_server="filesystem")  # must not raise


def test_parse_channel_rejects_wrong_protocol():
    with pytest.raises(ValueError, match="Unknown channel"):
        parse_channel("http:filesystem", expected_server="filesystem")


def test_parse_channel_rejects_wrong_server():
    with pytest.raises(ValueError, match="Unknown channel"):
        parse_channel("mcp:other-server", expected_server="filesystem")


def test_content_blocks_to_text_extracts_text_content():
    blocks = [TextContent(type="text", text="hello world")]
    result = content_blocks_to_text(blocks)
    assert "hello world" in result
    assert '"type": "text"' in result


def test_content_blocks_to_text_handles_multiple_blocks():
    blocks = [TextContent(type="text", text="first"), TextContent(type="text", text="second")]
    result = content_blocks_to_text(blocks)
    assert "first" in result and "second" in result
