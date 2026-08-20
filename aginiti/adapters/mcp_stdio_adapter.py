"""BaseAdapter implementation for real, stdio-transport MCP servers -- a
genuinely new adapter-contract shape. DVLA is one HTTP agent; DVAA's MCP
servers are simplified JSON-RPC over plain HTTP with no handshake. A real
MCP server (the official reference implementations at
github.com/modelcontextprotocol/servers) is spawned as a subprocess and
speaks stdio, with a real `initialize`/capability-negotiation handshake
before any tool call is valid.

Verified live against the official filesystem server
(@modelcontextprotocol/server-filesystem) before writing any operators
against it: a `../` traversal and a direct absolute path outside the
declared allowed root were BOTH correctly rejected ("Access denied - path
outside allowed directories"). That's a genuinely different, STRONGER
security posture than DVAA's ToolBot, which had zero path validation --
exactly the kind of finding a real target can produce that a simulated
one can't: not "found a vulnerability" but "confirmed a real defense
actually holds," which is just as informative.

`channel` is "mcp:<server_name>" (currently only "mcp:filesystem" is
wired up, but the shape generalizes to other stdio MCP servers).
`prompt` is the same JSON-payload convention DVAAAdapter already uses:
'{"tool": name, "arguments": {...}}', with "tool": "__list__" for
tools/list.

Bridges Aginiti's SYNCHRONOUS BaseAdapter.send() to the mcp Python SDK's
async client by running one persistent asyncio event loop in a background
thread for the adapter's whole lifetime: the subprocess and MCP session
are opened ONCE (matching every other adapter's one-persistent-connection
pattern), not respawned per probe. This is the one piece of real
complexity this adapter needed to earn -- a real MCP server genuinely
requires an async client and a stateful handshake; DVAA's plain HTTP
calls never did.
"""
from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import Future

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aginiti.adapters.base import SendResult

_LIST_TOOLS_SENTINEL = "__list__"
_CONNECT_TIMEOUT = 15.0
_CALL_TIMEOUT = 30.0


def parse_channel(channel: str, expected_server: str) -> None:
    """Pulled out as a pure function so channel validation is testable
    without a live subprocess/session -- the rest of send() genuinely
    needs the async connection and is proven by the live run instead."""
    protocol, _, server = channel.partition(":")
    if protocol != "mcp" or server != expected_server:
        raise ValueError(f"Unknown channel '{channel}' for adapter bound to server '{expected_server}'")


def content_blocks_to_text(content_blocks) -> str:
    return json.dumps([{"type": c.type, "text": getattr(c, "text", None)} for c in content_blocks])


class McpStdioAdapter:
    def __init__(self, server_name: str, command: str, args: list[str], secret_marker: str | None = None):
        self.server_name = server_name
        self.secret_marker = secret_marker
        self._raw_responses: list[str] = []
        self._session: ClientSession | None = None

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        self._closed_event: asyncio.Event | None = None
        ready: Future = Future()
        asyncio.run_coroutine_threadsafe(self._session_manager(command, args, ready), self._loop)
        ready.result(timeout=_CONNECT_TIMEOUT)  # blocks until initialize() completes or raises

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    async def _session_manager(self, command: str, args: list[str], ready: Future) -> None:
        """Keeps the stdio subprocess and ClientSession open for the
        adapter's whole life -- the `async with` blocks stay entered until
        `close()` signals `_closed_event`, not per-call."""
        self._closed_event = asyncio.Event()
        try:
            params = StdioServerParameters(command=command, args=args)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    ready.set_result(True)
                    await self._closed_event.wait()
        except Exception as e:
            if not ready.done():
                ready.set_exception(e)

    def send(self, channel: str, prompt: str) -> SendResult:
        parse_channel(channel, self.server_name)

        payload = json.loads(prompt)
        tool_name = payload.get("tool")
        if tool_name == _LIST_TOOLS_SENTINEL:
            future = asyncio.run_coroutine_threadsafe(self._session.list_tools(), self._loop)
            tools = future.result(timeout=_CALL_TIMEOUT).tools
            final_text = json.dumps([{"name": t.name, "description": t.description} for t in tools])
            tool_trace: list[dict] = []
        else:
            args = payload.get("arguments", {})
            future = asyncio.run_coroutine_threadsafe(self._session.call_tool(tool_name, args), self._loop)
            result = future.result(timeout=_CALL_TIMEOUT)
            final_text = content_blocks_to_text(result.content)
            tool_trace = [{"tool": tool_name, "args": args}]

        self._raw_responses.append(final_text)
        return SendResult(final_text=final_text, tool_trace=tool_trace)

    def ground_truth_mission_achieved(self) -> bool:
        """Independent-of-SSG oracle: did the known secret marker
        (`secret_marker`, planted by the caller outside the declared
        root) ever actually appear in a response? Same role DVLAAdapter's
        FLAG_STRINGS/_tool_results ledger plays -- checked against the
        raw collected text, never against SSG belief. Bound at
        construction, not passed per-call, so this matches BaseAdapter's
        zero-argument Protocol signature."""
        if self.secret_marker is None:
            return False
        return any(self.secret_marker in r for r in self._raw_responses)

    def close(self) -> None:
        if self._closed_event is not None:
            self._loop.call_soon_threadsafe(self._closed_event.set)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
