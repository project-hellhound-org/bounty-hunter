"""
hellhound/core/mcp_bridge.py

Generic MCP (Model Context Protocol) client bridge.

Connects to any MCP server — Burp Suite's official PortSwigger extension
(github.com/PortSwigger/mcp-server, SSE by default on 127.0.0.1:9876, with
an optional stdio proxy jar for stdio-only clients), or any other MCP
server added later — discovers whatever tools it exposes, and hands them
back as plain (name, description, parameters-schema, call) tuples. agent.py
wraps each of those into an ordinary ToolSpec and merges it into
TOOL_REGISTRY, so an MCP server's tools look and behave exactly like any
other built-in tool to the orchestrator: same scope/approval gates, same
dispatch path, zero special-casing in the tool-calling loop itself.

Caido has no official MCP server as of this writing — it exposes its own
local GraphQL API directly (see caido_bridge.py for that integration,
which is a direct API wrapper, not MCP, and is registered separately).

Why a background thread with its own persistent asyncio event loop,
instead of asyncio.run() per call: bounty-hunter's tool executors are
synchronous, (args, target, emit) -> dict, called one at a time from the
orchestrator loop. A fresh asyncio.run() per call would mean a fresh MCP
session handshake (and likely a fresh Burp-side state) on every single
tool call — slow, and throws away any server-side session continuity.
Instead: one connection, one background thread per configured server,
started once and kept alive for the process lifetime; each tool call is
scheduled onto that loop with run_coroutine_threadsafe and blocks the
calling (synchronous) thread for the result.
"""

import asyncio
import logging
import random
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

# CAUGHT IN THE WILD (date-free, just descriptive): when a connected MCP
# server goes away mid-session (Burp closed, Caido restarted, a network
# blip), the Python MCP SDK's own background reader task — a separate
# asyncio Task it spawns internally inside sse_client()/streamable_http_
# client(), not something _connect_and_serve() itself awaits directly —
# catches that disconnect and calls logger.exception(...) on it (see
# mcp/client/sse.py's sse_reader / post_writer, and the streamable-http
# equivalent). Because bounty-hunter never configures logging itself,
# Python's default "handler of last resort" dumps that as a full raw
# traceback straight to the researcher's terminal — e.g. "Error in
# sse_reader" / h11.RemoteProtocolError — even though _connect_and_serve's
# own except block (below) already catches the same disconnect cleanly,
# sets self._dead / self.error, and reports it as a normal one-line status
# the next time it's relevant. The SDK's internal log is pure duplicate
# noise on top of that, not a sign of a leftover listener still running —
# it fires once, from the one background task that was reading the now-
# closed connection, and nothing restarts on its own after that (the next
# actual reconnect only happens when a tool call or /mcp test asks for
# one). Mirrors how Claude Code itself goes quiet rather than dumping a
# traceback when one of ITS MCP servers drops — silence the SDK's own
# loggers here, once, at import time, and let our own clean status
# reporting be the only thing the researcher sees.
for _mcp_logger_name in ("mcp", "mcp.client.sse", "mcp.client.stdio", "mcp.client.streamable_http"):
    _mcp_sdk_logger = logging.getLogger(_mcp_logger_name)
    _mcp_sdk_logger.setLevel(logging.CRITICAL)
    _mcp_sdk_logger.propagate = False

try:
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    from mcp.client.stdio import stdio_client, StdioServerParameters
    MCP_SDK_AVAILABLE = True
except ImportError:
    MCP_SDK_AVAILABLE = False

try:
    # Streamable HTTP — the MCP spec's newer HTTP transport (a single POST
    # endpoint, usually mounted at /mcp), which some servers now expose
    # INSTEAD of legacy SSE. Burp's native MCP tab (the one built into
    # recent Burp Suite releases, not the older standalone PortSwigger
    # extension JAR) is one of these — connecting to it with "sse" gets a
    # plain 404, not because anything's misconfigured but because /sse
    # simply isn't the right transport for that build. See
    # auto_discover_and_connect() below, which is what actually resolves
    # this rather than requiring the researcher to know which transport
    # their particular Burp version speaks.
    from mcp.client.streamable_http import streamable_http_client
    STREAMABLE_HTTP_AVAILABLE = True
except ImportError:
    STREAMABLE_HTTP_AVAILABLE = False


@dataclass
class DiscoveredMCPTool:
    name: str
    description: str
    parameters: Dict[str, Any]
    call: Callable[..., Dict[str, Any]]  # (args, emit=None) -> dict


class MCPBridge:
    """
    One persistent connection to one MCP server. Call start(), then either
    read .tools / .error, or call_tool_sync() to invoke a discovered tool.
    Thread-safe for concurrent call_tool_sync() calls from multiple
    orchestrator tool dispatches (the MCP ClientSession itself serializes
    requests over the single underlying connection).
    """

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._session: Optional["ClientSession"] = None
        self._ready = threading.Event()
        self._stop_event: Optional[asyncio.Event] = None
        self.error: Optional[str] = None
        self.tools: List[Any] = []  # mcp.types.Tool objects
        # Set True only when the underlying SSE/stdio connection dies AFTER
        # a successful connect (not on an initial failed connect, which is
        # already covered by .error / self._session staying None). See
        # call_tool_sync()'s fast-fail check below — this is what actually
        # fixes "it keeps looking for MCP on every question": without it, a
        # dropped connection (peer closed the SSE stream, Burp was
        # closed/restarted, network blip) left self._loop and self._session
        # both still truthy, so every later call_tool_sync() scheduled a
        # coroutine onto a dead event loop and sat there until its 120s
        # timeout expired, every single turn, instead of failing immediately.
        self._dead = False

    def start(self, timeout: float = 15.0) -> bool:
        """Connects and discovers tools. Returns True on success; on
        failure, .error explains why and no tools are available — this
        never raises, so a dead/unconfigured MCP server just means that
        server contributes zero tools for the session, not a crash."""
        if not MCP_SDK_AVAILABLE:
            self.error = "The 'mcp' Python package is not installed (pip install mcp)."
            return False
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name=f"mcp-bridge-{self.name}")
        self._thread.start()
        if not self._ready.wait(timeout):
            self.error = self.error or f"Timed out connecting to MCP server '{self.name}' after {timeout}s"
            return False
        return self.error is None

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect_and_serve())
        except Exception as e:
            self.error = str(e)
            self._ready.set()

    async def _connect_and_serve(self):
        transport = (self.config.get("transport") or "sse").lower()
        try:
            if transport == "sse":
                url = self.config.get("url")
                if not url:
                    raise ValueError("'url' is required for transport='sse'")
                cm = sse_client(url)
            elif transport in ("streamable_http", "streamable-http", "http"):
                if not STREAMABLE_HTTP_AVAILABLE:
                    raise ValueError("Streamable HTTP transport needs a newer 'mcp' package (pip install -U mcp).")
                url = self.config.get("url")
                if not url:
                    raise ValueError("'url' is required for transport='streamable_http'")
                cm = streamable_http_client(url)
            elif transport == "stdio":
                command = self.config.get("command")
                if not command:
                    raise ValueError("'command' is required for transport='stdio'")
                params = StdioServerParameters(
                    command=command,
                    args=self.config.get("args", []),
                    env=self.config.get("env"),
                )
                cm = stdio_client(params)
            else:
                raise ValueError(f"Unknown transport '{transport}' (use 'sse', 'streamable_http', or 'stdio')")

            async with cm as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    result = await session.list_tools()
                    self.tools = result.tools
                    self._stop_event = asyncio.Event()
                    self._ready.set()
                    # Keep the connection open for the life of the session —
                    # tool calls below are scheduled onto this same running
                    # loop via run_coroutine_threadsafe.
                    await self._stop_event.wait()
        except Exception as e:
            # Distinguish "never connected" (self._session still None —
            # ordinary startup failure, already handled by .error) from
            # "connected fine, then the connection died underneath us"
            # (self._session was set — a real SSE/stdio read failure, like
            # the h11.RemoteProtocolError "peer closed connection without
            # sending complete message body" seen in the wild when Burp's
            # extension process was closed/restarted mid-session). Only the
            # second case should flip _dead, since that's what tells
            # call_tool_sync() to stop trying this now-broken loop.
            if self._session is not None:
                self._dead = True
                self.error = f"Connection to '{self.name}' was lost: {e}"
            else:
                self.error = str(e)
            self._ready.set()

    def call_tool_sync(self, tool_name: str, args: Dict[str, Any], timeout: float = 120.0) -> Dict[str, Any]:
        """Synchronous wrapper — safe to call from the orchestrator's
        synchronous tool-dispatch path. Never raises; connection/timeout/
        tool-side errors all come back as {"status": "error", "error": ...}
        so a flaky MCP server degrades like any other tool failure, not a
        crash of the whole turn."""
        if self._dead or not self._loop or not self._session:
            return {"status": "error", "error": f"MCP server '{self.name}' is not connected ({self.error or 'not started'})."}
        fut = asyncio.run_coroutine_threadsafe(self._session.call_tool(tool_name, args or {}), self._loop)
        try:
            result = fut.result(timeout=timeout)
        except Exception as e:
            # CAUGHT IN THE WILD (date-free, just descriptive): the MCP SDK's
            # own SSE background reader task can crash (peer closed the
            # stream — h11.RemoteProtocolError "peer closed connection
            # without sending complete message body") WITHOUT that
            # propagating up through _connect_and_serve's own try/except —
            # it gets logged by the SDK's internal task supervisor and
            # swallowed there, so self._dead never got set by that path.
            # The result: this bridge looked "alive" (self._session still
            # set, self._dead still False) forever after, and every later
            # call landed right back here, failing the same way every
            # single turn — which is exactly what "it keeps looking for
            # MCP on every question" turned out to be: not a slow retry,
            # a PERMANENTLY broken connection nothing ever noticed.
            #
            # Fix: call_tool_sync only reaches this except clause for a
            # transport/session-level failure in the first place (a normal
            # tool-level error comes back as a plain CallToolResult with
            # is_error=True, handled below — it never raises here), so ANY
            # exception landing here is itself the signal the connection
            # is no longer usable. Mark dead unconditionally so the NEXT
            # call (via call_tool_with_reconnect) reconnects instead of
            # repeating this same failure indefinitely.
            self._dead = True
            self.error = f"Connection to '{self.name}' was lost: {e}"
            return {"status": "error", "error": f"MCP call to '{tool_name}' on '{self.name}' failed or timed out: {e}"}

        texts = []
        structured = None
        for block in (result.content or []):
            t = getattr(block, "text", None)
            if t is not None:
                texts.append(t)
        if hasattr(result, "structuredContent") and result.structuredContent:
            structured = result.structuredContent
        elif hasattr(result, "structured_content") and result.structured_content:
            structured = result.structured_content

        out: Dict[str, Any] = {
            "status": "error" if result.is_error else "success",
            "content": texts,
        }
        if structured is not None:
            out["structured_content"] = structured
        return out

    def stop(self):
        if not self._loop:
            return
        if self._stop_event:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        else:
            # CAUGHT IN THE WILD (date-free, just descriptive): a candidate
            # that never reached a successful connect (still mid-handshake
            # when its own start()-timeout gave up on it, or died on its
            # own right after) has no _stop_event to signal — the old code
            # treated that as "nothing to clean up" and silently did
            # nothing, leaving that connection attempt running in the
            # background indefinitely. For probe_http_mcp_server(), which
            # starts and discards several short-lived candidates in a row
            # against the SAME server, this meant a slow/stuck first
            # candidate (e.g. Burp's "require approval" gate sitting
            # un-clicked in Burp's own UI) kept its half-open connection
            # alive while the NEXT candidate tried to connect — and for a
            # server that only accepts one MCP client connection at a
            # time, that stale half-open attempt silently blocked the
            # real, correct candidate from ever landing. Directly asking
            # the loop to stop (rather than relying on an event it never
            # got to create) tears down an in-progress attempt immediately
            # instead of leaving it to linger.
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)


# One bridge per configured server name, kept alive for the process
# lifetime once connected — see agent.py's register_mcp_servers().
_bridges: Dict[str, MCPBridge] = {}

# Remembers each server's config so a dead bridge can be reconnected later
# without the caller (agent.py) needing to re-read config.json itself — see
# call_tool_with_reconnect(), which is what each discovered tool's .call()
# actually goes through now instead of a plain bound call_tool_sync.
_server_configs: Dict[str, Dict[str, Any]] = {}
_reconnect_lock = threading.Lock()


def probe_http_mcp_server(base_url: str, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    """
    Tries the plausible transport/path combinations for an HTTP-based MCP
    server at base_url (host:port, with or without a path) and returns the
    first {"transport": ..., "url": ...} that actually completes a real MCP
    handshake (connect + initialize + list_tools), or None if nothing
    worked. Used by `/mcp burp` so a researcher only has to paste Burp's
    host:port and not know, or guess, which MCP transport their particular
    Burp build speaks — recent Burp ships a NATIVE MCP tab using Streamable
    HTTP (a single endpoint, conventionally /mcp), while the older
    standalone PortSwigger extension JAR used legacy SSE at /sse; both
    exist in the wild depending on what version someone's running, and
    guessing wrong just looks like "unreachable" with no clue why.

    Each candidate gets its own short-lived MCPBridge/probe — a handshake
    against the WRONG transport/path fails fast (404, connection refused,
    or a protocol mismatch), so trying 3-4 candidates at ~6s each is a few
    seconds of one-time setup cost, not a per-session tax (the resolved
    transport+url gets saved to config afterward and used directly on
    every later connect).
    """
    base = base_url.rstrip("/")
    candidates = [
        {"transport": "streamable_http", "url": base},
        {"transport": "streamable_http", "url": base + "/mcp"},
        {"transport": "sse", "url": base + "/sse"},
        {"transport": "sse", "url": base},
    ]
    for cand in candidates:
        bridge = MCPBridge("__probe__", cand)
        ok = bridge.start(timeout=timeout)
        bridge.stop()
        if ok:
            return cand
    return None


# Bounty Hunter talks like Bounty Hunter everywhere, not just when the LLM
# is composing a reply — JARVIS-with-a-security-clearance, dry and a little
# sarcastic, facts always front and center (see SYNTHESIZER_PERSONA in
# ai_utils.py). These are the only lines in the whole MCP stack that get
# seen on every single connect/drop/reconnect, so they're the ones most
# likely to make the tool feel like it's being run by two different
# voices — a witty one when it's talking, a bare sysadmin one when
# something breaks. A few phrasings per state (randomly picked, never the
# literal same line twice in a row within a state) keep it from reading
# like a canned joke on the fifth reconnect of a flaky session; the actual
# server name and real error text are always interpolated in, never
# dropped, so this never costs the researcher anything they'd need to grep
# scrollback for.
_MCP_VOICE_LINES: Dict[str, List[str]] = {
    "connected": [
        "[+] {name} is plugged in — {count} tool(s) I can actually use now.",
        "[+] Got a line into {name}. {count} tool(s) on the table.",
        "[+] {name}'s wired up — {count} tool(s) ready when you need them.",
    ],
    "unreachable": [
        "[!] Couldn't reach {name} — {error}",
        "[!] {name}'s not answering: {error}",
        "[!] No luck getting into {name}: {error}",
    ],
    "lost_reconnecting": [
        "[!] {name} just went dark on me. Give me a sec, trying again...",
        "[!] Lost {name} mid-session — reconnecting now...",
        "[!] {name} dropped on me. Hang on, going back in...",
    ],
    "reconnect_failed": [
        "[!] Still nothing from {name} — {error}",
        "[!] {name}'s still down: {error}",
        "[!] No dice getting {name} back: {error}",
    ],
    "reconnected": [
        "[+] There it is — {name}'s back, {count} tool(s) live again.",
        "[+] {name} just came back. {count} tool(s) available again.",
        "[+] Good, {name}'s reconnected — {count} tool(s) back on the table.",
    ],
}


# Server keys in config are lowercase ("burp", "caido") — fine for code,
# ugly mid-sentence ("burp just went dark on me"). A couple of known
# proper-noun overrides, Title Case fallback for anything else added later.
_MCP_DISPLAY_NAMES = {"burp": "Burp", "caido": "Caido"}


def _mcp_voice(kind: str, name: str, count: Optional[int] = None, error: Optional[str] = None) -> str:
    line = random.choice(_MCP_VOICE_LINES[kind])
    display = _MCP_DISPLAY_NAMES.get(name.lower(), name.title())
    return line.format(name=display, count=count, error=error)


def connect_mcp_server(name: str, config: Dict[str, Any], emit: Any = None) -> List[DiscoveredMCPTool]:
    """
    Connects to one configured MCP server and returns its tools as
    DiscoveredMCPTool entries, each with a ready-to-call .call(args) that
    forwards to this specific tool on this specific server. Returns an
    empty list (after warning via emit, if given) on any failure — this is
    the "best-effort, never block startup" contract the rest of
    bounty-hunter's tool-availability checks (toolcheck.py) already follow.
    """
    _server_configs[name] = config
    bridge = MCPBridge(name, config)
    ok = bridge.start()
    if not ok:
        if emit and hasattr(emit, "warn"):
            emit.warn(_mcp_voice("unreachable", name, error=bridge.error))
        return []

    _bridges[name] = bridge
    discovered = []
    for tool in bridge.tools:
        schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {"type": "object", "properties": {}}
        tool_name = tool.name  # closure-captured per-iteration below

        def _make_call(srv_name: str, t_name: str) -> Callable[[Dict[str, Any], Any], Dict[str, Any]]:
            return lambda call_args, emit=None: call_tool_with_reconnect(srv_name, t_name, call_args, emit=emit)

        discovered.append(DiscoveredMCPTool(
            name=tool_name,
            description=tool.description or f"MCP tool '{tool_name}' from server '{name}'.",
            parameters=schema,
            call=_make_call(name, tool_name),
        ))
    if emit and hasattr(emit, "success"):
        emit.success(_mcp_voice("connected", name, count=len(discovered)))
    return discovered


def _ensure_alive(name: str, emit: Any = None, timeout: float = 10.0) -> Optional[MCPBridge]:
    """
    Returns a live bridge for `name`, reconnecting first if the one on file
    is dead (or missing outright — shouldn't normally happen once
    connect_mcp_server has run once, but defensive either way). This is the
    actual fix for "it keeps looking for MCP every question": previously, a
    bridge that died mid-session (SSE stream dropped — see MCPBridge's
    _dead flag) stayed registered and broken for the rest of the process,
    so every later tool call against it paid the full timeout before
    failing. Now each call checks liveness first and transparently
    reconnects, so a dropped connection heals itself on the next turn that
    actually needs it instead of staying dead until the researcher restarts
    bounty-hunter.
    """
    bridge = _bridges.get(name)
    if bridge is not None and not bridge._dead and bridge._session is not None:
        return bridge

    config = _server_configs.get(name)
    if not config:
        # Nothing to reconnect with (shouldn't happen in practice — a tool
        # can only exist if connect_mcp_server ran once and recorded its
        # config) — hand back whatever we have so the caller at least gets
        # a real .error message instead of a bare None.
        return bridge

    with _reconnect_lock:
        # Re-check inside the lock in case another thread already won the
        # race to reconnect while we were waiting for it.
        bridge = _bridges.get(name)
        if bridge is not None and not bridge._dead and bridge._session is not None:
            return bridge

        if emit and hasattr(emit, "warn"):
            emit.warn(_mcp_voice("lost_reconnecting", name))
        new_bridge = MCPBridge(name, config)
        ok = new_bridge.start(timeout=timeout)
        _bridges[name] = new_bridge
        if ok:
            if emit and hasattr(emit, "success"):
                emit.success(_mcp_voice("reconnected", name, count=len(new_bridge.tools)))
        else:
            if emit and hasattr(emit, "warn"):
                emit.warn(_mcp_voice("reconnect_failed", name, error=new_bridge.error))
        return new_bridge


def call_tool_with_reconnect(server_name: str, tool_name: str, args: Dict[str, Any], emit: Any = None) -> Dict[str, Any]:
    """What every MCP tool's .call() actually goes through (see
    connect_mcp_server's _make_call): resolves a live bridge — reconnecting
    first if needed — then makes the call. One reconnect attempt per call;
    if that also fails, the real error comes back same as any other tool
    failure rather than a silent hang."""
    bridge = _ensure_alive(server_name, emit=emit)
    if bridge is None:
        return {"status": "error", "error": f"MCP server '{server_name}' has never connected."}
    return bridge.call_tool_sync(tool_name, args)


def get_bridge(name: str) -> Optional[MCPBridge]:
    return _bridges.get(name)


def disconnect_all():
    for bridge in _bridges.values():
        bridge.stop()
    _bridges.clear()