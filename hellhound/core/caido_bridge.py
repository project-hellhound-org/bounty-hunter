"""
hellhound/core/caido_bridge.py

Direct Caido GraphQL API wrapper.

Caido has no official MCP server (see mcp_bridge.py's own docstring for
that side of the integration, used for Burp instead). Caido exposes its
own local GraphQL API directly — by default at http://localhost:8080/graphql
— authenticated with a Bearer access token. See docs.caido.io/app/concepts/
graphql and the schema at github.com/caido/schemas/blob/main/schemas/proxy/
schema.graphql (both fetched and read directly to build this module —
field/query names below are taken from that schema, not guessed).

Caido's access tokens (grabbed from devtools localStorage, per their own
docs) expire after 7 days, so this is meant to be re-pasted into config
occasionally, not a permanent credential — same "best-effort, degrade
quietly" contract as mcp_bridge.py: a missing/expired/unreachable Caido
instance means zero caido_* tools get registered for the session, never a
crash of bounty-hunter itself.

Unlike Burp (via MCP, where the SERVER tells us what tools exist),
Caido has no tool-discovery protocol — it's a fixed GraphQL schema, not a
dynamic tool list. So instead of discovering tools, this module exposes a
small, fixed, hand-written set of ToolSpec-shaped functions covering the
things a researcher actually wants from Caido in-loop:

  - caido_http_history_search : query already-proxied traffic via HTTPQL
  - caido_send_request        : fire a new raw request through Caido's
                                 proxy pipeline (so it lands in Caido's own
                                 history/scope/replay UI, same as Burp's
                                 send-to-repeater equivalent)
  - caido_create_finding      : push a confirmed finding into Caido's own
                                 Findings panel, tied to the request that
                                 proved it

agent.py registers these the same way it does MCP tools (one ToolSpec per
function, merged into TOOL_REGISTRY), gated on a "caido" block existing in
config.json — see register_caido_tools().
"""

import base64
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class CaidoConfig:
    url: str = "http://localhost:8080/graphql"
    token: Optional[str] = None
    verify_tls: bool = True


class CaidoClient:
    """
    Thin synchronous GraphQL client against one Caido instance. No
    persistent connection/thread needed here (unlike mcp_bridge.py) —
    Caido's API is plain request/response HTTP, so every call is just a
    POST; nothing to keep alive between turns.
    """

    def __init__(self, config: CaidoConfig):
        self.config = config
        self.last_error: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None, timeout: float = 30.0) -> Dict[str, Any]:
        """
        Raw GraphQL call. Returns {"data": ...} on success or
        {"error": "..."} on any failure (network, auth, GraphQL-level
        errors) — never raises, so a flaky/expired-token Caido instance
        degrades like any other tool failure.
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "The 'requests' package is not installed."}
        try:
            resp = requests.post(
                self.config.url,
                json={"query": query, "variables": variables or {}},
                headers=self._headers(),
                timeout=timeout,
                verify=self.config.verify_tls,
            )
        except Exception as e:
            self.last_error = str(e)
            return {"error": f"Could not reach Caido at {self.config.url}: {e}"}

        if resp.status_code == 401 or resp.status_code == 403:
            self.last_error = f"HTTP {resp.status_code} — Caido access token missing/expired (tokens expire after 7 days)."
            return {"error": self.last_error}
        if resp.status_code >= 400:
            self.last_error = f"HTTP {resp.status_code}: {resp.text[:500]}"
            return {"error": self.last_error}

        try:
            body = resp.json()
        except Exception as e:
            # CAUGHT IN THE WILD (date-free, just descriptive): this branch
            # used to return an {"error": ...} dict WITHOUT setting
            # self.last_error, so a caller reading last_error afterward
            # (register_caido_tools' failure warning, /mcp test) saw "None"
            # instead of the real reason — e.g. something other than Caido
            # answering 200 on that host:port (a dev server, Caido's own
            # static UI assets, a captive portal) with an HTML body instead
            # of JSON. Set it here too so the warning is actually
            # informative instead of silently swallowing the cause.
            self.last_error = f"Caido returned a non-JSON response (is something other than Caido listening at {self.config.url}?): {e}"
            return {"error": self.last_error}

        if body.get("errors"):
            msgs = "; ".join(e.get("message", str(e)) for e in body["errors"])
            self.last_error = msgs
            return {"error": f"Caido GraphQL error: {msgs}"}

        return {"data": body.get("data")}

    def ping(self) -> bool:
        """Cheap reachability/auth check used by register_caido_tools()."""
        # CAUGHT IN THE WILD (date-free, just descriptive): this used to ask
        # for "viewer { id }" — but Caido's User type isn't actually
        # published in their own public schema repo (caido/schemas only
        # ships schemas/proxy/schema.graphql, which references "viewer:
        # User!" without ever defining User), so "id" was a guess, and a
        # real Caido instance rejected it outright with a GraphQL
        # validation error ("Unknown field \"id\" on type \"User\"") —
        # meaning every ping on a perfectly reachable, correctly
        # authenticated Caido came back as "unreachable". __typename is a
        # universal GraphQL meta-field valid on every type without knowing
        # its schema, so this can never hit the same wall again — it still
        # proves the connection works AND that viewer resolves to a real,
        # authenticated user object (non-null) rather than just that the
        # endpoint exists.
        result = self.graphql("query { viewer { __typename } }")
        if "error" in result:
            return False
        data = result.get("data")
        if not data or data.get("viewer") is None:
            # A 200 with valid JSON but no viewer usually means the token
            # was accepted by the transport but Caido itself doesn't
            # recognize the session (e.g. an empty/placeholder token slipped
            # through, or Caido was restarted and invalidated it) — graphql()
            # doesn't treat this as an HTTP/GraphQL-level error since there's
            # no "errors" array, so set a clear message here instead of
            # leaving the caller with another silent "None".
            self.last_error = "Caido accepted the connection but returned no authenticated viewer — the access token is likely missing, empty, or invalid."
            return False
        return True


# ── caido_http_history_search ────────────────────────────────────────────
# Caido's query language (HTTPQL) is passed as a plain string, e.g.
# 'req.host.cont:"example.com" and resp.code.eq:200' — same syntax as
# typing into Caido's own search bar. No local parsing/validation here;
# Caido's own GraphQL error comes back verbatim via graphql()'s "error"
# key if the HTTPQL string is malformed, which is informative enough for
# the orchestrator to self-correct on a retry.
_HISTORY_QUERY = """
query SearchHistory($filter: HTTPQLInput, $first: Int) {
  requests(filter: $filter, first: $first, order: {by: CREATED_AT, ordering: DESC}) {
    count { value }
    nodes {
      id
      method
      host
      port
      path
      isTls
      createdAt
      response {
        id
        statusCode
        length
        roundtripTime
      }
    }
  }
}
"""


def caido_http_history_search(client: CaidoClient, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    args: {"httpql": "<Caido query-bar syntax string>", "limit": 50}
    An empty/omitted "httpql" returns the most recent traffic unfiltered.
    """
    httpql = (args or {}).get("httpql") or ""
    limit = int((args or {}).get("limit") or 50)
    variables = {"first": min(max(limit, 1), 200)}
    if httpql.strip():
        variables["filter"] = {"code": httpql}
    result = client.graphql(_HISTORY_QUERY, variables)
    if "error" in result:
        return {"status": "error", "error": result["error"]}
    data = (result.get("data") or {}).get("requests") or {}
    nodes = data.get("nodes") or []
    return {
        "status": "success",
        "total_matching": (data.get("count") or {}).get("value"),
        "returned": len(nodes),
        "requests": [
            {
                "id": n["id"],
                "method": n.get("method"),
                "host": n.get("host"),
                "port": n.get("port"),
                "path": n.get("path"),
                "is_tls": n.get("isTls"),
                "created_at": n.get("createdAt"),
                "status_code": (n.get("response") or {}).get("statusCode"),
                "response_length": (n.get("response") or {}).get("length"),
            }
            for n in nodes
        ],
    }


# ── caido_send_request ───────────────────────────────────────────────────
# Sends a raw HTTP request through Caido's createRequest mutation, which
# records it into Caido's own history/scope (same role as "send to
# repeater" in Burp) — this is NOT the same as createReplaySession (which
# opens an interactive Replay tab); createRequest is the simpler one-shot
# "fire it and get the id/response back" primitive, which is what an
# autonomous loop actually wants here.
_SEND_REQUEST_MUTATION = """
mutation SendRequest($input: CreateRequestInput!) {
  createRequest(input: $input) {
    id
    responseId
  }
}
"""


def caido_send_request(client: CaidoClient, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    args: {
      "host": "example.com", "port": 443, "is_tls": true,
      "method": "GET", "path": "/admin", "query": "",
      "raw": "<raw HTTP request text, CRLF line endings>"
    }
    "raw" is given as plain text here (not pre-base64'd) — this function
    does the base64 encoding Caido's Blob scalar expects, so the caller
    (the model) just writes an ordinary raw HTTP request.
    """
    a = args or {}
    raw_text = a.get("raw") or ""
    if not raw_text:
        return {"status": "error", "error": "'raw' (the raw HTTP request text) is required."}
    raw_b64 = base64.b64encode(raw_text.encode("utf-8", errors="replace")).decode("ascii")

    variables = {
        "input": {
            "host": a.get("host") or "",
            "isTls": bool(a.get("is_tls", False)),
            "method": a.get("method") or "GET",
            "path": a.get("path") or "/",
            "port": int(a.get("port") or (443 if a.get("is_tls") else 80)),
            "query": a.get("query") or "",
            "raw": raw_b64,
            "source": "REPLAY",
        }
    }
    if not variables["input"]["host"]:
        return {"status": "error", "error": "'host' is required."}

    result = client.graphql(_SEND_REQUEST_MUTATION, variables)
    if "error" in result:
        return {"status": "error", "error": result["error"]}
    payload = (result.get("data") or {}).get("createRequest") or {}
    return {
        "status": "success",
        "caido_request_id": payload.get("id"),
        "caido_response_id": payload.get("responseId"),
        "note": "Recorded into Caido's own HTTP history — open it there to inspect the full response, or use caido_http_history_search.",
    }


# ── caido_create_finding ─────────────────────────────────────────────────
_CREATE_FINDING_MUTATION = """
mutation PushFinding($requestId: ID!, $input: CreateFindingInput!) {
  createFinding(requestId: $requestId, input: $input) {
    error { __typename }
    finding { id title host path }
  }
}
"""


def caido_create_finding(client: CaidoClient, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    args: {"request_id": "<Caido request id, from caido_send_request or
    caido_http_history_search>", "title": "...", "description": "...",
    "reporter": "bounty-hunter"}
    Mirrors record_finding's role but writes into Caido's own Findings
    panel (visible to the researcher inside Caido itself), tied to the
    exact request/response pair that proved it — use alongside, not
    instead of, record_finding.
    """
    a = args or {}
    request_id = a.get("request_id")
    title = a.get("title")
    if not request_id or not title:
        return {"status": "error", "error": "'request_id' and 'title' are required."}
    variables = {
        "requestId": request_id,
        "input": {
            "title": title,
            "description": a.get("description") or "",
            "reporter": a.get("reporter") or "bounty-hunter",
        },
    }
    result = client.graphql(_CREATE_FINDING_MUTATION, variables)
    if "error" in result:
        return {"status": "error", "error": result["error"]}
    payload = (result.get("data") or {}).get("createFinding") or {}
    if payload.get("error"):
        return {"status": "error", "error": f"Caido rejected the finding: {payload['error']}"}
    finding = payload.get("finding") or {}
    return {"status": "success", "caido_finding_id": finding.get("id")}


# ── Registration ──────────────────────────────────────────────────────────
TOOL_SPECS: List[Dict[str, Any]] = [
    {
        "name": "caido_http_history_search",
        "fn": caido_http_history_search,
        "description": (
            "Search Caido's own HTTP proxy history using HTTPQL (Caido's query-bar syntax, "
            "e.g. 'req.host.cont:\"example.com\" and resp.code.eq:200'). Use this to pull up "
            "traffic already captured by Caido's proxy — including anything proxied through it "
            "outside of bounty-hunter's own tools — rather than re-requesting it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "httpql": {"type": "string", "description": "Caido query-bar syntax; omit or empty for most recent traffic unfiltered."},
                "limit": {"type": "integer", "description": "Max requests to return (default 50, capped at 200)."},
            },
        },
    },
    {
        "name": "caido_send_request",
        "fn": caido_send_request,
        "description": (
            "Send a raw HTTP request through Caido's own proxy pipeline, so it lands in Caido's "
            "history/scope/UI just like a browser-proxied or Repeater-sent request would in Burp. "
            "Returns Caido's own request/response ids for follow-up with caido_http_history_search "
            "or caido_create_finding."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "is_tls": {"type": "boolean"},
                "method": {"type": "string"},
                "path": {"type": "string"},
                "query": {"type": "string"},
                "raw": {"type": "string", "description": "Full raw HTTP request text (request line + headers + CRLF + body)."},
            },
            "required": ["host", "raw"],
        },
    },
    {
        "name": "caido_create_finding",
        "fn": caido_create_finding,
        "description": (
            "Push a confirmed finding into Caido's own Findings panel, tied to the exact request "
            "that proved it. Use alongside record_finding, not instead of it — this is for the "
            "researcher reviewing inside Caido itself."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Caido request id from caido_send_request or caido_http_history_search."},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "reporter": {"type": "string"},
            },
            "required": ["request_id", "title"],
        },
    },
]


def register_caido_tools(config: Dict[str, Any], emit: Any = None) -> List[Dict[str, Any]]:
    """
    Reads a "caido" config block, e.g.:

        "caido": {
            "url": "http://localhost:8080/graphql",
            "token": "<access token, from Caido's devtools localStorage — expires after 7 days>",
            "verify_tls": true
        }

    Pings the instance once; on success returns the fixed TOOL_SPECS list
    (each with its "fn" already bound to a CaidoClient via a closure the
    caller — agent.py's register_caido_tools_into_registry — wraps into a
    ToolSpec). On any failure (unreachable, expired/missing token) returns
    an empty list and warns via emit, exactly like a dead MCP server —
    never blocks bounty-hunter from starting.
    """
    if not isinstance(config, dict) or not config:
        return []
    if not REQUESTS_AVAILABLE:
        if emit and hasattr(emit, "warn"):
            emit.warn("[!] Caido support unavailable — the 'requests' package is missing.")
        return []

    caido_cfg = CaidoConfig(
        url=config.get("url") or "http://localhost:8080/graphql",
        token=config.get("token"),
        verify_tls=config.get("verify_tls", True),
    )
    client = CaidoClient(caido_cfg)
    if not client.ping():
        if emit and hasattr(emit, "warn"):
            emit.warn(f"[!] Caido unreachable at {caido_cfg.url} — skipping its tools: {client.last_error}")
        return []

    if emit and hasattr(emit, "success"):
        emit.success(f"[+] Caido connected at {caido_cfg.url} — {len(TOOL_SPECS)} tool(s) registered.")

    bound = []
    for spec in TOOL_SPECS:
        fn = spec["fn"]
        bound.append({
            "name": spec["name"],
            "description": spec["description"],
            "parameters": spec["parameters"],
            # Accepts an (ignored) emit kwarg for signature parity with
            # mcp_bridge.py's reconnect-aware calls — agent.py's
            # _make_mcp_executor passes emit to both uniformly now.
            "call": (lambda args, emit=None, _fn=fn, _client=client: _fn(_client, args)),
        })
    return bound