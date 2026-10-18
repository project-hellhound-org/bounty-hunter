# Burp Suite MCP Setup

Burp Suite can expose its own tooling (send-to-Repeater, scanner, etc.) as
MCP tools that bounty-hunter calls directly, alongside its own built-in
recon tools.

## 1. Turn on Burp's MCP server

Burp has shipped MCP in two different forms over time — which one you have
depends on your Burp version:

- **Recent Burp Suite (native MCP tab)** — open the **MCP** tab in Burp's
  top nav (next to Extensions, Logger++, etc.). Toggle **Enabled** on.
- **Older Burp (standalone extension)** — install the official
  [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)
  extension under **Extensions → Add**, then open its settings tab and
  enable the MCP server there.

Either way, note the **Server host** / **Server port** shown (default
`127.0.0.1` / `9876`).

> **Watch for this:** the **Enabled** toggle at the top of the MCP tab and
> the small status indicator in the bottom-right corner (it reads
> "Enabled" / "Disabled") are **two separate things**. The toggle is a
> setting; the indicator reflects whether the listener has actually
> started. If the indicator still says "Disabled" after you've flipped the
> toggle on, click it / toggle it again, or restart the MCP tab — the
> listener isn't actually up yet, and anything bounty-hunter tries will
> fail with a plain connection error until it is.

## 2. Connect bounty-hunter to it

Inside bounty-hunter, just give it the host:port Burp showed you:

```
/mcp burp http://127.0.0.1:9876
```

You don't need to know which of the two MCP implementations above you're
running, or what path/transport it speaks — `/mcp burp` probes the
plausible combinations (recent Burp's Streamable HTTP, typically at
`/mcp`, and the older extension's legacy SSE at `/sse`) and saves whichever
one actually answers. You'll see:

```
[*] Probing http://127.0.0.1:9876 for Burp's MCP transport (tries Streamable HTTP, then legacy SSE)...
[+] Burp connected via streamable_http at http://127.0.0.1:9876/mcp — N tool(s) discovered: ...
```

## 3. Verify and use it

```
/mcp              # shows current config for both Burp and Caido
/mcp test         # re-checks the live connection without changing anything
```

Once connected, Burp's tools show up prefixed as `mcp_burp_<toolname>` —
bounty-hunter calls them exactly like any built-in tool, through the same
scope and approval gates.

## If it still won't connect

| Symptom | Likely cause |
| :--- | :--- |
| `All connection attempts failed` | Nothing is listening on that host:port — Burp isn't running, or the MCP tab's listener hasn't actually started (see the toggle-vs-indicator note above). |
| `404 Not Found` even with auto-probe | Burp's configured on a non-default port — check **Advanced Options** in the MCP tab and re-run `/mcp burp http://<that host:port>`. |
| It connected once, then every tool call fails | The connection dropped (Burp was closed/restarted). This self-heals automatically on your next tool call — bounty-hunter reconnects transparently. If it doesn't, run `/mcp test` to force a fresh check. |
| `Require approval for HTTP requests` / `project data access` is checked in Burp | Burp will prompt you inside its own UI before letting a tool call through — this is Burp's own safety gate, not a bounty-hunter setting. Uncheck it in the MCP tab if you want tool calls to proceed without a manual click each time (understand what that means for your own workflow before turning it off). |

## Remove it

```
/mcp burp remove
```