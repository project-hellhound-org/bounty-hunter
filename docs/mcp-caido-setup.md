# Caido Setup

Caido now has a real, actively-maintained MCP server you can use —
[`caido-mcp-server`](https://github.com/c0tton-fluff/caido-mcp-server) by
c0tton-fluff — so this is the recommended path. It talks proper OAuth (no
manual token copy-pasting, no 7-day expiry to babysit) and exposes roughly
66 tools and 6 resources, versus the 3 tools bounty-hunter's original
hand-rolled GraphQL integration offers. That older integration is still
built in and works fine as a zero-install fallback — see
[Option B](#option-b--built-in-graphql-integration-fallback) below.

## Option A — caido-mcp-server (recommended)

### 1. Install it

```bash
curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/caido-mcp-server/main/install.sh | bash
```

This installs the `caido-mcp-server` binary to `~/.local/bin` (make sure
that's on your `PATH`).

### 2. Log in once

With Caido running and a project open:

```bash
CAIDO_URL=http://localhost:8080 caido-mcp-server login
```

This opens a browser consent flow against `dashboard.caido.io` — approve
it, and the resulting session is stored for `caido-mcp-server serve` to
reuse. You only need to do this once per machine (until the session
expires, at which point just run `login` again).

### 3. Point bounty-hunter at it

```
/mcp caido http://localhost:8080
```

`/mcp caido` automatically detects `caido-mcp-server` on your `PATH` and
uses it in preference to the built-in GraphQL integration — you don't
need to tell it which one to use. It connects immediately and reports
what it found:

```
[*] Found caido-mcp-server on PATH — using it instead of the old GraphQL integration. Testing http://localhost:8080 ...
[+] Caido connected via caido-mcp-server — 66 tool(s) discovered.
```

If you see a connection error here and haven't done step 2 yet, that's
almost always why — the message tells you the exact `login` command to run.

### 4. Verify and use it

```
/mcp              # shows current config
/mcp test         # re-checks without changing anything
```

Once connected, its tools show up prefixed `mcp_caido_<toolname>` and are
called exactly like any built-in tool, through the same scope and
approval gates.

### Remove it

```
/mcp caido remove
```

## Option B — Built-in GraphQL integration (fallback)

If you don't want to install anything extra, bounty-hunter can talk to
Caido's local GraphQL API directly. This is what `/mcp caido` falls back
to automatically if `caido-mcp-server` isn't found on your `PATH` — or you
can force it explicitly even if the binary IS installed:

```
/mcp caido graphql [url] [token]
```

### The two tokens Caido has — use the right one

- **Local session token** (what this integration actually uses) — comes
  from your logged-in Caido *desktop app* session, via a one-line devtools
  command below. This is what authenticates against your local
  `http://localhost:8080/graphql`.
- **Personal Access Token / PAT** (`dashboard.caido.io/developer`) — this
  is for **Caido Cloud** (team/org management), a separate product
  surface from your local instance, and a different use case from this
  fallback integration. See
  [Caido's PAT guide](https://docs.caido.io/dashboard/guides/create_pat)
  if that's what you actually need.

### 1. Get your local session token

1. Open Caido in your browser (or the desktop app's embedded browser) and
   make sure you're logged in with a project open.
2. Open devtools (`F12` or right-click → Inspect).
3. Go to the **Console** tab and run:
   ```js
   JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken
   ```
4. Copy the string it prints (no quotes) — that's your token.

**This token expires after 7 days.** When it stops working, repeat these
steps and re-paste it (step 2 below has a shortcut for that).

### 2. Give it to bounty-hunter

```
/mcp caido graphql http://localhost:8080/graphql <paste-token-here>
```

Or, if you're already configured and just need a fresh token:
```
/mcp caido token <paste-fresh-token-here>
```
(Running it with no token on the command line will prompt for it
interactively, hidden while you type, via `getpass` — safer than pasting
it as a plain argument someone could see in your shell history.)

### 3. Verify

```
/mcp
/mcp test
```

### If it says "unreachable"

| Message | What it means |
| :--- | :--- |
| `Could not reach Caido at ...` | Caido isn't running, or it's on a different port than `8080` — check Caido's own settings for the actual port and re-run step 2 with that URL. |
| `HTTP 401 ... token missing/expired` | Your token expired (7-day limit) or was pasted wrong — get a fresh one (step 1) and run `/mcp caido token <token>`. |
| `Caido accepted the connection but returned no authenticated viewer` | The token was syntactically accepted but Caido doesn't recognize the session behind it — usually means Caido was restarted since you grabbed the token. Get a fresh one. |
| `Caido returned a non-JSON response (is something other than Caido listening at ...)` | Something other than Caido answered on that host:port — double check you're not pointing at a different local service. |

### What you get

Three tools, prefixed `caido_`:
- `caido_http_history_search` — query Caido's captured traffic using its
  own query-bar syntax (HTTPQL), e.g. `req.host.cont:"example.com"`.
- `caido_send_request` — fire a raw request through Caido's proxy pipeline
  so it lands in Caido's own history, like send-to-Repeater in Burp.
- `caido_create_finding` — push a confirmed finding into Caido's own
  Findings panel, tied to the request that proved it.

### Remove it

```
/mcp caido remove
```
(Removes whichever of the two integrations — caido-mcp-server or GraphQL
— is currently configured.)