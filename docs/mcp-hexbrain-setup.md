# HexBrain Setup

[HexBrain](https://hexbrainai.com) is a hosted MCP server over **15,000+ publicly
disclosed HackerOne reports**, mapped to *how each bug was actually found* —
plus a payload library, a bypass library pulled from real reports, CVE checks,
and the known subdomains of many programs. Connecting it gives Beast
"learn from what actually worked" leverage mid-engagement: when it knows the
program, the tech stack, or a feature worth testing, it can pull proven
methodology from real write-ups instead of guessing.

It's **read-only reference material** — Beast mines it for technique, and treats
every report's text as untrusted third-party content (never as instructions).

The free tier is **200 calls/day** (90/min), which is plenty for querying it at
decision points during a hunt.

## 1. Get an API key (free)

1. Go to **[hexbrainai.com/account](https://hexbrainai.com/account)** and sign in
   with Google.
2. Under **API keys**, name a key (e.g. "beast") and click **Create API key**.
3. Copy the `sk_...` key — it's shown only once.

## 2. Connect Beast to it

```
/mcp hexbrain sk_your_key_here
```

That saves the server, live-tests the connection, and registers its tools. On
success you'll see:

```
[+] HexBrain connected — 11 tool(s): hexbrain_list_classes, hexbrain_search_reports, ...
```

If the key is wrong or expired you'll get a clear `Server returned an error
response` instead — recheck it at
[hexbrainai.com/account](https://hexbrainai.com/account).

## 3. Verify

```
/mcp              # shows integration status, incl. HexBrain (key masked)
/mcp test         # re-connects and lists the tools without changing config
```

## What you get

Eleven tools, registered as `mcp_hexbrain_<toolname>` and called like any other
tool (through the same scope/approval gates):

| Tool | What it does |
| :--- | :--- |
| `mcp_hexbrain_search_reports` | Query disclosed findings by text, class, program, severity, bounty |
| `mcp_hexbrain_get_report` | Pull the full write-up for a specific HackerOne report |
| `mcp_hexbrain_get_testing_playbook` | Real examples of how a vulnerability class was discovered |
| `mcp_hexbrain_get_program_history` | What a target program has reported/paid for before |
| `mcp_hexbrain_find_bypasses` | Techniques researchers used to get around protections |
| `mcp_hexbrain_find_payloads` | Ready-made exploitation techniques across 60+ bug types |
| `mcp_hexbrain_plan_tests` | Which vulnerability classes fit a specific feature |
| `mcp_hexbrain_find_cves` | Match technologies to known CVEs with severity/exploitability |
| `mcp_hexbrain_get_cve` | Full details on a specific CVE |
| `mcp_hexbrain_get_attack_surface` | Known subdomains for a program (not a statement of scope) |
| `mcp_hexbrain_list_classes` | Enumerate vulnerability classes and report counts |

## How Beast uses it

Unlike the Burp/Caido proxy integrations (which only connect when you name them),
HexBrain is a **passive knowledge source**, so it **auto-registers on any real
hunting turn** — you don't have to mention it. Once a hunt is underway and the
stack/feature is known, Beast consults it at decision points: program history
("has this program paid for this bug class?"), testing playbooks, and
payloads/bypasses for the stack in front of it, feeding the leads into its
hypothesis generation. It's rate-limited, so it queries with intent rather than
on every turn.

## Remove it

```
/mcp hexbrain remove
```

## Notes

- **Unauthenticated access** (no key, 240 req/min per IP) is also available
  directly for individual reports: `https://hexbrainai.com/report/{id}.json`
  (or `.md`), plus `/feed`, `/sitemap.xml`, and `/llms.txt`.
- The MCP endpoint is `https://hexbrainai.com/api/mcp` (Streamable HTTP,
  `Authorization: Bearer <key>`). `/mcp hexbrain` configures all of that for you;
  you only paste the key.
- Report text is written by third-party researchers — Beast treats it as
  reference data to learn technique from, never as instructions to follow.
