<p align="center">
  <img src="Images/hellhound.gif" alt="Hellhound Bounty Hunter Animation" width="100%"/>
</p>

<h1 align="center">BOUNTY HUNTER</h1>
<p align="center">
  <b>Autonomous AI Bug Bounty & Penetration Testing Framework — runs as <code>beast</code>, built by Project Hellhound</b>
  <br>
  <i>Target enumeration, two-tier neural reasoning, 30 methodology skills, persistent artifact blackboard, live SPA crawling, visual evidence capture, and zero-bypass scope guardrails — from recon to submission-ready report.</i>
</p>

<p align="center">
  <a href="#what-is-this">What Is This?</a> ·
  <a href="#how-it-works">How It Works</a> ·
  <a href="#installation--setup">Installation</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#capabilities">Capabilities</a> ·
  <a href="#roadmap--whats-next">Roadmap</a> ·
  <a href="#license">License</a>
</p>

<p align="center">
  <a href="https://github.com/project-hellhound-org/bounty-hunter/stargazers"><img src="https://img.shields.io/github/stars/project-hellhound-org/bounty-hunter?style=flat-square&color=gold" alt="GitHub Stars"/></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python Version"/></a>
  <a href="https://github.com/project-hellhound-org/bounty-hunter/releases"><img src="https://img.shields.io/badge/Release-v13.21-red?style=flat-square" alt="Release Version"/></a>
  <img src="https://img.shields.io/badge/AI--Powered-Ollama%20%7C%20NVIDIA%20NIM%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenAI-red?style=flat-square" alt="AI Support"/>
  <img src="https://img.shields.io/badge/Recon-Shuffledns%20%7C%20AlterX%20%7C%20DNSX%20%7C%20Naabu%20%7C%20HTTPX%20%7C%20FFUF%20%7C%20Gowitness-orange?style=flat-square" alt="Recon Toolchain"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL2-lightgrey?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/License-GPLv3-blue?style=flat-square" alt="License"/>
</p>

---

> [!WARNING]
> ### Project Status — Where It Actually Stands
> **Bounty Hunter — "Beast" — is under active development.** Here's an honest read of how it performs across the environments it's run against, so you know what to expect before you point it at anything:
>
> - **PortSwigger Web Security Academy labs** — solves them **autonomously, end to end**, across multiple vulnerability classes: password-reset poisoning via host-header injection, deleting a user through an exposed API-documentation endpoint, reflected / stored / DOM-based XSS (confirmed by firing a real `alert()` in a headless browser), CORS, and SSRF. Not just recon — the full exploit.
> - **Hardened & intentionally-vulnerable ranges** (HackTheBox, CTFHub, local hardened labs) — recon, foothold, and exploitation hold up well.
> - **Real, authorized bug-bounty programs** — strong at recon, scoping, and triage; it surfaces and verifies genuine issues. But it is **not yet "fire and forget"** on production targets — **review every finding before you rely on it or submit it.**
>
> What it reports is meant to be a *confirmed* bug, not a guess: XSS has to actually execute in a browser to be recorded, `verify_finding` runs class-specific live checks, and a dismissed false positive can't silently reappear. Use responsibly and strictly on authorized targets.

---

## What Is This?

**Bounty Hunter** (nickname **"Beast"**) is an **autonomous AI agent for bug bounty and penetration testing**, built by **Project Hellhound**. Give it a target and a goal in plain English — it runs the recon, finds *and exploits* the vulnerability, and writes a submission-ready report, all behind a scope gate that can't be bypassed. Built for bug-bounty hunters, pentesters, and CTF players.

**What makes it different:**

- **It exploits, not just scans.** It proves DOM and stored XSS by firing a real `alert()` in a headless browser, forges JWTs, and chains IDOR into account takeover — then runs a live `verify_finding` check before recording anything. You get confirmed bugs, not a wall of maybes.
- **It refuses to fabricate findings.** A "privileged access" or "solved" claim is rejected unless the captured HTTP responses actually back it. No hallucinated criticals, no reports that collapse at triage.
- **It remembers.** A persistent per-target blackboard (tokens, credentials, cookies, open ports, crawl trees, screenshots) under `~/.beast/targets/<target>/` lets hunts resume across sessions with no context loss.
- **Unconditional scope gate.** Every network call is scope-checked before a packet leaves; out-of-scope targets are blocked, always.
- **Free to run.** Works on free NVIDIA NIM credits, commercial APIs (Claude, Gemini, OpenAI), or fully offline via Ollama.

**Two ways to drive it:**

- **Interactive terminal** (`beast`) — a full-screen TUI with live streaming, collapsible tool cards, a findings browser, and a command palette.
- **Headless** (`beast -p "..."`) — one-line runs for scripts and CI pipelines.

---

## Proving Ground — Simulated Bounty Arena

<p align="center">
  <img src="Images/simulated-arena.svg" alt="Bounty Hunter simulated bounty arena scoreboard — $16,000 across 5 confirmed findings" width="100%"/>
</p>

> **What this is:** a controlled benchmark, not a real-world payout record. Bounty Hunter was run end-to-end against an **internal simulated bounty arena** — intentionally-vulnerable targets (e.g. a mock banking/storefront app) with a triage LLM acting as the program, validating each report and assigning a bounty. It's how we measure the thing the project cares about most: telling a *confirmed* bug apart from a false positive and capturing evidence strong enough to score. Every finding above was confirmed with real captured request/response evidence before it was awarded. Figures are simulated and do not represent real bug-bounty earnings.

---

## How It Works

```mermaid
flowchart TD
    U(["Researcher"]) --> CMD["/recon or /hunt &lt;target&gt;"]
    CMD --> ORC["Orchestrator role<br/>selects and runs tools<br/>(native function-calling)"]
    ORC --> GATE{{"Scope Security Gate<br/>unconditionally blocks out-of-scope<br/>before any traffic leaves"}}
    GATE -. verifies binaries .-> TOOLS["Toolchain check<br/>subfinder / dnsx / naabu / httpx<br/>gowitness / ffuf / sqlmap / subzy"]
    GATE == in scope ==> RECON["Active recon and exploitation<br/>86 scope-gated tools<br/>surgical HTTP, SPA spider, JS mining,<br/>injection, access-control, auth probes"]
    RECON --> LEDGER[("Non-prunable Artifact Ledger<br/>tokens, credentials, cookies,<br/>crawl trees, screenshots")]
    RECON --> VERIFY["Per-finding verification<br/>verify_finding then record_finding<br/>(evidence-gated)"]
    LEDGER --> VERIFY
    VERIFY --> REVERIFY["Pre-submission sweep<br/>reverify_findings<br/>(flags stale PoCs)"]
    SKILLS["30 methodology skills<br/>access-control, auth-bypass,<br/>web2, web3, mobile, CTF"] --> SYN
    REVERIFY --> SYN["Synthesizer role<br/>writes the researcher-facing report"]
    SYN --> REP["export_report<br/>submission-ready<br/>Markdown / JSON / HTML"]

    classDef gate fill:#3a0d0d,stroke:#ff4d4d,color:#ffd1d1;
    classDef store fill:#0d2a3a,stroke:#4db8ff,color:#d1ecff;
    class GATE gate;
    class LEDGER,REVERIFY store;
```

> **Orchestrator vs Synthesizer are ROLES, not model tiers.** Orchestrator calls select/run tools (native function-calling); Synthesizer calls write the researcher-facing prose at the end of a turn. Both can point at the SAME model — e.g. the recommended NVIDIA Nemotron 550B config below runs both roles on one model — or at two different ones if you want a cheap/fast model for tool selection and a stronger one for write-ups. Either way, the synthesizer call is always made with the same tool schema attached (just set to "don't call anything"), so it stays in a consistent tool-aware frame of reference for the whole turn rather than being dropped into a schema-free completion right after a history full of the orchestrator's own tool-call JSON.

- **Scope Security Gate**: Unscoped targets are unconditionally blocked before any active network traffic leaves your system.
- **Harvested Artifact Ledger**: Harvested credentials, tokens, session cookies, and delegation endpoints are automatically captured into a structured, non-prunable blackboard and pinned to every turn.
- **Missing Tool Grace**: External tool dependencies are verified on-demand—missing binaries trigger guided installation prompts rather than crashing.
- **Persistent Workspace State**: Target assets, screenshots, history, and extracted findings are stored automatically in isolated target workspaces.

---

## Installation & Setup

Everything you need to install, configure AI backends, and run Bounty Hunter in one unified workflow. The steps below cover the quick path — for more detail on any one piece (model routing options, Burp, or Caido), see the [step-by-step setup guides](docs/README.md).

### 1. Requirements & Prerequisites
- **Operating System**: Linux (Kali, Ubuntu, Debian, Arch, Parrot OS), macOS (Apple Silicon & Intel), or Windows (WSL2).
- **Python**: Version 3.10 or higher (Python 3.12 / 3.13 recommended).
- **Go**: Version 1.20+ (Required for ProjectDiscovery tools, Gowitness, and FFUF).
- **Git & Curl**: Required for installation and updates.

### 2. Fast Deploy (One-Line Pipe or Git Clone)

#### Option A: One-Line Remote Installer
```bash
curl -fsSL https://raw.githubusercontent.com/project-hellhound-org/bounty-hunter/main/install.sh | bash
```

#### Option B: Standard Git Clone
```bash
git clone https://github.com/project-hellhound-org/bounty-hunter.git
cd bounty-hunter
chmod +x install.sh
./install.sh
```

#### Reload Shell Environment
```bash
source ~/.bashrc   # or source ~/.zshrc
```

The automated installer will:
- Set up an isolated Python virtual environment at `~/.beast-env`.
- Mount the headless browser & Playwright SPA engine with all system dependencies.
- Verify and install the offensive toolchain (`gowitness`, `subfinder`, `httpx`, `dnsx`, `naabu`, `ffuf`, `alterx`, `tlsx`, `shuffledns`, `subzy`).
- Create a global `beast` command symlink.

---

### 3. AI Backend Configuration

Beast runs two roles — an **Orchestrator** (selects/runs tools) and a **Synthesizer** (writes the researcher-facing report). You point each at a model with `/model orchestrator <provider> <id>` and `/model synthesizer <provider> <id>` (or `/model both <provider> <id>` to set both at once). Pick a provider below.

> [!TIP]
> ### Which model should I use?
> - **Free (recommended):** **NVIDIA NIM** — one free API key works against *any* model it serves (`nvidia/nemotron-3-ultra-550b-a55b`, `meta/llama-3.3-70b-instruct`, …; browse current IDs at [build.nvidia.com/models](https://build.nvidia.com/models), NVIDIA periodically retires old ones). Generous free credits, frontier-class reasoning, zero local GPU.
> - **Paid:** Anthropic **Claude 3.5 Sonnet**, Google **Gemini 2.0 Flash / Pro**, or **OpenAI GPT-4o**.
> - **Local (Ollama):** 32B+ models (`qwen2.5:32b`, `deepseek-r1:32b`) — small local models under 14B struggle with multi-stage IDOR chaining and strict JSON tool-calling.

#### A. Free Cloud AI via NVIDIA NIM (Strongly Recommended for Free Users)
Get free API credits and frontier-class 120B model inference with zero local GPU requirements:
1. Sign up at [build.nvidia.com](https://build.nvidia.com/) to obtain your free API key.
2. Export your key in your environment or `~/.bashrc`:
```bash
export NVIDIA_API_KEY="nvapi-your-key-here"
```
3. Inside Bounty Hunter, select Nemotron or Llama 3.3:
```bash
beast
> /model orchestrator nvidia nvidia/nemotron-3-ultra-550b-a55b
> /model synthesizer nvidia nvidia/nemotron-3-ultra-550b-a55b
```

#### B. Commercial Frontier Cloud Providers (Claude, Gemini, OpenAI)
For researchers with commercial API access:
```bash
# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Google Gemini
export GEMINI_API_KEY="AIza..."

# OpenAI
export OPENAI_API_KEY="sk-..."
```

Inside the console:
```bash
> /model synthesizer anthropic claude-3-5-sonnet
> /model synthesizer gemini gemini-2.0-flash
```

Want the same model doing both the orchestrator and synthesizer job? You
don't need to run `/model` twice — `/model both <provider> <model-id>`
sets both tiers at once (e.g. `/model both nvidia nvidia/nemotron-3-ultra-550b-a55b`).
See [AI Model Setup](docs/ai-model-setup.md) for the full picture, including
per-tier splits and session-only overrides.

#### C. Fully Offline Local AI (Ollama)
For air-gapped or 100% offline environments (32B+ models recommended for reliable tool chaining):
```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull local model
ollama pull qwen2.5:32b-instruct-q4_0

# 3. Connect inside Bounty Hunter
beast
> /model orchestrator ollama qwen2.5:32b-instruct-q4_0
> /model synthesizer ollama qwen2.5:32b-instruct-q4_0
```

---

### 4. Burp Suite & Caido Integration (MCP)

Bounty Hunter can drive Burp Suite and/or Caido directly as additional
tools, alongside its own built-in recon arsenal. Both are configured
inside the console with one command each — no manual config editing:

```bash
beast
> /mcp burp http://127.0.0.1:9876   # auto-detects Burp's MCP transport
> /mcp caido http://localhost:8080  # uses caido-mcp-server if installed, else falls back to built-in GraphQL
> /mcp                              # shows current config + live status for both
> /mcp test                         # re-checks without changing anything
```

Full step-by-step guides (where to find Burp's MCP tab, getting Caido's
token or setting up `caido-mcp-server`'s OAuth login, and a troubleshooting
table for each): [Burp Suite MCP Setup](docs/mcp-burp-setup.md) ·
[Caido Setup](docs/mcp-caido-setup.md).

---

### 5. Health Check & Tool Verification
Verify that your environment, AI models, and binary tools are fully connected:
```bash
beast
> /setup
> /setup tools
```

To enable automatic on-demand installation of any missing tools during scans:
```bash
> /setup tools auto-install on
```

#### Third-party recon tool API keys
A few recon tools call external services that need their own free API key (separate from your LLM provider key above) — `/setup` shows exactly which ones are set and which aren't, with a signup link for each. Set any of them with:
```bash
> /setup set-key <tool> <api_key>
```
Every tool in the arsenal that needs one is self-describing this way — run `/setup` any time to see current status rather than hunting through docs for which key goes where.

---

## Quick Start

### 1. Interactive Terminal
Launch the interactive terminal console with live autocomplete and syntax highlighting:
```bash
beast
```

### 2. Headless CLI Automation
Run one-off prompts and scripted pipeline jobs directly:
```bash
# Scoped reconnaissance against a domain
beast -p "recon targetcorp.example"

# Say what you actually want done — the agent picks the right skill and
# recon depth (active vs. passive) itself, it isn't hardcoded off the domain name
beast -p "target is https://lab.ctfio.com and creds user:pass, takeover admin account"

# Direct slash command execution with JSON output
beast -p "/hunt target.com --json"
```

### 3. Never used it before? Your first hunt in 4 steps

No prior security tooling knowledge needed — you talk to it in plain English.

1. **Launch it** — type `beast`. You land in the interactive terminal.
2. **Point it at a target, in plain words** — no flags, no tool names:
   > `scan example.com for common web vulnerabilities`

   It sets the target, chooses how deep to go, and starts. *(Only ever test targets you're authorized to — see [Scope Policy](#scope-policy--legal-compliance) below.)*
3. **Watch it work** — long scans appear as live cards on the right. Press **`Ctrl+P`** any time to browse every command, **`Ctrl+F`** to see findings so far.
4. **Review what it found** — run `/report` for a self-contained HTML report. **Always read a finding before you trust or submit it.**

> **Working a real program with many in-scope domains?** Group them once: `/program create acme example.com,api.example.com`, then `/program select acme` to enter it and `/list` to see its hosts. Everything you do from then on is saved under that program.

For the full command reference, run `/help` inside the console (or `beast --help`). Not sure what a command does? Press **`Ctrl+P`** to fuzzy-search them all.

---

## Capabilities

Bounty Hunter coordinates **86 scope-gated tools** and **30 methodology skills**, both loaded on demand by the orchestrator — you rarely call anything by name.

- **Recon** — subdomain and DNS enumeration, port and TLS scanning, passive URL harvesting (Wayback, OTX, urlscan, VirusTotal), cloud-asset discovery, WAF fingerprinting.
- **Crawling** — SPA spider, katana, content and vhost fuzzing, JavaScript endpoint and secret mining.
- **Browser** — a persistent headless Playwright browser that runs real JS (how DOM and stored XSS are *proven*, not guessed), auth-flow capture/replay, and screenshots.
- **Exploitation** — SQLi, XSS, SSRF, SSTI, CORS, IDOR, JWT forgery, GraphQL introspection, mass-assignment, host-header injection, 403-bypass, and race conditions — each confirmed by a live `verify_finding` check.
- **Takeover & exposure** — dangling-CNAME subdomain takeovers, leaked API keys and bearer tokens, PII and internal-endpoint disclosure in client-side code and API responses.
- **Reporting** — evidence-backed finding records with pre-submission re-verification and self-contained HTML/Markdown export.

Everything runs behind the unconditional scope gate and rate limiter and writes to a per-target artifact ledger. For the exact live tool and skill list, run `/help` or just ask the agent (*"what tools do you have for X?"*).

---

## Recent Upgrades

Highlights of recent work (full history in [CHANGELOG.md](CHANGELOG.md)):

- **Solves PortSwigger labs end-to-end** — reset-poisoning via host-header injection, exposed-API-doc user deletion, reflected / stored / DOM XSS (real browser `alert()`), CORS.
- **Exploitation validation hardened** — XSS gated on real browser execution (a browser-disproved payload is refused, not recorded), `verify_finding` live class-checks, dismissed false positives can't silently re-appear, per-finding report splitting.
- **Tool-calling made robust** — native-function-calling-first across every provider; the reasoning-model preamble that used to truncate calls mid-JSON is disabled; a provably regex-free path on Claude.
- **Identity & session model** — `capture_identity`/`swap_session` and `save_auth_flow`/`replay_auth_flow`, bridged into the headless browser and the fuzzers.
- **Textual TUI** — full-screen console with clickable, collapsible request/response cards (classic REPL still available via `HELLHOUND_CLASSIC_UI=1`).
- **Codebase refactor** — the 20k-line `agent.py` is being split into focused `tools/` modules (one file per tool domain), each change gated by an AST import scan + smoke test.

---

## Roadmap — What's Next

The real gap between "runs tools well" and "hunts like a pro" is architecture, not more tools. Fuller reasoning in [CHANGELOG.md](CHANGELOG.md).

**Already landed** (was on this list, now shipped):
- Passive recon surface — Wayback, OTX, urlscan, `gau` → `nuclei`, and CT-log subdomain sweeps are live tools.
- Scriptable browser with record/replay of auth flows (`save_auth_flow` / `replay_auth_flow`) and live request observation.
- Native-function-calling tool execution across every provider.

**Open, in rough priority:**
1. **Browser request *interception*** — the browser already observes traffic; modifying or blocking requests mid-flight is what's left.
2. **Burp/Caido ↔ identity bridge** — push/pull live sessions through the already-integrated MCP tools.
3. **Passive → active fusion** — the passive tools exist; wiring their output *automatically* into the probing/fuzzing loop (dedup, JS sourcemap → secrets → endpoints → fuzzer) is the remaining glue.
4. **A playbook engine** — conditional branching workflows, not just sequential tool chaining.

---


## Scope Policy & Legal Compliance

Bounty Hunter is built strictly for **authorized security assessments, bug bounty programs, and educational CTF training environments**.
- The built-in Scope Security Gate refuses commands targeting assets outside your configured scope rules.
- Always obtain explicit written authorization before testing any target.
- Users are solely responsible for ensuring compliance with all applicable laws and program guidelines.

---

## License

This project is licensed under the [GNU General Public License v3 (GPLv3)](LICENSE). The "Hellhound"/"Bounty Hunter" name and logo are trademarks, separate from the code license — see [NOTICE](NOTICE) for what that does and doesn't mean for forks. Contributing (human or AI-assisted)? Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and point your AI coding assistant at [AGENTS.md](AGENTS.md) — a few rules (the scope gate above all) are non-negotiable regardless of how reasonable a change sounds.

---

## Author

<p align="center">
  <a href="https://l4zz3rj0d.github.io">
    <img src="https://img.shields.io/badge/Founder-L4ZZ3RJ0D-c0392b?style=for-the-badge" alt="L4ZZ3RJ0D"/>
  </a>
</p>