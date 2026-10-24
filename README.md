<p align="center">
  <img src="Images/hellhound.gif" alt="Hellhound Bounty Hunter Animation" width="100%"/>
</p>

<h1 align="center">HELLHOUND : BOUNTY HUNTER</h1>
<p align="center">
  <b>Autonomous AI Bug Bounty & Penetration Testing Framework by Project Hellhound</b>
  <br>
  <i>Target enumeration, two-tier neural reasoning, 30 methodology skills, persistent artifact blackboard, live SPA crawling, visual evidence capture, and zero-bypass scope guardrails — from recon to submission-ready report.</i>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#installation--setup">Installation & Setup</a> ·
  <a href="#two-tier-neural-routing">Two-Tier AI Routing</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#the-recon--triage-arsenal">Arsenal</a> ·
  <a href="#what-it-finds">What It Finds</a> ·
  <a href="#hunting-methodology-skills">Skills</a> ·
  <a href="#recent-upgrades">Recent Upgrades</a> ·
  <a href="#roadmap--whats-next">Roadmap</a> ·
  <a href="#license">License</a>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python Version"/></a>
  <a href="https://github.com/project-hellhound-org/bounty-hunter/releases"><img src="https://img.shields.io/badge/Release-v13.21-red?style=flat-square" alt="Release Version"/></a>
  <img src="https://img.shields.io/badge/AI--Powered-Ollama%20%7C%20NVIDIA%20NIM%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenAI-red?style=flat-square" alt="AI Support"/>
  <img src="https://img.shields.io/badge/Recon-Shuffledns%20%7C%20AlterX%20%7C%20DNSX%20%7C%20Naabu%20%7C%20HTTPX%20%7C%20FFUF%20%7C%20Gowitness-orange?style=flat-square" alt="Recon Toolchain"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL2-lightgrey?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/License-GPLv3-blue?style=flat-square" alt="License"/>
</p>

---

> [!WARNING]
> ### ⚠️ Project Status & Active Development Notice
> **Hellhound Bounty Hunter is currently under active development.** While it features automated multi-stage exploit chaining, two-tier neural routing, non-prunable artifact memory, and visual PoC verification, it is **not yet fully battle-tested on live production bug bounty targets**. Extensive testing and validation are actively ongoing across intentionally vulnerable CTF ranges (HackTheBox, CTFHub, PortSwigger Web Security Academy) and hardened local test environments. Use responsibly and strictly on authorized targets.

---

## What Is This?

**Bounty Hunter** is the autonomous bug bounty reconnaissance and vulnerability triage framework developed by **Project Hellhound**. Built for security researchers, penetration testers, and CTF practitioners, Bounty Hunter autonomously maps attack surfaces, verifies discovered assets, spiders dynamic Single Page Applications (SPAs) for hidden APIs and secrets, captures visual screenshot evidence via Gowitness, executes security audits through an unconditional scope gate, and writes submission-ready reports for HackerOne, Bugcrowd, and private engagements.

It features **persistent target memory and an automated artifact blackboard**—harvested tokens, credentials, session cookies, open ports, crawl trees, visual screenshots, and triage notes are automatically retained in isolated per-target workspaces (`~/.hellhound/targets/<target>/`) so hunts seamlessly resume across sessions without token loss or "lost-in-the-middle" reasoning drops.

Works across two flexible interfaces:
- **Interactive Terminal**: An interactive terminal environment with real-time token streaming, live progress feedback, and inline command autocompletion (`hellhound`).
- **Headless CLI Runner**: Direct one-line command execution for quick scripts and CI/CD pipelines (`hellhound -p "prompt"`).

---

## How It Works

```
You ──> /recon target.com ──> Orchestrator (Tool Selection) ──> Scope Security Gate
                                     │                            │ (Blocks out-of-scope)
                                     ▼                            ▼
                          Active Reconnaissance        Binary Toolchain Verification
                          ├─ Low-Noise Surgical HTTP   (Subfinder, DNSX, Naabu, HTTPX)
                          ├─ Shuffledns + AlterX       (Gowitness, FFUF, Subzy)
                          ├─ MassDNS + TLSX            (Native BAC & Logic Auditors)
                          └─ Headless SPA Spider      
                                     │
                                     ▼ (Populates Non-Prunable Artifact Ledger)
                          Synthesizer (Report Write-up) <── 30 Methodology Skills
                                     │                     (Access Control, Auth Bypass,
                                     ▼                      Web2, Web3, Mobile, CTF)
                                /report (Submission-ready markdown/JSON/HTML)
```

> **Orchestrator vs Synthesizer are ROLES, not model tiers.** Orchestrator calls select/run tools (native function-calling); Synthesizer calls write the researcher-facing prose at the end of a turn. Both can point at the SAME model — e.g. the recommended NVIDIA Nemotron 550B config below runs both roles on one model — or at two different ones if you want a cheap/fast model for tool selection and a stronger one for write-ups. Either way, the synthesizer call is always made with the same tool schema attached (just set to "don't call anything"), so it stays in a consistent tool-aware frame of reference for the whole turn rather than being dropped into a schema-free completion right after a history full of the orchestrator's own tool-call JSON.

- **Scope Security Gate**: Unscoped targets are unconditionally blocked before any active network traffic leaves your system.
- **Harvested Artifact Ledger**: Harvested credentials, tokens, session cookies, and delegation endpoints are automatically captured into a structured, non-prunable blackboard and pinned to every turn.
- **Missing Tool Grace**: External tool dependencies are verified on-demand—missing binaries trigger guided installation prompts rather than crashing.
- **Persistent Workspace State**: Target assets, screenshots, history, and extracted findings are stored automatically in isolated target workspaces.

---

## AI Model Routing & Recommended Providers

Autonomous vulnerability exploitation and multi-step attack chaining require models with high reasoning fidelity, reliable JSON tool execution, and complex state tracking.

> [!TIP]
> ### 💡 Recommended AI Providers (Free & Paid)
> - **For Free Users (Strongly Recommended)**: Use **NVIDIA NIM** (one free API key works against ANY model NIM serves — e.g. `nvidia/nemotron-3-ultra-550b-a55b` or `meta/llama-3.3-70b-instruct`; browse current model IDs at [build.nvidia.com/models](https://build.nvidia.com/models), NVIDIA periodically retires old ones). NVIDIA provides **generous free API credits** with access to massive frontier models, delivering high-speed inference and exceptional reasoning at zero cost.
> - **For Paid API Users**: Use **Anthropic Claude 3.5 Sonnet**, **Google Gemini 2.0 Flash / Pro**, or **OpenAI GPT-4o**.
> - **Local Models (Ollama)**: While supported for fully offline environments, small local models (SLMs under 14B) may struggle with nuanced multi-stage IDOR chaining and complex JSON schema adherence. For local setups, 32B+ models (e.g. `qwen2.5:32b` or `deepseek-r1:32b`) are recommended if hardware permits.

```bash
# Inspect active model routing status
> /model

# Configure NVIDIA NIM (Recommended Free Tier - Ultra Fast 120B Reasoning)
> /model orchestrator nvidia nvidia/nemotron-3-ultra-550b-a55b
> /model synthesizer nvidia nvidia/nemotron-3-ultra-550b-a55b
> # Any other NIM model ID works too — the same API key covers all of them:
> /model synthesizer nvidia <any-model-id-from-build.nvidia.com/models>

# Or configure Claude / Gemini for advanced cloud reasoning
> /model synthesizer anthropic claude-3-5-sonnet
> /model synthesizer gemini gemini-2.0-flash
```

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
- Set up an isolated Python virtual environment at `~/.hellhound-env`.
- Mount the headless browser & Playwright SPA engine with all system dependencies.
- Verify and install the offensive toolchain (`gowitness`, `subfinder`, `httpx`, `dnsx`, `naabu`, `ffuf`, `alterx`, `tlsx`, `shuffledns`, `subzy`).
- Create a global `hellhound` command symlink.

---

### 3. AI Backend Configuration

#### A. Free Cloud AI via NVIDIA NIM (Strongly Recommended for Free Users)
Get free API credits and frontier-class 120B model inference with zero local GPU requirements:
1. Sign up at [build.nvidia.com](https://build.nvidia.com/) to obtain your free API key.
2. Export your key in your environment or `~/.bashrc`:
```bash
export NVIDIA_API_KEY="nvapi-your-key-here"
```
3. Inside Bounty Hunter, select Nemotron or Llama 3.3:
```bash
hellhound
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
hellhound
> /model orchestrator ollama qwen2.5:32b-instruct-q4_0
> /model synthesizer ollama qwen2.5:32b-instruct-q4_0
```

---

### 4. Burp Suite & Caido Integration (MCP)

Bounty Hunter can drive Burp Suite and/or Caido directly as additional
tools, alongside its own built-in recon arsenal. Both are configured
inside the console with one command each — no manual config editing:

```bash
hellhound
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
hellhound
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
hellhound
```

### 2. Headless CLI Automation
Run one-off prompts and scripted pipeline jobs directly:
```bash
# Scoped reconnaissance against a domain
hellhound -p "recon targetcorp.example"

# Say what you actually want done — the agent picks the right skill and
# recon depth (active vs. passive) itself, it isn't hardcoded off the domain name
hellhound -p "target is https://lab.ctfio.com and creds user:pass, takeover admin account"

# Direct slash command execution with JSON output
hellhound -p "/hunt target.com --json"
```

---

## Commands

All actions can be triggered via slash commands or natural language:

### Core Slash Commands

| Command | Aliases | Description | Usage |
| :--- | :--- | :--- | :--- |
| `/recon` | `/surface`, `/spider` | Run scoped reconnaissance pipeline against target | `/recon <target> [--json]` |
| `/hunt` | `/auto` | Autonomous, scope-aware multi-stage hunt and triage | `/hunt [target] [--json]` |
| `/scan` | `/strike` | Execute a specific discovery or audit module | `/scan <module> [target] [key=val...]` |
| `/howl` | `/correlate`, `/graph` | Correlate discoveries or generate visual attack graph | `/howl [--graph] [target]` |
| `/scope` | `/rules` | View, clear, or configure program scope rules | `/scope [show \| clear \| <rules_text>]` |
| `/program` | `/programs`, `/engagement` | Group several in-scope domains of one engagement under a shared scope | `/program [show \| list \| create <name> [domains] \| add <domain...> \| scope <text>]` |
| `/output` | `/tail`, `/show-output` | Show the full captured output of the last long-running tool call | `/output [stderr] [N]` |
| `/skills` | `/skill` | Search or list loaded methodology skills & checklists | `/skills [query] [--json]` |
| `/model` | `/ai` | Inspect/switch active model for orchestrator/synthesizer | `/model [orchestrator\|synthesizer] <model-id>` |
| `/headers` | `/head` | Manage custom HTTP request & BugBounty identity headers | `/headers [Header: Value \| --clear]` |
| `/setup` | `/health`, `/doctor` | Check AI connectivity, tool dependencies & auto-install | `/setup [tools [auto-install on\|off]]` |
| `/report` | `/loot` | Generate structured bug bounty reconnaissance report | `/report [--format html\|json]` |
| `/ask` | `/chat` | Query co-pilot with session context and tool access | `/ask <question>` |
| `/help` | `/?` | Show all available slash commands and usage | `/help` |

---

## The Recon & Triage Arsenal

Bounty Hunter coordinates **57 tools** into a unified, scope-governed execution pipeline. Every tool is scope-gated and rate-limited where it matters, and the orchestrator picks the right one for the job — you rarely need to call one by name yourself.

| Category | Tools |
| :--- | :--- |
| **Passive & Active Recon** | `subfinder` `permute_subdomains` `resolve_candidates` `dns_bruteforce` `dig` `port_scan` `tls_cert_scan` `httpx` `nmap_service_scan` `wayback_urls` `gau_nuclei_sweep` `urlscan_recon` `google_dork` `otx_urls` `virustotal_lookup` `cloudscout` |
| **Crawling & Content Discovery** | `spider` `katana` `content_discovery` `fuzz_hunter` `vhost_fuzz` `403_bypass` `wafbuster` |
| **Visual & Browser** | `browser_control` `gowitness` |
| **Active Exploitation & Validation** | `sqlmap_scan` `hydra` `jwt_forge` `graphql_probe` `cors_checker` `generate_cors_poc` `schema_fuzzer` `waf_evasion_probe` `js_static_analysis` `jsluice` `punycode_homoglyphs` `transport_auditor` `surface_auditor` |
| **Takeover & Subdomain Health** | `takeover_scanner` `subzy` |
| **Session, Scope & Workspace** | `cookie_inspector` `curl` `run_terminal_command` `set_target` `manage_scope` `manage_program` `listener` |
| **HackerOne Program Intel** | `hackerone_policy` `hackerone_search` `hackerone_stats` |
| **Findings, Artifacts & Reporting** | `record_finding` `dismiss_finding` `export_report` `read_artifact` `save_file` `delete_file` `load_skill` |

Ask the agent itself ("what tools do you have for X?") for what any one of these actually does — asking beats a wall of description text here, and the answer always reflects the real, current tool list instead of a snapshot that can drift out of date.

---

## What It Finds

### 1. Attack Surface Discovery
- **Subdomains**: Passive OSINT (`subfinder`) -> Permutations (`alterx`) -> MassDNS brute-forcing (`shuffledns`) -> Candidate resolving (`dnsx`).
- **Infrastructure**: TLS/SAN extraction (`tlsx`), Virtual host fuzzing (`vhost_fuzz`), and open port mapping (`naabu`).
- **Web & SPA Attack Surface**: Deep SPA DOM rendering, background XHR/Fetch request interception, dynamic route discovery, OpenAPI/Swagger specifications, and GraphQL endpoints.
- **Visual Mapping**: Automated browser screenshots via `gowitness` indexed directly into the target workspace.

### 2. Vulnerability & Exposure Indicators
- **Broken Access Control & IDOR**: Direct object reference leaks in client-side state (`window.__INIT_PROFILE__`), authorization bypass via parameter swapping, and privilege escalation.
- **Authentication & Delegation Flaws**: Leaked auth tokens, impersonation handler bypasses, JWT algorithm confusion, and session fixation.
- **Dangling CNAME Takeovers**: Detection of orphaned DNS pointers to unclaimed S3 buckets, GitHub Pages, Azure services, and Heroku apps.
- **Sensitive Data & Secrets**: API keys, bearer tokens, PII leaks, internal endpoints, and CTF flag formats in client-side code and API responses.

---

## Hunting Methodology Skills

Bounty Hunter includes **30 specialized methodology skills**, loaded dynamically into the agent's reasoning context only when a turn actually needs one — not injected all at once.

| Category | Skills |
| :--- | :--- |
| **Access Control & Auth** | `access-control` `auth-bypass` `authentication` `idor` `credential-attack` `403-bypass` |
| **Web Vulnerability Classes** | `web2-vuln-classes` `xss` `ssrf` `ssti` `insecure-deserialization` `prototype-pollution-mass-assignment` `server-side-parameter-pollution` `cors-misconfig` `race-condition` |
| **Recon & Methodology** | `web2-recon` `bb-methodology` `bug-bounty` `exposed-source-recon` `argus` `security-arsenal` `graphql-audit` |
| **Specialized Targets** | `web3-audit` `meme-coin-audit` `mobile-pentest` `client-reverse` `cicd-security` `llm-prompt-injection` |
| **Validation & Reporting** | `triage-validation` `report-writing` |

Search skills anytime inside the console:
```bash
> /skills auth
> /skills ctf
> /skills graphql
```

---

## Recent Upgrades

A few things landed recently that materially change how the agent feels to run:

- **Real-time fuzzer output** — `ffuf` and `feroxbuster` now stream actual hit lines live as they're found (`[301] /admin`, `[200] /robots.txt`, ...), the same live-feed feel as the spider crawl, instead of a static "still running" placeholder for the whole scan.
- **Configurable rate limiting** — every fuzzing run (`content_discovery`, `vhost_fuzz`, `fuzz_hunter`) is capped at a sane requests/sec by default (`fuzz_rate_limit` in config, 150 by default) so an aggressive scan doesn't trip a WAF or lock out an account on a live target. Override per-call with `rate_limit`, or set it to `0` to go uncapped on a disposable lab/CTF box.
- **`/output`** — pull the complete stdout/stderr of the last tool run on demand. In-memory only, nothing extra written to disk.
- **`/program`** — group several in-scope domains of one engagement under a shared scope: create a program, set in/out-of-scope rules once, every attached domain inherits them. Entirely optional, never forced on a plain `/target` call, and switching between domains across different programs mid-session just works via `/target <domain>` — no restart needed.
- **Cleaner `/help`** — no longer dumps all 30 skill descriptions into the main command listing; that lives at `/skills` (or `/help skills`) instead.
- **`katana` + `jsluice`** added to the arsenal, for faster crawling and JS secret/endpoint extraction.
- **Correctness fixes** — no more duplicated "still running" spinner lines; a successful login with valid, given credentials is no longer auto-recorded as a finding; related hosts named up front (e.g. an OAuth/IdP server needed for legitimate auth testing) can be pre-authorized into scope in one shot instead of tripping the scope gate mid-flow.

---

## Roadmap — What's Next

The honest gap between "runs tools well" and "hunts like a pro" is architecture, not more tools. Rough priority order for what's next:

1. **Persistent, scriptable browser** — record an auth flow once (login → 2FA → token capture), replay it headless; programmatic DOM read/write; request/response interception; multi-tab sessions for cross-user IDOR testing.
2. **Unified session state** — one cookie jar shared by the browser, `curl`, `fuzz_hunter`, `sqlmap_scan`, `hydra`, and Burp/Caido, so logging in once is inherited everywhere instead of manually copying headers across tools. *(Smallest, highest-leverage piece of this — see below.)*
3. **Intelligent request/response correlation** — spider output auto-parameterized and fed to the fuzzer by param type (ID, email, file, JSON); built-in response diffing against a baseline; endpoints auto-grouped by function (auth, payments, admin).
4. **Real race/logic testing** — single-packet / last-byte synced requests across endpoints with configurable jitter, automatic state-mutation detection, multi-context coordinated race attacks.
5. **Cross-session campaign memory** — target profiles (tech stack, WAF behavior, rate limits, quirks) and structured finding templates that survive past one context window, not just chat history.
6. **Stealth/evasion as a first-class profile** — UA/TLS-fingerprint/IP rotation, WAF-fingerprint-driven bypass selection, distributed scan coordination with deduped results.
7. **Validation over detection** — auto-extract one row on a confirmed SQLi, render XSS in a headless browser to confirm it actually executes, verify SSRF reaches an internal endpoint, confirm BOLA actually crosses accounts — not just "the request went through."
8. **Report-ready evidence capture** — request/response pairs, screenshots, and curl repros auto-assembled per finding; finding-chaining (e.g. "XSS on /profile + IDOR on /api/user/{id} = account takeover").
9. **Passive → active intel fusion** — CT logs + Wayback + gau + OTX deduped straight into `httpx`/fuzzing; JS sourcemap recovery → secret extraction → endpoint mapping, fed straight back into the fuzzer.
10. **A real playbook engine** — conditional branching workflows ("new subdomain → screenshot → tech-detect → if WordPress, run X"), not just sequential tool chaining.

**Next concrete step:** item 2's easy win — a single `CookieJar` per target, shared between `browser_control` and `curl` (~50 lines of backend glue) — turns "browser for auth, curl for the API" into one continuous session instead of manual cookie hand-offs between tools.

---

## Scope Policy & Legal Compliance

Bounty Hunter is built strictly for **authorized security assessments, bug bounty programs, and educational CTF training environments**.
- The built-in Scope Security Gate refuses commands targeting assets outside your configured scope rules.
- Always obtain explicit written authorization before testing any target.
- Users are solely responsible for ensuring compliance with all applicable laws and program guidelines.

---

## License

This project is licensed under the [GNU General Public License v3 (GPLv3)](LICENSE).

---

## Author

<p align="center">
  <a href="https://l4zz3rj0d.github.io">
    <img src="https://img.shields.io/badge/Founder-L4ZZ3RJ0D-c0392b?style=for-the-badge" alt="L4ZZ3RJ0D"/>
  </a>
</p>