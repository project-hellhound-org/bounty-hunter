<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound Bounty Hunter" width="100%"/>
</p>

<h1 align="center">HELLHOUND : BOUNTY HUNTER</h1>
<p align="center">
  <b>Autonomous AI Bug Bounty Framework by Project Hellhound</b>
  <br>
  <i>Target enumeration, two-tier neural reasoning, 16 methodology skills, live SPA crawling, visual evidence capture, and zero-bypass scope guardrails — from recon to submission-ready report.</i>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#installation--setup">Installation & Setup</a> ·
  <a href="#two-tier-model-routing">Two-Tier AI Routing</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#the-recon--triage-arsenal">Arsenal</a> ·
  <a href="#what-it-finds">What It Finds</a> ·
  <a href="#hunting-methodology-skills">Skills</a> ·
  <a href="#desktop-gui-app">Desktop GUI</a> ·
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

## What Is This?

**Bounty Hunter** is the autonomous bug bounty reconnaissance and vulnerability triage framework developed by **Project Hellhound**. Built for security researchers, penetration testers, and CTF practitioners, Bounty Hunter autonomously maps attack surfaces, verifies discovered assets, spiders dynamic Single Page Applications (SPAs) for hidden APIs and secrets, captures visual screenshot evidence via Gowitness, executes security audits through an unconditional scope gate, and writes submission-ready reports for HackerOne, Bugcrowd, and private engagements.

It features persistent target memory—assets, open ports, crawl trees, visual screenshots, and triage notes are automatically retained in isolated per-target workspaces (`~/.hellhound/targets/<target>/`) so hunts seamlessly resume across sessions.

Works across three flexible interfaces:
- **Interactive Terminal**: An interactive terminal environment with real-time feedback and inline command autocompletion (`hellhound`).
- **Headless CLI Runner**: Direct one-line command execution for quick scripts and pipelines (`hellhound -p "prompt"`).
- **Desktop GUI Application**: A dedicated desktop application with persistent target management, topology graphs, and a live findings drawer (`hellhound --gui`).

---

## How It Works

```
You ──> /recon target.com ──> Orchestrator (Fast SLM) ──> Scope Security Gate
                                     │                            │ (Blocks out-of-scope)
                                     ▼                            ▼
                          Active Reconnaissance        Binary Toolchain Verification
                          ├─ Shuffledns + AlterX       (Subfinder, DNSX, Naabu, HTTPX)
                          ├─ MassDNS + TLSX            (Gowitness, FFUF, Subzy)
                          └─ Headless SPA Spider      
                                     │
                                     ▼
                          Synthesizer (Reasoning LLM) <── 16 Methodology Skills
                                     │                     (CTF, Web2, GraphQL, Web3)
                                     ▼
                                /report (Submission-ready markdown/JSON/HTML)
```

- **Scope Security Gate**: Unscoped targets are unconditionally blocked before any active network traffic leaves your system.
- **Missing Tool Grace**: External tool dependencies are verified on-demand—missing binaries trigger guided installation prompts rather than crashing.
- **Persistent Workspace State**: Target assets, screenshots, history, and extracted findings are stored automatically in isolated target workspaces.

---

## Two-Tier Model Routing

Bounty Hunter eliminates LLM latency bottlenecks by decoupling real-time tool selection from deep vulnerability synthesis:

1. **Orchestrator Tier (Fast & Local)**: An ultra-fast local model (e.g. Ollama `qwen2.5:3b-instruct` or Groq) handles rapid, iterative tool-selection decisions with zero reasoning lag.
2. **Synthesizer Tier (Deep Reasoning LLM)**: A high-parameter reasoning model (NVIDIA NIM `nemotron-3-super`, Anthropic `claude-3-5-sonnet`, Google `gemini-2.0-flash`, or OpenAI `gpt-4o`) executes upon completing recon passes to correlate discoveries, apply methodology checklists, and format the final triage report.

```bash
# Inspect active two-tier routing status
> /model

# Set local orchestrator (tool selection)
> /model orchestrator ollama qwen2.5:3b-instruct-q4_0

# Set cloud synthesizer (deep analysis & reporting)
> /model synthesizer nvidia nvidia/nemotron-3-super-120b-a12b
```

---

## Installation & Setup

Everything you need to install, configure AI backends, and run Bounty Hunter in one unified workflow.

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
- Create global symlinks and desktop launcher integrations (`hellhound`, `hellhound --gui`).

---

### 3. AI Backend Configuration

Bounty Hunter supports both **100% zero-cost offline local models** and **high-capacity cloud reasoning providers**.

#### A. Zero-Cost Offline Local AI (Ollama)
Run completely offline without any API keys or network leakage:
```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull recommended local models
ollama pull qwen2.5:3b-instruct-q4_0    # ~2GB — fast orchestrator (tool caller)
ollama pull mistral:7b                  # ~4GB — local synthesizer (report generator)

# 3. Connect inside Bounty Hunter
hellhound
> /model orchestrator ollama qwen2.5:3b-instruct-q4_0
> /model synthesizer ollama mistral:7b
```

#### B. Cloud AI Providers (NVIDIA NIM, Claude, Gemini, OpenAI)
For state-of-the-art reasoning on complex vulnerability chains, export your API key:
```bash
# NVIDIA NIM (Ultra-fast inference — Recommended)
export NVIDIA_API_KEY="nvapi-your-key-here"

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Google Gemini
export GEMINI_API_KEY="AIza..."

# OpenAI
export OPENAI_API_KEY="sk-..."
```

Inside the console, bind the synthesizer model:
```bash
> /model synthesizer nvidia/nemotron-3-super-120b-a12b
> /model synthesizer anthropic claude-3-5-sonnet
> /model synthesizer gemini gemini-2.0-flash
```

---

### 4. Health Check & Tool Verification
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

# Automated CTF/lab active enumeration
hellhound -p "recon topaz.ctfio.com, it is a CTF target"

# Direct slash command execution with JSON output
hellhound -p "/hunt target.com --json"
```

### 3. Native Desktop GUI App
Launch the desktop application with target workspace switcher and live visual drawers:
```bash
hellhound --gui
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
| `/skills` | `/skill` | Search or list loaded methodology skills & checklists | `/skills [query] [--json]` |
| `/model` | `/ai` | Inspect/switch active model for orchestrator/synthesizer | `/model [orchestrator\|synthesizer] <model-id>` |
| `/headers` | `/head` | Manage custom HTTP request & BugBounty identity headers | `/headers [Header: Value \| --clear]` |
| `/setup` | `/health`, `/doctor` | Check AI connectivity, tool dependencies & auto-install | `/setup [tools [auto-install on\|off]]` |
| `/report` | `/loot` | Generate structured bug bounty reconnaissance report | `/report [--format html\|json]` |
| `/ask` | `/chat` | Query co-pilot with session context and tool access | `/ask <question>` |
| `/help` | `/?` | Show all available slash commands and usage | `/help` |

---

## The Recon & Triage Arsenal

Bounty Hunter coordinates specialized security tooling into a unified, scope-governed execution pipeline:

| Module | Category | Binary / Engine | Description |
| :--- | :--- | :--- | :--- |
| `subfinder` | Passive OSINT | ProjectDiscovery Subfinder | Passive subdomain harvesting from certificate transparency logs and APIs. |
| `dns_bruteforce` | Active Recon | Shuffledns + MassDNS | High-speed active DNS brute-forcing with wildcard handling and custom resolvers. |
| `permute_subdomains`| Speculative Recon | AlterX | Subdomain permutation and mutation generation from discovered assets. |
| `resolve_candidates`| Bulk DNS | DNSX | Multi-threaded candidate resolution with CNAME, A, AAAA, and wildcard filtering. |
| `port_scan` | Network Recon | Naabu | High-performance port scanning across top ports (`top-100`, `top-1000`, `full`). |
| `httpx` | Live Probing | ProjectDiscovery HTTPX | Probes live services, status codes, tech stacks, redirects, and titles. |
| `tls_cert_scan` | TLS Inspection | TLSX | Extracts Subject Alternative Names (SANs) and certificate chains. |
| `gowitness` | Visual Recon | Gowitness | High-fidelity headless screenshot capture & visual evidence indexing into target workspace. |
| `vhost_fuzz` | Active Fuzzing | FFUF | Virtual-host fuzzing on target IPs with custom host header routing. |
| `content_discovery` | Path Discovery | FFUF + SecLists | Active path and endpoint discovery on live web applications. |
| `fuzz_hunter` | Smart Fuzzing | FUZZhunter Engine | Deep recursive path fuzzing with dynamic 404 similarity baseline calibration. |
| `subzy` | Takeover Triage | Subzy / CNAME Engine | Verifies dangling CNAME records against cloud takeover signatures. |
| `spider` | SPA Crawling | Headless SPA Engine | Intercepts dynamic background XHR/Fetch calls, forms, query params, and secrets. |
| `wafbuster` | WAF Profiling | Signature Matrix | Detects WAF / CDN signatures (Cloudflare, AWS WAF, Akamai) and headers. |
| `surface_auditor` | Surface Audit | Native Engine Auditor | Audits OpenAPI/Swagger specs, `.well-known` endpoints, and sensitive files. |
| `cors_checker` | Logic Audit | CORS Engine | Active CORS audit for arbitrary origin reflection and credential exposure. |
| `graphql_probe` | API Recon | GraphQL Engine | Detects GraphQL endpoints and audits schema introspection status. |
| `hydra` | Logic & BAC | Hydra Engine | Multi-engine differential mutation probe for broken access control & parameter anomalies. |
| `cloudscout` | Cloud Assets | CloudScout Engine | Discovers and verifies public AWS S3, Azure Blob, GCP, and Firebase buckets. |
| `transport_auditor` | Transport Audit | SSL/TLS & Cookie Engine| Audits TLS ciphers, HSTS enforcement, and cookie security flags (HttpOnly/Secure/SameSite). |
| `hackerone_search` | Threat Intel | Hacktivity Engine | Retrieves disclosed HackerOne reports and program policy scopes. |

---

## What It Finds

### 1. Attack Surface Discovery
- **Subdomains**: Passive OSINT (`subfinder`) -> Permutations (`alterx`) -> MassDNS brute-forcing (`shuffledns`) -> Candidate resolving (`dnsx`).
- **Infrastructure**: TLS/SAN extraction (`tlsx`), Virtual host fuzzing (`vhost_fuzz`), and open port mapping (`naabu`).
- **Web & SPA Attack Surface**: Deep SPA DOM rendering, background XHR/Fetch request interception, dynamic route discovery, OpenAPI/Swagger specifications, and GraphQL endpoints.
- **Visual Mapping**: Automated browser screenshots via `gowitness` indexed directly into the target workspace.

### 2. Vulnerability & Exposure Indicators
- **Dangling CNAME Takeovers**: Detection of orphaned DNS pointers to unclaimed S3 buckets, GitHub Pages, Azure services, and Heroku apps.
- **Authentication & Logic**: Broken access controls, parameter-sensitive endpoints, CORS origin reflection misconfigurations.
- **Sensitive Data & Secrets**: API keys, bearer tokens, PII leaks, internal endpoints, and CTF flag formats in client-side code and API responses.

---

## Hunting Methodology Skills

Bounty Hunter includes **16 specialized methodology skills** loaded dynamically into the agent reasoning context:

| Skill | Category | Description |
| :--- | :--- | :--- |
| `ctf-lab-recon` | CTF & Labs | Active enumeration doctrine for HTB, THM, and isolated training ranges. |
| `bb-methodology` | Core Mindset | Systematic 5-phase bug bounty workflow and session discipline. |
| `web2-recon` | Surface Mapping | Comprehensive subdomain enumeration, port scanning, and live service mapping. |
| `web2-vuln-classes`| Vulnerability Rules | In-depth heuristics for IDOR, SSRF, SQLi, XSS, SSTI, and OAuth flaws. |
| `security-arsenal` | Payloads & Bypasses | Curated payload lists, filter bypasses, and WAF evasion techniques. |
| `triage-validation`| Quality Gate | Strict finding validation to eliminate false positives before reporting. |
| `report-writing` | Submissions | Formatted templates for HackerOne, Bugcrowd, Intigriti, and Immunefi. |
| `graphql-audit` | API Security | Introspection queries, batching attacks, and field suggestion exploitation. |
| `web3-audit` | Smart Contracts | EVM / Solidity vulnerability patterns, reentrancy, and flash loan attacks. |
| `meme-coin-audit` | Token Security | Liquidity pool manipulation, honeypot detection, and bonding curve flaws. |
| `mobile-pentest` | Mobile Security | Android/iOS static analysis, deep-link routing, and certificate pinning bypasses. |
| `cicd-security` | Pipeline Security | GitHub Actions / GitLab CI misconfigurations, secret leakage, and runner abuse. |
| `credential-attack`| Identity Recon | Password spray strategies, username enumeration, and credential auditing. |
| `client-reverse` | Reverse Eng | Request-signing analysis and anti-bot token de-obfuscation. |
| `argus` | Threat Intel | Deep intelligence correlation and entity relationship graphing. |
| `bug-bounty` | Master Playbook | End-to-end bug bounty lifecycle orchestration and triage tracking. |

Search skills anytime inside the console:
```bash
> /skills ctf
> /skills graphql
```

---

## Desktop GUI App

Bounty Hunter includes a native desktop interface:

```bash
hellhound --gui
```

- **Target-Archive Sidebar**: Switch between targets or spin up new target workspaces instantly.
- **Live Thinking Drawer**: Real-time inspection of the AI co-pilot's tool-selection rationale.
- **Instant Slash Palette**: Execute `/recon`, `/hunt`, `/model`, and `/report` directly with UI feedback.
- **Findings & Evidence Pane**: Tabbed view of discovered subdomains, live hosts, open ports, visual screenshots, and extracted loot.

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

