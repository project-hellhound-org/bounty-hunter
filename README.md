<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound Bounty Hunter" width="100%"/>
</p>

<h1 align="center">HELLHOUND : BOUNTY HUNTER</h1>
<p align="center">
  <b>Autonomous AI Bug Bounty & Penetration Testing Framework by Project Hellhound</b>
  <br>
  <i>Target enumeration, two-tier neural reasoning, 26 methodology skills, persistent artifact blackboard, live SPA crawling, visual evidence capture, and zero-bypass scope guardrails — from recon to submission-ready report.</i>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#installation--setup">Installation & Setup</a> ·
  <a href="#two-tier-neural-routing">Two-Tier AI Routing</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#the-recon--triage-arsenal">Arsenal</a> ·
  <a href="#what-it-finds">What It Finds</a> ·
  <a href="#hunting-methodology-skills">Skills</a> ·
  <a href="#desktop-gui-app">Desktop GUI</a> ·
  <a href="#license">License</a>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python Version"/></a>
  <a href="https://github.com/project-hellhound-org/bounty-hunter/releases"><img src="https://img.shields.io/badge/Release-v12.6.0-red?style=flat-square" alt="Release Version"/></a>
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

Works across three flexible interfaces:
- **Interactive Terminal**: An interactive terminal environment with real-time token streaming, live progress feedback, and inline command autocompletion (`hellhound`).
- **Headless CLI Runner**: Direct one-line command execution for quick scripts and CI/CD pipelines (`hellhound -p "prompt"`).
- **Desktop GUI Application**: A dedicated Electron/React desktop application with persistent target management, topology graphs, live findings drawers, and visual screenshot proof (`hellhound --gui`).

---

## How It Works

```
You ──> /recon target.com ──> Orchestrator (Fast SLM) ──> Scope Security Gate
                                     │                            │ (Blocks out-of-scope)
                                     ▼                            ▼
                          Active Reconnaissance        Binary Toolchain Verification
                          ├─ Low-Noise Surgical HTTP   (Subfinder, DNSX, Naabu, HTTPX)
                          ├─ Shuffledns + AlterX       (Gowitness, FFUF, Subzy)
                          ├─ MassDNS + TLSX            (Native BAC & Logic Auditors)
                          └─ Headless SPA Spider      
                                     │
                                     ▼ (Populates Non-Prunable Artifact Ledger)
                          Synthesizer (Reasoning LLM) <── 26 Methodology Skills
                                     │                     (Access Control, Auth Bypass,
                                     ▼                      Web2, Web3, Mobile, CTF)
                                /report (Submission-ready markdown/JSON/HTML)
```

- **Scope Security Gate**: Unscoped targets are unconditionally blocked before any active network traffic leaves your system.
- **Harvested Artifact Ledger**: Harvested credentials, tokens, session cookies, and delegation endpoints are automatically captured into a structured, non-prunable blackboard and pinned to every turn.
- **Missing Tool Grace**: External tool dependencies are verified on-demand—missing binaries trigger guided installation prompts rather than crashing.
- **Persistent Workspace State**: Target assets, screenshots, history, and extracted findings are stored automatically in isolated target workspaces.

---

## AI Model Routing & Recommended Providers

Autonomous vulnerability exploitation and multi-step attack chaining require models with high reasoning fidelity, reliable JSON tool execution, and complex state tracking.

> [!TIP]
> ### 💡 Recommended AI Providers (Free & Paid)
> - **For Free Users (Strongly Recommended)**: Use **NVIDIA NIM** (`nvidia/nemotron-3-super-120b-a12b` or `meta/llama-3.3-70b-instruct`). NVIDIA provides **generous free API credits** with access to massive 70B–120B frontier models, delivering high-speed inference and exceptional reasoning at zero cost.
> - **For Paid API Users**: Use **Anthropic Claude 3.5 Sonnet**, **Google Gemini 2.0 Flash / Pro**, or **OpenAI GPT-4o**.
> - **Local Models (Ollama)**: While supported for fully offline environments, small local models (SLMs under 14B) may struggle with nuanced multi-stage IDOR chaining and complex JSON schema adherence. For local setups, 32B+ models (e.g. `qwen2.5:32b` or `deepseek-r1:32b`) are recommended if hardware permits.

```bash
# Inspect active model routing status
> /model

# Configure NVIDIA NIM (Recommended Free Tier - Ultra Fast 120B Reasoning)
> /model orchestrator nvidia nvidia/nemotron-3-super-120b-a12b
> /model synthesizer nvidia nvidia/nemotron-3-super-120b-a12b

# Or configure Claude / Gemini for advanced cloud reasoning
> /model synthesizer anthropic claude-3-5-sonnet
> /model synthesizer gemini gemini-2.0-flash
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
> /model orchestrator nvidia nvidia/nemotron-3-super-120b-a12b
> /model synthesizer nvidia nvidia/nemotron-3-super-120b-a12b
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

# Automated CTF/lab active enumeration and takeover
hellhound -p "target is https://lab.ctfio.com and creds user:pass, takeover admin account"

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
| `curl` | Surgical Probing | Native HTTP Engine | Low-noise HTTP requests, route harvesting, and automatic session state tracking. |
| `spider` | SPA Crawling | Headless SPA Engine | Intercepts dynamic background XHR/Fetch calls, forms, query params, and embedded JS state. |
| `gowitness` | Visual Recon | Gowitness | High-fidelity headless screenshot capture & visual evidence indexing into target workspace. |
| `subfinder` | Passive OSINT | ProjectDiscovery Subfinder | Passive subdomain harvesting from certificate transparency logs and APIs. |
| `dns_bruteforce` | Active Recon | Shuffledns + MassDNS | High-speed active DNS brute-forcing with wildcard handling and custom resolvers. |
| `permute_subdomains`| Speculative Recon | AlterX | Subdomain permutation and mutation generation from discovered assets. |
| `resolve_candidates`| Bulk DNS | DNSX | Multi-threaded candidate resolution with CNAME, A, AAAA, and wildcard filtering. |
| `port_scan` | Network Recon | Naabu | High-performance port scanning across top ports (`top-100`, `top-1000`, `full`). |
| `httpx` | Live Probing | ProjectDiscovery HTTPX | Probes live services, status codes, tech stacks, redirects, and titles. |
| `tls_cert_scan` | TLS Inspection | TLSX | Extracts Subject Alternative Names (SANs) and certificate chains. |
| `vhost_fuzz` | Active Fuzzing | FFUF | Virtual-host fuzzing on target IPs with custom host header routing. |
| `content_discovery` | Path Discovery | FFUF + SecLists | Active path and endpoint discovery on live web applications. |
| `fuzz_hunter` | Smart Fuzzing | FUZZhunter Engine | Deep recursive path fuzzing with dynamic 404 similarity baseline calibration. |
| `subzy` | Takeover Triage | Subzy / CNAME Engine | Verifies dangling CNAME records against cloud takeover signatures. |
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
- **Broken Access Control & IDOR**: Direct object reference leaks in client-side state (`window.__INIT_PROFILE__`), authorization bypass via parameter swapping, and privilege escalation.
- **Authentication & Delegation Flaws**: Leaked auth tokens, impersonation handler bypasses, JWT algorithm confusion, and session fixation.
- **Dangling CNAME Takeovers**: Detection of orphaned DNS pointers to unclaimed S3 buckets, GitHub Pages, Azure services, and Heroku apps.
- **Sensitive Data & Secrets**: API keys, bearer tokens, PII leaks, internal endpoints, and CTF flag formats in client-side code and API responses.

---

## Hunting Methodology Skills

Bounty Hunter includes **26 specialized methodology skills** loaded dynamically into the agent reasoning context:

| Skill | Category | Description |
| :--- | :--- | :--- |
| `access-control` | Access Control | IDOR, Broken Object-Level Authorization, and privilege escalation mechanics. |
| `auth-bypass` | Auth Bypass | Leaked delegation tokens, impersonation chaining, and session hijacking. |
| `authentication` | Authentication | OAuth, JWT, 2FA/MFA, password recovery, and session token auditing. |
| `bb-methodology` | Core Mindset | Systematic 5-phase bug bounty workflow and session discipline. |
| `bug-bounty` | Master Playbook | End-to-end bug bounty lifecycle orchestration and triage tracking. |
| `ctf-lab-recon` | CTF & Labs | Active enumeration doctrine for HTB, THM, and isolated training ranges. |
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
| `exposed-source-recon` | Source Code | Git dumps, `.env` leakage, source map recovery, and hardcoded secrets. |
| `insecure-deserialization` | Deserialization | Python Pickle, PHP serialization, and Java gadget chain exploitation. |
| `llm-prompt-injection` | AI Security | Indirect prompt injection, system prompt extraction, and guardrail bypass. |
| `prototype-pollution-mass-assignment`| JS & Object Flaws | JavaScript prototype pollution, object merge flaws, and HTTP mass assignment. |
| `race-condition` | Concurrency | Limit-overrun, balance exhaustion, TOCTOU flaws, and parallel request probing. |
| `ssrf` | SSRF | Server-Side Request Forgery, cloud metadata extraction, and internal network pivots. |
| `ssti` | Template Injection | Server-Side Template Injection across Jinja2, Twig, Freemarker, and Mako. |
| `argus` | Threat Intel | Deep intelligence correlation and entity relationship graphing. |

Search skills anytime inside the console:
```bash
> /skills auth
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
- **Live Thinking Drawer**: Real-time inspection of the AI co-pilot's tool-selection rationale and artifact ledger.
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
