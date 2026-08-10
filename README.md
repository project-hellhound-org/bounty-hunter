<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound Bounty Hunter" width="100%"/>
</p>

<h1 align="center">HELLHOUND BOUNTY HUNTER</h1>
<h1 align="center">Autonomous AI Recon & Triage Framework</h1>

<p align="center">
  <b>High-performance autonomous bug bounty reconnaissance and triage assistant with integrated neural intelligence.</b>
  <br>
  <br>
  <code style="color: #ff2244; font-weight: bold;">[ UNDER ACTIVE DEVELOPMENT ]</code>
  <br>
  <i>Drop a target. Define your scope. Let the neural co-pilot hunt.</i>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python Version"/></a>
  <a href="https://github.com/project-hellhound-org/bounty-hunter/releases"><img src="https://img.shields.io/badge/Release-v13.21-red?style=flat-square" alt="Release Version"/></a>
  <img src="https://img.shields.io/badge/AI--Powered-Gemini%20%7C%20NVIDIA%20NIM%20%7C%20Ollama%20%7C%20Claude-red?style=flat-square" alt="AI Support"/>
  <img src="https://img.shields.io/badge/Recon-Shuffledns%20%7C%20AlterX%20%7C%20DNSX%20%7C%20Naabu%20%7C%20HTTPX%20%7C%20FFUF%20%7C%20TLSX-orange?style=flat-square" alt="Recon Toolchain"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL2-lightgrey?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square" alt="License"/>
</p>

---

## The Bounty Hunter Advantage

**Hellhound** is an autonomous reconnaissance and triage framework engineered for bug bounty hunters, penetration testers, and CTF researchers. It automates high-speed target enumeration, asset verification, subdomain mutation generation, live service fingerprinting, port scanning, dangling DNS takeover checks, and SPA crawling—all governed by strict, code-level engagement scope boundaries.

Traditional tools dump thousands of unverified records, forcing you to waste hours filtering noise. Hellhound operates as an **autonomous reconnaissance co-pilot**: it reasons over target data, escalates between passive lookups and active brute-forcing intelligently, validates findings factually, and persists all intelligence in isolated per-target workspaces.

---

> [!NOTE]
> **The Hellhound Advantage:**
> *"Traditional reconnaissance tools are like generic metal detectors—they dump thousands of unverified records, leaving you to manually filter false positives and noise. **Hellhound operates like an autonomous reconnaissance co-pilot.** It reasons over target data, escalates between passive lookups and active brute-forcing intelligently, and validates findings factually within your scope rules."*

---

## What It Does

Hellhound unifies a dual-engine architecture:

1. **High-Performance Binary Pipeline**: High-speed active DNS brute-forcing (`shuffledns` + `massdns`), subdomain permutation (`alterx`), bulk resolving (`dnsx`), port scanning (`naabu`), TLS/SAN inspection (`tlsx`), vhost/content fuzzing (`ffuf`), and service probing (`httpx`).
2. **Universal Headless SPA Spider**: An integrated crawler powered by asynchronous HTTP workers and headless Chromium (`playwright`/`patchright`) that intercepts live background XHR/fetch calls, forms, query parameters, JS routes, secrets, and CTF flags.
3. **Neural Reasoning Core**: Seamlessly integrates local offline SLMs (`qwen2.5:3b`, `gemma2:2b` via Ollama) and cloud inference (NVIDIA NIM Nemotron/Llama-3.3, Google Gemini, Anthropic Claude, OpenAI) to plan and execute multi-step recon strategies.
4. **Hard Code-Level Scope Enforcement**: Pre-execution scope gate (`is_in_scope`) guarantees that no packets leave your machine targeting out-of-scope assets or wildcard-violating domains.

---

## The Recon & Triage Arsenal

Each module is integrated directly into the autonomous execution loop and available for manual dispatch:

| Tool | Category | Engine / Binary | Description |
| :--- | :--- | :--- | :--- |
| `subfinder` | Passive Recon | ProjectDiscovery Subfinder + crt.sh | Passive subdomain discovery from certificate transparency & OSINT APIs. |
| `dns_bruteforce` | Active Recon | Shuffledns + MassDNS | High-speed active DNS brute-forcing with wildcard handling and custom resolvers. |
| `permute_subdomains` | Speculative Recon | AlterX | Subdomain permutation and mutation generation from discovered assets. |
| `resolve_candidates` | Bulk Resolution | DNSX | Bulk-resolves candidate wordlists and permutations with CNAME & A tracking. |
| `port_scan` | Network Recon | Naabu | Active TCP/UDP port scanning across top ports (`top-100`, `top-1000`, `full`) or custom ranges. |
| `httpx` | Live Probing | ProjectDiscovery HTTPX | Probes live services, status codes, content-lengths, redirects (`location`), page titles, and tech stacks. |
| `tls_cert_scan` | TLS / SAN Recon | TLSX | Inspects TLS/SSL certificates to extract Subject Alternative Names (SANs) and Common Names (CNs). |
| `vhost_fuzz` | Active Fuzzing | FFUF | Virtual-host fuzzing against target IPs sharing hosts and internal infrastructure. |
| `content_discovery` | Content Fuzzing | FFUF + SecLists | Active path and directory discovery fuzzing on live web applications. |
| `subzy` | Takeover Triage | Subzy / CNAME Engine | Verifies dangling CNAME records against known cloud takeover signatures. |
| `spider` | Web Crawling | Hellhound Spider (v13.21) | Dual-engine crawler (Async HTTP + Headless Chromium SPA) mapping endpoints, parameters, and secrets. |
| `wafbuster` | WAF Profiling | Custom Signature Matrix | Detects WAF / CDN signatures (Cloudflare, AWS WAF, Akamai) and security headers. |
| `surface_auditor` | Surface Audit | Native Engine Auditor | Audits exposed API routes, OpenAPI/Swagger specs, `.well-known` endpoints, and sensitive files. |
| `cors_checker` | Logic Audit | CORS Engine | Active CORS audit for arbitrary origin reflection and credential exposure. |
| `graphql_probe` | API Recon | GraphQL Engine | Detects GraphQL endpoints and audits schema introspection status. |
| `dig` | DNS Resolution | Native DNS | Non-destructive DNS queries for A, CNAME, TXT, MX, and NS records. |
| `curl` | HTTP Probe | Custom Client | Fetches headers and body previews with researcher identity headers. |

---

## What Gets Found

### Discovery Vectors
- **Subdomain Pipelines**: Passive OSINT & CT logs (`subfinder`, `crt.sh`) → Alteration permutations (`alterx`) → Mass-DNS verification (`dnsx`) → Wildcard filtering (`shuffledns`).
- **Infrastructure Discovery**: TLS/SSL SAN parsing (`tlsx`), Virtual host fuzzing (`vhost_fuzz`), open port mapping (`naabu`).
- **Web & API Attack Surface**: Full HTML crawling, live SPA XHR/Fetch interception, robots.txt & sitemap XML index recursion, `.well-known` discovery (OIDC/JWKS), OpenAPI/Swagger endpoints, GraphQL schema introspection.
- **Parameter & Asset Mining**: Form fields (hidden, file, required), JS fetch/axios body keys, query parameters, dynamic runtime template strings (`/api/${id}`), and orphan parameters.
- **Vulnerability Indicators**: Dangling CNAME takeovers, CORS reflection misconfigurations, exposed secrets & API keys, WAF/CDN signatures, and CTF flag formats.

---

## System Compatibility & Prerequisites

Hellhound is engineered for high performance across all major operating systems:

* **Linux (Native)**: Fully optimized for Kali Linux, Ubuntu, Debian, Arch, and Parrot OS.
* **macOS (Native)**: Runs natively on Apple Silicon (M1/M2/M3/M4) and Intel-based Macs.
* **Windows (via WSL2)**: Fully supported through Windows Subsystem for Linux (WSL2).

### Prerequisites
- **Python 3.10+** (Recommended: Python 3.12 / 3.13)
- **Git**
- **Go Binaries / Toolchain** (`shuffledns`, `massdns`, `subfinder`, `alterx`, `dnsx`, `naabu`, `httpx`, `tlsx`, `ffuf`)
- **Ollama** *(Optional, for 100% offline local SLM execution)*

---

## One-Step Automated Install

```bash
# Clone repository
git clone https://github.com/project-hellhound-org/bounty-hunter.git
cd bounty-hunter

# Run installer
chmod +x install.sh
./install.sh
```

*After installation, reload your shell configuration:*
```bash
source ~/.bashrc   # or source ~/.zshrc
```

### Manual / Virtual Environment Installation

```bash
cd bounty-hunter
python3 -m venv ~/.hellhound-env
source ~/.hellhound-env/bin/activate
pip install --upgrade pip
pip install -e .
playwright install chromium
playwright install-deps chromium
```

---

## AI Neural Core Configuration

Hellhound supports completely offline local models via Ollama as well as high-performance cloud providers.

### Option 1: NVIDIA NIM (Recommended Cloud Engine)

NVIDIA NIM provides ultra-fast reasoning with Nemotron and Llama models:

```bash
# Set your API key
export NVIDIA_API_KEY="nvapi-your-key-here"

# Launch Hellhound and select NIM model
hellhound
> /model nvidia/nemotron-3-super-120b-a12b
```

Supported NVIDIA models:
- `nvidia/nemotron-3-super-120b-a12b` *(Default NIM Model)*
- `meta/llama-3.3-70b-instruct`
- `meta/llama-3.1-70b-instruct`
- `deepseek-ai/deepseek-r1`

---

### Option 2: Ollama (Local SLM — 100% Offline)

For private, offline operation without API keys or external data transfer:

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull the recommended local SLM
ollama pull qwen2.5:3b-instruct-q4_0
# or
ollama pull gemma2:2b

# 3. Launch Hellhound with the local model
hellhound
> /model qwen2.5:3b-instruct-q4_0
```

---

### Option 3: Google Gemini, Anthropic Claude, or OpenAI

Set your API key in your shell environment:

```bash
# Google Gemini
export GEMINI_API_KEY="AIza..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-..."
```

Switch models dynamically inside the console:
```bash
> /model gemini-2.0-flash
> /model claude-3-5-sonnet-20240620
> /model gpt-4o
```

---

## Interactive Console & Workflow

### Starting the Console
```bash
hellhound
```

### 1. Setting Scope & Target
Define target domain and authorized boundaries before launching tools:
```bash
# Set target domain
> /target example.com

# Define in-scope assets, wildcards, and exclusions
> /scope in:example.com,*.example.com out:dev.example.com rule:no-dos
```

### 2. Conversational Recon & Natural Language Execution
Prompt Hellhound naturally—the agent autonomously decides tool chains and escalations:

- **Active CTF / Lab Escalation**:
  `"Recon this target topaz.ctfio.com it is a CTF target so skip passive recon and do active brute-force"`
- **Permutations & Bulk Resolution**:
  `"Generate subdomain mutations from discovered subdomains and resolve them with dnsx"`
- **Port Scanning & Service Fingerprinting**:
  `"Scan top 100 ports on all resolved hosts with naabu, then probe live web services with httpx"`
- **TLS Certificate Discovery**:
  `"Inspect TLS certificates on example.com and extract all Subject Alternative Names (SANs)"`
- **VHost Discovery**:
  `"Fuzz virtual hosts on 10.10.10.50 with base domain ctf.local"`
- **Endpoint & SPA Spidering**:
  `"Spider https://app.example.com to depth 3 with deep SPA mode to capture background API calls"`
- **Findings Triage & Loot**:
  `"Summarize all verified findings and export loot for target example.com"`

---

## Slash Commands Reference

| Command | Usage | Description |
| :--- | :--- | :--- |
| `/target` | `/target [domain]` | Set active target context or display current target details |
| `/scope` | `/scope [in:domain out:domain rule:no-dos]` | View or update engagement boundaries and restrictions |
| `/hunt` | `/hunt [target]` | Execute full autonomous reconnaissance and triage pipeline |
| `/scan` | `/scan <tool> [target]` | Execute a single tool (`shuffledns`, `subfinder`, `httpx`, `spider`, `naabu`, `dnsx`, etc.) |
| `/model` | `/model [name]` | List available models or switch active inference model |
| `/loot` | `/loot [target]` | View discovered assets, live hosts, open ports, and verified findings |
| `/headers` | `/headers [Key: Value]` | Configure persistent research identity headers (e.g. `X-Bug-Bounty: handle`) |
| `/clear` | `/clear` | Clear screen and redraw dashboard |
| `/exit` | `/exit` | Exit the session |

---

## Output Formats & Target Storage

Target findings, state, and reports are persisted in isolated workspaces under `~/.hellhound/targets/<target_name>/`:

- **`task.json`** — Complete target state, in-scope rules, discovered subdomains, open ports, live web hosts, and triage notes.
- **`spider_report.json`** — Detailed crawl graph with mapped endpoints, query parameters, forms, and detected secrets.
- **Export Options**: Export loot in `JSON`, `CSV`, `Burp XML`, `JSONL`, `URLs`, and `Nuclei` formats.

---

## Compliance & Scope Policy

Hellhound is developed strictly for **authorized security assessments, bug bounty programs, and educational CTF lab environments**. Users must ensure explicit written authorization exists before testing any target.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

## Author

<p align="center">
  <a href="https://l4zz3rj0d.github.io">
    <img src="https://img.shields.io/badge/Founder-L4ZZ3RJ0D-c0392b?style=for-the-badge" alt="L4ZZ3RJ0D"/>
  </a>
</p>
