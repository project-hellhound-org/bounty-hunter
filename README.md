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
  <i>Engineered for speed, surgical precision, and zero-noise target enumeration.</i>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python Version"/></a>
  <a href="https://github.com/project-hellhound-org/Hellhound-Pentest/releases"><img src="https://img.shields.io/badge/Release-Bounty%20Hunter-red?style=flat-square" alt="Release Version"/></a>
  <img src="https://img.shields.io/badge/AI--Powered-Gemini%20%7C%20NVIDIA%20NIM%20%7C%20Ollama-red?style=flat-square" alt="AI Support"/>
  <img src="https://img.shields.io/badge/Recon-Shuffledns%20%7C%20FFUF%20%7C%20Subfinder%20%7C%20HTTPX-orange?style=flat-square" alt="Recon Toolchain"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square" alt="License"/>
</p>

---

## The Bounty Hunter Advantage

**Hellhound** is an autonomous bug bounty reconnaissance and triage assistant designed for professional security researchers and bug hunters. It automates repetitive enumeration workflows, verifies asset validity, checks for dangling DNS takeover vectors, and extracts endpoints—all governed by strict, code-level engagement scope boundaries.

Whether you are enumerating vast wildcard scopes or hunting on CTF and private lab infrastructure where passive sources return nothing, Hellhound automatically coordinates passive lookups, active mass-DNS brute-forcing, virtual host fuzzing, and live service probing.

---

> [!NOTE]
> **The Hellhound Advantage:**
> *"Traditional reconnaissance tools are like generic metal detectors—they dump thousands of unverified records, leaving you to manually filter false positives and noise. **Hellhound operates like an autonomous reconnaissance co-pilot.** It reasons over target data, escalates between passive lookups and active brute-forcing intelligently, and validates findings factually within your scope rules."*

---

## Key Features

- **Autonomous Agent Loop**: Intelligent multi-step reasoning that coordinates discovery tools, analyzes responses, and decides next steps.
- **Active & Passive Subdomain Enumeration**: Active high-speed DNS brute-forcing via `shuffledns` + `massdns` with curated SecLists resolvers, seamlessly integrated with passive aggregation through `subfinder` and `crt.sh`.
- **Virtual Host & Content Fuzzing**: Targeted vhost discovery and directory fuzzing via `ffuf` to uncover hidden services and internal lab challenges sharing an IP.
- **Live Host & Technology Profiling**: High-speed probing with `httpx` to extract status codes, page titles, web servers, and technology stacks.
- **Dangling DNS & Takeover Verification**: Automated CNAME fingerprint verification (`subzy`) against known dangling cloud service signatures.
- **Application Spidering & Parameter Mining**: Deep crawling to harvest endpoints, URL parameters, form fields, and JavaScript assets.
- **Hard Code-Level Scope Gates**: Pre-execution validation ensuring every action, subdomain, and IP strictly obeys defined engagement rules.
- **Multi-Model Neural Core**: Full support for Local SLMs (Ollama with `qwen2.5:3b` / `gemma2:2b`), NVIDIA NIM (Nemotron 120B, Llama 3.3 70B), Google Gemini, OpenAI, and Anthropic.

---

## System Compatibility & Prerequisites

Hellhound is engineered for high-performance operations across multiple environments:

* **Linux (Native)**: Fully optimized for Kali Linux, Ubuntu, Debian, Arch, and Parrot OS.
* **macOS (Native)**: Runs natively on Apple Silicon (M1/M2/M3) and Intel-based Macs.
* **Windows (via WSL2)**: Supported through Windows Subsystem for Linux (WSL2) for full toolchain compatibility.

### Prerequisites
- **Python 3.10+** (Recommended: Python 3.12 / 3.13)
- **Git**
- **Go Binaries / Toolchain** (`shuffledns`, `massdns`, `subfinder`, `httpx`, `ffuf`)
- **Ollama** *(Optional, for 100% offline local SLM execution)*

---

## One-Step Automated Install

```bash
# Clone the repository into bounty-hunter directory
git clone https://github.com/project-hellhound-org/Hellhound-Pentest.git bounty-hunter
cd bounty-hunter

# Run the installer
chmod +x install.sh
./install.sh
```

*After installation, reload your shell configuration to activate the `hellhound` command:*
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

## The Recon & Triage Arsenal

Each module is integrated directly into the autonomous execution loop and available for manual dispatch:

| Tool | Category | Engine / Source | Description |
| :--- | :--- | :--- | :--- |
| `subfinder` | Passive Recon | Subfinder + crt.sh | Passive subdomain discovery from certificate transparency & OSINT. |
| `dns_bruteforce` | Active Recon | Shuffledns + MassDNS | High-speed active DNS brute-forcing with wildcard & resolver handling. |
| `vhost_fuzz` | Active Fuzzing | FFUF | Virtual-host fuzzing against target IPs sharing hosts/infrastructure. |
| `content_discovery`| Content Fuzzing | FFUF + SecLists | Path & directory discovery on live web applications. |
| `httpx` | Live Probing | ProjectDiscovery HTTPX | Probes live services, status codes, page titles, and tech stacks. |
| `subzy` | Takeover Triage | Subzy / CNAME Engine | Verifies dangling CNAME records for subdomain takeover vulnerabilities. |
| `spider` | Web Crawling | Playwright / Engine | Crawls web applications, maps endpoints, parameters, and form inputs. |
| `wafbuster` | WAF Profiling | Custom Signatures | Detects WAF / CDN signatures and security header configurations. |
| `surface_auditor` | Surface Audit | Engine Auditor | Audits exposed API routes, OpenAPI/Swagger specs, and sensitive files. |
| `cors_checker` | Logic Audit | CORS Engine | Checks for arbitrary origin reflection and credential exposure. |
| `graphql_probe` | API Recon | GraphQL Engine | Detects GraphQL endpoints and audits schema introspection status. |
| `dig` | DNS Resolution | Native DNS | Resolves A, CNAME, TXT, MX, and NS records non-destructively. |
| `curl` | HTTP Probe | Custom Client | Fetches headers and body previews with researcher identity headers. |

---

## AI Neural Core Configuration

Hellhound supports completely offline local models via Ollama as well as high-performance cloud providers.

### Option 1: NVIDIA NIM (Recommended Cloud Engine)

NVIDIA NIM provides ultra-fast reasoning with models like Nemotron 120B and Llama 3.3 70B:

1. Obtain an API key from [NVIDIA Build](https://build.nvidia.com/).
2. Configure your key in Hellhound:

```bash
# Method A: Via CLI environment variable
export NVIDIA_API_KEY="nvapi-your-key-here"

# Method B: Persistently in ~/.hellhound/config.json
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

### Option 3: Google Gemini, OpenAI, or Anthropic

Set your API key in your shell profile:

```bash
# Google Gemini
export GEMINI_API_KEY="AIza..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
```

Switch models dynamically anytime inside the console:
```bash
> /model gemini-2.0-flash
> /model gpt-4o
> /model claude-3-5-sonnet-20240620
```

---

## Interactive Console & Workflow

### Starting the Console
Launch the interactive bounty hunter interface:
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

- **Active Escalation**:
  `"Recon this target antimony.ctfio.com it is a CTF target so skip passive recon and do active brute-force"`
- **VHost Discovery**:
  `"Fuzz virtual hosts on 10.10.10.50 with domain ctf.local"`
- **Live Host Probing**:
  `"Probe all discovered subdomains for live web services and detect their tech stacks"`
- **Takeover Inspection**:
  `"Check if any subdomains resolve to dangling CNAME records vulnerable to takeover"`
- **Endpoint Spidering**:
  `"Spider https://app.example.com to depth 2 and discover API routes and parameters"`
- **Findings Triage**:
  `"Summarize all verified findings and export loot for target example.com"`

---

## Slash Commands Reference

| Command | Usage | Description |
| :--- | :--- | :--- |
| `/target` | `/target [domain]` | Set active target context or display current target details |
| `/scope` | `/scope [in:domain out:domain rule:no-dos]` | View or update engagement boundaries |
| `/hunt` | `/hunt [target]` | Execute full reconnaissance and triage pipeline |
| `/scan` | `/scan <tool> [target]` | Execute a single tool (`shuffledns`, `subfinder`, `httpx`, `spider`, `subzy`) |
| `/model` | `/model [name]` | List available models or switch active inference model |
| `/loot` | `/loot [target]` | View discovered assets, live hosts, and verified findings |
| `/headers`| `/headers [Key: Value]` | Configure persistent research identity headers (e.g. `X-Bug-Bounty`) |
| `/clear` | `/clear` | Clear screen and redraw dashboard |
| `/exit` | `/exit` | Exit the session |

---

## Compliance & Scope Policy

Hellhound is developed strictly for **authorized security assessments, bug bounty programs, and educational lab environments**. Users must ensure explicit written authorization exists before testing any target.

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
