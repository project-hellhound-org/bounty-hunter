<p align="center">
  <img src="Images/logo.png" alt="Hellhound Bounty Hunter" width="160"/>
</p>

# HELLHOUND BOUNTY HUNTER
### Autonomous AI Bug Bounty Reconnaissance & Triage Assistant

Hellhound is an autonomous reconnaissance and finding triage assistant built for bug bounty hunters and security researchers. It automates repetitive enumeration workflows, verifies asset validity, checks for dangling DNS takeover vectors, and extracts endpoints—all governed by strict, code-level engagement scope boundaries.

---

## Overview

Modern bug bounty workflows require significant manual coordination across various reconnaissance utilities. Hellhound unifies these tasks into an autonomous reasoning loop driven by local SLMs or cloud LLMs.

### Core Capabilities

- **Subdomain Discovery**: Active high-speed DNS brute-forcing via `shuffledns` + SecLists, and passive aggregation through `subfinder` and certificate transparency (`crt.sh`).
- **Live Host and Technology Profiling**: High-speed probing with `httpx` to extract status codes, page titles, web servers, and technology stacks.
- **Takeover Verification**: Verifying dangling DNS records and CNAME fingerprints (`subzy`) against known service signatures.
- **Deep Endpoint Discovery**: Spidering and parameter extraction to map application endpoints, query keys, and hidden form fields.
- **Configuration & Surface Audits**: Non-destructive inspections for CORS misconfigurations, WAF signatures, and GraphQL introspection.
- **Hard Scope Enforcement**: Hard pre-execution validation ensuring all operations stay strictly within defined scope boundaries.

---

## Technical Specifications

| Component | Detail |
| :--- | :--- |
| **Interface** | Claude Code-style interactive chat HUD with instant slash command dispatch |
| **Execution Architecture** | Multi-iteration autonomous agent with tool dispatch and state persistence |
| **Active DNS Engine** | `shuffledns` + `massdns` with curated SecLists resolvers/wordlists |
| **Passive Recon Engine** | `subfinder` + `crt.sh` Certificate Transparency API |
| **HTTP Inspection** | `httpx` + custom lightweight connection pool |
| **AI Inference Options** | NVIDIA NIM, Ollama (Local SLM), OpenAI, Google Gemini, Anthropic |
| **State Storage** | `~/.hellhound/targets/<target>/task.json` |

---

## Installation & Setup

### System Prerequisites

- **OS**: Linux (Debian, Ubuntu, Kali, Parrot, Arch), macOS, or Windows via WSL2
- **Python**: Version 3.10 or newer (Python 3.12 / 3.13 recommended)
- **Optional Binaries**: `shuffledns`, `massdns`, `subfinder`, `httpx`, `seclists`

### Automated Installation

Run the automated installer from the project root:

```bash
git clone https://github.com/project-hellhound-org/Hellhound-Pentest.git
cd Hellhound-Pentest
chmod +x install.sh
./install.sh
```

After installation completes, reload your shell configuration:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

### Manual / Virtual Environment Installation

If you prefer manual setup in an isolated environment:

```bash
python3 -m venv ~/.hellhound-env
source ~/.hellhound-env/bin/activate
pip install --upgrade pip
pip install -e .
playwright install chromium
playwright install-deps chromium
```

---

## AI Configuration

Hellhound supports completely offline local models via Ollama as well as high-performance cloud providers.

### Option 1: NVIDIA NIM (Recommended Cloud Engine)

NVIDIA NIM provides high throughput reasoning with models like Nemotron 120B and Llama 3.3 70B.

1. Obtain an API key from [NVIDIA Build](https://build.nvidia.com/).
2. Configure your key in Hellhound:

```bash
# Method A: Via CLI environment variable
export NVIDIA_API_KEY="nvapi-your-key-here"

# Method B: Persistently in ~/.hellhound/config.json
# Run hellhound and enter:
> /model nvidia/nemotron-3-super-120b-a12b
```

Supported NVIDIA models:
- `nvidia/nemotron-3-super-120b-a12b` (Default NIM Model)
- `meta/llama-3.3-70b-instruct`
- `meta/llama-3.1-70b-instruct`
- `deepseek-ai/deepseek-r1`

---

### Option 2: Ollama (Local SLM — 100% Offline)

For private, offline operation without API keys or external data transfer:

1. Install Ollama:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

2. Pull the recommended local SLM:
```bash
ollama pull qwen2.5:3b-instruct-q4_0
# or
ollama pull gemma2:2b
```

3. Select your local model in Hellhound:
```bash
hellhound
> /model qwen2.5:3b-instruct-q4_0
```

---

### Option 3: OpenAI, Google Gemini, or Anthropic

Set the appropriate environment variable in your shell profile:

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Google Gemini
export GEMINI_API_KEY="AIza..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
```

Switch models at any time within the chat prompt:
```bash
> /model gpt-4o
> /model gemini-2.0-flash
> /model claude-3-5-sonnet-20240620
```

---

## Usage Guide

### Starting the Console

Launch the interactive interface:

```bash
hellhound
```

---

### Defining Scope

Engagement scope rules can be set before running reconnaissance. The scope guard validates all targets prior to any tool execution:

```bash
# Set target domain
> /target example.com

# Define in-scope assets, wildcards, and exclusions
> /scope in:example.com,*.example.com out:dev.example.com rule:no-dos
```

---

### Interactive Natural Language Execution

You can prompt Hellhound directly in natural language:

- **Active Enumeration**:
  `"Recon target example.com with active DNS brute-forcing only"`
- **Live Host Discovery**:
  `"Probe all discovered subdomains for live web services and detect their tech stacks"`
- **Takeover Inspection**:
  `"Check if any subdomains resolve to dangling CNAME records vulnerable to takeover"`
- **Application Spidering**:
  `"Spider https://app.example.com to depth 2 and discover API endpoints and parameters"`
- **Triage & Reporting**:
  `"Summarize all verified findings and export loot for target example.com"`

---

### Slash Commands Reference

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

## Ethical Use & Scope Policy

Hellhound is designed exclusively for **authorized security testing, bug bounty programs, and educational environments**. Users must ensure explicit written authorization exists before testing any target.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
