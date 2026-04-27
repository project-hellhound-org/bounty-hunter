<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="100%"/>
</p>

<h1 align="center">HELLHOUND v12.5</h1>
<h1 align="center">Apex-King Pentest Framework</h1>

<p align="center">
  <b>High-performance modular web offensive framework with Zero-Config AI Intelligence.</b>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.13-blue?style=flat-square&logo=python&logoColor=white" alt="Python Version"/></a>
  <a href="https://github.com/project-hellhound-org/Hellhound-Pentest/releases"><img src="https://img.shields.io/badge/Release-v12.5.0-red?style=flat-square" alt="Release Version"/></a>
  <img src="https://img.shields.io/badge/AI--Agnostic-OpenAI%20%7C%20Anthropic%20%7C%20Gemini-red?style=flat-square" alt="AI Support"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square" alt="License"/>
  <a href="https://github.com/project-hellhound-org/Hellhound-Pentest/stargazers"><img src="https://img.shields.io/github/stars/project-hellhound-org/Hellhound-Pentest?style=flat-square&color=yellow" alt="Stars"/></a>
</p>

---

## The Apex-King of Web Offense

**Hellhound** is a high-fidelity security framework engineered for professional web application assessments. Engineered for speed and surgical precision, version 12.5 introduces the **Apex-King AI Core**, enabling intelligent attack-chain correlation, automated context-aware verification, and a robust arsenal of modular security auditors.

Whether you're performing surface reconnaissance or deep logical vulnerability analysis, Hellhound provides a unified console to manage your entire offensive pipeline.

---

## Key Features

- **Cinematic HUD**: Ultra-wide 60-character Braille-wave status dashboard with real-time pulsing case-waves.
- **Technical Fidelity**: Automated terminal synchronization ensures clean logs even during high-volume vulnerability testing.
- **Zero-Config AI Intelligence**: Instant integration with Gemini, OpenAI, and Anthropic for vulnerability confirmation and exploit generation.
- **Asynchronous Native**: Built from the ground up on `aiohttp` and `playwright` for lightning-fast multi-target analysis.
- **Modular Arsenal**: 30+ specialized modules covering Recon, Vuln, Intel, and Exploitation.
- **Integrated OOB**: Built-in Out-of-Band (OOB) server support for detecting blind vulnerabilities (SSRF, XXE, SQLi).
- **Universal Rendering Engine**: Full SPA/JavaScript support via Playwright-powered technology profiling and spidering.
- **Seamless Upgrades**: Keep your framework updated with a single `hellhound upgrade` command.

---

### System Compatibility
Hellhound is engineered for high-performance offensive operations across multiple environments:

*   **Linux (Native)**: Fully optimized for Kali Linux, Ubuntu, Debian, Arch, and Parrot OS. Version 12.6 introduces a hardened installer specifically for Kali's `t64` package architecture.
*   **macOS (Native)**: Runs natively on Apple Silicon (M1/M2/M3) and Intel-based Macs.
*   **Windows (via WSL2)**: Supported through Windows Subsystem for Linux (WSL2). This is the recommended way to run Hellhound on Windows to ensure full tool compatibility and performance.

### Prerequisites
- **Python 3.10+** (Recommended: 3.13)
- **Git**
- **Playwright Dependencies** (Automated via `install.sh`)

### One-Step Automated Install
```bash
# Clone the repository
git clone https://github.com/project-hellhound-org/Hellhound-Pentest.git
cd Hellhound-Pentest

# Run the professional installer
chmod +x install.sh
./install.sh
```
*After installation, restart your terminal or run `source ~/.bashrc` to activate the `hellhound` command. Windows users should run these commands within their WSL2 terminal.*

### Keeping Hellhound Updated
Hellhound features a professional self-update mechanism:
```bash
# From your terminal
hellhound upgrade

# Or from within the Hellhound console
hellhound > upgrade
```

---

## The Arsenal

Hellhound's power lies in its modularity. Each module is optimized for high high-fidelity results with minimal false positives.

| Category | Modules | Description |
| :--- | :--- | :--- |
| **Recon** | `Spider`, `SurfaceAuditor`, `TransportAuditor`, `WAFbuster`, `GraphQL`, `CORSbuster`, `FUZZhunter` | Deep surface mapping and service discovery. |
| **Vulnerability Audit** | `XSStrike`, `SQLIdetector`, `SSRFdetector`, `XXEdetector`, `IDORdetector`, `LFIauditor`, `RBAC` | Targeted vulnerability identification and logic auditing. |
| **Intelligence** | `SecretScanner`, `TechProfiler`, `SourceAuditor`, `CloudScout`, `BlobUnpacker` | Harvesting sensitive data and infrastructure intelligence. |
| **Analysis & Exploitation** | `Exmap`, `Hydra`, `CMDinj` | Universal exploitation matrix and parameter orchestration. |

---

## ◓ Recent Updates (v12.5.1)

- **Consolidated Transport Security**: `CookieAuditor` and `HeaderAuditor` have been merged into the new **`TransportAuditor`** for unified SSL/TLS, HSTS, and session security analysis.
- **Spider v12.3**: Integrated high-fidelity standalone recon engine with full SPA support, suppressed CLI noise for cleaner console operations, and automated risk scoring.
- **Improved Scoping**: `Stalk` and legacy auditors have been deprecated in favor of the enhanced `Spider` + `SurfaceAuditor` reconnaissance pipeline.
- **Hardened Dependencies**: Automated fallback for BeautifulSoup parsers (`lxml` -> `html.parser`) to ensure stability across all environments.

---

## Getting Started

Launch the framework console from any directory:
```bash
hellhound
```

### Initial Configuration
Setup your AI provider and OOB listener for maximum impact:
```bash
# 1. Connect AI Intelligence (e.g. Gemini)
hellhound > setg ai_key <your_api_key>

# 2. Start OOB Listener
hellhound > oob start
```

### Core Operational Workflow
```bash
# 1. Acquire Target
hellhound > prey https://target-app.com --cookie "session=..."

# 2. Map Attack Surface
hellhound [Spider] > strike

# 3. High-Fidelity Audit
hellhound [XSStrike] > strike      # Advanced XSS audit
hellhound [IDORdetector] > strike  # Logical scoping audit

# 4. Intelligence Synthesis
hellhound > howl                   # AI Attack-Chain Correlation
```

---

## Documentation
For deep-dives into framework architecture, module logic, and detection signatures, visit:
- [Architecture Guide](ARCHITECTURE.md)
- [Module Scaffolding](scaffold_module.py)

---

---

## Compliance & Usage
Hellhound is developed strictly for **authorized security assessments**. This software is licensed under the **GNU General Public License v3 (GPLv3)**. Usage must comply with all applicable local, national, and international laws.



## Author

<a href="https://l4zz3rj0d.github.io">
  <img src="https://img.shields.io/badge/Founder-Sree%20Danush%20S%20(L4ZZ3RJ0D)-c0392b?style=for-the-badge" alt="Sree Danush S (L4ZZ3RJ0D)"/>
</a>