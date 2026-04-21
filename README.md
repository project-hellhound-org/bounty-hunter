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
  <a href="https://github.com/l4zz3rj0d/Hellhound-Pentest/releases"><img src="https://img.shields.io/badge/Release-v12.5.0-red?style=flat-square" alt="Release Version"/></a>
  <img src="https://img.shields.io/badge/AI--Agnostic-OpenAI%20%7C%20Anthropic%20%7C%20Gemini-red?style=flat-square" alt="AI Support"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square" alt="License"/>
  <a href="https://github.com/l4zz3rj0d/Hellhound-Pentest/stargazers"><img src="https://img.shields.io/github/stars/l4zz3rj0d/Hellhound-Pentest?style=flat-square&color=yellow" alt="Stars"/></a>
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

## Installation & Setup

### Prerequisites
- **Python 3.10+** (Recommended: 3.13)
- **Git**
- **Playwright Dependencies** (Automated during install)

### One-Step Automated Install
```bash
# Clone the repository
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest

# Run the professional installer
chmod +x install.sh
./install.sh
```
*After installation, restart your terminal or run `source ~/.bashrc` to activate the `hellhound` command.*

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
| **Recon** | `Spider`, `SurfaceAuditor`, `WAFbuster`, `GraphQL`, `CORSbuster`, `FUZZhunter`, `JWTanalyzer` | Deep surface mapping and service discovery. |
| **Vulnerability Audit** | `XSStrike`, `SQLIdetector`, `SSRFdetector`, `XXEdetector`, `IDORdetector`, `LFIauditor`, `RBAC` | Targeted vulnerability identification and logic auditing. |
| **Intelligence** | `SecretScanner`, `TechProfiler`, `SourceAuditor`, `CloudScout`, `BlobUnpacker` | Harvesting sensitive data and infrastructure intelligence. |
| **Analysis & Exploitation** | `Exmap`, `Hydra`, `CMDinj` | Universal exploitation matrix and parameter orchestration. |

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

## Compliance & Usage
Hellhound is developed strictly for **authorized security assessments**. This software is licensed under the **GNU General Public License v3 (GPLv3)**. Usage must comply with all applicable local, national, and international laws.

**Developer**: [l4zz3rj0d](https://github.com/l4zz3rj0d)  
**License**: GPLv3
