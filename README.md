<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="600"/>
</p>
<h1 align="center">HELLHOUND v12.5</h1>
<h1 align="center">Apex-King Pentest Framework</h1>
<p align="center">
  High-performance modular web offensive framework with Zero-Config AI Intelligence.
</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI--Agnostic-OpenAI%20%7C%20Anthropic%20%7C%20Gemini-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/architecture-Modular%20%7C%20AI--Powered-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

---

## The Apex-King of Web Offense

Hellhound is a professional-grade security framework designed for high-fidelity web application assessments. Engineered for speed and precision, version 12.5 integrates the **Apex-King AI Core**, enabling intelligent attack-chain correlation alongside a robust, rule-based hunting arsenal.

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Git
- Internet connectivity (for initial browser and AI setup)

### One-Step Automated Install
Run the installation script from the project root. This will create a dedicated virtual environment and register the `hellhound` command alias.

```bash
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
chmod +x install.sh
./install.sh
```

After installation, restart your terminal or run `source ~/.bashrc` (or `~/.zshrc`) to activate the command.

---

## Getting Started

Launch the framework console from any directory:
```bash
hellhound
```

### Initial Configuration
Before starting an assessment, it is recommended to configure your AI provider and Out-of-Band (OOB) listener.

```bash
# 1. Connect AI Intelligence (Gemini/OpenAI/Anthropic)
hellhound > setg ai_key <your_api_key>

# 2. Start OOB Listener (for blind detection)
hellhound > oob start
```

### Core Operational Workflow
Getting from target acquisition to actionable intel:

```bash
# 1. Acquire Target
hellhound > prey https://target-app.com

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
For detailed technical specifications, internal logic, and detection matrices, see the [Architecture Guide](ARCHITECTURE.md).

---

## Compliance & Usage
Hellhound is developed strictly for authorized security assessments. The developers assume no liability for misuse or damage caused by this tool. Usage must comply with local and international laws.

**Developer**: [l4zz3rj0d](https://github.com/l4zz3rj0d)  
**License**: MIT
