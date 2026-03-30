<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="600"/>
</p>
<h1 align="center">HELLHOUND v12.5</h1>
<h1 align="center">Apex-King Pentest Framework</h1>
<p align="center">
  Modular web offensive framework with AI-agnostic intelligence correlation and deep surface auditing.
</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI--Agnostic-OpenAI%20%7C%20Anthropic%20%7C%20Gemini-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

---

## The Next Evolution of Web Offense

Hellhound is a high-performance, modular security framework engineered for comprehensive web application penetration testing. Version 12.5 introduces the **Apex-King AI Core**, transitioning the framework from deterministic rule-matching to an intelligent, multi-provider correlation engine.

### Why Hellhound?
- **AI-Agnostic Core**: First-class support for OpenAI (GPT-4o), Anthropic (Claude 3.5), and Google (Gemini) via a zero-SDK REST architecture.
- **Unified Intelligence**: Data discovered by reconnaissance modules is automatically correlated into multi-step "Kill Chains."
- **Headless Orchestration**: Custom Chromium engine for high-fidelity analysis of modern SPAs and complex JS environments.
- **First-Party Logic**: Implements deep-level offensive logic with no heavy third-party wrappers, ensuring maximum speed and direct control.

---

## Core Architecture

Hellhound utilizes a distributed intelligence model structured into four functional layers:

1. **Reconnaissance (Surface Layer)**: Deep mapping of the target's public and internal surface using SPA-aware crawling and OSINT.
2. **Intelligence (Asset Layer)**: High-fidelity extraction of sensitive assets, technology profiling, and source code reconstruction.
3. **Vulnerability (Analysis Layer)**: Logical flaw validation, parameter-level risk assessment, and broken access control mapping.
4. **AI Core (Correlation Layer)**: Intelligent synthesis of all collected "loot" to identify high-value attack paths and eliminate false positives.

---

## AI Intelligence Core

Hellhound's AI Core enables a new level of offensive precision:

- **Intelligent Howl**: Uses your preferred LLM to identify correlated attack chains across discovery modules (e.g., "Spider found a JWT + SecretScanner found a key => Trigger JWT Broker").
- **Deep Source Auditing**: Automatically verifies regex matches in recovered source code (e.g., verifying if a detected `eval()` call is truly reachable and exploitable).
- **Multi-Provider Support**:
  - **OpenAI**: GPT-4o integration for high-reasoning exploit chaining.
  - **Anthropic**: Claude 3.5 Sonnet for precise code-level logic auditing.
  - **Gemini**: Flash models for high-speed, cost-effective surface correlation.

---

## Module Arsenal

| Layer | Module | Purpose | AI Feature |
| :--- | :--- | :--- | :--- |
| **Recon** | **Spider** | Deep SPA/API Surface Mapping | Target Correlation |
| **Recon** | **WAFbuster** | Stack Fingerprinting | Bypass Prediction |
| **Intel** | **BlobUnpacker** | Source Reconstruction | Path Synthesis |
| **Intel** | **SourceAuditor** | Static Analysis | **Deep AI Verification** |
| **Vuln** | **IDORdetector** | Object Scoping | Logic Prediction |
| **Vuln** | **BACdetector** | Access Control Flaws | Role Matrix Audit |
| **Exploit** | **CMDinj** | RCE Confirmation | Payload Optimization |
| **Exploit** | **Exmap** | CVE Correlation | Exploit Chain Synthesis |

---

## Deployment and Setup

### System Requirements
- Python 3.10+
- Linux or macOS
- Chromium/Chrome (for Headless SPA scanning)

### Installation
```bash
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
chmod +x install.sh
./install.sh
```

---

## Operational Workflow

Hellhound utilizes an interactive console designed for speed and modularity.

### 1. Initialize Intelligence
```bash
hellhound > prey http://internal-app.example.com
hellhound > setg ai_provider openai
hellhound > setg ai_key sk-proj-xxxxxxxxxxxx
```

### 2. Map & Audit
```bash
hellhound > equip Spider
hellhound [Spider] > strike
hellhound [Spider] > equip SourceAuditor
hellhound [SourceAuditor] > set use_ai true
hellhound [SourceAuditor] > strike
```

### 3. Correlate with Howl
```bash
hellhound > howl
```
*Howl will now utilize the AI Core to identify the 3 most promising attack paths based on the multi-module intelligence collected.*

---

## Compliance and Usage
This framework is developed for **authorized security assessments only**. Users must obtain explicit written authorization before testing. Unauthorized use may violate local and international laws.

---
**Developer**: [l4zz3rj0d](https://github.com/l4zz3rj0d)  
**License**: MIT
