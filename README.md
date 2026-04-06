<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="600"/>
</p>
<h1 align="center">HELLHOUND v12.5</h1>
<h1 align="center">Apex-King Pentest Framework</h1>
<p align="center">
  Modular web offensive framework with Zero-Config AI Intelligence and High-Fidelity Persona correlation.
</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI--Agnostic-OpenAI%20%7C%20Anthropic%20%7C%20Gemini-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/architecture-Zero--Config%20AI-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

---

##  The Next Evolution of Web Offense

Hellhound is a high-performance, modular security framework engineered for comprehensive web application penetration testing. Version 12.5 introduces the **Apex-King AI Core**, transitioning the framework from static rule-matching to an intelligent, multi-provider correlation engine.

### Why Hellhound?
- **Zero-Config AI**: Standardized discovery handshakes. Provide your API key, and Hellhound automatically identifies, verifies, and persists the optimal model for your assessment.
- **High-Fidelity Personas**: Specialized offensive identities (The Correlator, The Auditor) ensure that your AI insights are technical, strategic, and professional.
- **Non-Blocking Logic**: AI features are strictly optional. The framework handles quota-exhaustion and network failures gracefully, ensuring your scan never stalls.
- **Headless Orchestration**: Custom Chromium engine for high-fidelity analysis of modern SPAs and complex JS environments.

---

##  Core Architecture

Hellhound utilizes a distributed intelligence model structured into four functional layers:

1. **Reconnaissance (Surface Layer)**: Deep mapping of the target's public and internal surface using SPA-aware crawling and OSINT.
2. **Intelligence (Asset Layer)**: High-fidelity extraction of sensitive assets, technology profiling, and source code reconstruction.
3. **Vulnerability (Analysis Layer)**: Logical flaw validation, autonomous parameter audit, and broken access control mapping. Powered by the **Hydra** logic engine.
4. **AI Core (Correlation Layer)**: Intelligent synthesis of all collected "loot" via specialized offensive personas.

---

##  AI Intelligence Core

Hellhound's AI Core has been refactored for professional offensive speed:

- **The Strategic Correlator**: Used by `howl` to identify multi-step attack chains (e.g., mapping an IDOR to a 2FA secret disclosure for full Admin ATO).
- **The Deep Logic Auditor**: Used by `SourceAuditor` to perform high-fidelity verification of dangerous sinks (eval, system, RCE) in reconstructed source code.
- **Instant Parallel Discovery**: Zerond-wait handshakes. Hellhound polls entire model tiers simultaneously to establish connectivity in seconds.

---

## Module Arsenal

| Layer | Module | Purpose | AI Persona |
| :--- | :--- | :--- | :--- |
| **Recon** | **Spider** | Deep SPA/API Surface Mapping | The Strategist |
| **Recon** | **Stalk** | Passive OSINT & Passive Recon | The Observer |
| **Intel** | **Hydra** | Universal Logic & Parameter Auditor | The Polymath |
| **Intel** | **BlobUnpacker** | Source Reconstruction from Maps | The Architect |
| **Intel** | **SourceAuditor** | Static Analysis & Sink Detection | **Deep Logic Auditor** |
| **Intel** | **SecretScanner** | API Key & Secret Extraction | The Harvester |
| **Vuln** | **IDORdetector** | Object Scoping & IDOR Auditor | Logic Prediction |
| **Vuln** | **PATHtraveller** | 6-Tier Path Traversal Auditor | The Navigator |
| **Vuln** | **RBAC** | Multi-Role Privilege Escalation | Role Matrix Audit |
| **Exploit** | **CMDinj** | RCE Confirmation & Proof | The Executioner |

---

## 🐲 The Hydra Logic Engine

Version 12.5 introduces **Hydra**, a multi-headed analysis engine that bridges the gap between reconnaissance and exploitation. Hydra doesn't just find parameters; it understands their **intent**.

*   **Cerberus Head (Entropy)**: Discovers hidden data roles (IDs, Tokens, Secrets) using passive heuristic analysis and technology profiling.
*   **Lailaps Head (Differential)**: Actively probes for dynamism. Identifies how the application reacts to parameter shifts, length deltas, and status code variations.
*   **Geryon Head (Correlation)**: Correlates parameters across distinct endpoints to identify potential cross-context logic flaws (e.g., a "username" from a profile page leaking into an unauthenticated API).

Hydra acts as the **Intelligence Orchestrator**, automatically recommending and seeding specialized auditors like `IDORdetector` or `CORSbuster` with high-fidelity targets.

---

##  Operational Workflow

Hellhound utilizes an interactive console designed for speed and modularity.

### 1. Initialize Intelligence (Zero-Config)
```bash
hellhound > prey http://example.com
hellhound > setg ai_key sk-xxxxxxxxxxxx
```
*Hellhound will instantly discover the best model, verify your quota, and persist the connection.*

### 2. Map & Audit
```bash
hellhound [Spider] > strike
hellhound [PATHtraveller] > strike
hellhound [RBAC] > strike
```
*Modules will automatically utilize AI insights if a key is available.*

### 3. Correlate with Howl
```bash
hellhound > howl
```
*The Correlator persona will now identify the most promising attack paths from your loot.*

---

##  Targeted Reproduction

Hellhound is designed for stealth. It performs aggressive scanning directly, but allows you to replay only the winning findings through Burp Suite/Caido:

1. **Configure Proxy**: `setg proxy http://127.0.0.1:8080`
2. **Targeted Replay**:
   ```bash
   hellhound [IDORdetector] > repro
   ```
   *Only validated vulnerabilities are replayed through your manual testing proxy.*

---

## ⚖️ Compliance and Usage
This framework is developed for **authorized security assessments only**. Unauthorized use may violate local and international laws.

**Developer**: [l4zz3rj0d](https://github.com/l4zz3rj0d)  
**License**: MIT
