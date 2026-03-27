<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="600"/>
</p>
<h1 align="center">HELLHOUND</h1>
<h1 align="center">Hellhound-Pentest(In-Dev)</h1>
<p align="center">
  Modular web offensive framework for recon, attack surface mapping, and vulnerability detection.
</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

## Web Application Offensive Security Framework

Hellhound is a high-performance, modular security framework engineered for comprehensive web application penetration testing. Designed with a zero-wrapper architecture, Hellhound implements first-party logic for reconnaissance, surface mapping, and vulnerability exploitation, ensuring maximum reliability and deterministic results for security professionals.

---

## Core Architecture

Hellhound is built on a distributed intelligence model where independent modules contribute to a centralized session state. This allows for automated correlation across different stages of an assessment:

- **Unified Intelligence**: Data discovered by reconnaissance modules (e.g., endpoints, parameters, tech stacks) is automatically ingested by vulnerability scanners and exploitation engines.
- **Headless Orchestration**: Leverages a custom Chromium-based engine for high-fidelity analysis of Single Page Applications (SPAs) and dynamic JavaScript environments.
- **Stateless Execution**: Modules are isolated from the core engine, enabling high concurrency and granular performance tuning.
- **Deterministic Logic**: Avoids heuristic-based "guessing" in favor of signature-verified and structural analysis.

---

## Module Ecosystem (Arsenal)

Hellhound's power lies in its specialized module ecosystem, organized into functional layers that mirror a professional penetration testing workflow.

### 1. Reconnaissance & Surface Discovery
*Foundational mapping and identification of the target application's attack surface.*

| Module | Purpose | Key Capabilities |
| :--- | :--- | :--- |
| **Spider** | Deep Surface Mapping | SPA crawling, API endpoint discovery, JS-level link extraction. |
| **Stalk** | OSINT Aggregation | Unified mapping from public sources and internal sub-layers. |
| **FUZZhunter** | Content Discovery | Recursive directory fuzzing with smart 404 similarity detection. |
| **WAFbuster** | Stack Fingerprinting | Active/Passive identification of WAFs and technology stacks. |
| **CORSbuster** | Policy Analysis | Identification of Cross-Origin Resource Sharing vulnerabilities. |
| **GraphQL** | Schema Probing | Schema introspection, field suggestion risks, and DOS pathing. |
| **JWTanalyzer** | Token Decoding | Automated vulnerability testing (alg:none, weak-key brute force). |

### 2. Intelligence Layer
*High-fidelity extraction of sensitive assets and technology profiling.*

| Module | Purpose | Key Capabilities |
| :--- | :--- | :--- |
| **SecretScanner** | Token Discovery | Automated detection of API keys, hardcoded secrets, and high-entropy strings. |
| **CloudScout** | S3/Cloud Discovery | Identification of misconfigured S3 buckets, Azure Blobs, and GCP storage. |
| **TechProfiler** | Version Profiling | Deep fingerprinting of frameworks, container layers, and micro-services. |
| **BlobUnpacker** | Asset Reconstruction | Automated source map unpacking and hidden endpoint extraction from minified JS. |

### 3. Vulnerability & Analysis Layer
*Validation of security misconfigurations and logical flaws.*

| Module | Purpose | Key Capabilities |
| :--- | :--- | :--- |
| **IDORdetector** | Object Scoping | Dual-session mass enumeration of Insecure Direct Object References. |
| **BACdetector** | Access Control | Multi-role Broken Access Control validation and permission mapping. |
| **Parax** | Parameter Heuristics | Advanced classification of parameter-level risks (SQLi, XSS, SSRF). |

### 4. Exploitation Layer
*Confirmation of weaponized attack paths.*

| Module | Purpose | Key Capabilities |
| :--- | :--- | :--- |
| **CMDinj** | RCE Confirmation | Automated generation and verification of Command Injection PoCs. |
| **Exmap** | CVE Correlation | Mapping confirmed technology versions to weaponized exploits (Metasploit/Internal). |

---

## Deployment and Setup

### System Requirements
- Python 3.10 or higher
- Linux or macOS environment
- Up-to-date Chromium/Chrome installation (for Headless SPA scanning)

### Installation Sequence

```bash
# Clone the repository
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest

# Execute the automated deployment script
chmod +x install.sh
./install.sh
```

---

## Operational Workflow

Hellhound utilizes a standardized command-line interface for session management and module execution.

1. **Target Acquisition**: Initialize the session with a target URL.
2. **Module Selection**: Equip the desired analytical module from the arsenal.
3. **Execution**: Trigger the `strike` command to begin analysis.
4. **Data Review**: Utilize the `loot` command for correlated findings and `howl` for prioritized next-steps.

```bash
hellhound > prey http://internal-app.example.com
hellhound > equip Spider
hellhound [Spider] > strike
hellhound [Spider] > loot --summary
hellhound [Spider] > howl
```

---

## Compliance and Usage

This framework is developed for authorized security assessments only. Users are strictly required to obtain explicit written authorization before deploying Hellhound against any infrastructure. Unauthorized use of this tool may violate local and international laws.

---

**Developer**: [l4zz3rj0d](https://github.com/l4zz3rj0d)  
**License**: MIT
