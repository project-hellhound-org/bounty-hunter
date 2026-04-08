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

## The Next Evolution of Web Offense

Hellhound is a high-performance, modular security framework engineered for comprehensive web application penetration testing. Version 12.5 introduces the **Apex-King AI Core**, transitioning the framework from static rule-matching to an intelligent, multi-provider correlation engine.

### Why Hellhound?
- **Zero-Config AI**: Standardized discovery handshakes. Provide your API key, and Hellhound automatically identifies, verifies, and persists the optimal model for your assessment.
- **High-Fidelity Personas**: Specialized offensive identities (The Correlator, The Auditor) ensure that your AI insights are technical, strategic, and professional.
- **Non-Blocking Logic**: AI features are strictly optional. The framework handles quota-exhaustion and network failures gracefully, ensuring your scan never stalls.
- **Headless Orchestration**: Custom Chromium engine for high-fidelity analysis of modern SPAs and complex JS environments.

---

## Core Architecture

Hellhound utilizes a distributed intelligence model structured into four functional layers:

1. **Reconnaissance (Surface Layer)**: Deep mapping of the target's public and internal surface using SPA-aware crawling, transport/session analysis, and infrastructure fingerprinting.
2. **Intelligence (Asset Layer)**: High-fidelity extraction of sensitive assets, technology profiling, and source code reconstruction.
3. **Vulnerability (Analysis Layer)**: Logical flaw validation, autonomous parameter audit, and broken access control mapping. Powered by the **Hydra** logic engine.
4. **AI Core (Correlation Layer)**: Intelligent synthesis of all collected "loot" via specialized offensive personas.

---

## AI Intelligence Core

Hellhound's AI Core has been refactored for professional offensive speed:

- **The Strategic Correlator**: Used by `howl` to identify multi-step attack chains (e.g., mapping an IDOR to a 2FA secret disclosure for full Admin ATO).
- **The Deep Logic Auditor**: Used by `SourceAuditor` to perform high-fidelity verification of dangerous sinks (eval, system, RCE) in reconstructed source code.
- **Instant Parallel Discovery**: Zero-wait handshakes. Hellhound polls entire model tiers simultaneously to establish connectivity in seconds.

---

## Module Arsenal

| Layer | Module | Purpose | AI Persona |
| :--- | :--- | :--- | :--- |
| **Recon** | **Spider** | Deep SPA/API surface mapping + passive security detection | The Strategist |
| **Recon** | **TransportAuditor** | SSL/TLS, HTTPS enforcement, HSTS, session cookies, payment transit | — |
| **Recon** | **SurfaceAuditor** | Default configs, CDN/WAF, port scan, OS fingerprint, dependency CVE | — |
| **Recon** | **Stalk** | Passive OSINT & subdomain enumeration | The Observer |
| **Recon** | **CORSbuster** | Active CORS misconfiguration detection | — |
| **Recon** | **GraphQL** | GraphQL introspection, depth & alias abuse | — |
| **Recon** | **JWTanalyzer** | JWT algorithm confusion & weak secret detection | — |
| **Recon** | **WAFbuster** | WAF fingerprinting & bypass header generation | — |
| **Intel** | **Hydra** | Universal logic & parameter orchestration | The Polymath |
| **Intel** | **BlobUnpacker** | Source reconstruction from sourcemaps | The Architect |
| **Intel** | **SourceAuditor** | Static analysis, sink detection & OWASP pre-filtering | **Deep Logic Auditor** |
| **Vuln** | **IDORdetector** | Object scoping & IDOR auditor | Logic Prediction |
| **Vuln** | **PATHtraveller** | 6-tier path traversal auditor | The Navigator |
| **Vuln** | **RBAC** | Multi-role privilege escalation | Role Matrix Audit |
| **Exploit** | **CMDinj** | RCE confirmation & proof-of-concept | The Executioner |

---

## Detection Capabilities

### Sensitive Data Exposure
| Check | Module | Signal |
|---|---|---|
| Hardcoded secrets (API keys, JWTs, credentials) | Spider + SourceAuditor | `[SECRET:*]` |
| Logs / backup file exposure (`.log`, `.bak`, `.sql`) | Spider passive extraction | `[Leaked-File]` |
| Weak encryption (MD5, SHA1, RC4, DES) | SourceAuditor SA-013 | Pre-filter → AI verify |
| Client storage leak (sessionStorage, IndexedDB) | SourceAuditor SA-014 | Pre-filter → AI verify |
| Sensitive logger leak (`console.log(password)`) | SourceAuditor SA-015 | Pre-filter → AI verify |
| Geo-location coordinates in API responses | Spider | `GeoLocation_Leak` |
| Verbose error / stack trace in 5xx responses | Spider | `Error_Stack_Trace` |
| Session cookie flags (HttpOnly, Secure, SameSite) | TransportAuditor | TA-02x |
| Unencrypted HTTP traffic + missing HSTS | TransportAuditor | TA-010/011 |
| Payment endpoints over plain HTTP (PCI-DSS) | TransportAuditor | TA-030 |

### Misconfiguration & Outdated Components
| Check | Module | Signal |
|---|---|---|
| SSL cert expiry, weak ciphers, deprecated TLS | TransportAuditor | TA-00x |
| Default server/framework pages (Apache, Nginx, Django debug, Werkzeug) | SurfaceAuditor | SA-101 |
| CDN misconfiguration + origin IP leak via headers | SurfaceAuditor | SA-102/103 |
| No CDN / WAF protection detected | SurfaceAuditor | SA-104 |
| Open ports & unnecessary services (MySQL, Redis, RDP, MongoDB…) | SurfaceAuditor | SA-110 |
| OS / server version fingerprint (PHP, Apache, OpenSSL) | SurfaceAuditor | SA-12x |
| Outdated frontend SDK CDN version references | SourceAuditor SA-016 | Pre-filter → AI verify |
| Exposed dependency manifests + semver CVE threshold | SurfaceAuditor | SA-13x |
| Server/version header disclosure (Server, X-Powered-By) | Spider tech_stack | `[Tech]` |
| Exposed backup/config files (`.bak`, `.env`, `.git/HEAD`) | Spider BackupProber | `[BACKUP]` |
| CORS misconfiguration | CORSbuster | Finding |
| Source map exposure | Spider | `[SourceMap]` |

---

## The Hydra Logic Engine

Version 12.5 introduces **Hydra**, a multi-headed analysis engine that bridges the gap between reconnaissance and exploitation. Hydra doesn't just find parameters; it understands their **intent**.

- **Cerberus Head (Entropy)**: Discovers hidden data roles (IDs, Tokens, Secrets) using passive heuristic analysis and technology profiling.
- **Lailaps Head (Differential)**: Actively probes for dynamism. Identifies how the application reacts to parameter shifts, length deltas, and status code variations.
- **Geryon Head (Correlation)**: Correlates parameters across distinct endpoints to identify potential cross-context logic flaws.

Hydra acts as the **Intelligence Orchestrator**, automatically recommending and seeding specialized auditors like `IDORdetector` or `CORSbuster` with high-fidelity targets.

---

## The Universal Visual Renderer

Version 12.5 replaces hardcoded terminal loops with a completely dynamic, **schema-agnostic universal rendering engine**.

- **Intelligent UI Hooking**: Modules no longer execute their own `print()` commands. The console automatically detects data clusters, parses them, and organizes them neatly.
- **True-Positive High Value Targets**: The console autonomously correlates the output of all modules to synthesize a hyper-accurate hitlist of endpoints with confirmed vulnerabilities.
- **Professional Output**: Clean arrays, multi-line source reconstruction, recursive JSON cleaning, and immersive visual data aggregation.

---

## Operational Workflow

### 1. Initialize Intelligence (Zero-Config)
```bash
hellhound > prey http://example.com
hellhound > setg ai_key sk-xxxxxxxxxxxx
```

### 2. Recon & Surface Assessment
```bash
hellhound [Spider] > strike              # endpoint mapping + passive detection
hellhound [TransportAuditor] > strike   # SSL/TLS + HTTPS + session cookie audit
hellhound [SurfaceAuditor] > strike     # infra: ports, defaults, CDN, deps
hellhound [CORSbuster] > strike
```

### 3. Intelligence & Vulnerability
```bash
hellhound [SourceAuditor] > strike      # static analysis on reconstructed code
hellhound [IDORdetector] > strike
hellhound [PATHtraveller] > strike
hellhound [RBAC] > strike
```

### 4. Correlate with Howl
```bash
hellhound > howl
```

---

## Targeted Reproduction

1. **Configure Proxy**: `setg proxy http://127.0.0.1:8080`
2. **Targeted Replay**:
   ```bash
   hellhound [IDORdetector] > repro
   ```

---

## Compliance and Usage
This framework is developed for **authorized security assessments only**. Unauthorized use may violate local and international laws.

**Developer**: [l4zz3rj0d](https://github.com/l4zz3rj0d)  
**License**: MIT
